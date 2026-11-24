#define _POSIX_C_SOURCE 200809L
#include "apabi.h"
#include "apsys.h"
#include "aptransport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint64_t next_random(uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

static uint32_t below(uint64_t *state, uint32_t n) {
  return n == 0u ? 0u : (uint32_t)(next_random(state) % (uint64_t)n);
}

static int seal_send(int fd, const uint8_t *key, const ap_event *event) {
  return ap_sys_send_sealed(fd, key, event) == AP_OK ? 0 : 1;
}

static void fill_benign(ap_event *event, uint64_t seq, uint64_t *state) {
  static const uint16_t kinds[] = {
    AP_KIND_PROC, AP_KIND_EXEC, AP_KIND_TRACE, AP_KIND_HEARTBEAT,
    AP_KIND_NET, AP_KIND_MEMPROT, AP_KIND_MEMREGION, AP_KIND_FLOW
  };
  static const char digits[] = "0123456789abcdef";
  uint16_t kind = kinds[below(state, (uint32_t)(sizeof(kinds) / sizeof(kinds[0])))];
  size_t len = 4u + below(state, 32u);
  size_t i;

  ap_event_init(event, kind);
  event->seq = seq;
  event->pid = (int64_t)(below(state, 60u) + 1u);
  event->tid = event->pid;
  event->ts_ns = 1000000ull + seq * 1000ull + next_random(state) % 1000ull;
  event->severity = below(state, 5u);
  event->confidence_x1000 = below(state, 701u);
  event->arg[0] = next_random(state);
  event->arg[1] = next_random(state);
  event->arg[2] = next_random(state);
  event->arg[3] = next_random(state);

  switch (kind) {
    case AP_KIND_NET:
      event->subkind = below(state, 2u) == 0u ? AP_NET_SOCKET : AP_NET_CONNECT;
      event->arg[1] = 1u;
      break;
    case AP_KIND_MEMPROT:
    case AP_KIND_MEMREGION:
      event->subkind = 1u;
      event->arg[2] = 5u;
      break;
    case AP_KIND_FLOW:
      event->subkind = AP_FLOW_RETURN_SITE;
      break;
    default:
      event->subkind = below(state, 4u);
      break;
  }

  for (i = 0u; i < len; ++i) {
    event->text[i] = digits[below(state, 16u)];
  }
  event->text[len] = '\0';
}

static void fill_wx(ap_event *event, uint64_t seq) {
  ap_event_init(event, AP_KIND_MEMPROT);
  event->seq = seq;
  event->pid = (int64_t)(seq % 64u) + 1;
  event->tid = event->pid;
  event->ts_ns = 1000000ull + seq * 1000ull;
  event->subkind = 1u;
  event->severity = AP_SEV_CRITICAL;
  event->confidence_x1000 = 950u;
  event->arg[2] = 7u;
  snprintf(event->text, sizeof(event->text), "mprotect");
}

static int send_malformed(int fd, const uint8_t *key) {
  unsigned char raw[AP_TRANSPORT_PACKET_LEN + 16u];
  ap_event event;
  int bad = 0;

  memset(raw, 0x41, sizeof(raw));
  if (ap_sys_write_all(fd, raw, 0u) != AP_OK ||
      ap_sys_write_all(fd, raw, 1u) != AP_OK ||
      ap_sys_write_all(fd, raw, sizeof(ap_event) - 1u) != AP_OK ||
      ap_sys_write_all(fd, raw, sizeof(raw)) != AP_OK) {
    return -1;
  }

  ap_event_init(&event, AP_KIND_PROC);
  event.abi_version = 99u;
  if (seal_send(fd, key, &event) != 0) return -1;
  ++bad;

  ap_event_init(&event, AP_KIND_PROC);
  memset(event.text, 'x', sizeof(event.text));
  if (seal_send(fd, key, &event) != 0) return -1;
  ++bad;

  ap_event_init(&event, 0u);
  if (seal_send(fd, key, &event) != 0) return -1;
  ++bad;

  ap_event_init(&event, AP_KIND_PROC);
  event.size = 1u;
  if (seal_send(fd, key, &event) != 0) return -1;
  ++bad;

  return bad;
}

static int send_tampered(int fd, const uint8_t *key) {
  ap_event event;
  ap_packet packet;
  int sent = 0;

  fill_wx(&event, 1u);
  if (ap_transport_seal(key, &event, &packet) != AP_OK) return -1;
  packet.data[AP_TRANSPORT_HEADER_LEN] ^= 0x01u;
  if (ap_sys_write_all(fd, packet.data, sizeof(packet.data)) != AP_OK) return -1;
  ++sent;

  if (ap_transport_seal(key, &event, &packet) != AP_OK) return -1;
  packet.data[0] ^= 0x01u;
  if (ap_sys_write_all(fd, packet.data, sizeof(packet.data)) != AP_OK) return -1;
  ++sent;

  if (ap_transport_seal(key, &event, &packet) != AP_OK) return -1;
  packet.data[4] = (uint8_t)(AP_TRANSPORT_VERSION + 1u);
  if (ap_sys_write_all(fd, packet.data, sizeof(packet.data)) != AP_OK) return -1;
  ++sent;

  if (ap_transport_seal(key, &event, &packet) != AP_OK) return -1;
  packet.data[AP_TRANSPORT_PACKET_LEN - 1u] ^= 0x80u;
  if (ap_sys_write_all(fd, packet.data, sizeof(packet.data)) != AP_OK) return -1;
  ++sent;

  return sent;
}

static int send_unsigned(int fd) {
  ap_event event;
  fill_wx(&event, 1u);
  return ap_sys_write_all(fd, &event, sizeof(event)) == AP_OK ? 1 : -1;
}

int main(int argc, char **argv) {
  uint64_t state = 0x123456789abcdef0ull;
  uint64_t count = 0u;
  ap_event event;
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  int fd = -1;
  uint64_t i;
  int result;

  if (argc < 3 || (strcmp(argv[2], "findings") == 0 && argc < 4)) {
    fprintf(stderr, "usage: fuzz_inject <socket> <count|findings|malformed|tampered|unsigned> [seed|count]\n");
    return 2;
  }
  if (argc > 3) {
    state = strtoull(argv[3], NULL, 0);
    if (state == 0u) state = 0x123456789abcdef0ull;
  }
  if (ap_sys_client_open(argv[1], &fd) != AP_OK) {
    fprintf(stderr, "fuzz_inject: cannot connect to %s\n", argv[1]);
    return 1;
  }
  if (ap_transport_key_load(argv[1], key) != AP_OK) {
    fprintf(stderr, "fuzz_inject: cannot load transport key for %s\n", argv[1]);
    close(fd);
    return 1;
  }

  if (strcmp(argv[2], "findings") == 0) {
    count = strtoull(argv[3], NULL, 0);
    for (i = 0u; i < count; ++i) {
      fill_wx(&event, i + 1u);
      if (seal_send(fd, key, &event) != 0) {
        fprintf(stderr, "fuzz_inject: findings write failed at %llu\n", (unsigned long long)i);
        return 1;
      }
    }
    printf("fuzz_inject: findings=%llu\n", (unsigned long long)count);
    return 0;
  }

  if (strcmp(argv[2], "malformed") == 0) {
    result = send_malformed(fd, key);
    if (result < 0) {
      fprintf(stderr, "fuzz_inject: malformed send failed\n");
      return 1;
    }
    printf("fuzz_inject: malformed=%d\n", result);
    return 0;
  }

  if (strcmp(argv[2], "tampered") == 0) {
    result = send_tampered(fd, key);
    if (result < 0) {
      fprintf(stderr, "fuzz_inject: tampered send failed\n");
      return 1;
    }
    printf("fuzz_inject: tampered=%d\n", result);
    return 0;
  }

  if (strcmp(argv[2], "unsigned") == 0) {
    result = send_unsigned(fd);
    if (result < 0) {
      fprintf(stderr, "fuzz_inject: unsigned send failed\n");
      return 1;
    }
    printf("fuzz_inject: unsigned=%d\n", result);
    return 0;
  }

  count = strtoull(argv[2], NULL, 0);
  for (i = 0u; i < count; ++i) {
    fill_benign(&event, i + 1u, &state);
    if (seal_send(fd, key, &event) != 0) {
      fprintf(stderr, "fuzz_inject: write failed at %llu\n", (unsigned long long)i);
      return 1;
    }
  }
  printf("fuzz_inject: sent=%llu\n", (unsigned long long)count);
  return 0;
}
