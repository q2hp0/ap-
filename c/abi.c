#define _POSIX_C_SOURCE 200809L
#include "apabi.h"

#include <string.h>
#include <time.h>

void ap_event_init(ap_event *event, uint16_t kind) {
  if (event == NULL) {
    return;
  }
  memset(event, 0, sizeof(*event));
  event->size = (uint32_t)sizeof(*event);
  event->abi_version = AP_ABI_VERSION;
  event->kind = kind;
  event->ts_ns = ap_clock_ns();
  event->pid = -1;
  event->tid = -1;
}

void ap_verdict_init(ap_verdict *verdict, uint64_t seq) {
  if (verdict == NULL) {
    return;
  }
  memset(verdict, 0, sizeof(*verdict));
  verdict->size = (uint32_t)sizeof(*verdict);
  verdict->abi_version = AP_ABI_VERSION;
  verdict->event_seq = seq;
}

uint64_t ap_clock_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int ap_hex_encode(const uint8_t *data, size_t len, char *out, size_t out_len) {
  static const char digits[] = "0123456789abcdef";
  size_t i;
  if (data == NULL || out == NULL || out_len < 2 * len + 1) {
    return AP_ERR_ARG;
  }
  for (i = 0; i < len; ++i) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 0x0fu];
  }
  out[2 * len] = '\0';
  return AP_OK;
}

int ap_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len) {
  size_t i;
  size_t nibbles = in_len / 2u;
  if (in == NULL || out == NULL || (in_len & 1u) != 0u || nibbles > out_len) {
    return AP_ERR_ARG;
  }
  for (i = 0; i < nibbles; ++i) {
    int hi = -1;
    int lo = -1;
    unsigned char a = (unsigned char)in[2 * i];
    unsigned char b = (unsigned char)in[2 * i + 1];
    if (a >= '0' && a <= '9') hi = a - '0';
    else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
    else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
    if (b >= '0' && b <= '9') lo = b - '0';
    else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
    else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
    if (hi < 0 || lo < 0) {
      return AP_ERR_ARG;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return AP_OK;
}

const char *ap_kind_name(uint16_t kind) {
  switch (kind) {
    case AP_KIND_PROC: return "process";
    case AP_KIND_MEMREGION: return "memory_region";
    case AP_KIND_MEMPROT: return "memory_protection";
    case AP_KIND_EXEC: return "exec";
    case AP_KIND_PRIV: return "privilege";
    case AP_KIND_KERNEL: return "kernel";
    case AP_KIND_NET: return "network";
    case AP_KIND_HEAP: return "heap";
    case AP_KIND_FLOW: return "flow";
    case AP_KIND_TRACE: return "trace";
    case AP_KIND_HEARTBEAT: return "heartbeat";
    case AP_KIND_FILE: return "file";
    default: return "unknown";
  }
}

const char *ap_status_name(int status) {
  switch (status) {
    case AP_OK: return "ok";
    case AP_ERR_ARG: return "invalid_argument";
    case AP_ERR_STATE: return "invalid_state";
    case AP_ERR_NOMEM: return "out_of_memory";
    case AP_ERR_IO: return "io_error";
    case AP_ERR_UNSUPPORTED: return "unsupported";
    case AP_ERR_RANGE: return "out_of_range";
    case AP_ERR_AUTH: return "authentication_failed";
    case AP_ERR_REPLAY: return "replay_rejected";
    case AP_ERR_SEQUENCE: return "sequence_rejected";
    default: return "unknown";
  }
}
