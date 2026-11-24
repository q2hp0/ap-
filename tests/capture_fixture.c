#define _POSIX_C_SOURCE 200809L
#include "apcapture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t make_frame(uint8_t *out, size_t cap) {
  static const uint8_t ethernet[14] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x08, 0x00
  };
  static const char ip_tcp[] =
    "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000";
  size_t len;

  if (cap < sizeof(ethernet)) return 0;
  memcpy(out, ethernet, sizeof(ethernet));
  len = strlen(ip_tcp) / 2u;
  if (ap_hex_decode(ip_tcp, strlen(ip_tcp), out + sizeof(ethernet),
                    cap - sizeof(ethernet)) != AP_OK) {
    return 0;
  }
  return sizeof(ethernet) + len;
}

static int write_frame(FILE *file, const uint8_t *frame, size_t len) {
  uint8_t prefix[2];
  prefix[0] = (uint8_t)(len & 0xffu);
  prefix[1] = (uint8_t)(len >> 8);
  return fwrite(prefix, 1u, sizeof(prefix), file) == sizeof(prefix) &&
         fwrite(frame, 1u, len, file) == len;
}

int main(int argc, char **argv) {
  uint8_t frame[AP_CAPTURE_FRAME_MAX];
  size_t len = make_frame(frame, sizeof(frame));
  unsigned long count = 1u;
  FILE *file;
  unsigned long i;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: capture_fixture <path> [count]\n");
    return 2;
  }
  if (argc == 3) {
    count = strtoul(argv[2], NULL, 10);
    if (count == 0u || count > 1024u) return 2;
  }
  if (len == 0u) return 1;
  file = fopen(argv[1], "wb");
  if (file == NULL) {
    fprintf(stderr, "capture_fixture: cannot create %s\n", argv[1]);
    return 1;
  }
  for (i = 0u; i < count; ++i) {
    if (!write_frame(file, frame, len)) {
      fclose(file);
      return 1;
    }
  }
  fclose(file);
  return 0;
}
