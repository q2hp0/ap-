#define _POSIX_C_SOURCE 200809L
#include "apkernel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_count(FILE *file, uint32_t value) {
  uint8_t bytes[4];
  bytes[0] = (uint8_t)(value & 0xffu);
  bytes[1] = (uint8_t)((value >> 8) & 0xffu);
  bytes[2] = (uint8_t)((value >> 16) & 0xffu);
  bytes[3] = (uint8_t)((value >> 24) & 0xffu);
  fwrite(bytes, 1u, sizeof(bytes), file);
}

static void stage(ap_event *event, uint64_t seq, int64_t pid, uint64_t ts_ns,
                  uint16_t kind, uint32_t subkind, uint32_t severity,
                  uint32_t confidence, uint64_t old_uid, uint64_t new_uid,
                  const char *text) {
  ap_event_init(event, kind);
  event->seq = seq;
  event->pid = pid;
  event->tid = pid;
  event->ts_ns = ts_ns;
  event->subkind = subkind;
  event->severity = severity;
  event->confidence_x1000 = confidence;
  event->arg[0] = old_uid;
  event->arg[1] = new_uid;
  snprintf(event->text, sizeof(event->text), "%s", text);
}

int main(int argc, char **argv) {
  ap_event event;
  FILE *file;
  uint64_t now;

  if (argc != 2) {
    fprintf(stderr, "usage: kernel_fixture <path>\n");
    return 2;
  }
  file = fopen(argv[1], "wb");
  if (file == NULL) {
    fprintf(stderr, "kernel_fixture: cannot create %s\n", argv[1]);
    return 1;
  }
  now = ap_clock_ns();
  fwrite("apk1", 1u, 4u, file);
  write_count(file, 6u);

  stage(&event, 1u, 7000, now, AP_KIND_PROC, 0u, AP_SEV_INFO, 900u,
        0u, 0u, "kernel_source_probe");
  fwrite(&event, 1u, sizeof(event), file);
  stage(&event, 2u, 7000, now + 1000u, AP_KIND_KERNEL, 1u, AP_SEV_HIGH, 900u,
        0u, 0u, "bpf");
  fwrite(&event, 1u, sizeof(event), file);
  stage(&event, 3u, 7000, now + 2000u, AP_KIND_KERNEL, 1u, AP_SEV_HIGH, 900u,
        0u, 0u, "ptrace");
  fwrite(&event, 1u, sizeof(event), file);
  stage(&event, 4u, 7000, now + 3000u, AP_KIND_PRIV, 2u, AP_SEV_HIGH, 800u,
        1000u, 0u, "exec_uid_change");
  fwrite(&event, 1u, sizeof(event), file);
  stage(&event, 5u, 7001, now + 4000u, AP_KIND_KERNEL, 1u, AP_SEV_HIGH, 900u,
        0u, 0u, "bpf");
  fwrite(&event, 1u, sizeof(event), file);
  stage(&event, 6u, 7001, now + 5000u, AP_KIND_PRIV, 1u, AP_SEV_MEDIUM, 450u,
        0u, 0u, "setid");
  fwrite(&event, 1u, sizeof(event), file);

  fclose(file);
  return 0;
}
