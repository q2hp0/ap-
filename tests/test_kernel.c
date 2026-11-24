#define _POSIX_C_SOURCE 200809L
#include "apkernel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "kernel test fail: %s\n", name);
    ++failures;
  }
}

typedef struct kernel_sink {
  int count;
  ap_event events[4];
} kernel_sink;

static int on_event(const ap_event *event, void *user) {
  kernel_sink *sink = (kernel_sink *)user;
  if (sink->count < (int)(sizeof(sink->events) / sizeof(sink->events[0]))) {
    sink->events[sink->count] = *event;
  }
  ++sink->count;
  return 0;
}

static void write_count(FILE *file, uint32_t value) {
  uint8_t bytes[4];
  bytes[0] = (uint8_t)(value & 0xffu);
  bytes[1] = (uint8_t)((value >> 8) & 0xffu);
  bytes[2] = (uint8_t)((value >> 16) & 0xffu);
  bytes[3] = (uint8_t)((value >> 24) & 0xffu);
  fwrite(bytes, 1u, sizeof(bytes), file);
}

static void write_header(FILE *file, uint32_t count) {
  fwrite("apk1", 1u, 4u, file);
  write_count(file, count);
}

static void make_event(ap_event *event, uint16_t kind, uint64_t seq,
                       const char *text) {
  ap_event_init(event, kind);
  event->seq = seq;
  event->pid = 7000;
  event->tid = 7000;
  event->ts_ns = 1000u + seq;
  event->confidence_x1000 = 900u;
  snprintf(event->text, sizeof(event->text), "%s", text);
}

static void write_event(FILE *file, const ap_event *event) {
  fwrite(event, 1u, sizeof(*event), file);
}

static void path_for(char *out, size_t cap, const char *name) {
  snprintf(out, cap, "/tmp/ap-kernel-%ld-%s.apk1", (long)getpid(), name);
}

int main(void) {
  char path[128];
  char other[128];
  ap_kernel_counters counters;
  kernel_sink sink;
  ap_kernel *kernel;
  ap_event event;
  FILE *file;

  path_for(path, sizeof(path), "valid");
  file = fopen(path, "wb");
  check(file != NULL, "valid fixture create");
  if (file == NULL) return 1;
  write_header(file, 3u);
  make_event(&event, AP_KIND_PROC, 1u, "kernel_probe");
  write_event(file, &event);
  make_event(&event, AP_KIND_KERNEL, 2u, "bpf");
  write_event(file, &event);
  make_event(&event, AP_KIND_NET, 3u, "4500");
  write_event(file, &event);
  fclose(file);

  memset(&sink, 0, sizeof(sink));
  kernel = ap_kernel_open_file(path);
  check(kernel != NULL, "open valid file");
  if (kernel != NULL) {
    check(ap_kernel_pending(kernel) == 3u, "initial pending");
    check(ap_kernel_stats(kernel, &counters) == AP_OK, "valid stats");
    check(counters.frames == 3u && counters.invalid == 0u, "valid counters");
    check(ap_kernel_poll(kernel, 2u, on_event, &sink) == AP_OK, "first poll");
    check(sink.count == 2, "first poll count");
    check(ap_kernel_pending(kernel) == 1u, "pending after first poll");
    check(ap_kernel_poll(kernel, 8u, on_event, &sink) == AP_OK, "second poll");
    check(sink.count == 3, "second poll count");
    check(ap_kernel_pending(kernel) == 0u, "pending after replay");
    check(ap_kernel_poll(kernel, 8u, on_event, &sink) == AP_OK, "empty poll");
    check(ap_kernel_stats(kernel, &counters) == AP_OK, "final stats");
    check(counters.frames == 3u && counters.parsed == 3u, "final counters");
    check(counters.invalid == 0u && counters.errors == 0u, "final errors");
    if (sink.count == 3) {
      check(sink.events[0].seq == 1u && sink.events[1].seq == 2u, "event sequence");
      check(sink.events[0].kind == AP_KIND_PROC, "first event kind");
      check(sink.events[1].arg[3] == AP_KERNEL_SOURCE_MARK, "kernel mark");
      check(sink.events[2].arg[3] == 0u, "network event not marked");
      check(strcmp(sink.events[1].text, "bpf") == 0, "event text");
    }
    ap_kernel_free(kernel);
  }

  path_for(other, sizeof(other), "invalid-event");
  file = fopen(other, "wb");
  check(file != NULL, "invalid event fixture create");
  if (file != NULL) {
    write_header(file, 2u);
    make_event(&event, AP_KIND_PROC, 1u, "clean");
    write_event(file, &event);
    make_event(&event, AP_KIND_PROC, 2u, "bad");
    event.abi_version = 99u;
    write_event(file, &event);
    fclose(file);
  }
  memset(&sink, 0, sizeof(sink));
  kernel = ap_kernel_open_file(other);
  check(kernel != NULL, "open mixed file");
  if (kernel != NULL) {
    check(ap_kernel_stats(kernel, &counters) == AP_OK, "mixed stats");
    check(counters.frames == 2u && counters.invalid == 1u, "mixed counters");
    check(ap_kernel_pending(kernel) == 1u, "mixed pending");
    check(ap_kernel_poll(kernel, 8u, on_event, &sink) == AP_OK, "mixed poll");
    check(sink.count == 1, "mixed callback count");
    check(ap_kernel_stats(kernel, &counters) == AP_OK, "mixed final stats");
    check(counters.parsed == 1u && counters.errors == 0u, "mixed parsed");
    ap_kernel_free(kernel);
  }

  path_for(other, sizeof(other), "bad-magic");
  file = fopen(other, "wb");
  check(file != NULL, "bad magic fixture create");
  if (file != NULL) {
    fwrite("xxxx", 1u, 4u, file);
    write_count(file, 0u);
    fclose(file);
  }
  check(ap_kernel_open_file(other) == NULL, "bad magic rejected");

  path_for(other, sizeof(other), "bad-count");
  file = fopen(other, "wb");
  check(file != NULL, "bad count fixture create");
  if (file != NULL) {
    write_header(file, AP_KERNEL_MAX_EVENTS + 1u);
    fclose(file);
  }
  check(ap_kernel_open_file(other) == NULL, "oversized count rejected");

  path_for(other, sizeof(other), "truncated");
  file = fopen(other, "wb");
  check(file != NULL, "truncated fixture create");
  if (file != NULL) {
    write_header(file, 1u);
    fwrite("short", 1u, 5u, file);
    fclose(file);
  }
  check(ap_kernel_open_file(other) == NULL, "truncated file rejected");

  path_for(other, sizeof(other), "trailing");
  file = fopen(other, "wb");
  check(file != NULL, "trailing fixture create");
  if (file != NULL) {
    write_header(file, 0u);
    fwrite("x", 1u, 1u, file);
    fclose(file);
  }
  check(ap_kernel_open_file(other) == NULL, "trailing byte rejected");

  path_for(other, sizeof(other), "missing");
  check(ap_kernel_open_file(other) == NULL, "missing file rejected");
  check(ap_kernel_open_file(NULL) == NULL, "null path rejected");
  check(ap_kernel_open_file("") == NULL, "empty path rejected");
  check(ap_kernel_pending(NULL) == 0u, "null pending");
  check(ap_kernel_poll(NULL, 1u, on_event, &sink) == AP_ERR_ARG, "null poll");
  check(ap_kernel_stats(NULL, &counters) == AP_ERR_ARG, "null stats");
  kernel = ap_kernel_open_file(path);
  check(kernel != NULL, "reopen valid file");
  if (kernel != NULL) ap_kernel_free(kernel);

  remove(path);
  path_for(other, sizeof(other), "invalid-event");
  remove(other);
  path_for(other, sizeof(other), "bad-magic");
  remove(other);
  path_for(other, sizeof(other), "bad-count");
  remove(other);
  path_for(other, sizeof(other), "truncated");
  remove(other);
  path_for(other, sizeof(other), "trailing");
  remove(other);

  printf("kernel tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
