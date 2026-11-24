#define _POSIX_C_SOURCE 200809L
#include "apcapture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "capture test fail: %s\n", name);
    ++failures;
  }
}

typedef struct capture_sink {
  int count;
  ap_event events[4];
} capture_sink;

static int on_frame(const ap_event *event, void *user) {
  capture_sink *sink = (capture_sink *)user;
  if (sink->count < (int)(sizeof(sink->events) / sizeof(sink->events[0]))) {
    sink->events[sink->count] = *event;
  }
  ++sink->count;
  return 0;
}

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

static void write_frame(FILE *file, const uint8_t *frame, size_t len) {
  uint8_t prefix[2];
  prefix[0] = (uint8_t)(len & 0xffu);
  prefix[1] = (uint8_t)(len >> 8);
  fwrite(prefix, 1u, sizeof(prefix), file);
  fwrite(frame, 1u, len, file);
}

int main(void) {
  char path[128];
  uint8_t frame[AP_CAPTURE_FRAME_MAX];
  uint8_t short_frame[6];
  size_t len = make_frame(frame, sizeof(frame));
  ap_capture_counters counters;
  capture_sink sink;
  ap_capture *capture;
  FILE *file;

  check(len > 14u, "frame construction");
  snprintf(path, sizeof(path), "/tmp/ap-capture-%ld.bin", (long)getpid());
  file = fopen(path, "wb");
  check(file != NULL, "fixture create");
  if (file == NULL) return 1;
  write_frame(file, frame, len);
  write_frame(file, frame, len);
  memset(short_frame, 0, sizeof(short_frame));
  write_frame(file, short_frame, sizeof(short_frame));
  fclose(file);

  memset(&sink, 0, sizeof(sink));
  capture = ap_capture_open_file(path, AP_CAPTURE_DEFAULT_SNAP);
  check(capture != NULL, "open framed file");
  if (capture != NULL) {
    check(ap_capture_fd(capture) >= 0, "capture descriptor");
    (void)ap_capture_poll(capture, AP_CAPTURE_MAX_FRAMES, on_frame, &sink, 100);
    check(ap_capture_stats(capture, &counters) == AP_OK, "capture stats");
    check(counters.frames == 3u, "frame counter");
    check(counters.parsed == 2u, "parsed counter");
    check(counters.invalid == 1u, "invalid counter");
    check(counters.truncated == 0u, "snap counter");
    check(counters.errors == 0u, "error counter");
    check(sink.count == 2, "callback count");
    if (sink.count == 2) {
      check(sink.events[0].seq == 1u && sink.events[1].seq == 2u, "event sequence");
      check(sink.events[0].kind == AP_KIND_NET, "event kind");
      check(sink.events[0].subkind == AP_NET_PACKET, "event subkind");
      check(sink.events[0].pid == -1 && sink.events[0].tid == -1, "event pid");
      check(sink.events[0].arg[3] == AP_CAPTURE_SOURCE_MARK, "capture mark");
      check(strlen(sink.events[0].text) == 80u, "packet hex length");
      check(strncmp(sink.events[0].text, "4500", 4) == 0, "packet hex");
    }
    ap_capture_free(capture);
  }

  memset(&sink, 0, sizeof(sink));
  capture = ap_capture_open_file(path, 20u);
  check(capture != NULL, "open with small snaplen");
  if (capture != NULL) {
    (void)ap_capture_poll(capture, 1u, on_frame, &sink, 100);
    check(ap_capture_stats(capture, &counters) == AP_OK, "small snap stats");
    check(counters.frames == 1u, "small snap frame");
    check(counters.truncated == 1u, "small snap truncation");
    check(sink.count == 1, "small snap callback");
    if (sink.count == 1) {
      check(strlen(sink.events[0].text) == 40u, "truncated hex length");
    }
    ap_capture_free(capture);
  }

  check(ap_capture_open_file("/tmp/ap-capture-missing-file", 63u) == NULL, "missing file");
  check(ap_capture_open_file(NULL, 63u) == NULL, "null file path");
  check(ap_capture_poll(NULL, 1u, on_frame, &sink, 0) == AP_ERR_ARG, "null capture");
  check(ap_capture_stats(NULL, &counters) == AP_ERR_ARG, "null stats");
  capture = ap_capture_open_iface("lo", AP_CAPTURE_DEFAULT_SNAP);
  if (capture != NULL) ap_capture_free(capture);
  remove(path);

  printf("capture tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
