#ifndef APCAPTURE_H
#define APCAPTURE_H

#include "apabi.h"

#define AP_CAPTURE_SNAP_MIN 20u
#define AP_CAPTURE_SNAP_MAX 63u
#define AP_CAPTURE_DEFAULT_SNAP 63u
#define AP_CAPTURE_MAX_FRAMES 16u
#define AP_CAPTURE_FRAME_MAX 512u
#define AP_CAPTURE_SOURCE_MARK 1u

typedef struct ap_capture ap_capture;

typedef int (*ap_capture_cb)(const ap_event *event, void *user);

typedef struct ap_capture_counters {
  uint64_t frames;
  uint64_t parsed;
  uint64_t invalid;
  uint64_t truncated;
  uint64_t errors;
} ap_capture_counters;

#ifdef __cplusplus
extern "C" {
#endif

ap_capture *ap_capture_open_iface(const char *ifname, uint32_t snaplen);
ap_capture *ap_capture_open_file(const char *path, uint32_t snaplen);
void ap_capture_free(ap_capture *capture);
int ap_capture_fd(const ap_capture *capture);
int ap_capture_poll(ap_capture *capture, uint32_t max_frames,
                    ap_capture_cb callback, void *user, int timeout_ms);
int ap_capture_stats(const ap_capture *capture, ap_capture_counters *out);

#ifdef __cplusplus
}
#endif

#endif
