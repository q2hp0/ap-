#ifndef APKERNEL_H
#define APKERNEL_H

#include "apabi.h"

#define AP_KERNEL_SOURCE_MARK 2u
#define AP_KERNEL_MAX_EVENTS 4096u
#define AP_KERNEL_HEADER_SIZE 8u

typedef struct ap_kernel ap_kernel;

typedef struct ap_kernel_counters {
  uint64_t frames;
  uint64_t parsed;
  uint64_t invalid;
  uint64_t errors;
} ap_kernel_counters;

typedef int (*ap_kernel_cb)(const ap_event *event, void *user);

#ifdef __cplusplus
extern "C" {
#endif

ap_kernel *ap_kernel_open_file(const char *path);
void ap_kernel_free(ap_kernel *kernel);
uint32_t ap_kernel_pending(const ap_kernel *kernel);
int ap_kernel_poll(ap_kernel *kernel, uint32_t max_events,
                   ap_kernel_cb callback, void *user);
int ap_kernel_stats(const ap_kernel *kernel, ap_kernel_counters *out);

#ifdef __cplusplus
}
#endif

#endif
