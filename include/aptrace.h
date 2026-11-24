#ifndef APTRACE_H
#define APTRACE_H

#include "apabi.h"

#define AP_TRACE_FOLLOW_FORK 1u
#define AP_TRACE_MASK_MEM 1u
#define AP_TRACE_MASK_FLOW 2u
#define AP_TRACE_MASK_NET 4u
#define AP_TRACE_MASK_KERNEL 8u
#define AP_TRACE_MASK_PRIV 16u
#define AP_TRACE_MASK_FILE 32u
#define AP_TRACE_MASK_ALL 63u

typedef struct ap_trace_config {
  const char *const *argv;
  uint32_t argc;
  uint32_t flags;
  uint32_t mask;
  uint32_t max_events;
} ap_trace_config;

#ifdef __cplusplus
extern "C" {
#endif

int ap_trace_run(const ap_trace_config *config, ap_event_cb callback, void *user);

#ifdef __cplusplus
}
#endif

#endif
