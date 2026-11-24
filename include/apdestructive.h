#ifndef APDESTRUCTIVE_H
#define APDESTRUCTIVE_H

#include "apabi.h"

#include <stdint.h>

#define AP_DESTRUCTIVE_PID_SLOTS 64u
#define AP_DESTRUCTIVE_WINDOW_NS 10000000000ull
#define AP_DESTRUCTIVE_SUPPRESS_NS 5000000000ull
#define AP_DESTRUCTIVE_RESULTS 3u

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ap_destructive ap_destructive;

typedef struct ap_destructive_counters {
  uint64_t added;
  uint64_t evicted;
  uint64_t findings;
  uint64_t suppressed;
} ap_destructive_counters_t;

ap_destructive *ap_destructive_new(void);
void ap_destructive_free(ap_destructive *handle);
int ap_destructive_feed(ap_destructive *handle, const ap_event *event, ap_verdict *verdict);
int ap_destructive_stats(const ap_destructive *handle, ap_destructive_counters_t *counters);
void ap_destructive_reset(ap_destructive *handle);

#ifdef __cplusplus
}
#endif

#endif
