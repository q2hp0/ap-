#ifndef APINTRUSION_H
#define APINTRUSION_H

#include "apabi.h"

#include <stdint.h>

#define AP_INTRUSION_PID_SLOTS 64u
#define AP_INTRUSION_WINDOW_NS 10000000000ull
#define AP_INTRUSION_SUPPRESS_NS 5000000000ull
#define AP_INTRUSION_RESULTS 4u

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ap_intrusion ap_intrusion;

typedef struct ap_intrusion_counters {
  uint64_t added;
  uint64_t evicted;
  uint64_t findings;
  uint64_t suppressed;
} ap_intrusion_counters_t;

ap_intrusion *ap_intrusion_new(void);
void ap_intrusion_free(ap_intrusion *handle);
int ap_intrusion_feed(ap_intrusion *handle, const ap_event *event, ap_verdict *verdict);
int ap_intrusion_stats(const ap_intrusion *handle, ap_intrusion_counters_t *counters);
void ap_intrusion_reset(ap_intrusion *handle);

#ifdef __cplusplus
}
#endif

#endif
