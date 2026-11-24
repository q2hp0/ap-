#ifndef APFLOW_H
#define APFLOW_H

#include "apabi.h"

#define AP_FLOW_PID_SLOTS 32u
#define AP_FLOW_RANGE_SLOTS 64u
#define AP_FLOW_SHADOW_DEPTH 64u
#define AP_FLOW_KERNEL_LABELS 9u
#define AP_FLOW_ENTITY_SLOTS 32u
#define AP_FLOW_ENTITY_KEY_LEN 48u

#define AP_FLOW_STAGE_WX 1u
#define AP_FLOW_STAGE_EXEC 2u
#define AP_FLOW_STAGE_PRIV 4u
#define AP_FLOW_STAGE_NET 8u
#define AP_FLOW_STAGE_ALL 15u

typedef struct ap_flow_handle ap_flow_handle;

typedef struct ap_flow_counters {
  uint64_t events;
  uint64_t findings;
  uint64_t ranges;
  uint64_t stacks;
  uint64_t evictions;
  uint64_t entity_events;
  uint64_t entity_findings;
  uint64_t entity_evictions;
  uint64_t entity_refs_expired;
} ap_flow_counters;

#ifdef __cplusplus
extern "C" {
#endif

ap_flow_handle *ap_flow_new(void);
void ap_flow_free(ap_flow_handle *handle);
int ap_flow_feed(ap_flow_handle *handle, const ap_event *event, ap_verdict *verdict);
int ap_flow_stats(const ap_flow_handle *handle, ap_flow_counters *counters);
int ap_flow_reset(ap_flow_handle *handle);
int ap_flow_set_window_ms(ap_flow_handle *handle, uint32_t window_ms);

#ifdef __cplusplus
}
#endif

#endif
