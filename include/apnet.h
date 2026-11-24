#ifndef APNET_H
#define APNET_H

#include "apabi.h"

#define AP_NET_FLOW_SLOTS 512u
#define AP_NET_FRAG_SLOTS 128u
#define AP_NET_PEER_SLOTS 64u
#define AP_NET_PEER_WINDOW_NS 1000000000ull
#define AP_NET_PEER_BURST 32u

typedef struct ap_net_handle ap_net_handle;

typedef struct ap_net_counters {
  uint64_t packets;
  uint64_t findings;
  uint64_t states;
  uint64_t fragments;
  uint64_t invalid;
  uint64_t evictions;
  uint64_t peers;
  uint64_t peer_events;
  uint64_t peer_evictions;
  uint64_t peer_bursts;
  uint64_t peer_exhaustion;
} ap_net_counters;

#ifdef __cplusplus
extern "C" {
#endif

ap_net_handle *ap_net_new(void);
void ap_net_free(ap_net_handle *handle);
int ap_net_feed(ap_net_handle *handle, const ap_event *event, ap_verdict *verdict);
int ap_net_stats(const ap_net_handle *handle, ap_net_counters *stats);
int ap_net_reset(ap_net_handle *handle);

#ifdef __cplusplus
}
#endif

#endif
