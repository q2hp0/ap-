#ifndef APCOLLECTOR_H
#define APCOLLECTOR_H

#include "aptelemetry.h"

#define AP_COLLECTOR_MAX_PIDS 512u
#define AP_COLLECTOR_DEFAULT_MAPS_PER_SCAN 8u
#define AP_COLLECTOR_MAX_MAPS_PER_SCAN 32u
#define AP_COLLECTOR_DEFAULT_WX_PER_SCAN 4u
#define AP_COLLECTOR_MAX_WX_PER_SCAN 16u
#define AP_COLLECTOR_DEFAULT_IO_PER_SCAN 8u
#define AP_COLLECTOR_MAX_IO_PER_SCAN 32u

typedef struct ap_collector ap_collector;

typedef int (*ap_collector_cb)(const ap_event *event, void *user);

typedef struct ap_collector_counters {
  uint64_t scans;
  uint64_t pids_seen;
  uint64_t starts;
  uint64_t exits;
  uint64_t execs;
  uint64_t priv_changes;
  uint64_t wx_regions;
  uint64_t file_events;
  uint64_t file_samples;
  uint64_t file_errors;
  uint64_t evictions;
  uint64_t errors;
} ap_collector_counters;

#ifdef __cplusplus
extern "C" {
#endif

ap_collector *ap_collector_new(uint32_t max_pids);
int ap_collector_set_map_limits(ap_collector *collector, uint32_t map_samples,
                                uint32_t wx_per_scan);
int ap_collector_map_limits(const ap_collector *collector, uint32_t *map_samples,
                            uint32_t *wx_per_scan);
int ap_collector_set_io_per_scan(ap_collector *collector, uint32_t io_per_scan);
int ap_collector_io_per_scan(const ap_collector *collector, uint32_t *io_per_scan);
void ap_collector_free(ap_collector *collector);
int ap_collector_scan(ap_collector *collector, uint64_t now_ns,
                      ap_collector_cb callback, void *user);
int ap_collector_scan_pid_maps(ap_collector *collector, int64_t pid,
                               uint64_t now_ns, ap_collector_cb callback, void *user);
int ap_collector_scan_pid_io(ap_collector *collector, int64_t pid,
                             uint64_t now_ns, ap_collector_cb callback, void *user);
int ap_collector_stats(const ap_collector *collector, ap_collector_counters *out);

#ifdef __cplusplus
}
#endif

#endif
