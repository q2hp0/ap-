#ifndef APKSENSOR_H
#define APKSENSOR_H

#include "apabi.h"
#include "apcap.h"

#include <stddef.h>
#include <stdint.h>

#define AP_KSENSOR_SOURCE_MARK 3u
#define AP_KSENSOR_MAX_CPUS 16u
#define AP_KSENSOR_RING_PAGES 64u
#define AP_KSENSOR_MAX_EVENTS 256u
#define AP_KSENSOR_REASON_LEN 128u

#define AP_KSENSOR_FLAG_RAW_TRACEPOINTS 1u
#define AP_KSENSOR_FLAG_PERF_RING 2u
#define AP_KSENSOR_FLAG_LSM 4u

enum ap_ksensor_label {
  AP_KLABEL_NONE = 0,
  AP_KLABEL_EXEC = 1,
  AP_KLABEL_EXIT = 2,
  AP_KLABEL_MODULE = 3,
  AP_KLABEL_BPF_PROG = 4,
  AP_KLABEL_PTRACE = 5,
  AP_KLABEL_CRED = 6,
  AP_KLABEL_NET = 7,
  AP_KLABEL_ROOTKIT = 8,
  AP_KLABEL_CREDENTIAL_THEFT = 9,
  AP_KLABEL_PERSISTENCE = 10,
  AP_KLABEL_CONTAINER_ESCAPE = 11,
  AP_KLABEL_FILELESS_EXEC = 12,
  AP_KLABEL_ANTI_ANALYSIS = 13
};

typedef struct ap_ksample {
  uint64_t ts_ns;
  uint64_t pid_tgid;
  uint32_t label_id;
  uint32_t subkind;
  uint64_t arg[3];
} ap_ksample;

typedef struct ap_ksensor ap_ksensor;

typedef struct ap_ksensor_counters {
  uint64_t probes;
  uint64_t maps;
  uint64_t programs;
  uint64_t attached;
  uint64_t events;
  uint64_t invalid;
  uint64_t dropped;
  uint64_t lsm_loaded;
  uint64_t lsm_denies;
  uint64_t lsm_attach_failures;
} ap_ksensor_counters_t;

typedef struct ap_ksensor_status {
  uint32_t bpf_available;
  uint32_t perf_available;
  uint32_t lsm_available;
  uint32_t sensor_active;
  uint32_t lsm_active;
  uint32_t attached;
  uint32_t cpus;
  char reason[AP_KSENSOR_REASON_LEN];
} ap_ksensor_status_t;

#ifdef __cplusplus
extern "C" {
#endif

int ap_ksensor_probe(uint32_t *bpf_ok, uint32_t *perf_ok, uint32_t *lsm_ok);
int ap_ksensor_open(uint32_t flags, uint32_t lsm_mask, ap_ksensor **out,
                    char *reason, size_t reason_len);
int ap_ksensor_poll(ap_ksensor *handle, uint32_t max_events,
                    ap_event_cb callback, void *user);
int ap_ksensor_lsm_set_mask(ap_ksensor *handle, uint32_t mask);
void ap_ksensor_counters(const ap_ksensor *handle, ap_ksensor_counters_t *out);
void ap_ksensor_status(const ap_ksensor *handle, ap_ksensor_status_t *out);
void ap_ksensor_close(ap_ksensor *handle);
int ap_ksensor_sample_to_event(const ap_ksample *sample, ap_event *event);
const char *ap_ksensor_label_name(uint32_t label_id);

#ifdef __cplusplus
}
#endif

#endif
