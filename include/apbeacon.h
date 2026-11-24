#ifndef APBEACON_H
#define APBEACON_H

#include "apabi.h"

#include <stddef.h>
#include <stdint.h>

#define AP_BEACON_PEERS 64u
#define AP_BEACON_SAMPLES 8u
#define AP_BEACON_KEY_LEN 48u
#define AP_BEACON_WINDOW_NS 90000000000ULL
#define AP_BEACON_MIN_SAMPLES 3u

typedef struct ap_beacon_observation {
  uint64_t ts_ns;
  char peer[AP_BEACON_KEY_LEN];
  uint32_t bytes_out;
  uint32_t flags;
} ap_beacon_observation;

typedef struct ap_beacon_finding {
  uint64_t ts_ns;
  uint64_t span_ns;
  uint64_t jitter_ns;
  uint32_t connections;
  uint32_t bytes_out;
  uint32_t score_x1000;
  char peer[AP_BEACON_KEY_LEN];
} ap_beacon_finding;

typedef int (*ap_beacon_cb)(const ap_beacon_finding *finding, void *user);

typedef struct ap_beacon ap_beacon;

#ifdef __cplusplus
extern "C" {
#endif

ap_beacon *ap_beacon_new(void);
void ap_beacon_free(ap_beacon *beacon);
int ap_beacon_add(ap_beacon *beacon, const ap_beacon_observation *observation);
int ap_beacon_evaluate(ap_beacon *beacon, uint64_t now_ns, ap_beacon_cb callback,
                       void *user);
void ap_beacon_reset(ap_beacon *beacon);

#ifdef __cplusplus
}
#endif

#endif
