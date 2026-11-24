#ifndef APRISK_H
#define APRISK_H

#include "apabi.h"

#include <stddef.h>
#include <stdint.h>

#define AP_RISK_ENTITIES 64u
#define AP_RISK_SIGNALS 8u
#define AP_RISK_KEY_LEN 48u
#define AP_RISK_WINDOW_NS 90000000000ULL
#define AP_RISK_SUPPRESS_NS 30000000000ULL
#define AP_RISK_THRESHOLD 1500u

typedef struct ap_risk_signal {
  uint64_t ts_ns;
  uint32_t rule;
  uint32_t tactic;
  uint32_t confidence_x1000;
  char key[AP_RISK_KEY_LEN];
} ap_risk_signal;

typedef struct ap_risk_finding {
  uint64_t ts_ns;
  uint32_t score_x1000;
  uint32_t signals;
  uint32_t tactics;
  uint32_t high_rules;
  char key[AP_RISK_KEY_LEN];
} ap_risk_finding;

typedef int (*ap_risk_cb)(const ap_risk_finding *finding, void *user);

typedef struct ap_risk ap_risk;

#ifdef __cplusplus
extern "C" {
#endif

ap_risk *ap_risk_new(void);
void ap_risk_free(ap_risk *risk);
int ap_risk_add(ap_risk *risk, const ap_risk_signal *signal);
int ap_risk_evaluate(ap_risk *risk, uint64_t now_ns, ap_risk_cb callback,
                     void *user);
void ap_risk_reset(ap_risk *risk);

#ifdef __cplusplus
}
#endif

#endif
