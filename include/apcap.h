#ifndef APCAP_H
#define APCAP_H

#include "apabi.h"

#define AP_CAP_SECCOMP 1u
#define AP_CAP_PTRACE 2u
#define AP_CAP_PROC 4u
#define AP_CAP_PERF 8u
#define AP_CAP_TRACEPOINT 16u
#define AP_CAP_BPF 32u
#define AP_CAP_NETWORK 64u
#define AP_CAP_COUNT 7u

typedef struct ap_cap_desc {
  uint32_t id;
  const char *name;
  int available;
} ap_cap_desc;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t ap_cap_probe(void);
int ap_cap_status(uint32_t id);
uint32_t ap_cap_count(void);
const char *ap_cap_name(uint32_t id);
int ap_cap_report(uint32_t index, ap_cap_desc *out);

#ifdef __cplusplus
}
#endif

#endif
