#ifndef AP_TELEMETRY_H
#define AP_TELEMETRY_H

#include "apabi.h"
#include "apcap.h"

#define AP_SOURCE_TRACE 1u
#define AP_SOURCE_IPC 2u
#define AP_SOURCE_PROC 3u
#define AP_SOURCE_PERF 4u
#define AP_SOURCE_TRACEPOINT 5u
#define AP_SOURCE_BPF 6u
#define AP_SOURCE_CAPTURE 7u
#define AP_SOURCE_KERNEL 8u
#define AP_SOURCE_KSENSOR 9u
#define AP_SOURCE_LSM 10u
#define AP_SOURCE_COUNT 10u

typedef struct ap_source_desc {
  uint32_t id;
  const char *name;
  uint32_t cap;
} ap_source_desc;

#ifdef __cplusplus
extern "C" {
#endif

int ap_source_describe(uint32_t index, ap_source_desc *out);

#ifdef __cplusplus
}
#endif

#endif
