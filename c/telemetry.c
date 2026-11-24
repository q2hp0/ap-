#include "aptelemetry.h"

static const ap_source_desc ap_sources[AP_SOURCE_COUNT] = {
  { AP_SOURCE_TRACE, "trace", AP_CAP_PTRACE },
  { AP_SOURCE_IPC, "ipc", 0u },
  { AP_SOURCE_PROC, "proc", AP_CAP_PROC },
  { AP_SOURCE_PERF, "perf", AP_CAP_PERF },
  { AP_SOURCE_TRACEPOINT, "tracepoints", AP_CAP_TRACEPOINT },
  { AP_SOURCE_BPF, "bpf", AP_CAP_BPF },
  { AP_SOURCE_CAPTURE, "capture", AP_CAP_NETWORK },
  { AP_SOURCE_KERNEL, "kernel", 0u },
  { AP_SOURCE_KSENSOR, "ksensor", AP_CAP_BPF },
  { AP_SOURCE_LSM, "lsm", AP_CAP_BPF }
};

int ap_source_describe(uint32_t index, ap_source_desc *out) {
  if (index >= AP_SOURCE_COUNT || out == NULL) return AP_ERR_ARG;
  *out = ap_sources[index];
  return AP_OK;
}
