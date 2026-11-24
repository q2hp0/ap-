#define _POSIX_C_SOURCE 200809L
#include "apabi.h"
#include "apcap.h"
#include "apsys.h"
#include "aptelemetry.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "cap test fail: %s\n", name);
    ++failures;
  }
}

int main(void) {
  static const uint32_t cap_ids[AP_CAP_COUNT] = {
    AP_CAP_SECCOMP, AP_CAP_PTRACE, AP_CAP_PROC, AP_CAP_PERF, AP_CAP_TRACEPOINT,
    AP_CAP_BPF, AP_CAP_NETWORK
  };
  static const char *cap_names[AP_CAP_COUNT] = {
    "seccomp", "ptrace", "proc_maps", "perf", "tracepoints", "bpf", "packet_capture"
  };
  static const uint32_t source_ids[AP_SOURCE_COUNT] = {
    AP_SOURCE_TRACE, AP_SOURCE_IPC, AP_SOURCE_PROC, AP_SOURCE_PERF,
    AP_SOURCE_TRACEPOINT, AP_SOURCE_BPF, AP_SOURCE_CAPTURE, AP_SOURCE_KERNEL,
    AP_SOURCE_KSENSOR, AP_SOURCE_LSM
  };
  static const char *source_names[AP_SOURCE_COUNT] = {
    "trace", "ipc", "proc", "perf", "tracepoints", "bpf", "capture", "kernel",
    "ksensor", "lsm"
  };
  static const uint32_t source_caps[AP_SOURCE_COUNT] = {
    AP_CAP_PTRACE, 0u, AP_CAP_PROC, AP_CAP_PERF, AP_CAP_TRACEPOINT, AP_CAP_BPF,
    AP_CAP_NETWORK, 0u, AP_CAP_BPF, AP_CAP_BPF
  };
  ap_cap_desc cap;
  ap_source_desc desc;
  uint32_t mask;
  uint32_t i;
  ap_source_desc none;

  mask = ap_cap_probe();
  check(ap_cap_count() == AP_CAP_COUNT, "cap count");
  check((int)mask == ap_sys_capability_state(), "compat mask");
  for (i = 0u; i < AP_CAP_COUNT; ++i) {
    check(ap_cap_report(i, &cap) == AP_OK, "cap report");
    check(cap.id == cap_ids[i], "cap id");
    check(strcmp(cap.name, cap_names[i]) == 0, "cap name");
    check(strcmp(ap_cap_name(cap.id), cap_names[i]) == 0, "cap name helper");
    check(cap.available == 0 || cap.available == 1, "cap state");
    check(cap.available == ap_cap_status(cap.id), "cap status");
    check(((mask & cap.id) != 0u) == (cap.available == 1), "cap mask");
  }
  check(ap_cap_report(AP_CAP_COUNT, &cap) == AP_ERR_ARG, "cap index bound");
  check(strcmp(ap_cap_name(999u), "unknown") == 0, "unknown cap name");

  for (i = 0u; i < AP_SOURCE_COUNT; ++i) {
    check(ap_source_describe(i, &desc) == AP_OK, "source describe");
    check(desc.id == source_ids[i], "source id");
    check(desc.cap == source_caps[i], "source cap");
    check(desc.name != NULL && strcmp(desc.name, source_names[i]) == 0,
          "source name");
  }
  check(ap_source_describe(AP_SOURCE_COUNT, &desc) == AP_ERR_ARG, "source index bound");
  check(ap_source_describe(0u, NULL) == AP_ERR_ARG, "source argument");
  memset(&none, 0xaa, sizeof(none));
  check(ap_source_describe(1u, &none) == AP_OK && none.id == AP_SOURCE_IPC, "source ipc");

  printf("cap tests: %s mask=%u\n", failures == 0 ? "ok" : "failed", mask);
  return failures == 0 ? 0 : 1;
}
