#define _GNU_SOURCE
#include "apcap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/perf_event.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct ap_cap_entry {
  uint32_t id;
  const char *name;
} ap_cap_entry;

static const ap_cap_entry ap_cap_entries[AP_CAP_COUNT] = {
  { AP_CAP_SECCOMP, "seccomp" },
  { AP_CAP_PTRACE, "ptrace" },
  { AP_CAP_PROC, "proc_maps" },
  { AP_CAP_PERF, "perf" },
  { AP_CAP_TRACEPOINT, "tracepoints" },
  { AP_CAP_BPF, "bpf" },
  { AP_CAP_NETWORK, "packet_capture" }
};

static int ap_cap_seccomp(void) {
  return prctl(PR_GET_SECCOMP) >= 0 ? 1 : 0;
}

static int ap_cap_ptrace(void) {
  pid_t child;
  int status = 0;

  child = fork();
  if (child == 0) {
    _exit(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 ? 0 : 1);
  }
  if (child < 0) return 0;
  if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return 0;
  }
  return 1;
}

static int ap_cap_proc(void) {
  return access("/proc/self/maps", R_OK) == 0 ? 1 : 0;
}

static int ap_cap_perf(void) {
#ifdef SYS_perf_event_open
  struct perf_event_attr attr;
  int fd;

  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
#ifdef PERF_COUNT_SW_DUMMY
  attr.config = PERF_COUNT_SW_DUMMY;
#else
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
#endif
  attr.size = sizeof(attr);
  attr.disabled = 1;
  fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0u);
  if (fd >= 0) {
    close(fd);
    return 1;
  }
#endif
  return 0;
}

static int ap_cap_tracepoint(void) {
  if (access("/sys/kernel/tracing/available_events", R_OK) == 0) return 1;
  if (access("/sys/kernel/debug/tracing/available_events", R_OK) == 0) return 1;
  return 0;
}

static int ap_cap_bpf(void) {
#if defined(SYS_bpf) && defined(BPF_MAP_GET_NEXT_ID)
  union bpf_attr attr;
  int status;

  memset(&attr, 0, sizeof(attr));
  status = (int)syscall(SYS_bpf, BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr));
  if (status >= 0 || errno == ENOENT) return 1;
  if (errno == ENOSYS || errno == EINVAL) return 0;
#endif
  return 0;
}

static int ap_cap_packet(void) {
  int fd = socket(AF_PACKET, SOCK_RAW, htons((uint16_t)ETH_P_ALL));
  if (fd < 0) return 0;
  close(fd);
  return 1;
}

uint32_t ap_cap_probe(void) {
  static uint32_t mask = 0u;
  static int ready = 0;
  uint32_t found = 0u;

  if (ready) return mask;
  if (ap_cap_seccomp()) found |= AP_CAP_SECCOMP;
  if (ap_cap_ptrace()) found |= AP_CAP_PTRACE;
  if (ap_cap_proc()) found |= AP_CAP_PROC;
  if (ap_cap_perf()) found |= AP_CAP_PERF;
  if (ap_cap_tracepoint()) found |= AP_CAP_TRACEPOINT;
  if (ap_cap_bpf()) found |= AP_CAP_BPF;
  if (ap_cap_packet()) found |= AP_CAP_NETWORK;
  mask = found;
  ready = 1;
  return mask;
}

int ap_cap_status(uint32_t id) {
  return (ap_cap_probe() & id) != 0u ? 1 : 0;
}

uint32_t ap_cap_count(void) {
  return AP_CAP_COUNT;
}

const char *ap_cap_name(uint32_t id) {
  uint32_t i;
  for (i = 0u; i < AP_CAP_COUNT; ++i) {
    if (ap_cap_entries[i].id == id) return ap_cap_entries[i].name;
  }
  return "unknown";
}

int ap_cap_report(uint32_t index, ap_cap_desc *out) {
  if (index >= AP_CAP_COUNT || out == NULL) return AP_ERR_ARG;
  out->id = ap_cap_entries[index].id;
  out->name = ap_cap_entries[index].name;
  out->available = ap_cap_status(ap_cap_entries[index].id);
  return AP_OK;
}
