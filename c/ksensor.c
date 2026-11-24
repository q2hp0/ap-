#define _GNU_SOURCE
#include "apksensor.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

/*
 * Stable eBPF helper IDs and map/pseudo-fd constants.  Newer linux/bpf.h
 * headers expose the helpers through __BPF_FUNC_MAPPER; very old headers do
 * not expose the IDs at all, so provide the ABI values when needed.
 */
#if !defined(__BPF_FUNC_MAPPER) && !defined(BPF_FUNC_map_lookup_elem)
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_ktime_get_ns 5
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_perf_event_output 25
#endif
#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif
#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

/* BPF_PROG_TYPE_LSM / BPF_LSM_MAC arrived in headers for kernel 5.7. */
#if defined(KERNEL_VERSION) && defined(LINUX_VERSION_CODE)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef BPF_PROG_TYPE_LSM
#define BPF_PROG_TYPE_LSM 29
#endif
#ifndef BPF_LSM_MAC
#define BPF_LSM_MAC 28
#endif
#endif
#endif

#define AP_KSENSOR_MAX_ATTACH 16u
#define AP_KSENSOR_DENY_KEYS 32u
#define AP_KSENSOR_MAX_INSNS 32u
#define AP_KSENSOR_LSM_FILE_MAX 4096u

#define AP_INSN_MOV64_REG ((uint8_t)(BPF_ALU64 | BPF_MOV | BPF_X))
#define AP_INSN_MOV64_IMM ((uint8_t)(BPF_ALU64 | BPF_MOV | BPF_K))
#define AP_INSN_ADD64_IMM ((uint8_t)(BPF_ALU64 | BPF_ADD | BPF_K))
#define AP_INSN_ST_W ((uint8_t)(BPF_ST | BPF_MEM | BPF_W))
#define AP_INSN_STX_DW ((uint8_t)(BPF_STX | BPF_MEM | BPF_DW))
#define AP_INSN_LDX_W ((uint8_t)(BPF_LDX | BPF_MEM | BPF_W))
#define AP_INSN_LDDW ((uint8_t)(BPF_LD | BPF_DW | BPF_IMM))
#define AP_INSN_CALL ((uint8_t)(BPF_JMP | BPF_CALL))
#define AP_INSN_JEQ_K ((uint8_t)(BPF_JMP | BPF_JEQ | BPF_K))
#define AP_INSN_EXIT ((uint8_t)(BPF_JMP | BPF_EXIT))

/* 8 + 8 + 4 + 4 + 3 * 8 = 48 bytes in the supplied header contract. */
_Static_assert(sizeof(ap_ksample) == 48u, "ksensor sample abi must be 48 bytes");
_Static_assert(AP_KSENSOR_MAX_ATTACH >= 10u, "tracepoint table exceeds fd array");

typedef struct ap_ksensor_tp {
  const char *name;
  uint32_t label;
} ap_ksensor_tp;

static const ap_ksensor_tp ap_ksensor_tracepoints[] = {
  { "sched_process_exec", AP_KLABEL_EXEC },
  { "sched_process_exit", AP_KLABEL_EXIT },
  { "bpf_prog_load", AP_KLABEL_BPF_PROG },
  { "do_init_module", AP_KLABEL_MODULE },
  { "commit_creds", AP_KLABEL_CRED },
  { "ptrace_access_check", AP_KLABEL_PTRACE },
  { "security_file_open", AP_KLABEL_ROOTKIT },
  { "tty_write", AP_KLABEL_PERSISTENCE },
  { "vfs_write", AP_KLABEL_ANTI_ANALYSIS }
};

static const char *const ap_ksensor_names[] = {
  "none",
  "exec",
  "exit",
  "module_load",
  "bpf_prog_load",
  "ptrace",
  "cred_change",
  "network",
  "kernel_rootkit",
  "credential_theft",
  "persistence",
  "container_escape",
  "fileless_exec",
  "anti_analysis"
};

struct ap_ksensor {
  int perf_map_fd;
  int deny_map_fd;
  int prog_fds[AP_KSENSOR_MAX_ATTACH];
  int link_fds[AP_KSENSOR_MAX_ATTACH];
  uint32_t prog_count;
  uint32_t link_count;
  int perf_fds[AP_KSENSOR_MAX_CPUS];
  void *rings[AP_KSENSOR_MAX_CPUS];
  struct perf_event_mmap_page *headers[AP_KSENSOR_MAX_CPUS];
  size_t ring_sizes[AP_KSENSOR_MAX_CPUS];
  size_t page_size;
  uint32_t cpu_count;
  uint32_t flags;
  uint32_t lsm_mask;
  uint32_t bpf_available;
  uint32_t perf_available;
  uint32_t lsm_available;
  uint32_t sensor_active;
  uint32_t lsm_active;
  int lsm_prog_fd;
  int lsm_link_fd;
  uint64_t attach_failures;
  ap_ksensor_counters_t stats;
  char reason[AP_KSENSOR_REASON_LEN];
};

/* ------------------------------------------------------------------ */
/* Raw syscall wrappers: no libc wrappers and no external libraries.   */
/* ------------------------------------------------------------------ */

static long raw_bpf(int cmd, union bpf_attr *attr, size_t size) {
#ifdef SYS_bpf
  return syscall(SYS_bpf, cmd, attr, size);
#else
  (void)cmd;
  (void)attr;
  (void)size;
  errno = ENOSYS;
  return -1;
#endif
}

static long raw_perf_event_open(struct perf_event_attr *attr, pid_t pid,
                                int cpu, int group_fd, unsigned long flags) {
#ifdef SYS_perf_event_open
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
#else
  (void)attr;
  (void)pid;
  (void)cpu;
  (void)group_fd;
  (void)flags;
  errno = ENOSYS;
  return -1;
#endif
}

static int raw_ioctl(int fd, unsigned long request, void *arg) {
#ifdef SYS_ioctl
  return (int)syscall(SYS_ioctl, fd, request, arg);
#else
  return ioctl(fd, request, arg);
#endif
}

static void *raw_mmap(void *addr, size_t length, int prot, int flags,
                      int fd, off_t offset) {
#ifdef SYS_mmap
  return (void *)syscall(SYS_mmap, addr, length, prot, flags, fd,
                         (long)offset);
#else
  return mmap(addr, length, prot, flags, fd, offset);
#endif
}

static int raw_munmap(void *addr, size_t length) {
#ifdef SYS_munmap
  return (int)syscall(SYS_munmap, addr, length);
#else
  return munmap(addr, length);
#endif
}

static int raw_sched_getaffinity(cpu_set_t *mask) {
#ifdef SYS_sched_getaffinity
  return (int)syscall(SYS_sched_getaffinity, (pid_t)0, sizeof(*mask), mask);
#else
  return sched_getaffinity((pid_t)0, sizeof(*mask), mask);
#endif
}

static int raw_get_nprocs(void) {
  int found = (int)get_nprocs();
  if (found < 1) {
    long fallback = sysconf(_SC_NPROCESSORS_ONLN);
    found = fallback > 0 ? (int)fallback : 1;
  }
  return found;
}

static uint64_t ap_ptr_u64(const void *ptr) {
  return (uint64_t)(uintptr_t)ptr;
}

/* ------------------------------------------------------------------ */
/* Reason strings are lowercase and always NUL-terminated.             */
/* ------------------------------------------------------------------ */

static void copy_reason(char *dst, size_t len, const char *src) {
  size_t i = 0u;

  if (dst == NULL || len == 0u) return;
  if (src == NULL) src = "";
  while (i + 1u < len && src[i] != '\0') {
    dst[i] = (char)tolower((unsigned char)src[i]);
    ++i;
  }
  dst[i] = '\0';
}

static void append_reason(char *dst, size_t len, const char *suffix) {
  size_t used = 0u;
  size_t i = 0u;

  if (dst == NULL || len == 0u || suffix == NULL) return;
  if (strstr(dst, suffix) != NULL) return;
  while (used + 1u < len && dst[used] != '\0') ++used;
  if (used > 0u && used + 2u < len) {
    dst[used++] = ';';
    dst[used++] = ' ';
  }
  while (used + 1u < len && suffix[i] != '\0') {
    dst[used++] = (char)tolower((unsigned char)suffix[i]);
    ++i;
  }
  dst[used] = '\0';
}

static int fail_open(ap_ksensor *handle, char *reason, size_t reason_len,
                     const char *message, int status) {
  if (handle != NULL) copy_reason(handle->reason, sizeof(handle->reason), message);
  copy_reason(reason, reason_len, message);
  return status;
}

/* ------------------------------------------------------------------ */
/* Capability probes.                                                  */
/* ------------------------------------------------------------------ */

static int lsm_delimiter(char c) {
  return isspace((unsigned char)c) != 0 || c == ',' || c == '\0';
}

static uint32_t lsm_token_available(uint32_t bpf_available) {
  char buf[AP_KSENSOR_LSM_FILE_MAX];
  ssize_t total = 0;
  size_t i;
  int fd;

  if (bpf_available == 0u) return 0u;
  fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0u;
  for (;;) {
    ssize_t got;
    if ((size_t)total + 1u >= sizeof(buf)) break;
    got = read(fd, buf + total, sizeof(buf) - 1u - (size_t)total);
    if (got > 0) {
      total += got;
      continue;
    }
    if (got < 0 && errno == EINTR) continue;
    break;
  }
  close(fd);
  if (total <= 0) return 0u;
  buf[total] = '\0';
  for (i = 0u; i + 3u <= (size_t)total; ++i) {
    int before_ok = i == 0u || lsm_delimiter(buf[i - 1u]);
    int after_ok = i + 3u >= (size_t)total || lsm_delimiter(buf[i + 3u]);
    if (memcmp(buf + i, "bpf", 3u) == 0 && before_ok && after_ok) return 1u;
  }
  return 0u;
}

static void capabilities_probe(uint32_t *bpf_ok, uint32_t *perf_ok,
                               uint32_t *lsm_ok) {
  union bpf_attr attr;
  uint32_t bpf_available = 0u;
  uint32_t perf_available = 0u;

  memset(&attr, 0, sizeof(attr));
  errno = 0;
  if (raw_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) >= 0 ||
      errno == ENOENT) {
    bpf_available = 1u;
  }

  errno = 0;
  {
    struct perf_event_attr pattr;
    memset(&pattr, 0, sizeof(pattr));
    pattr.type = PERF_TYPE_SOFTWARE;
    pattr.config = PERF_COUNT_SW_BPF_OUTPUT;
    pattr.size = (uint32_t)sizeof(pattr);
    pattr.disabled = 1;
    {
      int fd = (int)raw_perf_event_open(&pattr, (pid_t)0, -1, -1, 0ul);
      if (fd >= 0) {
        perf_available = 1u;
        close(fd);
      }
    }
  }

  if (bpf_ok != NULL) *bpf_ok = bpf_available;
  if (perf_ok != NULL) *perf_ok = perf_available;
  if (lsm_ok != NULL) *lsm_ok = lsm_token_available(bpf_available);
}

int ap_ksensor_probe(uint32_t *bpf_ok, uint32_t *perf_ok, uint32_t *lsm_ok) {
  capabilities_probe(bpf_ok, perf_ok, lsm_ok);
  return AP_OK;
}

/* ------------------------------------------------------------------ */
/* BPF map and program helpers.                                        */
/* ------------------------------------------------------------------ */

static int map_create(uint32_t type, uint32_t key_size, uint32_t value_size,
                      uint32_t max_entries) {
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_type = (enum bpf_map_type)type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  return (int)raw_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int map_update(int map_fd, const void *key, const void *value) {
  union bpf_attr attr;

  if (map_fd < 0) return -1;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = (uint32_t)map_fd;
  attr.key = ap_ptr_u64(key);
  attr.value = ap_ptr_u64(value);
  attr.flags = 0u;
  return raw_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) == 0 ? 0 : -1;
}

static int prog_load(uint32_t prog_type, uint32_t attach_type,
                     const struct bpf_insn *insns, size_t count) {
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.prog_type = (enum bpf_prog_type)prog_type;
  attr.expected_attach_type = (enum bpf_attach_type)attach_type;
  attr.insn_cnt = (uint32_t)count;
  attr.insns = ap_ptr_u64(insns);
  attr.license = ap_ptr_u64("GPL");
  return (int)raw_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int attach_raw_tracepoint(int prog_fd, const char *name) {
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.raw_tracepoint.name = ap_ptr_u64(name);
  attr.raw_tracepoint.prog_fd = (uint32_t)prog_fd;
  return (int)raw_bpf(BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
}

static int attach_lsm_mac(int prog_fd) {
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.attach_type = (enum bpf_attach_type)BPF_LSM_MAC;
  attr.target_fd = 0u;
  attr.attach_bpf_fd = (uint32_t)prog_fd;
  attr.attach_flags = 0u;
  return (int)raw_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

/* ------------------------------------------------------------------ */
/* Hand-encoded eBPF programs.                                         */
/* ------------------------------------------------------------------ */

static void emit_insn(struct bpf_insn *insns, size_t capacity, size_t *count,
                      uint8_t code, uint8_t dst, uint8_t src, int16_t off,
                      int32_t imm) {
  struct bpf_insn *insn;

  if (*count >= capacity) return;
  insn = &insns[*count];
  insn->code = code;
  insn->dst_reg = dst;
  insn->src_reg = src;
  insn->off = off;
  insn->imm = imm;
  ++*count;
}

static void emit_lddw(struct bpf_insn *insns, size_t capacity, size_t *count,
                      uint8_t dst, uint8_t src, int32_t low) {
  emit_insn(insns, capacity, count, AP_INSN_LDDW, dst, src, 0, low);
  emit_insn(insns, capacity, count, 0u, 0u, 0u, 0, 0);
}

/*
 * Raw-tracepoint emitter: build the header-sized ap_ksample on the eBPF stack,
 * then write it to the PERF_EVENT_ARRAY using bpf_perf_event_output().
 * R6 keeps ctx alive across helper calls; the 48 byte stack area keeps
 * every 64 bit store negative-offset and 8 byte aligned.
 */
static size_t build_emit_program(struct bpf_insn *insns, size_t capacity,
                                 uint32_t label_id, int map_fd) {
  size_t n = 0u;

  emit_insn(insns, capacity, &n, AP_INSN_MOV64_REG, 6u, 1u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_CALL, 0u, 0u, 0,
            (int32_t)BPF_FUNC_get_current_pid_tgid);
  emit_insn(insns, capacity, &n, AP_INSN_STX_DW, 10u, 0u, -40, 0);
  emit_insn(insns, capacity, &n, AP_INSN_CALL, 0u, 0u, 0,
            (int32_t)BPF_FUNC_ktime_get_ns);
  emit_insn(insns, capacity, &n, AP_INSN_STX_DW, 10u, 0u, -48, 0);
  emit_insn(insns, capacity, &n, AP_INSN_ST_W, 10u, 0u, -32,
            (int32_t)label_id);
  emit_insn(insns, capacity, &n, AP_INSN_ST_W, 10u, 0u, -28,
            (int32_t)label_id);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_IMM, 3u, 0u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_STX_DW, 10u, 3u, -24, 0);
  emit_insn(insns, capacity, &n, AP_INSN_STX_DW, 10u, 3u, -16, 0);
  emit_insn(insns, capacity, &n, AP_INSN_STX_DW, 10u, 3u, -8, 0);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_REG, 1u, 6u, 0, 0);
  emit_lddw(insns, capacity, &n, 2u, (uint8_t)BPF_PSEUDO_MAP_FD,
            (int32_t)map_fd);
  emit_lddw(insns, capacity, &n, 3u, 0u, (int32_t)0xffffffffu);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_REG, 4u, 10u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_ADD64_IMM, 4u, 0u, 0, -48);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_IMM, 5u, 0u, 0,
            (int32_t)sizeof(ap_ksample));
  emit_insn(insns, capacity, &n, AP_INSN_CALL, 0u, 0u, 0,
            (int32_t)BPF_FUNC_perf_event_output);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_IMM, 0u, 0u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_EXIT, 0u, 0u, 0, 0);
  return n;
}

/*
 * BPF LSM MAC program: look up the deny-rule bit index in the array map.
 * A nonzero rule returns -EPERM, everything else returns 0.
 */
static size_t build_lsm_program(struct bpf_insn *insns, size_t capacity,
                                uint32_t key_index, int map_fd) {
  size_t n = 0u;

  emit_insn(insns, capacity, &n, AP_INSN_ST_W, 10u, 0u, -4,
            (int32_t)key_index);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_REG, 1u, 10u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_ADD64_IMM, 1u, 0u, 0, -4);
  emit_lddw(insns, capacity, &n, 2u, (uint8_t)BPF_PSEUDO_MAP_FD,
            (int32_t)map_fd);
  emit_insn(insns, capacity, &n, AP_INSN_CALL, 0u, 0u, 0,
            (int32_t)BPF_FUNC_map_lookup_elem);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_REG, 1u, 0u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_JEQ_K, 1u, 0u, 0, 4);
  emit_insn(insns, capacity, &n, AP_INSN_LDX_W, 2u, 1u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_JEQ_K, 2u, 0u, 0, 2);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_IMM, 0u, 0u, 0, -EPERM);
  emit_insn(insns, capacity, &n, AP_INSN_EXIT, 0u, 0u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_MOV64_IMM, 0u, 0u, 0, 0);
  emit_insn(insns, capacity, &n, AP_INSN_EXIT, 0u, 0u, 0, 0);
  return n;
}

/* ------------------------------------------------------------------ */
/* CPU discovery and perf ring setup.                                  */
/* ------------------------------------------------------------------ */

static uint32_t online_cpus(uint32_t *cpus, uint32_t capacity) {
  cpu_set_t set;
  uint32_t found = 0u;
  int i;

  if (cpus == NULL || capacity == 0u) return 0u;
  memset(&set, 0, sizeof(set));
  if (raw_sched_getaffinity(&set) == 0) {
    for (i = 0; i < CPU_SETSIZE && found < capacity; ++i) {
      if (CPU_ISSET(i, &set)) cpus[found++] = (uint32_t)i;
    }
  }
  if (found == 0u) {
    int count = raw_get_nprocs();
    for (i = 0; i < count && found < capacity; ++i) {
      cpus[found++] = (uint32_t)i;
    }
  }
  return found;
}

static int setup_perf_ring(ap_ksensor *handle, const uint32_t *cpus,
                           uint32_t count) {
  size_t page_size;
  size_t ring_bytes;
  uint32_t i;

  if (handle == NULL || cpus == NULL || count == 0u) return -1;
  {
    long detected = sysconf(_SC_PAGESIZE);
    page_size = detected > 0 ? (size_t)detected : 4096u;
  }
  if (page_size == 0u || page_size > (size_t)INT32_MAX) return -1;
  if ((size_t)AP_KSENSOR_RING_PAGES > SIZE_MAX / page_size) return -1;
  ring_bytes = (size_t)AP_KSENSOR_RING_PAGES * page_size;
  handle->page_size = page_size;

  for (i = 0u; i < count; ++i) {
    struct perf_event_attr attr;
    int fd;
    void *mapping;
    uint32_t key = cpus[i];
    uint32_t value;

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_BPF_OUTPUT;
    attr.size = (uint32_t)sizeof(attr);
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1ull;
    attr.wakeup_events = 1u;
    attr.disabled = 1;

    fd = (int)raw_perf_event_open(&attr, (pid_t)0, (int)cpus[i], -1, 0ul);
    if (fd < 0) return -1;
    handle->perf_fds[i] = fd;
    mapping = raw_mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
                       fd, (off_t)0);
    if (mapping == MAP_FAILED || mapping == NULL) return -1;
    handle->rings[i] = mapping;
    handle->headers[i] = (struct perf_event_mmap_page *)mapping;
    handle->ring_sizes[i] = ring_bytes;
    if (raw_ioctl(fd, PERF_EVENT_IOC_ENABLE, NULL) < 0) return -1;
    value = (uint32_t)fd;
    if (map_update(handle->perf_map_fd, &key, &value) < 0) return -1;
    ++handle->cpu_count;
  }
  return 0;
}

/* lsm_denies counts installed deny rules, not runtime lsm rejections. */
static uint64_t install_deny_mask(ap_ksensor *handle, uint32_t mask) {
  uint64_t installed = 0u;
  uint32_t i;

  if (handle == NULL || handle->deny_map_fd < 0) return 0u;
  for (i = 0u; i < AP_KSENSOR_DENY_KEYS; ++i) {
    uint32_t key = i;
    uint32_t value = ((mask >> i) & 1u) != 0u ? 1u : 0u;
    if (map_update(handle->deny_map_fd, &key, &value) == 0 &&
        value != 0u) {
      ++installed;
    }
  }
  return installed;
}

static void release_handle(ap_ksensor *handle) {
  uint32_t i;

  if (handle == NULL) return;
  for (i = 0u; i < AP_KSENSOR_MAX_CPUS; ++i) {
    if (handle->rings[i] != NULL && handle->rings[i] != MAP_FAILED) {
      raw_munmap(handle->rings[i], handle->ring_sizes[i]);
    }
    if (handle->perf_fds[i] > 0) close(handle->perf_fds[i]);
  }
  for (i = 0u; i < handle->prog_count; ++i) {
    if (handle->prog_fds[i] > 0) close(handle->prog_fds[i]);
  }
  for (i = 0u; i < handle->link_count; ++i) {
    if (handle->link_fds[i] > 0) close(handle->link_fds[i]);
  }
  if (handle->lsm_link_fd > 0) close(handle->lsm_link_fd);
  if (handle->lsm_prog_fd > 0) close(handle->lsm_prog_fd);
  if (handle->perf_map_fd > 0) close(handle->perf_map_fd);
  if (handle->deny_map_fd > 0) close(handle->deny_map_fd);
  free(handle);
}

void ap_ksensor_close(ap_ksensor *handle) {
  release_handle(handle);
}

int ap_ksensor_open(uint32_t flags, uint32_t lsm_mask, ap_ksensor **out,
                    char *reason, size_t reason_len) {
  static const uint32_t all_flags = AP_KSENSOR_FLAG_RAW_TRACEPOINTS |
                                    AP_KSENSOR_FLAG_PERF_RING |
                                    AP_KSENSOR_FLAG_LSM;
  const uint32_t tp_count = (uint32_t)(sizeof(ap_ksensor_tracepoints) /
                                       sizeof(ap_ksensor_tracepoints[0]));
  ap_ksensor *handle;
  uint32_t cpus[AP_KSENSOR_MAX_CPUS];
  uint32_t cpu_count;
  uint32_t bpf_available = 0u;
  uint32_t perf_available = 0u;
  uint32_t lsm_available = 0u;
  uint32_t need_events;
  uint32_t i;

  if (out == NULL) return AP_ERR_ARG;
  *out = NULL;
  copy_reason(reason, reason_len, "");
  if ((flags & ~all_flags) != 0u) {
    return fail_open(NULL, reason, reason_len, "unknown flags", AP_ERR_ARG);
  }

  capabilities_probe(&bpf_available, &perf_available, &lsm_available);
  handle = (ap_ksensor *)calloc(1u, sizeof(*handle));
  if (handle == NULL) {
    return fail_open(NULL, reason, reason_len, "out of memory", AP_ERR_NOMEM);
  }
  handle->perf_map_fd = -1;
  handle->deny_map_fd = -1;
  handle->lsm_prog_fd = -1;
  handle->lsm_link_fd = -1;
  for (i = 0u; i < AP_KSENSOR_MAX_ATTACH; ++i) {
    handle->prog_fds[i] = -1;
    handle->link_fds[i] = -1;
  }
  for (i = 0u; i < AP_KSENSOR_MAX_CPUS; ++i) handle->perf_fds[i] = -1;
  handle->flags = flags;
  handle->lsm_mask = lsm_mask;
  handle->bpf_available = bpf_available;
  handle->perf_available = perf_available;
  handle->lsm_available = lsm_available;
  handle->stats.probes = 3u;
  copy_reason(handle->reason, sizeof(handle->reason), "");

  need_events = (flags & (AP_KSENSOR_FLAG_RAW_TRACEPOINTS |
                          AP_KSENSOR_FLAG_PERF_RING)) != 0u;
  if (need_events && bpf_available == 0u) {
    int status = fail_open(handle, reason, reason_len,
                           "bpf syscall unavailable", AP_ERR_UNSUPPORTED);
    release_handle(handle);
    return status;
  }
  if (need_events && perf_available == 0u) {
    int status = fail_open(handle, reason, reason_len, "perf unavailable",
                           AP_ERR_UNSUPPORTED);
    release_handle(handle);
    return status;
  }
  if ((flags & AP_KSENSOR_FLAG_LSM) != 0u && bpf_available == 0u) {
    int status = fail_open(handle, reason, reason_len,
                           "bpf unavailable for lsm", AP_ERR_UNSUPPORTED);
    release_handle(handle);
    return status;
  }
  if (bpf_available == 0u) {
    append_reason(handle->reason, sizeof(handle->reason), "bpf unavailable");
    copy_reason(reason, reason_len, handle->reason);
    *out = handle;
    return AP_OK;
  }

  cpu_count = online_cpus(cpus, AP_KSENSOR_MAX_CPUS);
  if (cpu_count == 0u) cpu_count = 1u;
  handle->perf_map_fd = map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4u, 4u,
                                   cpu_count);
  /* 32 keys cover the full rule mask; at least four keys are always used. */
  handle->deny_map_fd = map_create(BPF_MAP_TYPE_ARRAY, 4u, 4u,
                                   AP_KSENSOR_DENY_KEYS);
  if (handle->perf_map_fd < 0 || handle->deny_map_fd < 0) {
    int status = fail_open(handle, reason, reason_len,
                           "bpf map create failed", AP_ERR_IO);
    release_handle(handle);
    return status;
  }
  handle->stats.maps = 2u;
  handle->stats.lsm_denies = install_deny_mask(handle, lsm_mask);

  if (need_events) {
    if (setup_perf_ring(handle, cpus, cpu_count) != 0) {
      int status = fail_open(handle, reason, reason_len,
                             "perf ring setup failed", AP_ERR_IO);
      release_handle(handle);
      return status;
    }
    for (i = 0u; i < tp_count && handle->prog_count < AP_KSENSOR_MAX_ATTACH;
         ++i) {
      struct bpf_insn insns[AP_KSENSOR_MAX_INSNS];
      size_t insn_count;
      int prog_fd;
      int link_fd;

      insn_count = build_emit_program(insns, sizeof(insns) / sizeof(insns[0]),
                                      ap_ksensor_tracepoints[i].label,
                                      handle->perf_map_fd);
      if (insn_count == 0u) {
        ++handle->attach_failures;
        continue;
      }
      prog_fd = prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, 0u, insns,
                          insn_count);
      if (prog_fd < 0) {
        ++handle->attach_failures;
        continue;
      }
      handle->prog_fds[handle->prog_count++] = prog_fd;
      ++handle->stats.programs;
      link_fd = attach_raw_tracepoint(prog_fd,
                                      ap_ksensor_tracepoints[i].name);
      if (link_fd < 0) {
        ++handle->attach_failures;
        continue;
      }
      if (link_fd > 0) handle->link_fds[handle->link_count++] = link_fd;
      ++handle->stats.attached;
      handle->sensor_active = 1u;
    }
    if (handle->stats.attached == 0u) {
      append_reason(handle->reason, sizeof(handle->reason),
                    "no tracepoints attached");
    } else if (handle->attach_failures > 0u) {
      append_reason(handle->reason, sizeof(handle->reason),
                    "some tracepoints unavailable");
    }
  }

  if ((flags & AP_KSENSOR_FLAG_LSM) != 0u) {
    struct bpf_insn insns[AP_KSENSOR_MAX_INSNS];
    size_t insn_count = build_lsm_program(
        insns, sizeof(insns) / sizeof(insns[0]), 0u, handle->deny_map_fd);
    int lsm_prog_fd = -1;
    int lsm_link_fd = -1;

    if (insn_count != 0u) {
      lsm_prog_fd = prog_load(BPF_PROG_TYPE_LSM,
                              (uint32_t)BPF_LSM_MAC, insns, insn_count);
    }
    if (lsm_prog_fd < 0) {
      ++handle->stats.lsm_attach_failures;
      append_reason(handle->reason, sizeof(handle->reason), "lsm unavailable");
    } else {
      handle->lsm_prog_fd = lsm_prog_fd;
      ++handle->stats.lsm_loaded;
      ++handle->stats.programs;
      lsm_link_fd = attach_lsm_mac(lsm_prog_fd);
      if (lsm_link_fd < 0) {
        ++handle->stats.lsm_attach_failures;
        append_reason(handle->reason, sizeof(handle->reason),
                      "lsm unavailable");
      } else {
        if (lsm_link_fd > 0) handle->lsm_link_fd = lsm_link_fd;
        handle->lsm_active = 1u;
      }
    }
  }

  copy_reason(reason, reason_len, handle->reason);
  *out = handle;
  return AP_OK;
}

/* ------------------------------------------------------------------ */
/* Event conversion and label metadata.                                */
/* ------------------------------------------------------------------ */

const char *ap_ksensor_label_name(uint32_t label_id) {
  size_t count = sizeof(ap_ksensor_names) / sizeof(ap_ksensor_names[0]);
  if ((size_t)label_id >= count) return "unknown";
  return ap_ksensor_names[label_id];
}

static uint32_t severity_for_label(uint32_t label_id) {
  switch (label_id) {
    case AP_KLABEL_ROOTKIT:
    case AP_KLABEL_CREDENTIAL_THEFT:
    case AP_KLABEL_PERSISTENCE:
    case AP_KLABEL_CONTAINER_ESCAPE:
    case AP_KLABEL_FILELESS_EXEC:
    case AP_KLABEL_ANTI_ANALYSIS:
      return AP_SEV_CRITICAL;
    default:
      return AP_SEV_HIGH;
  }
}

static uint32_t confidence_for_label(uint32_t label_id) {
  return severity_for_label(label_id) == AP_SEV_CRITICAL ? 950u : 900u;
}

int ap_ksensor_sample_to_event(const ap_ksample *sample, ap_event *event) {
  if (sample == NULL || event == NULL) return AP_ERR_ARG;
  if (sample->label_id > (uint32_t)AP_KLABEL_ANTI_ANALYSIS) return AP_ERR_RANGE;

  memset(event, 0, sizeof(*event));
  event->size = (uint32_t)sizeof(*event);
  event->abi_version = AP_ABI_VERSION;
  event->kind = AP_KIND_KERNEL;
  event->seq = 0u;
  event->ts_ns = sample->ts_ns;
  event->pid = (int64_t)(sample->pid_tgid >> 32);
  event->tid = (int64_t)(uint32_t)sample->pid_tgid;
  event->subkind = sample->subkind;
  event->severity = severity_for_label(sample->label_id);
  event->confidence_x1000 = confidence_for_label(sample->label_id);
  event->arg[0] = sample->arg[0];
  event->arg[1] = sample->arg[1];
  event->arg[2] = sample->arg[2];
  event->arg[3] = AP_KSENSOR_SOURCE_MARK;
  snprintf(event->text, sizeof(event->text), "%s",
           ap_ksensor_label_name(sample->label_id));
  return AP_OK;
}

int ap_ksensor_lsm_set_mask(ap_ksensor *handle, uint32_t mask) {
  if (handle == NULL) return AP_ERR_ARG;
  if (handle->deny_map_fd < 0) return AP_ERR_STATE;
  handle->lsm_mask = mask;
  handle->stats.lsm_denies = install_deny_mask(handle, mask);
  return AP_OK;
}

void ap_ksensor_counters(const ap_ksensor *handle,
                         ap_ksensor_counters_t *out) {
  if (out == NULL) return;
  if (handle == NULL) {
    memset(out, 0, sizeof(*out));
    return;
  }
  *out = handle->stats;
}

void ap_ksensor_status(const ap_ksensor *handle, ap_ksensor_status_t *out) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  if (handle == NULL) return;
  out->bpf_available = handle->bpf_available;
  out->perf_available = handle->perf_available;
  out->lsm_available = handle->lsm_available;
  out->sensor_active = handle->sensor_active;
  out->lsm_active = handle->lsm_active;
  out->attached = (uint32_t)handle->stats.attached;
  out->cpus = handle->cpu_count;
  copy_reason(out->reason, sizeof(out->reason), handle->reason);
}

/* ------------------------------------------------------------------ */
/* Non-blocking perf ring parsing.                                     */
/* ------------------------------------------------------------------ */

static void ring_copy(uint8_t *dst, const uint8_t *data, uint64_t size,
                      uint64_t pos, size_t len) {
  size_t i;
  for (i = 0u; i < len; ++i) {
    dst[i] = data[(size_t)((pos + (uint64_t)i) % size)];
  }
}

static void poll_ring(ap_ksensor *handle, uint32_t index, uint32_t limit,
                      uint32_t *handled, ap_event_cb callback, void *user) {
  struct perf_event_mmap_page *header = handle->headers[index];
  uint8_t *base = (uint8_t *)handle->rings[index];
  uint64_t data_offset;
  uint64_t data_size;
  uint64_t head;
  uint64_t tail;
  uint8_t *data;

  if (header == NULL || base == NULL || *handled >= limit) return;
  head = header->data_head;
  __atomic_thread_fence(__ATOMIC_ACQUIRE);
  tail = header->data_tail;
  data_offset = header->data_offset;
  data_size = header->data_size;
  if (data_offset == 0u || data_size == 0u) {
    data_offset = (uint64_t)handle->page_size;
    data_size = (uint64_t)handle->ring_sizes[index] - data_offset;
  }
  if (data_size == 0u || data_offset > (uint64_t)handle->ring_sizes[index] ||
      data_size > (uint64_t)handle->ring_sizes[index] - data_offset) {
    ++handle->stats.invalid;
    return;
  }
  data = base + (size_t)data_offset;

  if (head < tail) {
    header->data_tail = head;
    return;
  }
  if (head - tail > data_size) {
    uint64_t lost = (head - tail) - data_size;
    handle->stats.dropped += lost;
    tail = head - data_size;
  }

  while (*handled < limit && tail < head) {
    struct perf_event_header record;
    uint64_t remaining = head - tail;
    uint64_t pos = tail % data_size;

    if (remaining < (uint64_t)sizeof(record)) {
      ++handle->stats.invalid;
      handle->stats.dropped += remaining;
      tail = head;
      break;
    }
    ring_copy((uint8_t *)&record, data, data_size, pos, sizeof(record));
    if ((uint64_t)record.size <
            (uint64_t)sizeof(record) + (uint64_t)sizeof(uint32_t) ||
        (uint64_t)record.size > remaining) {
      ++handle->stats.invalid;
      handle->stats.dropped += remaining;
      tail = head;
      break;
    }
    if (record.type == PERF_RECORD_SAMPLE) {
      uint32_t raw_size = 0u;
      uint64_t raw_offset = pos + (uint64_t)sizeof(record);
      uint64_t payload = (uint64_t)record.size - (uint64_t)sizeof(record) -
                         (uint64_t)sizeof(uint32_t);
      ring_copy((uint8_t *)&raw_size, data, data_size, raw_offset,
                sizeof(raw_size));
      if (raw_size >= sizeof(ap_ksample) && (uint64_t)raw_size <= payload) {
        ap_ksample sample;
        ap_event event;
        ap_verdict verdict;
        ring_copy((uint8_t *)&sample, data, data_size,
                  raw_offset + (uint64_t)sizeof(uint32_t), sizeof(sample));
        if (ap_ksensor_sample_to_event(&sample, &event) == AP_OK) {
          ap_verdict_init(&verdict, 0u);
          verdict.severity = event.severity;
          verdict.confidence_x1000 = event.confidence_x1000;
          ++handle->stats.events;
          ++*handled;
          if (callback != NULL && callback(&event, &verdict, user) != 0) {
            ++handle->stats.dropped;
          }
        } else {
          ++handle->stats.invalid;
        }
      } else {
        ++handle->stats.invalid;
      }
    }
    tail += (uint64_t)record.size;
  }
  __atomic_thread_fence(__ATOMIC_RELEASE);
  header->data_tail = tail;
}

int ap_ksensor_poll(ap_ksensor *handle, uint32_t max_events,
                    ap_event_cb callback, void *user) {
  uint32_t limit;
  uint32_t handled = 0u;
  uint32_t i;

  if (handle == NULL) return AP_ERR_ARG;
  if (max_events == 0u) return AP_OK;
  limit = max_events > AP_KSENSOR_MAX_EVENTS ? AP_KSENSOR_MAX_EVENTS
                                             : max_events;
  for (i = 0u; i < handle->cpu_count && handled < limit; ++i) {
    poll_ring(handle, i, limit, &handled, callback, user);
  }
  return AP_OK;
}
