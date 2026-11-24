#define _GNU_SOURCE
#include "aptrace.h"
#include "apsys.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define AP_TRACE_MAX_PIDS 32u
#define AP_TRACE_MAX_REGIONS 96u
#define AP_TRACE_MAX_TEXT 80u
#define AP_TRACE_MAX_FLOW 12u

#if defined(__x86_64__)
#define AP_TRACE_ARCH AUDIT_ARCH_X86_64
#define AP_REG_NR(r) ((long)(r).orig_rax)
#define AP_REG_A0(r) ((unsigned long)(r).rdi)
#define AP_REG_A1(r) ((unsigned long)(r).rsi)
#define AP_REG_A2(r) ((unsigned long)(r).rdx)
#define AP_REG_A3(r) ((unsigned long)(r).r10)
#define AP_REG_A4(r) ((unsigned long)(r).r8)
#define AP_REG_A5(r) ((unsigned long)(r).r9)
#define AP_REG_SP(r) ((unsigned long)(r).rsp)
#define AP_RET_ADDR(r) ((unsigned long)(r).rsp)
#elif defined(__aarch64__)
#define AP_TRACE_ARCH AUDIT_ARCH_AARCH64
#define AP_REG_NR(r) ((long)(r).x[8])
#define AP_REG_A0(r) ((unsigned long)(r).x[0])
#define AP_REG_A1(r) ((unsigned long)(r).x[1])
#define AP_REG_A2(r) ((unsigned long)(r).x[2])
#define AP_REG_A3(r) ((unsigned long)(r).x[3])
#define AP_REG_A4(r) ((unsigned long)(r).x[4])
#define AP_REG_A5(r) ((unsigned long)(r).x[5])
#define AP_REG_SP(r) ((unsigned long)(r).sp)
#define AP_RET_ADDR(r) ((unsigned long)(r).x[30])
#else
#define AP_TRACE_ARCH 0
#define AP_REG_NR(r) (0L)
#define AP_REG_A0(r) (0ul)
#define AP_REG_A1(r) (0ul)
#define AP_REG_A2(r) (0ul)
#define AP_REG_A3(r) (0ul)
#define AP_REG_A4(r) (0ul)
#define AP_REG_A5(r) (0ul)
#define AP_REG_SP(r) (0ul)
#define AP_RET_ADDR(r) (0ul)
#endif

typedef struct ap_region {
  uint64_t start;
  uint64_t end;
  uint32_t bits;
  uint64_t hash;
  char path[AP_TEXT_LEN];
} ap_region;

typedef struct ap_pid_state {
  pid_t pid;
  uint32_t uid;
  uint32_t euid;
  int have_uid;
  int refresh_pending;
  int in_use;
  uint32_t region_count;
  uint64_t old_hash[AP_TRACE_MAX_REGIONS];
  uint64_t region_hash[AP_TRACE_MAX_REGIONS];
  ap_region regions[AP_TRACE_MAX_REGIONS];
  uint64_t last_return;
  uint32_t flow_reports;
} ap_pid_state;

typedef struct ap_trace_state {
  ap_event_cb callback;
  void *user;
  uint64_t seq;
  uint32_t emitted;
  uint32_t dropped;
  uint32_t max_events;
  uint32_t mask;
  pid_t root;
  ap_pid_state *pids;
} ap_trace_state;

typedef struct ap_refresh_ctx {
  ap_trace_state *state;
  ap_pid_state *pid_state;
  ap_region *out;
  uint32_t count;
} ap_refresh_ctx;

static struct sock_filter ap_trace_bpf_stmt(unsigned short code, uint32_t k) {
  struct sock_filter f;
  f.code = code;
  f.jt = 0;
  f.jf = 0;
  f.k = k;
  return f;
}

static struct sock_filter ap_trace_bpf_jump(unsigned short code, uint32_t k,
                                             unsigned char jt, unsigned char jf) {
  struct sock_filter f;
  f.code = code;
  f.jt = jt;
  f.jf = jf;
  f.k = k;
  return f;
}

static const int *ap_trace_watched(size_t *count) {
  static const int numbers[] = {
#ifdef SYS_mprotect
    SYS_mprotect,
#endif
#ifdef SYS_mmap
    SYS_mmap,
#endif
#ifdef SYS_munmap
    SYS_munmap,
#endif
#ifdef SYS_brk
    SYS_brk,
#endif
#ifdef SYS_setuid
    SYS_setuid,
#endif
#ifdef SYS_setgid
    SYS_setgid,
#endif
#ifdef SYS_setreuid
    SYS_setreuid,
#endif
#ifdef SYS_setresuid
    SYS_setresuid,
#endif
#ifdef SYS_setresgid
    SYS_setresgid,
#endif
#ifdef SYS_init_module
    SYS_init_module,
#endif
#ifdef SYS_finit_module
    SYS_finit_module,
#endif
#ifdef SYS_delete_module
    SYS_delete_module,
#endif
#ifdef SYS_bpf
    SYS_bpf,
#endif
#ifdef SYS_ptrace
    SYS_ptrace,
#endif
#ifdef SYS_kexec_load
    SYS_kexec_load,
#endif
#ifdef SYS_kexec_file_load
    SYS_kexec_file_load,
#endif
#ifdef SYS_open_by_handle_at
    SYS_open_by_handle_at,
#endif
#ifdef SYS_process_vm_writev
    SYS_process_vm_writev,
#endif
#ifdef SYS_process_vm_readv
    SYS_process_vm_readv,
#endif
#ifdef SYS_userfaultfd
    SYS_userfaultfd,
#endif
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup,
#endif
#ifdef SYS_rename
    SYS_rename,
#endif
#ifdef SYS_renameat
    SYS_renameat,
#endif
#ifdef SYS_renameat2
    SYS_renameat2,
#endif
#ifdef SYS_unlink
    SYS_unlink,
#endif
#ifdef SYS_unlinkat
    SYS_unlinkat,
#endif
#ifdef SYS_chmod
    SYS_chmod,
#endif
#ifdef SYS_fchmodat
    SYS_fchmodat,
#endif
#ifdef SYS_mount
    SYS_mount,
#endif
#ifdef SYS_umount2
    SYS_umount2,
#endif
#ifdef SYS_setns
    SYS_setns,
#endif
#ifdef SYS_socket
    SYS_socket,
#endif
#ifdef SYS_connect
    SYS_connect,
#endif
#ifdef SYS_sendto
    SYS_sendto,
#endif
#ifdef SYS_sendmsg
    SYS_sendmsg,
#endif
  };
  *count = sizeof(numbers) / sizeof(numbers[0]);
  return numbers;
}

static const char *ap_trace_kernel_label(long nr) {
#ifdef SYS_init_module
  if (nr == SYS_init_module) {
    return "module_load";
  }
#endif
#ifdef SYS_finit_module
  if (nr == SYS_finit_module) {
    return "module_load";
  }
#endif
#ifdef SYS_delete_module
  if (nr == SYS_delete_module) {
    return "module_load";
  }
#endif
#ifdef SYS_kexec_load
  if (nr == SYS_kexec_load) {
    return "kexec";
  }
#endif
#ifdef SYS_kexec_file_load
  if (nr == SYS_kexec_file_load) {
    return "kexec";
  }
#endif
#ifdef SYS_rename
  if (nr == SYS_rename) return "file_rename";
#endif
#ifdef SYS_renameat
  if (nr == SYS_renameat) return "file_rename";
#endif
#ifdef SYS_renameat2
  if (nr == SYS_renameat2) return "file_rename";
#endif
#ifdef SYS_unlink
  if (nr == SYS_unlink) return "file_unlink";
#endif
#ifdef SYS_unlinkat
  if (nr == SYS_unlinkat) return "file_unlink";
#endif
#ifdef SYS_chmod
  if (nr == SYS_chmod) return "file_chmod";
#endif
#ifdef SYS_fchmodat
  if (nr == SYS_fchmodat) return "file_chmod";
#endif
#ifdef SYS_mount
  if (nr == SYS_mount) {
    return "mount";
  }
#endif
#ifdef SYS_umount2
  if (nr == SYS_umount2) {
    return "mount";
  }
#endif
#ifdef SYS_setns
  if (nr == SYS_setns) {
    return "namespace_change";
  }
#endif
#ifdef SYS_bpf
  if (nr == SYS_bpf) {
    return "bpf";
  }
#endif
#ifdef SYS_ptrace
  if (nr == SYS_ptrace) {
    return "ptrace";
  }
#endif
#ifdef SYS_process_vm_writev
  if (nr == SYS_process_vm_writev) {
    return "process_vm_writev";
  }
#endif
#ifdef SYS_process_vm_readv
  if (nr == SYS_process_vm_readv) {
    return "process_vm_readv";
  }
#endif
#ifdef SYS_userfaultfd
  if (nr == SYS_userfaultfd) {
    return "userfaultfd";
  }
#endif
#ifdef SYS_io_uring_setup
  if (nr == SYS_io_uring_setup) {
    return "io_uring_setup";
  }
#endif
#ifdef SYS_open_by_handle_at
  if (nr == SYS_open_by_handle_at) {
    return "open_by_handle_at";
  }
#endif
  return "kernel_interface";
}

static int ap_trace_install_filter(void) {
  struct sock_filter filter[128];
  struct sock_fprog prog;
  const int *numbers;
  size_t count = 0;
  size_t i = 0;
  size_t n;

  if (AP_TRACE_ARCH == 0) {
    return AP_ERR_UNSUPPORTED;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return AP_ERR_UNSUPPORTED;
  }
  numbers = ap_trace_watched(&count);
  filter[i++] = ap_trace_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
  filter[i++] = ap_trace_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AP_TRACE_ARCH, 1, 0);
  filter[i++] = ap_trace_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  filter[i++] = ap_trace_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
  for (n = 0; n < count; ++n) {
    filter[i++] = ap_trace_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)numbers[n], 0, 1);
    filter[i++] = ap_trace_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE);
  }
  filter[i++] = ap_trace_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  prog.len = (unsigned short)i;
  prog.filter = filter;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    return AP_ERR_UNSUPPORTED;
  }
  return AP_OK;
}

static void ap_trace_event(ap_trace_state *state, ap_event *event, uint16_t kind, pid_t pid) {
  ap_event_init(event, kind);
  event->seq = ++state->seq;
  event->pid = pid;
  event->tid = pid;
}

static int ap_trace_emit(ap_trace_state *state, const ap_event *event) {
  ap_verdict verdict;
  int decision;
  if (state->max_events != 0u && state->emitted >= state->max_events) {
    ++state->dropped;
    return AP_DECISION_ALLOW;
  }
  ++state->emitted;
  ap_verdict_init(&verdict, event->seq);
  decision = state->callback(event, &verdict, state->user);
  if (decision == AP_DECISION_DENY && verdict.rule == AP_RULE_NONE) {
    return AP_DECISION_ALLOW;
  }
  return decision;
}

static ap_pid_state *ap_trace_pid(ap_trace_state *state, pid_t pid) {
  uint32_t i;
  ap_pid_state *free_slot = NULL;
  for (i = 0; i < AP_TRACE_MAX_PIDS; ++i) {
    if (state->pids[i].in_use && state->pids[i].pid == pid) {
      return &state->pids[i];
    }
    if (!state->pids[i].in_use && free_slot == NULL) {
      free_slot = &state->pids[i];
    }
  }
  if (free_slot == NULL) {
    return NULL;
  }
  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->in_use = 1;
  free_slot->pid = pid;
  free_slot->refresh_pending = 1;
  return free_slot;
}

static uint64_t ap_trace_hash_region(uint64_t start, uint64_t end, uint32_t bits, const char *path) {
  uint64_t hash = 1469598103934665603ull;
  const unsigned char *p;
  hash = (hash ^ start) * 1099511628211ull;
  hash = (hash ^ end) * 1099511628211ull;
  hash = (hash ^ bits) * 1099511628211ull;
  for (p = (const unsigned char *)path; *p != 0; ++p) {
    hash = (hash ^ *p) * 1099511628211ull;
  }
  return hash;
}

static int ap_trace_region_cb(const ap_event *region, void *user) {
  ap_refresh_ctx *ctx = (ap_refresh_ctx *)user;
  ap_region item;
  uint64_t hash;
  int changed = 1;
  uint32_t i;

  if (ctx->count >= AP_TRACE_MAX_REGIONS) {
    return 0;
  }
  memset(&item, 0, sizeof(item));
  item.start = region->arg[0];
  item.end = region->arg[1];
  item.bits = (uint32_t)region->arg[2];
  snprintf(item.path, sizeof(item.path), "%s", region->text);
  hash = ap_trace_hash_region(item.start, item.end, item.bits, item.path);
  item.hash = hash;
  for (i = 0; i < ctx->pid_state->region_count; ++i) {
    if (ctx->pid_state->old_hash[i] == hash) {
      changed = 0;
      break;
    }
  }
  if (changed && (ctx->state->mask & AP_TRACE_MASK_MEM) != 0u) {
    ap_event event;
    ap_trace_event(ctx->state, &event, AP_KIND_MEMREGION, ctx->pid_state->pid);
    event.subkind = (item.bits & 6u) == 6u ? 2u : 1u;
    event.severity = event.subkind == 2u ? AP_SEV_HIGH : AP_SEV_INFO;
    event.confidence_x1000 = event.subkind == 2u ? 950u : 1000u;
    event.arg[0] = item.start;
    event.arg[1] = item.end;
    event.arg[2] = item.bits;
    snprintf(event.text, sizeof(event.text), "%s", item.path);
    (void)ap_trace_emit(ctx->state, &event);
  }
  ctx->out[ctx->count++] = item;
  return 0;
}

static void ap_trace_refresh(ap_trace_state *state, ap_pid_state *ps) {
  ap_region buffer[AP_TRACE_MAX_REGIONS];
  ap_refresh_ctx ctx;
  uint32_t i;
  if (ps == NULL || !ps->in_use) {
    return;
  }
  ctx.state = state;
  ctx.pid_state = ps;
  ctx.out = buffer;
  ctx.count = 0;
  memcpy(ps->old_hash, ps->region_hash, sizeof(ps->old_hash));
  if (ap_sys_read_maps(ps->pid, ap_trace_region_cb, &ctx) == AP_OK) {
    ps->region_count = ctx.count;
    for (i = 0; i < ctx.count; ++i) {
      ps->regions[i] = buffer[i];
      ps->region_hash[i] = buffer[i].hash;
    }
  }
  ps->refresh_pending = 0;
}

static const ap_region *ap_trace_region_at(ap_pid_state *ps, uint64_t addr) {
  uint32_t i;
  if (ps == NULL) {
    return NULL;
  }
  for (i = 0; i < ps->region_count; ++i) {
    if (addr >= ps->regions[i].start && addr < ps->regions[i].end) {
      return &ps->regions[i];
    }
  }
  return NULL;
}

static int ap_trace_read(pid_t pid, uint64_t addr, void *out, size_t len) {
  char *bytes = (char *)out;
  size_t done = 0;
  while (done < len) {
    long word;
    size_t take;
    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)(addr + (uint64_t)done), NULL);
    if (errno != 0) {
      return AP_ERR_IO;
    }
    take = sizeof(word) < len - done ? sizeof(word) : len - done;
    memcpy(bytes + done, &word, take);
    done += take;
  }
  return AP_OK;
}

static void ap_trace_string(pid_t pid, uint64_t addr, char *out, size_t cap) {
  char buffer[AP_TRACE_MAX_TEXT];
  size_t i;
  memset(buffer, 0, sizeof(buffer));
  if (addr == 0u || ap_trace_read(pid, addr, buffer, sizeof(buffer) - 1u) != AP_OK) {
    out[0] = '\0';
    return;
  }
  buffer[sizeof(buffer) - 1u] = '\0';
  for (i = 0; i < sizeof(buffer); ++i) {
    if (buffer[i] == '\0') break;
    if (buffer[i] < 0x20 || buffer[i] > 0x7e) {
      buffer[i] = '?';
    }
  }
  snprintf(out, cap, "%s", buffer);
}

static void ap_trace_flow(ap_trace_state *state, ap_pid_state *ps, pid_t pid,
                          uint64_t ret, uint64_t sp, long nr) {
  const ap_region *site;
  const ap_region *stack;
  ap_event event;

  if (ret == 0u || ps == NULL || ret == ps->last_return ||
      ps->flow_reports >= AP_TRACE_MAX_FLOW) {
    return;
  }
  ps->last_return = ret;
  ++ps->flow_reports;
  site = ap_trace_region_at(ps, ret);
  if (site != NULL && (site->bits & 4u) != 0u) {
    return;
  }
  ap_trace_event(state, &event, AP_KIND_FLOW, pid);
  event.subkind = AP_FLOW_RETURN_SITE;
  event.arg[0] = ret;
  event.arg[1] = sp;
  event.arg[2] = (uint64_t)nr;
  if (site != NULL && (site->bits & 6u) == 6u) {
    event.severity = AP_SEV_CRITICAL;
    event.confidence_x1000 = 900u;
    snprintf(event.text, sizeof(event.text), "return_site_wx");
  } else {
    event.severity = AP_SEV_LOW;
    event.confidence_x1000 = 250u;
    snprintf(event.text, sizeof(event.text), "return_site_unverified");
  }
  (void)ap_trace_emit(state, &event);

  stack = ap_trace_region_at(ps, sp);
  if (stack != NULL && (stack->bits & 4u) != 0u) {
    ap_trace_event(state, &event, AP_KIND_FLOW, pid);
    event.subkind = AP_FLOW_STACK;
    event.severity = AP_SEV_CRITICAL;
    event.confidence_x1000 = 900u;
    event.arg[0] = sp;
    event.arg[1] = stack->start;
    event.arg[2] = stack->end;
    (void)ap_trace_emit(state, &event);
  }
}

static int ap_trace_syscall(ap_trace_state *state, pid_t pid, long nr,
                            unsigned long *a, struct user_regs_struct *regs) {
  ap_pid_state *ps = ap_trace_pid(state, pid);
  ap_event event;
  int decision = AP_DECISION_ALLOW;
  int emitted = 0;

  if (ps == NULL) {
    return AP_DECISION_ALLOW;
  }
  if (ps->refresh_pending) {
    ap_trace_refresh(state, ps);
  }

  switch (nr) {
#ifdef SYS_mprotect
    case SYS_mprotect:
#endif
#ifdef SYS_mmap
    case SYS_mmap:
#endif
      if ((state->mask & AP_TRACE_MASK_MEM) != 0u) {
        int wx = (a[2] & PROT_WRITE) != 0u && (a[2] & PROT_EXEC) != 0u;
        ap_trace_event(state, &event, AP_KIND_MEMPROT, pid);
        event.subkind = nr == SYS_mprotect ? 1u : 2u;
        event.severity = wx ? AP_SEV_CRITICAL : AP_SEV_INFO;
        event.confidence_x1000 = wx ? 940u : 600u;
        event.arg[0] = (uint64_t)a[0];
        event.arg[1] = (uint64_t)a[1];
        event.arg[2] = (uint64_t)a[2];
        event.arg[3] = (uint64_t)nr;
        snprintf(event.text, sizeof(event.text), "%s", nr == SYS_mprotect ? "mprotect" : "mmap");
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
        ++emitted;
        ps->refresh_pending = 1;
      }
      break;
#ifdef SYS_munmap
    case SYS_munmap:
#endif
#ifdef SYS_brk
    case SYS_brk:
#endif
      ps->refresh_pending = 1;
      break;
#ifdef SYS_execve
    case SYS_execve:
#endif
#ifdef SYS_execveat
    case SYS_execveat:
#endif
      if ((state->mask & AP_TRACE_MASK_MEM) != 0u) {
        ap_trace_event(state, &event, AP_KIND_EXEC, pid);
        event.subkind = 1u;
        event.severity = AP_SEV_INFO;
        event.confidence_x1000 = 1000u;
        event.arg[0] = (uint64_t)nr;
        ap_trace_string(pid, a[0], event.text, sizeof(event.text));
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
        ps->refresh_pending = 1;
      }
      break;
#ifdef SYS_setuid
    case SYS_setuid:
#endif
#ifdef SYS_setgid
    case SYS_setgid:
#endif
#ifdef SYS_setreuid
    case SYS_setreuid:
#endif
#ifdef SYS_setresuid
    case SYS_setresuid:
#endif
#ifdef SYS_setresgid
    case SYS_setresgid:
#endif
      if ((state->mask & AP_TRACE_MASK_PRIV) != 0u) {
        ap_trace_event(state, &event, AP_KIND_PRIV, pid);
        event.subkind = 1u;
        event.severity = AP_SEV_MEDIUM;
        event.confidence_x1000 = 450u;
        event.arg[0] = (uint64_t)a[0];
        event.arg[1] = (uint64_t)nr;
        snprintf(event.text, sizeof(event.text), "setid");
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
      }
      break;
#ifdef SYS_init_module
    case SYS_init_module:
#endif
#ifdef SYS_finit_module
    case SYS_finit_module:
#endif
#ifdef SYS_delete_module
    case SYS_delete_module:
#endif
#ifdef SYS_bpf
    case SYS_bpf:
#endif
#ifdef SYS_ptrace
    case SYS_ptrace:
#endif
#ifdef SYS_kexec_load
    case SYS_kexec_load:
#endif
#ifdef SYS_kexec_file_load
    case SYS_kexec_file_load:
#endif
#ifdef SYS_open_by_handle_at
    case SYS_open_by_handle_at:
#endif
#ifdef SYS_process_vm_writev
    case SYS_process_vm_writev:
#endif
#ifdef SYS_process_vm_readv
    case SYS_process_vm_readv:
#endif
#ifdef SYS_userfaultfd
    case SYS_userfaultfd:
#endif
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup:
#endif
#ifdef SYS_mount
    case SYS_mount:
#endif
#ifdef SYS_umount2
    case SYS_umount2:
#endif
#ifdef SYS_setns
    case SYS_setns:
#endif
      if ((state->mask & AP_TRACE_MASK_KERNEL) != 0u) {
        ap_trace_event(state, &event, AP_KIND_KERNEL, pid);
        event.subkind = 1u;
        event.severity = AP_SEV_HIGH;
        event.confidence_x1000 = 780u;
        event.arg[0] = (uint64_t)nr;
        event.arg[1] = (uint64_t)a[0];
        event.arg[2] = (uint64_t)a[1];
        snprintf(event.text, sizeof(event.text), "%s", ap_trace_kernel_label(nr));
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
      }
      break;
#ifdef SYS_rename
    case SYS_rename:
#endif
#ifdef SYS_renameat
    case SYS_renameat:
#endif
#ifdef SYS_renameat2
    case SYS_renameat2:
#endif
#ifdef SYS_unlink
    case SYS_unlink:
#endif
#ifdef SYS_unlinkat
    case SYS_unlinkat:
#endif
#ifdef SYS_chmod
    case SYS_chmod:
#endif
#ifdef SYS_fchmodat
    case SYS_fchmodat:
#endif
      if ((state->mask & AP_TRACE_MASK_FILE) != 0u) {
        ap_trace_event(state, &event, AP_KIND_FILE, pid);
        event.subkind = AP_FILE_ACTION;
        event.severity = AP_SEV_MEDIUM;
        event.confidence_x1000 = 720u;
        event.arg[0] = (uint64_t)nr;
        event.arg[1] = (uint64_t)a[0];
        event.arg[2] = (uint64_t)a[1];
        snprintf(event.text, sizeof(event.text), "%s", ap_trace_kernel_label(nr));
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
      }
      break;
#ifdef SYS_socket
    case SYS_socket:
#endif
      if ((state->mask & AP_TRACE_MASK_NET) != 0u) {
        int raw = (int)(a[1] & SOCK_RAW) == SOCK_RAW;
        ap_trace_event(state, &event, AP_KIND_NET, pid);
        event.subkind = AP_NET_SOCKET;
        event.severity = raw ? AP_SEV_HIGH : AP_SEV_INFO;
        event.confidence_x1000 = raw ? 800u : 500u;
        event.arg[0] = (uint64_t)a[0];
        event.arg[1] = (uint64_t)a[1];
        event.arg[2] = (uint64_t)a[2];
        snprintf(event.text, sizeof(event.text), "socket");
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
      }
      break;
#ifdef SYS_connect
    case SYS_connect:
#endif
      if ((state->mask & AP_TRACE_MASK_NET) != 0u) {
        ap_trace_event(state, &event, AP_KIND_NET, pid);
        event.subkind = AP_NET_CONNECT;
        event.severity = AP_SEV_LOW;
        event.confidence_x1000 = 500u;
        event.arg[0] = (uint64_t)a[0];
        event.arg[1] = (uint64_t)nr;
        snprintf(event.text, sizeof(event.text), "connect");
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
      }
      break;
#ifdef SYS_sendto
    case SYS_sendto:
#endif
      if ((state->mask & AP_TRACE_MASK_NET) != 0u) {
        char hex[AP_TRACE_MAX_TEXT];
        uint8_t bytes[40];
        size_t len = (size_t)a[2];
        ap_trace_event(state, &event, AP_KIND_NET, pid);
        event.subkind = AP_NET_PACKET;
        event.severity = AP_SEV_INFO;
        event.confidence_x1000 = 500u;
        event.arg[0] = (uint64_t)a[0];
        event.arg[1] = (uint64_t)nr;
        event.arg[2] = (uint64_t)len;
        if (len > sizeof(bytes)) len = sizeof(bytes);
        if (len > 0u && ap_trace_read(pid, a[1], bytes, len) == AP_OK &&
            ap_hex_encode(bytes, len, hex, sizeof(hex)) == AP_OK) {
          snprintf(event.text, sizeof(event.text), "%s", hex);
        }
        int emitted_decision = ap_trace_emit(state, &event);
        if (emitted_decision != AP_DECISION_ALLOW && decision == AP_DECISION_ALLOW) {
          decision = emitted_decision;
        }
      }
      break;
    default:
      break;
  }

  (void)emitted;
  if ((state->mask & AP_TRACE_MASK_FLOW) != 0u) {
    ap_trace_flow(state, ps, pid, AP_RET_ADDR(*regs), AP_REG_SP(*regs), nr);
  }
  return decision;
}

static void ap_trace_deny(pid_t pid, struct user_regs_struct *regs) {
#if defined(__x86_64__)
  regs->orig_rax = (unsigned long long)-1;
  regs->rax = (unsigned long long)-EPERM;
#elif defined(__aarch64__)
  regs->x[8] = (unsigned long)-1;
  regs->x[0] = (unsigned long)-EPERM;
#else
  (void)pid;
  (void)regs;
#endif
  (void)pid;
  (void)ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

static void ap_trace_seccomp_stop(ap_trace_state *state, pid_t pid) {
  struct user_regs_struct regs;
  unsigned long a[6];
  int decision;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
    (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
    return;
  }
  a[0] = AP_REG_A0(regs);
  a[1] = AP_REG_A1(regs);
  a[2] = AP_REG_A2(regs);
  a[3] = AP_REG_A3(regs);
  a[4] = AP_REG_A4(regs);
  a[5] = AP_REG_A5(regs);
  decision = ap_trace_syscall(state, pid, AP_REG_NR(regs), a, &regs);
  if (decision == AP_DECISION_DENY) {
    ap_trace_deny(pid, &regs);
  } else if (decision == AP_DECISION_STOP) {
    (void)kill(pid, SIGSTOP);
  }
  (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
}

static int ap_trace_set_options(pid_t pid) {
  long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC |
                 PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                 PTRACE_O_EXITKILL;
  return ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)options) == 0 ? AP_OK : AP_ERR_IO;
}

static void ap_trace_exec_event(ap_trace_state *state, pid_t pid) {
  ap_pid_state *ps = ap_trace_pid(state, pid);
  ap_event event;
  uint32_t uid = 0;
  uint32_t euid = 0;

  if (ps == NULL) {
    return;
  }
  ap_trace_refresh(state, ps);
  ap_trace_event(state, &event, AP_KIND_EXEC, pid);
  event.subkind = 2u;
  event.severity = AP_SEV_INFO;
  event.confidence_x1000 = 1000u;
  ap_sys_proc_comm(pid, event.text, sizeof(event.text));
  (void)ap_trace_emit(state, &event);

  if (ap_sys_proc_uid(pid, &uid, &euid) == AP_OK) {
    if (ps->have_uid && (uid != ps->uid || euid != ps->euid)) {
      ap_trace_event(state, &event, AP_KIND_PRIV, pid);
      event.subkind = 2u;
      event.severity = AP_SEV_HIGH;
      event.confidence_x1000 = 780u;
      event.arg[0] = ps->euid;
      event.arg[1] = euid;
      event.arg[2] = uid;
      snprintf(event.text, sizeof(event.text), "exec_uid_change");
      (void)ap_trace_emit(state, &event);
    }
    ps->uid = uid;
    ps->euid = euid;
    ps->have_uid = 1;
  }
}

int ap_trace_run(const ap_trace_config *config, ap_event_cb callback, void *user) {
  ap_trace_state *state;
  pid_t child;
  int status = 0;

  if (config == NULL || config->argv == NULL || config->argc == 0u || callback == NULL) {
    return AP_ERR_ARG;
  }
  if (AP_TRACE_ARCH == 0 || (ap_sys_capability_state() & 2u) == 0u) {
    return AP_ERR_UNSUPPORTED;
  }
  state = (ap_trace_state *)calloc(1, sizeof(*state));
  if (state == NULL) {
    return AP_ERR_NOMEM;
  }
  state->pids = (ap_pid_state *)calloc(AP_TRACE_MAX_PIDS, sizeof(ap_pid_state));
  if (state->pids == NULL) {
    free(state);
    return AP_ERR_NOMEM;
  }
  state->callback = callback;
  state->user = user;
  state->mask = config->mask;
  state->max_events = config->max_events;

  child = fork();
  if (child == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
      _exit(126);
    }
    if (ap_trace_install_filter() != AP_OK) {
      _exit(125);
    }
    execvp(config->argv[0], (char *const *)config->argv);
    _exit(127);
  }
  if (child < 0) {
    free(state->pids);
    free(state);
    return AP_ERR_IO;
  }
  state->root = child;
  if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
    fprintf(stderr, "ap_trace: initial stop failed status=0x%x errno=%d\n", status, errno);
    kill(child, SIGKILL);
    free(state->pids);
    free(state);
    return AP_ERR_IO;
  }
  if (ap_trace_set_options(child) != AP_OK) {
    fprintf(stderr, "ap_trace: set options failed errno=%d\n", errno);
    kill(child, SIGKILL);
    free(state->pids);
    free(state);
    return AP_ERR_UNSUPPORTED;
  }
  (void)ptrace(PTRACE_CONT, child, NULL, NULL);

  for (;;) {
    pid_t pid = waitpid(-1, &status, __WALL);
    unsigned int event;
    ap_pid_state *ps;

    if (pid < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      ps = ap_trace_pid(state, pid);
      if (ps != NULL) ps->in_use = 0;
      if (pid == state->root) break;
      continue;
    }
    if (!WIFSTOPPED(status)) {
      continue;
    }
    event = (unsigned int)status >> 16;
    if (event == PTRACE_EVENT_SECCOMP) {
      ap_trace_seccomp_stop(state, pid);
    } else if (event == PTRACE_EVENT_EXEC) {
      ap_trace_exec_event(state, pid);
      (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
    } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
               event == PTRACE_EVENT_CLONE) {
      unsigned long message = 0;
      if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &message) == 0 && message > 0) {
        pid_t new_pid = (pid_t)message;
        (void)ap_trace_pid(state, new_pid);
        (void)ap_trace_set_options(new_pid);
        (void)ptrace(PTRACE_CONT, new_pid, NULL, NULL);
      }
      (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
    } else if (WSTOPSIG(status) == SIGTRAP) {
      (void)ap_trace_set_options(pid);
      (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
    } else {
      (void)ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)WSTOPSIG(status));
    }
  }

  {
    ap_event event;
    ap_trace_event(state, &event, AP_KIND_HEARTBEAT, state->root);
    event.subkind = 2u;
    event.arg[0] = state->emitted;
    event.arg[1] = state->dropped;
    snprintf(event.text, sizeof(event.text), "tracer_stopped");
    (void)ap_trace_emit(state, &event);
  }
  free(state->pids);
  free(state);
  return AP_OK;
}
