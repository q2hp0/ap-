#include "apintrusion.h"
#include "apksensor.h"

#include <cstdio>
#include <cstring>
#include <new>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

namespace {

constexpr uint64_t counter_max = ~0ull;
constexpr size_t label_len = 24u;

constexpr uint32_t bit_remote_write = 1u << 0;
constexpr uint32_t bit_remote_read = 1u << 1;
constexpr uint32_t bit_cred_access = 1u << 2;
constexpr uint32_t bit_wx = 1u << 3;
constexpr uint32_t bit_exec = 1u << 4;
constexpr uint32_t bit_redirect = 1u << 5;
constexpr uint32_t bit_priv = 1u << 6;
constexpr uint32_t bit_net = 1u << 7;

static_assert(AP_INTRUSION_PID_SLOTS > 0u, "no pid slots");
static_assert(AP_INTRUSION_RESULTS >= 3u, "need three finding slots");
static_assert(AP_TEXT_LEN >= 48u, "detail buffer too small");

struct pid_intrusion {
  int64_t pid;
  uint64_t first_ns;
  uint64_t last_ns;
  uint32_t mask;
  uint64_t last_injection_ns;
  uint64_t last_exploit_ns;
  uint64_t last_dump_ns;
  int used;
  int emitted_injection;
  int emitted_exploit;
  int emitted_dump;
  char write_label[label_len];
  char read_label[label_len];
  char cred_label[label_len];
};

struct candidate {
  uint32_t rule;
  uint32_t confidence;
  const char *prefix;
  uint64_t *last_ns;
  int *emitted;
};

void copy_label(char *dst, size_t cap, const char *value) {
  if (dst == nullptr || cap == 0u) {
    return;
  }
  size_t i = 0u;
  if (value != nullptr) {
    for (; i + 1u < cap && value[i] != '\0'; ++i) {
      dst[i] = value[i];
    }
  }
  dst[i] = '\0';
}

void clear_labels(pid_intrusion *slot) {
  slot->write_label[0] = '\0';
  slot->read_label[0] = '\0';
  slot->cred_label[0] = '\0';
}

uint32_t stage_bit(const ap_event *event, char *label, size_t cap) {
  label[0] = '\0';
  switch (event->kind) {
    case AP_KIND_KERNEL:
      if (std::strcmp(event->text, "process_vm_writev") == 0) {
        copy_label(label, cap, "process_vm_writev");
        return bit_remote_write;
      }
      if (std::strcmp(event->text, "ptrace") == 0) {
        copy_label(label, cap, "ptrace");
        return bit_remote_write;
      }
      if (std::strcmp(event->text, "process_vm_readv") == 0) {
        copy_label(label, cap, "process_vm_readv");
        return bit_remote_read;
      }
      if (std::strcmp(event->text, "credential_theft") == 0 ||
          std::strcmp(event->text, "cred_change") == 0 ||
          std::strcmp(event->text, "cred") == 0 ||
          std::strcmp(event->text, "shadow_read") == 0 ||
          std::strcmp(event->text, "keyring_read") == 0) {
        copy_label(label, cap, event->text);
        return bit_cred_access;
      }
      if (std::strcmp(event->text, "kernel_interface") == 0) {
#ifdef SYS_process_vm_writev
        if (event->arg[0] == (uint64_t)SYS_process_vm_writev) {
          copy_label(label, cap, "process_vm_writev");
          return bit_remote_write;
        }
#endif
#ifdef SYS_process_vm_readv
        if (event->arg[0] == (uint64_t)SYS_process_vm_readv) {
          copy_label(label, cap, "process_vm_readv");
          return bit_remote_read;
        }
#endif
      }
      return 0u;
    case AP_KIND_MEMPROT:
    case AP_KIND_MEMREGION:
      return (event->arg[2] & 6u) == 6u ? bit_wx : 0u;
    case AP_KIND_EXEC:
      return bit_exec;
    case AP_KIND_FLOW:
      if (event->subkind == AP_FLOW_RETURN_SITE || event->subkind == AP_FLOW_STACK ||
          event->subkind == AP_FLOW_SHADOW) {
        return bit_redirect;
      }
      return 0u;
    case AP_KIND_PRIV:
      return bit_priv;
    case AP_KIND_NET:
      return bit_net;
    default:
      return 0u;
  }
}

bool window_fresh(uint64_t first, uint64_t now) {
  return now >= first && (now - first) <= AP_INTRUSION_WINDOW_NS;
}

void set_stage_label(pid_intrusion *slot, uint32_t bit, const char *label) {
  if (label == nullptr || label[0] == '\0') {
    return;
  }
  if (bit == bit_remote_write) {
    copy_label(slot->write_label, sizeof(slot->write_label), label);
  } else if (bit == bit_remote_read) {
    copy_label(slot->read_label, sizeof(slot->read_label), label);
  } else if (bit == bit_cred_access) {
    copy_label(slot->cred_label, sizeof(slot->cred_label), label);
  }
}

void merge_stage(pid_intrusion *slot, uint64_t now, uint32_t bit, const char *label) {
  if (!window_fresh(slot->first_ns, now)) {
    slot->mask = 0u;
    slot->first_ns = now;
    clear_labels(slot);
  }
  slot->last_ns = now;
  slot->mask |= bit;
  set_stage_label(slot, bit, label);
}

const char *stage_name(uint32_t bit, const pid_intrusion *slot) {
  switch (bit) {
    case bit_remote_write:
      return slot->write_label[0] != '\0' ? slot->write_label : "remote_write";
    case bit_remote_read:
      return slot->read_label[0] != '\0' ? slot->read_label : "remote_read";
    case bit_cred_access:
      return slot->cred_label[0] != '\0' ? slot->cred_label : "cred_access";
    case bit_wx:
      return "wx";
    case bit_exec:
      return "exec";
    case bit_redirect:
      return "redirect";
    case bit_priv:
      return "priv";
    case bit_net:
      return "net";
    default:
      return nullptr;
  }
}

void append_text(char *out, size_t cap, const char *value) {
  size_t used = std::strlen(out);
  if (used >= cap || value == nullptr) {
    return;
  }
  for (; used + 1u < cap && *value != '\0'; ++used) {
    out[used] = *value++;
  }
  out[used] = '\0';
}

void format_detail(const char *prefix, const pid_intrusion *slot, char *out, size_t cap) {
  if (cap == 0u) {
    return;
  }
  out[0] = '\0';
  append_text(out, cap, prefix);
  for (uint32_t bit = 1u; bit <= bit_net; bit <<= 1u) {
    if ((slot->mask & bit) == 0u) {
      continue;
    }
    append_text(out, cap, "+");
    append_text(out, cap, stage_name(bit, slot));
  }
}

void set_verdict(ap_verdict *verdict, const ap_event *event, uint32_t rule,
                 uint32_t confidence, uint64_t evidence, const char *text) {
  ap_verdict_init(verdict, event->seq);
  verdict->kind = AP_KIND_FLOW;
  verdict->rule = rule;
  verdict->severity = AP_SEV_CRITICAL;
  verdict->confidence_x1000 = confidence;
  verdict->evidence = evidence;
  std::snprintf(verdict->text, sizeof(verdict->text), "%s", text);
}

void bump(uint64_t *value) {
  if (*value != counter_max) {
    ++*value;
  }
}

bool injection_ready(uint32_t mask) {
  return (mask & bit_remote_write) != 0u &&
         (mask & (bit_wx | bit_exec | bit_redirect)) != 0u;
}

bool exploit_ready(uint32_t mask) {
  return (mask & bit_wx) != 0u && (mask & bit_redirect) != 0u &&
         (mask & (bit_priv | bit_exec | bit_net)) != 0u;
}

bool dump_ready(uint32_t mask) {
  return (mask & bit_remote_read) != 0u && (mask & bit_cred_access) != 0u &&
         (mask & (bit_priv | bit_net | bit_remote_write)) != 0u;
}

bool suppressed_now(const candidate &item, uint64_t now) {
  return *item.emitted != 0 && now >= *item.last_ns &&
         (now - *item.last_ns) <= AP_INTRUSION_SUPPRESS_NS;
}

}  // namespace

struct ap_intrusion {
  pid_intrusion pids[AP_INTRUSION_PID_SLOTS];
  ap_intrusion_counters_t counters;
};

namespace {

pid_intrusion *pid_slot(ap_intrusion *handle, int64_t pid, uint64_t now) {
  pid_intrusion *free_slot = nullptr;
  pid_intrusion *oldest = nullptr;
  for (uint32_t i = 0u; i < AP_INTRUSION_PID_SLOTS; ++i) {
    pid_intrusion *slot = &handle->pids[i];
    if (slot->used != 0 && slot->pid == pid) {
      return slot;
    }
    if (slot->used == 0 && free_slot == nullptr) {
      free_slot = slot;
    }
    if (slot->used != 0 && (oldest == nullptr || slot->last_ns < oldest->last_ns)) {
      oldest = slot;
    }
  }
  if (free_slot == nullptr) {
    free_slot = oldest;
    if (free_slot == nullptr) {
      return nullptr;
    }
    bump(&handle->counters.evicted);
  }
  std::memset(free_slot, 0, sizeof(*free_slot));
  free_slot->used = 1;
  free_slot->pid = pid;
  free_slot->first_ns = now;
  free_slot->last_ns = now;
  bump(&handle->counters.added);
  return free_slot;
}

}  // namespace

ap_intrusion *ap_intrusion_new(void) {
  ap_intrusion *handle = new (std::nothrow) ap_intrusion;
  if (handle != nullptr) {
    std::memset(handle, 0, sizeof(*handle));
  }
  return handle;
}

void ap_intrusion_free(ap_intrusion *handle) {
  delete handle;
}

int ap_intrusion_feed(ap_intrusion *handle, const ap_event *event, ap_verdict *verdict) {
  if (verdict != nullptr) {
    ap_verdict_init(verdict, event != nullptr ? event->seq : 0u);
  }
  if (handle == nullptr || event == nullptr || verdict == nullptr) {
    return AP_ERR_ARG;
  }

  char label[label_len];
  uint32_t bit = stage_bit(event, label, sizeof(label));
  if (bit == 0u) {
    return AP_OK;
  }

  pid_intrusion *slot = pid_slot(handle, event->pid, event->ts_ns);
  if (slot == nullptr) {
    return AP_OK;
  }
  merge_stage(slot, event->ts_ns, bit, label);

  candidate results[AP_INTRUSION_RESULTS];
  uint32_t count = 0u;
  if (dump_ready(slot->mask)) {
    results[count].rule = AP_RULE_CREDENTIAL_DUMP;
    results[count].confidence = 900u;
    results[count].prefix = "credential_dump:";
    results[count].last_ns = &slot->last_dump_ns;
    results[count].emitted = &slot->emitted_dump;
    ++count;
  }
  if (injection_ready(slot->mask)) {
    results[count].rule = AP_RULE_PROCESS_INJECTION;
    results[count].confidence = (slot->mask & bit_redirect) != 0u ? 890u : 870u;
    results[count].prefix = "process_injection:";
    results[count].last_ns = &slot->last_injection_ns;
    results[count].emitted = &slot->emitted_injection;
    ++count;
  }
  if (exploit_ready(slot->mask)) {
    results[count].rule = AP_RULE_EXPLOIT_CHAIN;
    results[count].confidence = (slot->mask & bit_priv) != 0u ? 920u : 890u;
    results[count].prefix = "exploit_chain:";
    results[count].last_ns = &slot->last_exploit_ns;
    results[count].emitted = &slot->emitted_exploit;
    ++count;
  }
  if (count == 0u) {
    return AP_OK;
  }

  for (uint32_t i = 0u; i < count; ++i) {
    candidate &choice = results[i];
    if (suppressed_now(choice, event->ts_ns)) {
      bump(&handle->counters.suppressed);
      continue;
    }
    char detail[AP_TEXT_LEN];
    format_detail(choice.prefix, slot, detail, sizeof(detail));
    uint64_t evidence = event->arg[0] != 0u ? event->arg[0] : (uint64_t)event->pid;
    set_verdict(verdict, event, choice.rule, choice.confidence, evidence, detail);
    bump(&handle->counters.findings);
    *choice.last_ns = event->ts_ns;
    *choice.emitted = 1;
    return AP_OK;
  }
  return AP_OK;
}

int ap_intrusion_stats(const ap_intrusion *handle, ap_intrusion_counters_t *counters) {
  if (handle == nullptr || counters == nullptr) {
    return AP_ERR_ARG;
  }
  *counters = handle->counters;
  return AP_OK;
}

void ap_intrusion_reset(ap_intrusion *handle) {
  if (handle == nullptr) {
    return;
  }
  std::memset(handle, 0, sizeof(*handle));
}
