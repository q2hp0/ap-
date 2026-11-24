#include "apflow.h"
#include "apksensor.h"

#include <cstdio>
#include <cstring>

namespace {

constexpr uint64_t weak_window_ns = 2000000000ull;
constexpr uint64_t wx_window_ns = 5000000000ull;
constexpr uint64_t kernel_window_ns = 5000000000ull;
constexpr uint64_t default_entity_window_ns = 5000000000ull;
constexpr uint64_t min_entity_window_ns = 100000000ull;
constexpr uint64_t max_entity_window_ns = 60000000000ull;
constexpr uint32_t class_pid_bit = 1u << 0;
constexpr uint32_t class_binary_bit = 1u << 1;
constexpr uint32_t class_peer_bit = 1u << 2;
constexpr uint32_t class_priv_bit = 1u << 3;
constexpr uint32_t kernel_module_bit = 1u << 0;
constexpr uint32_t kernel_kexec_bit = 1u << 1;
constexpr uint32_t kernel_mount_bit = 1u << 2;
constexpr uint32_t kernel_namespace_bit = 1u << 3;
constexpr uint32_t kernel_iface_bit = 1u << 4;
constexpr uint32_t kernel_bpf_bit = 1u << 5;
constexpr uint32_t kernel_ptrace_bit = 1u << 6;
constexpr uint32_t kernel_setid_bit = 1u << 7;
constexpr uint32_t kernel_exec_uid_bit = 1u << 8;
constexpr uint32_t kernel_strong_bits =
    kernel_module_bit | kernel_kexec_bit | kernel_bpf_bit;
constexpr uint32_t kernel_stop_bits =
    kernel_module_bit | kernel_kexec_bit | kernel_bpf_bit | kernel_ptrace_bit;
constexpr uint32_t kernel_priv_bits = kernel_setid_bit | kernel_exec_uid_bit;

// New high-value kernel sensor labels (arg[3] == AP_KSENSOR_SOURCE_MARK) join the
// existing kernel chain mask. Replay events (arg[3] == 2) never set these bits.
constexpr uint32_t kernel_rootkit_bit = 1u << 9;
constexpr uint32_t kernel_cred_theft_bit = 1u << 10;
constexpr uint32_t kernel_fileless_bit = 1u << 11;
constexpr uint32_t kernel_anti_analysis_bit = 1u << 12;
constexpr uint32_t kernel_bpf_prog_bit = 1u << 13;
constexpr uint32_t kernel_text_write_bit = 1u << 14;
constexpr uint32_t kernel_ftrace_bit = 1u << 15;
constexpr uint32_t kernel_kcore_bit = 1u << 16;
constexpr uint32_t kernel_debugfs_bit = 1u << 17;
constexpr uint32_t kernel_generic_bits =
    kernel_rootkit_bit | kernel_cred_theft_bit | kernel_fileless_bit |
    kernel_anti_analysis_bit | kernel_bpf_prog_bit | kernel_text_write_bit |
    kernel_ftrace_bit | kernel_kcore_bit | kernel_debugfs_bit;
constexpr uint32_t kernel_generic_label_count = 9u;

// Persistence chain: bounded per-pid mask. Four write labels, an exec/start
// stage and a network stage all share the same 5-second window.
constexpr uint32_t persist_cron_bit = 1u << 0;
constexpr uint32_t persist_systemd_bit = 1u << 1;
constexpr uint32_t persist_rc_bit = 1u << 2;
constexpr uint32_t persist_ssh_bit = 1u << 3;
constexpr uint32_t persist_exec_bit = 1u << 4;
constexpr uint32_t persist_start_bit = 1u << 5;
constexpr uint32_t persist_connect_bit = 1u << 6;
constexpr uint32_t persist_packet_bit = 1u << 7;
constexpr uint32_t persist_write_bits =
    persist_cron_bit | persist_systemd_bit | persist_rc_bit | persist_ssh_bit;
constexpr uint32_t persist_start_stage_bits = persist_exec_bit | persist_start_bit;
constexpr uint32_t persist_net_stage_bits = persist_connect_bit | persist_packet_bit;

// Container escape chain: namespace + mount + one privileged label.
constexpr uint32_t container_ns_bit = 1u << 0;
constexpr uint32_t container_mount_bit = 1u << 1;
constexpr uint32_t container_capset_bit = 1u << 2;
constexpr uint32_t container_cgroup_bit = 1u << 3;
constexpr uint32_t container_cred_bit = 1u << 4;
constexpr uint32_t container_uid_bit = 1u << 5;
constexpr uint32_t container_privileged_bits =
    container_capset_bit | container_cgroup_bit | container_cred_bit | container_uid_bit;

static_assert(AP_FLOW_KERNEL_LABELS <= 32u, "kernel label mask too wide");
static_assert(AP_FLOW_KERNEL_LABELS + kernel_generic_label_count <= 32u,
              "generic kernel label mask too wide");
static_assert((AP_FLOW_STAGE_ALL & ~15u) == 0u, "stage mask too wide");

struct exec_range {
  uint64_t start;
  uint64_t end;
  int used;
};

enum entity_type {
  entity_binary = 1,
  entity_peer = 2,
  entity_priv = 3
};

struct entity_state {
  uint32_t type;
  char key[AP_FLOW_ENTITY_KEY_LEN];
  uint32_t stages;
  uint64_t first;
  uint64_t last;
  int used;
};

struct pid_flow {
  int64_t pid;
  exec_range ranges[AP_FLOW_RANGE_SLOTS];
  uint64_t shadow[AP_FLOW_SHADOW_DEPTH];
  uint32_t depth;
  uint32_t weak;
  uint64_t weak_first;
  uint64_t weak_last;
  uint64_t wx_time;
  uint64_t kernel_first;
  uint32_t kernel_mask;
  uint32_t persist_mask;
  uint64_t persist_first;
  uint64_t persist_last;
  uint32_t container_mask;
  uint64_t container_first;
  uint64_t container_last;
  uint64_t priv_first;
  uint32_t priv_mask;
  uint64_t last_seen;
  int used;
  char binary[AP_FLOW_ENTITY_KEY_LEN];
  char peer[AP_FLOW_ENTITY_KEY_LEN];
  char priv[AP_FLOW_ENTITY_KEY_LEN];
  uint64_t binary_time;
  uint64_t peer_time;
  uint64_t priv_time;
  uint8_t has_binary;
  uint8_t has_peer;
  uint8_t has_priv;
  uint32_t entity_stages;
  uint64_t entity_first;
  uint64_t entity_last;
};

void set_verdict(ap_verdict *verdict, const ap_event *event, uint32_t rule,
                 uint32_t severity, uint32_t confidence, uint64_t evidence,
                 const char *text) {
  if (verdict == nullptr) {
    return;
  }
  ap_verdict_init(verdict, event->seq);
  verdict->kind = AP_KIND_FLOW;
  verdict->rule = rule;
  verdict->severity = severity;
  verdict->confidence_x1000 = confidence;
  verdict->evidence = evidence;
  std::snprintf(verdict->text, sizeof(verdict->text), "%s", text);
}

bool in_ranges(const pid_flow *state, uint64_t address) {
  for (uint32_t i = 0; i < AP_FLOW_RANGE_SLOTS; ++i) {
    if (state->ranges[i].used != 0 &&
        address >= state->ranges[i].start && address < state->ranges[i].end) {
      return true;
    }
  }
  return false;
}

void put_range(pid_flow *state, uint64_t start, uint64_t end, uint32_t *count,
               uint64_t *evictions) {
  uint32_t free_slot = AP_FLOW_RANGE_SLOTS;
  for (uint32_t i = 0; i < AP_FLOW_RANGE_SLOTS; ++i) {
    if (state->ranges[i].used != 0 && state->ranges[i].start == start) {
      if (end <= start) {
        memset(&state->ranges[i], 0, sizeof(state->ranges[i]));
        if (*count > 0u) --*count;
      } else {
        state->ranges[i].end = end;
      }
      return;
    }
    if (state->ranges[i].used == 0 && free_slot == AP_FLOW_RANGE_SLOTS) {
      free_slot = i;
    }
  }
  if (end <= start) {
    return;
  }
  if (free_slot == AP_FLOW_RANGE_SLOTS) {
    ++*evictions;
    return;
  }
  state->ranges[free_slot].start = start;
  state->ranges[free_slot].end = end;
  state->ranges[free_slot].used = 1;
  ++*count;
}

}  // namespace

struct ap_flow_handle {
  pid_flow pids[AP_FLOW_PID_SLOTS];
  entity_state entities[AP_FLOW_ENTITY_SLOTS];
  ap_flow_counters counters;
  uint32_t range_count[AP_FLOW_PID_SLOTS];
  uint64_t entity_window_ns;
};

ap_flow_handle *ap_flow_new(void) {
  ap_flow_handle *handle = new ap_flow_handle;
  memset(handle, 0, sizeof(*handle));
  handle->entity_window_ns = default_entity_window_ns;
  return handle;
}

void ap_flow_free(ap_flow_handle *handle) {
  delete handle;
}

int ap_flow_reset(ap_flow_handle *handle) {
  if (handle == nullptr) {
    return AP_ERR_ARG;
  }
  memset(handle->pids, 0, sizeof(handle->pids));
  memset(handle->entities, 0, sizeof(handle->entities));
  memset(handle->range_count, 0, sizeof(handle->range_count));
  return AP_OK;
}

int ap_flow_stats(const ap_flow_handle *handle, ap_flow_counters *counters) {
  if (handle == nullptr || counters == nullptr) {
    return AP_ERR_ARG;
  }
  *counters = handle->counters;
  return AP_OK;
}

int ap_flow_set_window_ms(ap_flow_handle *handle, uint32_t window_ms) {
  if (handle == nullptr) {
    return AP_ERR_ARG;
  }
  uint64_t window_ns = (uint64_t)window_ms * 1000000ull;
  if (window_ns < min_entity_window_ns || window_ns > max_entity_window_ns) {
    return AP_ERR_RANGE;
  }
  handle->entity_window_ns = window_ns;
  return AP_OK;
}

namespace {

pid_flow *flow_pid(ap_flow_handle *handle, int64_t pid, uint32_t *index_out) {
  uint32_t free_slot = AP_FLOW_PID_SLOTS;
  for (uint32_t i = 0; i < AP_FLOW_PID_SLOTS; ++i) {
    if (handle->pids[i].used != 0 && handle->pids[i].pid == pid) {
      if (index_out != nullptr) *index_out = i;
      return &handle->pids[i];
    }
    if (handle->pids[i].used == 0 && free_slot == AP_FLOW_PID_SLOTS) {
      free_slot = i;
    }
  }
  if (free_slot == AP_FLOW_PID_SLOTS) {
    return nullptr;
  }
  memset(&handle->pids[free_slot], 0, sizeof(handle->pids[free_slot]));
  handle->pids[free_slot].used = 1;
  handle->pids[free_slot].pid = pid;
  if (index_out != nullptr) *index_out = free_slot;
  return &handle->pids[free_slot];
}

bool add_weak(pid_flow *state, uint64_t now) {
  if (state->weak == 0u || now - state->weak_first > weak_window_ns) {
    state->weak = 0u;
    state->weak_first = now;
  }
  ++state->weak;
  state->weak_last = now;
  if (state->weak >= 3u && state->wx_time != 0u &&
      now - state->wx_time <= wx_window_ns && now - state->weak_first <= weak_window_ns) {
    state->weak = 0u;
    state->wx_time = 0u;
    return true;
  }
  return false;
}

uint32_t kernel_label_bit(const char *text) {
  if (std::strcmp(text, "module_load") == 0) return kernel_module_bit;
  if (std::strcmp(text, "kexec") == 0) return kernel_kexec_bit;
  if (std::strcmp(text, "mount") == 0) return kernel_mount_bit;
  if (std::strcmp(text, "namespace_change") == 0) return kernel_namespace_bit;
  if (std::strcmp(text, "kernel_interface") == 0) return kernel_iface_bit;
  if (std::strcmp(text, "process_vm_writev") == 0) return kernel_iface_bit;
  if (std::strcmp(text, "process_vm_readv") == 0) return kernel_iface_bit;
  if (std::strcmp(text, "userfaultfd") == 0) return kernel_iface_bit;
  if (std::strcmp(text, "io_uring_setup") == 0) return kernel_iface_bit;
  if (std::strcmp(text, "open_by_handle_at") == 0) return kernel_iface_bit;
  if (std::strcmp(text, "bpf") == 0) return kernel_bpf_bit;
  if (std::strcmp(text, "ptrace") == 0) return kernel_ptrace_bit;
  return 0u;
}

uint32_t ksensor_generic_bit(const char *text) {
  if (std::strcmp(text, "kernel_rootkit") == 0) return kernel_rootkit_bit;
  if (std::strcmp(text, "credential_theft") == 0) return kernel_cred_theft_bit;
  if (std::strcmp(text, "fileless_exec") == 0) return kernel_fileless_bit;
  if (std::strcmp(text, "anti_analysis") == 0) return kernel_anti_analysis_bit;
  if (std::strcmp(text, "bpf_prog_load") == 0) return kernel_bpf_prog_bit;
  if (std::strcmp(text, "kernel_text_write") == 0) return kernel_text_write_bit;
  if (std::strcmp(text, "ftrace_write") == 0) return kernel_ftrace_bit;
  if (std::strcmp(text, "kcore_open") == 0) return kernel_kcore_bit;
  if (std::strcmp(text, "debugfs_write") == 0) return kernel_debugfs_bit;
  return 0u;
}

uint32_t persist_label_bit(const char *text) {
  if (std::strcmp(text, "cron_write") == 0) return persist_cron_bit;
  if (std::strcmp(text, "systemd_unit_write") == 0) return persist_systemd_bit;
  if (std::strcmp(text, "rc_write") == 0) return persist_rc_bit;
  if (std::strcmp(text, "ssh_key_write") == 0) return persist_ssh_bit;
  if (std::strcmp(text, "exec") == 0) return persist_exec_bit;
  if (std::strcmp(text, "process_start") == 0) return persist_start_bit;
  if (std::strcmp(text, "connect") == 0) return persist_connect_bit;
  if (std::strcmp(text, "net_packet") == 0) return persist_packet_bit;
  return 0u;
}

uint32_t container_label_bit(const char *text) {
  if (std::strcmp(text, "namespace_change") == 0) return container_ns_bit;
  if (std::strcmp(text, "mount") == 0) return container_mount_bit;
  if (std::strcmp(text, "capset") == 0) return container_capset_bit;
  if (std::strcmp(text, "cgroup_write") == 0) return container_cgroup_bit;
  if (std::strcmp(text, "cred") == 0) return container_cred_bit;
  if (std::strcmp(text, "exec_uid_change") == 0) return container_uid_bit;
  return 0u;
}

uint32_t priv_label_bit(const ap_event *event) {
  if (event->kind == AP_KIND_PRIV) {
    if (event->subkind == 2u || std::strcmp(event->text, "exec_uid_change") == 0) {
      return kernel_exec_uid_bit;
    }
    if (std::strcmp(event->text, "setid") == 0) {
      return kernel_setid_bit;
    }
  }
  return 0u;
}

uint32_t bit_count(uint32_t value) {
  uint32_t count = 0u;
  while (value != 0u) {
    value &= value - 1u;
    ++count;
  }
  return count;
}

const char *label_name(uint32_t bit) {
  switch (bit) {
    case kernel_module_bit: return "module_load";
    case kernel_kexec_bit: return "kexec";
    case kernel_mount_bit: return "mount";
    case kernel_namespace_bit: return "namespace_change";
    case kernel_iface_bit: return "kernel_interface";
    case kernel_bpf_bit: return "bpf";
    case kernel_ptrace_bit: return "ptrace";
    case kernel_setid_bit: return "setid";
    case kernel_exec_uid_bit: return "exec_uid_change";
    case kernel_rootkit_bit: return "kernel_rootkit";
    case kernel_cred_theft_bit: return "credential_theft";
    case kernel_fileless_bit: return "fileless_exec";
    case kernel_anti_analysis_bit: return "anti_analysis";
    case kernel_bpf_prog_bit: return "bpf_prog_load";
    case kernel_text_write_bit: return "kernel_text_write";
    case kernel_ftrace_bit: return "ftrace_write";
    case kernel_kcore_bit: return "kcore_open";
    case kernel_debugfs_bit: return "debugfs_write";
    default: return nullptr;
  }
}

void append_text(char *out, size_t cap, const char *value) {
  size_t used = std::strlen(out);
  for (; used + 1u < cap && *value != '\0'; ++used) {
    out[used] = *value++;
  }
  out[used] = '\0';
}

void append_label(char *out, size_t cap, const char *label) {
  if (out[0] != '\0') {
    append_text(out, cap, "+");
  }
  append_text(out, cap, label);
}

void format_labels(uint32_t mask, char *out, size_t cap) {
  out[0] = '\0';
  for (uint32_t bit = 1u; bit != 0u && bit <= mask; bit <<= 1u) {
    if ((mask & bit) != 0u) {
      const char *name = label_name(bit);
      if (name != nullptr) {
        append_label(out, cap, name);
      }
    }
  }
  if (out[0] == '\0') {
    std::snprintf(out, cap, "%s", "unknown");
  }
}

const char *persist_label_name(uint32_t bit) {
  switch (bit) {
    case persist_cron_bit: return "cron_write";
    case persist_systemd_bit: return "systemd_unit_write";
    case persist_rc_bit: return "rc_write";
    case persist_ssh_bit: return "ssh_key_write";
    case persist_exec_bit: return "exec";
    case persist_start_bit: return "process_start";
    case persist_connect_bit: return "connect";
    case persist_packet_bit: return "net_packet";
    default: return nullptr;
  }
}

const char *container_label_name(uint32_t bit) {
  switch (bit) {
    case container_ns_bit: return "namespace_change";
    case container_mount_bit: return "mount";
    case container_capset_bit: return "capset";
    case container_cgroup_bit: return "cgroup_write";
    case container_cred_bit: return "cred";
    case container_uid_bit: return "exec_uid_change";
    default: return nullptr;
  }
}

void format_named_bits(uint32_t mask, const char *(*name)(uint32_t), char *out,
                       size_t cap) {
  out[0] = '\0';
  for (uint32_t bit = 1u; bit != 0u && bit <= mask; bit <<= 1u) {
    const char *value = name(bit);
    if ((mask & bit) != 0u && value != nullptr) {
      append_label(out, cap, value);
    }
  }
  if (out[0] == '\0') {
    std::snprintf(out, cap, "%s", "unknown");
  }
}

bool kernel_chain_ready(uint32_t mask) {
  uint32_t distinct = bit_count(mask);
  if (distinct < 2u) {
    return false;
  }
  if ((mask & kernel_kexec_bit) != 0u) {
    return true;
  }
  if ((mask & kernel_module_bit) != 0u && distinct >= 3u) {
    return true;
  }
  constexpr uint32_t bpf_partners = (kernel_stop_bits | kernel_mount_bit |
                                     kernel_namespace_bit | kernel_iface_bit) &
                                    ~kernel_bpf_bit;
  if ((mask & kernel_bpf_bit) != 0u && (mask & bpf_partners) != 0u) {
    return true;
  }
  if ((mask & kernel_ptrace_bit) != 0u &&
      (mask & (kernel_module_bit | kernel_kexec_bit | kernel_bpf_bit)) != 0u) {
    return true;
  }
  // Generic high-value sensor labels join the existing chain: any second
  // distinct kernel label completes the chain when one of them is generic.
  return (mask & kernel_generic_bits) != 0u;
}

bool persistence_ready(uint32_t mask) {
  return bit_count(mask & persist_write_bits) >= 2u &&
         (mask & persist_start_stage_bits) != 0u &&
         (mask & persist_net_stage_bits) != 0u;
}

bool container_escape_ready(uint32_t mask) {
  return (mask & container_ns_bit) != 0u && (mask & container_mount_bit) != 0u &&
         (mask & container_privileged_bits) != 0u;
}

bool priv_chain_ready(uint32_t mask) {
  if ((mask & kernel_priv_bits) == 0u) {
    return false;
  }
  if ((mask & kernel_setid_bit) != 0u && (mask & kernel_exec_uid_bit) != 0u) {
    return true;
  }
  return (mask & kernel_stop_bits) != 0u;
}

void observe_privilege(pid_flow *state, uint64_t now, uint32_t bit) {
  if (bit == 0u) {
    return;
  }
  if (state->priv_mask == 0u || now < state->priv_first ||
      now - state->priv_first > kernel_window_ns) {
    state->priv_mask = 0u;
    state->priv_first = now;
  }
  state->priv_mask |= bit;
}

bool window_fresh(uint64_t first, uint64_t now, uint64_t window) {
  return first != 0u && now >= first && now - first <= window;
}

void merge_stage(uint32_t &stages, uint64_t &first, uint64_t &last,
                 uint32_t stage, uint64_t now, uint64_t window) {
  if (stages == 0u || !window_fresh(first, now, window)) {
    stages = 0u;
    first = now;
  }
  stages |= stage;
  last = now;
}

void merge_window(uint32_t &stages, uint64_t &first, uint64_t &last,
                  uint32_t source_stages, uint64_t source_first,
                  uint64_t source_last, uint64_t now, uint64_t window) {
  if (source_stages == 0u || !window_fresh(source_first, now, window)) {
    return;
  }
  if (stages == 0u || !window_fresh(first, now, window)) {
    stages = 0u;
    first = source_first;
    last = source_last;
  }
  stages |= source_stages;
  if (last < source_last) {
    last = source_last;
  }
}

void clear_window(uint32_t &stages, uint64_t &first, uint64_t &last) {
  stages = 0u;
  first = 0u;
  last = 0u;
}

void copy_key(char *out, size_t cap, const char *text) {
  size_t i = 0u;
  for (; i + 1u < cap && text[i] != '\0'; ++i) {
    out[i] = text[i];
  }
  out[i] = '\0';
}

entity_state *entity_slot(ap_flow_handle *handle, uint32_t type,
                          const char *key, uint64_t now, bool create) {
  if (key == nullptr || key[0] == '\0') {
    return nullptr;
  }
  for (uint32_t i = 0; i < AP_FLOW_ENTITY_SLOTS; ++i) {
    entity_state *slot = &handle->entities[i];
    if (slot->used != 0 && slot->type == type &&
        std::strncmp(slot->key, key, sizeof(slot->key)) == 0) {
      return slot;
    }
  }
  if (!create) {
    return nullptr;
  }
  uint32_t target = AP_FLOW_ENTITY_SLOTS;
  for (uint32_t i = 0; i < AP_FLOW_ENTITY_SLOTS; ++i) {
    if (handle->entities[i].used == 0) {
      target = i;
      break;
    }
  }
  if (target == AP_FLOW_ENTITY_SLOTS) {
    uint64_t oldest = 0u;
    for (uint32_t i = 0; i < AP_FLOW_ENTITY_SLOTS; ++i) {
      if (oldest == 0u || handle->entities[i].last < oldest) {
        oldest = handle->entities[i].last;
        target = i;
      }
    }
    ++handle->counters.entity_evictions;
  }
  entity_state *slot = &handle->entities[target];
  memset(slot, 0, sizeof(*slot));
  slot->type = type;
  slot->used = 1;
  copy_key(slot->key, sizeof(slot->key), key);
  slot->last = now;
  return slot;
}

void set_reference(char *dst, size_t cap, uint8_t *flag, uint64_t *time,
                   const char *key, uint64_t now) {
  if (key == nullptr || key[0] == '\0') {
    return;
  }
  copy_key(dst, cap, key);
  *flag = 1u;
  *time = now;
}

void expire_reference(char *key, uint8_t *flag, uint64_t *time, uint64_t now,
                      uint64_t window, uint64_t *expired) {
  if (*flag == 0u || *time == 0u || now < *time || now - *time <= window) {
    return;
  }
  *flag = 0u;
  key[0] = '\0';
  *time = 0u;
  ++*expired;
}

void expire_references(ap_flow_handle *handle, uint64_t now) {
  for (uint32_t i = 0; i < AP_FLOW_PID_SLOTS; ++i) {
    pid_flow *state = &handle->pids[i];
    if (state->used == 0u) {
      continue;
    }
    expire_reference(state->binary, &state->has_binary, &state->binary_time, now,
                     handle->entity_window_ns, &handle->counters.entity_refs_expired);
    expire_reference(state->peer, &state->has_peer, &state->peer_time, now,
                     handle->entity_window_ns, &handle->counters.entity_refs_expired);
    expire_reference(state->priv, &state->has_priv, &state->priv_time, now,
                     handle->entity_window_ns, &handle->counters.entity_refs_expired);
  }
}

bool path_like(const char *text) {
  return text != nullptr && text[0] != '\0' &&
         (text[0] == '/' || std::strchr(text, '/') != nullptr);
}

bool extract_binary(const ap_event *event, char *out, size_t cap) {
  const char *text = event->text;
  if (text[0] == '\0') {
    return false;
  }
  if (event->kind == AP_KIND_EXEC ||
      (event->kind == AP_KIND_PROC &&
       (event->subkind == AP_PROC_EXEC_PATH || event->subkind == AP_PROC_EXEC_COMM))) {
    copy_key(out, cap, text);
    return true;
  }
  if (event->kind == AP_KIND_MEMREGION && path_like(text)) {
    copy_key(out, cap, text);
    return true;
  }
  if (event->kind == AP_KIND_PROC && path_like(text)) {
    copy_key(out, cap, text);
    return true;
  }
  return false;
}

int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

bool decode_hex(const char *text, uint8_t *out, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    int high = hex_value(text[i * 2u]);
    int low = hex_value(text[i * 2u + 1u]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[i] = (uint8_t)((high << 4) | low);
  }
  return true;
}

uint64_t hash_text(const char *text, size_t len) {
  uint64_t hash = 1469598103934665603ull;
  for (size_t i = 0; i < len; ++i) {
    hash = (hash ^ (uint8_t)text[i]) * 1099511628211ull;
  }
  return hash;
}

uint16_t read_be16(const uint8_t *data) {
  return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

bool extract_peer(const ap_event *event, char *out, size_t cap) {
  const char *text = event->text;
  if (std::strncmp(text, "peer:", 5) == 0 && text[5] != '\0') {
    copy_key(out, cap, text + 5);
    return true;
  }
  if (event->kind == AP_KIND_NET) {
    size_t len = std::strlen(text);
    if (len >= 48u && text[0] == '4') {
      uint8_t bytes[24];
      if (decode_hex(text, bytes, sizeof(bytes))) {
        std::snprintf(out, cap, "v4:%02x%02x%02x%02x:%02x%02x%02x%02x:%u:%u",
                      bytes[12], bytes[13], bytes[14], bytes[15],
                      bytes[16], bytes[17], bytes[18], bytes[19],
                      read_be16(&bytes[20]), read_be16(&bytes[22]));
        return true;
      }
    }
    if (len >= 88u && text[0] == '6') {
      uint8_t bytes[44];
      if (decode_hex(text, bytes, sizeof(bytes))) {
        std::snprintf(out, cap, "v6:%016llx",
                      (unsigned long long)hash_text(text, len));
        return true;
      }
    }
  }
  if (event->arg[0] != 0u || event->arg[1] != 0u) {
    std::snprintf(out, cap, "k:%llx:%llx",
                  (unsigned long long)event->arg[0],
                  (unsigned long long)event->arg[1]);
    return true;
  }
  return false;
}

bool extract_priv(const ap_event *event, char *out, size_t cap) {
  if (event->kind != AP_KIND_PRIV || event->subkind != 2u) {
    return false;
  }
  if (event->arg[1] != 0u || event->arg[3] != 0u) {
    std::snprintf(out, cap, "uid:%llx:%llx",
                  (unsigned long long)event->arg[1],
                  (unsigned long long)event->arg[3]);
  } else {
    std::snprintf(out, cap, "%s", "uid:changed");
  }
  return true;
}

void closure(ap_flow_handle *handle, uint64_t now) {
  uint64_t window = handle->entity_window_ns;
  expire_references(handle, now);
  for (uint32_t round = 0; round < 3u; ++round) {
    bool changed = false;
    for (uint32_t i = 0; i < AP_FLOW_PID_SLOTS; ++i) {
      pid_flow *state = &handle->pids[i];
      if (state->used == 0u) {
        continue;
      }
      uint32_t before = state->entity_stages;
      if (state->has_binary != 0u) {
        entity_state *slot = entity_slot(handle, entity_binary, state->binary,
                                         now, false);
        if (slot != nullptr) {
          merge_window(state->entity_stages, state->entity_first, state->entity_last,
                       slot->stages, slot->first, slot->last, now, window);
        }
      }
      if (state->has_peer != 0u) {
        entity_state *slot = entity_slot(handle, entity_peer, state->peer,
                                         now, false);
        if (slot != nullptr) {
          merge_window(state->entity_stages, state->entity_first, state->entity_last,
                       slot->stages, slot->first, slot->last, now, window);
        }
      }
      if (state->has_priv != 0u) {
        entity_state *slot = entity_slot(handle, entity_priv, state->priv,
                                         now, false);
        if (slot != nullptr) {
          merge_window(state->entity_stages, state->entity_first, state->entity_last,
                       slot->stages, slot->first, slot->last, now, window);
        }
      }
      if (state->entity_stages != before) {
        changed = true;
      }
      if (state->has_binary != 0u) {
        entity_state *slot = entity_slot(handle, entity_binary, state->binary,
                                         now, false);
        if (slot != nullptr) {
          uint32_t prior = slot->stages;
          merge_window(slot->stages, slot->first, slot->last,
                       state->entity_stages, state->entity_first, state->entity_last,
                       now, window);
          if (slot->stages != prior) changed = true;
        }
      }
      if (state->has_peer != 0u) {
        entity_state *slot = entity_slot(handle, entity_peer, state->peer,
                                         now, false);
        if (slot != nullptr) {
          uint32_t prior = slot->stages;
          merge_window(slot->stages, slot->first, slot->last,
                       state->entity_stages, state->entity_first, state->entity_last,
                       now, window);
          if (slot->stages != prior) changed = true;
        }
      }
      if (state->has_priv != 0u) {
        entity_state *slot = entity_slot(handle, entity_priv, state->priv,
                                         now, false);
        if (slot != nullptr) {
          uint32_t prior = slot->stages;
          merge_window(slot->stages, slot->first, slot->last,
                       state->entity_stages, state->entity_first, state->entity_last,
                       now, window);
          if (slot->stages != prior) changed = true;
        }
      }
    }
    if (!changed) {
      break;
    }
  }
}

uint32_t linked_classes(ap_flow_handle *handle, const pid_flow *state,
                        uint64_t now) {
  uint32_t classes = class_pid_bit;
  if (state->has_binary != 0u) {
    entity_state *slot = entity_slot(handle, entity_binary, state->binary,
                                     now, false);
    if (slot != nullptr && slot->stages != 0u &&
        window_fresh(slot->first, now, handle->entity_window_ns)) {
      classes |= class_binary_bit;
    }
  }
  if (state->has_peer != 0u) {
    entity_state *slot = entity_slot(handle, entity_peer, state->peer,
                                     now, false);
    if (slot != nullptr && slot->stages != 0u &&
        window_fresh(slot->first, now, handle->entity_window_ns)) {
      classes |= class_peer_bit;
    }
  }
  if (state->has_priv != 0u) {
    entity_state *slot = entity_slot(handle, entity_priv, state->priv,
                                     now, false);
    if (slot != nullptr && slot->stages != 0u &&
        window_fresh(slot->first, now, handle->entity_window_ns)) {
      classes |= class_priv_bit;
    }
  }
  return classes;
}

const char *stage_name(uint32_t bit) {
  switch (bit) {
    case AP_FLOW_STAGE_WX: return "wx";
    case AP_FLOW_STAGE_EXEC: return "exec";
    case AP_FLOW_STAGE_PRIV: return "priv";
    case AP_FLOW_STAGE_NET: return "net";
    default: return nullptr;
  }
}

void format_stages(uint32_t stages, char *out, size_t cap) {
  out[0] = '\0';
  for (uint32_t bit = 1u; bit != 0u && bit <= AP_FLOW_STAGE_ALL; bit <<= 1u) {
    if ((stages & bit) != 0u) {
      const char *name = stage_name(bit);
      if (name != nullptr) {
        append_label(out, cap, name);
      }
    }
  }
}

void format_classes(uint32_t classes, char *out, size_t cap) {
  out[0] = '\0';
  if ((classes & class_pid_bit) != 0u) append_label(out, cap, "pid");
  if ((classes & class_binary_bit) != 0u) append_label(out, cap, "binary");
  if ((classes & class_peer_bit) != 0u) append_label(out, cap, "peer");
  if ((classes & class_priv_bit) != 0u) append_label(out, cap, "priv");
}

void clear_entity_stages(ap_flow_handle *handle) {
  for (uint32_t i = 0; i < AP_FLOW_PID_SLOTS; ++i) {
    clear_window(handle->pids[i].entity_stages, handle->pids[i].entity_first,
                 handle->pids[i].entity_last);
  }
  for (uint32_t i = 0; i < AP_FLOW_ENTITY_SLOTS; ++i) {
    clear_window(handle->entities[i].stages, handle->entities[i].first,
                 handle->entities[i].last);
  }
}

void report_entity_chain(ap_flow_handle *handle, pid_flow *state,
                         const ap_event *event, ap_verdict *verdict,
                         uint32_t classes) {
  char stages[40];
  char links[60];
  char text[AP_TEXT_LEN];
  const char *link_detail = "none";
  if (state->has_peer != 0u) {
    link_detail = state->peer;
  } else if (state->has_priv != 0u) {
    link_detail = state->priv;
  } else if (state->has_binary != 0u) {
    link_detail = state->binary;
  }
  format_stages(state->entity_stages, stages, sizeof(stages));
  format_classes(classes, links, sizeof(links));
  copy_key(text, sizeof(text), "entity_chain:");
  append_text(text, sizeof(text), stages);
  append_text(text, sizeof(text), ":");
  append_text(text, sizeof(text), links);
  append_text(text, sizeof(text), ":");
  append_text(text, sizeof(text), link_detail);
  ++handle->counters.findings;
  ++handle->counters.entity_findings;
  set_verdict(verdict, event, AP_RULE_CORRELATED, AP_SEV_HIGH, 880u,
              state->entity_first, text);
  clear_entity_stages(handle);
}

void observe_stage(ap_flow_handle *handle, const ap_event *event,
                   uint32_t stage, uint64_t now, const char *binary,
                   const char *peer, const char *priv, ap_verdict *verdict) {
  pid_flow *state = flow_pid(handle, event->pid, nullptr);
  if (state == nullptr) {
    return;
  }
  ++handle->counters.entity_events;
  set_reference(state->binary, sizeof(state->binary), &state->has_binary,
                &state->binary_time, binary, now);
  set_reference(state->peer, sizeof(state->peer), &state->has_peer,
                &state->peer_time, peer, now);
  set_reference(state->priv, sizeof(state->priv), &state->has_priv,
                &state->priv_time, priv, now);
  merge_stage(state->entity_stages, state->entity_first, state->entity_last,
              stage, now, handle->entity_window_ns);
  if (state->has_binary != 0u) {
    entity_state *slot = entity_slot(handle, entity_binary, state->binary,
                                     now, true);
    if (slot != nullptr) {
      merge_stage(slot->stages, slot->first, slot->last, stage, now,
                  handle->entity_window_ns);
    }
  }
  if (state->has_peer != 0u) {
    entity_state *slot = entity_slot(handle, entity_peer, state->peer,
                                     now, true);
    if (slot != nullptr) {
      merge_stage(slot->stages, slot->first, slot->last, stage, now,
                  handle->entity_window_ns);
    }
  }
  if (state->has_priv != 0u) {
    entity_state *slot = entity_slot(handle, entity_priv, state->priv,
                                     now, true);
    if (slot != nullptr) {
      merge_stage(slot->stages, slot->first, slot->last, stage, now,
                  handle->entity_window_ns);
    }
  }
  closure(handle, now);
  if (state->entity_stages != AP_FLOW_STAGE_ALL ||
      !window_fresh(state->entity_first, now, handle->entity_window_ns)) {
    return;
  }
  uint32_t classes = linked_classes(handle, state, now);
  if (bit_count(classes) < 3u) {
    return;
  }
  report_entity_chain(handle, state, event, verdict, classes);
}

void observe_reference(ap_flow_handle *handle, const ap_event *event,
                       uint64_t now, const char *binary) {
  pid_flow *state = flow_pid(handle, event->pid, nullptr);
  if (state == nullptr) {
    return;
  }
  set_reference(state->binary, sizeof(state->binary), &state->has_binary,
                &state->binary_time, binary, now);
  closure(handle, now);
}

void report_correlation(ap_flow_handle *handle, pid_flow *state,
                        const ap_event *event, ap_verdict *verdict) {
  ++handle->counters.findings;
  set_verdict(verdict, event, AP_RULE_CORRELATED, AP_SEV_HIGH, 820u,
              state->weak_last, "wx_with_return_anomalies");
}

void report_kernel_chain(ap_flow_handle *handle, pid_flow *state,
                         const ap_event *event, ap_verdict *verdict) {
  char labels[80];
  char text[AP_TEXT_LEN];
  format_labels(state->kernel_mask, labels, sizeof(labels));
  std::snprintf(text, sizeof(text), "kernel_chain:%s", labels);
  ++handle->counters.findings;
  set_verdict(verdict, event, AP_RULE_KERNEL_CHAIN, AP_SEV_CRITICAL,
              (state->kernel_mask & kernel_bpf_bit) != 0u ? 880u : 850u,
              state->kernel_first, text);
}

void report_privilege_crossing(ap_flow_handle *handle, pid_flow *state,
                               const ap_event *event, ap_verdict *verdict) {
  char labels[80];
  char text[AP_TEXT_LEN];
  format_labels(state->priv_mask, labels, sizeof(labels));
  std::snprintf(text, sizeof(text), "privilege_crossing:%s", labels);
  ++handle->counters.findings;
  set_verdict(verdict, event, AP_RULE_PRIV_CROSSING, AP_SEV_HIGH, 860u,
              state->priv_first, text);
}

void report_persistence(ap_flow_handle *handle, pid_flow *state,
                        const ap_event *event, ap_verdict *verdict) {
  char labels[96];
  char text[AP_TEXT_LEN];
  format_named_bits(state->persist_mask, persist_label_name, labels, sizeof(labels));
  std::snprintf(text, sizeof(text), "persistence_chain:%s", labels);
  ++handle->counters.findings;
  set_verdict(verdict, event, AP_RULE_PERSISTENCE, AP_SEV_CRITICAL, 860u,
              state->persist_first, text);
  clear_window(state->persist_mask, state->persist_first, state->persist_last);
}

void report_container_escape(ap_flow_handle *handle, pid_flow *state,
                             const ap_event *event, ap_verdict *verdict) {
  char labels[96];
  char text[AP_TEXT_LEN];
  format_named_bits(state->container_mask, container_label_name, labels, sizeof(labels));
  std::snprintf(text, sizeof(text), "container_escape:%s", labels);
  ++handle->counters.findings;
  set_verdict(verdict, event, AP_RULE_CONTAINER_ESCAPE, AP_SEV_CRITICAL, 880u,
              state->container_first, text);
  clear_window(state->container_mask, state->container_first, state->container_last);
  // The same sensor events also feed the generic kernel mask. Drop it so a
  // later unrelated event cannot report a second, stale chain for this pid.
  state->kernel_mask = 0u;
  state->kernel_first = 0u;
}

}  // namespace

int ap_flow_feed(ap_flow_handle *handle, const ap_event *event, ap_verdict *verdict) {
  uint32_t index = 0;
  pid_flow *state;
  uint64_t now;

  if (handle == nullptr || event == nullptr || verdict == nullptr) {
    return AP_ERR_ARG;
  }
  ap_verdict_init(verdict, event->seq);
  ++handle->counters.events;
  now = event->ts_ns;

  if (event->kind == AP_KIND_MEMREGION) {
    if ((event->arg[2] & 4u) != 0u) {
      char binary[AP_FLOW_ENTITY_KEY_LEN];
      bool has_binary = extract_binary(event, binary, sizeof(binary));
      state = flow_pid(handle, event->pid, &index);
      if (state != nullptr) {
        put_range(state, event->arg[0], event->arg[1], &handle->range_count[index],
                  &handle->counters.evictions);
        ++handle->counters.ranges;
        if ((event->arg[2] & 2u) != 0u) {
          state->wx_time = now;
          set_verdict(verdict, event, AP_RULE_WX_REGION, AP_SEV_CRITICAL, 940u,
                      event->arg[0], "wx_mapping");
          ++handle->counters.findings;
        }
        if (std::strstr(event->text, "[stack]") != nullptr) {
          set_verdict(verdict, event, AP_RULE_STACK_EXEC, AP_SEV_CRITICAL, 960u,
                      event->arg[0], "executable_stack");
          ++handle->counters.findings;
        }
      }
      if ((event->arg[2] & 2u) != 0u) {
        observe_stage(handle, event, AP_FLOW_STAGE_WX, now,
                      has_binary ? binary : nullptr, nullptr, nullptr, verdict);
      }
    }
    return AP_OK;
  }

  if (event->kind == AP_KIND_MEMPROT) {
    uint64_t prot = event->arg[2];
    if ((prot & 2u) != 0u && (prot & 4u) != 0u) {
      state = flow_pid(handle, event->pid, &index);
      bool correlated = false;
      if (state != nullptr) {
        state->wx_time = event->ts_ns;
        correlated = add_weak(state, event->ts_ns);
      }
      set_verdict(verdict, event, AP_RULE_WX_TRANSITION, AP_SEV_CRITICAL, 930u,
                  prot, "wx_transition");
      ++handle->counters.findings;
      observe_stage(handle, event, AP_FLOW_STAGE_WX, now, nullptr, nullptr,
                    nullptr, verdict);
      if (correlated) {
        report_correlation(handle, state, event, verdict);
      }
    }
    return AP_OK;
  }

  if (event->kind == AP_KIND_EXEC) {
    char binary[AP_FLOW_ENTITY_KEY_LEN];
    bool has_binary = extract_binary(event, binary, sizeof(binary));
    state = flow_pid(handle, event->pid, &index);
    if (state != nullptr && state->wx_time != 0u && now >= state->wx_time &&
        now - state->wx_time <= wx_window_ns) {
      uint64_t evidence = state->wx_time;
      state->wx_time = 0u;
      set_verdict(verdict, event, AP_RULE_EXEC_AFTER_WX, AP_SEV_CRITICAL, 870u,
                  evidence, "exec_after_wx");
      ++handle->counters.findings;
    }
    observe_stage(handle, event, AP_FLOW_STAGE_EXEC, now,
                  has_binary ? binary : nullptr, nullptr, nullptr, verdict);
    return AP_OK;
  }

  if (event->kind == AP_KIND_PRIV) {
    uint32_t bit = priv_label_bit(event);
    if (bit == 0u) {
      return AP_OK;
    }
    char priv[AP_FLOW_ENTITY_KEY_LEN];
    bool has_priv = extract_priv(event, priv, sizeof(priv));
    state = flow_pid(handle, event->pid, &index);
    if (state == nullptr) {
      return AP_OK;
    }
    observe_privilege(state, now, bit);
    if (priv_chain_ready(state->priv_mask)) {
      report_privilege_crossing(handle, state, event, verdict);
      state->priv_mask = 0u;
    }
    if (has_priv) {
      observe_stage(handle, event, AP_FLOW_STAGE_PRIV, now, nullptr, nullptr,
                    priv, verdict);
    }
    return AP_OK;
  }

  if (event->kind == AP_KIND_KERNEL) {
    const bool from_ksensor = event->arg[3] == AP_KSENSOR_SOURCE_MARK;
    uint32_t bit = kernel_label_bit(event->text);
    if (from_ksensor) {
      bit |= ksensor_generic_bit(event->text);
      uint32_t persist_bit = persist_label_bit(event->text);
      uint32_t container_bit = container_label_bit(event->text);
      if (persist_bit != 0u || container_bit != 0u) {
        state = flow_pid(handle, event->pid, &index);
        if (state == nullptr) {
          return AP_OK;
        }
        if (persist_bit != 0u) {
          merge_stage(state->persist_mask, state->persist_first,
                      state->persist_last, persist_bit, now, kernel_window_ns);
        }
        if (container_bit != 0u) {
          merge_stage(state->container_mask, state->container_first,
                      state->container_last, container_bit, now, kernel_window_ns);
        }
        if (persistence_ready(state->persist_mask)) {
          report_persistence(handle, state, event, verdict);
          return AP_OK;
        }
        if (container_escape_ready(state->container_mask)) {
          report_container_escape(handle, state, event, verdict);
          return AP_OK;
        }
      }
    }
    if (bit == 0u) {
      return AP_OK;
    }
    state = flow_pid(handle, event->pid, &index);
    if (state == nullptr) {
      return AP_OK;
    }
    if (state->kernel_mask == 0u || now < state->kernel_first ||
        now - state->kernel_first > kernel_window_ns) {
      state->kernel_mask = 0u;
      state->kernel_first = now;
    }
    state->kernel_mask |= bit;
    observe_privilege(state, now, bit & kernel_stop_bits);
    if (kernel_chain_ready(state->kernel_mask)) {
      report_kernel_chain(handle, state, event, verdict);
      state->kernel_mask = 0u;
    } else if (priv_chain_ready(state->priv_mask)) {
      report_privilege_crossing(handle, state, event, verdict);
      state->priv_mask = 0u;
    }
    return AP_OK;
  }

  if (event->kind == AP_KIND_PROC) {
    char binary[AP_FLOW_ENTITY_KEY_LEN];
    if (extract_binary(event, binary, sizeof(binary))) {
      observe_reference(handle, event, now, binary);
    }
    return AP_OK;
  }

  if (event->kind == AP_KIND_NET) {
    char peer[AP_FLOW_ENTITY_KEY_LEN];
    if (extract_peer(event, peer, sizeof(peer))) {
      observe_stage(handle, event, AP_FLOW_STAGE_NET, now, nullptr, peer,
                    nullptr, verdict);
    }
    return AP_OK;
  }

  if (event->kind != AP_KIND_FLOW) {
    return AP_OK;
  }
  state = flow_pid(handle, event->pid, &index);
  if (state == nullptr) {
    return AP_OK;
  }
  state->last_seen = now;

  switch (event->subkind) {
    case AP_FLOW_SHADOW:
      if (state->depth > 0u) {
        uint64_t expected = state->shadow[state->depth - 1u];
        --state->depth;
        if (expected != event->arg[0]) {
          set_verdict(verdict, event, AP_RULE_SHADOW_MISMATCH, AP_SEV_HIGH, 900u,
                      event->arg[0], "shadow_mismatch");
          ++handle->counters.findings;
        }
      } else if (state->depth < AP_FLOW_SHADOW_DEPTH) {
        state->shadow[state->depth++] = event->arg[1];
      }
      break;
    case AP_FLOW_STACK:
      set_verdict(verdict, event, AP_RULE_STACK_EXEC, AP_SEV_CRITICAL, 920u,
                  event->arg[0], "stack_pointer_exec");
      ++handle->counters.findings;
      break;
    case AP_FLOW_RETURN_SITE:
      if (event->confidence_x1000 >= 800u) {
        if (!in_ranges(state, event->arg[0])) {
          set_verdict(verdict, event, AP_RULE_RETURN_OUTSIDE_EXEC, AP_SEV_HIGH, 880u,
                      event->arg[0], "return_outside_exec");
          ++handle->counters.findings;
        }
      } else if (add_weak(state, now)) {
        report_correlation(handle, state, event, verdict);
      }
      break;
    default:
      break;
  }
  return AP_OK;
}
