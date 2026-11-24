#include "apdestructive.h"

#include <cstdio>
#include <cstring>
#include <new>

namespace {

constexpr uint64_t counter_max = ~0ull;
constexpr uint64_t burst_write_bytes = 1048576ull;
constexpr uint64_t burst_write_calls = 64u;
constexpr uint64_t exfil_read_bytes = 4194304ull;
constexpr uint64_t exfil_read_chars = 8388608ull;
constexpr uint32_t file_action_threshold = 2u;

constexpr uint32_t bit_write = 1u << 0;
constexpr uint32_t bit_read = 1u << 1;
constexpr uint32_t bit_rename = 1u << 2;
constexpr uint32_t bit_unlink = 1u << 3;
constexpr uint32_t bit_chmod = 1u << 4;
constexpr uint32_t bit_net = 1u << 5;
constexpr uint32_t bit_handle = 1u << 6;
constexpr uint32_t action_bits = bit_rename | bit_unlink | bit_chmod | bit_handle;

static_assert(AP_DESTRUCTIVE_PID_SLOTS > 0u, "no pid slots");
static_assert(AP_DESTRUCTIVE_RESULTS >= 3u, "need three finding slots");
static_assert(AP_TEXT_LEN >= 48u, "detail buffer too small");

struct pid_destructive {
  int64_t pid;
  uint64_t first_ns;
  uint64_t last_ns;
  uint32_t mask;
  uint64_t write_bytes;
  uint64_t write_calls;
  uint64_t read_bytes;
  uint64_t read_chars;
  uint32_t actions;
  uint64_t last_burst_ns;
  uint64_t last_chain_ns;
  uint64_t last_exfil_ns;
  int used;
  int emitted_burst;
  int emitted_chain;
  int emitted_exfil;
};

struct candidate {
  uint32_t rule;
  uint32_t severity;
  uint32_t confidence;
  const char *prefix;
  uint64_t *last_ns;
  int *emitted;
};

void bump(uint64_t *value) {
  if (*value != counter_max) {
    ++*value;
  }
}

void add_saturating(uint64_t *value, uint64_t amount) {
  if (counter_max - *value < amount) {
    *value = counter_max;
  } else {
    *value += amount;
  }
}

bool window_fresh(uint64_t first, uint64_t now) {
  return now >= first && (now - first) <= AP_DESTRUCTIVE_WINDOW_NS;
}

uint32_t action_bit(const ap_event *event) {
  if (event->kind != AP_KIND_FILE || event->subkind != AP_FILE_ACTION) {
    return 0u;
  }
  const char *text = event->text;
  if (std::strcmp(text, "file_rename") == 0) return bit_rename;
  if (std::strcmp(text, "file_unlink") == 0) return bit_unlink;
  if (std::strcmp(text, "file_chmod") == 0) return bit_chmod;
  return 0u;
}

uint32_t stage_bit(const ap_event *event) {
  if (event->kind == AP_KIND_FILE && event->subkind == AP_FILE_IO) {
    uint32_t bits = 0u;
    if (event->arg[0] >= 4096u || event->arg[1] >= 4u) {
      bits |= bit_write;
    }
    if (event->arg[2] >= 4096u || event->arg[3] >= 4096u) {
      bits |= bit_read;
    }
    return bits;
  }
  if (event->kind == AP_KIND_NET && event->subkind == AP_NET_CONNECT) {
    return bit_net;
  }
  if (event->kind == AP_KIND_KERNEL &&
      std::strcmp(event->text, "open_by_handle_at") == 0) {
    return bit_handle;
  }
  return action_bit(event);
}

void merge_stage(pid_destructive *slot, const ap_event *event, uint32_t bits) {
  uint64_t now = event->ts_ns;
  if (!window_fresh(slot->first_ns, now)) {
    slot->mask = 0u;
    slot->write_bytes = 0u;
    slot->write_calls = 0u;
    slot->read_bytes = 0u;
    slot->read_chars = 0u;
    slot->actions = 0u;
    slot->first_ns = now;
    slot->emitted_burst = 0;
    slot->emitted_chain = 0;
    slot->emitted_exfil = 0;
  }
  slot->last_ns = now;
  slot->mask |= bits;
  if ((bits & bit_write) != 0u) {
    add_saturating(&slot->write_bytes, event->arg[0]);
    add_saturating(&slot->write_calls, event->arg[1]);
  }
  if ((bits & bit_read) != 0u) {
    add_saturating(&slot->read_chars, event->arg[2]);
    add_saturating(&slot->read_bytes, event->arg[3]);
  }
  if ((bits & action_bits) != 0u && slot->actions != 0xffffffffu) {
    ++slot->actions;
  }
}

const char *stage_name(uint32_t bit) {
  switch (bit) {
    case bit_write: return "write";
    case bit_read: return "read";
    case bit_rename: return "rename";
    case bit_unlink: return "unlink";
    case bit_chmod: return "chmod";
    case bit_net: return "net";
    case bit_handle: return "handle";
    default: return nullptr;
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

void format_detail(const char *prefix, const pid_destructive *slot, char *out, size_t cap) {
  out[0] = '\0';
  append_text(out, cap, prefix);
  for (uint32_t bit = 1u; bit <= bit_handle; bit <<= 1u) {
    if ((slot->mask & bit) == 0u) {
      continue;
    }
    append_text(out, cap, "+");
    append_text(out, cap, stage_name(bit));
  }
}

bool write_burst_ready(const pid_destructive *slot) {
  return slot->write_calls >= burst_write_calls ||
         (slot->write_bytes >= burst_write_bytes &&
          slot->write_calls >= 8u && (slot->mask & bit_write) != 0u);
}

bool chain_ready(const pid_destructive *slot) {
  return write_burst_ready(slot) && (slot->mask & action_bits) != 0u &&
         slot->actions >= file_action_threshold;
}

bool exfil_ready(const pid_destructive *slot) {
  return (slot->mask & bit_net) != 0u &&
         ((slot->mask & bit_read) != 0u &&
          (slot->read_bytes >= exfil_read_bytes || slot->read_chars >= exfil_read_chars));
}

bool suppressed_now(const candidate &item, uint64_t now) {
  return *item.emitted != 0 && now >= *item.last_ns &&
         (now - *item.last_ns) <= AP_DESTRUCTIVE_SUPPRESS_NS;
}

void set_verdict(ap_verdict *verdict, const ap_event *event, const candidate &item,
                 const char *detail, uint64_t evidence) {
  ap_verdict_init(verdict, event->seq);
  verdict->kind = AP_KIND_FILE;
  verdict->rule = item.rule;
  verdict->severity = item.severity;
  verdict->confidence_x1000 = item.confidence;
  verdict->evidence = evidence;
  std::snprintf(verdict->text, sizeof(verdict->text), "%s", detail);
}

}  // namespace

struct ap_destructive {
  pid_destructive pids[AP_DESTRUCTIVE_PID_SLOTS];
  ap_destructive_counters_t counters;
};

namespace {

pid_destructive *pid_slot(ap_destructive *handle, int64_t pid, uint64_t now) {
  pid_destructive *free_slot = nullptr;
  pid_destructive *oldest = nullptr;
  for (uint32_t i = 0u; i < AP_DESTRUCTIVE_PID_SLOTS; ++i) {
    pid_destructive *slot = &handle->pids[i];
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

ap_destructive *ap_destructive_new(void) {
  ap_destructive *handle = new (std::nothrow) ap_destructive;
  if (handle != nullptr) {
    std::memset(handle, 0, sizeof(*handle));
  }
  return handle;
}

void ap_destructive_free(ap_destructive *handle) {
  delete handle;
}

int ap_destructive_feed(ap_destructive *handle, const ap_event *event, ap_verdict *verdict) {
  if (verdict != nullptr) {
    ap_verdict_init(verdict, event != nullptr ? event->seq : 0u);
  }
  if (handle == nullptr || event == nullptr || verdict == nullptr) {
    return AP_ERR_ARG;
  }
  uint32_t bits = stage_bit(event);
  if (bits == 0u) {
    return AP_OK;
  }
  pid_destructive *slot = pid_slot(handle, event->pid, event->ts_ns);
  if (slot == nullptr) {
    return AP_OK;
  }
  merge_stage(slot, event, bits);

  candidate results[AP_DESTRUCTIVE_RESULTS];
  uint32_t count = 0u;
  if (chain_ready(slot)) {
    results[count].rule = AP_RULE_DESTRUCTIVE_CHAIN;
    results[count].severity = AP_SEV_CRITICAL;
    results[count].confidence = 900u;
    results[count].prefix = "destructive_chain:";
    results[count].last_ns = &slot->last_chain_ns;
    results[count].emitted = &slot->emitted_chain;
    ++count;
  }
  if (exfil_ready(slot)) {
    results[count].rule = AP_RULE_DATA_EXFILTRATION;
    results[count].severity = AP_SEV_HIGH;
    results[count].confidence = 880u;
    results[count].prefix = "data_exfiltration:";
    results[count].last_ns = &slot->last_exfil_ns;
    results[count].emitted = &slot->emitted_exfil;
    ++count;
  }
  if (write_burst_ready(slot)) {
    results[count].rule = AP_RULE_FILE_WRITE_BURST;
    results[count].severity = AP_SEV_HIGH;
    results[count].confidence = 870u;
    results[count].prefix = "file_write_burst:";
    results[count].last_ns = &slot->last_burst_ns;
    results[count].emitted = &slot->emitted_burst;
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
    set_verdict(verdict, event, choice, detail, evidence);
    bump(&handle->counters.findings);
    *choice.last_ns = event->ts_ns;
    *choice.emitted = 1;
    return AP_OK;
  }
  return AP_OK;
}

int ap_destructive_stats(const ap_destructive *handle, ap_destructive_counters_t *counters) {
  if (handle == nullptr || counters == nullptr) {
    return AP_ERR_ARG;
  }
  *counters = handle->counters;
  return AP_OK;
}

void ap_destructive_reset(ap_destructive *handle) {
  if (handle == nullptr) {
    return;
  }
  std::memset(handle, 0, sizeof(*handle));
}
