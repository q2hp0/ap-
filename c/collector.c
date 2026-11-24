#define _GNU_SOURCE
#include "apcollector.h"
#include "apsys.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AP_COLLECTOR_WX_REPEAT_NS 10000000000ull
#define AP_COLLECTOR_IO_MIN_WRITE_BYTES 8192ull
#define AP_COLLECTOR_IO_MIN_WRITE_CALLS 8ull
#define AP_COLLECTOR_IO_MIN_READ_BYTES 8192ull

typedef struct ap_proc_state {
  int64_t pid;
  uint64_t starttime;
  uint64_t last_seen;
  uint64_t wx_hash;
  uint64_t wx_time;
  ap_proc_io io;
  uint32_t uid;
  uint32_t euid;
  char comm[64];
  int has_io;
  int used;
} ap_proc_state;

struct ap_collector {
  ap_proc_state pids[AP_COLLECTOR_MAX_PIDS];
  pid_t order[AP_COLLECTOR_MAX_PIDS];

  ap_collector_counters counters;
  uint32_t max_pids;
  uint32_t map_samples;
  uint32_t wx_per_scan;
  uint32_t io_per_scan;
  uint32_t generation;
  uint32_t map_cursor;
  uint32_t io_cursor;
  uint64_t seq;
  int baseline;
};

typedef struct ap_map_context {
  ap_collector *collector;
  ap_proc_state *state;
  ap_collector_cb callback;
  void *user;
  uint64_t now_ns;
  uint32_t emitted;
} ap_map_context;

static uint64_t ap_hash_update(uint64_t hash, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t i;
  for (i = 0u; i < len; ++i) {
    hash ^= (uint64_t)bytes[i];
    hash *= 1099511628211ull;
  }
  return hash;
}

static int ap_pid_from_name(const char *name, pid_t *out) {
  char *end = NULL;
  long value;

  if (name == NULL || name[0] < '0' || name[0] > '9') {
    return 0;
  }
  errno = 0;
  value = strtol(name, &end, 10);
  if (errno != 0 || end == name || *end != '\0' || value <= 0 || value > INT_MAX) {
    return 0;
  }
  *out = (pid_t)value;
  return 1;
}

static int ap_pid_compare(const void *left, const void *right) {
  pid_t a = *(const pid_t *)left;
  pid_t b = *(const pid_t *)right;
  if (a > b) return -1;
  if (a < b) return 1;
  return 0;
}

static ap_proc_state *ap_find_state(ap_collector *collector, pid_t pid) {
  uint32_t i;
  for (i = 0u; i < collector->max_pids; ++i) {
    if (collector->pids[i].used != 0 && collector->pids[i].pid == (int64_t)pid) {
      return &collector->pids[i];
    }
  }
  return NULL;
}

static ap_proc_state *ap_take_state(ap_collector *collector) {
  uint32_t i;
  uint32_t oldest = collector->max_pids;

  for (i = 0u; i < collector->max_pids; ++i) {
    if (collector->pids[i].used == 0) {
      memset(&collector->pids[i], 0, sizeof(collector->pids[i]));
      return &collector->pids[i];
    }
    if (oldest == collector->max_pids ||
        collector->pids[i].last_seen < collector->pids[oldest].last_seen) {
      oldest = i;
    }
  }
  if (oldest == collector->max_pids) {
    return NULL;
  }
  ++collector->counters.evictions;
  memset(&collector->pids[oldest], 0, sizeof(collector->pids[oldest]));
  return &collector->pids[oldest];
}

static void ap_collector_emit(ap_collector *collector, uint64_t now_ns,
                              ap_collector_cb callback, void *user,
                              uint16_t kind, uint32_t subkind, int64_t pid,
                              uint32_t severity, uint32_t confidence,
                              uint64_t arg0, uint64_t arg1, uint64_t arg2,
                              uint64_t arg3, const char *text) {
  ap_event event;

  if (callback == NULL) {
    return;
  }
  ap_event_init(&event, kind);
  event.seq = ++collector->seq;
  event.ts_ns = now_ns != 0u ? now_ns : ap_clock_ns();
  event.pid = pid;
  event.tid = pid;
  event.subkind = subkind;
  event.severity = severity;
  event.confidence_x1000 = confidence;
  event.arg[0] = arg0;
  event.arg[1] = arg1;
  event.arg[2] = arg2;
  event.arg[3] = arg3;
  if (text != NULL) {
    snprintf(event.text, sizeof(event.text), "%s", text);
  }
  (void)callback(&event, user);
}

static void ap_emit_exit(ap_collector *collector, ap_proc_state *state,
                         uint64_t now_ns, ap_collector_cb callback, void *user) {
  ap_collector_emit(collector, now_ns, callback, user, AP_KIND_PROC,
                    AP_PROC_EXIT, state->pid, AP_SEV_MEDIUM, 650u,
                    state->starttime, 0u, 0u, 0u, state->comm);
  ++collector->counters.exits;
}

static uint64_t ap_region_hash(const ap_event *region) {
  uint64_t hash = 1469598103934665603ull;
  uint64_t values[4];
  size_t text_len;

  values[0] = (uint64_t)region->pid;
  values[1] = region->arg[0];
  values[2] = region->arg[1];
  values[3] = region->arg[3];
  hash = ap_hash_update(hash, values, sizeof(values));
  text_len = strnlen(region->text, sizeof(region->text));
  return ap_hash_update(hash, region->text, text_len);
}

static int ap_wx_map_callback(const ap_event *region, void *user) {
  ap_map_context *context = (ap_map_context *)user;
  uint32_t bits;
  uint64_t hash;

  if (context == NULL || context->state == NULL) {
    return 1;
  }
  bits = (uint32_t)region->arg[2];
  if ((bits & 2u) == 0u || (bits & 4u) == 0u) {
    return 0;
  }
  hash = ap_region_hash(region);
  if (context->state->wx_hash == hash && context->now_ns >= context->state->wx_time &&
      context->now_ns - context->state->wx_time <= AP_COLLECTOR_WX_REPEAT_NS) {
    return 0;
  }
  context->state->wx_hash = hash;
  context->state->wx_time = context->now_ns;
  ap_collector_emit(context->collector, context->now_ns, context->callback,
                    context->user, AP_KIND_MEMREGION, 2u, region->pid,
                    AP_SEV_CRITICAL, 920u, region->arg[0], region->arg[1],
                    region->arg[2], region->arg[3], region->text);
  ++context->collector->counters.wx_regions;
  ++context->emitted;
  return context->emitted >= context->collector->wx_per_scan ? 1 : 0;
}

int ap_collector_scan_pid_maps(ap_collector *collector, int64_t pid,
                               uint64_t now_ns, ap_collector_cb callback, void *user) {
  ap_proc_state *state;
  ap_map_context context;

  if (collector == NULL || callback == NULL || pid <= 0) {
    return AP_ERR_ARG;
  }
  state = ap_find_state(collector, (pid_t)pid);
  if (state == NULL) {
    return AP_ERR_STATE;
  }
  context.collector = collector;
  context.state = state;
  context.callback = callback;
  context.user = user;
  context.now_ns = now_ns;
  context.emitted = 0u;
  return ap_sys_read_maps((pid_t)pid, ap_wx_map_callback, &context);
}

static uint64_t ap_counter_delta(uint64_t now, uint64_t prior) {
  return now >= prior ? now - prior : 0u;
}

static void ap_scan_proc_io(ap_collector *collector, ap_proc_state *state,
                            uint64_t now_ns, ap_collector_cb callback, void *user) {
  ap_proc_io current;
  uint64_t write_bytes;
  uint64_t write_calls;
  uint64_t read_bytes;
  uint64_t read_chars;

  if (ap_sys_proc_io((pid_t)state->pid, &current) != AP_OK) {
    ++collector->counters.file_errors;
    return;
  }
  ++collector->counters.file_samples;
  if (state->has_io == 0) {
    state->io = current;
    state->has_io = 1;
    return;
  }
  write_bytes = ap_counter_delta(current.wchar, state->io.wchar);
  write_calls = ap_counter_delta(current.syscw, state->io.syscw);
  read_bytes = ap_counter_delta(current.read_bytes, state->io.read_bytes);
  read_chars = ap_counter_delta(current.rchar, state->io.rchar);
  state->io = current;
  if (write_bytes < AP_COLLECTOR_IO_MIN_WRITE_BYTES &&
      write_calls < AP_COLLECTOR_IO_MIN_WRITE_CALLS &&
      read_bytes < AP_COLLECTOR_IO_MIN_READ_BYTES) {
    return;
  }
  ap_collector_emit(collector, now_ns, callback, user, AP_KIND_FILE, AP_FILE_IO,
                    state->pid, AP_SEV_LOW, 650u, write_bytes, write_calls,
                    read_chars, read_bytes, state->comm);
  ++collector->counters.file_events;
}

int ap_collector_scan_pid_io(ap_collector *collector, int64_t pid,
                             uint64_t now_ns, ap_collector_cb callback, void *user) {
  ap_proc_state *state;

  if (collector == NULL || callback == NULL || pid <= 0) {
    return AP_ERR_ARG;
  }
  state = ap_find_state(collector, (pid_t)pid);
  if (state == NULL) {
    return AP_ERR_STATE;
  }
  ap_scan_proc_io(collector, state, now_ns, callback, user);
  return AP_OK;
}

ap_collector *ap_collector_new(uint32_t max_pids) {
  ap_collector *collector;

  if (max_pids == 0u || max_pids > AP_COLLECTOR_MAX_PIDS) {
    return NULL;
  }
  collector = (ap_collector *)calloc(1u, sizeof(*collector));
  if (collector == NULL) {
    return NULL;
  }
  collector->max_pids = max_pids;
  collector->map_samples = AP_COLLECTOR_DEFAULT_MAPS_PER_SCAN;
  collector->wx_per_scan = AP_COLLECTOR_DEFAULT_WX_PER_SCAN;
  collector->io_per_scan = AP_COLLECTOR_DEFAULT_IO_PER_SCAN;
  collector->baseline = 1;
  return collector;
}

int ap_collector_set_map_limits(ap_collector *collector, uint32_t map_samples,
                                uint32_t wx_per_scan) {
  if (collector == NULL || map_samples == 0u ||
      map_samples > AP_COLLECTOR_MAX_MAPS_PER_SCAN || wx_per_scan == 0u ||
      wx_per_scan > AP_COLLECTOR_MAX_WX_PER_SCAN) {
    return AP_ERR_ARG;
  }
  collector->map_samples = map_samples;
  collector->wx_per_scan = wx_per_scan;
  return AP_OK;
}

int ap_collector_map_limits(const ap_collector *collector, uint32_t *map_samples,
                            uint32_t *wx_per_scan) {
  if (collector == NULL || map_samples == NULL || wx_per_scan == NULL) {
    return AP_ERR_ARG;
  }
  *map_samples = collector->map_samples;
  *wx_per_scan = collector->wx_per_scan;
  return AP_OK;
}

int ap_collector_set_io_per_scan(ap_collector *collector, uint32_t io_per_scan) {
  if (collector == NULL || io_per_scan == 0u ||
      io_per_scan > AP_COLLECTOR_MAX_IO_PER_SCAN) {
    return AP_ERR_ARG;
  }
  collector->io_per_scan = io_per_scan;
  return AP_OK;
}

int ap_collector_io_per_scan(const ap_collector *collector, uint32_t *io_per_scan) {
  if (collector == NULL || io_per_scan == NULL) {
    return AP_ERR_ARG;
  }
  *io_per_scan = collector->io_per_scan;
  return AP_OK;
}

void ap_collector_free(ap_collector *collector) {
  free(collector);
}

int ap_collector_stats(const ap_collector *collector, ap_collector_counters *out) {
  if (collector == NULL || out == NULL) {
    return AP_ERR_ARG;
  }
  *out = collector->counters;
  return AP_OK;
}

int ap_collector_scan(ap_collector *collector, uint64_t now_ns,
                      ap_collector_cb callback, void *user) {
  DIR *dir;
  struct dirent *entry;
  uint32_t count = 0u;
  uint32_t i;
  uint32_t attempts = 0u;
  uint32_t checked = 0u;
  uint32_t io_attempts = 0u;
  uint32_t io_checked = 0u;
  int baseline;

  if (collector == NULL || callback == NULL) {
    return AP_ERR_ARG;
  }
  ++collector->counters.scans;
  ++collector->generation;
  if (collector->generation == 0u) {
    for (i = 0u; i < collector->max_pids; ++i) {
      collector->pids[i].last_seen = 0u;
    }
    collector->generation = 1u;
  }
  baseline = collector->baseline;

  dir = opendir("/proc");
  if (dir == NULL) {
    ++collector->counters.errors;
    return AP_ERR_IO;
  }
  while ((entry = readdir(dir)) != NULL && count < AP_COLLECTOR_MAX_PIDS) {
    pid_t pid;
    if (!ap_pid_from_name(entry->d_name, &pid) || pid == getpid()) {
      continue;
    }
    collector->order[count++] = pid;
  }
  closedir(dir);
  qsort(collector->order, count, sizeof(collector->order[0]), ap_pid_compare);
  if (count > collector->max_pids) {
    count = collector->max_pids;
  }

  for (i = 0u; i < count; ++i) {
    pid_t pid = collector->order[i];
    uint64_t starttime = 0u;
    uint32_t uid = 0u;
    uint32_t euid = 0u;
    char comm[64];
    ap_proc_state *state;

    if (ap_sys_proc_starttime(pid, &starttime) != AP_OK ||
        ap_sys_proc_uid(pid, &uid, &euid) != AP_OK ||
        ap_sys_proc_comm(pid, comm, sizeof(comm)) != AP_OK) {
      ++collector->counters.errors;
      continue;
    }
    ++collector->counters.pids_seen;
    state = ap_find_state(collector, pid);
    if (state != NULL && state->starttime != starttime) {
      if (baseline == 0) {
        ap_emit_exit(collector, state, now_ns, callback, user);
      }
      memset(state, 0, sizeof(*state));
      state = NULL;
    }
    if (state == NULL) {
      state = ap_take_state(collector);
      if (state == NULL) {
        continue;
      }
      state->used = 1;
      state->pid = (int64_t)pid;
      state->starttime = starttime;
      state->uid = uid;
      state->euid = euid;
      snprintf(state->comm, sizeof(state->comm), "%s", comm);
      if (baseline == 0) {
        ap_collector_emit(collector, now_ns, callback, user, AP_KIND_PROC,
                          AP_PROC_START, state->pid, AP_SEV_MEDIUM, 650u,
                          starttime, 0u, 0u, 0u, comm);
        ++collector->counters.starts;
      }
    } else {
      if (baseline == 0 && strcmp(state->comm, comm) != 0) {
        uint64_t old_hash = ap_hash_update(1469598103934665603ull,
                                           state->comm, strlen(state->comm));
        uint64_t new_hash = ap_hash_update(1469598103934665603ull,
                                           comm, strlen(comm));
        ap_collector_emit(collector, now_ns, callback, user, AP_KIND_EXEC,
                          AP_PROC_EXEC_COMM, state->pid, AP_SEV_MEDIUM, 400u,
                          old_hash, new_hash, 0u, 0u, comm);
        ++collector->counters.execs;
      }
      if (baseline == 0 && (state->uid != uid || state->euid != euid)) {
        ap_collector_emit(collector, now_ns, callback, user, AP_KIND_PRIV,
                          2u, state->pid, AP_SEV_HIGH, 800u,
                          state->uid, uid, state->euid, euid, comm);
        ++collector->counters.priv_changes;
      }
      state->uid = uid;
      state->euid = euid;
      snprintf(state->comm, sizeof(state->comm), "%s", comm);
    }
    state->last_seen = collector->generation;
  }

  if (baseline == 0) {
    for (i = 0u; i < collector->max_pids; ++i) {
      ap_proc_state *state = &collector->pids[i];
      if (state->used != 0 && state->last_seen != collector->generation) {
        ap_emit_exit(collector, state, now_ns, callback, user);
        memset(state, 0, sizeof(*state));
      }
    }
  }
  collector->baseline = 0;

  while (checked < collector->map_samples && attempts < collector->max_pids) {
    ap_proc_state *state;
    collector->map_cursor = (collector->map_cursor + 1u) % collector->max_pids;
    state = &collector->pids[collector->map_cursor];
    ++attempts;
    if (state->used == 0) {
      continue;
    }
    (void)ap_collector_scan_pid_maps(collector, state->pid, now_ns, callback, user);
    ++checked;
  }

  while (io_checked < collector->io_per_scan && io_attempts < collector->max_pids) {
    ap_proc_state *state;
    collector->io_cursor = (collector->io_cursor + 1u) % collector->max_pids;
    state = &collector->pids[collector->io_cursor];
    ++io_attempts;
    if (state->used == 0) {
      continue;
    }
    ap_scan_proc_io(collector, state, now_ns, callback, user);
    ++io_checked;
  }
  return AP_OK;
}
