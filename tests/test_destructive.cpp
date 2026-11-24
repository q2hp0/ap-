#include "apdestructive.h"

#include <cstdio>
#include <cstring>

static int failures = 0;
static const uint64_t stage_step = 1000000000ull;

static void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "fail: %s\n", name);
    ++failures;
  }
}

static ap_verdict feed(ap_destructive *handle, uint64_t seq, int64_t pid,
                       uint64_t ts, uint16_t kind, uint32_t subkind,
                       uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                       const char *text) {
  ap_event event;
  ap_event_init(&event, kind);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = pid;
  event.tid = pid;
  event.subkind = subkind;
  event.severity = AP_SEV_LOW;
  event.confidence_x1000 = 650u;
  event.arg[0] = a;
  event.arg[1] = b;
  event.arg[2] = c;
  event.arg[3] = d;
  std::snprintf(event.text, sizeof(event.text), "%s", text);
  ap_verdict verdict;
  check(ap_destructive_feed(handle, &event, &verdict) == AP_OK, "feed ok");
  return verdict;
}

static ap_verdict write_event(ap_destructive *handle, uint64_t seq,
                              int64_t pid, uint64_t ts, uint64_t bytes,
                              uint64_t calls) {
  return feed(handle, seq, pid, ts, AP_KIND_FILE, AP_FILE_IO, bytes, calls,
              0u, 0u, "worker");
}

static ap_verdict read_event(ap_destructive *handle, uint64_t seq,
                             int64_t pid, uint64_t ts, uint64_t chars,
                             uint64_t bytes) {
  return feed(handle, seq, pid, ts, AP_KIND_FILE, AP_FILE_IO, 0u, 0u,
              chars, bytes, "worker");
}

static ap_verdict action_event(ap_destructive *handle, uint64_t seq,
                               int64_t pid, uint64_t ts, const char *label) {
  return feed(handle, seq, pid, ts, AP_KIND_FILE, AP_FILE_ACTION,
              7u, 9u, 0u, 0u, label);
}

static bool has_rule(const ap_verdict &verdict, uint32_t rule) {
  return verdict.rule == rule;
}

int main() {
  ap_destructive *handle = ap_destructive_new();
  check(handle != nullptr, "analyzer allocation");
  if (handle == nullptr) {
    return 1;
  }

  ap_verdict verdict = write_event(handle, 1, 42, stage_step, 2000000u, 100u);
  check(has_rule(verdict, AP_RULE_FILE_WRITE_BURST), "write burst fires");
  check(std::strncmp(verdict.text, "file_write_burst:", 17u) == 0,
        "write burst detail prefix");
  check(std::strstr(verdict.text, "write") != nullptr, "write stage detail");
  check(verdict.confidence_x1000 == 870u, "write burst confidence");
  check(verdict.severity == AP_SEV_HIGH, "write burst severity");
  verdict = write_event(handle, 2, 42, 2u * stage_step, 2000000u, 100u);
  check(verdict.rule == AP_RULE_NONE, "write burst suppressed");

  ap_destructive_reset(handle);
  write_event(handle, 3, 43, stage_step, 2000000u, 100u);
  verdict = action_event(handle, 4, 43, 2u * stage_step, "file_rename");
  check(verdict.rule == AP_RULE_NONE, "single action is not a chain");
  verdict = action_event(handle, 5, 43, 3u * stage_step, "file_unlink");
  check(has_rule(verdict, AP_RULE_DESTRUCTIVE_CHAIN), "destructive chain fires");
  check(std::strncmp(verdict.text, "destructive_chain:", 18u) == 0,
        "chain detail prefix");
  check(std::strstr(verdict.text, "rename") != nullptr, "rename stage detail");
  check(std::strstr(verdict.text, "unlink") != nullptr, "unlink stage detail");
  check(verdict.confidence_x1000 == 900u, "chain confidence");
  check(verdict.severity == AP_SEV_CRITICAL, "chain severity");

  ap_destructive_reset(handle);
  verdict = read_event(handle, 6, 44, stage_step, 9000000u, 6000000u);
  check(verdict.rule == AP_RULE_NONE, "read alone is not exfiltration");
  verdict = feed(handle, 7, 44, 2u * stage_step, AP_KIND_NET, AP_NET_CONNECT,
                 0u, 0u, 0u, 0u, "peer:10.0.0.9:443");
  check(has_rule(verdict, AP_RULE_DATA_EXFILTRATION), "exfiltration fires");
  check(std::strncmp(verdict.text, "data_exfiltration:", 18u) == 0,
        "exfiltration detail prefix");
  check(std::strstr(verdict.text, "read") != nullptr, "read stage in exfil detail");
  check(std::strstr(verdict.text, "net") != nullptr, "net stage in exfil detail");
  check(verdict.confidence_x1000 == 880u, "exfiltration confidence");

  ap_destructive_reset(handle);
  write_event(handle, 8, 45, stage_step, 2000000u, 100u);
  action_event(handle, 9, 45, 2u * stage_step, "file_chmod");
  verdict = action_event(handle, 10, 45, 30u * stage_step, "file_unlink");
  check(verdict.rule == AP_RULE_NONE, "expired window does not chain");

  ap_destructive_reset(handle);
  for (uint64_t i = 0u; i < 80u; ++i) {
    write_event(handle, 100u + i, 1000 + (int64_t)i, stage_step + i, 2000000u, 100u);
  }
  ap_destructive_counters_t counters;
  check(ap_destructive_stats(handle, &counters) == AP_OK, "stats ok");
  check(counters.added == 80u, "every new pid gets a slot");
  check(counters.evicted == 16u, "old slots are bounded");
  check(counters.findings == 80u, "each new pid emits one finding");
  check(counters.suppressed == 0u, "distinct pids are not suppressed");

  ap_destructive_reset(handle);
  check(ap_destructive_stats(handle, &counters) == AP_OK, "stats after reset");
  check(counters.added == 0u && counters.findings == 0u, "reset clears counters");
  check(ap_destructive_feed(handle, nullptr, &verdict) == AP_ERR_ARG,
        "null event rejected");
  check(ap_destructive_feed(handle, nullptr, nullptr) == AP_ERR_ARG,
        "null handle rejected");
  check(ap_destructive_stats(nullptr, &counters) == AP_ERR_ARG,
        "null stats rejected");
  ap_destructive_free(handle);

  std::printf("test destructive: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
