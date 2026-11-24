#include "apabi.h"
#include "apdestructive.h"
#include "apflow.h"
#include "apintrusion.h"
#include "apnet.h"

#include <cstdio>
#include <cstring>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "fuzz fail: %s\n", name);
    ++failures;
  }
}

class Rng {
 public:
  explicit Rng(uint64_t seed) : state_(seed == 0u ? 0x9e3779b97f4a7c15ull : seed) {}

  uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  uint32_t below(uint32_t n) {
    return n == 0u ? 0u : (uint32_t)(next() % (uint64_t)n);
  }

 private:
  uint64_t state_;
};

static bool terminated(const ap_verdict &verdict) {
  for (size_t i = 0; i < AP_TEXT_LEN; ++i) {
    if (verdict.text[i] == '\0') {
      return true;
    }
  }
  return false;
}

static bool valid_rule(uint32_t rule) {
  return rule <= AP_RULE_MAX;
}

static const char *const kernel_labels[] = {
    "module_load", "kexec", "mount", "namespace_change", "kernel_interface",
    "module_load_extra", "not_a_label", ""};

static const char *const file_labels[] = {
    "file_rename", "file_unlink", "file_chmod", "open_by_handle_at", "not_a_label", ""};

static const char *const seed_packets[] = {
    "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000",
    "4500001c123420004011c549c0a80101c0a801020800440000000000",
    "600000000014064020010db800000000000000000000000120010db8000000000000000000000002"
    "050a008000000000000000005003ffff00000000",
    "6000000000102c4020010db800000000000000000000000120010db8000000000000000000000002"
    "1100000112345678050a008000080000"
};

static void mutate(Rng &rng, char *text, size_t cap) {
  static const char hex[] = "0123456789abcdef";
  static const char junk[] = "gz![]:\0/ ";
  size_t len = std::strlen(text);

  switch (rng.below(6u)) {
    case 0u:
      if (len > 0u) {
        text[rng.below((uint32_t)len)] = hex[rng.below(16u)];
      }
      break;
    case 1u:
      if (len > 2u) {
        text[rng.below((uint32_t)len - 1u)] = '\0';
      }
      break;
    case 2u:
      while (len + 2u < cap) {
        text[len++] = hex[rng.below(16u)];
        text[len] = '\0';
        if (rng.below(4u) == 0u) {
          break;
        }
      }
      break;
    case 3u:
      if (len > 2u) {
        uint32_t at = rng.below((uint32_t)len - 1u);
        char tmp = text[at];
        text[at] = text[at + 1u];
        text[at + 1u] = tmp;
      }
      break;
    case 4u:
      if (len > 0u) {
        text[rng.below((uint32_t)len)] = junk[rng.below(sizeof(junk) - 1u)];
      }
      break;
    default:
      break;
  }
  text[cap - 1u] = '\0';
}

static void random_text(Rng &rng, char *text, size_t cap) {
  static const char chars[] = "0123456789abcdefgz![]:\0/ mprotect";
  size_t len = rng.below((uint32_t)cap - 1u);
  for (size_t i = 0; i < len; ++i) {
    text[i] = chars[rng.below(sizeof(chars) - 1u)];
  }
  text[len] = '\0';
}

int main() {
  static const uint32_t seeds[] = {0x41424344u, 0xdeadbeefu, 0xfeedfaceu};
  const uint32_t rounds = (uint32_t)(sizeof(seeds) / sizeof(seeds[0]));
  const uint32_t per_round = 10000u;
  const uint32_t iterations = rounds * per_round;
  ap_net_handle *net = ap_net_new();
  ap_flow_handle *flow = ap_flow_new();
  ap_intrusion *intrusion = ap_intrusion_new();
  ap_destructive *destructive = ap_destructive_new();
  check(net != nullptr && flow != nullptr && intrusion != nullptr && destructive != nullptr,
        "analyzer allocation");

  for (uint32_t round = 0; round < rounds; ++round) {
    Rng rng(seeds[round]);
    for (uint32_t i = 0; i < per_round; ++i) {
      uint32_t index = round * per_round + i;
    ap_event event;
    ap_verdict verdict;
    char text[AP_TEXT_LEN];
    uint64_t ts = 1000000ull + (uint64_t)index * 1000ull + rng.next() % 1000ull;
    if (rng.below(200u) == 0u) {
      ts += 6000000000ull;
    }

    ap_event_init(&event, AP_KIND_NET);
    event.seq = (uint64_t)index + 1u;
    event.pid = (int64_t)(rng.below(48u) + 1u);
    event.tid = event.pid;
    event.ts_ns = ts;
    event.subkind = AP_NET_PACKET;
    event.confidence_x1000 = rng.below(1001u);
    const char *seed = seed_packets[rng.below((uint32_t)(sizeof(seed_packets) / sizeof(seed_packets[0])))];
    std::snprintf(text, sizeof(text), "%s", seed);
    if (rng.below(4u) == 0u) {
      random_text(rng, text, sizeof(text));
    } else {
      mutate(rng, text, sizeof(text));
    }
    std::snprintf(event.text, sizeof(event.text), "%s", text);
    (void)ap_net_feed(net, &event, &verdict);
    check(terminated(verdict), "net verdict terminator");
    check(valid_rule(verdict.rule), "net verdict rule");
    (void)ap_intrusion_feed(intrusion, &event, &verdict);
    check(terminated(verdict), "intrusion verdict terminator");
    check(valid_rule(verdict.rule), "intrusion verdict rule");
    (void)ap_destructive_feed(destructive, &event, &verdict);
    check(terminated(verdict), "destructive verdict terminator");
    check(valid_rule(verdict.rule), "destructive verdict rule");

    uint32_t kind_pick = rng.below(12u);
    uint16_t kind = kind_pick < 2u    ? AP_KIND_MEMREGION
                    : kind_pick < 4u  ? AP_KIND_MEMPROT
                    : kind_pick < 6u  ? AP_KIND_FLOW
                    : kind_pick < 8u  ? AP_KIND_KERNEL
                                      : AP_KIND_FILE;
    ap_event_init(&event, kind);
    event.seq = (uint64_t)index + 1u;
    event.pid = (int64_t)(rng.below(48u) + 1u);
    event.tid = event.pid;
    event.ts_ns = rng.below(100u) == 0u && ts > 2000ull ? ts - rng.below(2000ull) : ts;
    event.subkind = rng.below(8u);
    event.severity = rng.below(8u);
    event.confidence_x1000 = rng.below(1001u);
    event.arg[0] = rng.next();
    event.arg[1] = rng.next();
    event.arg[2] = rng.next();
    event.arg[3] = rng.next();
    if (kind == AP_KIND_KERNEL && rng.below(2u) == 0u) {
      std::snprintf(event.text, sizeof(event.text), "%s",
                    kernel_labels[rng.below((uint32_t)(sizeof(kernel_labels) /
                                                      sizeof(kernel_labels[0])))]);
    } else if (kind == AP_KIND_FILE && rng.below(2u) == 0u) {
      event.subkind = AP_FILE_ACTION;
      std::snprintf(event.text, sizeof(event.text), "%s",
                    file_labels[rng.below((uint32_t)(sizeof(file_labels) /
                                                    sizeof(file_labels[0])))]);
    } else {
      if (kind == AP_KIND_FILE) {
        event.subkind = AP_FILE_IO;
      }
      random_text(rng, event.text, sizeof(event.text));
    }
    (void)ap_flow_feed(flow, &event, &verdict);
    check(terminated(verdict), "flow verdict terminator");
    check(valid_rule(verdict.rule), "flow verdict rule");
    (void)ap_intrusion_feed(intrusion, &event, &verdict);
    check(terminated(verdict), "intrusion verdict terminator");
    check(valid_rule(verdict.rule), "intrusion verdict rule");
    (void)ap_destructive_feed(destructive, &event, &verdict);
    check(terminated(verdict), "destructive verdict terminator");
    check(valid_rule(verdict.rule), "destructive verdict rule");
    }
  }

  ap_net_counters net_counters;
  ap_flow_counters flow_counters;
  ap_intrusion_counters_t intrusion_counters;
  ap_destructive_counters_t destructive_counters;
  check(ap_net_stats(net, &net_counters) == AP_OK, "net stats");
  check(ap_flow_stats(flow, &flow_counters) == AP_OK, "flow stats");
  check(ap_intrusion_stats(intrusion, &intrusion_counters) == AP_OK, "intrusion stats");
  check(ap_destructive_stats(destructive, &destructive_counters) == AP_OK, "destructive stats");
  check(net_counters.packets == iterations, "net event count");
  check(net_counters.findings <= iterations, "net finding bound");
  check(flow_counters.events == iterations, "flow event count");
  check(flow_counters.findings <= iterations, "flow finding bound");
  check(intrusion_counters.added <= iterations, "intrusion slot bound");
  check(intrusion_counters.findings <= iterations * 2u, "intrusion finding bound");
  check(destructive_counters.added <= iterations * 2u, "destructive slot bound");
  check(destructive_counters.findings <= iterations * 2u, "destructive finding bound");

  check(ap_net_reset(net) == AP_OK, "net reset");
  check(ap_flow_reset(flow) == AP_OK, "flow reset");
  ap_intrusion_reset(intrusion);
  ap_destructive_reset(destructive);
  ap_net_free(net);
  ap_flow_free(flow);
  ap_intrusion_free(intrusion);
  ap_destructive_free(destructive);
  std::printf("fuzz analyzers: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
