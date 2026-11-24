#include "apnet.h"

#include <cstdio>
#include <cstring>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "fail: %s\n", name);
    ++failures;
  }
}

static ap_verdict feed(ap_net_handle *handle, uint64_t seq, const char *hex) {
  ap_event event;
  ap_event_init(&event, AP_KIND_NET);
  event.seq = seq;
  event.ts_ns = 1000 + seq;
  event.pid = 77;
  event.subkind = AP_NET_PACKET;
  std::snprintf(event.text, sizeof(event.text), "%s", hex);
  ap_verdict verdict;
  ap_net_feed(handle, &event, &verdict);
  return verdict;
}

int main() {
  ap_net_handle *handle = ap_net_new();
  check(handle != nullptr, "handle allocation");
  ap_net_counters counters;

  ap_verdict bad_version = feed(handle, 1, "65000014000000004011a5c2c0a80101c0a80102");
  check(bad_version.rule == AP_RULE_IP_MALFORMED, "ip version");

  ap_verdict bad_length = feed(handle, 2, "45000064000000004011a5c2c0a80101c0a80102");
  check(bad_length.rule == AP_RULE_IP_MALFORMED, "ip length");

  ap_verdict syn_fin = feed(handle, 3,
      "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000");
  check(syn_fin.rule == AP_RULE_TCP_FLAGS &&
        std::strcmp(syn_fin.text, "syn_fin") == 0, "syn fin");

  ap_verdict reserved = feed(handle, 4,
      "45000028000000004006f77cc0a80101c0a80102050a0080000000000000000051f3ffff00000000");
  check(reserved.rule == AP_RULE_TCP_FLAGS, "reserved bits");

  feed(handle, 5, "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005002ffff00000000");
  feed(handle, 6, "45000028000000004006f77cc0a80102c0a801010080050a00000000000000015012ffff00000000");
  ap_verdict syn_again = feed(handle, 7,
      "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005002ffff00000000");
  check(syn_again.rule == AP_RULE_TCP_STATE, "syn in established");

  const char *frag = "4500001c123420004011c549c0a80101c0a801020800440000000000";
  ap_verdict first = feed(handle, 8, frag);
  check(first.rule == AP_RULE_NONE, "first fragment clean");
  ap_verdict overlap = feed(handle, 9, frag);
  check(overlap.rule == AP_RULE_FRAG_OVERLAP, "fragment overlap");

  ap_verdict invalid_hex = feed(handle, 10, "zzzz");
  check(invalid_hex.rule == AP_RULE_NONE, "invalid hex ignored");

  ap_verdict v6_bad_length = feed(handle, 11,
      "60000000003c114020010db800000000000000000000000120010db8000000000000000000000002");
  check(v6_bad_length.rule == AP_RULE_IP_MALFORMED &&
        std::strcmp(v6_bad_length.text, "ipv6_length") == 0, "ipv6 length");

  ap_verdict v6_syn_fin = feed(handle, 12,
      "600000000014064020010db800000000000000000000000120010db8000000000000000000000002"
      "050a008000000000000000005003ffff00000000");
  check(v6_syn_fin.rule == AP_RULE_TCP_FLAGS &&
        std::strcmp(v6_syn_fin.text, "syn_fin") == 0, "ipv6 syn fin");

  ap_verdict v6_udp_length = feed(handle, 13,
      "600000000008114020010db800000000000000000000000120010db8000000000000000000000002"
      "050a008000040000");
  check(v6_udp_length.rule == AP_RULE_IP_MALFORMED &&
        std::strcmp(v6_udp_length.text, "udp_length") == 0, "ipv6 udp length");

  const char *v6_frag =
      "6000000000102c4020010db800000000000000000000000120010db8000000000000000000000002"
      "1100000112345678050a008000080000";
  ap_verdict v6_first = feed(handle, 14, v6_frag);
  check(v6_first.rule == AP_RULE_NONE, "ipv6 first fragment clean");
  ap_verdict v6_overlap = feed(handle, 15, v6_frag);
  check(v6_overlap.rule == AP_RULE_FRAG_OVERLAP, "ipv6 fragment overlap");

  ap_verdict v6_ext_truncated = feed(handle, 16,
      "6000000000013a4020010db800000000000000000000000120010db8000000000000000000000002"
      "00");
  check(v6_ext_truncated.rule == AP_RULE_IP_MALFORMED &&
        std::strcmp(v6_ext_truncated.text, "ipv6_extension_truncated") == 0,
        "ipv6 extension truncated");

  for (int i = 0; i < 40; ++i) {
    (void)feed(handle, (uint64_t)(400 + i),
        "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000");
  }

  for (int i = 0; i < 600; ++i) {
    char hex[88];
    std::snprintf(hex, sizeof(hex),
                  "45000028000000004006f77cc0a80101c0a8%02x%02x%04x008000000000000000005002ffff00000000",
                  2, 2, (unsigned)(i & 0xffff));
    (void)feed(handle, (uint64_t)(100 + i), hex);
  }
  check(ap_net_stats(handle, &counters) == AP_OK, "stats call");
  check(counters.evictions > 0, "bounded flow table evicts");
  check(counters.invalid == 1, "invalid counter");
  check(counters.findings >= 11, "finding counter");
  check(counters.peers <= AP_NET_PEER_SLOTS, "bounded peer table");
  check(counters.peer_events > 0, "peer events");
  check(counters.peer_evictions > 0, "peer evictions");
  check(counters.peer_bursts > 0, "peer burst signal");
  check(counters.peer_exhaustion > 0, "peer exhaustion signal");

  check(ap_net_reset(handle) == AP_OK, "reset");
  check(ap_net_stats(handle, &counters) == AP_OK && counters.peers == 0, "peer reset");
  ap_net_free(handle);
  std::printf("net tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
