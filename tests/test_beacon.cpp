#include "apbeacon.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;
ap_beacon_finding last;

void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "beacon test fail: %s\n", name);
    ++failures;
  }
}

int on_finding(const ap_beacon_finding *finding, void *user) {
  int *count = static_cast<int *>(user);
  if (finding == nullptr || count == nullptr) return AP_ERR_ARG;
  last = *finding;
  ++(*count);
  return AP_OK;
}

void add(ap_beacon *beacon, uint64_t ts, const char *peer, uint32_t bytes) {
  ap_beacon_observation observation;
  std::memset(&observation, 0, sizeof(observation));
  observation.ts_ns = ts;
  observation.bytes_out = bytes;
  std::strncpy(observation.peer, peer, sizeof(observation.peer) - 1u);
  check(ap_beacon_add(beacon, &observation) == AP_OK, "add observation");
}

}  // namespace

int main() {
  ap_beacon *beacon = ap_beacon_new();
  check(beacon != nullptr, "allocate analyzer");
  if (beacon == nullptr) return 1;

  int findings = 0;
  check(ap_beacon_add(nullptr, nullptr) == AP_ERR_ARG, "null add");
  check(ap_beacon_evaluate(beacon, 0u, on_finding, &findings) == AP_ERR_ARG,
        "zero time");
  check(ap_beacon_evaluate(beacon, 1000u, nullptr, &findings) == AP_ERR_ARG,
        "null callback");

  add(beacon, 1000000000ULL, "198.51.100.7:443", 512u);
  add(beacon, 31000000000ULL, "198.51.100.7:443", 518u);
  add(beacon, 61000000000ULL, "198.51.100.7:443", 508u);
  check(ap_beacon_evaluate(beacon, 62000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate periodic peer");
  check(findings == 1, "one periodic finding");
  check(last.connections == 3u, "three samples in finding");
  check(last.bytes_out == 1538u, "byte total");
  check(last.jitter_ns < 300000000ULL, "low periodic jitter");
  check(std::strcmp(last.peer, "198.51.100.7:443") == 0, "finding peer");

  check(ap_beacon_evaluate(beacon, 63000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate repeat");
  check(findings == 1, "repeat suppressed");

  ap_beacon_reset(beacon);
  add(beacon, 1000000000ULL, "203.0.113.9:8443", 700u);
  add(beacon, 2000000000ULL, "203.0.113.9:8443", 100u);
  add(beacon, 62000000000ULL, "203.0.113.9:8443", 700u);
  check(ap_beacon_evaluate(beacon, 63000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate jittered peer");
  check(findings == 1, "jittered peer rejected");

  ap_beacon_reset(beacon);
  add(beacon, 1000000000ULL, "192.0.2.4:53", 0u);
  add(beacon, 31000000000ULL, "192.0.2.4:53", 0u);
  add(beacon, 61000000000ULL, "192.0.2.4:53", 0u);
  check(ap_beacon_evaluate(beacon, 62000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate empty peer");
  check(findings == 1, "zero-byte peer rejected");

  ap_beacon_reset(beacon);
  check(ap_beacon_evaluate(beacon, 1000u, on_finding, &findings) == AP_OK,
        "evaluate empty analyzer");
  check(findings == 1, "empty analyzer stays quiet");

  ap_beacon_free(beacon);
  ap_beacon_free(nullptr);
  ap_beacon_reset(nullptr);

  std::printf("beacon tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
