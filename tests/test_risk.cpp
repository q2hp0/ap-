#include "aprisk.h"

#include "apgraph.h"

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;
ap_risk_finding last;

void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "risk test fail: %s\n", name);
    ++failures;
  }
}

int on_finding(const ap_risk_finding *finding, void *user) {
  int *count = static_cast<int *>(user);
  if (finding == nullptr || count == nullptr) return AP_ERR_ARG;
  last = *finding;
  ++(*count);
  return AP_OK;
}

void add(ap_risk *risk, uint64_t ts, uint32_t rule, uint32_t tactic,
         uint32_t confidence, const char *key) {
  ap_risk_signal signal;
  std::memset(&signal, 0, sizeof(signal));
  signal.ts_ns = ts;
  signal.rule = rule;
  signal.tactic = tactic;
  signal.confidence_x1000 = confidence;
  std::strncpy(signal.key, key, sizeof(signal.key) - 1u);
  check(ap_risk_add(risk, &signal) == AP_OK, "add signal");
}

}  // namespace

int main() {
  ap_risk *risk = ap_risk_new();
  int findings = 0;
  check(risk != nullptr, "allocate accumulator");
  if (risk == nullptr) return 1;

  check(ap_risk_add(nullptr, nullptr) == AP_ERR_ARG, "null add");
  check(ap_risk_evaluate(risk, 0u, on_finding, &findings) == AP_ERR_ARG,
        "zero time");
  check(ap_risk_evaluate(risk, 1000u, nullptr, &findings) == AP_ERR_ARG,
        "null callback");

  add(risk, 1000000000ULL, AP_RULE_KERNEL_ROOTKIT,
      AP_GRAPH_TACTIC_DEFENSE_EVASION, 900u, "host-bravo");
  add(risk, 2000000000ULL, AP_RULE_CREDENTIAL_THEFT,
      AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, 870u, "host-bravo");
  check(ap_risk_evaluate(risk, 3000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate correlated risk");
  check(findings == 1, "one risk finding");
  check(last.score_x1000 == 1770u, "score sum");
  check(last.high_rules == 2u, "high rule count");
  check(std::strcmp(last.key, "host-bravo") == 0, "finding key");

  check(ap_risk_evaluate(risk, 4000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate repeat");
  check(findings == 1, "repeat suppressed");

  ap_risk_reset(risk);
  add(risk, 1000000000ULL, AP_RULE_CORRELATED, AP_GRAPH_TACTIC_DISCOVERY, 900u,
      "host-charlie");
  add(risk, 2000000000ULL, AP_RULE_CORRELATED, AP_GRAPH_TACTIC_DISCOVERY, 900u,
      "host-charlie");
  check(ap_risk_evaluate(risk, 3000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate low-risk entity");
  check(findings == 1, "no finding without high rules or tactic diversity");

  ap_risk_reset(risk);
  add(risk, 1000000000ULL, AP_RULE_KERNEL_ROOTKIT,
      AP_GRAPH_TACTIC_DEFENSE_EVASION, 700u, "host-delta");
  add(risk, 2000000000ULL, AP_RULE_CREDENTIAL_THEFT,
      AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, 700u, "host-delta");
  check(ap_risk_evaluate(risk, 3000000000ULL, on_finding, &findings) == AP_OK,
        "evaluate below-threshold entity");
  check(findings == 1, "below threshold stays quiet");

  ap_risk_free(risk);
  ap_risk_free(nullptr);
  ap_risk_reset(nullptr);

  std::printf("risk tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
