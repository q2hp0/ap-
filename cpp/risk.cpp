#include "aprisk.h"

#include <cstring>

namespace {

struct RiskEntity {
  bool used;
  char key[AP_RISK_KEY_LEN];
  ap_risk_signal signals[AP_RISK_SIGNALS];
  uint32_t cursor;
  uint32_t count;
  uint64_t last_finding;
};

struct RiskState {
  RiskEntity entities[AP_RISK_ENTITIES];
  uint64_t cursor;
  uint64_t added;
  uint64_t evicted;
  uint64_t findings;
  uint64_t suppressed;
};

bool high_rule(uint32_t rule) {
  return rule >= AP_RULE_KERNEL_ROOTKIT && rule <= AP_RULE_ANTI_ANALYSIS;
}

void copy_key(char out[AP_RISK_KEY_LEN], const char *key) {
  if (key == nullptr || key[0] == '\0') {
    out[0] = '\0';
    return;
  }
  std::size_t i = 0;
  for (; i + 1 < AP_RISK_KEY_LEN && key[i] != '\0'; ++i) out[i] = key[i];
  out[i] = '\0';
}

}  // namespace

struct ap_risk {
  RiskState state;
};

extern "C" ap_risk *ap_risk_new(void) {
  ap_risk *risk = new ap_risk;
  std::memset(&risk->state, 0, sizeof(risk->state));
  return risk;
}

extern "C" void ap_risk_free(ap_risk *risk) { delete risk; }

extern "C" void ap_risk_reset(ap_risk *risk) {
  if (risk == nullptr) return;
  std::memset(&risk->state, 0, sizeof(risk->state));
}

extern "C" int ap_risk_add(ap_risk *risk, const ap_risk_signal *signal) {
  if (risk == nullptr || signal == nullptr) return AP_ERR_ARG;
  if (signal->ts_ns == 0u) return AP_ERR_ARG;
  if (signal->key[0] == '\0') return AP_ERR_ARG;
  if (signal->rule == AP_RULE_NONE) return AP_ERR_ARG;

  RiskEntity *target = nullptr;
  for (uint32_t i = 0; i < AP_RISK_ENTITIES; ++i) {
    if (risk->state.entities[i].used &&
        std::strcmp(risk->state.entities[i].key, signal->key) == 0) {
      target = &risk->state.entities[i];
      break;
    }
  }
  if (target == nullptr) {
    uint32_t at = static_cast<uint32_t>(risk->state.cursor % AP_RISK_ENTITIES);
    target = &risk->state.entities[at];
    if (target->used) ++risk->state.evicted;
    std::memset(target, 0, sizeof(*target));
    target->used = true;
    copy_key(target->key, signal->key);
    ++risk->state.cursor;
  }

  target->signals[target->cursor] = *signal;
  copy_key(target->signals[target->cursor].key, signal->key);
  target->cursor = (target->cursor + 1u) % AP_RISK_SIGNALS;
  if (target->count < AP_RISK_SIGNALS) ++target->count;
  ++risk->state.added;
  return AP_OK;
}

extern "C" int ap_risk_evaluate(ap_risk *risk, uint64_t now_ns,
                                ap_risk_cb callback, void *user) {
  if (risk == nullptr || callback == nullptr) return AP_ERR_ARG;
  if (now_ns == 0u) return AP_ERR_ARG;

  for (uint32_t i = 0; i < AP_RISK_ENTITIES; ++i) {
    RiskEntity &entity = risk->state.entities[i];
    if (!entity.used || entity.count < 2u) continue;
    if (entity.last_finding != 0u && now_ns >= entity.last_finding &&
        now_ns - entity.last_finding < AP_RISK_SUPPRESS_NS) {
      ++risk->state.suppressed;
      continue;
    }

    uint32_t score = 0u;
    uint32_t signals = 0u;
    uint32_t tactics = 0u;
    uint32_t high_rules = 0u;
    uint64_t newest = 0u;
    for (uint32_t j = 0; j < entity.count; ++j) {
      const ap_risk_signal &signal = entity.signals[j];
      if (signal.ts_ns == 0u || now_ns < signal.ts_ns) continue;
      if (now_ns - signal.ts_ns > AP_RISK_WINDOW_NS) continue;
      score += signal.confidence_x1000;
      if (signal.tactic != 0u && signal.tactic < 32u)
        tactics |= 1u << signal.tactic;
      if (high_rule(signal.rule)) ++high_rules;
      ++signals;
      if (signal.ts_ns > newest) newest = signal.ts_ns;
    }
    if (signals < 2u || score < AP_RISK_THRESHOLD || high_rules == 0u) continue;
    {
      uint32_t tactic_count = 0u;
      for (uint32_t bit = 1u; bit < 32u; ++bit) {
        if ((tactics & (1u << bit)) != 0u) ++tactic_count;
      }
      if (tactic_count < 2u) continue;
    }

    ap_risk_finding finding;
    std::memset(&finding, 0, sizeof(finding));
    finding.ts_ns = newest;
    finding.score_x1000 = score > 1000000u ? 1000000u : score;
    finding.signals = signals;
    finding.tactics = tactics;
    finding.high_rules = high_rules;
    copy_key(finding.key, entity.key);
    if (callback(&finding, user) == AP_OK) ++risk->state.findings;
    entity.last_finding = newest;
  }
  return AP_OK;
}
