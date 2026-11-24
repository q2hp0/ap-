#include "apevidence.h"

#include <stdio.h>
#include <string.h>

static uint64_t ap_evidence_hash(const char *key) {
  uint64_t hash = 1469598103934665603ULL;
  size_t i;
  if (key == NULL) return 0u;
  for (i = 0u; key[i] != '\0' && i < AP_EVIDENCE_KEY_LEN; ++i) {
    hash ^= (uint64_t)(unsigned char)key[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static void ap_evidence_copy(char out[AP_EVIDENCE_KEY_LEN], const char *key) {
  size_t i;
  if (key == NULL || key[0] == '\0') {
    out[0] = '\0';
    return;
  }
  for (i = 0u; i + 1u < AP_EVIDENCE_KEY_LEN && key[i] != '\0'; ++i) {
    out[i] = key[i];
  }
  out[i] = '\0';
}

void ap_evidence_init(ap_evidence *ledger) {
  if (ledger != NULL) memset(ledger, 0, sizeof(*ledger));
}

int ap_evidence_add(ap_evidence *ledger, uint64_t ts_ns, int64_t pid,
                    uint32_t rule, uint32_t confidence_x1000, const char *key) {
  uint32_t at;
  char copy[AP_EVIDENCE_KEY_LEN];

  if (ledger == NULL || ts_ns == 0u || rule == AP_RULE_NONE) return AP_ERR_ARG;
  ap_evidence_copy(copy, key);
  if (copy[0] == '\0') return AP_ERR_ARG;

  at = (uint32_t)(ledger->cursor % AP_EVIDENCE_SLOTS);
  if (ledger->records[at].used != 0u) ++ledger->evicted;
  ledger->records[at].ts_ns = ts_ns;
  ledger->records[at].hash = ap_evidence_hash(copy);
  ledger->records[at].pid = pid;
  ledger->records[at].rule = rule;
  ledger->records[at].confidence_x1000 =
      confidence_x1000 > 1000u ? 1000u : confidence_x1000;
  ledger->records[at].used = 1u;
  ap_evidence_copy(ledger->records[at].key, copy);
  ++ledger->cursor;
  ++ledger->inserted;
  return AP_OK;
}

int ap_evidence_add_once(ap_evidence *ledger, uint64_t ts_ns, int64_t pid,
                         uint32_t rule, uint32_t confidence_x1000,
                         const char *key) {
  if (ap_evidence_is_duplicate(ledger, ts_ns, rule, key) != 0) {
    if (ledger != NULL) ++ledger->duplicates;
    return AP_ERR_REPLAY;
  }
  return ap_evidence_add(ledger, ts_ns, pid, rule, confidence_x1000, key);
}

int ap_evidence_is_duplicate(const ap_evidence *ledger, uint64_t now_ns,
                             uint32_t rule, const char *key) {
  uint64_t hash;
  uint32_t i;

  if (ledger == NULL || now_ns == 0u || rule == AP_RULE_NONE) return 0;
  hash = ap_evidence_hash(key);
  if (hash == 0u) return 0;

  for (i = 0u; i < AP_EVIDENCE_SLOTS; ++i) {
    const ap_evidence_record *record = &ledger->records[i];
    if (record->used == 0u || record->hash != hash || record->rule != rule)
      continue;
    if (strcmp(record->key, key) != 0) continue;
    if (now_ns >= record->ts_ns && now_ns - record->ts_ns < AP_EVIDENCE_DEDUP_NS)
      return 1;
  }
  return 0;
}

void ap_evidence_stats(const ap_evidence *ledger, uint64_t *inserted,
                       uint64_t *duplicates, uint64_t *evicted) {
  if (ledger == NULL) return;
  if (inserted != NULL) *inserted = ledger->inserted;
  if (duplicates != NULL) *duplicates = ledger->duplicates;
  if (evicted != NULL) *evicted = ledger->evicted;
}
