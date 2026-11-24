#include "apevidence.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "evidence test fail: %s\n", name);
    ++failures;
  }
}

int main(void) {
  ap_evidence ledger;
  uint64_t inserted = 0u;
  uint64_t duplicates = 0u;
  uint64_t evicted = 0u;
  uint32_t i;

  ap_evidence_init(&ledger);
  ap_evidence_stats(&ledger, &inserted, &duplicates, &evicted);
  check(inserted == 0u && duplicates == 0u && evicted == 0u,
        "initial stats");

  check(ap_evidence_add(&ledger, 1000u, 42, AP_RULE_KERNEL_ROOTKIT, 900u,
                        "host-alpha/rootkit") == AP_OK,
        "add record");
  check(ap_evidence_is_duplicate(&ledger, 2000u, AP_RULE_KERNEL_ROOTKIT,
                                 "host-alpha/rootkit") == 1,
        "detect duplicate");
  check(ap_evidence_add_once(&ledger, 2000u, 42, AP_RULE_KERNEL_ROOTKIT, 900u,
                             "host-alpha/rootkit") == AP_ERR_REPLAY,
        "reject duplicate add");
  check(ap_evidence_is_duplicate(&ledger, AP_EVIDENCE_DEDUP_NS + 2001u,
                                 AP_RULE_KERNEL_ROOTKIT,
                                 "host-alpha/rootkit") == 0,
        "duplicate expires");
  check(ap_evidence_is_duplicate(&ledger, 2000u, AP_RULE_CREDENTIAL_THEFT,
                                 "host-alpha/rootkit") == 0,
        "rule is part of duplicate key");
  check(ap_evidence_is_duplicate(&ledger, 2000u, AP_RULE_KERNEL_ROOTKIT,
                                 "host-alpha/other") == 0,
        "key is part of duplicate key");

  check(ap_evidence_add(NULL, 1u, 1, AP_RULE_CORRELATED, 1u, "x") == AP_ERR_ARG,
        "null ledger");
  check(ap_evidence_add(&ledger, 0u, 1, AP_RULE_CORRELATED, 1u, "x") == AP_ERR_ARG,
        "zero timestamp");
  check(ap_evidence_add(&ledger, 1u, 1, AP_RULE_NONE, 1u, "x") == AP_ERR_ARG,
        "no rule");
  check(ap_evidence_add(&ledger, 1u, 1, AP_RULE_CORRELATED, 1u, "") == AP_ERR_ARG,
        "empty key");

  {
    ap_evidence capped;
    ap_evidence_init(&capped);
    check(ap_evidence_add(&capped, 1500u, 42, AP_RULE_CORRELATED, 5000u,
                          "capped") == AP_OK,
          "add capped confidence");
    check(capped.records[0u].confidence_x1000 == 1000u,
          "confidence capped to abi range");
  }

  for (i = 0u; i < AP_EVIDENCE_SLOTS + 8u; ++i) {
    char key[32];
    snprintf(key, sizeof(key), "entity-%u", i);
    check(ap_evidence_add(&ledger, 5000u + i, 1, AP_RULE_CORRELATED, 500u,
                          key) == AP_OK,
          "bounded add");
  }
  ap_evidence_stats(&ledger, &inserted, &duplicates, &evicted);
  check(inserted == AP_EVIDENCE_SLOTS + 9u, "inserted count");
  check(duplicates == 1u, "duplicate count");
  check(evicted >= 8u, "bounded eviction");
  check(ap_evidence_is_duplicate(&ledger, 6000u, AP_RULE_CORRELATED,
                                 "entity-0") == 0,
        "oldest key evicted");

  printf("evidence tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
