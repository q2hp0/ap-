#ifndef APEVIDENCE_H
#define APEVIDENCE_H

#include "apabi.h"

#include <stddef.h>
#include <stdint.h>

#define AP_EVIDENCE_SLOTS 256u
#define AP_EVIDENCE_KEY_LEN 64u
#define AP_EVIDENCE_DEDUP_NS 30000000000ULL

typedef struct ap_evidence_record {
  uint64_t ts_ns;
  uint64_t hash;
  int64_t pid;
  uint32_t rule;
  uint32_t confidence_x1000;
  uint32_t used;
  char key[AP_EVIDENCE_KEY_LEN];
} ap_evidence_record;

typedef struct ap_evidence {
  ap_evidence_record records[AP_EVIDENCE_SLOTS];
  uint64_t cursor;
  uint64_t inserted;
  uint64_t duplicates;
  uint64_t evicted;
} ap_evidence;

#ifdef __cplusplus
extern "C" {
#endif

void ap_evidence_init(ap_evidence *ledger);
int ap_evidence_add(ap_evidence *ledger, uint64_t ts_ns, int64_t pid,
                    uint32_t rule, uint32_t confidence_x1000, const char *key);
int ap_evidence_add_once(ap_evidence *ledger, uint64_t ts_ns, int64_t pid,
                         uint32_t rule, uint32_t confidence_x1000,
                         const char *key);
int ap_evidence_is_duplicate(const ap_evidence *ledger, uint64_t now_ns,
                             uint32_t rule, const char *key);
void ap_evidence_stats(const ap_evidence *ledger, uint64_t *inserted,
                       uint64_t *duplicates, uint64_t *evicted);

#ifdef __cplusplus
}
#endif

#endif
