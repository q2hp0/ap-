#ifndef APTAXONOMY_H
#define APTAXONOMY_H

#include "apabi.h"

#include <stddef.h>
#include <stdint.h>

typedef struct ap_taxonomy_entry {
  uint32_t label_id;
  uint32_t rule_id;
  uint32_t tactic;
  uint32_t confidence_x1000;
  const char *name;
} ap_taxonomy_entry;

#ifdef __cplusplus
extern "C" {
#endif

const ap_taxonomy_entry *ap_taxonomy_find(uint32_t label_id);
const ap_taxonomy_entry *ap_taxonomy_find_name(const char *name);
uint32_t ap_taxonomy_count(void);
uint32_t ap_taxonomy_rule(uint32_t label_id);
uint32_t ap_taxonomy_tactic(uint32_t label_id);
uint32_t ap_taxonomy_confidence(uint32_t label_id);
const char *ap_taxonomy_name(uint32_t label_id);

#ifdef __cplusplus
}
#endif

#endif
