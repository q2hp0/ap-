#include "aptaxonomy.h"

#include "apgraph.h"
#include "apksensor.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "taxonomy test fail: %s\n", name);
    ++failures;
  }
}

int main(void) {
  const ap_taxonomy_entry *entry;
  uint32_t i;

  check(ap_taxonomy_count() == 12u, "canonical entry count");
  check(ap_taxonomy_find(AP_KLABEL_ROOTKIT) != NULL, "find rootkit label");
  check(ap_taxonomy_rule(AP_KLABEL_ROOTKIT) == AP_RULE_KERNEL_ROOTKIT,
        "rootkit rule");
  check(ap_taxonomy_tactic(AP_KLABEL_ROOTKIT) ==
            AP_GRAPH_TACTIC_DEFENSE_EVASION,
        "rootkit tactic");
  check(ap_taxonomy_confidence(AP_KLABEL_ROOTKIT) == 900u,
        "rootkit confidence");
  check(strcmp(ap_taxonomy_name(AP_KLABEL_FILELESS_EXEC), "fileless_exec") == 0,
        "canonical name");

  entry = ap_taxonomy_find_name("kernel_text_write");
  check(entry != NULL, "find rootkit alias");
  check(entry != NULL && entry->rule_id == AP_RULE_KERNEL_ROOTKIT,
        "alias rule");
  entry = ap_taxonomy_find_name("namespace_change");
  check(entry != NULL && entry->tactic == AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION,
        "container alias tactic");
  entry = ap_taxonomy_find_name("rootkit");
  check(entry != NULL && entry->label_id == AP_KLABEL_ROOTKIT,
        "legacy rootkit alias");
  entry = ap_taxonomy_find_name("ptrace");
  check(entry != NULL && entry->label_id == AP_KLABEL_PTRACE,
        "ptrace alias");
  entry = ap_taxonomy_find_name("credential_change");
  check(entry != NULL && entry->label_id == AP_KLABEL_CRED,
        "credential change alias");
  entry = ap_taxonomy_find_name("cred");
  check(entry != NULL && entry->label_id == AP_KLABEL_CRED,
        "cred alias");
  check(ap_taxonomy_find_name(NULL) == NULL, "null alias");
  check(ap_taxonomy_find_name("") == NULL, "empty alias");
  check(ap_taxonomy_find_name("not_a_label") == NULL, "unknown alias");

  check(ap_taxonomy_find(999u) == NULL, "unknown label");
  check(ap_taxonomy_rule(999u) == AP_RULE_NONE, "unknown rule");
  check(ap_taxonomy_tactic(999u) == 0u, "unknown tactic");
  check(ap_taxonomy_confidence(999u) == 0u, "unknown confidence");
  check(strcmp(ap_taxonomy_name(999u), "unknown") == 0, "unknown name");

  for (i = 1u; i <= AP_KLABEL_ANTI_ANALYSIS; ++i) {
    if (i == AP_KLABEL_NONE || i == AP_KLABEL_EXIT) continue;
    check(ap_taxonomy_find(i) != NULL, "canonical coverage");
  }

  printf("taxonomy tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
