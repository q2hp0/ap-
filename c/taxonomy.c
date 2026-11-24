#include "aptaxonomy.h"

#include "apgraph.h"
#include "apksensor.h"

#include <string.h>

static const ap_taxonomy_entry ap_taxonomy_entries[] = {
  { AP_KLABEL_EXEC, AP_RULE_NONE, AP_GRAPH_TACTIC_EXECUTION, 500u, "exec" },
  { AP_KLABEL_MODULE, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_PERSISTENCE, 720u,
    "module_load" },
  { AP_KLABEL_BPF_PROG, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    780u, "bpf_prog_load" },
  { AP_KLABEL_PTRACE, AP_RULE_CREDENTIAL_THEFT, AP_GRAPH_TACTIC_CREDENTIAL_ACCESS,
    620u, "ptrace_access" },
  { AP_KLABEL_CRED, AP_RULE_CREDENTIAL_THEFT, AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION,
    700u, "cred_change" },
  { AP_KLABEL_NET, AP_RULE_NONE, AP_GRAPH_TACTIC_COMMAND_AND_CONTROL, 520u,
    "network" },
  { AP_KLABEL_ROOTKIT, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    900u, "kernel_rootkit" },
  { AP_KLABEL_CREDENTIAL_THEFT, AP_RULE_CREDENTIAL_THEFT,
    AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, 870u, "credential_theft" },
  { AP_KLABEL_PERSISTENCE, AP_RULE_PERSISTENCE, AP_GRAPH_TACTIC_PERSISTENCE, 860u,
    "persistence" },
  { AP_KLABEL_CONTAINER_ESCAPE, AP_RULE_CONTAINER_ESCAPE,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 880u, "container_escape" },
  { AP_KLABEL_FILELESS_EXEC, AP_RULE_FILELESS_EXEC, AP_GRAPH_TACTIC_EXECUTION,
    850u, "fileless_exec" },
  { AP_KLABEL_ANTI_ANALYSIS, AP_RULE_ANTI_ANALYSIS,
    AP_GRAPH_TACTIC_DEFENSE_EVASION, 820u, "anti_analysis" }
};

static const ap_taxonomy_entry ap_taxonomy_aliases[] = {
  { AP_KLABEL_PTRACE, AP_RULE_CREDENTIAL_THEFT,
    AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, 620u, "ptrace" },
  { AP_KLABEL_CRED, AP_RULE_CREDENTIAL_THEFT,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 700u, "credential_change" },
  { AP_KLABEL_CRED, AP_RULE_CREDENTIAL_THEFT,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 700u, "cred" },
  { AP_KLABEL_ROOTKIT, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    900u, "rootkit" },
  { AP_KLABEL_ROOTKIT, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    900u, "kernel_text_write" },
  { AP_KLABEL_ROOTKIT, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    900u, "ftrace_write" },
  { AP_KLABEL_ROOTKIT, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    900u, "kcore_open" },
  { AP_KLABEL_ROOTKIT, AP_RULE_KERNEL_ROOTKIT, AP_GRAPH_TACTIC_DEFENSE_EVASION,
    900u, "debugfs_write" },
  { AP_KLABEL_CREDENTIAL_THEFT, AP_RULE_CREDENTIAL_THEFT,
    AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, 870u, "shadow_read" },
  { AP_KLABEL_CREDENTIAL_THEFT, AP_RULE_CREDENTIAL_THEFT,
    AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, 870u, "keyring_read" },
  { AP_KLABEL_FILELESS_EXEC, AP_RULE_FILELESS_EXEC, AP_GRAPH_TACTIC_EXECUTION,
    850u, "memfd_exec" },
  { AP_KLABEL_FILELESS_EXEC, AP_RULE_FILELESS_EXEC, AP_GRAPH_TACTIC_EXECUTION,
    850u, "pipe_exec" },
  { AP_KLABEL_ANTI_ANALYSIS, AP_RULE_ANTI_ANALYSIS,
    AP_GRAPH_TACTIC_DEFENSE_EVASION, 820u, "tracer_check" },
  { AP_KLABEL_ANTI_ANALYSIS, AP_RULE_ANTI_ANALYSIS,
    AP_GRAPH_TACTIC_DEFENSE_EVASION, 820u, "audit_disable" },
  { AP_KLABEL_PERSISTENCE, AP_RULE_PERSISTENCE, AP_GRAPH_TACTIC_PERSISTENCE, 860u,
    "cron_write" },
  { AP_KLABEL_PERSISTENCE, AP_RULE_PERSISTENCE, AP_GRAPH_TACTIC_PERSISTENCE, 860u,
    "systemd_unit_write" },
  { AP_KLABEL_PERSISTENCE, AP_RULE_PERSISTENCE, AP_GRAPH_TACTIC_PERSISTENCE, 860u,
    "rc_write" },
  { AP_KLABEL_PERSISTENCE, AP_RULE_PERSISTENCE, AP_GRAPH_TACTIC_PERSISTENCE, 860u,
    "ssh_key_write" },
  { AP_KLABEL_CONTAINER_ESCAPE, AP_RULE_CONTAINER_ESCAPE,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 880u, "namespace_change" },
  { AP_KLABEL_CONTAINER_ESCAPE, AP_RULE_CONTAINER_ESCAPE,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 880u, "mount" },
  { AP_KLABEL_CONTAINER_ESCAPE, AP_RULE_CONTAINER_ESCAPE,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 880u, "capset" },
  { AP_KLABEL_CONTAINER_ESCAPE, AP_RULE_CONTAINER_ESCAPE,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 880u, "cgroup_write" },
  { AP_KLABEL_CONTAINER_ESCAPE, AP_RULE_CONTAINER_ESCAPE,
    AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, 880u, "exec_uid_change" }
};

const ap_taxonomy_entry *ap_taxonomy_find(uint32_t label_id) {
  size_t i;
  for (i = 0u; i < sizeof(ap_taxonomy_entries) / sizeof(ap_taxonomy_entries[0]);
       ++i) {
    if (ap_taxonomy_entries[i].label_id == label_id) return &ap_taxonomy_entries[i];
  }
  return NULL;
}

const ap_taxonomy_entry *ap_taxonomy_find_name(const char *name) {
  size_t i;
  if (name == NULL || name[0] == '\0') return NULL;
  for (i = 0u; i < sizeof(ap_taxonomy_entries) / sizeof(ap_taxonomy_entries[0]);
       ++i) {
    if (strcmp(name, ap_taxonomy_entries[i].name) == 0)
      return &ap_taxonomy_entries[i];
  }
  for (i = 0u; i < sizeof(ap_taxonomy_aliases) / sizeof(ap_taxonomy_aliases[0]);
       ++i) {
    if (strcmp(name, ap_taxonomy_aliases[i].name) == 0)
      return &ap_taxonomy_aliases[i];
  }
  return NULL;
}

uint32_t ap_taxonomy_count(void) {
  return (uint32_t)(sizeof(ap_taxonomy_entries) / sizeof(ap_taxonomy_entries[0]));
}

uint32_t ap_taxonomy_rule(uint32_t label_id) {
  const ap_taxonomy_entry *entry = ap_taxonomy_find(label_id);
  return entry == NULL ? AP_RULE_NONE : entry->rule_id;
}

uint32_t ap_taxonomy_tactic(uint32_t label_id) {
  const ap_taxonomy_entry *entry = ap_taxonomy_find(label_id);
  return entry == NULL ? 0u : entry->tactic;
}

uint32_t ap_taxonomy_confidence(uint32_t label_id) {
  const ap_taxonomy_entry *entry = ap_taxonomy_find(label_id);
  return entry == NULL ? 0u : entry->confidence_x1000;
}

const char *ap_taxonomy_name(uint32_t label_id) {
  const ap_taxonomy_entry *entry = ap_taxonomy_find(label_id);
  return entry == NULL ? "unknown" : entry->name;
}
