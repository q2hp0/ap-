# label taxonomy

the taxonomy module is a small c lookup table in `c/taxonomy.c` shared by the
kernel sensor bridge, attack graph, and detection layer. it turns semantic labels
into a rule id, a mitre-style tactic, and a confidence value without allocating
memory. it supplies graph and risk priors; it does not itself emit a detection
verdict. see `docs/detection/attack_graph.md` for the bridge that consumes it and
`docs/detection/advanced_rules.md` for the rule-confidence split.

## canonical labels

canonical labels mirror the numeric `apksensor.h` label ids:
`exec`, `module_load`, `bpf_prog_load`, `ptrace_access`, `cred_change`, `network`,
`kernel_rootkit`, `credential_theft`, `persistence`, `container_escape`,
`fileless_exec`, and `anti_analysis`. each canonical entry carries a rule and
tactic prior; examples are `kernel_rootkit` -> rule 20, defense evasion, 900 and
`container_escape` -> rule 23, privilege escalation, 880.

the canonical name strings are the taxonomy table's names. sensor conversion uses
the same `kernel_rootkit`, `cred_change`, and other canonical text where one exists;
`ap_taxonomy_find_name()` also accepts `ptrace`, `credential_change`, `cred`, and
`rootkit` as aliases for common replay and integration labels. numeric lookup
`ap_taxonomy_find()` is id-based and does not depend on text. label names are
internal observation labels, not authenticated process or sensor identities.
`docs/kernel/sensor.md` describes the sensor event conversion.

## aliases

aliases map c++ correlation text labels onto canonical entries. examples:
`kernel_text_write`, `ftrace_write`, `kcore_open`, and `debugfs_write` map to
`kernel_rootkit`; `shadow_read` and `keyring_read` map to `credential_theft`;
`cron_write`, `systemd_unit_write`, `rc_write`, and `ssh_key_write` map to
`persistence`; `memfd_exec` and `pipe_exec` map to `fileless_exec`;
`namespace_change`, `mount`, `capset`, `cgroup_write`, and `exec_uid_change` map to
`container_escape`.

`c/trace.c` adds explicit kernel labels `process_vm_writev`, `process_vm_readv`,
`userfaultfd`, `io_uring_setup`, and `open_by_handle_at`; `process_vm_readv` is
watched. `cpp/flow.cpp` maps these labels to the existing `kernel_iface_bit` for
legacy kernel-chain compatibility, so they add no new taxonomy rule id.
`cpp/intrusion.cpp` uses the write and read labels as remote-write and remote-read
stage bits. `tests/kernel_probe.c` touches `process_vm_readv`.

## use

`ap_taxonomy_find_name()` lets analyzers produce a bounded graph observation from
the same text label they use in a verdict detail string. `ap_taxonomy_find()`
provides the numeric reverse mapping for ksensor labels. unknown labels return
`AP_RULE_NONE`, tactic zero, confidence zero, and the name `unknown` so callers
fail closed instead of guessing. in `rust/src/correlation.rs`, an unknown text
label still produces an observation with a kind-derived tactic and the event's own
confidence, but no rule id is inferred. rule-to-tactic mapping for risk signals is
done in the same bridge: rules 20 and 25 map to defense evasion, 21 to credential
access, 22 to persistence, 23 to privilege escalation, 24 to execution, 26 to
command and control, 27 to defense evasion, 28 to privilege escalation, 29 to
credential access, 30 and 31 to impact, and 32 to exfiltration.

## scope

the table is deliberately conservative. it models observed operations, not intent.
a module load is not automatically malicious, and a persistence write may be an
administrative action. confidence values are starting priors that higher-level
correlation may raise or lower; they are not probabilities or proof of a successful
exploit.
