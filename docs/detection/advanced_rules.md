# advanced rules

thirteen rules extend the original detector set with kernel-sensor, correlation,
long-window behavioral, bounded intrusion-stage, and destructive file/chain coverage.
`AP_RULE_MAX` is 32 in c and `RULE_MAX` is 32 in rust; rule ids are 1..32. the static
detector registry has 32 descriptors, all enabled by default; disabling one yields 31,
and `--enable all` expands to 32. the current rust suite has 136 tests. every rule is
explicit, bounded, and auditable; none guarantees detection of all exploitation
types.

| rule | name | emitted confidence | registry prior | owner | trigger |
| --- | --- | --- | --- | --- | --- |
| 20 | `kernel_rootkit` | 900 | 900 | rust cheap label | ksensor text label `kernel_rootkit`; related high-value labels also join the c++ kernel-chain mask |
| 21 | `credential_theft` | 870 | 870 | rust cheap label | ksensor text label `credential_theft` |
| 22 | `persistence_chain` | 860 | 880 | c++ flow analyzer | two write labels plus exec/start and network in one ksensor-marked entity window |
| 23 | `container_escape` | 880 | 900 | c++ flow analyzer | namespace, mount, and privileged change in one ksensor-marked entity window |
| 24 | `fileless_exec` | 850 | 850 | rust cheap label | ksensor text label `fileless_exec` |
| 25 | `anti_analysis` | 820 | 820 | rust cheap label | ksensor text label `anti_analysis` |
| 26 | `beaconing` | 700/800/900 | 700 | c++ beacon analyzer | periodic peer timing with a small nonzero byte count, mapped by the rust bridge |
| 27 | `process_injection` | 870/890 | 870 | c++ intrusion analyzer | remote write plus w+x, exec, or redirect in a 10-second pid window; 890 with redirect |
| 28 | `exploit_chain` | 890/920 | 890 | c++ intrusion analyzer | w+x plus redirect and priv, exec, or net; 920 with priv |
| 29 | `credential_dump` | 900 | 900 | c++ intrusion analyzer | remote read plus cred_access and priv, net, or remote write |
| 30 | `file_write_burst` | 870 | 870 | c++ destructive analyzer | sampled proc io with 64 write calls, or 1 MiB plus 8 write calls, in a 10-second window |
| 31 | `destructive_chain` | 900 | 900 | c++ destructive analyzer | write burst plus at least two rename/unlink/chmod/handle actions |
| 32 | `data_exfiltration` | 880 | 880 | c++ destructive analyzer | network connect plus a read burst of 4 MiB bytes or 8 MiB chars |

the registry value is a starting prior used for coverage output and gating; the
emitted value is the confidence in the verdict. the two differ for rules 22 and
23 because the flow analyzer reports the concrete correlation, rule 26 scores
700/800/900 for 3/4/5-or-more in-window samples, rule 27 scores 870 or 890 with
redirect, and rule 28 scores 920 with priv else 890. all values are x1000
heuristics, not probabilities.

## ownership split

- rust cheap rules own 20, 21, 24, and 25 in `rust/src/detect.rs`. they require
  source `"ksensor"` (`arg[3] == 3`) and an exact text match; a suffixed or
  differently named label does not fire them.
- the c++ flow analyzer owns 22 and 23 in `cpp/flow.cpp`. both use bounded
  five-second per-pid masks and only read persistence and container stage labels
  from events with `arg[3] == 3`. two write labels from `cron_write`,
  `systemd_unit_write`, `rc_write`, or `ssh_key_write`, an `exec` or
  `process_start` stage, and a `connect` or `net_packet` stage produce
  `persistence_chain` at 860. `namespace_change`, `mount`, and one of `capset`,
  `cgroup_write`, `cred`, or `exec_uid_change` produce `container_escape` at 880.
  each finding clears its own window; a container escape also clears the generic
  kernel mask to avoid a stale second chain. `c/trace.c` adds explicit labels
  `process_vm_writev`, `process_vm_readv`, `userfaultfd`, `io_uring_setup`, and
  `open_by_handle_at`; `process_vm_readv` is watched. `cpp/flow.cpp` maps these
  labels to the existing `kernel_iface_bit` for legacy kernel-chain compatibility,
  and `tests/kernel_probe.c` touches `process_vm_readv`.
- the c++ beacon analyzer owns rule 26 in `cpp/beacon.cpp`; `rust/src/correlation.rs`
  maps its findings to `RULE_BEACONING`, source `"network"`, and severity medium.
- the c++ intrusion analyzer owns rules 27-29 in `cpp/intrusion.cpp` with api
  `include/apintrusion.h` and library `build/libapintrusion.a`. `rust/src/ffi.rs`
  wraps it, `DetectorRegistry::intrusion_enabled()` gates it, `rust/src/detect.rs`
  feeds it, and `rust/src/correlation.rs` maps process_injection to defense evasion,
  exploit_chain to privilege escalation, and credential_dump to credential access.
  it keeps 64 fixed pid slots, a 10-second stage window, and 5-second per-slot
  per-rule suppression. stage bits are remote_write, remote_read, cred_access, wx,
  exec, redirect, priv, and net; w+x requires both write and exec bits
  (`arg[2] & 6 == 6`), not either alone. detail prefixes are exactly
  `process_injection:`, `exploit_chain:`, and `credential_dump:`. priority is
  credential_dump > process_injection > exploit_chain, so at most one verdict is
  emitted per event. counters are added, evicted, findings, and suppressed;
  the summary publishes `intrusion_findings` and `intrusion_suppressed`.
- the c++ destructive analyzer owns rules 30-32 in `cpp/destructive.cpp` with api
  `include/apdestructive.h` and library `build/libapdestructive.a`. `rust/src/ffi.rs`
  wraps it, `DetectorRegistry::destructive_enabled()` gates it, and `rust/src/detect.rs`
  feeds `AP_KIND_FILE`, `AP_KIND_NET` and `AP_KIND_KERNEL` events into it. it keeps 64
  fixed pid slots, a 10-second window and 5-second per-slot per-rule suppression. stage
  bits are write, read, rename, unlink, chmod, net and handle; io stages need at least
  4096 bytes or 4 write calls, or 4096 read bytes/chars. detail prefixes are exactly
  `file_write_burst:`, `destructive_chain:` and `data_exfiltration:`. priority is
  destructive_chain > data_exfiltration > file_write_burst, so at most one verdict is
  emitted per feed. counters are added, evicted, findings and suppressed; the summary
  publishes `destructive_findings` and `destructive_suppressed`. opt-in `--chain-guard`
  adds a separate rust-side tracker: 64 pid slots, a 10-second window and three distinct
  high-value rules before guard decisions can fire, counted as `chain_findings`.
- the bounded attack graph, evidence ledger, and c++ risk accumulator emit
  `correlated_exploit_indicators` (rule 16), not new rule ids. their counters are
  separate from the rule set. see `docs/detection/attack_graph.md`.
- `c/taxonomy.c` maps canonical labels and aliases to rule, tactic, and confidence
  for the graph and risk bridge; it does not itself create detection verdicts.
  see `docs/detection/taxonomy.md`.

replay events carry mark `2`, not the ksensor mark `3`, and deliberately keep
their prior behavior: they can feed older kernel-chain logic but never set the
new persistence or container-escape bits. file telemetry carries no mark `3` or `2`
requirement: it comes from the sampled `/proc` collector or traced file actions.
detector gating is shared: all thirteen rules
honor `--enable`, `--disable`, confidence, and policy selection through
`rust/src/detection/registry.rs`, including findings produced after bridge
evaluation. `scripts/test_detectors.sh` checks `"enabled": 31` after one detector
is disabled.

## limitations

a label is an observation, not proof of a successful operation. module or bpf
loads can be legitimate administrative work. shadow or process-memory access can
be authorized tooling. fileless execution is common in build systems and
containers. anti-analysis telemetry can be produced by benign security software.
periodic polling by ntp, metrics exporters, health checks, and package updaters
can match the beacon rule. intrusion findings are bounded stage correlations over
supplied labels; missing labels, pid reuse, or a 64-slot eviction can hide a real
chain, and a verdict does not prove code injection, exploit success, or a dumped
secret. destructive findings are process-wide and sampled: bulk maintenance, backups
and downloads can mimic write or read bursts, per-file attribution is unavailable, and
sampling gaps can hide a real chain. `--chain-guard` is a heuristic readiness gate, not
proof of attack or coverage of zero-days.

the sensor emits canonical `kernel_rootkit` and `cred_change` text and `ptrace`
is accepted as a taxonomy alias for `ptrace_access`; the cheap rules still require
their own exact label strings. other replay spellings are mapped only through the
bounded alias table in `c/taxonomy.c`; an unknown spelling yields no taxonomy
prior. the c++ chains depend on supplied labels, stable keys, and a five-second
window: missing telemetry or pid reuse can hide or confuse them. live bpf, perf,
and lsm attachment cannot be validated on this host, whose capability mask is 7.

these rules increase coverage of modeled high-value behavior; they are bounded
behavioral and telemetry correlation, not a guarantee of detecting all exploitation
types, proof of intent, or protection after kernel compromise. lsm is optional,
`kernel_compromise` stays `"unprotected"`, and live eBPF, perf, lsm, and AF_PACKET
paths remain unvalidated here (capability mask 7).
