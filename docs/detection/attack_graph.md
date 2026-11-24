# bounded attack graph and correlation bridge

the attack graph is a fixed-size correlation structure in c. it links observations
that share an entity key or pid and emits a finding only when several distinct
tactics appear in one bounded time window. in the running engine it is one part of
a bounded correlation bridge owned by `rust/src/correlation.rs`: the graph, a
256-record evidence ledger, a canonical label taxonomy, a c++ beacon analyzer, a
c++ risk accumulator, and a c++ intrusion analyzer. none creates a new collector
process or a new event schema.

## limits

- 128 nodes
- 256 edges
- 32 chain-suppression slots
- 64-byte entity keys
- 60-second correlation window
- 30-second repeat suppression

all graph and ledger storage is allocated by the caller. the c event path performs
no heap allocation. oldest nodes, edges, and suppression slots are evicted in
circular order. the c++ beacon, risk, and intrusion analyzers use bounded heap
objects created once by `ap_beacon_new()`, `ap_risk_new()`, and
`ap_intrusion_new()`; the intrusion analyzer keeps 64 fixed pid slots.

## observation fields

an observation carries a monotonic timestamp, pid, tactic id, semantic label id,
confidence, and an entity key. when no key is supplied, the key is derived from
the pid. keys are copied by length and always NUL-terminated. in the rust bridge,
the key is `pid-<pid>` when the pid is nonzero, otherwise the event text or
`unknown`; the numeric label, tactic, and confidence come from
`ap_taxonomy_find_name()` when the text is a known label or alias. unknown text
falls back to a kind-derived tactic and the event's own confidence, so the bridge
does not guess a rule id.

## finding rule

a finding requires:

- at least three linked nodes in the window,
- at least three distinct tactics,
- at least one high-value tactic: persistence, privilege escalation, credential
  access, command and control, exfiltration, or impact,
- summed confidence of at least 1800.

the finding records the newest timestamp, pid, tactic bitmask, confidence sum,
linked node count, and entity key. repeat findings for the same key are suppressed
for 30 seconds and counted explicitly. only the newest node in a window is
evaluated, so a graph finding is one-shot per chain until the suppression expires.

## evidence ledger

`c/evidence.c` keeps 256 records with 64-byte keys and a 30-second dedupe window.
`ap_evidence_add_once()` hashes the key with a bounded non-cryptographic fnv-1a
hash, compares rule and full key, and returns `AP_ERR_REPLAY` for a repeat inside
the window. the ledger counts `inserted`, `duplicates`, and `evicted` records; the
oldest slot is overwritten when full. it is a bounded dedupe aid for findings, not
an authenticated evidence store. the audit store and its hmac chain remain the
durable record.

## taxonomy

`c/taxonomy.c` is the shared lookup table between ksensor labels, graph
observations, and risk signals. canonical entries and aliases map a text label to
a numeric ksensor label id, a rule id, a tactic, and a confidence prior. examples:
`kernel_rootkit`, `shadow_read`, `cron_write`, and `namespace_change`. unknown
labels return `AP_RULE_NONE`, tactic zero, confidence zero, and `unknown`. see
`docs/detection/taxonomy.md` for the exact table and bounded alias set.

## risk accumulator

`cpp/risk.cpp` is a separate bounded accumulator, distinct from the decaying
per-pid score in `rust/src/risk.rs` that feeds guard decisions. it holds 64
entities, 8 signals per entity, 48-byte keys, a 90-second signal window, and a
30-second finding suppression. the rust bridge feeds it one signal per finding:
rule, rule-derived tactic, confidence, and entity key. rules 20-25 count as
high-value rules; rule 26 maps to command and control. rules 27, 28, and 29 map to
defense evasion, privilege escalation, and credential access respectively; rules 30
and 31 map to impact and rule 32 to exfiltration. an
entity produces a finding when at least two in-window signals have summed confidence
of at least 1500, at least two distinct tactics, and at least one high-value rule.
the bridge reports it as `correlated_exploit_indicators` (rule 16) with source
`"risk"`. the summary counter `risk_findings` counts these accumulator findings;
it is not the rust per-pid risk score. see `docs/detection/beacon.md` for the
companion timing analyzer.

## page out and counters

the bridge evaluates graph, beacon, and risk roughly every 500 ms. it appends
findings to the same vector as cheap rules and the c++ analyzers, including
intrusion findings fed from `rust/src/detect.rs`. registry filtering runs
afterward, so disabled rules never reach risk or guard. the final summary publishes
`graph_added`, `graph_evicted`, `graph_findings`, `graph_suppressed`,
`evidence_inserted`, `evidence_duplicates`, `evidence_evicted`, `beacon_findings`,
`risk_findings`, `intrusion_findings`, and `intrusion_suppressed`, plus the ksensor
and lsm counters. expired graph nodes and deduped evidence stay in their slots
until circular eviction; they are simply ignored by the window checks.
`scripts/test_correlation.sh` and `scripts/test_intrusion.sh` check the counters end
to end, and c/c++ tests `test_graph`, `test_taxonomy`, `test_evidence`, and
`test_intrusion` cover the bounded structures directly.

## honesty

this is a heuristic over supplied observations. it does not prove that the same
actor performed every step, that a tactic succeeded, or that a key is an authentic
process identity. pid reuse and shared binary or peer keys can still create false
links. missing telemetry can break a real chain. hashes and marks are internal,
not cryptographic sensor identity, and no part of this bridge protects the kernel
after compromise.
