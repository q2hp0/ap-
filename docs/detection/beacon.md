# bounded beacon analyzer

the beacon analyzer is a fixed-size c++ module in `cpp/beacon.cpp` for periodic
network check-ins. it does not inspect payloads and does not decrypt traffic. it
looks only for timing regularity, repeated external peers, and a small but nonzero
byte count. its rule is `beaconing` (rule 26), one of 32 entries in the static
registry (`AP_RULE_MAX` is 32 in c and `RULE_MAX` is 32 in rust). rules 27-32
follow it, so it is no longer the last detector.

## limits

- 64 peers
- 8 recent samples per peer
- 90-second analysis window
- 30-second repeat suppression
- 48-byte peer keys

all state lives in one bounded heap object created by `ap_beacon_new()`. no event
adds storage. eviction is circular and counted.

## decision rule

a finding requires at least three samples in the window, a nonzero mean interval
no larger than 60 seconds, jitter within `mean / 5 + 500 ms`, and at least two
samples with bytes sent. the score is 700/800/900 for 3/4/5+ samples. findings
report the peer, span, jitter, connection count, and byte total.

## wiring

`rust/src/correlation.rs` feeds `kind_network` and `kind_flow` events to the
analyzer, using the event text or a `peer-<pid>-<arg0>` fallback as the peer key and
`arg[0]` as the byte count. a c++ finding is mapped to `RULE_BEACONING`, source
`"network"`, severity medium, with the score as confidence. the summary counter
`beacon_findings` reports these findings. `tests/test_beacon.cpp` covers the
bounded analyzer directly; `scripts/test_correlation.sh` checks the summary path.
beaconing is gated like every other detector through `--enable`, `--disable`, and
the detector registry.

this analyzer is related to, but separate from, the c++ risk accumulator described
in `docs/detection/attack_graph.md` and the decaying per-pid risk in
`rust/src/risk.rs`. beacon findings are emitted after risk signals are collected in
the same pass, so they are not re-fed to that accumulator on that pass. rule 26
maps to the command-and-control tactic for findings that are supplied as signals.

## honesty

many legitimate agents poll on a timer. ntp, metrics exporters, package updates,
health checks, and load balancers can all look periodic. this analyzer is only a
feature producer. it must be combined with process lineage, user context,
destination reputation, and policy before it becomes an alert. silence here does
not rule out low-and-slow or jittered command and control.
