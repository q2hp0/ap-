# technical architecture assessment

## what the current design is

ap is a single-process, event-driven analyzer. c libraries are linked into the rust
binary through a small ffi layer; c++ analyzers are statically linked the same way.
telemetry comes from a supervised child, hmac-authenticated unix datagrams with a bounded
exact-duplicate ring and opt-in epoch-aware sequence check, a bounded `/proc` sampler,
a bounded capture backend, an optional bounded kernel event file, and an opt-in kernel
sensor backed by raw tracepoints and a perf ring. an optional bpf-lsm deny hook can
enforce a configured local mask, but it is not a boundary against kernel compromise.
one-shot modes verify store, policy and update-bundle integrity before the engine starts.

the engine validates and normalizes events, runs 32 gated detector descriptors, feeds
bounded c++ flow, network, beacon, risk, intrusion and destructive analyzers, and
evaluates a bounded correlation bridge made of an attack graph, an evidence ledger, a
canonical label taxonomy, a beacon analyzer and a separate c++ risk accumulator. cheap
rules 20, 21, 24 and 25 live in rust; flow rules 22 and 23 live in c++; the beacon
analyzer owns rule 26, the intrusion analyzer owns rules 27-29, and the destructive
analyzer owns rules 30-32 from sampled file IO, file actions and network connects.
graph and risk findings map back to `correlated_exploit_indicators` (rule 16) and do
not add rule ids. findings
update the rust per-pid risk score, an opt-in guard policy, the terminal stream and a
rotating hmac-chained jsonl store. update staging
copies verified payloads into a new directory; local installation keeps two verified
snapshots under a private root and rolls back recorded state, but it does not activate
them.

## strengths worth preserving

- versioned, fixed-size abi checked from both c and rust; no serialization layer.
- clear separation between detection findings, rust per-pid risk and guard decisions.
- 32 static detector descriptors with explicit telemetry needs, cost and gating.
- ten named source states, including `ksensor` and `lsm`, with honest degradation.
- bounded graph, evidence, taxonomy, beacon, risk, intrusion and destructive state;
  no second producer schema.
- cheap rules and c++ analyzers have explicit ownership: 20/21/24/25, 22/23, 26,
  27/28/29 and 30/31/32.
- saturating arithmetic, bounded eviction, nonblocking handoff, validated caps and
  an opt-in chain gate over three distinct high-value rules.
- fixed 256-tag ipc duplicate ring and opt-in 64-peer sequence check with `/proc` epochs.
- kernel sensor setup happens before self-hardening seccomp denies `bpf()`.
- local 0600 keys, hmac chains, sealed policy, update proof and same-uid audit writer.
- reproducible tests: 136 rust tests and 23 shell suites, with 22 in `make check`
  plus `test_sanitizers.sh` for `make asan`.

## architectural shape

```
trace, ipc, proc, capture, replay and ksensor callbacks --\
                     -> rust engine -> c/c++ analyzers -> bridge -> risk -> guard -> cli/store
optional bpf-lsm deny hook ---------> configured local keys only, not kernel defense
```

the shape is compact, but it still has one analysis loop and mostly one trust domain.
the tracer sees only the supervised child. external producers and the proc, capture,
replay and ksensor paths are bounded local samplers or file/ring readers whose marks are
internal, not cryptographic sensor identity. the correlation bridge improves context
over supplied observations; it does not prove that a tactic succeeded or that one actor
performed every step.

## honesty

the observed capability mask is 7: seccomp, ptrace and proc are available, while perf,
tracepoints, bpf and `AF_PACKET` are not. the raw sensor, perf ring and bpf-lsm code is
integrated and tested as bounded c/c++ logic, but no live attach or deny can be validated
on this host. an active report on a capable host remains a design claim here, not a
measured result. `kernel_compromise` stays `unprotected` even when lsm is active.

sensor conversion uses canonical taxonomy strings where available and accepts a
bounded alias set for common replay names; unknown text yields no taxonomy prior.
cheap rules still require their own exact strings. see `docs/detection/taxonomy.md`.
these rules are bounded heuristics, not guarantees of detection for all exploitation
types. intrusion findings correlate supplied stage labels in 64 pid slots and do not
prove code injection, exploit success, or credential access. destructive findings use
sampled process-wide io deltas, file action labels and network connects, so they cannot
name a file, inspect content or close sampling gaps; `--chain-guard` is an explicit
heuristic precondition, not proof of attack. lsm is optional and none of these paths
protects a compromised kernel.

## consequence

the current implementation is a credible foundation for a research engine and a
controlled workload monitor. it is not yet a system-wide security platform. the
remaining work is live sensor validation, kprobes, authenticated sensor identity,
vendor-backed activation, privilege separation, and kernel-compromise protection.
sensor and taxonomy text is now reconciled through canonical names and bounded
aliases. the engine and analyzer code should be preserved while those boundaries
are made explicit rather than implied.
