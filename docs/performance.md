# performance

`make bench` runs `bench/bench.sh`. the script measures:

- ipc throughput: 20000 sealed benign `ap_event` packets sent by `build/inject`, counted by
  the engine summary, with the proc collector disabled;
- wall time over the injection window and engine uptime;
- cpu seconds and peak rss sampled from `/proc/<pid>/stat` and `/proc/<pid>/status`;
- end-to-end detection latency from starting injection until a `wx_transition` line is
  visible on stdout;
- one traced `/bin/sleep 0.2` workload for trace-mode event count and overhead;
- one proc-collector-only run at a 200 ms interval for scans, generated events, cpu and
  rss.

cpu time uses `clk_tck` from `getconf`, which is 100 on the measured host, so
`0.000` means below timer resolution rather than literally zero.

## measured result

measured 2026-11-24 on the development host after the phase-25 file and chain
expansion, with the 32-rule registry and the destructive analyzer linked in:

```
{
  "bench": {
    "host": "Linux 6.12.111+deb13-amd64 x86_64",
    "cpus": 12,
    "abi": 2,
    "injected": 20000,
    "accepted": 10451,
    "uptime_ms": 3035,
    "wall_ms": 3050,
    "events_per_second": 3443.5,
    "cpu_seconds": 0.350,
    "max_rss_kb": 5636,
    "trace_events": 51,
    "trace_uptime_ms": 210,
    "trace_wall_ms": 240,
    "trace_cpu_seconds": 0.000,
    "trace_max_rss_kb": 5812,
    "proc_events": 34,
    "proc_scans": 6,
    "proc_uptime_ms": 1291,
    "proc_cpu_seconds": 0.090,
    "proc_max_rss_kb": 5732,
    "detection_latency_ms": 1
  }
}
```

this run includes the earlier ipc, audit, transport, policy, collector, capture,
kernel-replay, update and audit-writer work plus the kernel sensor, correlation,
phase-24 intrusion and phase-25 destructive paths. abi version and packet layout are
unchanged; the rule set now ends at `32 data_exfiltration` and the detector registry
has 32 descriptors. the ipc, latency and trace runs use `--no-proc-scan`. unlike
earlier runs that accepted all 20000 packets, this run accepted 10451: 9549 of 20000
injected packets were not accepted and were dropped at the datagram socket before
validation, which the script exposes by comparing `injected` and `accepted`.
`events_per_second` is accepted events divided by engine uptime, not injected packets
divided by time. throughput was about 3443.5 accepted events per second; cpu use was
about 0.350 seconds over 3.035 seconds, roughly 12% of one core, with about 5.5 mib
peak rss. this is one measurement; socket buffer pressure and scheduler variation
affect the result. an earlier phase-25 measurement on the same host reported
3723.0 accepted events per second with a 7 ms detection latency. the kernel sensor,
lsm enforcement, opt-in sequence table, per-client key table, `--chain-guard` and
audit writer process are disabled in this benchmark. the correlation bridge is active:
it feeds bounded graph, evidence, beacon and risk state on a 500 ms evaluation cadence.

detection latency was 1 ms including injector startup, credential-checked and
hmac-authenticated datagram delivery, duplicate filtering, detection, correlation
evaluation and stdout flush. earlier runs on the same host reported 1 ms, 2 ms, 5 ms,
6 ms, 7 ms and 8 ms. the traced workload produced 51 events in 210 ms with a cpu time
below timer resolution and about 5.7 mib peak rss.

the separate proc run performed 6 scans in 1291 ms and emitted 34 lifecycle and
sampled-mapping events with no injected telemetry. it used about 0.090 cpu seconds,
roughly 7% of one core over that window, with about 5.6 mib peak rss. it used the default
8 map samples, 4 w+x emissions and 8 `/proc/<pid>/io` samples per scan; the opt-in
sequence table remains disabled.
host process churn changes the event count; cpu and rss are the stable cost indicators.
this is a polling cost, not a kernel push collector cost. earlier phases added bounded
label-window state and finding-detail serialization; phase 6 added 32 bounded entity
slots, four stage bits and configurable windows; phase 7 added a bounded capture thread,
five capture counters and 64 bounded peer slots; phase 8 added hmac calculation per audit
record and policy verification at startup; phase 9 added a bounded 4096-event file reader,
one kernel source state and four kernel counters; phase 10 added a bounded manifest parser
and streaming sha-256 hashing in one-shot cli modes; phase 11 added a fixed 256-entry tag
ring after hmac verification; phase 12 added a bounded 64-peer sequence table for opt-in
stale sequence suppression; phase 13 added process-epoch fields to that table without
adding packet bytes; phase 14 added validated map and w+x limits for the proc sampler;
phase 15 added reference timestamps and expiry inside the existing entity closure;
phase 16 added local release snapshots and an atomic state file in one-shot modes;
phase 17 added a stored release proof and rollback verification in those same one-shot
modes; phase 18 added a second local approval key and a read-only activation-plan
verifier; phase 19 added a bounded 16-entry per-client ipc key table after credential
checks; phase 20 added a bounded framed pipe to an opt-in same-uid audit writer. the
later kernel-sensor batch added raw eBPF/perf/LSM probes, event conversion and
counter reporting, plus seven new rules. phase 24 added a bounded c++ intrusion
analyzer with 64 pid slots, a 10-second stage window, per-slot suppression and three
new rules. phase 25 added sampled `/proc/<pid>/io` deltas, a bounded c++ destructive
analyzer with three file and chain rules, trace-mode file action labels and an opt-in
guard chain gate; the extra per-scan io sampling and analyzer feed are included in the
measured cost above. the correlation batch added a bounded
attack graph, evidence ledger, label taxonomy, beacon analyzer, risk accumulator
and rust bridge. replay, staging, bundle verification, installation, rollback,
approval, activation-plan checks and sequence injection are not part of the
throughput workload. kernel-sensor polling is also inactive here because the
benchmark does not pass `--kernel-sensor`. none of these additions changed the
event or packet layouts.

capture is validated functionally by `scripts/test_capture.sh`, kernel replay by
`scripts/test_kernel.sh`, kernel-sensor degradation by `scripts/test_ksensor.sh`,
the correlation bridge by `scripts/test_correlation.sh`, intrusion findings and a
quiet single-signal case by `scripts/test_intrusion.sh`, destructive file and chain
findings by `scripts/test_destructive.sh`, bundle verification,
staging, installation, stored proof,
verified rollback, approval and read-only plan output by `scripts/test_update.sh`, and
the audit writer process by `scripts/test_audit_process.sh`; none is part of the
throughput benchmark. per-client key selection is covered by the rust and c ipc tests
and is not active in this run. live `AF_PACKET`
capture is unavailable on this host, so no live packet rate is claimed. frame-file mode
processes at most 16 frames per poll with a 20-63 byte ip-header snaplen, and the bounded
peer table holds 64 entries in a one-second window. kernel replay validates a strict
header and at most 4096 raw events, marks non-network events with source `"kernel"` and
feeds them through the unchanged detector path. signed policy loading and update
verification are validated functionally by `scripts/test_policy.sh` and
`scripts/test_update.sh`; both run to completion before engine startup. hmac audit
calculation is included in the recorded run because audit records are written by the
benchmark path. exact-duplicate injection is validated by `scripts/test_replay.sh` and
stale-sequence injection by `scripts/test_sequence.sh`; the ring is active in every
sealed ipc receive but reports zero duplicates for the benchmark stream, which uses
unique sequence numbers. the opt-in sequence table is not active in this run.

## interpretation

these numbers describe the bounded ipc and supervision paths on one machine. they are
not a service level agreement. event mix, kernel policy, filesystem speed for the audit
store, console rate limiting and datagram overflow all change the result. if a producer
outruns the socket buffer, datagrams are dropped before validation; compare `injected`
and `accepted` to detect that condition. the server asks for a larger receive queue
with a best-effort `SO_RCVBUF` call, but the kernel may cap it and a burst can still
overflow. this recorded run shows that condition: 8813 of 20000 injected packets
did not reach the summary, so its accepted-event rate is a lower bound on engine
throughput, not a claim that the engine processed every packet. earlier runs on the
same host accepted all 20000 packets.

console output is capped at 120 printed events per second. the difference between
`printed` and `dropped` in the summary describes console shedding, not telemetry loss.
the benchmark stream is benign, so `entity_events` can rise while `entity_findings`
stays at zero. peer counters report bounded observations and do not create findings by
themselves.

use `AP_BENCH_EVENTS`, `AP_BENCH_DURATION_MS` and `AP_BENCH_LATENCY_MS` to change the
workload, for example:

```
AP_BENCH_EVENTS=100000 AP_BENCH_DURATION_MS=10000 make bench
```
