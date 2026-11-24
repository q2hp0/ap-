# implementation inventory

snapshot of the current tree. counts are source lines and are approximate; they
describe the branched, file-rich layout now in place, not the pre-transformation
baseline.

## runtime and language ownership

| subsystem | files | lines | role |
| --- | --- | --- | --- |
| c platform and core | `include/apabi.h`, `apcap.h`, `apsys.h`, `aptelemetry.h`, `aptransport.h`, `c/abi.c`, `cap.c`, `crypto.c`, `sys.c`, `telemetry.c`, `transport.c` | ~1670 | fixed event and verdict layout, capability probe, seccomp, self-hardening, unix datagram ipc, sha-256/hmac, source descriptors |
| c telemetry backends | `include/apcollector.h`, `apcapture.h`, `apkernel.h`, `apreplay.h`, `aptrace.h`, `c/collector.c`, `capture.c`, `kernel.c`, `replay.c`, `trace.c` | ~2100 | bounded `/proc` snapshot/delta with sampled `io` deltas, frame capture, strict `apk1` replay, duplicate and sequence rings, ptrace supervision with file action labels |
| c correlation and sensor | `include/apgraph.h`, `apevidence.h`, `aptaxonomy.h`, `apksensor.h`, `c/graph.c`, `evidence.c`, `taxonomy.c`, `ksensor.c` | ~1690 | bounded attack graph, evidence ledger, canonical labels, raw eBPF/perf/lsm sensor with hand-encoded programs |
| c heap shim | `include/apheap.h`, `c/heap.c` | ~300 | `ld_preload` allocator instrumentation |
| c++ analyzers | `include/apflow.h`, `apnet.h`, `apbeacon.h`, `aprisk.h`, `apintrusion.h`, `apdestructive.h`, `cpp/flow.cpp`, `net.cpp`, `beacon.cpp`, `risk.cpp`, `intrusion.cpp`, `destructive.cpp` | ~2850 | w+x and kernel/entity chains, protocol analysis, bounded beacon timing, bounded risk accumulation, bounded intrusion-stage and destructive file/chain correlation |
| rust core | `engine.rs`, `policy.rs`, `policyfile.rs`, `guard.rs`, `risk.rs`, `source.rs` | part of ~9100 | event loop, policy, sealed policy, enforcement decisions, decaying per-pid risk, named source states |
| rust detection and bridge | `abi.rs`, `detect.rs`, `event.rs`, `correlation.rs`, `ksensor.rs`, `detection/registry.rs`, `adversarial.rs` | part of ~9100 | validation, cheap rules, 32-descriptor registry, graph/evidence/beacon/risk bridge, intrusion and destructive feeds with tactic mapping, sensor wrapper, fuzz tests |
| rust transport and output | `ipc.rs`, `cli.rs`, `store.rs`, `ffi.rs`, `audit.rs`, `auth.rs`, `capture.rs`, `collector.rs`, `kernel.rs`, `update.rs` | part of ~9100 | sealed ipc, console, hmac audit store, ffi bindings including intrusion and destructive wrappers, backend wrappers, bounded update modes |
| rust entry | `main.rs`, `lib.rs`, `build.rs` | part of ~9100 | cli entry, exports, linker wiring |
| tests | `tests/` | ~4100 | c/c++ unit suites including `test_ksensor`, `test_graph`, `test_taxonomy`, `test_evidence`, `test_beacon`, `test_risk`, `test_intrusion`, `test_destructive`, plus injectors, probes, file fixtures and fuzzers |
| scripts | `scripts/` | ~1330 | 23 shell suites: 22 in `make check`, including `test_ksensor.sh`, `test_correlation.sh`, `test_intrusion.sh` and `test_destructive.sh`, plus `test_sanitizers.sh` under `make asan` |
| docs and bench | `docs/`, `README.md`, `bench/bench.sh` | ~3240 | architecture, interfaces, detection, kernel, transformation notes and measurement harness |

total: about 25,900 source lines, plus generated build artifacts. the current
rust suite has 136 tests.

## build and entry points

- `make` builds all c and c++ libraries (`libapsys.a`, `libaptrace.a`,
  `libapnet.a`, `libapflow.a`, `libapbeacon.a`, `libaprisk.a`,
  `build/libapintrusion.a` and `build/libapdestructive.a`), the heap shim and
  `out/ap`; all c/c++ libraries are built by make before cargo runs.
- cargo builds offline with no external rust crates.
- `make check` runs c/c++ unit tests, 136 rust tests and 22 shell suites, including
  `scripts/test_ksensor.sh`, `scripts/test_correlation.sh`,
  `scripts/test_intrusion.sh`, `scripts/test_destructive.sh`,
  `scripts/test_audit_process.sh` and the expanded `scripts/test_update.sh`.
- `make asan` rebuilds c/c++ with gcc address and undefined sanitizers and runs
  c/c++ suites including `test_intrusion` and `test_destructive` plus
  `scripts/test_sanitizers.sh`; there are 23 shell suites in all, 22 in
  `make check` plus the sanitizer suite.
- `make bench` measures the current ipc and trace paths.

## current data paths

1. supervised child: `c/trace.c` with process-memory, kernel and file action labels ->
   `rust/src/engine.rs::trace_callback` -> detection.
2. external producer: sealed unix datagram -> `c/sys.c::ap_sys_recv_sealed` ->
   `rust/src/ipc.rs` -> engine queue -> detection.
3. bounded samplers: `c/collector.c` `/proc` lifecycle, w+x and sampled process-wide
   `io` deltas, `c/capture.c` frame or file capture, and `c/kernel.c` strict `apk1`
   replay feed standard events into the same queue.
4. kernel sensor: `c/ksensor.c` raw tracepoints and perf rings ->
   `rust/src/ksensor.rs` -> `ksensor_callback` in `engine.rs` -> engine queue;
   optional bpf-lsm deny mask is an enforcement hook, not another event source.
5. heap shim: in-process callback into the target, not a system-wide sensor.

all paths end in one in-process rust engine. `rust/src/detect.rs` feeds the
intrusion and destructive analyzers; `rust/src/correlation.rs` feeds graph, evidence,
beacon, and risk state from findings already in that engine and maps intrusion and
destructive rule tactics.
there is no separate collector process. the optional audit writer child is same-uid
and does not collect telemetry or decide policy.
