# dependency and integration plan

## dependency order

1. authenticated transport and key lifecycle. everything else sends events through it.
2. capability probe as a shared source of truth for rust policy and c collectors; ten
   source states are published by name, including `ksensor` and `lsm`.
3. telemetry backends: trace callback with file actions, authenticated ipc, a bounded
   `/proc` collector with validated map and io limits, a bounded capture backend,
   bounded kernel event-file replay and the raw kernel sensor are implemented. live eBPF, perf and lsm attach is
   unavailable and unvalidated on this host, and kprobes remain future work. analyzers
   stay source-independent except for explicit mark-3 rules.
4. detection registry with 32 descriptors, explicit telemetry requirements and cost class.
5. correlation engine fed by normalized standard events and findings, not by a second
   producer schema; bounded entity links use pid, binary, peer and privilege keys, and
   the graph/evidence/taxonomy/beacon/risk bridge appends findings to the same vector
   as the intrusion and destructive feeds in `rust/src/detect.rs`.
6. prevention backends selected by capability and policy, never by finding alone;
   ptrace stop and an optional local bpf-lsm deny mask are reported honestly, and
   `kernel_compromise` always stays `unprotected`.
7. cryptographic audit and evidence export: shared `auth` keys, hmac store chain,
   legacy fnv verification, sealed policy files, explicit degradation and a same-uid
   child audit writer with explicit status are implemented; true privilege separation
   remains unsupported.
8. bounded update-bundle integrity: strict manifest parsing, local hmac, streaming
   payload hashes, safe staging, local private-root installation with a stored release
   proof, proof-verified rollback, second-key approval and a read-only activation plan
   are implemented as one-shot local modes; secure activation, privileged replacement
   and vendor identity remain deferred.
9. bounded ipc exact-duplicate suppression, the opt-in 64-peer sequence check and its
   `/proc` starttime epochs after hmac verification, plus bounded per-client key
   selection from `SCM_CREDENTIALS`; nonces, kernel-sealed identity, durable process
   identity, vendor identity and full replay protection remain deferred.
10. bounded packet capture with frame-file validation and honest `AF_PACKET` degradation.
11. kernel sensor with hand-encoded raw tracepoint programs, bounded perf rings and
    sample-to-event conversion is wired into the engine before self-hardening. bounded
    file replay remains a separate observational substitute, not a collector. live
    attach validation on a capable host and kprobe support remain future work.
12. lsm backend for enforce mode exists as a local 32-key deny bitmap in the same c
    module. live hook validation, authenticated sensor identity and protection after
    kernel compromise remain out of scope.

## interfaces

- `apabi.h` keeps the fixed event and verdict layout. transport v3 wraps the event in
  a 256-byte authenticated packet and does not change event bytes.
- `aptransport.h` owns packet magic, size, tag and key file conventions. an optional
  bounded table maps `SCM_CREDENTIALS` pids to exact 32-byte 0600 `--client-key` files
  without changing packet bytes. `apreplay.h` owns a receiver-local tag ring and opt-in
  sequence table that also leave packet bytes unchanged.
- `aptelemetry.h` exposes ten source descriptors, not a second event schema.
- `apcollector.h` exposes a bounded, callback-driven `/proc` snapshot api that emits
  standard `ap_event` values into the same engine queue. map reads and w+x emissions are
  policy-set values with hard caps, not an unbounded scan.
- `apcapture.h` exposes a bounded capture handle that emits standard network events
  with an internal source mark; rust normalizes that mark to source `"capture"`.
- `apkernel.h` exposes a bounded `apk1` file reader that emits standard events with an
  internal non-network mark; rust normalizes that mark to source `"kernel"`. replay
  mark 2 deliberately keeps prior flow behavior and never sets the new mark-3 bits.
- `apksensor.h` exposes `ap_ksensor_probe`, `ap_ksensor_open`, `ap_ksensor_poll`,
  counters and status. `--kernel-sensor` requests raw tracepoints and the perf ring;
  `--lsm-enforce` and `--lsm-mask n` request a local bpf-lsm deny bitmap. samples become
  standard `ap_event` values with mark 3, which rust normalizes to source `"ksensor"`.
  an unavailable backend emits degraded lines and counters, never silent success.
- `apgraph.h`, `apevidence.h`, `aptaxonomy.h`, `apbeacon.h`, `aprisk.h` and
  `apintrusion.h` expose fixed limits and no new event layout. the graph has 128 nodes,
  256 edges and a 60-second window; the ledger has 256 dedupe records; the taxonomy maps
  canonical labels and aliases to rule, tactic and prior; the beacon analyzer has 64
  peers and eight samples; the risk accumulator has 64 entities and eight signals; the
  intrusion analyzer has 64 pid slots, a 10-second stage window and 5-second per-slot
  per-rule suppression.
- `rust/src/update.rs` parses bounded `ap_update_v1` manifests, reuses the shared local
  key and c sha-256 primitive, stages verified payloads and can keep two release snapshots
  under a private root with an atomic state file. each release stores a `0600` manifest
  and key; rollback re-verifies the previous release before switching. reserved payload
  names keep those proof files out of bundles. an optional `approval=<hex>` line before
  `mac=` is checked with the exact 0600 `<manifest>.approval.key` and domain
  `ap_update_approval_v1\n` when present, and `--require-approval` requires it for seal,
  verify, stage, install, rollback and plan; `manifest.approval.key` is reserved. `plan`
  verifies active proof and private state, prints `executed:false` and performs no
  writes, spawn, restart or activation. no mode touches running files.
- the audit writer can run in a same-uid child started from `/proc/self/exe` with
  `--audit-process [--audit-key path]`; records use 4-byte frames capped at 4096 bytes
  (4092-byte payload) and an exact custom key path. startup reports `"backend":"process"`
  and `"process":true`, and the summary reports `audit_writer_status` (complete, degraded
  or failed), `audit_writer_queued` and `audit_writer_dropped`; queued is not durable.
- rust owns policy, normalization, the ten-state source registry, detector selection,
  cheap rules 20/21/24/25, the bridge that maps c/c++ findings into rule 16 or 26,
  intrusion verdicts into rules 27-29, destructive verdicts into rules 30-32, decaying
  per-pid risk, prevention selection and audit. `rust/src/detect.rs` feeds the intrusion
  and destructive analyzers through `rust/src/ffi.rs`; `rust/src/correlation.rs` feeds
  graph, evidence, beacon and risk state and maps intrusion and destructive rules to
  tactics. registry filtering runs after bridge findings are appended.
- c owns syscalls, kernel interfaces, the raw sensor and lsm program, the graph,
  evidence ledger, taxonomy, cryptographic primitives, transport framing and local
  capture. `c/trace.c` emits explicit process-memory and kernel-interface labels,
  including watched `process_vm_readv`; `cpp/flow.cpp` maps the explicit labels to
  the existing `kernel_iface_bit`.
- c++ owns bounded protocol, flow, beacon, risk, intrusion and destructive computation.
  `cpp/flow.cpp` emits rules 22 and 23 only from mark-3 ksensor labels,
  `cpp/beacon.cpp` emits rule 26, `cpp/risk.cpp` reports through rule 16,
  `cpp/intrusion.cpp` emits rules 27-29 through `build/libapintrusion.a`, and
  `cpp/destructive.cpp` emits rules 30-32 through `build/libapdestructive.a`. the entity
  stage graph uses standard events, so correlation does not depend on a collector
  implementation.

## build integration

- one Makefile drives all languages; cargo stays offline with no external crates.
- new c sources join `libapsys.a` or the dedicated c/c++ libraries when they are part
  of the trusted path; the native libraries using `apksensor.h`, `apgraph.h`,
  `apevidence.h`, `aptaxonomy.h`, `apbeacon.h`, `aprisk.h`, `apintrusion.h` and
  `apdestructive.h` are built before cargo, including `build/libapintrusion.a` and
  `build/libapdestructive.a`.
- kernel-specific sources use feature checks at compile time and runtime capability
  checks; unavailable features compile into a degraded backend, not a stub that
  reports success. the sensor is opened before `ap_sys_self_harden()` denies `bpf()`.
- every new module adds its tests to `make check` and its c/c++ paths to `make asan`.
  replay, sequence, ksensor, correlation, intrusion and destructive suites run through
  the same engine and injector helpers. the current suite has 136 rust tests and 22
  shell suites in `make check`, including `test_intrusion.sh` and
  `test_destructive.sh`; `test_sanitizers.sh` runs under `make asan`, for 23 shell
  suites in total.
- the capture, kernel, ksensor and correlation fixtures are built with the test targets
  and used by the shell suites. the update suite prepares its own manifest and payloads
  inside a temporary directory.

## security boundaries

- the key file is mode 0600 and created atomically. it authenticates the transport,
  not a human identity; a same-uid process that can read it can still forge packets.
- per-client keys map the `SCM_CREDENTIALS` pid to one of at most 16 exact 32-byte 0600
  files; unmapped pids are rejected and counted with `ipc_client_key_matches` and
  `ipc_client_key_misses`. pid reuse can misroute a key, so this is not durable process
  identity. nonces and kernel-sealed identity remain deferred.
- verification uses a constant-time tag comparison. a second constant-time comparison
  against 256 stored tags drops only byte-identical replays inside the current window.
  the opt-in sequence table adds a bounded check for stale nonzero `event.seq` values from
  the observed sender pid. it stores the pid's `/proc` starttime when readable and resets a
  stale sequence after an epoch change; it does not identify processes or detect reuse when
  `/proc` is unavailable.
- verification happens at the transport boundary; event validation remains in rust.
- policy and key paths are validated before use; no environment string is trusted
  without a path check.
- capture inputs are local and bounded; capture events are observational and carry a
  source mark, not a cryptographic sensor identity. peer counters are resource signals,
  not denial inputs.
- kernel replay files are local, size-checked and abi-validated, but their events are
  supplied input. the `"kernel"` mark describes the pipeline path, not a trusted sensor,
  and replay has no containment path.
- ksensor samples are converted from bounded 48-byte records with validated label ids,
  but the resulting `"ksensor"` mark is internal. conversion emits canonical names
  where available and the taxonomy accepts a bounded alias set for common replay
  spellings; unseen text yields no prior. no mark authenticates a sensor.
- bpf-lsm enforces only the configured 32-key local deny bitmap. it is unavailable on
  this host, and even an attached hook cannot protect a compromised kernel; the
  enforcement report always keeps `kernel_compromise` as `unprotected`.
- correlation findings are heuristics over supplied observations. graph keys, evidence
  dedupe hashes and confidence totals are internal values, not proof of one actor, a
  successful tactic or a trustworthy entity identity. intrusion stage bits are inferred
  from bounded per-pid windows, so missing labels, pid reuse or eviction can hide or
  confuse a chain, and no verdict proves code injection, exploit success or a dumped
  secret.
- update manifests are local, size-checked and hmac-protected by a 0600 key, but that key
  only proves possession. installation writes verified files and a copy of the proof into
  a private root, and rollback re-verifies that proof before switching unsigned local
  state. a same-uid key holder can still forge or reseal the proof; no mode activates,
  replaces privileged files or proves vendor identity.
- the second 0600 `<manifest>.approval.key` is another local possession check, and
  `--require-approval` makes it mandatory across seal, verify, stage, install, rollback
  and plan. it is not a vendor key. `plan` prints `executed:false` and performs no
  activation, writes, spawn or file switching; neither mode proves a release is safe.
- the audit writer child shares uid and executable with the engine, so moving the write
  call site is not privilege separation. an explicit status is reported with queued and
  dropped counters; queued is not durable and a start failure is reported as degraded.
  true privilege separation, vendor identity, secure activation, live kernel validation,
  kprobes and kernel-compromise protection remain unsupported.

## validation gates

a phase is complete only when all of the following hold:

- unit tests for the new primitive or module pass;
- cross-language interop test passes where two languages touch the same bytes;
- `make check`, `make asan` and `make bench` remain clean;
- the coverage matrix and docs are updated with honest status values;
- controlled fixtures are described by what they actually exercise; live capabilities
  denied by the host are reported as degraded, not marked implemented.
