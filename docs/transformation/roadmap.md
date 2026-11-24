# phased implementation roadmap

current reference counts are 32 detector descriptors, `AP_RULE_MAX = 32` in c and
`RULE_MAX = 32` in rust, ten named source states (`ksensor` is 9 and `lsm` is 10),
136 rust tests, and 23 shell suites: 22 in `make check`, including
`test_intrusion.sh` and `test_destructive.sh`, plus `test_sanitizers.sh` for
`make asan`. older phases keep the counts recorded when they landed.

## phase 0 — assessment

deliverables: inventory, assessment, weaknesses, coverage matrix, structure,
integration plan, roadmap. status: complete.

## phase 1 — secure transport foundation

status: complete.

- add sha-256 and hmac-sha256 in c with known-answer tests.
- define a 256-byte authenticated packet wrapping the unchanged 216-byte event.
- generate and store a 0600 key at engine startup; load it in producers.
- verify credentials, packet size, magic and hmac before any event validation.
- add constant-time tag comparison and a tamper test.
- update all injectors, ipc tests, adversarial tests and docs.

acceptance: `make check`, `make asan`, `make bench` pass; forged and tampered
datagrams are rejected before detection. measured 20000/20000 accepted sealed
events at 6455.8 events per second, 0.100 cpu seconds and 5028 kb peak rss.

## phase 2 — capability and source abstraction

status: complete.

- shared capability probe for ptrace, seccomp, proc, perf, tracepoints and bpf.
- source descriptors and a rust-side source registry shown in terminal status.
- keep trace and ipc working through the same internal path.

acceptance: degraded mode reports each unavailable source by name. the observed host
mask is `7`; `perf`, `tracepoints` and `bpf` are named as unavailable in the
`sources` status line and in separate `degraded` records. `docs/compatibility.md`
records the tested configuration.

## phase 3 — detection registry

status: complete.

- module descriptors with telemetry needs, confidence, severity, cost and limits.
- per-detector enable and disable through policy, including `all` and an explicit
  allowlist; zero enabled detectors is rejected at startup.
- coverage registry generated from descriptors and printed in the terminal stream.
- analyzer gating: disabled network rules skip the packet analyzer and disabled flow
  rules skip the flow analyzer; disabled findings are filtered in every path.
- detector summary count in the final summary and auditable policy selection text.

acceptance: a new detector can be added as a descriptor without editing the engine
loop. `make check`, `make asan` and `make bench` pass. 45 rust tests pass.
`scripts/test_detectors.sh` verifies allowlisting, disablement, coverage output and
the zero-detector error. measured 20000/20000 accepted sealed events at 6620.3 events
per second, 0.120 cpu seconds and 5004 kb peak rss.

## phase 4 — system telemetry collector

status: complete for the available host backend.

- bounded c `/proc` snapshot/delta collector running in the main loop; no separate
  collector process or thread yet.
- startup baseline suppresses existing processes; later scans emit process start and
  exit, comm-change exec proxies, uid/euid changes and sampled w+x mappings.
- policy flags `--no-proc-scan`, `--proc-interval-ms` and `--proc-max-pids`, with
  defaults of 1000 ms and 256 pids and a hard cap of 512 pids.
- collector events feed the same queue, detectors, risk and store as ipc and trace
  telemetry. guard decisions on proc events are observational because no syscall stop
  is available for an external pid.
- `test_collector` and `scripts/test_proc.sh` cover lifecycle, w+x sampling, counters
  and the disabled source state.
- perf, tracepoint and bpf collectors, kernel-side filtering and ring buffers remain
  unsupported; no capability is reported active without a backend.

acceptance: `scripts/test_proc.sh` observes `process_start` and `process_exit` from a
workload outside the supervised child. `make check`, `make asan` and `make bench` pass.
48 rust tests pass. isolated ipc bench: 20000/20000 accepted at 6664.4 events per
second, 0.100 cpu seconds and 5148 kb peak rss. dedicated proc run: 6 scans, 87 events,
0.070 cpu seconds over 1279 ms and 5224 kb peak rss.

## phase 5 — kernel defense integration

status: complete for the available host backends.

- tracer and standard events distinguish `module_load`, `kexec`, `mount`,
  `namespace_change`, generic `kernel_interface`, `bpf`, `ptrace`, `setid` and
  `exec_uid_change`. the label set is bounded to nine per pid in a five-second window.
- weak `setid` telemetry no longer alerts alone. it correlates with a uid delta or a
  kernel-stop label into an explained `privilege_crossing` finding with confidence 860.
- `bpf` plus ptrace, module, kexec or another kernel interface label produces an
  explained `kernel_chain` finding with confidence 880. existing kexec and module
  chains remain, and repeated or stale windows stay quiet.
- verdict details are carried into the store and console rule arrays as a `findings`
  detail list, so chain explanations are auditable.
- enforcement status reports the real backend, seccomp and ptrace states, scope,
  `lsm` as `bpf_lsm` only when the optional hook is active and `unavailable` otherwise,
  and kernel compromise as `unprotected`. phase 21 adds that optional local deny hook;
  no protection after kernel compromise is claimed.
- `kernel_probe` exercises bpf, ptrace and module syscalls. controlled injected fixtures
  cover bpf/ptrace chains and setid/bpf privilege crossings.

acceptance: `make check`, `make asan` and `make bench` pass. 53 rust tests pass.
`test_flow` and `scripts/test_kernel_chain.sh` verify explained kernel-chain and
privilege-crossing findings. isolated ipc bench: 20000/20000 accepted at 6651.1 events
per second, 0.120 cpu seconds and 5032 kb peak rss.

## phase 6 — correlation and behavioral intelligence

status: complete for the available telemetry backends.

- bounded c++ entity graph across pid, binary, network peer and privilege context with
  32 slots and 48-byte keys; abi, transport and rule set are unchanged.
- four stage bits (`wx`, `exec`, `priv`, `net`) in a `--correlate-window-ms` window,
  default 5000 ms with a 100-60000 ms validated range.
- one explained `correlated_exploit_indicators` finding with confidence 880 when all
  four stages and at least three linked classes appear; stage windows clear after the
  finding so repeated events stay quiet.
- peer keys normalize `peer:host:port` text and ipv4/ipv6 packet hex; binary keys come
  from exec and mapped paths; privilege keys come from exec uid changes.
- `test_flow` covers positive, benign jit, benign container, window expiry, packet peer
  and one-shot behavior; `scripts/test_entity_chain.sh` checks the end-to-end store
  detail and benign silence; counters report entity events, findings and evictions.

acceptance: `make check`, `make asan` and `make bench` passed with 57 rust tests at the
time; the current suite has 136. `test_flow` and `scripts/test_entity_chain.sh` verify
the multi-stage fixture and quiet benign fixtures. isolated ipc bench then reported
20000/20000 accepted at 6655.6 events per second, 0.120 cpu seconds and 5184 kb peak
rss.

## phase 7 — live network engine

status: complete for the available host backends.

- bounded c capture backend with `AF_PACKET` interface mode and a length-prefixed
  raw-frame file/fifo mode, 20-63 byte ip-header snaplen and 16 frames per poll.
- captured frames become standard `AP_KIND_NET`/`AP_NET_PACKET` events with `pid=-1`,
  `tid=-1` and `arg[3]=1`; rust reports source `"capture"` and reuses the unchanged
  network analyzer, abi, transport and rule set.
- named `packet_capture` capability (`64`) and `capture` source state with honest
  degradation; this host denies raw packet sockets, so live interface mode is
  unavailable and frame-file mode is the validated path.
- bounded 64-slot peer tracking with one-second windows, burst and exhaustion
  counters, eviction and explicit counters; no new rule or denial path is added.
- `test_capture`, `test_cap`, `test_net`, rust policy/source/normalization tests and
  `scripts/test_capture.sh` cover framing, counters, source state, degradation and
  capture-to-detection with a controlled tcp fixture.

acceptance: `make check`, `make asan` and `make bench` passed with 60 rust tests at the
time.
`test_capture` and `scripts/test_capture.sh` verify the framed fixture produces
`"capture": "active"`, compact store records with `"source":"capture"` and a
`tcp_flag_violation` finding while `packet_capture` stays `unavailable`. isolated ipc
bench: 20000/20000 accepted at 6660.0 events per second, 0.110 cpu seconds and 5184 kb
peak rss. live packet capture is not claimed on this host.

## phase 8 — evidence and hardening

status: partial. cryptographic audit and protected policy loading are implemented;
privilege separation and secure update installation remain open. bounded update-bundle
integrity was added in phase 10.

- shared `auth` module for 0600 key lifecycle, hex codec, hmac-sha256 and constant-time
  compare, reusing the existing c crypto primitives without new rust crates.
- store records carry `v:"hmac"` and a 64-hex hmac chain keyed by `<store>.key`.
  legacy fnv-1a records still verify; new keys are created with the same strict file
  checks as transport keys. if audit key setup fails, the engine reports
  `integrity:fnv1a` and an explicit degraded line instead of silently continuing.
- signed policy file format `ap_policy_v1`, strict `key=value` lines, duplicate and
  unknown key rejection, size, line and value bounds, final `mac` over all preceding
  bytes, and `<policy>.key` with mode 0600.
- `--seal-policy`, `--verify-policy` and `--policy`; a sealed policy is converted to
  cli-like args, parsed by `Policy::from_args`, and explicit cli arguments appended
  after it override file values. `auth` errors are reported before engine startup.
- `auth`, `store`, `policyfile` and shell tests cover hex roundtrip, hmac stability,
  hmac chain verification and tamper, missing keys, strict parsing, sealed policy
  load, tampered policy rejection and cli override.

acceptance: `make check`, `make asan` and `make bench` remain clean. `test_store` and
`scripts/test_store.sh` verify hmac records, key mode and tamper failure.
`scripts/test_policy.sh` verifies sealed load, guard from policy, explicit cli override
and tampered policy rejection. 69 rust tests passed at the time; the current suite has
126. secure update installation was deferred at this phase; true privilege separation
remains unsupported.

## phase 9 — kernel event ingest

status: complete for bounded file replay. live `perf`, tracepoint and bpf collection is
not implemented and stays unavailable on this host.

- `include/apkernel.h` and `c/kernel.c` define a strict `apk1` file format: four-byte
  magic, a little-endian u32 record count and raw 216-byte `ap_event` records.
- files must be regular, exactly sized and capped at 4096 records. bad magic, bad count,
  truncation, trailing bytes, bad abi version, bad kind, wrong size and missing text
  terminators are rejected; counters report frames, parsed, invalid and errors.
- non-network events receive `arg[3]=2`; network capture marks are left unchanged, so
  rust reports source `"kernel"` without stealing source `"capture"`.
- `--kernel-events path` opens the file before startup, publishes a `kernel` source as
  active or unavailable with a named reason, streams a status line with mode and
  counters, and adds kernel counters to the final summary.
- `--once` now waits for both the tracer and kernel replay to finish. a missing or
  invalid file degrades cleanly and is counted as complete for `--once`.
- kernel replay feeds the unchanged detectors, risk and store. it is observational:
  findings and policy decisions are recorded, but no live collector or containment is
  implied.
- `test_kernel`, `kernel_fixture`, rust kernel wrapper tests and `scripts/test_kernel.sh`
  cover replay, marking, counters, strict rejection, explained bpf/ptrace and setid
  chains, completion and missing-file degradation.

acceptance: `make clean && make check && make asan && make bench` passed at the time
with 74 rust tests; the current suite has 136. `test_kernel` and
`scripts/test_kernel.sh` verify the fixture path and explicit degradation. the recorded
phase 9 bench is 20000/20000 accepted sealed events at 6657.8 events per second, 0.100
cpu seconds and 5184 kb peak rss; replay is not part of the throughput workload. the
separate kernel sensor in phase 21 adds live-capable c machinery, but this replay path
and its mark 2 behavior are unchanged.

## phase 10 — update bundle integrity

status: complete for bounded verification and staging. automatic installation,
activation, privileged replacement and vendor identity were not implemented at this phase;
local snapshots and rollback came in phase 16.

- `rust/src/update.rs` parses a strict `ap_update_v1` manifest: a fixed header, relative
  normalized `file=` lines, lowercase sha-256 hashes, a final `mac=` line and no extra
  keys. bounds are 64 kib, 256 lines, 4096 bytes per line and 16 mib per payload.
- manifests and payloads must be regular non-symlink files that are not group or other
  writable. absolute paths, `.` and `..`, doubled slashes, trailing slashes, whitespace,
  backslashes and duplicates are rejected before any key is used.
- the final hmac-sha256 is computed by the existing c primitive over all preceding
  manifest bytes using a 0600 key at `<manifest>.key`. the key authenticates possession
  only; it does not establish a vendor or process identity.
- payload hashes stream through the c sha-256 api via a layout-checked rust ffi context.
  hash and mac comparisons are constant-time.
- `--seal-update` seals an unsealed manifest, `--verify-update` checks the mac and every
  payload, and `--stage-update manifest destination` verifies then copies into a fresh
  `0700` directory with `0600` files. an existing destination is rejected; no running
  file is replaced.
- `update.rs` unit tests and `scripts/test_update.sh` cover sealing, verification,
  staging, mode checks, payload and mac tamper, five unsafe path forms, duplicate paths,
  symlinks, missing payloads and an existing destination.

acceptance: `make clean && make check && make asan && make bench` passed at the time with
80 rust tests; the current suite has 136. update modes are one-shot and are not part of
the throughput workload. the
recorded phase 10 bench is 20000/20000 accepted sealed events at 6662.2 events per
second, 0.110 cpu seconds and 5236 kb peak rss. staging is not installation and the
local key is not a vendor signature.

## phase 11 — bounded ipc duplicate suppression

status: complete for exact duplicate packets. this is not full replay protection, a nonce,
per-client identity or containment of a key holder.

- `include/apreplay.h` and `c/replay.c` define a fixed 256-entry ring of 32-byte packet
  tags, a validity byte per slot, a wrap index and accepted/duplicate counters.
- `ap_replay_accept` runs only after `ap_transport_open` verifies magic, version, type,
  exact size, hmac and ucred checks in `ap_sys_recv_packet`. it uses `ap_constant_time_eq`
  for tag membership and evicts the oldest tag when full.
- `ap_sys_recv_sealed_filtered` adds the filter to the existing receive path without
  changing the 256-byte packet or 216-byte event layout. the unfiltered c api remains for
  producers and legacy callers.
- rust owns one filter per `Ipc` receiver, counts only `AP_ERR_REPLAY` through an
  `Arc<AtomicU64>` and publishes the count as `ipc_duplicates` when ipc is enabled.
  foreign-uid `AP_ERR_STATE` drops are not counted as duplicates. no new cli option or
  packet byte is introduced.
- `test_replay` checks fresh state, exact-duplicate rejection, 257-packet wrap eviction,
  counters and filtered socket receive. `scripts/test_replay.sh` injects three
  byte-identical packets and requires two suppressed duplicates in the engine summary.
  rust tests check the c/rust layout and duplicate suppression.

acceptance: `make clean && make check && make asan && make bench` passed at the time with
82 rust tests; the current suite has 136. the recorded phase 11 bench is 20000/20000
accepted sealed events at 6512.5 events per second, 0.180 cpu seconds and 5268 kb peak
rss. the fixed comparison loop is included in the ipc path; an older exact packet or a
resealed forgery is still outside coverage.

## phase 12 — opt-in bounded ipc sequence check

status: complete for stale nonzero sequence suppression on the authenticated ipc path.
this is not process identity, pid-reuse detection, a nonce or full replay protection.

- `AP_ERR_SEQUENCE = -9` and `sequence_rejected` separate stale sequence drops from exact
  duplicates and foreign-uid state errors.
- `ap_replay` keeps a fixed 64-peer table in addition to the 256-tag ring. peers are keyed
  by the pid already supplied in `SCM_CREDENTIALS`; the table evicts its oldest slot when
  full. the packet and event layouts are unchanged.
- `ap_replay_accept_sequence` checks the exact tag first, so byte-identical packets stay
  `ipc_duplicates`. nonzero `event.seq` must increase per peer; equal or lower values are
  dropped and counted as sequence drops. sequence zero is unsequenced.
- `ap_sys_recv_sealed_sequenced` routes the opt-in receive path. rust `Ipc::open` takes a
  strict-sequence flag, counts `ERR_SEQUENCE` separately and publishes
  `ipc_sequence_drops` in the summary when ipc is enabled.
- `--ipc-strict-seq` is accepted on the cli and in sealed `ap_policy_v1` files. it is off
  by default; the normal filtered receive path keeps phase 11 behavior.
- `test_replay` covers stale sequences, zero handling, 64-peer eviction and the sequenced
  socket path. `scripts/test_sequence.sh` starts the engine with the opt-in flag and
  injects a stale sequence with a fresh tag; rust checks layout, flag parsing and separate
  counters.

acceptance: `make clean && make check && make asan && make bench` pass with 84 rust tests.
the recorded phase 12 bench is 20000/20000 accepted sealed events at 6506.2 events per
second, 0.180 cpu seconds and 5320 kb peak rss; the opt-in sequence check is not part of
the benchmark path. a same-uid key reader can still forge or reseal a fresh higher
sequence; phase 12 alone left pid reuse undetected, which phase 13 narrows when `/proc` is
readable.

## phase 13 — pid epoch aware sequence state

status: complete for reducing stale drops after a changed process epoch in the opt-in
sequence path. this is not process identity, containment or full replay protection.

- `ap_replay` stores one `/proc` starttime epoch per sequence peer inside the existing
  64-slot table. the packet and event layouts are unchanged and no new cli option appears.
- `ap_sys_proc_starttime` now reads field 22, the process starttime, from
  `/proc/<pid>/stat`; it previously read `utime`. `test_collector` checks the parser
  against a known answer from `/proc/self/stat`.
- the epoch is read when a peer slot is created and again when a sequence is stale. a
  changed nonzero epoch resets that slot and treats the stale value as the first sequence
  of the new pid epoch. unchanged or zero epochs keep the stale drop.
- when `/proc` is unreadable the epoch is zero, so earlier sequence behavior remains.
  `test_replay` simulates an epoch change by replacing the stored value; it does not
  create a real reused pid. rust mirrors the extended `Replay` layout.

acceptance: `make clean && make check && make asan && make bench` pass with 84 rust tests.
the final phase 13 bench is 20000/20000 accepted sealed events at 6478.8 events per
second, 0.190 cpu seconds and 5324 kb peak rss; the opt-in sequence table and its
starttime lookup are not part of the benchmark path. full values are recorded in
`docs/performance.md`. an unreadable starttime still leaves pid reuse undetected, and a
same-uid key reader can still forge a fresh higher sequence.

## phase 14 — bounded proc sampling policy

status: complete for validated map-sample and w+x emission limits on the proc collector.
this is not kernel push telemetry and does not close the short-lived process gap.

- `ap_collector_set_map_limits` stores 1-32 map reads and 1-16 w+x emissions per scan;
  defaults remain 8 and 4. `ap_collector_map_limits` reads the active values back, and
  the event, packet and abi layouts are unchanged.
- `--proc-map-samples` and `--proc-wx-per-scan` are accepted on the cli and in sealed
  policy files. out-of-range and zero values are rejected before engine startup.
- the proc status line publishes `map_samples` and `wx_per_scan`, and the policy summary
  records both values. `test_collector` checks setter bounds, getter state and a two-emission
  cap against multiple writable-executable mappings; `scripts/test_proc.sh` checks the
  end-to-end status fields and rejects invalid values.

acceptance: `make clean && make check && make asan && make bench` pass with 84 rust tests.
the final phase 14 bench is 20000/20000 accepted sealed events at 6493.5 events per
second, 0.180 cpu seconds and 5360 kb peak rss; the proc run uses the default 8 map
samples and 4 w+x emissions, and the opt-in sequence table is disabled. full values are
recorded in `docs/performance.md`. raising the bounds increases map reads and cost, and
comm changes remain exec proxies rather than proof.

## phase 15 — aged entity references

status: complete for limiting stale text-derived links in the bounded c++ entity graph.
this is not authenticated sensor identity and does not prove exploit chains.

- `pid_flow` records the timestamp of each binary, peer and privilege reference. the
  configured entity window now ages them out; expired keys are cleared and counted in
  `entity_refs_expired` in the flow status and summary.
- closure ages references before merging stage windows, so an old binary, peer or uid key
  cannot keep linking four fresh stages. the fixed 32 entity slots and 48-byte keys are
  unchanged, and no event, packet or verdict layout changes.
- `test_flow` feeds a stale binary key and four fresh stages with a one-second window and
  requires no entity finding plus a counted expiry. a rust test mirrors the stream, and
  `detect.rs` exposes the counter through `Analyzers::counters`.

acceptance: `make clean && make check && make asan && make bench` pass with 85 rust tests.
the final phase 15 bench is 20000/20000 accepted sealed events at 6489.3 events per
second, 0.190 cpu seconds and 5252 kb peak rss; the opt-in sequence table remains disabled.
full values are recorded in `docs/performance.md`. missing, changed or aliased keys can
still hide or confuse a chain.

## phase 16 — local update snapshots and rollback

status: complete for verified release snapshots under a private application-owned root.
this is not activation, privileged replacement, a vendor key or proof that files are safe.

- `--install-update manifest root` verifies the sealed bundle, stages it into
  `releases/<32-hex-id>` and writes `state` with `ap_update_state_v1`, `active` and
  `previous` through a temporary file and rename. roots, release directories and state
  must be regular, current-uid-owned and not group or other writable. older generated
  releases are pruned best-effort after the state switch.
- `--rollback-update root` validates the same root and state, checks the previous release
  directory, swaps active and previous in one atomic state rewrite, and prunes older
  releases. a missing state file means no installed release; invalid state is rejected.
- nested staging directories are created at `0700`. rust unit tests cover two releases,
  state, rollback, invalid state and a group-writable root. `scripts/test_update.sh`
  covers the same cli lifecycle and rejects a non-private root. update modes are one-shot.

acceptance: `make clean && make check && make asan && make bench` pass with 88 rust tests.
the final phase 16 bench is 20000/20000 accepted sealed events at 6655.6 events per
second, 0.210 cpu seconds and 5340 kb peak rss; the opt-in sequence table remains disabled
and update modes are not part of the throughput workload. full values are recorded in
`docs/performance.md`. activation, vendor identity and privileged replacement remain
outside scope.

## phase 17 — stored release proof and verified rollback

status: complete for local proof carried inside verified release snapshots.
this is not a vendor signature, signed state, activation or protection against a
same-uid key holder.

- installation copies the sealed manifest and its local key into the release as `manifest`
  and `manifest.key` at mode `0600`, then verifies the stored proof against the installed
  payloads before switching state. both names are reserved in bundle manifests.
- rollback re-verifies the previous release with its stored proof before switching state.
  a tampered payload or missing proof is rejected and the recorded state is left unchanged.
- rust unit tests cover stored proof, reserved names, a tampered previous payload and a
  missing proof. `scripts/test_update.sh` checks the stored file modes and rejects a
  tampered rollback target. no new cli mode was needed.

acceptance: `make clean && make check && make asan && make bench` pass with 89 rust tests.
the final phase 17 bench is 20000/20000 accepted sealed events at 6487.2 events per
second, 0.190 cpu seconds and 5348 kb peak rss; the opt-in sequence table remains disabled
and update modes are not part of the throughput workload. full values are recorded in
`docs/performance.md`. the proof is local, a same-uid key holder can forge or reseal it,
state is unsigned, and activation, privileged replacement and vendor identity remain
outside scope.

## phase 18 — second-key approval and read-only activation plan

status: complete for local one-shot approval and a read-only activation plan.
this is not vendor identity, activation, durable process identity or privilege
separation.

- `--require-approval` is accepted for seal, verify, stage, install, rollback and
  plan; an optional `approval=<hex>` line before `mac=` is verified when present,
  and the flag requires it.
- the second key must be an exact 32-byte file at `<manifest>.approval.key` with
  mode 0600; the hmac uses the domain `ap_update_approval_v1\n`, and
  `manifest.approval.key` is a reserved payload name. the key proves local
  possession only.
- `plan` verifies the active release proof and private state and prints
  `executed:false`; it performs no writes, spawn, restart, activation or file
  switching.
- rust update and policy tests plus the expanded `scripts/test_update.sh` cover
  approval verification, missing or failed approval, the reserved name, key mode
  and the read-only plan output.

acceptance: `make check` and `make asan` passed with an earlier, smaller rust suite;
the current suite has 136 tests. the recorded phase benchmark is in
`docs/performance.md`.
a second local key is not a vendor key, the plan is not activation, and neither is a
proof that a release is safe.

## phase 19 — per-client ipc keys

status: complete for bounded per-client key selection on the authenticated ipc
path. this is not vendor identity, activation, durable process identity or
privilege separation.

- `--client-key pid:path` is repeatable up to 16 entries; each key path must be an
  exact 32-byte regular file with mode 0600.
- the key is selected from the pid in `SCM_CREDENTIALS`; packet bytes and the
  216-byte event layout are unchanged.
- unmapped pids are counted and rejected; `ipc_client_key_matches` and
  `ipc_client_key_misses` report selection outcomes.
- rust ipc tests cover the table bound, key and mode checks, pid selection,
  misses and counters. pid reuse can map a new process to the wrong key, so no
  durable process identity is established.

acceptance: `make check` and `make asan` passed with an earlier, smaller rust suite;
the current suite has 136 tests. the recorded phase benchmark is in
`docs/performance.md`.
the shared key and same-uid readers remain, and per-client selection adds no nonces,
vendor identity or full replay protection.

## phase 20 — audit writer process boundary

status: complete for a same-uid child write boundary for the audit store. this is
not vendor identity, activation, durable process identity or privilege
separation.

- `--audit-process [--audit-key path]` starts a child from `/proc/self/exe` under
  the same uid; the child owns the audit store write call site. an explicit
  custom key path must be exact.
- records use a 4-byte length frame with a 4096-byte frame cap and a 4092-byte
  payload cap.
- startup reports `"backend":"process"` and `"process":true`; the summary reports
  `audit_writer_status` as `complete`, `degraded` or `failed`, plus
  `audit_writer_queued` and `audit_writer_dropped`. a failed start emits a
  degraded line rather than silent success.
- c `test_audit`, rust audit and store tests and `scripts/test_audit_process.sh`
  cover framing, key path checks, status and counters. queued is not durable, and
  the child shares uid and executable with the engine.

acceptance: `make check` and `make asan` passed with an earlier, smaller rust suite;
the current suite has 136 tests. the recorded phase benchmark is in
`docs/performance.md`.
the child moves the write call site only; it is not privilege separation, and queued
records are not a durable audit boundary.

## phase 21 — raw kernel sensor and optional lsm

status: complete for the bounded c backend and engine wiring. live eBPF, perf and lsm
attachment cannot be validated on this host, whose capability mask is 7; kprobes remain
future work and lsm does not protect a compromised kernel.

- `--kernel-sensor` requests raw tracepoint attach and the perf ring collector.
  `--lsm-enforce` requests an optional `BPF_PROG_TYPE_LSM` program at `BPF_LSM_MAC`,
  and `--lsm-mask n` configures up to 32 local deny keys. none of the flags implies
  host support.
- `ap_ksensor_probe()` checks the `bpf()` syscall, a `PERF_COUNT_SW_BPF_OUTPUT`
  perf event and the `bpf` token in `/sys/kernel/security/lsm`. the sensor creates
  a per-cpu `PERF_EVENT_ARRAY`, a 32-key deny map and up to 16 program, link and perf
  fd slots.
- nine hand-encoded raw tracepoint programs cover `sched_process_exec`,
  `sched_process_exit`, `bpf_prog_load`, `do_init_module`, `commit_creds`,
  `ptrace_access_check`, `security_file_open`, `tty_write` and `vfs_write`. each
  attach is independent; a partial attach yields a degraded reason, while at least
  one success is required for an active sensor.
- the perf path uses 16 bounded cpus and 64 pages per ring, validates 48-byte
  `PERF_RECORD_SAMPLE` payloads and label ids, handles at most 256 samples per poll,
  and counts invalid or lost records instead of dispatching them.
- `ap_ksensor_sample_to_event()` emits standard 216-byte `ap_event` values with
  `AP_KIND_KERNEL`, split pid/tid, mark 3 and confidence 900 or 950. rust normalizes
  mark 3 to source `"ksensor"`; replay mark 2 deliberately keeps its prior behavior.
- the sensor is opened before self-hardening seccomp denies `bpf()`. `ksensor` and
  `lsm` join the named source registry as its ninth and tenth states; requested but
  unavailable backends emit lowercase degraded lines with probe bits.
- the summary publishes `ksensor_events`, `ksensor_invalid`, `ksensor_dropped`,
  `ksensor_attached`, `lsm_active` and `lsm_denies`, plus the graph, evidence, beacon,
  risk and intrusion counters from phases 22-24. `lsm_denies` counts installed deny
  keys, not runtime rejections.
- `test_ksensor`, c taxonomy/graph/evidence tests, c++ beacon/risk tests and
  `scripts/test_ksensor.sh` cover probes, null safety, sample conversion, source
  states, degraded lines and counters.

acceptance: `make check` includes `test_ksensor` and `scripts/test_ksensor.sh`; the
current suite has 136 rust tests. no live eBPF program, perf ring or lsm deny is claimed
on this host, and `kernel_compromise` remains `unprotected` even when lsm is active.

## phase 22 — graph, evidence and taxonomy bridge

status: complete for bounded observational correlation. it adds no event, packet or
verdict layout change and no new rule id.

- `c/graph.c` keeps 128 nodes, 256 edges, 64-byte entity keys and 32 chain-suppression
  slots in a 60-second window with 30-second repeat suppression. a finding needs three
  linked nodes, three distinct tactics, one high-value tactic and confidence sum 1800.
- `c/evidence.c` keeps 256 dedupe records with 64-byte keys and a 30-second window. it
  uses a bounded non-cryptographic fnv-1a hash and counts inserts, duplicates and
  evictions; the hmac audit store remains the durable record.
- `c/taxonomy.c` maps canonical labels and bounded aliases to rule, tactic and confidence
  priors. sensor conversion uses canonical names where available, and common replay
  spellings are accepted as aliases; unknown text yields no prior. numeric lookup by
  label id remains independent of text. the alias limit is recorded in
  `docs/detection/taxonomy.md` and `docs/transformation/weaknesses.md`.
- `rust/src/correlation.rs` turns findings into graph observations, dedupes them through
  the ledger and emits `correlated_exploit_indicators` (rule 16). unknown text falls
  back to a kind-derived tactic and the event confidence, and no rule id is inferred.
- bridge findings are appended to the same vector as cheap rules and c++ analyzers;
  registry filtering runs afterward, so `--enable`, `--disable` and policy selection
  apply to every emitted verdict. graph and ledger keys are internal, not authenticated
  process identities.
- `test_graph`, `test_taxonomy`, `test_evidence` and `scripts/test_correlation.sh`
  cover bounded insertion, eviction, aliases, dedupe and the end-to-end summary path.

acceptance: the current suite has 136 rust tests. `graph_added`, `graph_evicted`,
`graph_findings`, `graph_suppressed`, `evidence_inserted`, `evidence_duplicates` and
`evidence_evicted` are published in the final summary. the bridge remains a heuristic
over supplied observations and does not prove actor identity or a successful tactic.

## phase 23 — beacon and risk findings

status: complete for bounded observational timing and risk accumulation. rule 26 exists
in the 29-descriptor registry and is no longer the last rule; the c++ accumulator
reports through rule 16.

- `cpp/beacon.cpp` tracks 64 peers with eight samples each in a 90-second window and
  30-second repeat suppression. a finding needs three samples, a nonzero mean interval
  no larger than 60 seconds, jitter within `mean / 5 + 500 ms` and at least two samples
  with bytes sent. scores are 700/800/900 for 3/4/5-or-more samples.
- `rust/src/correlation.rs` feeds network and flow events to the analyzer, using event
  text or a `peer-<pid>-<arg0>` fallback and `arg[0]` as the byte count. a c++ finding
  maps to `RULE_BEACONING`, source `"network"` and severity medium; `beacon_findings`
  counts it in the summary.
- `cpp/risk.cpp` holds 64 entities with eight 48-byte-key signals each in a 90-second
  window and 30-second finding suppression. it needs two in-window signals, sum 1500,
  two tactics and one high-value rule. rules 20-25 are high-value; rule 26 maps to
  command and control.
- that c++ accumulator is separate from the decaying per-pid risk in `rust/src/risk.rs`
  that feeds guard. its finding maps to `RULE_CORRELATED`, source `"risk"` and is
  counted as `risk_findings`; it does not add a new rule id.
- cheap rules 20, 21, 24 and 25 remain in rust; `cpp/flow.cpp` owns rules 22 and 23
  from mark-3 labels. all ten advanced rules (20-29) honor the shared registry gating.
- `test_beacon`, `test_risk` and `scripts/test_correlation.sh` cover the bounded
  analyzers and the summary path. benign timers, shared keys and missing sensor labels
  can still cause false positives or false negatives.

acceptance: the current suite has 136 rust tests and 22 shell suites in `make check`,
including `test_intrusion.sh`. `beacon_findings` and `risk_findings` are published with
the graph, intrusion and ksensor counters. no timing or accumulator result is treated
as proof of command and control or intent.

## phase 24 — bounded intrusion-stage analyzer

status: complete for bounded behavioral and telemetry correlation. no live coverage is
claimed, and the analyzer does not guarantee detection of all exploitation types.

- `include/apintrusion.h` and `cpp/intrusion.cpp` add 64 fixed pid slots, a 10-second
  stage window and 5-second per-slot per-rule suppression. stage bits are remote_write,
  remote_read, cred_access, wx, exec, redirect, priv and net; w+x requires both write
  and exec bits (`arg[2] & 6 == 6`), not either bit alone.
- rules 27 `process_injection` (870, or 890 with redirect), 28 `exploit_chain` (920 with
  priv else 890) and 29 `credential_dump` (900) use detail prefixes exactly
  `process_injection:`, `exploit_chain:` and `credential_dump:`. priority is
  credential_dump > process_injection > exploit_chain, so at most one verdict is
  emitted per event. counters are added, evicted, findings and suppressed; the
  summary publishes `intrusion_findings` and `intrusion_suppressed`.
- `build/libapintrusion.a` is linked through `rust/src/ffi.rs`, gated by
  `DetectorRegistry::intrusion_enabled()`, fed from `rust/src/detect.rs`, and mapped to
  tactics in `rust/src/correlation.rs`: process_injection to defense evasion,
  exploit_chain to privilege escalation and credential_dump to credential access.
- `c/trace.c` adds explicit labels `process_vm_writev`, `process_vm_readv`,
  `userfaultfd`, `io_uring_setup` and `open_by_handle_at`; `process_vm_readv` is watched.
  `cpp/flow.cpp` maps them to the existing `kernel_iface_bit` for legacy kernel-chain
  compatibility, and `tests/kernel_probe.c` touches `process_vm_readv`.
- `AP_RULE_MAX` is 29 in c and `RULE_MAX` is 29 in rust; rule ids are 1..29. the static
  registry has 29 descriptors, all enabled by default; disabling one yields 28 and
  `--enable all` yields 29. `scripts/test_detectors.sh` checks `"enabled": 28`.
  `tests/test_intrusion.cpp` and `scripts/test_intrusion.sh` cover the analyzer and exact
  store rules `"rule":"process_injection"`, `"rule":"exploit_chain"` and
  `"rule":"credential_dump"`, plus a negative single-signal case. `test_intrusion` joins
  `make check` and `make asan`, and `fuzz_analyzers` links `libapintrusion.a`.

acceptance: the current suite has 136 rust tests and 22 shell suites in `make check`,
plus `test_sanitizers.sh` for `make asan`. final phase-24 bench: 20000 injected, 11187
accepted, 3670.3 events per second, 0.360 cpu seconds, 5632 kb max rss and 1 ms
detection latency; 8813 of 20000 were not accepted. lsm is optional, live eBPF, perf,
lsm and AF_PACKET remain unvalidated here at capability mask 7, and `kernel_compromise`
stays `unprotected`.

## phase 25 — bounded destructive file and chain analysis

status: complete for bounded file telemetry and behavioral correlation. no live file
sensor is available here, and the analyzer does not guarantee detection of all
destructive behavior, exploitation types or zero-days.

- `include/apabi.h` adds `AP_KIND_FILE=12`, `AP_FILE_IO=1`, `AP_FILE_ACTION=2`, rules
  30 `file_write_burst`, 31 `destructive_chain` and 32 `data_exfiltration`, and
  `AP_RULE_MAX=32`. c `tests/test_abi.c` and rust abi tests check the bound.
- `c/collector.c` samples bounded process-wide `/proc/<pid>/io` deltas with
  `ap_collector_scan_pid_io()`. `--proc-io-per-scan` sets 1-32 pids per scan, default
  8. events carry `arg[0]=wchar_delta`, `arg[1]=syscw_delta`, `arg[2]=rchar_delta`,
  `arg[3]=read_bytes_delta` and `text=comm`; they are not per-file write records.
- `c/trace.c` emits traced `file_rename`, `file_unlink` and `file_chmod` actions as
  `AP_FILE_ACTION` under `AP_TRACE_MASK_FILE=32`; `--mask` now defaults to 63.
- `include/apdestructive.h` and `cpp/destructive.cpp` add 64 pid slots, a 10-second
  window and 5-second per-slot per-rule suppression. write bursts use 64 write calls
  or 1 MiB with at least 8 write calls; destructive chains add at least two
  rename/unlink/chmod/handle actions; exfiltration adds a network connect to a read
  burst of 4 MiB bytes or 8 MiB chars. confidences are exactly 870, 900 and 880, with
  prefixes `file_write_burst:`, `destructive_chain:` and `data_exfiltration:`. at most
  one verdict is emitted per feed with priority destructive_chain > data_exfiltration >
  file_write_burst.
- `rust/src/ffi.rs` links `build/libapdestructive.a`, `DetectorRegistry::destructive_enabled()`
  gates it and `rust/src/detect.rs` feeds file, network and kernel events. summary
  counters are `destructive_findings` and `destructive_suppressed`; proc status adds
  `file_events`, `file_samples`, `file_errors` and `io_per_scan`.
- `--chain-guard` is opt-in and requires `--guard` plus a nonempty `--deny` or `--stop`
  set. `rust/src/guard.rs` keeps 64 pid slots over 10 seconds and needs three distinct
  high-value rules at or above `--min-confidence` before a deny or stop can happen;
  risk, confidence and rule gates still apply. `chain_findings` counts crossings.
- `tests/test_destructive.cpp`, `tests/test_collector.c`, fuzz coverage,
  `tests/inject.c` fixtures `fileburst`, `destructive`, `exfil` and `filebenign`, and
  `scripts/test_detectors.sh`, `scripts/test_proc.sh` and `scripts/test_destructive.sh`
  cover the new paths. exact store rules are checked; final phase-25 bench reported
  3723.0 accepted events per second with a 7 ms detection latency, and a later repeated
  run reported 3443.5 with 1 ms. capability mask stays 7, so live eBPF, perf, lsm and
  `AF_PACKET` remain unvalidated, and `kernel_compromise` stays `unprotected`.

phases are implemented in order; each phase compiles and tests before the next begins.
remaining work is live sensor validation, kprobes, authenticated sensor identity,
vendor-backed activation, privilege separation, and kernel-compromise protection.
sensor and taxonomy text is reconciled through canonical names and bounded aliases.
