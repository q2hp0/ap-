# status

ap is at abi version 2 with authenticated transport, ten named sources, a 32-rule
detector registry, a bounded `/proc` collector with sampled file IO deltas, kernel,
credential and cross-entity correlation, an optional raw kernel sensor, bounded graph,
evidence, beacon, intrusion, destructive-file and risk analyzers, a bounded packet-capture
backend, bounded kernel event-file replay and
keyed audit, policy and update-bundle integrity. bounded ipc duplicate suppression,
an opt-in sequence check with process-epoch awareness, configurable `/proc` map
sampling, aged entity references, local update snapshots and verified rollback are
part of the same platform. four trust-boundary additions cover optional update
approval, a read-only activation plan, per-client ipc keys and a same-uid audit
writer process.

phase 8 is partial: audit and policy signing are implemented, while privilege
separation is not. phase 9 is complete for bounded `apk1` replay; live `perf`,
tracepoint and bpf collectors remain unavailable on this host. phase 10 is complete
for bounded update-bundle verification and staging. activation itself, privileged
replacement and vendor identity remain unimplemented; the plan mode only reads and
reports. phase 11 adds a bounded 256-slot exact-duplicate filter at the authenticated
ipc boundary; it does not stop a key holder from generating new packets. phase 12
adds an opt-in 64-peer monotonic sequence check that drops stale nonzero sequence
numbers from the same observed sender pid. phase 13 binds those sequence slots to the
`/proc` starttime of the observed pid when it is readable, so a changed epoch resets
stale sequence state. phase 14 makes the bounded `/proc` map-sample and w+x emission
counts configurable through validated policy flags with hard caps. phase 15 ages
text-derived binary, peer and privilege references with the entity window so stale
keys cannot keep linking fresh stages; it does not make the keys authenticated. phase 16
verifies bundles into private-root release snapshots, prunes older generated releases
best-effort and switches an atomic local state file; phase 17 stores a sealed manifest
and 0600 key in each release and verifies the rollback target before switching. neither
activates code or proves vendor identity.

a later sensor and correlation layer adds `c/ksensor.c`, `c/graph.c`, `c/evidence.c`,
`c/taxonomy.c`, `cpp/beacon.cpp`, `cpp/risk.cpp` and `rust/src/correlation.rs`. the
sensor opens before self-hardening because seccomp denies `bpf()`, and any open, map,
perf or attach failure emits a degraded line and continues. phase 24 is complete and
validated: it adds `include/apintrusion.h`, `cpp/intrusion.cpp` linked as
`build/libapintrusion.a`, the `rust/src/ffi.rs` wrapper, `DetectorRegistry::intrusion_enabled()`
gating, the `rust/src/detect.rs` feed path and tactic mappings in
`rust/src/correlation.rs`. phase 25 is complete and validated for bounded file and
chain telemetry: it adds `include/apdestructive.h`, `cpp/destructive.cpp` linked as
`build/libapdestructive.a`, `ap_collector_scan_pid_io()` and sampled `/proc/<pid>/io`
deltas in `c/collector.c`, `AP_KIND_FILE` with `AP_FILE_IO` and `AP_FILE_ACTION`,
trace labels `file_rename`, `file_unlink` and `file_chmod`, `AP_TRACE_MASK_FILE`,
the `--proc-io-per-scan` and `--chain-guard` policy flags, and the
`rust/src/guard.rs` bounded chain tracker. rule ids 20-32 and
`AP_RULE_MAX`/`RULE_MAX=32` are checked from c and rust. the registry has 32 default
enabled descriptors; disabling one yields 31 and `--enable all` expands to 32. the
suite has 136 rust tests and 22 check-time shell suites alongside the c and c++
unit tests; `test_sanitizers.sh` brings the total `test_*.sh` count to 23.

the observed host mask stays `7`: perf, tracepoints, bpf and `AF_PACKET` are denied,
so live ebpf, perf, lsm and raw capture cannot be validated here. `lsm` reports
`bpf_lsm` only when an attach succeeds and `unavailable` otherwise; kernel compromise
stays `unprotected`. frame-file capture and bounded `apk1` replay are validated.
none of this is process identity, a nonce or full replay protection. the default mode
is monitor-only; enforcement is opt-in through `--guard`.

## subsystems

| area | implementation | state |
| --- | --- | --- |
| abi | `include/apabi.h`, `c/abi.c`, `rust/src/abi.rs` | versioned 216-byte events and 168-byte verdicts, layout checked from both languages, v1 producers rejected |
| engine | `rust/src/engine.rs` | bounded queue, event loop, validation, telemetry, correlation bridge, summary and degraded-capability handling |
| policy and risk | `rust/src/policy.rs`, `rust/src/policyfile.rs`, `rust/src/risk.rs`, `cpp/risk.cpp` | explicit opt-in actions, sealed policy loading with cli override, saturating decay, bounded per-pid and entity state with eviction, configurable queue depth with nonblocking drop counting |
| guard and audit | `rust/src/guard.rs`, `rust/src/store.rs`, `rust/src/auth.rs`, `c/sys.c` | audited allow/deny/stop decisions, honest backend and lsm status, bounded audit, rotating jsonl store with an hmac-sha256 chain and legacy fnv verification, optional same-uid framed writer process |
| capability | `include/apcap.h`, `c/cap.c` | named probe for seccomp, ptrace, proc, perf, tracepoints, bpf and packet capture; mask stays 7 on this host |
| source registry | `include/aptelemetry.h`, `c/telemetry.c`, `rust/src/source.rs` | ten named source states in the terminal stream; trace, ipc, proc, perf, tracepoints, bpf, capture, kernel, ksensor and lsm share one reporting path |
| proc collector | `include/apcollector.h`, `c/collector.c`, `rust/src/collector.rs` | bounded `/proc` snapshot/delta: process lifecycle with starttime-based reuse checks, comm and uid/euid changes, configurable sampled w+x maps and sampled process-wide `io` deltas; poll-based and observational |
| capture | `include/apcapture.h`, `c/capture.c`, `rust/src/capture.rs` | bounded `AF_PACKET`/frame-file reader, 20-63 byte snaplen, 16 frames per poll, source-marked `ap_event` values, counters and degraded live mode |
| kernel replay | `include/apkernel.h`, `c/kernel.c`, `rust/src/kernel.rs` | strict `apk1` file ingest, 4096-event cap, source-marked events, kernel source state and counters; observational |
| kernel sensor | `include/apksensor.h`, `c/ksensor.c`, `rust/src/ksensor.rs` | optional raw `bpf()`/`perf_event_open()` sensor, hand-encoded ebpf tracepoints, bounded 48-byte samples, source mark `3`, optional `BPF_LSM_MAC` hook, degrade and continue on failure; live behavior unvalidated here |
| correlation | `include/apgraph.h`, `include/apevidence.h`, `include/aptaxonomy.h`, `include/apbeacon.h`, `include/aprisk.h`, `c/graph.c`, `c/evidence.c`, `c/taxonomy.c`, `cpp/beacon.cpp`, `cpp/risk.cpp`, `rust/src/correlation.rs` | 12 canonical labels with aliases; bounded tactic graph, 256-slot evidence ledger, beacon and risk analyzers; summary counters for added, evicted, duplicate and finding observations; heuristics over supplied telemetry |
| update integrity | `rust/src/update.rs`, `rust/src/auth.rs`, `include/apcrypto.h`, `c/crypto.c` | bounded `ap_update_v1` manifest, local hmac, streaming sha-256, safe relative paths, 0700 staging, local release snapshots with atomic state switching, stored release proof and verified rollback, optional second local approval key and read-only activation plan; no activation or vendor identity |
| crypto | `include/apcrypto.h`, `c/crypto.c` | sha-256, hmac-sha256, constant-time tag compare |
| transport | `include/aptransport.h`, `c/transport.c`, `c/sys.c` | 256-byte sealed packets, 0600 key file, credential and hmac verification, optional bounded per-client key table |
| ipc replay and sequence filter | `include/apreplay.h`, `c/replay.c`, `rust/src/ipc.rs` | 256-slot exact-duplicate suppression after hmac verification plus an opt-in 64-peer monotonic sequence table with `/proc` starttime epochs; counted as `ipc_duplicates` and `ipc_sequence_drops`; optional per-client key selection by `SCM_CREDENTIALS` pid, not durable identity |
| ipc | `rust/src/ipc.rs`, `tests/inject.c`, `c/heap.c` | mode 0600 unix datagrams, sealed producers, tampered and unsigned packets dropped |
| cli | `rust/src/cli.rs` | minimal black-terminal json-inspired output, rate-limited console |
| mini gui | `include/apgui.h`, `cpp/guiparse.cpp`, `cpp/gui.cpp`, `out/apgui` | raw-X11 white frame with one black terminal-like area, filtered one-line events, six useful buttons and keyboard shortcuts, no toolkit, engine unchanged |
| tracing | `c/trace.c` | ptrace/seccomp syscall supervision, kernel syscall telemetry including explicit `process_vm_writev`, `process_vm_readv`, `userfaultfd`, `io_uring_setup` and `open_by_handle_at` labels, trace-mode verdicts; `process_vm_readv` is watched |
| heap shim | `c/heap.c` | `ld_preload` double-free and use-after-free signals, bounded table |
| network | `cpp/net.cpp` | bounded ipv4/ipv6 parsing, fragment reassembly, tcp/udp invariant checks and 64-slot peer counters |
| control flow | `cpp/flow.cpp` | w+x regions, weak return sites, shadow stack, bounded ranges, bounded kernel and credential chains, bounded cross-entity stage graph with aged references, ksensor-only persistence and container chains gated on `arg[3]=3`, explicit telemetry labels mapped to `kernel_iface_bit` |
| intrusion | `include/apintrusion.h`, `cpp/intrusion.cpp`, `build/libapintrusion.a`, `rust/src/ffi.rs`, `rust/src/detect.rs`, `rust/src/correlation.rs` | 64 fixed pid slots, 8 stage bits, 10 s stage window, 5 s per-slot per-rule suppression, rules 27-29 gated by `DetectorRegistry::intrusion_enabled()`, tactic mappings for those rules, `intrusion_findings` and `intrusion_suppressed` counters |
| destructive file | `include/apdestructive.h`, `cpp/destructive.cpp`, `build/libapdestructive.a`, `rust/src/ffi.rs`, `rust/src/detect.rs` | 64 fixed pid slots, 10 s window, 5 s per-slot per-rule suppression, rules 30-32 gated by `DetectorRegistry::destructive_enabled()`, one verdict per feed with priority `destructive_chain` above `data_exfiltration` above `file_write_burst`, `destructive_findings` and `destructive_suppressed` counters |
| detection | `rust/src/detect.rs`, `rust/src/event.rs` | rule correlation through id 32, including exec after w+x, bpf/ptrace/module and credential chains, intrusion and destructive analyzer feeds, normalized and explained findings, capture source override, every rule recorded, no guaranteed zero-day claim |
| detector registry | `rust/src/detection/registry.rs` | 32 static descriptors, all enabled by default, per-detector enable and disable, coverage output, analyzer gating including intrusion and destructive, zero-detector startup rejection |
| tests | `tests/`, `rust/src/adversarial.rs`, `scripts/` | 136 rust tests plus c/c++ unit, intrusion, destructive, mini-gui parser, integration, guard, matrix, adversarial, fuzz, capture, kernel replay, kernel-sensor, correlation, update, approval and plan, client-key, audit-process, ipc replay and sanitizer suites; 22 check-time shell suites, 23 total |
| documentation | `docs/`, `README.md` | architecture, interfaces, testing, performance, limitations, security, status, compatibility, transformation |

## build and validation

```
make
make check
make asan
make bench
```

`make` builds the c and c++ libraries first, then `cargo build --offline`. there are
no external rust crates. `make check` covers abi, capability, ksensor, graph, taxonomy,
evidence, capture, kernel replay, collector, crypto, ipc lifecycle and tamper, network,
flow, beacon, intrusion, destructive, risk, fuzz, tracer, 136 rust tests, heap,
integration, detector, process telemetry, guard, detection matrix, adversarial ipc,
ipc replay and sequence, hmac audit-chain, sealed policy, resource limit, real-trace
kernel-chain, entity-stage, frame-file capture, kernel-event replay, kernel-sensor
request states, correlation counters, exact intrusion store rules, destructive file
and chain store rules and quiet single-signal cases, update-bundle, approval and
activation-plan, client-key and audit-process cases. it includes injected bpf,
ptrace, credential, file and benign jit or container transitions.
`ap --verify-store path` checks audit integrity, `ap --verify-policy path`
checks policy integrity, and `ap --verify-update path` checks a bundle manifest and its
payloads. `make asan` runs the c/c++ paths with address and undefined sanitizers using
gcc because this host lacks the clang sanitizer runtime, and includes the intrusion
and destructive units. `fuzz_analyzers` links `build/libapintrusion.a` and
`build/libapdestructive.a`. `make bench` prints measured
throughput, cpu, rss, latency and trace overhead. see `docs/testing.md` and
`docs/performance.md`.

## release notes

- no external rust crates; `cargo build --offline` is used.
- unavailable kernel capabilities degrade to reduced telemetry, not silent failure.
- `packet_capture` is a named capability bit (`64`) but stays `unavailable` here because
  this host denies raw packet sockets.
- self-hardening is deferred in trace mode and reported as `deferred_trace_mode`.
- `--trace` consumes all remaining arguments and must be passed last.
- guard rules require `--guard`, an explicit `--deny`/`--stop`, confidence at least 800
  and the configured risk threshold at the same time.
- the transport key is shared per socket path; it authenticates packet integrity but
  not distinct process identity. an authenticated 256-slot ring suppresses exact duplicate
  packets and reports the count as `ipc_duplicates`; it is not a nonce or a unique-sender
  guarantee, and a key holder can generate new packets. `--ipc-strict-seq` additionally
  drops stale or repeated nonzero `event.seq` values from the same observed sender pid,
  counted as `ipc_sequence_drops`; sequence zero is unsequenced. each peer slot records the
  `/proc` starttime of the observed pid when readable; a changed epoch on a stale sequence
  resets that slot, while an unavailable starttime leaves reuse undetected. neither path
  proves process identity or stops fresh resealed packets.
- `--client-key pid:path` is repeatable up to 16 entries, with pid `1..i32::MAX`
  and no duplicate pids; each path is an exact 32-byte `0600` regular key file
  loaded with the exact-path loader. when any are configured, the receiver
  selects the key from the `SCM_CREDENTIALS` pid using the existing hmac
  verification; unmapped pids are rejected and counted. packet bytes are
  unchanged. summary counters are `ipc_client_key_matches` and
  `ipc_client_key_misses`; policy summary reports `client_keys:n` or
  `no_client_keys`. pid is not durable identity: pid reuse remains a caveat, a
  same-uid reader of any key can still forge or reseal, and this is not a nonce
  or full replay protection.
- store records use an hmac-sha256 chain keyed by `<store>.key`; legacy fnv-1a records
  still verify. audit key failure degrades to fnv1a with an explicit status line.
- `--audit-process [--audit-key path]` requests a same-uid child writer spawned
  from `/proc/self/exe` over an `O_CLOEXEC` pipe with a nonblocking parent fd;
  frames are 4-byte little-endian length plus payload, bounded by
  `AP_AUDIT_MAX_FRAME=4096` and `AP_AUDIT_MAX_PAYLOAD=4092`. the internal
  `--audit-writer store key` child mode is not a normal user mode. the default
  audit key stays `<store>.key`; `--audit-key path` uses that exact path with no
  extra `.key`, including for `ap --verify-store path --audit-key key`.
  startup reports
  `{"audit":{"integrity":"hmac_sha256","backend":"process","process":true}}`
  when the writer starts and the same line with `"backend":"local"` when it
  does not; `process` echoes the request. if it cannot start, an explicit
  degraded line is emitted:
  `{"degraded":{"audit_writer":"unavailable","reason":"..."}}`. summary fields
  are `audit_process`, `audit_writer_status` (`complete`/`degraded`/`failed`),
  `audit_writer_queued` and `audit_writer_dropped`; queued means frames queued
  to the child, not durable store writes. guard audit entries are flushed
  before writer finish and shutdown waits bounded before `SIGTERM`. same-uid
  code can still tamper with the child, key, pipe or store; this is not
  privilege separation, and a dropped or degraded writer stays explicit.
- `--seal-policy` signs a strict `ap_policy_v1` file with `<policy>.key`,
  `--verify-policy` checks it, and `--policy` loads it before explicit cli overrides.
  policy files must be regular, non-symlink and not group or other writable.
- `--seal-update` seals a strict `ap_update_v1` manifest with `<manifest>.key`,
  `--verify-update` checks the manifest mac and every payload hash, and
  `--stage-update manifest destination` copies verified payloads into a new `0700`
  directory. manifests and payloads must be regular, non-symlink and not group or other
  writable; paths are relative and normalized. `--install-update manifest root` verifies a
  bundle, stages it into a new release under an existing private root and atomically records
  it as active; `--rollback-update root` verifies the previous release's stored proof and
  then swaps the recorded active and previous releases.
  roots, release directories and the state file must be regular, current-uid-owned and not
  group or other writable. older generated releases are pruned best-effort after the state
  switch. each release stores a `0600` sealed manifest and key, and rollback re-verifies the
  previous release before switching. `manifest`, `manifest.key` and `manifest.approval.key` are reserved payload names; release proof copying
   stores the approval key at `0600`.
  these are local file operations, not activation, privileged replacement or containment.
- `--require-approval` applies to `--seal-update`, `--verify-update`,
  `--stage-update`, `--install-update`, `--rollback-update` and
  `--activation-plan`. sealing adds an optional `approval=<64 lowercase hex>`
  line before `mac=` using `<manifest>.approval.key` at `0600` and the exact
  path helper, with no extra `.key` suffix. the approval mac domain is
  `ap_update_approval_v1\n`; the manifest mac covers all bytes before `mac=`,
  including any approval line. approval is verified whenever present, even
  without the flag; the flag requires it and fails with `update approval missing`
  when absent. a tampered key fails with `update approval mac mismatch` and a
  missing key with `update approval key unavailable`. this is a second local
  possession domain, not a vendor signature, second human, process identity or
  protection against a same-uid key reader.
- `--activation-plan root [--require-approval]` is read-only and one-shot. it
  checks the private root, releases and state, verifies the active release
  proof, checks a previous release if present, optionally requires approval,
  and prints `{"update":{"state":"plan","active":"<id>","previous":"<id|none>","integrity":"verified","entries":n,"bytes":n,"executed":false}}`.
  it performs no writes, spawn, restart, activation, file switching or
  privileged replacement.
- `--enable` is an allowlist; `--disable` removes rules from the active set. `all` is
  accepted by both and expands to 32 rules. all 32 detectors are enabled by default,
  disabling one yields 31 and zero enabled detectors is a startup error.
- rule ids 20-29 add `kernel_rootkit`, `credential_theft`, `persistence_chain`,
  `container_escape`, `fileless_exec`, `anti_analysis`, `beaconing`,
  `process_injection`, `exploit_chain` and `credential_dump`. rule ids 30-32 add
  `file_write_burst`, `destructive_chain` and `data_exfiltration`.
  `AP_RULE_MAX` and rust `RULE_MAX` are both 32.
- the c++ intrusion analyzer uses 64 fixed pid slots, a 10-second stage window and
  5-second per-slot per-rule suppression. it emits at most one verdict per event with
  priority `credential_dump` above `process_injection` above `exploit_chain`, and a
  w+x bit requires both write and exec bits (`arg[2] & 6 == 6`). its rules map to
  credential access, defense evasion and privilege escalation tactics. summary fields
  are `intrusion_findings` and `intrusion_suppressed`.
- the c++ destructive analyzer uses 64 fixed pid slots, a 10-second window and
  5-second per-slot per-rule suppression. it reads sampled `/proc/<pid>/io` deltas as
  `AP_KIND_FILE`/`AP_FILE_IO`, file action labels as `AP_FILE_ACTION`, network connects
  and `open_by_handle_at` kernel labels. it emits at most one verdict per feed with
  priority `destructive_chain` above `data_exfiltration` above `file_write_burst`.
  details use exactly `file_write_burst:`, `destructive_chain:` and `data_exfiltration:`
  prefixes. summary fields are `destructive_findings` and `destructive_suppressed`.
- the tracer emits explicit `process_vm_writev`, `process_vm_readv`, `userfaultfd`,
  `io_uring_setup` and `open_by_handle_at` labels; `process_vm_readv` is watched.
  `cpp/flow.cpp` maps them to the existing `kernel_iface_bit` so legacy kernel-chain
  expectations still hold.
- the detector registry is compiled in; runtime module loading is not supported.
- `--kernel-sensor` opens the raw ebpf/perf sensor before self-hardening because the
  seccomp filter denies `bpf()`. `--lsm-enforce` implies the sensor and requests the
  optional bpf lsm hook; `--lsm-mask n` accepts a hex or decimal u32 for the 32
  deny-map keys. any open, map, perf or attach failure emits a `degraded` line and
  continues. `lsm_denies` counts installed deny-map entries, not runtime lsm rejections.
- the source registry has ten named sources; `ksensor` is id 9 and `lsm` is id 10.
  `perf`, `tracepoints` and `bpf` may report `active` with a kernel sensor reason when
  the sensor opens, otherwise they keep their unavailable or degraded states.
- graph, evidence, beacon, intrusion and risk analysis is bounded and local: 128 graph
  nodes and 256 edges with a 60-second window and 30-second suppression, 256 evidence
  slots with 30-second dedupe, 64 beacon peers with 8 samples over 90 seconds, 64
  intrusion pid slots with 8 stage bits, a 10-second stage window and 5-second
  per-slot per-rule suppression, and 64 risk entities with 8 signals over 90 seconds
  and 30-second suppression. findings are heuristics over supplied telemetry, not
  proof of attack.
- `--correlate-window-ms` sets the entity stage window to 100-60000 ms, default 5000.
  an entity finding needs four observed stages and at least three linked classes;
  binary, peer and privilege references age out with that window. it is a heuristic
  over supplied telemetry, not proof of exploit.
- `--no-proc-scan` disables the `/proc` collector; `--proc-interval-ms` and
  `--proc-max-pids` bound its cadence and pid table. the minimum interval is 100 ms and
  the pid cap is 512. `--proc-map-samples` and `--proc-wx-per-scan` bound map reads and
  w+x emissions per scan to 1-32 and 1-16; defaults are 8 and 4. `--proc-io-per-scan`
  bounds sampled `/proc/<pid>/io` deltas to 1-32, default 8.
- file telemetry is process-wide and sampled, not per-file writes or file contents. the
  collector emits `AP_FILE_IO` with `arg[0]=wchar_delta`, `arg[1]=syscw_delta`,
  `arg[2]=rchar_delta` and `arg[3]=read_bytes_delta`; traced file actions use
  `AP_FILE_ACTION` with `arg[0]=syscall_nr` and text `file_rename`, `file_unlink` or
  `file_chmod`. `--mask` bit 32 (`AP_TRACE_MASK_FILE`, all bits `63`) enables trace-mode
  file actions. all file findings are observational.
- proc findings are observational: guard cannot deny or stop an external pid without a
  syscall stop. comm changes are exec proxies, sampled w+x mappings can be benign, and
  process-wide IO deltas cannot identify a specific file.
- kernel replay is bounded file ingest, not live telemetry. a crafted or replayed file
  can drive findings and policy decisions; the kernel source mark is internal and not an
  authenticated sensor identity.
- `--capture` enables capture, `--capture-iface` selects an interface, `--capture-file`
  selects a length-prefixed raw-frame file and `--capture-snaplen` sets a 20-63 byte
  ip-header snapshot. file mode is validated here; live interface mode degrades when
  raw packet capture is denied.
- captured packets arrive as `AP_KIND_NET`/`AP_NET_PACKET` with `pid=-1`, `tid=-1` and
  `arg[3]=1`; rust reports their source as `"capture"` and feeds the unchanged network
  analyzer and rule set.
- peer counters are bounded observations (`peers`, `peer_events`, `peer_evictions`,
  `peer_bursts`, `peer_exhaustion`), not a new rule or proof of attack.
- `--kernel-events path` reads a strict `apk1` file: magic, a little-endian count and
  raw 216-byte events, maximum 4096. non-network events carry `arg[3]=2`, report source
  `"kernel"`, and `--once` waits for replay completion. the kernel status line reports
  file mode and counters; replay is observational and is not a live kernel collector.
  ksensor samples carry `arg[3]=3`; replay marks do not enter the ksensor-only
  `persistence_chain` or `container_escape` chains.
- enforcement status reports the real backend. `lsm` is `bpf_lsm` only when a lsm attach
  succeeds and `unavailable` otherwise; kernel compromise stays `unprotected`. lsm is a
  narrow local hook, not kernel-compromise protection, and telemetry alone cannot defend
  a system after compromise.
- `--chain-guard` is explicit opt-in and requires `--guard` plus `--deny` or `--stop`
  rules. it adds a bounded 64-slot, 10-second distinct-rule readiness gate over three
  distinct high-value rules before a decision can reach deny or stop; risk, confidence
  and rule membership still apply. `chain_findings` counts crossings.
- store and console findings carry a `findings` detail array, so correlated alerts keep
  the labels and window that produced them, for example `kernel_chain:bpf+ptrace`,
  `attack_graph:pid-4242:tactics=5:nodes=3`, `beacon:198.51.100.7:443:connections=3:...`,
  `process_injection:...`, `exploit_chain:...`, `credential_dump:...`,
  `file_write_burst:...`, `destructive_chain:...`, `data_exfiltration:...` or
  `entity_chain:wx+exec+priv+net:pid+binary+peer+priv:10.9.8.7:4444`.

## known limits

detection is invariant-based and can miss unseen behavior. entity correlation needs
four observed stage bits in one window and at least three linked classes; missing
telemetry or changing keys can hide a chain. the proc collector is a
poll-based sample, not kernel push telemetry; short-lived processes and unmatched maps
can be missed. the optional kernel sensor needs raw bpf and perf access; this host denies
both, so live ebpf, perf and lsm behavior is not validated here. its labels are internal
and not authenticated sensor identity. graph, evidence, beacon, intrusion and risk
findings are bounded heuristics over supplied telemetry and can be driven by crafted
or replayed input. intrusion findings need multi-signal stage combinations inside a
10-second window and do not guarantee detection of all exploitation types or
zero-days. destructive-file findings need sampled process-wide IO deltas, distinct file
actions, a network stage or an `open_by_handle_at` label in a 10-second pid window;
sampling gaps, short-lived processes and benign maintenance can hide or imitate a
chain. `--chain-guard` is a heuristic readiness gate, not proof of an attack or a
zero-day detector. the capture backend is bounded and unprivileged here; live `AF_PACKET` open fails
with `operation not permitted`, so the validated capture path is a local frame file.
audit and policy hmacs authenticate possession of local `0600` keys, not a
distinct process identity, and a same-uid process that can read them can still rewrite
signed inputs. ipc duplicate suppression only remembers the last 256 authenticated
packets; older exact replays and altered packets from a key holder can still be accepted.
per-client keys select by observed pid for one receiver, not durable identity; pid reuse
and a same-uid reader of any key remain caveats. update bundles use the same local-key
model and do not establish a vendor identity; a same-uid key reader can forge a manifest,
including one with a second approval key. installation writes verified
snapshots under a private root and switches local state, but it does not activate code,
replace a running process or protect the system; the activation plan only reads it. the
audit writer process is same-uid and is not privilege separation. the heap shim is
bypassable by a determined target. one ptrace tracer may
attach at a time, so `strace` cannot run alongside it. sanitizers do not instrument rust
or the intentional heap probes. read `docs/limitations.md` and `docs/security.md` before
deploying guard mode.
