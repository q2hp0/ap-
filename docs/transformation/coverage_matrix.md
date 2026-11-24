# capability and coverage matrix

status values: `implemented`, `partial`, `experimental`, `unsupported`.
baseline was taken before the transformation; status is updated after each phase.
current reference counts are 32 detector descriptors, `AP_RULE_MAX = 32` in c and
`RULE_MAX = 32` in rust, ten named source states (`ksensor` is 9 and `lsm` is 10),
136 rust tests, and 23 shell suites: 22 in `make check`, including
`test_intrusion.sh` and `test_destructive.sh`, plus `test_sanitizers.sh` for
`make asan`. earlier phase notes keep their historical counts.

| area | capability | status | evidence |
| --- | --- | --- | --- |
| telemetry | supervised syscall telemetry | implemented | `test_trace`, `kernel_probe` |
| telemetry | system-wide process lifecycle | partial | bounded `/proc` snapshot/delta in `c/collector.c`, `test_collector`, `test_proc.sh`; poll-only |
| telemetry | system-wide exec proxy | partial | comm change between scans, not proof of exec |
| telemetry | system-wide w+x mapping observations | partial | sampled `/proc/<pid>/maps`, validated 1-32 map samples and 1-16 w+x emissions, repeated-mapping suppression |
| telemetry | sampled process-wide file IO deltas | partial | bounded `/proc/<pid>/io` sampling, 1-32 pids per scan default 8, process-wide counters only, `test_collector`, `test_proc.sh`; no per-file writes |
| telemetry | eBPF raw tracepoints | partial | `c/ksensor.c` hand-encodes nine `BPF_PROG_TYPE_RAW_TRACEPOINT` programs and 48-byte samples; no live attach on this host, whose mask is 7 |
| telemetry | kprobes | unsupported | no kprobe attach path in the current sensor |
| telemetry | perf events | partial | bounded per-cpu perf ring in `c/ksensor.c`, capped at 16 cpus and 64 pages per ring; perf is unavailable and unvalidated here |
| telemetry | kernel module, bpf, ptrace and integrity labels | partial | nine traced attach points, standard events and ksensor samples; canonical labels plus bounded aliases map sensor and replay names |
| telemetry | explicit process-memory and kernel-interface labels | partial | `c/trace.c` emits `process_vm_writev`, `process_vm_readv`, `userfaultfd`, `io_uring_setup` and `open_by_handle_at`; `process_vm_readv` is watched, `cpp/flow.cpp` maps them to the existing `kernel_iface_bit`, and `tests/kernel_probe.c` touches `process_vm_readv` |
| telemetry | bounded packet capture | partial | `c/capture.c`, `test_capture`, `test_capture.sh`; frame-file mode validated, live `AF_PACKET` denied on this host |
| telemetry | bounded kernel event-file replay | implemented, observational | `apkernel.h`, `c/kernel.c`, `rust/src/kernel.rs`, `test_kernel`, `test_kernel.sh`; strict `apk1`, max 4096 events, no live collector |
| memory | w+x mapping and transition | implemented | `test_abi`, `test_flow`, matrix |
| memory | exec after w+x | implemented | `test_flow`, matrix |
| memory | shadow-stack mismatch | implemented | `test_flow` |
| memory | heap canary, double and invalid free | partial | `ld_preload` shim only |
| memory | out-of-bounds and use-after-free | partial | allocator shim, no page-protection sensor |
| memory | control-flow integrity | partial | return-site and shadow heuristics |
| kernel | interface and module labeling | partial | tracer text labels and ksample label ids |
| kernel | multi-label kernel chain | implemented | `test_flow`, `detect.rs`, `test_kernel_chain.sh`, explained labels |
| kernel | privilege escalation correlation | implemented | `test_flow`, `detect.rs`, injected setid plus bpf fixture, `/proc` uid/euid deltas |
| kernel | bounded attack graph | implemented, observational | `apgraph.h`, `c/graph.c`, 128 nodes, 256 edges, 64-byte keys, 60-second window, repeat suppression |
| kernel | evidence ledger and taxonomy | implemented, observational | `apevidence.h`, `c/evidence.c`, `aptaxonomy.h`, `c/taxonomy.c`; 256 dedupe records, canonical labels and bounded aliases for common replay names |
| kernel | kernel integrity observation | partial | raw sensor labels can report kernel and credential operations; a label is an observation, not proof of a successful operation |
| kernel | kernel-compromise protection | unsupported | lsm enforces only a configured local deny mask; the report keeps `kernel_compromise` as `unprotected` |
| network | ipv4/ipv6 protocol validation | implemented | `test_net` |
| network | tcp state and fragment analysis | implemented | `test_net`, `fuzz_analyzers` |
| network | live packet capture | partial | raw socket backend exists; denied on this host, so no live capture claim |
| network | framed-file packet replay | implemented | `ap_capture_open_file`, `capture_fixture`, `test_capture.sh` |
| network | resource exhaustion analysis | partial | 64 bounded peer slots, one-second window, burst and exhaustion counters; no rule |
| behavior | temporal correlation | implemented | bounded per-pid and entity stage windows; `--correlate-window-ms` 100-60000 ms, default 5000; binary, peer and privilege references age with that window |
| behavior | cross-process multi-stage correlation | implemented | bounded c++ entity graph, 32 slots, four stages, three linked classes; `test_flow`, `test_entity_chain.sh`; heuristic over supplied telemetry |
| behavior | graph and evidence bridge | implemented, observational | `rust/src/correlation.rs` maps findings into graph observations and dedupes them through `c/evidence.c`; `test_graph`, `test_evidence`, `test_correlation.sh` |
| behavior | beacon timing analyzer | implemented | `apbeacon.h`, `cpp/beacon.cpp`, 64 peers, 8 samples, 90-second window, rule 26 with 700/800/900 scores; `test_beacon`, `test_correlation.sh` |
| behavior | bounded intrusion-stage analyzer | implemented, observational | `apintrusion.h`, `cpp/intrusion.cpp`, `build/libapintrusion.a`, 64 pid slots, 10-second stage window, 5-second per-slot per-rule suppression, rules 27/28/29 at 870-890/890-920/900; `test_intrusion`, `test_intrusion.sh` |
| behavior | bounded destructive file and chain analyzer | implemented, observational | `apdestructive.h`, `cpp/destructive.cpp`, `build/libapdestructive.a`, 64 pid slots, 10-second window, 5-second per-slot per-rule suppression, rules 30/31/32 at 870/900/880, one verdict per feed; `test_destructive`, `test_destructive.sh`, fuzz coverage |
| prevention | opt-in guard chain gate | implemented, observational | `--chain-guard` requires `--guard` and deny/stop rules; `rust/src/guard.rs` uses 64 pid slots, a 10-second window and three distinct high-value rules, counted as `chain_findings`; policy validation and decision tests |
| behavior | c++ risk accumulator | implemented, observational | `aprisk.h`, `cpp/risk.cpp`, 64 entities, 8 signals, 48-byte keys, 90-second window; distinct from rust per-pid risk; `test_risk`, `test_correlation.sh` |
| prevention | monitor, alert, enforce modes | partial | monitor and enforce; alert is monitor with findings |
| prevention | ptrace deny and stop | implemented | `test_guard.sh` |
| prevention | bpf-lsm configured-key deny | partial | `c/ksensor.c` builds an optional `BPF_PROG_TYPE_LSM` program at `BPF_LSM_MAC`; mask is local, attach unavailable here, and kernel compromise stays unprotected |
| prevention | seccomp policy, isolation | partial | seccomp child stop only; process, system and network containment remain absent |
| security | versioned fixed-size abi | implemented | `test_abi` |
| security | credential check on ipc | implemented | `test_ipc` |
| security | sha-256 and hmac-sha256 primitives | implemented | `test_crypto` rfc 4231 vectors |
| security | authenticated ipc and message integrity | implemented, shared key with optional per-client key | `test_ipc` tamper and `test_adversarial.sh`; same-uid key readers remain |
| security | per-client ipc key selection | implemented, bounded | `--client-key pid:path` repeatable to 16, exact 32-byte 0600 key path, selection by `SCM_CREDENTIALS` pid, unchanged packet bytes, `ipc_client_key_matches`/`ipc_client_key_misses`; pid reuse caveat |
| security | second-key approval for update modes | implemented, local key | `--require-approval` on seal/verify/stage/install/rollback/plan, optional `approval=<hex>` before `mac=`, exact `<manifest>.approval.key` 0600, domain `ap_update_approval_v1\n`, reserved `manifest.approval.key`; local possession only |
| security | read-only activation plan | implemented, observational | `plan` verifies active release proof and private state and prints `executed:false`; no writes, spawn, restart, activation or file switching |
| security | audit process writer status | implemented, same-uid child | `--audit-process [--audit-key path]`, child from `/proc/self/exe`, 4-byte frames capped at 4096 bytes (4092 payload), `"backend":"process"`/`"process":true`, `audit_writer_status` complete/degraded/failed, `audit_writer_queued`/`audit_writer_dropped`; queued is not durable, no privilege separation |
| security | bounded exact-duplicate and opt-in sequence suppression | implemented, local bounds | `apreplay.h`, `c/replay.c`, `test_replay`, `test_replay.sh`, `test_sequence.sh`; 256 hmac-verified tags plus an opt-in 64-peer monotonic table with starttime epochs |
| security | pid-epoch aware sequence reset | implemented, local observation | `c/sys.c`, `c/replay.c`, `test_collector`, `test_replay`; `/proc` starttime read on peer creation and stale sequence, simulated epoch change only in unit test |
| security | distinct producer and sensor identity | unsupported | same-uid readers of the `0600` key can forge telemetry; ksensor, capture, replay and kernel marks are internal and unauthenticated; no kernel-sealed identity |
| security | distinct audit and policy identity | unsupported | local 0600 keys, including the second approval key, authenticate possession, not a process identity |
| security | cryptographic audit integrity | implemented, local key | hmac-sha256 chain with `<store>.key`, legacy fnv records verify, `test_store.sh` and rust store tests |
| security | secure policy loading | implemented, local key | `ap_policy_v1`, strict parser, `<policy>.key`, `--seal-policy`, `--verify-policy`, `--policy`, `test_policy.sh` |
| security | bounded update manifest integrity and staging | implemented, local key | `rust/src/update.rs`, `test_update.sh`; hmac manifest, streaming sha-256 payloads, 0700 staging, reserved release-proof names; no vendor identity |
| security | local update installation and rollback | implemented, local root | verified release snapshots with stored 0600 proof, 0700 private root, atomic state switch, proof-verified rollback, best-effort two-release pruning; no activation, privileged replacement or vendor identity |
| security | secure update activation and privileged replacement | unsupported | local installation changes files under a private root and records unsigned state only; the read-only plan prints `executed:false` and does not activate |
| security | true privilege separation | unsupported | the audit writer can run in a same-uid child from `/proc/self/exe`; one uid and one executable, so the write boundary is not privilege separation |
| validation | unit, fuzz, sanitizer, integration | implemented | `make check`, `make asan`, capture, kernel replay, ksensor, correlation, intrusion, destructive, update, audit process, ipc replay and ipc sequence suites; 136 rust tests and 22 shell suites in check, plus `test_sanitizers.sh` for `make asan` |
| validation | controlled exploit fixtures and vm tests | unsupported | probes only; no live exploit or vm matrix |
| validation | live eBPF, perf and lsm validation | unsupported | bounded c code and unit/degraded-path tests exist, but capability mask 7 prevents live attach here |
| platform | capability probe for ptrace, seccomp, proc, perf, tracepoint, bpf, packet capture | implemented | `test_cap`; observed mask 7, packet capture bit unavailable |
| platform | tested compatibility matrix | partial | `docs/compatibility.md`; one x86_64 host only |
| interface | minimal json-inspired terminal stream | implemented | `cli.rs` |
| interface | telemetry source registry and degraded source names | implemented | `source.rs`, `aptelemetry.h`, 10 source states including `ksensor` and `lsm`, `test_cap`, 136 rust tests |
| interface | enforcement backend status | implemented | `guard.rs`, `engine.rs`, `test_kernel_chain.sh`; lsm reports `bpf_lsm` only when active, otherwise `unavailable`, and kernel compromise is always `unprotected` |
| interface | correlation summary counters | implemented | `engine.rs` publishes `graph_added`, `graph_evicted`, `graph_findings`, `graph_suppressed`, `evidence_inserted`, `evidence_duplicates`, `evidence_evicted`, `beacon_findings`, `risk_findings`, `intrusion_findings`, `intrusion_suppressed`, `destructive_findings`, `destructive_suppressed`, `chain_findings`, ksensor and lsm counters; `test_correlation.sh`, `test_intrusion.sh`, `test_destructive.sh` |
| interface | detector registry and coverage output | implemented | `detection/registry.rs`, 32 descriptors, all enabled by default; disabling one yields 31 and `--enable all` yields 32; `test_detectors.sh` checks `"enabled": 31` |
| configuration | per-detector enable and disable | implemented | `--enable`, `--disable`, `policy.rs`, `test_detectors.sh` |
| configuration | correlation window control | implemented | `--correlate-window-ms`, 100-60000 ms, `policy.rs`, `test_entity_chain.sh` |
| configuration | capture mode and snaplen control | implemented | `--capture`, `--capture-iface`, `--capture-file`, `--capture-snaplen`, `policy.rs`, `test_capture.sh` |
| configuration | opt-in ipc sequence checking | implemented | `--ipc-strict-seq`, `policy.rs`, sealed-policy flag, `test_sequence.sh` |
| configuration | kernel sensor and lsm request flags | implemented, availability not implied | `--kernel-sensor`, `--lsm-enforce`, `--lsm-mask`; `policy.rs`, `ksensor.rs`, `test_ksensor.sh`; unavailable states emit degraded lines |
| detection | analyzer gating by enabled detector set | implemented | `detect_with_registry`, disabled network tests |
| detection | advanced rules 20-29 | implemented, live labels unvalidated here | rust cheap rules 20/21/24/25, c++ flow rules 22/23, c++ beacon rule 26, c++ intrusion rules 27/28/29; `test_ksensor.sh`, `test_correlation.sh`, `test_intrusion.sh`, `test_detectors.sh` |
| detection | destructive file rules 30-32 | implemented, observational | sampled `/proc/<pid>/io` deltas, traced file actions, network connects and `open_by_handle_at` labels; `cpp/destructive.cpp`, rules 30/31/32 with exact prefixes and one verdict per feed; `test_destructive.sh`, `test_proc.sh` |
| detection | runtime detector loading | unsupported | static descriptor table, rebuild required |
| performance | event-driven bounded processing | implemented | `bench/bench.sh` |
| performance | bounded `/proc` scan cadence and state | implemented | `--proc-interval-ms`, `--proc-max-pids`, `--proc-map-samples`, `--proc-wx-per-scan`, `--proc-io-per-scan`, `test_proc.sh` |
| performance | bounded capture and peer state | implemented | 16 frames per poll, 63-byte snaplen, 64 peer slots, `test_capture` |
| performance | bounded sensor perf rings | partial | capped at 16 cpus and 64 pages per ring, 256 samples per poll; no live validation here |
| performance | adaptive analysis | unsupported | fixed windows, caps and circular eviction only |
