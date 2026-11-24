# testing

run everything with `make check`. it rebuilds all libraries, the binary and all test
helpers, then runs c, c++, rust, collector, capture, kernel-replay, kernel-sensor, graph,
taxonomy, evidence, beacon, intrusion, destructive, risk, correlation, heap,
integration, detector, process telemetry, guard, matrix, kernel-chain,
entity-correlation, mini-gui parser, hmac audit, sealed-policy, update-bundle,
approval and activation-plan, client-key, audit-process, ipc replay and ipc
sequence tests.
`make check` runs 22 shell suites; with `scripts/test_sanitizers.sh` there are
23 `test_*.sh` scripts in total.

## unit tests

| test | coverage |
| --- | --- |
| `test_abi` | struct sizes, abi version 2, rule values, hex codec and naming helpers |
| `test_cap` | seven named capability bits including `packet_capture`, compat mask, capability report bounds, ten named source descriptors including `ksensor` and `lsm`, and cap mapping |
| `test_ksensor` | 48-byte `ap_ksample` layout, probe booleans, sample-to-event mapping, source mark `3`, canonical label bounds, status and counter shape, null arguments |
| `test_capture` | framed-file open, frame and event counters, source mark, event sequence, invalid and truncated frames, snaplen bound, null and missing-file errors, harmless `AF_PACKET` open attempt |
| `test_kernel` | `apk1` file open and bounded replay, source mark on non-network events, network events left unmarked, counters, invalid-event filtering, bad magic, oversized count, truncation, trailing bytes, null and missing-file errors |
| `test_collector` | `/proc` starttime known answer, map-limit validation, io-limit validation, baseline scan, process start and exit deltas from a forked child, multiple sampled w+x maps with a two-emission cap when permitted, synchronized bounded child write bursts through `ap_collector_scan_pid_io()`, file event subkind and argument checks, event sequence and bounded counters |
| `test_crypto` | sha-256 known answers, hmac rfc 4231 vectors, long-key hashing, constant-time compare, auth, replay and sequence status names |
| `test_ipc` | private-directory bind, mode 0600, symlink and regular-file rejection, 0600 key creation and reload, loose-key rejection, sealed exact-size receive, modified event, bad magic, bad version, bad tag, unsigned and foreign-uid drop |
| `test_graph` | bounded tactic graph, callback and stats, node and edge eviction, window expiry and repeated-finding suppression |
| `test_taxonomy` | 12 canonical labels plus aliases, rule ids, graph tactics, confidence values and unknown-name rejection |
| `test_evidence` | bounded 256-slot ledger, 64-byte keys, 30-second dedupe, duplicate rejection, expiry, rule and key parts of the duplicate key, eviction and argument checks |
| `test_audit` | exact custom audit key path with a 0600 regular file and matching bytes, 4-byte little-endian length frames, framed payload roundtrip, oversized payload and header rejection |
| `test_replay` | fresh ring state, exact-duplicate rejection, ring eviction after 257 unique packets, accepted and duplicate counters, filtered receive of a replayed sealed packet, stale and zero sequence handling, peer epoch reset, 64-peer eviction and sequenced socket receive |
| `test_net` | malformed ipv4/ipv6, tcp flags and phase on both families, udp length, fragment overlap, extension bounds, invalid hex, bounded eviction, 64-slot peer tracking, burst and exhaustion counters, reset |
| `test_flow` | w+x transition, exec after w+x mapping or transition, stale-window suppression, weak-signal correlation, executable stack, strong return site, shadow mismatch, kernel chains with per-pid and stale-window checks, bpf/ptrace and setid/kernel labels with explanations, entity chains across four stages, benign jit/container streams, window validation, expired binary reference aging with a counted stale reference, packet peer keys, eviction and reset |
| `test_beacon` | bounded 64-peer and 8-sample beacon table, periodic timing with counted connections and jitter, zero-time and null-callback rejection |
| `test_risk` | bounded 64-entity and 8-signal accumulator, correlated high-confidence signals, score and suppression checks, eviction, zero-time and null-callback rejection |
| `test_trace` | ptrace/seccomp startup, kernel syscall telemetry from `kernel_probe`, including `process_vm_readv`, event emission, capability degradation |
| `test_intrusion` | 64 fixed pid slots, 8 bounded stage bits, 10-second stage window, 5-second per-slot per-rule suppression, `process_injection`, `exploit_chain` and `credential_dump` confidences and detail prefixes, one-verdict priority, w+x requiring both write and exec bits (`arg[2] & 6 == 6`), quiet single-signal case |
| `test_destructive` | 64 fixed pid slots, sampled file io and file action stages, 10-second window, 5-second per-slot per-rule suppression, `file_write_burst`, `destructive_chain` and `data_exfiltration` confidences and exact detail prefixes, one-verdict priority, benign io and stale-window cases, bounded counters and reset |
| `test_gui` | raw-X11 viewer parser: startup and shutdown lines, quiet observed events, event lines with one or more rules, degraded reasons, summary and stats reduction, escaped strings, labels and string arrays |
| `fuzz_analyzers` | 30000 mutations over three fixed seeds of ipv4/ipv6 packets, memory/flow events, kernel labels, file io/action events and analyzer state, linking `build/libapintrusion.a` and `build/libapdestructive.a`; verdict termination, rule bounds, counters and reset |
| `cargo test` | 136 tests: abi layout and `RULE_MAX=32` with rules 30-32 and `AP_KIND_FILE`, validation, normalization, process lifecycle kinds, capture, kernel and ksensor source overrides, bounded kernel file replay and rejection, detect rules through 32 including exec_after_wx, bpf/ptrace kernel chains, setid/credential crossings, entity chains plus intrusion and destructive analyzer gating, benign jit suppression, expired entity reference aging, entity window validation, weak setid suppression, analyzer gating, all-rules audit field, risk decay/overflow/eviction, slow-drip evasion, guard fail-safe and `--chain-guard` validation/decision gates, honest enforcement reporting, store flood and hash-chain verification, auth hex/hmac/compare helpers, hmac store chain and key failure, sealed policy parsing, verification and cli override, policy including detector, chain-guard, kernel-sensor/lsm, `--proc-io-per-scan` and trace-mask keys, proc-scan, strict-sequence, capture, kernel-event and correlation-window selection, sealed ipc roundtrip, replay and sequence filter layout, exact-duplicate and stale-sequence suppression with separate counters, source registry with 10 sources and detector registry with 32 descriptors, rule-max and coverage fields, cli escaping, sha layout, bundle seal/verify/stage, local release install and verified rollback, stored proof tamper and missing-proof rejection, invalid state and non-private root rejection, payload and mac tamper, unsafe, reserved and duplicate paths, symlinks and missing payloads, approval key and mac domain, missing and tampered approval, approval-required install and rollback, read-only activation plan, client key layout, pid selection, unmapped pid counting and table bound, audit writer status names, clean exit, exact custom audit key path and audit-process policy parsing |
| `scripts/test_limits.sh` | `--max-states` cap under 64 finding producers, queue-depth reporting, zero-depth rejection |
| `scripts/test_kernel_chain.sh` | real `kernel_probe` telemetry and injected bpf/ptrace/setid events produce explained kernel-chain and privilege-crossing findings; enforcement status is checked; `--deny kernel_chain` denies and audits it; degrades cleanly without ptrace |
| `scripts/test_entity_chain.sh` | injected four-stage stream produces an explained entity-chain finding and auditable peer key; benign jit and container streams stay quiet; `--correlate-window-ms` appears in the policy status |
| `scripts/test_capture.sh` | framed fixture produces four validated packets, `"capture": "active"`, compact store records with `"source":"capture"`, `tcp_flag_violation`, capture counters and `packet_capture` degradation |
| `scripts/test_kernel.sh` | `apk1` fixture produces six marked kernel events with `"kernel": "active"`, kernel counters and explained `kernel_chain`/`privilege_crossing` store details; `--once` completes; a missing file reports an unavailable kernel source without denial |
| `scripts/test_update.sh` | seals a two-payload manifest, checks the 0600 key, verifies entry and byte counts, stages a 0700 directory with 0600 files, rejects an existing destination, detects payload and mac tamper, rejects unsafe paths, symlinks and missing payloads, seals and verifies with approval, and prints a read-only plan |
| `scripts/test_audit_process.sh` | process audit backend with a custom exact 0600 key, queued frames, custom-key store verification, tamper rejection and explicit degraded fallback |
| `scripts/test_replay.sh` | starts the engine, injects three byte-identical sealed events, requires two suppressed duplicates in `ipc_duplicates` and at least one accepted event in the summary |
| `scripts/test_sequence.sh` | starts the engine with `--ipc-strict-seq`, injects sequence 2, a stale sequence 1 with a new tag, then sequence 3; requires one `ipc_sequence_drops`, zero `ipc_duplicates` and at least two accepted events |
| `scripts/test_intrusion.sh` | requires exact store findings `"rule":"process_injection"`, `"rule":"exploit_chain"` and `"rule":"credential_dump"`, plus a quiet single-signal case |
| `scripts/test_destructive.sh` | injects `fileburst`, `destructive` and `exfil` fixtures and requires exact `"rule":"file_write_burst"`, `"rule":"destructive_chain"` and `"rule":"data_exfiltration"` findings with their detail prefixes; a `filebenign` fixture stays quiet |

the added rust test names are `client_key_layout_matches_c`,
`explicit_client_key_is_selected_by_pid`,
`unmapped_client_pid_is_counted_and_rejected`, `client_key_table_is_bounded`,
`writer_status_names_match_stream`, `clean_exit_accepts_zero_only`,
`hmac_chain_uses_exact_custom_key_path` and `parses_audit_process_policy`.
these cover exact key paths, pid mapping and table bounds, writer status names,
bounded clean exit, the custom audit key and the process policy flag.

`test_trace` runs `build/kernel_probe` under the tracer and requires at least one
`AP_KIND_KERNEL` event. the probe calls the added kernel interface syscalls with
invalid arguments so no privilege change or mount is performed. it accepts
`ap_err_unsupported` as a pass when the kernel policy denies ptrace. the engine
reports the same state as `degraded` at runtime.

## integration tests

`scripts/test_integration.sh` starts the engine, injects `wx`, `net`, `heap`, `module`
and `badabi`, and checks that the corresponding rules, invalid count and stopped state
appear in the output.

`scripts/test_heap.sh` runs `heap_probe` under `ld_preload` with `libapheap.so` and
checks the three reported heap errors: trailing canary, double free and invalid free.

`scripts/test_detectors.sh` runs three separate engine instances:

| control | configuration and input | expected |
| --- | --- | --- |
| disable | `--disable wx_transition`, inject `wx` and `net` | no `wx_transition` finding, `tcp_flag_violation` still reported, coverage shows `wx_transition` disabled and `"enabled": 31` of 32 detectors |
| allowlist | `--enable wx_transition,tcp_flag_violation`, inject `wx`, `net` and `heap` | only the two listed rules report findings, coverage shows `double_free` disabled and 2 of 32 detectors enabled |
| empty set | `--disable all` | startup fails with `no detectors enabled` and status 1 |

`--enable all` expands to 32 rules and all 32 detectors are enabled by default.

`scripts/test_proc.sh` runs two engine instances. the first scans `/proc` every 200 ms
with a 512-pid cap, 16 map samples, 8 w+x emissions and a configurable
`--proc-io-per-scan` bound, and requires `process_start`, `process_exit`, the `ipc` and
`proc` source states, matching `map_samples`, `wx_per_scan` and `io_per_scan` summary
fields, collector counters and the final summary. the workload is a short-lived `sleep`
child outside any supervised trace. the second uses `--no-proc-scan` and requires the
`proc` source to read `disabled` with no collector counters. out-of-range map, w+x and
io values are rejected at startup.

`scripts/test_entity_chain.sh` starts three duration-bounded engine instances with
`--correlate-window-ms 1000`. the positive fixture emits w+x mapping, exec, uid change
and peer connect for one pid, then requires the exact
`entity_chain:wx+exec+priv+net:pid+binary+peer+priv:10.9.8.7:4444` detail. separate jit
and container fixtures check that benign w+x+exec and exec+uid+network streams do not
produce a correlated finding.

`scripts/test_capture.sh` builds a length-prefixed frame file with
`build/capture_fixture` and runs the engine with `--capture --capture-file`. it requires
the capture source to be active, four parsed frames, zero truncated frames, compact
store records with source `"capture"`, a `tcp_flag_violation` finding and a
`packet_capture` capability reported as `unavailable`. this validates the frame-file
backend and capture-to-detection path, not live `AF_PACKET` capture on this host.

`scripts/test_kernel.sh` builds a six-event `apk1` fixture with
`build/kernel_fixture` and runs the engine with `--kernel-events` and `--once`. it
requires the kernel source to be active, six parsed events, compact store records with
source `"kernel"`, kernel counters, and the explained details
`kernel_chain:bpf+ptrace`, `privilege_crossing:bpf+ptrace+exec_uid_change` and
`privilege_crossing:bpf+setid`. it also checks that no action is denied. a second run
with a missing file requires the kernel source to be unavailable with the explicit
reason `kernel event file open failed or invalid` and zero kernel events. this validates
bounded file replay and degradation, not live kernel collection.

`scripts/test_ksensor.sh` runs two short engine instances. the first requests
`--kernel-sensor`, requires `ksensor` and `lsm` source states and the
`ksensor_events`, `ksensor_invalid`, `ksensor_dropped`, `ksensor_attached`,
`lsm_active` and `lsm_denies` summary counters. an unavailable ksensor must also emit
a `degraded` line with source `ksensor`. the second requests `--lsm-enforce` with
`--lsm-mask 0x1`, requires the lsm state and counters, and requires a `degraded` line
when lsm is unavailable. both verify the audit store. this checks requested states,
reasons and graceful unprivileged failure; it does not validate live ebpf, perf or lsm
behavior on this host.

`scripts/test_correlation.sh` builds a `kernel_fixture` replay file and runs the engine
with `--kernel-events`. it requires `graph_added` above zero, `graph_evicted` at zero
and the presence of graph suppression, evidence, beacon and risk counters, then verifies
the audit store. this checks the bounded correlation bridge and summary reporting, not
a finding guarantee or live sensor truth.

`scripts/test_intrusion.sh` injects the modeled stage combinations and requires exact
store findings with `"rule":"process_injection"`, `"rule":"exploit_chain"` and
`"rule":"credential_dump"`, with the `process_injection:`, `exploit_chain:` and
`credential_dump:` detail prefixes. a negative case injects a single signal and
requires no intrusion finding. this validates the bounded offline analyzer and store
path, not real exploitation or live kernel telemetry.

`scripts/test_update.sh` creates two payload files and a strict `ap_update_v1`
manifest, then uses `sha256sum` to fill the expected hashes. it requires `--seal-update`
to print a sealed state with two entries and create a `0600` `<manifest>.key`.
`--verify-update` must print two entries and fourteen bytes. `--stage-update` must print
a staged state, copy both payloads into a new `0700` directory with `0600` files, and
refuse a second stage into the same destination. the suite then replaces one payload
byte and requires `update payload hash mismatch`, edits a manifest path and requires
`update mac mismatch`, seals five unsafe relative paths expecting `unsafe update path`, and
seals two reserved names expecting `reserved update path`. it installs the first bundle into
a `0700` root, checks the active release id, copied files and `0600` stored manifest and key,
then installs a second one-payload bundle and checks active and previous ids. a tampered
previous payload must make rollback fail with `update payload hash mismatch`; after it is
restored, rollback must restore the first release and swap the state ids, and the release
directory count must stay at two. a group-writable root must be rejected. finally the script
replaces a payload with a symlink and then removes it, requiring `update payload must be a
regular file` and `update payload unreadable`. this validates bounded integrity, staging,
local snapshots, stored proof and rollback, not activation, privileged replacement or vendor
identity. it also rejects `manifest.approval.key` as a reserved payload name.

a third bundle is sealed with `--require-approval`, which creates an exact
`<manifest>.approval.key` at `0600`; verification and install then require that key,
and a bundle without it fails with `update approval missing`. install copies the
approval key at `0600` as `manifest.approval.key` in the release proof.
`--activation-plan root --require-approval` verifies the active proof and prints a
plan with `"state": "plan"` and `"executed": false` without switching files.
a tampered stored approval key makes rollback fail with `update approval mac mismatch`.
this covers a second local possession domain, not vendor identity.

`scripts/test_audit_process.sh` starts the engine with `--audit-process` and
`--audit-key path`, injects a w+x event and requires the process backend status,
`"process": true`, `audit_writer_status` `complete`, queued frames and zero
dropped frames. it checks that the exact key path is a `0600` file with no
extra `.key`, verifies the store with `ap --verify-store path --audit-key key`,
and rejects a tampered copy. a second run with an unusable key path requires a
local backend, an explicit `audit_writer` `unavailable` degraded line, a
`failed` writer status and fnv1a verification. queued frames are pipe frames,
not durable store writes; this is not privilege separation.

per-client ipc keys are covered by the rust tests listed above: layout against
the c table, selection by `SCM_CREDENTIALS` pid, unmapped-pid counting and the
16-entry bound. packet bytes stay unchanged, and pid reuse and same-uid key
readers remain caveats.

`scripts/test_replay.sh` starts the engine with a fresh socket and injects one clean
event three times as byte-identical sealed packets. the summary must report
`"ipc_duplicates": 2` and at least one accepted event. `build/test_replay` also fills the
256-slot ring with unique packets and checks that an older exact packet is accepted after
eviction while a retained packet is still rejected. this validates bounded duplicate
suppression, not protection against a key holder that can alter and reseal events.

`scripts/test_sequence.sh` runs with `--ipc-strict-seq` and injects sequence 2, then
sequence 1 with a different tag, then sequence 3. the summary must report one
`ipc_sequence_drops`, zero `ipc_duplicates` and at least two accepted events. `build/test_replay`
also checks stale-sequence rejection, unsequenced zero handling, a simulated epoch change
that resets a peer slot, 64-peer eviction and the sequenced socket receive path. the
starttime parser is checked against `/proc/self/stat` in `test_collector`. this validates a
bounded monotonic check on the observed sender pid; it does not identify processes, detect
reuse when `/proc` is unavailable or stop a key holder from sending fresh higher sequences.

negative matrix and adversarial noise runs also use `--no-proc-scan`: unrelated host
mappings can produce genuine `wx_region` findings, which would otherwise break fixtures
that inject only benign events. this keeps those tests about injection, not host state.

`scripts/test_guard.sh` uses both injection and a real supervised syscall:

```
ap --json --guard --deny wx_transition --threshold 10 --trace build/rwx_probe
```

it injects a w+x event for the audit path and runs `rwx_probe`, which calls
`mprotect(..., prot_read | prot_write | prot_exec)`. the test requires:

- at least two denials in the summary,
- `"action": "denied"` and a `wx_transition` rule,
- `mprotect=-1 errno=1` from the child,
- `{"audit":"denied:wx_transition"}` in the store.

`scripts/test_matrix.sh` runs negative and positive controls in separate engine
instances:

| control | injected events | expected |
| --- | --- | --- |
| negative | `clean`, `weak`, `exec`, `badabi` | no rule lines, zero findings, one invalid event |
| positive | `wx`, `exec`, `shadowcall`, `shadowret`, `raw`, `wxregion`, `flowstrong`, `net`, `net6`, `heap`, `kernelchain` | exec_after_wx, shadow_mismatch, raw_socket, wx_region, return_outside_exec, tcp_flag_violation, double_free and kernel_chain in the `rules` field |

injector names are listed by `build/inject` with no arguments.

`scripts/test_store.sh` writes verbose records, verifies the chain with
`ap --verify-store`, requires `"integrity": "hmac_sha256"`, `"v":"hmac"` and a `0600`
`<store>.key`, then tampers with one record and checks that verification fails.

`scripts/test_policy.sh` seals a strict policy file, checks the `0600` `<policy>.key`,
verifies the clean file, rejects a tampered file for both `--verify-policy` and
`--policy`, then starts the engine with `--policy`. the sealed file supplies guard,
deny rule, threshold, socket and store; an injected w+x event must be denied and
audited. a second run appends `--threshold 100 --deny double_free` after `--policy`
and checks that explicit cli values replace file values, so no denial occurs.

## adversarial validation

`scripts/test_adversarial.sh` adds deterministic abuse cases:

| phase | input | expected |
| --- | --- | --- |
| noise | 20000 sealed benign randomized events from `fuzz_inject` | zero findings |
| malformed | zero-length, short, oversized and unsigned datagrams, plus sealed wrong abi, unterminated text, bad kind and bad size events | four invalid events, no findings; wrong-size and unsigned datagrams are dropped before validation |
| tampered | sealed w+x packets with a modified event byte, bad magic, bad version and bad tag | no findings; all four packets dropped at the transport boundary |
| guard fail-safe | injected `wx` with `--guard --deny wx_transition --threshold 100` | no denial because risk stays below threshold |
| guard live | injected `wx` with threshold 10 | one denial and an audit record |

`fuzz_analyzers` mutates seed ipv4/ipv6 packets and flow events with three fixed seeds
and checks that verdict strings stay terminated, rules stay within the defined set
and bounded tables keep their counters. the rust adversarial tests fuzz validation,
normalization, detection, risk, guard and store with three more seeds totaling 30000
events. this found
and fixed an overflow in risk decay for extreme timestamps and an eviction path that
could exceed the configured state cap; both now have explicit regression tests.

deterministic fuzzing is coverage, not proof. it does not replace kernel-level
testing or random fuzzing with sanitizers.

`make asan` builds the c and c++ libraries and tests with `address,undefined`
sanitizers in `build-asan/` and runs abi, capability, capture, kernel, collector, crypto,
ipc, network, flow, intrusion, destructive, mini-gui parser, fuzz and tracer tests.
`fuzz_analyzers` links `build/libapintrusion.a` and `build/libapdestructive.a`. it
does not instrument the rust binary or the deliberate heap-corruption probes.

## benchmarks

`make bench` runs `bench/bench.sh` and prints a json-inspired report. it measures ipc
throughput with 20000 benign events and `--no-proc-scan`, peak rss and cpu time from
`/proc`, end-to-end detection latency for an injected w+x event, one traced `/bin/sleep`
workload, and a separate proc-collector-only run at a 200 ms interval. capture,
kernel replay, update staging, local installation, rollback and exact-duplicate injection
are covered by the functional fixtures above; replay suppression itself is active during
the ipc throughput benchmark.
see `docs/performance.md`.

## manual checks

```
./out/ap --json --verbose --duration 2000 --socket /tmp/ap.sock --store /tmp/ap.jsonl
./build/inject /tmp/ap.sock wx 1
./out/ap --json --once --trace /bin/true
./build/capture_fixture /tmp/ap-frames.bin 4
./out/ap --json --verbose --duration 1500 --no-proc-scan --capture --capture-file /tmp/ap-frames.bin
./build/kernel_fixture /tmp/ap-kernel.apk1
./out/ap --json --verbose --once --no-proc-scan --kernel-events /tmp/ap-kernel.apk1
./out/ap --seal-update bundle.manifest
./out/ap --verify-update bundle.manifest
./out/ap --stage-update bundle.manifest /tmp/ap-stage
mkdir -p /tmp/ap-install && chmod 700 /tmp/ap-install
./out/ap --install-update bundle.manifest /tmp/ap-install
./out/ap --rollback-update /tmp/ap-install
./out/ap --seal-update bundle.manifest --require-approval
./out/ap --activation-plan /tmp/ap-install --require-approval
./out/ap --json --verbose --duration 1500 --no-proc-scan --socket /tmp/ap-audit.sock --store /tmp/ap-audit.jsonl --audit-process --audit-key /tmp/ap-audit.key
./out/ap --verify-store /tmp/ap-audit.jsonl --audit-key /tmp/ap-audit.key
```

`--trace` consumes all remaining arguments, so place it last.
