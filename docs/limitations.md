# limitations

ap is a detection and response engine, not a guarantee. it has no privileged kernel
agent. the optional raw sensor loads small ebpf programs and reads perf rings, but this
host denies bpf and perf access, so no live kernel push path is validated here. it
observes a supervised child, whatever producers send to its unix socket, a bounded
poll-based sample of `/proc`, an optional bounded packet capture backend, an optional
bounded kernel event file and optional ksensor samples. live `AF_PACKET` capture is
unavailable on this host; frame-file capture is the validated path. kernel replay
validates a file format, not a live collector, and ksensor source marks are internal
metadata, not authenticated sensor identity.

## detection coverage

- unknown exploits are not guaranteed to be detected. behavior rules only cover the
  modeled invariants: w+x memory, executable stacks, return-site anomalies, shadow
  stack mismatches, process credential changes, kernel interfaces, heap shim errors,
  exec after w+x, bounded kernel-operation chains and ipv4/ipv6 tcp/udp state violations.
- weak return-site telemetry has confidence 250 and never alerts alone. it needs
  correlation with a w+x transition and enough weak indicators in the time window.
- kernel-chain and credential correlation use nine labels from tracer, ipc or proc
  telemetry and a five-second per-pid window. they see distinct operations, not their
  order, and only from a pid the tracer follows or a producer reports. a weak `setid`
  signal stays quiet alone and needs kernel-stop telemetry or a uid delta to alert.
- entity correlation needs all four stage observations (`wx`, `exec`, `priv`, `net`)
  and at least three linked classes (`pid`, `binary`, `peer`, `priv`) in one window.
  binary, peer and privilege references age with that window, so stale text keys do not
  link fresh stages. missing telemetry, changing keys or key aliasing can still hide a
  chain; a matching chain is a heuristic over supplied events, not proof of exploit.
- kernel event replay accepts at most 4096 raw `ap_event` records from a strict `apk1`
  file. it validates framing and abi fields, not the truth of the events. a crafted or
  replayed file can produce labels, findings and policy decisions, and the `"kernel"`
  source mark is internal rather than an authenticated sensor identity.
- rules 20-29 add bounded heuristic views of rootkit-like, credential-theft,
  persistence, container-escape, fileless, anti-analysis, beaconing,
  `process_injection`, `exploit_chain` and `credential_dump` activity. they depend on
  supplied labels, findings and timing; they are not proof of compromise and do not
  guarantee detection of all exploitation types or zero-days. ksensor labels with
  `arg[3]=3` feed persistence and
  container chains; replay marks with `arg[3]=2` do not.
- rules 30-32 add bounded heuristic views of write bursts, destructive file chains and
  data exfiltration. file io comes from sampled process-wide `/proc/<pid>/io` deltas,
  not per-file write records, file content or a complete audit log. the collector
  samples at most `--proc-io-per-scan` pids per scan; short-lived processes, changes
  between scans and counter resets can be missed. `file_rename`, `file_unlink` and
  `file_chmod` actions require trace mode with bit 32 in `--mask`, and a traced action
  is a syscall observation, not proof that a file was changed. `destructive_chain`
  needs at least two distinct actions plus a write burst, and `data_exfiltration` needs
  a network connect plus a read burst; missing telemetry can hide both. these are
  heuristics over supplied events, not proof of an attack.
- the intrusion analyzer uses 64 fixed pid slots, a 10-second stage window and
  5-second per-slot per-rule suppression. it needs multi-signal stage combinations,
  emits at most one verdict per event with priority `credential_dump` above
  `process_injection` above `exploit_chain`, and requires both write and exec bits for
  w+x (`arg[2] & 6 == 6`). a single signal stays quiet, so incomplete telemetry can
  hide an intrusion stage.
- the destructive analyzer uses 64 fixed pid slots, a 10-second window and 5-second
  per-slot per-rule suppression. it emits at most one verdict per feed with priority
  `destructive_chain` above `data_exfiltration` above `file_write_burst`; lower-priority
  candidates wait for a later feed. pid eviction, sampling gaps or a stale window can
  hide a chain. `--chain-guard` adds a separate rust-side 64-slot, 10-second gate over
  three distinct high-value rules; it is an explicit heuristic precondition for guard
  decisions, not proof of compromise or coverage of zero-days.
- graph, evidence, beacon, intrusion, destructive and risk correlation is local and bounded. crafted
  input can inflate counters or produce heuristic findings. dedupe uses 64-byte keys over 30
  seconds, beacon timing uses 8 samples per peer over 90 seconds, and risk suppresses
  repeated entity findings for 30 seconds. eviction drops older state rather than
  proving absence of behavior.
- update verification checks only files listed in a bounded `ap_update_v1` manifest.
  it does not inspect unlisted files, prove vendor origin, decide whether content is safe,
  or install anything. an approval line is a second local key check, not vendor origin, a
  second human or process identity. a same-uid reader of `<manifest>.key` can forge the mac
  and payload hashes, and a reader of `<manifest>.approval.key` can forge approval. the
  activation plan only reads private root, `releases` and `state` and verifies the active
  proof; it does not activate or replace a running version.
- labels are syscall- or sensor-derived, not proof of a successful kernel operation. a
  denied bpf, ptrace or module syscall is still a label; kernel compromise is not
  observable from these events. the optional lsm hook is a narrow local deny map, not
  kernel-compromise protection or proof that the kernel is honest.
- the tracer watches a fixed syscall list. syscalls outside that list produce no
  telemetry. kernel events include module, bpf, ptrace, kexec, file-handle,
  cross-process write, userfaultfd, io_uring, mount and namespace calls, plus explicit
  `process_vm_writev`, `process_vm_readv`, `userfaultfd`, `io_uring_setup` and
  `open_by_handle_at` labels; `process_vm_readv` is watched. `cpp/flow.cpp` maps those
  labels to the existing `kernel_iface_bit` so legacy kernel-chain expectations hold,
  but the mapped label still does not prove a successful kernel operation. a behavior
  that never reaches a watched call stays invisible. `execve` is observed through
  ptrace, not seccomp.
- `/proc` maps are cached and refreshed on memory-changing syscalls. a mapping change
  that does not pass through a watched syscall can be missed until the next refresh.
- the proc collector is a snapshot/delta sampler, not a complete system log. processes
  that start and exit between scans are missed, `comm` changes are exec proxies rather
  than exec proof, and each runtime scan samples a configurable 1-32 pids with
  1-16 w+x emissions and 1-32 `/proc/<pid>/io` delta samples. higher bounds raise read
  cost but do not close the poll gap. its w+x observations can be legitimate jit or
  runtime behavior, and its io deltas are process-wide rather than per-file.
- the tracer tracks at most 32 pids and 96 regions per pid. states beyond those bounds
  are dropped or evicted.
- network analysis accepts ipv4 and ipv6, examines at most the first 256 captured
  bytes or 127 text hex chars, and does not reassemble tcp streams or ip fragments.
  ipv6 extension chains are bounded to eight headers. encrypted or tunneled traffic
  is opaque.
- the tcp state machine is a validator, not a full tcp implementation. legitimate
  unusual sequences can disagree with it.
- fragment overlap is a signal, not proof of attack; legitimate retransmissions can
  look similar without the surrounding evidence.
- capture snapshots only 20-63 bytes of the ip header after ethernet and vlan tags.
  it does not feed payload bytes to the analyzer and cannot inspect encrypted or
  tunneled contents. the frame-file reader handles the length-prefixed fixture format,
  not pcap or pcapng. at most 16 frames are handled per poll.
- live capture needs a raw packet socket. this host denies that operation, so
  `packet_capture` is reported `unavailable` and interface mode degrades. frame-file
  mode is validated but is not evidence of system-wide live visibility.
- peer tracking holds 64 endpoints in a one-second window and counts bursts after 32
  events. these are bounded resource observations, not a detection rule or proof of
  scanning; eviction and exhaustion counters only describe table pressure.
- the heap shim requires `ld_preload`. it cannot see allocations made before it is
  loaded, allocations in statically linked binaries, kernel heap corruption or writes
  that preserve the trailing canary.

## false positives

likely sources include just-in-time compilers using w+x transitions or exec after a
w+x region, sampled `/proc` w+x mappings from language runtimes, network tools opening
raw sockets, emulators using executable stacks,
custom shadow-stack calling conventions, ip fragmentation in tunnel software and
container tooling that combines module, mount and namespace operations, and unrelated
activity that shares a binary path or peer key inside one entity window. legitimate
maintenance can resemble persistence writes, and periodic health checks can resemble
beaconing. benign cross-process writes paired with jit w+x, exec or redirect stages,
or administrative credential-access tooling paired with privilege or network stages,
can resemble the intrusion findings. backups, package updates, log rotation, database
maintenance and bulk downloads can resemble `file_write_burst`, `destructive_chain` or
`data_exfiltration`, especially when sampled io counters are attributed to a busy pid.
crafted or repeated ksensor labels can inflate
graph, evidence and risk counters without being hostile. repeated or aliased capture
frames can inflate peer counters. keep protection rules narrow and start in monitor
mode. `--verbose` plus the audit store makes tuning auditable.

## validation limits

the deterministic fuzzers in `make check` exercise fixed seeds and modeled inputs.
they are regression coverage, not a proof of absence of crashes or false negatives.
sanitizer builds, kernel-level tests and attacker-generated traffic remain separate
activities. entity fixtures cover one controlled positive stream plus benign jit and
container streams; they do not prove absence of false positives in real workloads.
capture fixtures cover one framed ipv4/tcp stream and truncation/invalid-frame cases;
they do not exercise live traffic, high packet rates or other link types. kernel
fixtures cover one bounded replay file, strict rejection cases and missing-file
degradation; they do not exercise live `perf`, tracepoint or bpf collection. ksensor
fixtures check sample layout, label mapping, requested source states, degraded reasons
and summary counters; they do not attach real tracepoints or lsm hooks on this host.
correlation fixtures check that graph, evidence, beacon and risk counters appear and
that the audit store verifies; they do not prove detection quality. intrusion fixtures
cover three positive stage combinations and one quiet single-signal case with exact
store rules, not real exploitation or live kernel activity. destructive fixtures cover
three positive file/chain combinations and a quiet benign case with exact store rules;
they do not prove detection of real destructive behavior or live file telemetry. update
fixtures cover one two-payload bundle, payload and mac tamper, unsafe paths, symlinks,
missing files, reserved names and an existing staging destination. the installation fixtures
cover two private roots, two verified releases, active and previous state, stored release
proof, rollback, tampered and missing proof rejection, and a group-writable root rejection;
approval fixtures cover sealed, required, missing, mismatched and unavailable approval plus
a read-only plan. they do not test activation, privileged replacement, vendor identity, a
second human or approval by another party. replay
fixtures cover one 256-slot ring and three byte-identical
injected packets. sequence fixtures cover stale, unsequenced and 64-peer eviction cases plus a simulated
epoch change in the c unit test; they do not exercise a real reused pid or resealed
forgeries. per-client key fixtures cover pid selection, unmapped pid rejection and the
16-mapping bound, not durable identity across pid reuse.
ipc sender checks use `scm_credentials`, effective uid equality and an
hmac-sha256 packet tag. a 256-entry ring after hmac verification suppresses exact
duplicate packets and reports them as `ipc_duplicates`. without client mappings the key is
shared by all producers for a socket path; with `--client-key pid:path` the receiver selects
a key by sender pid and counts `ipc_client_key_matches` and `ipc_client_key_misses`. a
same-uid process that can read the relevant `0600` key file can still forge or reseal
packets, replay an exact packet after the 256-packet window, or send altered packets with a
fresh tag. `--ipc-strict-seq` adds a 64-peer monotonic check for nonzero sequence numbers,
reported as `ipc_sequence_drops`. peer slots store the `/proc` starttime when readable and
reset a stale sequence after a simulated or real epoch change; an unreadable starttime
leaves reuse undetected. it does not identify processes or stop higher-sequence forgeries.
per-client keys add no durable identity, nonce or full replay window, and pid reuse remains
a caveat. sequence zero is unsequenced.
audit process fixtures cover writer startup, a custom-key store and a failed writer; they
do not exercise same-uid tampering or durable delivery. `audit_writer_queued` counts frames
queued to the child, not durable writes. audit and policy hmacs use the
same local-key model: they detect edits by a party without the key, not a rewrite by a
key holder or by kernel compromise. signed policy loading checks the file before cli
parsing but does not privilege-separate the loader from the rest of the engine. the audit
process writer is same-uid code and is not privilege separation.

## false negatives

missed cases include in-process control-flow hijack with no watched syscall and no
weak telemetry, kernel-mode exploitation that never emits a watched interface,
fileless or script-based behavior with no mapped-memory transition, entity chains split
across windows or using unobserved binary, peer or uid keys, heap corruption in
processes that do not preload the shim, and network exploits hidden in payload bytes
that are not captured. kernel replay only sees events supplied in its file, so it adds
no visibility into unrecorded activity. the raw sensor is unavailable on this host and
would still see only the tracepoints and perf rings it can attach; graph, evidence,
beacon, intrusion and risk findings can miss behaviors that do not produce their
expected labels, timing, stage combinations or linked keys. the intrusion rules need
their exact multi-signal combinations, use a 10-second stage window and require both
write and exec bits for w+x, so a single observed signal or a missing stage stays
quiet. update verification only sees files listed in
its manifest; unlisted files, unsafe code in a hashed file, a forged bundle from a
key holder and forged approval from an approval-key holder are outside its coverage.
local installation only tracks verified payload files
listed in the manifest; it does not prove those files are safe, does not touch files outside
the selected private root and does not control what a running process executes. rollback
re-verifies stored payload hashes, but a same-uid writer that ignores the cli can change the
release directories, the copied key or the unsigned state file.
on this host, live packets are not captured at all because raw packet sockets are denied.

## protection

- default policy is monitor-only. no action occurs without `--guard` and an explicit
  rule.
- denial is enforced only when the verdict returns through the ptrace/seccomp stop.
  ipc, proc, capture, kernel replay, ksensor and correlation telemetry are observational;
  the engine records a decision but cannot undo an external process action, a packet
  already seen, a replayed event or a kernel path.
- the optional lsm hook is a narrow local deny map for 32 configured keys. `lsm` reports
  `bpf_lsm` only when an attach succeeds and `unavailable` otherwise; `lsm_denies` counts
  installed deny-map entries, not runtime rejections. kernel compromise stays
  `unprotected`, and lsm is not kernel-compromise protection.
- update staging writes a copy into a new directory. local installation keeps verified
  snapshots under a private root, stores a local proof and verifies the rollback target.
  approval is a local possession check and the activation plan is read-only; none of these
  activate a version, replace running files, restart a service or protect the system.
- `--audit-process` moves appends to a same-uid child, not a trust boundary. queued frames
  are not durable writes, and a writer that cannot start reports degradation.
- `deny` rewrites the syscall registers to return `eperm`. `stop` sends `sigstop` and
  requires an external responder to inspect or resume the process. the engine does
  not kill processes.
- if ptrace is denied, tracing is unavailable and the engine continues in degraded
  mode with the other requested sources.
- self-hardening is skipped in trace mode because the inherited seccomp filter would
  deny the child. the raw sensor opens before self-hardening when requested, because
  that filter also denies `bpf()`. use a separate hardened launcher if that boundary
  matters.
- a low `--threshold` or broad `--deny` list increases availability risk. test with
  the target workload before enabling guard mode in production.

## portability

- syscall register handling is implemented for x86_64 and aarch64 only.
- seccomp filters carry an architecture check and fail closed to allow on mismatch.
- capability probing uses `prctl`, `ptrace`, `/proc` and a raw socket attempt; restricted
  containers may report all sensors unavailable. proc maps can be unreadable for other
  uids, so the sample is limited to processes the engine can inspect.
- live capture depends on `CAP_NET_RAW` or an equivalent kernel policy. the observed host
  denies it, so frame-file mode is used for validation.
- the raw sensor depends on bpf, perf and raw tracepoint access, and lsm depends on a
  compatible `BPF_LSM_MAC` attach point. the observed host has none of them; attach
  layout and behavior across kernels are unvalidated.
- no external rust crates are used; builds are offline from `cargo.lock`. `make` builds
  the c and c++ libraries before the rust binary.
