# security

## trust model

- rust engine: trusted. it owns validation, policy, risk, guard, output and audit.
- c tracer: trusted sensor for a supervised child. it can deny or stop only at a
  ptrace/seccomp stop.
- c heap shim: best-effort sensor inside a `ld_preload` target. a determined process
  can avoid or tamper with it.
- external ipc producers: untrusted bytes. the socket is created in a private
  `0700` directory and renamed into place with mode `0600`; symlinks and regular
  files are not replaced. `scm_credentials` uid equality, an exact 256-byte
  authenticated packet, header checks and an hmac-sha256 tag are enforced before
  any event validation. with `--client-key pid:path`, the key is selected by the sender
  pid and unmapped pids are rejected; the packet layout is unchanged.
- capture backend: trusted local sensor, not a remote input. it reads a raw socket or a
  local frame file and emits standard events directly to the engine. captured packets
  carry an internal source mark, but the mark is not a cryptographic identity and
  guard cannot stop a packet or a peer.
- kernel replay file: local input, not an authenticated sensor. the parser bounds and
  validates the format and abi fields, then marks non-network events as source
  `"kernel"`. a crafted or replayed file can still drive findings and recorded policy
  decisions, and guard cannot stop an already replayed event.
- raw kernel sensor: optional local sensor that calls `bpf()` and `perf_event_open()`
  directly, loads small hand-encoded ebpf programs on raw tracepoints and emits 48-byte
  samples as `AP_KIND_KERNEL` with `arg[3]=3`. the mark is internal pipeline metadata,
  not authenticated sensor identity. bpf, perf and lsm access are unavailable on this
  host, so live sensor behavior is not validated here.
- lsm hook: optional narrow `BPF_LSM_MAC` deny map requested by `--lsm-enforce`. it is
  reported as `bpf_lsm` only when an attach succeeds and `unavailable` otherwise.
  `lsm_denies` counts installed deny-map entries, not runtime lsm rejections. this is
  not kernel-compromise protection and not a trust boundary against a compromised kernel.
- graph, evidence, beacon, intrusion and risk analyzers: derived local state, not new
  trust boundaries. they consume labels and findings through text-derived keys or
  bounded stage bits and produce bounded heuristic findings and counters; crafted or
  replayed input can drive them. the intrusion analyzer reads supplied telemetry only
  and does not protect a process or the kernel.
- update bundle: local files verified by a key stored beside the manifest. an optional
  `approval=` line is verified with a second local key when present or required. the hmac
  authenticates possession of local keys, not a vendor, second human or process identity.
  verification, staging, local installation and the read-only activation plan are one-shot
  operations and never replace running files. installed releases keep a copy of the sealed
  manifest, key and any approval key for rollback verification.
- audit process writer: a same-uid child from `/proc/self/exe` that appends to the store
  over a framed pipe with an exact-path key. it moves appends off the main loop, not the
  key out of same-uid reach; it is not privilege separation.
- kernel interfaces: trusted but partial. `ptrace`, seccomp, `/proc`, raw packet
  sockets, bpf, perf and lsm may be unavailable; the engine then degrades rather than
  failing open into protection. the sensor opens before self-hardening because the
  seccomp filter denies `bpf()`, and failures emit a degraded line and continue.

## enforced boundaries

- fixed-size versioned structs; no heap growth in the abi path.
- transport keys are generated with `getrandom`, stored in a `0600` regular file
  beside the socket path, loaded with `O_NOFOLLOW`, and rejected if group or other
  bits are set. key paths are exact through `ap_transport_key_create_path` and
  `ap_transport_key_load_path`. `--client-key pid:path` loads at most 16 exact 32-byte
  `0600` regular keys for pids `1..i32::MAX` with no duplicate pids; the receiver selects
  the key from `SCM_CREDENTIALS` and uses the same hmac check without changing packet
  bytes.
- packet tags are verified with a constant-time compare; malformed, unsigned,
  tampered and foreign-uid datagrams are dropped before event validation. an hmac-verified
  packet tag is then checked against a fixed 256-entry ring with constant-time compares;
  exact duplicates are dropped and counted in `ipc_duplicates`. with
  `--ipc-strict-seq`, nonzero sequence numbers must increase per observed sender pid in a
  64-slot table; stale values are dropped and counted in `ipc_sequence_drops`. each slot
  records the `/proc` starttime of that pid when readable and resets its sequence when the
  epoch changes on a stale value. unmapped pids are rejected and counted in
  `ipc_client_key_misses`; successful selections count in `ipc_client_key_matches`.
- event size, abi version, kind range and text terminator are validated before detect.
- proc map reads and w+x emissions are bounded to validated 1-32 and 1-16 policy values
  with defaults of 8 and 4; pid state remains capped at 512.
- network and flow analyzers use fixed tables with oldest-state eviction.
- peer tracking uses 64 slots, a one-second window and bounded burst and exhaustion
  counters; it adds no rule and no denial path.
- capture uses a 20-63 byte ip-header snaplen, 512-byte maximum frames, 16 frames per
  poll, bounded counters and nonblocking descriptors. frames with unknown link types or
  invalid lengths are counted and dropped.
- kernel replay requires a regular exactly sized `apk1` file with at most 4096 raw
  216-byte events. magic, count, total size, event size, abi version, kind range and
  text termination are checked before dispatch, and non-network events receive an
  internal source mark of `2`.
- the raw sensor uses fixed 48-byte samples, at most 16 cpus, 64 ring pages and 256
  events per poll. its 13 label ids map through 12 canonical taxonomy entries plus
  aliases; events carry internal mark `3`. `--lsm-mask n` is a hex or decimal u32 for
  32 deny-map keys, and `lsm_denies` counts installed entries, not runtime rejections.
- source and detector registries are fixed: ten named sources (`ksensor` id `9`, `lsm`
  id `10`) and 32 detector descriptors with ids 1..32. `AP_RULE_MAX` and rust
  `RULE_MAX` are both 32. all detectors are enabled by default, disabling one yields
  31 and `--enable all` expands to 32. rules 30-32 come from the bounded c++
  destructive analyzer over sampled file and network telemetry. zero active
  detectors is rejected at startup.
- correlation state is bounded to 128 graph nodes, 256 edges and 32 chains with 64-byte
  keys and a 60-second window; 256 evidence slots with 30-second dedupe; 64 beacon
  peers with 8 samples, 48-byte keys and a 90-second window; 64 intrusion pid slots
  with 8 stage bits, a 10-second stage window and 5-second per-slot per-rule
  suppression; and 64 risk entities with 8 signals, 48-byte keys, a 90-second window
  and 30-second suppression. keys are text-derived and are not authenticated
  identities. the intrusion analyzer emits at most one verdict per event with priority
  `credential_dump` over `process_injection` over `exploit_chain`, and a w+x bit needs
  both write and exec bits (`arg[2] & 6 == 6`). summary counters `intrusion_findings`
  and `intrusion_suppressed` report findings and suppression. the destructive analyzer
  adds 64 pid slots, seven stage bits, a 10-second window, 5-second per-slot per-rule
  suppression and at most one verdict per feed with priority `destructive_chain` over
  `data_exfiltration` over `file_write_burst`; summary counters are
  `destructive_findings` and `destructive_suppressed`. file telemetry is sampled and
  process-wide, not per-file or content inspection.
- update manifests are regular non-symlink files, not group or other writable, bounded
  to 64 kib, 256 lines, 4096 bytes per line and 16 mib per payload. payload paths must
  be relative and normalized; duplicate paths, symlinks, wrong sizes and loose modes are
  rejected. the mac and every sha-256 hash use constant-time comparison, and staging
  uses a new `0700` directory with `0600` files. installation roots, release directories
  and the state file must be regular, current-uid-owned and not group or other writable;
  new nested staging directories are also created at `0700`. the names `manifest`,
  `manifest.key` and `manifest.approval.key` are reserved for release proof. rollback
  verifies the previous release with its stored proof before changing state. an approval
  line, when present, is checked with hmac over `ap_update_approval_v1\n` plus the bytes
  before that line; the main mac covers those bytes and the approval line. approval is
  required by `--require-approval` in seal, verify, stage, install, rollback and plan modes;
  missing, mismatched or unavailable approval is reported as an error. the activation plan checks
  the private root and state, verifies the active release and prints a read-only result.
- entity correlation uses 32 fixed slots, 48-byte keys and a validated 100-60000 ms
  window; a finding clears all stage windows to prevent repeated alerts.
- ipv4/ipv6 parsers bound extension chains, fragment ranges and captured lengths.
- risk arithmetic saturates and eviction restores the configured cap even when a
  caller inserts before evicting.
- default policy is monitor-only. an action requires `--guard`, an explicit rule,
  minimum confidence and risk threshold at the same time. opt-in `--chain-guard`
  additionally requires a nonempty deny or stop set and a bounded 64-slot, 10-second
  tracker that sees three distinct high-value rules at or above `--min-confidence`;
  `chain_findings` counts tracker crossings, not enforced actions.
- `deny` rewrites the supervised syscall to `eperm`; `stop` sends `sigstop` and needs
  an external responder. nothing kills a process.
- guard decisions from ipc, proc, capture, kernel replay, ksensor, correlation, the
  intrusion analyzer and the destructive analyzer are recorded but cannot be enforced
  on the producer, an external pid, a network peer, a replayed event or a kernel path.
  file io deltas cannot be tied to a file name. the optional lsm hook is a
  separate narrow deny map.
- audit records carry a per-file hmac-sha256 chain over sequence, previous digest and
  record bytes. `ap --verify-store path` detects edits and reordering; the key is local,
  so this is tamper evidence, not a signature or protection against a key holder.
  legacy fnv-1a records still verify as `v:"fnv1a"` when no `v` field is present.
- audit and policy keys are created or loaded through the 0600 regular-file key path;
  symlinks, foreign owners, wrong sizes and loose modes are rejected. the default audit
  key is `<store>.key`; `--audit-key path` is exact with no extra `.key` suffix, and
  `ap --verify-store path --audit-key key` verifies custom-key stores.
- with `--audit-process`, a same-uid child from `/proc/self/exe` receives frames over an
  `O_CLOEXEC` pipe with a nonblocking parent write end. frames use a 4-byte little-endian
  length plus payload, capped at 4096 bytes per frame and 4092 bytes of payload. guard
  entries are flushed before the writer finishes; shutdown waits a bounded time and then
  sends `SIGTERM`. startup reports the backend as `process` or `local`, with a degraded
  line when the writer cannot start. the summary reports `audit_writer_status` and
  `audit_writer_queued`/`audit_writer_dropped`; queued frames are not durable writes.
- signed policy files are regular, non-symlink, not group or other writable, bounded to
  64 kib, 256 lines and 4096 bytes per line. duplicate keys, unknown keys, control
  characters, bad boolean values and a mac outside the final line are rejected before
  engine startup. `ap --verify-policy path` checks the mac without starting the engine.
- `--policy` converts verified entries to cli-like arguments and passes them through
  `Policy::from_args`, so the same range checks apply. explicit cli arguments are
  appended after file arguments and therefore override them.

## reviewed findings

these were found by the adversarial tests and fixed:

- risk decay overflow for extreme timestamps;
- risk state cap bypass when insertion happened before eviction;
- tracer collapsing `deny` into a stop-only path;
- seccomp architecture jumps and missing `no_new_privs` in the child;
- tcp flow key collision for reversed port-only differences;
- udp fragment false positives;
- stale rust relink after a static library change;
- framed-file clean end of input counted as an invalid frame;
- undefined name and C++ include mismatch in the capture backend;
- audit key helper duplication in the store, now centralized in `auth`;
- policy entry count reported as generated argument count, now reported as entries;
- w+x detection accepting either write or exec alone, now requiring both bits
  (`arg[2] & 6 == 6`).

## residual risks

- without client mappings, the transport key is shared by all local producers using the
  socket path. `--client-key pid:path` selects a local key by the sender pid, but a pid is
  not durable identity and pid reuse remains a caveat. a same-uid process that can read
  the relevant `0600` key file can still forge or reseal packets. the 256-entry ring drops
  only byte-identical replays inside its window; altered packets and older exact replays
  are accepted. per-client keys add no nonce, kernel-sealed identity or full replay window.
  the opt-in sequence table drops stale values from an observed pid and resets a slot when
  `/proc` shows a changed starttime, but it cannot do this when `/proc` is unreadable,
  reject fresh higher sequences or identify a process. hmac authenticates possession of a
  local key, not a human or process identity.
- audit and policy keys are local 0600 files. hmac authenticates possession of those
  keys, not a human or process identity. a same-uid process that can read a key can
  rewrite the corresponding store or policy and recompute its mac; an attacker with
  kernel compromise can bypass all local evidence integrity.
- update keys use the same local 0600 model. an approval key adds another possession check,
  not a vendor identity, second human, process identity or defense against a same-uid key
  reader. a same-uid reader can forge a manifest, payload hashes and approval because there
  is no vendor key, signature chain or trusted timestamp. verification detects edits by
  parties without the keys, not a key holder or kernel compromise.
- staging copies verified payloads into a new directory. local installation keeps verified
  snapshots in a private root and verifies the stored release proof before rollback. it
  does not activate, replace running files, restart a service or prove that files are safe
  to run.
- audit rotation keeps one backup and resets the chain sequence at rotation. only the
  current file and one backup are checked by `--verify-store`; older rotated evidence
  is outside that command.
- the process writer is same-uid code. a same-uid process can tamper with the child, key,
  pipe or store; `audit_writer_queued` counts queued frames, not durable writes, and a
  writer that cannot start reports degradation instead of adding a trust boundary.
- proc telemetry is poll-based. raising map samples covers more pids per scan but costs
  more reads; short-lived processes can still be missed and `comm` changes remain exec
  proxies rather than proof.
- there is no privileged kernel agent or full-system sensor. the optional raw sensor
  loads small ebpf programs on selected raw tracepoints, but it needs bpf and perf
  access that this host denies. unseen syscalls, unattached tracepoints and kernel-only
  corruption remain outside coverage. its labels and source mark are not authenticated,
  and a crafted event stream can drive findings and counters.
- the optional lsm hook is a narrow local deny map for 32 configured keys. it does not
  protect the kernel after compromise, does not attest that telemetry is honest and does
  not replace ptrace/seccomp enforcement for supervised children. `lsm_denies` reports
  installed entries, not observed runtime rejections.
- graph, evidence, beacon, intrusion and risk analyzers use text-derived keys or stage
  bits and bounded windows. a producer can omit labels or stages, alias keys, repeat
  timing or craft traffic to inflate counters or trigger heuristic findings; eviction
  and suppression do not authenticate input or prove absence of behavior. the intrusion
  rules are bounded behavioral correlations and cannot guarantee detection of all
  exploitation types or zero-days.
- live capture requires raw packet socket permission. this host denies it, so
  validation uses a local frame file. a capture file can be replayed or crafted; the
  source mark describes origin within the pipeline, not an authenticated sensor.
- capture observes only bounded ip-header bytes. it cannot inspect encrypted payloads,
  high-rate traffic beyond the poll budget or frames outside ethernet/ipv4/ipv6.
- kernel replay files can be crafted or replayed. strict framing prevents malformed
  records from reaching detection, but the source mark is not proof that an event came
  from a kernel collector, and replay has no containment path.
- broad deny rules or a low threshold can deny benign work. test the target workload
  before enabling guard mode.
- correlated detection is a heuristic. skilled attackers can avoid the modeled
  invariants or spread indicators over time. entity keys are text-derived, so a
  producer can omit a stage, change a key or alias an unrelated chain. references age
  with the configured window, which limits stale links but does not authenticate keys.
- sanitizer builds cover c/c++, not the rust binary or the intentional heap probes.

## verification

- `make check`: crypto known-answer and tamper tests, unit, process starttime, capture,
  kernel replay, ksensor layout and mapping, graph, taxonomy, evidence, beacon, intrusion,
  destructive and risk units, integration, guard, matrix, kernel-chain, entity-chain,
  kernel-sensor request states, correlation counters, exact intrusion and destructive
  store rules and quiet single-signal cases, hmac audit, sealed-policy, update-bundle,
  update-approval and activation-plan, audit process and custom-key store, per-client key
  selection, ipc replay, ipc sequence and adversarial tests. it runs 136 rust tests
  offline and 22 check-time shell suites; `test_sanitizers.sh` makes 23 in total.
- `make asan`: address and undefined sanitizer pass for c/c++ paths, including capture,
  kernel replay, the correlation units and the intrusion and destructive units.
  fuzz_analyzers links
  `build/libapintrusion.a` and `build/libapdestructive.a`.
- `make bench`: measured bounded ipc and supervision overhead.
