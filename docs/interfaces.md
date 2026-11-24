# interfaces

## c abi

`include/apabi.h` is versioned by `ap_abi_version` and `ap_engine_version`, both `2`.
version 2 widens `text` from 96 to 128 bytes so a full ipv6/tcp packet hex can fit;
the datagram and struct sizes changed with it. structures are fixed size and shared
directly with rust; there is no conversion layer.

| type | size | layout |
| --- | --- | --- |
| `ap_event` | 216 | `u32 size`, `u16 abi_version`, `u16 kind`, `u64 seq`, `u64 ts_ns`, `i64 pid`, `i64 tid`, `u32 subkind`, `u32 severity`, `u32 confidence_x1000`, `u64 arg[4]`, `char text[128]` |
| `ap_verdict` | 168 | `u32 size`, `u16 abi_version`, `u16 kind`, `u64 event_seq`, `u32 rule`, `u32 severity`, `u32 confidence_x1000`, `u64 evidence`, `char text[128]` |

`confidence_x1000` is an integer in `0..1000`. `arg` meaning depends on `kind` and
`subkind`. `text` is nul-terminated; producers must leave at least one zero byte.
rust rejects events without a terminator.

### event kinds

| value | name | common subkinds |
| --- | --- | --- |
| 1 | process | 0 process, 1 exec path, 2 exec comm, 3 process start, 4 process exit |
| 2 | memory region | 1 region change, 2 w+x mapping |
| 3 | memory protection | 1 `mprotect`, 2 `mmap` |
| 4 | exec | 1 exec path, 2 exec comm |
| 5 | privilege | 1 `setid`, 2 exec uid change |
| 6 | kernel | 1 kernel interface or module operation |
| 7 | network | 1 socket, 2 connect, 3 packet (ipv4/ipv6 hex), 4 fragment |
| 8 | heap | 1 overflow, 2 double free, 3 invalid free, 4 quarantine |
| 9 | flow | 1 return site, 2 indirect branch, 3 executable stack, 4 shadow stack |
| 10 | trace | 0 syscall |
| 11 | heartbeat | 2 tracer stopped |
| 12 | file | 1 proc io delta, 2 rename/unlink/chmod action |

`AP_KIND_FILE` carries process-wide sampled IO deltas with `AP_FILE_IO` (`arg[0]=wchar_delta`,
`arg[1]=syscw_delta`, `arg[2]=rchar_delta`, `arg[3]=read_bytes_delta`, `text=comm`) and
traced file actions with `AP_FILE_ACTION` (`arg[0]=syscall_nr`, `arg[1]=a[0]`,
`arg[2]=a[1]`, `text=file_rename`, `file_unlink` or `file_chmod`). IO deltas come from the
`/proc` collector; actions come from the tracer under `AP_TRACE_MASK_FILE`. neither is a
per-file write record or proof of an attack.

### rules

| value | name |
| --- | --- |
| 0 | none |
| 1 | wx_region |
| 2 | wx_transition |
| 3 | stack_exec |
| 4 | return_outside_exec |
| 5 | shadow_mismatch |
| 6 | privilege_crossing |
| 7 | module_load |
| 8 | kernel_interface |
| 9 | tcp_state_violation |
| 10 | tcp_flag_violation |
| 11 | ip_malformed |
| 12 | fragment_overlap |
| 13 | heap_canary |
| 14 | double_free |
| 15 | invalid_free |
| 16 | correlated_exploit_indicators |
| 17 | raw_socket |
| 18 | exec_after_wx |
| 19 | kernel_chain |
| 20 | kernel_rootkit |
| 21 | credential_theft |
| 22 | persistence_chain |
| 23 | container_escape |
| 24 | fileless_exec |
| 25 | anti_analysis |
| 26 | beaconing |
| 27 | process_injection |
| 28 | exploit_chain |
| 29 | credential_dump |
| 30 | file_write_burst |
| 31 | destructive_chain |
| 32 | data_exfiltration |

rule ids are 1..32. `AP_RULE_MAX` and rust `RULE_MAX` are both 32. c
`tests/test_abi.c` and rust `abi_layout_matches_c` and `rule_max_matches_c`
check that bound. rule 22 is named `persistence_chain` in the detector
registry and rule names. rules 30-32 are produced by the bounded c++ destructive
analyzer from file and network telemetry. these ids widen the abi without changing
event or verdict layout.

### statuses and decisions

statuses: `ok=0`, `invalid_argument=-1`, `invalid_state=-2`, `out_of_memory=-3`,
`io_error=-4`, `unsupported=-5`, `out_of_range=-6`, `authentication_failed=-7`,
`replay_rejected=-8`, `sequence_rejected=-9`. exact ipc duplicates use the replay status
and stale sequence numbers use the sequence status, so foreign-uid and other invalid-state
drops are not counted as either.

decisions: `allow=0`, `deny=1`, `stop=2`. a `deny` callback must also set
`verdict.rule`; otherwise the tracer treats it as `allow`.

### ownership

- `ap_event_init` and `ap_verdict_init` zero the structure and fill size, version and timestamp.
- the caller owns every `ap_event`; callbacks borrow it for the call only.
- the tracer supplies a zeroed `ap_verdict` to the callback and reads it after return.
- `callback` and `user` are borrowed pointers; neither may be stored after the call.
- opaque `ap_net_handle`, `ap_flow_handle`, `ap_capture` and `ap_kernel` are allocated by
  `ap_net_new`, `ap_flow_new`, `ap_capture_open_file`/`ap_capture_open_iface` and
  `ap_kernel_open_file`, and must be released by the matching `free` function.
  `ap_flow_set_window_ms` changes the entity stage and reference window; it accepts
  100 to 60000 ms and also ages stored binary, peer and privilege references.
- analyzers are private to the engine thread; the capture handle belongs to the optional
  capture thread. neither is thread-safe.
- text buffers are never heap allocated and never grow.

## transport

the ipc server is a nonblocking `AF_UNIX` `SOCK_DGRAM` socket with mode `0600`.
it binds inside a private `0700` temporary directory and renames the socket into the
final path, so permissions are set before the path becomes visible. a symlink or
regular file at the final path is rejected rather than replaced. the server enables
`SO_PASSCRED` and drops datagrams whose sender effective uid differs from the engine.

transport v3 carries the unchanged 216-byte `ap_event` inside a fixed 256-byte packet:

| offset | length | field |
| --- | --- | --- |
| 0 | 4 | magic `aptr` |
| 4 | 1 | transport version `1` |
| 5 | 1 | type `event` |
| 6 | 2 | reserved zero |
| 8 | 216 | raw `ap_event` bytes |
| 224 | 32 | hmac-sha256 over bytes `0..223` |

without client mappings, the engine creates or loads a 32-byte key in `<socket>.key` at
startup. the file is mode `0600`, opened without following symlinks, and rejected if it is
not a regular file of exactly 32 bytes owned by the engine uid. producers load the same
file with `ap_transport_key_load` and send sealed packets with `ap_sys_send_sealed`. the
receiver checks credentials, exact size, magic, version, type and the constant-time
tag before copying event bytes. unsigned, short, oversized, tampered and
foreign-uid datagrams never reach validation. invalid abi events increment `invalid`
in the summary but do not reach detection.

after hmac verification, `ap_sys_recv_sealed_filtered` compares the packet tag against a
fixed 256-entry ring in `ap_replay`. an exact duplicate is dropped before validation and
increments `ipc_duplicates` in the summary. the ring is bounded, wraps by evicting the
oldest tag, and adds no allocation or packet bytes.

with `--client-key pid:path`, mappings are repeatable up to 16 with pids `1..i32::MAX`
and no duplicate pids. each key is an exact 32-byte `0600` regular file loaded through
`ap_transport_key_load_path`. the receiver selects the key by the sender `SCM_CREDENTIALS`
pid and uses the same framing and hmac verification; packet bytes are unchanged. unmapped
pids are rejected and counted whatever key sealed the packet. the summary reports
`ipc_client_key_matches` and `ipc_client_key_misses`.

with `--ipc-strict-seq`, `ap_sys_recv_sealed_sequenced` adds a 64-slot table keyed by the
observed `SCM_CREDENTIALS` pid. nonzero `event.seq` values must increase per pid; equal or
lower values are dropped with `sequence_rejected` and counted as `ipc_sequence_drops`.
sequence zero is treated as unsequenced, the table replaces its oldest slot when full,
and no packet byte is added. the check is opt-in and does not identify a process.

each sequence slot also stores the `/proc/<pid>/stat` starttime of the observed sender when
it is readable. the epoch is read when a peer slot is created and again when a sequence is
stale; if it changed, the slot is reset and that sequence is treated as the first value of
the new pid epoch. if `/proc` is unavailable, the epoch is zero and stale values remain
drops. this reduces false drops after pid reuse but is not process identity.

a key authenticates possession of a local secret, not a durable process identity. a
per-client mapping is selected from `SCM_CREDENTIALS`, so pid reuse remains a caveat and
does not identify the sender. keys add no nonce and no full replay window. a same-uid
reader of the socket key or a configured client key can alter an event and reseal it with
a higher sequence, and an exact packet older than the 256-packet window can be accepted
again. duplicate suppression and the sequence table are not full replay protection.

the heap shim uses the same transport through `AP_SOCKET`. it loads the key without
heap allocation, seals each event on the stack and sends the packet with
`MSG_NOSIGNAL | MSG_DONTWAIT`, so a missing or full collector cannot block the target.

`include/apcrypto.h` exposes sha-256, hmac-sha256 and a constant-time byte compare.
`ap_sha256_init`, `ap_sha256_update` and `ap_sha256_final` stream through a 112-byte
context; rust mirrors that layout in `ffi::Sha256` and asserts its size. update
verification uses this streaming API for payload hashes and `ap_hmac_sha256` for the
manifest mac. `include/aptransport.h` owns the packet layout and key lifecycle.
`c/crypto.c`, `c/transport.c` and `c/replay.c` are linked into `libapsys.a`; the replay
filter is used by the receiver, not by the heap shim.

## callback contract

```
int callback(const ap_event *event, ap_verdict *verdict, void *user);
```

the callback returns a decision. it must not block indefinitely; the rust tracer
adapter waits at most 100 ms for a policy decision and falls back to `allow`.
`verdict.rule` is written only for `deny`. `verdict.text` is optional and currently
unused by the tracer. capture and kernel replay use one-argument callbacks that only
enqueue a copy, so those events have no verdict and cannot be denied by those paths.

## proc collector

`include/apcollector.h` exposes a bounded `/proc` snapshot API:

- `ap_collector_new(max_pids)` allocates a state table for 1 to 512 pids.
- `ap_collector_set_map_limits(collector, map_samples, wx_per_scan)` sets 1-32 map reads
  and 1-16 w+x emissions per scan; defaults are 8 and 4.
- `ap_collector_map_limits(collector, map_samples_out, wx_per_scan_out)` reads those
  bounds back.
- `ap_collector_set_io_per_scan(collector, io_per_scan)` and
  `ap_collector_io_per_scan(collector, io_per_scan_out)` set and read 1-32 sampled
  `/proc/<pid>/io` pids per scan; the default is 8.
- `ap_collector_scan(now_ns, callback, user)` enumerates `/proc`, diffs the bounded
  pid table and invokes the callback with ordinary `ap_event` values.
- `ap_collector_scan_pid_maps(pid, now_ns, callback, user)` samples one tracked pid's
  maps; the engine calls it for at most `map_samples` pids per runtime scan.
- `ap_collector_scan_pid_io(pid, now_ns, callback, user)` samples one tracked pid's
  `/proc/<pid>/io` deltas; the engine calls it for at most `io_per_scan` pids per scan.
- `ap_collector_stats(collector, out)` copies scan, pid, start, exit, exec, privilege,
  w+x, file event, file sample, file error, eviction and error counters.

the first scan is a baseline: it records pids and map hashes without emitting events.
later scans emit `AP_KIND_PROC` subkind `3` for a new pid, subkind `4` for a vanished or
replaced pid, `AP_KIND_EXEC` subkind `2` when `comm` changes, `AP_KIND_PRIV` subkind `2`
when uid or euid changes, and `AP_KIND_MEMREGION` subkind `2` for sampled writable and
executable mappings. an identical mapping is suppressed for ten seconds. at most
`wx_per_scan` w+x mappings are emitted per scan; reaching that cap ends the map read
early and the engine treats the resulting state return as a normal bounded stop. later
scans also emit `AP_KIND_FILE`/`AP_FILE_IO` when a sampled pid crosses the byte or call
thresholds, using the process-wide counters and `comm` text; they do not identify a file.
the callback must not block; the engine uses a nonblocking queue and counts drops.

this is polling, not kernel push telemetry. a comm change is an exec proxy, not proof
of exec, and a w+x mapping can be legitimate jit or runtime behavior. guard decisions
on proc events are recorded but cannot be enforced on an external pid.

## packet capture

`include/apcapture.h` exposes a bounded local capture API:

- `ap_capture_open_iface(name, snaplen)` opens a nonblocking `AF_PACKET` raw socket and
  binds it to an interface, or to all interfaces when `name` is `any`.
- `ap_capture_open_file(path, snaplen)` opens a regular file or fifo of length-prefixed
  raw ethernet frames. each frame is a little-endian 16-bit length followed by at most
  512 bytes.
- `ap_capture_poll(capture, max_frames, callback, user, timeout_ms)` waits once for
  readability and handles at most `max_frames`, capped at 16 per call.
- `ap_capture_stats(capture, out)` copies `frames`, `parsed`, `invalid`, `truncated` and
  `errors`. `ap_capture_free` closes the descriptor and releases the handle.

snaplen is 20-63 bytes and applies to the ip header after ethernet and up to two vlan
tags. each accepted frame becomes one `AP_KIND_NET`/`AP_NET_PACKET` event with the ip
header as hex text, `pid=-1`, `tid=-1` and `arg[3]=1`. rust interprets that mark as
source `"capture"` and sends the event through the unchanged network analyzer. capture
events do not pass through the authenticated ipc transport; the capture backend is a
local sensor and the source state is reported separately.

`--capture-file` is the validated path on this host. `AF_PACKET` open fails here with
`operation not permitted`, so the `packet_capture` capability and `capture` source stay
unavailable in live interface mode. guard decisions on capture events are observational.

## kernel event replay

`include/apkernel.h` exposes a bounded local event-file reader:

- `ap_kernel_open_file(path)` opens a regular `apk1` file: magic `apk1`, a little-endian
  u32 record count and raw `ap_event` records of exactly 216 bytes.
- the file must be exactly the declared size and hold at most 4096 records. bad magic,
  bad count, truncation, trailing bytes, wrong event size, wrong abi version, invalid
  kind and an unterminated `text` field are rejected.
- `ap_kernel_poll(kernel, max_events, callback, user)` invokes the callback with
  borrowed events in file order, up to `max_events` per call.
- `ap_kernel_pending`, `ap_kernel_stats` and `ap_kernel_free` expose the remaining count
  and the `frames`, `parsed`, `invalid` and `errors` counters, then release the handle.

non-network events receive `arg[3]=2`; network events keep any existing capture mark.
rust reports marked non-network events with source `"kernel"` and leaves marked network
events with source `"capture"`. replayed events do not pass through the authenticated
ipc transport; the file is a local sensor input and its source mark is internal, not a
cryptographic sensor identity. findings and guard decisions from replay are
observational. this is bounded file ingest, not live `perf`, tracepoint or bpf
collection.

## kernel sensor and lsm

`include/apksensor.h` and `c/ksensor.c` implement an optional raw kernel
sensor. it calls `bpf()` and `perf_event_open()` directly, loads small
hand-encoded ebpf programs on raw tracepoints, reads bounded per-cpu perf rings
and can attach a `BPF_LSM_MAC` program. it does not use a privileged in-kernel
agent. `ap_ksample` is a fixed 48-byte record; `ap_ksensor_sample_to_event`
maps it to a standard `AP_KIND_KERNEL` event with `arg[3]=3`, a canonical label
in `text`, and a bounded severity and confidence. that mark is internal
pipeline metadata, not an authenticated sensor identity.

the engine opens the sensor before `ap_sys_self_harden()` because the seccomp
filter denies `bpf()`. `--kernel-sensor` requests the event sensor and
`--lsm-enforce` also requests the lsm program. `--lsm-mask n` accepts a hex or
decimal u32 mask for the 32 deny-map keys. on any open, map, perf or attach
failure the engine prints a `degraded` line with a reason and continues; it
does not fail startup. `lsm_denies` counts installed deny-map entries, not
runtime lsm rejections.

source ids `9` (`ksensor`) and `10` (`lsm`) join the registry in
`c/telemetry.c`, giving ten named sources. when the kernel sensor is active
and capability probes allow it, the `perf`, `tracepoints` and `bpf` sources may
report `active` with the reason `kernel sensor raw tracepoint/perf ring`;
otherwise they keep their prior unavailable or degraded states. the `lsm`
source reports `active` only when `--lsm-enforce` is set and a bpf lsm attach
succeeds, and `unavailable` with a reason otherwise. the enforcement line
reports `lsm` as `bpf_lsm` when active and `unavailable` otherwise;
`kernel_compromise` remains `unprotected`. lsm here is a narrow local hook,
not kernel-compromise protection.

`c/taxonomy.c` maps canonical labels and aliases to rule ids, graph tactics
and confidence. `c/graph.c`, `c/evidence.c`, `cpp/beacon.cpp`, `cpp/risk.cpp`
and `rust/src/correlation.rs` turn those labels, findings and network timing
into bounded graph, ledger, beacon and risk observations. the C++ flow
analyzer also correlates `persistence_chain` and `container_escape` from
ksensor labels only when `arg[3] == 3`; replay marks (`arg[3]=2`) do not enter
those two chains. these are bounded heuristics over supplied telemetry, not
proof of attack.

on this host the capability mask stays `7`: there is no `CAP_BPF`, perf,
tracepoint or `AF_PACKET` access. live ebpf, perf, lsm and `AF_PACKET` behavior
cannot be validated here; `scripts/test_ksensor.sh` checks the requested
states, reasons and summary counters, including graceful unprivileged failure.

## intrusion analyzer

`include/apintrusion.h` and `cpp/intrusion.cpp` define a bounded c++ intrusion
analyzer linked as `build/libapintrusion.a`. `rust/src/ffi.rs` wraps it,
`DetectorRegistry::intrusion_enabled()` gates it, and `rust/src/detect.rs` feeds events
into it. `rust/src/correlation.rs` maps its rules to tactics: `process_injection` to
defense evasion, `exploit_chain` to privilege escalation and `credential_dump` to
credential access. all three are enabled by default and can be disabled through the
detector registry.

the analyzer keeps 64 fixed pid slots, a 10-second stage window and 5-second
per-slot per-rule suppression. stage bits are bounded to `remote_write`,
`remote_read`, `cred_access`, `wx`, `exec`, `redirect`, `priv` and `net`; a w+x bit
requires both write and exec bits (`arg[2] & 6 == 6`). `process_injection` fires on
`remote_write` plus `wx`, `exec` or `redirect` at confidence 870, or 890 with
`redirect`. `exploit_chain` fires on `wx` plus `redirect` and `priv`, `exec` or `net`
at confidence 920 with `priv` and 890 otherwise. `credential_dump` fires on
`remote_read` plus `cred_access` and `priv`, `net` or `remote_write` at confidence
900. detail prefixes are exactly `process_injection:`, `exploit_chain:` and
`credential_dump:`. at most one verdict is emitted per event, with priority
`credential_dump` over `process_injection` over `exploit_chain`. summary counters
`intrusion_findings` and `intrusion_suppressed` report findings and suppression. these
are bounded behavioral correlations over supplied telemetry, not proof of exploitation.

## destructive analyzer

`include/apdestructive.h` and `cpp/destructive.cpp` define a bounded c++ analyzer
linked as `build/libapdestructive.a`. `rust/src/ffi.rs` wraps it,
`DetectorRegistry::destructive_enabled()` gates it, and `rust/src/detect.rs` feeds
`AP_KIND_FILE`, `AP_KIND_NET` and `AP_KIND_KERNEL` events into it. it keeps 64 fixed
pid slots, a 10-second window and 5-second per-slot per-rule suppression. stage bits
are `write`, `read`, `rename`, `unlink`, `chmod`, `net` and `handle`; io thresholds are
4096 bytes or 4 write calls and 4096 read bytes/chars. `file_write_burst` (rule 30,
870) needs 64 write calls or 1 MiB with at least 8 write calls. `destructive_chain`
(rule 31, 900) adds at least two file actions such as rename, unlink or chmod to a
write burst. `data_exfiltration` (rule 32, 880) adds a network connect to a read burst
of 4 MiB bytes or 8 MiB chars. details use exactly `file_write_burst:`,
`destructive_chain:` and `data_exfiltration:` prefixes. at most one verdict is emitted
per feed, with priority `destructive_chain` above `data_exfiltration` above
`file_write_burst`; summary counters are `destructive_findings` and
`destructive_suppressed`. `--chain-guard` adds a separate rust-side 64-slot,
10-second gate over three distinct high-value rules before guard decisions can fire;
`chain_findings` counts those crossings. these are heuristics over sampled telemetry,
not proof of an attack.

## cli

```
ap [options] [--trace command args]
```

| option | meaning |
| --- | --- |
| `--guard` | enable protection decisions |
| `--deny rules` | comma-separated deny rules |
| `--stop rules` | comma-separated stop rules |
| `--enable rules` | detector allowlist; comma-separated rule names or `all` |
| `--disable rules` | remove detectors from the active set; comma-separated names or `all` |
| `--threshold n` | risk threshold, default 60 |
| `--min-confidence n` | minimum finding confidence, default 800 |
| `--max-states n` | risk state cap, default 4096 |
| `--queue-depth n` | engine handoff queue depth, default 4096; full queues drop telemetry instead of blocking |
| `--socket path` | telemetry socket, default `/tmp/ap.sock` |
| `--store path` | audit store, default `ap.jsonl` |
| `--audit-key path` | exact audit key path, default `<store>.key`; also used with `--verify-store` |
| `--max-events n` | tracer event cap, 0 means unlimited |
| `--mask n` | trace category bitmask, default 63 (`mem=1`, `flow=2`, `net=4`, `kernel=8`, `priv=16`, `file=32`) |
| `--duration ms` | stop after this duration |
| `--once` | stop when requested sources finish: the tracer and kernel replay |
| `--trace` | run and supervise the remaining arguments |
| `--json` | disable terminal colors and clear codes |
| `--verbose` | print all non-heartbeat events |
| `--no-self-harden` | skip seccomp self-hardening |
| `--no-fork` | do not follow fork, vfork and clone |
| `--no-proc-scan` | disable the `/proc` collector |
| `--ipc-strict-seq` | drop stale nonzero event sequence numbers per observed sender pid |
| `--client-key pid:path` | repeatable per-pid 32-byte `0600` key file, at most 16 mappings |
| `--audit-process` | append audit records through a same-uid child process |
| `--proc-interval-ms n` | proc scan interval, default 1000, minimum 100 |
| `--proc-max-pids n` | proc pid table size, default 256, maximum 512 |
| `--proc-map-samples n` | proc map samples per scan, default 8, minimum 1, maximum 32 |
| `--proc-wx-per-scan n` | w+x emissions per scan, default 4, minimum 1, maximum 16 |
| `--proc-io-per-scan n` | sampled `/proc/<pid>/io` pids per scan, default 8, minimum 1, maximum 32 |
| `--correlate-window-ms n` | entity stage window, default 5000, minimum 100, maximum 60000 |
| `--capture` | enable packet capture |
| `--capture-iface name` | select a capture interface, default `any`; implies capture |
| `--capture-file path` | read length-prefixed raw frames from a file or fifo; implies capture |
| `--capture-snaplen n` | ip-header snapshot length, default 63, minimum 20, maximum 63 |
| `--kernel-events path` | replay a strict `apk1` kernel event file; maximum 4096 events |
| `--kernel-sensor` | open the raw ebpf/perf kernel sensor before self-hardening |
| `--lsm-enforce` | request the optional bpf lsm program; implies the kernel sensor |
| `--lsm-mask n` | hex or decimal u32 mask for the 32 lsm deny-map keys |
| `--chain-guard` | require a bounded distinct-rule chain before guard deny/stop; needs `--guard` and deny or stop rules |
| `--policy path` | load a sealed policy file before explicit cli overrides |
| `--seal-policy path` | sign a plaintext `ap_policy_v1` file and add its `mac` line, then exit |
| `--verify-policy path` | check a sealed policy file and print the verified entry count, then exit |
| `--verify-store path` | check the audit chain and print the verified record count; `--audit-key path` selects an exact key instead of `<store>.key`, then exit |
| `--seal-update manifest` | sign a plaintext `ap_update_v1` manifest and add its `mac` line, then exit |
| `--verify-update manifest` | check the manifest mac and every payload hash, then exit |
| `--stage-update manifest destination` | verify and copy payloads into a new `0700` directory, then exit |
| `--install-update manifest root` | verify, stage a release under a private root and record it as active, then exit |
| `--rollback-update root` | switch the recorded active and previous releases, then exit |
| `--activation-plan root` | print a read-only verified active release plan, then exit |
| `--require-approval` | require and verify an approval line in the update modes below |
| `--help` | print usage |

`--enable` restricts detection to the listed rules; an empty `--enable` value is
ignored. `--disable` removes rules from the active set after `--enable` is applied.
`all` expands to all 32 rules in the table above. the registry has 32 static
descriptors and all are enabled by default; disabling one yields 31. zero
active detectors is a startup error, so silent monitor mode without detection
is not possible. `--chain-guard` is rejected unless `--guard` and a nonempty
`--deny` or `--stop` set are also present.

### mini gui

`./out/apgui` is a small raw-X11 viewer, not a second engine. it spawns
`./out/ap --json`, reads its stdout, and reduces each json object to one short
line. the window is a white frame with one black terminal-like area; no raw json,
chat or extra panels are shown. default arguments start guard mode with
`--deny wx_transition`, `--stop file_write_burst,destructive_chain,data_exfiltration`,
`--chain-guard`, `--threshold 10`, `--kernel-sensor`, `--lsm-enforce` and a
supervised `/bin/tail -f /dev/null`. any arguments passed to `apgui` replace those
defaults and are forwarded to `ap`; `--json` is always added first.

the default view shows guard state and real findings only. buttons and keys
`1` events, `2` guard, `3` stats and `4` degraded toggle those categories; `c`
clears the black area and `q` or Escape quits and terminates the child engine.
`paused` freezes the view while rows continue to be retained. this viewer needs
an X11 display and `libX11`; it uses no toolkit and changes no engine behavior.
enforcement status is still read from the engine, so `lsm` and kernel-compromise
limits remain explicit.

### signed policy file

`--seal-policy path` reads a plaintext file with the exact header `ap_policy_v1`, one
`key=value` line per setting and no final `mac`. `--seal-policy` creates or loads a
0600 key at `<path>.key`, computes hmac-sha256 over every byte before the final line,
appends `mac=<64 lowercase hex>` and atomically rewrites the file at mode 0600.
`--verify-policy path` checks the file and key without starting the engine and prints
the verified entry count. `--policy path` verifies, converts entries to cli-like
arguments, parses them through `Policy::from_args`, then appends the remaining cli
arguments, so explicit options override file values.

accepted boolean keys are `guard`, `json`, `verbose`, `once`, `no-self-harden`,
`no-fork`, `no-proc-scan`, `ipc-strict-seq`, `capture`, `kernel-sensor`,
`lsm-enforce`, `chain-guard` and `audit-process`; values must be `true`, `1`, `false` or `0`.
accepted value keys are `deny`, `stop`, `enable`, `disable`, `threshold`,
`min-confidence`, `max-states`, `queue-depth`, `socket`, `store`, `max-events`, `mask`,
`duration`, `proc-interval-ms`, `proc-max-pids`, `proc-map-samples`,
`proc-wx-per-scan`, `proc-io-per-scan`, `correlate-window-ms`, `capture-iface`,
`capture-file`, `capture-snaplen`, `kernel-events`, `lsm-mask`, `client-key` and `audit-key`;
their syntax matches the cli
option of the same name without the leading dashes. `trace`, nested policy flags and
`--verify-store` are not accepted. the parser rejects duplicate or unknown keys,
empty values, control characters, a non-final `mac`, a bad or duplicate `mac`, more
than 256 lines, more than 4096 bytes in a line and files over 64 kib. the policy must
be a regular non-symlink file that is not group or other writable.

### update bundle integrity

`--seal-update manifest` reads a plaintext `ap_update_v1` manifest with the exact header
`ap_update_v1`, then one `file=<relative path> <size> <sha256 hex>` line per payload.
paths must be relative, normalized, non-empty and free of whitespace, backslashes,
`.` and `..` components. a payload must be a regular, non-symlink file of the exact
declared size, at most 16 mib, and must not be group or other writable. the manifest
must also be regular, non-symlink and not group or other writable, and is limited to
64 kib, 256 lines and 4096 bytes per line.

sealing creates or loads a 0600 key at `<manifest>.key`, computes hmac-sha256 over all
bytes before the final line, appends `mac=<64 lowercase hex>` and atomically rewrites
the manifest at mode 0600. `--verify-update` checks the mac with a constant-time compare,
then hashes each payload through the C streaming sha-256 API and compares the lowercase
hash with a constant-time compare. `--stage-update manifest destination` performs the
same verification, copies payloads into a fresh `0700` directory with `0600` files and
renames the temporary directory into place. an existing destination is rejected.

`--require-approval` applies to `--seal-update`, `--verify-update`, `--stage-update`,
`--install-update`, `--rollback-update` and `--activation-plan`. with the flag, sealing
adds an `approval=<64 lowercase hex>` line immediately before the final `mac=` and creates
or loads a 0600 key at `<manifest>.approval.key`; that exact path has no extra suffix. the
approval hmac uses the domain `ap_update_approval_v1\n` plus all manifest bytes before the
approval line. the main mac covers every byte before `mac=`, including the approval line.
approval is verified whenever present; the flag requires it. errors are
`update approval missing`, `update approval mac mismatch` and
`update approval key unavailable`. the payload name `manifest.approval.key` is reserved as
well.

`--install-update manifest root` verifies the bundle, requires an existing root directory
that is owned by the current uid, is not a symlink and is not group or other writable, then
stages the payloads into `releases/<32-hex-id>` under that root. it writes `state` with
`ap_update_state_v1`, `active=<id>` and `previous=<id|none>` through a temporary file and
rename. older generated release directories are pruned on a best-effort basis after the
state switch, so active and previous are retained. installation also copies the sealed
manifest, its key and any approval key into the release as `manifest`, `manifest.key` and
`manifest.approval.key` at mode `0600`, then verifies the stored proof against the installed
payloads. those three payload names are reserved and are rejected in a bundle manifest.
`--rollback-update root` requires that
state file, checks that the previous release directory is still private, re-verifies its
stored proof, then swaps active and previous and rewrites state atomically. a missing
state file means no installed release; an invalid, loose or foreign-owned state file is
rejected. the state file is local bookkeeping, not a signed attestation.

`--install-update` prints `{"update": {"state": "installed", "entries": n, "bytes": n,
"release": "<id>"}}`; `--rollback-update` prints `{"update": {"state": "rolled_back",
"release": "<id>"}}`. `--activation-plan root [--require-approval]` reads the private
root, `releases` and `state`, checks the previous release directory when one is recorded,
verifies the active release proof and its approval when required, then prints
`{"update": {"state": "plan", "active": "<id>", "previous": "<id|none>",
"integrity": "verified", "entries": n, "bytes": n, "executed": false}}`. it makes no
writes, starts no process and performs no restart, activation, file switch or privileged
replacement. errors go to stderr with exit status 1 for verification or filesystem
failure and 2 for a missing option value.

the local key authenticates possession of `<manifest>.key`, not a vendor, a human or a
distinct process; a same-uid key reader can forge a manifest and the copied release key.
an approval line is another local possession check, not a vendor identity, a second human,
a process identity or defense against a same-uid key reader. stored proof detects payload
edits by a party without those keys, but installation and rollback do not activate code,
replace a running process, restart a service or contain a compromise. no update mode
starts the engine or changes running files.

### audit process

`--audit-process [--audit-key path]` moves store appends to a same-uid child started from
`/proc/self/exe` in internal `ap --audit-writer store key` mode. the parent writes to an
`O_CLOEXEC` pipe with a nonblocking write end. frames are a 4-byte little-endian length
plus payload, limited to a 4096-byte frame and a 4092-byte payload. the default audit key
is `<store>.key`; `--audit-key path` is an exact path with no extra `.key` suffix, and
`ap --verify-store path --audit-key key` checks a store made with a custom key. key paths
are exact through `ap_transport_key_create_path` and `ap_transport_key_load_path`.

startup reports `{"audit": {"integrity": "hmac_sha256", "backend": "process",
"process": true}}`; `backend` is `process` when the child is running and `local` otherwise,
and `process` echoes the request. when the writer cannot start, a line like
`{"degraded": {"audit_writer": "unavailable", "reason": "..."}}` is printed and appends
fall back to the parent. the summary adds `audit_process`, `audit_writer_status`
(`complete`, `degraded` or `failed`), `audit_writer_queued` and `audit_writer_dropped`;
`queued` counts frames queued to the child, not durable writes. guard audit entries are
flushed before the writer finishes; shutdown waits a bounded time and then sends `SIGTERM`.
same-uid code can tamper with the child, key, pipe or store, so this is not privilege
separation.

trace mask bits: `1` memory, `2` privilege, `4` kernel, `8` network, `16` flow.
`execve` is not watched through seccomp; exec telemetry comes from the exec ptrace event.
kernel mask events cover module operations, bpf, ptrace, kexec, file-handle opens,
cross-process writes, userfaultfd, io_uring setup, mount changes and namespace changes.
the tracer emits distinct `module_load`, `kexec`, `mount`, `namespace_change`, `bpf`,
`ptrace` and generic `kernel_interface` labels, plus `process_vm_writev`,
`process_vm_readv`, `userfaultfd`, `io_uring_setup` and `open_by_handle_at`;
`process_vm_readv` is now watched. `cpp/flow.cpp` maps those explicit labels to the
existing `kernel_iface_bit`, so legacy kernel-chain expectations still hold. w+x bits
require both write and exec bits (`arg[2] & 6 == 6`), not either bit alone. `setid` and
exec uid changes arrive as privilege events. flow correlation uses nine bounded labels
per pid. the entity graph
also treats `AP_KIND_PROC` path text as a binary reference and `AP_KIND_NET` connect or
packet text as a peer link; `--correlate-window-ms` bounds their stage window and ages
binary, peer and privilege references so old text keys do not link fresh stages. expired
references are counted in `entity_refs_expired`. these keys remain text-derived and are
not authenticated sensor identities.

## output

startup, status, summary and shutdown objects use this shape:

```
{"ap": {"state": "active", "mode": "monitor", "abi": 2, "caps": 7, "self_hardened": false}}
{"caps": {"seccomp": "available", "ptrace": "available", "proc_maps": "available",
           "perf": "unavailable", "tracepoints": "unavailable", "bpf": "unavailable",
           "packet_capture": "unavailable", ...}}
{"audit": {"integrity": "hmac_sha256", "backend": "process", "process": true}}
{"enforcement": {"backend": "ptrace_seccomp_stop", "lsm": "unavailable",
                  "seccomp": "child_filter", "ptrace": "child_stop",
                  "scope": "supervised_child", "kernel_compromise": "unprotected",
                  "note": "telemetry cannot protect the kernel after compromise; ...",
                  "lsm_denies": 0}}
{"sources": {"trace": "disabled", "ipc": "active", "proc": "active",
              "perf": "unavailable", "tracepoints": "unavailable",
              "bpf": "unavailable", "capture": "active", "kernel": "active",
              "ksensor": "unavailable", "lsm": "unavailable"}}
{"detectors": {"total": 32, "enabled": 32, "disabled": 0,
                "enabled_rules": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32],
                "disabled_rules": [], "coverage": [{"rule":1,"name":"wx_region",...}]}}
{"proc": {"scans": 6, "pids_seen": 1536, "starts": 2, "exits": 1,
           "execs": 0, "priv_changes": 0, "wx_regions": 1,
           "file_events": 1, "file_samples": 6, "file_errors": 0,
           "evictions": 0, "errors": 0, "interval_ms": 200, "max_pids": 512,
           "map_samples": 8, "wx_per_scan": 4, "io_per_scan": 8}}
{"capture": {"mode": "file", "snaplen": 63, "frames": 4, "parsed": 4,
              "invalid": 0, "truncated": 0, "errors": 0}}
{"kernel": {"mode": "file", "events": 6, "parsed": 6, "invalid": 0, "errors": 0}}
{"degraded": {"source": "perf", "state": "unavailable", "reason": "perf_event_open denied"}}
{"degraded": {"source": "capture", "state": "unavailable", "reason": "raw packet socket denied by kernel policy"}}
{"degraded": {"source": "kernel", "state": "unavailable", "reason": "kernel event file open failed or invalid"}}
{"degraded": {"source": "ksensor", "state": "unavailable", "reason": "kernel sensor unavailable"}}
{"degraded": {"source": "lsm", "state": "unavailable", "reason": "bpf lsm unavailable"}}
{"degraded": {"correlation": "unavailable", "reason": "correlation analyzer allocation failed"}}
{"degraded": {"audit": "fnv1a", "reason": "audit key unavailable"}}
{"degraded": {"audit_writer": "unavailable", "reason": "audit writer spawn failed"}}
{"stats": {"events": 200, "findings": 3, "invalid": 0, "risk_states": 1,
            "net_packets": 0, "peer_events": 0, "flow_events": 8,
            "entity_events": 4, "entity_findings": 1,
            "entity_refs_expired": 1, "intrusion_findings": 0,
            "intrusion_suppressed": 0, "destructive_findings": 0,
            "destructive_suppressed": 0, "chain_findings": 0, ...}}
{"summary": {"events": 200, "findings": 3, "invalid": 0, "recorded": 3,
              "printed": 12, "dropped": 0, "denials": 0, "risk_states": 1,
              "queue_drops": 0, "ipc_duplicates": 2, "ipc_sequence_drops": 0,
              "ipc_client_key_matches": 2, "ipc_client_key_misses": 1,
              "audit_process": true, "audit_writer_status": "complete",
              "audit_writer_queued": 3, "audit_writer_dropped": 0,
              "net_packets": 0, "peers": 2, "peer_events": 8,
              "peer_evictions": 0, "peer_bursts": 0, "peer_exhaustion": 0,
              "flow_events": 8, "entity_events": 4, "entity_findings": 1,
              "entity_evictions": 0, "entity_refs_expired": 1,
              "capture_frames": 4, "capture_parsed": 4,
              "capture_invalid": 0, "capture_truncated": 0, "capture_errors": 0,
              "kernel_events": 6, "kernel_parsed": 6, "kernel_invalid": 0,
              "kernel_errors": 0,
              "ksensor_events": 0, "ksensor_invalid": 0, "ksensor_dropped": 0,
              "ksensor_attached": 0, "lsm_active": 0, "lsm_denies": 0,
              "graph_added": 4, "graph_evicted": 0, "graph_findings": 0,
              "graph_suppressed": 0, "evidence_inserted": 1,
              "evidence_duplicates": 0, "evidence_evicted": 0,
              "beacon_findings": 0, "risk_findings": 0,
              "intrusion_findings": 0, "intrusion_suppressed": 0,
              "destructive_findings": 0, "destructive_suppressed": 0,
              "chain_findings": 0,
              "sources": ["ipc","proc","capture","kernel"], "detectors": "32/32",
              "proc_scans": 6, "proc_starts": 2, "proc_exits": 1,
              "proc_wx_regions": 1, "proc_file_events": 1,
              "proc_file_samples": 6, "proc_file_errors": 0, ...}}
{"ap": {"state": "stopped", "reason": "duration", "events": 200, "findings": 3}}
```

one-shot modes print only their own object and do not start the engine:

```
{"verify": {"state": "ok", "records": 12}}
{"policy": {"state": "ok", "entries": 6}}
{"policy": {"state": "sealed", "entries": 6}}
{"update": {"state": "sealed", "entries": 2}}
{"update": {"state": "ok", "entries": 2, "bytes": 14}}
{"update": {"state": "staged", "entries": 2, "bytes": 14}}
{"update": {"state": "installed", "entries": 2, "bytes": 14, "release": "<id>"}}
{"update": {"state": "rolled_back", "release": "<id>"}}
{"update": {"state": "plan", "active": "<id>", "previous": "none",
            "integrity": "verified", "entries": 2, "bytes": 14, "executed": false}}
```

`audit_writer_queued` counts frames queued to the child, not durable writes. the client
key counters appear when mappings are configured; the audit writer fields appear when
`--audit-process` is requested. the startup `policy` string carries `client_keys:n` or
`no_client_keys`, and `audit_process` or `no_audit_process`.

`ksensor_events`, `ksensor_invalid`, `ksensor_dropped` and `ksensor_attached` describe
the optional raw sensor. `lsm_active` is `1` only when a bpf lsm attach succeeds, and
`lsm_denies` counts installed deny-map entries, not runtime lsm rejections. graph and
evidence counters describe bounded local correlation; `beacon_findings`,
`risk_findings`, `intrusion_findings` and `intrusion_suppressed` are heuristic
observations, not proof of attack. all are `0` when the matching feature is not
requested.

capability bits are `1` seccomp, `2` ptrace, `4` proc maps, `8` perf, `16` tracepoints,
`32` bpf and `64` packet capture. the observed host mask is `7`. source states are
`active`, `degraded`, `unavailable` and `disabled`.

`rule` is the first finding for an event; `rules` lists every finding rule in order.
store records also carry `findings`, a compact list of `rule` and `detail` pairs. the
detail is the verdict explanation, for example `kernel_chain:bpf+ptrace`,
`privilege_crossing:bpf+setid`, `process_injection:...`, `exploit_chain:...`,
`credential_dump:...` or
`entity_chain:wx+exec+priv+net:pid+binary+peer+priv:10.9.8.7:4444`, so correlated
findings remain auditable.

event records add `"rule"` when a finding exists and one of these actions:
`observed`, `investigating`, `denied`, `isolated`. the store appends one compact json
object per finding or, with `--verbose`, per event. guard actions also append
`{"audit":"denied:wx_transition"}` records at shutdown.

every record ends with a `chain` object: `seq` restarts at 1 after rotation, `prev`
holds the previous digest, and `hash` is the current digest. new records set
`"v":"hmac"` and use a 64-hex hmac-sha256 over a domain prefix, `seq`, `prev` with
length, the record bytes with length and the local `<store>.key`. v1 records without
`v` remain verifiable with the original 16-hex fnv-1a digest over `prev` plus record
bytes. mixed files verify in order; each record chooses its own version.

`ap --verify-store path` validates order and digests and prints the record count. it
loads `<store>.key` only when an hmac record is present. a missing, loose, foreign or
wrong-size key fails verification with `audit key unavailable`. startup reports
`{"audit":{"integrity":"hmac_sha256"}}` when signing is active, or `fnv1a` plus an
explicit degraded line when key setup fails. hmac is tamper evidence against a party
without the local key, not a signature or protection against a key holder.
