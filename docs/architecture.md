# architecture

ap is an event-driven engine. supervised telemetry arrives from a child process, from
external producers over a unix datagram socket, from the optional heap shim, from an
optional bounded packet-capture backend, from an optional bounded kernel event file and
from an optional raw kernel sensor. a bounded `/proc` snapshot/delta collector also runs
on a configurable interval. all paths feed one bounded pipeline.

## data flow

```
producers              transport                    engine                  output
c tracer  ---------->  callback  -----------------\
c heap shim -------->  sealed datagram ------------>  validate -> detect -> correlate
external producers ->  sealed datagram ------------/                          -> risk -> guard -> cli
c /proc collector --->  callback  -----------------/                                   |       |
c capture backend --->  callback  -----------------/                                   |       |
c kernel replay ----->  callback  -----------------/                                   |       |
c ksensor ----------->  callback  -----------------/                                   v       v
                                                                                    verdict  store
```

1. a producer fills a fixed `ap_event`. datagram producers seal it into a 256-byte
   hmac-authenticated packet; the tracer, proc collector, capture backend, kernel
   replay reader and optional ksensor use a direct callback.
2. the proc collector reads bounded `/proc` snapshots on the main loop and sends
   standard events into the same queue; the startup baseline emits no events.
3. the capture backend reads a raw socket or a length-prefixed frame file on an optional
   thread and sends standard network events into the same queue. it marks `arg[3]=1` so
   normalization can report source `"capture"`.
4. the kernel replay reader validates a strict `apk1` file on an optional thread and
   sends raw events into the same queue. it marks non-network events with `arg[3]=2` so
   normalization can report source `"kernel"`.
5. the optional ksensor opens before self-hardening, reads bounded 48-byte samples from
   raw tracepoint perf rings and sends standard kernel events with `arg[3]=3`. it may
   also install a narrow bpf lsm deny hook. open, map, perf and attach failures emit a
   degraded line and do not stop the engine.
6. the transport verifies credentials, size, header and tag, using the socket key or a
   key selected by sender pid when `--client-key pid:path` mappings are configured;
   unmapped pids are rejected. the engine then validates size, abi version, kind and
   string termination.
7. cheap rules in rust and bounded analyzers in c++, including the intrusion
   analyzer, produce findings. bounded flow correlation combines weak indicators and
   links stage observations across pid, binary, peer and uid entities.
8. `rust/src/correlation.rs` feeds labels and findings into a bounded taxonomy, tactic
   graph, evidence ledger, beacon, intrusion and risk accumulators. it evaluates them
   on a 500 ms cadence and adds heuristic findings to the same pipeline.
9. per-pid risk accumulates and decays; guard applies policy. monitor only records;
   guard may deny or stop.
10. cli emits json-inspired lines; store appends bounded jsonl records with an hmac chain
    while a local audit key is available, directly or through an optional same-uid writer
    child, and reports explicit degradation otherwise.
11. for traced syscalls, the verdict returns through the callback to ptrace.

## responsibilities

- rust owns runtime, threading, validation, policy, sealed policy loading, update-bundle
  verification, staging, approval and read-only activation plans, risk, guard, ipc with
  per-client key mappings, cli and store. it starts and finishes the optional same-uid
  audit writer child. `auth` centralizes 0600 key lifecycle through exact paths, hmac and
  constant-time comparison for audit, policy, update and approval integrity.
- c owns `ptrace`/`seccomp` supervision, `/proc` parsing including sampled `io` deltas,
  capability probes, sha-256, hmac-sha256, packet framing, key lifecycle, bounded ipc
  duplicate suppression, per-client key selection by pid, the opt-in per-pid sequence
  table, the framed audit pipe and same-uid writer spawn, local capture, bounded kernel
  event replay, the raw kernel sensor, taxonomy, graph and evidence correlation, and
  the heap shim.
- c++ owns the bounded network, control-flow, entity-correlation, beacon, intrusion,
  destructive-file and risk analyzers.
- `apabi.h` is the canonical versioned c abi; rust mirrors only the layout constants.
  rule ids are 1..32 with `AP_RULE_MAX` and rust `RULE_MAX` both at 32.
- `aptransport.h` wraps that abi without changing event bytes; `apreplay.h` adds a
  receiver-local 256-tag ring and opt-in 64-peer sequence table with `/proc` starttime
  epochs without changing the packet layout.
- `apcapture.h` emits standard network events from a bounded local sensor without
  changing the abi or rule set.
- `apkernel.h` emits standard events from a bounded `apk1` file without changing the abi
  or rule set.
- `apksensor.h` emits standard kernel events from a bounded raw sensor with source mark
  `3`. `apgraph.h`, `apevidence.h`, `aptaxonomy.h`, `apbeacon.h`, `apintrusion.h`,
  `apdestructive.h` and `aprisk.h` define the bounded local correlation contracts. no
  source mark is an authenticated identity.

the internal format is the c struct itself. no json is used between subsystems, only at
the cli and audit-store boundary.

## runtime

`engine::run` installs signal handlers, probes capabilities, opens the optional ksensor
and only then optionally self-hardens, because the seccomp filter denies `bpf()`. it
starts the ipc server and creates a bounded `sync_channel(4096)`. if proc telemetry is
enabled and readable, it takes a startup baseline and schedules further scans on the
main loop at `--proc-interval-ms`; each runtime scan also samples up to
`--proc-io-per-scan` tracked pids for `/proc/<pid>/io` deltas. one thread receives ipc datagrams through the hmac
verifier, bounded replay ring and opt-in per-pid sequence table, selecting a key by sender
pid when `--client-key pid:path` mappings are configured. one optional thread runs
the tracer, one optional thread runs capture, and one optional thread runs kernel replay.
the ksensor polls raw perf rings on the main loop and emits `arg[3]=3` kernel events;
`--lsm-enforce` also requests a bpf lsm deny hook. capture opens a file without a
capability check; interface mode requires the `packet_capture` capability and degrades
with a named reason when raw sockets are denied. kernel replay opens a strict local file
without a capability check and degrades with a named reason when the file is missing or
invalid. sensor failures emit a degraded line and do not stop startup. the main loop owns
all mutable analyzer, correlation and risk state, so there are no locks around those
structures; only capture and kernel counters use small mutexes at shutdown.

with `--audit-process`, startup spawns a same-uid child from `/proc/self/exe` in internal
`ap --audit-writer store key` mode. the parent writes 4-byte little-endian length plus
payload frames to an `O_CLOEXEC` pipe with a nonblocking write end; frames are capped at
4096 bytes with a 4092-byte payload. the audit key is `<store>.key` by default, and
`--audit-key path` is an exact path with no extra `.key` suffix. startup reports the
backend as `process` or `local` and `process` echoes the request; a writer that cannot
start emits a degraded line and appends fall back to the parent. guard audit entries are
flushed before the writer finishes, followed by a bounded wait and `SIGTERM` if needed.
`audit_writer_queued` counts frames queued to the child, not durable writes, with
`audit_writer_dropped` and `audit_writer_status` alongside it in the summary.

before engine construction, `main` handles `--verify-store`, `--seal-policy`,
`--verify-policy`, `--seal-update`, `--verify-update`, `--stage-update`,
`--install-update`, `--rollback-update` and `--activation-plan` as separate exits.
`--verify-store path --audit-key key` verifies a store made with a custom key. update
modes parse a bounded manifest, verify local hmac and payload hashes, copy payloads into
a new `0700` directory, and optionally keep the copy as a release under a private root with
a stored sealed proof, an atomic local state switch and verified rollback.
`--require-approval` applies to seal, verify, stage, install, rollback and plan modes;
sealing adds an `approval=` line backed by the exact `<manifest>.approval.key`, and every
listed mode checks it when present or required. the main mac covers the approval line.
`--activation-plan root` reads private root, `releases` and `state`, checks the previous
release when present, verifies the active proof and prints a read-only plan. none of these
modes starts the engine, activates code or replaces running files. installation and rollback
change only the local state file; the plan performs no writes, file switch or process start.
with `--policy`, the signed file is verified, converted to
cli-like arguments and joined with explicit cli arguments in that order, so later cli
options override file values. `Policy::from_args` remains the only policy parser; no
second configuration schema reaches the engine.

signal handling and shutdown are cooperative: sigint and sigterm set a flag checked by
the main loop. `--duration` provides a bounded run. `--once` stops when requested sources
finish: the tracer and kernel replay. the capture thread polls with a 100 ms timeout and
stops through an atomic flag, so shutdown remains bounded.

## detection

detection is split by cost and selected by a static registry of 32 descriptors. each
rule has one descriptor with its telemetry needs, severity, default confidence, cost
class and limits. rule ids 20-29 cover `kernel_rootkit`, `credential_theft`,
`persistence_chain`, `container_escape`, `fileless_exec`, `anti_analysis`, `beaconing`,
`process_injection`, `exploit_chain` and `credential_dump`; ids 30-32 add
`file_write_burst`, `destructive_chain` and `data_exfiltration`. `AP_RULE_MAX` and rust
`RULE_MAX` are both 32. all 32 detectors are enabled by default; disabling one yields
31 and `--enable all` expands to 32. policy turns `--enable` and `--disable` into an
active rule set; the engine prints the same descriptors as coverage status. disabled
rules are filtered after cheap analysis, and disabled network, flow, intrusion or
destructive families skip their bounded c++ analyzer entirely. zero active detectors
is rejected at startup.

- cheap rust rules handle explicit w+x mappings, w+x transitions, executable stacks,
  shadow mismatch, privilege crossing, kernel interfaces, heap errors and raw sockets.
- c++ network analysis validates ipv4 and ipv6 headers, ipv4 checksums, tcp flags
  and phase, udp length, extension-header chains and fragment overlap using bounded
  family-aware flow and fragment tables. it also tracks 64 bounded peer endpoints in
  one-second windows and reports burst and exhaustion counters without adding rules.
- captured packets enter the same network analyzer as ipc packets. ethernet and up to
  two vlan tags are stripped, 20-63 ip-header bytes are hex encoded, and `arg[3]=1`
  selects the `"capture"` source in normalization and findings. capture is local and
  observational; only framed-file mode is validated on this host.
- replayed kernel events enter the same cheap rules, c++ analyzers, risk and store as
  other sources. non-network events carry `arg[3]=2`, which selects the `"kernel"` source
  without overriding network capture marks. the reader validates framing and abi fields,
  but replay is local file ingest, not live kernel push telemetry.
- ksensor samples enter as `AP_KIND_KERNEL` events with `arg[3]=3` and canonical labels
  such as `kernel_rootkit`, `credential_theft`, `persistence`, `container_escape`,
  `fileless_exec` and `anti_analysis`. aliases such as `rootkit`, `memfd_exec` and
  `namespace_change` map to the same taxonomy entries. the mark is internal metadata,
  not proof that a kernel collector produced the event.
- c++ flow analysis tracks executable ranges, weak return-site indicators and
  shadow-stack pairs. a weak return site has confidence 250 and never alerts alone.
  at least three weak indicators in the correlation window, one of which may be
  the w+x transition itself, yields a `correlated_exploit_indicators` finding
  with confidence 820. an exec event within five seconds of a w+x transition or
  mapping yields one `exec_after_wx` finding with confidence 870; the state is then
  cleared so repeated exec events do not repeat the alert. kernel and privilege events
  are also fed to this analyzer: each pid keeps bounded five-second sets of nine
  distinct labels (`module_load`, `kexec`, `mount`, `namespace_change`,
  `kernel_interface`, `bpf`, `ptrace`, `setid`, `exec_uid_change`). `kexec` plus any
  other label, `module_load` plus two other labels, or `bpf` plus a kernel-stop or
  interface label yields one explained `kernel_chain` finding. `setid` alone stays
  quiet; `setid` with a uid delta or a kernel-stop label yields one explained
  `privilege_crossing` finding with confidence 860. ksensor-only labels with `arg[3]=3`
  join that kernel mask, and two persistence writes plus an exec or start and a network
  stage yield `persistence_chain`; namespace, mount and one privileged label yield
  `container_escape`. replay marks with `arg[3]=2` do not enter those two chains.
  the tracer also emits explicit `process_vm_writev`, `process_vm_readv`,
  `userfaultfd`, `io_uring_setup` and `open_by_handle_at` labels; `process_vm_readv`
  is watched. `cpp/flow.cpp` maps these labels to the existing `kernel_iface_bit`,
  so established kernel-chain expectations still hold. repeated labels and stale
  windows stay quiet. state is limited to the 32 flow pid slots and resets after a
  finding.

the same flow analyzer runs a bounded entity graph. it observes four stage bits
(`wx`, `exec`, `priv`, `net`) in a configurable default 5000 ms window, links `pid`,
`binary`, `peer` and `priv` references, and fires one
`correlated_exploit_indicators` finding with confidence 880 only when all four stages
and at least three linked classes are present. binary keys come from exec and mapped
paths, peer keys are normalized from `peer:host:port` text or ipv4/ipv6 packet hex, and
privilege keys come from exec uid changes. after a finding, all stage windows clear so
repeated network or exec events stay quiet. benign jit wx+exec and container
exec+uid+network streams stay below the finding threshold.

`include/apintrusion.h` and `cpp/intrusion.cpp` add a separate bounded c++ intrusion
analyzer linked as `build/libapintrusion.a`. `rust/src/ffi.rs` wraps it,
`DetectorRegistry::intrusion_enabled()` gates it, `rust/src/detect.rs` feeds events
into it, and `rust/src/correlation.rs` maps its rules to tactics: `process_injection` to
defense evasion, `exploit_chain` to privilege escalation and `credential_dump` to
credential access. it keeps 64 fixed pid slots, a 10-second stage window and 5-second
per-slot per-rule suppression, with bounded stage bits `remote_write`, `remote_read`,
`cred_access`, `wx`, `exec`, `redirect`, `priv` and `net`. a w+x bit requires both
write and exec bits (`arg[2] & 6 == 6`), not either alone. `process_injection` fires on
`remote_write` plus `wx`, `exec` or `redirect` with confidence 870, or 890 with
`redirect`; `exploit_chain` fires on `wx` plus `redirect` and `priv`, `exec` or `net`
with confidence 920 when `priv` is present and 890 otherwise; `credential_dump` fires
on `remote_read` plus `cred_access` and `priv`, `net` or `remote_write` with confidence
900. details use exactly `process_injection:`, `exploit_chain:` and
`credential_dump:` prefixes. at most one verdict is emitted per event, with priority
`credential_dump` above `process_injection` above `exploit_chain`. summary counters
`intrusion_findings` and `intrusion_suppressed` report findings and suppression. these
are heuristics over supplied telemetry, not proof of exploitation.

`include/apdestructive.h` and `cpp/destructive.cpp` add a separate bounded c++
destructive analyzer linked as `build/libapdestructive.a`. `rust/src/ffi.rs` wraps it,
`DetectorRegistry::destructive_enabled()` gates it, and `rust/src/detect.rs` feeds
`AP_KIND_FILE`, `AP_KIND_NET` and `AP_KIND_KERNEL` events into it. it keeps 64 fixed
pid slots, a 10-second window and 5-second per-slot per-rule suppression. stage bits
are `write`, `read`, `rename`, `unlink`, `chmod`, `net` and `handle`; file io stage bits
need at least 4096 bytes or 4 write calls, or 4096 read bytes/chars. `file_write_burst`
(rule 30, 870) fires on 64 write calls or 1 MiB plus 8 write calls; `destructive_chain`
(rule 31, 900) adds at least two file actions such as rename, unlink or chmod to a
write burst; `data_exfiltration` (rule 32, 880) adds a network connect to a read burst
of at least 4 MiB bytes or 8 MiB chars. details use exactly `file_write_burst:`,
`destructive_chain:` and `data_exfiltration:` prefixes. at most one verdict is emitted
per feed, with priority `destructive_chain` above `data_exfiltration` above
`file_write_burst`; summary counters are `destructive_findings` and
`destructive_suppressed`. these are bounded heuristics over sampled telemetry.

`rust/src/correlation.rs` adds a separate bounded correlation bridge. it maps a label
or finding through `c/taxonomy.c` to a tactic, rule and confidence, adds the observation
to `c/graph.c`, records an evidence key in `c/evidence.c` with 30-second dedupe, feeds
network timing to `cpp/beacon.cpp` and finding signals to `cpp/risk.cpp`. the graph holds
128 nodes, 256 edges and 32 chains in a 60-second window with 30-second suppression;
evidence uses 256 slots and 64-byte keys; beacon uses 64 peers, 8 samples and a 90-second
window; risk uses 64 entities, 8 signals, a 90-second window and 30-second suppression.
evaluation runs every 500 ms and emits `attack_graph`, `beacon` and `risk` findings with
their own counters. these are heuristics over supplied telemetry, not proof of attack.

risk is per pid, capped at 100, decays by 5 every 5 seconds and crosses the alert
threshold at 60 by default. the engine updates risk with severity weight and a fixed
confidence of 500; detection confidence is kept separate.

## protection

protection is deliberately separate from detection. a finding never causes an action
by itself. an action requires all of:

1. `--guard`,
2. an explicit `--deny` or `--stop` rule,
3. finding confidence at or above `--min-confidence` (800 by default),
4. risk at or above `--threshold` (60 by default).

`--chain-guard` is optional and requires `--guard` plus a nonempty `--deny` or `--stop`
set. it adds a fifth gate: a bounded 64-slot, 10-second per-pid tracker must observe
three distinct high-value rules at or above `--min-confidence` before the same decision
can deny or stop. high-value rules include file-write burst, destructive chain, data
exfiltration, process injection, exploit chain, credential dump, kernel rootkit,
persistence, container escape, fileless exec, kernel chain and privilege crossing.
`chain_findings` counts tracker crossings, not enforced actions.

`deny` is enforced only on supervised syscall stops by rewriting the syscall registers.
`stop` sends `sigstop` to the traced pid. telemetry received over ipc, the proc
collector, the capture backend, kernel replay or the raw kernel sensor is observational:
the engine records the decision but cannot enforce it on an external producer, pid,
network peer, replayed event or kernel path. an `enforcement` status line reports the
active backend, seccomp and ptrace states. `lsm` is `bpf_lsm` only when an optional
lsm attach succeeds and `unavailable` otherwise; `lsm_denies` counts installed deny-map
entries, not runtime lsm rejections. kernel compromise stays `unprotected`. lsm is a
narrow local hook, not kernel-compromise protection, and telemetry cannot defend a
system after compromise.

## bounds

| subsystem | bound |
| --- | --- |
| engine queue | 4096 envelopes |
| proc scan interval | 1000 ms default, 100 ms minimum |
| proc pid states | 256 default, 512 maximum |
| proc map samples | 8 pids and 4 w+x emissions per scan by default, validated 1-32 and 1-16, 10 s repeat suppression |
| proc io samples | 8 pids per scan by default, validated 1-32 |
| tracer pids | 32 |
| tracer regions per pid | 96 |
| flow pid slots | 32 |
| flow ranges per pid | 64 |
| flow kernel and privilege labels | 9 per pid, 5 s window |
| intrusion pid slots | 64 fixed slots, 8 stage bits, 10 s stage window, 5 s per-slot per-rule suppression |
| destructive pid slots | 64 fixed slots, 7 stage bits, 10 s window, 5 s per-slot per-rule suppression, 3 result candidates |
| chain guard slots | 64 fixed pid slots, 10 s window, 3 distinct high-value rules, one crossing per slot |
| entity correlation slots | 32 |
| entity key length | 48 bytes |
| entity stage window | 5000 ms default, 100 ms minimum, 60000 ms maximum; ages binary, peer and privilege references |
| shadow stack depth | 64 per pid |
| network flows | 512 |
| fragment states | 128 |
| peer states | 64, one-second window, burst after 32 events |
| capture frames per poll | 16 |
| capture frame size | 512 bytes raw, 20-63 bytes ip header snaplen |
| kernel replay events | 4096 raw events per file |
| ksensor sample | 48 bytes, 16 cpus, 64 ring pages, 256 events per poll, source mark `3` |
| ksensor labels | 13 label ids, 12 canonical taxonomy entries plus aliases |
| tactic graph | 128 nodes, 256 edges, 32 chains, 64-byte keys, 60 s window, 30 s suppression |
| evidence ledger | 256 slots, 64-byte keys, 30 s dedupe |
| beacon samples | 64 peers, 8 samples, 48-byte keys, 90 s window |
| entity risk | 64 entities, 8 signals, 48-byte keys, 90 s window, 30 s suppression |
| ipc replay tags | 256 packet tags, oldest evicted first |
| ipc sequence peers | 64 observed sender pids with `/proc` starttime epochs, oldest evicted first, opt-in |
| client key mappings | 16 pids, `1..i32::MAX`, no duplicates, exact 32-byte `0600` regular key files |
| client key counters | `ipc_client_key_matches`, `ipc_client_key_misses` |
| audit frame | 4-byte little-endian length plus payload, 4096-byte frame, 4092-byte payload |
| audit writer counters | `audit_writer_queued`, `audit_writer_dropped`; queued is not durable |
| update manifest | 64 kib, 256 lines, 4096 bytes per line |
| update payload | 16 mib per listed file |
| per-pid risk states | 4096 pids |
| guard audit | 256 entries |
| audit store | 4 mib, rotates to `.1.jsonl` |
| console output | 120 printed events per second |

when a table is full, the implementation evicts the oldest state or drops new state.
new pids beyond the tracer pid limit continue untraced.

## degraded mode

capability bits are reported at startup: `1` seccomp, `2` ptrace, `4`
`/proc/self/maps`, `8` perf, `16` tracepoints, `32` bpf and `64` packet capture. the
observed host mask is `7`. a rust source registry maps these bits to ten named telemetry
sources and prints each source state: `trace`, `ipc`, `proc`, `perf`, `tracepoints`,
`bpf`, `capture`, `kernel`, `ksensor` and `lsm`. all active sources follow the same event
queue, so source addition does not change detection. the `proc` source is `active` when
the capability and policy allow it, `disabled` under `--no-proc-scan`, and `degraded`
when allocation fails. the `capture` source is `disabled` unless requested, `active` when
a file or interface backend opens, and `unavailable` with a reason when interface mode is
denied. the `kernel` source is `disabled` unless `--kernel-events` is requested, `active`
when the `apk1` file opens, and `unavailable` with a named reason when the file is missing
or invalid. the `ksensor` source is `disabled` unless `--kernel-sensor` or
`--lsm-enforce` is set, `active` when the raw sensor opens, and `unavailable` with a
reason on failure. `lsm` is `disabled` unless requested, `active` only on a successful
bpf lsm attach, and `unavailable` otherwise. `perf`, `tracepoints` and `bpf` may report
`active` with the reason `kernel sensor raw tracepoint/perf ring` when the sensor opens;
without it they remain `unavailable` or `degraded`. if ptrace is unavailable, the engine
reports `degraded` and continues with the other requested sources. on this host no raw
sensor path is available, so live ebpf, perf and lsm behavior is not validated.

audit starts with backend `process` when the writer child is running and `local` otherwise,
while the `process` field echoes the request. when the writer cannot start, the engine
prints `{"degraded": {"audit_writer": "unavailable", "reason": "..."}}` and appends in the
parent. the summary reports `audit_writer_status` as `complete`, `degraded` or `failed`,
with `audit_writer_queued` and `audit_writer_dropped`; queued frames are not durable writes.
the writer is same-uid code, not privilege separation, and same-uid code can tamper with
the child, key, pipe or store.
self-hardening is skipped in trace mode because the inherited seccomp filter would deny
the traced child; the engine reports `deferred_trace_mode`. unsupported operations return
`ap_err_unsupported` instead of failing the process.
