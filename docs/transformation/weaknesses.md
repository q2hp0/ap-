# architectural weaknesses

each item names the gap and the layer it blocks.

| id | weakness | impact |
| --- | --- | --- |
| w01 | core syscall telemetry is ptrace-supervised-child only | `/proc` and sensor observations are partial; no complete system view |
| w02 | fixed syscall list | unseen syscalls produce no evidence |
| w03 | eBPF, tracepoint and perf sensor code exists but is unvalidated here | capability mask 7 prevents live attach; no kprobes or measured low-overhead claim |
| w04 | bpf-lsm hook is a local configured-key deny mask, unavailable on this host | no validated kernel-hook enforcement; policy cannot be claimed at kernel hooks |
| w05 | ipc trust is effective-uid equality | same-uid process can read the 0600 key and forge valid telemetry |
| w06 | hmac authenticates packet bytes, not producer identity | a key holder can reseal a fresh packet, so integrity is not provenance |
| w07 | audit chain uses hmac with a local key | legacy fnv records still verify and a key holder can recompute the chain |
| w08 | cross-entity evidence is sparse and text-derived | chains need observed stages and linked keys; missing or aliased keys can hide or confuse them |
| w09 | fixed 32 pid and 96 region slots | state is dropped under load |
| w10 | heap visibility depends on `ld_preload` | determined target can avoid the shim |
| w11 | network engine historically parsed supplied hex, not live packets | bounded capture backend exists, but live capture is denied on this host |
| w12 | enforcement is ptrace rewrite, `sigstop` or a local lsm deny mask | no process, system or network containment |
| w13 | detector registry is compiled in | 32 descriptors gate rules, but adding a detector still requires a rebuild |
| w14 | coverage output comes from static descriptors | implemented and experimental behavior are distinguished by hand-written limits, not runtime proof |
| w15 | no capability matrix for kernels and distributions | compatibility is asserted, not tested |
| w16 | validation uses fixed seeds and no controlled exploit or vm tests | false-negative claims are unproven |
| w17 | single trust domain | one compromised component can influence all others |
| w18 | source health is named, but sensor truth is not verified | degraded states are visible, yet an active mark is not proof of a real sensor |
| w19 | `/proc` telemetry is poll-based and sampled | short-lived processes can be missed, comm changes are exec proxies, w+x comes from 1-32 map samples per scan with 1-16 emissions, and io comes from 1-32 process-wide samples per scan |
| w20 | raw packet sockets are unavailable on the measured host | live interface capture cannot be validated here; frame-file mode is used instead |
| w21 | capture marks are internal and unauthenticated | a local capture file can be crafted or replayed and is not proof of an authenticated sensor |
| w22 | kernel replay is file ingest, not live collection | only supplied events are seen; the source mark is unauthenticated and replay cannot contain anything |
| w23 | update trust is local and installation is not activation | manifest, stored release proofs and the second approval key prove possession of local 0600 keys, not a vendor identity; a same-uid reader can forge a bundle, copy release or approval keys or edit unsigned state, and the read-only plan adds no activation or privileged replacement boundary |
| w24 | replay defense is bounded duplicate, sequence and per-client key checks, not a nonce | a 256-packet window drops byte-identical replays only; the opt-in 64-peer table drops stale nonzero sequences from an observed pid and resets on a readable `/proc` epoch change; up to 16 `--client-key pid:path` entries select a local key by credentials pid with match/miss counters, but pid reuse can misroute it, and resealed higher sequences, older replays and durable process identity remain outside coverage |
| w25 | second-key approval and read-only plan do not prove vendor identity or safety | `--require-approval` and the 0600 `<manifest>.approval.key` are local one-shot checks; `plan` verifies active proof and private state and prints `executed:false` without writes, spawn, restart or file switching, so no activation, privileged replacement or release-safety proof follows |
| w26 | audit child writer is a call-site boundary, not privilege separation | the same-uid child from `/proc/self/exe` owns the store write but shares uid and executable with the engine; `audit_writer_queued` is not durable, and a same-uid writer can still alter evidence |
| w27 | ksensor labels are internal names with a bounded alias set | conversion emits `kernel_rootkit` and `cred_change` directly and `ptrace` is aliased to `ptrace_access`; `rootkit`, `credential_change` and `cred` are also accepted for replay fixtures, but an unseen label spelling yields no taxonomy prior |
| w28 | ksensor, replay, capture and kernel source marks are internal | a local producer can label an event as a trusted path; marks select pipeline behavior, not cryptographic sensor identity |
| w29 | lsm cannot protect a compromised kernel | even an active `bpf_lsm` hook is bypassable after kernel compromise, so the enforcement report keeps `kernel_compromise` as `unprotected` |
| w30 | intrusion rules are bounded label-derived stage correlations | 64 pid slots, a 10-second window and 5-second per-rule suppression can drop or confuse chains; missing labels or pid reuse can hide one, and no verdict proves code injection, exploit success or credential access |
| w31 | destructive file rules are sampled and process-wide | `/proc/<pid>/io` deltas cannot name a file or inspect content; short-lived pids, counter resets and sampling gaps can hide a chain, while benign bulk work can imitate one, and `--chain-guard` remains a heuristic gate |

phase 1 addresses w05 and w06: ipc now requires credentials and an hmac tag. the
shared key is still a same-uid secret, so w05 is reduced but not eliminated and w06
records that integrity is not provenance. phase 2 addresses the health half of w18 and
partially addresses w15: ten sources are named with their state and one x86_64 host is
recorded in `docs/compatibility.md`. phase 3 addresses the registry half of w13 and the
visibility half of w14: detectors are described in one static registry with telemetry
needs, limits, cost and coverage state, and policy selects them by name; runtime module
loading and runtime proof remain out of scope. phase 4 partially addresses w01 with a
bounded `/proc` snapshot/delta collector, but that phase itself is not kernel push
telemetry and does not cover perf, tracepoints or bpf; its findings are observational for
guard because no syscall stop exists for an external pid. w19 records the poll and
sampling limits. phase 5 improves w08 with per-pid kernel and credential label windows,
but it remains per-pid and order-insensitive. it also reports the real enforcement
backend; phase 21 later adds optional lsm code, but w04 and w29 stay open because no
live hook is validated here and kernel compromise remains outside the protection
boundary. phase 6 addresses w08 with bounded cross-entity stage links and configurable
windows, but the graph still depends on supplied stage telemetry, normalized keys and
three linked classes. phase 7 partially addresses w11 with a bounded `AF_PACKET` and
frame-file backend, named capture state, bounded peer counters and a controlled frame
fixture. w20 keeps live capture unverified on this host, w21 records the unauthenticated
source mark, and w12 remains open because capture cannot deny or contain a peer. phase 8
replaces the fnv-only audit chain with hmac-sha256 while keeping legacy verification, and
adds a signed policy file with strict parsing and cli override. w07 is reduced but not
closed because the key is local and a key holder can recompute the chain; w17 remains
open because the loader shares one process with the engine. phase 9 partially addresses
w01 and w03 with a strict 4096-event `apk1` replay path and a named kernel source, but it
does not add a live collector. w22 records that replayed events are supplied input,
carry an internal mark and cannot be contained. phase 10 adds bounded `ap_update_v1`
integrity checking and staging with a local key; phase 16 adds local verified snapshots
and rollback under a private root, but it does not activate, replace privileged files or
establish a vendor key. w23 still records that trust and lifecycle gap. phase 11 reduces
w06 for byte-identical packets with a bounded 256-tag ring, but it adds no nonce and no
protection against a resealed forgery. phase 12 further reduces w24 with an opt-in
64-peer sequence check that drops stale nonzero values from an observed pid. phase 13
binds those peers to the `/proc` starttime when readable, so a changed epoch resets stale
sequence state; it is not process identity and does nothing when `/proc` is unreadable.
fresh higher sequences and per-client identity remain outside coverage. phase 14 makes
the proc map sample and w+x emission counts configurable within validated hard caps, so
w19 can be tuned at a measured read cost; it remains poll-based and cannot close the
short-lived pid gap. phase 15 ages binary, peer and privilege references with the entity
window, so stale text keys cannot keep linking fresh stages; it does not authenticate the
keys or close w08. phase 16 keeps verified releases in a private root and switches
unsigned local state. phase 17 stores the sealed manifest and local key in each release
and re-verifies the rollback target before the switch, so payload edits without that key
are rejected; a same-uid key holder can still forge or reseal proofs and edit state, so
w23 stays open and activation is still absent.

phases 18-20 map to these gaps: phase 18 adds the second local approval key and the
read-only plan for w23 and w25; phase 19 adds bounded per-client ipc key selection
for w24; phase 20 moves the audit write to a same-uid child for w26. w23, w24, w25
and w26 stay open: approval and plan are local and non-activating, per-client keys
keep the pid-reuse and same-uid caveats, and the audit child is not privilege
separation with durable queued state.

phases 21-23 add the current correlation stack without closing those trust gaps. phase 21
partly addresses w03 and w04 with a raw tracepoint and perf sensor plus an optional
bpf-lsm deny program, all integrated before self-hardening; it adds no kprobe backend,
cannot be live-validated on this host, and leaves w29 open. phase 22 adds the bounded
graph, evidence ledger and taxonomy bridge for w08, while w27 records the bounded
label alias set and w28 records that marks and keys are not authenticated. phase 23 adds the
beacon analyzer and c++ risk accumulator: rule 26 gains timing-based coverage and risk
findings reuse rule 16, while the separate rust per-pid risk still feeds guard. these are
heuristics over supplied observations, so benign periodic traffic, shared keys and
missing sensor labels can still produce false negatives or false positives.

phase 24 adds the bounded intrusion analyzer for rules 27-29 and explicit
process-memory labels from `c/trace.c`; w30 records that stage bits come from
supplied telemetry in fixed windows and cannot prove an injection, exploit or dump.
the rule set reached 29 descriptors at that phase, but no live coverage is added:
eBPF, perf, lsm and AF_PACKET remain unvalidated here at capability mask 7, lsm is
optional, and `kernel_compromise` stays `unprotected`. phase 25 adds sampled
`/proc/<pid>/io` deltas, file action labels, the bounded destructive analyzer for
rules 30-32 and an opt-in chain gate, but w31 records that file telemetry is
process-wide, sampled and not proof of attack. nonces, kernel-sealed identity, vendor
identity, secure activation, live kernel validation, kprobes, kernel-compromise
protection and true privilege separation remain unsupported.
