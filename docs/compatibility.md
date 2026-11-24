# compatibility

this matrix records configurations actually exercised on the development host.
it is not a claim of universal linux support.

| item | observed |
| --- | --- |
| kernel | `linux 6.12.111+deb13-amd64` |
| architecture | `x86_64` |
| cpus | 12 |
| build | `make` with `gcc`, `g++`, `cargo --offline`; `out/apgui` links system `libX11` only |
| validation | `make check`, `make asan`, `make bench`, including `test_kernel_chain.sh`, `test_entity_chain.sh`, `test_capture.sh`, `test_kernel.sh`, `test_ksensor.sh`, `test_correlation.sh`, `test_intrusion.sh`, `test_destructive.sh`, `test_update.sh`, `test_audit_process.sh`, `test_replay.sh`, `test_sequence.sh`, `test_store.sh` and `test_policy.sh`; 136 rust tests plus the c/c++ graph, taxonomy, evidence, beacon, risk, ksensor, intrusion, destructive and mini-gui parser units |
| capability mask | `7` |
| mini gui | raw X11 on `DISPLAY=:1`, no toolkit; only the parser is unit-tested, the window is exercised manually |

## capability interpretation

| bit | source | observed | note |
| --- | --- | --- | --- |
| 1 | `seccomp` | available | self-hardening filter installs outside trace mode |
| 2 | `ptrace` | available | supervised child and `kernel_probe` tests pass |
| 4 | `proc_maps` | available | bounded snapshot collector with configurable map limits, exercised by `test_collector` and `test_proc.sh` |
| 8 | `perf` | unavailable | `perf_event_open` denied on this host |
| 16 | `tracepoints` | unavailable | tracing interface unreadable |
| 32 | `bpf` | unavailable | bpf syscall denied or unavailable; no `CAP_BPF` |
| 64 | `packet_capture` | unavailable | raw `AF_PACKET` socket open denied; frame-file mode is used instead |

unavailable sources are reported by name in the `sources` status line. the `proc`
source runs the bounded snapshot collector described in `docs/interfaces.md`; map reads
and w+x emissions are validated at 1-32 and 1-16 with defaults of 8 and 4. the optional
raw kernel sensor can make `perf`, `tracepoints` and `bpf` report `active` with the reason
`kernel sensor raw tracepoint/perf ring` when it opens, even though the capability bits
stay zero. without the sensor they remain `unavailable` or `degraded`.

the detector registry has 32 static descriptors and all are enabled by default;
`--disable` of one yields 31 and `--enable all` expands to 32. rule ids are 1..32 with
`AP_RULE_MAX` and rust `RULE_MAX` at 32. the source registry has ten entries, with
`ksensor` at id `9` and `lsm` at id `10`. c and rust layout tests check those bounds.
`make check` runs 22 shell suites, including `test_intrusion.sh` and
`test_destructive.sh`; `test_sanitizers.sh` brings the total `test_*.sh` count to 23.

the bounded c++ intrusion analyzer is exercised by `tests/test_intrusion.cpp` and
`scripts/test_intrusion.sh`, which check exact store findings for rules 27-29 and a
quiet single-signal case. the bounded c++ destructive analyzer is exercised by
`tests/test_destructive.cpp`, `tests/fuzz_analyzers.cpp` and `scripts/test_destructive.sh`,
which check rules 30-32, exact detail prefixes, bounded counters and a benign case using
injected process-wide io deltas and file action events. `tests/kernel_probe.c` touches
`process_vm_readv`, which is now watched and mapped by `cpp/flow.cpp` with the other
explicit labels to the existing `kernel_iface_bit`. these are offline correlation
fixtures, not live kernel or exploit validation.

the mini gui parser is exercised by `tests/test_gui.cpp` with startup, shutdown, event,
degraded and summary objects. the X11 window itself is not unit-tested; it is verified by
opening `out/apgui` on the development display and checking that raw json never reaches
the black area.

the capture backend compiles into `libapsys.a` on this host, but live interface mode
fails at `AF_PACKET` open and reports the `capture` source as `unavailable` with a
reason. `scripts/test_capture.sh` validates the same event path using a length-prefixed
frame file, not a live packet socket. this distinction is intentional; no live capture
coverage is claimed here.

the kernel replay backend compiles into `libapsys.a` and needs no special capability.
`scripts/test_kernel.sh` validates a strict `apk1` file, counters, source marking,
explained findings and missing-file degradation. it does not validate live `perf`,
tracepoint or bpf collection, and those sources remain unavailable on this host.

the raw kernel sensor in `c/ksensor.c` compiles into `libapsys.a` but needs raw bpf and
perf access at runtime. it loads hand-encoded ebpf programs on raw tracepoints, reads
bounded per-cpu perf rings and can attach a narrow `BPF_LSM_MAC` deny hook. this host
has mask `7`, so those operations fail; `--kernel-sensor` and `--lsm-enforce` emit
degraded lines and continue. `scripts/test_ksensor.sh` checks the requested source
states, reasons, `--lsm-mask` parsing and summary counters, including unprivileged
failure. it does not validate live ebpf, perf or lsm behavior. `scripts/test_correlation.sh`
checks that bounded graph, evidence, beacon and risk counters appear and that store
verification still succeeds. neither script proves sensor truth or finding quality.

the ipc replay filter is a fixed 256-tag ring in `c/replay.c` called after hmac
verification. it needs no kernel capability or allocation and is covered by `test_replay`
and `scripts/test_replay.sh`. the test injects byte-identical packets through a fresh
socket; it does not alter and reseal them, so it does not claim per-client identity or
full replay protection.

`--ipc-strict-seq` adds a 64-peer sequence table to the same filter using the pid already
present in `SCM_CREDENTIALS`; it needs no new capability, packet byte or allocation. each
slot also records the pid's `/proc` starttime when readable and resets stale sequence state
if that epoch changes. `test_replay` covers stale sequences, zero handling, peer eviction
and a simulated epoch change, and `scripts/test_sequence.sh` checks the opt-in path through
the engine summary. it does not claim process identity, detection when `/proc` is
unavailable or protection against higher-sequence forgeries.

`--client-key pid:path` adds up to 16 exact 32-byte `0600` regular key files, loaded
by exact path and selected from the `SCM_CREDENTIALS` pid by the existing hmac path.
packet bytes are unchanged, and mapped and unmapped pids are counted in
`ipc_client_key_matches` and `ipc_client_key_misses`. the rust tests cover
layout, pid selection, unmapped-pid counting and the table bound. no new
capability is needed. the pid is not durable identity: reuse remains a caveat,
and a same-uid reader of any key can forge or reseal packets. this is not a
nonce or full replay protection.

the update integrity path is a one-shot rust CLI mode over the existing c sha-256 and
hmac primitives. it needs no kernel capability and uses the same 0600 local key model as
audit and policy. `scripts/test_update.sh` uses `sha256sum` to prepare payload hashes,
then validates sealing, verification, staging, tamper detection, unsafe paths, reserved
names, symlinks and missing payloads on this host. it also installs two private-root
releases, checks stored proof and active and previous state, rejects a tampered rollback
target, rolls back and rejects a group-writable root. it does not validate activation,
privileged replacement or a vendor signing key.

`--require-approval` adds a second local `0600` key at the exact
`<manifest>.approval.key` path (no extra `.key`) and an `approval=` line with
64 lowercase hex digits before `mac=` under the `ap_update_approval_v1\n`
domain. the manifest mac covers that line; verification checks approval whenever
present, and the flag requires it. release proof copying stores
`manifest.approval.key` at `0600`, and
that name is reserved in bundles. `--activation-plan root [--require-approval]`
is a read-only one-shot mode that checks the private root, active proof, an
optional previous release and approval, then prints a plan with `executed: false`.
`scripts/test_update.sh` exercises sealed, missing and tampered approval, install,
rollback and the plan on this host. this needs no kernel capability and
proves possession of local keys, not a vendor signature, second human or process
identity.

`--audit-process [--audit-key path]` starts a same-uid writer child from
`/proc/self/exe` over an `O_CLOEXEC` pipe with 4-byte little-endian frames
(`AP_AUDIT_MAX_FRAME=4096`, `AP_AUDIT_MAX_PAYLOAD=4092`). the internal
`--audit-writer store key` mode is not a normal user mode. no kernel capability
is needed. `scripts/test_audit_process.sh` checks process status, the exact
`0600` key path, custom-key verification with `--verify-store --audit-key`,
tamper rejection and degraded fallback when the writer cannot start. summary
queued counts are pipe frames, not durable store writes. `test_audit` checks the
exact key path and framing bounds on this host. same-uid code can still tamper
with the child, key, pipe or store; this is not privilege separation.

untested: arm64, other distributions, older kernels, hardened container policies,
systems where ptrace or seccomp are denied, systems where raw packet capture is
permitted, hosts with `CAP_BPF` and usable perf, tracepoint, raw-sensor or bpf lsm
collection, and kernel versions with different tracepoint or lsm layout. those
configurations must be measured before deployment.
