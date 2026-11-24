# kernel sensor

the kernel sensor is an opt-in low-level backend in `c/ksensor.c` for host telemetry
that cannot be observed from a supervised child, sealed ipc, or sampled `/proc`
alone. it uses raw `bpf()`, `perf_event_open()`, and lsm syscalls from c. no
external rust crate, libbpf, bpftool, or clang runtime is required at build time.
the c and c++ libraries, including `libapsys.a`, are built by `make` before cargo
builds the offline rust binary.

## flags and probing

- `--kernel-sensor` requests raw tracepoint attach and the perf ring collector.
- `--lsm-enforce` requests an optional bpf-lsm mac program.
- `--lsm-mask n` selects up to 32 local deny keys (accepted as hexadecimal or
  decimal by the policy parser).

`ap_ksensor_probe()` checks `bpf()` with `BPF_MAP_GET_NEXT_ID`, checks
`perf_event_open()` with a `PERF_COUNT_SW_BPF_OUTPUT` event, and looks for the
`bpf` token in `/sys/kernel/security/lsm`. the observed host capability mask is
7: seccomp, ptrace, and proc are available, while perf, tracepoints, bpf, and
`AF_PACKET` are not. no live eBPF, perf, or lsm attach can be validated locally,
so an active report on a capable host remains a design claim here, not a measured
result on this one.

none of the flags implies that the host grants the capability. the engine reports
`ksensor` and `lsm` by name as `active`, `unavailable`, or `disabled`. a failed
load produces an explicit degraded line with a lowercase reason and the probe
bits; the engine continues without treating the sensor as a working boundary.
`scripts/test_ksensor.sh` requires a requested sensor never to report `disabled`,
checks the degraded line when it is unavailable, and verifies the summary counters.

## why raw syscalls

the build must stay offline with no vendored dependencies. `c/ksensor.c` wraps
`bpf`, `perf_event_open`, `ioctl`, `mmap`, `munmap`, and `sched_getaffinity` through
raw syscall numbers and hand-encodes small eBPF programs with stable opcodes and
helper ids:

- `bpf_get_current_pid_tgid`
- `bpf_ktime_get_ns`
- `bpf_map_lookup_elem`
- `bpf_perf_event_output`

programs are capped at 32 instructions each. the tracepoint program builds a
48-byte `ap_ksample` on the eBPF stack: monotonic timestamp, pid/tgid, label id,
subkind, and three bounded arguments. it does not read arbitrary kernel memory
and does not parse process credentials in kernel context.

## maps, programs, and attach points

`ap_ksensor_open()` validates flags, re-probes capabilities, and creates two maps:
a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` sized to the discovered online cpus, capped at
`AP_KSENSOR_MAX_CPUS` (16), and a 32-key `BPF_MAP_TYPE_ARRAY` deny map. program
and link fd arrays are capped at 16. a hand-built `BPF_PROG_TYPE_RAW_TRACEPOINT`
program is loaded per attach point, then attached through
`BPF_RAW_TRACEPOINT_OPEN`.

the nine bounded attach points are `sched_process_exec`, `sched_process_exit`,
`bpf_prog_load`, `do_init_module`, `commit_creds`, `ptrace_access_check`,
`security_file_open`, `tty_write`, and `vfs_write`. each attach is independent.
failures increment an attach counter and leave a reason such as `some tracepoints
unavailable`; at least one successful attachment is required for `sensor_active`.
maps, programs, links, and perf fds are closed on failure or at `ap_ksensor_close()`.

## perf ring and event conversion

a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` is populated with one bounded mmap ring per
available cpu, capped at 16 cpus and `AP_KSENSOR_RING_PAGES` (64) pages per ring,
by `perf_event_open()` plus raw `mmap`. parent polling is nonblocking, handles at
most `AP_KSENSOR_MAX_EVENTS` (256) samples per call, copies only complete
`PERF_RECORD_SAMPLE` records with a valid 48-byte payload, validates the label id,
and advances `data_tail` with release semantics after an acquire load of
`data_head`. invalid or truncated records and lost ring bytes are counted rather
than dispatched.

`ap_ksensor_sample_to_event()` converts each sample to a standard 216-byte
`ap_event` with `AP_KIND_KERNEL`, split pid/tid, the sample timestamp and
arguments, severity from the label, confidence of 900 or 950, and source mark 3
(`AP_KSENSOR_SOURCE_MARK`). rust normalizes that mark to source `"ksensor"`; replay
mark 2 is a different path and deliberately keeps prior flow behavior. the
canonical `kernel_rootkit` and `cred_change` strings are used directly; `ptrace`
is an accepted alias for the canonical `ptrace_access` taxonomy label. labels are
internal observations, not authenticated sensor identities; see
`docs/detection/taxonomy.md`.

## bpf lsm

`--lsm-enforce` attempts a `BPF_PROG_TYPE_LSM` program attached at `BPF_LSM_MAC`.
the deny map is a local 32-key bitmap configured by `--lsm-mask`; the program
returns `-EPERM` for a configured key and allows otherwise. `ap_ksensor_lsm_set_mask()`
updates the bitmap while the handle is open. `lsm_denies` counts installed deny
rules, not runtime LSM rejections, and the enforcement report publishes the count
alongside `lsm_active`.

if program load or attach fails, the telemetry sensor can stay active while the
engine reports `lsm` as unavailable, increments `lsm_attach_failures`, and emits a
degraded line. lsm policy is not kernel compromise protection: a compromised
kernel can bypass both the loader and the enforcement hook. the enforcement status
keeps `kernel_compromise` as `"unprotected"` even when `lsm` is active.

## counters, status, and tests

`ap_ksensor_counters()` reports probes, maps, programs, attached, events, invalid,
dropped, `lsm_loaded`, `lsm_denies`, and `lsm_attach_failures`.
`ap_ksensor_status()` reports bpf/perf/lsm availability, `sensor_active`,
`lsm_active`, attached count, cpu count, and a bounded lowercase reason string.
the engine publishes `ksensor_events`, `ksensor_invalid`, `ksensor_dropped`,
`ksensor_attached`, `lsm_active`, and `lsm_denies` in the final summary.

`tests/test_ksensor.c` covers probe booleans, unprivileged failure with a
lowercase reason, sample conversion, label bounds, and null safety.
`scripts/test_ksensor.sh` checks source states, degraded lines, and counters end
to end. `test_taxonomy`, `test_graph`, `test_evidence`, `test_beacon`, and
`test_risk` cover the bounded consumers wired through
`rust/src/correlation.rs`. because the host mask is 7, none of these tests
validates a live eBPF program, perf ring, or lsm deny in this environment.

## ordering

self-hardening seccomp denies `bpf()`. the kernel sensor must be opened and its
maps, programs, rings, and lsm hooks installed **before** `ap_sys_self_harden()`
runs. this ordering is enforced in the engine startup path in `rust/src/engine.rs`,
which opens the sensor before the hardening call and then reports status and
degradation lines.
