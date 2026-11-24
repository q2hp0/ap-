use crate::abi::{Event, Verdict};
use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureCounters {
    pub frames: u64,
    pub parsed: u64,
    pub invalid: u64,
    pub truncated: u64,
    pub errors: u64,
}

#[repr(C)]
pub struct Sha256 {
    pub state: [u32; 8],
    pub bits: u64,
    pub block: [u8; 64],
    pub used: usize,
}

pub const REPLAY_SLOTS: usize = 256;
pub const SEQUENCE_SLOTS: usize = 64;
pub const CLIENT_KEY_MAX: usize = 16;
pub const AUDIT_MAX_FRAME: usize = 4096;
pub const AUDIT_MAX_PAYLOAD: usize = 4092;
pub const WNOHANG: c_int = 1;
pub const SIGTERM: c_int = 15;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ClientKeys {
    pub pids: [u32; CLIENT_KEY_MAX],
    pub keys: [[u8; 32]; CLIENT_KEY_MAX],
    pub count: u32,
    pub matched: u64,
    pub unmatched: u64,
}

impl Default for ClientKeys {
    fn default() -> Self {
        Self {
            pids: [0u32; CLIENT_KEY_MAX],
            keys: [[0u8; 32]; CLIENT_KEY_MAX],
            count: 0,
            matched: 0,
            unmatched: 0,
        }
    }
}

#[repr(C)]
pub struct Replay {
    pub tags: [[u8; 32]; REPLAY_SLOTS],
    pub used: [u8; REPLAY_SLOTS],
    pub next: u32,
    pub count: u32,
    pub accepted: u64,
    pub duplicates: u64,
    pub peer_pid: [u32; SEQUENCE_SLOTS],
    pub peer_epoch: [u64; SEQUENCE_SLOTS],
    pub peer_next: u32,
    pub peer_count: u32,
    pub peer_seq: [u64; SEQUENCE_SLOTS],
    pub peer_used: [u8; SEQUENCE_SLOTS],
    pub sequences: u64,
    pub sequence_drops: u64,
    pub peer_evictions: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelCounters {
    pub frames: u64,
    pub parsed: u64,
    pub invalid: u64,
    pub errors: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KSample {
    pub ts_ns: u64,
    pub pid_tgid: u64,
    pub label_id: u32,
    pub subkind: u32,
    pub arg: [u64; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KSensorCounters {
    pub probes: u64,
    pub maps: u64,
    pub programs: u64,
    pub attached: u64,
    pub events: u64,
    pub invalid: u64,
    pub dropped: u64,
    pub lsm_loaded: u64,
    pub lsm_denies: u64,
    pub lsm_attach_failures: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KSensorStatus {
    pub bpf_available: u32,
    pub perf_available: u32,
    pub lsm_available: u32,
    pub sensor_active: u32,
    pub lsm_active: u32,
    pub attached: u32,
    pub cpus: u32,
    pub reason: [c_char; KSENSOR_REASON_LEN],
}

impl Default for KSensorStatus {
    fn default() -> Self {
        Self {
            bpf_available: 0,
            perf_available: 0,
            lsm_available: 0,
            sensor_active: 0,
            lsm_active: 0,
            attached: 0,
            cpus: 0,
            reason: [0 as c_char; KSENSOR_REASON_LEN],
        }
    }
}

#[repr(C)]
pub struct TraceConfig {
    pub argv: *const *const c_char,
    pub argc: u32,
    pub flags: u32,
    pub mask: u32,
    pub max_events: u32,
}

#[repr(C)]
pub struct PollFd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

pub const POLLIN: i16 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetCounters {
    pub packets: u64,
    pub findings: u64,
    pub states: u64,
    pub fragments: u64,
    pub invalid: u64,
    pub evictions: u64,
    pub peers: u64,
    pub peer_events: u64,
    pub peer_evictions: u64,
    pub peer_bursts: u64,
    pub peer_exhaustion: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowCounters {
    pub events: u64,
    pub findings: u64,
    pub ranges: u64,
    pub stacks: u64,
    pub evictions: u64,
    pub entity_events: u64,
    pub entity_findings: u64,
    pub entity_evictions: u64,
    pub entity_refs_expired: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IntrusionCounters {
    pub added: u64,
    pub evicted: u64,
    pub findings: u64,
    pub suppressed: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DestructiveCounters {
    pub added: u64,
    pub evicted: u64,
    pub findings: u64,
    pub suppressed: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CollectorCounters {
    pub scans: u64,
    pub pids_seen: u64,
    pub starts: u64,
    pub exits: u64,
    pub execs: u64,
    pub priv_changes: u64,
    pub wx_regions: u64,
    pub file_events: u64,
    pub file_samples: u64,
    pub file_errors: u64,
    pub evictions: u64,
    pub errors: u64,
}

pub const CAP_SECCOMP: u32 = 1;
pub const CAP_PTRACE: u32 = 2;
pub const CAP_PROC: u32 = 4;
pub const CAP_PERF: u32 = 8;
pub const CAP_TRACEPOINT: u32 = 16;
pub const CAP_BPF: u32 = 32;
pub const CAP_NETWORK: u32 = 64;

pub const SOURCE_TRACE: u32 = 1;
pub const SOURCE_IPC: u32 = 2;
pub const SOURCE_PROC: u32 = 3;
pub const SOURCE_PERF: u32 = 4;
pub const SOURCE_TRACEPOINT: u32 = 5;
pub const SOURCE_BPF: u32 = 6;
pub const SOURCE_CAPTURE: u32 = 7;
pub const SOURCE_KERNEL: u32 = 8;
pub const SOURCE_KSENSOR: u32 = 9;
pub const SOURCE_LSM: u32 = 10;
pub const SOURCE_COUNT: u32 = 10;

pub const CAPTURE_SOURCE_MARK: u64 = 1;
pub const KERNEL_SOURCE_MARK: u64 = 2;
pub const KSENSOR_SOURCE_MARK: u64 = 3;
pub const KERNEL_MAX_EVENTS: u32 = 4096;

pub const KSENSOR_FLAG_RAW_TRACEPOINTS: u32 = 1;
pub const KSENSOR_FLAG_PERF_RING: u32 = 2;
pub const KSENSOR_FLAG_LSM: u32 = 4;
pub const KSENSOR_MAX_CPUS: u32 = 16;
pub const KSENSOR_RING_PAGES: u32 = 64;
pub const KSENSOR_MAX_EVENTS: u32 = 256;
pub const KSENSOR_REASON_LEN: usize = 128;
pub const CAPTURE_MAX_FRAMES: u32 = 16;
pub const CAPTURE_SNAP_MIN: u32 = 20;
pub const CAPTURE_SNAP_MAX: u32 = 63;
pub const CAPTURE_DEFAULT_SNAP: u32 = 63;

pub const COLLECTOR_DEFAULT_MAPS_PER_SCAN: u32 = 8;
pub const COLLECTOR_MAX_MAPS_PER_SCAN: u32 = 32;
pub const COLLECTOR_DEFAULT_WX_PER_SCAN: u32 = 4;
pub const COLLECTOR_MAX_WX_PER_SCAN: u32 = 16;
pub const COLLECTOR_DEFAULT_IO_PER_SCAN: u32 = 8;
pub const COLLECTOR_MAX_IO_PER_SCAN: u32 = 32;

#[repr(C)]
pub struct CapDesc {
    pub id: u32,
    pub name: *const c_char,
    pub available: c_int,
}

#[repr(C)]
pub struct SourceDesc {
    pub id: u32,
    pub name: *const c_char,
    pub cap: u32,
}

pub const GRAPH_MAX_NODES: usize = 128;
pub const GRAPH_MAX_EDGES: usize = 256;
pub const GRAPH_MAX_CHAINS: usize = 32;
pub const GRAPH_KEY_LEN: usize = 64;
pub const EVIDENCE_SLOTS: usize = 256;
pub const EVIDENCE_KEY_LEN: usize = 64;
pub const BEACON_KEY_LEN: usize = 48;
pub const RISK_KEY_LEN: usize = 48;
pub const CORRELATION_RESULTS: usize = 8;

pub const LABEL_ROOTKIT: u32 = 8;
pub const TACTIC_EXECUTION: u32 = 2;
pub const TACTIC_PERSISTENCE: u32 = 3;
pub const TACTIC_PRIVILEGE_ESCALATION: u32 = 4;
pub const TACTIC_DEFENSE_EVASION: u32 = 5;
pub const TACTIC_CREDENTIAL_ACCESS: u32 = 6;
pub const TACTIC_DISCOVERY: u32 = 7;
pub const TACTIC_LATERAL_MOVEMENT: u32 = 8;
pub const TACTIC_COMMAND_AND_CONTROL: u32 = 10;
pub const TACTIC_EXFILTRATION: u32 = 11;
pub const TACTIC_IMPACT: u32 = 12;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GraphObservation {
    pub ts_ns: u64,
    pub pid: i64,
    pub tactic: u32,
    pub label_id: u32,
    pub confidence_x1000: u32,
    pub key: [u8; GRAPH_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GraphFinding {
    pub ts_ns: u64,
    pub pid: i64,
    pub tactics: u32,
    pub confidence_x1000: u32,
    pub nodes: u32,
    pub key: [u8; GRAPH_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GraphNode {
    pub ts_ns: u64,
    pub pid: i64,
    pub tactic: u32,
    pub label_id: u32,
    pub confidence_x1000: u32,
    pub used: u32,
    pub key: [u8; GRAPH_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GraphEdge {
    pub from: u32,
    pub to: u32,
    pub used: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GraphChain {
    pub last_ns: u64,
    pub used: u32,
    pub key: [u8; GRAPH_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Graph {
    pub nodes: [GraphNode; GRAPH_MAX_NODES],
    pub edges: [GraphEdge; GRAPH_MAX_EDGES],
    pub chains: [GraphChain; GRAPH_MAX_CHAINS],
    pub node_cursor: u64,
    pub edge_cursor: u64,
    pub chain_cursor: u64,
    pub added: u64,
    pub evicted: u64,
    pub findings: u64,
    pub suppressed: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EvidenceRecord {
    pub ts_ns: u64,
    pub hash: u64,
    pub pid: i64,
    pub rule: u32,
    pub confidence_x1000: u32,
    pub used: u32,
    pub key: [u8; EVIDENCE_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Evidence {
    pub records: [EvidenceRecord; EVIDENCE_SLOTS],
    pub cursor: u64,
    pub inserted: u64,
    pub duplicates: u64,
    pub evicted: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BeaconObservation {
    pub ts_ns: u64,
    pub peer: [u8; BEACON_KEY_LEN],
    pub bytes_out: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BeaconFinding {
    pub ts_ns: u64,
    pub span_ns: u64,
    pub jitter_ns: u64,
    pub connections: u32,
    pub bytes_out: u32,
    pub score_x1000: u32,
    pub peer: [u8; BEACON_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RiskSignal {
    pub ts_ns: u64,
    pub rule: u32,
    pub tactic: u32,
    pub confidence_x1000: u32,
    pub key: [u8; RISK_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RiskFinding {
    pub ts_ns: u64,
    pub score_x1000: u32,
    pub signals: u32,
    pub tactics: u32,
    pub high_rules: u32,
    pub key: [u8; RISK_KEY_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TaxonomyEntry {
    pub label_id: u32,
    pub rule_id: u32,
    pub tactic: u32,
    pub confidence_x1000: u32,
    pub name: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CorrelationResults {
    pub graph: [GraphFinding; CORRELATION_RESULTS],
    pub graph_count: u32,
    pub beacon: [BeaconFinding; CORRELATION_RESULTS],
    pub beacon_count: u32,
    pub risk: [RiskFinding; CORRELATION_RESULTS],
    pub risk_count: u32,
}

impl Default for CorrelationResults {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

pub type RegionCallback = extern "C" fn(*const Event, *mut c_void) -> c_int;
pub type CollectorCallback = extern "C" fn(*const Event, *mut c_void) -> c_int;
pub type TraceCallback = extern "C" fn(*const Event, *mut Verdict, *mut c_void) -> c_int;
pub type CaptureCallback = extern "C" fn(*const Event, *mut c_void) -> c_int;
pub type KernelCallback = extern "C" fn(*const Event, *mut c_void) -> c_int;
pub type KSensorCallback = extern "C" fn(*const Event, *mut Verdict, *mut c_void) -> c_int;
pub type GraphCallback = extern "C" fn(*const GraphFinding, *mut c_void) -> c_int;
pub type BeaconCallback = extern "C" fn(*const BeaconFinding, *mut c_void) -> c_int;
pub type RiskCallback = extern "C" fn(*const RiskFinding, *mut c_void) -> c_int;

extern "C" {
    pub fn ap_clock_ns() -> u64;
    pub fn ap_kind_name(kind: u16) -> *const c_char;
    pub fn ap_sys_init() -> c_int;
    pub fn ap_sys_self_harden() -> c_int;
    pub fn ap_sys_capability_state() -> c_int;
    pub fn ap_cap_probe() -> u32;
    pub fn ap_cap_count() -> u32;
    pub fn ap_cap_report(index: u32, desc: *mut CapDesc) -> c_int;
    pub fn ap_source_describe(index: u32, desc: *mut SourceDesc) -> c_int;
    pub fn ap_collector_new(max_pids: u32) -> *mut c_void;
    pub fn ap_collector_set_map_limits(collector: *mut c_void, map_samples: u32,
                                       wx_per_scan: u32) -> c_int;
    pub fn ap_collector_set_io_per_scan(collector: *mut c_void, io_per_scan: u32) -> c_int;
    pub fn ap_collector_io_per_scan(collector: *const c_void, io_per_scan: *mut u32) -> c_int;
    pub fn ap_collector_free(collector: *mut c_void);
    pub fn ap_collector_scan(collector: *mut c_void, now_ns: u64,
                             callback: CollectorCallback, user: *mut c_void) -> c_int;
    pub fn ap_collector_stats(collector: *const c_void,
                              out: *mut CollectorCounters) -> c_int;
    pub fn ap_sys_read_maps(pid: c_int, callback: RegionCallback, user: *mut c_void) -> c_int;
    pub fn ap_sys_proc_uid(pid: c_int, uid: *mut u32, euid: *mut u32) -> c_int;
    pub fn ap_sys_proc_comm(pid: c_int, out: *mut c_char, len: usize) -> c_int;
    pub fn ap_sys_server_open(path: *const c_char, fd: *mut c_int) -> c_int;
    pub fn ap_sys_client_open(path: *const c_char, fd: *mut c_int) -> c_int;
    pub fn ap_transport_key_create(path: *const c_char, key: *mut u8) -> c_int;
    pub fn ap_transport_key_create_path(path: *const c_char, key: *mut u8) -> c_int;
    pub fn ap_transport_key_load(path: *const c_char, key: *mut u8) -> c_int;
    pub fn ap_transport_key_load_path(path: *const c_char, key: *mut u8) -> c_int;
    pub fn ap_client_keys_init(keys: *mut ClientKeys) -> c_int;
    pub fn ap_client_keys_add(keys: *mut ClientKeys, pid: u32, key: *const u8) -> c_int;
    pub fn ap_sha256_init(ctx: *mut Sha256);
    pub fn ap_sha256_update(ctx: *mut Sha256, data: *const u8, len: usize);
    pub fn ap_sha256_final(ctx: *mut Sha256, out: *mut u8);
    pub fn ap_hmac_sha256(key: *const u8, key_len: usize, data: *const u8,
                          data_len: usize, out: *mut u8);
    pub fn ap_constant_time_eq(a: *const u8, b: *const u8, len: usize) -> c_int;
    pub fn ap_sys_send_sealed(fd: c_int, key: *const u8, event: *const Event) -> c_int;
    pub fn ap_sys_recv_sealed(fd: c_int, key: *const u8, data: *mut c_void, cap: usize,
                              received: *mut usize) -> c_int;
    pub fn ap_sys_recv_sealed_filtered(fd: c_int, key: *const u8, data: *mut c_void, cap: usize,
                                       received: *mut usize, replay: *mut Replay) -> c_int;
    pub fn ap_sys_recv_sealed_sequenced(fd: c_int, key: *const u8, data: *mut c_void, cap: usize,
                                        received: *mut usize, replay: *mut Replay) -> c_int;
    pub fn ap_sys_recv_sealed_client(fd: c_int, client_keys: *mut ClientKeys, data: *mut c_void,
                                     cap: usize, received: *mut usize, replay: *mut Replay,
                                     strict: c_int) -> c_int;
    pub fn ap_replay_init(replay: *mut Replay);
    pub fn ap_sys_write_all(fd: c_int, data: *const c_void, len: usize) -> c_int;
    pub fn ap_audit_writer_spawn(store: *const c_char, key: *const c_char,
                                  write_fd: *mut c_int, child_pid: *mut c_int) -> c_int;
    pub fn ap_audit_send(fd: c_int, data: *const u8, len: usize) -> c_int;
    pub fn ap_audit_recv(fd: c_int, data: *mut u8, cap: usize, len: *mut usize) -> c_int;

    pub fn ap_trace_run(config: *const TraceConfig, callback: TraceCallback, user: *mut c_void) -> c_int;

    pub fn ap_capture_open_iface(ifname: *const c_char, snaplen: u32) -> *mut c_void;
    pub fn ap_capture_open_file(path: *const c_char, snaplen: u32) -> *mut c_void;
    pub fn ap_capture_free(capture: *mut c_void);
    pub fn ap_capture_fd(capture: *const c_void) -> c_int;
    pub fn ap_capture_poll(capture: *mut c_void, max_frames: u32,
                           callback: CaptureCallback, user: *mut c_void,
                           timeout_ms: c_int) -> c_int;
    pub fn ap_capture_stats(capture: *const c_void, counters: *mut CaptureCounters) -> c_int;

    pub fn ap_kernel_open_file(path: *const c_char) -> *mut c_void;
    pub fn ap_kernel_free(kernel: *mut c_void);
    pub fn ap_kernel_pending(kernel: *const c_void) -> u32;
    pub fn ap_kernel_poll(kernel: *mut c_void, max_events: u32,
                          callback: KernelCallback, user: *mut c_void) -> c_int;
    pub fn ap_kernel_stats(kernel: *const c_void, counters: *mut KernelCounters) -> c_int;

    pub fn ap_ksensor_probe(bpf_ok: *mut u32, perf_ok: *mut u32, lsm_ok: *mut u32) -> c_int;
    pub fn ap_ksensor_open(flags: u32, lsm_mask: u32, out: *mut *mut c_void,
                           reason: *mut c_char, reason_len: usize) -> c_int;
    pub fn ap_ksensor_poll(handle: *mut c_void, max_events: u32,
                           callback: KSensorCallback, user: *mut c_void) -> c_int;
    pub fn ap_ksensor_lsm_set_mask(handle: *mut c_void, mask: u32) -> c_int;
    pub fn ap_ksensor_counters(handle: *const c_void, out: *mut KSensorCounters);
    pub fn ap_ksensor_status(handle: *const c_void, out: *mut KSensorStatus);
    pub fn ap_ksensor_close(handle: *mut c_void);
    pub fn ap_ksensor_sample_to_event(sample: *const KSample, event: *mut Event) -> c_int;
    pub fn ap_ksensor_label_name(label_id: u32) -> *const c_char;

    pub fn ap_graph_init(graph: *mut Graph);
    pub fn ap_graph_add(graph: *mut Graph, observation: *const GraphObservation) -> c_int;
    pub fn ap_graph_evaluate(graph: *mut Graph, now_ns: u64, callback: GraphCallback,
                             user: *mut c_void) -> c_int;
    pub fn ap_graph_tactic_name(tactic: u32) -> *const c_char;
    pub fn ap_graph_stats(graph: *const Graph, added: *mut u64, evicted: *mut u64,
                          findings: *mut u64, suppressed: *mut u64);

    pub fn ap_evidence_init(ledger: *mut Evidence);
    pub fn ap_evidence_add(ledger: *mut Evidence, ts_ns: u64, pid: i64, rule: u32,
                           confidence_x1000: u32, key: *const c_char) -> c_int;
    pub fn ap_evidence_add_once(ledger: *mut Evidence, ts_ns: u64, pid: i64, rule: u32,
                                confidence_x1000: u32, key: *const c_char) -> c_int;
    pub fn ap_evidence_is_duplicate(ledger: *const Evidence, now_ns: u64, rule: u32,
                                    key: *const c_char) -> c_int;
    pub fn ap_evidence_stats(ledger: *const Evidence, inserted: *mut u64,
                             duplicates: *mut u64, evicted: *mut u64);

    pub fn ap_taxonomy_find(label_id: u32) -> *const TaxonomyEntry;
    pub fn ap_taxonomy_find_name(name: *const c_char) -> *const TaxonomyEntry;
    pub fn ap_taxonomy_count() -> u32;
    pub fn ap_taxonomy_rule(label_id: u32) -> u32;
    pub fn ap_taxonomy_tactic(label_id: u32) -> u32;
    pub fn ap_taxonomy_confidence(label_id: u32) -> u32;
    pub fn ap_taxonomy_name(label_id: u32) -> *const c_char;

    pub fn ap_beacon_new() -> *mut c_void;
    pub fn ap_beacon_free(handle: *mut c_void);
    pub fn ap_beacon_add(handle: *mut c_void, observation: *const BeaconObservation) -> c_int;
    pub fn ap_beacon_evaluate(handle: *mut c_void, now_ns: u64, callback: BeaconCallback,
                              user: *mut c_void) -> c_int;
    pub fn ap_beacon_reset(handle: *mut c_void);

    pub fn ap_risk_new() -> *mut c_void;
    pub fn ap_risk_free(handle: *mut c_void);
    pub fn ap_risk_add(handle: *mut c_void, signal: *const RiskSignal) -> c_int;
    pub fn ap_risk_evaluate(handle: *mut c_void, now_ns: u64, callback: RiskCallback,
                            user: *mut c_void) -> c_int;
    pub fn ap_risk_reset(handle: *mut c_void);

    pub fn ap_net_new() -> *mut c_void;
    pub fn ap_net_free(handle: *mut c_void);
    pub fn ap_net_feed(handle: *mut c_void, event: *const Event, verdict: *mut Verdict) -> c_int;
    pub fn ap_net_stats(handle: *const c_void, counters: *mut NetCounters) -> c_int;
    pub fn ap_net_reset(handle: *mut c_void) -> c_int;

    pub fn ap_flow_new() -> *mut c_void;
    pub fn ap_flow_free(handle: *mut c_void);
    pub fn ap_flow_feed(handle: *mut c_void, event: *const Event, verdict: *mut Verdict) -> c_int;
    pub fn ap_flow_stats(handle: *const c_void, counters: *mut FlowCounters) -> c_int;
    pub fn ap_flow_reset(handle: *mut c_void) -> c_int;
    pub fn ap_flow_set_window_ms(handle: *mut c_void, window_ms: u32) -> c_int;

    pub fn ap_intrusion_new() -> *mut c_void;
    pub fn ap_intrusion_free(handle: *mut c_void);
    pub fn ap_intrusion_feed(handle: *mut c_void, event: *const Event, verdict: *mut Verdict) -> c_int;
    pub fn ap_intrusion_stats(handle: *const c_void, counters: *mut IntrusionCounters) -> c_int;
    pub fn ap_intrusion_reset(handle: *mut c_void);

    pub fn ap_destructive_new() -> *mut c_void;
    pub fn ap_destructive_free(handle: *mut c_void);
    pub fn ap_destructive_feed(handle: *mut c_void, event: *const Event, verdict: *mut Verdict) -> c_int;
    pub fn ap_destructive_stats(handle: *const c_void, counters: *mut DestructiveCounters) -> c_int;
    pub fn ap_destructive_reset(handle: *mut c_void);

    pub fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn signal(signum: c_int, handler: usize) -> usize;
    pub fn getpid() -> c_int;
    pub fn geteuid() -> u32;
    pub fn kill(pid: c_int, sig: c_int) -> c_int;
    pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
}
