use crate::abi::*;
use crate::audit::{Writer, WriterStatus};
use crate::capture::Capture;
use crate::cli::{escape, timestamp, Cli};
use crate::collector::ProcCollector;
use crate::correlation::Correlation;
use crate::detection::DetectorRegistry;
use crate::detect::{detect_with_registry, Analyzers};
use crate::event::{normalize, rule_name, Finding};
use crate::ffi;
use crate::guard::{enforcement_report, Guard};
use crate::ipc::Ipc;
use crate::kernel::Kernel;
use crate::ksensor::KSensor;
use crate::policy::Policy;
use crate::risk::Risk;
use crate::source::SourceRegistry;
use crate::store::Store;
use std::ffi::{c_int, c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

#[derive(Clone, Copy, Debug)]
struct Decision {
    code: i32,
    rule: u32,
}

enum Envelope {
    Telemetry(Event),
    TraceRequest {
        event: Event,
        ack: SyncSender<Decision>,
    },
    TraceDone(i32),
    KernelDone,
}

struct TraceContext {
    tx: SyncSender<Envelope>,
}

struct KernelContext {
    tx: SyncSender<Envelope>,
    stop: Arc<AtomicBool>,
}

struct CollectorContext<'a> {
    tx: &'a SyncSender<Envelope>,
    drops: &'a AtomicU64,
}

struct CaptureContext {
    tx: SyncSender<Envelope>,
    drops: Arc<AtomicU64>,
}

struct KSensorContext {
    tx: SyncSender<Envelope>,
    drops: Arc<AtomicU64>,
}

extern "C" fn noop_collector_callback(_: *const Event, _: *mut c_void) -> c_int {
    0
}

extern "C" fn collector_callback(event: *const Event, user: *mut c_void) -> c_int {
    if event.is_null() || user.is_null() {
        return 0;
    }
    let context = unsafe { &*(user as *const CollectorContext) };
    let copy = unsafe { *event };
    if context.tx.try_send(Envelope::Telemetry(copy)).is_err() {
        context.drops.fetch_add(1, Ordering::Relaxed);
    }
    0
}

extern "C" fn capture_callback(event: *const Event, user: *mut c_void) -> c_int {
    if event.is_null() || user.is_null() {
        return 0;
    }
    let context = unsafe { &*(user as *const CaptureContext) };
    let copy = unsafe { *event };
    if context.tx.try_send(Envelope::Telemetry(copy)).is_err() {
        context.drops.fetch_add(1, Ordering::Relaxed);
    }
    0
}

extern "C" fn ksensor_callback(raw: *const Event, _: *mut Verdict, user: *mut c_void) -> c_int {
    if raw.is_null() || user.is_null() {
        return 0;
    }
    let context = unsafe { &*(user as *const KSensorContext) };
    let copy = unsafe { *raw };
    if context.tx.try_send(Envelope::Telemetry(copy)).is_err() {
        context.drops.fetch_add(1, Ordering::Relaxed);
    }
    0
}

extern "C" fn kernel_callback(event: *const Event, user: *mut c_void) -> c_int {
    if event.is_null() || user.is_null() {
        return 1;
    }
    let context = unsafe { &*(user as *const KernelContext) };
    let copy = unsafe { *event };
    while !context.stop.load(Ordering::SeqCst) {
        match context.tx.try_send(Envelope::Telemetry(copy)) {
            Ok(()) => return 0,
            Err(TrySendError::Full(_)) => std::thread::yield_now(),
            Err(TrySendError::Disconnected(_)) => return 1,
        }
    }
    1
}

extern "C" fn trace_callback(
    raw: *const Event,
    verdict: *mut Verdict,
    user: *mut c_void,
) -> c_int {
    if raw.is_null() || user.is_null() {
        return DECISION_ALLOW;
    }
    let context = unsafe { &*(user as *const TraceContext) };
    let event = unsafe { *raw };
    let (tx, rx) = sync_channel::<Decision>(1);
    if context
        .tx
        .send(Envelope::TraceRequest { event, ack: tx })
        .is_err()
    {
        return DECISION_ALLOW;
    }
    let decision = rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or(Decision {
            code: DECISION_ALLOW,
            rule: RULE_NONE,
        });
    if decision.code == DECISION_DENY && !verdict.is_null() {
        unsafe {
            (*verdict).rule = decision.rule;
            (*verdict).text[0] = 0;
        }
    }
    decision.code
}

struct Stats {
    events_in: u64,
    invalid: u64,
    findings: u64,
    recorded: u64,
    started: Instant,
    tracer_status: i32,
}

fn json_record(item: &crate::event::Normalized, findings: &[Finding], decision: i32) -> String {
    let rule = findings.first().map(|f| f.rule_name).unwrap_or("none");
    let action = match decision {
        DECISION_DENY => "denied",
        DECISION_STOP => "isolated",
        _ if findings.is_empty() => "observed",
        _ => "investigating",
    };
    let names: Vec<String> = findings
        .iter()
        .map(|f| format!("\"{}\"", escape(f.rule_name)))
        .collect();
    let rules = if names.is_empty() {
        String::new()
    } else {
        format!(",\"rules\":[{}]", names.join(","))
    };
    let details: Vec<String> = findings
        .iter()
        .map(|finding| {
            format!(
                "{{\"rule\":\"{}\",\"detail\":\"{}\"}}",
                escape(finding.rule_name),
                escape(&finding.detail)
            )
        })
        .collect();
    let details = if details.is_empty() {
        String::new()
    } else {
        format!(",\"findings\":[{}]", details.join(","))
    };
    format!(
        "{{\"ts\":\"{}\",\"source\":\"{}\",\"type\":\"{}\",\"severity\":\"{}\",\"confidence\":{:.3},\"pid\":{},\"tid\":{},\"rule\":\"{}\",\"action\":\"{}\",\"detail\":\"{}\"{}{}}}",
        timestamp(),
        escape(item.source),
        escape(item.kind),
        item.severity,
        item.confidence as f64 / 1000.0,
        item.pid,
        item.tid,
        escape(rule),
        action,
        escape(&item.detail),
        rules,
        details
    )
}

pub struct Engine {
    policy: Policy,
    analyzers: Analyzers,
    detectors: DetectorRegistry,
    correlation: Option<Correlation>,
    risk: Risk,
    guard: Guard,
    store: Store,
    writer: Option<Writer>,
    audit_integrity: &'static str,
    audit_writer_error: Option<String>,
    cli: Cli,
    stats: Stats,
}

impl Engine {
    pub fn new(policy: Policy) -> Result<Self, String> {
        let mut analyzers = Analyzers::new().ok_or("analyzer allocation failed")?;
        let window_status = analyzers.set_entity_window_ms(policy.correlate_window_ms);
        if window_status != OK {
            return Err("bad correlation window".to_string());
        }
        let detectors = DetectorRegistry::from_policy(&policy);
        if detectors.enabled_count() == 0 {
            return Err("no detectors enabled".to_string());
        }
        let max_states = policy.max_states;
        let cli = Cli::new(policy.json_only, policy.verbose, 120);
        let audit_key_path = policy
            .audit_key
            .clone()
            .unwrap_or_else(|| crate::auth::key_path(&policy.store_path));
        let (store, audit_integrity) = match Store::open_signed_with_key(
            &policy.store_path,
            4 * 1024 * 1024,
            &audit_key_path,
        ) {
            Ok(store) => {
                let integrity = store.integrity();
                (store, integrity)
            }
            Err(_) => {
                let store = Store::open(&policy.store_path, 4 * 1024 * 1024);
                let integrity = store.integrity();
                (store, integrity)
            }
        };
        let mut writer = None;
        let mut audit_writer_error = None;
        if policy.audit_process {
            match crate::auth::key_load_path(&audit_key_path) {
                Ok(_) => match Writer::start(&policy.store_path, &audit_key_path) {
                    Ok(started) => writer = Some(started),
                    Err(message) => audit_writer_error = Some(message),
                },
                Err(_) => audit_writer_error = Some("audit key unavailable".to_string()),
            }
        }
        Ok(Self {
            policy,
            analyzers,
            detectors,
            correlation: Correlation::new(),
            risk: Risk::new(max_states, 5_000_000_000),
            guard: Guard::new(256),
            store,
            writer,
            audit_integrity,
            audit_writer_error,
            cli,
            stats: Stats {
                events_in: 0,
                invalid: 0,
                findings: 0,
                recorded: 0,
                started: Instant::now(),
                tracer_status: OK,
            },
        })
    }

    fn append_audit(&mut self, line: &str) -> bool {
        match self.writer.as_mut() {
            Some(writer) => writer.send(line),
            None => self.store.append(line),
        }
    }

    fn process(&mut self, event: Event, ack: Option<SyncSender<Decision>>) {
        self.stats.events_in += 1;
        let now = unsafe { ffi::ap_clock_ns() };
        let item = match normalize(&event, now) {
            Some(item) => item,
            None => {
                self.stats.invalid += 1;
                if let Some(ack) = ack {
                    let _ = ack.send(Decision {
                        code: DECISION_ALLOW,
                        rule: RULE_NONE,
                    });
                }
                return;
            }
        };
        let mut findings = detect_with_registry(&event, &mut self.analyzers, &self.detectors);
        if let Some(ref mut correlation) = self.correlation {
            correlation.observe(&event, now, &findings);
            correlation.maybe_evaluate(now, &mut findings);
            findings = self.detectors.filter(findings);
        }
        let (score, crossed) = if findings.is_empty() {
            (self.risk.score(event.pid), false)
        } else {
            self.risk.evict_if_needed(event.pid);
            self.risk.update(event.pid, event.severity.max(2), 500, now)
        };
        let decision = self.guard.apply_event(
            &self.policy,
            &findings,
            score,
            now,
            event.pid,
        );
        if crossed
            && !findings.is_empty()
            && self.detectors.is_enabled(RULE_CORRELATED)
            && !findings.iter().any(|f| f.rule == RULE_CORRELATED)
        {
            findings.push(Finding {
                rule: RULE_CORRELATED,
                rule_name: rule_name(RULE_CORRELATED),
                source: item.source,
                severity: SEV_HIGH,
                confidence: 700,
                evidence: score as u64,
                detail: format!("risk score {}", score),
                decision,
            });
        }
        for finding in findings.iter_mut() {
            finding.decision = decision;
        }
        self.stats.findings += findings.len() as u64;
        if !findings.is_empty() || self.policy.verbose {
            if self.append_audit(&json_record(&item, &findings, decision)) {
                self.stats.recorded += 1;
            }
        }
        self.cli.event(&item, &findings, decision, self.stats.events_in);

        if let Some(ack) = ack {
            let rule = findings
                .iter()
                .filter(|f| {
                    f.confidence >= self.policy.min_confidence
                        && (self.policy.deny_rules.contains(&f.rule)
                            || self.policy.stop_rules.contains(&f.rule))
                })
                .max_by_key(|f| f.confidence)
                .map(|f| f.rule)
                .unwrap_or(RULE_NONE);
            let _ = ack.send(Decision { code: decision, rule });
        }
    }

    fn tick(&self) {
        if self.stats.events_in % 200 == 0 && self.stats.events_in > 0 {
            let (net, flow, intrusion) = self.analyzers.counters();
            let destructive = self.analyzers.destructive_counters();
            self.cli.status("stats", &[
                ("events", self.stats.events_in.to_string()),
                ("findings", self.stats.findings.to_string()),
                ("invalid", self.stats.invalid.to_string()),
                ("risk_states", self.risk.len().to_string()),
                ("net_packets", net.packets.to_string()),
                ("peer_events", net.peer_events.to_string()),
                ("flow_events", flow.events.to_string()),
                ("entity_events", flow.entity_events.to_string()),
                ("entity_findings", flow.entity_findings.to_string()),
                ("entity_refs_expired", flow.entity_refs_expired.to_string()),
                ("intrusion_findings", intrusion.findings.to_string()),
                ("intrusion_suppressed", intrusion.suppressed.to_string()),
                ("destructive_findings", destructive.findings.to_string()),
                ("destructive_suppressed", destructive.suppressed.to_string()),
                ("chain_findings", self.guard.stats.chain_findings.to_string()),
                ("correlation", self
                    .correlation
                    .as_ref()
                    .map(|value| (value.stats().graph_findings + value.stats().risk_findings).to_string())
                    .unwrap_or_else(|| "unavailable".to_string())),
            ]);
        }
    }

    pub fn run(mut self, ipc: Option<Ipc>) -> Result<(), String> {
        unsafe {
            let handler = on_signal as *const () as usize;
            ffi::signal(2, handler);
            ffi::signal(15, handler);
        }
        unsafe { ffi::ap_sys_init() };
        let caps = unsafe { ffi::ap_cap_probe() };
        let tracing = !self.policy.trace_argv.is_empty();
        let ipc_enabled = ipc.is_some();
        let ipc_duplicates = ipc.as_ref().map(|ipc| ipc.duplicate_counter());
        let ipc_sequences = ipc.as_ref().map(|ipc| ipc.sequence_counter());
        let ipc_client_matches = ipc.as_ref().map(|ipc| ipc.client_match_counter());
        let ipc_client_misses = ipc.as_ref().map(|ipc| ipc.client_miss_counter());
        let proc_enabled = self.policy.proc_scan && caps & ffi::CAP_PROC != 0;
        let capture_requested = self.policy.capture_requested();
        let mut capture_error: Option<String> = None;
        let mut capture: Option<Capture> = None;
        if capture_requested {
            if let Some(ref path) = self.policy.capture_file {
                capture = Capture::open_file(path, self.policy.capture_snaplen);
                if capture.is_none() {
                    capture_error = Some("frame file open failed".to_string());
                }
            } else if caps & ffi::CAP_NETWORK == 0 {
                capture_error = Some("raw packet socket denied by kernel policy".to_string());
            } else {
                capture = Capture::open_iface(
                    &self.policy.capture_iface,
                    self.policy.capture_snaplen,
                );
                if capture.is_none() {
                    capture_error = Some("packet capture backend could not open".to_string());
                }
            }
        }
        let kernel_requested = self.policy.kernel_events.is_some();
        let mut kernel_error: Option<String> = None;
        let mut kernel: Option<Kernel> = None;
        if let Some(ref path) = self.policy.kernel_events {
            kernel = Kernel::open_file(path);
            if kernel.is_none() {
                kernel_error = Some("kernel event file open failed or invalid".to_string());
            }
        }
        let kernel_active = kernel.is_some();
        // The self-hardening seccomp filter denies bpf(); the kernel sensor must
        // be opened before ap_sys_self_harden() below.
        let ksensor_requested = self.policy.kernel_sensor || self.policy.lsm_enforce;
        let mut ksensor_error: Option<String> = None;
        let mut lsm_error: Option<String> = None;
        let mut ksensor: Option<KSensor> = None;
        let mut lsm_active = false;
        if ksensor_requested {
            match KSensor::open(&self.policy) {
                Ok(sensor) => {
                    let status = sensor.status();
                    lsm_active = self.policy.lsm_enforce && status.lsm_active != 0;
                    if self.policy.lsm_enforce && !lsm_active {
                        lsm_error = Some(format!(
                            "bpf lsm did not become active ({})",
                            crate::ksensor::status_reason(&status)
                        ));
                    }
                    ksensor = Some(sensor);
                }
                Err(message) => {
                    ksensor_error = Some(message.clone());
                    if self.policy.lsm_enforce {
                        lsm_error = Some(message);
                    }
                }
            }
        }
        let ksensor_active = ksensor.is_some();
        let collector = if proc_enabled {
            let handle = ProcCollector::new(
                self.policy.proc_max_pids,
                self.policy.proc_map_samples,
                self.policy.proc_wx_per_scan,
                self.policy.proc_io_per_scan,
            );
            if handle.is_none() {
                self.cli.status("degraded", &[
                    ("source", "\"proc\"".to_string()),
                    ("state", "\"unavailable\"".to_string()),
                    ("reason", "\"collector allocation failed\"".to_string()),
                ]);
            }
            handle
        } else {
            None
        };
        if let Some(ref handle) = collector {
            unsafe {
                ffi::ap_collector_scan(
                    handle.ptr(),
                    ffi::ap_clock_ns(),
                    noop_collector_callback,
                    std::ptr::null_mut(),
                );
            }
        }
        let sources = SourceRegistry::new(
            caps,
            tracing,
            ipc_enabled,
            proc_enabled,
            capture.is_some(),
            capture_error.as_deref(),
            kernel_active,
            kernel_error.as_deref(),
            ksensor_active,
            ksensor_error.as_deref(),
            lsm_active,
            lsm_error.as_deref(),
        );
        let hardened = if self.policy.no_self_harden || tracing {
            false
        } else {
            unsafe { ffi::ap_sys_self_harden() == OK }
        };
        // Start the ipc receiver before announcing "active"; external injectors
        // wait for that line and can otherwise overrun the datagram buffer.
        let (tx, rx): (SyncSender<Envelope>, Receiver<Envelope>) =
            sync_channel(self.policy.queue_depth);
        let queue_drops = Arc::new(AtomicU64::new(0));
        if let Some(ipc) = ipc {
            let tx_ipc = tx.clone();
            let drops = queue_drops.clone();
            std::thread::spawn(move || {
                while !SHUTDOWN.load(Ordering::SeqCst) {
                    if let Some(event) = ipc.recv_event(100) {
                        if tx_ipc.try_send(Envelope::Telemetry(event)).is_err() {
                            drops.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
        self.cli.startup(
            if self.policy.guard_mode { "guard" } else { "monitor" },
            caps as i32,
            hardened,
        );
        let cap_name = |bit: u32| -> String {
            format!("\"{}\"", if caps & bit != 0 { "available" } else { "unavailable" })
        };
        self.cli.status("caps", &[
            ("seccomp", cap_name(ffi::CAP_SECCOMP)),
            ("ptrace", cap_name(ffi::CAP_PTRACE)),
            ("proc_maps", cap_name(ffi::CAP_PROC)),
            ("perf", cap_name(ffi::CAP_PERF)),
            ("tracepoints", cap_name(ffi::CAP_TRACEPOINT)),
            ("bpf", cap_name(ffi::CAP_BPF)),
            ("packet_capture", cap_name(ffi::CAP_NETWORK)),
            ("policy", format!("\"{}\"", escape(&self.policy.summary()))),
        ]);
        let audit_backend = if self.writer.is_some() {
            "process"
        } else {
            "local"
        };
        self.cli.status("audit", &[
            ("integrity", format!("\"{}\"", self.audit_integrity)),
            ("backend", format!("\"{}\"", audit_backend)),
            ("process", self.policy.audit_process.to_string()),
        ]);
        let lsm_denies_report = ksensor
            .as_ref()
            .map(|sensor| sensor.counters().lsm_denies)
            .unwrap_or(0);
        self.cli.status("enforcement", &enforcement_report(
            self.policy.guard_mode,
            tracing,
            caps & ffi::CAP_PTRACE != 0,
            caps & ffi::CAP_SECCOMP != 0,
            hardened,
            lsm_active,
            lsm_denies_report,
        ));
        sources.emit(&self.cli);
        if self.correlation.is_none() {
            self.cli.status("degraded", &[
                ("source", "\"correlation\"".to_string()),
                ("state", "\"unavailable\"".to_string()),
                ("reason", "\"correlation analyzer allocation failed\"".to_string()),
            ]);
        }
        if let Some(ref reason) = ksensor_error {
            self.cli.status("degraded", &[
                ("source", "\"ksensor\"".to_string()),
                ("state", "\"unavailable\"".to_string()),
                ("reason", format!("\"{}\"", escape(reason))),
            ]);
        }
        if let Some(ref reason) = lsm_error {
            self.cli.status("degraded", &[
                ("source", "\"lsm\"".to_string()),
                ("state", "\"unavailable\"".to_string()),
                ("reason", format!("\"{}\"", escape(reason))),
            ]);
        }
        self.detectors.emit(&self.cli);
        if tracing {
            self.cli.status("degraded", &[
                ("self_hardening", "\"deferred_trace_mode\"".to_string()),
                ("reason", "\"seccomp filter would deny traced child\"".to_string()),
            ]);
        }
        if self.audit_integrity != "hmac_sha256" {
            self.cli.status("degraded", &[
                ("audit", "\"fnv1a\"".to_string()),
                ("reason", "\"audit key unavailable\"".to_string()),
            ]);
        }
        if let Some(ref reason) = self.audit_writer_error {
            self.cli.status("degraded", &[
                ("audit_writer", "\"unavailable\"".to_string()),
                ("reason", format!("\"{}\"", escape(reason))),
            ]);
        }

        let scan_tx = tx.clone();
        let mut next_proc_scan = Instant::now() + Duration::from_millis(self.policy.proc_interval_ms);
        if tracing {
            if caps & ffi::CAP_PTRACE == 0 {
                self.cli.status("degraded", &[
                    ("tracer", "\"unavailable\"".to_string()),
                    ("reason", "\"ptrace denied by kernel policy\"".to_string()),
                ]);
            } else {
                let argv = self.policy.trace_argv.clone();
                let tx_thread = tx.clone();
                let mask = self.policy.trace_mask;
                let follow = self.policy.follow_fork;
                let max_events = self.policy.max_events;
                std::thread::spawn(move || {
                    let cstrings: Vec<CString> = argv
                        .iter()
                        .filter_map(|s| CString::new(s.as_str()).ok())
                        .collect();
                    if cstrings.is_empty() {
                        let _ = tx_thread.send(Envelope::TraceDone(ERR_ARG));
                        return;
                    }
                    let pointers: Vec<*const std::ffi::c_char> =
                        cstrings.iter().map(|s| s.as_ptr()).collect();
                    let config = ffi::TraceConfig {
                        argv: pointers.as_ptr(),
                        argc: cstrings.len() as u32,
                        flags: if follow { 1 } else { 0 },
                        mask,
                        max_events,
                    };
                    let context = Box::leak(Box::new(TraceContext { tx: tx_thread.clone() }));
                    let status = unsafe {
                        ffi::ap_trace_run(
                            &config,
                            trace_callback,
                            context as *mut TraceContext as *mut c_void,
                        )
                    };
                    let _ = tx_thread.send(Envelope::TraceDone(status));
                });
            }
        }

        let capture_stats = Arc::new(Mutex::new(ffi::CaptureCounters::default()));
        let capture_stop = Arc::new(AtomicBool::new(false));
        let mut capture_thread = None;
        if let Some(capture) = capture {
            let tx_cap = tx.clone();
            let drops = queue_drops.clone();
            let stats = capture_stats.clone();
            let stop = capture_stop.clone();
            capture_thread = Some(std::thread::spawn(move || {
                let context = Box::leak(Box::new(CaptureContext {
                    tx: tx_cap,
                    drops,
                }));
                while !stop.load(Ordering::SeqCst) {
                    let status = capture.poll(
                        ffi::CAPTURE_MAX_FRAMES,
                        capture_callback,
                        context as *mut CaptureContext as *mut c_void,
                        100,
                    );
                    if status != OK {
                        break;
                    }
                }
                let counters = capture.counters();
                if let Ok(mut out) = stats.lock() {
                    *out = counters;
                }
            }));
        }
        let kernel_stats = Arc::new(Mutex::new(ffi::KernelCounters::default()));
        let kernel_stop = Arc::new(AtomicBool::new(false));
        let mut kernel_thread = None;
        if let Some(kernel) = kernel {
            let tx_kernel = tx.clone();
            let done_tx = tx.clone();
            let stats = kernel_stats.clone();
            let stop = kernel_stop.clone();
            kernel_thread = Some(std::thread::spawn(move || {
                let context = Box::leak(Box::new(KernelContext {
                    tx: tx_kernel,
                    stop,
                }));
                let status = kernel.poll(
                    ffi::KERNEL_MAX_EVENTS,
                    kernel_callback,
                    context as *mut KernelContext as *mut c_void,
                );
                let counters = kernel.counters();
                if let Ok(mut out) = stats.lock() {
                    *out = counters;
                }
                if status == OK && kernel.pending() == 0 {
                    let _ = done_tx.send(Envelope::KernelDone);
                }
            }));
        }
        let ksensor_stats = Arc::new(Mutex::new(ffi::KSensorCounters::default()));
        let ksensor_stop = Arc::new(AtomicBool::new(false));
        let mut ksensor_thread = None;
        if let Some(sensor) = ksensor {
            let tx_sensor = tx.clone();
            let drops = queue_drops.clone();
            let stats = ksensor_stats.clone();
            let stop = ksensor_stop.clone();
            ksensor_thread = Some(std::thread::spawn(move || {
                let context = Box::leak(Box::new(KSensorContext {
                    tx: tx_sensor,
                    drops,
                }));
                while !stop.load(Ordering::SeqCst) {
                    let status = sensor.poll(
                        ffi::KSENSOR_MAX_EVENTS,
                        ksensor_callback,
                        context as *mut KSensorContext as *mut c_void,
                    );
                    if status != OK {
                        break;
                    }
                }
                let counters = sensor.counters();
                if let Ok(mut out) = stats.lock() {
                    *out = counters;
                }
            }));
        }
        drop(tx);

        let deadline = self.policy.duration_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let mut tracer_done = !tracing;
        let mut kernel_done = !kernel_active;
        let reason: &str;
        loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                reason = "signal";
                break;
            }
            if deadline.map_or(false, |end| Instant::now() >= end) {
                reason = "duration";
                break;
            }
            if let Some(ref handle) = collector {
                if Instant::now() >= next_proc_scan {
                    let context = CollectorContext {
                        tx: &scan_tx,
                        drops: &queue_drops,
                    };
                    let now = unsafe { ffi::ap_clock_ns() };
                    unsafe {
                        ffi::ap_collector_scan(
                            handle.ptr(),
                            now,
                            collector_callback,
                            &context as *const CollectorContext as *mut c_void,
                        );
                    }
                    next_proc_scan =
                        Instant::now() + Duration::from_millis(self.policy.proc_interval_ms);
                }
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Envelope::Telemetry(event)) => self.process(event, None),
                Ok(Envelope::TraceRequest { event, ack }) => self.process(event, Some(ack)),
                Ok(Envelope::TraceDone(status)) => {
                    self.stats.tracer_status = status;
                    tracer_done = true;
                }
                Ok(Envelope::KernelDone) => kernel_done = true,
                Err(RecvTimeoutError::Timeout) => self.tick(),
                Err(RecvTimeoutError::Disconnected) => {
                    reason = "disconnected";
                    break;
                }
            }
            if self.policy.once && tracer_done && kernel_done {
                while let Ok(message) = rx.try_recv() {
                    match message {
                        Envelope::Telemetry(event) => self.process(event, None),
                        Envelope::TraceRequest { event, ack } => self.process(event, Some(ack)),
                        Envelope::TraceDone(status) => self.stats.tracer_status = status,
                        Envelope::KernelDone => {}
                    }
                }
                reason = "complete";
                break;
            }
        }
        capture_stop.store(true, Ordering::SeqCst);
        if let Some(thread) = capture_thread.take() {
            let _ = thread.join();
        }
        let capture_counters = capture_stats
            .lock()
            .map(|value| *value)
            .unwrap_or_default();
        kernel_stop.store(true, Ordering::SeqCst);
        if let Some(thread) = kernel_thread.take() {
            let _ = thread.join();
        }
        let kernel_counters = kernel_stats
            .lock()
            .map(|value| *value)
            .unwrap_or_default();
        ksensor_stop.store(true, Ordering::SeqCst);
        if let Some(thread) = ksensor_thread.take() {
            let _ = thread.join();
        }
        let ksensor_counters = ksensor_stats
            .lock()
            .map(|value| *value)
            .unwrap_or_default();
        self.tick();
        let audit_entries: Vec<String> = self
            .guard
            .audit()
            .iter()
            .map(|entry| format!("{{\"audit\":\"{}\"}}", escape(entry)))
            .collect();
        for line in audit_entries {
            self.append_audit(&line);
        }
        let audit_report = self.writer.take().map(|writer| writer.finish());
        let (net, flow, intrusion) = self.analyzers.counters();
        let destructive = self.analyzers.destructive_counters();
        let correlation_stats = self
            .correlation
            .as_ref()
            .map(|value| value.stats())
            .unwrap_or_default();
        if let Some(ref handle) = collector {
            let proc = handle.counters();
            self.cli.status("proc", &[
                ("scans", proc.scans.to_string()),
                ("pids_seen", proc.pids_seen.to_string()),
                ("starts", proc.starts.to_string()),
                ("exits", proc.exits.to_string()),
                ("execs", proc.execs.to_string()),
                ("priv_changes", proc.priv_changes.to_string()),
                ("wx_regions", proc.wx_regions.to_string()),
                ("file_events", proc.file_events.to_string()),
                ("file_samples", proc.file_samples.to_string()),
                ("file_errors", proc.file_errors.to_string()),
                ("evictions", proc.evictions.to_string()),
                ("errors", proc.errors.to_string()),
                ("interval_ms", self.policy.proc_interval_ms.to_string()),
                ("max_pids", self.policy.proc_max_pids.to_string()),
                ("map_samples", self.policy.proc_map_samples.to_string()),
                ("wx_per_scan", self.policy.proc_wx_per_scan.to_string()),
                ("io_per_scan", self.policy.proc_io_per_scan.to_string()),
            ]);
        }
        if capture_requested {
            let mode = if self.policy.capture_file.is_some() {
                "file"
            } else {
                "iface"
            };
            self.cli.status("capture", &[
                ("mode", format!("\"{}\"", mode)),
                ("snaplen", self.policy.capture_snaplen.to_string()),
                ("frames", capture_counters.frames.to_string()),
                ("parsed", capture_counters.parsed.to_string()),
                ("invalid", capture_counters.invalid.to_string()),
                ("truncated", capture_counters.truncated.to_string()),
                ("errors", capture_counters.errors.to_string()),
            ]);
        }
        if kernel_requested {
            self.cli.status("kernel", &[
                ("mode", "\"file\"".to_string()),
                ("events", kernel_counters.frames.to_string()),
                ("parsed", kernel_counters.parsed.to_string()),
                ("invalid", kernel_counters.invalid.to_string()),
                ("errors", kernel_counters.errors.to_string()),
            ]);
        }
        let mut summary: Vec<(&str, String)> = vec![
            ("events", self.stats.events_in.to_string()),
            ("findings", self.stats.findings.to_string()),
            ("invalid", self.stats.invalid.to_string()),
            ("recorded", self.stats.recorded.to_string()),
            ("printed", self.cli.printed.to_string()),
            ("dropped", self.cli.dropped.to_string()),
            ("denials", self.guard.stats.denials.to_string()),
            ("risk_states", self.risk.len().to_string()),
            ("queue_drops", queue_drops.load(Ordering::Relaxed).to_string()),
            ("net_packets", net.packets.to_string()),
            ("peers", net.peers.to_string()),
            ("peer_events", net.peer_events.to_string()),
            ("peer_evictions", net.peer_evictions.to_string()),
            ("peer_bursts", net.peer_bursts.to_string()),
            ("peer_exhaustion", net.peer_exhaustion.to_string()),
            ("flow_events", flow.events.to_string()),
            ("entity_events", flow.entity_events.to_string()),
            ("entity_findings", flow.entity_findings.to_string()),
            ("entity_evictions", flow.entity_evictions.to_string()),
            ("entity_refs_expired", flow.entity_refs_expired.to_string()),
            ("intrusion_findings", intrusion.findings.to_string()),
            ("intrusion_suppressed", intrusion.suppressed.to_string()),
            ("destructive_findings", destructive.findings.to_string()),
            ("destructive_suppressed", destructive.suppressed.to_string()),
            ("chain_findings", self.guard.stats.chain_findings.to_string()),
            ("tracer_status", self.stats.tracer_status.to_string()),
            ("sources", sources.active_json()),
            ("ksensor_events", ksensor_counters.events.to_string()),
            ("ksensor_invalid", ksensor_counters.invalid.to_string()),
            ("ksensor_dropped", ksensor_counters.dropped.to_string()),
            ("ksensor_attached", ksensor_counters.attached.to_string()),
            ("lsm_active", lsm_active.to_string()),
            ("lsm_denies", ksensor_counters.lsm_denies.to_string()),
            ("graph_added", correlation_stats.graph_added.to_string()),
            ("graph_evicted", correlation_stats.graph_evicted.to_string()),
            ("graph_findings", correlation_stats.graph_findings.to_string()),
            ("graph_suppressed", correlation_stats.graph_suppressed.to_string()),
            ("evidence_inserted", correlation_stats.evidence_inserted.to_string()),
            ("evidence_duplicates", correlation_stats.evidence_duplicates.to_string()),
            ("evidence_evicted", correlation_stats.evidence_evicted.to_string()),
            ("beacon_findings", correlation_stats.beacon_findings.to_string()),
            ("risk_findings", correlation_stats.risk_findings.to_string()),
            ("detectors", self.detectors.summary()),
            ("uptime_ms", self.stats.started.elapsed().as_millis().to_string()),
        ];
        summary.push(("audit_process", self.policy.audit_process.to_string()));
        if self.policy.audit_process {
            let status = match audit_report {
                Some(report) => report.status.as_str().to_string(),
                None => WriterStatus::Failed.as_str().to_string(),
            };
            summary.push(("audit_writer_status", format!("\"{}\"", status)));
            summary.push((
                "audit_writer_queued",
                audit_report.map(|report| report.queued).unwrap_or(0).to_string(),
            ));
            summary.push((
                "audit_writer_dropped",
                audit_report.map(|report| report.dropped).unwrap_or(0).to_string(),
            ));
        }
        if ipc_enabled {
            let duplicates = ipc_duplicates
                .map(|counter| counter.load(Ordering::Relaxed))
                .unwrap_or(0);
            summary.push(("ipc_duplicates", duplicates.to_string()));
            let sequences = ipc_sequences
                .map(|counter| counter.load(Ordering::Relaxed))
                .unwrap_or(0);
            summary.push(("ipc_sequence_drops", sequences.to_string()));
            let matches = ipc_client_matches
                .as_ref()
                .map(|counter| counter.load(Ordering::Relaxed))
                .unwrap_or(0);
            let misses = ipc_client_misses
                .as_ref()
                .map(|counter| counter.load(Ordering::Relaxed))
                .unwrap_or(0);
            if matches > 0 || misses > 0 {
                summary.push(("ipc_client_key_matches", matches.to_string()));
                summary.push(("ipc_client_key_misses", misses.to_string()));
            }
        }
        if capture_requested {
            summary.push(("capture_frames", capture_counters.frames.to_string()));
            summary.push(("capture_parsed", capture_counters.parsed.to_string()));
            summary.push(("capture_invalid", capture_counters.invalid.to_string()));
            summary.push(("capture_truncated", capture_counters.truncated.to_string()));
            summary.push(("capture_errors", capture_counters.errors.to_string()));
        }
        if kernel_requested {
            summary.push(("kernel_events", kernel_counters.frames.to_string()));
            summary.push(("kernel_parsed", kernel_counters.parsed.to_string()));
            summary.push(("kernel_invalid", kernel_counters.invalid.to_string()));
            summary.push(("kernel_errors", kernel_counters.errors.to_string()));
        }
        if let Some(ref handle) = collector {
            let proc = handle.counters();
            summary.push(("proc_scans", proc.scans.to_string()));
            summary.push(("proc_starts", proc.starts.to_string()));
            summary.push(("proc_exits", proc.exits.to_string()));
            summary.push(("proc_wx_regions", proc.wx_regions.to_string()));
            summary.push(("proc_file_events", proc.file_events.to_string()));
            summary.push(("proc_file_samples", proc.file_samples.to_string()));
            summary.push(("proc_file_errors", proc.file_errors.to_string()));
        }
        self.cli.status("summary", &summary);
        self.cli.shutdown(reason, self.stats.events_in, self.stats.findings);
        Ok(())
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.stats.events_in, self.stats.findings, self.stats.invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::validate;

    #[test]
    fn rejects_bad_abi_event() {
        let mut event = Event::new(KIND_PROC, 1, 2, 3);
        assert!(validate(&event).is_ok());
        event.abi_version = 0;
        assert!(validate(&event).is_err());
    }

    #[test]
    fn record_includes_every_rule() {
        let item = crate::event::Normalized {
            source: "kernel",
            kind: "kernel_interface",
            severity: "high",
            severity_code: SEV_HIGH,
            confidence: 780,
            pid: 7,
            tid: 7,
            seq: 1,
            ts_ns: 2,
            detail: "namespace_change".to_string(),
            subkind: 1,
            event_kind: KIND_KERNEL,
            arg: [0; 4],
        };
        let findings: Vec<Finding> = [
            RULE_PROCESS_INJECTION,
            RULE_EXPLOIT_CHAIN,
            RULE_CREDENTIAL_DUMP,
            RULE_KERNEL_IFACE,
            RULE_KERNEL_CHAIN,
        ]
        .iter()
            .map(|rule| Finding {
                rule: *rule,
                rule_name: crate::event::rule_name(*rule),
                source: "kernel",
                severity: SEV_HIGH,
                confidence: 800,
                evidence: 0,
                detail: "test".to_string(),
                decision: DECISION_ALLOW,
            })
            .collect();
        let line = json_record(&item, &findings, DECISION_ALLOW);
        assert!(line.contains("\"rule\":\"process_injection\""));
        assert!(line.contains(
            "\"rules\":[\"process_injection\",\"exploit_chain\",\"credential_dump\",\"kernel_interface\",\"kernel_chain\"]"
        ));
        for name in ["process_injection", "exploit_chain", "credential_dump"] {
            let expected = format!("{{\"rule\":\"{}\",\"detail\":\"test\"}}", name);
            assert!(line.contains(expected.as_str()));
        }
        assert!(line.contains("\"findings\":[{\"rule\":\"process_injection\",\"detail\":\"test\"}"));
    }
}
