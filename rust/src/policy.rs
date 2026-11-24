use crate::abi::*;
use crate::event::{rule_name, Finding};
use crate::ffi;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Policy {
    pub guard_mode: bool,
    pub deny_rules: Vec<u32>,
    pub stop_rules: Vec<u32>,
    pub enabled_rules: Vec<u32>,
    pub disabled_rules: Vec<u32>,
    pub min_confidence: u32,
    pub alert_threshold: u32,
    pub max_states: usize,
    pub queue_depth: usize,
    pub socket_path: PathBuf,
    pub store_path: PathBuf,
    pub trace_argv: Vec<String>,
    pub follow_fork: bool,
    pub trace_mask: u32,
    pub proc_scan: bool,
    pub ipc_strict_seq: bool,
    pub client_keys: Vec<(u32, PathBuf)>,
    pub audit_process: bool,
    pub audit_key: Option<PathBuf>,
    pub proc_interval_ms: u64,
    pub proc_max_pids: u32,
    pub proc_map_samples: u32,
    pub proc_wx_per_scan: u32,
    pub proc_io_per_scan: u32,
    pub correlate_window_ms: u32,
    pub capture: bool,
    pub capture_iface: String,
    pub capture_file: Option<PathBuf>,
    pub capture_snaplen: u32,
    pub kernel_events: Option<PathBuf>,
    pub json_only: bool,
    pub verbose: bool,
    pub once: bool,
    pub no_self_harden: bool,
    pub kernel_sensor: bool,
    pub lsm_enforce: bool,
    pub lsm_mask: u32,
    pub chain_guard: bool,
    pub max_events: u32,
    pub duration_ms: Option<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            guard_mode: false,
            deny_rules: Vec::new(),
            stop_rules: Vec::new(),
            enabled_rules: Vec::new(),
            disabled_rules: Vec::new(),
            min_confidence: 800,
            alert_threshold: 60,
            max_states: 4096,
            queue_depth: 4096,
            socket_path: PathBuf::from("/tmp/ap.sock"),
            store_path: PathBuf::from("ap.jsonl"),
            trace_argv: Vec::new(),
            follow_fork: true,
            trace_mask: 63,
            proc_scan: true,
            ipc_strict_seq: false,
            client_keys: Vec::new(),
            audit_process: false,
            audit_key: None,
            proc_interval_ms: 1000,
            proc_max_pids: 256,
            proc_map_samples: ffi::COLLECTOR_DEFAULT_MAPS_PER_SCAN,
            proc_wx_per_scan: ffi::COLLECTOR_DEFAULT_WX_PER_SCAN,
            proc_io_per_scan: ffi::COLLECTOR_DEFAULT_IO_PER_SCAN,
            correlate_window_ms: 5000,
            capture: false,
            capture_iface: String::from("any"),
            capture_file: None,
            capture_snaplen: ffi::CAPTURE_DEFAULT_SNAP,
            kernel_events: None,
            json_only: false,
            verbose: false,
            once: false,
            no_self_harden: false,
            kernel_sensor: false,
            lsm_enforce: false,
            lsm_mask: 0,
            chain_guard: false,
            max_events: 0,
            duration_ms: None,
        }
    }
}

pub fn rule_from_name(name: &str) -> Option<u32> {
    match name {
        "wx_region" => Some(RULE_WX_REGION),
        "wx_transition" => Some(RULE_WX_TRANSITION),
        "stack_exec" => Some(RULE_STACK_EXEC),
        "return_outside_exec" => Some(RULE_RETURN_OUTSIDE_EXEC),
        "shadow_mismatch" => Some(RULE_SHADOW_MISMATCH),
        "privilege_crossing" => Some(RULE_PRIV_CROSSING),
        "module_load" => Some(RULE_MODULE_LOAD),
        "kernel_interface" => Some(RULE_KERNEL_IFACE),
        "tcp_state_violation" => Some(RULE_TCP_STATE),
        "tcp_flag_violation" => Some(RULE_TCP_FLAGS),
        "ip_malformed" => Some(RULE_IP_MALFORMED),
        "fragment_overlap" => Some(RULE_FRAG_OVERLAP),
        "heap_canary" => Some(RULE_HEAP_CANARY),
        "double_free" => Some(RULE_DOUBLE_FREE),
        "invalid_free" => Some(RULE_INVALID_FREE),
        "correlated_exploit_indicators" => Some(RULE_CORRELATED),
        "raw_socket" => Some(RULE_RAW_SOCKET),
        "exec_after_wx" => Some(RULE_EXEC_AFTER_WX),
        "kernel_chain" => Some(RULE_KERNEL_CHAIN),
        "kernel_rootkit" => Some(RULE_KERNEL_ROOTKIT),
        "credential_theft" => Some(RULE_CREDENTIAL_THEFT),
        "persistence_chain" => Some(RULE_PERSISTENCE),
        "container_escape" => Some(RULE_CONTAINER_ESCAPE),
        "fileless_exec" => Some(RULE_FILELESS_EXEC),
        "anti_analysis" => Some(RULE_ANTI_ANALYSIS),
        "beaconing" => Some(RULE_BEACONING),
        "process_injection" => Some(RULE_PROCESS_INJECTION),
        "exploit_chain" => Some(RULE_EXPLOIT_CHAIN),
        "credential_dump" => Some(RULE_CREDENTIAL_DUMP),
        "file_write_burst" => Some(RULE_FILE_WRITE_BURST),
        "destructive_chain" => Some(RULE_DESTRUCTIVE_CHAIN),
        "data_exfiltration" => Some(RULE_DATA_EXFILTRATION),
        _ => None,
    }
}

fn parse_rules(value: &str) -> Result<Vec<u32>, String> {
    let mut rules = Vec::new();
    for name in value.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        match rule_from_name(name) {
            Some(rule) if !rules.contains(&rule) => rules.push(rule),
            Some(_) => {}
            None => return Err(format!("unknown rule: {}", name)),
        }
    }
    Ok(rules)
}

fn parse_selection(value: &str) -> Result<Vec<u32>, String> {
    if value.trim() == "all" {
        return Ok(vec![
            RULE_WX_REGION,
            RULE_WX_TRANSITION,
            RULE_STACK_EXEC,
            RULE_RETURN_OUTSIDE_EXEC,
            RULE_SHADOW_MISMATCH,
            RULE_PRIV_CROSSING,
            RULE_MODULE_LOAD,
            RULE_KERNEL_IFACE,
            RULE_TCP_STATE,
            RULE_TCP_FLAGS,
            RULE_IP_MALFORMED,
            RULE_FRAG_OVERLAP,
            RULE_HEAP_CANARY,
            RULE_DOUBLE_FREE,
            RULE_INVALID_FREE,
            RULE_CORRELATED,
            RULE_RAW_SOCKET,
            RULE_EXEC_AFTER_WX,
            RULE_KERNEL_CHAIN,
            RULE_KERNEL_ROOTKIT,
            RULE_CREDENTIAL_THEFT,
            RULE_PERSISTENCE,
            RULE_CONTAINER_ESCAPE,
            RULE_FILELESS_EXEC,
            RULE_ANTI_ANALYSIS,
            RULE_BEACONING,
            RULE_PROCESS_INJECTION,
            RULE_EXPLOIT_CHAIN,
            RULE_CREDENTIAL_DUMP,
            RULE_FILE_WRITE_BURST,
            RULE_DESTRUCTIVE_CHAIN,
            RULE_DATA_EXFILTRATION,
        ]);
    }
    parse_rules(value)
}

fn parse_u32_mask(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("bad lsm mask".to_string());
    }
    let (digits, radix) = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        (rest, 16)
    } else {
        (trimmed, 10)
    };
    if digits.is_empty() {
        return Err("bad lsm mask".to_string());
    }
    u32::from_str_radix(digits, radix).map_err(|_| "bad lsm mask".to_string())
}

fn parse_client_key(value: &str) -> Result<(u32, &str), String> {
    let mut parts = value.splitn(2, ':');
    let pid_text = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let pid: u32 = pid_text.parse().map_err(|_| "bad client key pid")?;
    if pid == 0 || pid > i32::MAX as u32 || path.is_empty() {
        return Err("bad client key mapping".to_string());
    }
    Ok((pid, path))
}

impl Policy {
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut policy = Self::default();
        let mut i = 1;
        while i < args.len() {
            let arg = args[i].as_str();
            match arg {
                "--guard" => policy.guard_mode = true,
                "--json" => policy.json_only = true,
                "--verbose" => policy.verbose = true,
                "--once" => policy.once = true,
                "--no-self-harden" => policy.no_self_harden = true,
                "--kernel-sensor" => policy.kernel_sensor = true,
                "--lsm-enforce" => policy.lsm_enforce = true,
                "--chain-guard" => policy.chain_guard = true,
                "--no-fork" => policy.follow_fork = false,
                "--no-proc-scan" => policy.proc_scan = false,
                "--ipc-strict-seq" => policy.ipc_strict_seq = true,
                "--capture" => policy.capture = true,
                "--audit-process" => policy.audit_process = true,
                "--client-key" => {
                    i += 1;
                    let value = args.get(i).ok_or_else(|| "missing value for --client-key")?;
                    let (pid, path) = parse_client_key(value)?;
                    if policy.client_keys.len() >= ffi::CLIENT_KEY_MAX {
                        return Err("too many client keys".to_string());
                    }
                    if policy.client_keys.iter().any(|(other, _)| *other == pid) {
                        return Err("duplicate client pid".to_string());
                    }
                    policy.client_keys.push((pid, PathBuf::from(path)));
                }
                "--deny" | "--stop" => {
                    i += 1;
                    let value = args.get(i).ok_or_else(|| format!("missing value for {}", arg))?;
                    let rules = parse_rules(value)?;
                    if arg == "--deny" {
                        policy.deny_rules = rules;
                    } else {
                        policy.stop_rules = rules;
                    }
                }
                "--enable" | "--disable" => {
                    i += 1;
                    let value = args.get(i).ok_or_else(|| format!("missing value for {}", arg))?;
                    let rules = parse_selection(value)?;
                    if arg == "--enable" {
                        policy.enabled_rules = rules;
                    } else {
                        policy.disabled_rules = rules;
                    }
                }
                "--socket" | "--store" | "--threshold" | "--min-confidence" |
                "--max-states" | "--queue-depth" | "--max-events" | "--duration" |
                "--proc-interval-ms" | "--proc-max-pids" | "--proc-map-samples" |
                "--proc-wx-per-scan" | "--proc-io-per-scan" | "--correlate-window-ms" |
                "--capture-iface" | "--capture-file" | "--capture-snaplen" |
                "--kernel-events" | "--audit-key" | "--lsm-mask" => {
                    i += 1;
                    let value = args.get(i).ok_or_else(|| format!("missing value for {}", arg))?;
                    match arg {
                        "--socket" => policy.socket_path = PathBuf::from(value),
                        "--store" => policy.store_path = PathBuf::from(value),
                        "--threshold" => {
                            policy.alert_threshold = value.parse().map_err(|_| "bad threshold")?;
                        }
                        "--min-confidence" => {
                            policy.min_confidence = value.parse().map_err(|_| "bad confidence")?;
                        }
                        "--max-states" => {
                            policy.max_states = value.parse().map_err(|_| "bad state count")?;
                        }
                        "--queue-depth" => {
                            let depth: usize = value.parse().map_err(|_| "bad queue depth")?;
                            if depth == 0 {
                                return Err("bad queue depth".to_string());
                            }
                            policy.queue_depth = depth;
                        }
                        "--max-events" => {
                            policy.max_events = value.parse().map_err(|_| "bad event count")?;
                        }
                        "--duration" => {
                            policy.duration_ms = Some(value.parse().map_err(|_| "bad duration")?);
                        }
                        "--proc-interval-ms" => {
                            let interval: u64 = value.parse().map_err(|_| "bad proc interval")?;
                            if interval < 100 {
                                return Err("bad proc interval".to_string());
                            }
                            policy.proc_interval_ms = interval;
                        }
                        "--proc-max-pids" => {
                            let max_pids: u32 = value.parse().map_err(|_| "bad proc pid count")?;
                            if max_pids == 0 || max_pids > 512 {
                                return Err("bad proc pid count".to_string());
                            }
                            policy.proc_max_pids = max_pids;
                        }
                        "--proc-map-samples" => {
                            let samples: u32 =
                                value.parse().map_err(|_| "bad proc map sample count")?;
                            if samples == 0 || samples > ffi::COLLECTOR_MAX_MAPS_PER_SCAN {
                                return Err("bad proc map sample count".to_string());
                            }
                            policy.proc_map_samples = samples;
                        }
                        "--proc-wx-per-scan" => {
                            let limit: u32 =
                                value.parse().map_err(|_| "bad proc wx limit")?;
                            if limit == 0 || limit > ffi::COLLECTOR_MAX_WX_PER_SCAN {
                                return Err("bad proc wx limit".to_string());
                            }
                            policy.proc_wx_per_scan = limit;
                        }
                        "--proc-io-per-scan" => {
                            let limit: u32 = value.parse().map_err(|_| "bad proc io limit")?;
                            if limit == 0 || limit > ffi::COLLECTOR_MAX_IO_PER_SCAN {
                                return Err("bad proc io limit".to_string());
                            }
                            policy.proc_io_per_scan = limit;
                        }
                        "--correlate-window-ms" => {
                            let window_ms: u32 = value.parse().map_err(|_| "bad correlate window")?;
                            if window_ms < 100 || window_ms > 60000 {
                                return Err("bad correlate window".to_string());
                            }
                            policy.correlate_window_ms = window_ms;
                        }
                        "--capture-iface" => {
                            if value.is_empty() {
                                return Err("bad capture interface".to_string());
                            }
                            policy.capture_iface = value.to_string();
                            policy.capture = true;
                        }
                        "--capture-file" => {
                            policy.capture_file = Some(PathBuf::from(value));
                            policy.capture = true;
                        }
                        "--capture-snaplen" => {
                            let snaplen: u32 = value.parse().map_err(|_| "bad capture snaplen")?;
                            if snaplen < ffi::CAPTURE_SNAP_MIN || snaplen > ffi::CAPTURE_SNAP_MAX {
                                return Err("bad capture snaplen".to_string());
                            }
                            policy.capture_snaplen = snaplen;
                        }
                        "--kernel-events" => {
                            if value.is_empty() {
                                return Err("bad kernel event file".to_string());
                            }
                            policy.kernel_events = Some(PathBuf::from(value));
                        }
                        "--audit-key" => {
                            if value.is_empty() {
                                return Err("bad audit key path".to_string());
                            }
                            policy.audit_key = Some(PathBuf::from(value));
                        }
                        "--lsm-mask" => {
                            policy.lsm_mask = parse_u32_mask(value)?;
                        }
                        _ => {}
                    }
                }
                "--mask" => {
                    i += 1;
                    let value = args.get(i).ok_or_else(|| "missing mask")?;
                    policy.trace_mask = value.parse().map_err(|_| "bad mask")?;
                }
                "--trace" => {
                    i += 1;
                    while i < args.len() {
                        policy.trace_argv.push(args[i].clone());
                        i += 1;
                    }
                    break;
                }
                "--help" => return Err("help".to_string()),
                _ => return Err(format!("unknown option: {}", arg)),
            }
            i += 1;
        }
        if policy.min_confidence > 1000 || policy.alert_threshold > 100 {
            return Err("policy value out of range".to_string());
        }
        if policy.chain_guard && !policy.guard_mode {
            return Err("--chain-guard requires --guard".to_string());
        }
        if policy.chain_guard && policy.deny_rules.is_empty() && policy.stop_rules.is_empty() {
            return Err("--chain-guard requires deny or stop rules".to_string());
        }
        Ok(policy)
    }

    pub fn capture_requested(&self) -> bool {
        self.capture || self.capture_file.is_some()
    }

    pub fn decision(&self, findings: &[Finding], risk_score: u32) -> i32 {
        self.decision_with_chain(findings, risk_score, !self.chain_guard)
    }

    pub fn decision_with_chain(
        &self,
        findings: &[Finding],
        risk_score: u32,
        chain_ready: bool,
    ) -> i32 {
        if !self.guard_mode || risk_score < self.alert_threshold {
            return DECISION_ALLOW;
        }
        if self.chain_guard && !chain_ready {
            return DECISION_ALLOW;
        }
        let mut best: Option<&Finding> = None;
        for finding in findings {
            if finding.confidence < self.min_confidence {
                continue;
            }
            if !self.deny_rules.contains(&finding.rule) && !self.stop_rules.contains(&finding.rule) {
                continue;
            }
            if best.map_or(true, |current| finding.confidence > current.confidence) {
                best = Some(finding);
            }
        }
        match best {
            Some(finding) if self.stop_rules.contains(&finding.rule) && !self.deny_rules.contains(&finding.rule) => {
                DECISION_STOP
            }
            Some(_) => DECISION_DENY,
            None => DECISION_ALLOW,
        }
    }

    pub fn summary(&self) -> String {
        let mut rules = Vec::new();
        for rule in &self.deny_rules {
            rules.push(format!("deny:{}", rule_name(*rule)));
        }
        for rule in &self.stop_rules {
            rules.push(format!("stop:{}", rule_name(*rule)));
        }
        if rules.is_empty() {
            rules.push("monitor_only".to_string());
        }
        if !self.enabled_rules.is_empty() {
            let names: Vec<String> = self
                .enabled_rules
                .iter()
                .map(|rule| rule_name(*rule).to_string())
                .collect();
            rules.push(format!("enable:{}", names.join(",")));
        }
        if !self.disabled_rules.is_empty() {
            let names: Vec<String> = self
                .disabled_rules
                .iter()
                .map(|rule| rule_name(*rule).to_string())
                .collect();
            rules.push(format!("disable:{}", names.join(",")));
        }
        if self.proc_scan {
            rules.push(format!(
                "proc:{}ms/{}/maps{}/wx{}/io{}",
                self.proc_interval_ms,
                self.proc_max_pids,
                self.proc_map_samples,
                self.proc_wx_per_scan,
                self.proc_io_per_scan
            ));
        } else {
            rules.push("no_proc_scan".to_string());
        }
        rules.push(format!("correlate:{}ms", self.correlate_window_ms));
        if self.client_keys.is_empty() {
            rules.push("no_client_keys".to_string());
        } else {
            rules.push(format!("client_keys:{}", self.client_keys.len()));
        }
        rules.push(if self.audit_process {
            "audit_process".to_string()
        } else {
            "no_audit_process".to_string()
        });
        if self.audit_key.is_some() {
            rules.push("audit_key:custom".to_string());
        }
        if self.capture_requested() {
            let mode = if self.capture_file.is_some() { "file" } else { "iface" };
            rules.push(format!("capture:{}:{}", mode, self.capture_snaplen));
        } else {
            rules.push("no_capture".to_string());
        }
        if self.kernel_events.is_some() {
            rules.push("kernel:file".to_string());
        } else {
            rules.push("no_kernel_events".to_string());
        }
        rules.push(if self.kernel_sensor {
            "kernel_sensor".to_string()
        } else {
            "no_kernel_sensor".to_string()
        });
        rules.push(if self.lsm_enforce {
            "lsm_enforce".to_string()
        } else {
            "no_lsm_enforce".to_string()
        });
        rules.push(format!("lsm_mask:{:x}", self.lsm_mask));
        rules.push(if self.chain_guard {
            "chain_guard".to_string()
        } else {
            "no_chain_guard".to_string()
        });
        rules.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rule: u32, confidence: u32) -> Finding {
        Finding {
            rule,
            rule_name: rule_name(rule),
            source: "memory",
            severity: SEV_CRITICAL,
            confidence,
            evidence: 1,
            detail: "test".to_string(),
            decision: DECISION_ALLOW,
        }
    }

    #[test]
    fn monitor_mode_never_denies() {
        let policy = Policy::default();
        assert_eq!(policy.decision(&[sample(RULE_WX_TRANSITION, 950)], 100), DECISION_ALLOW);
    }

    #[test]
    fn guard_requires_rule_confidence_and_risk() {
        let mut policy = Policy::default();
        policy.guard_mode = true;
        policy.deny_rules.push(RULE_WX_TRANSITION);
        assert_eq!(policy.decision(&[sample(RULE_WX_TRANSITION, 950)], 20), DECISION_ALLOW);
        assert_eq!(policy.decision(&[sample(RULE_WX_TRANSITION, 500)], 90), DECISION_ALLOW);
        assert_eq!(policy.decision(&[sample(RULE_WX_TRANSITION, 950)], 90), DECISION_DENY);
        assert_eq!(policy.decision(&[sample(RULE_STACK_EXEC, 950)], 90), DECISION_ALLOW);
    }

    #[test]
    fn maps_raw_socket_rule_name() {
        assert_eq!(rule_from_name("raw_socket"), Some(RULE_RAW_SOCKET));
        assert_eq!(rule_from_name("not_a_rule"), None);
    }

    #[test]
    fn parses_command_line() {
        let args = vec![
            "ap".to_string(), "--guard".to_string(), "--deny".to_string(),
            "wx_transition,double_free".to_string(), "--trace".to_string(),
            "/bin/true".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert!(policy.guard_mode);
        assert_eq!(policy.deny_rules.len(), 2);
        assert_eq!(policy.trace_argv, vec!["/bin/true"]);
    }

    #[test]
    fn parses_ipc_strict_seq_flag() {
        assert!(!Policy::default().ipc_strict_seq);
        let policy = Policy::from_args(&["ap".to_string(), "--ipc-strict-seq".to_string()]).unwrap();
        assert!(policy.ipc_strict_seq);
    }

    #[test]
    fn parses_kernel_sensor_policy() {
        let policy = Policy::default();
        assert!(!policy.kernel_sensor);
        assert!(!policy.lsm_enforce);
        assert_eq!(policy.lsm_mask, 0);
        let summary = policy.summary();
        assert!(summary.contains("no_kernel_sensor"));
        assert!(summary.contains("no_lsm_enforce"));
        assert!(summary.contains("lsm_mask:0"));

        let args = vec![
            "ap".to_string(),
            "--kernel-sensor".to_string(),
            "--lsm-enforce".to_string(),
            "--lsm-mask".to_string(),
            "0xff".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert!(policy.kernel_sensor);
        assert!(policy.lsm_enforce);
        assert_eq!(policy.lsm_mask, 255);
        let summary = policy.summary();
        assert!(summary.contains("kernel_sensor"));
        assert!(summary.contains("lsm_enforce"));
        assert!(summary.contains("lsm_mask:ff"));

        let args = vec![
            "ap".to_string(),
            "--lsm-mask".to_string(),
            "4294967295".to_string(),
        ];
        assert_eq!(Policy::from_args(&args).unwrap().lsm_mask, 0xffff_ffff);
        for value in ["", "0x", "xyz", "4294967296", "-1", "0x1g"] {
            let args = vec!["ap".to_string(), "--lsm-mask".to_string(), value.to_string()];
            assert!(Policy::from_args(&args).is_err(), "accepted bad mask {}", value);
        }
    }

    #[test]
    fn maps_new_kernel_rule_names() {
        assert_eq!(rule_from_name("kernel_rootkit"), Some(RULE_KERNEL_ROOTKIT));
        assert_eq!(rule_from_name("credential_theft"), Some(RULE_CREDENTIAL_THEFT));
        assert_eq!(rule_from_name("persistence_chain"), Some(RULE_PERSISTENCE));
        assert_eq!(rule_from_name("container_escape"), Some(RULE_CONTAINER_ESCAPE));
        assert_eq!(rule_from_name("fileless_exec"), Some(RULE_FILELESS_EXEC));
        assert_eq!(rule_from_name("anti_analysis"), Some(RULE_ANTI_ANALYSIS));
        assert_eq!(rule_from_name("process_injection"), Some(RULE_PROCESS_INJECTION));
        assert_eq!(rule_from_name("exploit_chain"), Some(RULE_EXPLOIT_CHAIN));
        assert_eq!(rule_from_name("credential_dump"), Some(RULE_CREDENTIAL_DUMP));
    }

    #[test]
    fn maps_file_and_chain_rule_names() {
        assert_eq!(rule_from_name("file_write_burst"), Some(RULE_FILE_WRITE_BURST));
        assert_eq!(rule_from_name("destructive_chain"), Some(RULE_DESTRUCTIVE_CHAIN));
        assert_eq!(rule_from_name("data_exfiltration"), Some(RULE_DATA_EXFILTRATION));
        assert_eq!(rule_from_name("not_a_file_rule"), None);
    }

    #[test]
    fn parses_detector_selection() {
        let args = vec![
            "ap".to_string(),
            "--enable".to_string(),
            "wx_transition,tcp_flag_violation,wx_transition".to_string(),
            "--disable".to_string(),
            "double_free".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert_eq!(policy.enabled_rules, vec![RULE_WX_TRANSITION, RULE_TCP_FLAGS]);
        assert_eq!(policy.disabled_rules, vec![RULE_DOUBLE_FREE]);
    }

    #[test]
    fn parses_all_detector_selection() {
        let args = vec!["ap".to_string(), "--enable".to_string(), "all".to_string()];
        let policy = Policy::from_args(&args).unwrap();
        assert_eq!(policy.enabled_rules.len(), 32);
        assert!(policy.enabled_rules.contains(&RULE_KERNEL_CHAIN));
        assert!(policy.enabled_rules.contains(&RULE_ANTI_ANALYSIS));
        assert!(policy.enabled_rules.contains(&RULE_PROCESS_INJECTION));
        assert!(policy.enabled_rules.contains(&RULE_EXPLOIT_CHAIN));
        assert!(policy.enabled_rules.contains(&RULE_CREDENTIAL_DUMP));
        assert!(policy.enabled_rules.contains(&RULE_FILE_WRITE_BURST));
        assert!(policy.enabled_rules.contains(&RULE_DESTRUCTIVE_CHAIN));
        assert!(policy.enabled_rules.contains(&RULE_DATA_EXFILTRATION));
        let args = vec!["ap".to_string(), "--disable".to_string(), "all".to_string()];
        let policy = Policy::from_args(&args).unwrap();
        assert_eq!(policy.disabled_rules.len(), 32);
    }

    #[test]
    fn rejects_unknown_detector_name() {
        let args = vec!["ap".to_string(), "--enable".to_string(), "not_a_rule".to_string()];
        assert!(Policy::from_args(&args).is_err());
        let args = vec!["ap".to_string(), "--disable".to_string(), "all,not_a_rule".to_string()];
        assert!(Policy::from_args(&args).is_err());
    }

    #[test]
    fn parses_proc_scan_policy() {
        let policy = Policy::default();
        assert!(policy.proc_scan);
        assert_eq!(policy.proc_interval_ms, 1000);
        assert_eq!(policy.proc_max_pids, 256);
        assert_eq!(policy.proc_map_samples, ffi::COLLECTOR_DEFAULT_MAPS_PER_SCAN);
        assert_eq!(policy.proc_wx_per_scan, ffi::COLLECTOR_DEFAULT_WX_PER_SCAN);
        assert_eq!(policy.proc_io_per_scan, ffi::COLLECTOR_DEFAULT_IO_PER_SCAN);
        let args = vec![
            "ap".to_string(),
            "--proc-interval-ms".to_string(),
            "250".to_string(),
            "--proc-max-pids".to_string(),
            "64".to_string(),
            "--proc-map-samples".to_string(),
            "16".to_string(),
            "--proc-wx-per-scan".to_string(),
            "8".to_string(),
            "--proc-io-per-scan".to_string(),
            "12".to_string(),
            "--no-proc-scan".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert!(!policy.proc_scan);
        assert_eq!(policy.proc_interval_ms, 250);
        assert_eq!(policy.proc_max_pids, 64);
        assert_eq!(policy.proc_map_samples, 16);
        assert_eq!(policy.proc_wx_per_scan, 8);
        assert_eq!(policy.proc_io_per_scan, 12);
        assert!(policy.summary().contains("no_proc_scan"));
        let args = vec!["ap".to_string(), "--proc-interval-ms".to_string(), "10".to_string()];
        assert!(Policy::from_args(&args).is_err());
        let args = vec!["ap".to_string(), "--proc-max-pids".to_string(), "513".to_string()];
        assert!(Policy::from_args(&args).is_err());
        let args = vec!["ap".to_string(), "--proc-map-samples".to_string(), "33".to_string()];
        assert!(Policy::from_args(&args).is_err());
        let args = vec!["ap".to_string(), "--proc-wx-per-scan".to_string(), "17".to_string()];
        assert!(Policy::from_args(&args).is_err());
        for value in ["0", "33", "bad"] {
            let args = vec![
                "ap".to_string(),
                "--proc-io-per-scan".to_string(),
                value.to_string(),
            ];
            assert!(Policy::from_args(&args).is_err(), "accepted bad io limit {}", value);
        }
        let args = vec![
            "ap".to_string(),
            "--proc-io-per-scan".to_string(),
            "32".to_string(),
        ];
        assert_eq!(Policy::from_args(&args).unwrap().proc_io_per_scan, 32);
    }

    #[test]
    fn chain_guard_requires_explicit_guard_and_rules() {
        let args = vec![
            "ap".to_string(),
            "--chain-guard".to_string(),
            "--deny".to_string(),
            "destructive_chain".to_string(),
        ];
        assert!(Policy::from_args(&args).is_err());

        let args = vec!["ap".to_string(), "--guard".to_string(), "--chain-guard".to_string()];
        assert!(Policy::from_args(&args).is_err());

        let policy = Policy::from_args(&[
            "ap".to_string(),
            "--guard".to_string(),
            "--chain-guard".to_string(),
            "--deny".to_string(),
            "destructive_chain".to_string(),
        ])
        .unwrap();
        assert!(policy.chain_guard);
        assert!(policy.summary().contains(",chain_guard"));
        assert!(Policy::default().summary().contains("no_chain_guard"));
        assert_eq!(
            policy.decision(&[sample(RULE_DESTRUCTIVE_CHAIN, 950)], 90),
            DECISION_ALLOW
        );
        assert_eq!(
            policy.decision_with_chain(&[sample(RULE_DESTRUCTIVE_CHAIN, 950)], 90, true),
            DECISION_DENY
        );
    }

    #[test]
    fn parses_correlation_window_policy() {
        assert_eq!(Policy::default().correlate_window_ms, 5000);
        let args = vec![
            "ap".to_string(),
            "--correlate-window-ms".to_string(),
            "1500".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert_eq!(policy.correlate_window_ms, 1500);
        assert!(policy.summary().contains("correlate:1500ms"));
        for value in ["50", "60001"] {
            let args = vec![
                "ap".to_string(),
                "--correlate-window-ms".to_string(),
                value.to_string(),
            ];
            assert!(Policy::from_args(&args).is_err());
        }
    }

    #[test]
    fn parses_capture_policy() {
        let policy = Policy::default();
        assert!(!policy.capture_requested());
        assert_eq!(policy.capture_iface, "any");
        assert_eq!(policy.capture_snaplen, 63);
        assert!(policy.summary().contains("no_capture"));

        let args = vec![
            "ap".to_string(),
            "--capture".to_string(),
            "--capture-iface".to_string(),
            "eth0".to_string(),
            "--capture-snaplen".to_string(),
            "40".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert!(policy.capture_requested());
        assert_eq!(policy.capture_iface, "eth0");
        assert_eq!(policy.capture_snaplen, 40);
        assert!(policy.summary().contains("capture:iface:40"));

        let args = vec![
            "ap".to_string(),
            "--capture-file".to_string(),
            "/tmp/frames.bin".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert!(policy.capture_requested());
        assert!(policy.capture_file.is_some());
        assert!(policy.summary().contains("capture:file:63"));

        for value in ["19", "64"] {
            let args = vec![
                "ap".to_string(),
                "--capture-snaplen".to_string(),
                value.to_string(),
            ];
            assert!(Policy::from_args(&args).is_err());
        }
    }

    #[test]
    fn parses_kernel_event_file_policy() {
        assert!(Policy::default().kernel_events.is_none());
        assert!(Policy::default().summary().contains("no_kernel_events"));
        let args = vec![
            "ap".to_string(),
            "--kernel-events".to_string(),
            "/tmp/ap-kernel.apk1".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert_eq!(policy.kernel_events, Some(PathBuf::from("/tmp/ap-kernel.apk1")));
        assert!(policy.summary().contains("kernel:file"));
        let args = vec!["ap".to_string(), "--kernel-events".to_string(), "".to_string()];
        assert!(Policy::from_args(&args).is_err());
    }

    #[test]
    fn parses_client_key_mappings() {
        assert!(Policy::default().summary().contains("no_client_keys"));
        let args = vec![
            "ap".to_string(),
            "--client-key".to_string(),
            "120:/tmp/ap-client.key".to_string(),
            "--client-key".to_string(),
            "121:/tmp/ap-other.key".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert_eq!(policy.client_keys.len(), 2);
        assert_eq!(policy.client_keys[0].0, 120);
        assert_eq!(policy.client_keys[1].1, PathBuf::from("/tmp/ap-other.key"));
        assert!(policy.summary().contains("client_keys:2"));

        for value in ["0:/tmp/key", "120:", "bad:/tmp/key", "120"] {
            let args = vec!["ap".to_string(), "--client-key".to_string(), value.to_string()];
            assert!(Policy::from_args(&args).is_err());
        }
        let args = vec![
            "ap".to_string(),
            "--client-key".to_string(),
            "120:/tmp/key".to_string(),
            "--client-key".to_string(),
            "120:/tmp/other".to_string(),
        ];
        assert!(Policy::from_args(&args).is_err());
    }

    #[test]
    fn parses_audit_process_policy() {
        let policy = Policy::default();
        assert!(!policy.audit_process);
        assert!(policy.audit_key.is_none());
        assert!(policy.summary().contains("no_audit_process"));

        let args = vec![
            "ap".to_string(),
            "--audit-process".to_string(),
            "--audit-key".to_string(),
            "/tmp/ap-shared.key".to_string(),
        ];
        let policy = Policy::from_args(&args).unwrap();
        assert!(policy.audit_process);
        assert_eq!(policy.audit_key, Some(PathBuf::from("/tmp/ap-shared.key")));
        assert!(policy.summary().contains("audit_process"));
        assert!(policy.summary().contains("audit_key:custom"));

        let args = vec!["ap".to_string(), "--audit-key".to_string(), "".to_string()];
        assert!(Policy::from_args(&args).is_err());
    }
}
