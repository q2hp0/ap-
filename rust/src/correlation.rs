use crate::abi::*;
use crate::event::Finding;
use crate::ffi;
use std::ffi::{c_int, c_void, CString};

const EVAL_INTERVAL_NS: u64 = 500_000_000;

#[derive(Clone, Copy, Debug, Default)]
pub struct CorrelationStats {
    pub graph_added: u64,
    pub graph_evicted: u64,
    pub graph_findings: u64,
    pub graph_suppressed: u64,
    pub evidence_inserted: u64,
    pub evidence_duplicates: u64,
    pub evidence_evicted: u64,
    pub beacon_findings: u64,
    pub risk_findings: u64,
}

pub struct Correlation {
    graph: ffi::Graph,
    evidence: ffi::Evidence,
    beacon: *mut c_void,
    risk: *mut c_void,
    last_eval_ns: u64,
    stats: CorrelationStats,
}

fn event_text(event: &Event) -> String {
    let bytes = &event.text;
    let len = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn copy_key(out: &mut [u8], value: &str) {
    out.fill(0);
    let bytes = value.as_bytes();
    let len = bytes.len().min(out.len().saturating_sub(1));
    out[..len].copy_from_slice(&bytes[..len]);
}

fn c_string(value: &str) -> Option<CString> {
    CString::new(value).ok()
}

extern "C" fn on_graph(finding: *const ffi::GraphFinding, user: *mut c_void) -> c_int {
    if finding.is_null() || user.is_null() {
        return ERR_ARG;
    }
    let results = unsafe { &mut *(user as *mut ffi::CorrelationResults) };
    if results.graph_count as usize >= ffi::CORRELATION_RESULTS {
        return OK;
    }
    let at = results.graph_count as usize;
    results.graph[at] = unsafe { *finding };
    results.graph_count += 1;
    OK
}

extern "C" fn on_beacon(finding: *const ffi::BeaconFinding, user: *mut c_void) -> c_int {
    if finding.is_null() || user.is_null() {
        return ERR_ARG;
    }
    let results = unsafe { &mut *(user as *mut ffi::CorrelationResults) };
    if results.beacon_count as usize >= ffi::CORRELATION_RESULTS {
        return OK;
    }
    let at = results.beacon_count as usize;
    results.beacon[at] = unsafe { *finding };
    results.beacon_count += 1;
    OK
}

extern "C" fn on_risk(finding: *const ffi::RiskFinding, user: *mut c_void) -> c_int {
    if finding.is_null() || user.is_null() {
        return ERR_ARG;
    }
    let results = unsafe { &mut *(user as *mut ffi::CorrelationResults) };
    if results.risk_count as usize >= ffi::CORRELATION_RESULTS {
        return OK;
    }
    let at = results.risk_count as usize;
    results.risk[at] = unsafe { *finding };
    results.risk_count += 1;
    OK
}

fn text_key(value: &[u8]) -> String {
    let len = value.iter().position(|byte| *byte == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..len]).into_owned()
}

impl Correlation {
    pub fn new() -> Option<Self> {
        let mut graph: ffi::Graph = unsafe { std::mem::zeroed() };
        let mut evidence: ffi::Evidence = unsafe { std::mem::zeroed() };
        let beacon = unsafe { ffi::ap_beacon_new() };
        let risk = unsafe { ffi::ap_risk_new() };
        if beacon.is_null() || risk.is_null() {
            if !beacon.is_null() {
                unsafe { ffi::ap_beacon_free(beacon) };
            }
            if !risk.is_null() {
                unsafe { ffi::ap_risk_free(risk) };
            }
            return None;
        }
        unsafe {
            ffi::ap_graph_init(&mut graph);
            ffi::ap_evidence_init(&mut evidence);
        }
        Some(Self {
            graph,
            evidence,
            beacon,
            risk,
            last_eval_ns: 0,
            stats: CorrelationStats::default(),
        })
    }

    fn entity_key(&self, event: &Event) -> [u8; ffi::GRAPH_KEY_LEN] {
        let text = event_text(event);
        let value = if event.pid != 0 {
            format!("pid-{}", event.pid)
        } else if !text.is_empty() {
            text
        } else {
            "unknown".to_string()
        };
        let mut key = [0u8; ffi::GRAPH_KEY_LEN];
        copy_key(&mut key, &value);
        key
    }

    fn fallback_tactic(event: &Event) -> u32 {
        match event.kind {
            KIND_EXEC | KIND_PROC => ffi::TACTIC_EXECUTION,
            KIND_PRIV => ffi::TACTIC_PRIVILEGE_ESCALATION,
            KIND_MEMREGION | KIND_MEMPROT | KIND_HEAP | KIND_TRACE => {
                ffi::TACTIC_DEFENSE_EVASION
            }
            KIND_NET | KIND_FLOW => ffi::TACTIC_COMMAND_AND_CONTROL,
            KIND_FILE => ffi::TACTIC_IMPACT,
            _ => 0,
        }
    }

    fn label_info(&self, label: &str, event: &Event) -> (u32, u32, u32) {
        if !label.is_empty() {
            if let Some(name) = c_string(label) {
                let entry = unsafe { ffi::ap_taxonomy_find_name(name.as_ptr()) };
                if !entry.is_null() {
                    let value = unsafe { *entry };
                    return (
                        value.label_id,
                        value.tactic,
                        value.confidence_x1000,
                    );
                }
            }
        }
        (0, Self::fallback_tactic(event), event.confidence_x1000)
    }

    fn rule_tactic(rule: u32) -> u32 {
        match rule {
            RULE_KERNEL_ROOTKIT | RULE_ANTI_ANALYSIS => ffi::TACTIC_DEFENSE_EVASION,
            RULE_CREDENTIAL_THEFT => ffi::TACTIC_CREDENTIAL_ACCESS,
            RULE_PERSISTENCE => ffi::TACTIC_PERSISTENCE,
            RULE_CONTAINER_ESCAPE => ffi::TACTIC_PRIVILEGE_ESCALATION,
            RULE_FILELESS_EXEC => ffi::TACTIC_EXECUTION,
            RULE_BEACONING => ffi::TACTIC_COMMAND_AND_CONTROL,
            RULE_PROCESS_INJECTION => ffi::TACTIC_DEFENSE_EVASION,
            RULE_EXPLOIT_CHAIN => ffi::TACTIC_PRIVILEGE_ESCALATION,
            RULE_CREDENTIAL_DUMP => ffi::TACTIC_CREDENTIAL_ACCESS,
            RULE_FILE_WRITE_BURST | RULE_DESTRUCTIVE_CHAIN => ffi::TACTIC_IMPACT,
            RULE_DATA_EXFILTRATION => ffi::TACTIC_EXFILTRATION,
            RULE_WX_REGION | RULE_WX_TRANSITION | RULE_STACK_EXEC |
            RULE_RETURN_OUTSIDE_EXEC | RULE_EXEC_AFTER_WX => ffi::TACTIC_DEFENSE_EVASION,
            RULE_MODULE_LOAD | RULE_KERNEL_IFACE | RULE_KERNEL_CHAIN => {
                ffi::TACTIC_PRIVILEGE_ESCALATION
            }
            RULE_TCP_STATE | RULE_TCP_FLAGS | RULE_IP_MALFORMED |
            RULE_FRAG_OVERLAP | RULE_RAW_SOCKET => ffi::TACTIC_COMMAND_AND_CONTROL,
            RULE_HEAP_CANARY | RULE_DOUBLE_FREE | RULE_INVALID_FREE => {
                ffi::TACTIC_IMPACT
            }
            _ => ffi::TACTIC_DISCOVERY,
        }
    }

    pub fn observe(&mut self, event: &Event, now_ns: u64, findings: &[Finding]) {
        let key = self.entity_key(event);
        let text = event_text(event);
        let (label_id, tactic, confidence) = self.label_info(&text, event);
        if tactic != 0 {
            let observation = ffi::GraphObservation {
                ts_ns: now_ns,
                pid: event.pid,
                tactic,
                label_id,
                confidence_x1000: confidence,
                key,
            };
            unsafe {
                ffi::ap_graph_add(&mut self.graph, &observation);
            }
        }

        for finding in findings {
            let evidence_key = format!("{}:{}", text_key(&key), finding.rule);
            if let Some(name) = c_string(&evidence_key) {
                unsafe {
                    ffi::ap_evidence_add_once(
                        &mut self.evidence,
                        now_ns,
                        event.pid,
                        finding.rule,
                        finding.confidence,
                        name.as_ptr(),
                    );
                }
            }
            let mut signal_key = [0u8; ffi::RISK_KEY_LEN];
            copy_key(&mut signal_key, &text_key(&key));
            let signal = ffi::RiskSignal {
                ts_ns: now_ns,
                rule: finding.rule,
                tactic: Self::rule_tactic(finding.rule),
                confidence_x1000: finding.confidence,
                key: signal_key,
            };
            unsafe {
                ffi::ap_risk_add(self.risk, &signal);
            }
        }

        if event.kind == KIND_NET || event.kind == KIND_FLOW {
            let peer = if text.is_empty() {
                format!("peer-{}-{}", event.pid, event.arg[0])
            } else {
                text
            };
            let mut peer_key = [0u8; ffi::BEACON_KEY_LEN];
            copy_key(&mut peer_key, &peer);
            let observation = ffi::BeaconObservation {
                ts_ns: now_ns,
                peer: peer_key,
                bytes_out: event.arg[0].min(u64::from(u32::MAX)) as u32,
                flags: event.subkind,
            };
            unsafe {
                ffi::ap_beacon_add(self.beacon, &observation);
            }
        }
    }

    pub fn maybe_evaluate(&mut self, now_ns: u64, findings: &mut Vec<Finding>) {
        if self.last_eval_ns != 0 && now_ns.saturating_sub(self.last_eval_ns) < EVAL_INTERVAL_NS {
            return;
        }
        self.last_eval_ns = now_ns;
        let mut results = ffi::CorrelationResults::default();
        let user = &mut results as *mut ffi::CorrelationResults as *mut c_void;
        unsafe {
            ffi::ap_graph_evaluate(&mut self.graph, now_ns, on_graph, user);
            ffi::ap_beacon_evaluate(self.beacon, now_ns, on_beacon, user);
            ffi::ap_risk_evaluate(self.risk, now_ns, on_risk, user);
        }

        for index in 0..results.graph_count as usize {
            let value = results.graph[index];
            self.stats.graph_findings += 1;
            findings.push(Finding {
                rule: RULE_CORRELATED,
                rule_name: crate::event::rule_name(RULE_CORRELATED),
                source: "graph",
                severity: SEV_HIGH,
                confidence: value.confidence_x1000.min(1000),
                evidence: value.nodes as u64,
                detail: format!(
                    "attack_graph:{}:tactics={}:nodes={}",
                    text_key(&value.key), value.tactics, value.nodes
                ),
                decision: DECISION_ALLOW,
            });
        }
        for index in 0..results.beacon_count as usize {
            let value = results.beacon[index];
            self.stats.beacon_findings += 1;
            findings.push(Finding {
                rule: RULE_BEACONING,
                rule_name: crate::event::rule_name(RULE_BEACONING),
                source: "network",
                severity: SEV_MEDIUM,
                confidence: value.score_x1000.min(1000),
                evidence: value.connections as u64,
                detail: format!(
                    "beacon:{}:connections={}:jitter_ns={}",
                    text_key(&value.peer), value.connections, value.jitter_ns
                ),
                decision: DECISION_ALLOW,
            });
        }
        for index in 0..results.risk_count as usize {
            let value = results.risk[index];
            self.stats.risk_findings += 1;
            findings.push(Finding {
                rule: RULE_CORRELATED,
                rule_name: crate::event::rule_name(RULE_CORRELATED),
                source: "risk",
                severity: SEV_HIGH,
                confidence: value.score_x1000.min(1000),
                evidence: value.high_rules as u64,
                detail: format!(
                    "risk:{}:score={}:signals={}",
                    text_key(&value.key), value.score_x1000, value.signals
                ),
                decision: DECISION_ALLOW,
            });
        }

        unsafe {
            ffi::ap_graph_stats(
                &self.graph,
                &mut self.stats.graph_added,
                &mut self.stats.graph_evicted,
                &mut self.stats.graph_findings,
                &mut self.stats.graph_suppressed,
            );
            ffi::ap_evidence_stats(
                &self.evidence,
                &mut self.stats.evidence_inserted,
                &mut self.stats.evidence_duplicates,
                &mut self.stats.evidence_evicted,
            );
        }
    }

    pub fn stats(&self) -> CorrelationStats {
        self.stats
    }
}

impl Drop for Correlation {
    fn drop(&mut self) {
        unsafe {
            if !self.beacon.is_null() {
                ffi::ap_beacon_free(self.beacon);
            }
            if !self.risk.is_null() {
                ffi::ap_risk_free(self.risk);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u16, pid: i64, text: &str) -> Event {
        let mut value: Event = unsafe { std::mem::zeroed() };
        value.size = EVENT_SIZE as u32;
        value.abi_version = ABI_VERSION;
        value.kind = kind;
        value.pid = pid;
        value.tid = pid;
        value.ts_ns = 1;
        value.confidence_x1000 = 800;
        copy_key(&mut value.text, text);
        value
    }

    #[test]
    fn correlation_starts_empty() {
        let value = Correlation::new().expect("correlation allocation");
        let stats = value.stats();
        assert_eq!(stats.graph_added, 0);
        assert_eq!(stats.graph_findings, 0);
        assert_eq!(stats.beacon_findings, 0);
    }

    #[test]
    fn taxonomy_mapping_is_bounded() {
        let value = Correlation::new().expect("correlation allocation");
        let info = value.label_info("kernel_rootkit", &event(KIND_KERNEL, 7, "kernel_rootkit"));
        assert_eq!(info.0, ffi::LABEL_ROOTKIT);
        assert_eq!(info.1, ffi::TACTIC_DEFENSE_EVASION);
        assert_eq!(info.2, 900);
        let fallback = value.label_info("unmapped", &event(KIND_NET, 7, "unmapped"));
        assert_eq!(fallback.1, ffi::TACTIC_COMMAND_AND_CONTROL);
    }

    #[test]
    fn rule_tactic_covers_new_rules() {
        assert_eq!(Correlation::rule_tactic(RULE_BEACONING), ffi::TACTIC_COMMAND_AND_CONTROL);
        assert_eq!(Correlation::rule_tactic(RULE_PERSISTENCE), ffi::TACTIC_PERSISTENCE);
        assert_eq!(Correlation::rule_tactic(RULE_PROCESS_INJECTION), ffi::TACTIC_DEFENSE_EVASION);
        assert_eq!(Correlation::rule_tactic(RULE_EXPLOIT_CHAIN), ffi::TACTIC_PRIVILEGE_ESCALATION);
        assert_eq!(Correlation::rule_tactic(RULE_CREDENTIAL_DUMP), ffi::TACTIC_CREDENTIAL_ACCESS);
    }
}
