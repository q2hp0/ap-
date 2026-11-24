use crate::abi::{
    DECISION_ALLOW, DECISION_DENY, DECISION_STOP, RULE_CONTAINER_ESCAPE, RULE_CREDENTIAL_DUMP,
    RULE_DESTRUCTIVE_CHAIN, RULE_EXPLOIT_CHAIN, RULE_FILELESS_EXEC, RULE_FILE_WRITE_BURST,
    RULE_KERNEL_CHAIN, RULE_KERNEL_ROOTKIT, RULE_PERSISTENCE, RULE_PRIV_CROSSING,
    RULE_PROCESS_INJECTION, RULE_DATA_EXFILTRATION,
};
use crate::event::{rule_name, Finding};
use crate::policy::Policy;

#[derive(Clone, Debug, Default)]
pub struct GuardStats {
    pub alerts: u64,
    pub denials: u64,
    pub stops: u64,
    pub chain_findings: u64,
}

const CHAIN_PID_SLOTS: usize = 64;
const CHAIN_WINDOW_NS: u64 = 10_000_000_000;
const CHAIN_MIN_DISTINCT: u32 = 3;

#[derive(Clone, Copy, Default)]
struct ChainState {
    pid: i64,
    first_ns: u64,
    last_ns: u64,
    mask: u64,
    rules: u32,
    used: bool,
    reported: bool,
}

struct ChainTracker {
    slots: [ChainState; CHAIN_PID_SLOTS],
    cursor: usize,
}

impl ChainTracker {
    fn new() -> Self {
        Self {
            slots: [ChainState::default(); CHAIN_PID_SLOTS],
            cursor: 0,
        }
    }

    fn chain_rule(rule: u32) -> bool {
        matches!(
            rule,
            RULE_FILE_WRITE_BURST
                | RULE_DESTRUCTIVE_CHAIN
                | RULE_DATA_EXFILTRATION
                | RULE_PROCESS_INJECTION
                | RULE_EXPLOIT_CHAIN
                | RULE_CREDENTIAL_DUMP
                | RULE_KERNEL_ROOTKIT
                | RULE_PERSISTENCE
                | RULE_CONTAINER_ESCAPE
                | RULE_FILELESS_EXEC
                | RULE_KERNEL_CHAIN
                | RULE_PRIV_CROSSING
        )
    }

    fn slot(&mut self, pid: i64, now_ns: u64) -> &mut ChainState {
        let found = self.slots.iter().position(|slot| slot.used && slot.pid == pid);
        let is_new = found.is_none();
        let at = match found {
            Some(index) => index,
            None => {
                let index = self.cursor;
                self.cursor = (self.cursor + 1) % CHAIN_PID_SLOTS;
                index
            }
        };
        let slot = &mut self.slots[at];
        if is_new {
            *slot = ChainState {
                pid,
                first_ns: now_ns,
                last_ns: now_ns,
                used: true,
                ..ChainState::default()
            };
        }
        slot
    }

    fn observe(
        &mut self,
        policy: &Policy,
        findings: &[Finding],
        now_ns: u64,
        pid: i64,
    ) -> (bool, bool) {
        if !policy.chain_guard || pid <= 0 {
            return (false, false);
        }
        let mut mask = 0u64;
        for finding in findings {
            if finding.confidence >= policy.min_confidence && Self::chain_rule(finding.rule) {
                mask |= 1u64 << finding.rule;
            }
        }
        if mask == 0u64 {
            return (false, false);
        }
        let (ready, crossed) = {
            let slot = self.slot(pid, now_ns);
            if now_ns < slot.first_ns || now_ns.saturating_sub(slot.first_ns) > CHAIN_WINDOW_NS {
                *slot = ChainState {
                    pid,
                    first_ns: now_ns,
                    last_ns: now_ns,
                    used: true,
                    ..ChainState::default()
                };
            }
            slot.mask |= mask;
            slot.last_ns = now_ns;
            slot.rules = slot.mask.count_ones();
            let ready = slot.rules >= CHAIN_MIN_DISTINCT;
            let crossed = ready && !slot.reported;
            if ready {
                slot.reported = true;
            }
            (ready, crossed)
        };
        (ready, crossed)
    }
}

pub struct Guard {
    pub stats: GuardStats,
    audit: Vec<String>,
    max_audit: usize,
    chain: ChainTracker,
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", value)
}

pub fn enforcement_report(
    guard_mode: bool,
    tracing: bool,
    ptrace: bool,
    seccomp: bool,
    hardened: bool,
    lsm_active: bool,
    lsm_denies: u64,
) -> [(&'static str, String); 8] {
    let backend = if !guard_mode {
        "monitor_only"
    } else if tracing && ptrace && seccomp {
        "ptrace_seccomp_stop"
    } else if tracing && ptrace {
        "ptrace_stop"
    } else {
        "observational"
    };
    let seccomp_state = if tracing && seccomp {
        "child_filter"
    } else if hardened {
        "engine_filter"
    } else if seccomp {
        "available_unused"
    } else {
        "unavailable"
    };
    let ptrace_state = if tracing && ptrace {
        "child_stop"
    } else if ptrace {
        "available_unused"
    } else {
        "unavailable"
    };
    [
        ("backend", quoted(backend)),
        ("lsm", quoted(if lsm_active { "bpf_lsm" } else { "unavailable" })),
        ("seccomp", quoted(seccomp_state)),
        ("ptrace", quoted(ptrace_state)),
        ("scope", quoted(if tracing { "supervised_child" } else { "none" })),
        ("kernel_compromise", quoted("unprotected")),
        (
            "note",
            quoted("telemetry cannot protect the kernel after compromise; external findings are observational"),
        ),
        ("lsm_denies", lsm_denies.to_string()),
    ]
}

impl Guard {
    pub fn new(max_audit: usize) -> Self {
        Self {
            stats: GuardStats::default(),
            audit: Vec::with_capacity(max_audit.min(1024)),
            max_audit,
            chain: ChainTracker::new(),
        }
    }

    pub fn apply(&mut self, policy: &Policy, findings: &[Finding], risk_score: u32) -> i32 {
        let decision = policy.decision(findings, risk_score);
        self.finish(policy, findings, decision)
    }

    pub fn apply_event(
        &mut self,
        policy: &Policy,
        findings: &[Finding],
        risk_score: u32,
        now_ns: u64,
        pid: i64,
    ) -> i32 {
        let (chain_ready, crossed) = self.chain.observe(policy, findings, now_ns, pid);
        if crossed {
            self.stats.chain_findings += 1;
        }
        let decision = policy.decision_with_chain(findings, risk_score, chain_ready);
        self.finish(policy, findings, decision)
    }

    fn finish(&mut self, policy: &Policy, findings: &[Finding], decision: i32) -> i32 {
        if findings.is_empty() {
            return DECISION_ALLOW;
        }
        if decision == DECISION_ALLOW {
            self.stats.alerts += 1;
        } else {
            match decision {
                DECISION_DENY => self.stats.denials += 1,
                DECISION_STOP => self.stats.stops += 1,
                _ => {}
            }
            let rule = findings
                .iter()
                .filter(|finding| {
                    finding.confidence >= policy.min_confidence
                        && (policy.deny_rules.contains(&finding.rule)
                            || policy.stop_rules.contains(&finding.rule))
                })
                .max_by_key(|finding| finding.confidence)
                .map(|finding| rule_name(finding.rule))
                .unwrap_or("unknown");
            self.record(rule, decision);
        }
        decision
    }

    pub fn record(&mut self, rule: &str, decision: i32) {
        let action = match decision {
            DECISION_DENY => "denied",
            DECISION_STOP => "stopped",
            _ => "alerted",
        };
        if self.audit.len() == self.max_audit {
            self.audit.remove(0);
        }
        self.audit.push(format!("{}:{}", action, rule));
    }

    pub fn audit(&self) -> &[String] {
        &self.audit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::*;
    use crate::event::{rule_name, Finding};

    fn finding() -> Finding {
        finding_rule(RULE_WX_TRANSITION)
    }

    fn finding_rule(rule: u32) -> Finding {
        Finding {
            rule,
            rule_name: rule_name(rule),
            source: "memory",
            severity: SEV_CRITICAL,
            confidence: 950,
            evidence: 1,
            detail: "test".to_string(),
            decision: DECISION_ALLOW,
        }
    }

    #[test]
    fn deny_is_audited_and_bounded() {
        let mut policy = Policy::default();
        policy.guard_mode = true;
        policy.deny_rules.push(RULE_WX_TRANSITION);
        let mut guard = Guard::new(2);
        assert_eq!(guard.apply(&policy, &[finding()], 90), DECISION_DENY);
        assert_eq!(guard.apply(&policy, &[finding()], 90), DECISION_DENY);
        assert_eq!(guard.apply(&policy, &[finding()], 90), DECISION_DENY);
        assert_eq!(guard.audit().len(), 2);
        assert_eq!(guard.stats.denials, 3);
    }

    #[test]
    fn enforcement_report_names_real_backends() {
        let report = enforcement_report(true, true, true, true, false, false, 0);
        assert_eq!(report[0].1, "\"ptrace_seccomp_stop\"");
        assert_eq!(report[1].1, "\"unavailable\"");
        assert_eq!(report[5].1, "\"unprotected\"");
        assert!(report[6].1.contains("cannot protect the kernel"));
        assert_eq!(report[7].1, "0");
    }

    #[test]
    fn enforcement_report_reports_lsm_without_claiming_kernel_protection() {
        let report = enforcement_report(true, false, true, true, true, true, 7);
        assert_eq!(report[1].1, "\"bpf_lsm\"");
        assert_eq!(report[5].1, "\"unprotected\"");
        assert_eq!(report[7].1, "7");
    }

    #[test]
    fn enforcement_report_without_trace_is_observational() {
        let report = enforcement_report(true, false, true, true, true, false, 0);
        assert_eq!(report[0].1, "\"observational\"");
        assert_eq!(report[2].1, "\"engine_filter\"");
        assert_eq!(report[3].1, "\"available_unused\"");
        assert_eq!(report[4].1, "\"none\"");
    }

    #[test]
    fn monitor_mode_counts_alerts_only() {
        let mut guard = Guard::new(4);
        assert_eq!(guard.apply(&Policy::default(), &[finding()], 90), DECISION_ALLOW);
        assert_eq!(guard.stats.alerts, 1);
        assert_eq!(guard.stats.denials, 0);
    }

    fn chain_policy() -> Policy {
        let policy = Policy::from_args(&[
            "ap".to_string(),
            "--guard".to_string(),
            "--chain-guard".to_string(),
            "--deny".to_string(),
            "destructive_chain".to_string(),
        ])
        .unwrap();
        policy
    }

    #[test]
    fn chain_guard_requires_distinct_high_value_rules() {
        let policy = chain_policy();
        let mut guard = Guard::new(8);
        let burst = [finding_rule(RULE_FILE_WRITE_BURST)];
        assert_eq!(
            guard.apply_event(&policy, &burst, 90, 1_000_000_000, 410),
            DECISION_ALLOW
        );
        let exfil = [finding_rule(RULE_DATA_EXFILTRATION)];
        assert_eq!(
            guard.apply_event(&policy, &exfil, 90, 2_000_000_000, 410),
            DECISION_ALLOW
        );
        let chain = [finding_rule(RULE_DESTRUCTIVE_CHAIN)];
        assert_eq!(
            guard.apply_event(&policy, &chain, 90, 3_000_000_000, 410),
            DECISION_DENY
        );
        assert_eq!(guard.stats.chain_findings, 1);
        assert_eq!(guard.stats.denials, 1);
        assert_eq!(guard.audit(), &["denied:destructive_chain"]);
    }

    #[test]
    fn chain_guard_window_and_reported_flag_bound_escalation() {
        let policy = chain_policy();
        let mut guard = Guard::new(8);
        for (index, rule) in [
            RULE_FILE_WRITE_BURST,
            RULE_DATA_EXFILTRATION,
            RULE_DESTRUCTIVE_CHAIN,
        ]
        .iter()
        .enumerate()
        {
            let item = [finding_rule(*rule)];
            let at = (index as u64 + 1) * 1_000_000_000;
            let expected = if index == 2 { DECISION_DENY } else { DECISION_ALLOW };
            assert_eq!(guard.apply_event(&policy, &item, 90, at, 411), expected);
        }
        let late = [finding_rule(RULE_DESTRUCTIVE_CHAIN)];
        assert_eq!(
            guard.apply_event(&policy, &late, 90, 30_000_000_000, 411),
            DECISION_ALLOW
        );
        assert_eq!(guard.stats.chain_findings, 1);
    }

    #[test]
    fn ordinary_guard_does_not_depend_on_chain_state() {
        let mut policy = Policy::default();
        policy.guard_mode = true;
        policy.deny_rules.push(RULE_WX_TRANSITION);
        let mut guard = Guard::new(8);
        assert_eq!(
            guard.apply_event(&policy, &[finding()], 90, 1_000_000_000, 412),
            DECISION_DENY
        );
        assert_eq!(guard.stats.chain_findings, 0);
    }
}
