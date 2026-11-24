use crate::abi::*;
use crate::cli::{escape, Cli};
use crate::event::Finding;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectorInfo {
    pub rule: u32,
    pub name: &'static str,
    pub family: &'static str,
    pub telemetry: &'static [&'static str],
    pub severity: u32,
    pub confidence: u32,
    pub cost: &'static str,
    pub limits: &'static str,
}

pub const DETECTORS: [DetectorInfo; 32] = [
    DetectorInfo {
        rule: RULE_WX_REGION,
        name: "wx_region",
        family: "memory",
        telemetry: &["memory_region"],
        severity: SEV_CRITICAL,
        confidence: 940,
        cost: "low",
        limits: "labeled writable-executable regions only",
    },
    DetectorInfo {
        rule: RULE_WX_TRANSITION,
        name: "wx_transition",
        family: "memory",
        telemetry: &["mprotect", "mmap"],
        severity: SEV_CRITICAL,
        confidence: 900,
        cost: "low",
        limits: "protection arguments from watched calls",
    },
    DetectorInfo {
        rule: RULE_STACK_EXEC,
        name: "stack_exec",
        family: "memory",
        telemetry: &["flow_stack"],
        severity: SEV_CRITICAL,
        confidence: 960,
        cost: "low",
        limits: "flow telemetry must report the stack pointer",
    },
    DetectorInfo {
        rule: RULE_RETURN_OUTSIDE_EXEC,
        name: "return_outside_exec",
        family: "control_flow",
        telemetry: &["flow_return_site", "executable_ranges"],
        severity: SEV_HIGH,
        confidence: 880,
        cost: "medium",
        limits: "weak return sites need corroboration",
    },
    DetectorInfo {
        rule: RULE_SHADOW_MISMATCH,
        name: "shadow_mismatch",
        family: "control_flow",
        telemetry: &["flow_shadow"],
        severity: SEV_HIGH,
        confidence: 900,
        cost: "low",
        limits: "shadow telemetry must be supplied",
    },
    DetectorInfo {
        rule: RULE_PRIV_CROSSING,
        name: "privilege_crossing",
        family: "kernel",
        telemetry: &["privilege_change", "kernel_label", "time_window"],
        severity: SEV_HIGH,
        confidence: 860,
        cost: "low",
        limits: "weak setid needs kernel corroboration or a uid delta",
    },
    DetectorInfo {
        rule: RULE_MODULE_LOAD,
        name: "module_load",
        family: "kernel",
        telemetry: &["kernel_label"],
        severity: SEV_CRITICAL,
        confidence: 800,
        cost: "low",
        limits: "label based, not module signature verification",
    },
    DetectorInfo {
        rule: RULE_KERNEL_IFACE,
        name: "kernel_interface",
        family: "kernel",
        telemetry: &["kernel_label"],
        severity: SEV_HIGH,
        confidence: 700,
        cost: "low",
        limits: "watched kernel interfaces only",
    },
    DetectorInfo {
        rule: RULE_TCP_STATE,
        name: "tcp_state_violation",
        family: "network",
        telemetry: &["network_packet", "tcp_state"],
        severity: SEV_HIGH,
        confidence: 840,
        cost: "medium",
        limits: "packet hex input, bounded flow table",
    },
    DetectorInfo {
        rule: RULE_TCP_FLAGS,
        name: "tcp_flag_violation",
        family: "network",
        telemetry: &["network_packet", "tcp_header"],
        severity: SEV_HIGH,
        confidence: 940,
        cost: "medium",
        limits: "packet hex input, parser coverage limits apply",
    },
    DetectorInfo {
        rule: RULE_IP_MALFORMED,
        name: "ip_malformed",
        family: "network",
        telemetry: &["network_packet", "ip_header"],
        severity: SEV_HIGH,
        confidence: 900,
        cost: "medium",
        limits: "bounded header and extension checks",
    },
    DetectorInfo {
        rule: RULE_FRAG_OVERLAP,
        name: "fragment_overlap",
        family: "network",
        telemetry: &["network_fragment"],
        severity: SEV_HIGH,
        confidence: 860,
        cost: "medium",
        limits: "bounded fragment table",
    },
    DetectorInfo {
        rule: RULE_HEAP_CANARY,
        name: "heap_canary",
        family: "memory",
        telemetry: &["heap_canary"],
        severity: SEV_HIGH,
        confidence: 930,
        cost: "low",
        limits: "allocator shim only",
    },
    DetectorInfo {
        rule: RULE_DOUBLE_FREE,
        name: "double_free",
        family: "memory",
        telemetry: &["heap_free"],
        severity: SEV_HIGH,
        confidence: 930,
        cost: "low",
        limits: "allocator shim only",
    },
    DetectorInfo {
        rule: RULE_INVALID_FREE,
        name: "invalid_free",
        family: "memory",
        telemetry: &["heap_free"],
        severity: SEV_MEDIUM,
        confidence: 700,
        cost: "low",
        limits: "allocator shim only",
    },
    DetectorInfo {
        rule: RULE_CORRELATED,
        name: "correlated_exploit_indicators",
        family: "behavior",
        telemetry: &["entity_stage", "binary_link", "peer_link", "uid_link"],
        severity: SEV_HIGH,
        confidence: 880,
        cost: "medium",
        limits: "bounded cross entity stage graph in a configurable window",
    },
    DetectorInfo {
        rule: RULE_RAW_SOCKET,
        name: "raw_socket",
        family: "network",
        telemetry: &["socket_open"],
        severity: SEV_HIGH,
        confidence: 800,
        cost: "low",
        limits: "socket flags from watched calls",
    },
    DetectorInfo {
        rule: RULE_EXEC_AFTER_WX,
        name: "exec_after_wx",
        family: "memory",
        telemetry: &["memory_region", "process_exec"],
        severity: SEV_CRITICAL,
        confidence: 870,
        cost: "medium",
        limits: "bounded per pid stale window",
    },
    DetectorInfo {
        rule: RULE_KERNEL_CHAIN,
        name: "kernel_chain",
        family: "behavior",
        telemetry: &["kernel_label", "time_window"],
        severity: SEV_CRITICAL,
        confidence: 880,
        cost: "medium",
        limits: "bounded per pid label sequence, not syscall proof",
    },
    DetectorInfo {
        rule: RULE_KERNEL_ROOTKIT,
        name: "kernel_rootkit",
        family: "kernel",
        telemetry: &["ksensor"],
        severity: SEV_CRITICAL,
        confidence: 900,
        cost: "low",
        limits: "kernel sensor label only, not rootkit signature proof",
    },
    DetectorInfo {
        rule: RULE_CREDENTIAL_THEFT,
        name: "credential_theft",
        family: "kernel",
        telemetry: &["ksensor", "proc"],
        severity: SEV_CRITICAL,
        confidence: 870,
        cost: "low",
        limits: "credential label from kernel sensor, correlate with process context",
    },
    DetectorInfo {
        rule: RULE_PERSISTENCE,
        name: "persistence_chain",
        family: "behavior",
        telemetry: &["ksensor", "proc"],
        severity: SEV_CRITICAL,
        confidence: 880,
        cost: "high",
        limits: "bounded correlated kernel and process labels",
    },
    DetectorInfo {
        rule: RULE_CONTAINER_ESCAPE,
        name: "container_escape",
        family: "behavior",
        telemetry: &["ksensor", "proc"],
        severity: SEV_CRITICAL,
        confidence: 900,
        cost: "medium",
        limits: "bounded correlated namespace, mount, and credential labels",
    },
    DetectorInfo {
        rule: RULE_FILELESS_EXEC,
        name: "fileless_exec",
        family: "kernel",
        telemetry: &["ksensor"],
        severity: SEV_HIGH,
        confidence: 850,
        cost: "low",
        limits: "kernel sensor label only, no in-memory payload inspection",
    },
    DetectorInfo {
        rule: RULE_ANTI_ANALYSIS,
        name: "anti_analysis",
        family: "kernel",
        telemetry: &["ksensor"],
        severity: SEV_HIGH,
        confidence: 820,
        cost: "low",
        limits: "kernel sensor label only, not evasion proof",
    },
    DetectorInfo {
        rule: RULE_BEACONING,
        name: "beaconing",
        family: "network",
        telemetry: &["network_peer", "timing", "byte_count"],
        severity: SEV_MEDIUM,
        confidence: 700,
        cost: "medium",
        limits: "timing regularity only; legitimate pollers can match",
    },
    DetectorInfo {
        rule: RULE_PROCESS_INJECTION,
        name: "process_injection",
        family: "behavior",
        telemetry: &["kernel_label", "memory_protection", "process_exec", "flow_return_site"],
        severity: SEV_CRITICAL,
        confidence: 870,
        cost: "medium",
        limits: "bounded per pid stage window, not code injection proof",
    },
    DetectorInfo {
        rule: RULE_EXPLOIT_CHAIN,
        name: "exploit_chain",
        family: "behavior",
        telemetry: &["memory_region", "control_flow", "privilege_change", "network_peer"],
        severity: SEV_CRITICAL,
        confidence: 890,
        cost: "medium",
        limits: "bounded per pid stage sequence, not exploit proof",
    },
    DetectorInfo {
        rule: RULE_CREDENTIAL_DUMP,
        name: "credential_dump",
        family: "behavior",
        telemetry: &["kernel_label", "remote_read", "privilege_change", "network_peer"],
        severity: SEV_CRITICAL,
        confidence: 900,
        cost: "medium",
        limits: "bounded per pid stage window, no memory content inspection",
    },
    DetectorInfo {
        rule: RULE_FILE_WRITE_BURST,
        name: "file_write_burst",
        family: "file",
        telemetry: &["file_io", "proc_io_delta"],
        severity: SEV_HIGH,
        confidence: 870,
        cost: "low",
        limits: "sampled process-wide /proc io counters, not per-file writes",
    },
    DetectorInfo {
        rule: RULE_DESTRUCTIVE_CHAIN,
        name: "destructive_chain",
        family: "behavior",
        telemetry: &["file_io", "file_action", "kernel_label", "time_window"],
        severity: SEV_CRITICAL,
        confidence: 900,
        cost: "medium",
        limits: "bounded stage correlation, no file content or path proof",
    },
    DetectorInfo {
        rule: RULE_DATA_EXFILTRATION,
        name: "data_exfiltration",
        family: "behavior",
        telemetry: &["file_io", "network_peer", "time_window"],
        severity: SEV_HIGH,
        confidence: 880,
        cost: "medium",
        limits: "bounded sampled volume and peer timing heuristic, no payload inspection",
    },
];

#[derive(Clone, Debug)]
pub struct DetectorRegistry {
    enabled: BTreeSet<u32>,
}

fn telemetry_json(values: &[&str]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", escape(value)))
        .collect();
    format!("[{}]", items.join(","))
}

impl DetectorRegistry {
    pub fn new(enabled: &[u32], disabled: &[u32]) -> Self {
        let mut active: BTreeSet<u32> = if enabled.is_empty() {
            DETECTORS.iter().map(|info| info.rule).collect()
        } else {
            enabled
                .iter()
                .copied()
                .filter(|rule| DETECTORS.iter().any(|info| info.rule == *rule))
                .collect()
        };
        for rule in disabled {
            active.remove(rule);
        }
        Self { enabled: active }
    }

    pub fn from_policy(policy: &crate::policy::Policy) -> Self {
        Self::new(&policy.enabled_rules, &policy.disabled_rules)
    }

    pub fn is_enabled(&self, rule: u32) -> bool {
        self.enabled.contains(&rule)
    }

    pub fn enabled_count(&self) -> usize {
        self.enabled.len()
    }

    pub fn total_count(&self) -> usize {
        DETECTORS.len()
    }

    pub fn enabled_rules(&self) -> Vec<u32> {
        self.enabled.iter().copied().collect()
    }

    pub fn disabled_rules(&self) -> Vec<u32> {
        DETECTORS
            .iter()
            .map(|info| info.rule)
            .filter(|rule| !self.enabled.contains(rule))
            .collect()
    }

    pub fn filter(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|finding| self.is_enabled(finding.rule))
            .collect()
    }

    pub fn net_enabled(&self) -> bool {
        [
            RULE_TCP_STATE,
            RULE_TCP_FLAGS,
            RULE_IP_MALFORMED,
            RULE_FRAG_OVERLAP,
        ]
        .iter()
        .any(|rule| self.is_enabled(*rule))
    }

    pub fn flow_enabled(&self) -> bool {
        [
            RULE_WX_REGION,
            RULE_WX_TRANSITION,
            RULE_STACK_EXEC,
            RULE_RETURN_OUTSIDE_EXEC,
            RULE_SHADOW_MISMATCH,
            RULE_EXEC_AFTER_WX,
            RULE_KERNEL_CHAIN,
            RULE_PERSISTENCE,
            RULE_CONTAINER_ESCAPE,
            RULE_CORRELATED,
            RULE_BEACONING,
        ]
        .iter()
        .any(|rule| self.is_enabled(*rule))
    }

    pub fn intrusion_enabled(&self) -> bool {
        [
            RULE_PROCESS_INJECTION,
            RULE_EXPLOIT_CHAIN,
            RULE_CREDENTIAL_DUMP,
        ]
        .iter()
        .any(|rule| self.is_enabled(*rule))
    }

    pub fn destructive_enabled(&self) -> bool {
        [
            RULE_FILE_WRITE_BURST,
            RULE_DESTRUCTIVE_CHAIN,
            RULE_DATA_EXFILTRATION,
        ]
        .iter()
        .any(|rule| self.is_enabled(*rule))
    }

    pub fn coverage_json(&self) -> String {
        let mut entries = Vec::with_capacity(DETECTORS.len());
        for info in DETECTORS.iter() {
            entries.push(format!(
                "{{\"rule\":{},\"name\":\"{}\",\"family\":\"{}\",\"telemetry\":{},\"severity\":{},\"confidence\":{},\"cost\":\"{}\",\"limits\":\"{}\",\"enabled\":{}}}",
                info.rule,
                escape(info.name),
                escape(info.family),
                telemetry_json(info.telemetry),
                info.severity,
                info.confidence,
                escape(info.cost),
                escape(info.limits),
                self.is_enabled(info.rule)
            ));
        }
        format!("[{}]", entries.join(","))
    }

    pub fn summary(&self) -> String {
        format!("{}/{}", self.enabled_count(), self.total_count())
    }

    pub fn emit(&self, cli: &Cli) {
        let enabled: Vec<String> = self
            .enabled_rules()
            .iter()
            .map(|rule| rule.to_string())
            .collect();
        let disabled: Vec<String> = self
            .disabled_rules()
            .iter()
            .map(|rule| rule.to_string())
            .collect();
        cli.status(
            "detectors",
            &[
                ("total", self.total_count().to_string()),
                ("enabled", self.enabled_count().to_string()),
                ("disabled", (self.total_count() - self.enabled_count()).to_string()),
                ("enabled_rules", format!("[{}]", enabled.join(","))),
                ("disabled_rules", format!("[{}]", disabled.join(","))),
                ("coverage", self.coverage_json()),
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::rule_name;

    fn sample(rule: u32) -> Finding {
        Finding {
            rule,
            rule_name: rule_name(rule),
            source: "test",
            severity: SEV_HIGH,
            confidence: 900,
            evidence: 1,
            detail: "test".to_string(),
            decision: DECISION_ALLOW,
        }
    }

    #[test]
    fn descriptors_cover_every_rule() {
        assert_eq!(DETECTORS.len(), 32);
        let mut seen = BTreeSet::new();
        for info in DETECTORS.iter() {
            assert_eq!(info.name, rule_name(info.rule));
            assert!((RULE_WX_REGION..=RULE_MAX).contains(&info.rule));
            assert!(!info.family.is_empty());
            assert!(!info.telemetry.is_empty());
            assert!(info.telemetry.iter().all(|value| !value.is_empty()));
            assert!(info.confidence <= 1000);
            assert!(info.severity <= SEV_CRITICAL);
            assert!(["low", "medium", "high"].contains(&info.cost));
            assert!(!info.limits.is_empty());
            assert!(seen.insert(info.rule));
        }
        for rule in RULE_WX_REGION..=RULE_MAX {
            assert!(seen.contains(&rule));
        }
    }

    #[test]
    fn kernel_sensor_descriptors_are_registered() {
        let expected = [
            (RULE_KERNEL_ROOTKIT, "kernel_rootkit"),
            (RULE_CREDENTIAL_THEFT, "credential_theft"),
            (RULE_PERSISTENCE, "persistence_chain"),
            (RULE_CONTAINER_ESCAPE, "container_escape"),
            (RULE_FILELESS_EXEC, "fileless_exec"),
            (RULE_ANTI_ANALYSIS, "anti_analysis"),
        ];
        for (rule, name) in expected.iter() {
            let info = DETECTORS
                .iter()
                .find(|info| info.rule == *rule)
                .unwrap_or_else(|| panic!("missing detector {}", name));
            assert_eq!(info.name, *name);
            assert!(info.telemetry.contains(&"ksensor"));
            assert!(info.telemetry.iter().all(|value| !value.is_empty()));
            assert!(info.severity == SEV_CRITICAL || info.severity == SEV_HIGH);
            assert!(["low", "medium", "high"].contains(&info.cost));
        }
    }

    #[test]
    fn destructive_chain_descriptors_are_registered() {
        let expected = [
            (RULE_FILE_WRITE_BURST, "file_write_burst", SEV_HIGH, 870),
            (RULE_DESTRUCTIVE_CHAIN, "destructive_chain", SEV_CRITICAL, 900),
            (RULE_DATA_EXFILTRATION, "data_exfiltration", SEV_HIGH, 880),
        ];
        for (rule, name, severity, confidence) in expected.iter() {
            let info = DETECTORS
                .iter()
                .find(|info| info.rule == *rule)
                .unwrap_or_else(|| panic!("missing detector {}", name));
            assert_eq!(info.name, *name);
            assert_eq!(info.severity, *severity);
            assert_eq!(info.confidence, *confidence);
            assert!(info.telemetry.contains(&"file_io"));
            assert!(info.limits.contains("sampled") || info.limits.contains("bounded"));
        }
    }

    #[test]
    fn default_enables_all_descriptors() {
        let registry = DetectorRegistry::new(&[], &[]);
        assert_eq!(registry.summary(), "32/32");
        assert!(registry.disabled_rules().is_empty());
        assert!(DETECTORS.iter().all(|info| registry.is_enabled(info.rule)));
    }

    #[test]
    fn enable_and_disable_select_descriptors() {
        let registry = DetectorRegistry::new(
            &[RULE_WX_TRANSITION, RULE_DOUBLE_FREE],
            &[RULE_DOUBLE_FREE],
        );
        assert_eq!(registry.enabled_rules(), vec![RULE_WX_TRANSITION]);
        assert_eq!(registry.summary(), "1/32");
        assert!(registry.is_enabled(RULE_WX_TRANSITION));
        assert!(!registry.is_enabled(RULE_DOUBLE_FREE));
        assert!(!registry.is_enabled(RULE_WX_REGION));
    }

    #[test]
    fn filter_removes_disabled_findings() {
        let registry = DetectorRegistry::new(&[], &[RULE_WX_TRANSITION, RULE_KERNEL_CHAIN]);
        let findings = vec![
            sample(RULE_WX_TRANSITION),
            sample(RULE_TCP_FLAGS),
            sample(RULE_KERNEL_CHAIN),
        ];
        let filtered = registry.filter(findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule, RULE_TCP_FLAGS);
    }

    #[test]
    fn coverage_reports_descriptor_fields() {
        let registry = DetectorRegistry::new(&[], &[RULE_WX_TRANSITION]);
        let coverage = registry.coverage_json();
        assert!(coverage.contains("\"name\":\"wx_region\""));
        assert!(coverage.contains("\"family\":\"control_flow\""));
        assert!(coverage.contains("\"telemetry\":[\"network_packet\",\"tcp_header\"]"));
        assert!(coverage.contains("\"cost\":\"medium\""));
        assert!(coverage.contains("\"name\":\"wx_transition\""));
        assert!(coverage.contains("\"enabled\":false"));
        assert!(coverage.contains("\"enabled\":true"));
    }
}
