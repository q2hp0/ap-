use crate::abi::*;
use crate::detection::DetectorRegistry;
use crate::event::{event_source, rule_name, Finding};
use crate::ffi;
use std::ffi::c_void;

pub struct Analyzers {
    net: *mut c_void,
    flow: *mut c_void,
    intrusion: *mut c_void,
    destructive: *mut c_void,
}

impl Analyzers {
    pub fn new() -> Option<Self> {
        unsafe {
            let net = ffi::ap_net_new();
            let flow = ffi::ap_flow_new();
            let intrusion = ffi::ap_intrusion_new();
            let destructive = ffi::ap_destructive_new();
            if net.is_null() || flow.is_null() || intrusion.is_null() || destructive.is_null() {
                if !net.is_null() {
                    ffi::ap_net_free(net);
                }
                if !flow.is_null() {
                    ffi::ap_flow_free(flow);
                }
                if !intrusion.is_null() {
                    ffi::ap_intrusion_free(intrusion);
                }
                if !destructive.is_null() {
                    ffi::ap_destructive_free(destructive);
                }
                return None;
            }
            Some(Self { net, flow, intrusion, destructive })
        }
    }

    pub fn feed_net(&mut self, event: &Event) -> Option<Verdict> {
        let mut verdict = Verdict::new(event.seq);
        let status = unsafe { ffi::ap_net_feed(self.net, event, &mut verdict) };
        if status == OK && verdict.rule != RULE_NONE {
            Some(verdict)
        } else {
            None
        }
    }

    pub fn feed_flow(&mut self, event: &Event) -> Option<Verdict> {
        let mut verdict = Verdict::new(event.seq);
        let status = unsafe { ffi::ap_flow_feed(self.flow, event, &mut verdict) };
        if status == OK && verdict.rule != RULE_NONE {
            Some(verdict)
        } else {
            None
        }
    }

    pub fn feed_intrusion(&mut self, event: &Event) -> Option<Verdict> {
        let mut verdict = Verdict::new(event.seq);
        let status = unsafe { ffi::ap_intrusion_feed(self.intrusion, event, &mut verdict) };
        if status == OK && verdict.rule != RULE_NONE {
            Some(verdict)
        } else {
            None
        }
    }

    pub fn feed_destructive(&mut self, event: &Event) -> Option<Verdict> {
        let mut verdict = Verdict::new(event.seq);
        let status = unsafe { ffi::ap_destructive_feed(self.destructive, event, &mut verdict) };
        if status == OK && verdict.rule != RULE_NONE {
            Some(verdict)
        } else {
            None
        }
    }

    pub fn set_entity_window_ms(&mut self, window_ms: u32) -> i32 {
        unsafe { ffi::ap_flow_set_window_ms(self.flow, window_ms) }
    }

    pub fn destructive_counters(&self) -> ffi::DestructiveCounters {
        let mut counters = ffi::DestructiveCounters::default();
        unsafe {
            ffi::ap_destructive_stats(self.destructive, &mut counters);
        }
        counters
    }

    pub fn counters(&self) -> (ffi::NetCounters, ffi::FlowCounters, ffi::IntrusionCounters) {
        let mut net = ffi::NetCounters::default();
        let mut flow = ffi::FlowCounters::default();
        let mut intrusion = ffi::IntrusionCounters::default();
        unsafe {
            ffi::ap_net_stats(self.net, &mut net);
            ffi::ap_flow_stats(self.flow, &mut flow);
            ffi::ap_intrusion_stats(self.intrusion, &mut intrusion);
        }
        (net, flow, intrusion)
    }

    pub fn reset(&mut self) {
        unsafe {
            ffi::ap_net_reset(self.net);
            ffi::ap_flow_reset(self.flow);
            ffi::ap_intrusion_reset(self.intrusion);
            ffi::ap_destructive_reset(self.destructive);
        }
    }
}

impl Drop for Analyzers {
    fn drop(&mut self) {
        unsafe {
            ffi::ap_net_free(self.net);
            ffi::ap_flow_free(self.flow);
            ffi::ap_intrusion_free(self.intrusion);
            ffi::ap_destructive_free(self.destructive);
        }
    }
}

fn finding(event: &Event, rule: u32, severity: u32, confidence: u32,
           detail: String, source: &'static str) -> Finding {
    Finding {
        rule,
        rule_name: rule_name(rule),
        source,
        severity,
        confidence: confidence.min(1000),
        evidence: event.arg[0],
        detail,
        decision: DECISION_ALLOW,
    }
}

fn from_verdict(event: &Event, verdict: &Verdict) -> Finding {
    let mut item = finding(
        event,
        verdict.rule,
        verdict.severity,
        verdict.confidence_x1000,
        if verdict.text().is_empty() { verdict.rule_name().to_string() } else { verdict.text().to_string() },
        event_source(event),
    );
    item.evidence = verdict.evidence;
    item
}

fn push_finding(findings: &mut Vec<Finding>, candidate: Finding) {
    if let Some(existing) = findings.iter_mut().find(|item| item.rule == candidate.rule) {
        if candidate.confidence > existing.confidence {
            *existing = candidate;
        }
        return;
    }
    findings.push(candidate);
}

trait VerdictText {
    fn rule_name(&self) -> &'static str;
}

impl VerdictText for Verdict {
    fn rule_name(&self) -> &'static str {
        rule_name(self.rule)
    }
}

fn ksensor_label_finding(event: &Event, source: &'static str) -> Option<Finding> {
    if source != "ksensor" {
        return None;
    }
    let (rule, severity, confidence) = match event.text() {
        "kernel_rootkit" => (RULE_KERNEL_ROOTKIT, SEV_CRITICAL, 900),
        "credential_theft" => (RULE_CREDENTIAL_THEFT, SEV_CRITICAL, 870),
        "fileless_exec" => (RULE_FILELESS_EXEC, SEV_CRITICAL, 850),
        "anti_analysis" => (RULE_ANTI_ANALYSIS, SEV_HIGH, 820),
        _ => return None,
    };
    Some(finding(
        event,
        rule,
        severity,
        confidence,
        event.text().to_string(),
        source,
    ))
}

fn cheap_rules(event: &Event) -> Vec<Finding> {
    let mut out = Vec::with_capacity(2);
    let source = event_source(event);
    if let Some(label) = ksensor_label_finding(event, source) {
        return vec![label];
    }
    match (event.kind, event.subkind) {
        (KIND_MEMREGION, 2) => out.push(finding(
            event, RULE_WX_REGION, SEV_CRITICAL, event.confidence_x1000.max(900),
            format!("writable executable mapping {:x}", event.arg[0]), source,
        )),
        (KIND_MEMPROT, _) if event.arg[2] & 2 != 0 && event.arg[2] & 4 != 0 => out.push(finding(
            event, RULE_WX_TRANSITION, SEV_CRITICAL, event.confidence_x1000.max(900),
            format!("{} requested rwx protection", event.text()), source,
        )),
        (KIND_FLOW, FLOW_STACK) => out.push(finding(
            event, RULE_STACK_EXEC, SEV_CRITICAL, event.confidence_x1000,
            "stack pointer inside executable mapping".to_string(), source,
        )),
        (KIND_FLOW, FLOW_RETURN_SITE) if event.confidence_x1000 >= 800 => out.push(finding(
            event, RULE_RETURN_OUTSIDE_EXEC, SEV_HIGH, event.confidence_x1000,
            format!("return site {:x} outside executable ranges", event.arg[0]), source,
        )),
        (KIND_FLOW, FLOW_SHADOW) if event.arg[0] != event.arg[1] => out.push(finding(
            event, RULE_SHADOW_MISMATCH, SEV_HIGH, 900,
            format!("expected {:x} actual {:x}", event.arg[0], event.arg[1]), source,
        )),
        (KIND_PRIV, 2) => out.push(finding(
            event, RULE_PRIV_CROSSING, SEV_HIGH, event.confidence_x1000,
            format!("uid {} to {}", event.arg[0], event.arg[1]), source,
        )),
        (KIND_PRIV, _) if event.text().contains("setid") => {}
        (KIND_PRIV, _) => out.push(finding(
            event, RULE_PRIV_CROSSING, SEV_HIGH, event.confidence_x1000,
            format!("privilege event {}", event.text()), source,
        )),
        (KIND_KERNEL, _) if event.text().contains("module") => out.push(finding(
            event, RULE_MODULE_LOAD, SEV_CRITICAL, event.confidence_x1000.max(800),
            format!("kernel module operation {}", event.text()), source,
        )),
        (KIND_KERNEL, _) => out.push(finding(
            event, RULE_KERNEL_IFACE, SEV_HIGH, event.confidence_x1000,
            format!("kernel interface {}", event.text()), source,
        )),
        (KIND_HEAP, HEAP_OVERFLOW) => out.push(finding(
            event, RULE_HEAP_CANARY, SEV_HIGH, event.confidence_x1000,
            format!("{} at {:x}", event.text(), event.arg[0]), source,
        )),
        (KIND_HEAP, HEAP_DOUBLE_FREE) => out.push(finding(
            event, RULE_DOUBLE_FREE, SEV_HIGH, event.confidence_x1000,
            format!("double free at {:x}", event.arg[0]), source,
        )),
        (KIND_HEAP, HEAP_INVALID_FREE) => out.push(finding(
            event, RULE_INVALID_FREE, SEV_MEDIUM, event.confidence_x1000,
            format!("invalid free at {:x}", event.arg[0]), source,
        )),
        (KIND_NET, NET_SOCKET) if event.arg[1] & 3 == 3 => out.push(finding(
            event, RULE_RAW_SOCKET, SEV_HIGH, 800,
            "raw socket requested".to_string(), source,
        )),
        _ => {}
    }
    out
}

pub fn detect(event: &Event, analyzers: &mut Analyzers) -> Vec<Finding> {
    detect_with_registry(event, analyzers, &DetectorRegistry::new(&[], &[]))
}

pub fn detect_with_registry(
    event: &Event,
    analyzers: &mut Analyzers,
    registry: &DetectorRegistry,
) -> Vec<Finding> {
    let mut findings = registry.filter(cheap_rules(event));
    if registry.net_enabled() && event.kind == KIND_NET {
        if let Some(verdict) = analyzers.feed_net(event) {
            if registry.is_enabled(verdict.rule) {
                push_finding(&mut findings, from_verdict(event, &verdict));
            }
        }
    }
    if registry.flow_enabled()
        && matches!(
            event.kind,
            KIND_PROC
                | KIND_MEMREGION
                | KIND_MEMPROT
                | KIND_EXEC
                | KIND_PRIV
                | KIND_KERNEL
                | KIND_NET
                | KIND_FLOW
        )
    {
        if let Some(verdict) = analyzers.feed_flow(event) {
            if registry.is_enabled(verdict.rule) {
                push_finding(&mut findings, from_verdict(event, &verdict));
            }
        }
    }
    if registry.intrusion_enabled()
        && matches!(
            event.kind,
            KIND_KERNEL
                | KIND_MEMREGION
                | KIND_MEMPROT
                | KIND_EXEC
                | KIND_FLOW
                | KIND_PRIV
                | KIND_NET
        )
    {
        if let Some(verdict) = analyzers.feed_intrusion(event) {
            if registry.is_enabled(verdict.rule) {
                push_finding(&mut findings, from_verdict(event, &verdict));
            }
        }
    }
    if registry.destructive_enabled()
        && matches!(event.kind, KIND_FILE | KIND_NET | KIND_KERNEL)
    {
        if let Some(verdict) = analyzers.feed_destructive(event) {
            if registry.is_enabled(verdict.rule) {
                push_finding(&mut findings, from_verdict(event, &verdict));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wx_transition() {
        let mut event = Event::new(KIND_MEMPROT, 1, 10, 4);
        event.arg[2] = 7;
        event.set_text("mprotect");
        let mut analyzers = Analyzers::new().unwrap();
        let findings = detect(&event, &mut analyzers);
        assert!(findings.iter().any(|f| f.rule == RULE_WX_TRANSITION));
        assert!(findings.iter().any(|f| f.rule_name == "wx_transition"));
    }

    #[test]
    fn detects_exec_after_wx() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut wx = Event::new(KIND_MEMPROT, 1, 10, 4);
        wx.arg[2] = 7;
        assert!(detect(&wx, &mut analyzers).iter().any(|f| f.rule == RULE_WX_TRANSITION));
        let exec = Event::new(KIND_EXEC, 2, 10, 4);
        let findings = detect(&exec, &mut analyzers);
        assert!(findings.iter().any(|f| f.rule == RULE_EXEC_AFTER_WX));
        assert!(detect(&exec, &mut analyzers).is_empty());
    }

    #[test]
    fn detects_kernel_chain() {
        let mut analyzers = Analyzers::new().unwrap();
        let labels = ["module_load", "mount", "namespace_change"];
        for (seq, label) in labels.iter().enumerate() {
            let mut event = Event::new(KIND_KERNEL, seq as u64 + 1, 10, 4);
            event.set_text(label);
            let findings = detect(&event, &mut analyzers);
            if seq == 2 {
                assert!(findings.iter().any(|f| f.rule == RULE_KERNEL_CHAIN));
            }
        }
    }

    #[test]
    fn detects_high_confidence_ksensor_labels() {
        let labels = [
            ("kernel_rootkit", RULE_KERNEL_ROOTKIT, 900),
            ("credential_theft", RULE_CREDENTIAL_THEFT, 870),
            ("fileless_exec", RULE_FILELESS_EXEC, 850),
            ("anti_analysis", RULE_ANTI_ANALYSIS, 820),
        ];
        let mut analyzers = Analyzers::new().unwrap();
        for (seq, (label, rule, confidence)) in labels.iter().enumerate() {
            let mut event = Event::new(KIND_EXEC, seq as u64 + 1, 10, 4);
            event.arg[3] = ffi::KSENSOR_SOURCE_MARK;
            event.set_text(label);
            let findings = detect(&event, &mut analyzers);
            assert_eq!(findings.len(), 1, "one finding for {}", label);
            assert_eq!(findings[0].rule, *rule);
            assert_eq!(findings[0].rule_name, rule_name(*rule));
            assert_eq!(findings[0].confidence, *confidence);
            assert_eq!(findings[0].source, "ksensor");
            assert_eq!(findings[0].detail, *label);
        }
    }

    #[test]
    fn ksensor_label_must_match_exactly() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut event = Event::new(KIND_EXEC, 1, 10, 4);
        event.arg[3] = ffi::KSENSOR_SOURCE_MARK;
        event.set_text("kernel_rootkit:extra");
        assert!(detect(&event, &mut analyzers).is_empty());
        event.set_text("kernel_rootkit");
        event.arg[3] = 0;
        assert!(!detect(&event, &mut analyzers)
            .iter()
            .any(|finding| finding.rule == RULE_KERNEL_ROOTKIT));
    }

    #[test]
    fn weak_setid_alone_is_not_a_finding() {
        let mut event = Event::new(KIND_PRIV, 1, 10, 4);
        event.subkind = 1;
        event.confidence_x1000 = 450;
        event.set_text("setid");
        let mut analyzers = Analyzers::new().unwrap();
        assert!(detect(&event, &mut analyzers).is_empty());
    }

    #[test]
    fn bpf_and_ptrace_explain_kernel_chain() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut bpf = Event::new(KIND_KERNEL, 1, 10, 4);
        bpf.set_text("bpf");
        assert!(!detect(&bpf, &mut analyzers)
            .iter()
            .any(|finding| finding.rule == RULE_KERNEL_CHAIN));
        let mut ptrace = Event::new(KIND_KERNEL, 2, 11, 4);
        ptrace.set_text("ptrace");
        let chain = detect(&ptrace, &mut analyzers)
            .into_iter()
            .find(|finding| finding.rule == RULE_KERNEL_CHAIN)
            .expect("kernel chain finding");
        assert!(chain.detail.contains("bpf+ptrace"));
    }

    #[test]
    fn setid_and_bpf_explain_privilege_crossing() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut setid = Event::new(KIND_PRIV, 1, 10, 4);
        setid.subkind = 1;
        setid.confidence_x1000 = 450;
        setid.set_text("setid");
        assert!(detect(&setid, &mut analyzers).is_empty());
        let mut bpf = Event::new(KIND_KERNEL, 2, 11, 4);
        bpf.set_text("bpf");
        let crossing = detect(&bpf, &mut analyzers)
            .into_iter()
            .find(|finding| finding.rule == RULE_PRIV_CROSSING)
            .expect("privilege crossing finding");
        assert!(crossing.detail.contains("bpf+setid"));
        assert!(crossing.confidence >= 800);
    }

    #[test]
    fn repeated_kernel_label_does_not_chain() {
        let mut analyzers = Analyzers::new().unwrap();
        for seq in 1..=6u64 {
            let mut event = Event::new(KIND_KERNEL, seq, 10, 4);
            event.set_text("kernel_interface");
            let findings = detect(&event, &mut analyzers);
            assert!(!findings.iter().any(|f| f.rule == RULE_KERNEL_CHAIN));
        }
    }

    #[test]
    fn weak_return_site_alone_is_not_a_finding() {
        let mut event = Event::new(KIND_FLOW, 1, 10, 4);
        event.subkind = FLOW_RETURN_SITE;
        event.confidence_x1000 = 250;
        event.arg[0] = 0x1234;
        let mut analyzers = Analyzers::new().unwrap();
        assert!(detect(&event, &mut analyzers).is_empty());
    }

    #[test]
    fn detects_tcp_flag_violation() {
        let mut event = Event::new(KIND_NET, 2, 20, 4);
        event.subkind = NET_PACKET;
        event.set_text("45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000");
        let mut analyzers = Analyzers::new().unwrap();
        let findings = detect(&event, &mut analyzers);
        assert!(findings.iter().any(|f| f.rule == RULE_TCP_FLAGS));
    }

    #[test]
    fn entity_chain_links_stages_across_events() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut wx = Event::new(KIND_MEMREGION, 1, 1_000_000_000, 4);
        wx.subkind = 2;
        wx.arg[0] = 0x1000;
        wx.arg[1] = 0x2000;
        wx.arg[2] = 6;
        wx.set_text("/srv/payload");
        detect(&wx, &mut analyzers);
        let mut exec = Event::new(KIND_EXEC, 2, 2_000_000_000, 4);
        exec.set_text("/srv/payload");
        detect(&exec, &mut analyzers);
        let mut priv_change = Event::new(KIND_PRIV, 3, 3_000_000_000, 4);
        priv_change.subkind = 2;
        priv_change.arg[1] = 1000;
        priv_change.set_text("init");
        detect(&priv_change, &mut analyzers);
        let mut net = Event::new(KIND_NET, 4, 4_000_000_000, 4);
        net.subkind = NET_CONNECT;
        net.set_text("peer:10.0.0.9:4444");
        let findings = detect(&net, &mut analyzers);
        let chain = findings
            .iter()
            .find(|finding| finding.rule == RULE_CORRELATED)
            .expect("entity chain finding");
        assert!(chain.detail.contains("entity_chain:wx+exec+priv+net"));
        assert!(chain.detail.contains("10.0.0.9"));
        assert!(chain.confidence >= 800);
    }

    #[test]
    fn expired_entity_reference_does_not_link_fresh_stages() {
        let mut analyzers = Analyzers::new().unwrap();
        assert_eq!(analyzers.set_entity_window_ms(1000), OK);
        let mut old_exec = Event::new(KIND_EXEC, 1, 1_000_000_000, 7);
        old_exec.set_text("/srv/old");
        detect(&old_exec, &mut analyzers);

        let mut wx = Event::new(KIND_MEMPROT, 2, 3_000_000_000, 7);
        wx.arg[2] = 6;
        detect(&wx, &mut analyzers);
        let fresh_exec = Event::new(KIND_EXEC, 3, 3_000_000_001, 7);
        detect(&fresh_exec, &mut analyzers);
        let mut setid = Event::new(KIND_PRIV, 4, 3_000_000_002, 7);
        setid.subkind = 3;
        setid.set_text("setid");
        detect(&setid, &mut analyzers);
        let mut net = Event::new(KIND_NET, 5, 3_000_000_003, 7);
        net.subkind = NET_CONNECT;
        net.set_text("peer:10.0.0.12:4444");
        let findings = detect(&net, &mut analyzers);
        assert!(!findings.iter().any(|finding| finding.rule == RULE_CORRELATED));
        let (_, flow, _) = analyzers.counters();
        assert!(flow.entity_refs_expired > 0);
    }

    #[test]
    fn benign_jit_stream_has_no_entity_chain() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut wx = Event::new(KIND_MEMREGION, 1, 1_000_000_000, 4);
        wx.subkind = 2;
        wx.arg[0] = 0x1000;
        wx.arg[1] = 0x2000;
        wx.arg[2] = 6;
        wx.set_text("/opt/jit/code");
        detect(&wx, &mut analyzers);
        let mut exec = Event::new(KIND_EXEC, 2, 2_000_000_000, 4);
        exec.set_text("/opt/jit/code");
        let findings = detect(&exec, &mut analyzers);
        assert!(!findings.iter().any(|f| f.rule == RULE_CORRELATED));
    }

    #[test]
    fn entity_window_setter_validates_range() {
        let mut analyzers = Analyzers::new().unwrap();
        assert_eq!(analyzers.set_entity_window_ms(1000), OK);
        assert_eq!(analyzers.set_entity_window_ms(50), ERR_RANGE);
        assert_eq!(analyzers.set_entity_window_ms(60001), ERR_RANGE);
    }

    #[test]
    fn disabled_network_rules_skip_the_analyzer() {
        let registry = DetectorRegistry::new(
            &[],
            &[
                RULE_TCP_STATE,
                RULE_TCP_FLAGS,
                RULE_IP_MALFORMED,
                RULE_FRAG_OVERLAP,
            ],
        );
        assert!(!registry.net_enabled());
        let mut event = Event::new(KIND_NET, 2, 20, 4);
        event.subkind = NET_PACKET;
        event.set_text("45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000");
        let mut analyzers = Analyzers::new().unwrap();
        let (before, _, _) = analyzers.counters();
        assert!(detect_with_registry(&event, &mut analyzers, &registry).is_empty());
        let (after, _, _) = analyzers.counters();
        assert_eq!(after.packets, before.packets);
    }

    #[test]
    fn intrusion_process_injection_chain_fires() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut write = Event::new(KIND_KERNEL, 1, 1_000_000_000, 91);
        write.set_text("ptrace");
        detect(&write, &mut analyzers);
        let mut wx = Event::new(KIND_MEMPROT, 2, 2_000_000_000, 91);
        wx.arg[2] = 7;
        wx.set_text("mprotect");
        let findings = detect(&wx, &mut analyzers);
        let injection = findings
            .iter()
            .find(|finding| finding.rule == RULE_PROCESS_INJECTION)
            .expect("process injection finding");
        assert_eq!(injection.rule_name, "process_injection");
        assert!(injection.detail.starts_with("process_injection:"));
        assert!(injection.detail.contains("ptrace"));
        assert!(injection.detail.contains("wx"));
        assert_eq!(injection.confidence, 870);
        let exec = Event::new(KIND_EXEC, 3, 3_000_000_000, 91);
        let repeated = detect(&exec, &mut analyzers);
        assert!(!repeated.iter().any(|f| f.rule == RULE_PROCESS_INJECTION));
        let (_, _, intrusion) = analyzers.counters();
        assert_eq!(intrusion.findings, 1);
        assert_eq!(intrusion.suppressed, 1);
    }

    #[test]
    fn intrusion_exploit_chain_fires() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut wx = Event::new(KIND_MEMREGION, 1, 1_000_000_000, 92);
        wx.subkind = 2;
        wx.arg[0] = 0x1000;
        wx.arg[1] = 0x2000;
        wx.arg[2] = 6;
        wx.set_text("/tmp/payload");
        detect(&wx, &mut analyzers);
        let mut redirect = Event::new(KIND_FLOW, 2, 2_000_000_000, 92);
        redirect.subkind = FLOW_STACK;
        redirect.arg[0] = 0x7000;
        redirect.set_text("stack");
        detect(&redirect, &mut analyzers);
        let mut setid = Event::new(KIND_PRIV, 3, 3_000_000_000, 92);
        setid.subkind = 1;
        setid.set_text("setid");
        let findings = detect(&setid, &mut analyzers);
        let chain = findings
            .iter()
            .find(|finding| finding.rule == RULE_EXPLOIT_CHAIN)
            .expect("exploit chain finding");
        assert_eq!(chain.rule_name, "exploit_chain");
        assert!(chain.detail.starts_with("exploit_chain:"));
        assert!(chain.detail.contains("wx"));
        assert!(chain.detail.contains("redirect"));
        assert!(chain.detail.contains("priv"));
        assert_eq!(chain.confidence, 920);
    }

    #[test]
    fn intrusion_credential_dump_chain_fires() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut read = Event::new(KIND_KERNEL, 1, 1_000_000_000, 93);
        read.set_text("process_vm_readv");
        read.arg[3] = ffi::KSENSOR_SOURCE_MARK;
        detect(&read, &mut analyzers);
        let mut cred = Event::new(KIND_KERNEL, 2, 2_000_000_000, 93);
        cred.set_text("credential_theft");
        cred.arg[3] = ffi::KSENSOR_SOURCE_MARK;
        detect(&cred, &mut analyzers);
        let mut setid = Event::new(KIND_PRIV, 3, 3_000_000_000, 93);
        setid.subkind = 1;
        setid.set_text("setid");
        let findings = detect(&setid, &mut analyzers);
        let dump = findings
            .iter()
            .find(|finding| finding.rule == RULE_CREDENTIAL_DUMP)
            .expect("credential dump finding");
        assert_eq!(dump.rule_name, "credential_dump");
        assert!(dump.detail.starts_with("credential_dump:"));
        assert!(dump.detail.contains("process_vm_readv"));
        assert!(dump.detail.contains("credential_theft"));
        assert!(dump.detail.contains("priv"));
        assert_eq!(dump.confidence, 900);
    }

    #[test]
    fn intrusion_benign_stage_stream_stays_quiet() {
        let mut analyzers = Analyzers::new().unwrap();
        let mut wx = Event::new(KIND_MEMREGION, 1, 1_000_000_000, 94);
        wx.subkind = 2;
        wx.arg[2] = 6;
        detect(&wx, &mut analyzers);
        let exec = Event::new(KIND_EXEC, 2, 2_000_000_000, 94);
        detect(&exec, &mut analyzers);
        let mut setid = Event::new(KIND_PRIV, 3, 3_000_000_000, 94);
        setid.subkind = 1;
        setid.set_text("setid");
        detect(&setid, &mut analyzers);
        let mut net = Event::new(KIND_NET, 4, 4_000_000_000, 94);
        net.subkind = NET_CONNECT;
        net.set_text("peer:10.0.0.9:4444");
        let findings = detect(&net, &mut analyzers);
        assert!(!findings.iter().any(|finding| matches!(
            finding.rule,
            RULE_PROCESS_INJECTION | RULE_EXPLOIT_CHAIN | RULE_CREDENTIAL_DUMP
        )));
        let (_, _, intrusion) = analyzers.counters();
        assert!(intrusion.added > 0);
        assert_eq!(intrusion.findings, 0);
    }

    #[test]
    fn intrusion_disabled_rules_are_not_reported() {
        let registry = DetectorRegistry::new(
            &[],
            &[RULE_PROCESS_INJECTION, RULE_EXPLOIT_CHAIN, RULE_CREDENTIAL_DUMP],
        );
        assert!(!registry.intrusion_enabled());
        let mut analyzers = Analyzers::new().unwrap();
        let mut write = Event::new(KIND_KERNEL, 1, 1_000_000_000, 95);
        write.set_text("ptrace");
        detect_with_registry(&write, &mut analyzers, &registry);
        let mut wx = Event::new(KIND_MEMPROT, 2, 2_000_000_000, 95);
        wx.arg[2] = 7;
        detect_with_registry(&wx, &mut analyzers, &registry);
        let exec = Event::new(KIND_EXEC, 3, 3_000_000_000, 95);
        let findings = detect_with_registry(&exec, &mut analyzers, &registry);
        assert!(!findings.iter().any(|finding| matches!(
            finding.rule,
            RULE_PROCESS_INJECTION | RULE_EXPLOIT_CHAIN | RULE_CREDENTIAL_DUMP
        )));
        let (_, _, intrusion) = analyzers.counters();
        assert_eq!(intrusion.added, 0);
        assert_eq!(intrusion.findings, 0);

        let registry = DetectorRegistry::new(&[], &[RULE_PROCESS_INJECTION]);
        assert!(registry.intrusion_enabled());
        let mut analyzers = Analyzers::new().unwrap();
        let mut write = Event::new(KIND_KERNEL, 1, 1_000_000_000, 96);
        write.set_text("ptrace");
        detect_with_registry(&write, &mut analyzers, &registry);
        let mut wx = Event::new(KIND_MEMPROT, 2, 2_000_000_000, 96);
        wx.arg[2] = 7;
        detect_with_registry(&wx, &mut analyzers, &registry);
        let exec = Event::new(KIND_EXEC, 3, 3_000_000_000, 96);
        let findings = detect_with_registry(&exec, &mut analyzers, &registry);
        assert!(!findings.iter().any(|finding| finding.rule == RULE_PROCESS_INJECTION));
        let (_, _, intrusion) = analyzers.counters();
        assert!(intrusion.findings > 0);
    }

    fn file_io(seq: u64, ts_ns: u64, pid: i64, write_bytes: u64, write_calls: u64,
               read_chars: u64, read_bytes: u64) -> Event {
        let mut event = Event::new(KIND_FILE, seq, ts_ns, pid);
        event.subkind = FILE_IO;
        event.arg[0] = write_bytes;
        event.arg[1] = write_calls;
        event.arg[2] = read_chars;
        event.arg[3] = read_bytes;
        event.set_text("testproc");
        event
    }

    fn file_action(seq: u64, ts_ns: u64, pid: i64, label: &str) -> Event {
        let mut event = Event::new(KIND_FILE, seq, ts_ns, pid);
        event.subkind = FILE_ACTION;
        event.set_text(label);
        event
    }

    #[test]
    fn destructive_burst_then_chain_fires_with_distinct_stages() {
        let mut analyzers = Analyzers::new().unwrap();
        let write = file_io(1, 1_000_000_000, 201, 2_000_000, 100, 0, 0);
        let findings = detect(&write, &mut analyzers);
        let burst = findings
            .iter()
            .find(|finding| finding.rule == RULE_FILE_WRITE_BURST)
            .expect("write burst finding");
        assert_eq!(burst.rule_name, "file_write_burst");
        assert_eq!(burst.confidence, 870);
        assert!(burst.detail.starts_with("file_write_burst:"));

        assert!(detect(&file_action(2, 2_000_000_000, 201, "file_rename"), &mut analyzers)
            .is_empty());
        let findings = detect(&file_action(3, 3_000_000_000, 201, "file_unlink"), &mut analyzers);
        let chain = findings
            .iter()
            .find(|finding| finding.rule == RULE_DESTRUCTIVE_CHAIN)
            .expect("destructive chain finding");
        assert_eq!(chain.rule_name, "destructive_chain");
        assert_eq!(chain.confidence, 900);
        assert!(chain.detail.starts_with("destructive_chain:"));
        assert!(chain.detail.contains("write"));
        assert!(chain.detail.contains("rename"));
        assert!(chain.detail.contains("unlink"));
        let counters = analyzers.destructive_counters();
        assert_eq!(counters.findings, 2);
        assert_eq!(counters.suppressed, 1);
    }

    #[test]
    fn destructive_exfil_requires_read_volume_and_peer() {
        let mut analyzers = Analyzers::new().unwrap();
        let read = file_io(1, 1_000_000_000, 202, 0, 0, 9_000_000, 6_000_000);
        assert!(!detect(&read, &mut analyzers)
            .iter()
            .any(|finding| finding.rule == RULE_DATA_EXFILTRATION));
        let mut net = Event::new(KIND_NET, 2, 2_000_000_000, 202);
        net.subkind = NET_CONNECT;
        net.set_text("peer:10.1.1.7:443");
        let findings = detect(&net, &mut analyzers);
        let exfil = findings
            .iter()
            .find(|finding| finding.rule == RULE_DATA_EXFILTRATION)
            .expect("exfiltration finding");
        assert_eq!(exfil.rule_name, "data_exfiltration");
        assert_eq!(exfil.confidence, 880);
        assert!(exfil.detail.starts_with("data_exfiltration:"));
        assert!(exfil.detail.contains("read"));
        assert!(exfil.detail.contains("net"));
    }

    #[test]
    fn destructive_benign_small_stream_stays_quiet() {
        let mut analyzers = Analyzers::new().unwrap();
        detect(&file_io(1, 1_000_000_000, 203, 512, 1, 256, 128), &mut analyzers);
        detect(&file_action(2, 2_000_000_000, 203, "file_chmod"), &mut analyzers);
        let findings = detect(&file_action(3, 3_000_000_000, 203, "file_rename"), &mut analyzers);
        assert!(!findings.iter().any(|finding| matches!(
            finding.rule,
            RULE_FILE_WRITE_BURST | RULE_DESTRUCTIVE_CHAIN | RULE_DATA_EXFILTRATION
        )));
        let counters = analyzers.destructive_counters();
        assert!(counters.added > 0);
        assert_eq!(counters.findings, 0);
    }

    #[test]
    fn destructive_disabled_rules_skip_the_analyzer() {
        let registry = DetectorRegistry::new(
            &[],
            &[
                RULE_FILE_WRITE_BURST,
                RULE_DESTRUCTIVE_CHAIN,
                RULE_DATA_EXFILTRATION,
            ],
        );
        assert!(!registry.destructive_enabled());
        let mut analyzers = Analyzers::new().unwrap();
        let findings = detect_with_registry(
            &file_io(1, 1_000_000_000, 204, 4_000_000, 100, 0, 0),
            &mut analyzers,
            &registry,
        );
        assert!(findings.is_empty());
        let counters = analyzers.destructive_counters();
        assert_eq!(counters.added, 0);
        assert_eq!(counters.findings, 0);
    }
}
