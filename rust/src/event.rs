use crate::abi::*;
use crate::ffi;

#[derive(Clone, Debug)]
pub struct Normalized {
    pub source: &'static str,
    pub kind: &'static str,
    pub severity: &'static str,
    pub severity_code: u32,
    pub confidence: u32,
    pub pid: i64,
    pub tid: i64,
    pub seq: u64,
    pub ts_ns: u64,
    pub detail: String,
    pub subkind: u32,
    pub event_kind: u16,
    pub arg: [u64; 4],
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: u32,
    pub rule_name: &'static str,
    pub source: &'static str,
    pub severity: u32,
    pub confidence: u32,
    pub evidence: u64,
    pub detail: String,
    pub decision: i32,
}

pub fn severity_name(severity: u32) -> &'static str {
    match severity {
        SEV_INFO => "info",
        SEV_LOW => "low",
        SEV_MEDIUM => "medium",
        SEV_HIGH => "high",
        _ => "critical",
    }
}

pub fn rule_name(rule: u32) -> &'static str {
    match rule {
        RULE_NONE => "none",
        RULE_WX_REGION => "wx_region",
        RULE_WX_TRANSITION => "wx_transition",
        RULE_STACK_EXEC => "stack_exec",
        RULE_RETURN_OUTSIDE_EXEC => "return_outside_exec",
        RULE_SHADOW_MISMATCH => "shadow_mismatch",
        RULE_PRIV_CROSSING => "privilege_crossing",
        RULE_MODULE_LOAD => "module_load",
        RULE_KERNEL_IFACE => "kernel_interface",
        RULE_TCP_STATE => "tcp_state_violation",
        RULE_TCP_FLAGS => "tcp_flag_violation",
        RULE_IP_MALFORMED => "ip_malformed",
        RULE_FRAG_OVERLAP => "fragment_overlap",
        RULE_HEAP_CANARY => "heap_canary",
        RULE_DOUBLE_FREE => "double_free",
        RULE_INVALID_FREE => "invalid_free",
        RULE_CORRELATED => "correlated_exploit_indicators",
        RULE_RAW_SOCKET => "raw_socket",
        RULE_EXEC_AFTER_WX => "exec_after_wx",
        RULE_KERNEL_CHAIN => "kernel_chain",
        RULE_KERNEL_ROOTKIT => "kernel_rootkit",
        RULE_CREDENTIAL_THEFT => "credential_theft",
        RULE_PERSISTENCE => "persistence_chain",
        RULE_CONTAINER_ESCAPE => "container_escape",
        RULE_FILELESS_EXEC => "fileless_exec",
        RULE_ANTI_ANALYSIS => "anti_analysis",
        RULE_BEACONING => "beaconing",
        RULE_PROCESS_INJECTION => "process_injection",
        RULE_EXPLOIT_CHAIN => "exploit_chain",
        RULE_CREDENTIAL_DUMP => "credential_dump",
        RULE_FILE_WRITE_BURST => "file_write_burst",
        RULE_DESTRUCTIVE_CHAIN => "destructive_chain",
        RULE_DATA_EXFILTRATION => "data_exfiltration",
        _ => "unknown",
    }
}

pub fn source_for(kind: u16) -> &'static str {
    match kind {
        KIND_PROC | KIND_EXEC => "process",
        KIND_MEMREGION | KIND_MEMPROT | KIND_HEAP => "memory",
        KIND_PRIV | KIND_KERNEL => "kernel",
        KIND_FILE => "file",
        KIND_NET => "network",
        KIND_FLOW => "flow",
        KIND_HEARTBEAT => "core",
        _ => "trace",
    }
}

pub fn event_source(event: &Event) -> &'static str {
    if event.kind == KIND_NET && event.arg[3] == ffi::CAPTURE_SOURCE_MARK {
        "capture"
    } else if event.kind != KIND_NET && event.arg[3] == ffi::KSENSOR_SOURCE_MARK {
        "ksensor"
    } else if event.kind != KIND_NET && event.arg[3] == ffi::KERNEL_SOURCE_MARK {
        "kernel"
    } else {
        source_for(event.kind)
    }
}

pub fn validate(event: &Event) -> Result<(), &'static str> {
    if event.size as usize != EVENT_SIZE {
        return Err("event size");
    }
    if event.abi_version != ABI_VERSION {
        return Err("abi version");
    }
    if event.kind == KIND_NONE || event.kind > KIND_FILE {
        return Err("event kind");
    }
    if !event.text.iter().any(|b| *b == 0) {
        return Err("text terminator");
    }
    Ok(())
}

pub fn normalize(event: &Event, now_ns: u64) -> Option<Normalized> {
    if validate(event).is_err() {
        return None;
    }
    let (_, kind) = match (event.kind, event.subkind) {
        (KIND_MEMREGION, 2) => ("memory", "wx_region"),
        (KIND_MEMREGION, _) => ("memory", "region_change"),
        (KIND_MEMPROT, 1) => ("memory", "mprotect"),
        (KIND_MEMPROT, 2) => ("memory", "mmap"),
        (KIND_MEMPROT, _) => ("memory", "permission_change"),
        (KIND_EXEC, _) => ("process", "exec"),
        (KIND_PROC, PROC_START) => ("process", "process_start"),
        (KIND_PROC, PROC_EXIT) => ("process", "process_exit"),
        (KIND_PROC, _) => ("process", "process"),
        (KIND_PRIV, 2) => ("kernel", "exec_uid_change"),
        (KIND_PRIV, _) => ("kernel", "setid"),
        (KIND_KERNEL, _) => ("kernel", "kernel_interface"),
        (KIND_NET, NET_SOCKET) => ("network", "socket"),
        (KIND_NET, NET_CONNECT) => ("network", "connect"),
        (KIND_NET, NET_PACKET) => ("network", "packet"),
        (KIND_NET, NET_FRAGMENT) => ("network", "fragment"),
        (KIND_NET, _) => ("network", "network_event"),
        (KIND_HEAP, HEAP_OVERFLOW) => ("memory", "heap_overflow"),
        (KIND_HEAP, HEAP_DOUBLE_FREE) => ("memory", "double_free"),
        (KIND_HEAP, HEAP_INVALID_FREE) => ("memory", "invalid_free"),
        (KIND_HEAP, HEAP_QUARANTINE) => ("memory", "write_after_free"),
        (KIND_HEAP, _) => ("memory", "heap_event"),
        (KIND_FLOW, FLOW_RETURN_SITE) => ("flow", "return_site"),
        (KIND_FLOW, FLOW_INDIRECT) => ("flow", "indirect_branch"),
        (KIND_FLOW, FLOW_STACK) => ("flow", "executable_stack"),
        (KIND_FLOW, FLOW_SHADOW) => ("flow", "shadow_stack"),
        (KIND_FLOW, _) => ("flow", "flow_event"),
        (KIND_FILE, FILE_IO) => ("file", "file_io"),
        (KIND_FILE, FILE_ACTION) => ("file", "file_action"),
        (KIND_FILE, _) => ("file", "file_event"),
        (KIND_TRACE, _) => ("trace", "syscall"),
        (KIND_HEARTBEAT, _) => ("core", "heartbeat"),
        _ => ("trace", "unknown"),
    };
    let source = event_source(event);
    let severity = event.severity.min(SEV_CRITICAL);
    let mut detail = event.text().to_string();
    if detail.is_empty() {
        detail = format!(
            "a={:x} b={:x} c={:x} d={:x}",
            event.arg[0], event.arg[1], event.arg[2], event.arg[3]
        );
    }
    Some(Normalized {
        source,
        kind,
        severity: severity_name(severity),
        severity_code: severity,
        confidence: event.confidence_x1000.min(1000),
        pid: event.pid,
        tid: event.tid,
        seq: event.seq,
        ts_ns: if event.ts_ns == 0 { now_ns } else { event.ts_ns },
        detail,
        subkind: event.subkind,
        event_kind: event.kind,
        arg: event.arg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_events() {
        let mut event = Event::new(KIND_PROC, 1, 2, 3);
        assert!(validate(&event).is_ok());
        event.size = 12;
        assert_eq!(validate(&event), Err("event size"));
        event.size = EVENT_SIZE as u32;
        event.abi_version = 9;
        assert_eq!(validate(&event), Err("abi version"));
        event.abi_version = ABI_VERSION;
        event.kind = KIND_NONE;
        assert_eq!(validate(&event), Err("event kind"));
    }

    #[test]
    fn maps_process_lifecycle_subkinds() {
        let mut event = Event::new(KIND_PROC, 4, 5, 7);
        event.subkind = PROC_START;
        assert_eq!(normalize(&event, 9).unwrap().kind, "process_start");
        event.subkind = PROC_EXIT;
        assert_eq!(normalize(&event, 9).unwrap().kind, "process_exit");
    }

    #[test]
    fn maps_kinds_to_sources() {
        let mut event = Event::new(KIND_HEAP, 4, 5, 7);
        event.subkind = HEAP_DOUBLE_FREE;
        event.set_text("double_free");
        let item = normalize(&event, 9).unwrap();
        assert_eq!(item.source, "memory");
        assert_eq!(item.kind, "double_free");
        assert_eq!(item.ts_ns, 5);
    }

    #[test]
    fn marked_packets_report_capture_source() {
        let mut event = Event::new(KIND_NET, 4, 5, 7);
        event.subkind = NET_PACKET;
        event.set_text("4500");
        assert_eq!(normalize(&event, 9).unwrap().source, "network");
        event.arg[3] = ffi::CAPTURE_SOURCE_MARK;
        let item = normalize(&event, 9).unwrap();
        assert_eq!(item.source, "capture");
        assert_eq!(item.kind, "packet");
    }

    #[test]
    fn marked_non_network_events_report_ksensor_source() {
        let mut event = Event::new(KIND_EXEC, 4, 5, 7);
        event.set_text("kernel_rootkit");
        assert_eq!(normalize(&event, 9).unwrap().source, "process");
        event.arg[3] = ffi::KSENSOR_SOURCE_MARK;
        let item = normalize(&event, 9).unwrap();
        assert_eq!(item.source, "ksensor");
        assert_eq!(item.kind, "exec");

        let mut network = Event::new(KIND_NET, 5, 5, 7);
        network.set_text("4500");
        network.arg[3] = ffi::KSENSOR_SOURCE_MARK;
        assert_eq!(normalize(&network, 9).unwrap().source, "network");
    }

    #[test]
    fn marked_non_network_events_report_kernel_source() {
        let mut event = Event::new(KIND_PROC, 4, 5, 7);
        event.set_text("kernel_bootstrap");
        assert_eq!(normalize(&event, 9).unwrap().source, "process");
        event.arg[3] = ffi::KERNEL_SOURCE_MARK;
        let item = normalize(&event, 9).unwrap();
        assert_eq!(item.source, "kernel");
        assert_eq!(item.kind, "process");

        let mut network = Event::new(KIND_NET, 5, 5, 7);
        network.set_text("4500");
        network.arg[3] = ffi::KERNEL_SOURCE_MARK;
        assert_eq!(normalize(&network, 9).unwrap().source, "network");
    }
}
