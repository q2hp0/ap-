pub const ABI_VERSION: u16 = 2;
pub const TEXT_LEN: usize = 128;
pub const EVENT_SIZE: usize = 216;
pub const VERDICT_SIZE: usize = 168;

pub const OK: i32 = 0;
pub const ERR_ARG: i32 = -1;
pub const ERR_STATE: i32 = -2;
pub const ERR_NOMEM: i32 = -3;
pub const ERR_IO: i32 = -4;
pub const ERR_UNSUPPORTED: i32 = -5;
pub const ERR_RANGE: i32 = -6;
pub const ERR_AUTH: i32 = -7;
pub const ERR_REPLAY: i32 = -8;
pub const ERR_SEQUENCE: i32 = -9;

pub const KIND_NONE: u16 = 0;
pub const KIND_PROC: u16 = 1;
pub const KIND_MEMREGION: u16 = 2;
pub const KIND_MEMPROT: u16 = 3;
pub const KIND_EXEC: u16 = 4;
pub const KIND_PRIV: u16 = 5;
pub const KIND_KERNEL: u16 = 6;
pub const KIND_NET: u16 = 7;
pub const KIND_HEAP: u16 = 8;
pub const KIND_FLOW: u16 = 9;
pub const KIND_TRACE: u16 = 10;
pub const KIND_HEARTBEAT: u16 = 11;
pub const KIND_FILE: u16 = 12;

pub const SEV_INFO: u32 = 0;
pub const SEV_LOW: u32 = 1;
pub const SEV_MEDIUM: u32 = 2;
pub const SEV_HIGH: u32 = 3;
pub const SEV_CRITICAL: u32 = 4;

pub const DECISION_ALLOW: i32 = 0;
pub const DECISION_DENY: i32 = 1;
pub const DECISION_STOP: i32 = 2;

pub const PROC_INFO: u32 = 0;
pub const PROC_EXEC_PATH: u32 = 1;
pub const PROC_EXEC_COMM: u32 = 2;
pub const PROC_START: u32 = 3;
pub const PROC_EXIT: u32 = 4;

pub const NET_SOCKET: u32 = 1;
pub const NET_CONNECT: u32 = 2;
pub const NET_PACKET: u32 = 3;
pub const NET_FRAGMENT: u32 = 4;

pub const FLOW_RETURN_SITE: u32 = 1;
pub const FLOW_INDIRECT: u32 = 2;
pub const FLOW_STACK: u32 = 3;
pub const FLOW_SHADOW: u32 = 4;

pub const HEAP_OVERFLOW: u32 = 1;
pub const HEAP_DOUBLE_FREE: u32 = 2;
pub const HEAP_INVALID_FREE: u32 = 3;
pub const HEAP_QUARANTINE: u32 = 4;

pub const FILE_IO: u32 = 1;
pub const FILE_ACTION: u32 = 2;

pub const RULE_NONE: u32 = 0;
pub const RULE_WX_REGION: u32 = 1;
pub const RULE_WX_TRANSITION: u32 = 2;
pub const RULE_STACK_EXEC: u32 = 3;
pub const RULE_RETURN_OUTSIDE_EXEC: u32 = 4;
pub const RULE_SHADOW_MISMATCH: u32 = 5;
pub const RULE_PRIV_CROSSING: u32 = 6;
pub const RULE_MODULE_LOAD: u32 = 7;
pub const RULE_KERNEL_IFACE: u32 = 8;
pub const RULE_TCP_STATE: u32 = 9;
pub const RULE_TCP_FLAGS: u32 = 10;
pub const RULE_IP_MALFORMED: u32 = 11;
pub const RULE_FRAG_OVERLAP: u32 = 12;
pub const RULE_HEAP_CANARY: u32 = 13;
pub const RULE_DOUBLE_FREE: u32 = 14;
pub const RULE_INVALID_FREE: u32 = 15;
pub const RULE_CORRELATED: u32 = 16;
pub const RULE_RAW_SOCKET: u32 = 17;
pub const RULE_EXEC_AFTER_WX: u32 = 18;
pub const RULE_KERNEL_CHAIN: u32 = 19;
pub const RULE_KERNEL_ROOTKIT: u32 = 20;
pub const RULE_CREDENTIAL_THEFT: u32 = 21;
pub const RULE_PERSISTENCE: u32 = 22;
pub const RULE_CONTAINER_ESCAPE: u32 = 23;
pub const RULE_FILELESS_EXEC: u32 = 24;
pub const RULE_ANTI_ANALYSIS: u32 = 25;
pub const RULE_BEACONING: u32 = 26;
pub const RULE_PROCESS_INJECTION: u32 = 27;
pub const RULE_EXPLOIT_CHAIN: u32 = 28;
pub const RULE_CREDENTIAL_DUMP: u32 = 29;
pub const RULE_FILE_WRITE_BURST: u32 = 30;
pub const RULE_DESTRUCTIVE_CHAIN: u32 = 31;
pub const RULE_DATA_EXFILTRATION: u32 = 32;
pub const RULE_MAX: u32 = 32;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub size: u32,
    pub abi_version: u16,
    pub kind: u16,
    pub seq: u64,
    pub ts_ns: u64,
    pub pid: i64,
    pub tid: i64,
    pub subkind: u32,
    pub severity: u32,
    pub confidence_x1000: u32,
    pub arg: [u64; 4],
    pub text: [u8; TEXT_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    pub size: u32,
    pub abi_version: u16,
    pub kind: u16,
    pub event_seq: u64,
    pub rule: u32,
    pub severity: u32,
    pub confidence_x1000: u32,
    pub evidence: u64,
    pub text: [u8; TEXT_LEN],
}

impl Event {
    pub fn new(kind: u16, seq: u64, ts_ns: u64, pid: i64) -> Self {
        Self {
            size: EVENT_SIZE as u32,
            abi_version: ABI_VERSION,
            kind,
            seq,
            ts_ns,
            pid,
            tid: pid,
            subkind: 0,
            severity: SEV_INFO,
            confidence_x1000: 1000,
            arg: [0; 4],
            text: [0; TEXT_LEN],
        }
    }

    pub fn set_text(&mut self, value: &str) {
        let bytes = value.as_bytes();
        let len = bytes.len().min(TEXT_LEN - 1);
        self.text[..len].copy_from_slice(&bytes[..len]);
        for item in self.text[len..].iter_mut() {
            *item = 0;
        }
    }

    pub fn text(&self) -> &str {
        let len = self.text.iter().position(|b| *b == 0).unwrap_or(TEXT_LEN);
        std::str::from_utf8(&self.text[..len]).unwrap_or("")
    }
}

impl Verdict {
    pub fn new(seq: u64) -> Self {
        Self {
            size: VERDICT_SIZE as u32,
            abi_version: ABI_VERSION,
            kind: 0,
            event_seq: seq,
            rule: RULE_NONE,
            severity: SEV_INFO,
            confidence_x1000: 0,
            evidence: 0,
            text: [0; TEXT_LEN],
        }
    }

    pub fn set_text(&mut self, value: &str) {
        let bytes = value.as_bytes();
        let len = bytes.len().min(TEXT_LEN - 1);
        self.text[..len].copy_from_slice(&bytes[..len]);
        for item in self.text[len..].iter_mut() {
            *item = 0;
        }
    }

    pub fn text(&self) -> &str {
        let len = self.text.iter().position(|b| *b == 0).unwrap_or(TEXT_LEN);
        std::str::from_utf8(&self.text[..len]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_layout_matches_c() {
        assert_eq!(std::mem::size_of::<Event>(), EVENT_SIZE);
        assert_eq!(std::mem::size_of::<Verdict>(), VERDICT_SIZE);
        assert_eq!(std::mem::align_of::<Event>(), 8);
    }

    #[test]
    fn rule_max_matches_c_header() {
        assert_eq!(RULE_MAX, 32);
        assert_eq!(RULE_DATA_EXFILTRATION, RULE_MAX);
    }

    #[test]
    fn text_roundtrip() {
        let mut event = Event::new(KIND_PROC, 1, 10, 42);
        event.set_text("mprotect");
        assert_eq!(event.text(), "mprotect");
        let long = "x".repeat(TEXT_LEN + 10);
        event.set_text(&long);
        assert_eq!(event.text().len(), TEXT_LEN - 1);
        assert_eq!(event.text[TEXT_LEN - 1], 0);
    }
}
