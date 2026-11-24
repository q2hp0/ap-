use crate::abi::OK;
#[cfg(test)]
use crate::abi::ERR_ARG;
use crate::cli::{escape, Cli};
use crate::ffi;
use std::ffi::{c_char, CStr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceState {
    Active,
    Degraded,
    Unavailable,
    Disabled,
}

impl SourceState {
    fn text(self) -> &'static str {
        match self {
            SourceState::Active => "active",
            SourceState::Degraded => "degraded",
            SourceState::Unavailable => "unavailable",
            SourceState::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourceStatus {
    pub id: u32,
    pub name: String,
    pub cap: u32,
    pub state: SourceState,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct SourceRegistry {
    pub sources: Vec<SourceStatus>,
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", escape(value))
}

impl SourceRegistry {
    pub fn new(caps: u32, trace: bool, ipc: bool, proc: bool,
               capture_active: bool, capture_reason: Option<&str>,
               kernel_active: bool, kernel_reason: Option<&str>,
               ksensor_active: bool, ksensor_reason: Option<&str>,
               lsm_active: bool, lsm_reason: Option<&str>) -> Self {
        let capture_requested = capture_active || capture_reason.is_some();
        let kernel_requested = kernel_active || kernel_reason.is_some();
        let ksensor_requested = ksensor_active || ksensor_reason.is_some();
        let lsm_requested = lsm_active || lsm_reason.is_some();
        let mut sources = Vec::new();
        let mut index = 0u32;
        loop {
            let mut desc = ffi::SourceDesc {
                id: 0,
                name: std::ptr::null::<c_char>(),
                cap: 0,
            };
            let status = unsafe { ffi::ap_source_describe(index, &mut desc) };
            if status != OK {
                break;
            }
            let name = if desc.name.is_null() {
                String::from("unknown")
            } else {
                unsafe { CStr::from_ptr(desc.name) }.to_string_lossy().into_owned()
            };
            let cap_ok = desc.cap == 0 || caps & desc.cap != 0;
            let (state, reason) = match desc.id {
                ffi::SOURCE_TRACE if !trace => (
                    SourceState::Disabled,
                    String::from("no supervised command requested"),
                ),
                ffi::SOURCE_TRACE if !cap_ok => (
                    SourceState::Unavailable,
                    String::from("ptrace denied by kernel policy"),
                ),
                ffi::SOURCE_TRACE => (SourceState::Active, String::from("supervised child")),
                ffi::SOURCE_IPC if !ipc => (
                    SourceState::Disabled,
                    String::from("no telemetry socket opened"),
                ),
                ffi::SOURCE_IPC => (
                    SourceState::Active,
                    String::from("authenticated datagram transport"),
                ),
                ffi::SOURCE_PROC if !proc => (
                    SourceState::Disabled,
                    String::from("system process scan disabled"),
                ),
                ffi::SOURCE_PROC if cap_ok => (
                    SourceState::Active,
                    String::from("bounded /proc process scan"),
                ),
                ffi::SOURCE_PROC => (
                    SourceState::Unavailable,
                    String::from("process maps unreadable"),
                ),
                ffi::SOURCE_PERF if ksensor_active && cap_ok => (
                    SourceState::Active,
                    String::from("kernel sensor raw tracepoint/perf ring"),
                ),
                ffi::SOURCE_PERF if cap_ok => (
                    SourceState::Degraded,
                    String::from("perf available but no collector loaded"),
                ),
                ffi::SOURCE_PERF => (
                    SourceState::Unavailable,
                    String::from("perf_event_open denied"),
                ),
                ffi::SOURCE_TRACEPOINT if ksensor_active && cap_ok => (
                    SourceState::Active,
                    String::from("kernel sensor raw tracepoint/perf ring"),
                ),
                ffi::SOURCE_TRACEPOINT if cap_ok => (
                    SourceState::Degraded,
                    String::from("tracepoints available but no collector loaded"),
                ),
                ffi::SOURCE_TRACEPOINT => (
                    SourceState::Unavailable,
                    String::from("tracepoint interface unreadable"),
                ),
                ffi::SOURCE_BPF if ksensor_active && cap_ok => (
                    SourceState::Active,
                    String::from("kernel sensor raw tracepoint/perf ring"),
                ),
                ffi::SOURCE_BPF if cap_ok => (
                    SourceState::Degraded,
                    String::from("bpf available but no program loaded"),
                ),
                ffi::SOURCE_BPF => (
                    SourceState::Unavailable,
                    String::from("bpf syscall unavailable or denied"),
                ),
                ffi::SOURCE_CAPTURE if !capture_requested => (
                    SourceState::Disabled,
                    String::from("no packet capture requested"),
                ),
                ffi::SOURCE_CAPTURE if capture_active => (
                    SourceState::Active,
                    String::from("bounded packet capture"),
                ),
                ffi::SOURCE_CAPTURE => (
                    SourceState::Unavailable,
                    capture_reason
                        .unwrap_or("packet capture unavailable")
                        .to_string(),
                ),
                ffi::SOURCE_KERNEL if !kernel_requested => (
                    SourceState::Disabled,
                    String::from("no kernel event file requested"),
                ),
                ffi::SOURCE_KERNEL if kernel_active => (
                    SourceState::Active,
                    String::from("bounded kernel event file replay"),
                ),
                ffi::SOURCE_KERNEL => (
                    SourceState::Unavailable,
                    kernel_reason
                        .unwrap_or("kernel event file unavailable")
                        .to_string(),
                ),
                ffi::SOURCE_KSENSOR if !ksensor_requested => (
                    SourceState::Disabled,
                    String::from("no kernel sensor requested"),
                ),
                ffi::SOURCE_KSENSOR if ksensor_active => (
                    SourceState::Active,
                    ksensor_reason
                        .unwrap_or("kernel sensor raw tracepoint/perf ring")
                        .to_string(),
                ),
                ffi::SOURCE_KSENSOR => (
                    SourceState::Unavailable,
                    ksensor_reason
                        .unwrap_or("kernel sensor unavailable")
                        .to_string(),
                ),
                ffi::SOURCE_LSM if !lsm_requested => (
                    SourceState::Disabled,
                    String::from("no lsm enforcement requested"),
                ),
                ffi::SOURCE_LSM if lsm_active => (
                    SourceState::Active,
                    lsm_reason
                        .unwrap_or("bpf lsm enforcement active")
                        .to_string(),
                ),
                ffi::SOURCE_LSM => (
                    SourceState::Unavailable,
                    lsm_reason
                        .unwrap_or("bpf lsm unavailable")
                        .to_string(),
                ),
                _ => (SourceState::Unavailable, String::from("unknown source")),
            };
            sources.push(SourceStatus {
                id: desc.id,
                name,
                cap: desc.cap,
                state,
                reason,
            });
            index += 1;
        }
        Self { sources }
    }

    pub fn emit(&self, cli: &Cli) {
        let mut fields: Vec<(&str, String)> = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            fields.push((source.name.as_str(), quoted(source.state.text())));
        }
        cli.status("sources", &fields);
        for source in &self.sources {
            if source.state == SourceState::Active || source.state == SourceState::Disabled {
                continue;
            }
            cli.status("degraded", &[
                ("source", quoted(&source.name)),
                ("state", quoted(source.state.text())),
                ("reason", quoted(&source.reason)),
            ]);
        }
    }

    pub fn active_json(&self) -> String {
        let names: Vec<String> = self
            .sources
            .iter()
            .filter(|source| source.state == SourceState::Active)
            .map(|source| quoted(&source.name))
            .collect();
        format!("[{}]", names.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_every_source_by_name() {
        let registry = SourceRegistry::new(
            0, false, false, false, false, None, false, None, false, None, false, None,
        );
        assert_eq!(registry.sources.len(), 10);
        for status in &registry.sources {
            assert!(!status.name.is_empty());
            assert_ne!(status.state, SourceState::Active);
        }
        assert_eq!(registry.sources[8].name, "ksensor");
        assert_eq!(registry.sources[8].state, SourceState::Disabled);
        assert_eq!(registry.sources[9].name, "lsm");
        assert_eq!(registry.sources[9].state, SourceState::Disabled);
        assert_eq!(registry.active_json(), "[]");
    }

    #[test]
    fn requested_sources_become_active() {
        let all = u32::MAX;
        let registry = SourceRegistry::new(
            all, true, true, true, false, None, false, None, false, None, false, None,
        );
        assert_eq!(registry.sources.len(), 10);
        assert_eq!(registry.sources[0].state, SourceState::Active);
        assert_eq!(registry.sources[1].state, SourceState::Active);
        assert_eq!(registry.sources[2].state, SourceState::Active);
        assert_eq!(registry.sources[3].state, SourceState::Degraded);
        assert_eq!(registry.sources[4].state, SourceState::Degraded);
        assert_eq!(registry.sources[5].state, SourceState::Degraded);
        assert_eq!(registry.sources[6].name, "capture");
        assert_eq!(registry.sources[6].state, SourceState::Disabled);
        assert_eq!(registry.sources[7].name, "kernel");
        assert_eq!(registry.sources[7].state, SourceState::Disabled);
        assert_eq!(registry.sources[8].state, SourceState::Disabled);
        assert_eq!(registry.sources[9].state, SourceState::Disabled);
        let active = registry.active_json();
        assert!(active.contains("\"trace\""));
        assert!(active.contains("\"ipc\""));
        assert!(!active.contains("\"bpf\""));
        assert!(!active.contains("\"ksensor\""));
    }

    #[test]
    fn disabled_proc_scan_is_reported() {
        let registry = SourceRegistry::new(
            u32::MAX, false, false, false, false, None, false, None, false, None, false, None,
        );
        assert_eq!(registry.sources[2].state, SourceState::Disabled);
        assert_eq!(registry.sources[2].reason, "system process scan disabled");
    }

    #[test]
    fn capture_source_reports_active_and_degraded_states() {
        let active = SourceRegistry::new(
            u32::MAX, false, false, false, true, None, false, None, false, None, false, None,
        );
        assert_eq!(active.sources[6].state, SourceState::Active);
        assert!(active.active_json().contains("\"capture\""));

        let denied = SourceRegistry::new(
            0,
            false,
            false,
            false,
            false,
            Some("raw packet socket denied by kernel policy"),
            false,
            None,
            false,
            None,
            false,
            None,
        );
        assert_eq!(denied.sources[6].state, SourceState::Unavailable);
        assert_eq!(denied.sources[6].reason, "raw packet socket denied by kernel policy");
        assert!(!denied.active_json().contains("\"capture\""));
    }

    #[test]
    fn kernel_source_reports_file_replay_states() {
        let active = SourceRegistry::new(
            0, false, false, false, false, None, true, None, false, None, false, None,
        );
        assert_eq!(active.sources[7].state, SourceState::Active);
        assert_eq!(active.sources[7].reason, "bounded kernel event file replay");
        assert!(active.active_json().contains("\"kernel\""));

        let denied = SourceRegistry::new(
            0,
            false,
            false,
            false,
            false,
            None,
            false,
            Some("kernel event file open failed or invalid"),
            false,
            None,
            false,
            None,
        );
        assert_eq!(denied.sources[7].state, SourceState::Unavailable);
        assert_eq!(denied.sources[7].reason, "kernel event file open failed or invalid");
        assert!(!denied.active_json().contains("\"kernel\""));
    }

    #[test]
    fn active_ksensor_promotes_capable_sources() {
        let registry = SourceRegistry::new(
            u32::MAX, false, false, false, false, None, false, None, true, None, false, None,
        );
        assert_eq!(registry.sources[8].state, SourceState::Active);
        for index in [3usize, 4, 5] {
            assert_eq!(registry.sources[index].state, SourceState::Active);
            assert_eq!(
                registry.sources[index].reason,
                "kernel sensor raw tracepoint/perf ring"
            );
        }
        let active = registry.active_json();
        assert!(active.contains("\"ksensor\""));
        assert!(active.contains("\"perf\""));
        assert!(active.contains("\"tracepoints\""));
        assert!(active.contains("\"bpf\""));
    }

    #[test]
    fn unavailable_ksensor_reports_reason_and_honest_capabilities() {
        let registry = SourceRegistry::new(
            0,
            false,
            false,
            false,
            false,
            None,
            false,
            None,
            false,
            Some("bpf syscall unavailable or denied"),
            false,
            None,
        );
        assert_eq!(registry.sources[8].state, SourceState::Unavailable);
        assert_eq!(registry.sources[8].reason, "bpf syscall unavailable or denied");
        assert_eq!(registry.sources[3].state, SourceState::Unavailable);
        assert_eq!(
            registry.sources[3].reason,
            "perf_event_open denied"
        );
        assert!(!registry.active_json().contains("\"ksensor\""));
    }

    #[test]
    fn lsm_source_reports_active_and_unavailable_states() {
        let active = SourceRegistry::new(
            u32::MAX, false, false, false, false, None, false, None, true, None, true, None,
        );
        assert_eq!(active.sources[9].state, SourceState::Active);
        assert!(active.active_json().contains("\"lsm\""));

        let denied = SourceRegistry::new(
            u32::MAX,
            false,
            false,
            false,
            false,
            None,
            false,
            None,
            true,
            None,
            false,
            Some("bpf lsm attach failed"),
        );
        assert_eq!(denied.sources[9].state, SourceState::Unavailable);
        assert_eq!(denied.sources[9].reason, "bpf lsm attach failed");
        assert!(!denied.active_json().contains("\"lsm\""));
    }

    #[test]
    fn unknown_descriptor_is_rejected() {
        let mut desc = ffi::SourceDesc {
            id: 0,
            name: std::ptr::null::<c_char>(),
            cap: 0,
        };
        assert_eq!(unsafe { ffi::ap_source_describe(u32::MAX, &mut desc) }, ERR_ARG);
    }
}
