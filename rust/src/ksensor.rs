use crate::abi::OK;
use crate::ffi;
use crate::policy::Policy;
use std::ffi::{c_char, c_void};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensorState {
    Active,
    Unavailable,
    Disabled,
}

impl SensorState {
    pub fn name(self) -> &'static str {
        match self {
            SensorState::Active => "active",
            SensorState::Unavailable => "unavailable",
            SensorState::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub bpf: bool,
    pub perf: bool,
    pub lsm: bool,
}

pub struct KSensor {
    handle: *mut c_void,
    pub reason: String,
    state: SensorState,
}

unsafe impl Send for KSensor {}

fn reason_string(buffer: &[c_char], fallback: &str) -> String {
    let bytes: Vec<u8> = buffer
        .iter()
        .take_while(|value| **value != 0)
        .map(|value| *value as u8)
        .collect();
    if bytes.is_empty() {
        fallback.to_string()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

pub fn open_flags(policy: &Policy) -> u32 {
    let mut flags = ffi::KSENSOR_FLAG_RAW_TRACEPOINTS | ffi::KSENSOR_FLAG_PERF_RING;
    if policy.lsm_enforce {
        flags |= ffi::KSENSOR_FLAG_LSM;
    }
    flags
}

pub fn state_from_status(status: &ffi::KSensorStatus) -> SensorState {
    if status.sensor_active != 0 {
        SensorState::Active
    } else if status.reason[0] != 0 {
        SensorState::Unavailable
    } else {
        SensorState::Disabled
    }
}

pub fn status_name(status: &ffi::KSensorStatus) -> &'static str {
    state_from_status(status).name()
}

pub fn status_reason(status: &ffi::KSensorStatus) -> String {
    reason_string(&status.reason, "kernel sensor status unavailable")
}

impl KSensor {
    pub fn probe() -> Result<Probe, String> {
        let mut bpf = 0u32;
        let mut perf = 0u32;
        let mut lsm = 0u32;
        let status = unsafe { ffi::ap_ksensor_probe(&mut bpf, &mut perf, &mut lsm) };
        if status != OK {
            return Err(format!("kernel sensor probe failed ({})", status));
        }
        Ok(Probe {
            bpf: bpf != 0,
            perf: perf != 0,
            lsm: lsm != 0,
        })
    }

    pub fn open(policy: &Policy) -> Result<Self, String> {
        let probe = Self::probe()?;
        let flags = open_flags(policy);
        let mut handle: *mut c_void = std::ptr::null_mut();
        let mut buffer = [0 as c_char; ffi::KSENSOR_REASON_LEN];
        let status = unsafe {
            ffi::ap_ksensor_open(
                flags,
                policy.lsm_mask,
                &mut handle,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if status != OK || handle.is_null() {
            if !handle.is_null() {
                unsafe { ffi::ap_ksensor_close(handle) };
            }
            let reason = reason_string(&buffer, "kernel sensor open failed");
            let reason = if probe.bpf && probe.perf {
                reason
            } else {
                format!(
                    "{} (bpf={}, perf={}, lsm={})",
                    reason, probe.bpf, probe.perf, probe.lsm
                )
            };
            return Err(reason);
        }
        Ok(Self {
            handle,
            reason: reason_string(&buffer, "kernel sensor active"),
            state: SensorState::Active,
        })
    }

    pub fn handle(&self) -> *mut c_void {
        self.handle
    }

    pub fn state(&self) -> SensorState {
        self.state
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn poll(&self, max_events: u32, callback: ffi::KSensorCallback,
                user: *mut c_void) -> i32 {
        unsafe { ffi::ap_ksensor_poll(self.handle, max_events, callback, user) }
    }

    pub fn lsm_set_mask(&self, mask: u32) -> i32 {
        unsafe { ffi::ap_ksensor_lsm_set_mask(self.handle, mask) }
    }

    pub fn counters(&self) -> ffi::KSensorCounters {
        let mut counters = ffi::KSensorCounters::default();
        unsafe { ffi::ap_ksensor_counters(self.handle, &mut counters) };
        counters
    }

    pub fn status(&self) -> ffi::KSensorStatus {
        let mut status = ffi::KSensorStatus::default();
        unsafe { ffi::ap_ksensor_status(self.handle, &mut status) };
        status
    }
}

impl Drop for KSensor {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::ap_ksensor_close(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_names_are_consistent() {
        let mut status = ffi::KSensorStatus::default();
        assert_eq!(state_from_status(&status), SensorState::Disabled);
        assert_eq!(status_name(&status), "disabled");
        assert_eq!(status_name(&status), SensorState::Disabled.name());

        status.reason[0] = b'x' as c_char;
        assert_eq!(state_from_status(&status), SensorState::Unavailable);
        assert_eq!(status_name(&status), "unavailable");

        status.sensor_active = 1;
        assert_eq!(state_from_status(&status), SensorState::Active);
        assert_eq!(status_name(&status), SensorState::Active.name());
    }

    #[test]
    fn status_reason_reads_c_buffer() {
        let mut status = ffi::KSensorStatus::default();
        assert_eq!(status_reason(&status), "kernel sensor status unavailable");
        for (index, byte) in b"bpf denied".iter().enumerate() {
            status.reason[index] = *byte as c_char;
        }
        assert_eq!(status_reason(&status), "bpf denied");
    }

    #[test]
    fn lsm_policy_maps_to_c_flag() {
        let mut policy = Policy::default();
        assert_eq!(
            open_flags(&policy),
            ffi::KSENSOR_FLAG_RAW_TRACEPOINTS | ffi::KSENSOR_FLAG_PERF_RING
        );
        policy.kernel_sensor = true;
        assert_eq!(
            open_flags(&policy),
            ffi::KSENSOR_FLAG_RAW_TRACEPOINTS | ffi::KSENSOR_FLAG_PERF_RING
        );
        policy.lsm_enforce = true;
        policy.lsm_mask = 0xff;
        assert_eq!(
            open_flags(&policy),
            ffi::KSENSOR_FLAG_RAW_TRACEPOINTS
                | ffi::KSENSOR_FLAG_PERF_RING
                | ffi::KSENSOR_FLAG_LSM
        );
        assert_eq!(policy.lsm_mask, 0xff);
    }
}
