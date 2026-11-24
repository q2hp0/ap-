use crate::ffi;
use std::ffi::c_void;

pub struct ProcCollector {
    ptr: *mut c_void,
}

impl ProcCollector {
    pub fn new(
        max_pids: u32,
        map_samples: u32,
        wx_per_scan: u32,
        io_per_scan: u32,
    ) -> Option<Self> {
        let ptr = unsafe { ffi::ap_collector_new(max_pids) };
        if ptr.is_null() {
            return None;
        }
        let status =
            unsafe { ffi::ap_collector_set_map_limits(ptr, map_samples, wx_per_scan) };
        let io_status = unsafe { ffi::ap_collector_set_io_per_scan(ptr, io_per_scan) };
        if status != crate::abi::OK || io_status != crate::abi::OK {
            unsafe { ffi::ap_collector_free(ptr) };
            return None;
        }
        Some(Self { ptr })
    }

    pub fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn counters(&self) -> ffi::CollectorCounters {
        let mut counters = ffi::CollectorCounters::default();
        unsafe {
            ffi::ap_collector_stats(self.ptr, &mut counters);
        }
        counters
    }
}

impl Drop for ProcCollector {
    fn drop(&mut self) {
        unsafe { ffi::ap_collector_free(self.ptr) };
    }
}
