use crate::ffi;
use std::ffi::{c_int, c_void, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub struct Capture {
    ptr: *mut c_void,
}

unsafe impl Send for Capture {}

impl Capture {
    pub fn open_iface(name: &str, snaplen: u32) -> Option<Self> {
        let name = CString::new(name).ok()?;
        let ptr = unsafe { ffi::ap_capture_open_iface(name.as_ptr(), snaplen) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    pub fn open_file(path: &Path, snaplen: u32) -> Option<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let ptr = unsafe { ffi::ap_capture_open_file(path.as_ptr(), snaplen) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    pub fn poll(&self, max_frames: u32, callback: ffi::CaptureCallback,
                user: *mut c_void, timeout_ms: c_int) -> i32 {
        unsafe { ffi::ap_capture_poll(self.ptr, max_frames, callback, user, timeout_ms) }
    }

    pub fn counters(&self) -> ffi::CaptureCounters {
        let mut counters = ffi::CaptureCounters::default();
        unsafe { ffi::ap_capture_stats(self.ptr, &mut counters) };
        counters
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { ffi::ap_capture_free(self.ptr) };
    }
}
