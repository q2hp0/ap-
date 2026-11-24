use crate::ffi;
use std::ffi::{c_void, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub struct Kernel {
    ptr: *mut c_void,
}

unsafe impl Send for Kernel {}

impl Kernel {
    pub fn open_file(path: &Path) -> Option<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let ptr = unsafe { ffi::ap_kernel_open_file(path.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    pub fn pending(&self) -> u32 {
        unsafe { ffi::ap_kernel_pending(self.ptr) }
    }

    pub fn poll(&self, max_events: u32, callback: ffi::KernelCallback,
                user: *mut c_void) -> i32 {
        unsafe { ffi::ap_kernel_poll(self.ptr, max_events, callback, user) }
    }

    pub fn counters(&self) -> ffi::KernelCounters {
        let mut counters = ffi::KernelCounters::default();
        unsafe { ffi::ap_kernel_stats(self.ptr, &mut counters) };
        counters
    }
}

impl Drop for Kernel {
    fn drop(&mut self) {
        unsafe { ffi::ap_kernel_free(self.ptr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{EVENT_SIZE, KIND_PROC};
    use std::fs;

    extern "C" fn gather(event: *const crate::abi::Event,
                         user: *mut c_void) -> std::ffi::c_int {
        if event.is_null() || user.is_null() {
            return 1;
        }
        let events = unsafe { &mut *(user as *mut Vec<crate::abi::Event>) };
        events.push(unsafe { *event });
        0
    }

    fn push_event(out: &mut Vec<u8>, seq: u64, text: &str) {
        out.extend_from_slice(&(EVENT_SIZE as u32).to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&(KIND_PROC as u16).to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&1000u64.to_le_bytes());
        out.extend_from_slice(&42i64.to_le_bytes());
        out.extend_from_slice(&42i64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&900u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        for _ in 0..4 {
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        let mut field = [0u8; 128];
        let bytes = text.as_bytes();
        let len = bytes.len().min(field.len() - 1);
        field[..len].copy_from_slice(&bytes[..len]);
        out.extend_from_slice(&field);
    }

    #[test]
    fn replays_bounded_marked_events() {
        let path = std::env::temp_dir().join(format!("ap-kernel-test-{}.apk1", std::process::id()));
        let mut content = Vec::new();
        content.extend_from_slice(b"apk1");
        content.extend_from_slice(&2u32.to_le_bytes());
        push_event(&mut content, 1, "probe");
        push_event(&mut content, 2, "probe");
        fs::write(&path, content).unwrap();

        let kernel = Kernel::open_file(&path).unwrap();
        assert_eq!(kernel.pending(), 2);
        let mut events: Vec<crate::abi::Event> = Vec::new();
        assert_eq!(
            kernel.poll(ffi::KERNEL_MAX_EVENTS, gather,
                        &mut events as *mut Vec<crate::abi::Event> as *mut c_void),
            0
        );
        assert_eq!(kernel.pending(), 0);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(events[0].arg[3], ffi::KERNEL_SOURCE_MARK);
        assert_eq!(events[0].text(), "probe");
        let counters = kernel.counters();
        assert_eq!(counters.frames, 2);
        assert_eq!(counters.parsed, 2);
        assert_eq!(counters.invalid, 0);
        assert_eq!(counters.errors, 0);
        drop(kernel);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_bad_header_and_missing_file() {
        let dir = std::env::temp_dir().join(format!("ap-kernel-test-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.apk1");
        fs::write(&bad, b"apk1").unwrap();
        assert!(Kernel::open_file(&bad).is_none());
        let missing = dir.join("missing.apk1");
        assert!(Kernel::open_file(&missing).is_none());
        assert!(Kernel::open_file(Path::new("")).is_none());
        fs::remove_dir_all(dir).unwrap();
    }
}
