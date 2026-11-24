use crate::ffi;
use crate::store::Store;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const WAIT_STEPS: u32 = 25;
const WAIT_STEP_MS: u64 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterStatus {
    Complete,
    Degraded,
    Failed,
}

impl WriterStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WriterReport {
    pub status: WriterStatus,
    pub queued: u64,
    pub dropped: u64,
}

pub struct Writer {
    fd: i32,
    pid: i32,
    queued: u64,
    dropped: u64,
    failed: bool,
}

fn c_path(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| "bad audit path".to_string())
}

fn clean_exit(status: i32) -> bool {
    (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0
}

impl Writer {
    pub fn start(store: &Path, key: &Path) -> Result<Self, String> {
        let c_store = c_path(store)?;
        let c_key = c_path(key)?;
        let mut fd = -1;
        let mut pid = -1;
        let status = unsafe {
            ffi::ap_audit_writer_spawn(
                c_store.as_ptr(),
                c_key.as_ptr(),
                &mut fd,
                &mut pid,
            )
        };
        if status != crate::abi::OK || fd < 0 || pid <= 0 {
            return Err("audit writer spawn failed".to_string());
        }
        Ok(Self {
            fd,
            pid,
            queued: 0,
            dropped: 0,
            failed: false,
        })
    }

    pub fn queued(&self) -> u64 {
        self.queued
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn send(&mut self, line: &str) -> bool {
        if self.failed || line.is_empty() || line.len() > ffi::AUDIT_MAX_PAYLOAD {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let status = unsafe { ffi::ap_audit_send(self.fd, line.as_ptr(), line.len()) };
        if status == crate::abi::OK {
            self.queued = self.queued.saturating_add(1);
            return true;
        }
        self.dropped = self.dropped.saturating_add(1);
        if status == crate::abi::ERR_IO {
            self.failed = true;
        }
        false
    }

    pub fn finish(mut self) -> WriterReport {
        if self.fd >= 0 {
            unsafe { ffi::close(self.fd) };
            self.fd = -1;
        }
        let mut status = 0i32;
        let mut reaped = false;
        for _ in 0..WAIT_STEPS {
            let result = unsafe { ffi::waitpid(self.pid, &mut status, ffi::WNOHANG) };
            if result == self.pid {
                reaped = true;
                break;
            }
            if result < 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(WAIT_STEP_MS));
        }
        if !reaped {
            unsafe { ffi::kill(self.pid, ffi::SIGTERM) };
            for _ in 0..5 {
                let result = unsafe { ffi::waitpid(self.pid, &mut status, ffi::WNOHANG) };
                if result == self.pid || result < 0 {
                    reaped = result == self.pid;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(WAIT_STEP_MS));
            }
        }
        let status = if !reaped || !clean_exit(status) {
            WriterStatus::Failed
        } else if self.dropped > 0 {
            WriterStatus::Degraded
        } else {
            WriterStatus::Complete
        };
        WriterReport {
            status,
            queued: self.queued,
            dropped: self.dropped,
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { ffi::close(self.fd) };
            self.fd = -1;
        }
    }
}

pub fn writer_loop(store: &Path, key: &Path) -> Result<(), String> {
    let mut store = Store::open_signed_with_key(store, 4 * 1024 * 1024, key)?;
    let mut buffer = [0u8; ffi::AUDIT_MAX_PAYLOAD];
    loop {
        let mut len = 0usize;
        let status = unsafe {
            ffi::ap_audit_recv(
                0,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut len,
            )
        };
        if status != crate::abi::OK {
            return Err("audit frame read failed".to_string());
        }
        if len == 0 {
            return Ok(());
        }
        let line = std::str::from_utf8(&buffer[..len])
            .map_err(|_| "audit frame is not text".to_string())?;
        if !store.append(line) {
            return Err("audit store append failed".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_status_names_match_stream() {
        assert_eq!(WriterStatus::Complete.as_str(), "complete");
        assert_eq!(WriterStatus::Degraded.as_str(), "degraded");
        assert_eq!(WriterStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn clean_exit_accepts_zero_only() {
        assert!(clean_exit(0));
        assert!(!clean_exit(9));
        assert!(!clean_exit(15));
    }
}
