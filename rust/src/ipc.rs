use crate::abi::Event;
use crate::ffi;
use std::cell::RefCell;
use std::ffi::{CString, c_void};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY_LEN: usize = 32;

pub struct Ipc {
    fd: i32,
    path: PathBuf,
    key: [u8; KEY_LEN],
    client_keys: Option<RefCell<ffi::ClientKeys>>,
    replay: RefCell<ffi::Replay>,
    strict_seq: bool,
    duplicates: Arc<AtomicU64>,
    sequences: Arc<AtomicU64>,
    client_matches: Arc<AtomicU64>,
    client_misses: Arc<AtomicU64>,
}

fn load_client_keys(mappings: &[(u32, PathBuf)]) -> Result<ffi::ClientKeys, String> {
    if mappings.is_empty() {
        return Err("no client keys configured".to_string());
    }
    if mappings.len() > ffi::CLIENT_KEY_MAX {
        return Err("too many client keys".to_string());
    }
    let mut table = ffi::ClientKeys::default();
    let status = unsafe { ffi::ap_client_keys_init(&mut table) };
    if status != crate::abi::OK {
        return Err("client key table unavailable".to_string());
    }
    for (index, (pid, path)) in mappings.iter().enumerate() {
        if *pid == 0 || *pid > i32::MAX as u32 {
            return Err("bad client pid".to_string());
        }
        if mappings[..index].iter().any(|(other, _)| other == pid) {
            return Err("duplicate client pid".to_string());
        }
        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| "bad client key path")?;
        let mut key = [0u8; KEY_LEN];
        let status = unsafe { ffi::ap_transport_key_load_path(c_path.as_ptr(), key.as_mut_ptr()) };
        if status != crate::abi::OK {
            return Err(format!("client key unavailable: {}", path.display()));
        }
        let status = unsafe { ffi::ap_client_keys_add(&mut table, *pid, key.as_ptr()) };
        if status != crate::abi::OK {
            return Err("client key table rejected a mapping".to_string());
        }
    }
    Ok(table)
}

impl Ipc {
    pub fn open(path: &Path, strict_seq: bool) -> Result<Self, String> {
        Self::open_with_client_keys(path, strict_seq, &[])
    }

    pub fn open_with_client_keys(
        path: &Path,
        strict_seq: bool,
        mappings: &[(u32, PathBuf)],
    ) -> Result<Self, String> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "bad socket path")?;
        let mut fd = -1;
        let status = unsafe { ffi::ap_sys_server_open(c_path.as_ptr(), &mut fd) };
        if status != crate::abi::OK {
            return Err(format!("socket bind failed: {}", path.display()));
        }
        let client_keys = if mappings.is_empty() {
            None
        } else {
            match load_client_keys(mappings) {
                Ok(table) => Some(RefCell::new(table)),
                Err(message) => {
                    unsafe { ffi::close(fd) };
                    let _ = std::fs::remove_file(path);
                    return Err(message);
                }
            }
        };
        let mut key = [0u8; KEY_LEN];
        if client_keys.is_none() {
            let key_status =
                unsafe { ffi::ap_transport_key_create(c_path.as_ptr(), key.as_mut_ptr()) };
            if key_status != crate::abi::OK {
                unsafe { ffi::close(fd) };
                let _ = std::fs::remove_file(path);
                return Err(format!("transport key unavailable: {}", path.display()));
            }
        }
        let mut replay: ffi::Replay = unsafe { std::mem::zeroed() };
        unsafe { ffi::ap_replay_init(&mut replay) };
        Ok(Self {
            fd,
            path: path.to_path_buf(),
            key,
            client_keys,
            replay: RefCell::new(replay),
            strict_seq,
            duplicates: Arc::new(AtomicU64::new(0)),
            sequences: Arc::new(AtomicU64::new(0)),
            client_matches: Arc::new(AtomicU64::new(0)),
            client_misses: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn duplicate_counter(&self) -> Arc<AtomicU64> {
        self.duplicates.clone()
    }

    pub fn duplicates(&self) -> u64 {
        self.duplicates.load(Ordering::Relaxed)
    }

    pub fn sequence_counter(&self) -> Arc<AtomicU64> {
        self.sequences.clone()
    }

    pub fn sequence_drops(&self) -> u64 {
        self.sequences.load(Ordering::Relaxed)
    }

    pub fn client_match_counter(&self) -> Arc<AtomicU64> {
        self.client_matches.clone()
    }

    pub fn client_miss_counter(&self) -> Arc<AtomicU64> {
        self.client_misses.clone()
    }

    pub fn client_matches(&self) -> u64 {
        self.client_matches.load(Ordering::Relaxed)
    }

    pub fn client_misses(&self) -> u64 {
        self.client_misses.load(Ordering::Relaxed)
    }

    pub fn recv_event(&self, timeout_ms: i32) -> Option<Event> {
        let mut pfd = ffi::PollFd {
            fd: self.fd,
            events: ffi::POLLIN,
            revents: 0,
        };
        let ready = unsafe { ffi::poll(&mut pfd, 1, timeout_ms) };
        if ready <= 0 || pfd.revents & ffi::POLLIN == 0 {
            return None;
        }
        let mut storage = MaybeUninit::<Event>::uninit();
        let mut received = 0usize;
        let before = self
            .client_keys
            .as_ref()
            .map(|cell| {
                let table = cell.borrow();
                (table.matched, table.unmatched)
            })
            .unwrap_or((0, 0));
        let status = {
            let mut replay = self.replay.borrow_mut();
            let filter = &mut *replay;
            match self.client_keys.as_ref() {
                Some(cell) => {
                    let mut table = cell.borrow_mut();
                    unsafe {
                        ffi::ap_sys_recv_sealed_client(
                            self.fd,
                            &mut *table as *mut ffi::ClientKeys,
                            storage.as_mut_ptr() as *mut c_void,
                            std::mem::size_of::<Event>(),
                            &mut received,
                            filter,
                            if self.strict_seq { 1 } else { 0 },
                        )
                    }
                }
                None => unsafe {
                    if self.strict_seq {
                        ffi::ap_sys_recv_sealed_sequenced(
                            self.fd,
                            self.key.as_ptr(),
                            storage.as_mut_ptr() as *mut c_void,
                            std::mem::size_of::<Event>(),
                            &mut received,
                            filter,
                        )
                    } else {
                        ffi::ap_sys_recv_sealed_filtered(
                            self.fd,
                            self.key.as_ptr(),
                            storage.as_mut_ptr() as *mut c_void,
                            std::mem::size_of::<Event>(),
                            &mut received,
                            filter,
                        )
                    }
                },
            }
        };
        if let Some(cell) = self.client_keys.as_ref() {
            let table = cell.borrow();
            self.client_matches.fetch_add(
                table.matched.saturating_sub(before.0),
                Ordering::Relaxed,
            );
            self.client_misses.fetch_add(
                table.unmatched.saturating_sub(before.1),
                Ordering::Relaxed,
            );
        }
        if status == crate::abi::ERR_REPLAY {
            self.duplicates.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if status == crate::abi::ERR_SEQUENCE {
            self.sequences.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if status != crate::abi::OK || received != std::mem::size_of::<Event>() {
            return None;
        }
        Some(unsafe { storage.assume_init() })
    }
}

impl Drop for Ipc {
    fn drop(&mut self) {
        unsafe {
            ffi::close(self.fd);
        }
        let _ = std::fs::remove_file(&self.path);
        let mut key_path = self.path.clone().into_os_string();
        key_path.push(".key");
        let _ = std::fs::remove_file(PathBuf::from(key_path));
    }
}

pub fn send_event(path: &Path, event: &Event) -> Result<(), String> {
    send_event_with_loader(path, None, event)
}

pub fn send_event_with_key(path: &Path, key_path: &Path, event: &Event) -> Result<(), String> {
    send_event_with_loader(path, Some(key_path), event)
}

fn send_event_with_loader(
    path: &Path,
    key_path: Option<&Path>,
    event: &Event,
) -> Result<(), String> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "bad socket path")?;
    let mut fd = -1;
    let status = unsafe { ffi::ap_sys_client_open(c_path.as_ptr(), &mut fd) };
    if status != crate::abi::OK {
        return Err(format!("cannot connect to {}", path.display()));
    }
    let mut key = [0u8; KEY_LEN];
    let key_status = match key_path {
        Some(source) => {
            let c_key = CString::new(source.as_os_str().as_bytes())
                .map_err(|_| "bad client key path".to_string())?;
            unsafe { ffi::ap_transport_key_load_path(c_key.as_ptr(), key.as_mut_ptr()) }
        }
        None => unsafe { ffi::ap_transport_key_load(c_path.as_ptr(), key.as_mut_ptr()) },
    };
    if key_status != crate::abi::OK {
        unsafe { ffi::close(fd) };
        return Err(format!("cannot load transport key for {}", path.display()));
    }
    let status = unsafe { ffi::ap_sys_send_sealed(fd, key.as_ptr(), event) };
    unsafe { ffi::close(fd) };
    if status != crate::abi::OK {
        return Err(format!("sealed send failed: {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn roundtrip_binary_event() {
        let dir = std::env::temp_dir().join(format!("ap-ipc-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ap.sock");
        let server = Ipc::open(&path, false).unwrap();
        let mut event = Event::new(KIND_HEAP, 11, 12, 13);
        event.subkind = HEAP_DOUBLE_FREE;
        event.set_text("double_free");
        send_event(&path, &event).unwrap();
        let received = server.recv_event(1000).unwrap();
        assert_eq!(received.seq, 11);
        assert_eq!(received.subkind, HEAP_DOUBLE_FREE);
        assert_eq!(received.text(), "double_free");

        let mut key_path = path.clone().into_os_string();
        key_path.push(".key");
        let mode = std::fs::metadata(PathBuf::from(key_path)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_layout_matches_c() {
        let expected = ffi::REPLAY_SLOTS * 32 + ffi::REPLAY_SLOTS + 8 + 16 +
            ffi::SEQUENCE_SLOTS * 4 + ffi::SEQUENCE_SLOTS * 8 + 8 +
            ffi::SEQUENCE_SLOTS * 8 + ffi::SEQUENCE_SLOTS + 24;
        assert_eq!(std::mem::size_of::<ffi::Replay>(), expected);
    }

    #[test]
    fn duplicate_events_are_suppressed() {
        let dir = std::env::temp_dir().join(format!("ap-ipc-replay-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ap.sock");
        let server = Ipc::open(&path, false).unwrap();
        let mut event = Event::new(KIND_HEARTBEAT, 21, 22, 23);
        event.set_text("replay_probe");

        send_event(&path, &event).unwrap();
        assert_eq!(server.recv_event(1000).unwrap().seq, 21);
        send_event(&path, &event).unwrap();
        assert!(server.recv_event(1000).is_none());
        assert_eq!(server.duplicates(), 1);

        event.seq = 22;
        send_event(&path, &event).unwrap();
        assert_eq!(server.recv_event(1000).unwrap().seq, 22);
        assert_eq!(server.duplicates(), 1);
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_sequences_are_suppressed_when_enabled() {
        let dir = std::env::temp_dir()
            .join(format!("ap-ipc-sequence-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ap.sock");
        let server = Ipc::open(&path, true).unwrap();
        let mut event = Event::new(KIND_HEARTBEAT, 31, 22, 23);
        event.set_text("seq_ok");

        send_event(&path, &event).unwrap();
        assert_eq!(server.recv_event(1000).unwrap().seq, 31);

        event.seq = 30;
        event.set_text("seq_stale");
        send_event(&path, &event).unwrap();
        assert!(server.recv_event(1000).is_none());
        assert_eq!(server.sequence_drops(), 1);

        event.seq = 32;
        event.set_text("seq_next");
        send_event(&path, &event).unwrap();
        assert_eq!(server.recv_event(1000).unwrap().seq, 32);
        assert_eq!(server.duplicates(), 0);
        assert_eq!(server.sequence_drops(), 1);
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_key_layout_matches_c() {
        let expected = ffi::CLIENT_KEY_MAX * 4 + ffi::CLIENT_KEY_MAX * KEY_LEN + 8 + 16;
        assert_eq!(std::mem::size_of::<ffi::ClientKeys>(), expected);
    }

    fn write_raw_key(path: &Path, fill: u8) -> PathBuf {
        let key = [fill; KEY_LEN];
        std::fs::write(path, key).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path.to_path_buf()
    }

    #[test]
    fn explicit_client_key_is_selected_by_pid() {
        let dir = std::env::temp_dir()
            .join(format!("ap-client-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ap.sock");
        let first = write_raw_key(&dir.join("first.key"), 0x31);
        let second = write_raw_key(&dir.join("second.key"), 0x72);
        let mappings = vec![(std::process::id(), first.clone())];
        let server = Ipc::open_with_client_keys(&path, false, &mappings).unwrap();
        let mut event = Event::new(KIND_HEARTBEAT, 41, 22, 23);
        event.set_text("client_key_ok");

        send_event_with_key(&path, &first, &event).unwrap();
        assert_eq!(server.recv_event(1000).unwrap().seq, 41);
        assert_eq!(server.client_matches(), 1);
        assert_eq!(server.client_misses(), 0);

        send_event_with_key(&path, &second, &event).unwrap();
        assert!(server.recv_event(1000).is_none());
        assert_eq!(server.client_matches(), 2);
        assert_eq!(server.client_misses(), 0);

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unmapped_client_pid_is_counted_and_rejected() {
        let dir = std::env::temp_dir()
            .join(format!("ap-client-miss-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ap.sock");
        let key = write_raw_key(&dir.join("client.key"), 0x55);
        let mappings = vec![(std::process::id() + 1000, key.clone())];
        let server = Ipc::open_with_client_keys(&path, false, &mappings).unwrap();
        let mut event = Event::new(KIND_HEARTBEAT, 42, 22, 23);
        event.set_text("client_key_miss");

        send_event_with_key(&path, &key, &event).unwrap();
        assert!(server.recv_event(1000).is_none());
        assert_eq!(server.client_matches(), 0);
        assert_eq!(server.client_misses(), 1);

        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_key_table_is_bounded() {
        let dir = std::env::temp_dir()
            .join(format!("ap-client-limit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = write_raw_key(&dir.join("client.key"), 0x61);
        let mappings: Vec<(u32, PathBuf)> = (1..=ffi::CLIENT_KEY_MAX as u32)
            .map(|pid| (pid, key.clone()))
            .collect();
        assert!(load_client_keys(&mappings).is_ok());
        let mut too_many = mappings;
        too_many.push((ffi::CLIENT_KEY_MAX as u32 + 1, key));
        assert_eq!(load_client_keys(&too_many).unwrap_err(), "too many client keys");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
