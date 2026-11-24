use crate::ffi;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const KEY_LEN: usize = 32;

pub fn key_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".key");
    PathBuf::from(value)
}

pub fn approval_base(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".approval");
    PathBuf::from(value)
}

pub fn approval_key_path(path: &Path) -> PathBuf {
    key_path(&approval_base(path))
}

fn name(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains a nul byte".to_string())
}

pub fn key_create(path: &Path) -> Result<[u8; KEY_LEN], String> {
    let value = name(path)?;
    let mut key = [0u8; KEY_LEN];
    let status = unsafe { ffi::ap_transport_key_create(value.as_ptr(), key.as_mut_ptr()) };
    if status != 0 {
        return Err("key unavailable".to_string());
    }
    Ok(key)
}

pub fn key_load(path: &Path) -> Result<[u8; KEY_LEN], String> {
    let value = name(path)?;
    let mut key = [0u8; KEY_LEN];
    let status = unsafe { ffi::ap_transport_key_load(value.as_ptr(), key.as_mut_ptr()) };
    if status != 0 {
        return Err("key unavailable".to_string());
    }
    Ok(key)
}

pub fn key_create_path(path: &Path) -> Result<[u8; KEY_LEN], String> {
    let value = name(path)?;
    let mut key = [0u8; KEY_LEN];
    let status = unsafe { ffi::ap_transport_key_create_path(value.as_ptr(), key.as_mut_ptr()) };
    if status != 0 {
        return Err("key unavailable".to_string());
    }
    Ok(key)
}

pub fn key_load_path(path: &Path) -> Result<[u8; KEY_LEN], String> {
    let value = name(path)?;
    let mut key = [0u8; KEY_LEN];
    let status = unsafe { ffi::ap_transport_key_load_path(value.as_ptr(), key.as_mut_ptr()) };
    if status != 0 {
        return Err("key unavailable".to_string());
    }
    Ok(key)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

pub fn decode_hex(value: &str, len: usize) -> Option<Vec<u8>> {
    if value.len() != len * 2 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(len);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

pub fn hmac(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    unsafe {
        ffi::ap_hmac_sha256(
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
        );
    }
    out
}

pub fn hmac_hex(key: &[u8; KEY_LEN], data: &[u8]) -> String {
    hex(&hmac(key, data))
}

pub fn constant_eq(expected: &str, found: &str) -> bool {
    if expected.len() != found.len() {
        return false;
    }
    unsafe {
        ffi::ap_constant_time_eq(
            expected.as_ptr(),
            found.as_ptr(),
            expected.len(),
        ) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 15, 16, 255];
        assert_eq!(decode_hex(&hex(&bytes), bytes.len()), Some(bytes.to_vec()));
        assert_eq!(decode_hex("abc", 2), None);
        assert_eq!(decode_hex("zz", 1), None);
    }

    #[test]
    fn hmac_is_stable_and_comparison_is_exact() {
        let key = [7u8; KEY_LEN];
        let first = hmac_hex(&key, b"ap policy");
        let second = hmac_hex(&key, b"ap policy");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(constant_eq(&first, &second));
        assert!(!constant_eq(&first, &second[..63]));
    }
}
