use crate::auth;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const GENESIS: &str = "0000000000000000";
const MARKER: &str = ",\"chain\":{";
const HMAC_VERSION: &str = "hmac";

pub struct Store {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    max_bytes: u64,
    chain_seq: u64,
    prev: String,
    key: Option<[u8; 32]>,
    pub records: u64,
    pub rotations: u64,
}

fn digest(prev: &str, line: &str) -> u64 {
    let mut value = 0xcbf29ce484222325u64;
    for byte in prev.as_bytes().iter().chain(line.as_bytes()) {
        value ^= *byte as u64;
        value = value.wrapping_mul(0x100000001b3u64);
    }
    value
}

fn mac(key: &[u8; 32], seq: u64, prev: &str, line: &str) -> String {
    let mut data = Vec::with_capacity(16 + 4 + prev.len() + 8 + line.len());
    data.extend_from_slice(b"apstore2");
    data.extend_from_slice(&seq.to_le_bytes());
    data.extend_from_slice(&(prev.len() as u32).to_le_bytes());
    data.extend_from_slice(prev.as_bytes());
    data.extend_from_slice(&(line.len() as u64).to_le_bytes());
    data.extend_from_slice(line.as_bytes());
    auth::hmac_hex(key, &data)
}

fn audit_key_create(path: &Path) -> Result<[u8; 32], String> {
    auth::key_create_path(path).map_err(|_| "audit key unavailable".to_string())
}

fn audit_key_load(path: &Path) -> Result<[u8; 32], String> {
    auth::key_load_path(path).map_err(|_| "audit key unavailable".to_string())
}

fn field(line: &str, name: &str) -> Option<String> {
    let key = format!("\"{}\":\"", name);
    let start = line.find(&key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn sequence(line: &str) -> Option<u64> {
    let key = "\"seq\":";
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find(',')?;
    rest[..end].parse().ok()
}

impl Store {
    pub fn open(path: &Path, max_bytes: u64) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();
        let bytes = file.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len()).unwrap_or(0);
        Self {
            path: path.to_path_buf(),
            file,
            bytes,
            max_bytes,
            chain_seq: 0,
            prev: GENESIS.to_string(),
            key: None,
            records: 0,
            rotations: 0,
        }
    }

    pub fn open_signed(path: &Path, max_bytes: u64) -> Result<Self, String> {
        Self::open_signed_with_key(path, max_bytes, &auth::key_path(path))
    }

    pub fn open_signed_with_key(
        path: &Path,
        max_bytes: u64,
        key_path: &Path,
    ) -> Result<Self, String> {
        let key = audit_key_create(key_path)?;
        let mut store = Self::open(path, max_bytes);
        store.key = Some(key);
        Ok(store)
    }

    pub fn integrity(&self) -> &'static str {
        if self.key.is_some() { "hmac_sha256" } else { "fnv1a" }
    }

    pub fn append(&mut self, line: &str) -> bool {
        let base = line.strip_suffix('}').unwrap_or(line);
        if self.bytes + base.len() as u64 + 192u64 > self.max_bytes {
            self.rotate();
        }
        self.chain_seq = self.chain_seq.saturating_add(1);
        let signed = self.key.is_some();
        let hash = match self.key {
            Some(ref key) => mac(key, self.chain_seq, &self.prev, base),
            None => format!("{:016x}", digest(&self.prev, base)),
        };
        let mut record = String::with_capacity(base.len() + 160);
        record.push_str(base);
        record.push_str(MARKER);
        record.push_str("\"seq\":");
        record.push_str(&self.chain_seq.to_string());
        record.push_str(",\"prev\":\"");
        record.push_str(&self.prev);
        record.push_str("\",\"hash\":\"");
        record.push_str(&hash);
        record.push('"');
        if signed {
            record.push_str(",\"v\":\"hmac\"");
        }
        record.push_str("}}");

        let needed = record.len() as u64 + 1;
        let written = self
            .file
            .as_mut()
            .and_then(|f| writeln!(f, "{}", record).ok());
        if written.is_some() {
            self.bytes += needed;
            self.records += 1;
            self.prev = hash;
            return true;
        }
        false
    }

    pub fn rotate(&mut self) {
        self.file.take();
        let backup = self.path.with_extension("1.jsonl");
        let _ = fs::remove_file(&backup);
        if self.path.exists() {
            let _ = fs::rename(&self.path, &backup);
        }
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
        self.bytes = 0;
        self.chain_seq = 0;
        self.prev = GENESIS.to_string();
        self.rotations += 1;
    }

    pub fn verify(path: &Path) -> Result<usize, String> {
        Self::verify_with_key(path, &auth::key_path(path))
    }

    pub fn verify_with_key(path: &Path, key_path: &Path) -> Result<usize, String> {
        let content = fs::read_to_string(path).map_err(|_| "store unreadable".to_string())?;
        let mut expected_seq = 0u64;
        let mut prev = GENESIS.to_string();
        let mut count = 0usize;
        let mut key: Option<[u8; 32]> = None;
        for line in content.lines() {
            let split = line.find(MARKER).ok_or_else(|| "missing chain".to_string())?;
            let base = &line[..split];
            let chain = &line[split..];
            let seq = sequence(chain).ok_or_else(|| "bad chain sequence".to_string())?;
            let found_prev = field(chain, "prev")
                .ok_or_else(|| "missing previous hash".to_string())?;
            let found_hash = field(chain, "hash")
                .ok_or_else(|| "missing record hash".to_string())?;
            let version = field(chain, "v").unwrap_or_else(|| "fnv1a".to_string());
            expected_seq = expected_seq.saturating_add(1);
            if seq != expected_seq || found_prev != prev {
                return Err("chain order broken".to_string());
            }
            let actual = if version == HMAC_VERSION {
                if key.is_none() {
                    key = Some(audit_key_load(key_path)?);
                }
                let material = key.as_ref().ok_or_else(|| "audit key unavailable".to_string())?;
                mac(material, seq, &prev, base)
            } else if version == "fnv1a" {
                format!("{:016x}", digest(&prev, base))
            } else {
                return Err("unsupported chain version".to_string());
            };
            if !auth::constant_eq(&actual, &found_hash) {
                return Err("hash mismatch".to_string());
            }
            prev = found_hash;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ap-store-test-{}-{}", std::process::id(), name));
        let _ = fs::create_dir_all(&path);
        path
    }

    #[test]
    fn rotates_when_full() {
        let path = dir("rotate").join("events.jsonl");
        let mut store = Store::open(&path, 120);
        for i in 0..20 {
            store.append(&format!("{{\"n\":{}}}", i));
        }
        assert!(store.rotations > 0);
        assert_eq!(store.records, 20);
        assert!(dir("rotate").join("events.1.jsonl").exists());
        assert!(Store::verify(&path).unwrap() > 0);
        let _ = fs::remove_dir_all(dir("rotate"));
    }

    #[test]
    fn chain_verifies_clean_records() {
        let path = dir("chain").join("chain.jsonl");
        let mut store = Store::open(&path, 4096);
        for i in 0..4 {
            assert!(store.append(&format!("{{\"n\":{}}}", i)));
        }
        drop(store);
        assert_eq!(Store::verify(&path), Ok(4));
        let _ = fs::remove_dir_all(dir("chain"));
    }

    #[test]
    fn chain_detects_content_tamper() {
        let path = dir("tamper").join("tamper.jsonl");
        let mut store = Store::open(&path, 4096);
        assert!(store.append("{\"n\":1}"));
        drop(store);
        let content = fs::read_to_string(&path).unwrap().replace("\"n\":1", "\"n\":9");
        fs::write(&path, content).unwrap();
        assert!(Store::verify(&path).is_err());
        let _ = fs::remove_dir_all(dir("tamper"));
    }

    #[test]
    fn chain_detects_broken_previous_hash() {
        let path = dir("break").join("break.jsonl");
        let mut store = Store::open(&path, 4096);
        assert!(store.append("{\"n\":1}"));
        assert!(store.append("{\"n\":2}"));
        drop(store);
        let content = fs::read_to_string(&path).unwrap().replacen(
            "\"prev\":\"0000000000000000\"",
            "\"prev\":\"1111111111111111\"",
            1,
        );
        fs::write(&path, content).unwrap();
        assert!(Store::verify(&path).is_err());
        let _ = fs::remove_dir_all(dir("break"));
    }

    #[test]
    fn hmac_chain_verifies_and_detects_tamper() {
        let path = dir("hmac").join("chain.jsonl");
        let mut store = Store::open_signed(&path, 8192).unwrap();
        assert_eq!(store.integrity(), "hmac_sha256");
        for i in 0..4 {
            assert!(store.append(&format!("{{\"n\":{}}}", i)));
        }
        drop(store);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"v\":\"hmac\""));
        assert_eq!(Store::verify(&path), Ok(4));
        let changed = content.replace("\"n\":2", "\"n\":7");
        fs::write(&path, changed).unwrap();
        assert_eq!(Store::verify(&path), Err("hash mismatch".to_string()));
        let _ = fs::remove_dir_all(dir("hmac"));
    }

    #[test]
    fn hmac_chain_requires_key() {
        let path = dir("hmac-key").join("chain.jsonl");
        let mut store = Store::open_signed(&path, 4096).unwrap();
        assert!(store.append("{\"n\":1}"));
        drop(store);
        assert!(auth::key_path(&path).exists());
        fs::remove_file(auth::key_path(&path)).unwrap();
        assert_eq!(Store::verify(&path), Err("audit key unavailable".to_string()));
        let _ = fs::remove_dir_all(dir("hmac-key"));
    }

    #[test]
    fn hmac_chain_uses_exact_custom_key_path() {
        let base = dir("hmac-custom");
        let path = base.join("chain.jsonl");
        let key_path = base.join("shared.audit.key");
        let mut store = Store::open_signed_with_key(&path, 8192, &key_path).unwrap();
        assert_eq!(store.integrity(), "hmac_sha256");
        assert!(key_path.exists());
        assert!(!auth::key_path(&key_path).exists());
        assert!(store.append("{\"n\":1}"));
        drop(store);
        assert_eq!(Store::verify_with_key(&path, &key_path), Ok(1));
        assert_eq!(Store::verify(&path), Err("audit key unavailable".to_string()));
        let _ = fs::remove_dir_all(base);
    }
}
