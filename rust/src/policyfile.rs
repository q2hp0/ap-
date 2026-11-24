use crate::auth;
use crate::policy::Policy;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const HEADER: &[u8] = b"ap_policy_v1\n";
const MAX_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 256;
const MAX_LINE: usize = 4096;
const MAC_PREFIX: &str = "mac=";
const MAC_LEN: usize = 64;

const FLAG_KEYS: &[&str] = &[
    "guard",
    "json",
    "verbose",
    "once",
    "no-self-harden",
    "no-fork",
    "no-proc-scan",
    "ipc-strict-seq",
    "capture",
    "audit-process",
    "kernel-sensor",
    "lsm-enforce",
    "chain-guard",
];

const VALUE_KEYS: &[&str] = &[
    "deny",
    "stop",
    "enable",
    "disable",
    "threshold",
    "min-confidence",
    "max-states",
    "queue-depth",
    "socket",
    "store",
    "max-events",
    "mask",
    "duration",
    "proc-interval-ms",
    "proc-max-pids",
    "proc-map-samples",
    "proc-wx-per-scan",
    "proc-io-per-scan",
    "correlate-window-ms",
    "capture-iface",
    "capture-file",
    "capture-snaplen",
    "kernel-events",
    "client-key",
    "audit-key",
    "lsm-mask",
];

struct Parsed {
    body_len: usize,
    entries: Vec<(String, String)>,
    mac: Option<String>,
}

fn check_path(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "policy unreadable".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("policy must be a regular file".to_string());
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err("policy must not be group or other writable".to_string());
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    check_path(path)?;
    fs::read(path).map_err(|_| "policy unreadable".to_string())
}

fn next_line<'a>(content: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if *offset >= content.len() {
        return Err("unexpected end of policy".to_string());
    }
    let rest = &content[*offset..];
    let end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "unterminated policy line".to_string())?;
    *offset += end + 1;
    Ok(&rest[..end + 1])
}

fn printable(line: &str) -> bool {
    line.chars().all(|value| value >= ' ' && value != '\x7f')
}

fn valid_mac(value: &str) -> bool {
    value.len() == MAC_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse(content: &[u8]) -> Result<Parsed, String> {
    if content.len() > MAX_BYTES {
        return Err("policy too large".to_string());
    }
    if !content.ends_with(b"\n") {
        return Err("policy lines must end with newline".to_string());
    }
    let mut offset = 0usize;
    if next_line(content, &mut offset)? != HEADER {
        return Err("bad policy header".to_string());
    }
    let mut lines = 1usize;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    let mut mac = None;
    let mut body_len = content.len();
    while offset < content.len() {
        let start = offset;
        let raw = next_line(content, &mut offset)?;
        lines += 1;
        if lines > MAX_LINES || raw.len() > MAX_LINE {
            return Err("policy line count or length exceeded".to_string());
        }
        let line = std::str::from_utf8(&raw[..raw.len() - 1])
            .map_err(|_| "policy line is not utf-8".to_string())?;
        if !printable(line) {
            return Err("policy line contains control characters".to_string());
        }
        if let Some(value) = line.strip_prefix(MAC_PREFIX) {
            if !valid_mac(value) {
                return Err("bad policy mac".to_string());
            }
            if mac.is_some() {
                return Err("duplicate policy mac".to_string());
            }
            if offset != content.len() {
                return Err("policy mac must be last".to_string());
            }
            body_len = start;
            mac = Some(value.to_string());
            break;
        }
        let split = line.find('=').ok_or_else(|| "bad policy line".to_string())?;
        let key = &line[..split];
        let value = &line[split + 1..];
        if key.is_empty() || value.is_empty() || key.len() > 64 {
            return Err("bad policy key or value".to_string());
        }
        if !FLAG_KEYS.contains(&key) && !VALUE_KEYS.contains(&key) {
            return Err(format!("unknown policy key: {}", key));
        }
        if !seen.insert(key.to_string()) {
            return Err(format!("duplicate policy key: {}", key));
        }
        entries.push((key.to_string(), value.to_string()));
    }
    Ok(Parsed {
        body_len,
        entries,
        mac,
    })
}

fn args_from_entries(entries: Vec<(String, String)>) -> Result<Vec<String>, String> {
    let mut args = vec!["ap".to_string()];
    for (key, value) in entries {
        if FLAG_KEYS.contains(&key.as_str()) {
            match value.as_str() {
                "true" | "1" => args.push(format!("--{}", key)),
                "false" | "0" => {}
                _ => return Err(format!("bad policy value for {}", key)),
            }
        } else {
            args.push(format!("--{}", key));
            args.push(value);
        }
    }
    Ok(args)
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|_| "policy write failed".to_string())
}

fn read_signed(path: &Path) -> Result<(Vec<String>, usize), String> {
    let content = read_file(path)?;
    let parsed = parse(&content)?;
    let found = parsed.mac.ok_or_else(|| "policy is not sealed".to_string())?;
    let key = auth::key_load(path).map_err(|_| "policy key unavailable".to_string())?;
    let expected = auth::hmac_hex(&key, &content[..parsed.body_len]);
    if !auth::constant_eq(&expected, &found) {
        return Err("policy mac mismatch".to_string());
    }
    let entries = parsed.entries.len();
    Ok((args_from_entries(parsed.entries)?, entries))
}

pub fn seal(path: &Path) -> Result<usize, String> {
    let content = read_file(path)?;
    let parsed = parse(&content)?;
    if parsed.mac.is_some() {
        return Err("policy already sealed".to_string());
    }
    let entries = parsed.entries.len();
    let key = auth::key_create(path)?;
    let mac = auth::hmac_hex(&key, &content[..parsed.body_len]);
    let mut sealed = Vec::with_capacity(content.len() + MAC_LEN + MAC_PREFIX.len() + 1);
    sealed.extend_from_slice(&content);
    sealed.extend_from_slice(format!("mac={}\n", mac).as_bytes());
    write_atomic(path, &sealed)?;
    Ok(entries)
}

pub fn verify(path: &Path) -> Result<usize, String> {
    Ok(read_signed(path)?.1)
}

pub fn load_args(path: &Path) -> Result<Vec<String>, String> {
    Ok(read_signed(path)?.0)
}

pub fn load(path: &Path) -> Result<Policy, String> {
    Policy::from_args(&load_args(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::RULE_WX_TRANSITION;

    fn dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ap-policy-test-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn plain() -> &'static [u8] {
        b"ap_policy_v1\nguard=true\ndeny=wx_transition\nthreshold=10\nno-proc-scan=true\nipc-strict-seq=true\n"
    }

    fn write_policy(path: &Path, content: &[u8]) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn sealed_policy_loads_and_verifies() {
        let path = dir("load").join("ap.policy");
        write_policy(&path, plain());
        assert_eq!(seal(&path), Ok(5));
        assert_eq!(verify(&path), Ok(5));
        let policy = load(&path).unwrap();
        assert!(policy.guard_mode);
        assert_eq!(policy.deny_rules, vec![RULE_WX_TRANSITION]);
        assert_eq!(policy.alert_threshold, 10);
        assert!(!policy.proc_scan);
        assert!(policy.ipc_strict_seq);
        let mut args = load_args(&path).unwrap();
        args.push("--threshold".to_string());
        args.push("90".to_string());
        let overridden = Policy::from_args(&args).unwrap();
        assert_eq!(overridden.alert_threshold, 90);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn kernel_sensor_policy_keys_are_accepted() {
        let path = dir("ksensor").join("ap.policy");
        write_policy(
            &path,
            b"ap_policy_v1\nkernel-sensor=true\nlsm-enforce=true\nlsm-mask=0xff\n",
        );
        seal(&path).unwrap();
        let policy = load(&path).unwrap();
        assert!(policy.kernel_sensor);
        assert!(policy.lsm_enforce);
        assert_eq!(policy.lsm_mask, 255);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn tampered_policy_is_rejected() {
        let path = dir("tamper").join("ap.policy");
        write_policy(&path, plain());
        seal(&path).unwrap();
        let content = fs::read_to_string(&path).unwrap().replace("threshold=10", "threshold=90");
        fs::write(&path, content).unwrap();
        assert_eq!(verify(&path), Err("policy mac mismatch".to_string()));
        assert!(load(&path).is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn missing_policy_key_is_rejected() {
        let path = dir("key").join("ap.policy");
        write_policy(&path, plain());
        seal(&path).unwrap();
        fs::remove_file(auth::key_path(&path)).unwrap();
        assert_eq!(verify(&path), Err("policy key unavailable".to_string()));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn strict_parser_rejects_bad_policy() {
        let dir = dir("strict");
        let unknown = dir.join("unknown.policy");
        write_policy(&unknown, b"ap_policy_v1\nbogus=1\n");
        assert_eq!(seal(&unknown), Err("unknown policy key: bogus".to_string()));
        let duplicate = dir.join("duplicate.policy");
        write_policy(&duplicate, b"ap_policy_v1\nguard=true\nguard=false\n");
        assert_eq!(seal(&duplicate), Err("duplicate policy key: guard".to_string()));
        let missing = dir.join("missing.policy");
        write_policy(&missing, b"ap_policy_v1\nguard=true");
        assert_eq!(seal(&missing), Err("policy lines must end with newline".to_string()));
        let mac = dir.join("mac.policy");
        write_policy(&mac, b"ap_policy_v1\nmac=0000000000000000000000000000000000000000000000000000000000000000\n");
        assert_eq!(verify(&mac), Err("policy key unavailable".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsealed_policy_is_not_loaded() {
        let path = dir("unsealed").join("ap.policy");
        write_policy(&path, plain());
        match load(&path) {
            Err(message) => assert_eq!(message, "policy is not sealed"),
            Ok(_) => panic!("unsealed policy was loaded"),
        }
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
