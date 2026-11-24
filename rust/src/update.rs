use crate::auth;
use crate::ffi;
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HEADER: &[u8] = b"ap_update_v1\n";
const MAX_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 256;
const MAX_LINE: usize = 4096;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const FILE_PREFIX: &str = "file=";
const APPROVAL_PREFIX: &str = "approval=";
const MAC_PREFIX: &str = "mac=";
const APPROVAL_DOMAIN: &[u8] = b"ap_update_approval_v1\n";
const HEX_LEN: usize = 64;
const CHUNK: usize = 64 * 1024;
const RELEASE_ID_LEN: usize = 32;
const STATE_HEADER: &[u8] = b"ap_update_state_v1\n";
const STATE_MAX: usize = 512;
const RELEASE_MANIFEST: &str = "manifest";

#[derive(Clone, Debug)]
struct Entry {
    path: PathBuf,
    size: u64,
    hash: String,
}

#[derive(Debug)]
struct Parsed {
    body_len: usize,
    approval_body_len: usize,
    entries: Vec<Entry>,
    approval: Option<String>,
    mac: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub require_approval: bool,
}

#[derive(Debug)]
struct Signed {
    entries: Vec<Entry>,
}

#[derive(Clone, Debug, Default)]
struct State {
    active: Option<String>,
    previous: Option<String>,
}

fn check_manifest(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "update manifest unreadable".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("update manifest must be a regular file".to_string());
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err("update manifest must not be group or other writable".to_string());
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Vec<u8>, String> {
    check_manifest(path)?;
    fs::read(path).map_err(|_| "update manifest unreadable".to_string())
}

fn next_line<'a>(content: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if *offset >= content.len() {
        return Err("unexpected end of update manifest".to_string());
    }
    let rest = &content[*offset..];
    let end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "unterminated update manifest line".to_string())?;
    *offset += end + 1;
    Ok(&rest[..end + 1])
}

fn printable(value: &str) -> bool {
    value.chars().all(|ch| ch >= ' ' && ch != '\x7f')
}

fn valid_hex64(value: &str) -> bool {
    value.len() == HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_relative(value: &str) -> Option<PathBuf> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value.chars().any(char::is_whitespace)
    {
        return None;
    }
    let path = Path::new(value);
    for part in path.components() {
        if !matches!(part, Component::Normal(_)) {
            return None;
        }
    }
    Some(path.to_path_buf())
}

fn parse_entry(line: &str) -> Result<Entry, String> {
    let rest = line
        .strip_prefix(FILE_PREFIX)
        .ok_or_else(|| "bad update manifest line".to_string())?;
    let mut parts = rest.split(' ');
    let relative = parts.next().ok_or_else(|| "bad update path".to_string())?;
    let size = parts.next().ok_or_else(|| "bad update size".to_string())?;
    let hash = parts.next().ok_or_else(|| "bad update hash".to_string())?;
    if parts.next().is_some() {
        return Err("bad update file line".to_string());
    }
    let path = parse_relative(relative).ok_or_else(|| "unsafe update path".to_string())?;
    if path == Path::new(RELEASE_MANIFEST)
        || path == Path::new("manifest.key")
        || path == Path::new("manifest.approval.key")
    {
        return Err("reserved update path".to_string());
    }
    if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("bad update size".to_string());
    }
    let size: u64 = size.parse().map_err(|_| "bad update size".to_string())?;
    if size > MAX_FILE_BYTES {
        return Err("update file too large".to_string());
    }
    if !valid_hex64(hash) {
        return Err("bad update hash".to_string());
    }
    Ok(Entry {
        path,
        size,
        hash: hash.to_string(),
    })
}

fn parse(content: &[u8]) -> Result<Parsed, String> {
    if content.len() > MAX_BYTES {
        return Err("update manifest too large".to_string());
    }
    if !content.ends_with(b"\n") {
        return Err("update manifest lines must end with newline".to_string());
    }
    let mut offset = 0usize;
    if next_line(content, &mut offset)? != HEADER {
        return Err("bad update manifest header".to_string());
    }
    let mut lines = 1usize;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    let mut approval = None;
    let mut mac = None;
    let mut body_len = content.len();
    let mut approval_body_len = content.len();
    while offset < content.len() {
        let start = offset;
        let raw = next_line(content, &mut offset)?;
        lines += 1;
        if lines > MAX_LINES || raw.len() > MAX_LINE {
            return Err("update manifest line count or length exceeded".to_string());
        }
        let line = std::str::from_utf8(&raw[..raw.len() - 1])
            .map_err(|_| "update manifest line is not utf-8".to_string())?;
        if !printable(line) {
            return Err("update manifest line contains control characters".to_string());
        }
        if let Some(value) = line.strip_prefix(APPROVAL_PREFIX) {
            if mac.is_some() {
                return Err("update approval must precede mac".to_string());
            }
            if approval.is_some() {
                return Err("duplicate update approval".to_string());
            }
            if entries.is_empty() {
                return Err("update approval has no payload".to_string());
            }
            if !valid_hex64(value) {
                return Err("bad update approval".to_string());
            }
            approval_body_len = start;
            approval = Some(value.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix(MAC_PREFIX) {
            if !valid_hex64(value) {
                return Err("bad update mac".to_string());
            }
            if mac.is_some() {
                return Err("duplicate update mac".to_string());
            }
            if offset != content.len() {
                return Err("update mac must be last".to_string());
            }
            body_len = start;
            mac = Some(value.to_string());
            break;
        }
        if approval.is_some() {
            return Err("update file must precede approval".to_string());
        }
        let entry = parse_entry(line)?;
        if !seen.insert(entry.path.clone()) {
            return Err("duplicate update path".to_string());
        }
        entries.push(entry);
    }
    Ok(Parsed {
        body_len,
        approval_body_len,
        entries,
        approval,
        mac,
    })
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(format!(".ap-update-{}-{}", std::process::id(), nonce()));
    let temp = PathBuf::from(temp);
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|_| "update manifest write failed".to_string())
}

fn write_new_private(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "update release proof write failed".to_string())?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|_| "update release proof write failed".to_string())
}

fn copy_private(source: &Path, target: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(source)
        .map_err(|_| "update release proof unreadable".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("update release proof must be a regular file".to_string());
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err("update release proof must not be group or other writable".to_string());
    }
    let content = fs::read(source).map_err(|_| "update release proof unreadable".to_string())?;
    write_new_private(target, &content)
}

fn approval_mac(key: &[u8; auth::KEY_LEN], content: &[u8], body_len: usize) -> String {
    let mut data = Vec::with_capacity(APPROVAL_DOMAIN.len() + body_len);
    data.extend_from_slice(APPROVAL_DOMAIN);
    data.extend_from_slice(&content[..body_len]);
    auth::hmac_hex(key, &data)
}

fn verify_release(release: &Path, options: Options) -> Result<(usize, u64), String> {
    verify_with(&release.join(RELEASE_MANIFEST), options)
}

fn store_release_proof(
    release: &Path,
    manifest: &Path,
    options: Options,
) -> Result<(), String> {
    let stored = release.join(RELEASE_MANIFEST);
    copy_private(manifest, &stored)?;
    copy_private(&auth::key_path(manifest), &auth::key_path(&stored))?;
    let content = fs::read(&stored).map_err(|_| "update manifest unreadable".to_string())?;
    if parse(&content)?.approval.is_some() {
        copy_private(
            &auth::approval_key_path(manifest),
            &auth::approval_key_path(&stored),
        )?;
    }
    verify_release(release, options).map(|_| ())
}

fn read_signed(path: &Path, options: Options) -> Result<Signed, String> {
    let content = read_manifest(path)?;
    let parsed = parse(&content)?;
    let found = parsed.mac.ok_or_else(|| "update is not sealed".to_string())?;
    let key = auth::key_load(path).map_err(|_| "update key unavailable".to_string())?;
    let expected = auth::hmac_hex(&key, &content[..parsed.body_len]);
    if !auth::constant_eq(&expected, &found) {
        return Err("update mac mismatch".to_string());
    }
    if let Some(ref approval) = parsed.approval {
        let key = auth::key_load(&auth::approval_base(path))
            .map_err(|_| "update approval key unavailable".to_string())?;
        let expected = approval_mac(&key, &content, parsed.approval_body_len);
        if !auth::constant_eq(&expected, approval) {
            return Err("update approval mac mismatch".to_string());
        }
    } else if options.require_approval {
        return Err("update approval missing".to_string());
    }
    Ok(Signed {
        entries: parsed.entries,
    })
}

fn create_private_dirs(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err("update staging failed".to_string());
                }
            }
            Err(_) => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| "update staging failed".to_string())?;
            }
        }
    }
    Ok(())
}

fn hash_file(source: &Path, entry: &Entry, target: Option<&Path>) -> Result<u64, String> {
    let meta = fs::symlink_metadata(source).map_err(|_| "update payload unreadable".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("update payload must be a regular file".to_string());
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err("update payload must not be group or other writable".to_string());
    }
    if meta.len() != entry.size {
        return Err("update payload size mismatch".to_string());
    }
    let mut input = File::open(source).map_err(|_| "update payload unreadable".to_string())?;
    let mut output = match target {
        Some(path) => {
            if let Some(parent) = path.parent() {
                create_private_dirs(parent)?;
            }
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| "update staging failed".to_string())?;
            Some(file)
        }
        None => None,
    };
    let mut context: ffi::Sha256 = unsafe { std::mem::zeroed() };
    unsafe { ffi::ap_sha256_init(&mut context) };
    let mut buffer = [0u8; CHUNK];
    let mut total = 0u64;
    let result = (|| -> Result<(), String> {
        loop {
            let count = input.read(&mut buffer).map_err(|_| "update payload read failed".to_string())?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > entry.size {
                return Err("update payload size mismatch".to_string());
            }
            unsafe { ffi::ap_sha256_update(&mut context, buffer.as_ptr(), count) };
            if let Some(ref mut file) = output {
                file.write_all(&buffer[..count])
                    .map_err(|_| "update staging failed".to_string())?;
            }
        }
        if total != entry.size {
            return Err("update payload size mismatch".to_string());
        }
        let mut digest = [0u8; 32];
        unsafe { ffi::ap_sha256_final(&mut context, digest.as_mut_ptr()) };
        let found = auth::hex(&digest);
        if !auth::constant_eq(&entry.hash, &found) {
            return Err("update payload hash mismatch".to_string());
        }
        if let Some(ref mut file) = output {
            file.sync_all().map_err(|_| "update staging failed".to_string())?;
        }
        Ok(())
    })();
    if result.is_err() {
        if let Some(path) = target {
            let _ = fs::remove_file(path);
        }
    }
    result.map(|()| total)
}

fn check_payloads(root: &Path, entries: &[Entry], target: Option<&Path>) -> Result<(usize, u64), String> {
    let meta = fs::symlink_metadata(root).map_err(|_| "update root unreadable".to_string())?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("update root must be a directory".to_string());
    }
    let mut bytes = 0u64;
    for entry in entries {
        let source = root.join(&entry.path);
        let destination = target.map(|path| path.join(&entry.path));
        bytes += hash_file(&source, entry, destination.as_deref())?;
    }
    Ok((entries.len(), bytes))
}

fn root_for(manifest: &Path) -> PathBuf {
    manifest.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
}

fn check_private_dir(path: &Path, label: &str) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|_| format!("update {} unreadable", label))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(format!("update {} must be a directory", label));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("update {} must not be group or other writable", label));
    }
    if meta.uid() != unsafe { ffi::geteuid() } {
        return Err(format!("update {} must be owned by current uid", label));
    }
    Ok(())
}

fn prepare_root(root: &Path) -> Result<PathBuf, String> {
    check_private_dir(root, "root")?;
    let releases = root.join("releases");
    if fs::symlink_metadata(&releases).is_ok() {
        check_private_dir(&releases, "release directory")?;
    } else {
        DirBuilder::new()
            .mode(0o700)
            .create(&releases)
            .map_err(|_| "update release directory creation failed".to_string())?;
        check_private_dir(&releases, "release directory")?;
    }
    Ok(releases)
}

fn valid_release_id(value: &str) -> bool {
    value.len() == RELEASE_ID_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn state_value(line: &str) -> Result<Option<String>, String> {
    let value = line
        .strip_prefix("active=")
        .or_else(|| line.strip_prefix("previous="))
        .ok_or_else(|| "update state invalid".to_string())?;
    if value == "none" {
        return Ok(None);
    }
    if !valid_release_id(value) {
        return Err("update state invalid".to_string());
    }
    Ok(Some(value.to_string()))
}

fn parse_state(content: &[u8]) -> Result<State, String> {
    if content.len() > STATE_MAX || !content.ends_with(b"\n") {
        return Err("update state invalid".to_string());
    }
    let text = std::str::from_utf8(content).map_err(|_| "update state invalid".to_string())?;
    let mut lines = text.split('\n');
    let tag = std::str::from_utf8(&STATE_HEADER[..STATE_HEADER.len() - 1])
        .map_err(|_| "update state invalid".to_string())?;
    if lines.next() != Some(tag) {
        return Err("update state invalid".to_string());
    }
    let active_line = lines.next().ok_or_else(|| "update state invalid".to_string())?;
    let previous_line = lines.next().ok_or_else(|| "update state invalid".to_string())?;
    if lines.next() != Some("") {
        return Err("update state invalid".to_string());
    }
    if !active_line.starts_with("active=") || !previous_line.starts_with("previous=") {
        return Err("update state invalid".to_string());
    }
    Ok(State {
        active: state_value(active_line)?,
        previous: state_value(previous_line)?,
    })
}

fn read_state(root: &Path) -> Result<State, String> {
    let path = root.join("state");
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(_) => return Ok(State::default()),
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("update state must be a regular file".to_string());
    }
    if meta.mode() & 0o022 != 0 {
        return Err("update state must not be group or other writable".to_string());
    }
    if meta.uid() != unsafe { ffi::geteuid() } {
        return Err("update state must be owned by current uid".to_string());
    }
    let content = fs::read(&path).map_err(|_| "update state unreadable".to_string())?;
    parse_state(&content)
}

fn write_state(root: &Path, state: &State) -> Result<(), String> {
    let active = state.active.as_deref().unwrap_or("none");
    let previous = state.previous.as_deref().unwrap_or("none");
    let mut content = STATE_HEADER.to_vec();
    content.extend_from_slice(format!("active={}\nprevious={}\n", active, previous).as_bytes());
    write_atomic(&root.join("state"), &content)
}

fn new_release_id(releases: &Path) -> Result<String, String> {
    let base = nonce() ^ ((std::process::id() as u128) << 64);
    for attempt in 0..16u128 {
        let id = format!("{:032x}", base ^ (attempt << 96));
        if fs::symlink_metadata(releases.join(&id)).is_err() {
            return Ok(id);
        }
    }
    Err("update release id exhausted".to_string())
}

fn prune_releases(releases: &Path, state: &State) -> Result<(), String> {
    let mut keep: Vec<&str> = Vec::new();
    if let Some(active) = state.active.as_deref() {
        keep.push(active);
    }
    if let Some(previous) = state.previous.as_deref() {
        keep.push(previous);
    }
    let entries = fs::read_dir(releases).map_err(|_| "update release listing failed".to_string())?;
    for entry in entries {
        let entry = entry.map_err(|_| "update release listing failed".to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_release_id(&name) || keep.contains(&name.as_str()) {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())
            .map_err(|_| "update release cleanup failed".to_string())?;
        if meta.file_type().is_dir() {
            fs::remove_dir_all(entry.path())
                .map_err(|_| "update release cleanup failed".to_string())?;
        }
    }
    Ok(())
}

pub fn seal(path: &Path) -> Result<usize, String> {
    seal_with(path, Options::default())
}

pub fn seal_with(path: &Path, options: Options) -> Result<usize, String> {
    let content = read_manifest(path)?;
    let parsed = parse(&content)?;
    if parsed.mac.is_some() || parsed.approval.is_some() {
        return Err("update is already sealed".to_string());
    }
    if parsed.entries.is_empty() {
        return Err("update has no files".to_string());
    }
    let mut sealed = content.clone();
    if options.require_approval {
        let approval_key = auth::key_create(&auth::approval_base(path))?;
        let approval = approval_mac(&approval_key, &content, parsed.approval_body_len);
        sealed.extend_from_slice(format!("approval={}\n", approval).as_bytes());
    }
    let entries = parsed.entries.len();
    let key = auth::key_create(path)?;
    let mac = auth::hmac_hex(&key, &sealed);
    sealed.extend_from_slice(format!("mac={}\n", mac).as_bytes());
    write_atomic(path, &sealed)?;
    Ok(entries)
}

pub fn verify(path: &Path) -> Result<(usize, u64), String> {
    verify_with(path, Options::default())
}

pub fn verify_with(path: &Path, options: Options) -> Result<(usize, u64), String> {
    let signed = read_signed(path, options)?;
    check_payloads(&root_for(path), &signed.entries, None)
}

pub fn stage(manifest: &Path, destination: &Path) -> Result<(usize, u64), String> {
    stage_with(manifest, destination, Options::default())
}

pub fn stage_with(
    manifest: &Path,
    destination: &Path,
    options: Options,
) -> Result<(usize, u64), String> {
    let signed = read_signed(manifest, options)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err("update destination already exists".to_string());
    }
    let mut temporary = destination.as_os_str().to_os_string();
    temporary.push(format!(".ap-stage-{}-{}", std::process::id(), nonce()));
    let temporary = PathBuf::from(temporary);
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err("update staging path already exists".to_string());
    }
    let result = (|| -> Result<(usize, u64), String> {
        DirBuilder::new()
            .mode(0o700)
            .create(&temporary)
            .map_err(|_| "update staging failed".to_string())?;
        let checked = check_payloads(&root_for(manifest), &signed.entries, Some(&temporary))?;
        if let Ok(directory) = File::open(&temporary) {
            let _ = directory.sync_all();
        }
        if fs::symlink_metadata(destination).is_ok() {
            return Err("update destination already exists".to_string());
        }
        fs::rename(&temporary, destination).map_err(|_| "update staging failed".to_string())?;
        Ok(checked)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

pub fn install(manifest: &Path, root: &Path) -> Result<(usize, u64, String), String> {
    install_with(manifest, root, Options::default())
}

pub fn install_with(
    manifest: &Path,
    root: &Path,
    options: Options,
) -> Result<(usize, u64, String), String> {
    let _signed = read_signed(manifest, options)?;
    let releases = prepare_root(root)?;
    let state = read_state(root)?;
    let release_id = new_release_id(&releases)?;
    let pending = root.join(format!(".ap-pending-{}", release_id));
    if fs::symlink_metadata(&pending).is_ok() {
        return Err("update pending path already exists".to_string());
    }
    let checked = stage_with(manifest, &pending, options)?;
    let release = releases.join(&release_id);
    let result = (|| -> Result<(), String> {
        if fs::symlink_metadata(&release).is_ok() {
            return Err("update release already exists".to_string());
        }
        fs::rename(&pending, &release).map_err(|_| "update installation failed".to_string())?;
        store_release_proof(&release, manifest, options)?;
        let next = State {
            active: Some(release_id.clone()),
            previous: state.active.clone(),
        };
        if let Err(message) = write_state(root, &next) {
            let _ = fs::remove_dir_all(&release);
            return Err(message);
        }
        let _ = prune_releases(&releases, &next);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&pending);
    }
    result.map(|()| (checked.0, checked.1, release_id))
}

pub fn rollback(root: &Path) -> Result<String, String> {
    rollback_with(root, Options::default())
}

pub fn rollback_with(root: &Path, options: Options) -> Result<String, String> {
    let releases = prepare_root(root)?;
    let state = read_state(root)?;
    let target = state.previous.clone().ok_or_else(|| "update has no previous release".to_string())?;
    let target_release = releases.join(&target);
    check_private_dir(&target_release, "release directory")?;
    verify_release(&target_release, options)?;
    let next = State {
        active: Some(target.clone()),
        previous: state.active.clone(),
    };
    write_state(root, &next)?;
    let _ = prune_releases(&releases, &next);
    Ok(target)
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub active: String,
    pub previous: Option<String>,
    pub entries: usize,
    pub bytes: u64,
}

pub fn plan(root: &Path, options: Options) -> Result<Plan, String> {
    check_private_dir(root, "root")?;
    let releases = root.join("releases");
    check_private_dir(&releases, "release directory")?;
    let state = read_state(root)?;
    let active = state.active.ok_or_else(|| "update has no active release".to_string())?;
    let active_release = releases.join(&active);
    check_private_dir(&active_release, "release directory")?;
    if let Some(ref previous) = state.previous {
        check_private_dir(&releases.join(previous), "release directory")?;
    }
    let (entries, bytes) = verify_release(&active_release, options)?;
    Ok(Plan {
        active,
        previous: state.previous,
        entries,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ap-update-test-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_private(path: &Path, data: &[u8]) {
        fs::write(path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn hash_bytes(data: &[u8]) -> String {
        let mut context: ffi::Sha256 = unsafe { std::mem::zeroed() };
        unsafe { ffi::ap_sha256_init(&mut context) };
        unsafe { ffi::ap_sha256_update(&mut context, data.as_ptr(), data.len()) };
        let mut digest = [0u8; 32];
        unsafe { ffi::ap_sha256_final(&mut context, digest.as_mut_ptr()) };
        auth::hex(&digest)
    }

    fn manifest(files: &[(&str, &[u8])]) -> String {
        let mut out = String::from("ap_update_v1\n");
        for (path, data) in files {
            out.push_str(&format!("file={} {} {}\n", path, data.len(), hash_bytes(data)));
        }
        out
    }

    fn setup(name: &str, files: &[(&str, &[u8])]) -> (PathBuf, PathBuf) {
        let root = dir(name);
        for (relative, data) in files {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_private(&path, data);
        }
        let manifest_path = root.join("bundle.manifest");
        write_private(&manifest_path, manifest(files).as_bytes());
        (root, manifest_path)
    }

    fn tamper_mac(path: &Path) {
        let mut content = fs::read_to_string(path).unwrap();
        let newline = content.pop().unwrap();
        let last = content.pop().unwrap();
        content.push(if last == '0' { '1' } else { '0' });
        content.push(newline);
        write_private(path, content.as_bytes());
    }

    #[test]
    fn sha_layout_matches_c() {
        assert_eq!(std::mem::size_of::<ffi::Sha256>(), 112);
    }

    #[test]
    fn seals_verifies_and_stages_bundle() {
        let files: &[(&str, &[u8])] = &[("bin/tool", b"tool bytes"), ("etc/note", b"note")];
        let (root, path) = setup("clean", files);
        assert_eq!(seal(&path).unwrap(), 2);
        let key = auth::key_path(&path);
        let mode = fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        assert_eq!(verify(&path).unwrap(), (2, 14));

        let staged = root.join("staged");
        assert_eq!(stage(&path, &staged).unwrap(), (2, 14));
        assert_eq!(fs::read(staged.join("bin/tool")).unwrap(), b"tool bytes");
        assert_eq!(fs::read(staged.join("etc/note")).unwrap(), b"note");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_payload_and_manifest_tamper() {
        let files: &[(&str, &[u8])] = &[("bin/tool", b"tool bytes")];
        let (root, path) = setup("tamper", files);
        seal(&path).unwrap();
        assert!(verify(&path).is_ok());

        write_private(&root.join("bin/tool"), b"tool byteX");
        assert_eq!(verify(&path).unwrap_err(), "update payload hash mismatch");
        write_private(&root.join("bin/tool"), b"tool bytes");

        tamper_mac(&path);
        assert_eq!(verify(&path).unwrap_err(), "update mac mismatch");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_and_duplicate_entries() {
        let root = dir("unsafe");
        let path = root.join("bad.manifest");
        for relative in ["../escape", "/tmp/escape", "bin/../escape", "bin//tool", "bin/tool/"] {
            let content = format!(
                "ap_update_v1\nfile={} 1 {}\n",
                relative,
                hash_bytes(b"x")
            );
            write_private(&path, content.as_bytes());
            assert!(seal(&path).is_err(), "unsafe path accepted: {}", relative);
        }
        let hash = hash_bytes(b"x");
        let content = format!(
            "ap_update_v1\nfile=bin/tool 1 {}\nfile=bin/tool 1 {}\n",
            hash, hash
        );
        write_private(&path, content.as_bytes());
        assert_eq!(seal(&path).unwrap_err(), "duplicate update path");
        let hash = hash_bytes(b"x");
        for relative in ["manifest", "manifest.key", "manifest.approval.key"] {
            let content = format!("ap_update_v1\nfile={} 1 {}\n", relative, hash);
            write_private(&path, content.as_bytes());
            assert_eq!(seal(&path).unwrap_err(), "reserved update path");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_symlink_and_missing_payload() {
        let files: &[(&str, &[u8])] = &[("bin/tool", b"tool"), ("etc/note", b"note")];
        let (root, path) = setup("symlink", files);
        seal(&path).unwrap();
        fs::remove_file(root.join("bin/tool")).unwrap();
        std::os::unix::fs::symlink(root.join("etc/note"), root.join("bin/tool")).unwrap();
        assert_eq!(
            verify(&path).unwrap_err(),
            "update payload must be a regular file"
        );
        fs::remove_file(root.join("bin/tool")).unwrap();
        assert_eq!(verify(&path).unwrap_err(), "update payload unreadable");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsealed_and_absent_manifest() {
        let files: &[(&str, &[u8])] = &[("bin/tool", b"tool")];
        let (root, path) = setup("unsealed", files);
        assert_eq!(verify(&path).unwrap_err(), "update is not sealed");
        fs::remove_file(&path).unwrap();
        assert_eq!(verify(&path).unwrap_err(), "update manifest unreadable");
        fs::remove_dir_all(root).unwrap();
    }

    fn state_ids(root: &Path) -> State {
        let content = fs::read(root.join("state")).unwrap();
        parse_state(&content).unwrap()
    }

    #[test]
    fn installs_and_rolls_back_release_snapshots() {
        let (bundle1, manifest1) = setup("install-first", &[("bin/tool", b"first"), ("etc/note", b"one")]);
        seal(&manifest1).unwrap();
        let root = dir("install-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let first = install(&manifest1, &root).unwrap();
        assert_eq!((first.0, first.1), (2, 8));
        let state = state_ids(&root);
        assert_eq!(state.active.as_deref(), Some(first.2.as_str()));
        assert_eq!(state.previous, None);
        let first_release = root.join("releases").join(&first.2);
        assert_eq!(fs::read(first_release.join("bin/tool")).unwrap(), b"first");
        assert_eq!(
            verify_release(&first_release, Options::default()).unwrap(),
            (2, 8)
        );
        assert_eq!(rollback(&root).unwrap_err(), "update has no previous release");

        let (bundle2, manifest2) = setup("install-second", &[("bin/tool", b"second")]);
        seal(&manifest2).unwrap();
        let second = install(&manifest2, &root).unwrap();
        let state = state_ids(&root);
        assert_eq!(state.active.as_deref(), Some(second.2.as_str()));
        assert_eq!(state.previous.as_deref(), Some(first.2.as_str()));
        assert_eq!(
            fs::read(root.join("releases").join(&second.2).join("bin/tool")).unwrap(),
            b"second"
        );

        let target = rollback(&root).unwrap();
        assert_eq!(target, first.2);
        let state = state_ids(&root);
        assert_eq!(state.active.as_deref(), Some(first.2.as_str()));
        assert_eq!(state.previous.as_deref(), Some(second.2.as_str()));
        assert_eq!(
            fs::read(root.join("releases").join(&target).join("bin/tool")).unwrap(),
            b"first"
        );
        let releases = fs::read_dir(root.join("releases")).unwrap().count();
        assert_eq!(releases, 2);

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(bundle1).unwrap();
        fs::remove_dir_all(bundle2).unwrap();
    }

    #[test]
    fn rollback_verifies_previous_release_proof() {
        let (bundle1, manifest1) = setup("rollback-proof-first", &[("bin/tool", b"first")]);
        seal(&manifest1).unwrap();
        let root = dir("rollback-proof-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let first = install(&manifest1, &root).unwrap();

        let (bundle2, manifest2) = setup("rollback-proof-second", &[("bin/tool", b"second")]);
        seal(&manifest2).unwrap();
        install(&manifest2, &root).unwrap();

        let previous = root.join("releases").join(&first.2);
        write_private(&previous.join("bin/tool"), b"firzt");
        assert_eq!(rollback(&root).unwrap_err(), "update payload hash mismatch");
        write_private(&previous.join("bin/tool"), b"first");

        fs::remove_file(previous.join("manifest")).unwrap();
        assert_eq!(rollback(&root).unwrap_err(), "update manifest unreadable");

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(bundle1).unwrap();
        fs::remove_dir_all(bundle2).unwrap();
    }

    #[test]
    fn install_rejects_non_private_root() {
        let (bundle, manifest) = setup("install-bad-root", &[("bin/tool", b"tool")]);
        seal(&manifest).unwrap();
        let root = dir("install-bad-root-target");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            install(&manifest, &root).unwrap_err(),
            "update root must not be group or other writable"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let parent = dir("install-bad-root-link");
        let link = parent.join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert_eq!(
            install(&manifest, &link).unwrap_err(),
            "update root must be a directory"
        );
        fs::remove_dir_all(parent).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn rollback_rejects_invalid_state() {
        let root = dir("install-bad-state");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&root.join("state"), b"bad state\n");
        assert_eq!(rollback(&root).unwrap_err(), "update state invalid");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn approval_requires_a_second_local_key() {
        let (bundle, path) = setup("approval-key", &[("bin/tool", b"tool")]);
        let options = Options { require_approval: true };
        assert_eq!(seal_with(&path, options).unwrap(), 1);
        let key = auth::approval_key_path(&path);
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o077, 0);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.find("approval=").unwrap() < content.find("mac=").unwrap());
        assert_eq!(verify(&path).unwrap(), (1, 4));
        assert_eq!(verify_with(&path, options).unwrap(), (1, 4));

        write_private(&key, &[0u8; auth::KEY_LEN]);
        assert_eq!(verify(&path).unwrap_err(), "update approval mac mismatch");
        fs::remove_file(&key).unwrap();
        assert_eq!(verify(&path).unwrap_err(), "update approval key unavailable");
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn approval_is_required_when_flagged() {
        let (bundle, path) = setup("approval-missing", &[("bin/tool", b"tool")]);
        seal(&path).unwrap();
        let options = Options { require_approval: true };
        assert_eq!(verify_with(&path, options).unwrap_err(), "update approval missing");
        let root = dir("approval-missing-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            install_with(&path, &root, options).unwrap_err(),
            "update approval missing"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn install_and_rollback_with_approval() {
        let options = Options { require_approval: true };
        let (bundle1, manifest1) = setup("approval-install-first", &[("bin/tool", b"first")]);
        seal_with(&manifest1, options).unwrap();
        let root = dir("approval-install-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let first = install_with(&manifest1, &root, options).unwrap();

        let previous = root.join("releases").join(&first.2);
        let stored_key = previous.join("manifest.approval.key");
        assert_eq!(fs::metadata(&stored_key).unwrap().permissions().mode() & 0o077, 0);
        let saved = fs::read(&stored_key).unwrap();

        let (bundle2, manifest2) = setup("approval-install-second", &[("bin/tool", b"second")]);
        seal_with(&manifest2, options).unwrap();
        let second = install_with(&manifest2, &root, options).unwrap();

        write_private(&stored_key, &[0u8; auth::KEY_LEN]);
        assert_eq!(
            rollback_with(&root, options).unwrap_err(),
            "update approval mac mismatch"
        );
        write_private(&stored_key, &saved);

        let rolled = rollback_with(&root, options).unwrap();
        assert_eq!(rolled, first.2);
        let planned = plan(&root, options).unwrap();
        assert_eq!(planned.active, first.2);
        assert_eq!(planned.previous.as_deref(), Some(second.2.as_str()));
        assert_eq!((planned.entries, planned.bytes), (1, 5));

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(bundle1).unwrap();
        fs::remove_dir_all(bundle2).unwrap();
    }

    #[test]
    fn plan_is_read_only_and_verifies_active_release() {
        let (bundle, manifest) = setup("plan", &[("bin/tool", b"tool")]);
        seal(&manifest).unwrap();
        let root = dir("plan-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let release = install(&manifest, &root).unwrap();
        let before = fs::read(root.join("state")).unwrap();
        let planned = plan(&root, Options::default()).unwrap();
        assert_eq!(planned.active, release.2);
        assert_eq!(planned.previous, None);
        assert_eq!((planned.entries, planned.bytes), (1, 4));
        assert_eq!(fs::read(root.join("state")).unwrap(), before);

        let active = root.join("releases").join(&release.2);
        write_private(&active.join("bin/tool"), b"toxl");
        assert_eq!(
            plan(&root, Options::default()).unwrap_err(),
            "update payload hash mismatch"
        );
        assert_eq!(fs::read(root.join("state")).unwrap(), before);

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(bundle).unwrap();
    }

    #[test]
    fn plan_rejects_missing_or_invalid_state() {
        let root = dir("plan-bad-state");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("releases")).unwrap();
        fs::set_permissions(root.join("releases"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            plan(&root, Options::default()).unwrap_err(),
            "update has no active release"
        );
        write_private(&root.join("state"), b"bad state\n");
        assert_eq!(
            plan(&root, Options::default()).unwrap_err(),
            "update state invalid"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
