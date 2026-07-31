use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MANIFEST_SCHEMA_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 8;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTarget {
    OpenWrtFirewall,
    LinuxNftablesManaged,
}

impl RollbackTarget {
    fn path(self) -> &'static Path {
        match self {
            Self::OpenWrtFirewall => Path::new("/etc/config/firewall"),
            Self::LinuxNftablesManaged => Path::new("/etc/mbed-agent/managed/firewall.nft"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackReload {
    OpenWrtFirewall,
    LinuxNftables,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SnapshotEntry {
    target: RollbackTarget,
    existed: bool,
    snapshot_name: String,
    digest: Option<String>,
    mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RollbackManifest {
    schema_version: u16,
    transaction_id: String,
    timeout_secs: u64,
    entries: Vec<SnapshotEntry>,
    reload: RollbackReload,
}

pub struct RollbackBundle {
    pub directory: PathBuf,
}

/// Creates a bounded rollback bundle before any managed configuration write.
///
/// # Errors
///
/// Returns an error for invalid identifiers, unsafe target types, capacity
/// overflow, or any failure to durably write the bundle below the rollback root.
pub fn create_rollback_bundle(
    rollback_root: &Path,
    transaction_id: &str,
    targets: &[RollbackTarget],
    reload: RollbackReload,
    timeout_secs: u64,
    max_bytes: u64,
) -> Result<RollbackBundle, RollbackError> {
    for target in targets {
        match fs::symlink_metadata(target.path()) {
            Ok(metadata) if metadata.uid() == 0 && metadata.gid() == 0 => {}
            Ok(_) => return Err(RollbackError::UnsafeTarget(target.path().to_path_buf())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RollbackError::Io(error)),
        }
    }
    create_bundle_with(
        rollback_root,
        transaction_id,
        targets,
        reload,
        timeout_secs,
        max_bytes,
        |target| target.path().to_path_buf(),
    )
}

fn create_bundle_with<F>(
    rollback_root: &Path,
    transaction_id: &str,
    targets: &[RollbackTarget],
    reload: RollbackReload,
    timeout_secs: u64,
    max_bytes: u64,
    resolve: F,
) -> Result<RollbackBundle, RollbackError>
where
    F: Fn(RollbackTarget) -> PathBuf,
{
    validate_transaction_id(transaction_id)?;
    if targets.is_empty() || targets.len() > MAX_ENTRIES || !(5..=600).contains(&timeout_secs) {
        return Err(RollbackError::InvalidManifest);
    }
    let target_set: HashSet<_> = targets.iter().copied().collect();
    if target_set.len() != targets.len() || !targets_match_reload(&target_set, reload) {
        return Err(RollbackError::InvalidManifest);
    }
    fs::create_dir_all(rollback_root).map_err(RollbackError::Io)?;
    fs::set_permissions(rollback_root, fs::Permissions::from_mode(0o700))
        .map_err(RollbackError::Io)?;
    let directory = rollback_root.join(transaction_id);
    fs::create_dir(&directory).map_err(RollbackError::Io)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(RollbackError::Io)?;

    let result = (|| {
        let mut entries = Vec::with_capacity(targets.len());
        let mut total_bytes = 0_u64;
        for (index, target) in targets.iter().copied().enumerate() {
            let source = resolve(target);
            let metadata = match fs::symlink_metadata(&source) {
                Ok(metadata) if metadata.is_file() => Some(metadata),
                Ok(_) => return Err(RollbackError::UnsafeTarget(source)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(RollbackError::Io(error)),
            };
            let snapshot_name = format!("snapshot-{index}.bin");
            if let Some(metadata) = metadata {
                total_bytes = total_bytes.saturating_add(metadata.len());
                if total_bytes > max_bytes {
                    return Err(RollbackError::CapacityExceeded);
                }
                let bytes = read_bounded_file(&source, max_bytes.saturating_add(1))?;
                if bytes.len() as u64 != metadata.len() {
                    return Err(RollbackError::TargetChanged(source));
                }
                write_new_file(&directory.join(&snapshot_name), &bytes, 0o600)?;
                entries.push(SnapshotEntry {
                    target,
                    existed: true,
                    snapshot_name,
                    digest: Some(lower_hex(digest(&SHA256, &bytes).as_ref())),
                    mode: Some(metadata.permissions().mode() & 0o777),
                });
            } else {
                entries.push(SnapshotEntry {
                    target,
                    existed: false,
                    snapshot_name,
                    digest: None,
                    mode: None,
                });
            }
        }
        let manifest = RollbackManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
            timeout_secs,
            entries,
            reload,
        };
        let encoded = serde_json::to_vec(&manifest).map_err(RollbackError::Encode)?;
        if encoded.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(RollbackError::InvalidManifest);
        }
        write_new_file(&directory.join("manifest.json"), &encoded, 0o600)?;
        sync_directory(&directory)?;
        sync_directory(rollback_root)?;
        Ok(RollbackBundle {
            directory: directory.clone(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

/// Runs the independent watchdog for one daemon-created rollback transaction.
///
/// # Errors
///
/// Returns an error if the bundle is invalid or recovery cannot complete.
pub fn run_rollback_helper(
    rollback_root: &Path,
    transaction_id: &str,
    max_bytes: u64,
) -> Result<(), RollbackError> {
    run_helper_with(
        rollback_root,
        transaction_id,
        max_bytes,
        |target| target.path().to_path_buf(),
        execute_reload,
    )
}

fn run_helper_with<F, R>(
    rollback_root: &Path,
    transaction_id: &str,
    max_bytes: u64,
    resolve: F,
    reload: R,
) -> Result<(), RollbackError>
where
    F: Fn(RollbackTarget) -> PathBuf,
    R: Fn(RollbackReload) -> Result<(), RollbackError>,
{
    validate_transaction_id(transaction_id)?;
    let directory = rollback_root.join(transaction_id);
    let manifest = load_manifest(&directory, transaction_id)?;
    let started = Instant::now();
    let timeout = Duration::from_secs(manifest.timeout_secs);
    while started.elapsed() < timeout {
        let decision = directory.join("decision");
        if decision.is_file() {
            let value = read_bounded_file(&decision, 80)?;
            if value == decision_value("confirm", transaction_id).as_bytes() {
                fs::remove_dir_all(&directory).map_err(RollbackError::Io)?;
                return Ok(());
            }
            if value == decision_value("rollback", transaction_id).as_bytes() {
                return recover_bundle(&directory, &manifest, max_bytes, resolve, reload);
            }
            return Err(RollbackError::InvalidManifest);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    recover_bundle(&directory, &manifest, max_bytes, resolve, reload)
}

fn recover_bundle<F, R>(
    directory: &Path,
    manifest: &RollbackManifest,
    max_bytes: u64,
    resolve: F,
    reload: R,
) -> Result<(), RollbackError>
where
    F: Fn(RollbackTarget) -> PathBuf,
    R: Fn(RollbackReload) -> Result<(), RollbackError>,
{
    let recovery =
        restore(directory, manifest, max_bytes, resolve).and_then(|()| reload(manifest.reload));
    match recovery {
        Ok(()) => {
            write_new_file(&directory.join("rolled-back"), b"ok", 0o600)?;
            sync_directory(directory)
        }
        Err(error) => {
            let stage = if matches!(error, RollbackError::ReloadFailed) {
                b"reload".as_slice()
            } else {
                b"restore".as_slice()
            };
            let _ = write_new_file(&directory.join("rollback-failed"), stage, 0o600);
            let _ = sync_directory(directory);
            Err(error)
        }
    }
}

/// Confirms a transaction by atomically creating its fixed confirmation marker.
///
/// # Errors
///
/// Returns an error for an invalid transaction or filesystem failure.
pub fn confirm_rollback(rollback_root: &Path, transaction_id: &str) -> Result<(), RollbackError> {
    validate_transaction_id(transaction_id)?;
    let directory = rollback_root.join(transaction_id);
    load_manifest(&directory, transaction_id)?;
    write_decision(&directory, "confirm", transaction_id)
}

/// Requests immediate recovery from the already running independent helper.
///
/// The marker contains only the exact validated transaction ID and is durable before return.
/// Repeating the same request is idempotent.
///
/// # Errors
///
/// Returns an error for an invalid bundle, conflicting marker, or filesystem failure.
pub fn request_rollback(rollback_root: &Path, transaction_id: &str) -> Result<(), RollbackError> {
    validate_transaction_id(transaction_id)?;
    let directory = rollback_root.join(transaction_id);
    load_manifest(&directory, transaction_id)?;
    write_decision(&directory, "rollback", transaction_id)
}

fn write_decision(
    directory: &Path,
    action: &str,
    transaction_id: &str,
) -> Result<(), RollbackError> {
    let marker = directory.join("decision");
    let expected = decision_value(action, transaction_id);
    if marker.exists() {
        return validate_existing_decision(&marker, &expected);
    }
    let temporary = directory.join(format!(".decision-{action}"));
    match write_new_file(&temporary, expected.as_bytes(), 0o600) {
        Ok(()) => {}
        Err(RollbackError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            for _ in 0..100 {
                if marker.exists() {
                    return validate_existing_decision(&marker, &expected);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(RollbackError::DecisionConflict);
        }
        Err(error) => return Err(error),
    }
    match fs::hard_link(&temporary, &marker) {
        Ok(()) => {
            fs::remove_file(&temporary).map_err(RollbackError::Io)?;
            sync_directory(directory)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            validate_existing_decision(&marker, &expected)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(RollbackError::Io(error))
        }
    }
}

fn validate_existing_decision(marker: &Path, expected: &str) -> Result<(), RollbackError> {
    let value = read_bounded_file(marker, 80)?;
    if value == expected.as_bytes() {
        Ok(())
    } else {
        Err(RollbackError::DecisionConflict)
    }
}

fn decision_value(action: &str, transaction_id: &str) -> String {
    format!("{action}:{transaction_id}")
}

/// Reads the durable recovery result without waiting or trusting process state.
///
/// # Errors
///
/// Returns an error for an invalid bundle, malformed outcome marker, or filesystem failure.
pub fn rollback_outcome(
    rollback_root: &Path,
    transaction_id: &str,
) -> Result<RollbackOutcome, RollbackError> {
    validate_transaction_id(transaction_id)?;
    let directory = rollback_root.join(transaction_id);
    load_manifest(&directory, transaction_id)?;
    let rolled_back = directory.join("rolled-back");
    if rolled_back.is_file() {
        return if read_bounded_file(&rolled_back, 16)? == b"ok" {
            Ok(RollbackOutcome::RolledBack)
        } else {
            Err(RollbackError::InvalidManifest)
        };
    }
    let failed = directory.join("rollback-failed");
    if failed.is_file() {
        return match read_bounded_file(&failed, 16)?.as_slice() {
            b"restore" => Ok(RollbackOutcome::RestoreFailed),
            b"reload" => Ok(RollbackOutcome::ReloadFailed),
            _ => Err(RollbackError::InvalidManifest),
        };
    }
    Ok(RollbackOutcome::Pending)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackOutcome {
    Pending,
    RolledBack,
    RestoreFailed,
    ReloadFailed,
}

fn restore<F>(
    directory: &Path,
    manifest: &RollbackManifest,
    max_bytes: u64,
    resolve: F,
) -> Result<(), RollbackError>
where
    F: Fn(RollbackTarget) -> PathBuf,
{
    let mut restored_bytes = 0_u64;
    for entry in &manifest.entries {
        let target = resolve(entry.target);
        if entry.existed {
            let snapshot = read_bounded_file(&directory.join(&entry.snapshot_name), max_bytes)?;
            restored_bytes = restored_bytes.saturating_add(
                u64::try_from(snapshot.len()).map_err(|_| RollbackError::CapacityExceeded)?,
            );
            if restored_bytes > max_bytes {
                return Err(RollbackError::CapacityExceeded);
            }
            let actual = lower_hex(digest(&SHA256, &snapshot).as_ref());
            if entry.digest.as_deref() != Some(&actual) {
                return Err(RollbackError::SnapshotDigestMismatch);
            }
            atomic_replace(
                &target,
                &snapshot,
                entry.mode.ok_or(RollbackError::InvalidManifest)?,
                &manifest.transaction_id,
            )?;
        } else {
            match fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.is_file() => {
                    fs::remove_file(&target).map_err(RollbackError::Io)?;
                    sync_directory(target.parent().ok_or(RollbackError::InvalidManifest)?)?;
                }
                Ok(_) => return Err(RollbackError::UnsafeTarget(target)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(RollbackError::Io(error)),
            }
        }
    }
    Ok(())
}

fn load_manifest(
    directory: &Path,
    transaction_id: &str,
) -> Result<RollbackManifest, RollbackError> {
    let metadata = fs::symlink_metadata(directory).map_err(RollbackError::Io)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(RollbackError::UnsafeBundle);
    }
    let encoded = read_bounded_file(&directory.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: RollbackManifest =
        serde_json::from_slice(&encoded).map_err(RollbackError::Decode)?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || manifest.transaction_id != transaction_id
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_ENTRIES
        || !(5..=600).contains(&manifest.timeout_secs)
    {
        return Err(RollbackError::InvalidManifest);
    }
    let mut targets = HashSet::with_capacity(manifest.entries.len());
    for (index, entry) in manifest.entries.iter().enumerate() {
        let metadata_shape_valid = if entry.existed {
            entry.digest.as_deref().is_some_and(valid_digest)
                && entry.mode.is_some_and(|mode| mode <= 0o777)
        } else {
            entry.digest.is_none() && entry.mode.is_none()
        };
        if entry.snapshot_name != format!("snapshot-{index}.bin")
            || !metadata_shape_valid
            || !targets.insert(entry.target)
        {
            return Err(RollbackError::InvalidManifest);
        }
    }
    if !targets_match_reload(&targets, manifest.reload) {
        return Err(RollbackError::InvalidManifest);
    }
    Ok(manifest)
}

fn atomic_replace(
    target: &Path,
    bytes: &[u8],
    mode: u32,
    transaction_id: &str,
) -> Result<(), RollbackError> {
    let parent = target.parent().ok_or(RollbackError::InvalidManifest)?;
    if !parent.is_dir() {
        return Err(RollbackError::UnsafeTarget(parent.to_path_buf()));
    }
    if let Ok(metadata) = fs::symlink_metadata(target) {
        if !metadata.is_file() {
            return Err(RollbackError::UnsafeTarget(target.to_path_buf()));
        }
    }
    let temporary = parent.join(format!(".mbed-agent-rollback-{transaction_id}"));
    write_new_file(&temporary, bytes, mode)?;
    fs::rename(&temporary, target).map_err(RollbackError::Io)?;
    sync_directory(parent)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, RollbackError> {
    let metadata = fs::symlink_metadata(path).map_err(RollbackError::Io)?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(RollbackError::UnsafeTarget(path.to_path_buf()));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(RollbackError::Io)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(RollbackError::Io)?;
    if bytes.len() as u64 > max_bytes {
        return Err(RollbackError::CapacityExceeded);
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), RollbackError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(RollbackError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(RollbackError::Io)?;
    file.write_all(bytes).map_err(RollbackError::Io)?;
    file.sync_all().map_err(RollbackError::Io)
}

fn sync_directory(path: &Path) -> Result<(), RollbackError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(RollbackError::Io)
}

fn execute_reload(reload: RollbackReload) -> Result<(), RollbackError> {
    let (program, arguments): (&str, &[&str]) = match reload {
        RollbackReload::OpenWrtFirewall => ("/etc/init.d/firewall", &["reload"]),
        RollbackReload::LinuxNftables => (
            "/usr/sbin/nft",
            &["-f", "/etc/mbed-agent/managed/firewall.nft"],
        ),
    };
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .status()
        .map_err(RollbackError::Io)?;
    if status.success() {
        Ok(())
    } else {
        Err(RollbackError::ReloadFailed)
    }
}

fn validate_transaction_id(value: &str) -> Result<(), RollbackError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(RollbackError::InvalidTransactionId);
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn targets_match_reload(targets: &HashSet<RollbackTarget>, reload: RollbackReload) -> bool {
    match reload {
        RollbackReload::OpenWrtFirewall => {
            targets == &HashSet::from([RollbackTarget::OpenWrtFirewall])
        }
        RollbackReload::LinuxNftables => {
            targets == &HashSet::from([RollbackTarget::LinuxNftablesManaged])
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug, Error)]
pub enum RollbackError {
    #[error("invalid rollback transaction id")]
    InvalidTransactionId,
    #[error("invalid rollback manifest")]
    InvalidManifest,
    #[error("rollback bundle is unsafe")]
    UnsafeBundle,
    #[error("unsafe rollback target: {0}")]
    UnsafeTarget(PathBuf),
    #[error("rollback target changed while being snapshotted: {0}")]
    TargetChanged(PathBuf),
    #[error("rollback capacity exceeded")]
    CapacityExceeded,
    #[error("rollback snapshot digest mismatch")]
    SnapshotDigestMismatch,
    #[error("rollback reload failed")]
    ReloadFailed,
    #[error("rollback decision conflicts with an existing terminal decision")]
    DecisionConflict,
    #[error("rollback manifest encoding failed: {0}")]
    Encode(serde_json::Error),
    #[error("rollback manifest decoding failed: {0}")]
    Decode(serde_json::Error),
    #[error("rollback I/O failed: {0}")]
    Io(io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_watchdog_removes_bundle_without_restoring() {
        let root = test_root("confirm");
        let target = root.join("managed.nft");
        fs::write(&target, b"before").expect("target");
        create_bundle_with(
            &root.join("rollback"),
            "txn-confirm",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| target.clone(),
        )
        .expect("bundle");
        confirm_rollback(&root.join("rollback"), "txn-confirm").expect("confirm");
        fs::write(&target, b"after").expect("change target");
        run_helper_with(
            &root.join("rollback"),
            "txn-confirm",
            1024,
            |_| target.clone(),
            |_| panic!("confirmed transaction must not reload"),
        )
        .expect("watchdog");
        assert_eq!(fs::read(&target).expect("target"), b"after");
        assert!(!root.join("rollback/txn-confirm").exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn timeout_restore_rejects_tampered_snapshot() {
        let root = test_root("tamper");
        let rollback = root.join("rollback");
        let target = root.join("managed.nft");
        fs::write(&target, b"before").expect("target");
        let bundle = create_bundle_with(
            &rollback,
            "txn-tamper",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| target.clone(),
        )
        .expect("bundle");
        fs::write(bundle.directory.join("snapshot-0.bin"), b"tampered").expect("tamper");
        let manifest = load_manifest(&bundle.directory, "txn-tamper").expect("manifest");
        assert!(matches!(
            restore(&bundle.directory, &manifest, 1024, |_| target.clone()),
            Err(RollbackError::SnapshotDigestMismatch)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn failed_reload_leaves_a_durable_failure_stage() {
        let root = test_root("reload-failure");
        let rollback = root.join("rollback");
        let target = root.join("managed.nft");
        fs::write(&target, b"before").expect("target");
        let bundle = create_bundle_with(
            &rollback,
            "txn-reload-failure",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| target.clone(),
        )
        .expect("bundle");
        fs::write(&target, b"after").expect("change");
        let manifest = load_manifest(&bundle.directory, "txn-reload-failure").expect("manifest");
        assert!(matches!(
            recover_bundle(
                &bundle.directory,
                &manifest,
                1024,
                |_| target.clone(),
                |_| Err(RollbackError::ReloadFailed),
            ),
            Err(RollbackError::ReloadFailed)
        ));
        assert_eq!(fs::read(&target).expect("restored"), b"before");
        assert_eq!(
            fs::read(bundle.directory.join("rollback-failed")).expect("failure marker"),
            b"reload"
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn restore_atomically_reinstates_existing_and_absent_files() {
        let root = test_root("restore");
        let rollback = root.join("rollback");
        let existing = root.join("existing");
        let absent = root.join("absent");
        fs::write(&existing, b"before").expect("existing");
        let bundle = create_bundle_with(
            &rollback,
            "txn-existing",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| existing.clone(),
        )
        .expect("bundle");
        fs::write(&existing, b"after").expect("change existing");
        let manifest = load_manifest(&bundle.directory, "txn-existing").expect("manifest");
        restore(&bundle.directory, &manifest, 1024, |_| existing.clone()).expect("restore");
        assert_eq!(fs::read(&existing).expect("restored"), b"before");

        let bundle = create_bundle_with(
            &rollback,
            "txn-absent",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| absent.clone(),
        )
        .expect("bundle");
        fs::write(&absent, b"created").expect("create absent");
        let manifest = load_manifest(&bundle.directory, "txn-absent").expect("manifest");
        restore(&bundle.directory, &manifest, 1024, |_| absent.clone()).expect("restore");
        assert!(!absent.exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn immediate_request_is_idempotent_and_reports_durable_outcome() {
        let root = test_root("immediate");
        let rollback = root.join("rollback");
        let target = root.join("managed.nft");
        fs::write(&target, b"before").expect("target");
        create_bundle_with(
            &rollback,
            "txn-immediate",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| target.clone(),
        )
        .expect("bundle");
        fs::write(&target, b"after").expect("change");
        let helper_rollback = rollback.clone();
        let helper_target = target.clone();
        let helper = std::thread::spawn(move || {
            run_helper_with(
                &helper_rollback,
                "txn-immediate",
                1024,
                |_| helper_target.clone(),
                |_| Ok(()),
            )
        });
        request_rollback(&rollback, "txn-immediate").expect("request");
        request_rollback(&rollback, "txn-immediate").expect("repeat request");
        helper.join().expect("join").expect("helper");
        assert_eq!(fs::read(&target).expect("restored"), b"before");
        assert_eq!(
            rollback_outcome(&rollback, "txn-immediate").expect("outcome"),
            RollbackOutcome::RolledBack
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn first_terminal_decision_wins() {
        let root = test_root("decision-conflict");
        let rollback = root.join("rollback");
        let target = root.join("managed.nft");
        fs::write(&target, b"before").expect("target");
        create_bundle_with(
            &rollback,
            "txn-decision",
            &[RollbackTarget::LinuxNftablesManaged],
            RollbackReload::LinuxNftables,
            5,
            1024,
            |_| target.clone(),
        )
        .expect("bundle");
        request_rollback(&rollback, "txn-decision").expect("rollback wins");
        assert!(matches!(
            confirm_rollback(&rollback, "txn-decision"),
            Err(RollbackError::DecisionConflict)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mbed-agent-rollback-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test root");
        root
    }
}
