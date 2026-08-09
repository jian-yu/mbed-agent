use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MANIFEST_SCHEMA_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 8;
const ROLLBACK_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IPTABLES_SAVE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTarget {
    OpenWrtFirewall,
    OpenWrtNetwork,
    OpenWrtDhcp,
    LinuxNftablesManaged,
    LinuxNftablesRuntime,
    LinuxFirewallCanonical,
    LinuxNetworkRouteBatch,
    LinuxNetworkCanonical,
    LinuxIptablesIpv4FromOwned,
    LinuxIptablesIpv4FromAbsent,
    LinuxIptablesIpv6FromOwned,
    LinuxIptablesIpv6FromAbsent,
}

impl RollbackTarget {
    fn path(self) -> Option<&'static Path> {
        match self {
            Self::OpenWrtFirewall => Some(Path::new("/etc/config/firewall")),
            Self::OpenWrtNetwork => Some(Path::new("/etc/config/network")),
            Self::OpenWrtDhcp => Some(Path::new("/etc/config/dhcp")),
            Self::LinuxNftablesManaged => Some(Path::new("/etc/mbed-agent/managed/firewall.nft")),
            Self::LinuxNftablesRuntime
            | Self::LinuxFirewallCanonical
            | Self::LinuxNetworkRouteBatch
            | Self::LinuxNetworkCanonical
            | Self::LinuxIptablesIpv4FromOwned
            | Self::LinuxIptablesIpv4FromAbsent
            | Self::LinuxIptablesIpv6FromOwned
            | Self::LinuxIptablesIpv6FromAbsent => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackReload {
    OpenWrtFirewall,
    OpenWrtNetwork,
    LinuxNftables,
    LinuxNftablesRuntime,
    LinuxIptablesRuntime,
    LinuxNetworkRoutesRuntime,
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

/// Prior volatile canonical state carried by a generic nftables rollback bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCanonicalSnapshot {
    NotRuntime,
    Absent,
    Present(Vec<u8>),
    NetworkAbsent,
    NetworkPresent(Vec<u8>),
}

/// Conditional rollback inputs for one iptables address family.
#[derive(Debug, Clone, Copy)]
pub struct IptablesRuntimeRollback<'a> {
    pub restore_from_owned: Option<&'a [u8]>,
    pub restore_from_absent: Option<&'a [u8]>,
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
        let path = target.path().ok_or(RollbackError::InvalidManifest)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.uid() == 0 && metadata.gid() == 0 => {}
            Ok(_) => return Err(RollbackError::UnsafeTarget(path.to_path_buf())),
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
        |target| target.path().unwrap_or(Path::new("/")).to_path_buf(),
    )
}

/// Creates a runtime-only nftables rollback bundle from a pre-rendered owned-table snapshot.
///
/// The ruleset is stored only below the private rollback root and is consumed by the independent
/// helper. It never creates or updates persistent Linux configuration.
///
/// # Errors
///
/// Returns an error for invalid identifiers or limits, an unsafe rollback root, an empty or
/// oversized ruleset, or a failure to durably create the bundle.
pub fn create_nftables_runtime_rollback_bundle(
    rollback_root: &Path,
    transaction_id: &str,
    ruleset: &[u8],
    prior_table_existed: bool,
    canonical_state: Option<&[u8]>,
    timeout_secs: u64,
    max_bytes: u64,
) -> Result<RollbackBundle, RollbackError> {
    validate_transaction_id(transaction_id)?;
    let canonical_bytes: u64 = canonical_state
        .map_or(0, <[u8]>::len)
        .try_into()
        .map_err(|_| RollbackError::CapacityExceeded)?;
    if !(5..=600).contains(&timeout_secs)
        || ruleset.is_empty()
        || ruleset.len() as u64 > max_bytes
        || canonical_bytes > max_bytes.saturating_sub(ruleset.len() as u64)
    {
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
        let snapshot_name = "snapshot-0.bin".to_owned();
        write_new_file(&directory.join(&snapshot_name), ruleset, 0o600)?;
        let canonical_name = "snapshot-1.bin".to_owned();
        let canonical_entry = if let Some(canonical) = canonical_state {
            write_new_file(&directory.join(&canonical_name), canonical, 0o600)?;
            SnapshotEntry {
                target: RollbackTarget::LinuxFirewallCanonical,
                existed: true,
                snapshot_name: canonical_name,
                digest: Some(lower_hex(digest(&SHA256, canonical).as_ref())),
                mode: None,
            }
        } else {
            SnapshotEntry {
                target: RollbackTarget::LinuxFirewallCanonical,
                existed: false,
                snapshot_name: canonical_name,
                digest: None,
                mode: None,
            }
        };
        let manifest = RollbackManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
            timeout_secs,
            entries: vec![
                SnapshotEntry {
                    target: RollbackTarget::LinuxNftablesRuntime,
                    existed: prior_table_existed,
                    snapshot_name,
                    digest: Some(lower_hex(digest(&SHA256, ruleset).as_ref())),
                    mode: None,
                },
                canonical_entry,
            ],
            reload: RollbackReload::LinuxNftablesRuntime,
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

/// Creates a runtime-only generic Linux network rollback bundle.
///
/// The reverse `ip` batch and optional prior network canonical state remain below the private
/// rollback root. The helper executes only a fixed `ip -force -batch <snapshot>` command.
///
/// # Errors
///
/// Returns an error for invalid identifiers/limits, empty or oversized artifacts, or failure to
/// durably create the bundle.
pub fn create_network_routes_runtime_rollback_bundle(
    rollback_root: &Path,
    transaction_id: &str,
    rollback_batch: &[u8],
    canonical_state: Option<&[u8]>,
    timeout_secs: u64,
    max_bytes: u64,
) -> Result<RollbackBundle, RollbackError> {
    validate_transaction_id(transaction_id)?;
    let canonical_len = canonical_state.map_or(0, <[u8]>::len);
    let total = rollback_batch.len().saturating_add(canonical_len);
    if !(5..=600).contains(&timeout_secs)
        || rollback_batch.is_empty()
        || u64::try_from(total).unwrap_or(u64::MAX) > max_bytes
    {
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
        write_new_file(&directory.join("snapshot-0.bin"), rollback_batch, 0o600)?;
        let canonical_entry = if let Some(canonical) = canonical_state {
            write_new_file(&directory.join("snapshot-1.bin"), canonical, 0o600)?;
            SnapshotEntry {
                target: RollbackTarget::LinuxNetworkCanonical,
                existed: true,
                snapshot_name: "snapshot-1.bin".into(),
                digest: Some(lower_hex(digest(&SHA256, canonical).as_ref())),
                mode: None,
            }
        } else {
            SnapshotEntry {
                target: RollbackTarget::LinuxNetworkCanonical,
                existed: false,
                snapshot_name: "snapshot-1.bin".into(),
                digest: None,
                mode: None,
            }
        };
        let manifest = RollbackManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            transaction_id: transaction_id.into(),
            timeout_secs,
            entries: vec![
                SnapshotEntry {
                    target: RollbackTarget::LinuxNetworkRouteBatch,
                    existed: true,
                    snapshot_name: "snapshot-0.bin".into(),
                    digest: Some(lower_hex(digest(&SHA256, rollback_batch).as_ref())),
                    mode: None,
                },
                canonical_entry,
            ],
            reload: RollbackReload::LinuxNetworkRoutesRuntime,
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

/// Creates a bounded runtime-only dual-stack iptables rollback bundle.
///
/// Each family supplies an artifact selected when current state is owned and an optional artifact
/// selected when current state is absent. Missing artifacts mean that recovery for that observed
/// state is intentionally a no-op.
///
/// # Errors
///
/// Returns an error for invalid identifiers/limits, missing owned-state recovery, empty or
/// oversized artifacts, or a failure to durably create the bundle below the rollback root.
pub fn create_iptables_runtime_rollback_bundle(
    rollback_root: &Path,
    transaction_id: &str,
    ipv4: IptablesRuntimeRollback<'_>,
    ipv6: IptablesRuntimeRollback<'_>,
    canonical_state: Option<&[u8]>,
    timeout_secs: u64,
    max_bytes: u64,
) -> Result<RollbackBundle, RollbackError> {
    validate_transaction_id(transaction_id)?;
    if !(5..=600).contains(&timeout_secs)
        || ipv4.restore_from_owned.is_none()
        || ipv6.restore_from_owned.is_none()
    {
        return Err(RollbackError::InvalidManifest);
    }
    let runtime_entries = [
        (
            RollbackTarget::LinuxIptablesIpv4FromOwned,
            ipv4.restore_from_owned,
        ),
        (
            RollbackTarget::LinuxIptablesIpv4FromAbsent,
            ipv4.restore_from_absent,
        ),
        (
            RollbackTarget::LinuxIptablesIpv6FromOwned,
            ipv6.restore_from_owned,
        ),
        (
            RollbackTarget::LinuxIptablesIpv6FromAbsent,
            ipv6.restore_from_absent,
        ),
        (RollbackTarget::LinuxFirewallCanonical, canonical_state),
    ];
    let mut total_bytes = 0_u64;
    for (_, bytes) in runtime_entries {
        if let Some(bytes) = bytes {
            if bytes.is_empty() {
                return Err(RollbackError::InvalidManifest);
            }
            total_bytes = total_bytes.saturating_add(
                u64::try_from(bytes.len()).map_err(|_| RollbackError::CapacityExceeded)?,
            );
            if total_bytes > max_bytes {
                return Err(RollbackError::CapacityExceeded);
            }
        }
    }
    fs::create_dir_all(rollback_root).map_err(RollbackError::Io)?;
    fs::set_permissions(rollback_root, fs::Permissions::from_mode(0o700))
        .map_err(RollbackError::Io)?;
    let directory = rollback_root.join(transaction_id);
    fs::create_dir(&directory).map_err(RollbackError::Io)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(RollbackError::Io)?;
    let result = (|| {
        let mut entries = Vec::with_capacity(runtime_entries.len());
        for (index, (target, bytes)) in runtime_entries.into_iter().enumerate() {
            let snapshot_name = format!("snapshot-{index}.bin");
            if let Some(bytes) = bytes {
                write_new_file(&directory.join(&snapshot_name), bytes, 0o600)?;
                entries.push(SnapshotEntry {
                    target,
                    existed: true,
                    snapshot_name,
                    digest: Some(lower_hex(digest(&SHA256, bytes).as_ref())),
                    mode: None,
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
            reload: RollbackReload::LinuxIptablesRuntime,
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

/// Loads the digest-verified prior canonical state from a rollback bundle.
///
/// # Errors
///
/// Returns an error for an invalid bundle or an oversized/tampered canonical snapshot.
pub fn nftables_runtime_rollback_canonical_state(
    rollback_root: &Path,
    transaction_id: &str,
    max_bytes: u64,
) -> Result<RuntimeCanonicalSnapshot, RollbackError> {
    runtime_rollback_canonical_state(rollback_root, transaction_id, max_bytes)
}

/// Loads prior canonical state from either supported runtime firewall rollback bundle.
///
/// # Errors
///
/// Returns an error for an invalid bundle or an oversized/tampered canonical snapshot.
pub fn runtime_rollback_canonical_state(
    rollback_root: &Path,
    transaction_id: &str,
    max_bytes: u64,
) -> Result<RuntimeCanonicalSnapshot, RollbackError> {
    validate_transaction_id(transaction_id)?;
    let directory = rollback_root.join(transaction_id);
    let manifest = load_manifest(&directory, transaction_id)?;
    let canonical_target = match manifest.reload {
        RollbackReload::LinuxNftablesRuntime | RollbackReload::LinuxIptablesRuntime => {
            RollbackTarget::LinuxFirewallCanonical
        }
        RollbackReload::LinuxNetworkRoutesRuntime => RollbackTarget::LinuxNetworkCanonical,
        _ => return Ok(RuntimeCanonicalSnapshot::NotRuntime),
    };
    let network = canonical_target == RollbackTarget::LinuxNetworkCanonical;
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.target == canonical_target)
        .ok_or(RollbackError::InvalidManifest)?;
    if !entry.existed {
        return Ok(if network {
            RuntimeCanonicalSnapshot::NetworkAbsent
        } else {
            RuntimeCanonicalSnapshot::Absent
        });
    }
    let snapshot = read_bounded_file(&directory.join(&entry.snapshot_name), max_bytes)?;
    let actual = lower_hex(digest(&SHA256, &snapshot).as_ref());
    if entry.digest.as_deref() != Some(&actual) {
        return Err(RollbackError::SnapshotDigestMismatch);
    }
    Ok(if network {
        RuntimeCanonicalSnapshot::NetworkPresent(snapshot)
    } else {
        RuntimeCanonicalSnapshot::Present(snapshot)
    })
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
        |target| target.path().unwrap_or(Path::new("/")).to_path_buf(),
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
    R: Fn(RollbackReload, &Path, &RollbackManifest) -> Result<(), RollbackError>,
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
    R: Fn(RollbackReload, &Path, &RollbackManifest) -> Result<(), RollbackError>,
{
    let recovery = restore(directory, manifest, max_bytes, resolve)
        .and_then(|()| reload(manifest.reload, directory, manifest));
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
        if is_runtime_target(entry.target) {
            if !matches!(
                entry.target,
                RollbackTarget::LinuxNftablesRuntime | RollbackTarget::LinuxNetworkRouteBatch
            ) && !entry.existed
            {
                continue;
            }
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
            continue;
        }
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
        let metadata_shape_valid = if entry.target == RollbackTarget::LinuxNftablesRuntime {
            entry.digest.as_deref().is_some_and(valid_digest) && entry.mode.is_none()
        } else if matches!(
            entry.target,
            RollbackTarget::LinuxFirewallCanonical
                | RollbackTarget::LinuxNetworkCanonical
                | RollbackTarget::LinuxNetworkRouteBatch
        ) || is_iptables_artifact(entry.target)
        {
            if entry.existed {
                entry.digest.as_deref().is_some_and(valid_digest) && entry.mode.is_none()
            } else {
                entry.digest.is_none() && entry.mode.is_none()
            }
        } else if entry.existed {
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

const fn is_iptables_artifact(target: RollbackTarget) -> bool {
    matches!(
        target,
        RollbackTarget::LinuxIptablesIpv4FromOwned
            | RollbackTarget::LinuxIptablesIpv4FromAbsent
            | RollbackTarget::LinuxIptablesIpv6FromOwned
            | RollbackTarget::LinuxIptablesIpv6FromAbsent
    )
}

const fn is_runtime_target(target: RollbackTarget) -> bool {
    matches!(
        target,
        RollbackTarget::LinuxNftablesRuntime
            | RollbackTarget::LinuxFirewallCanonical
            | RollbackTarget::LinuxNetworkRouteBatch
            | RollbackTarget::LinuxNetworkCanonical
    ) || is_iptables_artifact(target)
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

fn execute_reload(
    reload: RollbackReload,
    directory: &Path,
    manifest: &RollbackManifest,
) -> Result<(), RollbackError> {
    let (program, arguments): (PathBuf, Vec<PathBuf>) = match reload {
        RollbackReload::OpenWrtFirewall => (
            PathBuf::from("/etc/init.d/firewall"),
            vec![PathBuf::from("reload")],
        ),
        RollbackReload::OpenWrtNetwork => (
            PathBuf::from("/etc/init.d/network"),
            vec![PathBuf::from("reload")],
        ),
        RollbackReload::LinuxNftables => (
            resolve_fixed_program("nft")?,
            vec![
                PathBuf::from("--file"),
                PathBuf::from("/etc/mbed-agent/managed/firewall.nft"),
            ],
        ),
        RollbackReload::LinuxNftablesRuntime => {
            let nft = resolve_fixed_program("nft")?;
            let prior_runtime_table_existed = manifest
                .entries
                .iter()
                .find(|entry| entry.target == RollbackTarget::LinuxNftablesRuntime)
                .is_some_and(|entry| entry.existed);
            if !managed_nftables_table_exists(&nft)? {
                return if prior_runtime_table_existed {
                    Err(RollbackError::ReloadFailed)
                } else {
                    Ok(())
                };
            }
            (
                nft,
                vec![PathBuf::from("--file"), directory.join("snapshot-0.bin")],
            )
        }
        RollbackReload::LinuxIptablesRuntime => {
            return restore_iptables_families(directory, manifest);
        }
        RollbackReload::LinuxNetworkRoutesRuntime => {
            let ip = resolve_fixed_program("ip")?;
            let entry = manifest
                .entries
                .iter()
                .find(|entry| entry.target == RollbackTarget::LinuxNetworkRouteBatch)
                .ok_or(RollbackError::InvalidManifest)?;
            return run_fixed_status(
                &ip,
                &["-force", "-batch"],
                Some(&directory.join(&entry.snapshot_name)),
            );
        }
    };
    let status = Command::new(program)
        .args(&arguments)
        .env_clear()
        .status()
        .map_err(RollbackError::Io)?;
    if status.success() {
        Ok(())
    } else {
        Err(RollbackError::ReloadFailed)
    }
}

fn restore_iptables_families(
    directory: &Path,
    manifest: &RollbackManifest,
) -> Result<(), RollbackError> {
    let ipv4 = restore_iptables_family(directory, manifest, false);
    let ipv6 = restore_iptables_family(directory, manifest, true);
    if ipv4.is_ok() && ipv6.is_ok() {
        Ok(())
    } else {
        Err(RollbackError::ReloadFailed)
    }
}

fn restore_iptables_family(
    directory: &Path,
    manifest: &RollbackManifest,
    ipv6: bool,
) -> Result<(), RollbackError> {
    let save_program = resolve_fixed_program(if ipv6 {
        "ip6tables-save"
    } else {
        "iptables-save"
    })?;
    let output = run_fixed_capture(&save_program, &[], MAX_IPTABLES_SAVE_BYTES)?;
    let save = std::str::from_utf8(&output).map_err(|_| RollbackError::ReloadFailed)?;
    let current = inspect_runtime_iptables_state(save)?;
    let target = match (ipv6, current) {
        (false, RuntimeIptablesState::Owned) => RollbackTarget::LinuxIptablesIpv4FromOwned,
        (false, RuntimeIptablesState::Absent) => RollbackTarget::LinuxIptablesIpv4FromAbsent,
        (true, RuntimeIptablesState::Owned) => RollbackTarget::LinuxIptablesIpv6FromOwned,
        (true, RuntimeIptablesState::Absent) => RollbackTarget::LinuxIptablesIpv6FromAbsent,
    };
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.target == target)
        .ok_or(RollbackError::InvalidManifest)?;
    if !entry.existed {
        return Ok(());
    }
    let artifact = read_bounded_file(
        &directory.join(&entry.snapshot_name),
        MAX_IPTABLES_SAVE_BYTES,
    )?;
    let actual = lower_hex(digest(&SHA256, &artifact).as_ref());
    if entry.digest.as_deref() != Some(&actual) {
        return Err(RollbackError::SnapshotDigestMismatch);
    }
    let restore_program = resolve_fixed_program(if ipv6 {
        "ip6tables-restore"
    } else {
        "iptables-restore"
    })?;
    run_fixed_stdin(&restore_program, &["--noflush"], &artifact)
}

fn run_fixed_capture(
    program: &Path,
    arguments: &[&str],
    max_bytes: u64,
) -> Result<Vec<u8>, RollbackError> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(RollbackError::Io)?;
    let stdout = child.stdout.take().ok_or(RollbackError::ReloadFailed)?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut output)
            .map(|_| output)
    });
    wait_bounded(&mut child)?;
    let output = reader
        .join()
        .map_err(|_| RollbackError::ReloadFailed)?
        .map_err(RollbackError::Io)?;
    if u64::try_from(output.len()).unwrap_or(u64::MAX) > max_bytes {
        Err(RollbackError::CapacityExceeded)
    } else {
        Ok(output)
    }
}

fn run_fixed_stdin(program: &Path, arguments: &[&str], input: &[u8]) -> Result<(), RollbackError> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(RollbackError::Io)?;
    child
        .stdin
        .take()
        .ok_or(RollbackError::ReloadFailed)?
        .write_all(input)
        .map_err(RollbackError::Io)?;
    wait_bounded(&mut child)
}

fn run_fixed_status(
    program: &Path,
    arguments: &[&str],
    final_path: Option<&Path>,
) -> Result<(), RollbackError> {
    let mut command = Command::new(program);
    command.args(arguments).env_clear();
    if let Some(path) = final_path {
        command.arg(path);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(RollbackError::Io)?;
    wait_bounded(&mut child)
}

fn wait_bounded(child: &mut std::process::Child) -> Result<(), RollbackError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(RollbackError::Io)? {
            return if status.success() {
                Ok(())
            } else {
                Err(RollbackError::ReloadFailed)
            };
        }
        if started.elapsed() >= ROLLBACK_COMMAND_TIMEOUT {
            child.kill().map_err(RollbackError::Io)?;
            let _ = child.wait();
            return Err(RollbackError::ReloadFailed);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeIptablesState {
    Absent,
    Owned,
}

fn inspect_runtime_iptables_state(save: &str) -> Result<RuntimeIptablesState, RollbackError> {
    const BINDINGS: &[(&str, &str, &str, &str)] = &[
        ("filter", "INPUT", "MBED_INPUT", "mbed-agent-owned:v1:input"),
        (
            "filter",
            "OUTPUT",
            "MBED_OUTPUT",
            "mbed-agent-owned:v1:output",
        ),
        (
            "filter",
            "FORWARD",
            "MBED_FORWARD",
            "mbed-agent-owned:v1:forward",
        ),
        (
            "nat",
            "PREROUTING",
            "MBED_PREROUTING",
            "mbed-agent-owned:v1:prerouting",
        ),
        (
            "nat",
            "POSTROUTING",
            "MBED_POSTROUTING",
            "mbed-agent-owned:v1:postrouting",
        ),
        (
            "mangle",
            "FORWARD",
            "MBED_MANGLE_FORWARD",
            "mbed-agent-owned:v1:mangle-forward",
        ),
    ];
    if u64::try_from(save.len()).unwrap_or(u64::MAX) > MAX_IPTABLES_SAVE_BYTES
        || save
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t')))
    {
        return Err(RollbackError::ReloadFailed);
    }
    let mut table = "";
    let mut declarations = HashSet::new();
    let mut jumps = HashSet::new();
    for line in save.lines() {
        if let Some(value) = line.strip_prefix('*') {
            table = value;
            continue;
        }
        if line == "COMMIT" {
            table = "";
            continue;
        }
        for &(expected_table, builtin, managed, marker) in BINDINGS {
            let key = (expected_table, managed);
            if table == expected_table
                && line
                    .strip_prefix(':')
                    .and_then(|value| value.split_whitespace().next())
                    == Some(managed)
                && !declarations.insert(key)
            {
                return Err(RollbackError::ReloadFailed);
            }
            let tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
            let targets_managed = tokens
                .windows(2)
                .any(|pair| pair[0] == "-j" && pair[1] == managed);
            if table == expected_table && targets_managed {
                let exact = tokens.len() == 8
                    && tokens[0] == "-A"
                    && tokens[1] == builtin
                    && tokens[2] == "-m"
                    && tokens[3] == "comment"
                    && tokens[4] == "--comment"
                    && tokens[5].trim_matches('"') == marker
                    && tokens[6] == "-j"
                    && tokens[7] == managed;
                if !exact || !jumps.insert(key) {
                    return Err(RollbackError::ReloadFailed);
                }
            }
        }
    }
    if declarations.is_empty() && jumps.is_empty() {
        Ok(RuntimeIptablesState::Absent)
    } else if declarations.len() == BINDINGS.len() && jumps.len() == BINDINGS.len() {
        Ok(RuntimeIptablesState::Owned)
    } else {
        Err(RollbackError::ReloadFailed)
    }
}

fn managed_nftables_table_exists(nft: &Path) -> Result<bool, RollbackError> {
    let output = Command::new(nft)
        .args(["list", "tables"])
        .env_clear()
        .output()
        .map_err(RollbackError::Io)?;
    if !output.status.success()
        || u64::try_from(output.stdout.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES
    {
        return Err(RollbackError::ReloadFailed);
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| RollbackError::ReloadFailed)?;
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "table" {
            return Err(RollbackError::ReloadFailed);
        }
        if fields[1] == "inet" && fields[2] == "mbed_agent" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resolve_fixed_program(name: &str) -> Result<PathBuf, RollbackError> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let candidate = Path::new(directory).join(name);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 => {
                return Ok(candidate);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RollbackError::Io(error)),
        }
    }
    Err(RollbackError::ReloadFailed)
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
        RollbackReload::OpenWrtNetwork => {
            targets == &HashSet::from([RollbackTarget::OpenWrtNetwork])
                || targets
                    == &HashSet::from([RollbackTarget::OpenWrtNetwork, RollbackTarget::OpenWrtDhcp])
        }
        RollbackReload::LinuxNftables => {
            targets == &HashSet::from([RollbackTarget::LinuxNftablesManaged])
        }
        RollbackReload::LinuxNftablesRuntime => {
            targets
                == &HashSet::from([
                    RollbackTarget::LinuxNftablesRuntime,
                    RollbackTarget::LinuxFirewallCanonical,
                ])
        }
        RollbackReload::LinuxIptablesRuntime => {
            targets
                == &HashSet::from([
                    RollbackTarget::LinuxIptablesIpv4FromOwned,
                    RollbackTarget::LinuxIptablesIpv4FromAbsent,
                    RollbackTarget::LinuxIptablesIpv6FromOwned,
                    RollbackTarget::LinuxIptablesIpv6FromAbsent,
                    RollbackTarget::LinuxFirewallCanonical,
                ])
        }
        RollbackReload::LinuxNetworkRoutesRuntime => {
            targets
                == &HashSet::from([
                    RollbackTarget::LinuxNetworkRouteBatch,
                    RollbackTarget::LinuxNetworkCanonical,
                ])
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
    use std::cell::Cell;

    use super::*;

    const OWNED_IPTABLES_SAVE: &str = "*filter\n:MBED_INPUT - [0:0]\n-A INPUT -m comment --comment mbed-agent-owned:v1:input -j MBED_INPUT\n:MBED_OUTPUT - [0:0]\n-A OUTPUT -m comment --comment mbed-agent-owned:v1:output -j MBED_OUTPUT\n:MBED_FORWARD - [0:0]\n-A FORWARD -m comment --comment mbed-agent-owned:v1:forward -j MBED_FORWARD\nCOMMIT\n*mangle\n:MBED_MANGLE_FORWARD - [0:0]\n-A FORWARD -m comment --comment mbed-agent-owned:v1:mangle-forward -j MBED_MANGLE_FORWARD\nCOMMIT\n*nat\n:MBED_PREROUTING - [0:0]\n-A PREROUTING -m comment --comment mbed-agent-owned:v1:prerouting -j MBED_PREROUTING\n:MBED_POSTROUTING - [0:0]\n-A POSTROUTING -m comment --comment mbed-agent-owned:v1:postrouting -j MBED_POSTROUTING\nCOMMIT\n";

    #[test]
    fn iptables_runtime_bundle_carries_conditional_families_and_canonical_state() {
        let root = test_root("iptables-runtime");
        let rollback = root.join("rollback");
        let cleanup = b"*filter\n-D INPUT -j MBED_INPUT\nCOMMIT\n";
        let restore = b"*filter\n:MBED_INPUT - [0:0]\nCOMMIT\n";
        let bundle = create_iptables_runtime_rollback_bundle(
            &rollback,
            "txn-iptables-runtime",
            IptablesRuntimeRollback {
                restore_from_owned: Some(cleanup),
                restore_from_absent: None,
            },
            IptablesRuntimeRollback {
                restore_from_owned: Some(restore),
                restore_from_absent: Some(restore),
            },
            Some(b"canonical-before"),
            5,
            1024,
        )
        .expect("bundle");
        let manifest = load_manifest(&bundle.directory, "txn-iptables-runtime").expect("manifest");
        assert_eq!(manifest.reload, RollbackReload::LinuxIptablesRuntime);
        assert_eq!(manifest.entries.len(), 5);
        assert!(
            !manifest
                .entries
                .iter()
                .find(|entry| entry.target == RollbackTarget::LinuxIptablesIpv4FromAbsent)
                .expect("ipv4 absent selector")
                .existed
        );
        assert_eq!(
            runtime_rollback_canonical_state(&rollback, "txn-iptables-runtime", 1024)
                .expect("canonical"),
            RuntimeCanonicalSnapshot::Present(b"canonical-before".to_vec())
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rollback_helper_strictly_classifies_iptables_ownership() {
        assert!(matches!(
            inspect_runtime_iptables_state(""),
            Ok(RuntimeIptablesState::Absent)
        ));
        assert!(matches!(
            inspect_runtime_iptables_state(OWNED_IPTABLES_SAVE),
            Ok(RuntimeIptablesState::Owned)
        ));
        let conditional =
            OWNED_IPTABLES_SAVE.replace("-A INPUT -m comment", "-A INPUT -p tcp -m comment");
        assert!(matches!(
            inspect_runtime_iptables_state(&conditional),
            Err(RollbackError::ReloadFailed)
        ));
    }

    #[test]
    fn runtime_nftables_bundle_is_volatile_digest_bound_and_first_use_aware() {
        let root = test_root("nft-runtime");
        let rollback = root.join("rollback");
        let ruleset = b"delete table inet mbed_agent\n";
        let bundle = create_nftables_runtime_rollback_bundle(
            &rollback,
            "txn-nft-runtime",
            ruleset,
            false,
            Some(b"canonical-before"),
            5,
            1024,
        )
        .expect("runtime bundle");
        assert_eq!(
            fs::read(bundle.directory.join("snapshot-0.bin")).expect("snapshot"),
            ruleset
        );
        assert_eq!(
            nftables_runtime_rollback_canonical_state(&rollback, "txn-nft-runtime", 1024)
                .expect("canonical snapshot"),
            RuntimeCanonicalSnapshot::Present(b"canonical-before".to_vec())
        );
        request_rollback(&rollback, "txn-nft-runtime").expect("request");
        let called = Cell::new(false);
        run_helper_with(
            &rollback,
            "txn-nft-runtime",
            1024,
            |_| panic!("runtime rollback must not resolve a persistent target"),
            |reload, directory, manifest| {
                assert_eq!(reload, RollbackReload::LinuxNftablesRuntime);
                assert!(
                    !manifest
                        .entries
                        .iter()
                        .find(|entry| entry.target == RollbackTarget::LinuxNftablesRuntime)
                        .expect("nft entry")
                        .existed
                );
                assert_eq!(
                    fs::read(directory.join("snapshot-0.bin")).expect("snapshot"),
                    ruleset
                );
                called.set(true);
                Ok(())
            },
        )
        .expect("helper");
        assert!(called.get());
        assert_eq!(
            rollback_outcome(&rollback, "txn-nft-runtime").expect("outcome"),
            RollbackOutcome::RolledBack
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn runtime_route_bundle_binds_reverse_batch_and_network_canonical() {
        let root = test_root("network-routes-runtime");
        let rollback = root.join("rollback");
        let batch = b"-4 route del default via 192.0.2.1 table 100 proto 186\n";
        let bundle = create_network_routes_runtime_rollback_bundle(
            &rollback,
            "txn-network-routes",
            batch,
            Some(b"network-canonical-before"),
            5,
            1024,
        )
        .expect("bundle");
        assert_eq!(
            runtime_rollback_canonical_state(&rollback, "txn-network-routes", 1024)
                .expect("canonical"),
            RuntimeCanonicalSnapshot::NetworkPresent(b"network-canonical-before".to_vec())
        );
        request_rollback(&rollback, "txn-network-routes").expect("request");
        let called = Cell::new(false);
        run_helper_with(
            &rollback,
            "txn-network-routes",
            1024,
            |_| panic!("runtime route rollback must not resolve persistent targets"),
            |reload, directory, manifest| {
                assert_eq!(reload, RollbackReload::LinuxNetworkRoutesRuntime);
                let entry = manifest
                    .entries
                    .iter()
                    .find(|entry| entry.target == RollbackTarget::LinuxNetworkRouteBatch)
                    .expect("batch entry");
                assert_eq!(
                    fs::read(directory.join(&entry.snapshot_name)).expect("batch"),
                    batch
                );
                called.set(true);
                Ok(())
            },
        )
        .expect("helper");
        assert!(called.get());
        assert_eq!(
            rollback_outcome(&rollback, "txn-network-routes").expect("outcome"),
            RollbackOutcome::RolledBack
        );
        assert!(bundle.directory.join("rolled-back").is_file());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn runtime_route_bundle_rejects_tampered_reverse_batch() {
        let root = test_root("network-routes-tamper");
        let rollback = root.join("rollback");
        let bundle = create_network_routes_runtime_rollback_bundle(
            &rollback,
            "txn-network-tamper",
            b"-4 route del blackhole 192.0.2.0/24 table 100 proto 186\n",
            None,
            5,
            1024,
        )
        .expect("bundle");
        fs::write(bundle.directory.join("snapshot-0.bin"), b"tampered\n").expect("tamper");
        request_rollback(&rollback, "txn-network-tamper").expect("request");
        assert!(matches!(
            run_helper_with(
                &rollback,
                "txn-network-tamper",
                1024,
                |_| PathBuf::new(),
                |_, _, _| panic!("reload must not run after digest failure")
            ),
            Err(RollbackError::SnapshotDigestMismatch)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

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
            |_, _, _| panic!("confirmed transaction must not reload"),
        )
        .expect("watchdog");
        assert_eq!(fs::read(&target).expect("target"), b"after");
        assert!(!root.join("rollback/txn-confirm").exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn openwrt_network_bundle_restores_config_before_reload() {
        let root = test_root("openwrt-network");
        let rollback = root.join("rollback");
        let target = root.join("network");
        fs::write(&target, b"config-before").expect("target");
        let bundle = create_bundle_with(
            &rollback,
            "txn-openwrt-network",
            &[RollbackTarget::OpenWrtNetwork],
            RollbackReload::OpenWrtNetwork,
            5,
            1024,
            |_| target.clone(),
        )
        .expect("bundle");
        fs::write(&target, b"config-after").expect("activation");
        request_rollback(&rollback, "txn-openwrt-network").expect("request rollback");
        let reload_called = Cell::new(false);
        run_helper_with(
            &rollback,
            "txn-openwrt-network",
            1024,
            |_| target.clone(),
            |reload, _, _| {
                assert_eq!(reload, RollbackReload::OpenWrtNetwork);
                assert_eq!(fs::read(&target).expect("restored first"), b"config-before");
                reload_called.set(true);
                Ok(())
            },
        )
        .expect("helper");
        assert!(reload_called.get());
        assert_eq!(fs::read(&target).expect("restored"), b"config-before");
        assert_eq!(
            rollback_outcome(&rollback, "txn-openwrt-network").expect("outcome"),
            RollbackOutcome::RolledBack
        );
        assert!(bundle.directory.join("rolled-back").is_file());
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
                |_, _, _| Err(RollbackError::ReloadFailed),
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
                |_, _, _| Ok(()),
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
