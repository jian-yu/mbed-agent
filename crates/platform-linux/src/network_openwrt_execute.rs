//! Concrete `OpenWrt` network staging, validation, activation, and verification.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agent_core::{
    NetworkExecutionPlan, NetworkInventory, project_network_inventory, verify_network_plan_result,
};
use ring::digest::{SHA256, digest};
use thiserror::Error;

use crate::firewall_command::{
    FirewallCommand, FirewallCommandError, FirewallCommandExecutor, FirewallCommandRunner,
};
use crate::network_openwrt::{
    NetworkRenderError, OpenWrtNetworkInventorySnapshot, OpenWrtNetworkStage,
    OpenWrtNetworkValidation, inspect_openwrt_network_inventory,
    render_openwrt_network_stage_from_snapshot,
};

const MAX_NETWORK_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    New,
    Inspected,
    Staged,
    Validated,
    Activated,
    Verified,
}

/// One bounded `OpenWrt` network native transaction.
pub struct OpenWrtNetworkTransaction<R = FirewallCommandRunner> {
    runner: R,
    runtime_root: PathBuf,
    config_path: PathBuf,
    transaction_id: String,
    execution: NetworkExecutionPlan,
    require_root_owner: bool,
    state: TransactionState,
    source_digest: Option<String>,
    source_uci: Option<Vec<u8>>,
    source_bytes: Option<Vec<u8>>,
    snapshot: Option<OpenWrtNetworkInventorySnapshot>,
    expected: Option<NetworkInventory>,
    stage: Option<OpenWrtNetworkStage>,
    staging_dir: Option<PathBuf>,
}

impl OpenWrtNetworkTransaction<FirewallCommandRunner> {
    /// Creates a system transaction using fixed `OpenWrt` and `/tmp` paths.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid transaction identifier, executable plan, or runtime path.
    pub fn system(
        runner: FirewallCommandRunner,
        runtime_root: PathBuf,
        transaction_id: &str,
        execution: NetworkExecutionPlan,
    ) -> Result<Self, OpenWrtNetworkExecutionError> {
        Self::new(
            runner,
            runtime_root,
            PathBuf::from("/etc/config/network"),
            transaction_id,
            execution,
            true,
        )
    }
}

impl<R: FirewallCommandExecutor> OpenWrtNetworkTransaction<R> {
    fn new(
        runner: R,
        runtime_root: PathBuf,
        config_path: PathBuf,
        transaction_id: &str,
        execution: NetworkExecutionPlan,
        require_root_owner: bool,
    ) -> Result<Self, OpenWrtNetworkExecutionError> {
        if transaction_id.is_empty()
            || transaction_id.len() > 64
            || !transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(OpenWrtNetworkExecutionError::InvalidTransaction);
        }
        execution
            .validate()
            .map_err(|_| OpenWrtNetworkExecutionError::InvalidPlan)?;
        if require_root_owner && !safe_system_runtime_root(&runtime_root) {
            return Err(OpenWrtNetworkExecutionError::UnsafeRuntime);
        }
        Ok(Self {
            runner,
            runtime_root,
            config_path,
            transaction_id: transaction_id.into(),
            execution,
            require_root_owner,
            state: TransactionState::New,
            source_digest: None,
            source_uci: None,
            source_bytes: None,
            snapshot: None,
            expected: None,
            stage: None,
            staging_dir: None,
        })
    }

    /// Reinspects the live UCI package and binds the approved plan to that exact state.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, unsafe source files, malformed inspection, stale
    /// typed state, an unsupported field, or command failure.
    pub fn reinspect(&mut self) -> Result<(), OpenWrtNetworkExecutionError> {
        self.require_state(TransactionState::New)?;
        ensure_runtime_root(&self.runtime_root, self.require_root_owner)?;
        let source_bytes = read_safe_config(&self.config_path, self.require_root_owner)?;
        let source_digest = hex_digest(&source_bytes);
        let source_uci = self
            .runner
            .execute(&FirewallCommand::UciShowNetwork, None)?
            .stdout;
        let snapshot = inspect_openwrt_network_inventory(
            std::str::from_utf8(&source_uci)
                .map_err(|_| OpenWrtNetworkExecutionError::MalformedInspection)?,
        )?;
        let expected = project_network_inventory(snapshot.inventory(), &self.execution.typed)
            .map_err(|_| OpenWrtNetworkExecutionError::StalePlan)?;
        let stage = render_openwrt_network_stage_from_snapshot(&self.execution.typed, &snapshot)?;
        self.source_bytes = Some(source_bytes);
        self.source_digest = Some(source_digest);
        self.source_uci = Some(source_uci);
        self.snapshot = Some(snapshot);
        self.expected = Some(expected);
        self.stage = Some(stage);
        self.state = TransactionState::Inspected;
        Ok(())
    }

    /// Copies the live file into `/tmp`, applies the fixed batch, and checks staged typed state.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, unsafe staging paths, UCI failure, or a staged state
    /// that differs from the approved projection.
    pub fn stage(&mut self) -> Result<(), OpenWrtNetworkExecutionError> {
        self.require_state(TransactionState::Inspected)?;
        let staging_root = self.runtime_root.join("staging");
        create_private_dir_all(&staging_root)?;
        let staging_dir = staging_root.join(&self.transaction_id);
        fs::create_dir(&staging_dir).map_err(OpenWrtNetworkExecutionError::Io)?;
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700))
            .map_err(OpenWrtNetworkExecutionError::Io)?;
        self.staging_dir = Some(staging_dir.clone());
        let source = self
            .source_bytes
            .as_deref()
            .ok_or(OpenWrtNetworkExecutionError::InvalidState)?;
        write_new_synced(&staging_dir.join("network"), source, 0o600)?;
        sync_directory(&staging_dir)?;
        let batch = self
            .stage
            .as_ref()
            .ok_or(OpenWrtNetworkExecutionError::InvalidState)?
            .uci_batch
            .as_bytes();
        self.runner.execute(
            &FirewallCommand::UciBatch {
                staging_dir: staging_dir.clone(),
            },
            Some(batch),
        )?;
        let staged_uci = self
            .runner
            .execute(
                &FirewallCommand::UciShowNetworkAt {
                    staging_dir: staging_dir.clone(),
                },
                None,
            )?
            .stdout;
        let staged = inspect_openwrt_network_inventory(
            std::str::from_utf8(&staged_uci)
                .map_err(|_| OpenWrtNetworkExecutionError::MalformedInspection)?,
        )?;
        if !inventory_equal(
            staged.inventory(),
            self.expected
                .as_ref()
                .ok_or(OpenWrtNetworkExecutionError::InvalidState)?,
        ) {
            return Err(OpenWrtNetworkExecutionError::StagedStateMismatch);
        }
        self.state = TransactionState::Staged;
        Ok(())
    }

    /// Runs every fixed native validation against the private staged UCI package.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering or a failed UCI export check.
    pub fn validate_stage(&mut self) -> Result<(), OpenWrtNetworkExecutionError> {
        self.require_state(TransactionState::Staged)?;
        let directory = self
            .staging_dir
            .clone()
            .ok_or(OpenWrtNetworkExecutionError::InvalidState)?;
        let validations = self
            .stage
            .as_ref()
            .ok_or(OpenWrtNetworkExecutionError::InvalidState)?
            .validations
            .clone();
        for validation in validations {
            match validation {
                OpenWrtNetworkValidation::UciExport => {
                    self.runner.execute(
                        &FirewallCommand::UciExportNetworkAt {
                            staging_dir: directory.clone(),
                        },
                        None,
                    )?;
                }
            }
        }
        self.state = TransactionState::Validated;
        Ok(())
    }

    /// Installs the validated file and reloads netifd after an independent helper is armed.
    ///
    /// Both raw UCI output and the source-file digest are checked again immediately before the
    /// atomic rename. The caller must not invoke this method until rollback is durable and running.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, concurrent source drift, unsafe files, installation
    /// failure, or network reload failure.
    pub fn activate_after_rollback_armed(&mut self) -> Result<(), OpenWrtNetworkExecutionError> {
        self.require_state(TransactionState::Validated)?;
        let fresh_uci = self
            .runner
            .execute(&FirewallCommand::UciShowNetwork, None)?
            .stdout;
        if self.source_uci.as_deref() != Some(fresh_uci.as_slice()) {
            return Err(OpenWrtNetworkExecutionError::SourceDrift);
        }
        let fresh_source = read_safe_config(&self.config_path, self.require_root_owner)?;
        if self.source_digest.as_deref() != Some(hex_digest(&fresh_source).as_str()) {
            return Err(OpenWrtNetworkExecutionError::SourceDrift);
        }
        let staged_path = self
            .staging_dir
            .as_ref()
            .ok_or(OpenWrtNetworkExecutionError::InvalidState)?
            .join("network");
        atomic_install(
            &staged_path,
            &self.config_path,
            &self.transaction_id,
            self.require_root_owner,
        )?;
        self.runner
            .execute(&FirewallCommand::OpenWrtNetworkReload, None)?;
        self.state = TransactionState::Activated;
        Ok(())
    }

    /// Reconstructs live typed state and compares it with the approved projection.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, inspection failure, or post-apply mismatch.
    pub fn verify(&mut self) -> Result<(), OpenWrtNetworkExecutionError> {
        self.require_state(TransactionState::Activated)?;
        let actual = self
            .runner
            .execute(&FirewallCommand::UciShowNetwork, None)?
            .stdout;
        let snapshot = inspect_openwrt_network_inventory(
            std::str::from_utf8(&actual)
                .map_err(|_| OpenWrtNetworkExecutionError::MalformedInspection)?,
        )?;
        if !inventory_equal(
            snapshot.inventory(),
            self.expected
                .as_ref()
                .ok_or(OpenWrtNetworkExecutionError::InvalidState)?,
        ) {
            return Err(OpenWrtNetworkExecutionError::VerificationFailed);
        }
        self.state = TransactionState::Verified;
        Ok(())
    }

    pub fn discard_stage(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
    }

    fn require_state(
        &self,
        expected: TransactionState,
    ) -> Result<(), OpenWrtNetworkExecutionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(OpenWrtNetworkExecutionError::InvalidState)
        }
    }
}

/// Reinspects live state and verifies every object touched by an approved execution plan.
///
/// # Errors
///
/// Returns an error for command, decoding, inventory, or approved-result mismatch failures.
pub fn verify_openwrt_network_plan(
    runner: &impl FirewallCommandExecutor,
    execution: &NetworkExecutionPlan,
) -> Result<(), OpenWrtNetworkExecutionError> {
    execution
        .validate()
        .map_err(|_| OpenWrtNetworkExecutionError::InvalidPlan)?;
    let actual = runner
        .execute(&FirewallCommand::UciShowNetwork, None)?
        .stdout;
    let snapshot = inspect_openwrt_network_inventory(
        std::str::from_utf8(&actual)
            .map_err(|_| OpenWrtNetworkExecutionError::MalformedInspection)?,
    )?;
    verify_network_plan_result(snapshot.inventory(), &execution.typed)
        .map_err(|_| OpenWrtNetworkExecutionError::VerificationFailed)
}

impl<R> Drop for OpenWrtNetworkTransaction<R> {
    fn drop(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn read_safe_config(
    path: &Path,
    require_root: bool,
) -> Result<Vec<u8>, OpenWrtNetworkExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(OpenWrtNetworkExecutionError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_NETWORK_CONFIG_BYTES
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtNetworkExecutionError::UnsafeConfig);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| {
            file.take(MAX_NETWORK_CONFIG_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(OpenWrtNetworkExecutionError::Io)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(OpenWrtNetworkExecutionError::SourceDrift);
    }
    Ok(bytes)
}

fn atomic_install(
    staged: &Path,
    destination: &Path,
    transaction_id: &str,
    require_root: bool,
) -> Result<(), OpenWrtNetworkExecutionError> {
    let bytes = read_safe_config(staged, false)?;
    let metadata = fs::symlink_metadata(destination).map_err(OpenWrtNetworkExecutionError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtNetworkExecutionError::UnsafeConfig);
    }
    let parent = destination
        .parent()
        .ok_or(OpenWrtNetworkExecutionError::UnsafeConfig)?;
    let temporary = parent.join(format!(".mbed-agent-{transaction_id}.tmp"));
    let result = (|| {
        write_new_synced(&temporary, &bytes, metadata.permissions().mode() & 0o777)?;
        fs::rename(&temporary, destination).map_err(OpenWrtNetworkExecutionError::Io)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn safe_system_runtime_root(root: &Path) -> bool {
    root.is_absolute()
        && root != Path::new("/tmp")
        && root.starts_with("/tmp")
        && !root.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

fn ensure_runtime_root(
    root: &Path,
    require_root: bool,
) -> Result<(), OpenWrtNetworkExecutionError> {
    create_private_dir_all(root)?;
    let metadata = fs::symlink_metadata(root).map_err(OpenWrtNetworkExecutionError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtNetworkExecutionError::UnsafeRuntime);
    }
    Ok(())
}

fn create_private_dir_all(path: &Path) -> Result<(), OpenWrtNetworkExecutionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(OpenWrtNetworkExecutionError::UnsafeRuntime),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or(OpenWrtNetworkExecutionError::UnsafeRuntime)?;
            let parent_metadata =
                fs::symlink_metadata(parent).map_err(OpenWrtNetworkExecutionError::Io)?;
            if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(OpenWrtNetworkExecutionError::UnsafeRuntime);
            }
            fs::create_dir(path).map_err(OpenWrtNetworkExecutionError::Io)?;
        }
        Err(error) => return Err(OpenWrtNetworkExecutionError::Io(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(OpenWrtNetworkExecutionError::Io)
}

fn write_new_synced(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), OpenWrtNetworkExecutionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(OpenWrtNetworkExecutionError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(OpenWrtNetworkExecutionError::Io)?;
    file.write_all(bytes)
        .map_err(OpenWrtNetworkExecutionError::Io)?;
    file.sync_all().map_err(OpenWrtNetworkExecutionError::Io)
}

fn sync_directory(path: &Path) -> Result<(), OpenWrtNetworkExecutionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(OpenWrtNetworkExecutionError::Io)
}

fn inventory_equal(left: &NetworkInventory, right: &NetworkInventory) -> bool {
    let mut left = left.objects.clone();
    let mut right = right.objects.clone();
    let order = |a: &agent_protocol::NetworkObject, b: &agent_protocol::NetworkObject| {
        a.kind().cmp(b.kind()).then_with(|| a.id().cmp(b.id()))
    };
    left.sort_by(order);
    right.sort_by(order);
    left == right
}

fn hex_digest(value: &[u8]) -> String {
    let hash = digest(&SHA256, value);
    let mut output = String::with_capacity(64);
    for byte in hash.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Debug, Error)]
pub enum OpenWrtNetworkExecutionError {
    #[error("invalid OpenWrt network transaction")]
    InvalidTransaction,
    #[error("invalid executable network plan")]
    InvalidPlan,
    #[error("OpenWrt network transaction operation is out of order")]
    InvalidState,
    #[error("OpenWrt network runtime directory is unsafe")]
    UnsafeRuntime,
    #[error("OpenWrt network configuration file is unsafe")]
    UnsafeConfig,
    #[error("OpenWrt network inspection is malformed")]
    MalformedInspection,
    #[error("typed network plan is stale")]
    StalePlan,
    #[error("staged OpenWrt network differs from approved typed state")]
    StagedStateMismatch,
    #[error("live OpenWrt network changed before activation")]
    SourceDrift,
    #[error("applied OpenWrt network verification failed")]
    VerificationFailed,
    #[error("OpenWrt network command failed: {0}")]
    Command(#[from] FirewallCommandError),
    #[error("OpenWrt network rendering failed: {0}")]
    Render(#[from] NetworkRenderError),
    #[error("OpenWrt network I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use agent_core::{
        NETWORK_EXECUTION_PLAN_SCHEMA_VERSION, NetworkMutation, NetworkRiskContext,
        plan_network_mutations,
    };
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, ChangePlan, IpNetwork, NetworkAddressMode,
        NetworkInterfaceConfig, NetworkObject, ObjectOwnership,
    };

    use super::*;
    use crate::firewall_command::FirewallCommandOutput;

    struct FakeRunner {
        responses: Mutex<VecDeque<Vec<u8>>>,
        calls: Mutex<Vec<FirewallCommand>>,
    }

    impl FakeRunner {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl FirewallCommandExecutor for FakeRunner {
        fn execute(
            &self,
            operation: &FirewallCommand,
            _: Option<&[u8]>,
        ) -> Result<FirewallCommandOutput, FirewallCommandError> {
            self.calls.lock().expect("calls").push(operation.clone());
            let stdout = self
                .responses
                .lock()
                .expect("responses")
                .pop_front()
                .unwrap_or_default();
            Ok(FirewallCommandOutput {
                stdout,
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            })
        }
    }

    #[test]
    fn stages_validates_activates_and_verifies_typed_network_state() {
        let root = fixture_root("success");
        let config = root.join("etc/config/network");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-network\n").expect("config");
        let desired = desired_uci();
        let runner = FakeRunner::new([
            Vec::new(),
            Vec::new(),
            desired.as_bytes().to_vec(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            desired.as_bytes().to_vec(),
        ]);
        let mut transaction = OpenWrtNetworkTransaction::new(
            runner,
            root.join("runtime"),
            config.clone(),
            "network-change-1",
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("inspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate");
        let staged = transaction
            .staging_dir
            .as_ref()
            .expect("staging")
            .join("network");
        fs::write(&staged, b"desired-network\n").expect("rendered fixture");
        transaction
            .activate_after_rollback_armed()
            .expect("activate");
        transaction.verify().expect("verify");
        assert_eq!(fs::read(&config).expect("installed"), b"desired-network\n");
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn source_drift_blocks_network_install() {
        let root = fixture_root("drift");
        let config = root.join("etc/config/network");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-network\n").expect("config");
        let runner = FakeRunner::new([
            Vec::new(),
            Vec::new(),
            desired_uci().into_bytes(),
            Vec::new(),
            b"network.changed=interface\n".to_vec(),
        ]);
        let mut transaction = OpenWrtNetworkTransaction::new(
            runner,
            root.join("runtime"),
            config.clone(),
            "network-change-2",
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("inspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate");
        assert!(matches!(
            transaction.activate_after_rollback_armed(),
            Err(OpenWrtNetworkExecutionError::SourceDrift)
        ));
        assert_eq!(fs::read(&config).expect("unchanged"), b"original-network\n");
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn staged_typed_mismatch_fails_before_validation() {
        let root = fixture_root("mismatch");
        let config = root.join("etc/config/network");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-network\n").expect("config");
        let runner = FakeRunner::new([Vec::new(), Vec::new(), Vec::new()]);
        let mut transaction = OpenWrtNetworkTransaction::new(
            runner,
            root.join("runtime"),
            config,
            "network-change-3",
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("inspect");
        assert!(matches!(
            transaction.stage(),
            Err(OpenWrtNetworkExecutionError::StagedStateMismatch)
        ));
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn execution_plan() -> NetworkExecutionPlan {
        let typed = plan_network_mutations(
            &NetworkInventory { objects: vec![] },
            &[NetworkMutation::Create(NetworkObject::Interface(
                NetworkInterfaceConfig {
                    id: "guest".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    device: "br-guest".into(),
                    ipv4_mode: NetworkAddressMode::Static,
                    ipv6_mode: NetworkAddressMode::Disabled,
                    addresses: vec![IpNetwork {
                        address: Ipv4Addr::new(192, 0, 2, 1).into(),
                        prefix_len: 24,
                    }],
                    mtu: Some(1500),
                    mac_override: None,
                },
            ))],
            &NetworkRiskContext::default(),
        )
        .expect("typed plan");
        NetworkExecutionPlan {
            schema_version: NETWORK_EXECUTION_PLAN_SCHEMA_VERSION,
            preview: ChangePlan {
                schema_version: CHANGE_PLAN_SCHEMA_VERSION,
                plan_id: "network-change-1".into(),
                boot_id: "boot-1".into(),
                actor_id: "cli-local".into(),
                created_monotonic_ms: 1,
                expires_monotonic_ms: 100,
                risk: typed.risk,
                changes: typed
                    .changes
                    .iter()
                    .map(|value| value.diff.clone())
                    .collect(),
                validation_checks: vec!["UCI export succeeds".into()],
                verification_checks: vec!["typed network inventory matches".into()],
                rollback_required: true,
            },
            typed,
        }
    }

    fn desired_uci() -> String {
        [
            "network.guest=interface",
            "network.guest.mbed_managed='1'",
            "network.guest.mbed_id='guest'",
            "network.guest.proto='static'",
            "network.guest.device='br-guest'",
            "network.guest.disabled='0'",
            "network.guest.mtu='1500'",
            "network.guest.ipaddr='192.0.2.1/24'",
            "",
        ]
        .join("\n")
    }

    fn fixture_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("mbed-openwrt-network-{label}-{nonce}"))
    }
}
