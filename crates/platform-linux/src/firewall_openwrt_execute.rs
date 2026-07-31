//! Concrete `OpenWrt` firewall staging, validation, activation, and verification.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agent_core::{FirewallExecutionPlan, FirewallInventory, project_firewall_inventory};
use ring::digest::{SHA256, digest};
use thiserror::Error;

use crate::FirewallBackend;
use crate::firewall::{
    OpenWrtFirewallStage, OpenWrtValidation, render_openwrt_firewall_stage_from_snapshot,
};
use crate::firewall_command::{
    FirewallCommand, FirewallCommandError, FirewallCommandExecutor, FirewallCommandRunner,
};
use crate::firewall_inventory::{
    OpenWrtFirewallInventorySnapshot, inspect_openwrt_firewall_inventory,
};

const MAX_FIREWALL_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    New,
    Inspected,
    Staged,
    Validated,
    Activated,
    Verified,
}

/// One bounded `OpenWrt` firewall native transaction.
pub struct OpenWrtFirewallTransaction<R = FirewallCommandRunner> {
    runner: R,
    runtime_root: PathBuf,
    config_path: PathBuf,
    transaction_id: String,
    backend: FirewallBackend,
    execution: FirewallExecutionPlan,
    require_root_owner: bool,
    state: TransactionState,
    source_digest: Option<String>,
    source_uci: Option<Vec<u8>>,
    source_bytes: Option<Vec<u8>>,
    snapshot: Option<OpenWrtFirewallInventorySnapshot>,
    expected: Option<FirewallInventory>,
    stage: Option<OpenWrtFirewallStage>,
    staging_dir: Option<PathBuf>,
}

impl OpenWrtFirewallTransaction<FirewallCommandRunner> {
    /// Creates a system transaction using fixed `OpenWrt` and `/tmp` paths.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid transaction identifier or non-OpenWrt backend.
    pub fn system(
        runner: FirewallCommandRunner,
        runtime_root: PathBuf,
        transaction_id: &str,
        backend: FirewallBackend,
        execution: FirewallExecutionPlan,
    ) -> Result<Self, OpenWrtExecutionError> {
        Self::new(
            runner,
            runtime_root,
            PathBuf::from("/etc/config/firewall"),
            transaction_id,
            backend,
            execution,
            true,
        )
    }
}

impl<R: FirewallCommandExecutor> OpenWrtFirewallTransaction<R> {
    fn new(
        runner: R,
        runtime_root: PathBuf,
        config_path: PathBuf,
        transaction_id: &str,
        backend: FirewallBackend,
        execution: FirewallExecutionPlan,
        require_root_owner: bool,
    ) -> Result<Self, OpenWrtExecutionError> {
        if transaction_id.is_empty()
            || transaction_id.len() > 64
            || !transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !matches!(backend, FirewallBackend::Fw3 | FirewallBackend::Fw4)
        {
            return Err(OpenWrtExecutionError::InvalidTransaction);
        }
        execution
            .validate()
            .map_err(|_| OpenWrtExecutionError::InvalidPlan)?;
        if require_root_owner
            && (!runtime_root.is_absolute()
                || runtime_root == Path::new("/tmp")
                || !runtime_root.starts_with("/tmp")
                || runtime_root.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                }))
        {
            return Err(OpenWrtExecutionError::UnsafeRuntime);
        }
        Ok(Self {
            runner,
            runtime_root,
            config_path,
            transaction_id: transaction_id.into(),
            backend,
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

    /// Reinspects the live UCI package and binds the typed plan to it.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, unsafe source configuration, command failure,
    /// malformed inventory, stale typed before-state, or unsupported rendering.
    pub fn reinspect(&mut self) -> Result<(), OpenWrtExecutionError> {
        self.require_state(TransactionState::New)?;
        ensure_runtime_root(&self.runtime_root, self.require_root_owner)?;
        let source_bytes = read_safe_config(&self.config_path, self.require_root_owner)?;
        let source_digest = hex_digest(&source_bytes);
        let source_uci = self
            .runner
            .execute(&FirewallCommand::UciShowFirewall, None)?
            .stdout;
        let uci = std::str::from_utf8(&source_uci)
            .map_err(|_| OpenWrtExecutionError::MalformedInspection)?;
        let snapshot = inspect_openwrt_firewall_inventory(uci)?;
        let expected = project_firewall_inventory(snapshot.inventory(), &self.execution.typed)
            .map_err(|_| OpenWrtExecutionError::StalePlan)?;
        let stage = render_openwrt_firewall_stage_from_snapshot(
            &self.execution.typed,
            &snapshot,
            self.backend,
        )?;
        self.source_bytes = Some(source_bytes);
        self.source_digest = Some(source_digest);
        self.source_uci = Some(source_uci);
        self.snapshot = Some(snapshot);
        self.expected = Some(expected);
        self.stage = Some(stage);
        self.state = TransactionState::Inspected;
        Ok(())
    }

    /// Copies the live file into `/tmp`, applies the fixed UCI batch, and checks staged semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, unsafe staging paths/files, UCI failure, or staged
    /// typed state that differs from the approved projection.
    pub fn stage(&mut self) -> Result<(), OpenWrtExecutionError> {
        self.require_state(TransactionState::Inspected)?;
        let staging_root = self.runtime_root.join("staging");
        create_private_dir_all(&staging_root)?;
        let staging_dir = staging_root.join(&self.transaction_id);
        fs::create_dir(&staging_dir).map_err(OpenWrtExecutionError::Io)?;
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700))
            .map_err(OpenWrtExecutionError::Io)?;
        self.staging_dir = Some(staging_dir.clone());
        let source = self
            .source_bytes
            .as_deref()
            .ok_or(OpenWrtExecutionError::InvalidState)?;
        write_new_synced(&staging_dir.join("firewall"), source, 0o600)?;
        sync_directory(&staging_dir)?;
        let batch = self
            .stage
            .as_ref()
            .ok_or(OpenWrtExecutionError::InvalidState)?
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
                &FirewallCommand::UciShowFirewallAt {
                    staging_dir: staging_dir.clone(),
                },
                None,
            )?
            .stdout;
        let staged = inspect_openwrt_firewall_inventory(
            std::str::from_utf8(&staged_uci)
                .map_err(|_| OpenWrtExecutionError::MalformedInspection)?,
        )?;
        if !inventory_equal(
            staged.inventory(),
            self.expected
                .as_ref()
                .ok_or(OpenWrtExecutionError::InvalidState)?,
        ) {
            return Err(OpenWrtExecutionError::StagedStateMismatch);
        }
        self.state = TransactionState::Staged;
        Ok(())
    }

    /// Runs every backend-native validation against the staged UCI package.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering or any failed fw3/fw4 check.
    pub fn validate_stage(&mut self) -> Result<(), OpenWrtExecutionError> {
        self.require_state(TransactionState::Staged)?;
        let dir = self
            .staging_dir
            .clone()
            .ok_or(OpenWrtExecutionError::InvalidState)?;
        let validations = self
            .stage
            .as_ref()
            .ok_or(OpenWrtExecutionError::InvalidState)?
            .validations
            .clone();
        for validation in validations {
            let command = match validation {
                OpenWrtValidation::Fw3PrintIpv4 => FirewallCommand::Fw3PrintIpv4 {
                    staging_dir: dir.clone(),
                },
                OpenWrtValidation::Fw3PrintIpv6 => FirewallCommand::Fw3PrintIpv6 {
                    staging_dir: dir.clone(),
                },
                OpenWrtValidation::Fw4Check => FirewallCommand::Fw4Check {
                    staging_dir: dir.clone(),
                },
            };
            self.runner.execute(&command, None)?;
        }
        self.state = TransactionState::Validated;
        Ok(())
    }

    /// Atomically installs the validated file and reloads the `OpenWrt` firewall.
    ///
    /// The caller must invoke this only after the independent rollback helper is armed.
    /// Immediately before installation, both raw UCI output and source-file digest are checked
    /// again to reject concurrent configuration drift.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, drift, unsafe files, atomic installation failure, or
    /// reload failure.
    pub fn activate_after_rollback_armed(&mut self) -> Result<(), OpenWrtExecutionError> {
        self.require_state(TransactionState::Validated)?;
        let fresh_uci = self
            .runner
            .execute(&FirewallCommand::UciShowFirewall, None)?
            .stdout;
        if self.source_uci.as_deref() != Some(fresh_uci.as_slice()) {
            return Err(OpenWrtExecutionError::SourceDrift);
        }
        let fresh_source = read_safe_config(&self.config_path, self.require_root_owner)?;
        if self.source_digest.as_deref() != Some(hex_digest(&fresh_source).as_str()) {
            return Err(OpenWrtExecutionError::SourceDrift);
        }
        let staged_path = self
            .staging_dir
            .as_ref()
            .ok_or(OpenWrtExecutionError::InvalidState)?
            .join("firewall");
        atomic_install(
            &staged_path,
            &self.config_path,
            &self.transaction_id,
            self.require_root_owner,
        )?;
        self.runner
            .execute(&FirewallCommand::OpenWrtFirewallReload, None)?;
        self.state = TransactionState::Activated;
        Ok(())
    }

    /// Reconstructs live typed state and compares it with the approved projection.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, inspection failure, or post-apply mismatch.
    pub fn verify(&mut self) -> Result<(), OpenWrtExecutionError> {
        self.require_state(TransactionState::Activated)?;
        let actual = self
            .runner
            .execute(&FirewallCommand::UciShowFirewall, None)?
            .stdout;
        let snapshot = inspect_openwrt_firewall_inventory(
            std::str::from_utf8(&actual).map_err(|_| OpenWrtExecutionError::MalformedInspection)?,
        )?;
        if !inventory_equal(
            snapshot.inventory(),
            self.expected
                .as_ref()
                .ok_or(OpenWrtExecutionError::InvalidState)?,
        ) {
            return Err(OpenWrtExecutionError::VerificationFailed);
        }
        self.state = TransactionState::Verified;
        Ok(())
    }

    pub fn discard_stage(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
    }

    fn require_state(&self, expected: TransactionState) -> Result<(), OpenWrtExecutionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(OpenWrtExecutionError::InvalidState)
        }
    }
}

impl<R> Drop for OpenWrtFirewallTransaction<R> {
    fn drop(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn read_safe_config(path: &Path, require_root: bool) -> Result<Vec<u8>, OpenWrtExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(OpenWrtExecutionError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_FIREWALL_CONFIG_BYTES
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtExecutionError::UnsafeConfig);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| {
            file.take(MAX_FIREWALL_CONFIG_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(OpenWrtExecutionError::Io)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(OpenWrtExecutionError::SourceDrift);
    }
    Ok(bytes)
}

fn atomic_install(
    staged: &Path,
    destination: &Path,
    transaction_id: &str,
    require_root: bool,
) -> Result<(), OpenWrtExecutionError> {
    let bytes = read_safe_config(staged, false)?;
    let destination_metadata =
        fs::symlink_metadata(destination).map_err(OpenWrtExecutionError::Io)?;
    if !destination_metadata.is_file()
        || destination_metadata.file_type().is_symlink()
        || (require_root && (destination_metadata.uid() != 0 || destination_metadata.gid() != 0))
    {
        return Err(OpenWrtExecutionError::UnsafeConfig);
    }
    let parent = destination
        .parent()
        .ok_or(OpenWrtExecutionError::UnsafeConfig)?;
    let temporary = parent.join(format!(".mbed-agent-{transaction_id}.tmp"));
    let result = (|| {
        write_new_synced(
            &temporary,
            &bytes,
            destination_metadata.permissions().mode() & 0o777,
        )?;
        fs::rename(&temporary, destination).map_err(OpenWrtExecutionError::Io)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn ensure_runtime_root(root: &Path, require_root: bool) -> Result<(), OpenWrtExecutionError> {
    create_private_dir_all(root)?;
    let metadata = fs::symlink_metadata(root).map_err(OpenWrtExecutionError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtExecutionError::UnsafeRuntime);
    }
    Ok(())
}

fn create_private_dir_all(path: &Path) -> Result<(), OpenWrtExecutionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(OpenWrtExecutionError::UnsafeRuntime),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(OpenWrtExecutionError::UnsafeRuntime)?;
            let parent_metadata =
                fs::symlink_metadata(parent).map_err(OpenWrtExecutionError::Io)?;
            if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(OpenWrtExecutionError::UnsafeRuntime);
            }
            fs::create_dir(path).map_err(OpenWrtExecutionError::Io)?;
        }
        Err(error) => return Err(OpenWrtExecutionError::Io(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(OpenWrtExecutionError::Io)
}

fn write_new_synced(path: &Path, bytes: &[u8], mode: u32) -> Result<(), OpenWrtExecutionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(OpenWrtExecutionError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(OpenWrtExecutionError::Io)?;
    file.write_all(bytes).map_err(OpenWrtExecutionError::Io)?;
    file.sync_all().map_err(OpenWrtExecutionError::Io)
}

fn sync_directory(path: &Path) -> Result<(), OpenWrtExecutionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(OpenWrtExecutionError::Io)
}

fn inventory_equal(left: &FirewallInventory, right: &FirewallInventory) -> bool {
    let mut left = left.objects.clone();
    let mut right = right.objects.clone();
    let order = |a: &agent_protocol::FirewallObject, b: &agent_protocol::FirewallObject| {
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
pub enum OpenWrtExecutionError {
    #[error("invalid OpenWrt firewall transaction")]
    InvalidTransaction,
    #[error("invalid executable firewall plan")]
    InvalidPlan,
    #[error("OpenWrt firewall transaction operation is out of order")]
    InvalidState,
    #[error("OpenWrt firewall runtime directory is unsafe")]
    UnsafeRuntime,
    #[error("OpenWrt firewall configuration file is unsafe")]
    UnsafeConfig,
    #[error("OpenWrt firewall inspection is malformed")]
    MalformedInspection,
    #[error("typed firewall plan is stale")]
    StalePlan,
    #[error("staged OpenWrt firewall differs from approved typed state")]
    StagedStateMismatch,
    #[error("live OpenWrt firewall changed before activation")]
    SourceDrift,
    #[error("applied OpenWrt firewall verification failed")]
    VerificationFailed,
    #[error("OpenWrt firewall command failed: {0}")]
    Command(#[from] FirewallCommandError),
    #[error("OpenWrt firewall rendering failed: {0}")]
    Render(#[from] crate::firewall::FirewallRenderError),
    #[error("OpenWrt firewall I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use agent_core::{
        FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION, FirewallMutation, FirewallRiskContext,
        plan_firewall_mutations,
    };
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, ChangePlan, FirewallObject, FirewallVerdict, FirewallZone,
        ObjectOwnership,
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
    fn stages_validates_activates_and_verifies_typed_state() {
        let root = fixture_root();
        let config = root.join("etc/config/firewall");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-config\n").expect("config");
        let initial = initial_uci();
        let desired = desired_uci();
        let runner = FakeRunner::new([
            initial.as_bytes().to_vec(),
            Vec::new(),
            desired.as_bytes().to_vec(),
            Vec::new(),
            initial.as_bytes().to_vec(),
            Vec::new(),
            desired.as_bytes().to_vec(),
        ]);
        let mut transaction = OpenWrtFirewallTransaction::new(
            runner,
            root.join("runtime"),
            config.clone(),
            "change-1",
            FirewallBackend::Fw4,
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
            .expect("staging dir")
            .join("firewall");
        fs::write(&staged, b"desired-config\n").expect("rendered config fixture");
        transaction
            .activate_after_rollback_armed()
            .expect("activate");
        transaction.verify().expect("verify");
        assert_eq!(fs::read(&config).expect("installed"), b"desired-config\n");
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn source_drift_blocks_install_after_native_validation() {
        let root = fixture_root();
        let config = root.join("etc/config/firewall");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-config\n").expect("config");
        let runner = FakeRunner::new([
            initial_uci().into_bytes(),
            Vec::new(),
            desired_uci().into_bytes(),
            Vec::new(),
            b"firewall.changed=rule\n".to_vec(),
        ]);
        let mut transaction = OpenWrtFirewallTransaction::new(
            runner,
            root.join("runtime"),
            config.clone(),
            "change-2",
            FirewallBackend::Fw4,
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("inspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate");
        assert!(matches!(
            transaction.activate_after_rollback_armed(),
            Err(OpenWrtExecutionError::SourceDrift)
        ));
        assert_eq!(fs::read(&config).expect("unchanged"), b"original-config\n");
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn execution_plan() -> FirewallExecutionPlan {
        let typed = plan_firewall_mutations(
            &FirewallInventory {
                objects: Vec::new(),
            },
            &[FirewallMutation::Create(FirewallObject::Zone(
                FirewallZone {
                    id: "guest".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    networks: vec!["br-guest".into()],
                    input: FirewallVerdict::Drop,
                    output: FirewallVerdict::Accept,
                    forward: FirewallVerdict::Drop,
                    masquerade: false,
                    mtu_fix: false,
                },
            ))],
            &FirewallRiskContext::default(),
        )
        .expect("typed plan");
        FirewallExecutionPlan {
            schema_version: FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION,
            preview: ChangePlan {
                schema_version: CHANGE_PLAN_SCHEMA_VERSION,
                plan_id: "change-1".into(),
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
                validation_checks: vec!["fw4 native check".into()],
                verification_checks: vec!["typed inventory matches".into()],
                rollback_required: true,
            },
            typed,
        }
    }

    fn initial_uci() -> String {
        [
            "firewall.@defaults[0]=defaults",
            "firewall.@defaults[0].input='ACCEPT'",
            "firewall.@defaults[0].output='ACCEPT'",
            "firewall.@defaults[0].forward='REJECT'",
            "",
        ]
        .join("\n")
    }

    fn desired_uci() -> String {
        format!(
            "{}firewall.mbed_z_0123456789abcdef=zone\n\
             firewall.mbed_z_0123456789abcdef.name='guest'\n\
             firewall.mbed_z_0123456789abcdef.network='br-guest'\n\
             firewall.mbed_z_0123456789abcdef.input='DROP'\n\
             firewall.mbed_z_0123456789abcdef.output='ACCEPT'\n\
             firewall.mbed_z_0123456789abcdef.forward='DROP'\n",
            initial_uci()
        )
    }

    fn fixture_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("mbed-openwrt-execution-{nonce}"))
    }
}
