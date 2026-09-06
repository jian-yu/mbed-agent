//! Concrete `OpenWrt` wireless radio staging, validation, activation, and verification.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agent_core::{
    WirelessExecutionPlan, WirelessInventory, project_wireless_inventory,
    verify_wireless_plan_result,
};
use ring::digest::{SHA256, digest};
use thiserror::Error;

use crate::firewall_command::{
    FirewallCommand, FirewallCommandError, FirewallCommandExecutor, FirewallCommandRunner,
};
use crate::wireless_openwrt::{
    OpenWrtWirelessInventorySnapshot, OpenWrtWirelessStage, OpenWrtWirelessValidation,
    WirelessRenderError, inspect_openwrt_wireless_inventory,
    render_openwrt_wireless_stage_from_snapshot,
};

const MAX_WIRELESS_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    New,
    Inspected,
    Staged,
    Validated,
    Activated,
    Verified,
}

/// One bounded `OpenWrt` physical-radio native transaction.
pub struct OpenWrtWirelessTransaction<R = FirewallCommandRunner> {
    runner: R,
    runtime_root: PathBuf,
    config_path: PathBuf,
    transaction_id: String,
    execution: WirelessExecutionPlan,
    require_root_owner: bool,
    state: TransactionState,
    source_digest: Option<String>,
    source_uci: Option<Vec<u8>>,
    source_bytes: Option<Vec<u8>>,
    snapshot: Option<OpenWrtWirelessInventorySnapshot>,
    expected: Option<WirelessInventory>,
    stage: Option<OpenWrtWirelessStage>,
    staging_dir: Option<PathBuf>,
}

impl OpenWrtWirelessTransaction<FirewallCommandRunner> {
    /// Creates a system transaction using fixed `OpenWrt` and `/tmp` paths.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid transaction identifier, executable plan, or runtime path.
    pub fn system(
        runner: FirewallCommandRunner,
        runtime_root: PathBuf,
        transaction_id: &str,
        execution: WirelessExecutionPlan,
    ) -> Result<Self, OpenWrtWirelessExecutionError> {
        Self::new(
            runner,
            runtime_root,
            PathBuf::from("/etc/config/wireless"),
            transaction_id,
            execution,
            true,
        )
    }
}

impl<R: FirewallCommandExecutor> OpenWrtWirelessTransaction<R> {
    fn new(
        runner: R,
        runtime_root: PathBuf,
        config_path: PathBuf,
        transaction_id: &str,
        execution: WirelessExecutionPlan,
        require_root_owner: bool,
    ) -> Result<Self, OpenWrtWirelessExecutionError> {
        if transaction_id.is_empty()
            || transaction_id.len() > 64
            || !transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(OpenWrtWirelessExecutionError::InvalidTransaction);
        }
        execution
            .validate()
            .map_err(|_| OpenWrtWirelessExecutionError::InvalidPlan)?;
        if require_root_owner && !safe_system_runtime_root(&runtime_root) {
            return Err(OpenWrtWirelessExecutionError::UnsafeRuntime);
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
    /// typed state, unsupported radio semantics, or command failure.
    pub fn reinspect(&mut self) -> Result<(), OpenWrtWirelessExecutionError> {
        self.require_state(TransactionState::New)?;
        ensure_runtime_root(&self.runtime_root, self.require_root_owner)?;
        let source_bytes = read_safe_config(&self.config_path, self.require_root_owner)?;
        let source_digest = hex_digest(&source_bytes);
        let source_uci = self
            .runner
            .execute(&FirewallCommand::UciShowWireless, None)?
            .stdout;
        let snapshot = inspect_openwrt_wireless_inventory(
            std::str::from_utf8(&source_uci)
                .map_err(|_| OpenWrtWirelessExecutionError::MalformedInspection)?,
        )?;
        let expected = project_wireless_inventory(snapshot.inventory(), &self.execution.typed)
            .map_err(|_| OpenWrtWirelessExecutionError::StalePlan)?;
        let stage = render_openwrt_wireless_stage_from_snapshot(&self.execution.typed, &snapshot)?;
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
    pub fn stage(&mut self) -> Result<(), OpenWrtWirelessExecutionError> {
        self.require_state(TransactionState::Inspected)?;
        let staging_root = self.runtime_root.join("staging");
        create_private_dir_all(&staging_root)?;
        let staging_dir = staging_root.join(&self.transaction_id);
        fs::create_dir(&staging_dir).map_err(OpenWrtWirelessExecutionError::Io)?;
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700))
            .map_err(OpenWrtWirelessExecutionError::Io)?;
        self.staging_dir = Some(staging_dir.clone());
        let source = self
            .source_bytes
            .as_deref()
            .ok_or(OpenWrtWirelessExecutionError::InvalidState)?;
        write_new_synced(&staging_dir.join("wireless"), source, 0o600)?;
        sync_directory(&staging_dir)?;
        let stage = self
            .stage
            .as_ref()
            .ok_or(OpenWrtWirelessExecutionError::InvalidState)?;
        self.runner.execute(
            &FirewallCommand::UciBatch {
                staging_dir: staging_dir.clone(),
            },
            Some(stage.uci_batch.as_bytes()),
        )?;
        let staged_uci = self
            .runner
            .execute(
                &FirewallCommand::UciShowWirelessAt {
                    staging_dir: staging_dir.clone(),
                },
                None,
            )?
            .stdout;
        let staged = inspect_openwrt_wireless_inventory(
            std::str::from_utf8(&staged_uci)
                .map_err(|_| OpenWrtWirelessExecutionError::MalformedInspection)?,
        )?;
        if !inventory_equal(
            staged.inventory(),
            self.expected
                .as_ref()
                .ok_or(OpenWrtWirelessExecutionError::InvalidState)?,
        ) {
            return Err(OpenWrtWirelessExecutionError::StagedStateMismatch);
        }
        self.state = TransactionState::Staged;
        Ok(())
    }

    /// Runs every fixed native validation against the private staged UCI package.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering or a failed UCI export check.
    pub fn validate_stage(&mut self) -> Result<(), OpenWrtWirelessExecutionError> {
        self.require_state(TransactionState::Staged)?;
        let directory = self
            .staging_dir
            .clone()
            .ok_or(OpenWrtWirelessExecutionError::InvalidState)?;
        let validations = self
            .stage
            .as_ref()
            .ok_or(OpenWrtWirelessExecutionError::InvalidState)?
            .validations
            .clone();
        for validation in validations {
            match validation {
                OpenWrtWirelessValidation::UciExport => {
                    self.runner.execute(
                        &FirewallCommand::UciExportWirelessAt {
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

    /// Installs the validated file and reloads wireless after an independent helper is armed.
    ///
    /// Both raw UCI output and the source-file digest are checked again immediately before the
    /// atomic rename. The caller must not invoke this method until rollback is durable and running.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, concurrent source drift, unsafe files, installation
    /// failure, or wireless reload failure.
    pub fn activate_after_rollback_armed(&mut self) -> Result<(), OpenWrtWirelessExecutionError> {
        self.require_state(TransactionState::Validated)?;
        let fresh_uci = self
            .runner
            .execute(&FirewallCommand::UciShowWireless, None)?
            .stdout;
        if self.source_uci.as_deref() != Some(fresh_uci.as_slice()) {
            return Err(OpenWrtWirelessExecutionError::SourceDrift);
        }
        let fresh_source = read_safe_config(&self.config_path, self.require_root_owner)?;
        if self.source_digest.as_deref() != Some(hex_digest(&fresh_source).as_str()) {
            return Err(OpenWrtWirelessExecutionError::SourceDrift);
        }
        let staged_path = self
            .staging_dir
            .as_ref()
            .ok_or(OpenWrtWirelessExecutionError::InvalidState)?
            .join("wireless");
        atomic_install(
            &staged_path,
            &self.config_path,
            &self.transaction_id,
            self.require_root_owner,
        )?;
        self.runner
            .execute(&FirewallCommand::OpenWrtWirelessReload, None)?;
        self.state = TransactionState::Activated;
        Ok(())
    }

    /// Reconstructs live typed state and compares it with the approved projection.
    ///
    /// # Errors
    ///
    /// Returns an error for wrong ordering, inspection failure, or post-apply mismatch.
    pub fn verify(&mut self) -> Result<(), OpenWrtWirelessExecutionError> {
        self.require_state(TransactionState::Activated)?;
        let actual = self
            .runner
            .execute(&FirewallCommand::UciShowWireless, None)?
            .stdout;
        let snapshot = inspect_openwrt_wireless_inventory(
            std::str::from_utf8(&actual)
                .map_err(|_| OpenWrtWirelessExecutionError::MalformedInspection)?,
        )?;
        verify_wireless_plan_result(snapshot.inventory(), &self.execution.typed)
            .map_err(|_| OpenWrtWirelessExecutionError::VerificationFailed)?;
        if !inventory_equal(
            snapshot.inventory(),
            self.expected
                .as_ref()
                .ok_or(OpenWrtWirelessExecutionError::InvalidState)?,
        ) {
            return Err(OpenWrtWirelessExecutionError::VerificationFailed);
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
    ) -> Result<(), OpenWrtWirelessExecutionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(OpenWrtWirelessExecutionError::InvalidState)
        }
    }
}

/// Reinspects live state and verifies every radio touched by an approved execution plan.
///
/// # Errors
///
/// Returns an error for command, decoding, inventory, or approved-result mismatch failures.
pub fn verify_openwrt_wireless_plan(
    runner: &impl FirewallCommandExecutor,
    execution: &WirelessExecutionPlan,
) -> Result<(), OpenWrtWirelessExecutionError> {
    execution
        .validate()
        .map_err(|_| OpenWrtWirelessExecutionError::InvalidPlan)?;
    let actual = runner
        .execute(&FirewallCommand::UciShowWireless, None)?
        .stdout;
    let snapshot = inspect_openwrt_wireless_inventory(
        std::str::from_utf8(&actual)
            .map_err(|_| OpenWrtWirelessExecutionError::MalformedInspection)?,
    )?;
    verify_wireless_plan_result(snapshot.inventory(), &execution.typed)
        .map_err(|_| OpenWrtWirelessExecutionError::VerificationFailed)
}

impl<R> Drop for OpenWrtWirelessTransaction<R> {
    fn drop(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn read_safe_config(
    path: &Path,
    require_root: bool,
) -> Result<Vec<u8>, OpenWrtWirelessExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(OpenWrtWirelessExecutionError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_WIRELESS_CONFIG_BYTES
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtWirelessExecutionError::UnsafeConfig);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| {
            file.take(MAX_WIRELESS_CONFIG_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(OpenWrtWirelessExecutionError::Io)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(OpenWrtWirelessExecutionError::SourceDrift);
    }
    Ok(bytes)
}

fn atomic_install(
    staged: &Path,
    destination: &Path,
    transaction_id: &str,
    require_root: bool,
) -> Result<(), OpenWrtWirelessExecutionError> {
    let bytes = read_safe_config(staged, false)?;
    let metadata = fs::symlink_metadata(destination).map_err(OpenWrtWirelessExecutionError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtWirelessExecutionError::UnsafeConfig);
    }
    let parent = destination
        .parent()
        .ok_or(OpenWrtWirelessExecutionError::UnsafeConfig)?;
    let temporary = parent.join(format!(".mbed-agent-{transaction_id}.tmp"));
    let result = (|| {
        write_new_synced(&temporary, &bytes, metadata.permissions().mode() & 0o777)?;
        fs::rename(&temporary, destination).map_err(OpenWrtWirelessExecutionError::Io)?;
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
) -> Result<(), OpenWrtWirelessExecutionError> {
    create_private_dir_all(root)?;
    let metadata = fs::symlink_metadata(root).map_err(OpenWrtWirelessExecutionError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(OpenWrtWirelessExecutionError::UnsafeRuntime);
    }
    Ok(())
}

fn create_private_dir_all(path: &Path) -> Result<(), OpenWrtWirelessExecutionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(OpenWrtWirelessExecutionError::UnsafeRuntime),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or(OpenWrtWirelessExecutionError::UnsafeRuntime)?;
            let parent_metadata =
                fs::symlink_metadata(parent).map_err(OpenWrtWirelessExecutionError::Io)?;
            if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(OpenWrtWirelessExecutionError::UnsafeRuntime);
            }
            fs::create_dir(path).map_err(OpenWrtWirelessExecutionError::Io)?;
        }
        Err(error) => return Err(OpenWrtWirelessExecutionError::Io(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(OpenWrtWirelessExecutionError::Io)
}

fn write_new_synced(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), OpenWrtWirelessExecutionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(OpenWrtWirelessExecutionError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(OpenWrtWirelessExecutionError::Io)?;
    file.write_all(bytes)
        .map_err(OpenWrtWirelessExecutionError::Io)?;
    file.sync_all().map_err(OpenWrtWirelessExecutionError::Io)
}

fn sync_directory(path: &Path) -> Result<(), OpenWrtWirelessExecutionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(OpenWrtWirelessExecutionError::Io)
}

fn inventory_equal(left: &WirelessInventory, right: &WirelessInventory) -> bool {
    let mut left = left.objects.clone();
    let mut right = right.objects.clone();
    left.sort_by(|a, b| a.id().cmp(b.id()));
    right.sort_by(|a, b| a.id().cmp(b.id()));
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
pub enum OpenWrtWirelessExecutionError {
    #[error("invalid OpenWrt wireless transaction")]
    InvalidTransaction,
    #[error("invalid executable wireless plan")]
    InvalidPlan,
    #[error("OpenWrt wireless transaction operation is out of order")]
    InvalidState,
    #[error("OpenWrt wireless runtime directory is unsafe")]
    UnsafeRuntime,
    #[error("OpenWrt wireless configuration file is unsafe")]
    UnsafeConfig,
    #[error("OpenWrt wireless inspection is malformed")]
    MalformedInspection,
    #[error("typed wireless plan is stale")]
    StalePlan,
    #[error("staged OpenWrt wireless state differs from the approved typed state")]
    StagedStateMismatch,
    #[error("live OpenWrt wireless state changed before activation")]
    SourceDrift,
    #[error("applied OpenWrt wireless verification failed")]
    VerificationFailed,
    #[error("OpenWrt wireless command failed: {0}")]
    Command(#[from] FirewallCommandError),
    #[error("OpenWrt wireless rendering failed: {0}")]
    Render(#[from] WirelessRenderError),
    #[error("OpenWrt wireless I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use agent_core::{
        WIRELESS_EXECUTION_PLAN_SCHEMA_VERSION, WirelessMutation, WirelessRiskContext,
        plan_wireless_mutations, wireless_object_digest,
    };
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, ChangePlan, ObjectOwnership, WirelessBand, WirelessChannel,
        WirelessChannelWidth, WirelessObject, WirelessRadioConfig,
    };

    use super::*;
    use crate::firewall_command::FirewallCommandOutput;

    const SOURCE_UCI: &str = "wireless.radio0=wifi-device\n\
        wireless.radio0.type='mac80211'\n\
        wireless.radio0.path='platform/soc/radio'\n\
        wireless.radio0.hwmode='11a'\n\
        wireless.radio0.channel='36'\n\
        wireless.radio0.htmode='VHT80'\n\
        wireless.radio0.country='CN'\n\
        wireless.default_radio0=wifi-iface\n\
        wireless.default_radio0.device='radio0'\n\
        wireless.default_radio0.ssid='private'\n";

    const DESIRED_UCI: &str = "wireless.radio0=wifi-device\n\
        wireless.radio0.type='mac80211'\n\
        wireless.radio0.path='platform/soc/radio'\n\
        wireless.radio0.hwmode='11a'\n\
        wireless.radio0.channel='40'\n\
        wireless.radio0.htmode='VHT80'\n\
        wireless.radio0.country='CN'\n\
        wireless.radio0.disabled='0'\n\
        wireless.default_radio0=wifi-iface\n\
        wireless.default_radio0.device='radio0'\n\
        wireless.default_radio0.ssid='private'\n";

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
    fn stages_validates_activates_and_verifies_typed_radio_state() {
        let root = fixture_root("success");
        let config = root.join("etc/config/wireless");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-wireless\n").expect("config");
        let runner = FakeRunner::new([
            SOURCE_UCI.as_bytes().to_vec(),
            Vec::new(),
            DESIRED_UCI.as_bytes().to_vec(),
            Vec::new(),
            SOURCE_UCI.as_bytes().to_vec(),
            Vec::new(),
            DESIRED_UCI.as_bytes().to_vec(),
        ]);
        let mut transaction = OpenWrtWirelessTransaction::new(
            runner,
            root.join("runtime"),
            config.clone(),
            "wireless-change-1",
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
            .join("wireless");
        fs::write(&staged, b"desired-wireless\n").expect("rendered fixture");
        transaction
            .activate_after_rollback_armed()
            .expect("activate");
        transaction.verify().expect("verify");
        assert_eq!(fs::read(&config).expect("installed"), b"desired-wireless\n");
        assert!(
            transaction
                .runner
                .calls
                .lock()
                .expect("calls")
                .contains(&FirewallCommand::OpenWrtWirelessReload)
        );
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn source_drift_blocks_wireless_install() {
        let root = fixture_root("drift");
        let config = root.join("etc/config/wireless");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-wireless\n").expect("config");
        let runner = FakeRunner::new([
            SOURCE_UCI.as_bytes().to_vec(),
            Vec::new(),
            DESIRED_UCI.as_bytes().to_vec(),
            Vec::new(),
            b"wireless.changed=wifi-device\n".to_vec(),
        ]);
        let mut transaction = OpenWrtWirelessTransaction::new(
            runner,
            root.join("runtime"),
            config.clone(),
            "wireless-change-2",
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("inspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate");
        assert!(matches!(
            transaction.activate_after_rollback_armed(),
            Err(OpenWrtWirelessExecutionError::SourceDrift)
        ));
        assert_eq!(
            fs::read(&config).expect("unchanged"),
            b"original-wireless\n"
        );
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn staged_typed_mismatch_fails_before_validation() {
        let root = fixture_root("mismatch");
        let config = root.join("etc/config/wireless");
        fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
        fs::write(&config, b"original-wireless\n").expect("config");
        let runner = FakeRunner::new([
            SOURCE_UCI.as_bytes().to_vec(),
            Vec::new(),
            SOURCE_UCI.as_bytes().to_vec(),
        ]);
        let mut transaction = OpenWrtWirelessTransaction::new(
            runner,
            root.join("runtime"),
            config,
            "wireless-change-3",
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("inspect");
        assert!(matches!(
            transaction.stage(),
            Err(OpenWrtWirelessExecutionError::StagedStateMismatch)
        ));
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn execution_plan() -> WirelessExecutionPlan {
        let before = WirelessObject::Radio(WirelessRadioConfig {
            id: "radio0".into(),
            ownership: ObjectOwnership::PlatformNative,
            enabled: true,
            band: WirelessBand::Ghz5,
            channel: WirelessChannel::Fixed { channel: 36 },
            width: WirelessChannelWidth::Mhz80,
            country: Some("CN".into()),
            tx_power_dbm: None,
        });
        let mut after = before.clone();
        let WirelessObject::Radio(radio) = &mut after;
        radio.channel = WirelessChannel::Fixed { channel: 40 };
        let typed = plan_wireless_mutations(
            &WirelessInventory {
                objects: vec![before.clone()],
            },
            &[WirelessMutation::Update {
                expected_digest: wireless_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &WirelessRiskContext::default(),
        )
        .expect("typed plan");
        WirelessExecutionPlan {
            schema_version: WIRELESS_EXECUTION_PLAN_SCHEMA_VERSION,
            preview: ChangePlan {
                schema_version: CHANGE_PLAN_SCHEMA_VERSION,
                plan_id: "wireless-change-1".into(),
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
                verification_checks: vec!["typed wireless inventory matches".into()],
                rollback_required: true,
            },
            typed,
        }
    }

    fn fixture_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("mbed-openwrt-wireless-{label}-{nonce}"))
    }
}
