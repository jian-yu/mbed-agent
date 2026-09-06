//! Stateful native nftables transaction for generic Linux.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use agent_core::FirewallExecutionPlan;
use thiserror::Error;

use crate::firewall_command::{
    FirewallCommand, FirewallCommandError, FirewallCommandExecutor, FirewallCommandRunner,
};
use crate::firewall_runtime::{
    CollectedNftablesObservation, GenericFirewallInventorySnapshot, GenericFirewallObservation,
    GenericFirewallStateError, collect_nftables_observation, encode_applied_generic_firewall_state,
    reconcile_nftables_observation, render_nftables_stage_from_snapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    New,
    Inspected,
    Staged,
    Validated,
    Activated,
    Verified,
}

/// One generic Linux nftables transaction. Activation is intentionally named to require the
/// caller's independent rollback arm before the native load.
pub struct GenericNftablesTransaction<R = FirewallCommandRunner> {
    runner: R,
    runtime_root: PathBuf,
    transaction_id: String,
    boot_id: String,
    canonical_state: Option<Vec<u8>>,
    execution: FirewallExecutionPlan,
    state: TransactionState,
    source_observation: Option<CollectedNftablesObservation>,
    snapshot: Option<GenericFirewallInventorySnapshot>,
    staging_dir: Option<PathBuf>,
    ruleset_path: Option<PathBuf>,
    applied_canonical_state: Option<Vec<u8>>,
    require_root_runtime: bool,
}

impl GenericNftablesTransaction<FirewallCommandRunner> {
    /// Creates a transaction using the configured `/tmp` runtime root.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe runtime root, transaction ID, boot ID, or execution plan.
    pub fn system(
        runner: FirewallCommandRunner,
        runtime_root: PathBuf,
        transaction_id: &str,
        boot_id: &str,
        canonical_state: Option<Vec<u8>>,
        execution: FirewallExecutionPlan,
    ) -> Result<Self, GenericNftablesExecutionError> {
        Self::new(
            runner,
            runtime_root,
            transaction_id,
            boot_id,
            canonical_state,
            execution,
            true,
        )
    }
}

impl<R: FirewallCommandExecutor> GenericNftablesTransaction<R> {
    fn new(
        runner: R,
        runtime_root: PathBuf,
        transaction_id: &str,
        boot_id: &str,
        canonical_state: Option<Vec<u8>>,
        execution: FirewallExecutionPlan,
        require_tmp: bool,
    ) -> Result<Self, GenericNftablesExecutionError> {
        if !valid_transaction_id(transaction_id)
            || boot_id.is_empty()
            || boot_id.len() > 128
            || !boot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(GenericNftablesExecutionError::InvalidIdentity);
        }
        execution
            .validate()
            .map_err(|_| GenericNftablesExecutionError::InvalidPlan)?;
        if !runtime_root.is_absolute()
            || runtime_root
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
            || (require_tmp
                && (runtime_root == Path::new("/tmp") || !runtime_root.starts_with("/tmp")))
        {
            return Err(GenericNftablesExecutionError::UnsafeRuntime);
        }
        Ok(Self {
            runner,
            runtime_root,
            transaction_id: transaction_id.into(),
            boot_id: boot_id.into(),
            canonical_state,
            execution,
            state: TransactionState::New,
            source_observation: None,
            snapshot: None,
            staging_dir: None,
            ruleset_path: None,
            applied_canonical_state: None,
            require_root_runtime: require_tmp,
        })
    }

    /// Reconciles one fresh native observation and renders from its typed snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when inspection, canonical reconciliation, or typed rendering fails.
    pub fn reinspect(&mut self) -> Result<(), GenericNftablesExecutionError> {
        self.require_state(TransactionState::New)?;
        let observation = collect_nftables_observation(&self.runner)?;
        let snapshot = reconcile_nftables_observation(
            self.canonical_state.as_deref(),
            &self.boot_id,
            &observation,
        )?;
        render_nftables_stage_from_snapshot(&snapshot, &self.execution.typed)?;
        self.source_observation = Some(observation);
        self.snapshot = Some(snapshot);
        self.state = TransactionState::Inspected;
        Ok(())
    }

    /// Writes the complete rendered ruleset to a private, bounded `/tmp` staging file.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid transaction state or unsafe staging storage.
    pub fn stage(&mut self) -> Result<(), GenericNftablesExecutionError> {
        self.require_state(TransactionState::Inspected)?;
        ensure_private_runtime_root(&self.runtime_root, self.require_root_runtime)?;
        let staging_root = self.runtime_root.join("staging");
        create_private_directory(&staging_root, self.require_root_runtime)?;
        let staging_dir = staging_root.join(&self.transaction_id);
        fs::create_dir(&staging_dir).map_err(GenericNftablesExecutionError::Io)?;
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700))
            .map_err(GenericNftablesExecutionError::Io)?;
        self.staging_dir = Some(staging_dir.clone());
        let stage = render_nftables_stage_from_snapshot(
            self.snapshot
                .as_ref()
                .ok_or(GenericNftablesExecutionError::InvalidState)?,
            &self.execution.typed,
        )?;
        let ruleset_path = staging_dir.join("ruleset.nft");
        write_new_synced(&ruleset_path, stage.ruleset.as_bytes())?;
        File::open(&staging_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(GenericNftablesExecutionError::Io)?;
        self.ruleset_path = Some(ruleset_path);
        self.state = TransactionState::Staged;
        Ok(())
    }

    /// Runs `nft --check --file` against the exact staged artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction state is invalid or native validation fails.
    pub fn validate_stage(&mut self) -> Result<(), GenericNftablesExecutionError> {
        self.require_state(TransactionState::Staged)?;
        self.runner.execute(
            &FirewallCommand::NftCheck {
                ruleset: self.ruleset_path()?,
            },
            None,
        )?;
        self.state = TransactionState::Validated;
        Ok(())
    }

    /// Rejects concurrent native drift, then atomically loads the staged nftables transaction.
    /// The caller must arm an independent rollback helper before invoking this method.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state, concurrent drift, or a failed native load.
    pub fn activate_after_rollback_armed(&mut self) -> Result<(), GenericNftablesExecutionError> {
        self.require_state(TransactionState::Validated)?;
        let fresh = collect_nftables_observation(&self.runner)?;
        if self.source_observation.as_ref() != Some(&fresh) {
            return Err(GenericNftablesExecutionError::SourceDrift);
        }
        self.runner.execute(
            &FirewallCommand::NftLoad {
                ruleset: self.ruleset_path()?,
            },
            None,
        )?;
        self.state = TransactionState::Activated;
        Ok(())
    }

    /// Reinspects the applied table and produces the next boot-bound canonical `SQLite` payload.
    ///
    /// # Errors
    ///
    /// Returns an error when post-activation inspection or canonical encoding fails.
    pub fn verify(&mut self) -> Result<(), GenericNftablesExecutionError> {
        self.require_state(TransactionState::Activated)?;
        let observation = collect_nftables_observation(&self.runner)?;
        let encoded = encode_applied_generic_firewall_state(
            self.snapshot
                .as_ref()
                .ok_or(GenericNftablesExecutionError::InvalidState)?,
            &self.execution.typed,
            &self.boot_id,
            GenericFirewallObservation::Nftables(observation.managed_listing()),
        )?;
        self.applied_canonical_state = Some(encoded);
        self.state = TransactionState::Verified;
        Ok(())
    }

    /// Returns the verified canonical payload for atomic storage by the daemon port.
    ///
    /// # Errors
    ///
    /// Returns an error until native verification has completed successfully.
    pub fn verified_canonical_state(&self) -> Result<&[u8], GenericNftablesExecutionError> {
        if self.state != TransactionState::Verified {
            return Err(GenericNftablesExecutionError::InvalidState);
        }
        self.applied_canonical_state
            .as_deref()
            .ok_or(GenericNftablesExecutionError::InvalidState)
    }

    /// Builds the exact runtime-only rollback ruleset from the inspected owned table.
    ///
    /// # Errors
    ///
    /// Returns an error unless reinspection has completed and the observation is bounded UTF-8.
    pub fn rollback_ruleset(&self) -> Result<Vec<u8>, GenericNftablesExecutionError> {
        if !matches!(
            self.state,
            TransactionState::Inspected | TransactionState::Staged | TransactionState::Validated
        ) {
            return Err(GenericNftablesExecutionError::InvalidState);
        }
        let observation = self
            .source_observation
            .as_ref()
            .ok_or(GenericNftablesExecutionError::InvalidState)?;
        let mut ruleset = b"delete table inet mbed_agent\n".to_vec();
        if let Some(listing) = observation.managed_listing() {
            ruleset.extend_from_slice(listing.as_bytes());
            if !ruleset.ends_with(b"\n") {
                ruleset.push(b'\n');
            }
        }
        Ok(ruleset)
    }

    /// Reports whether the validated rollback snapshot contains a prior owned table.
    ///
    /// # Errors
    ///
    /// Returns an error unless reinspection has completed.
    pub fn rollback_table_existed(&self) -> Result<bool, GenericNftablesExecutionError> {
        if !matches!(
            self.state,
            TransactionState::Inspected | TransactionState::Staged | TransactionState::Validated
        ) {
            return Err(GenericNftablesExecutionError::InvalidState);
        }
        Ok(self
            .source_observation
            .as_ref()
            .ok_or(GenericNftablesExecutionError::InvalidState)?
            .managed_listing()
            .is_some())
    }

    pub fn discard_stage(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
        self.ruleset_path = None;
    }

    fn ruleset_path(&self) -> Result<PathBuf, GenericNftablesExecutionError> {
        self.ruleset_path
            .clone()
            .ok_or(GenericNftablesExecutionError::InvalidState)
    }

    fn require_state(
        &self,
        expected: TransactionState,
    ) -> Result<(), GenericNftablesExecutionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(GenericNftablesExecutionError::InvalidState)
        }
    }
}

impl<R> Drop for GenericNftablesTransaction<R> {
    fn drop(&mut self) {
        if let Some(directory) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn valid_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn ensure_private_runtime_root(
    path: &Path,
    require_root: bool,
) -> Result<(), GenericNftablesExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(GenericNftablesExecutionError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || (require_root && (metadata.uid() != 0 || metadata.gid() != 0))
    {
        return Err(GenericNftablesExecutionError::UnsafeRuntime);
    }
    Ok(())
}

fn create_private_directory(
    path: &Path,
    require_root: bool,
) -> Result<(), GenericNftablesExecutionError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(GenericNftablesExecutionError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_private_runtime_root(path, require_root)
        }
        Err(error) => Err(GenericNftablesExecutionError::Io(error)),
    }
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), GenericNftablesExecutionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(GenericNftablesExecutionError::Io)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(GenericNftablesExecutionError::Io)
}

#[derive(Debug, Error)]
pub enum GenericNftablesExecutionError {
    #[error("generic nftables transaction identity is invalid")]
    InvalidIdentity,
    #[error("generic nftables execution plan is invalid")]
    InvalidPlan,
    #[error("generic nftables transaction ordering is invalid")]
    InvalidState,
    #[error("generic nftables runtime path is unsafe")]
    UnsafeRuntime,
    #[error("generic nftables source changed before activation")]
    SourceDrift,
    #[error("generic nftables command failed: {0}")]
    Command(#[from] FirewallCommandError),
    #[error("generic nftables state failed: {0}")]
    State(#[from] GenericFirewallStateError),
    #[error("generic nftables staging I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use agent_core::{
        FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION, FirewallInventory, FirewallMutation,
        FirewallRiskContext, plan_firewall_mutations,
    };
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, ChangePlan, FirewallObject, FirewallVerdict, FirewallZone,
        ObjectOwnership,
    };

    use super::*;
    use crate::firewall_command::FirewallCommandOutput;
    use crate::firewall_runtime::inspect_generic_nftables_inventory;

    const OWNED_TABLE: &str = "table inet mbed_agent {\n\tcomment \"mbed-agent-owned:v1\"\n}\n";
    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct MockNft {
        managed: Cell<bool>,
        checked: Cell<bool>,
        loaded: Cell<bool>,
    }

    impl MockNft {
        fn new() -> Self {
            Self {
                managed: Cell::new(false),
                checked: Cell::new(false),
                loaded: Cell::new(false),
            }
        }

        fn output(value: &str) -> FirewallCommandOutput {
            FirewallCommandOutput {
                stdout: value.as_bytes().to_vec(),
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            }
        }
    }

    impl FirewallCommandExecutor for MockNft {
        fn execute(
            &self,
            operation: &FirewallCommand,
            _stdin: Option<&[u8]>,
        ) -> Result<FirewallCommandOutput, FirewallCommandError> {
            match operation {
                FirewallCommand::NftListTables if self.managed.get() => {
                    Ok(Self::output("table inet mbed_agent\n"))
                }
                FirewallCommand::NftListTables => Ok(Self::output("table ip filter\n")),
                FirewallCommand::NftListManagedTable if self.managed.get() => {
                    Ok(Self::output(OWNED_TABLE))
                }
                FirewallCommand::NftCheck { ruleset } => {
                    let value = fs::read_to_string(ruleset).map_err(FirewallCommandError::Io)?;
                    if !value.contains("mbed-agent-owned:v1") {
                        return Err(FirewallCommandError::Unsuccessful);
                    }
                    self.checked.set(true);
                    Ok(Self::output(""))
                }
                FirewallCommand::NftLoad { ruleset } if self.checked.get() => {
                    fs::metadata(ruleset).map_err(FirewallCommandError::Io)?;
                    self.managed.set(true);
                    self.loaded.set(true);
                    Ok(Self::output(""))
                }
                _ => Err(FirewallCommandError::UnexpectedInput),
            }
        }
    }

    #[test]
    fn stages_checks_loads_and_encodes_verified_canonical_state() {
        let root = fixture_root();
        let runner = MockNft::new();
        let mut transaction = GenericNftablesTransaction::new(
            runner,
            root.clone(),
            "change-nft-1",
            BOOT_ID,
            None,
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("reinspect");
        assert!(!transaction.rollback_table_existed().expect("prior state"));
        assert_eq!(
            transaction.rollback_ruleset().expect("rollback ruleset"),
            b"delete table inet mbed_agent\n"
        );
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("check");
        transaction
            .activate_after_rollback_armed()
            .expect("activate");
        transaction.verify().expect("verify");
        let canonical = transaction.verified_canonical_state().expect("canonical");
        let restored =
            inspect_generic_nftables_inventory(&transaction.runner, Some(canonical), BOOT_ID)
                .expect("reconcile applied state");
        assert_eq!(restored.inventory().objects.len(), 1);
        drop(transaction);
        assert!(!root.join("staging/change-nft-1").exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn concurrent_native_drift_blocks_activation() {
        let root = fixture_root();
        let runner = MockNft::new();
        let mut transaction = GenericNftablesTransaction::new(
            runner,
            root.clone(),
            "change-nft-drift",
            BOOT_ID,
            None,
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("reinspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("check");
        transaction.runner.managed.set(true);
        assert!(matches!(
            transaction.activate_after_rollback_armed(),
            Err(GenericNftablesExecutionError::SourceDrift)
        ));
        assert!(!transaction.runner.loaded.get());
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn fixture_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let pid = std::process::id();
        for _ in 0..8 {
            let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("mbed-agent-nft-execute-{pid}-{nonce}-{sequence}"));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .expect("permissions");
                    return root;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("root: {error}"),
            }
        }
        panic!("could not allocate a unique fixture root")
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
                    networks: vec!["guest0".into()],
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
        let preview = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "change-nft-1".into(),
            boot_id: BOOT_ID.into(),
            actor_id: "cli/local".into(),
            created_monotonic_ms: 1,
            expires_monotonic_ms: 10_000,
            risk: typed.risk,
            changes: typed
                .changes
                .iter()
                .map(|change| change.diff.clone())
                .collect(),
            validation_checks: vec!["nft check".into()],
            verification_checks: vec!["managed table".into()],
            rollback_required: true,
        };
        FirewallExecutionPlan {
            schema_version: FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION,
            preview,
            typed,
        }
    }
}
