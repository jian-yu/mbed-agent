//! Stateful transaction for Agent-owned volatile generic Linux routes.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use agent_core::NetworkExecutionPlan;
use thiserror::Error;

use crate::firewall_command::{
    FirewallCommand, FirewallCommandError, FirewallCommandExecutor, FirewallCommandRunner,
};
use crate::network_runtime::{
    RuntimeNetworkInventoryError, RuntimeRouteSnapshot, RuntimeRouteStage,
    reconcile_runtime_network_inventory, reconcile_runtime_network_inventory_with_links,
    render_runtime_route_stage, runtime_canonical_includes_interfaces,
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

pub struct GenericRuntimeRouteTransaction<R = FirewallCommandRunner> {
    runner: R,
    runtime_root: PathBuf,
    transaction_id: String,
    boot_id: String,
    canonical_state: Option<Vec<u8>>,
    execution: NetworkExecutionPlan,
    state: TransactionState,
    snapshot: Option<RuntimeRouteSnapshot>,
    rendered: Option<RuntimeRouteStage>,
    staging_dir: Option<PathBuf>,
    apply_path: Option<PathBuf>,
    rollback_path: Option<PathBuf>,
    verified_canonical: Option<Vec<u8>>,
    require_tmp: bool,
}

impl GenericRuntimeRouteTransaction<FirewallCommandRunner> {
    /// Creates a system transaction below the configured private `/tmp` runtime root.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity, unsafe runtime root, or invalid execution plan.
    pub fn system(
        runner: FirewallCommandRunner,
        runtime_root: PathBuf,
        transaction_id: &str,
        boot_id: &str,
        canonical_state: Option<Vec<u8>>,
        execution: NetworkExecutionPlan,
    ) -> Result<Self, GenericRuntimeRouteExecutionError> {
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

impl<R: FirewallCommandExecutor> GenericRuntimeRouteTransaction<R> {
    fn new(
        runner: R,
        runtime_root: PathBuf,
        transaction_id: &str,
        boot_id: &str,
        canonical_state: Option<Vec<u8>>,
        execution: NetworkExecutionPlan,
        require_tmp: bool,
    ) -> Result<Self, GenericRuntimeRouteExecutionError> {
        if !valid_identity(transaction_id)
            || !valid_identity(boot_id)
            || !runtime_root.is_absolute()
            || runtime_root
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || (require_tmp
                && (runtime_root == Path::new("/tmp") || !runtime_root.starts_with("/tmp")))
        {
            return Err(GenericRuntimeRouteExecutionError::InvalidIdentity);
        }
        execution
            .validate()
            .map_err(|_| GenericRuntimeRouteExecutionError::InvalidPlan)?;
        Ok(Self {
            runner,
            runtime_root,
            transaction_id: transaction_id.into(),
            boot_id: boot_id.into(),
            canonical_state,
            execution,
            state: TransactionState::New,
            snapshot: None,
            rendered: None,
            staging_dir: None,
            apply_path: None,
            rollback_path: None,
            verified_canonical: None,
            require_tmp,
        })
    }

    /// Reconciles fresh protocol-owned routes and binds the exact approved plan.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ordering, inspection, canonical reconciliation, or rendering.
    pub fn reinspect(&mut self) -> Result<(), GenericRuntimeRouteExecutionError> {
        self.require_state(TransactionState::New)?;
        let snapshot = self.reconcile_snapshot()?;
        let rendered = render_runtime_route_stage(&snapshot, &self.execution.typed)?;
        self.snapshot = Some(snapshot);
        self.rendered = Some(rendered);
        self.state = TransactionState::Inspected;
        Ok(())
    }

    /// Durably writes exact apply and reverse batches to a private runtime directory.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ordering, unsafe storage, or an I/O failure.
    pub fn stage(&mut self) -> Result<(), GenericRuntimeRouteExecutionError> {
        self.require_state(TransactionState::Inspected)?;
        ensure_runtime_root(&self.runtime_root, self.require_tmp)?;
        let staging_root = self.runtime_root.join("staging");
        create_private_dir(&staging_root)?;
        let staging_dir = staging_root.join(&self.transaction_id);
        fs::create_dir(&staging_dir).map_err(GenericRuntimeRouteExecutionError::Io)?;
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700))
            .map_err(GenericRuntimeRouteExecutionError::Io)?;
        self.staging_dir = Some(staging_dir.clone());
        let rendered = self
            .rendered
            .as_ref()
            .ok_or(GenericRuntimeRouteExecutionError::InvalidState)?;
        let apply = staging_dir.join("apply.ipbatch");
        let rollback = staging_dir.join("rollback.ipbatch");
        write_new(&apply, rendered.apply_batch.as_bytes())?;
        write_new(&rollback, rendered.rollback_batch.as_bytes())?;
        File::open(&staging_dir)
            .and_then(|file| file.sync_all())
            .map_err(GenericRuntimeRouteExecutionError::Io)?;
        self.apply_path = Some(apply);
        self.rollback_path = Some(rollback);
        self.state = TransactionState::Staged;
        Ok(())
    }

    /// Rechecks that staged bytes still equal the locally validated renderer output.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ordering, I/O failure, or staged artifact drift.
    pub fn validate_stage(&mut self) -> Result<(), GenericRuntimeRouteExecutionError> {
        self.require_state(TransactionState::Staged)?;
        let rendered = self
            .rendered
            .as_ref()
            .ok_or(GenericRuntimeRouteExecutionError::InvalidState)?;
        if fs::read(self.apply_path()?).map_err(GenericRuntimeRouteExecutionError::Io)?
            != rendered.apply_batch.as_bytes()
            || fs::read(self.rollback_path()?).map_err(GenericRuntimeRouteExecutionError::Io)?
                != rendered.rollback_batch.as_bytes()
        {
            return Err(GenericRuntimeRouteExecutionError::StagedDrift);
        }
        self.state = TransactionState::Validated;
        Ok(())
    }

    /// Reconciles source state again and executes the exact forward batch.
    ///
    /// The caller must arm an independent rollback helper before this method.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ordering, source drift, inspection, or native apply failure.
    pub fn activate_after_rollback_armed(
        &mut self,
    ) -> Result<(), GenericRuntimeRouteExecutionError> {
        self.require_state(TransactionState::Validated)?;
        let snapshot = self.reconcile_snapshot()?;
        if self.snapshot.as_ref() != Some(&snapshot) {
            return Err(GenericRuntimeRouteExecutionError::SourceDrift);
        }
        self.runner.execute(
            &FirewallCommand::IpBatch {
                batch_file: self.apply_path()?,
                continue_on_error: false,
            },
            None,
        )?;
        self.state = TransactionState::Activated;
        Ok(())
    }

    /// Verifies fresh protocol-owned routes against the projected canonical state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ordering, inspection failure, or post-apply mismatch.
    pub fn verify(&mut self) -> Result<(), GenericRuntimeRouteExecutionError> {
        self.require_state(TransactionState::Activated)?;
        let rendered = self
            .rendered
            .as_ref()
            .ok_or(GenericRuntimeRouteExecutionError::InvalidState)?;
        if self.execution_requires_full_inventory() {
            let links = self.collect_links()?;
            let addresses = self.collect_addresses()?;
            let routes = self.collect_routes()?;
            let rules = self.collect_rules()?;
            reconcile_runtime_network_inventory_with_links(
                &links,
                &addresses,
                &routes,
                &rules,
                Some(&rendered.projected_canonical_state),
                &self.boot_id,
            )?;
        } else {
            let fresh = self.collect_routes()?;
            let fresh_rules = self.collect_rules()?;
            reconcile_runtime_network_inventory(
                &fresh,
                &fresh_rules,
                Some(&rendered.projected_canonical_state),
                &self.boot_id,
            )?;
        }
        self.verified_canonical = Some(rendered.projected_canonical_state.clone());
        self.state = TransactionState::Verified;
        Ok(())
    }

    /// Loads the exact staged reverse batch before rollback is armed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ordering or an I/O failure.
    pub fn rollback_batch(&self) -> Result<Vec<u8>, GenericRuntimeRouteExecutionError> {
        if !matches!(
            self.state,
            TransactionState::Staged | TransactionState::Validated
        ) {
            return Err(GenericRuntimeRouteExecutionError::InvalidState);
        }
        fs::read(self.rollback_path()?).map_err(GenericRuntimeRouteExecutionError::Io)
    }

    /// Returns the canonical state proven by post-apply inspection.
    ///
    /// # Errors
    ///
    /// Returns an error until verification succeeds.
    pub fn verified_canonical_state(&self) -> Result<&[u8], GenericRuntimeRouteExecutionError> {
        if self.state != TransactionState::Verified {
            return Err(GenericRuntimeRouteExecutionError::InvalidState);
        }
        self.verified_canonical
            .as_deref()
            .ok_or(GenericRuntimeRouteExecutionError::InvalidState)
    }

    pub fn discard_stage(&mut self) {
        if let Some(path) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(path);
        }
    }

    fn collect_routes(&self) -> Result<String, GenericRuntimeRouteExecutionError> {
        String::from_utf8(
            self.runner
                .execute(&FirewallCommand::IpJsonRoute, None)?
                .stdout,
        )
        .map_err(|_| GenericRuntimeRouteExecutionError::Inspection)
    }

    fn collect_links(&self) -> Result<String, GenericRuntimeRouteExecutionError> {
        String::from_utf8(
            self.runner
                .execute(&FirewallCommand::IpJsonLink, None)?
                .stdout,
        )
        .map_err(|_| GenericRuntimeRouteExecutionError::Inspection)
    }

    fn collect_addresses(&self) -> Result<String, GenericRuntimeRouteExecutionError> {
        String::from_utf8(
            self.runner
                .execute(&FirewallCommand::IpJsonAddress, None)?
                .stdout,
        )
        .map_err(|_| GenericRuntimeRouteExecutionError::Inspection)
    }

    fn collect_rules(&self) -> Result<String, GenericRuntimeRouteExecutionError> {
        String::from_utf8(
            self.runner
                .execute(&FirewallCommand::IpJsonRule, None)?
                .stdout,
        )
        .map_err(|_| GenericRuntimeRouteExecutionError::Inspection)
    }

    fn execution_requires_full_inventory(&self) -> bool {
        let canonical_has_interfaces = self
            .canonical_state
            .as_deref()
            .map(runtime_canonical_includes_interfaces)
            .is_some_and(|result| result.unwrap_or(true));
        self.execution.typed.changes.iter().any(|change| {
            [change.before.as_ref(), change.after.as_ref()]
                .into_iter()
                .flatten()
                .any(|object| matches!(object, agent_protocol::NetworkObject::Interface(_)))
        }) || canonical_has_interfaces
    }

    fn reconcile_snapshot(
        &self,
    ) -> Result<RuntimeRouteSnapshot, GenericRuntimeRouteExecutionError> {
        if self.execution_requires_full_inventory() {
            let links = self.collect_links()?;
            let addresses = self.collect_addresses()?;
            let routes = self.collect_routes()?;
            let rules = self.collect_rules()?;
            Ok(reconcile_runtime_network_inventory_with_links(
                &links,
                &addresses,
                &routes,
                &rules,
                self.canonical_state.as_deref(),
                &self.boot_id,
            )?)
        } else {
            let routes = self.collect_routes()?;
            let rules = self.collect_rules()?;
            Ok(reconcile_runtime_network_inventory(
                &routes,
                &rules,
                self.canonical_state.as_deref(),
                &self.boot_id,
            )?)
        }
    }

    fn apply_path(&self) -> Result<PathBuf, GenericRuntimeRouteExecutionError> {
        self.apply_path
            .clone()
            .ok_or(GenericRuntimeRouteExecutionError::InvalidState)
    }

    fn rollback_path(&self) -> Result<PathBuf, GenericRuntimeRouteExecutionError> {
        self.rollback_path
            .clone()
            .ok_or(GenericRuntimeRouteExecutionError::InvalidState)
    }

    fn require_state(
        &self,
        expected: TransactionState,
    ) -> Result<(), GenericRuntimeRouteExecutionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(GenericRuntimeRouteExecutionError::InvalidState)
        }
    }
}

impl<R> Drop for GenericRuntimeRouteTransaction<R> {
    fn drop(&mut self) {
        if let Some(path) = self.staging_dir.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[derive(Debug, Error)]
pub enum GenericRuntimeRouteExecutionError {
    #[error("invalid transaction identity, runtime root, or execution plan")]
    InvalidIdentity,
    #[error("invalid execution plan")]
    InvalidPlan,
    #[error("invalid transaction state")]
    InvalidState,
    #[error("runtime route inspection failed")]
    Inspection,
    #[error("staged route artifact changed")]
    StagedDrift,
    #[error("runtime route source changed")]
    SourceDrift,
    #[error(transparent)]
    Command(#[from] FirewallCommandError),
    #[error(transparent)]
    Inventory(#[from] RuntimeNetworkInventoryError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn ensure_runtime_root(
    path: &Path,
    require_tmp: bool,
) -> Result<(), GenericRuntimeRouteExecutionError> {
    fs::create_dir_all(path).map_err(GenericRuntimeRouteExecutionError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(GenericRuntimeRouteExecutionError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || (require_tmp && !path.starts_with("/tmp"))
    {
        return Err(GenericRuntimeRouteExecutionError::InvalidIdentity);
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), GenericRuntimeRouteExecutionError> {
    fs::create_dir_all(path).map_err(GenericRuntimeRouteExecutionError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(GenericRuntimeRouteExecutionError::Io)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), GenericRuntimeRouteExecutionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(GenericRuntimeRouteExecutionError::Io)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(GenericRuntimeRouteExecutionError::Io)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    use agent_core::{
        NETWORK_EXECUTION_PLAN_SCHEMA_VERSION, NetworkInventory, NetworkMutation,
        NetworkRiskContext, plan_network_mutations,
    };
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, ChangePlan, IpNetwork, NetworkObject, NetworkRoute,
        NetworkRouteType, ObjectOwnership,
    };

    use super::*;
    use crate::firewall_command::FirewallCommandOutput;

    const APPLIED: &str = r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","table":100,"metric":20,"protocol":186}]"#;

    struct MockIp {
        applied: Cell<bool>,
    }

    impl FirewallCommandExecutor for MockIp {
        fn execute(
            &self,
            operation: &FirewallCommand,
            _stdin: Option<&[u8]>,
        ) -> Result<FirewallCommandOutput, FirewallCommandError> {
            let stdout = match operation {
                FirewallCommand::IpJsonRoute if self.applied.get() => APPLIED.as_bytes().to_vec(),
                FirewallCommand::IpJsonRoute | FirewallCommand::IpJsonRule => b"[]".to_vec(),
                FirewallCommand::IpBatch {
                    batch_file,
                    continue_on_error: false,
                } => {
                    let batch = fs::read_to_string(batch_file).map_err(FirewallCommandError::Io)?;
                    if !batch.contains("route add default") || !batch.contains("proto 186") {
                        return Err(FirewallCommandError::Unsuccessful);
                    }
                    self.applied.set(true);
                    Vec::new()
                }
                _ => return Err(FirewallCommandError::UnexpectedInput),
            };
            Ok(FirewallCommandOutput {
                stdout,
                stderr: vec![],
                truncated: false,
                duration_ms: 1,
            })
        }
    }

    #[test]
    fn stages_activates_and_verifies_runtime_route() {
        let root = fixture_root();
        let mut transaction = GenericRuntimeRouteTransaction::new(
            MockIp {
                applied: Cell::new(false),
            },
            root.clone(),
            "change-route-1",
            "boot-1",
            None,
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("reinspect");
        transaction.stage().expect("stage");
        assert!(
            String::from_utf8(transaction.rollback_batch().expect("rollback"))
                .expect("UTF-8")
                .contains("route del default")
        );
        transaction.validate_stage().expect("validate");
        transaction
            .activate_after_rollback_armed()
            .expect("activate");
        transaction.verify().expect("verify");
        assert!(
            !transaction
                .verified_canonical_state()
                .expect("canonical")
                .is_empty()
        );
        drop(transaction);
        assert!(!root.join("staging/change-route-1").exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn staged_or_native_drift_blocks_activation() {
        let root = fixture_root();
        let mut transaction = GenericRuntimeRouteTransaction::new(
            MockIp {
                applied: Cell::new(false),
            },
            root.clone(),
            "change-route-drift",
            "boot-1",
            None,
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("reinspect");
        transaction.stage().expect("stage");
        fs::write(transaction.apply_path().expect("path"), b"tampered\n").expect("tamper");
        assert!(matches!(
            transaction.validate_stage(),
            Err(GenericRuntimeRouteExecutionError::StagedDrift)
        ));
        drop(transaction);

        let mut transaction = GenericRuntimeRouteTransaction::new(
            MockIp {
                applied: Cell::new(false),
            },
            root.clone(),
            "change-route-native-drift",
            "boot-1",
            None,
            execution_plan(),
            false,
        )
        .expect("transaction");
        transaction.reinspect().expect("reinspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate");
        transaction.runner.applied.set(true);
        assert!(matches!(
            transaction.activate_after_rollback_armed(),
            Err(GenericRuntimeRouteExecutionError::Inventory(
                RuntimeNetworkInventoryError::NativeDrift
            ))
        ));
        drop(transaction);
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn fixture_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-route-execute-{nonce}"));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("permissions");
        root
    }

    fn execution_plan() -> NetworkExecutionPlan {
        let route = NetworkObject::Route(NetworkRoute {
            id: "guest-default".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            destination: IpNetwork {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            gateway: Some("192.0.2.1".parse().expect("gateway")),
            output_interface: Some("eth0".into()),
            preferred_source: None,
            table: 100,
            metric: Some(20),
            route_type: NetworkRouteType::Unicast,
        });
        let typed = plan_network_mutations(
            &NetworkInventory { objects: vec![] },
            &[NetworkMutation::Create(route)],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let changes = typed
            .changes
            .iter()
            .map(|change| change.diff.clone())
            .collect();
        let preview = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "route-plan-1".into(),
            boot_id: "boot-1".into(),
            actor_id: "cli/local".into(),
            created_monotonic_ms: 1,
            expires_monotonic_ms: 2,
            risk: typed.risk,
            changes,
            validation_checks: vec!["typed ip batch".into()],
            verification_checks: vec!["fresh protocol routes".into()],
            rollback_required: true,
        };
        NetworkExecutionPlan {
            schema_version: NETWORK_EXECUTION_PLAN_SCHEMA_VERSION,
            preview,
            typed,
        }
    }
}
