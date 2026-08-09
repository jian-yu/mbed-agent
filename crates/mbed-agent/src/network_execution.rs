use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use agent_core::{
    ChangeExecutionPort, ExecutionPortError, NetworkExecutionPlan, RollbackOutcome, RollbackReload,
    RollbackTarget, RuntimeCanonicalSnapshot, confirm_rollback,
    create_network_routes_runtime_rollback_bundle, create_rollback_bundle, request_rollback,
    rollback_outcome, runtime_rollback_canonical_state, verify_network_plan_result,
};
use agent_protocol::ChangeSetState;
use agent_store::Store;
use platform_linux::firewall_command::{
    FirewallCommand, FirewallCommandExecutor, FirewallCommandRunner,
};
use platform_linux::network_openwrt_execute::{
    OpenWrtNetworkTransaction, verify_openwrt_network_plan,
};
use platform_linux::network_runtime::{
    reconcile_runtime_network_inventory, reconcile_runtime_network_inventory_with_links,
    runtime_canonical_includes_interfaces,
};
use platform_linux::network_runtime_execute::GenericRuntimeRouteTransaction;

pub(crate) struct GenericRuntimeRouteExecutionPort {
    transaction: Option<GenericRuntimeRouteTransaction>,
    runner: FirewallCommandRunner,
    execution: NetworkExecutionPlan,
    canonical_state: Option<Vec<u8>>,
    store: Arc<Store>,
    runtime_root: PathBuf,
    config_path: PathBuf,
    change_set_id: String,
    plan_digest: String,
    boot_id: String,
    now_monotonic_ms: u64,
    rollback_timeout_secs: u64,
    max_rollback_bytes: u64,
    max_state_bytes: usize,
    confirmation_verified: bool,
}

pub(crate) struct GenericRuntimeRouteExecutionPortConfig {
    pub(crate) runner: FirewallCommandRunner,
    pub(crate) execution: NetworkExecutionPlan,
    pub(crate) canonical_state: Option<Vec<u8>>,
    pub(crate) store: Arc<Store>,
    pub(crate) runtime_root: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) change_set_id: String,
    pub(crate) plan_digest: String,
    pub(crate) boot_id: String,
    pub(crate) now_monotonic_ms: u64,
    pub(crate) rollback_timeout_secs: u64,
    pub(crate) max_rollback_bytes: u64,
    pub(crate) max_state_bytes: usize,
}

pub(crate) struct OpenWrtNetworkExecutionPort {
    transaction: Option<OpenWrtNetworkTransaction>,
    runner: FirewallCommandRunner,
    execution: NetworkExecutionPlan,
    store: Arc<Store>,
    runtime_root: PathBuf,
    config_path: PathBuf,
    change_set_id: String,
    plan_digest: String,
    boot_id: String,
    now_monotonic_ms: u64,
    rollback_timeout_secs: u64,
    max_rollback_bytes: u64,
    confirmation_verified: bool,
}

pub(crate) struct OpenWrtNetworkExecutionPortConfig {
    pub(crate) runner: FirewallCommandRunner,
    pub(crate) store: Arc<Store>,
    pub(crate) runtime_root: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) change_set_id: String,
    pub(crate) plan_digest: String,
    pub(crate) boot_id: String,
    pub(crate) now_monotonic_ms: u64,
    pub(crate) rollback_timeout_secs: u64,
    pub(crate) max_rollback_bytes: u64,
    pub(crate) execution: NetworkExecutionPlan,
}

impl OpenWrtNetworkExecutionPort {
    pub(crate) fn apply(
        config: OpenWrtNetworkExecutionPortConfig,
    ) -> Result<Self, ExecutionPortError> {
        let transaction = OpenWrtNetworkTransaction::system(
            config.runner.clone(),
            config.runtime_root.clone(),
            &config.change_set_id,
            config.execution.clone(),
        )
        .map_err(|_| ExecutionPortError)?;
        Ok(Self::new(config, Some(transaction)))
    }

    pub(crate) fn confirmation(config: OpenWrtNetworkExecutionPortConfig) -> Self {
        Self::new(config, None)
    }

    fn new(
        config: OpenWrtNetworkExecutionPortConfig,
        transaction: Option<OpenWrtNetworkTransaction>,
    ) -> Self {
        Self {
            transaction,
            runner: config.runner,
            execution: config.execution,
            store: config.store,
            runtime_root: config.runtime_root,
            config_path: config.config_path,
            change_set_id: config.change_set_id,
            plan_digest: config.plan_digest,
            boot_id: config.boot_id,
            now_monotonic_ms: config.now_monotonic_ms,
            rollback_timeout_secs: config.rollback_timeout_secs,
            max_rollback_bytes: config.max_rollback_bytes,
            confirmation_verified: false,
        }
    }

    fn transaction(&mut self) -> Result<&mut OpenWrtNetworkTransaction, ExecutionPortError> {
        self.transaction.as_mut().ok_or(ExecutionPortError)
    }

    fn rollback_root(&self) -> PathBuf {
        self.runtime_root.join("rollback")
    }

    fn spawn_helper(&self) -> Result<(), ExecutionPortError> {
        let executable = std::env::current_exe().map_err(|_| ExecutionPortError)?;
        let mut child = Command::new(executable)
            .arg("rollback-helper")
            .arg(&self.change_set_id)
            .arg("--config")
            .arg(&self.config_path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ExecutionPortError)?;
        thread::Builder::new()
            .name("network-rollback-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            })
            .map_err(|_| ExecutionPortError)?;
        Ok(())
    }
}

impl ChangeExecutionPort for OpenWrtNetworkExecutionPort {
    fn reinspect(&mut self) -> Result<(), ExecutionPortError> {
        if self.transaction.is_some() {
            self.transaction()?
                .reinspect()
                .map_err(|_| ExecutionPortError)
        } else {
            verify_openwrt_network_plan(&self.runner, &self.execution)
                .map_err(|_| ExecutionPortError)?;
            self.confirmation_verified = true;
            Ok(())
        }
    }

    fn stage(&mut self) -> Result<(), ExecutionPortError> {
        self.transaction()?.stage().map_err(|_| ExecutionPortError)
    }

    fn validate_stage(&mut self) -> Result<(), ExecutionPortError> {
        self.transaction()?
            .validate_stage()
            .map_err(|_| ExecutionPortError)
    }

    fn arm_rollback(&mut self, _deadline_monotonic_ms: u64) -> Result<(), ExecutionPortError> {
        create_rollback_bundle(
            &self.rollback_root(),
            &self.change_set_id,
            if execution_has_dhcp(&self.execution) {
                &[RollbackTarget::OpenWrtNetwork, RollbackTarget::OpenWrtDhcp]
            } else {
                &[RollbackTarget::OpenWrtNetwork]
            },
            RollbackReload::OpenWrtNetwork,
            self.rollback_timeout_secs,
            self.max_rollback_bytes,
        )
        .map_err(|_| ExecutionPortError)?;
        self.spawn_helper()
    }

    fn activate(&mut self) -> Result<(), ExecutionPortError> {
        self.transaction()?
            .activate_after_rollback_armed()
            .map_err(|_| ExecutionPortError)
    }

    fn verify(&mut self) -> Result<(), ExecutionPortError> {
        if self.transaction.is_some() {
            self.transaction()?.verify().map_err(|_| ExecutionPortError)
        } else if self.confirmation_verified {
            Ok(())
        } else {
            Err(ExecutionPortError)
        }
    }

    fn confirm_rollback(&mut self) -> Result<(), ExecutionPortError> {
        confirm_rollback(&self.rollback_root(), &self.change_set_id).map_err(|_| ExecutionPortError)
    }

    fn rollback(&mut self) -> Result<(), ExecutionPortError> {
        request_rollback(&self.rollback_root(), &self.change_set_id)
            .map_err(|_| ExecutionPortError)?;
        let started = Instant::now();
        let wait = Duration::from_secs(self.rollback_timeout_secs.saturating_add(5));
        while started.elapsed() < wait {
            match rollback_outcome(&self.rollback_root(), &self.change_set_id)
                .map_err(|_| ExecutionPortError)?
            {
                RollbackOutcome::Pending => thread::sleep(Duration::from_millis(100)),
                RollbackOutcome::RolledBack => return Ok(()),
                RollbackOutcome::RestoreFailed | RollbackOutcome::ReloadFailed => {
                    return Err(ExecutionPortError);
                }
            }
        }
        Err(ExecutionPortError)
    }

    fn discard_stage(&mut self) {
        if let Some(transaction) = self.transaction.as_mut() {
            transaction.discard_stage();
        }
    }

    fn transition(
        &mut self,
        expected: ChangeSetState,
        next: ChangeSetState,
    ) -> Result<(), ExecutionPortError> {
        self.store
            .transition_change_set(
                &self.change_set_id,
                expected,
                next,
                &self.plan_digest,
                &self.boot_id,
                self.now_monotonic_ms,
            )
            .map(|_| ())
            .map_err(|_| ExecutionPortError)
    }

    fn transition_rollback_armed(
        &mut self,
        deadline_monotonic_ms: u64,
    ) -> Result<(), ExecutionPortError> {
        self.store
            .arm_change_set_rollback(
                &self.change_set_id,
                &self.plan_digest,
                &self.boot_id,
                self.now_monotonic_ms,
                deadline_monotonic_ms,
            )
            .map(|_| ())
            .map_err(|_| ExecutionPortError)
    }
}

fn execution_has_dhcp(execution: &NetworkExecutionPlan) -> bool {
    execution.typed.changes.iter().any(|change| {
        [change.before.as_ref(), change.after.as_ref()]
            .into_iter()
            .flatten()
            .any(|object| {
                matches!(object, agent_protocol::NetworkObject::Interface(value) if value.dhcp_server.is_some())
            })
    })
}

impl GenericRuntimeRouteExecutionPort {
    pub(crate) fn apply(
        config: GenericRuntimeRouteExecutionPortConfig,
    ) -> Result<Self, ExecutionPortError> {
        let transaction = GenericRuntimeRouteTransaction::system(
            config.runner.clone(),
            config.runtime_root.clone(),
            &config.change_set_id,
            &config.boot_id,
            config.canonical_state.clone(),
            config.execution.clone(),
        )
        .map_err(|_| ExecutionPortError)?;
        Ok(Self::new(config, Some(transaction)))
    }

    pub(crate) fn confirmation(config: GenericRuntimeRouteExecutionPortConfig) -> Self {
        Self::new(config, None)
    }

    fn new(
        config: GenericRuntimeRouteExecutionPortConfig,
        transaction: Option<GenericRuntimeRouteTransaction>,
    ) -> Self {
        Self {
            transaction,
            runner: config.runner,
            execution: config.execution,
            canonical_state: config.canonical_state,
            store: config.store,
            runtime_root: config.runtime_root,
            config_path: config.config_path,
            change_set_id: config.change_set_id,
            plan_digest: config.plan_digest,
            boot_id: config.boot_id,
            now_monotonic_ms: config.now_monotonic_ms,
            rollback_timeout_secs: config.rollback_timeout_secs,
            max_rollback_bytes: config.max_rollback_bytes,
            max_state_bytes: config.max_state_bytes,
            confirmation_verified: false,
        }
    }

    fn transaction(&mut self) -> Result<&mut GenericRuntimeRouteTransaction, ExecutionPortError> {
        self.transaction.as_mut().ok_or(ExecutionPortError)
    }

    fn rollback_root(&self) -> PathBuf {
        self.runtime_root.join("rollback")
    }

    fn spawn_helper(&self) -> Result<(), ExecutionPortError> {
        let executable = std::env::current_exe().map_err(|_| ExecutionPortError)?;
        let mut child = Command::new(executable)
            .arg("rollback-helper")
            .arg(&self.change_set_id)
            .arg("--config")
            .arg(&self.config_path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ExecutionPortError)?;
        thread::Builder::new()
            .name("route-rollback-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            })
            .map_err(|_| ExecutionPortError)?;
        Ok(())
    }

    fn restore_canonical(&self) -> Result<(), ExecutionPortError> {
        match runtime_rollback_canonical_state(
            &self.rollback_root(),
            &self.change_set_id,
            self.max_rollback_bytes,
        )
        .map_err(|_| ExecutionPortError)?
        {
            RuntimeCanonicalSnapshot::NetworkPresent(payload) => self
                .store
                .replace_network_runtime_state(&payload, self.max_state_bytes)
                .map_err(|_| ExecutionPortError),
            RuntimeCanonicalSnapshot::NetworkAbsent => self
                .store
                .clear_network_runtime_state()
                .map_err(|_| ExecutionPortError),
            _ => Err(ExecutionPortError),
        }
    }
}

impl ChangeExecutionPort for GenericRuntimeRouteExecutionPort {
    fn reinspect(&mut self) -> Result<(), ExecutionPortError> {
        if self.transaction.is_some() {
            self.transaction()?
                .reinspect()
                .map_err(|_| ExecutionPortError)
        } else {
            let interfaces = self.execution.typed.changes.iter().any(|change| {
                [change.before.as_ref(), change.after.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|object| matches!(object, agent_protocol::NetworkObject::Interface(_)))
            }) || self
                .canonical_state
                .as_deref()
                .map(runtime_canonical_includes_interfaces)
                .is_some_and(|result| result.unwrap_or(true));
            let links = if interfaces {
                Some(
                    self.runner
                        .execute(&FirewallCommand::IpJsonLink, None)
                        .map_err(|_| ExecutionPortError)?
                        .stdout,
                )
            } else {
                None
            };
            let addresses = if interfaces {
                Some(
                    self.runner
                        .execute(&FirewallCommand::IpJsonAddress, None)
                        .map_err(|_| ExecutionPortError)?
                        .stdout,
                )
            } else {
                None
            };
            let routes = self
                .runner
                .execute(&FirewallCommand::IpJsonRoute, None)
                .map_err(|_| ExecutionPortError)?
                .stdout;
            let routes = std::str::from_utf8(&routes).map_err(|_| ExecutionPortError)?;
            let rules = self
                .runner
                .execute(&FirewallCommand::IpJsonRule, None)
                .map_err(|_| ExecutionPortError)?
                .stdout;
            let rules = std::str::from_utf8(&rules).map_err(|_| ExecutionPortError)?;
            let snapshot =
                if let (Some(links), Some(addresses)) = (links.as_deref(), addresses.as_deref()) {
                    reconcile_runtime_network_inventory_with_links(
                        std::str::from_utf8(links).map_err(|_| ExecutionPortError)?,
                        std::str::from_utf8(addresses).map_err(|_| ExecutionPortError)?,
                        routes,
                        rules,
                        self.canonical_state.as_deref(),
                        &self.boot_id,
                    )
                    .map_err(|_| ExecutionPortError)?
                } else {
                    reconcile_runtime_network_inventory(
                        routes,
                        rules,
                        self.canonical_state.as_deref(),
                        &self.boot_id,
                    )
                    .map_err(|_| ExecutionPortError)?
                };
            verify_network_plan_result(snapshot.inventory(), &self.execution.typed)
                .map_err(|_| ExecutionPortError)?;
            self.confirmation_verified = true;
            Ok(())
        }
    }

    fn stage(&mut self) -> Result<(), ExecutionPortError> {
        self.transaction()?.stage().map_err(|_| ExecutionPortError)
    }

    fn validate_stage(&mut self) -> Result<(), ExecutionPortError> {
        self.transaction()?
            .validate_stage()
            .map_err(|_| ExecutionPortError)
    }

    fn arm_rollback(&mut self, _deadline_monotonic_ms: u64) -> Result<(), ExecutionPortError> {
        let batch = self
            .transaction()?
            .rollback_batch()
            .map_err(|_| ExecutionPortError)?;
        create_network_routes_runtime_rollback_bundle(
            &self.rollback_root(),
            &self.change_set_id,
            &batch,
            self.canonical_state.as_deref(),
            self.rollback_timeout_secs,
            self.max_rollback_bytes,
        )
        .map_err(|_| ExecutionPortError)?;
        self.spawn_helper()
    }

    fn activate(&mut self) -> Result<(), ExecutionPortError> {
        self.transaction()?
            .activate_after_rollback_armed()
            .map_err(|_| ExecutionPortError)
    }

    fn verify(&mut self) -> Result<(), ExecutionPortError> {
        if self.transaction.is_some() {
            self.transaction()?
                .verify()
                .map_err(|_| ExecutionPortError)?;
            let canonical = self
                .transaction()?
                .verified_canonical_state()
                .map_err(|_| ExecutionPortError)?
                .to_vec();
            self.store
                .replace_network_runtime_state(&canonical, self.max_state_bytes)
                .map_err(|_| ExecutionPortError)
        } else if self.confirmation_verified {
            Ok(())
        } else {
            Err(ExecutionPortError)
        }
    }

    fn confirm_rollback(&mut self) -> Result<(), ExecutionPortError> {
        confirm_rollback(&self.rollback_root(), &self.change_set_id).map_err(|_| ExecutionPortError)
    }

    fn rollback(&mut self) -> Result<(), ExecutionPortError> {
        request_rollback(&self.rollback_root(), &self.change_set_id)
            .map_err(|_| ExecutionPortError)?;
        let started = Instant::now();
        let wait = Duration::from_secs(self.rollback_timeout_secs.saturating_add(5));
        while started.elapsed() < wait {
            match rollback_outcome(&self.rollback_root(), &self.change_set_id)
                .map_err(|_| ExecutionPortError)?
            {
                RollbackOutcome::Pending => thread::sleep(Duration::from_millis(100)),
                RollbackOutcome::RolledBack => return self.restore_canonical(),
                RollbackOutcome::RestoreFailed | RollbackOutcome::ReloadFailed => {
                    return Err(ExecutionPortError);
                }
            }
        }
        Err(ExecutionPortError)
    }

    fn discard_stage(&mut self) {
        if let Some(transaction) = self.transaction.as_mut() {
            transaction.discard_stage();
        }
    }

    fn transition(
        &mut self,
        expected: ChangeSetState,
        next: ChangeSetState,
    ) -> Result<(), ExecutionPortError> {
        self.store
            .transition_change_set(
                &self.change_set_id,
                expected,
                next,
                &self.plan_digest,
                &self.boot_id,
                self.now_monotonic_ms,
            )
            .map(|_| ())
            .map_err(|_| ExecutionPortError)
    }

    fn transition_rollback_armed(
        &mut self,
        deadline_monotonic_ms: u64,
    ) -> Result<(), ExecutionPortError> {
        self.store
            .arm_change_set_rollback(
                &self.change_set_id,
                &self.plan_digest,
                &self.boot_id,
                self.now_monotonic_ms,
                deadline_monotonic_ms,
            )
            .map(|_| ())
            .map_err(|_| ExecutionPortError)
    }
}
