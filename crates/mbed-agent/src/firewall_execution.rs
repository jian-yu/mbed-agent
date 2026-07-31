use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use agent_core::{
    ChangeExecutionPort, ExecutionPortError, FirewallExecutionPlan, RollbackOutcome,
    RollbackReload, RollbackTarget, confirm_rollback, create_nftables_runtime_rollback_bundle,
    create_rollback_bundle, nftables_runtime_rollback_canonical_state, request_rollback,
    rollback_outcome, verify_firewall_plan_result,
};
use agent_protocol::ChangeSetState;
use agent_store::Store;
use platform_linux::FirewallBackend;
use platform_linux::firewall_command::FirewallCommandRunner;
use platform_linux::firewall_nft_execute::GenericNftablesTransaction;
use platform_linux::firewall_openwrt_execute::{
    OpenWrtFirewallTransaction, verify_openwrt_firewall_plan,
};
use platform_linux::firewall_runtime::inspect_generic_nftables_inventory;

pub(crate) struct OpenWrtExecutionPort {
    transaction: Option<OpenWrtFirewallTransaction>,
    confirmation_runner: FirewallCommandRunner,
    execution: FirewallExecutionPlan,
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

pub(crate) struct OpenWrtExecutionPortConfig {
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
    pub(crate) backend: FirewallBackend,
    pub(crate) execution: FirewallExecutionPlan,
}

pub(crate) struct GenericNftablesExecutionPort {
    transaction: Option<GenericNftablesTransaction>,
    confirmation_runner: FirewallCommandRunner,
    execution: FirewallExecutionPlan,
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
    max_firewall_state_bytes: usize,
    confirmation_verified: bool,
}

pub(crate) struct GenericNftablesExecutionPortConfig {
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
    pub(crate) max_firewall_state_bytes: usize,
    pub(crate) canonical_state: Option<Vec<u8>>,
    pub(crate) execution: FirewallExecutionPlan,
}

impl OpenWrtExecutionPort {
    pub(crate) fn apply(config: OpenWrtExecutionPortConfig) -> Result<Self, ExecutionPortError> {
        let transaction = OpenWrtFirewallTransaction::system(
            config.runner.clone(),
            config.runtime_root.clone(),
            &config.change_set_id,
            config.backend,
            config.execution.clone(),
        )
        .map_err(|_| ExecutionPortError)?;
        Ok(Self {
            transaction: Some(transaction),
            confirmation_runner: config.runner,
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
        })
    }

    pub(crate) fn confirmation(config: OpenWrtExecutionPortConfig) -> Self {
        Self {
            transaction: None,
            confirmation_runner: config.runner,
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

    fn transaction(&mut self) -> Result<&mut OpenWrtFirewallTransaction, ExecutionPortError> {
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
            .name("rollback-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            })
            .map_err(|_| ExecutionPortError)?;
        Ok(())
    }
}

impl ChangeExecutionPort for OpenWrtExecutionPort {
    fn reinspect(&mut self) -> Result<(), ExecutionPortError> {
        if self.transaction.is_some() {
            self.transaction()?
                .reinspect()
                .map_err(|_| ExecutionPortError)
        } else {
            verify_openwrt_firewall_plan(&self.confirmation_runner, &self.execution)
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
            &[RollbackTarget::OpenWrtFirewall],
            RollbackReload::OpenWrtFirewall,
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

impl GenericNftablesExecutionPort {
    pub(crate) fn apply(
        config: GenericNftablesExecutionPortConfig,
    ) -> Result<Self, ExecutionPortError> {
        let transaction = GenericNftablesTransaction::system(
            config.runner.clone(),
            config.runtime_root.clone(),
            &config.change_set_id,
            &config.boot_id,
            config.canonical_state.clone(),
            config.execution.clone(),
        )
        .map_err(|_| ExecutionPortError)?;
        Ok(Self::from_config(config, Some(transaction)))
    }

    pub(crate) fn confirmation(config: GenericNftablesExecutionPortConfig) -> Self {
        Self::from_config(config, None)
    }

    fn from_config(
        config: GenericNftablesExecutionPortConfig,
        transaction: Option<GenericNftablesTransaction>,
    ) -> Self {
        Self {
            transaction,
            confirmation_runner: config.runner,
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
            max_firewall_state_bytes: config.max_firewall_state_bytes,
            confirmation_verified: false,
        }
    }

    fn transaction(&mut self) -> Result<&mut GenericNftablesTransaction, ExecutionPortError> {
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
            .name("rollback-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            })
            .map_err(|_| ExecutionPortError)?;
        Ok(())
    }

    fn restore_canonical_state(&self) -> Result<(), ExecutionPortError> {
        match nftables_runtime_rollback_canonical_state(
            &self.rollback_root(),
            &self.change_set_id,
            self.max_rollback_bytes,
        )
        .map_err(|_| ExecutionPortError)?
        {
            agent_core::RuntimeCanonicalSnapshot::Present(payload) => self
                .store
                .replace_firewall_runtime_state(&payload, self.max_firewall_state_bytes)
                .map_err(|_| ExecutionPortError),
            agent_core::RuntimeCanonicalSnapshot::Absent => self
                .store
                .clear_firewall_runtime_state()
                .map_err(|_| ExecutionPortError),
            agent_core::RuntimeCanonicalSnapshot::NotRuntime => Err(ExecutionPortError),
        }
    }
}

impl ChangeExecutionPort for GenericNftablesExecutionPort {
    fn reinspect(&mut self) -> Result<(), ExecutionPortError> {
        if self.transaction.is_some() {
            self.transaction()?
                .reinspect()
                .map_err(|_| ExecutionPortError)
        } else {
            let snapshot = inspect_generic_nftables_inventory(
                &self.confirmation_runner,
                self.canonical_state.as_deref(),
                &self.boot_id,
            )
            .map_err(|_| ExecutionPortError)?;
            verify_firewall_plan_result(snapshot.inventory(), &self.execution.typed)
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
        let ruleset = self
            .transaction()?
            .rollback_ruleset()
            .map_err(|_| ExecutionPortError)?;
        let prior_table_existed = self
            .transaction()?
            .rollback_table_existed()
            .map_err(|_| ExecutionPortError)?;
        create_nftables_runtime_rollback_bundle(
            &self.rollback_root(),
            &self.change_set_id,
            &ruleset,
            prior_table_existed,
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
            let payload = self
                .transaction()?
                .verified_canonical_state()
                .map_err(|_| ExecutionPortError)?
                .to_vec();
            self.store
                .replace_firewall_runtime_state(&payload, self.max_firewall_state_bytes)
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
                RollbackOutcome::RolledBack => return self.restore_canonical_state(),
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
