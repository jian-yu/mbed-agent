//! Stateful dual-stack iptables transaction for generic Linux.

use agent_core::FirewallExecutionPlan;
use thiserror::Error;

use crate::firewall_command::{
    FirewallCommand, FirewallCommandError, FirewallCommandExecutor, FirewallCommandRunner,
};
use crate::firewall_iptables::{
    IptablesFamilyRollback, IptablesFirewallStage, render_iptables_family_rollback,
};
use crate::firewall_runtime::{
    CollectedIptablesObservation, GenericFirewallInventorySnapshot, GenericFirewallObservation,
    GenericFirewallStateError, collect_iptables_observation, encode_applied_generic_firewall_state,
    reconcile_iptables_observation, render_iptables_stage_from_snapshot,
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

/// One generic Linux iptables/ip6tables transaction.
///
/// Activation remains private to callers that have already armed a dual-family independent
/// rollback helper. Both restore artifacts are validated before either family is changed.
pub struct GenericIptablesTransaction<R = FirewallCommandRunner> {
    runner: R,
    boot_id: String,
    canonical_state: Option<Vec<u8>>,
    execution: FirewallExecutionPlan,
    state: TransactionState,
    source_observation: Option<CollectedIptablesObservation>,
    snapshot: Option<GenericFirewallInventorySnapshot>,
    stage: Option<IptablesFirewallStage>,
    applied_canonical_state: Option<Vec<u8>>,
}

impl GenericIptablesTransaction<FirewallCommandRunner> {
    /// Creates a system transaction from a bounded closed command runner.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid boot identifier or execution plan.
    pub fn system(
        runner: FirewallCommandRunner,
        boot_id: &str,
        canonical_state: Option<Vec<u8>>,
        execution: FirewallExecutionPlan,
    ) -> Result<Self, GenericIptablesExecutionError> {
        Self::new(runner, boot_id, canonical_state, execution)
    }
}

impl<R: FirewallCommandExecutor> GenericIptablesTransaction<R> {
    fn new(
        runner: R,
        boot_id: &str,
        canonical_state: Option<Vec<u8>>,
        execution: FirewallExecutionPlan,
    ) -> Result<Self, GenericIptablesExecutionError> {
        if boot_id.is_empty()
            || boot_id.len() > 128
            || !boot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(GenericIptablesExecutionError::InvalidIdentity);
        }
        execution
            .validate()
            .map_err(|_| GenericIptablesExecutionError::InvalidPlan)?;
        Ok(Self {
            runner,
            boot_id: boot_id.into(),
            canonical_state,
            execution,
            state: TransactionState::New,
            source_observation: None,
            snapshot: None,
            stage: None,
            applied_canonical_state: None,
        })
    }

    /// Reconciles one paired IPv4/IPv6 observation with volatile canonical state.
    ///
    /// # Errors
    ///
    /// Returns an error for command failure, partial ownership, stale state, or native drift.
    pub fn reinspect(&mut self) -> Result<(), GenericIptablesExecutionError> {
        self.require_state(TransactionState::New)?;
        let observation = collect_iptables_observation(&self.runner)?;
        let snapshot = reconcile_iptables_observation(
            self.canonical_state.as_deref(),
            &self.boot_id,
            &observation,
        )?;
        self.source_observation = Some(observation);
        self.snapshot = Some(snapshot);
        self.state = TransactionState::Inspected;
        Ok(())
    }

    /// Renders both bounded no-flush restore artifacts from the reconciled snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state or unsupported typed mutation.
    pub fn stage(&mut self) -> Result<(), GenericIptablesExecutionError> {
        self.require_state(TransactionState::Inspected)?;
        self.stage = Some(render_iptables_stage_from_snapshot(
            self.snapshot
                .as_ref()
                .ok_or(GenericIptablesExecutionError::InvalidState)?,
            &self.execution.typed,
        )?);
        self.state = TransactionState::Staged;
        Ok(())
    }

    /// Runs native `--test --noflush` validation for both families before activation.
    ///
    /// # Errors
    ///
    /// Returns an error if either family rejects its exact staged artifact.
    pub fn validate_stage(&mut self) -> Result<(), GenericIptablesExecutionError> {
        self.require_state(TransactionState::Staged)?;
        let stage = self
            .stage
            .as_ref()
            .ok_or(GenericIptablesExecutionError::InvalidState)?;
        self.runner.execute(
            &FirewallCommand::IptablesRestoreTest { ipv6: false },
            Some(stage.ipv4_restore.as_bytes()),
        )?;
        self.runner.execute(
            &FirewallCommand::IptablesRestoreTest { ipv6: true },
            Some(stage.ipv6_restore.as_bytes()),
        )?;
        self.state = TransactionState::Validated;
        Ok(())
    }

    /// Rechecks both owned-family fingerprints, then loads IPv4 followed by IPv6.
    ///
    /// The caller must arm an independent rollback path before invoking this method. Failure of
    /// the second load is a partial-activation failure and must recover both families.
    ///
    /// # Errors
    ///
    /// Returns an error for source drift or either native restore failure.
    pub fn activate_after_rollback_armed(&mut self) -> Result<(), GenericIptablesExecutionError> {
        self.require_state(TransactionState::Validated)?;
        let fresh = collect_iptables_observation(&self.runner)?;
        let fresh_snapshot =
            reconcile_iptables_observation(self.canonical_state.as_deref(), &self.boot_id, &fresh)?;
        if self.snapshot.as_ref() != Some(&fresh_snapshot) {
            return Err(GenericIptablesExecutionError::SourceDrift);
        }
        let stage = self
            .stage
            .as_ref()
            .ok_or(GenericIptablesExecutionError::InvalidState)?;
        self.runner.execute(
            &FirewallCommand::IptablesRestore { ipv6: false },
            Some(stage.ipv4_restore.as_bytes()),
        )?;
        self.runner.execute(
            &FirewallCommand::IptablesRestore { ipv6: true },
            Some(stage.ipv6_restore.as_bytes()),
        )?;
        self.state = TransactionState::Activated;
        Ok(())
    }

    /// Verifies both live families and builds the next boot-bound canonical payload.
    ///
    /// # Errors
    ///
    /// Returns an error for partial application, native drift, or canonical encoding failure.
    pub fn verify(&mut self) -> Result<(), GenericIptablesExecutionError> {
        self.require_state(TransactionState::Activated)?;
        let observation = collect_iptables_observation(&self.runner)?;
        let encoded = encode_applied_generic_firewall_state(
            self.snapshot
                .as_ref()
                .ok_or(GenericIptablesExecutionError::InvalidState)?,
            &self.execution.typed,
            &self.boot_id,
            GenericFirewallObservation::Iptables {
                ipv4_save: observation.ipv4_save(),
                ipv6_save: observation.ipv6_save(),
            },
        )?;
        self.applied_canonical_state = Some(encoded);
        self.state = TransactionState::Verified;
        Ok(())
    }

    /// Returns the verified canonical payload for atomic `SQLite` replacement.
    ///
    /// # Errors
    ///
    /// Returns an error until both families have been verified.
    pub fn verified_canonical_state(&self) -> Result<&[u8], GenericIptablesExecutionError> {
        if self.state != TransactionState::Verified {
            return Err(GenericIptablesExecutionError::InvalidState);
        }
        self.applied_canonical_state
            .as_deref()
            .ok_or(GenericIptablesExecutionError::InvalidState)
    }

    /// Returns the paired pre-activation saves for independent rollback rendering.
    ///
    /// # Errors
    ///
    /// Returns an error before reinspection or after an invalid state transition.
    pub fn source_observation(
        &self,
    ) -> Result<&CollectedIptablesObservation, GenericIptablesExecutionError> {
        if self.state == TransactionState::New {
            return Err(GenericIptablesExecutionError::InvalidState);
        }
        self.source_observation
            .as_ref()
            .ok_or(GenericIptablesExecutionError::InvalidState)
    }

    /// Renders conditional rollback artifacts for both freshly inspected source families.
    ///
    /// # Errors
    ///
    /// Returns an error before reinspection or if either source save is no longer safely
    /// representable as owned-only recovery input.
    pub fn rollback_artifacts(
        &self,
    ) -> Result<(IptablesFamilyRollback, IptablesFamilyRollback), GenericIptablesExecutionError>
    {
        let source = self.source_observation()?;
        Ok((
            render_iptables_family_rollback(source.ipv4_save())
                .map_err(GenericFirewallStateError::from)?,
            render_iptables_family_rollback(source.ipv6_save())
                .map_err(GenericFirewallStateError::from)?,
        ))
    }

    pub fn discard_stage(&mut self) {
        self.stage = None;
    }

    fn require_state(
        &self,
        expected: TransactionState,
    ) -> Result<(), GenericIptablesExecutionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(GenericIptablesExecutionError::InvalidState)
        }
    }
}

#[derive(Debug, Error)]
pub enum GenericIptablesExecutionError {
    #[error("generic iptables transaction identity is invalid")]
    InvalidIdentity,
    #[error("generic iptables execution plan is invalid")]
    InvalidPlan,
    #[error("generic iptables transaction state is invalid")]
    InvalidState,
    #[error("generic iptables source state changed before activation")]
    SourceDrift,
    #[error("generic firewall state failed: {0}")]
    State(#[from] GenericFirewallStateError),
    #[error("generic iptables native command failed: {0}")]
    Command(#[from] FirewallCommandError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

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
    use crate::firewall_runtime::inspect_generic_iptables_inventory;

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const OWNED_SAVE: &str = "*filter\n:MBED_INPUT - [0:0]\n-A INPUT -m comment --comment mbed-agent-owned:v1:input -j MBED_INPUT\n:MBED_OUTPUT - [0:0]\n-A OUTPUT -m comment --comment mbed-agent-owned:v1:output -j MBED_OUTPUT\n:MBED_FORWARD - [0:0]\n-A FORWARD -m comment --comment mbed-agent-owned:v1:forward -j MBED_FORWARD\nCOMMIT\n*mangle\n:MBED_MANGLE_FORWARD - [0:0]\n-A FORWARD -m comment --comment mbed-agent-owned:v1:mangle-forward -j MBED_MANGLE_FORWARD\nCOMMIT\n*nat\n:MBED_PREROUTING - [0:0]\n-A PREROUTING -m comment --comment mbed-agent-owned:v1:prerouting -j MBED_PREROUTING\n:MBED_POSTROUTING - [0:0]\n-A POSTROUTING -m comment --comment mbed-agent-owned:v1:postrouting -j MBED_POSTROUTING\nCOMMIT\n";

    struct MockIptables {
        ipv4_owned: Cell<bool>,
        ipv6_owned: Cell<bool>,
        ipv4_validated: Cell<bool>,
        ipv6_validated: Cell<bool>,
        fail_ipv6_load: Cell<bool>,
    }

    impl MockIptables {
        fn output(value: &str) -> FirewallCommandOutput {
            FirewallCommandOutput {
                stdout: value.as_bytes().to_vec(),
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            }
        }

        fn save(&self, ipv6: bool) -> FirewallCommandOutput {
            if if ipv6 {
                self.ipv6_owned.get()
            } else {
                self.ipv4_owned.get()
            } {
                Self::output(OWNED_SAVE)
            } else {
                Self::output("")
            }
        }
    }

    impl FirewallCommandExecutor for MockIptables {
        fn execute(
            &self,
            operation: &FirewallCommand,
            stdin: Option<&[u8]>,
        ) -> Result<FirewallCommandOutput, FirewallCommandError> {
            match operation {
                FirewallCommand::IptablesSave { ipv6 } => Ok(self.save(*ipv6)),
                FirewallCommand::IptablesRestoreTest { ipv6 } => {
                    let input = stdin.ok_or(FirewallCommandError::UnexpectedInput)?;
                    if !input.windows(16).any(|value| value == b":MBED_INPUT - [0") {
                        return Err(FirewallCommandError::Unsuccessful);
                    }
                    if *ipv6 {
                        self.ipv6_validated.set(true);
                    } else {
                        self.ipv4_validated.set(true);
                    }
                    Ok(Self::output(""))
                }
                FirewallCommand::IptablesRestore { ipv6: false }
                    if self.ipv4_validated.get() && stdin.is_some() =>
                {
                    self.ipv4_owned.set(true);
                    Ok(Self::output(""))
                }
                FirewallCommand::IptablesRestore { ipv6: true }
                    if self.ipv6_validated.get()
                        && stdin.is_some()
                        && !self.fail_ipv6_load.get() =>
                {
                    self.ipv6_owned.set(true);
                    Ok(Self::output(""))
                }
                FirewallCommand::IptablesRestore { ipv6: true } => {
                    Err(FirewallCommandError::Unsuccessful)
                }
                _ => Err(FirewallCommandError::UnexpectedInput),
            }
        }
    }

    #[test]
    fn validates_both_families_before_loading_and_encodes_verified_state() {
        let runner = MockIptables {
            ipv4_owned: Cell::new(false),
            ipv6_owned: Cell::new(false),
            ipv4_validated: Cell::new(false),
            ipv6_validated: Cell::new(false),
            fail_ipv6_load: Cell::new(false),
        };
        let mut transaction =
            GenericIptablesTransaction::new(runner, BOOT_ID, None, execution_plan())
                .expect("transaction");
        transaction.reinspect().expect("reinspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate both");
        transaction
            .activate_after_rollback_armed()
            .expect("activate both");
        transaction.verify().expect("verify both");
        let canonical = transaction.verified_canonical_state().expect("canonical");
        let reconciled =
            inspect_generic_iptables_inventory(&transaction.runner, Some(canonical), BOOT_ID)
                .expect("reconcile");
        assert_eq!(reconciled.inventory().objects.len(), 1);
    }

    #[test]
    fn second_family_failure_exposes_partial_activation_for_external_rollback() {
        let runner = MockIptables {
            ipv4_owned: Cell::new(false),
            ipv6_owned: Cell::new(false),
            ipv4_validated: Cell::new(false),
            ipv6_validated: Cell::new(false),
            fail_ipv6_load: Cell::new(true),
        };
        let mut transaction =
            GenericIptablesTransaction::new(runner, BOOT_ID, None, execution_plan())
                .expect("transaction");
        transaction.reinspect().expect("reinspect");
        transaction.stage().expect("stage");
        transaction.validate_stage().expect("validate both");
        assert!(matches!(
            transaction.activate_after_rollback_armed(),
            Err(GenericIptablesExecutionError::Command(_))
        ));
        assert!(transaction.runner.ipv4_owned.get());
        assert!(!transaction.runner.ipv6_owned.get());
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
        .expect("plan");
        let preview = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "iptables-preview".into(),
            boot_id: BOOT_ID.into(),
            actor_id: "cli/local".into(),
            created_monotonic_ms: 1,
            expires_monotonic_ms: 100,
            risk: typed.risk,
            changes: typed
                .changes
                .iter()
                .map(|change| change.diff.clone())
                .collect(),
            validation_checks: vec!["iptables dual-stack restore test".into()],
            verification_checks: vec!["iptables dual-stack live verify".into()],
            rollback_required: true,
        };
        FirewallExecutionPlan {
            schema_version: FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION,
            preview,
            typed,
        }
    }
}
