//! Fail-closed configuration execution sequencing.

use agent_protocol::ChangeSetState;
use thiserror::Error;

/// Fixed operations supplied by a typed platform adapter and volatile state store.
#[allow(clippy::missing_errors_doc)] // Every adapter method has the same opaque fail-closed error.
pub trait ChangeExecutionPort {
    fn reinspect(&mut self) -> Result<(), ExecutionPortError>;
    fn stage(&mut self) -> Result<(), ExecutionPortError>;
    fn validate_stage(&mut self) -> Result<(), ExecutionPortError>;
    fn arm_rollback(&mut self, deadline_monotonic_ms: u64) -> Result<(), ExecutionPortError>;
    fn activate(&mut self) -> Result<(), ExecutionPortError>;
    fn verify(&mut self) -> Result<(), ExecutionPortError>;
    fn confirm_rollback(&mut self) -> Result<(), ExecutionPortError>;
    fn rollback(&mut self) -> Result<(), ExecutionPortError>;
    fn discard_stage(&mut self);
    fn transition(
        &mut self,
        expected: ChangeSetState,
        next: ChangeSetState,
    ) -> Result<(), ExecutionPortError>;
    fn transition_rollback_armed(
        &mut self,
        deadline_monotonic_ms: u64,
    ) -> Result<(), ExecutionPortError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    AwaitingConfirmation,
    Confirmed,
}

/// Executes an approved change in the only permitted safety order.
///
/// # Errors
///
/// Returns a closed stage error. Every failure after rollback arming attempts recovery.
pub fn execute_approved_change(
    port: &mut impl ChangeExecutionPort,
    now_monotonic_ms: u64,
    rollback_deadline_monotonic_ms: u64,
    confirmation_required: bool,
) -> Result<ExecutionOutcome, ChangeExecutionError> {
    if rollback_deadline_monotonic_ms <= now_monotonic_ms {
        return Err(ChangeExecutionError::InvalidDeadline);
    }
    port.reinspect()
        .map_err(|_| ChangeExecutionError::Failed(ExecutionStage::Reinspect))?;
    if port.stage().is_err() {
        port.discard_stage();
        return Err(ChangeExecutionError::Failed(ExecutionStage::Stage));
    }
    transition_or_discard(port, ChangeSetState::Approved, ChangeSetState::Staged)?;
    if port.validate_stage().is_err() {
        port.discard_stage();
        record_preapply_terminal(port, ChangeSetState::Staged);
        return Err(ChangeExecutionError::Failed(ExecutionStage::Validate));
    }
    transition_or_discard(port, ChangeSetState::Staged, ChangeSetState::Validated)?;
    if port.arm_rollback(rollback_deadline_monotonic_ms).is_err() {
        port.discard_stage();
        record_preapply_terminal(port, ChangeSetState::Validated);
        return Err(ChangeExecutionError::Failed(ExecutionStage::ArmRollback));
    }
    if port
        .transition_rollback_armed(rollback_deadline_monotonic_ms)
        .is_err()
    {
        return Err(rollback_after(
            port,
            ChangeSetState::Validated,
            ExecutionStage::RecordRollbackArmed,
        ));
    }
    transition_or_rollback(
        port,
        ChangeSetState::RollbackArmed,
        ChangeSetState::Applying,
        ExecutionStage::RecordApplying,
    )?;
    if port.activate().is_err() {
        return Err(rollback_after(
            port,
            ChangeSetState::Applying,
            ExecutionStage::Activate,
        ));
    }
    transition_or_rollback(
        port,
        ChangeSetState::Applying,
        ChangeSetState::Verifying,
        ExecutionStage::RecordVerifying,
    )?;
    if port.verify().is_err() {
        return Err(rollback_after(
            port,
            ChangeSetState::Verifying,
            ExecutionStage::Verify,
        ));
    }
    if confirmation_required {
        transition_or_rollback(
            port,
            ChangeSetState::Verifying,
            ChangeSetState::AwaitingConfirmation,
            ExecutionStage::RecordAwaitingConfirmation,
        )?;
        Ok(ExecutionOutcome::AwaitingConfirmation)
    } else {
        confirm_from(port, ChangeSetState::Verifying)?;
        Ok(ExecutionOutcome::Confirmed)
    }
}

/// Re-verifies an awaiting change before disarming its watchdog.
///
/// # Errors
///
/// Verification failure triggers rollback; watchdog confirmation failure remains retryable.
pub fn confirm_awaiting_execution(
    port: &mut impl ChangeExecutionPort,
) -> Result<ExecutionOutcome, ChangeExecutionError> {
    if port.reinspect().is_err() || port.verify().is_err() {
        return Err(rollback_after(
            port,
            ChangeSetState::AwaitingConfirmation,
            ExecutionStage::VerifyConfirmation,
        ));
    }
    confirm_from(port, ChangeSetState::AwaitingConfirmation)?;
    Ok(ExecutionOutcome::Confirmed)
}

/// Rolls back an awaiting change after a post-apply business probe failed.
///
/// The rollback uses the same armed helper and state transitions as native
/// verification failures. This keeps an active connectivity failure from
/// being reported as a normal confirmation opportunity.
///
/// # Errors
///
/// Returns a rollback outcome error; the port has already attempted recovery.
pub fn rollback_after_post_apply_probe(
    port: &mut impl ChangeExecutionPort,
) -> Result<(), ChangeExecutionError> {
    Err(rollback_after(
        port,
        ChangeSetState::AwaitingConfirmation,
        ExecutionStage::PostApplyProbe,
    ))
}

fn transition_or_discard(
    port: &mut impl ChangeExecutionPort,
    expected: ChangeSetState,
    next: ChangeSetState,
) -> Result<(), ChangeExecutionError> {
    if port.transition(expected, next).is_err() {
        port.discard_stage();
        Err(ChangeExecutionError::Failed(match next {
            ChangeSetState::Staged => ExecutionStage::RecordStaged,
            _ => ExecutionStage::RecordValidated,
        }))
    } else {
        Ok(())
    }
}

fn transition_or_rollback(
    port: &mut impl ChangeExecutionPort,
    expected: ChangeSetState,
    next: ChangeSetState,
    stage: ExecutionStage,
) -> Result<(), ChangeExecutionError> {
    port.transition(expected, next)
        .map_err(|_| rollback_after(port, expected, stage))
}

fn confirm_from(
    port: &mut impl ChangeExecutionPort,
    state: ChangeSetState,
) -> Result<(), ChangeExecutionError> {
    port.confirm_rollback()
        .map_err(|_| ChangeExecutionError::Failed(ExecutionStage::ConfirmRollback))?;
    port.transition(state, ChangeSetState::Confirmed)
        .map_err(|_| ChangeExecutionError::Failed(ExecutionStage::RecordConfirmed))
}

fn record_preapply_terminal(port: &mut impl ChangeExecutionPort, state: ChangeSetState) {
    if port.transition(state, ChangeSetState::ApplyFailed).is_ok()
        && port
            .transition(ChangeSetState::ApplyFailed, ChangeSetState::RollingBack)
            .is_ok()
    {
        let _ = port.transition(ChangeSetState::RollingBack, ChangeSetState::RolledBack);
    }
}

fn rollback_after(
    port: &mut impl ChangeExecutionPort,
    state: ChangeSetState,
    failed: ExecutionStage,
) -> ChangeExecutionError {
    let recorded = port.transition(state, ChangeSetState::RollingBack).is_ok();
    if !recorded || port.rollback().is_err() {
        let _ = port.transition(ChangeSetState::RollingBack, ChangeSetState::RollbackFailed);
        ChangeExecutionError::RollbackFailed(failed)
    } else {
        let _ = port.transition(ChangeSetState::RollingBack, ChangeSetState::RolledBack);
        ChangeExecutionError::RolledBack(failed)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("typed execution port operation failed")]
pub struct ExecutionPortError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStage {
    Reinspect,
    Stage,
    RecordStaged,
    Validate,
    RecordValidated,
    ArmRollback,
    RecordRollbackArmed,
    RecordApplying,
    Activate,
    RecordVerifying,
    Verify,
    RecordAwaitingConfirmation,
    VerifyConfirmation,
    PostApplyProbe,
    ConfirmRollback,
    RecordConfirmed,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChangeExecutionError {
    #[error("rollback deadline must be in the future")]
    InvalidDeadline,
    #[error("change execution failed at {0:?}")]
    Failed(ExecutionStage),
    #[error("change execution failed at {0:?} and was rolled back")]
    RolledBack(ExecutionStage),
    #[error("change execution failed at {0:?} and rollback failed")]
    RollbackFailed(ExecutionStage),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePort {
        calls: Vec<&'static str>,
        state: ChangeSetState,
        fail: Option<&'static str>,
    }

    impl FakePort {
        fn op(&mut self, name: &'static str) -> Result<(), ExecutionPortError> {
            self.calls.push(name);
            (self.fail != Some(name))
                .then_some(())
                .ok_or(ExecutionPortError)
        }
    }

    impl ChangeExecutionPort for FakePort {
        fn reinspect(&mut self) -> Result<(), ExecutionPortError> {
            self.op("reinspect")
        }
        fn stage(&mut self) -> Result<(), ExecutionPortError> {
            self.op("stage")
        }
        fn validate_stage(&mut self) -> Result<(), ExecutionPortError> {
            self.op("validate")
        }
        fn arm_rollback(&mut self, _: u64) -> Result<(), ExecutionPortError> {
            self.op("arm")
        }
        fn activate(&mut self) -> Result<(), ExecutionPortError> {
            self.op("activate")
        }
        fn verify(&mut self) -> Result<(), ExecutionPortError> {
            self.op("verify")
        }
        fn confirm_rollback(&mut self) -> Result<(), ExecutionPortError> {
            self.op("confirm")
        }
        fn rollback(&mut self) -> Result<(), ExecutionPortError> {
            self.op("rollback")
        }
        fn discard_stage(&mut self) {
            self.calls.push("discard");
        }
        fn transition(
            &mut self,
            expected: ChangeSetState,
            next: ChangeSetState,
        ) -> Result<(), ExecutionPortError> {
            self.calls.push(next.as_str());
            if self.state != expected || self.fail == Some(next.as_str()) {
                return Err(ExecutionPortError);
            }
            self.state = next;
            Ok(())
        }
        fn transition_rollback_armed(&mut self, _: u64) -> Result<(), ExecutionPortError> {
            self.transition(ChangeSetState::Validated, ChangeSetState::RollbackArmed)
        }
    }

    fn port(fail: Option<&'static str>) -> FakePort {
        FakePort {
            calls: Vec::new(),
            state: ChangeSetState::Approved,
            fail,
        }
    }

    #[test]
    fn activation_follows_validation_and_rollback_arming() {
        let mut port = port(None);
        assert_eq!(
            execute_approved_change(&mut port, 1, 10, true),
            Ok(ExecutionOutcome::AwaitingConfirmation)
        );
        assert_eq!(port.state, ChangeSetState::AwaitingConfirmation);
        assert!(
            port.calls.iter().position(|v| *v == "arm")
                < port.calls.iter().position(|v| *v == "activate")
        );
    }

    #[test]
    fn activation_failure_rolls_back() {
        let mut port = port(Some("activate"));
        assert_eq!(
            execute_approved_change(&mut port, 1, 10, false),
            Err(ChangeExecutionError::RolledBack(ExecutionStage::Activate))
        );
        assert_eq!(port.state, ChangeSetState::RolledBack);
    }

    #[test]
    fn validation_failure_never_arms_or_activates() {
        let mut port = port(Some("validate"));
        assert_eq!(
            execute_approved_change(&mut port, 1, 10, false),
            Err(ChangeExecutionError::Failed(ExecutionStage::Validate))
        );
        assert!(!port.calls.contains(&"arm"));
        assert!(!port.calls.contains(&"activate"));
    }

    #[test]
    fn partial_staging_is_discarded() {
        let mut port = port(Some("stage"));
        assert_eq!(
            execute_approved_change(&mut port, 1, 10, false),
            Err(ChangeExecutionError::Failed(ExecutionStage::Stage))
        );
        assert_eq!(port.calls, ["reinspect", "stage", "discard"]);
        assert_eq!(port.state, ChangeSetState::Approved);
    }

    #[test]
    fn failed_post_apply_probe_rolls_back_an_awaiting_change() {
        let mut port = port(None);
        assert_eq!(
            execute_approved_change(&mut port, 1, 10, true),
            Ok(ExecutionOutcome::AwaitingConfirmation)
        );
        assert_eq!(
            rollback_after_post_apply_probe(&mut port),
            Err(ChangeExecutionError::RolledBack(
                ExecutionStage::PostApplyProbe
            ))
        );
        assert_eq!(port.state, ChangeSetState::RolledBack);
    }
}
