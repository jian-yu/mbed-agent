use std::collections::HashSet;

use agent_protocol::{
    CHANGE_PLAN_SCHEMA_VERSION, ChangeDiff, ChangeOperation, ChangePlan, ChangeSetState,
    ObjectOwnership, RiskLevel,
};
use ring::digest::{SHA256, digest};
use thiserror::Error;

pub const MAX_CHANGE_OBJECTS: usize = 32;
pub const MAX_CHANGE_CHECKS: usize = 32;
pub const MAX_CHANGE_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CHANGE_KIND_BYTES: usize = 64;
pub const MAX_CHANGE_SUMMARY_BYTES: usize = 512;
pub const MAX_CHANGE_CHECK_BYTES: usize = 256;
pub const MAX_CHANGE_PLAN_BYTES: usize = 65_536;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChangePlanError {
    #[error("change plan schema version is unsupported")]
    UnsupportedSchema,
    #[error("change plan must contain at least one object")]
    EmptyPlan,
    #[error("change plan contains too many objects")]
    TooManyObjects,
    #[error("change plan contains too many validation or verification checks")]
    TooManyChecks,
    #[error("{0} is empty, too long, or contains unsupported characters")]
    InvalidIdentifier(&'static str),
    #[error("{0} is empty or exceeds its byte limit")]
    InvalidText(&'static str),
    #[error("change plan expiration must be after its creation time")]
    InvalidLifetime,
    #[error("change object appears more than once in one plan")]
    DuplicateObject,
    #[error("before/after digest shape does not match the requested operation")]
    InvalidOperationDigests,
    #[error("a content or version digest is not 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("unmanaged objects are read-only")]
    UnmanagedObject,
    #[error("a secret-changing diff is not marked as redacted")]
    SensitiveValueNotRedacted,
    #[error("all configuration changes require an armed rollback path")]
    RollbackRequired,
    #[error("declared risk {declared:?} does not match computed risk {computed:?}")]
    RiskMismatch {
        declared: RiskLevel,
        computed: RiskLevel,
    },
    #[error("failed to encode the canonical change plan")]
    Encode,
    #[error("canonical change plan exceeds its byte limit")]
    PlanTooLarge,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid change-set state transition from {from:?} to {to:?}")]
pub struct ChangeTransitionError {
    pub from: ChangeSetState,
    pub to: ChangeSetState,
}

/// Validates a plan and computes risk exclusively from its typed semantic signals.
///
/// The declared `plan.risk` is deliberately ignored by this function so a caller
/// can compare it with the locally computed value.
///
/// # Errors
///
/// Returns a validation error when the plan exceeds a bound, references an
/// unmanaged object, contains invalid digests, or cannot safely be rolled back.
pub fn assess_plan(plan: &ChangePlan) -> Result<RiskLevel, ChangePlanError> {
    validate_plan_shape(plan)?;
    let mut risk = RiskLevel::R2;
    for change in &plan.changes {
        let signals = change.risk_signals;
        if signals.affects_management_path
            || signals.widens_network_exposure
            || signals.disrupts_service
            || signals.changes_secret
        {
            risk = risk.max(RiskLevel::R3);
        }
        if signals.changes_device_authentication || signals.irreversible {
            risk = RiskLevel::R4;
        }
    }
    Ok(risk)
}

/// Produces a SHA-256 digest of the canonical typed plan.
///
/// The plan uses structs and ordered vectors only, so serde's field order is
/// stable for a fixed schema version. The digest binds actor, boot, lifetime,
/// object versions, semantic diff, checks, and computed risk.
///
/// # Errors
///
/// Returns an error when the plan is invalid, its declared risk was lowered or
/// otherwise changed, or canonical JSON encoding fails.
pub fn plan_digest(plan: &ChangePlan) -> Result<String, ChangePlanError> {
    let computed = assess_plan(plan)?;
    if plan.risk != computed {
        return Err(ChangePlanError::RiskMismatch {
            declared: plan.risk,
            computed,
        });
    }
    let encoded = serde_json::to_vec(plan).map_err(|_| ChangePlanError::Encode)?;
    if encoded.len() > MAX_CHANGE_PLAN_BYTES {
        return Err(ChangePlanError::PlanTooLarge);
    }
    let bytes = digest(&SHA256, &encoded);
    Ok(lower_hex(bytes.as_ref()))
}

/// Applies one locally allowed state transition.
///
/// # Errors
///
/// Returns an error when a caller attempts to skip approval, validation,
/// rollback arming, verification, or a terminal state.
pub fn transition_change_set(
    from: ChangeSetState,
    to: ChangeSetState,
) -> Result<ChangeSetState, ChangeTransitionError> {
    let allowed = matches!(
        (from, to),
        (
            ChangeSetState::Draft,
            ChangeSetState::Planned | ChangeSetState::Rejected
        ) | (
            ChangeSetState::Planned,
            ChangeSetState::AwaitingApproval | ChangeSetState::Rejected | ChangeSetState::Expired
        ) | (
            ChangeSetState::AwaitingApproval,
            ChangeSetState::Approved | ChangeSetState::Rejected | ChangeSetState::Expired
        ) | (
            ChangeSetState::Approved,
            ChangeSetState::Staged | ChangeSetState::Expired
        ) | (
            ChangeSetState::Staged,
            ChangeSetState::Validated | ChangeSetState::ApplyFailed | ChangeSetState::RollingBack
        ) | (
            ChangeSetState::Validated,
            ChangeSetState::RollbackArmed | ChangeSetState::ApplyFailed
        ) | (
            ChangeSetState::RollbackArmed,
            ChangeSetState::Applying | ChangeSetState::RollingBack
        ) | (
            ChangeSetState::Applying,
            ChangeSetState::Verifying | ChangeSetState::ApplyFailed | ChangeSetState::RollingBack
        ) | (
            ChangeSetState::Verifying,
            ChangeSetState::AwaitingConfirmation
                | ChangeSetState::Confirmed
                | ChangeSetState::RollingBack
        ) | (
            ChangeSetState::AwaitingConfirmation,
            ChangeSetState::Confirmed | ChangeSetState::RollingBack
        ) | (ChangeSetState::ApplyFailed, ChangeSetState::RollingBack)
            | (
                ChangeSetState::RollingBack,
                ChangeSetState::RolledBack | ChangeSetState::RollbackFailed
            )
    );
    if allowed {
        Ok(to)
    } else {
        Err(ChangeTransitionError { from, to })
    }
}

fn validate_plan_shape(plan: &ChangePlan) -> Result<(), ChangePlanError> {
    if plan.schema_version != CHANGE_PLAN_SCHEMA_VERSION {
        return Err(ChangePlanError::UnsupportedSchema);
    }
    validate_identifier(&plan.plan_id, "plan_id", MAX_CHANGE_IDENTIFIER_BYTES)?;
    validate_identifier(&plan.boot_id, "boot_id", MAX_CHANGE_IDENTIFIER_BYTES)?;
    validate_identifier(&plan.actor_id, "actor_id", MAX_CHANGE_IDENTIFIER_BYTES)?;
    if plan.expires_monotonic_ms <= plan.created_monotonic_ms {
        return Err(ChangePlanError::InvalidLifetime);
    }
    if plan.changes.is_empty() {
        return Err(ChangePlanError::EmptyPlan);
    }
    if plan.changes.len() > MAX_CHANGE_OBJECTS {
        return Err(ChangePlanError::TooManyObjects);
    }
    if plan.validation_checks.len() > MAX_CHANGE_CHECKS
        || plan.verification_checks.len() > MAX_CHANGE_CHECKS
    {
        return Err(ChangePlanError::TooManyChecks);
    }
    for check in plan
        .validation_checks
        .iter()
        .chain(&plan.verification_checks)
    {
        validate_text(check, "change check", MAX_CHANGE_CHECK_BYTES)?;
    }
    if !plan.rollback_required {
        return Err(ChangePlanError::RollbackRequired);
    }

    let mut objects = HashSet::with_capacity(plan.changes.len());
    for change in &plan.changes {
        validate_change(change)?;
        let key = (
            change.object.domain,
            change.object.kind.as_str(),
            change.object.id.as_str(),
        );
        if !objects.insert(key) {
            return Err(ChangePlanError::DuplicateObject);
        }
    }
    Ok(())
}

fn validate_change(change: &ChangeDiff) -> Result<(), ChangePlanError> {
    validate_identifier(&change.object.kind, "object kind", MAX_CHANGE_KIND_BYTES)?;
    validate_identifier(&change.object.id, "object id", MAX_CHANGE_IDENTIFIER_BYTES)?;
    validate_text(&change.summary, "change summary", MAX_CHANGE_SUMMARY_BYTES)?;
    if change.object.ownership == ObjectOwnership::Unmanaged {
        return Err(ChangePlanError::UnmanagedObject);
    }
    if let Some(version) = &change.object.expected_version {
        validate_digest(version)?;
    }
    match change.operation {
        ChangeOperation::Create
            if change.before_digest.is_none() && change.after_digest.is_some() => {}
        ChangeOperation::Update | ChangeOperation::Move
            if change.before_digest.is_some() && change.after_digest.is_some() => {}
        ChangeOperation::Delete
            if change.before_digest.is_some() && change.after_digest.is_none() => {}
        _ => return Err(ChangePlanError::InvalidOperationDigests),
    }
    if let Some(value) = &change.before_digest {
        validate_digest(value)?;
    }
    if let Some(value) = &change.after_digest {
        validate_digest(value)?;
    }
    if change.risk_signals.changes_secret && !change.sensitive_fields_redacted {
        return Err(ChangePlanError::SensitiveValueNotRedacted);
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ChangePlanError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
    {
        return Err(ChangePlanError::InvalidIdentifier(field));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ChangePlanError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ChangePlanError::InvalidText(field));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ChangePlanError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChangePlanError::InvalidDigest);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::{ChangeRiskSignals, ConfigDomain, ConfigObjectRef, ObjectOwnership};

    const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn change(signals: ChangeRiskSignals) -> ChangeDiff {
        ChangeDiff {
            object: ConfigObjectRef {
                domain: ConfigDomain::Firewall,
                kind: "rule".into(),
                id: "mbed-agent-test".into(),
                expected_version: Some(ZERO_DIGEST.into()),
                ownership: ObjectOwnership::PlatformNative,
            },
            operation: ChangeOperation::Update,
            before_digest: Some(ZERO_DIGEST.into()),
            after_digest: Some(ONE_DIGEST.into()),
            summary: "restrict source network for managed rule".into(),
            sensitive_fields_redacted: true,
            risk_signals: signals,
        }
    }

    fn plan(change: ChangeDiff, risk: RiskLevel) -> ChangePlan {
        ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "plan-1".into(),
            boot_id: "boot-1".into(),
            actor_id: "cli/root".into(),
            created_monotonic_ms: 100,
            expires_monotonic_ms: 200,
            risk,
            changes: vec![change],
            validation_checks: vec!["firewall schema validates".into()],
            verification_checks: vec!["management path remains reachable".into()],
            rollback_required: true,
        }
    }

    #[test]
    fn semantic_signals_only_raise_risk() {
        let local = plan(change(ChangeRiskSignals::default()), RiskLevel::R2);
        assert_eq!(assess_plan(&local), Ok(RiskLevel::R2));

        let exposure = plan(
            change(ChangeRiskSignals {
                widens_network_exposure: true,
                ..ChangeRiskSignals::default()
            }),
            RiskLevel::R3,
        );
        assert_eq!(assess_plan(&exposure), Ok(RiskLevel::R3));

        let authentication = plan(
            change(ChangeRiskSignals {
                changes_device_authentication: true,
                ..ChangeRiskSignals::default()
            }),
            RiskLevel::R4,
        );
        assert_eq!(assess_plan(&authentication), Ok(RiskLevel::R4));
    }

    #[test]
    fn digest_binds_actor_boot_and_semantic_diff() {
        let original = plan(change(ChangeRiskSignals::default()), RiskLevel::R2);
        let digest = plan_digest(&original).expect("digest");
        assert_eq!(digest.len(), 64);
        assert_eq!(plan_digest(&original).expect("stable digest"), digest);

        let mut changed_actor = original.clone();
        changed_actor.actor_id = "mqtt/operator".into();
        assert_ne!(plan_digest(&changed_actor).expect("actor digest"), digest);

        let mut changed_diff = original;
        changed_diff.changes[0].after_digest = Some(ZERO_DIGEST.into());
        assert_ne!(plan_digest(&changed_diff).expect("diff digest"), digest);
    }

    #[test]
    fn declared_risk_cannot_be_lowered() {
        let lowered = plan(
            change(ChangeRiskSignals {
                affects_management_path: true,
                ..ChangeRiskSignals::default()
            }),
            RiskLevel::R2,
        );
        assert_eq!(
            plan_digest(&lowered),
            Err(ChangePlanError::RiskMismatch {
                declared: RiskLevel::R2,
                computed: RiskLevel::R3,
            })
        );
    }

    #[test]
    fn unmanaged_and_unredacted_secret_changes_are_rejected() {
        let mut unmanaged_change = change(ChangeRiskSignals::default());
        unmanaged_change.object.ownership = ObjectOwnership::Unmanaged;
        assert_eq!(
            assess_plan(&plan(unmanaged_change, RiskLevel::R2)),
            Err(ChangePlanError::UnmanagedObject)
        );

        let mut secret_change = change(ChangeRiskSignals {
            changes_secret: true,
            ..ChangeRiskSignals::default()
        });
        secret_change.sensitive_fields_redacted = false;
        assert_eq!(
            assess_plan(&plan(secret_change, RiskLevel::R3)),
            Err(ChangePlanError::SensitiveValueNotRedacted)
        );
    }

    #[test]
    fn operation_digest_shapes_are_enforced() {
        let mut create = change(ChangeRiskSignals::default());
        create.operation = ChangeOperation::Create;
        assert_eq!(
            assess_plan(&plan(create, RiskLevel::R2)),
            Err(ChangePlanError::InvalidOperationDigests)
        );
    }

    #[test]
    fn duplicate_objects_and_capacity_overflow_are_rejected() {
        let duplicate = change(ChangeRiskSignals::default());
        let mut duplicate_plan = plan(duplicate.clone(), RiskLevel::R2);
        duplicate_plan.changes.push(duplicate);
        assert_eq!(
            assess_plan(&duplicate_plan),
            Err(ChangePlanError::DuplicateObject)
        );

        let mut oversized = plan(change(ChangeRiskSignals::default()), RiskLevel::R2);
        oversized.changes = (0..=MAX_CHANGE_OBJECTS)
            .map(|index| {
                let mut item = change(ChangeRiskSignals::default());
                item.object.id = format!("rule-{index}");
                item
            })
            .collect();
        assert_eq!(
            assess_plan(&oversized),
            Err(ChangePlanError::TooManyObjects)
        );
    }

    #[test]
    fn state_machine_cannot_skip_safety_stages() {
        assert_eq!(
            transition_change_set(ChangeSetState::AwaitingApproval, ChangeSetState::Approved),
            Ok(ChangeSetState::Approved)
        );
        assert_eq!(
            transition_change_set(ChangeSetState::Validated, ChangeSetState::Applying),
            Err(ChangeTransitionError {
                from: ChangeSetState::Validated,
                to: ChangeSetState::Applying,
            })
        );
        assert_eq!(
            transition_change_set(ChangeSetState::RollbackArmed, ChangeSetState::Applying),
            Ok(ChangeSetState::Applying)
        );
        assert_eq!(
            transition_change_set(ChangeSetState::RollingBack, ChangeSetState::RolledBack),
            Ok(ChangeSetState::RolledBack)
        );
        assert!(
            transition_change_set(ChangeSetState::RollbackFailed, ChangeSetState::Draft).is_err()
        );
    }
}
