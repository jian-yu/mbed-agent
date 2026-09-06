use std::collections::{HashMap, HashSet};

use agent_protocol::{
    ChangeDiff, ChangeOperation, ChangePlan, ChangeRiskSignals, ConfigDomain, ConfigObjectRef,
    ObjectOwnership, RiskLevel, WirelessBand, WirelessChannel, WirelessChannelWidth,
    WirelessObject,
};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_OBJECTS: usize = 64;
const MAX_MUTATIONS: usize = 16;
const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_EXECUTION_PLAN_BYTES: usize = 64 * 1024;
pub const WIRELESS_EXECUTION_PLAN_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirelessInventory {
    pub objects: Vec<WirelessObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WirelessMutation {
    Update {
        expected_digest: String,
        desired: WirelessObject,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WirelessRiskContext {
    pub management_radio_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirelessPlannedChange {
    pub before: WirelessObject,
    pub after: WirelessObject,
    pub diff: ChangeDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirelessMutationPlan {
    pub risk: RiskLevel,
    pub changes: Vec<WirelessPlannedChange>,
}

/// Stored executable payload paired with the exact user-visible plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WirelessExecutionPlan {
    pub schema_version: u16,
    pub preview: ChangePlan,
    pub typed: WirelessMutationPlan,
}

impl WirelessExecutionPlan {
    /// Revalidates every typed radio update and its public preview.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, invalid preview, forged digest,
    /// invalid radio object, or capacity overflow.
    pub fn validate(&self) -> Result<(), WirelessExecutionPlanError> {
        if self.schema_version != WIRELESS_EXECUTION_PLAN_SCHEMA_VERSION {
            return Err(WirelessExecutionPlanError::UnsupportedSchema);
        }
        crate::plan_digest(&self.preview)
            .map_err(|_| WirelessExecutionPlanError::InvalidPreview)?;
        if self.preview.risk != self.typed.risk
            || self.preview.changes.len() != self.typed.changes.len()
            || self.typed.changes.is_empty()
            || self.typed.changes.len() > MAX_MUTATIONS
        {
            return Err(WirelessExecutionPlanError::PlanMismatch);
        }
        for (preview, typed) in self.preview.changes.iter().zip(&self.typed.changes) {
            validate_execution_change(preview, typed)?;
        }
        let encoded = serde_json::to_vec(self).map_err(|_| WirelessExecutionPlanError::Encode)?;
        if encoded.len() > MAX_EXECUTION_PLAN_BYTES {
            return Err(WirelessExecutionPlanError::Capacity);
        }
        Ok(())
    }

    /// Encodes a bounded, fully validated wireless execution payload.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, WirelessExecutionPlanError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| WirelessExecutionPlanError::Encode)
    }

    /// Decodes and revalidates a bounded wireless execution payload.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, or inconsistent input.
    pub fn decode(encoded: &[u8]) -> Result<Self, WirelessExecutionPlanError> {
        if encoded.is_empty() || encoded.len() > MAX_EXECUTION_PLAN_BYTES {
            return Err(WirelessExecutionPlanError::Capacity);
        }
        let plan: Self =
            serde_json::from_slice(encoded).map_err(|_| WirelessExecutionPlanError::Decode)?;
        plan.validate()?;
        Ok(plan)
    }
}

/// Plans strict updates to radios already present in a fresh inventory.
///
/// The initial slice deliberately rejects create/delete/move and non-native radios.
/// Every accepted update is R3 because radio reconfiguration disrupts service.
///
/// # Errors
///
/// Returns an error for malformed inventories, stale versions, duplicate updates,
/// ownership changes, no-op mutations, or capacity overflow.
pub fn plan_wireless_mutations(
    inventory: &WirelessInventory,
    mutations: &[WirelessMutation],
    context: &WirelessRiskContext,
) -> Result<WirelessMutationPlan, WirelessPlanError> {
    if inventory.objects.len() > MAX_OBJECTS
        || mutations.is_empty()
        || mutations.len() > MAX_MUTATIONS
        || context.management_radio_ids.len() > MAX_OBJECTS
    {
        return Err(WirelessPlanError::Capacity);
    }
    let mut management = HashSet::with_capacity(context.management_radio_ids.len());
    for id in &context.management_radio_ids {
        validate_identifier(id)?;
        if !management.insert(id.as_str()) {
            return Err(WirelessPlanError::DuplicateValue);
        }
    }
    let mut current = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_wireless_object(object)?;
        if current
            .insert((object.kind(), object.id()), object)
            .is_some()
        {
            return Err(WirelessPlanError::DuplicateObject);
        }
    }

    let mut touched = HashSet::with_capacity(mutations.len());
    let mut changes = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        let WirelessMutation::Update {
            expected_digest,
            desired,
        } = mutation;
        validate_wireless_object(desired)?;
        let key = (desired.kind(), desired.id());
        if !touched.insert(key) {
            return Err(WirelessPlanError::DuplicateMutation);
        }
        let before = current
            .get(&key)
            .copied()
            .ok_or(WirelessPlanError::NotFound)?;
        if wireless_object_digest(before)? != *expected_digest {
            return Err(WirelessPlanError::StaleVersion);
        }
        if before.ownership() != ObjectOwnership::PlatformNative
            || desired.ownership() != ObjectOwnership::PlatformNative
        {
            return Err(WirelessPlanError::UnsupportedOwnership);
        }
        if before == desired {
            return Err(WirelessPlanError::NoChange);
        }
        let before_digest = wireless_object_digest(before)?;
        let after_digest = wireless_object_digest(desired)?;
        changes.push(WirelessPlannedChange {
            before: before.clone(),
            after: desired.clone(),
            diff: ChangeDiff {
                object: ConfigObjectRef {
                    domain: ConfigDomain::Wireless,
                    kind: desired.kind().into(),
                    id: desired.id().into(),
                    expected_version: Some(before_digest.clone()),
                    ownership: desired.ownership(),
                },
                operation: ChangeOperation::Update,
                before_digest: Some(before_digest),
                after_digest: Some(after_digest),
                summary: format!("update managed wireless radio {}", desired.id()),
                sensitive_fields_redacted: true,
                risk_signals: ChangeRiskSignals {
                    affects_management_path: management.contains(desired.id()),
                    disrupts_service: true,
                    ..ChangeRiskSignals::default()
                },
            },
        });
    }
    Ok(WirelessMutationPlan {
        risk: RiskLevel::R3,
        changes,
    })
}

/// Projects an approved radio update plan onto a fresh typed inventory.
///
/// # Errors
///
/// Returns an error when the plan does not exactly match the inventory.
pub fn project_wireless_inventory(
    inventory: &WirelessInventory,
    plan: &WirelessMutationPlan,
) -> Result<WirelessInventory, WirelessPlanError> {
    if inventory.objects.len() > MAX_OBJECTS
        || plan.changes.is_empty()
        || plan.changes.len() > MAX_MUTATIONS
        || plan.risk != RiskLevel::R3
    {
        return Err(WirelessPlanError::Capacity);
    }
    let mut projected = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_wireless_object(object)?;
        if projected
            .insert(
                (object.kind().to_owned(), object.id().to_owned()),
                object.clone(),
            )
            .is_some()
        {
            return Err(WirelessPlanError::DuplicateObject);
        }
    }
    let mut touched = HashSet::with_capacity(plan.changes.len());
    for change in &plan.changes {
        validate_execution_change(&change.diff, change)
            .map_err(|_| WirelessPlanError::PlanMismatch)?;
        let key = (
            change.before.kind().to_owned(),
            change.before.id().to_owned(),
        );
        if !touched.insert(key.clone()) || projected.get(&key) != Some(&change.before) {
            return Err(WirelessPlanError::PlanMismatch);
        }
        projected.insert(key, change.after.clone());
    }
    let mut objects: Vec<_> = projected.into_values().collect();
    objects.sort_by(|left, right| left.id().cmp(right.id()));
    Ok(WirelessInventory { objects })
}

/// Verifies touched radios against the approved desired state.
///
/// # Errors
///
/// Returns an error for duplicate/malformed live objects or desired-state drift.
pub fn verify_wireless_plan_result(
    inventory: &WirelessInventory,
    plan: &WirelessMutationPlan,
) -> Result<(), WirelessPlanError> {
    let mut live = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_wireless_object(object)?;
        if live.insert((object.kind(), object.id()), object).is_some() {
            return Err(WirelessPlanError::DuplicateObject);
        }
    }
    for change in &plan.changes {
        validate_execution_change(&change.diff, change)
            .map_err(|_| WirelessPlanError::PlanMismatch)?;
        if live.get(&(change.after.kind(), change.after.id())).copied() != Some(&change.after) {
            return Err(WirelessPlanError::PlanMismatch);
        }
    }
    Ok(())
}

/// Returns the canonical SHA-256 version of a validated wireless object.
///
/// # Errors
///
/// Returns an error when the object is invalid or cannot be encoded.
pub fn wireless_object_digest(object: &WirelessObject) -> Result<String, WirelessPlanError> {
    validate_wireless_object(object)?;
    let encoded = serde_json::to_vec(object).map_err(|_| WirelessPlanError::Encode)?;
    Ok(lower_hex(digest(&SHA256, &encoded).as_ref()))
}

/// Performs platform-independent radio schema checks.
///
/// # Errors
///
/// Returns a structured error for invalid identifiers, channel/width combinations,
/// country codes, transmit power, or unmanaged objects.
pub fn validate_wireless_object(object: &WirelessObject) -> Result<(), WirelessPlanError> {
    validate_identifier(object.id())?;
    if object.ownership() == ObjectOwnership::Unmanaged {
        return Err(WirelessPlanError::UnsupportedOwnership);
    }
    let WirelessObject::Radio(radio) = object;
    if let Some(country) = &radio.country {
        if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(WirelessPlanError::InvalidCountry);
        }
    }
    if radio
        .tx_power_dbm
        .is_some_and(|power| !(1..=40).contains(&power))
    {
        return Err(WirelessPlanError::InvalidTransmitPower);
    }
    if matches!(radio.band, WirelessBand::Ghz2)
        && matches!(
            radio.width,
            WirelessChannelWidth::Mhz80 | WirelessChannelWidth::Mhz160
        )
    {
        return Err(WirelessPlanError::InvalidWidth);
    }
    if let WirelessChannel::Fixed { channel } = radio.channel {
        let valid = match radio.band {
            WirelessBand::Ghz2 => (1..=14).contains(&channel),
            WirelessBand::Ghz5 => valid_5ghz_channel(channel),
            WirelessBand::Ghz6 => channel <= 233 && channel % 4 == 1,
        };
        if !valid {
            return Err(WirelessPlanError::InvalidChannel);
        }
    }
    Ok(())
}

fn validate_execution_change(
    preview: &ChangeDiff,
    typed: &WirelessPlannedChange,
) -> Result<(), WirelessExecutionPlanError> {
    if preview != &typed.diff
        || preview.object.domain != ConfigDomain::Wireless
        || preview.object.kind != typed.before.kind()
        || preview.object.id != typed.before.id()
        || preview.object.ownership != ObjectOwnership::PlatformNative
        || typed.before.kind() != typed.after.kind()
        || typed.before.id() != typed.after.id()
        || typed.before.ownership() != typed.after.ownership()
        || preview.operation != ChangeOperation::Update
        || !preview.sensitive_fields_redacted
        || !preview.risk_signals.disrupts_service
    {
        return Err(WirelessExecutionPlanError::PlanMismatch);
    }
    validate_wireless_object(&typed.before)
        .map_err(|_| WirelessExecutionPlanError::InvalidObject)?;
    validate_wireless_object(&typed.after)
        .map_err(|_| WirelessExecutionPlanError::InvalidObject)?;
    let before = wireless_object_digest(&typed.before)
        .map_err(|_| WirelessExecutionPlanError::InvalidObject)?;
    let after = wireless_object_digest(&typed.after)
        .map_err(|_| WirelessExecutionPlanError::InvalidObject)?;
    if preview.before_digest.as_deref() != Some(&before)
        || preview.after_digest.as_deref() != Some(&after)
        || preview.object.expected_version.as_deref() != Some(&before)
    {
        return Err(WirelessExecutionPlanError::DigestMismatch);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), WirelessPlanError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(WirelessPlanError::InvalidIdentifier);
    }
    Ok(())
}

fn valid_5ghz_channel(channel: u16) -> bool {
    matches!(channel, 36 | 40 | 44 | 48 | 52 | 56 | 60 | 64)
        || ((100..=144).contains(&channel) && (channel - 100) % 4 == 0)
        || ((149..=177).contains(&channel) && (channel - 149) % 4 == 0)
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WirelessExecutionPlanError {
    #[error("wireless execution plan schema is unsupported")]
    UnsupportedSchema,
    #[error("wireless execution plan preview is invalid")]
    InvalidPreview,
    #[error("wireless execution plan does not match its typed payload")]
    PlanMismatch,
    #[error("wireless execution plan contains an invalid object")]
    InvalidObject,
    #[error("wireless execution plan digest does not match")]
    DigestMismatch,
    #[error("wireless execution plan exceeds its capacity")]
    Capacity,
    #[error("failed to encode wireless execution plan")]
    Encode,
    #[error("failed to decode wireless execution plan")]
    Decode,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WirelessPlanError {
    #[error("wireless plan exceeds its capacity")]
    Capacity,
    #[error("invalid wireless identifier")]
    InvalidIdentifier,
    #[error("invalid wireless country code")]
    InvalidCountry,
    #[error("invalid wireless channel for the configured band")]
    InvalidChannel,
    #[error("invalid wireless channel width for the configured band")]
    InvalidWidth,
    #[error("wireless transmit power must be between 1 and 40 dBm")]
    InvalidTransmitPower,
    #[error("duplicate wireless object")]
    DuplicateObject,
    #[error("duplicate wireless mutation")]
    DuplicateMutation,
    #[error("duplicate wireless context value")]
    DuplicateValue,
    #[error("wireless object was not found")]
    NotFound,
    #[error("wireless object version is stale")]
    StaleVersion,
    #[error("wireless object ownership is unsupported by this slice")]
    UnsupportedOwnership,
    #[error("wireless mutation has no semantic change")]
    NoChange,
    #[error("failed to encode wireless object")]
    Encode,
    #[error("wireless mutation plan does not match fresh inventory")]
    PlanMismatch,
}

#[cfg(test)]
mod tests {
    use agent_protocol::{CHANGE_PLAN_SCHEMA_VERSION, WirelessRadioConfig};

    use super::*;

    fn radio(channel: u16) -> WirelessObject {
        WirelessObject::Radio(WirelessRadioConfig {
            id: "radio0".into(),
            ownership: ObjectOwnership::PlatformNative,
            enabled: true,
            band: WirelessBand::Ghz5,
            channel: WirelessChannel::Fixed { channel },
            width: WirelessChannelWidth::Mhz80,
            country: Some("CN".into()),
            tx_power_dbm: Some(20),
        })
    }

    fn radio_config(object: &mut WirelessObject) -> &mut WirelessRadioConfig {
        let WirelessObject::Radio(config) = object;
        config
    }

    #[test]
    fn validates_band_channel_width_country_and_power() {
        validate_wireless_object(&radio(149)).expect("valid radio");
        let mut invalid = radio(149);
        radio_config(&mut invalid).country = Some("cn".into());
        assert_eq!(
            validate_wireless_object(&invalid),
            Err(WirelessPlanError::InvalidCountry)
        );
        radio_config(&mut invalid).country = Some("CN".into());
        radio_config(&mut invalid).band = WirelessBand::Ghz2;
        assert_eq!(
            validate_wireless_object(&invalid),
            Err(WirelessPlanError::InvalidWidth)
        );
        radio_config(&mut invalid).width = WirelessChannelWidth::Mhz20;
        assert_eq!(
            validate_wireless_object(&invalid),
            Err(WirelessPlanError::InvalidChannel)
        );
        radio_config(&mut invalid).channel = WirelessChannel::Fixed { channel: 6 };
        radio_config(&mut invalid).tx_power_dbm = Some(41);
        assert_eq!(
            validate_wireless_object(&invalid),
            Err(WirelessPlanError::InvalidTransmitPower)
        );
    }

    #[test]
    fn plans_projects_and_verifies_an_r3_radio_update() {
        let before = radio(149);
        let mut after = before.clone();
        let WirelessObject::Radio(value) = &mut after;
        value.channel = WirelessChannel::Fixed { channel: 153 };
        let inventory = WirelessInventory {
            objects: vec![before.clone()],
        };
        let plan = plan_wireless_mutations(
            &inventory,
            &[WirelessMutation::Update {
                expected_digest: wireless_object_digest(&before).expect("digest"),
                desired: after.clone(),
            }],
            &WirelessRiskContext {
                management_radio_ids: vec!["radio0".into()],
            },
        )
        .expect("plan");
        assert_eq!(plan.risk, RiskLevel::R3);
        assert!(plan.changes[0].diff.risk_signals.disrupts_service);
        assert!(plan.changes[0].diff.risk_signals.affects_management_path);
        assert!(!plan.changes[0].diff.risk_signals.changes_secret);
        let projected = project_wireless_inventory(&inventory, &plan).expect("project");
        assert_eq!(projected.objects, [after]);
        verify_wireless_plan_result(&projected, &plan).expect("verify");
    }

    #[test]
    fn rejects_stale_noop_and_non_native_updates() {
        let before = radio(149);
        let inventory = WirelessInventory {
            objects: vec![before.clone()],
        };
        assert_eq!(
            plan_wireless_mutations(
                &inventory,
                &[WirelessMutation::Update {
                    expected_digest: "0".repeat(64),
                    desired: radio(153),
                }],
                &WirelessRiskContext::default(),
            ),
            Err(WirelessPlanError::StaleVersion)
        );
        assert_eq!(
            plan_wireless_mutations(
                &inventory,
                &[WirelessMutation::Update {
                    expected_digest: wireless_object_digest(&before).expect("digest"),
                    desired: before.clone(),
                }],
                &WirelessRiskContext::default(),
            ),
            Err(WirelessPlanError::NoChange)
        );
        let mut owned = radio(153);
        let WirelessObject::Radio(value) = &mut owned;
        value.ownership = ObjectOwnership::AgentOwned;
        assert_eq!(
            plan_wireless_mutations(
                &inventory,
                &[WirelessMutation::Update {
                    expected_digest: wireless_object_digest(&before).expect("digest"),
                    desired: owned,
                }],
                &WirelessRiskContext::default(),
            ),
            Err(WirelessPlanError::UnsupportedOwnership)
        );
    }

    #[test]
    fn execution_payload_rejects_tampered_radio() {
        let before = radio(149);
        let inventory = WirelessInventory {
            objects: vec![before.clone()],
        };
        let typed = plan_wireless_mutations(
            &inventory,
            &[WirelessMutation::Update {
                expected_digest: wireless_object_digest(&before).expect("digest"),
                desired: radio(153),
            }],
            &WirelessRiskContext::default(),
        )
        .expect("typed plan");
        let preview = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "wireless-plan".into(),
            boot_id: "boot-1".into(),
            actor_id: "cli/root".into(),
            created_monotonic_ms: 10,
            expires_monotonic_ms: 20,
            risk: typed.risk,
            changes: typed
                .changes
                .iter()
                .map(|change| change.diff.clone())
                .collect(),
            validation_checks: vec!["wireless UCI staging validates".into()],
            verification_checks: vec!["wireless radio matches desired state".into()],
            rollback_required: true,
        };
        let payload = WirelessExecutionPlan {
            schema_version: WIRELESS_EXECUTION_PLAN_SCHEMA_VERSION,
            preview,
            typed,
        };
        let encoded = payload.encode().expect("encode");
        assert_eq!(
            WirelessExecutionPlan::decode(&encoded).expect("decode"),
            payload
        );
        let mut tampered = payload;
        let WirelessObject::Radio(value) = &mut tampered.typed.changes[0].after;
        value.channel = WirelessChannel::Fixed { channel: 157 };
        assert_eq!(
            tampered.validate(),
            Err(WirelessExecutionPlanError::DigestMismatch)
        );
    }
}
