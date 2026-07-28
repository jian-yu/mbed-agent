use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use agent_protocol::{
    ChangeDiff, ChangeOperation, ChangePlan, ChangeRiskSignals, ConfigDomain, ConfigObjectRef,
    FirewallAddressSet, FirewallFilterRule, FirewallForwarding, FirewallMatch, FirewallNatKind,
    FirewallNatRule, FirewallObject, FirewallProtocol, FirewallSetEntry, FirewallVerdict,
    FirewallZone, IpNetwork, ObjectOwnership, PortRange, RiskLevel,
};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_OBJECTS: usize = 256;
const MAX_MUTATIONS: usize = 32;
const MAX_MATCH_VALUES: usize = 32;
const MAX_SET_ENTRIES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallInventory {
    pub objects: Vec<FirewallObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallMutation {
    Create(FirewallObject),
    Update {
        expected_digest: String,
        desired: FirewallObject,
    },
    Delete {
        kind: String,
        id: String,
        expected_digest: String,
    },
    Move {
        expected_digest: String,
        desired: FirewallObject,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallRiskContext {
    pub management_rule_ids: Vec<String>,
    pub management_zones: Vec<String>,
    pub management_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallPlannedChange {
    pub before: Option<FirewallObject>,
    pub after: Option<FirewallObject>,
    pub diff: ChangeDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallMutationPlan {
    pub risk: RiskLevel,
    pub changes: Vec<FirewallPlannedChange>,
}

pub const FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION: u16 = 1;
const MAX_FIREWALL_EXECUTION_PLAN_BYTES: usize = 256 * 1024;

/// Stored executable payload paired with the exact user-visible `ChangePlan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirewallExecutionPlan {
    pub schema_version: u16,
    pub preview: ChangePlan,
    pub typed: FirewallMutationPlan,
}

impl FirewallExecutionPlan {
    /// Validates every preview diff against its complete typed before/after objects.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed preview, schema/risk/diff mismatch, invalid object,
    /// forged digest, unsupported ownership, or encoded payload overflow.
    pub fn validate(&self) -> Result<(), FirewallExecutionPlanError> {
        if self.schema_version != FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION {
            return Err(FirewallExecutionPlanError::UnsupportedSchema);
        }
        crate::plan_digest(&self.preview)
            .map_err(|_| FirewallExecutionPlanError::InvalidPreview)?;
        if self.preview.risk != self.typed.risk
            || self.preview.changes.len() != self.typed.changes.len()
            || self.typed.changes.is_empty()
            || self.typed.changes.len() > MAX_MUTATIONS
        {
            return Err(FirewallExecutionPlanError::PlanMismatch);
        }
        for (preview, typed) in self.preview.changes.iter().zip(&self.typed.changes) {
            validate_execution_change(preview, typed)?;
        }
        let encoded = serde_json::to_vec(self).map_err(|_| FirewallExecutionPlanError::Encode)?;
        if encoded.len() > MAX_FIREWALL_EXECUTION_PLAN_BYTES {
            return Err(FirewallExecutionPlanError::Capacity);
        }
        Ok(())
    }

    /// Encodes one fully validated execution payload.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or bounded canonical encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, FirewallExecutionPlanError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| FirewallExecutionPlanError::Encode)
    }

    /// Decodes and fully revalidates a bounded execution payload.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, or semantically inconsistent input.
    pub fn decode(encoded: &[u8]) -> Result<Self, FirewallExecutionPlanError> {
        if encoded.is_empty() || encoded.len() > MAX_FIREWALL_EXECUTION_PLAN_BYTES {
            return Err(FirewallExecutionPlanError::Capacity);
        }
        let plan: Self =
            serde_json::from_slice(encoded).map_err(|_| FirewallExecutionPlanError::Decode)?;
        plan.validate()?;
        Ok(plan)
    }
}

fn validate_execution_change(
    preview: &ChangeDiff,
    typed: &FirewallPlannedChange,
) -> Result<(), FirewallExecutionPlanError> {
    if preview != &typed.diff {
        return Err(FirewallExecutionPlanError::PlanMismatch);
    }
    let object = typed
        .after
        .as_ref()
        .or(typed.before.as_ref())
        .ok_or(FirewallExecutionPlanError::PlanMismatch)?;
    if preview.object.domain != ConfigDomain::Firewall
        || preview.object.kind != object.kind()
        || preview.object.id != object.id()
        || preview.object.ownership != object.ownership()
        || object.ownership() == ObjectOwnership::Unmanaged
    {
        return Err(FirewallExecutionPlanError::PlanMismatch);
    }
    if let Some(before) = &typed.before {
        validate_firewall_object(before).map_err(|_| FirewallExecutionPlanError::InvalidObject)?;
    }
    if let Some(after) = &typed.after {
        validate_firewall_object(after).map_err(|_| FirewallExecutionPlanError::InvalidObject)?;
    }
    let before_digest = typed
        .before
        .as_ref()
        .map(firewall_object_digest)
        .transpose()
        .map_err(|_| FirewallExecutionPlanError::InvalidObject)?;
    let after_digest = typed
        .after
        .as_ref()
        .map(firewall_object_digest)
        .transpose()
        .map_err(|_| FirewallExecutionPlanError::InvalidObject)?;
    if preview.before_digest != before_digest
        || preview.after_digest != after_digest
        || preview.object.expected_version != before_digest
    {
        return Err(FirewallExecutionPlanError::DigestMismatch);
    }
    let valid_shape = match preview.operation {
        ChangeOperation::Create => typed.before.is_none() && typed.after.is_some(),
        ChangeOperation::Update | ChangeOperation::Move => {
            typed.before.is_some() && typed.after.is_some()
        }
        ChangeOperation::Delete => typed.before.is_some() && typed.after.is_none(),
    };
    if !valid_shape {
        return Err(FirewallExecutionPlanError::PlanMismatch);
    }
    Ok(())
}

/// Validates and plans explicit firewall CRUD mutations against a fresh inventory.
///
/// # Errors
///
/// Returns an error for invalid typed data, stale versions, unmanaged objects,
/// duplicate mutations, collisions, unsupported moves, or capacity overflow.
pub fn plan_firewall_mutations(
    inventory: &FirewallInventory,
    mutations: &[FirewallMutation],
    context: &FirewallRiskContext,
) -> Result<FirewallMutationPlan, FirewallPlanError> {
    if inventory.objects.len() > MAX_OBJECTS
        || mutations.is_empty()
        || mutations.len() > MAX_MUTATIONS
    {
        return Err(FirewallPlanError::Capacity);
    }
    validate_context(context)?;
    let mut current = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_firewall_object(object)?;
        let key = object_key(object);
        if current.insert(key, object).is_some() {
            return Err(FirewallPlanError::DuplicateObject);
        }
    }

    let mut touched = HashSet::with_capacity(mutations.len());
    let mut changes = Vec::with_capacity(mutations.len());
    let mut risk = RiskLevel::R2;
    for mutation in mutations {
        let (operation, before, after) = resolve_mutation(&current, mutation)?;
        let object = after
            .as_ref()
            .or(before.as_ref())
            .ok_or(FirewallPlanError::InvalidMutation)?;
        let kind = object.kind().to_owned();
        let id = object.id().to_owned();
        let ownership = object.ownership();
        let summary = mutation_summary(operation, object);
        let key = (kind.clone(), id.clone());
        if !touched.insert(key) {
            return Err(FirewallPlanError::DuplicateMutation);
        }
        if ownership == ObjectOwnership::Unmanaged {
            return Err(FirewallPlanError::Unmanaged);
        }
        if before
            .as_ref()
            .is_some_and(|value| value.ownership() != ownership)
        {
            return Err(FirewallPlanError::OwnershipChanged);
        }
        let signals = assess_mutation(operation, before.as_ref(), after.as_ref(), context);
        if signals.affects_management_path
            || signals.widens_network_exposure
            || signals.disrupts_service
        {
            risk = RiskLevel::R3;
        }
        let before_digest = before.as_ref().map(firewall_object_digest).transpose()?;
        let after_digest = after.as_ref().map(firewall_object_digest).transpose()?;
        changes.push(FirewallPlannedChange {
            before,
            after,
            diff: ChangeDiff {
                object: ConfigObjectRef {
                    domain: ConfigDomain::Firewall,
                    kind,
                    id,
                    expected_version: before_digest.clone(),
                    ownership,
                },
                operation,
                before_digest,
                after_digest,
                summary,
                sensitive_fields_redacted: true,
                risk_signals: signals,
            },
        });
    }
    validate_projected_references(inventory, &changes)?;
    Ok(FirewallMutationPlan { risk, changes })
}

fn validate_projected_references(
    inventory: &FirewallInventory,
    changes: &[FirewallPlannedChange],
) -> Result<(), FirewallPlanError> {
    let mut projected: HashMap<(String, String), FirewallObject> = inventory
        .objects
        .iter()
        .cloned()
        .map(|object| ((object.kind().to_owned(), object.id().to_owned()), object))
        .collect();
    for change in changes {
        if let Some(before) = &change.before {
            projected.remove(&(before.kind().to_owned(), before.id().to_owned()));
        }
        if let Some(after) = &change.after {
            projected.insert(
                (after.kind().to_owned(), after.id().to_owned()),
                after.clone(),
            );
        }
    }
    let zones: HashSet<&str> = projected
        .values()
        .filter_map(|object| match object {
            FirewallObject::Zone(zone) => Some(zone.id.as_str()),
            _ => None,
        })
        .collect();
    let sets: HashSet<&str> = projected
        .values()
        .filter_map(|object| match object {
            FirewallObject::AddressSet(set) => Some(set.id.as_str()),
            _ => None,
        })
        .collect();
    for object in projected.values() {
        match object {
            FirewallObject::Forwarding(forwarding)
                if !zones.contains(forwarding.source_zone.as_str())
                    || !zones.contains(forwarding.destination_zone.as_str()) =>
            {
                return Err(FirewallPlanError::DanglingReference);
            }
            FirewallObject::FilterRule(rule) => {
                validate_match_references(&rule.matches, &zones, &sets)?;
            }
            FirewallObject::NatRule(rule) => {
                validate_match_references(&rule.matches, &zones, &sets)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_match_references(
    value: &FirewallMatch,
    zones: &HashSet<&str>,
    sets: &HashSet<&str>,
) -> Result<(), FirewallPlanError> {
    if value
        .source_zones
        .iter()
        .chain(&value.destination_zones)
        .any(|zone| !zones.contains(zone.as_str()))
        || value
            .source_sets
            .iter()
            .chain(&value.destination_sets)
            .any(|set| !sets.contains(set.as_str()))
    {
        Err(FirewallPlanError::DanglingReference)
    } else {
        Ok(())
    }
}

fn resolve_mutation(
    current: &HashMap<(&str, &str), &FirewallObject>,
    mutation: &FirewallMutation,
) -> Result<
    (
        ChangeOperation,
        Option<FirewallObject>,
        Option<FirewallObject>,
    ),
    FirewallPlanError,
> {
    match mutation {
        FirewallMutation::Create(desired) => {
            validate_firewall_object(desired)?;
            if current.contains_key(&object_key(desired)) {
                return Err(FirewallPlanError::AlreadyExists);
            }
            Ok((ChangeOperation::Create, None, Some(desired.clone())))
        }
        FirewallMutation::Update {
            expected_digest,
            desired,
        } => {
            validate_firewall_object(desired)?;
            let existing = find_versioned(current, desired.kind(), desired.id(), expected_digest)?;
            if existing == desired {
                return Err(FirewallPlanError::NoChange);
            }
            Ok((
                ChangeOperation::Update,
                Some(existing.clone()),
                Some(desired.clone()),
            ))
        }
        FirewallMutation::Delete {
            kind,
            id,
            expected_digest,
        } => {
            validate_identifier(kind, "kind")?;
            validate_identifier(id, "id")?;
            let existing = find_versioned(current, kind, id, expected_digest)?;
            Ok((ChangeOperation::Delete, Some(existing.clone()), None))
        }
        FirewallMutation::Move {
            expected_digest,
            desired,
        } => resolve_move(current, expected_digest, desired),
    }
}

fn resolve_move(
    current: &HashMap<(&str, &str), &FirewallObject>,
    expected_digest: &str,
    desired: &FirewallObject,
) -> Result<
    (
        ChangeOperation,
        Option<FirewallObject>,
        Option<FirewallObject>,
    ),
    FirewallPlanError,
> {
    validate_firewall_object(desired)?;
    if !matches!(
        desired,
        FirewallObject::FilterRule(_) | FirewallObject::NatRule(_)
    ) {
        return Err(FirewallPlanError::UnsupportedMove);
    }
    let existing = find_versioned(current, desired.kind(), desired.id(), expected_digest)?;
    if same_except_order(existing, desired) != Some(true) {
        return Err(FirewallPlanError::MoveChangesContent);
    }
    if object_order(existing) == object_order(desired) {
        return Err(FirewallPlanError::NoChange);
    }
    Ok((
        ChangeOperation::Move,
        Some(existing.clone()),
        Some(desired.clone()),
    ))
}

/// Returns the canonical SHA-256 version of one validated typed firewall object.
///
/// # Errors
///
/// Returns an error if the object is invalid or cannot be encoded.
pub fn firewall_object_digest(object: &FirewallObject) -> Result<String, FirewallPlanError> {
    validate_firewall_object(object)?;
    let encoded = serde_json::to_vec(object).map_err(|_| FirewallPlanError::Encode)?;
    Ok(lower_hex(digest(&SHA256, &encoded).as_ref()))
}

/// Performs all platform-independent firewall schema checks.
///
/// # Errors
///
/// Returns a structured error when any field is invalid or exceeds a bound.
pub fn validate_firewall_object(object: &FirewallObject) -> Result<(), FirewallPlanError> {
    validate_identifier(object.id(), "id")?;
    match object {
        FirewallObject::Zone(value) => validate_zone(value),
        FirewallObject::Forwarding(value) => validate_forwarding(value),
        FirewallObject::FilterRule(value) => validate_filter_rule(value),
        FirewallObject::AddressSet(value) => validate_address_set(value),
        FirewallObject::NatRule(value) => validate_nat_rule(value),
    }
}

fn validate_zone(value: &FirewallZone) -> Result<(), FirewallPlanError> {
    validate_identifiers(&value.networks, "zone network")?;
    if value.networks.is_empty() {
        return Err(FirewallPlanError::InvalidField("zone networks"));
    }
    Ok(())
}

fn validate_forwarding(value: &FirewallForwarding) -> Result<(), FirewallPlanError> {
    validate_identifier(&value.source_zone, "source zone")?;
    validate_identifier(&value.destination_zone, "destination zone")?;
    if value.source_zone == value.destination_zone {
        return Err(FirewallPlanError::InvalidField("forwarding zones"));
    }
    Ok(())
}

fn validate_filter_rule(value: &FirewallFilterRule) -> Result<(), FirewallPlanError> {
    validate_match(&value.matches)?;
    if (value.verdict == FirewallVerdict::Reject) != value.reject_with.is_some() {
        return Err(FirewallPlanError::InvalidField("reject_with"));
    }
    if let Some(reject) = value.reject_with {
        let compatible = matches!(
            (value.matches.family, reject),
            (
                agent_protocol::FirewallFamily::Ipv4 | agent_protocol::FirewallFamily::Any,
                agent_protocol::FirewallRejectKind::TcpReset
                    | agent_protocol::FirewallRejectKind::IcmpPortUnreachable
                    | agent_protocol::FirewallRejectKind::IcmpHostUnreachable
            ) | (
                agent_protocol::FirewallFamily::Ipv6 | agent_protocol::FirewallFamily::Any,
                agent_protocol::FirewallRejectKind::Icmp6PortUnreachable
            )
        );
        if !compatible {
            return Err(FirewallPlanError::InvalidField("reject family"));
        }
    }
    if let Some(limit) = value.rate_limit {
        if limit.packets_per_second == 0
            || limit.packets_per_second > 1_000_000
            || limit.burst == 0
            || limit.burst > 1_000_000
        {
            return Err(FirewallPlanError::InvalidField("rate limit"));
        }
    }
    if let Some(log) = &value.log {
        if log.prefix.len() > 32 || log.prefix.chars().any(char::is_control) {
            return Err(FirewallPlanError::InvalidField("log prefix"));
        }
    }
    Ok(())
}

fn validate_address_set(value: &FirewallAddressSet) -> Result<(), FirewallPlanError> {
    if value.entries.is_empty() || value.entries.len() > MAX_SET_ENTRIES {
        return Err(FirewallPlanError::Capacity);
    }
    let first_kind = set_entry_kind(&value.entries[0]);
    if matches!(value.entries[0], FirewallSetEntry::Network(_))
        && value.family == agent_protocol::FirewallFamily::Any
    {
        return Err(FirewallPlanError::InvalidField("address set family"));
    }
    if !matches!(value.entries[0], FirewallSetEntry::Network(_))
        && value.family != agent_protocol::FirewallFamily::Any
    {
        return Err(FirewallPlanError::InvalidField("non-address set family"));
    }
    let mut unique = HashSet::with_capacity(value.entries.len());
    for entry in &value.entries {
        if set_entry_kind(entry) != first_kind {
            return Err(FirewallPlanError::MixedSetTypes);
        }
        match entry {
            FirewallSetEntry::Network(network) => validate_network(network, value.family)?,
            FirewallSetEntry::Mac(mac) => validate_mac(mac)?,
            FirewallSetEntry::Port(port) => validate_port(*port)?,
        }
        let encoded = serde_json::to_string(entry).map_err(|_| FirewallPlanError::Encode)?;
        if !unique.insert(encoded) {
            return Err(FirewallPlanError::DuplicateValue);
        }
    }
    Ok(())
}

fn validate_nat_rule(value: &FirewallNatRule) -> Result<(), FirewallPlanError> {
    validate_match(&value.matches)?;
    match value.kind {
        FirewallNatKind::Masquerade
            if value.translation_address.is_none() && value.translation_port.is_none() => {}
        FirewallNatKind::SourceNat | FirewallNatKind::DestinationNat
            if value.translation_address.is_some() => {}
        FirewallNatKind::Redirect
            if value.translation_address.is_none() && value.translation_port.is_some() => {}
        _ => return Err(FirewallPlanError::InvalidField("NAT translation")),
    }
    if let Some(port) = value.translation_port {
        validate_port(port)?;
        require_transport_protocol(&value.matches)?;
    }
    if let Some(address) = value.translation_address {
        validate_address_family(address, value.matches.family)?;
    }
    Ok(())
}

fn validate_match(value: &FirewallMatch) -> Result<(), FirewallPlanError> {
    for values in [
        &value.source_zones,
        &value.destination_zones,
        &value.input_interfaces,
        &value.output_interfaces,
        &value.source_sets,
        &value.destination_sets,
    ] {
        validate_identifiers(values, "firewall match identifier")?;
    }
    if value.source_networks.len() > MAX_MATCH_VALUES
        || value.destination_networks.len() > MAX_MATCH_VALUES
        || value.source_macs.len() > MAX_MATCH_VALUES
        || value.protocols.len() > 8
        || value.source_ports.len() > MAX_MATCH_VALUES
        || value.destination_ports.len() > MAX_MATCH_VALUES
        || value.icmp_types.len() > MAX_MATCH_VALUES
        || value.conntrack_states.len() > 4
    {
        return Err(FirewallPlanError::Capacity);
    }
    for network in value
        .source_networks
        .iter()
        .chain(&value.destination_networks)
    {
        validate_network(network, value.family)?;
    }
    for mac in &value.source_macs {
        validate_mac(mac)?;
    }
    for port in value.source_ports.iter().chain(&value.destination_ports) {
        validate_port(*port)?;
    }
    if !value.source_ports.is_empty() || !value.destination_ports.is_empty() {
        require_transport_protocol(value)?;
    }
    if !value.icmp_types.is_empty()
        && !value
            .protocols
            .iter()
            .any(|protocol| matches!(protocol, FirewallProtocol::Icmp | FirewallProtocol::Icmpv6))
    {
        return Err(FirewallPlanError::InvalidField("ICMP types"));
    }
    if (value.family == agent_protocol::FirewallFamily::Ipv4
        && value.protocols.contains(&FirewallProtocol::Icmpv6))
        || (value.family == agent_protocol::FirewallFamily::Ipv6
            && value.protocols.contains(&FirewallProtocol::Icmp))
    {
        return Err(FirewallPlanError::InvalidField("protocol family"));
    }
    reject_duplicates(&value.source_networks)?;
    reject_duplicates(&value.destination_networks)?;
    reject_duplicates(&value.source_macs)?;
    reject_duplicates(&value.protocols)?;
    reject_duplicates(&value.source_ports)?;
    reject_duplicates(&value.destination_ports)?;
    reject_duplicates(&value.icmp_types)?;
    reject_duplicates(&value.conntrack_states)?;
    Ok(())
}

fn require_transport_protocol(value: &FirewallMatch) -> Result<(), FirewallPlanError> {
    if value
        .protocols
        .iter()
        .any(|protocol| matches!(protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp))
    {
        Ok(())
    } else {
        Err(FirewallPlanError::InvalidField("ports require TCP or UDP"))
    }
}

fn validate_network(
    value: &IpNetwork,
    family: agent_protocol::FirewallFamily,
) -> Result<(), FirewallPlanError> {
    validate_address_family(value.address, family)?;
    let canonical = match value.address {
        IpAddr::V4(address) if value.prefix_len <= 32 => {
            let bits = u32::from(address);
            let mask = if value.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - value.prefix_len)
            };
            bits & mask == bits
        }
        IpAddr::V6(address) if value.prefix_len <= 128 => {
            let bits = u128::from(address);
            let mask = if value.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - value.prefix_len)
            };
            bits & mask == bits
        }
        _ => false,
    };
    if canonical {
        Ok(())
    } else {
        Err(FirewallPlanError::InvalidField("network prefix"))
    }
}

fn validate_address_family(
    address: IpAddr,
    family: agent_protocol::FirewallFamily,
) -> Result<(), FirewallPlanError> {
    let valid = matches!(
        (address, family),
        (_, agent_protocol::FirewallFamily::Any)
            | (IpAddr::V4(_), agent_protocol::FirewallFamily::Ipv4)
            | (IpAddr::V6(_), agent_protocol::FirewallFamily::Ipv6)
    );
    if valid {
        Ok(())
    } else {
        Err(FirewallPlanError::InvalidField("address family"))
    }
}

fn validate_port(value: PortRange) -> Result<(), FirewallPlanError> {
    if value.start == 0 || value.end == 0 || value.start > value.end {
        Err(FirewallPlanError::InvalidField("port range"))
    } else {
        Ok(())
    }
}

fn validate_mac(value: &str) -> Result<(), FirewallPlanError> {
    let valid = value.len() == 17
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 2 | 5 | 8 | 11 | 14) {
                byte == b':'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        });
    if valid {
        Ok(())
    } else {
        Err(FirewallPlanError::InvalidField("MAC address"))
    }
}

fn validate_context(value: &FirewallRiskContext) -> Result<(), FirewallPlanError> {
    validate_identifiers(&value.management_rule_ids, "management rule")?;
    validate_identifiers(&value.management_zones, "management zone")?;
    validate_identifiers(&value.management_interfaces, "management interface")
}

fn validate_identifiers(values: &[String], field: &'static str) -> Result<(), FirewallPlanError> {
    if values.len() > MAX_MATCH_VALUES {
        return Err(FirewallPlanError::Capacity);
    }
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        validate_identifier(value, field)?;
        if !unique.insert(value) {
            return Err(FirewallPlanError::DuplicateValue);
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), FirewallPlanError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        Err(FirewallPlanError::InvalidIdentifier(field))
    } else {
        Ok(())
    }
}

fn reject_duplicates<T>(values: &[T]) -> Result<(), FirewallPlanError>
where
    T: std::hash::Hash + Eq,
{
    let unique: HashSet<_> = values.iter().collect();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(FirewallPlanError::DuplicateValue)
    }
}

fn find_versioned<'a>(
    current: &HashMap<(&'a str, &'a str), &'a FirewallObject>,
    kind: &str,
    id: &str,
    expected_digest: &str,
) -> Result<&'a FirewallObject, FirewallPlanError> {
    let object = current
        .get(&(kind, id))
        .copied()
        .ok_or(FirewallPlanError::NotFound)?;
    if firewall_object_digest(object)? != expected_digest {
        return Err(FirewallPlanError::StaleVersion);
    }
    Ok(object)
}

fn assess_mutation(
    operation: ChangeOperation,
    before: Option<&FirewallObject>,
    after: Option<&FirewallObject>,
    context: &FirewallRiskContext,
) -> ChangeRiskSignals {
    let object = after.or(before).expect("mutation object");
    let management = touches_management(object, context);
    let (widens, disrupts) = match (operation, before, after) {
        (ChangeOperation::Create, _, Some(FirewallObject::FilterRule(rule))) => (
            rule.enabled && rule.verdict == FirewallVerdict::Accept,
            false,
        ),
        (ChangeOperation::Create, _, Some(FirewallObject::AddressSet(_))) => (false, false),
        (ChangeOperation::Create, _, Some(_)) => (true, false),
        (ChangeOperation::Delete, Some(FirewallObject::FilterRule(rule)), _) => (
            rule.enabled && rule.verdict != FirewallVerdict::Accept,
            rule.enabled && rule.verdict == FirewallVerdict::Accept,
        ),
        (ChangeOperation::Delete, _, _) => (false, true),
        (ChangeOperation::Update | ChangeOperation::Move, _, _) => {
            let changed_exposure = before != after;
            (changed_exposure, changed_exposure)
        }
        _ => (false, false),
    };
    ChangeRiskSignals {
        affects_management_path: management,
        widens_network_exposure: widens,
        disrupts_service: disrupts,
        ..ChangeRiskSignals::default()
    }
}

fn touches_management(object: &FirewallObject, context: &FirewallRiskContext) -> bool {
    if context
        .management_rule_ids
        .iter()
        .any(|id| id == object.id())
    {
        return true;
    }
    match object {
        FirewallObject::Zone(zone) => context.management_zones.contains(&zone.id),
        FirewallObject::Forwarding(forwarding) => {
            context.management_zones.contains(&forwarding.source_zone)
                || context
                    .management_zones
                    .contains(&forwarding.destination_zone)
        }
        FirewallObject::FilterRule(rule) => match_touches_management(&rule.matches, context),
        FirewallObject::NatRule(rule) => match_touches_management(&rule.matches, context),
        FirewallObject::AddressSet(_) => false,
    }
}

fn match_touches_management(value: &FirewallMatch, context: &FirewallRiskContext) -> bool {
    value
        .source_zones
        .iter()
        .chain(&value.destination_zones)
        .any(|zone| context.management_zones.contains(zone))
        || value
            .input_interfaces
            .iter()
            .chain(&value.output_interfaces)
            .any(|interface| context.management_interfaces.contains(interface))
}

fn same_except_order(before: &FirewallObject, after: &FirewallObject) -> Option<bool> {
    match (before, after) {
        (FirewallObject::FilterRule(before), FirewallObject::FilterRule(after)) => {
            let mut before = before.clone();
            before.order = after.order;
            Some(before == *after)
        }
        (FirewallObject::NatRule(before), FirewallObject::NatRule(after)) => {
            let mut before = before.clone();
            before.order = after.order;
            Some(before == *after)
        }
        _ => None,
    }
}

fn object_order(object: &FirewallObject) -> Option<u32> {
    match object {
        FirewallObject::FilterRule(value) => Some(value.order),
        FirewallObject::NatRule(value) => Some(value.order),
        _ => None,
    }
}

fn object_key(object: &FirewallObject) -> (&str, &str) {
    (object.kind(), object.id())
}

fn set_entry_kind(value: &FirewallSetEntry) -> u8 {
    match value {
        FirewallSetEntry::Network(_) => 0,
        FirewallSetEntry::Mac(_) => 1,
        FirewallSetEntry::Port(_) => 2,
    }
}

fn mutation_summary(operation: ChangeOperation, object: &FirewallObject) -> String {
    let verb = match operation {
        ChangeOperation::Create => "create",
        ChangeOperation::Update => "update",
        ChangeOperation::Delete => "delete",
        ChangeOperation::Move => "move",
    };
    format!("{verb} managed firewall {} {}", object.kind(), object.id())
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
pub enum FirewallExecutionPlanError {
    #[error("firewall execution plan schema is unsupported")]
    UnsupportedSchema,
    #[error("firewall execution plan preview is invalid")]
    InvalidPreview,
    #[error("firewall execution plan does not match its preview")]
    PlanMismatch,
    #[error("firewall execution plan contains an invalid typed object")]
    InvalidObject,
    #[error("firewall execution plan object digest does not match")]
    DigestMismatch,
    #[error("firewall execution plan exceeds its capacity")]
    Capacity,
    #[error("failed to encode firewall execution plan")]
    Encode,
    #[error("failed to decode firewall execution plan")]
    Decode,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FirewallPlanError {
    #[error("firewall plan exceeds its capacity")]
    Capacity,
    #[error("invalid firewall {0}")]
    InvalidField(&'static str),
    #[error("invalid firewall identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error("duplicate firewall object")]
    DuplicateObject,
    #[error("duplicate firewall mutation")]
    DuplicateMutation,
    #[error("duplicate firewall match or set value")]
    DuplicateValue,
    #[error("firewall address sets cannot mix entry types")]
    MixedSetTypes,
    #[error("firewall object already exists")]
    AlreadyExists,
    #[error("firewall object was not found")]
    NotFound,
    #[error("firewall object version is stale")]
    StaleVersion,
    #[error("unmanaged firewall objects are read-only")]
    Unmanaged,
    #[error("firewall ownership cannot change in an update")]
    OwnershipChanged,
    #[error("firewall mutation has no semantic change")]
    NoChange,
    #[error("only ordered firewall rules support move")]
    UnsupportedMove,
    #[error("move may change only object order")]
    MoveChangesContent,
    #[error("failed to encode typed firewall object")]
    Encode,
    #[error("firewall mutation does not contain an object")]
    InvalidMutation,
    #[error("firewall plan contains a dangling zone or set reference")]
    DanglingReference,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, FirewallDirection, FirewallFamily, FirewallLog,
        FirewallLogLevel, FirewallRateLimit,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn restrictive_rule(id: &str) -> FirewallObject {
        FirewallObject::FilterRule(FirewallFilterRule {
            id: id.into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Forward,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["guest".into()],
                destination_zones: vec!["lan".into()],
                source_networks: vec![IpNetwork {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    prefix_len: 24,
                }],
                source_macs: vec!["02:00:00:00:00:01".into()],
                protocols: vec![FirewallProtocol::Tcp, FirewallProtocol::Udp],
                destination_ports: vec![PortRange { start: 22, end: 22 }],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: Some(FirewallRateLimit {
                packets_per_second: 100,
                burst: 20,
            }),
            log: Some(FirewallLog {
                prefix: "mbed-guest".into(),
                level: FirewallLogLevel::Notice,
            }),
            order: 100,
        })
    }

    #[test]
    fn executable_plan_binds_preview_to_complete_typed_objects() {
        let inventory = FirewallInventory {
            objects: Vec::new(),
        };
        let zone = FirewallObject::Zone(FirewallZone {
            id: "guest".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            networks: vec!["br-guest".into()],
            input: FirewallVerdict::Drop,
            output: FirewallVerdict::Accept,
            forward: FirewallVerdict::Drop,
            masquerade: false,
            mtu_fix: false,
        });
        let typed = plan_firewall_mutations(
            &inventory,
            &[FirewallMutation::Create(zone)],
            &FirewallRiskContext::default(),
        )
        .expect("typed plan");
        let preview = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "firewall-plan-1".into(),
            boot_id: "boot-1".into(),
            actor_id: "cli-local".into(),
            created_monotonic_ms: 10,
            expires_monotonic_ms: 1_000,
            risk: typed.risk,
            changes: typed
                .changes
                .iter()
                .map(|change| change.diff.clone())
                .collect(),
            validation_checks: vec!["native firewall check".into()],
            verification_checks: vec!["managed object exists".into()],
            rollback_required: true,
        };
        let execution = FirewallExecutionPlan {
            schema_version: FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION,
            preview,
            typed,
        };
        let encoded = execution.encode().expect("encode");
        assert_eq!(
            FirewallExecutionPlan::decode(&encoded).expect("decode"),
            execution
        );

        let mut tampered = execution;
        let Some(FirewallObject::Zone(zone)) = tampered.typed.changes[0].after.as_mut() else {
            panic!("zone");
        };
        zone.output = FirewallVerdict::Drop;
        assert_eq!(
            tampered.validate(),
            Err(FirewallExecutionPlanError::DigestMismatch)
        );
    }

    fn inventory_with_zones(mut objects: Vec<FirewallObject>) -> FirewallInventory {
        for id in ["guest", "lan", "wan"] {
            objects.push(FirewallObject::Zone(FirewallZone {
                id: id.into(),
                ownership: ObjectOwnership::PlatformNative,
                enabled: true,
                networks: vec![id.into()],
                input: FirewallVerdict::Drop,
                output: FirewallVerdict::Accept,
                forward: FirewallVerdict::Drop,
                masquerade: id == "wan",
                mtu_fix: false,
            }));
        }
        FirewallInventory { objects }
    }

    #[test]
    fn restrictive_mac_ip_port_rule_is_typed_and_r2() {
        let plan = plan_firewall_mutations(
            &inventory_with_zones(vec![]),
            &[FirewallMutation::Create(restrictive_rule(
                "block-guest-admin",
            ))],
            &FirewallRiskContext::default(),
        )
        .expect("plan");
        assert_eq!(plan.risk, RiskLevel::R2);
        assert_eq!(plan.changes[0].diff.operation, ChangeOperation::Create);
        assert!(!plan.changes[0].diff.risk_signals.widens_network_exposure);
    }

    #[test]
    fn accept_nat_and_management_path_changes_are_r3() {
        let mut accept = restrictive_rule("allow-public-admin");
        let FirewallObject::FilterRule(rule) = &mut accept else {
            unreachable!()
        };
        rule.verdict = FirewallVerdict::Accept;
        rule.matches.source_zones = vec!["wan".into()];
        rule.matches.destination_zones = vec!["lan".into()];
        let plan = plan_firewall_mutations(
            &inventory_with_zones(vec![]),
            &[FirewallMutation::Create(accept)],
            &FirewallRiskContext {
                management_zones: vec!["lan".into()],
                ..FirewallRiskContext::default()
            },
        )
        .expect("plan");
        assert_eq!(plan.risk, RiskLevel::R3);
        assert!(plan.changes[0].diff.risk_signals.affects_management_path);
        assert!(plan.changes[0].diff.risk_signals.widens_network_exposure);
    }

    #[test]
    fn stale_update_and_content_changing_move_fail_closed() {
        let original = restrictive_rule("ordered");
        let digest = firewall_object_digest(&original).expect("digest");
        let mut desired = original.clone();
        let FirewallObject::FilterRule(rule) = &mut desired else {
            unreachable!()
        };
        rule.order = 200;
        assert!(
            plan_firewall_mutations(
                &inventory_with_zones(vec![original.clone()]),
                &[FirewallMutation::Move {
                    expected_digest: digest,
                    desired: desired.clone(),
                }],
                &FirewallRiskContext::default(),
            )
            .is_ok()
        );
        let FirewallObject::FilterRule(rule) = &mut desired else {
            unreachable!()
        };
        rule.enabled = false;
        assert_eq!(
            plan_firewall_mutations(
                &inventory_with_zones(vec![original]),
                &[FirewallMutation::Move {
                    expected_digest: "0".repeat(64),
                    desired,
                }],
                &FirewallRiskContext::default(),
            ),
            Err(FirewallPlanError::StaleVersion)
        );
    }

    #[test]
    fn canonical_networks_ports_macs_and_nat_shapes_are_enforced() {
        let mut invalid = restrictive_rule("invalid");
        let FirewallObject::FilterRule(rule) = &mut invalid else {
            unreachable!()
        };
        rule.matches.source_networks[0] = IpNetwork {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix_len: 24,
        };
        assert_eq!(
            validate_firewall_object(&invalid),
            Err(FirewallPlanError::InvalidField("network prefix"))
        );

        let nat = FirewallObject::NatRule(FirewallNatRule {
            id: "redirect-dns".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            kind: FirewallNatKind::Redirect,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv6,
                protocols: vec![FirewallProtocol::Udp],
                destination_ports: vec![PortRange { start: 53, end: 53 }],
                destination_networks: vec![IpNetwork {
                    address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix_len: 0,
                }],
                ..FirewallMatch::default()
            },
            translation_address: None,
            translation_port: Some(PortRange {
                start: 5353,
                end: 5353,
            }),
            order: 10,
        });
        assert!(validate_firewall_object(&nat).is_ok());
        let plan = plan_firewall_mutations(
            &inventory_with_zones(vec![]),
            &[FirewallMutation::Create(nat)],
            &FirewallRiskContext::default(),
        )
        .expect("NAT plan");
        assert_eq!(plan.risk, RiskLevel::R3);
        assert!(plan.changes[0].diff.risk_signals.widens_network_exposure);
    }

    #[test]
    fn mixed_address_sets_and_unmanaged_mutations_are_rejected() {
        let mixed = FirewallObject::AddressSet(FirewallAddressSet {
            id: "mixed".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: FirewallFamily::Any,
            entries: vec![
                FirewallSetEntry::Mac("02:00:00:00:00:01".into()),
                FirewallSetEntry::Port(PortRange {
                    start: 443,
                    end: 443,
                }),
            ],
        });
        assert_eq!(
            validate_firewall_object(&mixed),
            Err(FirewallPlanError::MixedSetTypes)
        );
        let mut unmanaged = restrictive_rule("foreign");
        let FirewallObject::FilterRule(rule) = &mut unmanaged else {
            unreachable!()
        };
        rule.ownership = ObjectOwnership::Unmanaged;
        assert_eq!(
            plan_firewall_mutations(
                &inventory_with_zones(vec![]),
                &[FirewallMutation::Create(unmanaged)],
                &FirewallRiskContext::default(),
            ),
            Err(FirewallPlanError::Unmanaged)
        );
    }

    #[test]
    fn deleting_a_restrictive_rule_is_versioned_and_r3() {
        let existing = restrictive_rule("block-untrusted");
        let digest = firewall_object_digest(&existing).expect("digest");
        let plan = plan_firewall_mutations(
            &inventory_with_zones(vec![existing]),
            &[FirewallMutation::Delete {
                kind: "filter_rule".into(),
                id: "block-untrusted".into(),
                expected_digest: digest,
            }],
            &FirewallRiskContext::default(),
        )
        .expect("delete plan");
        assert_eq!(plan.risk, RiskLevel::R3);
        assert!(plan.changes[0].diff.risk_signals.widens_network_exposure);
        assert!(plan.changes[0].after.is_none());
    }

    #[test]
    fn projected_state_rejects_dangling_zone_references() {
        let inventory = inventory_with_zones(vec![restrictive_rule("keep-reference")]);
        let guest = inventory
            .objects
            .iter()
            .find(|object| object.kind() == "zone" && object.id() == "guest")
            .expect("guest zone");
        let digest = firewall_object_digest(guest).expect("digest");
        assert_eq!(
            plan_firewall_mutations(
                &inventory,
                &[FirewallMutation::Delete {
                    kind: "zone".into(),
                    id: "guest".into(),
                    expected_digest: digest,
                }],
                &FirewallRiskContext::default(),
            ),
            Err(FirewallPlanError::DanglingReference)
        );
    }
}
