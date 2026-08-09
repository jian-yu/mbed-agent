use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use agent_protocol::{
    ChangeDiff, ChangeOperation, ChangePlan, ChangeRiskSignals, ConfigDomain, ConfigObjectRef,
    IpNetwork, NetworkAddressMode, NetworkBond, NetworkBridge, NetworkDhcpServerConfig,
    NetworkFamily, NetworkInterfaceConfig, NetworkObject, NetworkPolicyAction, NetworkPolicyRule,
    NetworkRoute, NetworkRouteType, NetworkVlan, NetworkVrf, ObjectOwnership, RiskLevel,
};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_OBJECTS: usize = 256;
const MAX_MUTATIONS: usize = 32;
const MAX_LIST_VALUES: usize = 32;
const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_EXECUTION_PLAN_BYTES: usize = 256 * 1024;
pub const NETWORK_EXECUTION_PLAN_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInventory {
    pub objects: Vec<NetworkObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMutation {
    Create(NetworkObject),
    Update {
        expected_digest: String,
        desired: NetworkObject,
    },
    Delete {
        kind: String,
        id: String,
        expected_digest: String,
    },
    Move {
        expected_digest: String,
        desired: NetworkObject,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRiskContext {
    pub management_interfaces: Vec<String>,
    pub management_addresses: Vec<IpAddr>,
    pub default_route_ids: Vec<String>,
    pub management_route_tables: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPlannedChange {
    pub before: Option<NetworkObject>,
    pub after: Option<NetworkObject>,
    pub diff: ChangeDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkMutationPlan {
    pub risk: RiskLevel,
    pub changes: Vec<NetworkPlannedChange>,
}

/// Stored executable payload paired with the exact user-visible plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkExecutionPlan {
    pub schema_version: u16,
    pub preview: ChangePlan,
    pub typed: NetworkMutationPlan,
}

impl NetworkExecutionPlan {
    /// Revalidates the complete typed payload and its user-visible preview.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, invalid preview, object or digest mismatch,
    /// malformed typed object, or capacity overflow.
    pub fn validate(&self) -> Result<(), NetworkExecutionPlanError> {
        if self.schema_version != NETWORK_EXECUTION_PLAN_SCHEMA_VERSION {
            return Err(NetworkExecutionPlanError::UnsupportedSchema);
        }
        crate::plan_digest(&self.preview).map_err(|_| NetworkExecutionPlanError::InvalidPreview)?;
        if self.preview.risk != self.typed.risk
            || self.preview.changes.len() != self.typed.changes.len()
            || self.typed.changes.is_empty()
            || self.typed.changes.len() > MAX_MUTATIONS
        {
            return Err(NetworkExecutionPlanError::PlanMismatch);
        }
        for (preview, typed) in self.preview.changes.iter().zip(&self.typed.changes) {
            validate_execution_change(preview, typed)?;
        }
        let encoded = serde_json::to_vec(self).map_err(|_| NetworkExecutionPlanError::Encode)?;
        if encoded.len() > MAX_EXECUTION_PLAN_BYTES {
            return Err(NetworkExecutionPlanError::Capacity);
        }
        Ok(())
    }

    /// Encodes one bounded and fully validated execution payload.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or bounded encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, NetworkExecutionPlanError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| NetworkExecutionPlanError::Encode)
    }

    /// Decodes and fully revalidates a bounded execution payload.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, or semantically inconsistent input.
    pub fn decode(encoded: &[u8]) -> Result<Self, NetworkExecutionPlanError> {
        if encoded.is_empty() || encoded.len() > MAX_EXECUTION_PLAN_BYTES {
            return Err(NetworkExecutionPlanError::Capacity);
        }
        let plan: Self =
            serde_json::from_slice(encoded).map_err(|_| NetworkExecutionPlanError::Decode)?;
        plan.validate()?;
        Ok(plan)
    }
}

fn validate_execution_change(
    preview: &ChangeDiff,
    typed: &NetworkPlannedChange,
) -> Result<(), NetworkExecutionPlanError> {
    if preview != &typed.diff {
        return Err(NetworkExecutionPlanError::PlanMismatch);
    }
    let object = typed
        .after
        .as_ref()
        .or(typed.before.as_ref())
        .ok_or(NetworkExecutionPlanError::PlanMismatch)?;
    if preview.object.domain != ConfigDomain::Network
        || preview.object.kind != object.kind()
        || preview.object.id != object.id()
        || preview.object.ownership != object.ownership()
        || object.ownership() == ObjectOwnership::Unmanaged
    {
        return Err(NetworkExecutionPlanError::PlanMismatch);
    }
    if let Some(before) = &typed.before {
        validate_network_object(before).map_err(|_| NetworkExecutionPlanError::InvalidObject)?;
    }
    if let Some(after) = &typed.after {
        validate_network_object(after).map_err(|_| NetworkExecutionPlanError::InvalidObject)?;
    }
    let before_digest = typed
        .before
        .as_ref()
        .map(network_object_digest)
        .transpose()
        .map_err(|_| NetworkExecutionPlanError::InvalidObject)?;
    let after_digest = typed
        .after
        .as_ref()
        .map(network_object_digest)
        .transpose()
        .map_err(|_| NetworkExecutionPlanError::InvalidObject)?;
    if preview.before_digest != before_digest
        || preview.after_digest != after_digest
        || preview.object.expected_version != before_digest
    {
        return Err(NetworkExecutionPlanError::DigestMismatch);
    }
    let valid_shape = match preview.operation {
        ChangeOperation::Create => typed.before.is_none() && typed.after.is_some(),
        ChangeOperation::Update | ChangeOperation::Move => {
            typed.before.is_some() && typed.after.is_some()
        }
        ChangeOperation::Delete => typed.before.is_some() && typed.after.is_none(),
    };
    if valid_shape {
        Ok(())
    } else {
        Err(NetworkExecutionPlanError::PlanMismatch)
    }
}

/// Plans typed L2/L3 mutations against a fresh inventory.
///
/// # Errors
///
/// Returns an error for invalid objects, stale versions, unsupported ownership or moves,
/// duplicate mutations, topology conflicts, or capacity overflow.
pub fn plan_network_mutations(
    inventory: &NetworkInventory,
    mutations: &[NetworkMutation],
    context: &NetworkRiskContext,
) -> Result<NetworkMutationPlan, NetworkPlanError> {
    if inventory.objects.len() > MAX_OBJECTS
        || mutations.is_empty()
        || mutations.len() > MAX_MUTATIONS
    {
        return Err(NetworkPlanError::Capacity);
    }
    validate_context(context)?;
    let mut current = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_network_object(object)?;
        if current.insert(object_key(object), object).is_some() {
            return Err(NetworkPlanError::DuplicateObject);
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
            .ok_or(NetworkPlanError::InvalidMutation)?;
        let key = (object.kind().to_owned(), object.id().to_owned());
        if !touched.insert(key.clone()) {
            return Err(NetworkPlanError::DuplicateMutation);
        }
        let ownership = object.ownership();
        if ownership == ObjectOwnership::Unmanaged {
            return Err(NetworkPlanError::Unmanaged);
        }
        if before
            .as_ref()
            .is_some_and(|value| value.ownership() != ownership)
        {
            return Err(NetworkPlanError::OwnershipChanged);
        }
        let signals = assess_mutation(operation, before.as_ref(), after.as_ref(), context);
        if signals.affects_management_path
            || signals.widens_network_exposure
            || signals.disrupts_service
        {
            risk = RiskLevel::R3;
        }
        let before_digest = before.as_ref().map(network_object_digest).transpose()?;
        let after_digest = after.as_ref().map(network_object_digest).transpose()?;
        let summary = mutation_summary(operation, object);
        changes.push(NetworkPlannedChange {
            before,
            after,
            diff: ChangeDiff {
                object: ConfigObjectRef {
                    domain: ConfigDomain::Network,
                    kind: key.0,
                    id: key.1,
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
    validate_projected_topology(inventory, &changes)?;
    Ok(NetworkMutationPlan { risk, changes })
}

/// Applies a validated plan to a fresh typed inventory without touching the host.
///
/// # Errors
///
/// Returns an error when the plan does not exactly match the inventory or the projected
/// topology violates platform-independent invariants.
pub fn project_network_inventory(
    inventory: &NetworkInventory,
    plan: &NetworkMutationPlan,
) -> Result<NetworkInventory, NetworkPlanError> {
    if inventory.objects.len() > MAX_OBJECTS
        || plan.changes.is_empty()
        || plan.changes.len() > MAX_MUTATIONS
    {
        return Err(NetworkPlanError::Capacity);
    }
    let mut projected = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_network_object(object)?;
        let key = (object.kind().to_owned(), object.id().to_owned());
        if projected.insert(key, object.clone()).is_some() {
            return Err(NetworkPlanError::DuplicateObject);
        }
    }
    let mut touched = HashSet::new();
    for change in &plan.changes {
        validate_execution_change(&change.diff, change)
            .map_err(|_| NetworkPlanError::PlanMismatch)?;
        let object = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(NetworkPlanError::PlanMismatch)?;
        let key = (object.kind().to_owned(), object.id().to_owned());
        if !touched.insert(key.clone()) {
            return Err(NetworkPlanError::DuplicateMutation);
        }
        match change.diff.operation {
            ChangeOperation::Create if !projected.contains_key(&key) => {
                projected.insert(
                    key,
                    change.after.clone().ok_or(NetworkPlanError::PlanMismatch)?,
                );
            }
            ChangeOperation::Update | ChangeOperation::Move
                if change.before.as_ref() == projected.get(&key) =>
            {
                projected.insert(
                    key,
                    change.after.clone().ok_or(NetworkPlanError::PlanMismatch)?,
                );
            }
            ChangeOperation::Delete if change.before.as_ref() == projected.get(&key) => {
                projected.remove(&key);
            }
            _ => return Err(NetworkPlanError::PlanMismatch),
        }
    }
    let mut objects: Vec<_> = projected.into_values().collect();
    objects.sort_by(|left, right| {
        left.kind()
            .cmp(right.kind())
            .then_with(|| left.id().cmp(right.id()))
    });
    let result = NetworkInventory { objects };
    validate_inventory_topology(&result)?;
    Ok(result)
}

/// Verifies all touched objects against the approved desired state.
///
/// # Errors
///
/// Returns an error for malformed or duplicate live objects, malformed plans, or any touched
/// object that differs from the approved desired state.
pub fn verify_network_plan_result(
    inventory: &NetworkInventory,
    plan: &NetworkMutationPlan,
) -> Result<(), NetworkPlanError> {
    let mut live = HashMap::with_capacity(inventory.objects.len());
    for object in &inventory.objects {
        validate_network_object(object)?;
        if live.insert((object.kind(), object.id()), object).is_some() {
            return Err(NetworkPlanError::DuplicateObject);
        }
    }
    for change in &plan.changes {
        validate_execution_change(&change.diff, change)
            .map_err(|_| NetworkPlanError::PlanMismatch)?;
        let object = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(NetworkPlanError::PlanMismatch)?;
        let key = (object.kind(), object.id());
        match &change.after {
            Some(expected) if live.get(&key).copied() == Some(expected) => {}
            None if !live.contains_key(&key) => {}
            _ => return Err(NetworkPlanError::PlanMismatch),
        }
    }
    Ok(())
}

fn resolve_mutation(
    current: &HashMap<(&str, &str), &NetworkObject>,
    mutation: &NetworkMutation,
) -> Result<
    (
        ChangeOperation,
        Option<NetworkObject>,
        Option<NetworkObject>,
    ),
    NetworkPlanError,
> {
    match mutation {
        NetworkMutation::Create(desired) => {
            validate_network_object(desired)?;
            if desired.ownership() == ObjectOwnership::Unmanaged {
                return Err(NetworkPlanError::Unmanaged);
            }
            if desired.ownership() != ObjectOwnership::AgentOwned {
                return Err(NetworkPlanError::CreateOwnership);
            }
            if current.contains_key(&object_key(desired)) {
                return Err(NetworkPlanError::AlreadyExists);
            }
            Ok((ChangeOperation::Create, None, Some(desired.clone())))
        }
        NetworkMutation::Update {
            expected_digest,
            desired,
        } => {
            validate_network_object(desired)?;
            let existing = find_versioned(current, desired.kind(), desired.id(), expected_digest)?;
            if existing == desired {
                return Err(NetworkPlanError::NoChange);
            }
            Ok((
                ChangeOperation::Update,
                Some(existing.clone()),
                Some(desired.clone()),
            ))
        }
        NetworkMutation::Delete {
            kind,
            id,
            expected_digest,
        } => {
            validate_identifier(kind, "kind")?;
            validate_identifier(id, "id")?;
            let existing = find_versioned(current, kind, id, expected_digest)?;
            Ok((ChangeOperation::Delete, Some(existing.clone()), None))
        }
        NetworkMutation::Move {
            expected_digest,
            desired,
        } => resolve_move(current, expected_digest, desired),
    }
}

fn resolve_move(
    current: &HashMap<(&str, &str), &NetworkObject>,
    expected_digest: &str,
    desired: &NetworkObject,
) -> Result<
    (
        ChangeOperation,
        Option<NetworkObject>,
        Option<NetworkObject>,
    ),
    NetworkPlanError,
> {
    validate_network_object(desired)?;
    let NetworkObject::PolicyRule(desired_rule) = desired else {
        return Err(NetworkPlanError::UnsupportedMove);
    };
    let existing = find_versioned(current, desired.kind(), desired.id(), expected_digest)?;
    let NetworkObject::PolicyRule(existing_rule) = existing else {
        return Err(NetworkPlanError::UnsupportedMove);
    };
    let mut reordered = existing_rule.clone();
    reordered.priority = desired_rule.priority;
    if reordered != *desired_rule {
        return Err(NetworkPlanError::MoveChangesContent);
    }
    if existing_rule.priority == desired_rule.priority {
        return Err(NetworkPlanError::NoChange);
    }
    Ok((
        ChangeOperation::Move,
        Some(existing.clone()),
        Some(desired.clone()),
    ))
}

fn find_versioned<'a>(
    current: &HashMap<(&str, &str), &'a NetworkObject>,
    kind: &str,
    id: &str,
    expected_digest: &str,
) -> Result<&'a NetworkObject, NetworkPlanError> {
    let object = current
        .get(&(kind, id))
        .copied()
        .ok_or(NetworkPlanError::NotFound)?;
    if object.ownership() == ObjectOwnership::Unmanaged {
        return Err(NetworkPlanError::Unmanaged);
    }
    if network_object_digest(object)? != expected_digest {
        return Err(NetworkPlanError::StaleVersion);
    }
    Ok(object)
}

/// Returns the canonical SHA-256 version of a validated network object.
///
/// # Errors
///
/// Returns an error when the object is invalid or canonical encoding fails.
pub fn network_object_digest(object: &NetworkObject) -> Result<String, NetworkPlanError> {
    validate_network_object(object)?;
    let encoded = serde_json::to_vec(object).map_err(|_| NetworkPlanError::Encode)?;
    Ok(lower_hex(digest(&SHA256, &encoded).as_ref()))
}

/// Performs platform-independent L2/L3 schema checks.
///
/// # Errors
///
/// Returns a structured error when any field, relationship, or bound is invalid.
pub fn validate_network_object(object: &NetworkObject) -> Result<(), NetworkPlanError> {
    validate_identifier(object.id(), "id")?;
    match object {
        NetworkObject::Interface(value) => validate_interface(value),
        NetworkObject::Bridge(value) => validate_bridge(value),
        NetworkObject::Vlan(value) => validate_vlan(value),
        NetworkObject::Bond(value) => validate_bond(value),
        NetworkObject::Vrf(value) => validate_vrf(value),
        NetworkObject::Route(value) => validate_route(value),
        NetworkObject::PolicyRule(value) => validate_policy_rule(value),
    }
}

fn validate_interface(value: &NetworkInterfaceConfig) -> Result<(), NetworkPlanError> {
    validate_identifier(&value.device, "interface device")?;
    validate_mtu(value.mtu)?;
    if let Some(mac) = &value.mac_override {
        validate_mac(mac)?;
    }
    if value.addresses.len() > MAX_LIST_VALUES {
        return Err(NetworkPlanError::Capacity);
    }
    let mut unique = HashSet::new();
    let mut has_v4 = false;
    let mut has_v6 = false;
    for address in &value.addresses {
        validate_host_prefix(address)?;
        has_v4 |= address.address.is_ipv4();
        has_v6 |= address.address.is_ipv6();
        if !unique.insert(address) {
            return Err(NetworkPlanError::DuplicateValue);
        }
    }
    if (has_v4 && value.ipv4_mode != NetworkAddressMode::Static)
        || (has_v6 && value.ipv6_mode != NetworkAddressMode::Static)
        || (value.ipv4_mode == NetworkAddressMode::Static && !has_v4)
        || (value.ipv6_mode == NetworkAddressMode::Static && !has_v6)
    {
        return Err(NetworkPlanError::InvalidField("interface address mode"));
    }
    if value.dns_servers.len() > 8 || value.dns_search.len() > 16 {
        return Err(NetworkPlanError::Capacity);
    }
    let mut dns_servers = HashSet::new();
    for server in &value.dns_servers {
        if server.is_unspecified() || server.is_multicast() || !dns_servers.insert(server) {
            return Err(NetworkPlanError::InvalidField("interface DNS server"));
        }
    }
    let mut search = HashSet::new();
    for suffix in &value.dns_search {
        if !valid_dns_search_suffix(suffix) || !search.insert(suffix) {
            return Err(NetworkPlanError::InvalidField(
                "interface DNS search suffix",
            ));
        }
    }
    for field in [
        value.dhcp_client_id.as_deref(),
        value.dhcp_vendor_id.as_deref(),
        value.dhcp_hostname.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !valid_dhcp_text(field) {
            return Err(NetworkPlanError::InvalidField("interface DHCP text"));
        }
    }
    if value.dhcp_request_options.len() > 16 {
        return Err(NetworkPlanError::Capacity);
    }
    let mut request_options = HashSet::new();
    for option in &value.dhcp_request_options {
        if *option == 0 || *option > 255 || !request_options.insert(option) {
            return Err(NetworkPlanError::InvalidField(
                "interface DHCP request option",
            ));
        }
    }
    if let Some(server) = &value.dhcp_server {
        validate_dhcp_server(value, server)?;
    }
    Ok(())
}

fn valid_dns_search_suffix(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn valid_dhcp_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !matches!(byte, b'\'' | b'\\'))
}

fn validate_dhcp_server(
    interface: &NetworkInterfaceConfig,
    value: &NetworkDhcpServerConfig,
) -> Result<(), NetworkPlanError> {
    if interface.ipv4_mode != NetworkAddressMode::Static
        || !interface
            .addresses
            .iter()
            .any(|address| address.address.is_ipv4())
    {
        return Err(NetworkPlanError::InvalidField("interface DHCP server mode"));
    }
    if !(1..=254).contains(&value.start)
        || !(1..=254).contains(&value.limit)
        || u32::from(value.start) + u32::from(value.limit) > 255
    {
        return Err(NetworkPlanError::InvalidField("interface DHCP pool"));
    }
    if !valid_dhcp_lease_time(&value.lease_time) {
        return Err(NetworkPlanError::InvalidField("interface DHCP lease time"));
    }
    if value.dhcp_options.len() > 16 {
        return Err(NetworkPlanError::Capacity);
    }
    let mut options = HashSet::new();
    for option in &value.dhcp_options {
        if !(1..=255).contains(&option.code)
            || !valid_dhcp_option_value(&option.value)
            || !options.insert((option.code, &option.value))
        {
            return Err(NetworkPlanError::InvalidField("interface DHCP option"));
        }
    }
    if value.static_leases.len() > 32 {
        return Err(NetworkPlanError::Capacity);
    }
    let interface_addresses: Vec<_> = interface
        .addresses
        .iter()
        .filter_map(|address| match address.address {
            IpAddr::V4(value) => Some((address, value)),
            IpAddr::V6(_) => None,
        })
        .collect();
    let mut lease_ids = HashSet::new();
    let mut lease_macs = HashSet::new();
    let mut lease_addresses = HashSet::new();
    for lease in &value.static_leases {
        validate_identifier(&lease.id, "DHCP static lease id")?;
        validate_mac(&lease.mac)?;
        let IpAddr::V4(address) = lease.address else {
            return Err(NetworkPlanError::InvalidField("DHCP static lease address"));
        };
        let matching_networks: Vec<_> = interface_addresses
            .iter()
            .filter(|(network, _)| ipv4_in_network(network, address))
            .collect();
        if matching_networks.len() != 1 {
            return Err(NetworkPlanError::InvalidField("DHCP static lease address"));
        }
        let (network, _) = matching_networks[0];
        let offset = ipv4_host_offset(network, address);
        let host_count = (!ipv4_mask(network.prefix_len)).saturating_sub(1);
        if offset == 0 || (network.prefix_len < 31 && offset == host_count) {
            return Err(NetworkPlanError::InvalidField("DHCP static lease address"));
        }
        if u32::from(value.start) <= offset
            && offset < u32::from(value.start).saturating_add(u32::from(value.limit))
        {
            return Err(NetworkPlanError::InvalidField("DHCP static lease pool"));
        }
        if !lease_ids.insert(&lease.id)
            || !lease_macs.insert(&lease.mac)
            || !lease_addresses.insert(address)
            || interface_addresses
                .iter()
                .any(|(_, current)| *current == address)
        {
            return Err(NetworkPlanError::InvalidField(
                "DHCP static lease duplicate",
            ));
        }
        if lease
            .hostname
            .as_deref()
            .is_some_and(|hostname| !valid_dhcp_text(hostname))
        {
            return Err(NetworkPlanError::InvalidField("DHCP static lease hostname"));
        }
        if lease
            .lease_time
            .as_deref()
            .is_some_and(|lease_time| !valid_dhcp_lease_time(lease_time))
        {
            return Err(NetworkPlanError::InvalidField("DHCP static lease time"));
        }
    }
    Ok(())
}

fn valid_dhcp_option_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !matches!(byte, b'\'' | b'\\' | b','))
}

fn valid_dhcp_lease_time(value: &str) -> bool {
    if value == "infinite" {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 2
        && bytes.len() <= 16
        && matches!(bytes.last(), Some(b's' | b'm' | b'h' | b'd' | b'w'))
        && bytes[..bytes.len() - 1].iter().all(u8::is_ascii_digit)
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len <= 32 {
        u32::MAX << (32 - prefix_len)
    } else {
        0
    }
}

fn ipv4_in_network(network: &IpNetwork, address: std::net::Ipv4Addr) -> bool {
    let IpAddr::V4(network_address) = network.address else {
        return false;
    };
    let mask = ipv4_mask(network.prefix_len);
    (u32::from(network_address) & mask) == (u32::from(address) & mask)
}

fn ipv4_host_offset(network: &IpNetwork, address: std::net::Ipv4Addr) -> u32 {
    let IpAddr::V4(network_address) = network.address else {
        return u32::MAX;
    };
    u32::from(address).saturating_sub(u32::from(network_address) & ipv4_mask(network.prefix_len))
}

fn validate_bridge(value: &NetworkBridge) -> Result<(), NetworkPlanError> {
    validate_members(&value.ports, "bridge port", true)?;
    validate_mtu(value.mtu)
}

fn validate_vlan(value: &NetworkVlan) -> Result<(), NetworkPlanError> {
    validate_identifier(&value.parent, "VLAN parent")?;
    if value.parent == value.id || !(1..=4094).contains(&value.vlan_id) {
        return Err(NetworkPlanError::InvalidField("VLAN"));
    }
    validate_mtu(value.mtu)
}

fn validate_bond(value: &NetworkBond) -> Result<(), NetworkPlanError> {
    validate_members(&value.ports, "bond port", true)?;
    if value.monitor_interval_ms > 60_000 {
        return Err(NetworkPlanError::InvalidField("bond monitor interval"));
    }
    if let Some(primary) = &value.primary {
        validate_identifier(primary, "bond primary")?;
        if !value.ports.contains(primary) {
            return Err(NetworkPlanError::InvalidField("bond primary"));
        }
    }
    validate_mtu(value.mtu)
}

fn validate_vrf(value: &NetworkVrf) -> Result<(), NetworkPlanError> {
    if value.table == 0 {
        return Err(NetworkPlanError::InvalidField("VRF table"));
    }
    validate_members(&value.ports, "VRF port", false)?;
    validate_mtu(value.mtu)
}

fn validate_route(value: &NetworkRoute) -> Result<(), NetworkPlanError> {
    validate_network_prefix(&value.destination)?;
    if value.table == 0 {
        return Err(NetworkPlanError::InvalidField("route table"));
    }
    if let Some(interface) = &value.output_interface {
        validate_identifier(interface, "route output interface")?;
    }
    for address in [value.gateway, value.preferred_source]
        .into_iter()
        .flatten()
    {
        if address.is_ipv4() != value.destination.address.is_ipv4() {
            return Err(NetworkPlanError::InvalidField("route address family"));
        }
    }
    match value.route_type {
        NetworkRouteType::Unicast
            if value.gateway.is_some() || value.output_interface.is_some() => {}
        NetworkRouteType::Blackhole
        | NetworkRouteType::Unreachable
        | NetworkRouteType::Prohibit
            if value.gateway.is_none()
                && value.output_interface.is_none()
                && value.preferred_source.is_none() => {}
        _ => return Err(NetworkPlanError::InvalidField("route next hop")),
    }
    Ok(())
}

fn validate_policy_rule(value: &NetworkPolicyRule) -> Result<(), NetworkPlanError> {
    if value.priority == 0 {
        return Err(NetworkPlanError::InvalidField("policy priority"));
    }
    for network in [value.source, value.destination].into_iter().flatten() {
        validate_network_prefix(&network)?;
        if network.address.is_ipv4() != (value.family == NetworkFamily::Ipv4) {
            return Err(NetworkPlanError::InvalidField("policy address family"));
        }
    }
    for interface in [&value.input_interface, &value.output_interface]
        .into_iter()
        .flatten()
    {
        validate_identifier(interface, "policy interface")?;
    }
    if value.fwmark.is_some() != value.fwmark_mask.is_some() || value.fwmark_mask == Some(0) {
        return Err(NetworkPlanError::InvalidField("policy fwmark"));
    }
    match value.action {
        NetworkPolicyAction::Lookup if value.table != 0 => {}
        NetworkPolicyAction::Blackhole
        | NetworkPolicyAction::Unreachable
        | NetworkPolicyAction::Prohibit
            if value.table == 0 => {}
        _ => return Err(NetworkPlanError::InvalidField("policy action table")),
    }
    Ok(())
}

fn validate_projected_topology(
    inventory: &NetworkInventory,
    changes: &[NetworkPlannedChange],
) -> Result<(), NetworkPlanError> {
    let mut objects: HashMap<(String, String), NetworkObject> = inventory
        .objects
        .iter()
        .cloned()
        .map(|object| ((object.kind().to_owned(), object.id().to_owned()), object))
        .collect();
    for change in changes {
        if let Some(before) = &change.before {
            objects.remove(&(before.kind().to_owned(), before.id().to_owned()));
        }
        if let Some(after) = &change.after {
            objects.insert(
                (after.kind().to_owned(), after.id().to_owned()),
                after.clone(),
            );
        }
    }
    validate_inventory_topology(&NetworkInventory {
        objects: objects.into_values().collect(),
    })
}

fn validate_inventory_topology(inventory: &NetworkInventory) -> Result<(), NetworkPlanError> {
    let mut aggregate_ports = HashSet::new();
    let mut vrf_tables = HashSet::new();
    let mut policy_priorities = HashSet::new();
    for object in &inventory.objects {
        match object {
            NetworkObject::Bridge(value) => {
                for port in &value.ports {
                    if port == &value.id || !aggregate_ports.insert(port) {
                        return Err(NetworkPlanError::TopologyConflict);
                    }
                }
            }
            NetworkObject::Bond(value) => {
                for port in &value.ports {
                    if port == &value.id || !aggregate_ports.insert(port) {
                        return Err(NetworkPlanError::TopologyConflict);
                    }
                }
            }
            NetworkObject::Vrf(value) => {
                if !vrf_tables.insert(value.table) {
                    return Err(NetworkPlanError::TopologyConflict);
                }
            }
            NetworkObject::PolicyRule(value) if value.enabled => {
                if !policy_priorities.insert((value.family, value.priority)) {
                    return Err(NetworkPlanError::TopologyConflict);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn assess_mutation(
    operation: ChangeOperation,
    before: Option<&NetworkObject>,
    after: Option<&NetworkObject>,
    context: &NetworkRiskContext,
) -> ChangeRiskSignals {
    let touches_management = before
        .into_iter()
        .chain(after)
        .any(|object| object_touches_management(object, context));
    let changes_default_route = before
        .into_iter()
        .chain(after)
        .any(|object| is_default_or_management_route(object, context));
    let disrupts_service = match (operation, before, after) {
        (ChangeOperation::Delete, Some(object), _) => object_enabled(object),
        (_, Some(before), Some(after)) => {
            object_enabled(before)
                && (!object_enabled(after) || active_network_content_changed(before, after))
        }
        _ => false,
    };
    ChangeRiskSignals {
        affects_management_path: touches_management || changes_default_route,
        widens_network_exposure: false,
        disrupts_service,
        changes_secret: false,
        changes_device_authentication: false,
        irreversible: false,
    }
}

fn object_touches_management(object: &NetworkObject, context: &NetworkRiskContext) -> bool {
    if context
        .management_interfaces
        .iter()
        .any(|interface| interface == object.id())
    {
        return true;
    }
    let references: Vec<&str> = match object {
        NetworkObject::Interface(value) => vec![&value.device],
        NetworkObject::Bridge(value) => value.ports.iter().map(String::as_str).collect(),
        NetworkObject::Vlan(value) => vec![&value.parent],
        NetworkObject::Bond(value) => value.ports.iter().map(String::as_str).collect(),
        NetworkObject::Vrf(value) => value.ports.iter().map(String::as_str).collect(),
        NetworkObject::Route(value) => value.output_interface.iter().map(String::as_str).collect(),
        NetworkObject::PolicyRule(value) => value
            .input_interface
            .iter()
            .chain(&value.output_interface)
            .map(String::as_str)
            .collect(),
    };
    references.iter().any(|reference| {
        context
            .management_interfaces
            .iter()
            .any(|value| value == reference)
    }) || match object {
        NetworkObject::Interface(value) => value
            .addresses
            .iter()
            .any(|address| context.management_addresses.contains(&address.address)),
        NetworkObject::Route(value) => value
            .preferred_source
            .is_some_and(|address| context.management_addresses.contains(&address)),
        _ => false,
    }
}

fn is_default_or_management_route(object: &NetworkObject, context: &NetworkRiskContext) -> bool {
    match object {
        NetworkObject::Route(value) => {
            value.destination.prefix_len == 0
                || context.default_route_ids.contains(&value.id)
                || context.management_route_tables.contains(&value.table)
        }
        NetworkObject::PolicyRule(value) => context.management_route_tables.contains(&value.table),
        NetworkObject::Vrf(value) => context.management_route_tables.contains(&value.table),
        _ => false,
    }
}

fn active_network_content_changed(before: &NetworkObject, after: &NetworkObject) -> bool {
    before != after
        && !matches!(
            (before, after),
            (NetworkObject::PolicyRule(left), NetworkObject::PolicyRule(right))
                if left.priority != right.priority && {
                    let mut reordered = left.clone();
                    reordered.priority = right.priority;
                    reordered == *right
                }
        )
}

fn object_enabled(object: &NetworkObject) -> bool {
    match object {
        NetworkObject::Interface(value) => value.enabled,
        NetworkObject::Bridge(value) => value.enabled,
        NetworkObject::Vlan(value) => value.enabled,
        NetworkObject::Bond(value) => value.enabled,
        NetworkObject::Vrf(value) => value.enabled,
        NetworkObject::Route(value) => value.enabled,
        NetworkObject::PolicyRule(value) => value.enabled,
    }
}

fn validate_context(value: &NetworkRiskContext) -> Result<(), NetworkPlanError> {
    validate_members(&value.management_interfaces, "management interface", false)?;
    validate_members(&value.default_route_ids, "default route", false)?;
    if value.management_addresses.len() > MAX_LIST_VALUES
        || value.management_route_tables.len() > MAX_LIST_VALUES
    {
        return Err(NetworkPlanError::Capacity);
    }
    reject_duplicates(&value.management_addresses)?;
    reject_duplicates(&value.management_route_tables)
}

fn validate_members(
    values: &[String],
    field: &'static str,
    require_nonempty: bool,
) -> Result<(), NetworkPlanError> {
    if values.len() > MAX_LIST_VALUES || (require_nonempty && values.is_empty()) {
        return Err(NetworkPlanError::Capacity);
    }
    for value in values {
        validate_identifier(value, field)?;
    }
    reject_duplicates(values)
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), NetworkPlanError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        Err(NetworkPlanError::InvalidIdentifier(field))
    } else {
        Ok(())
    }
}

fn validate_mtu(value: Option<u32>) -> Result<(), NetworkPlanError> {
    if value.is_some_and(|mtu| !(576..=65_535).contains(&mtu)) {
        Err(NetworkPlanError::InvalidField("MTU"))
    } else {
        Ok(())
    }
}

fn validate_mac(value: &str) -> Result<(), NetworkPlanError> {
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
        Err(NetworkPlanError::InvalidField("MAC address"))
    }
}

fn validate_host_prefix(value: &IpNetwork) -> Result<(), NetworkPlanError> {
    match value.address {
        IpAddr::V4(_) if value.prefix_len <= 32 => Ok(()),
        IpAddr::V6(_) if value.prefix_len <= 128 => Ok(()),
        _ => Err(NetworkPlanError::InvalidField("address prefix")),
    }
}

fn validate_network_prefix(value: &IpNetwork) -> Result<(), NetworkPlanError> {
    validate_host_prefix(value)?;
    let canonical = match value.address {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            let mask = if value.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - value.prefix_len)
            };
            bits & mask == bits
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            let mask = if value.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - value.prefix_len)
            };
            bits & mask == bits
        }
    };
    if canonical {
        Ok(())
    } else {
        Err(NetworkPlanError::InvalidField("network prefix"))
    }
}

fn reject_duplicates<T: Eq + std::hash::Hash>(values: &[T]) -> Result<(), NetworkPlanError> {
    let mut unique = HashSet::with_capacity(values.len());
    if values.iter().all(|value| unique.insert(value)) {
        Ok(())
    } else {
        Err(NetworkPlanError::DuplicateValue)
    }
}

fn object_key(object: &NetworkObject) -> (&str, &str) {
    (object.kind(), object.id())
}

fn mutation_summary(operation: ChangeOperation, object: &NetworkObject) -> String {
    let verb = match operation {
        ChangeOperation::Create => "create",
        ChangeOperation::Update => "update",
        ChangeOperation::Delete => "delete",
        ChangeOperation::Move => "move",
    };
    format!("{verb} managed network {} {}", object.kind(), object.id())
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
pub enum NetworkExecutionPlanError {
    #[error("network execution plan schema is unsupported")]
    UnsupportedSchema,
    #[error("network execution plan preview is invalid")]
    InvalidPreview,
    #[error("network execution plan does not match its preview")]
    PlanMismatch,
    #[error("network execution plan contains an invalid typed object")]
    InvalidObject,
    #[error("network execution plan object digest does not match")]
    DigestMismatch,
    #[error("network execution plan exceeds its capacity")]
    Capacity,
    #[error("failed to encode network execution plan")]
    Encode,
    #[error("failed to decode network execution plan")]
    Decode,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkPlanError {
    #[error("network plan exceeds its capacity")]
    Capacity,
    #[error("invalid network {0}")]
    InvalidField(&'static str),
    #[error("invalid network identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error("duplicate network object")]
    DuplicateObject,
    #[error("duplicate network mutation")]
    DuplicateMutation,
    #[error("duplicate network value")]
    DuplicateValue,
    #[error("network topology contains a conflicting port, table, or priority")]
    TopologyConflict,
    #[error("network object already exists")]
    AlreadyExists,
    #[error("network object was not found")]
    NotFound,
    #[error("network object version is stale")]
    StaleVersion,
    #[error("unmanaged network objects are read-only")]
    Unmanaged,
    #[error("network ownership cannot change in an update")]
    OwnershipChanged,
    #[error("new network objects must be Agent-owned")]
    CreateOwnership,
    #[error("network mutation has no semantic change")]
    NoChange,
    #[error("only policy rules support move")]
    UnsupportedMove,
    #[error("move may change only policy priority")]
    MoveChangesContent,
    #[error("failed to encode typed network object")]
    Encode,
    #[error("network mutation does not contain an object")]
    InvalidMutation,
    #[error("network mutation plan does not match fresh inventory")]
    PlanMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::{
        CHANGE_PLAN_SCHEMA_VERSION, NetworkDhcpMode, NetworkDhcpOption, NetworkDhcpStaticLease,
        NetworkPolicyAction, NetworkVlanProtocol,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn interface(id: &str, address: Ipv4Addr) -> NetworkObject {
        NetworkObject::Interface(NetworkInterfaceConfig {
            id: id.into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            device: id.into(),
            ipv4_mode: NetworkAddressMode::Static,
            ipv6_mode: NetworkAddressMode::Disabled,
            addresses: vec![IpNetwork {
                address: address.into(),
                prefix_len: 24,
            }],
            mtu: Some(1500),
            mac_override: None,
            peerdns: true,
            dns_servers: Vec::new(),
            dns_search: Vec::new(),
            dhcp_client_id: None,
            dhcp_vendor_id: None,
            dhcp_hostname: None,
            dhcp_request_options: Vec::new(),
            dhcp_no_release: false,
            dhcp_server: None,
        })
    }

    fn route(id: &str, prefix_len: u8) -> NetworkObject {
        NetworkObject::Route(NetworkRoute {
            id: id.into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            destination: IpNetwork {
                address: Ipv4Addr::UNSPECIFIED.into(),
                prefix_len,
            },
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
            output_interface: Some("wan".into()),
            preferred_source: None,
            table: 254,
            metric: Some(100),
            route_type: NetworkRouteType::Unicast,
        })
    }

    fn policy(id: &str, priority: u32) -> NetworkObject {
        NetworkObject::PolicyRule(NetworkPolicyRule {
            id: id.into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: NetworkFamily::Ipv4,
            priority,
            source: Some(IpNetwork {
                address: Ipv4Addr::new(192, 0, 2, 0).into(),
                prefix_len: 24,
            }),
            destination: None,
            input_interface: None,
            output_interface: None,
            fwmark: None,
            fwmark_mask: None,
            table: 100,
            action: NetworkPolicyAction::Lookup,
        })
    }

    #[test]
    fn plans_safe_new_interface_as_r2() {
        let inventory = NetworkInventory { objects: vec![] };
        let plan = plan_network_mutations(
            &inventory,
            &[NetworkMutation::Create(interface(
                "guest",
                Ipv4Addr::new(192, 0, 2, 1),
            ))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        assert_eq!(plan.risk, RiskLevel::R2);
        assert_eq!(plan.changes[0].diff.object.domain, ConfigDomain::Network);
    }

    #[test]
    fn management_interface_and_default_route_are_r3() {
        let existing = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        let digest = network_object_digest(&existing).expect("digest");
        let mut desired = existing.clone();
        let NetworkObject::Interface(value) = &mut desired else {
            unreachable!();
        };
        value.mtu = Some(1400);
        let plan = plan_network_mutations(
            &NetworkInventory {
                objects: vec![existing],
            },
            &[NetworkMutation::Update {
                expected_digest: digest,
                desired,
            }],
            &NetworkRiskContext {
                management_interfaces: vec!["lan".into()],
                ..NetworkRiskContext::default()
            },
        )
        .expect("plan");
        assert_eq!(plan.risk, RiskLevel::R3);
        assert!(plan.changes[0].diff.risk_signals.affects_management_path);

        let route_plan = plan_network_mutations(
            &NetworkInventory { objects: vec![] },
            &[NetworkMutation::Create(route("default-v4", 0))],
            &NetworkRiskContext::default(),
        )
        .expect("route plan");
        assert_eq!(route_plan.risk, RiskLevel::R3);
    }

    #[test]
    fn rejects_invalid_address_modes_and_route_families() {
        let mut invalid = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        let NetworkObject::Interface(value) = &mut invalid else {
            unreachable!();
        };
        value.ipv4_mode = NetworkAddressMode::Dhcp;
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface address mode"))
        );

        let mut invalid_route = route("bad", 0);
        let NetworkObject::Route(value) = &mut invalid_route else {
            unreachable!();
        };
        value.gateway = Some(Ipv6Addr::LOCALHOST.into());
        assert_eq!(
            validate_network_object(&invalid_route),
            Err(NetworkPlanError::InvalidField("route address family"))
        );
    }

    #[test]
    fn rejects_unsafe_interface_dns_overrides() {
        let mut invalid = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        if let NetworkObject::Interface(value) = &mut invalid {
            value.dns_servers = vec![Ipv4Addr::UNSPECIFIED.into()];
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface DNS server"))
        );

        if let NetworkObject::Interface(value) = &mut invalid {
            value.dns_servers.clear();
            value.dns_search = vec!["bad suffix".into()];
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField(
                "interface DNS search suffix"
            ))
        );
    }

    #[test]
    fn rejects_unsafe_interface_dhcp_options() {
        let mut invalid = interface("wan", Ipv4Addr::new(192, 0, 2, 1));
        if let NetworkObject::Interface(value) = &mut invalid {
            value.dhcp_client_id = Some("bad'client".into());
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface DHCP text"))
        );

        if let NetworkObject::Interface(value) = &mut invalid {
            value.dhcp_client_id = None;
            value.dhcp_request_options = vec![1, 1];
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField(
                "interface DHCP request option"
            ))
        );

        if let NetworkObject::Interface(value) = &mut invalid {
            value.dhcp_request_options = vec![256];
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField(
                "interface DHCP request option"
            ))
        );
    }

    #[test]
    fn rejects_dhcp_server_on_dynamic_interface_or_invalid_pool() {
        let mut invalid = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        if let NetworkObject::Interface(value) = &mut invalid {
            value.ipv4_mode = NetworkAddressMode::Dhcp;
            value.addresses.clear();
            value.dhcp_server = Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 100,
                limit: 100,
                lease_time: "12h".into(),
                force: false,
                dhcpv6_mode: NetworkDhcpMode::Server,
                ra_mode: NetworkDhcpMode::Server,
                ndp_mode: NetworkDhcpMode::Hybrid,
                dhcp_options: vec![],
                static_leases: vec![],
            });
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface DHCP server mode"))
        );

        let mut invalid = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        if let NetworkObject::Interface(value) = &mut invalid {
            value.dhcp_server = Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 200,
                limit: 100,
                lease_time: "12h".into(),
                force: false,
                dhcpv6_mode: NetworkDhcpMode::Server,
                ra_mode: NetworkDhcpMode::Server,
                ndp_mode: NetworkDhcpMode::Hybrid,
                dhcp_options: vec![],
                static_leases: vec![],
            });
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface DHCP pool"))
        );
    }

    #[test]
    fn rejects_unsafe_dhcp_server_options() {
        let mut invalid = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        if let NetworkObject::Interface(value) = &mut invalid {
            value.dhcp_server = Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 100,
                limit: 100,
                lease_time: "12h".into(),
                force: false,
                dhcpv6_mode: NetworkDhcpMode::Server,
                ra_mode: NetworkDhcpMode::Server,
                ndp_mode: NetworkDhcpMode::Hybrid,
                dhcp_options: vec![NetworkDhcpOption {
                    code: 6,
                    value: "1.1.1.1,8.8.8.8".into(),
                }],
                static_leases: vec![],
            });
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface DHCP option"))
        );

        let mut invalid = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        if let NetworkObject::Interface(value) = &mut invalid {
            value.dhcp_server = Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 100,
                limit: 100,
                lease_time: "12h".into(),
                force: false,
                dhcpv6_mode: NetworkDhcpMode::Server,
                ra_mode: NetworkDhcpMode::Server,
                ndp_mode: NetworkDhcpMode::Hybrid,
                dhcp_options: vec![
                    NetworkDhcpOption {
                        code: 6,
                        value: "1.1.1.1".into(),
                    },
                    NetworkDhcpOption {
                        code: 6,
                        value: "1.1.1.1".into(),
                    },
                ],
                static_leases: vec![],
            });
        } else {
            unreachable!();
        }
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("interface DHCP option"))
        );
    }

    #[test]
    fn accepts_dhcp_static_lease_outside_dynamic_pool() {
        let mut object = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        if let NetworkObject::Interface(value) = &mut object {
            value.dhcp_server = Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 100,
                limit: 100,
                lease_time: "12h".into(),
                force: false,
                dhcpv6_mode: NetworkDhcpMode::Server,
                ra_mode: NetworkDhcpMode::Server,
                ndp_mode: NetworkDhcpMode::Hybrid,
                dhcp_options: vec![],
                static_leases: vec![NetworkDhcpStaticLease {
                    id: "nas".into(),
                    mac: "11:22:33:44:55:66".into(),
                    address: "192.168.1.20".parse().expect("lease address"),
                    hostname: Some("nas".into()),
                    lease_time: Some("infinite".into()),
                }],
            });
        } else {
            unreachable!();
        }
        assert!(validate_network_object(&object).is_ok());
    }

    #[test]
    fn policy_move_changes_only_priority() {
        let existing = policy("guest-policy", 1000);
        let digest = network_object_digest(&existing).expect("digest");
        let mut desired = existing.clone();
        let NetworkObject::PolicyRule(value) = &mut desired else {
            unreachable!();
        };
        value.priority = 900;
        let plan = plan_network_mutations(
            &NetworkInventory {
                objects: vec![existing],
            },
            &[NetworkMutation::Move {
                expected_digest: digest,
                desired,
            }],
            &NetworkRiskContext::default(),
        )
        .expect("move");
        assert_eq!(plan.changes[0].diff.operation, ChangeOperation::Move);
    }

    #[test]
    fn rejects_stale_and_platform_native_create() {
        let existing = interface("lan", Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            plan_network_mutations(
                &NetworkInventory {
                    objects: vec![existing.clone()],
                },
                &[NetworkMutation::Update {
                    expected_digest: "0".repeat(64),
                    desired: interface("lan", Ipv4Addr::new(192, 168, 2, 1)),
                }],
                &NetworkRiskContext::default(),
            ),
            Err(NetworkPlanError::StaleVersion)
        );
        let mut native = interface("wan", Ipv4Addr::new(198, 51, 100, 2));
        let NetworkObject::Interface(value) = &mut native else {
            unreachable!();
        };
        value.ownership = ObjectOwnership::PlatformNative;
        assert_eq!(
            plan_network_mutations(
                &NetworkInventory { objects: vec![] },
                &[NetworkMutation::Create(native)],
                &NetworkRiskContext::default(),
            ),
            Err(NetworkPlanError::CreateOwnership)
        );
    }

    #[test]
    fn topology_rejects_duplicate_aggregate_port() {
        let bridge = NetworkObject::Bridge(NetworkBridge {
            id: "br-lan".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            ports: vec!["eth0".into()],
            stp: true,
            vlan_filtering: false,
            mtu: Some(1500),
        });
        let bond = NetworkObject::Bond(NetworkBond {
            id: "bond0".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            ports: vec!["eth0".into()],
            mode: agent_protocol::NetworkBondMode::ActiveBackup,
            primary: Some("eth0".into()),
            monitor_interval_ms: 100,
            mtu: Some(1500),
        });
        assert_eq!(
            plan_network_mutations(
                &NetworkInventory { objects: vec![] },
                &[
                    NetworkMutation::Create(bridge),
                    NetworkMutation::Create(bond)
                ],
                &NetworkRiskContext::default(),
            ),
            Err(NetworkPlanError::TopologyConflict)
        );
    }

    #[test]
    fn projects_and_verifies_approved_state() {
        let inventory = NetworkInventory { objects: vec![] };
        let plan = plan_network_mutations(
            &inventory,
            &[NetworkMutation::Create(interface(
                "guest",
                Ipv4Addr::new(192, 0, 2, 1),
            ))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let projected = project_network_inventory(&inventory, &plan).expect("project");
        verify_network_plan_result(&projected, &plan).expect("verify");
    }

    #[test]
    fn execution_payload_rejects_tampered_typed_object() {
        let typed = plan_network_mutations(
            &NetworkInventory { objects: vec![] },
            &[NetworkMutation::Create(interface(
                "guest",
                Ipv4Addr::new(192, 0, 2, 1),
            ))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let preview = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "network-plan-1".into(),
            boot_id: "boot-1".into(),
            actor_id: "cli:root".into(),
            created_monotonic_ms: 100,
            expires_monotonic_ms: 200,
            risk: typed.risk,
            changes: typed
                .changes
                .iter()
                .map(|change| change.diff.clone())
                .collect(),
            validation_checks: vec!["native network validation".into()],
            verification_checks: vec!["fresh network inventory matches desired state".into()],
            rollback_required: true,
        };
        let mut execution = NetworkExecutionPlan {
            schema_version: NETWORK_EXECUTION_PLAN_SCHEMA_VERSION,
            preview,
            typed,
        };
        execution.validate().expect("valid");
        let Some(NetworkObject::Interface(value)) = &mut execution.typed.changes[0].after else {
            unreachable!();
        };
        value.mtu = Some(1400);
        assert_eq!(
            execution.validate(),
            Err(NetworkExecutionPlanError::DigestMismatch)
        );
    }

    #[test]
    fn validates_vlan_and_policy_constraints() {
        let vlan = NetworkObject::Vlan(NetworkVlan {
            id: "eth0.100".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            parent: "eth0".into(),
            vlan_id: 100,
            protocol: NetworkVlanProtocol::Ieee8021Q,
            mtu: Some(1500),
        });
        validate_network_object(&vlan).expect("valid VLAN");

        let mut invalid = policy("marked", 100);
        let NetworkObject::PolicyRule(value) = &mut invalid else {
            unreachable!();
        };
        value.fwmark = Some(1);
        assert_eq!(
            validate_network_object(&invalid),
            Err(NetworkPlanError::InvalidField("policy fwmark"))
        );
    }
}
