//! Typed reconstruction of generic Linux network state from fixed `ip -j` observations.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use agent_core::{
    NetworkInventory, NetworkMutationPlan, network_object_digest, project_network_inventory,
    validate_network_object,
};
use agent_protocol::{
    IpNetwork, NetworkAddressMode, NetworkFamily, NetworkInterfaceConfig, NetworkObject,
    NetworkPolicyAction, NetworkPolicyRule, NetworkRoute, NetworkRouteType, ObjectOwnership,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MAX_OBJECTS: usize = 256;
const MAX_ADDRESSES_PER_INTERFACE: usize = 32;
const MAX_NAME_BYTES: usize = 64;
const MAX_CANONICAL_BYTES: usize = 256 * 1024;
const MAX_BATCH_BYTES: usize = 64 * 1024;
const RUNTIME_ROUTE_PROTOCOL: u64 = 186;
const RUNTIME_POLICY_PRIORITY_START: u32 = 32_000;
const RUNTIME_POLICY_PRIORITY_END: u32 = 32_063;
const RUNTIME_INTERFACE_PREFIX: &str = "agent_";

#[derive(Debug, Error)]
pub enum RuntimeNetworkInventoryError {
    #[error("runtime network observation is malformed")]
    Malformed,
    #[error("runtime network observation exceeds its bound")]
    Capacity,
    #[error("runtime network object is not safely representable")]
    Unsupported,
    #[error("runtime network canonical state is stale or corrupt")]
    StaleState,
    #[error("Agent-owned runtime network state is orphaned or drifted")]
    NativeDrift,
    #[error("network plan contains an unsupported runtime object")]
    InvalidPlan,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRouteCanonicalState {
    schema_version: u32,
    boot_id: String,
    inventory: NetworkInventory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRouteSnapshot {
    boot_id: String,
    inventory: NetworkInventory,
}

impl RuntimeRouteSnapshot {
    #[must_use]
    pub fn inventory(&self) -> &NetworkInventory {
        &self.inventory
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRouteStage {
    pub apply_batch: String,
    pub rollback_batch: String,
    pub projected_canonical_state: Vec<u8>,
}

/// Reports whether a bounded canonical runtime payload contains Agent-owned interface profiles.
///
/// # Errors
///
/// Returns an error for an empty, oversized, malformed, or unsupported canonical payload.
pub fn runtime_canonical_includes_interfaces(
    encoded: &[u8],
) -> Result<bool, RuntimeNetworkInventoryError> {
    if encoded.is_empty() || encoded.len() > MAX_CANONICAL_BYTES {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let canonical: RuntimeRouteCanonicalState =
        serde_json::from_slice(encoded).map_err(|_| RuntimeNetworkInventoryError::StaleState)?;
    if !matches!(canonical.schema_version, 1 | 2) {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    Ok(canonical
        .inventory
        .objects
        .iter()
        .any(|object| matches!(object, NetworkObject::Interface(_))))
}

/// Reconstructs a safely representable generic Linux interface and route inventory.
///
/// Kernel state cannot prove persistent-manager ownership, so objects are platform-native.
/// Ambiguous route forms such as multipath are intentionally omitted.
///
/// # Errors
///
/// Returns an error for malformed top-level JSON, duplicate identities, invalid typed values, or
/// capacity overflow.
pub fn inspect_runtime_network_inventory(
    links_json: &str,
    addresses_json: &str,
    routes_json: &str,
) -> Result<NetworkInventory, RuntimeNetworkInventoryError> {
    let links = json_array(links_json)?;
    let addresses = json_array(addresses_json)?;
    let routes = json_array(routes_json)?;
    if links.len() > MAX_OBJECTS || addresses.len() > MAX_OBJECTS || routes.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }

    let mut interface_addresses: HashMap<String, Vec<IpNetwork>> = HashMap::new();
    let mut dynamic_v4 = HashSet::new();
    let mut dynamic_v6 = HashSet::new();
    for record in &addresses {
        let Some(name) = bounded_string(record, "ifname") else {
            continue;
        };
        let Some(values) = record.get("addr_info").and_then(Value::as_array) else {
            continue;
        };
        if values.len() > MAX_ADDRESSES_PER_INTERFACE {
            return Err(RuntimeNetworkInventoryError::Capacity);
        }
        for value in values {
            let Some(network) = address(value) else {
                continue;
            };
            let dynamic = value.get("dynamic").and_then(Value::as_bool) == Some(true)
                || value.get("temporary").and_then(Value::as_bool) == Some(true);
            if dynamic && network.address.is_ipv4() {
                dynamic_v4.insert(name.clone());
            } else if dynamic {
                dynamic_v6.insert(name.clone());
            }
            let entries = interface_addresses.entry(name.clone()).or_default();
            if !entries.contains(&network) {
                entries.push(network);
            }
        }
    }

    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for link in &links {
        let name = bounded_string(link, "ifname").ok_or(RuntimeNetworkInventoryError::Malformed)?;
        if !seen.insert(name.clone()) {
            return Err(RuntimeNetworkInventoryError::Malformed);
        }
        let mut addresses = interface_addresses.remove(&name).unwrap_or_default();
        let observed_v4 = addresses.iter().any(|value| value.address.is_ipv4());
        let observed_v6 = addresses.iter().any(|value| value.address.is_ipv6());
        if dynamic_v4.contains(&name) {
            addresses.retain(|value| !value.address.is_ipv4());
        }
        if dynamic_v6.contains(&name) {
            addresses.retain(|value| !value.address.is_ipv6());
        }
        let enabled = link
            .get("flags")
            .and_then(Value::as_array)
            .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP")));
        let mtu = link
            .get("mtu")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok());
        objects.push(NetworkObject::Interface(NetworkInterfaceConfig {
            id: name.clone(),
            ownership: ObjectOwnership::PlatformNative,
            enabled,
            device: name.clone(),
            ipv4_mode: address_mode(observed_v4, dynamic_v4.contains(&name), false),
            ipv6_mode: address_mode(observed_v6, dynamic_v6.contains(&name), true),
            addresses,
            mtu,
            // The current kernel address does not prove a configured MAC override.
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
        }));
    }

    for route in &routes {
        if owned_protocol(route.get("protocol")) {
            continue;
        }
        if let Some(route) = route_object(route)? {
            if !seen.insert(route.id.clone()) {
                return Err(RuntimeNetworkInventoryError::Malformed);
            }
            objects.push(NetworkObject::Route(route));
        }
        if objects.len() > MAX_OBJECTS {
            return Err(RuntimeNetworkInventoryError::Capacity);
        }
    }
    for object in &objects {
        network_object_digest(object).map_err(|_| RuntimeNetworkInventoryError::Unsupported)?;
    }
    Ok(NetworkInventory { objects })
}

/// Reconstructs representable generic Linux policy rules outside the reserved
/// Agent-owned preference range.
///
/// # Errors
///
/// Returns an error for malformed JSON, unsafe reserved rules, or capacity overflow.
pub fn inspect_runtime_policy_inventory(
    rules_json: &str,
) -> Result<NetworkInventory, RuntimeNetworkInventoryError> {
    let values = json_array(rules_json)?;
    if values.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for value in &values {
        let Some(rule) = policy_rule_object(value)? else {
            continue;
        };
        if rule.ownership == ObjectOwnership::AgentOwned {
            continue;
        }
        if !seen.insert(rule.id.clone()) {
            return Err(RuntimeNetworkInventoryError::Malformed);
        }
        objects.push(NetworkObject::PolicyRule(rule));
    }
    Ok(NetworkInventory { objects })
}

/// Reconciles protocol-186 runtime routes with boot-bound volatile canonical state.
///
/// # Errors
///
/// Returns an error for malformed observations, orphaned owned routes, stale/corrupt canonical
/// state, native drift, invalid route objects, or capacity overflow.
pub fn reconcile_runtime_route_inventory(
    routes_json: &str,
    canonical_state: Option<&[u8]>,
    boot_id: &str,
) -> Result<RuntimeRouteSnapshot, RuntimeNetworkInventoryError> {
    reconcile_runtime_network_inventory(routes_json, "[]", canonical_state, boot_id)
}

/// Reconciles Agent-owned ephemeral routes and policy rules with boot-bound
/// volatile canonical state.
///
/// # Errors
///
/// Returns an error for malformed observations, orphaned owned objects, stale
/// canonical state, native drift, invalid objects, or capacity overflow.
pub fn reconcile_runtime_network_inventory(
    routes_json: &str,
    rules_json: &str,
    canonical_state: Option<&[u8]>,
    boot_id: &str,
) -> Result<RuntimeRouteSnapshot, RuntimeNetworkInventoryError> {
    if boot_id.is_empty() || boot_id.len() > 128 || boot_id.chars().any(char::is_control) {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    let mut native = owned_native_routes(routes_json)?;
    native.extend(owned_native_policy_rules(rules_json)?);
    let Some(encoded) = canonical_state else {
        if !native.is_empty() {
            return Err(RuntimeNetworkInventoryError::NativeDrift);
        }
        return Ok(RuntimeRouteSnapshot {
            boot_id: boot_id.into(),
            inventory: NetworkInventory { objects: vec![] },
        });
    };
    let canonical = decode_runtime_canonical(encoded, boot_id)?;
    let expected = canonical_runtime_objects(&canonical.inventory, false)?;
    if runtime_semantics(&native)? != runtime_semantics(&expected)? {
        return Err(RuntimeNetworkInventoryError::NativeDrift);
    }
    Ok(RuntimeRouteSnapshot {
        boot_id: canonical.boot_id,
        inventory: canonical.inventory,
    })
}

/// Reconciles the full generic Linux runtime inventory, including Agent-owned static-address
/// profiles bound to existing kernel links. Platform-native interfaces remain visible but are
/// never writable through this path.
///
/// # Errors
///
/// Returns an error for malformed observations, stale canonical state, orphaned Agent-owned
/// routes/rules/profiles, or an Agent-owned profile whose device/address no longer exists.
pub fn reconcile_runtime_network_inventory_with_links(
    links_json: &str,
    addresses_json: &str,
    routes_json: &str,
    rules_json: &str,
    canonical_state: Option<&[u8]>,
    boot_id: &str,
) -> Result<RuntimeRouteSnapshot, RuntimeNetworkInventoryError> {
    if boot_id.is_empty() || boot_id.len() > 128 || boot_id.chars().any(char::is_control) {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    let native_inventory =
        inspect_runtime_network_inventory(links_json, addresses_json, routes_json)?;
    let native_policy = inspect_runtime_policy_inventory(rules_json)?;
    let mut native_owned = owned_native_routes(routes_json)?;
    native_owned.extend(owned_native_policy_rules(rules_json)?);
    let Some(encoded) = canonical_state else {
        if !native_owned.is_empty() {
            return Err(RuntimeNetworkInventoryError::NativeDrift);
        }
        let mut inventory = native_inventory;
        inventory.objects.extend(native_policy.objects);
        return Ok(RuntimeRouteSnapshot {
            boot_id: boot_id.into(),
            inventory,
        });
    };
    let canonical = decode_runtime_canonical(encoded, boot_id)?;
    if canonical.schema_version == 1
        && canonical
            .inventory
            .objects
            .iter()
            .any(|object| matches!(object, NetworkObject::Interface(_)))
    {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    let expected = canonical_runtime_objects(&canonical.inventory, true)?;
    let expected_routes = expected
        .iter()
        .filter(|object| !matches!(object, NetworkObject::Interface(_)))
        .cloned()
        .collect::<Vec<_>>();
    if runtime_semantics(&native_owned)? != runtime_semantics(&expected_routes)? {
        return Err(RuntimeNetworkInventoryError::NativeDrift);
    }
    verify_runtime_interface_profiles(&canonical.inventory, links_json, addresses_json)?;

    let mut inventory = native_inventory;
    inventory.objects.extend(native_policy.objects);
    for object in expected {
        if inventory
            .objects
            .iter()
            .any(|existing| existing.kind() == object.kind() && existing.id() == object.id())
        {
            return Err(RuntimeNetworkInventoryError::NativeDrift);
        }
        inventory.objects.push(object);
    }
    if inventory.objects.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    Ok(RuntimeRouteSnapshot {
        boot_id: canonical.boot_id,
        inventory,
    })
}

/// Renders an exact typed route/policy-rule plan into closed apply/rollback `ip -batch` artifacts.
///
/// Only Agent-owned routes and reserved-priority policy rules are accepted. Every installed route
/// carries protocol 186; no caller text, command, argument, or path enters the artifacts.
///
/// # Errors
///
/// Returns an error for stale plans, non-route/platform-native objects, unsupported route shapes,
/// malformed boot identity, encoding failure, or bounded output overflow.
pub fn render_runtime_route_stage(
    snapshot: &RuntimeRouteSnapshot,
    plan: &NetworkMutationPlan,
) -> Result<RuntimeRouteStage, RuntimeNetworkInventoryError> {
    let projected = project_network_inventory(&snapshot.inventory, plan)
        .map_err(|_| RuntimeNetworkInventoryError::InvalidPlan)?;
    let projected_owned = projected_runtime_objects(&projected, true)?;
    let mut apply = String::new();
    let mut rollback = String::new();
    for change in &plan.changes {
        push_runtime_change(&mut apply, change)?;
    }
    for change in plan.changes.iter().rev() {
        push_runtime_reverse_change(&mut rollback, change)?;
    }
    if apply.is_empty() || apply.len() > MAX_BATCH_BYTES || rollback.len() > MAX_BATCH_BYTES {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let canonical = RuntimeRouteCanonicalState {
        schema_version: if projected_owned
            .iter()
            .any(|object| matches!(object, NetworkObject::Interface(_)))
        {
            2
        } else {
            1
        },
        boot_id: snapshot.boot_id.clone(),
        inventory: NetworkInventory {
            objects: projected_owned,
        },
    };
    let projected_canonical_state =
        serde_json::to_vec(&canonical).map_err(|_| RuntimeNetworkInventoryError::StaleState)?;
    if projected_canonical_state.len() > MAX_CANONICAL_BYTES {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    Ok(RuntimeRouteStage {
        apply_batch: apply,
        rollback_batch: rollback,
        projected_canonical_state,
    })
}

fn owned_native_routes(
    routes_json: &str,
) -> Result<Vec<NetworkObject>, RuntimeNetworkInventoryError> {
    let values = json_array(routes_json)?;
    if values.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let mut routes = Vec::new();
    for value in &values {
        if !owned_protocol(value.get("protocol")) {
            continue;
        }
        let Some(mut route) = route_object(value)? else {
            return Err(RuntimeNetworkInventoryError::Unsupported);
        };
        route.ownership = ObjectOwnership::AgentOwned;
        routes.push(NetworkObject::Route(route));
    }
    Ok(routes)
}

fn owned_native_policy_rules(
    rules_json: &str,
) -> Result<Vec<NetworkObject>, RuntimeNetworkInventoryError> {
    let values = json_array(rules_json)?;
    if values.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let mut rules = Vec::new();
    for value in &values {
        let Some(rule) = policy_rule_object(value)? else {
            continue;
        };
        if rule.ownership == ObjectOwnership::AgentOwned {
            rules.push(NetworkObject::PolicyRule(rule));
        }
    }
    Ok(rules)
}

fn owned_protocol(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Number(value)) => value.as_u64() == Some(RUNTIME_ROUTE_PROTOCOL),
        Some(Value::String(value)) => value == "186",
        _ => false,
    }
}

fn decode_runtime_canonical(
    encoded: &[u8],
    boot_id: &str,
) -> Result<RuntimeRouteCanonicalState, RuntimeNetworkInventoryError> {
    if encoded.is_empty() || encoded.len() > MAX_CANONICAL_BYTES {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let canonical: RuntimeRouteCanonicalState =
        serde_json::from_slice(encoded).map_err(|_| RuntimeNetworkInventoryError::StaleState)?;
    if !matches!(canonical.schema_version, 1 | 2) || canonical.boot_id != boot_id {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    Ok(canonical)
}

fn verify_runtime_interface_profiles(
    inventory: &NetworkInventory,
    links_json: &str,
    addresses_json: &str,
) -> Result<(), RuntimeNetworkInventoryError> {
    let links = json_array(links_json)?;
    let addresses = json_array(addresses_json)?;
    if links.len() > MAX_OBJECTS || addresses.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let mut devices = HashSet::new();
    for link in &links {
        let name = bounded_string(link, "ifname").ok_or(RuntimeNetworkInventoryError::Malformed)?;
        if !devices.insert(name) {
            return Err(RuntimeNetworkInventoryError::Malformed);
        }
    }
    let observed = observed_interface_addresses(&addresses)?;
    let mut claimed = HashSet::new();
    for object in &inventory.objects {
        let NetworkObject::Interface(interface) = object else {
            continue;
        };
        require_owned_interface(interface)?;
        if !devices.contains(&interface.device) {
            return Err(RuntimeNetworkInventoryError::NativeDrift);
        }
        let current = observed
            .get(&interface.device)
            .ok_or(RuntimeNetworkInventoryError::NativeDrift)?;
        for address in &interface.addresses {
            if !current.contains(address) || !claimed.insert((&interface.device, *address)) {
                return Err(RuntimeNetworkInventoryError::NativeDrift);
            }
        }
    }
    Ok(())
}

fn observed_interface_addresses(
    values: &[Value],
) -> Result<std::collections::HashMap<String, Vec<IpNetwork>>, RuntimeNetworkInventoryError> {
    let mut result = std::collections::HashMap::new();
    for record in values {
        let Some(name) = bounded_string(record, "ifname") else {
            continue;
        };
        let Some(entries) = record.get("addr_info").and_then(Value::as_array) else {
            continue;
        };
        if entries.len() > MAX_ADDRESSES_PER_INTERFACE {
            return Err(RuntimeNetworkInventoryError::Capacity);
        }
        let output = result.entry(name).or_insert_with(Vec::new);
        for entry in entries {
            if let Some(address) = address(entry) {
                if !output.contains(&address) {
                    output.push(address);
                }
            }
        }
    }
    Ok(result)
}

fn canonical_runtime_objects(
    inventory: &NetworkInventory,
    allow_interfaces: bool,
) -> Result<Vec<NetworkObject>, RuntimeNetworkInventoryError> {
    if inventory.objects.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let mut output = Vec::new();
    let mut interface_devices = HashSet::new();
    for object in &inventory.objects {
        if object.ownership() != ObjectOwnership::AgentOwned {
            return Err(RuntimeNetworkInventoryError::InvalidPlan);
        }
        if matches!(object, NetworkObject::Interface(_)) && !allow_interfaces {
            return Err(RuntimeNetworkInventoryError::InvalidPlan);
        }
        require_owned_runtime_object(object)?;
        if let NetworkObject::Interface(interface) = object {
            if !interface_devices.insert(interface.device.as_str()) {
                return Err(RuntimeNetworkInventoryError::InvalidPlan);
            }
        }
        output.push(object.clone());
    }
    Ok(output)
}

fn projected_runtime_objects(
    inventory: &NetworkInventory,
    allow_interfaces: bool,
) -> Result<Vec<NetworkObject>, RuntimeNetworkInventoryError> {
    let owned = NetworkInventory {
        objects: inventory
            .objects
            .iter()
            .filter(|object| object.ownership() == ObjectOwnership::AgentOwned)
            .cloned()
            .collect(),
    };
    canonical_runtime_objects(&owned, allow_interfaces)
}

fn require_owned_runtime_object(
    object: &NetworkObject,
) -> Result<(), RuntimeNetworkInventoryError> {
    match object {
        NetworkObject::Interface(interface) => require_owned_interface(interface),
        NetworkObject::Route(route) => require_owned_route(route),
        NetworkObject::PolicyRule(rule) => require_owned_policy_rule(rule),
        _ => Err(RuntimeNetworkInventoryError::InvalidPlan),
    }
}

fn require_owned_interface(
    interface: &NetworkInterfaceConfig,
) -> Result<(), RuntimeNetworkInventoryError> {
    if interface.ownership != ObjectOwnership::AgentOwned
        || !interface.enabled
        || !interface.id.starts_with(RUNTIME_INTERFACE_PREFIX)
        || interface.mtu.is_some()
        || interface.mac_override.is_some()
        || !interface.peerdns
        || !interface.dns_servers.is_empty()
        || !interface.dns_search.is_empty()
        || interface.dhcp_client_id.is_some()
        || interface.dhcp_vendor_id.is_some()
        || interface.dhcp_hostname.is_some()
        || !interface.dhcp_request_options.is_empty()
        || interface.dhcp_no_release
        || interface.dhcp_server.is_some()
    {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    if interface
        .addresses
        .iter()
        .any(|address| address.address.is_unspecified() || address.address.is_multicast())
    {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    network_object_digest(&NetworkObject::Interface(interface.clone()))
        .map(|_| ())
        .map_err(|_| RuntimeNetworkInventoryError::InvalidPlan)
}

fn require_owned_route(route: &NetworkRoute) -> Result<(), RuntimeNetworkInventoryError> {
    if route.ownership != ObjectOwnership::AgentOwned || !route.enabled {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    network_object_digest(&NetworkObject::Route(route.clone()))
        .map(|_| ())
        .map_err(|_| RuntimeNetworkInventoryError::InvalidPlan)
}

fn require_owned_policy_rule(rule: &NetworkPolicyRule) -> Result<(), RuntimeNetworkInventoryError> {
    if rule.ownership != ObjectOwnership::AgentOwned
        || !rule.enabled
        || !reserved_policy_priority(rule.priority)
    {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    network_object_digest(&NetworkObject::PolicyRule(rule.clone()))
        .map(|_| ())
        .map_err(|_| RuntimeNetworkInventoryError::InvalidPlan)
}

fn runtime_semantics(
    objects: &[NetworkObject],
) -> Result<Vec<Vec<u8>>, RuntimeNetworkInventoryError> {
    let mut values = objects
        .iter()
        .map(|object| {
            let mut normalized = object.clone();
            match &mut normalized {
                NetworkObject::Route(route) => {
                    route.id.clear();
                    route.ownership = ObjectOwnership::AgentOwned;
                }
                NetworkObject::PolicyRule(rule) => {
                    rule.id.clear();
                    rule.ownership = ObjectOwnership::AgentOwned;
                }
                _ => return Err(RuntimeNetworkInventoryError::InvalidPlan),
            }
            serde_json::to_vec(&normalized).map_err(|_| RuntimeNetworkInventoryError::StaleState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    Ok(values)
}

fn push_runtime_command(
    output: &mut String,
    operation: &str,
    object: &NetworkObject,
) -> Result<(), RuntimeNetworkInventoryError> {
    match object {
        NetworkObject::Interface(interface) => push_interface_command(output, operation, interface),
        NetworkObject::Route(route) => push_route_command(output, operation, route),
        NetworkObject::PolicyRule(rule) => push_policy_rule_command(output, operation, rule),
        _ => Err(RuntimeNetworkInventoryError::InvalidPlan),
    }
}

fn push_runtime_change(
    output: &mut String,
    change: &agent_core::NetworkPlannedChange,
) -> Result<(), RuntimeNetworkInventoryError> {
    match (change.before.as_ref(), change.after.as_ref()) {
        (Some(NetworkObject::Interface(before)), Some(NetworkObject::Interface(after))) => {
            require_owned_interface(before)?;
            require_owned_interface(after)?;
            push_interface_diff_command(output, before, after)
        }
        (before, after) => {
            if let Some(before) = before {
                require_owned_runtime_object(before)?;
                push_runtime_command(output, "del", before)?;
            }
            if let Some(after) = after {
                require_owned_runtime_object(after)?;
                push_runtime_command(output, "add", after)?;
            }
            Ok(())
        }
    }
}

fn push_runtime_reverse_change(
    output: &mut String,
    change: &agent_core::NetworkPlannedChange,
) -> Result<(), RuntimeNetworkInventoryError> {
    match (change.before.as_ref(), change.after.as_ref()) {
        (Some(NetworkObject::Interface(before)), Some(NetworkObject::Interface(after))) => {
            require_owned_interface(before)?;
            require_owned_interface(after)?;
            push_interface_diff_command_reverse(output, before, after)
        }
        (before, after) => {
            if let Some(after) = after {
                require_owned_runtime_object(after)?;
                push_runtime_command(output, "del", after)?;
            }
            if let Some(before) = before {
                require_owned_runtime_object(before)?;
                push_runtime_command(output, "add", before)?;
            }
            Ok(())
        }
    }
}

fn push_interface_command(
    output: &mut String,
    operation: &str,
    interface: &NetworkInterfaceConfig,
) -> Result<(), RuntimeNetworkInventoryError> {
    if operation != "add" && operation != "del" {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    for address in &interface.addresses {
        use std::fmt::Write;
        writeln!(
            output,
            "address {operation} {}/{} dev {}",
            address.address, address.prefix_len, interface.device
        )
        .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    Ok(())
}

fn push_interface_diff_command(
    output: &mut String,
    before: &NetworkInterfaceConfig,
    after: &NetworkInterfaceConfig,
) -> Result<(), RuntimeNetworkInventoryError> {
    let mut before_shape = before.clone();
    before_shape.addresses.clear();
    let mut after_shape = after.clone();
    after_shape.addresses.clear();
    if before_shape != after_shape {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    for address in &before.addresses {
        if !after.addresses.contains(address) {
            push_interface_command(
                output,
                "del",
                &NetworkInterfaceConfig {
                    addresses: vec![*address],
                    ..before.clone()
                },
            )?;
        }
    }
    for address in &after.addresses {
        if !before.addresses.contains(address) {
            push_interface_command(
                output,
                "add",
                &NetworkInterfaceConfig {
                    addresses: vec![*address],
                    ..after.clone()
                },
            )?;
        }
    }
    Ok(())
}

fn push_interface_diff_command_reverse(
    output: &mut String,
    before: &NetworkInterfaceConfig,
    after: &NetworkInterfaceConfig,
) -> Result<(), RuntimeNetworkInventoryError> {
    push_interface_diff_command(output, after, before)
}

fn push_route_command(
    output: &mut String,
    operation: &str,
    route: &NetworkRoute,
) -> Result<(), RuntimeNetworkInventoryError> {
    use std::fmt::Write;
    let family = if route.destination.address.is_ipv4() {
        "-4"
    } else {
        "-6"
    };
    write!(output, "{family} route {operation} ")
        .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    match route.route_type {
        NetworkRouteType::Unicast => {}
        NetworkRouteType::Blackhole => output.push_str("blackhole "),
        NetworkRouteType::Unreachable => output.push_str("unreachable "),
        NetworkRouteType::Prohibit => output.push_str("prohibit "),
    }
    if route.destination.prefix_len == 0 {
        output.push_str("default");
    } else {
        write!(
            output,
            "{}/{}",
            route.destination.address, route.destination.prefix_len
        )
        .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(gateway) = route.gateway {
        write!(output, " via {gateway}").map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(interface) = &route.output_interface {
        write!(output, " dev {interface}").map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(source) = route.preferred_source {
        write!(output, " src {source}").map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    write!(
        output,
        " table {} proto {RUNTIME_ROUTE_PROTOCOL}",
        route.table
    )
    .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    if let Some(metric) = route.metric {
        write!(output, " metric {metric}").map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    output.push('\n');
    Ok(())
}

fn push_policy_rule_command(
    output: &mut String,
    operation: &str,
    rule: &NetworkPolicyRule,
) -> Result<(), RuntimeNetworkInventoryError> {
    use std::fmt::Write;
    let family = match rule.family {
        NetworkFamily::Ipv4 => "-4",
        NetworkFamily::Ipv6 => "-6",
    };
    write!(
        output,
        "{family} rule {operation} priority {}",
        rule.priority
    )
    .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    if let Some(source) = rule.source {
        write!(output, " from {}/{}", source.address, source.prefix_len)
            .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(destination) = rule.destination {
        write!(
            output,
            " to {}/{}",
            destination.address, destination.prefix_len
        )
        .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(interface) = &rule.input_interface {
        write!(output, " iifname {interface}")
            .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(interface) = &rule.output_interface {
        write!(output, " oifname {interface}")
            .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
    }
    if let Some(mark) = rule.fwmark {
        write!(output, " fwmark {mark:#x}").map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
        if let Some(mask) = rule.fwmark_mask {
            write!(output, "/{mask:#x}").map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
        }
    }
    match rule.action {
        NetworkPolicyAction::Lookup => {
            write!(output, " table {}", rule.table)
                .map_err(|_| RuntimeNetworkInventoryError::Capacity)?;
        }
        NetworkPolicyAction::Blackhole => output.push_str(" blackhole"),
        NetworkPolicyAction::Unreachable => output.push_str(" unreachable"),
        NetworkPolicyAction::Prohibit => output.push_str(" prohibit"),
    }
    output.push('\n');
    Ok(())
}

fn json_array(input: &str) -> Result<Vec<Value>, RuntimeNetworkInventoryError> {
    serde_json::from_str::<Value>(input)
        .map_err(|_| RuntimeNetworkInventoryError::Malformed)?
        .as_array()
        .cloned()
        .ok_or(RuntimeNetworkInventoryError::Malformed)
}

fn address(value: &Value) -> Option<IpNetwork> {
    let address: IpAddr = value.get("local")?.as_str()?.parse().ok()?;
    let prefix_len = u8::try_from(value.get("prefixlen")?.as_u64()?).ok()?;
    (prefix_len <= if address.is_ipv4() { 32 } else { 128 }).then_some(IpNetwork {
        address,
        prefix_len,
    })
}

const fn address_mode(present: bool, dynamic: bool, ipv6: bool) -> NetworkAddressMode {
    if !present {
        NetworkAddressMode::Disabled
    } else if dynamic && ipv6 {
        NetworkAddressMode::Automatic
    } else if dynamic {
        NetworkAddressMode::Dhcp
    } else {
        NetworkAddressMode::Static
    }
}

fn route_object(value: &Value) -> Result<Option<NetworkRoute>, RuntimeNetworkInventoryError> {
    if value.get("multipath").is_some() || value.get("nhid").is_some() {
        return Ok(None);
    }
    let gateway: Option<IpAddr> = value
        .get("gateway")
        .and_then(Value::as_str)
        .and_then(|item| item.parse().ok());
    let destination = match value.get("dst").and_then(Value::as_str) {
        None | Some("default") => default_network(value, gateway),
        Some(value) => parse_network(value).ok_or(RuntimeNetworkInventoryError::Malformed)?,
    };
    let output_interface = bounded_string(value, "dev");
    let preferred_source = value
        .get("prefsrc")
        .and_then(Value::as_str)
        .and_then(|item| item.parse().ok());
    let table = route_table(value.get("table"))?;
    let metric = value
        .get("metric")
        .and_then(Value::as_u64)
        .and_then(|item| u32::try_from(item).ok());
    let route_type = match value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unicast")
    {
        "unicast" => NetworkRouteType::Unicast,
        "blackhole" => NetworkRouteType::Blackhole,
        "unreachable" => NetworkRouteType::Unreachable,
        "prohibit" => NetworkRouteType::Prohibit,
        _ => return Ok(None),
    };
    let identity = format!(
        "{}|{}|{gateway:?}|{output_interface:?}|{preferred_source:?}|{table}|{metric:?}|{route_type:?}",
        destination.address, destination.prefix_len
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
    Ok(Some(NetworkRoute {
        id: format!("kernel-{}", hex_prefix(digest.as_ref(), 12)),
        ownership: ObjectOwnership::PlatformNative,
        enabled: true,
        destination,
        gateway,
        output_interface,
        preferred_source,
        table,
        metric,
        route_type,
    }))
}

fn policy_rule_object(
    value: &Value,
) -> Result<Option<NetworkPolicyRule>, RuntimeNetworkInventoryError> {
    const SUPPORTED: &[&str] = &[
        "priority", "pref", "src", "from", "dst", "to", "iifname", "oifname", "fwmark", "table",
        "action", "family",
    ];
    let priority = value
        .get("priority")
        .or_else(|| value.get("pref"))
        .and_then(parse_u32)
        .ok_or(RuntimeNetworkInventoryError::Malformed)?;
    let reserved = reserved_policy_priority(priority);
    if value
        .as_object()
        .is_none_or(|object| object.keys().any(|key| !SUPPORTED.contains(&key.as_str())))
    {
        return if reserved {
            Err(RuntimeNetworkInventoryError::Unsupported)
        } else {
            Ok(None)
        };
    }
    let source = parse_rule_network(value.get("src").or_else(|| value.get("from")))?;
    let destination = parse_rule_network(value.get("dst").or_else(|| value.get("to")))?;
    let family = match value.get("family").and_then(Value::as_str) {
        Some("inet" | "ipv4") => NetworkFamily::Ipv4,
        Some("inet6" | "ipv6") => NetworkFamily::Ipv6,
        Some(_) => return Err(RuntimeNetworkInventoryError::Malformed),
        None if source.is_some_and(|network| network.address.is_ipv6())
            || destination.is_some_and(|network| network.address.is_ipv6()) =>
        {
            NetworkFamily::Ipv6
        }
        None if source.is_some() || destination.is_some() => NetworkFamily::Ipv4,
        None => {
            return if reserved {
                Err(RuntimeNetworkInventoryError::Unsupported)
            } else {
                Ok(None)
            };
        }
    };
    if source.is_some_and(|network| network.address.is_ipv4() != (family == NetworkFamily::Ipv4))
        || destination
            .is_some_and(|network| network.address.is_ipv4() != (family == NetworkFamily::Ipv4))
    {
        return Err(RuntimeNetworkInventoryError::Malformed);
    }
    let action = match value
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("lookup")
    {
        "lookup" | "to_tbl" => NetworkPolicyAction::Lookup,
        "blackhole" => NetworkPolicyAction::Blackhole,
        "unreachable" => NetworkPolicyAction::Unreachable,
        "prohibit" => NetworkPolicyAction::Prohibit,
        _ => {
            return if reserved {
                Err(RuntimeNetworkInventoryError::Unsupported)
            } else {
                Ok(None)
            };
        }
    };
    let table = parse_rule_table(value.get("table"))?;
    let (fwmark, fwmark_mask) = parse_fwmark(value.get("fwmark"))?;
    let input_interface = optional_bounded_rule_string(value, "iifname")?;
    let output_interface = optional_bounded_rule_string(value, "oifname")?;
    let mut rule = NetworkPolicyRule {
        id: "runtime-rule".into(),
        ownership: if reserved {
            ObjectOwnership::AgentOwned
        } else {
            ObjectOwnership::PlatformNative
        },
        enabled: true,
        family,
        priority,
        source,
        destination,
        input_interface,
        output_interface,
        fwmark,
        fwmark_mask,
        table,
        action,
    };
    validate_network_object(&NetworkObject::PolicyRule(rule.clone()))
        .map_err(|_| RuntimeNetworkInventoryError::Unsupported)?;
    rule.id.clear();
    let mut identity = serde_json::to_vec(&NetworkObject::PolicyRule(rule.clone()))
        .map_err(|_| RuntimeNetworkInventoryError::Unsupported)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &identity);
    rule.id = format!("kernel-rule-{}", hex_prefix(digest.as_ref(), 12));
    identity.fill(0);
    Ok(Some(rule))
}

fn parse_rule_network(
    value: Option<&Value>,
) -> Result<Option<IpNetwork>, RuntimeNetworkInventoryError> {
    let Some(value) = value.and_then(Value::as_str) else {
        return Ok(None);
    };
    if value == "all" {
        return Ok(None);
    }
    parse_network(value)
        .ok_or(RuntimeNetworkInventoryError::Malformed)
        .map(Some)
}

fn parse_u32(value: &Value) -> Option<u32> {
    match value {
        Value::Number(value) => value.as_u64().and_then(|value| u32::try_from(value).ok()),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn parse_rule_table(value: Option<&Value>) -> Result<u32, RuntimeNetworkInventoryError> {
    value
        .map_or(Some(254), parse_u32)
        .ok_or(RuntimeNetworkInventoryError::Malformed)
}

fn parse_fwmark(
    value: Option<&Value>,
) -> Result<(Option<u32>, Option<u32>), RuntimeNetworkInventoryError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let Some(raw) = value.as_str() else {
        return Err(RuntimeNetworkInventoryError::Malformed);
    };
    let (primary, mask_part) = raw.split_once('/').unwrap_or((raw, ""));
    let parse = |value: &str| {
        let value = value.strip_prefix("0x").unwrap_or(value);
        u32::from_str_radix(value, 16).map_err(|_| RuntimeNetworkInventoryError::Malformed)
    };
    Ok((
        Some(parse(primary)?),
        (!mask_part.is_empty())
            .then(|| parse(mask_part))
            .transpose()?,
    ))
}

fn optional_bounded_rule_string(
    value: &Value,
    field: &str,
) -> Result<Option<String>, RuntimeNetworkInventoryError> {
    let Some(value) = value.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(RuntimeNetworkInventoryError::Malformed);
    };
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value.chars().any(char::is_control) {
        return Err(RuntimeNetworkInventoryError::Malformed);
    }
    Ok(Some(value.to_owned()))
}

const fn reserved_policy_priority(priority: u32) -> bool {
    priority >= RUNTIME_POLICY_PRIORITY_START && priority <= RUNTIME_POLICY_PRIORITY_END
}

fn default_network(value: &Value, gateway: Option<IpAddr>) -> IpNetwork {
    if value.get("family").and_then(Value::as_str) == Some("inet6")
        || gateway.is_some_and(|address| address.is_ipv6())
    {
        IpNetwork {
            address: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            prefix_len: 0,
        }
    } else {
        IpNetwork {
            address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            prefix_len: 0,
        }
    }
}

fn parse_network(value: &str) -> Option<IpNetwork> {
    let (address, prefix) = value.split_once('/')?;
    Some(IpNetwork {
        address: address.parse().ok()?,
        prefix_len: prefix.parse().ok()?,
    })
}

fn route_table(value: Option<&Value>) -> Result<u32, RuntimeNetworkInventoryError> {
    match value {
        None => Ok(254),
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or(RuntimeNetworkInventoryError::Malformed),
        Some(Value::String(value)) => match value.as_str() {
            "default" => Ok(253),
            "main" => Ok(254),
            "local" => Ok(255),
            value => value
                .parse()
                .map_err(|_| RuntimeNetworkInventoryError::Malformed),
        },
        _ => Err(RuntimeNetworkInventoryError::Malformed),
    }
}

fn bounded_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_NAME_BYTES
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(count * 2);
    for byte in bytes.iter().take(count) {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::{NetworkMutation, NetworkRiskContext, plan_network_mutations};

    #[test]
    fn reconstructs_interfaces_dynamic_addresses_and_routes() {
        let inventory = inspect_runtime_network_inventory(
            r#"[{"ifname":"eth0","flags":["BROADCAST","UP"],"mtu":1500,"address":"02:00:00:00:00:01"}]"#,
            r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"dynamic":true},{"family":"inet6","local":"2001:db8::10","prefixlen":64}]}]"#,
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","table":"main","metric":100}]"#,
        )
        .expect("inventory");
        assert_eq!(inventory.objects.len(), 2);
        let NetworkObject::Interface(interface) = &inventory.objects[0] else {
            panic!("interface expected");
        };
        assert_eq!(interface.ipv4_mode, NetworkAddressMode::Dhcp);
        assert_eq!(interface.ipv6_mode, NetworkAddressMode::Static);
        assert_eq!(interface.ownership, ObjectOwnership::PlatformNative);
        let NetworkObject::Route(route) = &inventory.objects[1] else {
            panic!("route expected");
        };
        assert_eq!(route.destination.prefix_len, 0);
        assert_eq!(route.table, 254);
    }

    #[test]
    fn rejects_duplicate_links_and_omits_ambiguous_multipath() {
        assert!(
            inspect_runtime_network_inventory(
                r#"[{"ifname":"eth0"},{"ifname":"eth0"}]"#,
                "[]",
                "[]"
            )
            .is_err()
        );
        let inventory = inspect_runtime_network_inventory(
            r#"[{"ifname":"eth0","flags":[]}]"#,
            "[]",
            r#"[{"dst":"192.0.2.0/24","multipath":[{"dev":"eth0"}]}]"#,
        )
        .expect("inventory");
        assert_eq!(inventory.objects.len(), 1);
    }

    #[test]
    fn public_runtime_inventory_excludes_protocol_owned_routes() {
        let inventory = inspect_runtime_network_inventory(
            "[]",
            "[]",
            r#"[{"dst":"192.0.2.0/24","dev":"eth0","protocol":186},{"dst":"198.51.100.0/24","dev":"eth0","protocol":"186"},{"dst":"203.0.113.0/24","dev":"eth0","protocol":"static"}]"#,
        )
        .expect("inventory");
        assert_eq!(inventory.objects.len(), 1);
        let NetworkObject::Route(route) = &inventory.objects[0] else {
            panic!("route expected");
        };
        assert_eq!(route.destination.address.to_string(), "203.0.113.0");
        assert_eq!(route.ownership, ObjectOwnership::PlatformNative);
    }

    #[test]
    fn route_stage_is_protocol_owned_reversible_and_canonical_bound() {
        let snapshot = reconcile_runtime_route_inventory("[]", None, "boot-1").expect("empty");
        let route = NetworkRoute {
            id: "guest-default".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            destination: IpNetwork {
                address: "0.0.0.0".parse().expect("address"),
                prefix_len: 0,
            },
            gateway: Some("192.0.2.1".parse().expect("gateway")),
            output_interface: Some("eth0".into()),
            preferred_source: None,
            table: 100,
            metric: Some(20),
            route_type: NetworkRouteType::Unicast,
        };
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Create(NetworkObject::Route(route))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_runtime_route_stage(&snapshot, &plan).expect("stage");
        assert_eq!(
            stage.apply_batch,
            "-4 route add default via 192.0.2.1 dev eth0 table 100 proto 186 metric 20\n"
        );
        assert_eq!(
            stage.rollback_batch,
            "-4 route del default via 192.0.2.1 dev eth0 table 100 proto 186 metric 20\n"
        );
        let reconciled = reconcile_runtime_route_inventory(
            r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","table":100,"metric":20,"protocol":186}]"#,
            Some(&stage.projected_canonical_state),
            "boot-1",
        )
        .expect("reconcile");
        assert_eq!(reconciled.inventory().objects.len(), 1);
    }

    #[test]
    fn owned_native_route_without_canonical_state_fails_closed() {
        assert!(matches!(
            reconcile_runtime_route_inventory(
                r#"[{"dst":"192.0.2.0/24","dev":"eth0","protocol":"186"}]"#,
                None,
                "boot-1"
            ),
            Err(RuntimeNetworkInventoryError::NativeDrift)
        ));
    }

    #[test]
    fn policy_rules_use_reserved_priority_range_and_reversible_batch() {
        let rules = r#"[
            {"priority":100,"src":"192.0.2.0/24","table":254,"action":"lookup"},
            {"priority":32000,"src":"192.0.2.0/24","fwmark":"0x1/0xff","table":100,"action":"lookup"}
        ]"#;
        let public = inspect_runtime_policy_inventory(rules).expect("policy inventory");
        assert_eq!(public.objects.len(), 1);
        let NetworkObject::PolicyRule(native) = &public.objects[0] else {
            panic!("policy rule expected");
        };
        assert_eq!(native.priority, 100);
        assert_eq!(native.ownership, ObjectOwnership::PlatformNative);

        let snapshot = reconcile_runtime_network_inventory("[]", "[]", None, "boot-1")
            .expect("empty snapshot");
        let rule = NetworkPolicyRule {
            id: "guest-policy".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: NetworkFamily::Ipv4,
            priority: 32_000,
            source: Some(IpNetwork {
                address: "192.0.2.0".parse().expect("source"),
                prefix_len: 24,
            }),
            destination: None,
            input_interface: None,
            output_interface: None,
            fwmark: Some(1),
            fwmark_mask: Some(255),
            table: 100,
            action: NetworkPolicyAction::Lookup,
        };
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Create(NetworkObject::PolicyRule(rule))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_runtime_route_stage(&snapshot, &plan).expect("stage");
        assert_eq!(
            stage.apply_batch,
            "-4 rule add priority 32000 from 192.0.2.0/24 fwmark 0x1/0xff table 100\n"
        );
        let reconciled = reconcile_runtime_network_inventory(
            "[]",
            rules_with_owned_rule(),
            Some(&stage.projected_canonical_state),
            "boot-1",
        )
        .expect("reconcile");
        assert_eq!(reconciled.inventory().objects.len(), 1);
    }

    #[test]
    fn runtime_interface_profile_renders_static_address_batch_and_reconciles() {
        let snapshot = reconcile_runtime_network_inventory_with_links(
            r#"[{"ifname":"eth0","flags":["UP"],"mtu":1500}]"#,
            "[]",
            "[]",
            "[]",
            None,
            "boot-1",
        )
        .expect("full snapshot");
        let profile = NetworkObject::Interface(NetworkInterfaceConfig {
            id: "agent_eth0".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            device: "eth0".into(),
            ipv4_mode: NetworkAddressMode::Static,
            ipv6_mode: NetworkAddressMode::Disabled,
            addresses: vec![IpNetwork {
                address: "192.0.2.10".parse().expect("address"),
                prefix_len: 24,
            }],
            mtu: None,
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
        });
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Create(profile)],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_runtime_route_stage(&snapshot, &plan).expect("stage");
        assert_eq!(stage.apply_batch, "address add 192.0.2.10/24 dev eth0\n");
        assert_eq!(stage.rollback_batch, "address del 192.0.2.10/24 dev eth0\n");
        let reconciled = reconcile_runtime_network_inventory_with_links(
            r#"[{"ifname":"eth0","flags":["UP"],"mtu":1500}]"#,
            r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24}]}]"#,
            "[]",
            "[]",
            Some(&stage.projected_canonical_state),
            "boot-1",
        )
        .expect("reconciled");
        assert!(
            reconciled
                .inventory()
                .objects
                .iter()
                .any(|object| object.id() == "agent_eth0")
        );
    }

    #[test]
    fn runtime_interface_profile_rejects_missing_device() {
        let snapshot = reconcile_runtime_network_inventory_with_links(
            r#"[{"ifname":"eth0","flags":["UP"]}]"#,
            "[]",
            "[]",
            "[]",
            None,
            "boot-1",
        )
        .expect("snapshot");
        let profile = NetworkObject::Interface(NetworkInterfaceConfig {
            id: "agent_eth0".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            device: "eth0".into(),
            ipv4_mode: NetworkAddressMode::Static,
            ipv6_mode: NetworkAddressMode::Disabled,
            addresses: vec![IpNetwork {
                address: "192.0.2.10".parse().expect("address"),
                prefix_len: 24,
            }],
            mtu: None,
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
        });
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Create(profile)],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_runtime_route_stage(&snapshot, &plan).expect("stage");
        assert!(
            reconcile_runtime_network_inventory_with_links(
                r#"[{"ifname":"eth1","flags":["UP"]}]"#,
                "[]",
                "[]",
                "[]",
                Some(&stage.projected_canonical_state),
                "boot-1",
            )
            .is_err()
        );
    }

    #[test]
    fn reserved_policy_rule_without_canonical_state_fails_closed() {
        assert!(matches!(
            reconcile_runtime_network_inventory(
                "[]",
                r#"[{"priority":32000,"src":"192.0.2.0/24","table":100,"action":"lookup"}]"#,
                None,
                "boot-1"
            ),
            Err(RuntimeNetworkInventoryError::NativeDrift)
        ));
    }

    fn rules_with_owned_rule() -> &'static str {
        r#"[{"priority":32000,"src":"192.0.2.0/24","fwmark":"0x1/0xff","table":100,"action":"lookup"}]"#
    }
}
