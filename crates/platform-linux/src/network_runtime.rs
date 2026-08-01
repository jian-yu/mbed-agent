//! Typed reconstruction of generic Linux network state from fixed `ip -j` observations.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use agent_core::{
    NetworkInventory, NetworkMutationPlan, network_object_digest, project_network_inventory,
};
use agent_protocol::{
    IpNetwork, NetworkAddressMode, NetworkInterfaceConfig, NetworkObject, NetworkRoute,
    NetworkRouteType, ObjectOwnership,
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
    #[error("Agent-owned runtime route state is orphaned or drifted")]
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
        }));
    }

    for route in &routes {
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
    if boot_id.is_empty() || boot_id.len() > 128 || boot_id.chars().any(char::is_control) {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    let native = owned_native_routes(routes_json)?;
    let Some(encoded) = canonical_state else {
        if !native.is_empty() {
            return Err(RuntimeNetworkInventoryError::NativeDrift);
        }
        return Ok(RuntimeRouteSnapshot {
            boot_id: boot_id.into(),
            inventory: NetworkInventory { objects: vec![] },
        });
    };
    if encoded.is_empty() || encoded.len() > MAX_CANONICAL_BYTES {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let canonical: RuntimeRouteCanonicalState =
        serde_json::from_slice(encoded).map_err(|_| RuntimeNetworkInventoryError::StaleState)?;
    if canonical.schema_version != 1 || canonical.boot_id != boot_id {
        return Err(RuntimeNetworkInventoryError::StaleState);
    }
    let expected = canonical_routes(&canonical.inventory)?;
    if route_semantics(&native)? != route_semantics(&expected)? {
        return Err(RuntimeNetworkInventoryError::NativeDrift);
    }
    Ok(RuntimeRouteSnapshot {
        boot_id: canonical.boot_id,
        inventory: canonical.inventory,
    })
}

/// Renders an exact typed route plan into closed apply/rollback `ip -batch` artifacts.
///
/// Only Agent-owned routes are accepted. Every installed route carries protocol 186; no caller
/// text, command, argument, or path enters the artifacts.
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
    canonical_routes(&projected)?;
    let mut apply = String::new();
    let mut rollback = String::new();
    for change in &plan.changes {
        if let Some(before) = &change.before {
            let NetworkObject::Route(route) = before else {
                return Err(RuntimeNetworkInventoryError::InvalidPlan);
            };
            require_owned_route(route)?;
            push_route_command(&mut apply, "del", route)?;
        }
        if let Some(after) = &change.after {
            let NetworkObject::Route(route) = after else {
                return Err(RuntimeNetworkInventoryError::InvalidPlan);
            };
            require_owned_route(route)?;
            push_route_command(&mut apply, "add", route)?;
        }
    }
    for change in plan.changes.iter().rev() {
        if let Some(after) = &change.after {
            let NetworkObject::Route(route) = after else {
                return Err(RuntimeNetworkInventoryError::InvalidPlan);
            };
            push_route_command(&mut rollback, "del", route)?;
        }
        if let Some(before) = &change.before {
            let NetworkObject::Route(route) = before else {
                return Err(RuntimeNetworkInventoryError::InvalidPlan);
            };
            push_route_command(&mut rollback, "add", route)?;
        }
    }
    if apply.is_empty() || apply.len() > MAX_BATCH_BYTES || rollback.len() > MAX_BATCH_BYTES {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    let canonical = RuntimeRouteCanonicalState {
        schema_version: 1,
        boot_id: snapshot.boot_id.clone(),
        inventory: projected,
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
) -> Result<Vec<NetworkRoute>, RuntimeNetworkInventoryError> {
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
        routes.push(route);
    }
    Ok(routes)
}

fn owned_protocol(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Number(value)) => value.as_u64() == Some(RUNTIME_ROUTE_PROTOCOL),
        Some(Value::String(value)) => value == "186",
        _ => false,
    }
}

fn canonical_routes(
    inventory: &NetworkInventory,
) -> Result<Vec<NetworkRoute>, RuntimeNetworkInventoryError> {
    if inventory.objects.len() > MAX_OBJECTS {
        return Err(RuntimeNetworkInventoryError::Capacity);
    }
    inventory
        .objects
        .iter()
        .map(|object| {
            let NetworkObject::Route(route) = object else {
                return Err(RuntimeNetworkInventoryError::InvalidPlan);
            };
            require_owned_route(route)?;
            Ok(route.clone())
        })
        .collect()
}

fn require_owned_route(route: &NetworkRoute) -> Result<(), RuntimeNetworkInventoryError> {
    if route.ownership != ObjectOwnership::AgentOwned || !route.enabled {
        return Err(RuntimeNetworkInventoryError::InvalidPlan);
    }
    network_object_digest(&NetworkObject::Route(route.clone()))
        .map(|_| ())
        .map_err(|_| RuntimeNetworkInventoryError::InvalidPlan)
}

fn route_semantics(routes: &[NetworkRoute]) -> Result<Vec<Vec<u8>>, RuntimeNetworkInventoryError> {
    let mut values = routes
        .iter()
        .map(|route| {
            let mut normalized = route.clone();
            normalized.id.clear();
            normalized.ownership = ObjectOwnership::AgentOwned;
            serde_json::to_vec(&normalized).map_err(|_| RuntimeNetworkInventoryError::StaleState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    Ok(values)
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
}
