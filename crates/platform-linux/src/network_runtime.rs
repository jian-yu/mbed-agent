//! Typed reconstruction of generic Linux network state from fixed `ip -j` observations.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use agent_core::{NetworkInventory, network_object_digest};
use agent_protocol::{
    IpNetwork, NetworkAddressMode, NetworkInterfaceConfig, NetworkObject, NetworkRoute,
    NetworkRouteType, ObjectOwnership,
};
use serde_json::Value;
use thiserror::Error;

const MAX_OBJECTS: usize = 256;
const MAX_ADDRESSES_PER_INTERFACE: usize = 32;
const MAX_NAME_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum RuntimeNetworkInventoryError {
    #[error("runtime network observation is malformed")]
    Malformed,
    #[error("runtime network observation exceeds its bound")]
    Capacity,
    #[error("runtime network object is not safely representable")]
    Unsupported,
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
}
