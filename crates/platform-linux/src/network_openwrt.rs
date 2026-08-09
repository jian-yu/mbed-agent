//! Bounded `OpenWrt` UCI inventory and staging for typed L2/L3 objects.
//!
//! This module never installs `/etc/config/network` and never reloads netifd. It reconstructs
//! supported objects from one fresh `uci show network` result and renders a batch for a private
//! staging directory under `/tmp`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use agent_core::{
    NetworkInventory, NetworkMutationPlan, network_object_digest, validate_network_object,
};
use agent_protocol::{
    ChangeOperation, IpNetwork, NetworkAddressMode, NetworkBridge, NetworkDhcpMode,
    NetworkDhcpOption, NetworkDhcpServerConfig, NetworkFamily, NetworkInterfaceConfig,
    NetworkObject, NetworkPolicyAction, NetworkPolicyRule, NetworkRoute, NetworkRouteType,
    NetworkVlan, NetworkVlanProtocol, ObjectOwnership,
};
use thiserror::Error;

use crate::firewall::FirewallRenderError;
use crate::firewall_uci::{UciSection, parse_uci_show_package, safe_uci_identifier, valid_section};
use crate::{NetworkDeviceModel, PlatformCapabilities, PlatformKind};

const MAX_BINDINGS: usize = 256;
const MAX_PRESENT_OPTIONS: usize = 64;
const MAX_BATCH_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtNetworkObjectBinding {
    pub kind: String,
    pub id: String,
    pub section_type: String,
    pub section: String,
    pub present_options: Vec<String>,
    pub dhcp_section: Option<String>,
    pub dhcp_present_options: Vec<String>,
    pub dhcp_agent_owned: bool,
}

/// One bounded, internally consistent view of the current `OpenWrt` network package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtNetworkInventorySnapshot {
    inventory: NetworkInventory,
    bindings: Vec<OpenWrtNetworkObjectBinding>,
    occupied_sections: Vec<String>,
    read_only_sections: Vec<String>,
    dhcp_occupied_sections: Vec<String>,
    dhcp_read_only_sections: Vec<String>,
}

impl OpenWrtNetworkInventorySnapshot {
    #[must_use]
    pub fn inventory(&self) -> &NetworkInventory {
        &self.inventory
    }

    #[must_use]
    pub fn bindings(&self) -> &[OpenWrtNetworkObjectBinding] {
        &self.bindings
    }

    #[must_use]
    pub fn occupied_sections(&self) -> &[String] {
        &self.occupied_sections
    }

    #[must_use]
    pub fn read_only_sections(&self) -> &[String] {
        &self.read_only_sections
    }

    #[must_use]
    pub fn dhcp_occupied_sections(&self) -> &[String] {
        &self.dhcp_occupied_sections
    }

    #[must_use]
    pub fn dhcp_read_only_sections(&self) -> &[String] {
        &self.dhcp_read_only_sections
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenWrtNetworkValidation {
    /// Parse and export the staged package with `uci -c <staging-dir> export network`.
    UciExport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtNetworkStage {
    pub uci_batch: String,
    pub dhcp_uci_batch: String,
    pub validations: Vec<OpenWrtNetworkValidation>,
    pub activation_service: &'static str,
    pub activation_action: &'static str,
}

/// Selects the non-installing adapter only for supported `OpenWrt` releases with UCI available.
/// The returned device model lets later slices narrow DSA and swconfig features.
///
/// # Errors
///
/// Returns an error for generic Linux, `OpenWrt` before 21, or a missing UCI command.
pub fn select_openwrt_network_staging(
    capabilities: &PlatformCapabilities,
) -> Result<NetworkDeviceModel, NetworkRenderError> {
    let has_uci_command = capabilities
        .available_commands
        .iter()
        .any(|command| command == "uci");
    if capabilities.kind == PlatformKind::OpenWrt
        && capabilities.release_supported
        && capabilities.has_uci
        && has_uci_command
    {
        Ok(capabilities.device_model)
    } else {
        Err(NetworkRenderError::BackendUnavailable)
    }
}

/// Reconstructs supported typed objects and exact bindings from one fresh UCI snapshot.
///
/// Unsupported platform-native sections are reported as read-only. A section marked as
/// Agent-owned must decode exactly or inspection fails closed.
///
/// # Errors
///
/// Returns an error for malformed or oversized UCI output, duplicate typed identities, unsafe
/// ownership markers, or unrepresentable Agent-owned sections.
pub fn inspect_openwrt_network_inventory(
    uci_show: &str,
) -> Result<OpenWrtNetworkInventorySnapshot, NetworkRenderError> {
    inspect_openwrt_network_inventory_with_dhcp(uci_show, "")
}

/// Reconstructs the network package plus the safe DHCP server subset from one fresh pair of UCI
/// snapshots. The DHCP package is optional so existing network-only callers remain compatible.
///
/// # Errors
///
/// Returns an error for malformed UCI, unsafe ownership markers, duplicate identities, or an
/// Agent-owned section that cannot be represented by the bounded typed model.
#[allow(clippy::too_many_lines)] // Network and DHCP bindings are joined in one atomic snapshot.
pub fn inspect_openwrt_network_inventory_with_dhcp(
    uci_show: &str,
    dhcp_show: &str,
) -> Result<OpenWrtNetworkInventorySnapshot, NetworkRenderError> {
    let sections = parse_ci(uci_show)?;
    let dhcp_sections = parse_dhcp(dhcp_show)?;
    let mut objects = Vec::new();
    let mut bindings = Vec::new();
    let mut read_only_sections = Vec::new();
    let mut identities = HashSet::new();

    for section in &sections {
        let marker = section.first("mbed_managed");
        let reserved = section.selector.starts_with("mbed_");
        let managed = match marker {
            None if !reserved => false,
            Some("1") => true,
            _ => {
                return Err(NetworkRenderError::UnsafeOwnershipMarker(
                    section.selector.clone(),
                ));
            }
        };
        let supported_type = matches!(
            section.section_type.as_str(),
            "interface" | "device" | "route" | "route6" | "rule" | "rule6"
        );
        if !supported_type {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        }
        let ownership = if managed {
            ObjectOwnership::AgentOwned
        } else {
            ObjectOwnership::PlatformNative
        };
        let Some(object) = decode_section(section, ownership) else {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        };
        if validate_network_object(&object).is_err() {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        }
        let identity = (object.kind().to_owned(), object.id().to_owned());
        if !identities.insert(identity) {
            return Err(NetworkRenderError::DuplicateInventoryObject);
        }
        if section.options.len() > MAX_PRESENT_OPTIONS {
            return Err(NetworkRenderError::Capacity);
        }
        let mut present_options: Vec<_> = section.options.keys().cloned().collect();
        present_options.sort_unstable();
        bindings.push(OpenWrtNetworkObjectBinding {
            kind: object.kind().into(),
            id: object.id().into(),
            section_type: section.section_type.clone(),
            section: section.selector.clone(),
            present_options,
            dhcp_section: None,
            dhcp_present_options: Vec::new(),
            dhcp_agent_owned: false,
        });
        objects.push(object);
    }

    let mut dhcp_occupied_sections = Vec::new();
    let mut dhcp_read_only_sections = Vec::new();
    for section in &dhcp_sections {
        dhcp_occupied_sections.push(section.selector.clone());
        let marker = section.first("mbed_managed");
        let reserved = section.selector.starts_with("mbed_");
        let managed = match marker {
            None if !reserved => false,
            Some("1") => true,
            _ => {
                return Err(NetworkRenderError::UnsafeOwnershipMarker(
                    section.selector.clone(),
                ));
            }
        };
        if section.section_type != "dhcp" {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            dhcp_read_only_sections.push(section.selector.clone());
            continue;
        }
        let Some(interface_id) = optional(section, "interface") else {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            dhcp_read_only_sections.push(section.selector.clone());
            continue;
        };
        let Some(index) = objects.iter().position(
            |object| matches!(object, NetworkObject::Interface(value) if value.id == interface_id),
        ) else {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            dhcp_read_only_sections.push(section.selector.clone());
            continue;
        };
        let Some(server) = decode_dhcp_server(section) else {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            dhcp_read_only_sections.push(section.selector.clone());
            continue;
        };
        let object = objects
            .get_mut(index)
            .ok_or(NetworkRenderError::MalformedUci)?;
        if let NetworkObject::Interface(interface) = object {
            interface.dhcp_server = Some(server);
        } else {
            return Err(NetworkRenderError::MalformedUci);
        }
        if validate_network_object(object).is_err() {
            if managed {
                return Err(NetworkRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            let NetworkObject::Interface(interface) = object else {
                return Err(NetworkRenderError::MalformedUci);
            };
            interface.dhcp_server = None;
            dhcp_read_only_sections.push(section.selector.clone());
            continue;
        }
        let binding = bindings
            .get_mut(index)
            .ok_or(NetworkRenderError::MalformedUci)?;
        if section.options.len() > MAX_PRESENT_OPTIONS {
            return Err(NetworkRenderError::Capacity);
        }
        let mut present_options: Vec<_> = section.options.keys().cloned().collect();
        present_options.sort_unstable();
        binding.dhcp_section = Some(section.selector.clone());
        binding.dhcp_present_options = present_options;
        binding.dhcp_agent_owned = managed;
    }

    validate_inventory_topology(&NetworkInventory {
        objects: objects.clone(),
    })?;
    Ok(OpenWrtNetworkInventorySnapshot {
        inventory: NetworkInventory { objects },
        bindings,
        occupied_sections: sections
            .iter()
            .map(|section| section.selector.clone())
            .collect(),
        read_only_sections,
        dhcp_occupied_sections,
        dhcp_read_only_sections,
    })
}

/// Renders an approved typed plan against the exact fresh inventory snapshot.
///
/// The output is input only for `uci -c <private-/tmp-dir> batch`; this function neither writes
/// the persistent package nor invokes netifd.
///
/// # Errors
///
/// Returns an error for stale plan content, unsafe bindings, unsupported `OpenWrt` semantics,
/// section collisions, invalid objects, or bounded output overflow.
pub fn render_openwrt_network_stage_from_snapshot(
    plan: &NetworkMutationPlan,
    snapshot: &OpenWrtNetworkInventorySnapshot,
) -> Result<OpenWrtNetworkStage, NetworkRenderError> {
    validate_plan_against_snapshot(plan, snapshot)?;
    let bindings = validate_bindings(snapshot.bindings())?;
    let mut reserved: HashSet<String> = snapshot.occupied_sections().iter().cloned().collect();
    if reserved.len() != snapshot.occupied_sections().len() {
        return Err(NetworkRenderError::DuplicateSection);
    }
    for binding in bindings.values() {
        if !reserved.contains(&binding.section) {
            return Err(NetworkRenderError::UnsafeBinding);
        }
    }

    let mut batch = String::new();
    let mut dhcp_batch = String::new();
    let mut dhcp_reserved: HashSet<String> =
        snapshot.dhcp_occupied_sections().iter().cloned().collect();
    for change in &plan.changes {
        let object = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(NetworkRenderError::PlanMismatch)?;
        let key = (object.kind(), object.id());
        match change.diff.operation {
            ChangeOperation::Create => {
                let digest = change
                    .diff
                    .after_digest
                    .as_deref()
                    .ok_or(NetworkRenderError::PlanMismatch)?;
                let section = new_section_name(object, digest)?;
                if !reserved.insert(section.clone()) {
                    return Err(NetworkRenderError::DuplicateSection);
                }
                render_create(&mut batch, &section, object)?;
                render_dhcp_create(&mut dhcp_batch, &mut dhcp_reserved, object)?;
            }
            ChangeOperation::Update | ChangeOperation::Move => {
                let binding = binding_for(&bindings, key)?;
                render_update(&mut batch, binding, object)?;
                render_dhcp_update(&mut dhcp_batch, &mut dhcp_reserved, binding, object)?;
            }
            ChangeOperation::Delete => {
                let binding = binding_for(&bindings, key)?;
                writeln!(batch, "delete network.{}", binding.section)
                    .map_err(|_| NetworkRenderError::Output)?;
                render_dhcp_delete(&mut dhcp_batch, binding, object)?;
            }
        }
        if batch.len().saturating_add(dhcp_batch.len()) > MAX_BATCH_BYTES {
            return Err(NetworkRenderError::Capacity);
        }
    }
    batch.push_str("commit network\n");
    if !dhcp_batch.is_empty() {
        dhcp_batch.push_str("commit dhcp\n");
    }
    Ok(OpenWrtNetworkStage {
        uci_batch: batch,
        dhcp_uci_batch: dhcp_batch,
        validations: vec![OpenWrtNetworkValidation::UciExport],
        activation_service: "/etc/init.d/network",
        activation_action: "reload",
    })
}

fn parse_ci(input: &str) -> Result<Vec<UciSection>, NetworkRenderError> {
    parse_uci_show_package(input, "network").map_err(|error| match error {
        FirewallRenderError::Capacity => NetworkRenderError::Capacity,
        _ => NetworkRenderError::MalformedUci,
    })
}

fn parse_dhcp(input: &str) -> Result<Vec<UciSection>, NetworkRenderError> {
    parse_uci_show_package(input, "dhcp").map_err(|error| match error {
        FirewallRenderError::Capacity => NetworkRenderError::Capacity,
        _ => NetworkRenderError::MalformedUci,
    })
}

fn decode_section(section: &UciSection, ownership: ObjectOwnership) -> Option<NetworkObject> {
    if !valid_cardinality(section) || has_unsupported_semantics(section) {
        return None;
    }
    match section.section_type.as_str() {
        "interface" => decode_interface(section, ownership).map(NetworkObject::Interface),
        "device" => match section.first("type")? {
            "bridge" => decode_bridge(section, ownership).map(NetworkObject::Bridge),
            "8021q" | "8021ad" => decode_vlan(section, ownership).map(NetworkObject::Vlan),
            _ => None,
        },
        "route" | "route6" => decode_route(section, ownership).map(NetworkObject::Route),
        "rule" | "rule6" => decode_policy_rule(section, ownership).map(NetworkObject::PolicyRule),
        _ => None,
    }
}

fn decode_dhcp_server(section: &UciSection) -> Option<NetworkDhcpServerConfig> {
    Some(NetworkDhcpServerConfig {
        enabled: !optional_bool(section, "ignore").ok()?.unwrap_or(false),
        start: optional_u16(section, "start").ok()?.unwrap_or(100),
        limit: optional_u16(section, "limit").ok()?.unwrap_or(150),
        lease_time: optional(section, "leasetime").unwrap_or("12h").to_owned(),
        force: optional_bool(section, "force").ok()?.unwrap_or(false),
        dhcpv6_mode: dhcp_mode(section, "dhcpv6", NetworkDhcpMode::Server)?,
        ra_mode: dhcp_mode(section, "ra", NetworkDhcpMode::Server)?,
        ndp_mode: dhcp_mode(section, "ndp", NetworkDhcpMode::Hybrid)?,
        dhcp_options: parse_dhcp_options(section)?,
    })
}

fn valid_cardinality(section: &UciSection) -> bool {
    let list_options: &[&str] = match section.section_type.as_str() {
        "interface" => &["ipaddr", "ip6addr", "dns", "dns_search", "reqopts"],
        "device" => &["ports"],
        _ => &[],
    };
    section.options.iter().all(|(name, values)| {
        values.len() == 1 || (list_options.contains(&name.as_str()) && !values.is_empty())
    })
}

fn has_unsupported_semantics(section: &UciSection) -> bool {
    let unsupported: &[&str] = match section.section_type.as_str() {
        "interface" => &[
            "gateway",
            "ip6gw",
            "ip6assign",
            "ip6hint",
            "ip6class",
            "delegate",
            "metric",
            "type",
            "defaultroute",
            "force_link",
            "ip4table",
            "ip6table",
            "broadcast",
            "ip6prefix",
            "reqaddress",
            "reqprefix",
        ],
        "device" => &[
            "bridge_empty",
            "igmp_snooping",
            "multicast_querier",
            "macaddr",
            "promisc",
            "acceptlocal",
        ],
        "route" | "route6" => &["onlink", "mtu"],
        "rule" | "rule6" => &[
            "tos",
            "invert",
            "ipproto",
            "sport",
            "dport",
            "uidrange",
            "suppress_prefixlength",
        ],
        _ => &[],
    };
    unsupported
        .iter()
        .any(|name| section.options.contains_key(*name))
}

fn decode_interface(
    section: &UciSection,
    ownership: ObjectOwnership,
) -> Option<NetworkInterfaceConfig> {
    let id = managed_id(section).unwrap_or_else(|| section.selector.clone());
    let device = exclusive(section.first("device"), section.first("ifname"))?.to_owned();
    let proto = section.first("proto")?;
    let mut addresses = Vec::new();
    for raw in section.values("ipaddr") {
        addresses.push(parse_ipv4_interface_address(raw, section.first("netmask"))?);
    }
    for raw in section.values("ip6addr") {
        let network = parse_ip_network(raw)?;
        if !network.address.is_ipv6() {
            return None;
        }
        addresses.push(network);
    }
    let has_v4 = addresses.iter().any(|value| value.address.is_ipv4());
    let has_v6 = addresses.iter().any(|value| value.address.is_ipv6());
    let (ipv4_mode, ipv6_mode) = match proto {
        "none" if addresses.is_empty() => {
            (NetworkAddressMode::Disabled, NetworkAddressMode::Disabled)
        }
        "static" if !addresses.is_empty() => (
            if has_v4 {
                NetworkAddressMode::Static
            } else {
                NetworkAddressMode::Disabled
            },
            if has_v6 {
                NetworkAddressMode::Static
            } else {
                NetworkAddressMode::Disabled
            },
        ),
        "dhcp" if addresses.is_empty() => (NetworkAddressMode::Dhcp, NetworkAddressMode::Disabled),
        "dhcpv6" if addresses.is_empty() => {
            (NetworkAddressMode::Disabled, NetworkAddressMode::Dhcp)
        }
        _ => return None,
    };
    Some(NetworkInterfaceConfig {
        id,
        ownership,
        enabled: enabled(section)?,
        device,
        ipv4_mode,
        ipv6_mode,
        addresses,
        mtu: optional_u32(section, "mtu").ok()?,
        mac_override: optional(section, "macaddr").map(str::to_owned),
        peerdns: optional_bool(section, "peerdns").ok()?.unwrap_or(true),
        dns_servers: section
            .values("dns")
            .iter()
            .map(|raw| raw.parse().ok())
            .collect::<Option<Vec<IpAddr>>>()?,
        dns_search: section.values("dns_search").to_vec(),
        dhcp_client_id: optional(section, "clientid").map(str::to_owned),
        dhcp_vendor_id: optional(section, "vendorid").map(str::to_owned),
        dhcp_hostname: optional(section, "hostname").map(str::to_owned),
        dhcp_request_options: section
            .values("reqopts")
            .iter()
            .map(|raw| raw.parse().ok())
            .collect::<Option<Vec<u16>>>()?,
        dhcp_no_release: optional_bool(section, "norelease").ok()?.unwrap_or(false),
        dhcp_server: None,
    })
}

fn decode_bridge(section: &UciSection, ownership: ObjectOwnership) -> Option<NetworkBridge> {
    Some(NetworkBridge {
        id: scalar(section, "name")?.to_owned(),
        ownership,
        enabled: enabled(section)?,
        ports: section.values("ports").to_vec(),
        stp: optional_bool(section, "stp").ok()?.unwrap_or(false),
        vlan_filtering: optional_bool(section, "vlan_filtering")
            .ok()?
            .unwrap_or(false),
        mtu: optional_u32(section, "mtu").ok()?,
    })
}

fn decode_vlan(section: &UciSection, ownership: ObjectOwnership) -> Option<NetworkVlan> {
    Some(NetworkVlan {
        id: scalar(section, "name")?.to_owned(),
        ownership,
        enabled: enabled(section)?,
        parent: scalar(section, "ifname")?.to_owned(),
        vlan_id: scalar(section, "vid")?.parse().ok()?,
        protocol: match scalar(section, "type")? {
            "8021q" => NetworkVlanProtocol::Ieee8021Q,
            "8021ad" => NetworkVlanProtocol::Ieee8021Ad,
            _ => return None,
        },
        mtu: optional_u32(section, "mtu").ok()?,
    })
}

fn decode_route(section: &UciSection, ownership: ObjectOwnership) -> Option<NetworkRoute> {
    let ipv6 = section.section_type == "route6";
    let target = section
        .first("target")
        .unwrap_or(if ipv6 { "::/0" } else { "0.0.0.0/0" });
    let destination = parse_route_target(target, section.first("netmask"), ipv6)?;
    let route_type = match section.first("type").unwrap_or("unicast") {
        "unicast" => NetworkRouteType::Unicast,
        "blackhole" => NetworkRouteType::Blackhole,
        "unreachable" => NetworkRouteType::Unreachable,
        "prohibit" => NetworkRouteType::Prohibit,
        _ => return None,
    };
    if section
        .first("proto")
        .is_some_and(|protocol| protocol != "static")
    {
        return None;
    }
    let table = parse_table(section.first("table").unwrap_or("254"))?;
    if table > 65_535 {
        return None;
    }
    Some(NetworkRoute {
        id: section_id(section, "route")?,
        ownership,
        enabled: enabled(section)?,
        destination,
        gateway: optional_ip(section, "gateway").ok()?,
        output_interface: Some(scalar(section, "interface")?.to_owned()),
        preferred_source: optional_ip(section, "source").ok()?,
        table,
        metric: optional_u32(section, "metric").ok()?,
        route_type,
    })
}

fn decode_policy_rule(
    section: &UciSection,
    ownership: ObjectOwnership,
) -> Option<NetworkPolicyRule> {
    let family = if section.section_type == "rule6" {
        NetworkFamily::Ipv6
    } else {
        NetworkFamily::Ipv4
    };
    let (fwmark, fwmark_mask) = match optional(section, "mark") {
        Some(value) => parse_mark(value)?,
        None => (None, None),
    };
    let action = match section.first("action").unwrap_or("lookup") {
        "lookup" => NetworkPolicyAction::Lookup,
        "blackhole" => NetworkPolicyAction::Blackhole,
        "unreachable" => NetworkPolicyAction::Unreachable,
        "prohibit" => NetworkPolicyAction::Prohibit,
        _ => return None,
    };
    let table = if action == NetworkPolicyAction::Lookup {
        parse_table(section.first("lookup")?)?
    } else {
        0
    };
    if table > 65_535 {
        return None;
    }
    Some(NetworkPolicyRule {
        id: section_id(section, "rule")?,
        ownership,
        enabled: enabled(section)?,
        family,
        priority: scalar(section, "priority")?.parse().ok()?,
        source: parse_optional_network(section, "src").ok()?,
        destination: parse_optional_network(section, "dest").ok()?,
        input_interface: optional(section, "in").map(str::to_owned),
        output_interface: optional(section, "out").map(str::to_owned),
        fwmark,
        fwmark_mask,
        table,
        action,
    })
}

fn validate_plan_against_snapshot(
    plan: &NetworkMutationPlan,
    snapshot: &OpenWrtNetworkInventorySnapshot,
) -> Result<(), NetworkRenderError> {
    if plan.changes.is_empty() || plan.changes.len() > 32 {
        return Err(NetworkRenderError::PlanMismatch);
    }
    let inventory: HashMap<(&str, &str), &NetworkObject> = snapshot
        .inventory()
        .objects
        .iter()
        .map(|object| ((object.kind(), object.id()), object))
        .collect();
    if inventory.len() != snapshot.inventory().objects.len() {
        return Err(NetworkRenderError::DuplicateInventoryObject);
    }
    let mut touched = HashSet::new();
    for change in &plan.changes {
        let object = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(NetworkRenderError::PlanMismatch)?;
        let key = (object.kind(), object.id());
        if !touched.insert(key)
            || change.diff.object.kind != key.0
            || change.diff.object.id != key.1
            || change.diff.object.ownership != object.ownership()
        {
            return Err(NetworkRenderError::PlanMismatch);
        }
        let before_digest = change
            .before
            .as_ref()
            .map(network_object_digest)
            .transpose()
            .map_err(|_| NetworkRenderError::InvalidObject)?;
        let after_digest = change
            .after
            .as_ref()
            .map(network_object_digest)
            .transpose()
            .map_err(|_| NetworkRenderError::InvalidObject)?;
        if change.diff.before_digest != before_digest
            || change.diff.after_digest != after_digest
            || change.diff.object.expected_version != before_digest
        {
            return Err(NetworkRenderError::PlanMismatch);
        }
        match change.diff.operation {
            ChangeOperation::Create
                if change.before.is_none()
                    && change.after.is_some()
                    && !inventory.contains_key(&key) => {}
            ChangeOperation::Update | ChangeOperation::Move
                if change.before.as_ref() == inventory.get(&key).copied()
                    && change.after.is_some() => {}
            ChangeOperation::Delete
                if change.before.as_ref() == inventory.get(&key).copied()
                    && change.after.is_none() => {}
            _ => return Err(NetworkRenderError::PlanMismatch),
        }
    }
    Ok(())
}

fn validate_inventory_topology(inventory: &NetworkInventory) -> Result<(), NetworkRenderError> {
    // Reuse the core projector's topology checks by constructing no mutation is impossible;
    // enforce the native conflicts that could otherwise make identities ambiguous here.
    let mut aggregate_ports = HashSet::new();
    let mut priorities = HashSet::new();
    for object in &inventory.objects {
        match object {
            NetworkObject::Bridge(value) => {
                for port in &value.ports {
                    if !aggregate_ports.insert(port) {
                        return Err(NetworkRenderError::AmbiguousInventory);
                    }
                }
            }
            NetworkObject::PolicyRule(value) if value.enabled => {
                if !priorities.insert((value.family, value.priority)) {
                    return Err(NetworkRenderError::AmbiguousInventory);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_bindings(
    bindings: &[OpenWrtNetworkObjectBinding],
) -> Result<HashMap<(&str, &str), &OpenWrtNetworkObjectBinding>, NetworkRenderError> {
    if bindings.len() > MAX_BINDINGS {
        return Err(NetworkRenderError::Capacity);
    }
    let mut indexed = HashMap::new();
    let mut sections = HashSet::new();
    for binding in bindings {
        if !known_kind(&binding.kind)
            || !safe_id(&binding.id)
            || !valid_section_type(&binding.section_type, &binding.kind)
            || !valid_section(&binding.section, &binding.section_type)
            || binding.present_options.len() > MAX_PRESENT_OPTIONS
            || !binding
                .present_options
                .iter()
                .all(|option| safe_uci_identifier(option))
        {
            return Err(NetworkRenderError::UnsafeBinding);
        }
        if indexed
            .insert((binding.kind.as_str(), binding.id.as_str()), binding)
            .is_some()
        {
            return Err(NetworkRenderError::DuplicateBinding);
        }
        if !sections.insert(binding.section.as_str()) {
            return Err(NetworkRenderError::DuplicateSection);
        }
    }
    Ok(indexed)
}

fn render_create(
    batch: &mut String,
    section: &str,
    object: &NetworkObject,
) -> Result<(), NetworkRenderError> {
    let rendered = render_object(object)?;
    writeln!(batch, "set network.{section}={}", rendered.section_type)
        .map_err(|_| NetworkRenderError::Output)?;
    render_options(batch, section, &rendered)
}

fn render_dhcp_create(
    batch: &mut String,
    reserved: &mut HashSet<String>,
    object: &NetworkObject,
) -> Result<(), NetworkRenderError> {
    let NetworkObject::Interface(value) = object else {
        return Ok(());
    };
    let Some(server) = &value.dhcp_server else {
        return Ok(());
    };
    if !safe_uci_identifier(&value.id) {
        return Err(NetworkRenderError::UnsupportedField(
            "OpenWrt DHCP interface identifier",
        ));
    }
    let section = value.id.clone();
    if !reserved.insert(section.clone()) {
        return Err(NetworkRenderError::DuplicateSection);
    }
    writeln!(batch, "set dhcp.{section}=dhcp").map_err(|_| NetworkRenderError::Output)?;
    render_dhcp_options(batch, &section, value, server, true)
}

fn render_dhcp_update(
    batch: &mut String,
    reserved: &mut HashSet<String>,
    binding: &OpenWrtNetworkObjectBinding,
    object: &NetworkObject,
) -> Result<(), NetworkRenderError> {
    let NetworkObject::Interface(value) = object else {
        return Ok(());
    };
    let Some(server) = &value.dhcp_server else {
        if binding.dhcp_section.is_some() && !binding.dhcp_agent_owned {
            return Err(NetworkRenderError::UnsupportedField(
                "native OpenWrt DHCP server removal",
            ));
        }
        if let Some(section) = &binding.dhcp_section {
            writeln!(batch, "delete dhcp.{section}").map_err(|_| NetworkRenderError::Output)?;
        }
        return Ok(());
    };
    let section = if let Some(section) = &binding.dhcp_section {
        section.clone()
    } else {
        if !safe_uci_identifier(&value.id) {
            return Err(NetworkRenderError::UnsupportedField(
                "OpenWrt DHCP interface identifier",
            ));
        }
        let section = value.id.clone();
        if !reserved.insert(section.clone()) {
            return Err(NetworkRenderError::DuplicateSection);
        }
        writeln!(batch, "set dhcp.{section}=dhcp").map_err(|_| NetworkRenderError::Output)?;
        section
    };
    if binding.dhcp_section.is_some() {
        for option in &binding.dhcp_present_options {
            if supported_dhcp_options().contains(&option.as_str()) {
                writeln!(batch, "delete dhcp.{section}.{option}")
                    .map_err(|_| NetworkRenderError::Output)?;
            }
        }
    }
    render_dhcp_options(
        batch,
        &section,
        value,
        server,
        value.ownership == ObjectOwnership::AgentOwned,
    )
}

fn render_dhcp_delete(
    batch: &mut String,
    binding: &OpenWrtNetworkObjectBinding,
    object: &NetworkObject,
) -> Result<(), NetworkRenderError> {
    if !matches!(object, NetworkObject::Interface(_)) {
        return Ok(());
    }
    if let Some(section) = &binding.dhcp_section {
        if !binding.dhcp_agent_owned {
            return Err(NetworkRenderError::UnsupportedField(
                "native OpenWrt DHCP server removal",
            ));
        }
        writeln!(batch, "delete dhcp.{section}").map_err(|_| NetworkRenderError::Output)?;
    }
    Ok(())
}

fn render_dhcp_options(
    batch: &mut String,
    section: &str,
    interface: &NetworkInterfaceConfig,
    value: &NetworkDhcpServerConfig,
    agent_owned: bool,
) -> Result<(), NetworkRenderError> {
    if agent_owned {
        writeln!(batch, "set dhcp.{section}.mbed_managed='1'")
            .map_err(|_| NetworkRenderError::Output)?;
        writeln!(
            batch,
            "set dhcp.{section}.mbed_id={}",
            quote(&interface.id)?
        )
        .map_err(|_| NetworkRenderError::Output)?;
    }
    for (name, value) in [
        ("interface", interface.id.clone()),
        ("ignore", boolean(!value.enabled)),
        ("start", value.start.to_string()),
        ("limit", value.limit.to_string()),
        ("leasetime", value.lease_time.clone()),
        ("force", boolean(value.force)),
        ("dhcpv6", dhcp_mode_value(value.dhcpv6_mode).into()),
        ("ra", dhcp_mode_value(value.ra_mode).into()),
        ("ndp", dhcp_mode_value(value.ndp_mode).into()),
    ] {
        writeln!(batch, "set dhcp.{section}.{name}={}", quote(&value)?)
            .map_err(|_| NetworkRenderError::Output)?;
    }
    for option in &value.dhcp_options {
        let encoded = format!("{},{}", option.code, option.value);
        writeln!(
            batch,
            "add_list dhcp.{section}.dhcp_option={}",
            quote(&encoded)?
        )
        .map_err(|_| NetworkRenderError::Output)?;
    }
    Ok(())
}

fn supported_dhcp_options() -> &'static [&'static str] {
    &[
        "mbed_managed",
        "mbed_id",
        "interface",
        "ignore",
        "start",
        "limit",
        "leasetime",
        "force",
        "dhcpv6",
        "ra",
        "ndp",
        "dhcp_option",
    ]
}

fn dhcp_mode_value(value: NetworkDhcpMode) -> &'static str {
    match value {
        NetworkDhcpMode::Disabled => "disabled",
        NetworkDhcpMode::Server => "server",
        NetworkDhcpMode::Relay => "relay",
        NetworkDhcpMode::Hybrid => "hybrid",
    }
}

fn render_update(
    batch: &mut String,
    binding: &OpenWrtNetworkObjectBinding,
    object: &NetworkObject,
) -> Result<(), NetworkRenderError> {
    let rendered = render_object(object)?;
    if rendered.section_type != binding.section_type {
        return Err(NetworkRenderError::PlanMismatch);
    }
    let supported: HashSet<_> = supported_options(object.kind()).iter().copied().collect();
    for option in &binding.present_options {
        if supported.contains(option.as_str()) {
            writeln!(batch, "delete network.{}.{}", binding.section, option)
                .map_err(|_| NetworkRenderError::Output)?;
        }
    }
    render_options(batch, &binding.section, &rendered)
}

struct RenderedNetworkObject {
    section_type: &'static str,
    options: Vec<(&'static str, String)>,
    lists: Vec<(&'static str, Vec<String>)>,
}

fn render_object(object: &NetworkObject) -> Result<RenderedNetworkObject, NetworkRenderError> {
    validate_network_object(object).map_err(|_| NetworkRenderError::InvalidObject)?;
    match object {
        NetworkObject::Interface(value) => render_interface(value),
        NetworkObject::Bridge(value) => Ok(RenderedNetworkObject {
            section_type: "device",
            options: ownership_options(value.ownership, &value.id)
                .into_iter()
                .chain(vec![
                    ("name", value.id.clone()),
                    ("type", "bridge".into()),
                    ("disabled", disabled(value.enabled)),
                    ("stp", boolean(value.stp)),
                    ("vlan_filtering", boolean(value.vlan_filtering)),
                ])
                .chain(value.mtu.map(|mtu| ("mtu", mtu.to_string())))
                .collect(),
            lists: vec![("ports", value.ports.clone())],
        }),
        NetworkObject::Vlan(value) => Ok(RenderedNetworkObject {
            section_type: "device",
            options: ownership_options(value.ownership, &value.id)
                .into_iter()
                .chain(vec![
                    ("name", value.id.clone()),
                    (
                        "type",
                        match value.protocol {
                            NetworkVlanProtocol::Ieee8021Q => "8021q",
                            NetworkVlanProtocol::Ieee8021Ad => "8021ad",
                        }
                        .into(),
                    ),
                    ("ifname", value.parent.clone()),
                    ("vid", value.vlan_id.to_string()),
                    ("disabled", disabled(value.enabled)),
                ])
                .chain(value.mtu.map(|mtu| ("mtu", mtu.to_string())))
                .collect(),
            lists: Vec::new(),
        }),
        NetworkObject::Route(value) if value.output_interface.is_none() || value.table > 65_535 => {
            Err(NetworkRenderError::UnsupportedField(
                "OpenWrt route interface or table",
            ))
        }
        NetworkObject::Route(value) => Ok(render_route(value)),
        NetworkObject::PolicyRule(value) if value.table > 65_535 => Err(
            NetworkRenderError::UnsupportedField("OpenWrt policy rule table"),
        ),
        NetworkObject::PolicyRule(value) => Ok(render_policy_rule(value)),
        NetworkObject::Bond(_) => Err(NetworkRenderError::UnsupportedField("bond")),
        NetworkObject::Vrf(_) => Err(NetworkRenderError::UnsupportedField("VRF")),
    }
}

fn render_interface(
    value: &NetworkInterfaceConfig,
) -> Result<RenderedNetworkObject, NetworkRenderError> {
    let proto = match (value.ipv4_mode, value.ipv6_mode) {
        (NetworkAddressMode::Disabled, NetworkAddressMode::Disabled) => "none",
        (NetworkAddressMode::Static, NetworkAddressMode::Disabled | NetworkAddressMode::Static)
        | (NetworkAddressMode::Disabled, NetworkAddressMode::Static) => "static",
        (NetworkAddressMode::Dhcp, NetworkAddressMode::Disabled) => "dhcp",
        (NetworkAddressMode::Disabled, NetworkAddressMode::Dhcp) => "dhcpv6",
        _ => {
            return Err(NetworkRenderError::UnsupportedField(
                "combined address modes",
            ));
        }
    };
    let mut options = ownership_options(value.ownership, &value.id);
    options.extend([
        ("proto", proto.into()),
        ("device", value.device.clone()),
        ("disabled", disabled(value.enabled)),
    ]);
    if let Some(mtu) = value.mtu {
        options.push(("mtu", mtu.to_string()));
    }
    if let Some(mac) = &value.mac_override {
        options.push(("macaddr", mac.clone()));
    }
    options.push(("peerdns", boolean(value.peerdns)));
    if let Some(client_id) = &value.dhcp_client_id {
        options.push(("clientid", client_id.clone()));
    }
    if let Some(vendor_id) = &value.dhcp_vendor_id {
        options.push(("vendorid", vendor_id.clone()));
    }
    if let Some(hostname) = &value.dhcp_hostname {
        options.push(("hostname", hostname.clone()));
    }
    options.push(("norelease", boolean(value.dhcp_no_release)));
    let ipv4 = value
        .addresses
        .iter()
        .filter(|address| address.address.is_ipv4())
        .map(format_network)
        .collect();
    let ipv6 = value
        .addresses
        .iter()
        .filter(|address| address.address.is_ipv6())
        .map(format_network)
        .collect();
    Ok(RenderedNetworkObject {
        section_type: "interface",
        options,
        lists: vec![
            ("ipaddr", ipv4),
            ("ip6addr", ipv6),
            (
                "dns",
                value.dns_servers.iter().map(ToString::to_string).collect(),
            ),
            ("dns_search", value.dns_search.clone()),
            (
                "reqopts",
                value
                    .dhcp_request_options
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
        ],
    })
}

fn render_route(value: &NetworkRoute) -> RenderedNetworkObject {
    let mut options = ownership_options(value.ownership, &value.id);
    options.extend([
        ("target", format_network(&value.destination)),
        ("table", value.table.to_string()),
        ("disabled", disabled(value.enabled)),
        ("type", route_type(value.route_type).into()),
    ]);
    if let Some(gateway) = value.gateway {
        options.push(("gateway", gateway.to_string()));
    }
    if let Some(interface) = &value.output_interface {
        options.push(("interface", interface.clone()));
    }
    if let Some(source) = value.preferred_source {
        options.push(("source", source.to_string()));
    }
    if let Some(metric) = value.metric {
        options.push(("metric", metric.to_string()));
    }
    RenderedNetworkObject {
        section_type: if value.destination.address.is_ipv4() {
            "route"
        } else {
            "route6"
        },
        options,
        lists: Vec::new(),
    }
}

fn render_policy_rule(value: &NetworkPolicyRule) -> RenderedNetworkObject {
    let mut options = ownership_options(value.ownership, &value.id);
    options.extend([
        ("priority", value.priority.to_string()),
        ("disabled", disabled(value.enabled)),
        ("action", policy_action(value.action).into()),
    ]);
    if value.action == NetworkPolicyAction::Lookup {
        options.push(("lookup", value.table.to_string()));
    }
    if let Some(source) = value.source {
        options.push(("src", format_network(&source)));
    }
    if let Some(destination) = value.destination {
        options.push(("dest", format_network(&destination)));
    }
    if let Some(interface) = &value.input_interface {
        options.push(("in", interface.clone()));
    }
    if let Some(interface) = &value.output_interface {
        options.push(("out", interface.clone()));
    }
    if let (Some(mark), Some(mask)) = (value.fwmark, value.fwmark_mask) {
        options.push(("mark", format!("0x{mark:x}/0x{mask:x}")));
    }
    RenderedNetworkObject {
        section_type: if value.family == NetworkFamily::Ipv4 {
            "rule"
        } else {
            "rule6"
        },
        options,
        lists: Vec::new(),
    }
}

fn render_options(
    batch: &mut String,
    section: &str,
    rendered: &RenderedNetworkObject,
) -> Result<(), NetworkRenderError> {
    for (name, value) in &rendered.options {
        writeln!(batch, "set network.{section}.{name}={}", quote(value)?)
            .map_err(|_| NetworkRenderError::Output)?;
    }
    for (name, values) in &rendered.lists {
        for value in values {
            writeln!(batch, "add_list network.{section}.{name}={}", quote(value)?)
                .map_err(|_| NetworkRenderError::Output)?;
        }
    }
    Ok(())
}

fn ownership_options(ownership: ObjectOwnership, id: &str) -> Vec<(&'static str, String)> {
    if ownership == ObjectOwnership::AgentOwned {
        vec![("mbed_managed", "1".into()), ("mbed_id", id.into())]
    } else {
        Vec::new()
    }
}

fn new_section_name(object: &NetworkObject, digest: &str) -> Result<String, NetworkRenderError> {
    if digest.len() < 16 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(NetworkRenderError::PlanMismatch);
    }
    if matches!(object, NetworkObject::Interface(_)) {
        if !safe_uci_identifier(object.id()) {
            return Err(NetworkRenderError::UnsupportedField(
                "OpenWrt interface identifiers",
            ));
        }
        return Ok(object.id().to_owned());
    }
    let prefix = match object {
        NetworkObject::Bridge(_) => "b",
        NetworkObject::Vlan(_) => "v",
        NetworkObject::Route(_) => "r",
        NetworkObject::PolicyRule(_) => "p",
        NetworkObject::Bond(_) => return Err(NetworkRenderError::UnsupportedField("bond")),
        NetworkObject::Vrf(_) => return Err(NetworkRenderError::UnsupportedField("VRF")),
        NetworkObject::Interface(_) => unreachable!(),
    };
    Ok(format!(
        "mbed_{prefix}_{}",
        &digest[..16].to_ascii_lowercase()
    ))
}

fn binding_for<'a>(
    bindings: &HashMap<(&str, &str), &'a OpenWrtNetworkObjectBinding>,
    key: (&str, &str),
) -> Result<&'a OpenWrtNetworkObjectBinding, NetworkRenderError> {
    bindings
        .get(&key)
        .copied()
        .ok_or(NetworkRenderError::MissingBinding)
}

fn valid_section_type(section_type: &str, kind: &str) -> bool {
    matches!(
        (kind, section_type),
        ("interface", "interface")
            | ("bridge" | "vlan", "device")
            | ("route", "route" | "route6")
            | ("policy_rule", "rule" | "rule6")
    )
}

fn known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "interface" | "bridge" | "vlan" | "route" | "policy_rule"
    )
}

fn supported_options(kind: &str) -> &'static [&'static str] {
    match kind {
        "interface" => &[
            "mbed_managed",
            "mbed_id",
            "proto",
            "device",
            "ifname",
            "disabled",
            "auto",
            "ipaddr",
            "netmask",
            "ip6addr",
            "mtu",
            "macaddr",
            "peerdns",
            "dns",
            "dns_search",
            "clientid",
            "vendorid",
            "hostname",
            "reqopts",
            "norelease",
        ],
        "bridge" => &[
            "mbed_managed",
            "mbed_id",
            "name",
            "type",
            "disabled",
            "ports",
            "stp",
            "vlan_filtering",
            "mtu",
        ],
        "vlan" => &[
            "mbed_managed",
            "mbed_id",
            "name",
            "type",
            "disabled",
            "ifname",
            "vid",
            "mtu",
        ],
        "route" => &[
            "mbed_managed",
            "mbed_id",
            "name",
            "disabled",
            "target",
            "netmask",
            "gateway",
            "interface",
            "source",
            "table",
            "metric",
            "type",
        ],
        "policy_rule" => &[
            "mbed_managed",
            "mbed_id",
            "name",
            "disabled",
            "priority",
            "src",
            "dest",
            "in",
            "out",
            "mark",
            "lookup",
            "action",
        ],
        _ => &[],
    }
}

fn section_id(section: &UciSection, fallback_kind: &str) -> Option<String> {
    if let Some(id) = managed_id(section).or_else(|| optional(section, "name").map(str::to_owned)) {
        return Some(id);
    }
    let index = section
        .selector
        .strip_prefix('@')?
        .strip_prefix(&section.section_type)?
        .strip_prefix('[')?
        .strip_suffix(']')?;
    Some(format!("platform-{fallback_kind}-{index}"))
}

fn managed_id(section: &UciSection) -> Option<String> {
    optional(section, "mbed_id").map(str::to_owned)
}

fn scalar<'a>(section: &'a UciSection, name: &str) -> Option<&'a str> {
    let values = section.values(name);
    (values.len() == 1).then(|| values[0].as_str())
}

fn optional<'a>(section: &'a UciSection, name: &str) -> Option<&'a str> {
    scalar(section, name)
}

fn exclusive<'a>(left: Option<&'a str>, right: Option<&'a str>) -> Option<&'a str> {
    match (left, right) {
        (Some(value), None) | (None, Some(value)) => Some(value),
        _ => None,
    }
}

fn enabled(section: &UciSection) -> Option<bool> {
    let disabled = optional_bool(section, "disabled").ok()?.unwrap_or(false);
    let auto = optional_bool(section, "auto").ok()?.unwrap_or(true);
    Some(!disabled && auto)
}

fn optional_bool(section: &UciSection, name: &str) -> Result<Option<bool>, ()> {
    match optional(section, name) {
        None => Ok(None),
        Some("0" | "false" | "no" | "off") => Ok(Some(false)),
        Some("1" | "true" | "yes" | "on") => Ok(Some(true)),
        _ => Err(()),
    }
}

fn optional_u32(section: &UciSection, name: &str) -> Result<Option<u32>, ()> {
    optional(section, name)
        .map(str::parse)
        .transpose()
        .map_err(|_| ())
}

fn optional_u16(section: &UciSection, name: &str) -> Result<Option<u16>, ()> {
    optional(section, name)
        .map(str::parse)
        .transpose()
        .map_err(|_| ())
}

fn dhcp_mode(
    section: &UciSection,
    name: &str,
    default: NetworkDhcpMode,
) -> Option<NetworkDhcpMode> {
    match optional(section, name) {
        None => Some(default),
        Some("disabled") => Some(NetworkDhcpMode::Disabled),
        Some("server") => Some(NetworkDhcpMode::Server),
        Some("relay") => Some(NetworkDhcpMode::Relay),
        Some("hybrid") => Some(NetworkDhcpMode::Hybrid),
        _ => None,
    }
}

fn parse_dhcp_options(section: &UciSection) -> Option<Vec<NetworkDhcpOption>> {
    let values = section.values("dhcp_option");
    if values.len() > 16 {
        return None;
    }
    values
        .iter()
        .map(|raw| {
            let (code, value) = raw.split_once(',')?;
            let code = code.parse::<u16>().ok()?;
            if !(1..=255).contains(&code)
                || value.is_empty()
                || value.len() > 255
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || matches!(byte, b'\'' | b'\\' | b','))
            {
                return None;
            }
            Some(NetworkDhcpOption {
                code,
                value: value.to_owned(),
            })
        })
        .collect()
}

fn optional_ip(section: &UciSection, name: &str) -> Result<Option<IpAddr>, ()> {
    optional(section, name)
        .map(str::parse)
        .transpose()
        .map_err(|_| ())
}

fn parse_optional_network(section: &UciSection, name: &str) -> Result<Option<IpNetwork>, ()> {
    match optional(section, name) {
        Some(value) => parse_ip_network(value).map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn parse_ipv4_interface_address(raw: &str, netmask: Option<&str>) -> Option<IpNetwork> {
    if raw.contains('/') {
        let value = parse_ip_network(raw)?;
        return value.address.is_ipv4().then_some(value);
    }
    let address: Ipv4Addr = raw.parse().ok()?;
    let prefix_len = netmask_to_prefix(netmask?)?;
    Some(IpNetwork {
        address: address.into(),
        prefix_len,
    })
}

fn parse_route_target(raw: &str, netmask: Option<&str>, ipv6: bool) -> Option<IpNetwork> {
    let value = if raw.contains('/') {
        parse_ip_network(raw)?
    } else if ipv6 {
        IpNetwork {
            address: raw.parse().ok()?,
            prefix_len: 128,
        }
    } else {
        IpNetwork {
            address: raw.parse::<Ipv4Addr>().ok()?.into(),
            prefix_len: netmask_to_prefix(netmask?)?,
        }
    };
    (value.address.is_ipv6() == ipv6).then_some(value)
}

fn parse_ip_network(raw: &str) -> Option<IpNetwork> {
    let (address, prefix) = raw.split_once('/')?;
    Some(IpNetwork {
        address: address.parse().ok()?,
        prefix_len: prefix.parse().ok()?,
    })
}

fn netmask_to_prefix(raw: &str) -> Option<u8> {
    let mask = u32::from(raw.parse::<Ipv4Addr>().ok()?);
    let prefix = mask.leading_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (mask == expected)
        .then(|| u8::try_from(prefix).ok())
        .flatten()
}

fn parse_table(raw: &str) -> Option<u32> {
    match raw {
        "local" => Some(255),
        "main" => Some(254),
        "default" => Some(253),
        _ => raw.parse().ok(),
    }
}

fn parse_mark(raw: &str) -> Option<(Option<u32>, Option<u32>)> {
    let parts = raw.split_once('/')?;
    Some((Some(parse_number(parts.0)?), Some(parse_number(parts.1)?)))
}

fn parse_number(raw: &str) -> Option<u32> {
    raw.strip_prefix("0x").map_or_else(
        || raw.parse().ok(),
        |value| u32::from_str_radix(value, 16).ok(),
    )
}

fn route_type(value: NetworkRouteType) -> &'static str {
    match value {
        NetworkRouteType::Unicast => "unicast",
        NetworkRouteType::Blackhole => "blackhole",
        NetworkRouteType::Unreachable => "unreachable",
        NetworkRouteType::Prohibit => "prohibit",
    }
}

fn policy_action(value: NetworkPolicyAction) -> &'static str {
    match value {
        NetworkPolicyAction::Lookup => "lookup",
        NetworkPolicyAction::Blackhole => "blackhole",
        NetworkPolicyAction::Unreachable => "unreachable",
        NetworkPolicyAction::Prohibit => "prohibit",
    }
}

fn format_network(value: &IpNetwork) -> String {
    format!("{}/{}", value.address, value.prefix_len)
}

fn boolean(value: bool) -> String {
    if value { "1" } else { "0" }.into()
}

fn disabled(enabled: bool) -> String {
    boolean(!enabled)
}

fn quote(value: &str) -> Result<String, NetworkRenderError> {
    if value.len() > 1024
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'\'' | b'\\'))
    {
        return Err(NetworkRenderError::UnsafeValue);
    }
    Ok(format!("'{value}'"))
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkRenderError {
    #[error("OpenWrt network staging backend is unavailable")]
    BackendUnavailable,
    #[error("OpenWrt network staging input exceeds its capacity")]
    Capacity,
    #[error("UCI network inventory output is malformed")]
    MalformedUci,
    #[error("an Agent-owned network section cannot be represented safely: {0}")]
    UnsupportedManagedSection(String),
    #[error("a network section has an unsafe ownership marker: {0}")]
    UnsafeOwnershipMarker(String),
    #[error("typed network inventory contains a duplicate object identity")]
    DuplicateInventoryObject,
    #[error("typed network inventory is ambiguous")]
    AmbiguousInventory,
    #[error("network mutation plan contains an invalid object")]
    InvalidObject,
    #[error("network mutation plan does not match fresh inventory")]
    PlanMismatch,
    #[error("an existing network object has no fresh UCI binding")]
    MissingBinding,
    #[error("a UCI network binding is unsafe")]
    UnsafeBinding,
    #[error("duplicate UCI network binding")]
    DuplicateBinding,
    #[error("multiple network objects resolve to the same UCI section")]
    DuplicateSection,
    #[error("OpenWrt UCI cannot safely represent network field: {0}")]
    UnsupportedField(&'static str),
    #[error("unsafe value cannot be represented in a UCI batch")]
    UnsafeValue,
    #[error("failed to render the network staging artifact")]
    Output,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::{
        NetworkMutation, NetworkRiskContext, network_object_digest, plan_network_mutations,
    };
    use agent_protocol::{NetworkBond, NetworkBondMode, NetworkDhcpServerConfig};
    use std::net::Ipv4Addr;

    const NETWORK_FIXTURE: &str = "network.lan=interface\n\
network.lan.proto='static'\n\
network.lan.device='br-lan'\n\
network.lan.ipaddr='192.168.1.1'\n\
network.lan.netmask='255.255.255.0'\n\
network.lan.mtu='1500'\n\
network.lan.peerdns='0'\n\
network.lan.dns='1.1.1.1' '2606:4700:4700::1111'\n\
network.lan.dns_search='example.com'\n\
network.lan.clientid='01:02:03:04:05:06'\n\
network.lan.vendorid='mbed-router'\n\
network.lan.hostname='lan-router'\n\
network.lan.reqopts='1' '3' '6'\n\
network.lan.norelease='1'\n\
network.lan.vendor_keep='yes'\n\
network.@device[0]=device\n\
network.@device[0].name='br-lan'\n\
network.@device[0].type='bridge'\n\
network.@device[0].ports='lan1' 'lan2'\n\
network.@device[0].stp='1'\n\
network.@device[1]=device\n\
network.@device[1].name='eth0.100'\n\
network.@device[1].type='8021q'\n\
network.@device[1].ifname='eth0'\n\
network.@device[1].vid='100'\n\
network.@route[0]=route\n\
network.@route[0].name='guest-route'\n\
network.@route[0].interface='lan'\n\
network.@route[0].target='198.51.100.0'\n\
network.@route[0].netmask='255.255.255.0'\n\
network.@route[0].gateway='192.168.1.254'\n\
network.@route[0].table='100'\n\
network.@rule[0]=rule\n\
network.@rule[0].name='guest-policy'\n\
network.@rule[0].priority='1000'\n\
network.@rule[0].src='192.168.1.0/24'\n\
network.@rule[0].mark='0x1/0xff'\n\
network.@rule[0].lookup='100'\n";

    const DHCP_FIXTURE: &str = "dhcp.lan=dhcp\n\
dhcp.lan.interface='lan'\n\
dhcp.lan.start='100'\n\
dhcp.lan.limit='100'\n\
dhcp.lan.leasetime='12h'\n\
dhcp.lan.force='1'\n\
dhcp.lan.dhcpv6='server'\n\
dhcp.lan.ra='hybrid'\n\
dhcp.lan.ndp='relay'\n\
dhcp.lan.dhcp_option='6,192.168.1.1' '15,example.com'\n\
dhcp.lan.vendor_keep='yes'\n";

    fn guest_interface(ownership: ObjectOwnership) -> NetworkObject {
        NetworkObject::Interface(NetworkInterfaceConfig {
            id: "guest".into(),
            ownership,
            enabled: true,
            device: "br-guest".into(),
            ipv4_mode: NetworkAddressMode::Static,
            ipv6_mode: NetworkAddressMode::Disabled,
            addresses: vec![IpNetwork {
                address: Ipv4Addr::new(192, 0, 2, 1).into(),
                prefix_len: 24,
            }],
            mtu: Some(1500),
            mac_override: None,
            peerdns: false,
            dns_servers: vec![
                "9.9.9.9".parse().expect("DNS server"),
                "2620:fe::fe".parse().expect("DNS server"),
            ],
            dns_search: vec!["guest.example".into()],
            dhcp_client_id: Some("mbed-guest-client".into()),
            dhcp_vendor_id: Some("mbed-agent".into()),
            dhcp_hostname: Some("guest-router".into()),
            dhcp_request_options: vec![1, 3, 6],
            dhcp_no_release: true,
            dhcp_server: Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 100,
                limit: 100,
                lease_time: "12h".into(),
                force: false,
                dhcpv6_mode: NetworkDhcpMode::Disabled,
                ra_mode: NetworkDhcpMode::Disabled,
                ndp_mode: NetworkDhcpMode::Disabled,
                dhcp_options: vec![NetworkDhcpOption {
                    code: 6,
                    value: "192.0.2.53".into(),
                }],
            }),
        })
    }

    fn staging_capabilities(kind: PlatformKind, supported: bool) -> PlatformCapabilities {
        PlatformCapabilities {
            kind,
            release: Some("21.02.7".into()),
            release_supported: supported,
            firewall: crate::FirewallCapabilities {
                backend: crate::FirewallBackend::Fw3,
                has_iptables_save: true,
                has_ip6tables_save: true,
                has_nft: false,
                can_trace: false,
            },
            device_model: NetworkDeviceModel::Dsa,
            package_manager: crate::PackageManager::Opkg,
            init_system: crate::InitSystem::Procd,
            has_ubus: true,
            has_uci: true,
            has_procd: true,
            available_commands: vec!["uci".into(), "ubus".into()],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn selects_only_supported_openwrt_21_plus_staging() {
        assert_eq!(
            select_openwrt_network_staging(&staging_capabilities(PlatformKind::OpenWrt, true)),
            Ok(NetworkDeviceModel::Dsa)
        );
        assert_eq!(
            select_openwrt_network_staging(&staging_capabilities(PlatformKind::OpenWrt, false)),
            Err(NetworkRenderError::BackendUnavailable)
        );
        assert_eq!(
            select_openwrt_network_staging(&staging_capabilities(PlatformKind::GenericLinux, true)),
            Err(NetworkRenderError::BackendUnavailable)
        );
    }

    #[test]
    fn reconstructs_supported_openwrt_network_objects_and_bindings() {
        let snapshot = inspect_openwrt_network_inventory(NETWORK_FIXTURE).expect("inventory");
        assert_eq!(snapshot.inventory().objects.len(), 5);
        assert_eq!(snapshot.bindings().len(), 5);
        assert!(snapshot.read_only_sections().is_empty());

        let interface = snapshot
            .inventory()
            .objects
            .iter()
            .find(|object| object.kind() == "interface")
            .expect("interface");
        let NetworkObject::Interface(interface) = interface else {
            unreachable!();
        };
        assert_eq!(interface.id, "lan");
        assert_eq!(interface.ownership, ObjectOwnership::PlatformNative);
        assert_eq!(interface.addresses[0].prefix_len, 24);
        assert!(!interface.peerdns);
        assert_eq!(interface.dns_servers.len(), 2);
        assert_eq!(interface.dns_search, ["example.com"]);
        assert_eq!(
            interface.dhcp_client_id.as_deref(),
            Some("01:02:03:04:05:06")
        );
        assert_eq!(interface.dhcp_vendor_id.as_deref(), Some("mbed-router"));
        assert_eq!(interface.dhcp_hostname.as_deref(), Some("lan-router"));
        assert_eq!(interface.dhcp_request_options, [1, 3, 6]);
        assert!(interface.dhcp_no_release);

        let rule = snapshot
            .inventory()
            .objects
            .iter()
            .find(|object| object.kind() == "policy_rule")
            .expect("rule");
        let NetworkObject::PolicyRule(rule) = rule else {
            unreachable!();
        };
        assert_eq!(rule.fwmark, Some(1));
        assert_eq!(rule.fwmark_mask, Some(255));
    }

    #[test]
    fn reconstructs_and_binds_openwrt_dhcp_server_subset() {
        let snapshot = inspect_openwrt_network_inventory_with_dhcp(NETWORK_FIXTURE, DHCP_FIXTURE)
            .expect("inventory");
        assert_eq!(snapshot.dhcp_occupied_sections(), ["lan"]);
        assert!(snapshot.dhcp_read_only_sections().is_empty());
        let interface = snapshot
            .inventory()
            .objects
            .iter()
            .find_map(|object| match object {
                NetworkObject::Interface(value) if value.id == "lan" => Some(value),
                _ => None,
            })
            .expect("lan interface");
        assert_eq!(
            interface.dhcp_server,
            Some(NetworkDhcpServerConfig {
                enabled: true,
                start: 100,
                limit: 100,
                lease_time: "12h".into(),
                force: true,
                dhcpv6_mode: NetworkDhcpMode::Server,
                ra_mode: NetworkDhcpMode::Hybrid,
                ndp_mode: NetworkDhcpMode::Relay,
                dhcp_options: vec![
                    NetworkDhcpOption {
                        code: 6,
                        value: "192.168.1.1".into(),
                    },
                    NetworkDhcpOption {
                        code: 15,
                        value: "example.com".into(),
                    },
                ],
            })
        );
        let binding = snapshot
            .bindings()
            .iter()
            .find(|binding| binding.id == "lan")
            .expect("lan binding");
        assert_eq!(binding.dhcp_section.as_deref(), Some("lan"));
        assert!(!binding.dhcp_agent_owned);
        assert!(
            binding
                .dhcp_present_options
                .iter()
                .any(|option| option == "vendor_keep")
        );
    }

    #[test]
    fn rejects_unknown_dhcp_modes_without_claiming_native_sections() {
        let native = "dhcp.lan=dhcp\n\
dhcp.lan.interface='lan'\n\
dhcp.lan.dhcpv6='unknown'\n";
        let snapshot = inspect_openwrt_network_inventory_with_dhcp(NETWORK_FIXTURE, native)
            .expect("native unknown mode is read-only");
        assert_eq!(snapshot.dhcp_read_only_sections(), ["lan"]);
        let interface = snapshot
            .inventory()
            .objects
            .iter()
            .find_map(|object| match object {
                NetworkObject::Interface(value) if value.id == "lan" => Some(value),
                _ => None,
            })
            .expect("lan interface");
        assert!(interface.dhcp_server.is_none());
        let binding = snapshot
            .bindings()
            .iter()
            .find(|binding| binding.id == "lan")
            .expect("lan binding");
        assert!(binding.dhcp_section.is_none());

        let managed = "dhcp.mbed_lan=dhcp\n\
dhcp.mbed_lan.mbed_managed='1'\n\
dhcp.mbed_lan.interface='lan'\n\
dhcp.mbed_lan.ra='unknown'\n";
        assert_eq!(
            inspect_openwrt_network_inventory_with_dhcp(NETWORK_FIXTURE, managed),
            Err(NetworkRenderError::UnsupportedManagedSection(
                "mbed_lan".into()
            ))
        );
    }

    #[test]
    fn rejects_malformed_dhcp_options_without_claiming_sections() {
        let native = "dhcp.lan=dhcp\n\
dhcp.lan.interface='lan'\n\
dhcp.lan.dhcp_option='6,1.1.1.1,8.8.8.8'\n";
        let snapshot = inspect_openwrt_network_inventory_with_dhcp(NETWORK_FIXTURE, native)
            .expect("native malformed option is read-only");
        assert_eq!(snapshot.dhcp_read_only_sections(), ["lan"]);

        let managed = "dhcp.mbed_lan=dhcp\n\
dhcp.mbed_lan.mbed_managed='1'\n\
dhcp.mbed_lan.interface='lan'\n\
dhcp.mbed_lan.dhcp_option='6,1.1.1.1,8.8.8.8'\n";
        assert_eq!(
            inspect_openwrt_network_inventory_with_dhcp(NETWORK_FIXTURE, managed),
            Err(NetworkRenderError::UnsupportedManagedSection(
                "mbed_lan".into()
            ))
        );
    }

    #[test]
    fn unsupported_native_sections_are_read_only_but_managed_drift_fails_closed() {
        let native =
            "network.wan=interface\nnetwork.wan.proto='pppoe'\nnetwork.wan.device='eth0'\n";
        let snapshot = inspect_openwrt_network_inventory(native).expect("native read-only");
        assert!(snapshot.inventory().objects.is_empty());
        assert_eq!(snapshot.read_only_sections(), ["wan"]);

        let managed = "network.mbed_bad=interface\nnetwork.mbed_bad.mbed_managed='1'\nnetwork.mbed_bad.proto='pppoe'\nnetwork.mbed_bad.device='eth0'\n";
        assert_eq!(
            inspect_openwrt_network_inventory(managed),
            Err(NetworkRenderError::UnsupportedManagedSection(
                "mbed_bad".into()
            ))
        );
        assert!(
            inspect_openwrt_network_inventory(
                "network.mbed_bad=interface\nnetwork.mbed_bad.proto='none'\nnetwork.mbed_bad.device='eth0'\n"
            )
            .is_err()
        );
    }

    #[test]
    fn creates_agent_owned_interface_with_closed_staging_batch() {
        let snapshot = inspect_openwrt_network_inventory("").expect("empty inventory");
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Create(guest_interface(
                ObjectOwnership::AgentOwned,
            ))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_openwrt_network_stage_from_snapshot(&plan, &snapshot).expect("stage");
        assert!(stage.uci_batch.starts_with("set network.guest=interface\n"));
        assert!(stage.uci_batch.contains("network.guest.mbed_managed='1'"));
        assert!(stage.uci_batch.contains("network.guest.proto='static'"));
        assert!(
            stage
                .uci_batch
                .contains("add_list network.guest.ipaddr='192.0.2.1/24'")
        );
        assert!(stage.uci_batch.contains("network.guest.peerdns='0'"));
        assert!(
            stage
                .uci_batch
                .contains("network.guest.clientid='mbed-guest-client'")
        );
        assert!(
            stage
                .uci_batch
                .contains("network.guest.vendorid='mbed-agent'")
        );
        assert!(
            stage
                .uci_batch
                .contains("network.guest.hostname='guest-router'")
        );
        assert!(stage.uci_batch.contains("network.guest.norelease='1'"));
        assert!(
            stage
                .uci_batch
                .contains("add_list network.guest.dns='9.9.9.9'")
        );
        assert!(
            stage
                .uci_batch
                .contains("add_list network.guest.reqopts='1'")
        );
        assert!(
            stage
                .uci_batch
                .contains("add_list network.guest.dns_search='guest.example'")
        );
        assert!(stage.dhcp_uci_batch.contains("set dhcp.guest=dhcp"));
        assert!(
            stage
                .dhcp_uci_batch
                .contains("dhcp.guest.interface='guest'")
        );
        assert!(stage.dhcp_uci_batch.contains("dhcp.guest.start='100'"));
        assert!(stage.dhcp_uci_batch.contains("dhcp.guest.limit='100'"));
        assert!(stage.dhcp_uci_batch.contains("dhcp.guest.leasetime='12h'"));
        assert!(
            stage
                .dhcp_uci_batch
                .contains("dhcp.guest.dhcpv6='disabled'")
        );
        assert!(stage.dhcp_uci_batch.contains("dhcp.guest.ra='disabled'"));
        assert!(stage.dhcp_uci_batch.contains("dhcp.guest.ndp='disabled'"));
        assert!(
            stage
                .dhcp_uci_batch
                .contains("add_list dhcp.guest.dhcp_option='6,192.0.2.53'")
        );
        assert!(stage.dhcp_uci_batch.ends_with("commit dhcp\n"));
        assert!(stage.uci_batch.ends_with("commit network\n"));
        assert_eq!(stage.validations, [OpenWrtNetworkValidation::UciExport]);
    }

    #[test]
    fn updates_platform_native_interface_without_claiming_or_deleting_vendor_options() {
        let snapshot = inspect_openwrt_network_inventory(NETWORK_FIXTURE).expect("inventory");
        let before = snapshot
            .inventory()
            .objects
            .iter()
            .find(|object| object.kind() == "interface")
            .expect("interface")
            .clone();
        let digest = network_object_digest(&before).expect("digest");
        let mut desired = before;
        let NetworkObject::Interface(value) = &mut desired else {
            unreachable!();
        };
        value.mtu = Some(1400);
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Update {
                expected_digest: digest,
                desired,
            }],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_openwrt_network_stage_from_snapshot(&plan, &snapshot).expect("stage");
        assert!(stage.uci_batch.contains("delete network.lan.mtu"));
        assert!(stage.uci_batch.contains("set network.lan.mtu='1400'"));
        assert!(!stage.uci_batch.contains("vendor_keep"));
        assert!(!stage.uci_batch.contains("mbed_managed"));
    }

    #[test]
    fn renders_bridge_vlan_route_and_policy_rule_without_raw_expressions() {
        let snapshot = inspect_openwrt_network_inventory("").expect("empty");
        let objects = vec![
            NetworkObject::Bridge(NetworkBridge {
                id: "br-guest".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                ports: vec!["lan3".into()],
                stp: true,
                vlan_filtering: false,
                mtu: Some(1500),
            }),
            NetworkObject::Vlan(NetworkVlan {
                id: "eth0.200".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                parent: "eth0".into(),
                vlan_id: 200,
                protocol: NetworkVlanProtocol::Ieee8021Q,
                mtu: Some(1500),
            }),
            NetworkObject::Route(NetworkRoute {
                id: "guest-route".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                destination: IpNetwork {
                    address: Ipv4Addr::new(203, 0, 113, 0).into(),
                    prefix_len: 24,
                },
                gateway: Some(Ipv4Addr::new(192, 0, 2, 254).into()),
                output_interface: Some("guest".into()),
                preferred_source: None,
                table: 100,
                metric: Some(20),
                route_type: NetworkRouteType::Unicast,
            }),
            NetworkObject::PolicyRule(NetworkPolicyRule {
                id: "guest-policy".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                family: NetworkFamily::Ipv4,
                priority: 1000,
                source: Some(IpNetwork {
                    address: Ipv4Addr::new(192, 0, 2, 0).into(),
                    prefix_len: 24,
                }),
                destination: None,
                input_interface: None,
                output_interface: None,
                fwmark: Some(1),
                fwmark_mask: Some(255),
                table: 100,
                action: NetworkPolicyAction::Lookup,
            }),
        ];
        let mutations: Vec<_> = objects.into_iter().map(NetworkMutation::Create).collect();
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &mutations,
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let stage = render_openwrt_network_stage_from_snapshot(&plan, &snapshot).expect("stage");
        assert!(stage.uci_batch.contains(".type='bridge'"));
        assert!(stage.uci_batch.contains(".type='8021q'"));
        assert!(stage.uci_batch.contains(".vid='200'"));
        assert!(stage.uci_batch.contains(".target='203.0.113.0/24'"));
        assert!(stage.uci_batch.contains(".mark='0x1/0xff'"));
        assert!(!stage.uci_batch.contains(';'));
    }

    #[test]
    fn rejects_unsupported_bond_and_stale_snapshot() {
        let snapshot = inspect_openwrt_network_inventory("").expect("empty");
        let bond = NetworkObject::Bond(NetworkBond {
            id: "bond0".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            ports: vec!["eth0".into(), "eth1".into()],
            mode: NetworkBondMode::ActiveBackup,
            primary: Some("eth0".into()),
            monitor_interval_ms: 100,
            mtu: Some(1500),
        });
        let plan = plan_network_mutations(
            snapshot.inventory(),
            &[NetworkMutation::Create(bond)],
            &NetworkRiskContext::default(),
        )
        .expect("core plan");
        assert_eq!(
            render_openwrt_network_stage_from_snapshot(&plan, &snapshot),
            Err(NetworkRenderError::UnsupportedField("bond"))
        );

        let planned_from_empty = plan_network_mutations(
            &NetworkInventory { objects: vec![] },
            &[NetworkMutation::Create(guest_interface(
                ObjectOwnership::AgentOwned,
            ))],
            &NetworkRiskContext::default(),
        )
        .expect("plan");
        let occupied = inspect_openwrt_network_inventory(
            "network.guest=interface\nnetwork.guest.proto='none'\nnetwork.guest.device='br-guest'\n",
        )
        .expect("occupied");
        assert_eq!(
            render_openwrt_network_stage_from_snapshot(&planned_from_empty, &occupied),
            Err(NetworkRenderError::PlanMismatch)
        );
    }
}
