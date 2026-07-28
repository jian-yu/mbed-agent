use std::collections::HashSet;
use std::net::IpAddr;

use agent_core::{FirewallInventory, validate_firewall_object};
use agent_protocol::{
    FirewallAddressSet, FirewallDirection, FirewallFamily, FirewallFilterRule, FirewallForwarding,
    FirewallLog, FirewallLogLevel, FirewallMatch, FirewallNatKind, FirewallNatRule, FirewallObject,
    FirewallProtocol, FirewallRateLimit, FirewallSetEntry, FirewallVerdict, FirewallZone,
    IpNetwork, ObjectOwnership, PortRange,
};

use crate::firewall::{FirewallRenderError, OpenWrtObjectBinding};
use crate::firewall_uci::{UciSection, parse_uci_show};

const MAX_BINDING_OPTIONS: usize = 64;

/// One bounded, internally consistent view of the current `OpenWrt` firewall package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtFirewallInventorySnapshot {
    inventory: FirewallInventory,
    bindings: Vec<OpenWrtObjectBinding>,
    /// Every section selector, including unsupported vendor sections.
    occupied_sections: Vec<String>,
    /// Platform-native sections that cannot be represented without losing semantics.
    read_only_sections: Vec<String>,
}

impl OpenWrtFirewallInventorySnapshot {
    #[must_use]
    pub fn inventory(&self) -> &FirewallInventory {
        &self.inventory
    }

    #[must_use]
    pub fn bindings(&self) -> &[OpenWrtObjectBinding] {
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
}

#[derive(Debug, Clone, Copy)]
struct ZoneDefaults {
    input: FirewallVerdict,
    output: FirewallVerdict,
    forward: FirewallVerdict,
}

/// Builds typed firewall objects and exact UCI bindings from the same fresh snapshot.
///
/// Unsupported platform-native sections stay visible as read-only selectors. A section carrying
/// the reserved `mbed_` prefix must decode exactly or the entire inspection fails closed.
///
/// # Errors
///
/// Returns an error for malformed/bounded UCI data, duplicate typed identities, ambiguous
/// defaults, or an Agent-owned section whose native state no longer matches the typed model.
pub fn inspect_openwrt_firewall_inventory(
    uci_show: &str,
) -> Result<OpenWrtFirewallInventorySnapshot, FirewallRenderError> {
    let sections = parse_uci_show(uci_show)?;
    let defaults = zone_defaults(&sections)?;
    let mut objects = Vec::new();
    let mut bindings = Vec::new();
    let mut read_only_sections = Vec::new();
    let mut identities = HashSet::new();

    for section in &sections {
        if section.section_type == "defaults" {
            continue;
        }
        let managed = section.selector.starts_with("mbed_");
        if !matches!(
            section.section_type.as_str(),
            "zone" | "forwarding" | "rule" | "ipset" | "redirect" | "nat"
        ) {
            if managed {
                return Err(FirewallRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        }
        let Some(object) = decode_section(section, defaults) else {
            if managed {
                return Err(FirewallRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        };
        if managed && object.ownership() != ObjectOwnership::AgentOwned {
            return Err(FirewallRenderError::UnsupportedManagedSection(
                section.selector.clone(),
            ));
        }
        if validate_firewall_object(&object).is_err() {
            if managed {
                return Err(FirewallRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        }
        if section.options.len() > MAX_BINDING_OPTIONS {
            if managed {
                return Err(FirewallRenderError::UnsupportedManagedSection(
                    section.selector.clone(),
                ));
            }
            read_only_sections.push(section.selector.clone());
            continue;
        }
        let identity = (object.kind().to_owned(), object.id().to_owned());
        if !identities.insert(identity) {
            return Err(FirewallRenderError::DuplicateInventoryObject);
        }
        let mut present_options: Vec<String> = section.options.keys().cloned().collect();
        present_options.sort_unstable();
        bindings.push(OpenWrtObjectBinding {
            kind: object.kind().into(),
            id: object.id().into(),
            section_type: section.section_type.clone(),
            section: section.selector.clone(),
            present_options,
        });
        objects.push(object);
    }

    Ok(OpenWrtFirewallInventorySnapshot {
        inventory: FirewallInventory { objects },
        bindings,
        occupied_sections: sections
            .iter()
            .map(|section| section.selector.clone())
            .collect(),
        read_only_sections,
    })
}

fn zone_defaults(sections: &[UciSection]) -> Result<Option<ZoneDefaults>, FirewallRenderError> {
    let defaults: Vec<&UciSection> = sections
        .iter()
        .filter(|section| section.section_type == "defaults")
        .collect();
    if defaults.len() > 1 {
        return Err(FirewallRenderError::AmbiguousInventory);
    }
    let Some(defaults) = defaults.first() else {
        return Ok(None);
    };
    let input = verdict(defaults, "input").ok_or(FirewallRenderError::AmbiguousInventory)?;
    let output = verdict(defaults, "output").ok_or(FirewallRenderError::AmbiguousInventory)?;
    let forward = verdict(defaults, "forward").ok_or(FirewallRenderError::AmbiguousInventory)?;
    Ok(Some(ZoneDefaults {
        input,
        output,
        forward,
    }))
}

fn decode_section(section: &UciSection, defaults: Option<ZoneDefaults>) -> Option<FirewallObject> {
    valid_cardinality(section)?;
    let ownership = section_ownership(section)?;
    match section.section_type.as_str() {
        "zone" => decode_zone(section, defaults, ownership).map(FirewallObject::Zone),
        "forwarding" => decode_forwarding(section, ownership).map(FirewallObject::Forwarding),
        "rule" => decode_filter_rule(section, ownership).map(FirewallObject::FilterRule),
        "ipset" => decode_address_set(section, ownership).map(FirewallObject::AddressSet),
        "redirect" | "nat" => decode_nat_rule(section, ownership).map(FirewallObject::NatRule),
        _ => None,
    }
}

fn valid_cardinality(section: &UciSection) -> Option<()> {
    let list_options: &[&str] = match section.section_type.as_str() {
        "zone" => &["network"],
        "rule" => &[
            "src_ip",
            "src_mac",
            "src_port",
            "dest_ip",
            "dest_port",
            "icmp_type",
        ],
        "ipset" => &["entry"],
        "redirect" => &["src_mac"],
        _ => &[],
    };
    for (name, values) in &section.options {
        if values.len() > 1 && !list_options.contains(&name.as_str()) {
            return None;
        }
    }
    Some(())
}

fn decode_zone(
    section: &UciSection,
    defaults: Option<ZoneDefaults>,
    ownership: ObjectOwnership,
) -> Option<FirewallZone> {
    let defaults = defaults.unwrap_or(ZoneDefaults {
        input: FirewallVerdict::Reject,
        output: FirewallVerdict::Reject,
        forward: FirewallVerdict::Reject,
    });
    Some(FirewallZone {
        id: scalar(section, "name")?.to_owned(),
        ownership,
        enabled: enabled(section)?,
        networks: section.values("network").to_vec(),
        input: verdict(section, "input").unwrap_or(defaults.input),
        output: verdict(section, "output").unwrap_or(defaults.output),
        forward: verdict(section, "forward").unwrap_or(defaults.forward),
        masquerade: boolean(section, "masq").ok()?.unwrap_or(false),
        mtu_fix: boolean(section, "mtu_fix").ok()?.unwrap_or(false),
    })
}

fn decode_forwarding(
    section: &UciSection,
    ownership: ObjectOwnership,
) -> Option<FirewallForwarding> {
    let source_zone = scalar(section, "src")?.to_owned();
    let destination_zone = scalar(section, "dest")?.to_owned();
    let id = scalar(section, "name").map_or_else(
        || format!("{source_zone}-{destination_zone}"),
        str::to_owned,
    );
    Some(FirewallForwarding {
        id,
        ownership,
        enabled: enabled(section)?,
        source_zone,
        destination_zone,
    })
}

fn decode_filter_rule(
    section: &UciSection,
    ownership: ObjectOwnership,
) -> Option<FirewallFilterRule> {
    let mut matches = decode_common_matches(section)?;
    let direction = rule_direction(section, &mut matches)?;
    let verdict = verdict(section, "target")?;
    let rate_limit = match scalar(section, "limit") {
        Some(value) => Some(FirewallRateLimit {
            packets_per_second: value.strip_suffix("/second")?.parse().ok()?,
            burst: scalar(section, "limit_burst")?.parse().ok()?,
        }),
        None if section.options.contains_key("limit_burst") => return None,
        None => None,
    };
    let log = scalar(section, "log").map(|prefix| FirewallLog {
        prefix: prefix.to_owned(),
        level: FirewallLogLevel::Info,
    });
    Some(FirewallFilterRule {
        id: object_id(section, "rule")?,
        ownership,
        enabled: enabled(section)?,
        direction,
        matches,
        verdict,
        reject_with: None,
        rate_limit,
        log,
        order: section.order,
    })
}

fn decode_address_set(
    section: &UciSection,
    ownership: ObjectOwnership,
) -> Option<FirewallAddressSet> {
    let set_match = scalar(section, "match")?;
    let entries = match set_match {
        "src_net" => section
            .values("entry")
            .iter()
            .map(|value| parse_network(value).map(FirewallSetEntry::Network))
            .collect::<Option<Vec<_>>>()?,
        "src_mac" => section
            .values("entry")
            .iter()
            .map(|value| normalize_mac(value).map(FirewallSetEntry::Mac))
            .collect::<Option<Vec<_>>>()?,
        "src_port" => section
            .values("entry")
            .iter()
            .map(|value| parse_port(value).map(FirewallSetEntry::Port))
            .collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    Some(FirewallAddressSet {
        id: scalar(section, "name")?.to_owned(),
        ownership,
        enabled: enabled(section)?,
        family: parse_family(scalar(section, "family").unwrap_or("any"))?,
        entries,
    })
}

fn decode_nat_rule(section: &UciSection, ownership: ObjectOwnership) -> Option<FirewallNatRule> {
    let mut matches = decode_common_matches(section)?;
    if matches.source_networks.len() > 1
        || matches.source_ports.len() > 1
        || matches.source_zones.len() > 1
        || matches.destination_zones.len() > 1
        || matches.source_sets.len() + matches.destination_sets.len() > 1
    {
        return None;
    }
    let target = scalar(section, "target")?;
    let (kind, translation_address, translation_port) = match section.section_type.as_str() {
        "redirect" if target.eq_ignore_ascii_case("DNAT") => {
            matches.destination_networks.clear();
            matches.destination_ports.clear();
            matches.destination_networks = optional_network(section, "src_dip")?;
            matches.destination_ports = optional_port(section, "src_dport")?;
            let address = optional_ip(section, "dest_ip").ok()?;
            let port = optional_single_port(section, "dest_port").ok()?;
            let kind = if address.is_some() {
                FirewallNatKind::DestinationNat
            } else {
                FirewallNatKind::Redirect
            };
            (kind, address, port)
        }
        "nat" if target.eq_ignore_ascii_case("SNAT") => (
            FirewallNatKind::SourceNat,
            optional_ip(section, "snat_ip").ok()?,
            optional_single_port(section, "snat_port").ok()?,
        ),
        "nat" if target.eq_ignore_ascii_case("MASQUERADE") => (
            FirewallNatKind::Masquerade,
            optional_ip(section, "snat_ip").ok()?,
            optional_single_port(section, "snat_port").ok()?,
        ),
        _ => return None,
    };
    Some(FirewallNatRule {
        id: object_id(section, &section.section_type)?,
        ownership,
        enabled: enabled(section)?,
        kind,
        matches,
        translation_address,
        translation_port,
        order: section.order,
    })
}

fn decode_common_matches(section: &UciSection) -> Option<FirewallMatch> {
    let mut matches = FirewallMatch {
        family: parse_family(scalar(section, "family").unwrap_or("any"))?,
        source_networks: networks(section, "src_ip")?,
        destination_networks: networks(section, "dest_ip")?,
        source_macs: section
            .values("src_mac")
            .iter()
            .map(|value| normalize_mac(value))
            .collect::<Option<Vec<_>>>()?,
        protocols: protocols(section)?,
        source_ports: ports(section, "src_port")?,
        destination_ports: ports(section, "dest_port")?,
        icmp_types: section
            .values("icmp_type")
            .iter()
            .map(|value| value.parse::<u8>().ok())
            .collect::<Option<Vec<_>>>()?,
        ..FirewallMatch::default()
    };
    if let Some(source) = scalar(section, "src") {
        matches.source_zones.push(source.to_owned());
    }
    if let Some(destination) = scalar(section, "dest") {
        matches.destination_zones.push(destination.to_owned());
    }
    if let Some(set) = scalar(section, "ipset") {
        let mut fields = set.split_ascii_whitespace();
        let name = fields.next()?.to_owned();
        match (fields.next()?, fields.next()) {
            ("src", None) => matches.source_sets.push(name),
            ("dest", None) => matches.destination_sets.push(name),
            _ => return None,
        }
    }
    Some(matches)
}

fn rule_direction(section: &UciSection, matches: &mut FirewallMatch) -> Option<FirewallDirection> {
    match (scalar(section, "device"), scalar(section, "direction")) {
        (Some(device), Some("in")) => {
            matches.input_interfaces.push(device.to_owned());
            Some(FirewallDirection::Input)
        }
        (Some(device), Some("out")) => {
            matches.output_interfaces.push(device.to_owned());
            Some(FirewallDirection::Output)
        }
        (None, None) if !matches.destination_zones.is_empty() => {
            if matches.source_zones.is_empty() {
                Some(FirewallDirection::Output)
            } else {
                Some(FirewallDirection::Forward)
            }
        }
        (None, None) => Some(FirewallDirection::Input),
        _ => None,
    }
}

fn section_ownership(section: &UciSection) -> Option<ObjectOwnership> {
    if !section.selector.starts_with("mbed_") {
        return Some(ObjectOwnership::PlatformNative);
    }
    let marker = match section.section_type.as_str() {
        "zone" => "mbed_z_",
        "forwarding" => "mbed_f_",
        "rule" => "mbed_r_",
        "ipset" => "mbed_s_",
        "redirect" | "nat" => "mbed_n_",
        _ => return None,
    };
    let digest = section.selector.strip_prefix(marker)?;
    if digest.len() == 16 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(ObjectOwnership::AgentOwned)
    } else {
        None
    }
}

fn object_id(section: &UciSection, fallback_type: &str) -> Option<String> {
    scalar(section, "name")
        .map(str::to_owned)
        .or_else(|| fallback_id(section, fallback_type))
}

fn fallback_id(section: &UciSection, fallback_type: &str) -> Option<String> {
    let index = section
        .selector
        .strip_prefix('@')?
        .strip_prefix(fallback_type)?
        .strip_prefix('[')?
        .strip_suffix(']')?;
    Some(format!("platform-{fallback_type}-{index}"))
}

fn scalar<'a>(section: &'a UciSection, option: &str) -> Option<&'a str> {
    let values = section.options.get(option)?;
    (values.len() == 1).then(|| values[0].as_str())
}

fn enabled(section: &UciSection) -> Option<bool> {
    Some(boolean(section, "enabled").ok()?.unwrap_or(true))
}

fn boolean(section: &UciSection, option: &str) -> Result<Option<bool>, ()> {
    match scalar(section, option) {
        Some("1" | "true" | "yes" | "on") => Ok(Some(true)),
        Some("0" | "false" | "no" | "off") => Ok(Some(false)),
        Some(_) => Err(()),
        None if section.options.contains_key(option) => Err(()),
        None => Ok(None),
    }
}

fn verdict(section: &UciSection, option: &str) -> Option<FirewallVerdict> {
    match scalar(section, option)?.to_ascii_uppercase().as_str() {
        "ACCEPT" => Some(FirewallVerdict::Accept),
        "DROP" => Some(FirewallVerdict::Drop),
        "REJECT" => Some(FirewallVerdict::Reject),
        _ => None,
    }
}

fn parse_family(value: &str) -> Option<FirewallFamily> {
    match value {
        "any" | "*" => Some(FirewallFamily::Any),
        "ipv4" | "4" => Some(FirewallFamily::Ipv4),
        "ipv6" | "6" => Some(FirewallFamily::Ipv6),
        _ => None,
    }
}

fn protocols(section: &UciSection) -> Option<Vec<FirewallProtocol>> {
    let Some(values) = section.options.get("proto") else {
        return Some(Vec::new());
    };
    values
        .iter()
        .flat_map(|value| value.split_ascii_whitespace())
        .map(|value| match value {
            "tcp" => Some(FirewallProtocol::Tcp),
            "udp" => Some(FirewallProtocol::Udp),
            "icmp" => Some(FirewallProtocol::Icmp),
            "icmpv6" | "ipv6-icmp" => Some(FirewallProtocol::Icmpv6),
            "esp" => Some(FirewallProtocol::Esp),
            "ah" => Some(FirewallProtocol::Ah),
            "gre" => Some(FirewallProtocol::Gre),
            _ => None,
        })
        .collect()
}

fn networks(section: &UciSection, option: &str) -> Option<Vec<IpNetwork>> {
    section
        .values(option)
        .iter()
        .map(|value| parse_network(value))
        .collect()
}

fn optional_network(section: &UciSection, option: &str) -> Option<Vec<IpNetwork>> {
    let values = networks(section, option)?;
    (values.len() <= 1).then_some(values)
}

fn parse_network(value: &str) -> Option<IpNetwork> {
    let (address, prefix) = if let Some((address, prefix)) = value.split_once('/') {
        (address.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?)
    } else {
        let address = value.parse::<IpAddr>().ok()?;
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        (address, prefix)
    };
    Some(IpNetwork {
        address,
        prefix_len: prefix,
    })
}

fn ports(section: &UciSection, option: &str) -> Option<Vec<PortRange>> {
    section
        .values(option)
        .iter()
        .map(|value| parse_port(value))
        .collect()
}

fn optional_port(section: &UciSection, option: &str) -> Option<Vec<PortRange>> {
    let values = ports(section, option)?;
    (values.len() <= 1).then_some(values)
}

fn optional_single_port(section: &UciSection, option: &str) -> Result<Option<PortRange>, ()> {
    match section.options.get(option) {
        Some(values) if values.len() == 1 => parse_port(&values[0]).map(Some).ok_or(()),
        Some(_) => Err(()),
        None => Ok(None),
    }
}

fn parse_port(value: &str) -> Option<PortRange> {
    let (start, end) = if let Some((start, end)) = value.split_once('-') {
        (start.parse().ok()?, end.parse().ok()?)
    } else {
        let port = value.parse().ok()?;
        (port, port)
    };
    Some(PortRange { start, end })
}

fn optional_ip(section: &UciSection, option: &str) -> Result<Option<IpAddr>, ()> {
    match section.options.get(option) {
        Some(values) if values.len() == 1 => values[0].parse().map(Some).map_err(|_| ()),
        Some(_) => Err(()),
        None => Ok(None),
    }
}

fn normalize_mac(value: &str) -> Option<String> {
    let normalized = value.to_ascii_lowercase();
    let mut parts = normalized.split(':');
    if (0..6).all(|_| {
        parts.next().is_some_and(|part| {
            part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && parts.next().is_none()
    {
        Some(normalized)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_typed_openwrt_inventory_and_exact_bindings() {
        let snapshot = inspect_openwrt_firewall_inventory(
            "firewall.@defaults[0]=defaults\n\
             firewall.@defaults[0].input='REJECT'\n\
             firewall.@defaults[0].output='ACCEPT'\n\
             firewall.@defaults[0].forward='REJECT'\n\
             firewall.@zone[0]=zone\n\
             firewall.@zone[0].name='lan'\n\
             firewall.@zone[0].network='lan' 'guest'\n\
             firewall.@zone[0].input='ACCEPT'\n\
             firewall.@forwarding[0]=forwarding\n\
             firewall.@forwarding[0].src='lan'\n\
             firewall.@forwarding[0].dest='wan'\n\
             firewall.mbed_r_0123456789abcdef=rule\n\
             firewall.mbed_r_0123456789abcdef.name='block-camera'\n\
             firewall.mbed_r_0123456789abcdef.enabled='1'\n\
             firewall.mbed_r_0123456789abcdef.family='ipv4'\n\
             firewall.mbed_r_0123456789abcdef.src='lan'\n\
             firewall.mbed_r_0123456789abcdef.dest='wan'\n\
             firewall.mbed_r_0123456789abcdef.proto='tcp udp'\n\
             firewall.mbed_r_0123456789abcdef.src_mac='AA:BB:CC:DD:EE:FF'\n\
             firewall.mbed_r_0123456789abcdef.dest_port='443-445'\n\
             firewall.mbed_r_0123456789abcdef.target='DROP'\n\
             firewall.vendor=include\n\
             firewall.vendor.path='/etc/firewall.user'\n",
        )
        .expect("inventory");

        assert_eq!(snapshot.inventory().objects.len(), 3);
        assert_eq!(snapshot.bindings().len(), 3);
        assert_eq!(snapshot.read_only_sections(), ["vendor"]);
        assert_eq!(snapshot.occupied_sections().len(), 5);
        let rule = snapshot
            .inventory()
            .objects
            .iter()
            .find_map(|object| match object {
                FirewallObject::FilterRule(rule) => Some(rule),
                _ => None,
            })
            .expect("managed rule");
        assert_eq!(rule.ownership, ObjectOwnership::AgentOwned);
        assert_eq!(rule.direction, FirewallDirection::Forward);
        assert_eq!(rule.matches.protocols.len(), 2);
        assert_eq!(rule.matches.source_macs, ["aa:bb:cc:dd:ee:ff"]);
        assert_eq!(rule.matches.destination_ports[0].end, 445);
    }

    #[test]
    fn unsupported_platform_sections_are_read_only_but_managed_drift_fails_closed() {
        let platform = inspect_openwrt_firewall_inventory(
            "firewall.vendor_rule=rule\n\
             firewall.vendor_rule.name='unsupported'\n\
             firewall.vendor_rule.proto='all'\n\
             firewall.vendor_rule.target='ACCEPT'\n",
        )
        .expect("read-only platform rule");
        assert!(platform.inventory().objects.is_empty());
        assert_eq!(platform.read_only_sections(), ["vendor_rule"]);

        assert!(matches!(
            inspect_openwrt_firewall_inventory(
                "firewall.mbed_r_0123456789abcdef=rule\n\
                 firewall.mbed_r_0123456789abcdef.name='drifted'\n\
                 firewall.mbed_r_0123456789abcdef.proto='all'\n\
                 firewall.mbed_r_0123456789abcdef.target='ACCEPT'\n"
            ),
            Err(FirewallRenderError::UnsupportedManagedSection(_))
        ));
    }

    #[test]
    fn reconstructs_ipset_and_nat_without_guessing_unsupported_shapes() {
        let snapshot = inspect_openwrt_firewall_inventory(
            "firewall.mbed_s_0123456789abcdef=ipset\n\
             firewall.mbed_s_0123456789abcdef.name='blocked'\n\
             firewall.mbed_s_0123456789abcdef.family='ipv4'\n\
             firewall.mbed_s_0123456789abcdef.match='src_net'\n\
             firewall.mbed_s_0123456789abcdef.entry='198.51.100.0/24' '203.0.113.0/24'\n\
             firewall.mbed_n_0123456789abcdef=redirect\n\
             firewall.mbed_n_0123456789abcdef.name='https'\n\
             firewall.mbed_n_0123456789abcdef.family='ipv4'\n\
             firewall.mbed_n_0123456789abcdef.src='wan'\n\
             firewall.mbed_n_0123456789abcdef.proto='tcp'\n\
             firewall.mbed_n_0123456789abcdef.src_dport='8443'\n\
             firewall.mbed_n_0123456789abcdef.dest_ip='192.168.1.10'\n\
             firewall.mbed_n_0123456789abcdef.dest_port='443'\n\
             firewall.mbed_n_0123456789abcdef.target='DNAT'\n",
        )
        .expect("inventory");
        assert_eq!(snapshot.inventory().objects.len(), 2);
        assert!(matches!(
            &snapshot.inventory().objects[0],
            FirewallObject::AddressSet(set) if set.entries.len() == 2
        ));
        assert!(matches!(
            &snapshot.inventory().objects[1],
            FirewallObject::NatRule(rule)
                if rule.kind == FirewallNatKind::DestinationNat
                    && rule.translation_address.is_some()
        ));
    }
}
