//! Isolated nftables staging for generic Linux.
//!
//! The adapter owns exactly one `inet mbed_agent` table. It renders complete
//! projected state and never edits or reinterprets distribution-owned tables.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use agent_core::{FirewallInventory, FirewallMutationPlan};
use agent_protocol::{
    FirewallAddressSet, FirewallDirection, FirewallFamily, FirewallFilterRule, FirewallLogLevel,
    FirewallMatch, FirewallNatKind, FirewallNatRule, FirewallObject, FirewallProtocol,
    FirewallRejectKind, FirewallSetEntry, FirewallVerdict, IpNetwork, PortRange,
};
use thiserror::Error;

use crate::firewall_project::{FirewallProjectionError, project_agent_objects};
#[cfg(test)]
use agent_protocol::ObjectOwnership;

const TABLE_NAME: &str = "mbed_agent";
const OWNERSHIP_COMMENT: &str = "mbed-agent-owned:v1";
const MAX_RULESET_BYTES: usize = 256 * 1024;
const MAX_EXPANDED_RULES: usize = 1_024;
const MAX_INSPECTION_BYTES: usize = 64 * 1024;

/// Current ownership state of the fixed nftables table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftablesTableState {
    Absent,
    AgentOwned,
}

/// Fixed validation and activation operations for the staged ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftablesOperation {
    /// `nft --check --file <staged-ruleset>`.
    Check,
    /// `nft --file <staged-ruleset>`.
    Load,
}

/// Coexistence semantics of an isolated table on a generic Linux host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftablesCoexistence {
    /// Drops are final, but accepts can still be rejected by another later base chain. NAT rules
    /// run after conventional distribution priorities and apply only when no earlier mapping won.
    IsolatedAdditive,
}

/// Complete nftables staging artifact for the fixed Agent-owned table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftablesFirewallStage {
    pub ruleset: String,
    pub validation: NftablesOperation,
    pub activation: NftablesOperation,
    pub coexistence: NftablesCoexistence,
}

/// Classifies output from the fixed `nft list table inet mbed_agent` inspection.
///
/// Pass `None` only when the fixed list command returned the native not-found result. Any
/// existing table without the exact ownership comment is foreign and cannot be adopted.
///
/// # Errors
///
/// Returns an error for oversized, malformed, or foreign table output.
pub fn inspect_nftables_table_state(
    listing: Option<&str>,
) -> Result<NftablesTableState, NftablesRenderError> {
    let Some(listing) = listing else {
        return Ok(NftablesTableState::Absent);
    };
    if listing.len() > MAX_INSPECTION_BYTES
        || !listing.contains("table inet mbed_agent")
        || listing
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t')))
    {
        return Err(NftablesRenderError::MalformedInspection);
    }
    let ownership = format!("comment \"{OWNERSHIP_COMMENT}\"");
    if listing.lines().any(|line| line.trim() == ownership) {
        Ok(NftablesTableState::AgentOwned)
    } else {
        Err(NftablesRenderError::ForeignTable)
    }
}

/// Renders the complete projected Agent-owned firewall into an atomic nftables ruleset.
///
/// The plan is applied in memory to the fresh inventory. Only Agent-owned objects participate;
/// a mutation of any other ownership class fails. Loading the artifact deletes only the fixed
/// owned table (when present) and recreates it in the same nftables transaction.
///
/// # Errors
///
/// Returns an error for ownership violations, stale plan/object disagreement, unsupported
/// semantics, name collisions, expansion overflow, or an oversized ruleset.
pub fn render_nftables_firewall_stage(
    inventory: &FirewallInventory,
    plan: &FirewallMutationPlan,
    table_state: NftablesTableState,
) -> Result<NftablesFirewallStage, NftablesRenderError> {
    let projected = project_agent_objects(inventory, plan).map_err(|error| match error {
        FirewallProjectionError::InvalidObject => NftablesRenderError::InvalidObject,
        FirewallProjectionError::Ownership => NftablesRenderError::Ownership,
        FirewallProjectionError::PlanMismatch => NftablesRenderError::PlanMismatch,
    })?;
    let context = RenderContext::new(&projected)?;
    let mut ruleset = String::new();
    if table_state == NftablesTableState::AgentOwned {
        ruleset.push_str("delete table inet mbed_agent\n");
    }
    writeln!(ruleset, "table inet {TABLE_NAME} {{").map_err(|_| NftablesRenderError::Output)?;
    writeln!(ruleset, "    comment \"{OWNERSHIP_COMMENT}\"")
        .map_err(|_| NftablesRenderError::Output)?;
    context.render_sets(&mut ruleset)?;
    context.render_filter_chains(&mut ruleset)?;
    context.render_nat_chains(&mut ruleset)?;
    ruleset.push_str("}\n");
    if ruleset.len() > MAX_RULESET_BYTES {
        return Err(NftablesRenderError::Capacity);
    }
    Ok(NftablesFirewallStage {
        ruleset,
        validation: NftablesOperation::Check,
        activation: NftablesOperation::Load,
        coexistence: NftablesCoexistence::IsolatedAdditive,
    })
}

struct NftSet {
    name: String,
    value_type: NftSetType,
    enabled: bool,
}

#[derive(Clone, Copy)]
enum NftSetType {
    Ipv4Network,
    Ipv6Network,
    Mac,
    Port,
}

struct RenderContext<'a> {
    zones: HashMap<&'a str, &'a agent_protocol::FirewallZone>,
    forwardings: Vec<&'a agent_protocol::FirewallForwarding>,
    filter_rules: Vec<&'a FirewallFilterRule>,
    address_sets: Vec<&'a FirewallAddressSet>,
    nat_rules: Vec<&'a FirewallNatRule>,
    sets: HashMap<&'a str, NftSet>,
}

impl<'a> RenderContext<'a> {
    fn new(objects: &'a [FirewallObject]) -> Result<Self, NftablesRenderError> {
        let mut zones = HashMap::new();
        let mut forwardings = Vec::new();
        let mut filter_rules = Vec::new();
        let mut address_sets = Vec::new();
        let mut nat_rules = Vec::new();
        let mut sets = HashMap::new();
        let mut native_names = HashSet::new();
        for object in objects {
            match object {
                FirewallObject::Zone(value) => {
                    if value.mtu_fix {
                        return Err(NftablesRenderError::UnsupportedField(
                            "generic nftables zone MTU fixing",
                        ));
                    }
                    zones.insert(value.id.as_str(), value);
                }
                FirewallObject::Forwarding(value) => forwardings.push(value),
                FirewallObject::FilterRule(value) => filter_rules.push(value),
                FirewallObject::AddressSet(value) => {
                    let name = native_name("s", &value.id);
                    if !native_names.insert(name.clone()) {
                        return Err(NftablesRenderError::NameCollision);
                    }
                    sets.insert(
                        value.id.as_str(),
                        NftSet {
                            name,
                            value_type: set_type(value)?,
                            enabled: value.enabled,
                        },
                    );
                    address_sets.push(value);
                }
                FirewallObject::NatRule(value) => nat_rules.push(value),
            }
        }
        filter_rules.sort_by_key(|rule| (rule.order, rule.id.as_str()));
        nat_rules.sort_by_key(|rule| (rule.order, rule.id.as_str()));
        for forwarding in &forwardings {
            if !zones.contains_key(forwarding.source_zone.as_str())
                || !zones.contains_key(forwarding.destination_zone.as_str())
            {
                return Err(NftablesRenderError::MissingReference);
            }
        }
        Ok(Self {
            zones,
            forwardings,
            filter_rules,
            address_sets,
            nat_rules,
            sets,
        })
    }

    fn render_sets(&self, output: &mut String) -> Result<(), NftablesRenderError> {
        for set in &self.address_sets {
            if !set.enabled {
                continue;
            }
            let native = self
                .sets
                .get(set.id.as_str())
                .ok_or(NftablesRenderError::MissingReference)?;
            let (value_type, interval) = match native.value_type {
                NftSetType::Ipv4Network => ("ipv4_addr", true),
                NftSetType::Ipv6Network => ("ipv6_addr", true),
                NftSetType::Mac => ("ether_addr", false),
                NftSetType::Port => ("inet_service", true),
            };
            writeln!(output, "    set {} {{", native.name)
                .map_err(|_| NftablesRenderError::Output)?;
            writeln!(output, "        type {value_type}")
                .map_err(|_| NftablesRenderError::Output)?;
            if interval {
                output.push_str("        flags interval\n");
            }
            output.push_str("        elements = { ");
            for (index, entry) in set.entries.iter().enumerate() {
                if index > 0 {
                    output.push_str(", ");
                }
                output.push_str(&set_entry(entry));
            }
            output.push_str(" }\n    }\n");
        }
        Ok(())
    }

    fn render_filter_chains(&self, output: &mut String) -> Result<(), NftablesRenderError> {
        for direction in [
            FirewallDirection::Input,
            FirewallDirection::Output,
            FirewallDirection::Forward,
        ] {
            let name = direction_name(direction);
            writeln!(output, "    chain {name} {{").map_err(|_| NftablesRenderError::Output)?;
            writeln!(
                output,
                "        type filter hook {name} priority -5; policy accept;"
            )
            .map_err(|_| NftablesRenderError::Output)?;
            for rule in self
                .filter_rules
                .iter()
                .filter(|rule| rule.enabled && rule.direction == direction)
            {
                let rendered = self.render_filter_rule(rule)?;
                writeln!(output, "        {rendered}").map_err(|_| NftablesRenderError::Output)?;
            }
            if direction == FirewallDirection::Forward {
                self.render_forwardings(output)?;
            }
            self.render_zone_policies(output, direction)?;
            output.push_str("    }\n");
        }
        Ok(())
    }

    fn render_forwardings(&self, output: &mut String) -> Result<(), NftablesRenderError> {
        let mut expanded = 0_usize;
        for forwarding in self
            .forwardings
            .iter()
            .filter(|forwarding| forwarding.enabled)
        {
            let source = self.zone(&forwarding.source_zone)?;
            let destination = self.zone(&forwarding.destination_zone)?;
            expanded = expanded.saturating_add(
                source
                    .networks
                    .len()
                    .saturating_mul(destination.networks.len()),
            );
            if expanded > MAX_EXPANDED_RULES {
                return Err(NftablesRenderError::Capacity);
            }
            for input in &source.networks {
                for output_interface in &destination.networks {
                    writeln!(
                        output,
                        "        iifname {} oifname {} accept comment {}",
                        nft_string(input)?,
                        nft_string(output_interface)?,
                        nft_string(&forwarding.id)?
                    )
                    .map_err(|_| NftablesRenderError::Output)?;
                }
            }
        }
        Ok(())
    }

    fn render_zone_policies(
        &self,
        output: &mut String,
        direction: FirewallDirection,
    ) -> Result<(), NftablesRenderError> {
        let mut zones: Vec<_> = self.zones.values().copied().collect();
        zones.sort_by_key(|zone| zone.id.as_str());
        for zone in zones.into_iter().filter(|zone| zone.enabled) {
            let (interface_key, verdict) = match direction {
                FirewallDirection::Input => ("iifname", zone.input),
                FirewallDirection::Output => ("oifname", zone.output),
                FirewallDirection::Forward => ("iifname", zone.forward),
            };
            for interface in &zone.networks {
                writeln!(
                    output,
                    "        {interface_key} {} {} comment {}",
                    nft_string(interface)?,
                    verdict_name(verdict),
                    nft_string(&format!("zone:{}", zone.id))?
                )
                .map_err(|_| NftablesRenderError::Output)?;
            }
        }
        Ok(())
    }

    fn render_filter_rule(&self, rule: &FirewallFilterRule) -> Result<String, NftablesRenderError> {
        let mut parts = self.render_match(&rule.matches, rule.direction)?;
        if let Some(limit) = rule.rate_limit {
            parts.push(format!(
                "limit rate {}/second burst {} packets",
                limit.packets_per_second, limit.burst
            ));
        }
        if let Some(log) = &rule.log {
            parts.push(format!(
                "log prefix {} level {}",
                nft_string(&log.prefix)?,
                log_level(log.level)
            ));
        }
        parts.push(render_verdict(rule.verdict, rule.reject_with)?);
        parts.push(format!("comment {}", nft_string(&rule.id)?));
        Ok(parts.join(" "))
    }

    fn render_nat_chains(&self, output: &mut String) -> Result<(), NftablesRenderError> {
        output.push_str(
            "    chain prerouting {\n        type nat hook prerouting priority -90; policy accept;\n",
        );
        for rule in self.nat_rules.iter().filter(|rule| {
            rule.enabled
                && matches!(
                    rule.kind,
                    FirewallNatKind::DestinationNat | FirewallNatKind::Redirect
                )
        }) {
            let rendered = self.render_nat_rule(rule, FirewallDirection::Input)?;
            writeln!(output, "        {rendered}").map_err(|_| NftablesRenderError::Output)?;
        }
        let mut zones: Vec<_> = self.zones.values().copied().collect();
        zones.sort_by_key(|zone| zone.id.as_str());
        for zone in zones
            .into_iter()
            .filter(|zone| zone.enabled && zone.masquerade)
        {
            for interface in &zone.networks {
                writeln!(
                    output,
                    "        oifname {} masquerade comment {}",
                    nft_string(interface)?,
                    nft_string(&format!("zone-masq:{}", zone.id))?
                )
                .map_err(|_| NftablesRenderError::Output)?;
            }
        }
        output.push_str("    }\n");
        output.push_str(
            "    chain postrouting {\n        type nat hook postrouting priority 110; policy accept;\n",
        );
        for rule in self.nat_rules.iter().filter(|rule| {
            rule.enabled
                && matches!(
                    rule.kind,
                    FirewallNatKind::SourceNat | FirewallNatKind::Masquerade
                )
        }) {
            let rendered = self.render_nat_rule(rule, FirewallDirection::Forward)?;
            writeln!(output, "        {rendered}").map_err(|_| NftablesRenderError::Output)?;
        }
        output.push_str("    }\n");
        Ok(())
    }

    fn render_nat_rule(
        &self,
        rule: &FirewallNatRule,
        direction: FirewallDirection,
    ) -> Result<String, NftablesRenderError> {
        if matches!(
            rule.kind,
            FirewallNatKind::DestinationNat | FirewallNatKind::Redirect
        ) && !rule.matches.destination_zones.is_empty()
        {
            return Err(NftablesRenderError::UnsupportedField(
                "DNAT destination-zone matching is not stable in prerouting",
            ));
        }
        let mut parts = self.render_match(&rule.matches, direction)?;
        let action = match rule.kind {
            FirewallNatKind::Masquerade => "masquerade".into(),
            FirewallNatKind::Redirect => {
                let port = rule
                    .translation_port
                    .ok_or(NftablesRenderError::InvalidObject)?;
                format!("redirect to :{}", port_value(port))
            }
            FirewallNatKind::DestinationNat | FirewallNatKind::SourceNat => {
                let address = rule
                    .translation_address
                    .ok_or(NftablesRenderError::InvalidObject)?;
                let verb = if rule.kind == FirewallNatKind::DestinationNat {
                    "dnat"
                } else {
                    "snat"
                };
                render_nat_translation(verb, address, rule.translation_port)
            }
        };
        parts.push(action);
        parts.push(format!("comment {}", nft_string(&rule.id)?));
        Ok(parts.join(" "))
    }

    fn render_match(
        &self,
        value: &FirewallMatch,
        direction: FirewallDirection,
    ) -> Result<Vec<String>, NftablesRenderError> {
        validate_match_shape(value)?;
        let mut parts = Vec::new();
        match value.family {
            FirewallFamily::Any => {}
            FirewallFamily::Ipv4 => parts.push("meta nfproto ipv4".into()),
            FirewallFamily::Ipv6 => parts.push("meta nfproto ipv6".into()),
        }
        let source_interfaces = self.zone_interfaces(&value.source_zones)?;
        let destination_interfaces = self.zone_interfaces(&value.destination_zones)?;
        let (zone_source_key, zone_destination_key) = match direction {
            FirewallDirection::Input => ("iifname", None),
            FirewallDirection::Output => ("oifname", None),
            FirewallDirection::Forward => ("iifname", Some("oifname")),
        };
        if !source_interfaces.is_empty() {
            parts.push(render_string_set(zone_source_key, &source_interfaces)?);
        }
        if !destination_interfaces.is_empty() {
            let key = zone_destination_key.ok_or(NftablesRenderError::UnsupportedField(
                "destination zone for non-forward filter direction",
            ))?;
            parts.push(render_string_set(key, &destination_interfaces)?);
        }
        if !value.input_interfaces.is_empty() {
            parts.push(render_string_set("iifname", &value.input_interfaces)?);
        }
        if !value.output_interfaces.is_empty() {
            parts.push(render_string_set("oifname", &value.output_interfaces)?);
        }
        render_networks(&mut parts, "saddr", &value.source_networks)?;
        render_networks(&mut parts, "daddr", &value.destination_networks)?;
        if !value.source_macs.is_empty() {
            parts.push(render_atom_set("ether saddr", &value.source_macs));
        }
        if !value.protocols.is_empty() {
            parts.push(render_atom_set(
                "meta l4proto",
                &value
                    .protocols
                    .iter()
                    .copied()
                    .map(protocol_name)
                    .collect::<Vec<_>>(),
            ));
        }
        if !value.source_ports.is_empty() {
            parts.push(render_port_set("th sport", &value.source_ports));
        }
        if !value.destination_ports.is_empty() {
            parts.push(render_port_set("th dport", &value.destination_ports));
        }
        render_icmp_types(&mut parts, value)?;
        if !value.conntrack_states.is_empty() {
            parts.push(render_atom_set(
                "ct state",
                &value
                    .conntrack_states
                    .iter()
                    .map(|state| match state {
                        agent_protocol::FirewallConntrackState::New => "new",
                        agent_protocol::FirewallConntrackState::Established => "established",
                        agent_protocol::FirewallConntrackState::Related => "related",
                        agent_protocol::FirewallConntrackState::Invalid => "invalid",
                    })
                    .collect::<Vec<_>>(),
            ));
        }
        self.validate_set_composition(&value.source_sets, value.family)?;
        self.validate_set_composition(&value.destination_sets, value.family)?;
        for id in &value.source_sets {
            parts.push(self.render_set_match(id, true)?);
        }
        for id in &value.destination_sets {
            parts.push(self.render_set_match(id, false)?);
        }
        Ok(parts)
    }

    fn validate_set_composition(
        &self,
        ids: &[String],
        family: FirewallFamily,
    ) -> Result<(), NftablesRenderError> {
        let mut dimensions = HashSet::new();
        for id in ids {
            self.validate_set_family(id, family)?;
            let set = self
                .sets
                .get(id.as_str())
                .ok_or(NftablesRenderError::MissingReference)?;
            let dimension = match set.value_type {
                NftSetType::Ipv4Network | NftSetType::Ipv6Network => 0_u8,
                NftSetType::Mac => 1,
                NftSetType::Port => 2,
            };
            if !dimensions.insert(dimension) {
                return Err(NftablesRenderError::UnsupportedField(
                    "multiple same-dimension sets require rule expansion",
                ));
            }
        }
        Ok(())
    }

    fn render_set_match(&self, id: &str, source: bool) -> Result<String, NftablesRenderError> {
        let set = self
            .sets
            .get(id)
            .ok_or(NftablesRenderError::MissingReference)?;
        if !set.enabled {
            return Err(NftablesRenderError::MissingReference);
        }
        let expression = match (set.value_type, source) {
            (NftSetType::Ipv4Network, true) => "ip saddr",
            (NftSetType::Ipv4Network, false) => "ip daddr",
            (NftSetType::Ipv6Network, true) => "ip6 saddr",
            (NftSetType::Ipv6Network, false) => "ip6 daddr",
            (NftSetType::Mac, true) => "ether saddr",
            (NftSetType::Mac, false) => "ether daddr",
            (NftSetType::Port, true) => "th sport",
            (NftSetType::Port, false) => "th dport",
        };
        Ok(format!("{expression} @{}", set.name))
    }

    fn validate_set_family(
        &self,
        id: &str,
        family: FirewallFamily,
    ) -> Result<(), NftablesRenderError> {
        let set = self
            .sets
            .get(id)
            .ok_or(NftablesRenderError::MissingReference)?;
        let compatible = matches!(
            (family, set.value_type),
            (
                FirewallFamily::Any,
                NftSetType::Ipv4Network
                    | NftSetType::Ipv6Network
                    | NftSetType::Mac
                    | NftSetType::Port
            ) | (
                FirewallFamily::Ipv4,
                NftSetType::Ipv4Network | NftSetType::Mac | NftSetType::Port
            ) | (
                FirewallFamily::Ipv6,
                NftSetType::Ipv6Network | NftSetType::Mac | NftSetType::Port
            )
        );
        if compatible {
            Ok(())
        } else {
            Err(NftablesRenderError::UnsupportedField(
                "address-set family does not match rule family",
            ))
        }
    }

    fn zone_interfaces(&self, zones: &[String]) -> Result<Vec<String>, NftablesRenderError> {
        let mut interfaces = Vec::new();
        for id in zones {
            let zone = self.zone(id)?;
            interfaces.extend(zone.networks.iter().cloned());
        }
        interfaces.sort();
        interfaces.dedup();
        Ok(interfaces)
    }

    fn zone(&self, id: &str) -> Result<&'a agent_protocol::FirewallZone, NftablesRenderError> {
        let zone = self
            .zones
            .get(id)
            .copied()
            .ok_or(NftablesRenderError::MissingReference)?;
        if zone.enabled {
            Ok(zone)
        } else {
            Err(NftablesRenderError::MissingReference)
        }
    }
}

fn validate_match_shape(value: &FirewallMatch) -> Result<(), NftablesRenderError> {
    if (!value.source_ports.is_empty() || !value.destination_ports.is_empty())
        && value
            .protocols
            .iter()
            .any(|protocol| !matches!(protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp))
    {
        return Err(NftablesRenderError::UnsupportedField(
            "ports combined with a non-transport protocol",
        ));
    }
    let mut families = HashSet::new();
    for network in value
        .source_networks
        .iter()
        .chain(&value.destination_networks)
    {
        families.insert(network.address.is_ipv4());
    }
    if families.len() > 1 {
        return Err(NftablesRenderError::UnsupportedField(
            "mixed IPv4/IPv6 networks in one rule",
        ));
    }
    Ok(())
}

fn set_type(value: &FirewallAddressSet) -> Result<NftSetType, NftablesRenderError> {
    match value.entries.first() {
        Some(FirewallSetEntry::Network(_)) if value.family == FirewallFamily::Ipv4 => {
            Ok(NftSetType::Ipv4Network)
        }
        Some(FirewallSetEntry::Network(_)) if value.family == FirewallFamily::Ipv6 => {
            Ok(NftSetType::Ipv6Network)
        }
        Some(FirewallSetEntry::Mac(_)) => Ok(NftSetType::Mac),
        Some(FirewallSetEntry::Port(_)) => Ok(NftSetType::Port),
        _ => Err(NftablesRenderError::InvalidObject),
    }
}

fn set_entry(value: &FirewallSetEntry) -> String {
    match value {
        FirewallSetEntry::Network(value) => network_value(value),
        FirewallSetEntry::Mac(value) => value.clone(),
        FirewallSetEntry::Port(value) => port_value(*value),
    }
}

fn render_networks(
    output: &mut Vec<String>,
    direction: &str,
    values: &[IpNetwork],
) -> Result<(), NftablesRenderError> {
    if values.is_empty() {
        return Ok(());
    }
    let family = if values[0].address.is_ipv4() {
        "ip"
    } else {
        "ip6"
    };
    if values
        .iter()
        .any(|network| network.address.is_ipv4() != values[0].address.is_ipv4())
    {
        return Err(NftablesRenderError::UnsupportedField(
            "mixed IPv4/IPv6 network list",
        ));
    }
    output.push(render_atom_set(
        &format!("{family} {direction}"),
        &values.iter().map(network_value).collect::<Vec<_>>(),
    ));
    Ok(())
}

fn render_icmp_types(
    output: &mut Vec<String>,
    value: &FirewallMatch,
) -> Result<(), NftablesRenderError> {
    if value.icmp_types.is_empty() {
        return Ok(());
    }
    let has_v4 = value.protocols.contains(&FirewallProtocol::Icmp);
    let has_v6 = value.protocols.contains(&FirewallProtocol::Icmpv6);
    if has_v4 == has_v6 {
        return Err(NftablesRenderError::UnsupportedField(
            "ICMP types require exactly one ICMP family",
        ));
    }
    output.push(render_atom_set(
        if has_v4 { "icmp type" } else { "icmpv6 type" },
        &value
            .icmp_types
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    ));
    Ok(())
}

fn render_nat_translation(verb: &str, address: IpAddr, port: Option<PortRange>) -> String {
    let family = if address.is_ipv4() { "ip" } else { "ip6" };
    let endpoint = match (address, port) {
        (IpAddr::V4(address), Some(port)) => format!("{address}:{}", port_value(port)),
        (IpAddr::V6(address), Some(port)) => format!("[{address}]:{}", port_value(port)),
        (address, None) => address.to_string(),
    };
    format!("{verb} {family} to {endpoint}")
}

fn render_verdict(
    verdict: FirewallVerdict,
    reject: Option<FirewallRejectKind>,
) -> Result<String, NftablesRenderError> {
    match (verdict, reject) {
        (FirewallVerdict::Accept, None) => Ok("accept".into()),
        (FirewallVerdict::Drop, None) => Ok("drop".into()),
        (FirewallVerdict::Reject, Some(FirewallRejectKind::TcpReset)) => {
            Ok("reject with tcp reset".into())
        }
        (FirewallVerdict::Reject, Some(FirewallRejectKind::IcmpPortUnreachable)) => {
            Ok("reject with icmp type port-unreachable".into())
        }
        (FirewallVerdict::Reject, Some(FirewallRejectKind::IcmpHostUnreachable)) => {
            Ok("reject with icmp type host-unreachable".into())
        }
        (FirewallVerdict::Reject, Some(FirewallRejectKind::Icmp6PortUnreachable)) => {
            Ok("reject with icmpv6 type port-unreachable".into())
        }
        _ => Err(NftablesRenderError::InvalidObject),
    }
}

fn render_string_set(key: &str, values: &[String]) -> Result<String, NftablesRenderError> {
    let values = values
        .iter()
        .map(|value| nft_string(value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(render_atom_set(key, &values))
}

fn render_atom_set<T: AsRef<str>>(key: &str, values: &[T]) -> String {
    if values.len() == 1 {
        format!("{key} {}", values[0].as_ref())
    } else {
        format!(
            "{key} {{ {} }}",
            values
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn render_port_set(key: &str, values: &[PortRange]) -> String {
    render_atom_set(
        key,
        &values.iter().copied().map(port_value).collect::<Vec<_>>(),
    )
}

fn network_value(value: &IpNetwork) -> String {
    format!("{}/{}", value.address, value.prefix_len)
}

fn port_value(value: PortRange) -> String {
    if value.start == value.end {
        value.start.to_string()
    } else {
        format!("{}-{}", value.start, value.end)
    }
}

fn nft_string(value: &str) -> Result<String, NftablesRenderError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
    {
        return Err(NftablesRenderError::UnsafeValue);
    }
    Ok(format!("\"{value}\""))
}

fn native_name(prefix: &str, id: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{prefix}_{hash:016x}")
}

const fn direction_name(value: FirewallDirection) -> &'static str {
    match value {
        FirewallDirection::Input => "input",
        FirewallDirection::Output => "output",
        FirewallDirection::Forward => "forward",
    }
}

const fn verdict_name(value: FirewallVerdict) -> &'static str {
    match value {
        FirewallVerdict::Accept => "accept",
        FirewallVerdict::Drop => "drop",
        FirewallVerdict::Reject => "reject",
    }
}

const fn protocol_name(value: FirewallProtocol) -> &'static str {
    match value {
        FirewallProtocol::Tcp => "tcp",
        FirewallProtocol::Udp => "udp",
        FirewallProtocol::Icmp => "icmp",
        FirewallProtocol::Icmpv6 => "icmpv6",
        FirewallProtocol::Esp => "esp",
        FirewallProtocol::Ah => "ah",
        FirewallProtocol::Gre => "gre",
    }
}

const fn log_level(value: FirewallLogLevel) -> &'static str {
    match value {
        FirewallLogLevel::Emergency => "emerg",
        FirewallLogLevel::Alert => "alert",
        FirewallLogLevel::Critical => "crit",
        FirewallLogLevel::Error => "err",
        FirewallLogLevel::Warning => "warn",
        FirewallLogLevel::Notice => "notice",
        FirewallLogLevel::Info => "info",
        FirewallLogLevel::Debug => "debug",
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NftablesRenderError {
    #[error("nftables inspection output is malformed")]
    MalformedInspection,
    #[error("the fixed mbed_agent nftables table is not Agent-owned")]
    ForeignTable,
    #[error("nftables staging exceeds its capacity")]
    Capacity,
    #[error("nftables staging accepts only Agent-owned mutations")]
    Ownership,
    #[error("nftables mutation plan does not match fresh inventory")]
    PlanMismatch,
    #[error("nftables mutation contains an invalid typed object")]
    InvalidObject,
    #[error("nftables object references a missing Agent-owned zone or set")]
    MissingReference,
    #[error("nftables native name collision")]
    NameCollision,
    #[error("nftables cannot safely represent: {0}")]
    UnsupportedField(&'static str),
    #[error("unsafe string cannot be represented in nftables")]
    UnsafeValue,
    #[error("failed to render nftables staging artifact")]
    Output,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use agent_core::{
        FirewallMutation, FirewallRiskContext, firewall_object_digest, plan_firewall_mutations,
    };
    use agent_protocol::{
        FirewallConntrackState, FirewallForwarding, FirewallLog, FirewallRateLimit, FirewallZone,
    };

    use super::*;

    #[test]
    fn inspection_requires_the_exact_owned_table_marker() {
        assert_eq!(
            inspect_nftables_table_state(None),
            Ok(NftablesTableState::Absent)
        );
        assert_eq!(
            inspect_nftables_table_state(Some(
                "table inet mbed_agent {\n\tcomment \"mbed-agent-owned:v1\"\n}\n"
            )),
            Ok(NftablesTableState::AgentOwned)
        );
        assert_eq!(
            inspect_nftables_table_state(Some(
                "table inet mbed_agent {\n\tcomment \"other-owner\"\n}\n"
            )),
            Err(NftablesRenderError::ForeignTable)
        );
        assert_eq!(
            inspect_nftables_table_state(Some("table ip mbed_agent {\n}\n")),
            Err(NftablesRenderError::MalformedInspection)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One golden ruleset intentionally covers every object type.
    fn renders_complete_agent_owned_filter_set_forwarding_and_nat_state() {
        let inventory = base_inventory();
        let set = FirewallObject::AddressSet(FirewallAddressSet {
            id: "blocked-sources".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: FirewallFamily::Ipv4,
            entries: vec![
                FirewallSetEntry::Network(network4([198, 51, 100, 0], 24)),
                FirewallSetEntry::Network(network4([203, 0, 113, 0], 24)),
            ],
        });
        let rule = FirewallObject::FilterRule(FirewallFilterRule {
            id: "drop-admin-probes".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["wan".into()],
                source_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
                protocols: vec![FirewallProtocol::Tcp],
                destination_ports: vec![PortRange { start: 22, end: 23 }],
                conntrack_states: vec![FirewallConntrackState::New],
                source_sets: vec!["blocked-sources".into()],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: Some(FirewallRateLimit {
                packets_per_second: 10,
                burst: 20,
            }),
            log: Some(FirewallLog {
                prefix: "mbed-drop".into(),
                level: FirewallLogLevel::Warning,
            }),
            order: 10,
        });
        let dnat = FirewallObject::NatRule(FirewallNatRule {
            id: "publish-https".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            kind: FirewallNatKind::DestinationNat,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["wan".into()],
                protocols: vec![FirewallProtocol::Tcp],
                destination_ports: vec![PortRange {
                    start: 8443,
                    end: 8443,
                }],
                ..FirewallMatch::default()
            },
            translation_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            translation_port: Some(PortRange {
                start: 443,
                end: 443,
            }),
            order: 20,
        });
        let snat = FirewallObject::NatRule(FirewallNatRule {
            id: "service-snat".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            kind: FirewallNatKind::SourceNat,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["lan".into()],
                source_networks: vec![network4([192, 168, 1, 0], 24)],
                ..FirewallMatch::default()
            },
            translation_address: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))),
            translation_port: None,
            order: 30,
        });
        let plan = create_plan(&inventory, vec![set, rule, dnat, snat]);
        let stage = render_nftables_firewall_stage(&inventory, &plan, NftablesTableState::Absent)
            .expect("render nftables");

        assert!(!stage.ruleset.starts_with("delete table"));
        assert!(stage.ruleset.contains("table inet mbed_agent {"));
        assert!(stage.ruleset.contains("comment \"mbed-agent-owned:v1\""));
        assert!(stage.ruleset.contains("type ipv4_addr"));
        assert!(
            stage
                .ruleset
                .contains("elements = { 198.51.100.0/24, 203.0.113.0/24 }")
        );
        assert!(stage.ruleset.contains("iifname \"eth0\""));
        assert!(stage.ruleset.contains("meta nfproto ipv4"));
        assert!(stage.ruleset.contains("ether saddr aa:bb:cc:dd:ee:ff"));
        assert!(stage.ruleset.contains("th dport 22-23"));
        assert!(stage.ruleset.contains("ct state new"));
        assert!(
            stage
                .ruleset
                .contains("limit rate 10/second burst 20 packets")
        );
        assert!(
            stage
                .ruleset
                .contains("log prefix \"mbed-drop\" level warn")
        );
        assert!(stage.ruleset.contains("dnat ip to 192.168.1.10:443"));
        assert!(stage.ruleset.contains("snat ip to 203.0.113.8"));
        assert!(
            stage
                .ruleset
                .contains("oifname \"eth0\" masquerade comment \"zone-masq:wan\"")
        );
        assert!(
            stage
                .ruleset
                .contains("iifname \"br-lan\" oifname \"eth0\" accept")
        );
        assert_eq!(stage.validation, NftablesOperation::Check);
        assert_eq!(stage.activation, NftablesOperation::Load);
        assert_eq!(stage.coexistence, NftablesCoexistence::IsolatedAdditive);
    }

    #[test]
    fn existing_owned_table_is_replaced_in_one_ruleset() {
        let inventory = base_inventory();
        let plan = create_plan(
            &inventory,
            vec![FirewallObject::FilterRule(simple_drop_rule("deny-ssh", 10))],
        );
        let stage =
            render_nftables_firewall_stage(&inventory, &plan, NftablesTableState::AgentOwned)
                .expect("replace table");
        assert!(
            stage
                .ruleset
                .starts_with("delete table inet mbed_agent\ntable inet mbed_agent")
        );
    }

    #[test]
    fn renders_ipv6_mac_port_sets_reject_and_local_redirect() {
        let inventory = base_inventory();
        let objects = vec![
            FirewallObject::AddressSet(FirewallAddressSet {
                id: "admin-macs".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                family: FirewallFamily::Any,
                entries: vec![FirewallSetEntry::Mac("02:00:00:00:00:01".into())],
            }),
            FirewallObject::AddressSet(FirewallAddressSet {
                id: "admin-ports".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                family: FirewallFamily::Any,
                entries: vec![
                    FirewallSetEntry::Port(PortRange { start: 22, end: 22 }),
                    FirewallSetEntry::Port(PortRange {
                        start: 8000,
                        end: 8010,
                    }),
                ],
            }),
            FirewallObject::AddressSet(FirewallAddressSet {
                id: "v6-blocked".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                family: FirewallFamily::Ipv6,
                entries: vec![FirewallSetEntry::Network(IpNetwork {
                    address: "2001:db8::".parse().expect("IPv6"),
                    prefix_len: 32,
                })],
            }),
            FirewallObject::FilterRule(FirewallFilterRule {
                id: "reject-v6-admin".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                direction: FirewallDirection::Input,
                matches: FirewallMatch {
                    family: FirewallFamily::Ipv6,
                    source_zones: vec!["wan".into()],
                    protocols: vec![FirewallProtocol::Tcp],
                    source_sets: vec!["admin-macs".into(), "v6-blocked".into()],
                    destination_sets: vec!["admin-ports".into()],
                    ..FirewallMatch::default()
                },
                verdict: FirewallVerdict::Reject,
                reject_with: Some(FirewallRejectKind::Icmp6PortUnreachable),
                rate_limit: None,
                log: None,
                order: 5,
            }),
            FirewallObject::NatRule(FirewallNatRule {
                id: "local-dns".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                kind: FirewallNatKind::Redirect,
                matches: FirewallMatch {
                    family: FirewallFamily::Ipv4,
                    source_zones: vec!["lan".into()],
                    protocols: vec![FirewallProtocol::Udp],
                    destination_ports: vec![PortRange { start: 53, end: 53 }],
                    ..FirewallMatch::default()
                },
                translation_address: None,
                translation_port: Some(PortRange {
                    start: 5353,
                    end: 5353,
                }),
                order: 6,
            }),
        ];
        let plan = create_plan(&inventory, objects);
        let stage = render_nftables_firewall_stage(&inventory, &plan, NftablesTableState::Absent)
            .expect("render diverse nftables state");

        assert!(stage.ruleset.contains("type ether_addr"));
        assert!(stage.ruleset.contains("type inet_service"));
        assert!(stage.ruleset.contains("type ipv6_addr"));
        assert!(stage.ruleset.contains("elements = { 2001:db8::/32 }"));
        assert!(stage.ruleset.contains("ip6 saddr @s_"));
        assert!(stage.ruleset.contains("ether saddr @s_"));
        assert!(stage.ruleset.contains("th dport @s_"));
        assert!(
            stage
                .ruleset
                .contains("reject with icmpv6 type port-unreachable")
        );
        assert!(stage.ruleset.contains("udp"));
        assert!(stage.ruleset.contains("redirect to :5353"));
    }

    #[test]
    fn update_is_bound_to_the_exact_fresh_inventory_object() {
        let before = FirewallObject::FilterRule(simple_drop_rule("deny-ssh", 10));
        let mut inventory = base_inventory();
        inventory.objects.push(before.clone());
        let mut after = before.clone();
        let FirewallObject::FilterRule(rule) = &mut after else {
            panic!("filter fixture");
        };
        rule.order = 5;
        let plan = plan_firewall_mutations(
            &inventory,
            &[FirewallMutation::Move {
                expected_digest: firewall_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &FirewallRiskContext::default(),
        )
        .expect("plan move");

        let mut changed_inventory = inventory.clone();
        let FirewallObject::FilterRule(rule) = &mut changed_inventory.objects[3] else {
            panic!("filter fixture");
        };
        rule.enabled = false;
        assert_eq!(
            render_nftables_firewall_stage(
                &changed_inventory,
                &plan,
                NftablesTableState::AgentOwned
            ),
            Err(NftablesRenderError::PlanMismatch)
        );
    }

    #[test]
    fn platform_native_mutations_cannot_enter_the_owned_table() {
        let mut inventory = base_inventory();
        let FirewallObject::Zone(zone) = &mut inventory.objects[0] else {
            panic!("zone fixture");
        };
        zone.ownership = ObjectOwnership::PlatformNative;
        let before = inventory.objects[0].clone();
        let mut after = before.clone();
        let FirewallObject::Zone(zone) = &mut after else {
            panic!("zone fixture");
        };
        zone.input = FirewallVerdict::Drop;
        let plan = plan_firewall_mutations(
            &inventory,
            &[FirewallMutation::Update {
                expected_digest: firewall_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &FirewallRiskContext::default(),
        )
        .expect("platform plan");
        assert_eq!(
            render_nftables_firewall_stage(&inventory, &plan, NftablesTableState::Absent),
            Err(NftablesRenderError::Ownership)
        );
    }

    #[test]
    fn rejects_ambiguous_mixed_family_and_nontransport_port_semantics() {
        let inventory = base_inventory();
        let mixed = FirewallObject::FilterRule(FirewallFilterRule {
            id: "mixed-family".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch {
                family: FirewallFamily::Any,
                source_networks: vec![
                    network4([192, 0, 2, 0], 24),
                    IpNetwork {
                        address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        prefix_len: 128,
                    },
                ],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order: 1,
        });
        let mixed_plan = create_plan(&inventory, vec![mixed]);
        assert_eq!(
            render_nftables_firewall_stage(&inventory, &mixed_plan, NftablesTableState::Absent),
            Err(NftablesRenderError::UnsupportedField(
                "mixed IPv4/IPv6 networks in one rule"
            ))
        );

        let mut invalid_ports = simple_drop_rule("mixed-protocol", 2);
        invalid_ports.matches.protocols = vec![FirewallProtocol::Tcp, FirewallProtocol::Esp];
        invalid_ports.matches.destination_ports = vec![PortRange {
            start: 443,
            end: 443,
        }];
        let ports_plan = create_plan(&inventory, vec![FirewallObject::FilterRule(invalid_ports)]);
        assert_eq!(
            render_nftables_firewall_stage(&inventory, &ports_plan, NftablesTableState::Absent),
            Err(NftablesRenderError::UnsupportedField(
                "ports combined with a non-transport protocol"
            ))
        );
    }

    #[test]
    fn rejects_multiple_same_dimension_set_references_without_silent_intersection() {
        let inventory = base_inventory();
        let set_a = FirewallObject::AddressSet(FirewallAddressSet {
            id: "net-a".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: FirewallFamily::Ipv4,
            entries: vec![FirewallSetEntry::Network(network4([192, 0, 2, 0], 24))],
        });
        let set_b = FirewallObject::AddressSet(FirewallAddressSet {
            id: "net-b".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: FirewallFamily::Ipv4,
            entries: vec![FirewallSetEntry::Network(network4([198, 51, 100, 0], 24))],
        });
        let mut rule = simple_drop_rule("two-network-sets", 1);
        rule.matches.source_sets = vec!["net-a".into(), "net-b".into()];
        let plan = create_plan(
            &inventory,
            vec![set_a, set_b, FirewallObject::FilterRule(rule)],
        );
        assert_eq!(
            render_nftables_firewall_stage(&inventory, &plan, NftablesTableState::Absent),
            Err(NftablesRenderError::UnsupportedField(
                "multiple same-dimension sets require rule expansion"
            ))
        );
    }

    fn create_plan(
        inventory: &FirewallInventory,
        objects: Vec<FirewallObject>,
    ) -> FirewallMutationPlan {
        plan_firewall_mutations(
            inventory,
            &objects
                .into_iter()
                .map(FirewallMutation::Create)
                .collect::<Vec<_>>(),
            &FirewallRiskContext::default(),
        )
        .expect("create plan")
    }

    fn base_inventory() -> FirewallInventory {
        FirewallInventory {
            objects: vec![
                FirewallObject::Zone(FirewallZone {
                    id: "lan".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    networks: vec!["br-lan".into()],
                    input: FirewallVerdict::Accept,
                    output: FirewallVerdict::Accept,
                    forward: FirewallVerdict::Drop,
                    masquerade: false,
                    mtu_fix: false,
                }),
                FirewallObject::Zone(FirewallZone {
                    id: "wan".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    networks: vec!["eth0".into()],
                    input: FirewallVerdict::Drop,
                    output: FirewallVerdict::Accept,
                    forward: FirewallVerdict::Drop,
                    masquerade: true,
                    mtu_fix: false,
                }),
                FirewallObject::Forwarding(FirewallForwarding {
                    id: "lan-wan".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    source_zone: "lan".into(),
                    destination_zone: "wan".into(),
                }),
            ],
        }
    }

    fn simple_drop_rule(id: &str, order: u32) -> FirewallFilterRule {
        FirewallFilterRule {
            id: id.into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["wan".into()],
                protocols: vec![FirewallProtocol::Tcp],
                destination_ports: vec![PortRange { start: 22, end: 22 }],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order,
        }
    }

    fn network4(octets: [u8; 4], prefix_len: u8) -> IpNetwork {
        IpNetwork {
            address: IpAddr::V4(Ipv4Addr::from(octets)),
            prefix_len,
        }
    }
}
