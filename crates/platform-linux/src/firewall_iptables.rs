//! Isolated iptables/ip6tables staging for generic Linux.
//!
//! The adapter owns six fixed chains per address family and appends exactly
//! one ownership-marked jump from each corresponding built-in chain.

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

const MAX_SAVE_BYTES: usize = 256 * 1024;
const MAX_RESTORE_BYTES: usize = 256 * 1024;
const MAX_EXPANDED_RULES: usize = 1_024;

const CHAINS: &[ChainBinding] = &[
    ChainBinding {
        table: "filter",
        builtin: "INPUT",
        managed: "MBED_INPUT",
        marker: "mbed-agent-owned:v1:input",
    },
    ChainBinding {
        table: "filter",
        builtin: "OUTPUT",
        managed: "MBED_OUTPUT",
        marker: "mbed-agent-owned:v1:output",
    },
    ChainBinding {
        table: "filter",
        builtin: "FORWARD",
        managed: "MBED_FORWARD",
        marker: "mbed-agent-owned:v1:forward",
    },
    ChainBinding {
        table: "nat",
        builtin: "PREROUTING",
        managed: "MBED_PREROUTING",
        marker: "mbed-agent-owned:v1:prerouting",
    },
    ChainBinding {
        table: "nat",
        builtin: "POSTROUTING",
        managed: "MBED_POSTROUTING",
        marker: "mbed-agent-owned:v1:postrouting",
    },
    ChainBinding {
        table: "mangle",
        builtin: "FORWARD",
        managed: "MBED_MANGLE_FORWARD",
        marker: "mbed-agent-owned:v1:mangle-forward",
    },
];

struct ChainBinding {
    table: &'static str,
    builtin: &'static str,
    managed: &'static str,
    marker: &'static str,
}

/// Ownership state of all fixed chains in one iptables address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesFamilyState {
    Absent,
    AgentOwned,
}

/// Fixed validation and activation operations for the two restore artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesOperation {
    ValidateIpv4,
    ValidateIpv6,
    LoadIpv4,
    LoadIpv6,
}

/// Coexistence semantics of appended jumps on a generic Linux host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesCoexistence {
    /// Pre-existing rules run first. If they reach the appended Agent jump, an Agent ACCEPT or
    /// DROP is terminal for that packet in the current iptables hook.
    AppendedTerminal,
}

/// Complete IPv4 and IPv6 no-flush restore artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesFirewallStage {
    pub ipv4_restore: String,
    pub ipv6_restore: String,
    pub validations: Vec<IptablesOperation>,
    pub activations: Vec<IptablesOperation>,
    pub coexistence: IptablesCoexistence,
    /// Cross-table and cross-family loads can partially succeed despite prior validation.
    pub rollback_required: bool,
}

/// Inspects one bounded `iptables-save` or `ip6tables-save` snapshot.
///
/// All six managed chains and all six exact ownership-marked jumps must be either absent or
/// present exactly once. Partial state, duplicate jumps, or a foreign chain with the same name
/// fails closed.
///
/// # Errors
///
/// Returns an error for malformed/oversized output or a partial/foreign ownership state.
pub fn inspect_iptables_family_state(
    save: &str,
) -> Result<IptablesFamilyState, IptablesRenderError> {
    if save.len() > MAX_SAVE_BYTES
        || save
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t')))
    {
        return Err(IptablesRenderError::MalformedInspection);
    }
    let mut current_table = "";
    let mut declarations: HashMap<(&str, &str), usize> = HashMap::new();
    let mut jumps: HashMap<(&str, &str), usize> = HashMap::new();
    let mut marked: HashMap<(&str, &str), usize> = HashMap::new();
    for line in save.lines() {
        if let Some(table) = line.strip_prefix('*') {
            current_table = table;
            continue;
        }
        if line == "COMMIT" {
            current_table = "";
            continue;
        }
        for binding in CHAINS {
            let key = (binding.table, binding.managed);
            if current_table == binding.table
                && line
                    .strip_prefix(':')
                    .is_some_and(|value| value.starts_with(binding.managed))
                && line
                    .strip_prefix(':')
                    .and_then(|value| value.get(binding.managed.len()..))
                    .is_some_and(|suffix| suffix.starts_with(' '))
            {
                *declarations.entry(key).or_default() += 1;
            }
            if current_table == binding.table && jump_target(line) == Some(binding.managed) {
                *jumps.entry(key).or_default() += 1;
                if hook_marker_matches(line, binding) {
                    *marked.entry(key).or_default() += 1;
                }
            }
        }
    }

    let declared_count: usize = CHAINS
        .iter()
        .map(|binding| {
            declarations
                .get(&(binding.table, binding.managed))
                .copied()
                .unwrap_or(0)
        })
        .sum();
    let jump_count: usize = CHAINS
        .iter()
        .map(|binding| {
            jumps
                .get(&(binding.table, binding.managed))
                .copied()
                .unwrap_or(0)
        })
        .sum();
    if declared_count == 0 && jump_count == 0 {
        return Ok(IptablesFamilyState::Absent);
    }
    let complete = CHAINS.iter().all(|binding| {
        let key = (binding.table, binding.managed);
        declarations.get(&key) == Some(&1)
            && jumps.get(&key) == Some(&1)
            && marked.get(&key) == Some(&1)
    });
    if complete {
        Ok(IptablesFamilyState::AgentOwned)
    } else {
        Err(IptablesRenderError::ForeignChains)
    }
}

/// Renders complete projected state into IPv4 and IPv6 no-flush restore artifacts.
///
/// Only Agent-owned typed objects participate. Existing distribution chains and rules are never
/// flushed or reconstructed. Address sets are expanded into bounded typed rules, avoiding an
/// additional persistent ipset control plane.
///
/// # Errors
///
/// Returns an error for ownership/version mismatch, unsupported semantics, unsafe values,
/// expansion overflow, or an oversized artifact.
pub fn render_iptables_firewall_stage(
    inventory: &FirewallInventory,
    plan: &FirewallMutationPlan,
    ipv4_state: IptablesFamilyState,
    ipv6_state: IptablesFamilyState,
) -> Result<IptablesFirewallStage, IptablesRenderError> {
    let projected = project_agent_objects(inventory, plan).map_err(map_projection_error)?;
    let context = RenderContext::new(&projected)?;
    let ipv4_restore = context.render_family(IpFamily::Ipv4, ipv4_state)?;
    let ipv6_restore = context.render_family(IpFamily::Ipv6, ipv6_state)?;
    Ok(IptablesFirewallStage {
        ipv4_restore,
        ipv6_restore,
        validations: vec![
            IptablesOperation::ValidateIpv4,
            IptablesOperation::ValidateIpv6,
        ],
        activations: vec![IptablesOperation::LoadIpv4, IptablesOperation::LoadIpv6],
        coexistence: IptablesCoexistence::AppendedTerminal,
        rollback_required: true,
    })
}

fn map_projection_error(error: FirewallProjectionError) -> IptablesRenderError {
    match error {
        FirewallProjectionError::InvalidObject => IptablesRenderError::InvalidObject,
        FirewallProjectionError::Ownership => IptablesRenderError::Ownership,
        FirewallProjectionError::PlanMismatch => IptablesRenderError::PlanMismatch,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    Ipv4,
    Ipv6,
}

struct ExpandedSet {
    enabled: bool,
    kind: SetKind,
    entries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SetKind {
    Ipv4Network,
    Ipv6Network,
    Mac,
    Port,
}

struct RenderContext<'a> {
    zones: HashMap<&'a str, &'a agent_protocol::FirewallZone>,
    forwardings: Vec<&'a agent_protocol::FirewallForwarding>,
    filter_rules: Vec<&'a FirewallFilterRule>,
    nat_rules: Vec<&'a FirewallNatRule>,
    sets: HashMap<&'a str, ExpandedSet>,
}

impl<'a> RenderContext<'a> {
    fn new(objects: &'a [FirewallObject]) -> Result<Self, IptablesRenderError> {
        let mut zones = HashMap::new();
        let mut forwardings = Vec::new();
        let mut filter_rules = Vec::new();
        let mut nat_rules = Vec::new();
        let mut sets = HashMap::new();
        for object in objects {
            match object {
                FirewallObject::Zone(value) => {
                    zones.insert(value.id.as_str(), value);
                }
                FirewallObject::Forwarding(value) => forwardings.push(value),
                FirewallObject::FilterRule(value) => filter_rules.push(value),
                FirewallObject::AddressSet(value) => {
                    sets.insert(value.id.as_str(), expanded_set(value)?);
                }
                FirewallObject::NatRule(value) => nat_rules.push(value),
            }
        }
        filter_rules.sort_by_key(|rule| (rule.order, rule.id.as_str()));
        nat_rules.sort_by_key(|rule| (rule.order, rule.id.as_str()));
        Ok(Self {
            zones,
            forwardings,
            filter_rules,
            nat_rules,
            sets,
        })
    }

    fn render_family(
        &self,
        family: IpFamily,
        state: IptablesFamilyState,
    ) -> Result<String, IptablesRenderError> {
        let mut output = String::new();
        Self::render_table_header(&mut output, "filter", state)?;
        let mut count = 0_usize;
        for rule in self.filter_rules.iter().filter(|rule| rule.enabled) {
            let chain = direction_chain(rule.direction);
            if rule.reject_with == Some(FirewallRejectKind::TcpReset)
                && rule.matches.protocols != [FirewallProtocol::Tcp]
            {
                return Err(IptablesRenderError::UnsupportedField(
                    "TCP reset reject requires exactly TCP",
                ));
            }
            if !reject_applies(rule.reject_with, family) {
                continue;
            }
            let matchers = self.expand_match(&rule.matches, rule.direction, family)?;
            if rule.rate_limit.is_some() && matchers.len() > 1 {
                return Err(IptablesRenderError::UnsupportedField(
                    "rate limit across expanded iptables alternatives",
                ));
            }
            for matcher in matchers {
                if let Some(log) = &rule.log {
                    if log.prefix.len() > 29 {
                        return Err(IptablesRenderError::UnsupportedField(
                            "iptables LOG prefix exceeds 29 bytes",
                        ));
                    }
                    count = checked_rule_count(count, 1)?;
                    writeln!(
                        output,
                        "-A {chain}{matcher} -m limit --limit 1/second --limit-burst 5 -m comment --comment mbed:{} -j LOG --log-prefix {} --log-level {}",
                        rule.id,
                        shellless_quote(&log.prefix)?,
                        log_level(log.level)
                    )
                    .map_err(|_| IptablesRenderError::Output)?;
                }
                count = checked_rule_count(count, 1)?;
                let limit = rule.rate_limit.map_or_else(String::new, |limit| {
                    format!(
                        " -m limit --limit {}/second --limit-burst {}",
                        limit.packets_per_second, limit.burst
                    )
                });
                writeln!(
                    output,
                    "-A {chain}{matcher}{limit} -m comment --comment mbed:{} {}",
                    rule.id,
                    verdict_target(rule.verdict, rule.reject_with, family)?
                )
                .map_err(|_| IptablesRenderError::Output)?;
            }
        }
        self.render_forwardings(&mut output, family, &mut count)?;
        self.render_zone_policies(&mut output, family, &mut count)?;
        output.push_str("COMMIT\n");

        Self::render_table_header(&mut output, "mangle", state)?;
        self.render_mtu_fix(&mut output, &mut count)?;
        output.push_str("COMMIT\n");

        Self::render_table_header(&mut output, "nat", state)?;
        for rule in self.nat_rules.iter().filter(|rule| rule.enabled) {
            let (chain, direction) = match rule.kind {
                FirewallNatKind::DestinationNat | FirewallNatKind::Redirect => {
                    ("MBED_PREROUTING", FirewallDirection::Input)
                }
                FirewallNatKind::SourceNat | FirewallNatKind::Masquerade => {
                    ("MBED_POSTROUTING", FirewallDirection::Forward)
                }
            };
            if matches!(
                rule.kind,
                FirewallNatKind::DestinationNat | FirewallNatKind::Redirect
            ) && (!rule.matches.destination_zones.is_empty()
                || !rule.matches.output_interfaces.is_empty())
            {
                return Err(IptablesRenderError::UnsupportedField(
                    "DNAT destination zone/output interface in prerouting",
                ));
            }
            for matcher in self.expand_match(&rule.matches, direction, family)? {
                let Some(target) = nat_target(rule, family)? else {
                    continue;
                };
                count = checked_rule_count(count, 1)?;
                writeln!(
                    output,
                    "-A {chain}{matcher} -m comment --comment mbed:{} {target}",
                    rule.id
                )
                .map_err(|_| IptablesRenderError::Output)?;
            }
        }
        self.render_zone_nat(&mut output, family, &mut count)?;
        output.push_str("COMMIT\n");
        if output.len() > MAX_RESTORE_BYTES {
            return Err(IptablesRenderError::Capacity);
        }
        Ok(output)
    }

    fn render_table_header(
        output: &mut String,
        table: &str,
        state: IptablesFamilyState,
    ) -> Result<(), IptablesRenderError> {
        writeln!(output, "*{table}").map_err(|_| IptablesRenderError::Output)?;
        for binding in CHAINS.iter().filter(|binding| binding.table == table) {
            writeln!(output, ":{} - [0:0]", binding.managed)
                .map_err(|_| IptablesRenderError::Output)?;
            if state == IptablesFamilyState::Absent {
                writeln!(
                    output,
                    "-A {} -m comment --comment {} -j {}",
                    binding.builtin, binding.marker, binding.managed
                )
                .map_err(|_| IptablesRenderError::Output)?;
            }
        }
        Ok(())
    }

    fn render_forwardings(
        &self,
        output: &mut String,
        _family: IpFamily,
        count: &mut usize,
    ) -> Result<(), IptablesRenderError> {
        for forwarding in self
            .forwardings
            .iter()
            .filter(|forwarding| forwarding.enabled)
        {
            let source = self.zone(&forwarding.source_zone)?;
            let destination = self.zone(&forwarding.destination_zone)?;
            for input in &source.networks {
                for output_interface in &destination.networks {
                    *count = checked_rule_count(*count, 1)?;
                    writeln!(
                        output,
                        "-A MBED_FORWARD -i {input} -o {output_interface} -m comment --comment mbed:{} -j ACCEPT",
                        forwarding.id
                    )
                    .map_err(|_| IptablesRenderError::Output)?;
                }
            }
        }
        Ok(())
    }

    fn render_zone_policies(
        &self,
        output: &mut String,
        family: IpFamily,
        count: &mut usize,
    ) -> Result<(), IptablesRenderError> {
        let mut zones: Vec<_> = self.zones.values().copied().collect();
        zones.sort_by_key(|zone| zone.id.as_str());
        for zone in zones.into_iter().filter(|zone| zone.enabled) {
            for interface in &zone.networks {
                for (chain, interface_flag, verdict) in [
                    ("MBED_INPUT", "-i", zone.input),
                    ("MBED_OUTPUT", "-o", zone.output),
                    ("MBED_FORWARD", "-i", zone.forward),
                ] {
                    *count = checked_rule_count(*count, 1)?;
                    writeln!(
                        output,
                        "-A {chain} {interface_flag} {interface} -m comment --comment mbed:zone:{} {}",
                        zone.id,
                        verdict_target(verdict, None, family)?
                    )
                    .map_err(|_| IptablesRenderError::Output)?;
                }
            }
        }
        Ok(())
    }

    fn render_mtu_fix(
        &self,
        output: &mut String,
        count: &mut usize,
    ) -> Result<(), IptablesRenderError> {
        let mut zones: Vec<_> = self.zones.values().copied().collect();
        zones.sort_by_key(|zone| zone.id.as_str());
        for zone in zones
            .into_iter()
            .filter(|zone| zone.enabled && zone.mtu_fix)
        {
            for interface in &zone.networks {
                *count = checked_rule_count(*count, 1)?;
                writeln!(
                    output,
                    "-A MBED_MANGLE_FORWARD -o {interface} -p tcp --tcp-flags SYN,RST SYN -m comment --comment mbed:mtu:{} -j TCPMSS --clamp-mss-to-pmtu",
                    zone.id
                )
                .map_err(|_| IptablesRenderError::Output)?;
            }
        }
        Ok(())
    }

    fn render_zone_nat(
        &self,
        output: &mut String,
        _family: IpFamily,
        count: &mut usize,
    ) -> Result<(), IptablesRenderError> {
        let mut zones: Vec<_> = self.zones.values().copied().collect();
        zones.sort_by_key(|zone| zone.id.as_str());
        for zone in zones
            .into_iter()
            .filter(|zone| zone.enabled && zone.masquerade)
        {
            for interface in &zone.networks {
                *count = checked_rule_count(*count, 1)?;
                writeln!(
                    output,
                    "-A MBED_POSTROUTING -o {interface} -m comment --comment mbed:masq:{} -j MASQUERADE",
                    zone.id
                )
                .map_err(|_| IptablesRenderError::Output)?;
            }
        }
        Ok(())
    }

    fn expand_match(
        &self,
        value: &FirewallMatch,
        direction: FirewallDirection,
        family: IpFamily,
    ) -> Result<Vec<String>, IptablesRenderError> {
        if !family_applies(value.family, family) {
            return Ok(Vec::new());
        }
        validate_direction(value, direction)?;
        self.validate_transport_ports(value)?;
        let mut variants = vec![String::new()];
        let source_interfaces = self.zone_interfaces(&value.source_zones)?;
        let destination_interfaces = self.zone_interfaces(&value.destination_zones)?;
        let (zone_source_flag, zone_destination_flag) = match direction {
            FirewallDirection::Input => ("-i", None),
            FirewallDirection::Output => ("-o", None),
            FirewallDirection::Forward => ("-i", Some("-o")),
        };
        add_values(&mut variants, zone_source_flag, &source_interfaces)?;
        if !destination_interfaces.is_empty() {
            let flag = zone_destination_flag.ok_or(IptablesRenderError::UnsupportedField(
                "destination zone for non-forward direction",
            ))?;
            add_values(&mut variants, flag, &destination_interfaces)?;
        }
        add_values(&mut variants, "-i", &value.input_interfaces)?;
        add_values(&mut variants, "-o", &value.output_interfaces)?;
        add_networks(
            &mut variants,
            "-s",
            &value.source_networks,
            family,
            !value.source_networks.is_empty(),
        )?;
        add_networks(
            &mut variants,
            "-d",
            &value.destination_networks,
            family,
            !value.destination_networks.is_empty(),
        )?;
        add_values_with(
            &mut variants,
            &value.source_macs,
            |value| format!("-m mac --mac-source {value}"),
            !value.source_macs.is_empty(),
        )?;
        let applicable_protocols: Vec<FirewallProtocol> = value
            .protocols
            .iter()
            .copied()
            .filter(|protocol| protocol_applies(*protocol, family))
            .collect();
        if !value.icmp_types.is_empty() {
            let expected = if family == IpFamily::Ipv4 {
                FirewallProtocol::Icmp
            } else {
                FirewallProtocol::Icmpv6
            };
            if !applicable_protocols.is_empty() && applicable_protocols != [expected] {
                return Err(IptablesRenderError::UnsupportedField(
                    "ICMP types combined with another protocol",
                ));
            }
        }
        if !value.protocols.is_empty() {
            let protocols: Vec<String> = applicable_protocols
                .into_iter()
                .map(|protocol| format!("-p {}", protocol_name(protocol)))
                .collect();
            add_dimension(&mut variants, protocols)?;
        }
        add_ports(
            &mut variants,
            "--sport",
            &value.source_ports,
            !value.source_ports.is_empty(),
        )?;
        add_ports(
            &mut variants,
            "--dport",
            &value.destination_ports,
            !value.destination_ports.is_empty(),
        )?;
        add_state_and_icmp(&mut variants, value, family)?;
        self.add_set_dimensions(&mut variants, &value.source_sets, family, true)?;
        self.add_set_dimensions(&mut variants, &value.destination_sets, family, false)?;
        Ok(variants)
    }

    fn add_set_dimensions(
        &self,
        variants: &mut Vec<String>,
        ids: &[String],
        family: IpFamily,
        source: bool,
    ) -> Result<(), IptablesRenderError> {
        let mut dimensions = HashSet::new();
        for id in ids {
            let set = self
                .sets
                .get(id.as_str())
                .ok_or(IptablesRenderError::MissingReference)?;
            if !set.enabled {
                return Err(IptablesRenderError::MissingReference);
            }
            let dimension = match set.kind {
                SetKind::Ipv4Network | SetKind::Ipv6Network => 0_u8,
                SetKind::Mac => 1,
                SetKind::Port => 2,
            };
            if !dimensions.insert(dimension) {
                return Err(IptablesRenderError::UnsupportedField(
                    "multiple same-dimension sets require explicit rule expansion",
                ));
            }
            let options = match (set.kind, family) {
                (SetKind::Ipv4Network, IpFamily::Ipv4) | (SetKind::Ipv6Network, IpFamily::Ipv6) => {
                    let flag = if source { "-s" } else { "-d" };
                    set.entries
                        .iter()
                        .map(|entry| format!("{flag} {entry}"))
                        .collect()
                }
                (SetKind::Ipv4Network | SetKind::Ipv6Network, _) => {
                    variants.clear();
                    return Ok(());
                }
                (SetKind::Mac, _) if source => set
                    .entries
                    .iter()
                    .map(|entry| format!("-m mac --mac-source {entry}"))
                    .collect(),
                (SetKind::Mac, _) => {
                    return Err(IptablesRenderError::UnsupportedField(
                        "iptables destination MAC matching",
                    ));
                }
                (SetKind::Port, _) => {
                    let flag = if source { "--sport" } else { "--dport" };
                    set.entries
                        .iter()
                        .map(|entry| format!("{flag} {entry}"))
                        .collect()
                }
            };
            add_dimension(variants, options)?;
        }
        Ok(())
    }

    fn validate_transport_ports(&self, value: &FirewallMatch) -> Result<(), IptablesRenderError> {
        let has_port_set = value
            .source_sets
            .iter()
            .chain(&value.destination_sets)
            .any(|id| {
                self.sets
                    .get(id.as_str())
                    .is_some_and(|set| set.kind == SetKind::Port)
            });
        let has_ports =
            !value.source_ports.is_empty() || !value.destination_ports.is_empty() || has_port_set;
        let transport_only = !value.protocols.is_empty()
            && value
                .protocols
                .iter()
                .all(|protocol| matches!(protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp));
        if has_ports && !transport_only {
            Err(IptablesRenderError::UnsupportedField(
                "ports require only TCP/UDP protocols",
            ))
        } else {
            Ok(())
        }
    }

    fn zone_interfaces(&self, ids: &[String]) -> Result<Vec<String>, IptablesRenderError> {
        let mut interfaces = Vec::new();
        for id in ids {
            interfaces.extend(self.zone(id)?.networks.iter().cloned());
        }
        interfaces.sort();
        interfaces.dedup();
        Ok(interfaces)
    }

    fn zone(&self, id: &str) -> Result<&'a agent_protocol::FirewallZone, IptablesRenderError> {
        let zone = self
            .zones
            .get(id)
            .copied()
            .ok_or(IptablesRenderError::MissingReference)?;
        if zone.enabled {
            Ok(zone)
        } else {
            Err(IptablesRenderError::MissingReference)
        }
    }
}

fn expanded_set(value: &FirewallAddressSet) -> Result<ExpandedSet, IptablesRenderError> {
    let (kind, entries) = match value.entries.first() {
        Some(FirewallSetEntry::Network(_)) if value.family == FirewallFamily::Ipv4 => (
            SetKind::Ipv4Network,
            value
                .entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Network(value) => Ok(network_value(value)),
                    _ => Err(IptablesRenderError::InvalidObject),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(FirewallSetEntry::Network(_)) if value.family == FirewallFamily::Ipv6 => (
            SetKind::Ipv6Network,
            value
                .entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Network(value) => Ok(network_value(value)),
                    _ => Err(IptablesRenderError::InvalidObject),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(FirewallSetEntry::Mac(_)) => (
            SetKind::Mac,
            value
                .entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Mac(value) => Ok(value.clone()),
                    _ => Err(IptablesRenderError::InvalidObject),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(FirewallSetEntry::Port(_)) => (
            SetKind::Port,
            value
                .entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Port(value) => Ok(iptables_port(*value)),
                    _ => Err(IptablesRenderError::InvalidObject),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => return Err(IptablesRenderError::InvalidObject),
    };
    Ok(ExpandedSet {
        enabled: value.enabled,
        kind,
        entries,
    })
}

fn add_state_and_icmp(
    variants: &mut Vec<String>,
    value: &FirewallMatch,
    family: IpFamily,
) -> Result<(), IptablesRenderError> {
    if !value.conntrack_states.is_empty() {
        let states = value
            .conntrack_states
            .iter()
            .map(|state| match state {
                agent_protocol::FirewallConntrackState::New => "NEW",
                agent_protocol::FirewallConntrackState::Established => "ESTABLISHED",
                agent_protocol::FirewallConntrackState::Related => "RELATED",
                agent_protocol::FirewallConntrackState::Invalid => "INVALID",
            })
            .collect::<Vec<_>>()
            .join(",");
        add_dimension(variants, vec![format!("-m conntrack --ctstate {states}")])?;
    }
    if !value.icmp_types.is_empty() {
        let flag = if family == IpFamily::Ipv4 {
            "--icmp-type"
        } else {
            "--icmpv6-type"
        };
        add_values_with(
            variants,
            &value.icmp_types,
            |value| format!("{flag} {value}"),
            true,
        )?;
    }
    Ok(())
}

fn validate_direction(
    value: &FirewallMatch,
    direction: FirewallDirection,
) -> Result<(), IptablesRenderError> {
    let invalid = match direction {
        FirewallDirection::Input => {
            !value.destination_zones.is_empty() || !value.output_interfaces.is_empty()
        }
        FirewallDirection::Output => {
            !value.source_zones.is_empty() || !value.input_interfaces.is_empty()
        }
        FirewallDirection::Forward => false,
    };
    if invalid {
        Err(IptablesRenderError::UnsupportedField(
            "zone/interface does not exist at this hook",
        ))
    } else {
        Ok(())
    }
}

fn add_values(
    variants: &mut Vec<String>,
    flag: &str,
    values: &[String],
) -> Result<(), IptablesRenderError> {
    if !values.is_empty() {
        add_dimension(
            variants,
            values
                .iter()
                .map(|value| format!("{flag} {value}"))
                .collect(),
        )?;
    }
    Ok(())
}

fn add_values_with<T, F>(
    variants: &mut Vec<String>,
    values: &[T],
    render: F,
    required: bool,
) -> Result<(), IptablesRenderError>
where
    F: Fn(&T) -> String,
{
    if required {
        add_dimension(variants, values.iter().map(render).collect())?;
    }
    Ok(())
}

fn add_networks(
    variants: &mut Vec<String>,
    flag: &str,
    values: &[IpNetwork],
    family: IpFamily,
    required: bool,
) -> Result<(), IptablesRenderError> {
    if !required {
        return Ok(());
    }
    let values: Vec<String> = values
        .iter()
        .filter(|network| address_family(network.address) == family)
        .map(|network| format!("{flag} {}", network_value(network)))
        .collect();
    if values.is_empty() {
        variants.clear();
        Ok(())
    } else {
        add_dimension(variants, values)
    }
}

fn add_ports(
    variants: &mut Vec<String>,
    flag: &str,
    values: &[PortRange],
    required: bool,
) -> Result<(), IptablesRenderError> {
    if required {
        add_dimension(
            variants,
            values
                .iter()
                .map(|value| format!("{flag} {}", iptables_port(*value)))
                .collect(),
        )?;
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // Takes ownership of freshly rendered alternatives.
fn add_dimension(
    variants: &mut Vec<String>,
    options: Vec<String>,
) -> Result<(), IptablesRenderError> {
    if options.is_empty() {
        variants.clear();
        return Ok(());
    }
    if variants.len().saturating_mul(options.len()) > MAX_EXPANDED_RULES {
        return Err(IptablesRenderError::Capacity);
    }
    let current = std::mem::take(variants);
    variants.reserve(current.len().saturating_mul(options.len()));
    for base in current {
        for option in &options {
            variants.push(format!("{base} {option}"));
        }
    }
    Ok(())
}

fn checked_rule_count(current: usize, additional: usize) -> Result<usize, IptablesRenderError> {
    let value = current.saturating_add(additional);
    if value > MAX_EXPANDED_RULES {
        Err(IptablesRenderError::Capacity)
    } else {
        Ok(value)
    }
}

fn nat_target(
    rule: &FirewallNatRule,
    family: IpFamily,
) -> Result<Option<String>, IptablesRenderError> {
    if let Some(address) = rule.translation_address {
        if address_family(address) != family {
            return Ok(None);
        }
    }
    let target = match rule.kind {
        FirewallNatKind::Masquerade => "-j MASQUERADE".into(),
        FirewallNatKind::Redirect => format!(
            "-j REDIRECT --to-ports {}",
            iptables_port(
                rule.translation_port
                    .ok_or(IptablesRenderError::InvalidObject)?
            )
        ),
        FirewallNatKind::DestinationNat | FirewallNatKind::SourceNat => {
            let address = rule
                .translation_address
                .ok_or(IptablesRenderError::InvalidObject)?;
            let endpoint = translation_endpoint(address, rule.translation_port);
            if rule.kind == FirewallNatKind::DestinationNat {
                format!("-j DNAT --to-destination {endpoint}")
            } else {
                format!("-j SNAT --to-source {endpoint}")
            }
        }
    };
    Ok(Some(target))
}

fn translation_endpoint(address: IpAddr, port: Option<PortRange>) -> String {
    match (address, port) {
        (IpAddr::V4(address), Some(port)) => format!("{address}:{}", iptables_port(port)),
        (IpAddr::V6(address), Some(port)) => format!("[{address}]:{}", iptables_port(port)),
        (address, None) => address.to_string(),
    }
}

fn verdict_target(
    verdict: FirewallVerdict,
    reject: Option<FirewallRejectKind>,
    family: IpFamily,
) -> Result<String, IptablesRenderError> {
    match (verdict, reject, family) {
        (FirewallVerdict::Accept, None, _) => Ok("-j ACCEPT".into()),
        (FirewallVerdict::Drop, None, _) => Ok("-j DROP".into()),
        (FirewallVerdict::Reject, Some(FirewallRejectKind::TcpReset), _) => {
            Ok("-j REJECT --reject-with tcp-reset".into())
        }
        (
            FirewallVerdict::Reject,
            Some(FirewallRejectKind::IcmpPortUnreachable),
            IpFamily::Ipv4,
        ) => Ok("-j REJECT --reject-with icmp-port-unreachable".into()),
        (
            FirewallVerdict::Reject,
            Some(FirewallRejectKind::IcmpHostUnreachable),
            IpFamily::Ipv4,
        ) => Ok("-j REJECT --reject-with icmp-host-unreachable".into()),
        (
            FirewallVerdict::Reject,
            Some(FirewallRejectKind::Icmp6PortUnreachable),
            IpFamily::Ipv6,
        ) => Ok("-j REJECT --reject-with icmp6-port-unreachable".into()),
        (FirewallVerdict::Reject, None, _) => Ok("-j REJECT".into()),
        _ => Err(IptablesRenderError::UnsupportedField(
            "reject kind does not match iptables address family",
        )),
    }
}

fn hook_marker_matches(line: &str, binding: &ChainBinding) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens.first() == Some(&"-A")
        && tokens.get(1) == Some(&binding.builtin)
        && option_value(&tokens, "--comment").map(|value| value.trim_matches('"'))
            == Some(binding.marker)
        && option_value(&tokens, "-j") == Some(binding.managed)
}

fn jump_target(line: &str) -> Option<&str> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    option_value(&tokens, "-j")
}

fn option_value<'a>(tokens: &[&'a str], option: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == option)
        .and_then(|index| tokens.get(index + 1))
        .copied()
}

fn shellless_quote(value: &str) -> Result<String, IptablesRenderError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
    {
        return Err(IptablesRenderError::UnsafeValue);
    }
    Ok(format!("\"{value}\""))
}

fn network_value(value: &IpNetwork) -> String {
    format!("{}/{}", value.address, value.prefix_len)
}

fn iptables_port(value: PortRange) -> String {
    if value.start == value.end {
        value.start.to_string()
    } else {
        format!("{}:{}", value.start, value.end)
    }
}

const fn address_family(address: IpAddr) -> IpFamily {
    match address {
        IpAddr::V4(_) => IpFamily::Ipv4,
        IpAddr::V6(_) => IpFamily::Ipv6,
    }
}

const fn family_applies(value: FirewallFamily, family: IpFamily) -> bool {
    matches!(
        (value, family),
        (FirewallFamily::Any, _)
            | (FirewallFamily::Ipv4, IpFamily::Ipv4)
            | (FirewallFamily::Ipv6, IpFamily::Ipv6)
    )
}

const fn direction_chain(value: FirewallDirection) -> &'static str {
    match value {
        FirewallDirection::Input => "MBED_INPUT",
        FirewallDirection::Output => "MBED_OUTPUT",
        FirewallDirection::Forward => "MBED_FORWARD",
    }
}

const fn protocol_applies(value: FirewallProtocol, family: IpFamily) -> bool {
    !matches!(
        (value, family),
        (FirewallProtocol::Icmp, IpFamily::Ipv6) | (FirewallProtocol::Icmpv6, IpFamily::Ipv4)
    )
}

const fn reject_applies(value: Option<FirewallRejectKind>, family: IpFamily) -> bool {
    matches!(
        (value, family),
        (None | Some(FirewallRejectKind::TcpReset), _)
            | (
                Some(
                    FirewallRejectKind::IcmpPortUnreachable
                        | FirewallRejectKind::IcmpHostUnreachable
                ),
                IpFamily::Ipv4
            )
            | (
                Some(FirewallRejectKind::Icmp6PortUnreachable),
                IpFamily::Ipv6
            )
    )
}

const fn protocol_name(value: FirewallProtocol) -> &'static str {
    match value {
        FirewallProtocol::Tcp => "tcp",
        FirewallProtocol::Udp => "udp",
        FirewallProtocol::Icmp => "icmp",
        FirewallProtocol::Icmpv6 => "ipv6-icmp",
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
        FirewallLogLevel::Error => "error",
        FirewallLogLevel::Warning => "warning",
        FirewallLogLevel::Notice => "notice",
        FirewallLogLevel::Info => "info",
        FirewallLogLevel::Debug => "debug",
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IptablesRenderError {
    #[error("iptables-save inspection is malformed or oversized")]
    MalformedInspection,
    #[error("fixed MBED chains are partial, duplicated, or foreign")]
    ForeignChains,
    #[error("iptables staging exceeds its capacity")]
    Capacity,
    #[error("iptables staging accepts only Agent-owned mutations")]
    Ownership,
    #[error("iptables mutation plan does not match fresh inventory")]
    PlanMismatch,
    #[error("iptables mutation contains an invalid typed object")]
    InvalidObject,
    #[error("iptables object references a missing or disabled Agent-owned zone/set")]
    MissingReference,
    #[error("iptables cannot safely represent: {0}")]
    UnsupportedField(&'static str),
    #[error("unsafe value cannot be represented in iptables-restore")]
    UnsafeValue,
    #[error("failed to render iptables staging artifact")]
    Output,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use agent_core::{FirewallMutation, FirewallRiskContext, plan_firewall_mutations};
    use agent_protocol::{
        FirewallConntrackState, FirewallForwarding, FirewallLog, FirewallRateLimit, FirewallZone,
        ObjectOwnership,
    };

    use super::*;

    #[test]
    fn inspection_requires_all_six_owned_chains_and_exact_hooks() {
        assert_eq!(
            inspect_iptables_family_state(""),
            Ok(IptablesFamilyState::Absent)
        );
        let save = owned_save();
        assert_eq!(
            inspect_iptables_family_state(&save),
            Ok(IptablesFamilyState::AgentOwned)
        );
        let partial = save.replace(
            "-A FORWARD -m comment --comment \"mbed-agent-owned:v1:mangle-forward\" -j MBED_MANGLE_FORWARD\n",
            "",
        );
        assert_eq!(
            inspect_iptables_family_state(&partial),
            Err(IptablesRenderError::ForeignChains)
        );
        let duplicate = format!("{save}*filter\n-A INPUT -j MBED_INPUT\nCOMMIT\n");
        assert_eq!(
            inspect_iptables_family_state(&duplicate),
            Err(IptablesRenderError::ForeignChains)
        );
        assert_eq!(
            inspect_iptables_family_state("*filter\n:MBED_INPUTX - [0:0]\nCOMMIT\n"),
            Ok(IptablesFamilyState::Absent)
        );
        assert_eq!(
            inspect_iptables_family_state("*filter\0"),
            Err(IptablesRenderError::MalformedInspection)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One golden stage covers filter, mangle, NAT, and both AFs.
    fn renders_bounded_dual_stack_restore_artifacts() {
        let inventory = base_inventory();
        let objects = vec![
            FirewallObject::AddressSet(FirewallAddressSet {
                id: "blocked-v4".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                family: FirewallFamily::Ipv4,
                entries: vec![
                    FirewallSetEntry::Network(network4([198, 51, 100, 0], 24)),
                    FirewallSetEntry::Network(network4([203, 0, 113, 0], 24)),
                ],
            }),
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
            FirewallObject::FilterRule(FirewallFilterRule {
                id: "drop-admin".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                direction: FirewallDirection::Input,
                matches: FirewallMatch {
                    family: FirewallFamily::Ipv4,
                    source_zones: vec!["wan".into()],
                    protocols: vec![FirewallProtocol::Tcp],
                    conntrack_states: vec![FirewallConntrackState::New],
                    source_sets: vec!["blocked-v4".into(), "admin-macs".into()],
                    destination_sets: vec!["admin-ports".into()],
                    ..FirewallMatch::default()
                },
                verdict: FirewallVerdict::Drop,
                reject_with: None,
                rate_limit: None,
                log: Some(FirewallLog {
                    prefix: "mbed-drop".into(),
                    level: FirewallLogLevel::Warning,
                }),
                order: 10,
            }),
            FirewallObject::FilterRule(FirewallFilterRule {
                id: "rate-ssh".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                direction: FirewallDirection::Input,
                matches: FirewallMatch {
                    family: FirewallFamily::Ipv4,
                    source_zones: vec!["wan".into()],
                    protocols: vec![FirewallProtocol::Tcp],
                    destination_ports: vec![PortRange {
                        start: 2222,
                        end: 2222,
                    }],
                    ..FirewallMatch::default()
                },
                verdict: FirewallVerdict::Drop,
                reject_with: None,
                rate_limit: Some(FirewallRateLimit {
                    packets_per_second: 10,
                    burst: 20,
                }),
                log: None,
                order: 11,
            }),
            FirewallObject::NatRule(FirewallNatRule {
                id: "publish-v4".into(),
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
            }),
            FirewallObject::NatRule(FirewallNatRule {
                id: "publish-v6".into(),
                ownership: ObjectOwnership::AgentOwned,
                enabled: true,
                kind: FirewallNatKind::DestinationNat,
                matches: FirewallMatch {
                    family: FirewallFamily::Ipv6,
                    source_zones: vec!["wan".into()],
                    protocols: vec![FirewallProtocol::Tcp],
                    destination_ports: vec![PortRange {
                        start: 9443,
                        end: 9443,
                    }],
                    ..FirewallMatch::default()
                },
                translation_address: Some(IpAddr::V6(
                    "2001:db8::10".parse().expect("IPv6 address"),
                )),
                translation_port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
                order: 30,
            }),
        ];
        let plan = create_plan(&inventory, objects);
        let stage = render_iptables_firewall_stage(
            &inventory,
            &plan,
            IptablesFamilyState::Absent,
            IptablesFamilyState::Absent,
        )
        .expect("render iptables");

        assert!(stage.ipv4_restore.contains("*filter\n:MBED_INPUT - [0:0]"));
        assert!(
            stage
                .ipv4_restore
                .contains("-A INPUT -m comment --comment mbed-agent-owned:v1:input -j MBED_INPUT")
        );
        assert!(stage.ipv4_restore.contains("-s 198.51.100.0/24"));
        assert!(
            stage
                .ipv4_restore
                .contains("-m mac --mac-source 02:00:00:00:00:01")
        );
        assert!(stage.ipv4_restore.contains("--dport 8000:8010"));
        assert!(stage.ipv4_restore.contains("-m conntrack --ctstate NEW"));
        assert!(
            stage
                .ipv4_restore
                .contains("--limit 10/second --limit-burst 20")
        );
        assert!(
            stage
                .ipv4_restore
                .contains("-j LOG --log-prefix \"mbed-drop\" --log-level warning")
        );
        assert!(stage.ipv4_restore.contains("*mangle\n:MBED_MANGLE_FORWARD"));
        assert!(stage.ipv4_restore.contains("-j TCPMSS --clamp-mss-to-pmtu"));
        assert!(
            stage
                .ipv4_restore
                .contains("--to-destination 192.168.1.10:443")
        );
        assert!(stage.ipv4_restore.contains("-j MASQUERADE"));
        assert!(!stage.ipv4_restore.contains("2001:db8::10"));
        assert!(
            stage
                .ipv6_restore
                .contains("--to-destination [2001:db8::10]:443")
        );
        assert!(!stage.ipv6_restore.contains("198.51.100.0/24"));
        assert_eq!(
            stage.validations,
            vec![
                IptablesOperation::ValidateIpv4,
                IptablesOperation::ValidateIpv6
            ]
        );
        assert_eq!(
            stage.activations,
            vec![IptablesOperation::LoadIpv4, IptablesOperation::LoadIpv6]
        );
        assert_eq!(stage.coexistence, IptablesCoexistence::AppendedTerminal);
        assert!(stage.rollback_required);
    }

    #[test]
    fn owned_state_redeclares_only_managed_chains_without_duplicate_hooks() {
        let inventory = base_inventory();
        let plan = create_plan(
            &inventory,
            vec![FirewallObject::FilterRule(simple_rule("deny-ssh"))],
        );
        let stage = render_iptables_firewall_stage(
            &inventory,
            &plan,
            IptablesFamilyState::AgentOwned,
            IptablesFamilyState::AgentOwned,
        )
        .expect("render owned chains");

        assert!(stage.ipv4_restore.contains(":MBED_INPUT - [0:0]"));
        assert!(!stage.ipv4_restore.contains("mbed-agent-owned:v1:input"));
        assert!(!stage.ipv4_restore.contains(":INPUT "));
    }

    #[test]
    fn rejects_foreign_ownership_and_iptables_specific_ambiguity() {
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
                expected_digest: agent_core::firewall_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &FirewallRiskContext::default(),
        )
        .expect("platform plan");
        assert_eq!(
            render_iptables_firewall_stage(
                &inventory,
                &plan,
                IptablesFamilyState::Absent,
                IptablesFamilyState::Absent
            ),
            Err(IptablesRenderError::Ownership)
        );

        let inventory = base_inventory();
        let set = FirewallObject::AddressSet(FirewallAddressSet {
            id: "destination-macs".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: FirewallFamily::Any,
            entries: vec![FirewallSetEntry::Mac("02:00:00:00:00:02".into())],
        });
        let mut rule = simple_rule("dest-mac");
        rule.matches.destination_sets = vec!["destination-macs".into()];
        let plan = create_plan(&inventory, vec![set, FirewallObject::FilterRule(rule)]);
        assert_eq!(
            render_iptables_firewall_stage(
                &inventory,
                &plan,
                IptablesFamilyState::Absent,
                IptablesFamilyState::Absent
            ),
            Err(IptablesRenderError::UnsupportedField(
                "iptables destination MAC matching"
            ))
        );
    }

    #[test]
    fn expansion_is_hard_bounded() {
        let inventory = base_inventory();
        let mut rule = simple_rule("large-cross-product");
        rule.matches.source_networks = (1_u8..=32)
            .map(|last| network4([10, 0, last, 0], 24))
            .collect();
        rule.matches.destination_networks = (1_u8..=32)
            .map(|last| network4([172, 16, last, 0], 24))
            .collect();
        rule.matches.source_macs = vec!["02:00:00:00:00:01".into(), "02:00:00:00:00:02".into()];
        let plan = create_plan(&inventory, vec![FirewallObject::FilterRule(rule)]);
        assert_eq!(
            render_iptables_firewall_stage(
                &inventory,
                &plan,
                IptablesFamilyState::Absent,
                IptablesFamilyState::Absent
            ),
            Err(IptablesRenderError::Capacity)
        );
    }

    #[test]
    fn rate_limit_is_not_silently_multiplied_across_expanded_rules() {
        let inventory = base_inventory();
        let mut rule = simple_rule("rate-expanded");
        rule.matches.source_networks = vec![
            network4([192, 0, 2, 0], 24),
            network4([198, 51, 100, 0], 24),
        ];
        rule.rate_limit = Some(FirewallRateLimit {
            packets_per_second: 5,
            burst: 10,
        });
        let plan = create_plan(&inventory, vec![FirewallObject::FilterRule(rule)]);
        assert_eq!(
            render_iptables_firewall_stage(
                &inventory,
                &plan,
                IptablesFamilyState::Absent,
                IptablesFamilyState::Absent
            ),
            Err(IptablesRenderError::UnsupportedField(
                "rate limit across expanded iptables alternatives"
            ))
        );
    }

    fn owned_save() -> String {
        let mut output = String::new();
        for table in ["filter", "mangle", "nat"] {
            writeln!(output, "*{table}").expect("string write");
            for binding in CHAINS.iter().filter(|binding| binding.table == table) {
                writeln!(output, ":{} - [0:0]", binding.managed).expect("string write");
                writeln!(
                    output,
                    "-A {} -m comment --comment \"{}\" -j {}",
                    binding.builtin, binding.marker, binding.managed
                )
                .expect("string write");
            }
            output.push_str("COMMIT\n");
        }
        output
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
                    mtu_fix: true,
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

    fn simple_rule(id: &str) -> FirewallFilterRule {
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
            order: 1,
        }
    }

    fn network4(octets: [u8; 4], prefix_len: u8) -> IpNetwork {
        IpNetwork {
            address: IpAddr::V4(Ipv4Addr::from(octets)),
            prefix_len,
        }
    }

    #[test]
    fn ipv6_icmp_protocol_is_emitted_only_in_ip6tables() {
        let inventory = base_inventory();
        let rule = FirewallObject::FilterRule(FirewallFilterRule {
            id: "reject-v6-ping".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch {
                family: FirewallFamily::Any,
                protocols: vec![FirewallProtocol::Icmpv6],
                icmp_types: vec![128],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Reject,
            reject_with: Some(FirewallRejectKind::Icmp6PortUnreachable),
            rate_limit: None,
            log: None,
            order: 2,
        });
        let plan = create_plan(&inventory, vec![rule]);
        let stage = render_iptables_firewall_stage(
            &inventory,
            &plan,
            IptablesFamilyState::Absent,
            IptablesFamilyState::Absent,
        )
        .expect("render ICMPv6");
        assert!(!stage.ipv4_restore.contains("reject-v6-ping"));
        assert!(
            stage
                .ipv6_restore
                .contains("-p ipv6-icmp --icmpv6-type 128")
        );
        assert!(
            stage
                .ipv6_restore
                .contains("--reject-with icmp6-port-unreachable")
        );
    }

    #[test]
    fn ipv6_endpoint_formatter_uses_brackets_for_ports() {
        assert_eq!(
            translation_endpoint(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                Some(PortRange {
                    start: 443,
                    end: 443
                })
            ),
            "[::1]:443"
        );
    }
}
