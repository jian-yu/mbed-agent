//! Bounded firewall write adapters for Linux platforms.
//!
//! This module only renders a validated mutation plan into a staging artifact.
//! It never invokes UCI, reloads a firewall, or writes persistent storage.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use agent_core::{
    FirewallInventory, FirewallMutationPlan, firewall_object_digest, validate_firewall_object,
};
use agent_protocol::{
    ChangeOperation, FirewallDirection, FirewallFamily, FirewallFilterRule, FirewallMatch,
    FirewallNatKind, FirewallNatRule, FirewallObject, FirewallProtocol, FirewallSetEntry,
    FirewallVerdict, IpNetwork, PortRange,
};
use thiserror::Error;

use crate::firewall_inventory::OpenWrtFirewallInventorySnapshot;
use crate::firewall_uci::{UciSection, parse_uci_show, safe_uci_identifier, valid_section};
use crate::{FirewallBackend, PlatformCapabilities, PlatformKind};

const MAX_BINDINGS: usize = 256;
const MAX_PRESENT_OPTIONS: usize = 64;
const MAX_BATCH_BYTES: usize = 128 * 1024;

/// A firewall backend that is safe to use for configuration writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallWriteBackend {
    OpenWrtFw3,
    OpenWrtFw4,
    LinuxNftables,
    LinuxIptables,
}

/// Selects a write backend only when all commands required by that backend were discovered.
///
/// # Errors
///
/// Returns a structured error when the platform is unsupported or lacks a required command.
pub fn select_firewall_write_backend(
    capabilities: &PlatformCapabilities,
) -> Result<FirewallWriteBackend, FirewallRenderError> {
    let has = |command: &str| {
        capabilities
            .available_commands
            .iter()
            .any(|candidate| candidate == command)
    };
    match (capabilities.kind, capabilities.firewall.backend) {
        (PlatformKind::OpenWrt, FirewallBackend::Fw3) if has("uci") && has("fw3") => {
            Ok(FirewallWriteBackend::OpenWrtFw3)
        }
        (PlatformKind::OpenWrt, FirewallBackend::Fw4) if has("uci") && has("fw4") && has("nft") => {
            Ok(FirewallWriteBackend::OpenWrtFw4)
        }
        (PlatformKind::GenericLinux, FirewallBackend::Nftables) if has("nft") => {
            Ok(FirewallWriteBackend::LinuxNftables)
        }
        (PlatformKind::GenericLinux, FirewallBackend::Iptables)
            if has("iptables-restore")
                && has("ip6tables-restore")
                && has("iptables-save")
                && has("ip6tables-save") =>
        {
            Ok(FirewallWriteBackend::LinuxIptables)
        }
        _ => Err(FirewallRenderError::BackendUnavailable),
    }
}

/// A section identity obtained by inspecting the current UCI firewall package.
///
/// Bindings are intentionally separate from the user-facing firewall object. Existing objects
/// can only be changed through a section identity resolved from fresh local inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtObjectBinding {
    pub kind: String,
    pub id: String,
    pub section_type: String,
    pub section: String,
    pub present_options: Vec<String>,
}

/// Fixed native validation actions for a staged `OpenWrt` firewall package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenWrtValidation {
    /// Run `fw3 -4 -q print` with `UCI_CONFIG_DIR` fixed to the staging directory.
    Fw3PrintIpv4,
    /// Run `fw3 -6 -q print` with `UCI_CONFIG_DIR` fixed to the staging directory.
    Fw3PrintIpv6,
    /// Run `fw4 -q check` with `UCI_CONFIG_DIR` fixed to the staging directory.
    Fw4Check,
}

/// A complete, non-executing `OpenWrt` firewall staging artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtFirewallStage {
    /// Input for `uci -c <staging-dir> batch`.
    pub uci_batch: String,
    /// Native parser/ruleset checks that must all succeed before installation.
    pub validations: Vec<OpenWrtValidation>,
    /// The only allowed activation operation after the staged file is atomically installed.
    pub activation_service: &'static str,
    pub activation_action: &'static str,
}

/// Resolves typed inventory objects to sections in a bounded `uci show firewall` snapshot.
///
/// The snapshot and inventory must be obtained in the same inspection pass. Named objects match
/// their UCI `name`; forwarding sections may instead match their typed source and destination
/// zones. Unnamed rule/NAT sections use the documented `platform-<type>-<index>` fallback identity.
/// Ambiguous matches fail closed.
///
/// # Errors
///
/// Returns an error for malformed or oversized UCI output, unsafe section syntax, duplicate
/// definitions, ambiguous object matches, or inventory/schema disagreement.
pub fn inspect_openwrt_object_bindings(
    uci_show: &str,
    inventory: &FirewallInventory,
) -> Result<Vec<OpenWrtObjectBinding>, FirewallRenderError> {
    let sections = parse_uci_show(uci_show)?;
    let mut bindings = Vec::new();
    let mut claimed = HashSet::new();
    for object in &inventory.objects {
        validate_firewall_object(object).map_err(|_| FirewallRenderError::InvalidObject)?;
        let candidates: Vec<&UciSection> = sections
            .iter()
            .filter(|section| section_matches_object(section, object))
            .collect();
        if candidates.len() > 1 {
            return Err(FirewallRenderError::AmbiguousBinding);
        }
        let Some(section) = candidates.first() else {
            continue;
        };
        if !claimed.insert(section.selector.as_str()) {
            return Err(FirewallRenderError::AmbiguousBinding);
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
    }
    validate_bindings(&bindings)?;
    Ok(bindings)
}

/// Renders an already validated firewall mutation plan into a bounded UCI staging batch.
///
/// The caller must first copy `/etc/config/firewall` into a private directory under `/tmp`.
/// It then supplies this batch to `uci -c <dir> batch`, runs every native validation with the
/// fixed `UCI_CONFIG_DIR=<dir>` environment, and only later installs the checked file through
/// the `ChangeSet` transaction.
///
/// # Errors
///
/// Returns an error for unsafe/stale bindings, unsupported UCI semantics, invalid objects,
/// duplicate sections, or an oversized output artifact.
#[cfg(test)]
fn render_openwrt_firewall_stage(
    plan: &FirewallMutationPlan,
    bindings: &[OpenWrtObjectBinding],
    backend: FirewallBackend,
) -> Result<OpenWrtFirewallStage, FirewallRenderError> {
    render_openwrt_firewall_stage_inner(plan, bindings, &[], backend)
}

/// Renders against a fresh inventory snapshot while reserving every existing UCI section.
///
/// # Errors
///
/// Returns a closed error when the snapshot, plan, or backend cannot be represented safely.
pub fn render_openwrt_firewall_stage_from_snapshot(
    plan: &FirewallMutationPlan,
    snapshot: &OpenWrtFirewallInventorySnapshot,
    backend: FirewallBackend,
) -> Result<OpenWrtFirewallStage, FirewallRenderError> {
    validate_plan_against_snapshot(plan, snapshot)?;
    render_openwrt_firewall_stage_inner(
        plan,
        snapshot.bindings(),
        snapshot.occupied_sections(),
        backend,
    )
}

fn validate_plan_against_snapshot(
    plan: &FirewallMutationPlan,
    snapshot: &OpenWrtFirewallInventorySnapshot,
) -> Result<(), FirewallRenderError> {
    if plan.changes.is_empty() || plan.changes.len() > 32 {
        return Err(FirewallRenderError::PlanMismatch);
    }
    let inventory: HashMap<(&str, &str), &FirewallObject> = snapshot
        .inventory()
        .objects
        .iter()
        .map(|object| ((object.kind(), object.id()), object))
        .collect();
    if inventory.len() != snapshot.inventory().objects.len() {
        return Err(FirewallRenderError::DuplicateInventoryObject);
    }
    let mut touched = HashSet::new();
    for change in &plan.changes {
        let object = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(FirewallRenderError::PlanMismatch)?;
        let key = (object.kind(), object.id());
        if !touched.insert(key)
            || change.diff.object.kind != key.0
            || change.diff.object.id != key.1
            || change.diff.object.ownership != object.ownership()
        {
            return Err(FirewallRenderError::PlanMismatch);
        }
        let before_digest = change
            .before
            .as_ref()
            .map(firewall_object_digest)
            .transpose()
            .map_err(|_| FirewallRenderError::InvalidObject)?;
        let after_digest = change
            .after
            .as_ref()
            .map(firewall_object_digest)
            .transpose()
            .map_err(|_| FirewallRenderError::InvalidObject)?;
        if change.diff.before_digest != before_digest
            || change.diff.after_digest != after_digest
            || change.diff.object.expected_version != before_digest
        {
            return Err(FirewallRenderError::PlanMismatch);
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
            _ => return Err(FirewallRenderError::PlanMismatch),
        }
    }
    Ok(())
}

fn render_openwrt_firewall_stage_inner(
    plan: &FirewallMutationPlan,
    bindings: &[OpenWrtObjectBinding],
    occupied_sections: &[String],
    backend: FirewallBackend,
) -> Result<OpenWrtFirewallStage, FirewallRenderError> {
    if !matches!(backend, FirewallBackend::Fw3 | FirewallBackend::Fw4) {
        return Err(FirewallRenderError::WrongBackend);
    }
    let bindings = validate_bindings(bindings)?;
    let mut reserved_sections: HashSet<String> = occupied_sections.iter().cloned().collect();
    if reserved_sections.len() != occupied_sections.len() {
        return Err(FirewallRenderError::DuplicateSection);
    }
    for binding in bindings.values() {
        if occupied_sections.is_empty() {
            reserved_sections.insert(binding.section.clone());
        } else if !reserved_sections.contains(&binding.section) {
            return Err(FirewallRenderError::UnsafeBinding);
        }
    }
    let mut batch = String::new();

    for change in &plan.changes {
        let object = change
            .after
            .as_ref()
            .or(change.before.as_ref())
            .ok_or(FirewallRenderError::MissingObject)?;
        validate_firewall_object(object).map_err(|_| FirewallRenderError::InvalidObject)?;
        if change.diff.object.kind != object.kind() || change.diff.object.id != object.id() {
            return Err(FirewallRenderError::PlanMismatch);
        }
        let key = (object.kind(), object.id());
        match change.diff.operation {
            ChangeOperation::Create => {
                if bindings.contains_key(&key) {
                    return Err(FirewallRenderError::DuplicateBinding);
                }
                let digest = change
                    .diff
                    .after_digest
                    .as_deref()
                    .ok_or(FirewallRenderError::PlanMismatch)?;
                let section = agent_section_name(object.kind(), digest)?;
                if !reserved_sections.insert(section.clone()) {
                    return Err(FirewallRenderError::DuplicateSection);
                }
                render_create(&mut batch, &section, object, backend)?;
            }
            ChangeOperation::Update => {
                let binding = binding_for(&bindings, key)?;
                render_update(&mut batch, binding, object, backend)?;
            }
            ChangeOperation::Delete => {
                let binding = binding_for(&bindings, key)?;
                writeln!(batch, "delete firewall.{}", binding.section)
                    .map_err(|_| FirewallRenderError::Output)?;
            }
            ChangeOperation::Move => {
                let binding = binding_for(&bindings, key)?;
                let order = object_order(object).ok_or(FirewallRenderError::UnsupportedField(
                    "move is only supported for ordered rules",
                ))?;
                writeln!(batch, "reorder firewall.{}={order}", binding.section)
                    .map_err(|_| FirewallRenderError::Output)?;
            }
        }
        if batch.len() > MAX_BATCH_BYTES {
            return Err(FirewallRenderError::Capacity);
        }
    }
    batch.push_str("commit firewall\n");

    let validations = match backend {
        FirewallBackend::Fw3 => vec![
            OpenWrtValidation::Fw3PrintIpv4,
            OpenWrtValidation::Fw3PrintIpv6,
        ],
        FirewallBackend::Fw4 => vec![OpenWrtValidation::Fw4Check],
        _ => unreachable!("backend checked above"),
    };
    Ok(OpenWrtFirewallStage {
        uci_batch: batch,
        validations,
        activation_service: "/etc/init.d/firewall",
        activation_action: "reload",
    })
}

fn section_matches_object(section: &UciSection, object: &FirewallObject) -> bool {
    if !valid_section_type(&section.section_type, object.kind()) {
        return false;
    }
    let name_matches = section.first("name") == Some(object.id());
    match object {
        FirewallObject::Forwarding(forwarding) => {
            name_matches
                || (!section.options.contains_key("name")
                    && section.first("src") == Some(&forwarding.source_zone)
                    && section.first("dest") == Some(&forwarding.destination_zone))
        }
        FirewallObject::FilterRule(_) | FirewallObject::NatRule(_) => {
            name_matches
                || (!section.options.contains_key("name")
                    && fallback_section_id(section).as_deref() == Some(object.id()))
        }
        _ => name_matches,
    }
}

fn fallback_section_id(section: &UciSection) -> Option<String> {
    let index = section
        .selector
        .strip_prefix('@')?
        .strip_prefix(&section.section_type)?
        .strip_prefix('[')?
        .strip_suffix(']')?;
    let kind = match section.section_type.as_str() {
        "rule" => "rule",
        "redirect" => "redirect",
        "nat" => "nat",
        _ => return None,
    };
    Some(format!("platform-{kind}-{index}"))
}

fn validate_bindings(
    bindings: &[OpenWrtObjectBinding],
) -> Result<HashMap<(&str, &str), &OpenWrtObjectBinding>, FirewallRenderError> {
    if bindings.len() > MAX_BINDINGS {
        return Err(FirewallRenderError::Capacity);
    }
    let mut indexed = HashMap::with_capacity(bindings.len());
    let mut sections = HashSet::with_capacity(bindings.len());
    for binding in bindings {
        if !known_kind(&binding.kind)
            || !safe_identifier(&binding.id)
            || !valid_section_type(&binding.section_type, &binding.kind)
            || !valid_section(&binding.section, &binding.section_type)
            || binding.present_options.len() > MAX_PRESENT_OPTIONS
        {
            return Err(FirewallRenderError::UnsafeBinding);
        }
        if !binding
            .present_options
            .iter()
            .all(|option| safe_uci_identifier(option))
        {
            return Err(FirewallRenderError::UnsafeBinding);
        }
        if indexed
            .insert((binding.kind.as_str(), binding.id.as_str()), binding)
            .is_some()
        {
            return Err(FirewallRenderError::DuplicateBinding);
        }
        if !sections.insert(binding.section.as_str()) {
            return Err(FirewallRenderError::DuplicateSection);
        }
    }
    Ok(indexed)
}

fn binding_for<'a>(
    bindings: &HashMap<(&str, &str), &'a OpenWrtObjectBinding>,
    key: (&str, &str),
) -> Result<&'a OpenWrtObjectBinding, FirewallRenderError> {
    bindings
        .get(&key)
        .copied()
        .ok_or(FirewallRenderError::MissingBinding)
}

fn render_create(
    batch: &mut String,
    section: &str,
    object: &FirewallObject,
    backend: FirewallBackend,
) -> Result<(), FirewallRenderError> {
    let rendered = render_object(object, backend)?;
    writeln!(batch, "set firewall.{section}={}", rendered.section_type)
        .map_err(|_| FirewallRenderError::Output)?;
    render_options(batch, section, &rendered)
}

fn render_update(
    batch: &mut String,
    binding: &OpenWrtObjectBinding,
    object: &FirewallObject,
    backend: FirewallBackend,
) -> Result<(), FirewallRenderError> {
    let rendered = render_object(object, backend)?;
    if rendered.section_type != binding.section_type {
        return Err(FirewallRenderError::PlanMismatch);
    }
    let supported: HashSet<&str> = supported_options(object.kind()).iter().copied().collect();
    for option in &binding.present_options {
        if supported.contains(option.as_str()) {
            writeln!(batch, "delete firewall.{}.{}", binding.section, option)
                .map_err(|_| FirewallRenderError::Output)?;
        }
    }
    render_options(batch, &binding.section, &rendered)
}

fn render_options(
    batch: &mut String,
    section: &str,
    rendered: &RenderedObject,
) -> Result<(), FirewallRenderError> {
    for (name, value) in &rendered.options {
        writeln!(batch, "set firewall.{section}.{name}={}", quote(value)?)
            .map_err(|_| FirewallRenderError::Output)?;
    }
    for (name, values) in &rendered.lists {
        for value in values {
            writeln!(
                batch,
                "add_list firewall.{section}.{name}={}",
                quote(value)?
            )
            .map_err(|_| FirewallRenderError::Output)?;
        }
    }
    Ok(())
}

struct RenderedObject {
    section_type: &'static str,
    options: Vec<(&'static str, String)>,
    lists: Vec<(&'static str, Vec<String>)>,
}

fn render_object(
    object: &FirewallObject,
    backend: FirewallBackend,
) -> Result<RenderedObject, FirewallRenderError> {
    match object {
        FirewallObject::Zone(zone) => Ok(RenderedObject {
            section_type: "zone",
            options: vec![
                ("name", zone.id.clone()),
                ("enabled", bool_value(zone.enabled)),
                ("input", verdict(zone.input).into()),
                ("output", verdict(zone.output).into()),
                ("forward", verdict(zone.forward).into()),
                ("masq", bool_value(zone.masquerade)),
                ("mtu_fix", bool_value(zone.mtu_fix)),
            ],
            lists: vec![("network", zone.networks.clone())],
        }),
        FirewallObject::Forwarding(forwarding) => Ok(RenderedObject {
            section_type: "forwarding",
            options: vec![
                ("name", forwarding.id.clone()),
                ("enabled", bool_value(forwarding.enabled)),
                ("src", forwarding.source_zone.clone()),
                ("dest", forwarding.destination_zone.clone()),
            ],
            lists: Vec::new(),
        }),
        FirewallObject::FilterRule(rule) => render_filter_rule(rule),
        FirewallObject::AddressSet(set) => {
            let (set_match, entries) = render_set_entries(&set.entries)?;
            let mut options = vec![
                ("name", set.id.clone()),
                ("enabled", bool_value(set.enabled)),
                ("family", family(set.family).into()),
            ];
            if backend == FirewallBackend::Fw3 {
                options.push(("storage", "hash".into()));
            }
            Ok(RenderedObject {
                section_type: "ipset",
                options,
                lists: vec![("match", vec![set_match.into()]), ("entry", entries)],
            })
        }
        FirewallObject::NatRule(rule) => render_nat_rule(rule),
    }
}

fn render_filter_rule(rule: &FirewallFilterRule) -> Result<RenderedObject, FirewallRenderError> {
    if rule.verdict == FirewallVerdict::Reject {
        return Err(FirewallRenderError::UnsupportedField(
            "per-rule reject kind is not representable by fw3/fw4 UCI",
        ));
    }
    if !rule.matches.conntrack_states.is_empty() {
        return Err(FirewallRenderError::UnsupportedField(
            "conntrack state requires an unmanaged raw expression",
        ));
    }
    let mut options = vec![
        ("name", rule.id.clone()),
        ("enabled", bool_value(rule.enabled)),
        ("family", family(rule.matches.family).into()),
        ("target", verdict(rule.verdict).into()),
    ];
    render_rule_location(rule.direction, &rule.matches, &mut options)?;
    add_common_match_options(&rule.matches, &mut options, true)?;
    if let Some(limit) = rule.rate_limit {
        options.push(("limit", format!("{}/second", limit.packets_per_second)));
        options.push(("limit_burst", limit.burst.to_string()));
    }
    if let Some(log) = &rule.log {
        if log.level != agent_protocol::FirewallLogLevel::Info {
            return Err(FirewallRenderError::UnsupportedField(
                "fw3/fw4 UCI does not preserve a per-rule log level",
            ));
        }
        options.push(("log", log.prefix.clone()));
    }
    let lists = common_match_lists(&rule.matches, true);
    Ok(RenderedObject {
        section_type: "rule",
        options,
        lists,
    })
}

fn render_nat_rule(rule: &FirewallNatRule) -> Result<RenderedObject, FirewallRenderError> {
    if !rule.matches.conntrack_states.is_empty()
        || !rule.matches.icmp_types.is_empty()
        || !rule.matches.input_interfaces.is_empty()
        || !rule.matches.output_interfaces.is_empty()
    {
        return Err(FirewallRenderError::UnsupportedField(
            "NAT conntrack, ICMP type, or interface matching",
        ));
    }
    ensure_at_most_one(&rule.matches.source_zones, "NAT source zone")?;
    ensure_at_most_one(&rule.matches.destination_zones, "NAT destination zone")?;
    ensure_at_most_one(&rule.matches.source_networks, "NAT source network")?;
    ensure_at_most_one(
        &rule.matches.destination_networks,
        "NAT destination network",
    )?;
    ensure_at_most_one(&rule.matches.source_ports, "NAT source port")?;
    ensure_at_most_one(&rule.matches.destination_ports, "NAT destination port")?;
    let mut options = vec![
        ("name", rule.id.clone()),
        ("enabled", bool_value(rule.enabled)),
        ("family", family(rule.matches.family).into()),
    ];
    add_optional(&mut options, "src", rule.matches.source_zones.first());
    let protocol = protocols(&rule.matches.protocols);
    if !protocol.is_empty() {
        options.push(("proto", protocol.join(" ")));
    }
    add_optional_network(&mut options, "src_ip", rule.matches.source_networks.first());
    add_optional_port(&mut options, "src_port", rule.matches.source_ports.first());

    match rule.kind {
        FirewallNatKind::DestinationNat | FirewallNatKind::Redirect => {
            add_optional(&mut options, "dest", rule.matches.destination_zones.first());
            add_optional_network(
                &mut options,
                "src_dip",
                rule.matches.destination_networks.first(),
            );
            add_optional_port(
                &mut options,
                "src_dport",
                rule.matches.destination_ports.first(),
            );
            add_optional_ip(&mut options, "dest_ip", rule.translation_address);
            add_optional_port(&mut options, "dest_port", rule.translation_port.as_ref());
            options.push(("target", "DNAT".into()));
            add_single_set_match(&rule.matches, &mut options)?;
            Ok(RenderedObject {
                section_type: "redirect",
                options,
                lists: if rule.matches.source_macs.is_empty() {
                    Vec::new()
                } else {
                    vec![("src_mac", rule.matches.source_macs.clone())]
                },
            })
        }
        FirewallNatKind::SourceNat | FirewallNatKind::Masquerade => {
            if !rule.matches.source_sets.is_empty()
                || !rule.matches.destination_sets.is_empty()
                || !rule.matches.source_macs.is_empty()
            {
                return Err(FirewallRenderError::UnsupportedField(
                    "fw3/fw4 nat sections do not support sets or source MACs",
                ));
            }
            add_optional_network(
                &mut options,
                "dest_ip",
                rule.matches.destination_networks.first(),
            );
            add_optional_port(
                &mut options,
                "dest_port",
                rule.matches.destination_ports.first(),
            );
            add_optional_ip(&mut options, "snat_ip", rule.translation_address);
            add_optional_port(&mut options, "snat_port", rule.translation_port.as_ref());
            options.push((
                "target",
                if rule.kind == FirewallNatKind::Masquerade {
                    "MASQUERADE".into()
                } else {
                    "SNAT".into()
                },
            ));
            Ok(RenderedObject {
                section_type: "nat",
                options,
                lists: Vec::new(),
            })
        }
    }
}

fn render_rule_location(
    direction: FirewallDirection,
    matches: &FirewallMatch,
    options: &mut Vec<(&'static str, String)>,
) -> Result<(), FirewallRenderError> {
    ensure_at_most_one(&matches.source_zones, "rule source zone")?;
    ensure_at_most_one(&matches.destination_zones, "rule destination zone")?;
    ensure_at_most_one(&matches.input_interfaces, "rule input interface")?;
    ensure_at_most_one(&matches.output_interfaces, "rule output interface")?;
    match direction {
        FirewallDirection::Input => {
            if !matches.destination_zones.is_empty() || !matches.output_interfaces.is_empty() {
                return Err(FirewallRenderError::UnsupportedField(
                    "input rule destination zone or output interface",
                ));
            }
            add_optional(options, "src", matches.source_zones.first());
            if let Some(device) = matches.input_interfaces.first() {
                options.push(("device", device.clone()));
                options.push(("direction", "in".into()));
            }
        }
        FirewallDirection::Output => {
            if !matches.source_zones.is_empty() || !matches.input_interfaces.is_empty() {
                return Err(FirewallRenderError::UnsupportedField(
                    "output rule source zone or input interface",
                ));
            }
            add_optional(options, "dest", matches.destination_zones.first());
            if let Some(device) = matches.output_interfaces.first() {
                options.push(("device", device.clone()));
                options.push(("direction", "out".into()));
            }
        }
        FirewallDirection::Forward => {
            if !matches.input_interfaces.is_empty() || !matches.output_interfaces.is_empty() {
                return Err(FirewallRenderError::UnsupportedField(
                    "forward rule interface matching",
                ));
            }
            add_optional(options, "src", matches.source_zones.first());
            add_optional(options, "dest", matches.destination_zones.first());
        }
    }
    Ok(())
}

fn add_common_match_options(
    matches: &FirewallMatch,
    options: &mut Vec<(&'static str, String)>,
    allow_sets: bool,
) -> Result<(), FirewallRenderError> {
    let protocol = protocols(&matches.protocols);
    if !protocol.is_empty() {
        options.push(("proto", protocol.join(" ")));
    }
    if allow_sets {
        add_single_set_match(matches, options)?;
    }
    Ok(())
}

fn common_match_lists(
    matches: &FirewallMatch,
    include_icmp: bool,
) -> Vec<(&'static str, Vec<String>)> {
    let mut lists = Vec::new();
    add_list(
        &mut lists,
        "src_ip",
        matches.source_networks.iter().map(network),
    );
    add_list(
        &mut lists,
        "dest_ip",
        matches.destination_networks.iter().map(network),
    );
    add_list(&mut lists, "src_mac", matches.source_macs.iter().cloned());
    add_list(
        &mut lists,
        "src_port",
        matches.source_ports.iter().copied().map(port),
    );
    add_list(
        &mut lists,
        "dest_port",
        matches.destination_ports.iter().copied().map(port),
    );
    if include_icmp {
        add_list(
            &mut lists,
            "icmp_type",
            matches.icmp_types.iter().map(ToString::to_string),
        );
    }
    lists
}

fn add_single_set_match(
    matches: &FirewallMatch,
    options: &mut Vec<(&'static str, String)>,
) -> Result<(), FirewallRenderError> {
    let count = matches.source_sets.len() + matches.destination_sets.len();
    if count > 1 {
        return Err(FirewallRenderError::UnsupportedField(
            "fw3/fw4 UCI supports one set match per rule",
        ));
    }
    if let Some(value) = matches.source_sets.first() {
        options.push(("ipset", format!("{value} src")));
    } else if let Some(value) = matches.destination_sets.first() {
        options.push(("ipset", format!("{value} dest")));
    }
    Ok(())
}

fn render_set_entries(
    entries: &[FirewallSetEntry],
) -> Result<(&'static str, Vec<String>), FirewallRenderError> {
    match entries.first() {
        Some(FirewallSetEntry::Network(_)) => Ok((
            "src_net",
            entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Network(value) => Ok(network(value)),
                    _ => Err(FirewallRenderError::InvalidObject),
                })
                .collect::<Result<_, _>>()?,
        )),
        Some(FirewallSetEntry::Mac(_)) => Ok((
            "src_mac",
            entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Mac(value) => Ok(value.clone()),
                    _ => Err(FirewallRenderError::InvalidObject),
                })
                .collect::<Result<_, _>>()?,
        )),
        Some(FirewallSetEntry::Port(_)) => Ok((
            "src_port",
            entries
                .iter()
                .map(|entry| match entry {
                    FirewallSetEntry::Port(value) => Ok(port(*value)),
                    _ => Err(FirewallRenderError::InvalidObject),
                })
                .collect::<Result<_, _>>()?,
        )),
        None => Err(FirewallRenderError::InvalidObject),
    }
}

fn add_list<I>(lists: &mut Vec<(&'static str, Vec<String>)>, name: &'static str, values: I)
where
    I: Iterator<Item = String>,
{
    let values: Vec<String> = values.collect();
    if !values.is_empty() {
        lists.push((name, values));
    }
}

fn add_optional(
    options: &mut Vec<(&'static str, String)>,
    name: &'static str,
    value: Option<&String>,
) {
    if let Some(value) = value {
        options.push((name, value.clone()));
    }
}

fn add_optional_network(
    options: &mut Vec<(&'static str, String)>,
    name: &'static str,
    value: Option<&IpNetwork>,
) {
    if let Some(value) = value {
        options.push((name, network(value)));
    }
}

fn add_optional_port(
    options: &mut Vec<(&'static str, String)>,
    name: &'static str,
    value: Option<&PortRange>,
) {
    if let Some(value) = value {
        options.push((name, port(*value)));
    }
}

fn add_optional_ip(
    options: &mut Vec<(&'static str, String)>,
    name: &'static str,
    value: Option<std::net::IpAddr>,
) {
    if let Some(value) = value {
        options.push((name, value.to_string()));
    }
}

fn ensure_at_most_one<T>(values: &[T], field: &'static str) -> Result<(), FirewallRenderError> {
    if values.len() <= 1 {
        Ok(())
    } else {
        Err(FirewallRenderError::UnsupportedField(field))
    }
}

fn protocols(values: &[FirewallProtocol]) -> Vec<&'static str> {
    values
        .iter()
        .map(|value| match value {
            FirewallProtocol::Tcp => "tcp",
            FirewallProtocol::Udp => "udp",
            FirewallProtocol::Icmp => "icmp",
            FirewallProtocol::Icmpv6 => "icmpv6",
            FirewallProtocol::Esp => "esp",
            FirewallProtocol::Ah => "ah",
            FirewallProtocol::Gre => "gre",
        })
        .collect()
}

const fn family(value: FirewallFamily) -> &'static str {
    match value {
        FirewallFamily::Any => "any",
        FirewallFamily::Ipv4 => "ipv4",
        FirewallFamily::Ipv6 => "ipv6",
    }
}

const fn verdict(value: FirewallVerdict) -> &'static str {
    match value {
        FirewallVerdict::Accept => "ACCEPT",
        FirewallVerdict::Drop => "DROP",
        FirewallVerdict::Reject => "REJECT",
    }
}

fn bool_value(value: bool) -> String {
    if value { "1" } else { "0" }.into()
}

fn network(value: &IpNetwork) -> String {
    format!("{}/{}", value.address, value.prefix_len)
}

fn port(value: PortRange) -> String {
    if value.start == value.end {
        value.start.to_string()
    } else {
        format!("{}-{}", value.start, value.end)
    }
}

fn quote(value: &str) -> Result<String, FirewallRenderError> {
    if value.len() > 1024
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'\'' | b'\\'))
    {
        return Err(FirewallRenderError::UnsafeValue);
    }
    Ok(format!("'{value}'"))
}

fn agent_section_name(kind: &str, digest: &str) -> Result<String, FirewallRenderError> {
    if digest.len() < 16 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(FirewallRenderError::PlanMismatch);
    }
    let prefix = match kind {
        "zone" => "z",
        "forwarding" => "f",
        "filter_rule" => "r",
        "address_set" => "s",
        "nat_rule" => "n",
        _ => return Err(FirewallRenderError::PlanMismatch),
    };
    Ok(format!(
        "mbed_{prefix}_{}",
        &digest[..16].to_ascii_lowercase()
    ))
}

fn valid_section_type(section_type: &str, kind: &str) -> bool {
    matches!(
        (kind, section_type),
        ("zone", "zone")
            | ("forwarding", "forwarding")
            | ("filter_rule", "rule")
            | ("address_set", "ipset")
            | ("nat_rule", "redirect" | "nat")
    )
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

fn known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "zone" | "forwarding" | "filter_rule" | "address_set" | "nat_rule"
    )
}

fn object_order(object: &FirewallObject) -> Option<u32> {
    match object {
        FirewallObject::FilterRule(value) => Some(value.order),
        FirewallObject::NatRule(value) => Some(value.order),
        _ => None,
    }
}

fn supported_options(kind: &str) -> &'static [&'static str] {
    match kind {
        "zone" => &[
            "name", "enabled", "network", "input", "output", "forward", "masq", "mtu_fix",
        ],
        "forwarding" => &["name", "enabled", "src", "dest"],
        "filter_rule" => &[
            "name",
            "enabled",
            "family",
            "src",
            "dest",
            "device",
            "direction",
            "ipset",
            "proto",
            "src_ip",
            "src_mac",
            "src_port",
            "dest_ip",
            "dest_port",
            "icmp_type",
            "limit",
            "limit_burst",
            "log",
            "target",
        ],
        "address_set" => &["name", "enabled", "family", "storage", "match", "entry"],
        "nat_rule" => &[
            "name",
            "enabled",
            "family",
            "src",
            "dest",
            "ipset",
            "proto",
            "src_ip",
            "src_mac",
            "src_port",
            "src_dip",
            "src_dport",
            "dest_ip",
            "dest_port",
            "snat_ip",
            "snat_port",
            "target",
        ],
        _ => &[],
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FirewallRenderError {
    #[error("firewall write backend is unavailable")]
    BackendUnavailable,
    #[error("the selected backend is not an OpenWrt firewall backend")]
    WrongBackend,
    #[error("firewall staging input exceeds its capacity")]
    Capacity,
    #[error("firewall mutation plan contains an invalid object")]
    InvalidObject,
    #[error("firewall mutation plan metadata does not match its typed object")]
    PlanMismatch,
    #[error("firewall mutation plan is missing its typed object")]
    MissingObject,
    #[error("an existing firewall object has no fresh local UCI binding")]
    MissingBinding,
    #[error("a UCI binding contains an unsafe identifier or section selector")]
    UnsafeBinding,
    #[error("duplicate UCI object binding")]
    DuplicateBinding,
    #[error("multiple firewall objects resolve to the same UCI section")]
    DuplicateSection,
    #[error("UCI firewall inventory contains an ambiguous object binding")]
    AmbiguousBinding,
    #[error("UCI firewall inventory output is malformed")]
    MalformedUci,
    #[error("an Agent-owned UCI firewall section cannot be represented safely: {0}")]
    UnsupportedManagedSection(String),
    #[error("typed firewall inventory contains a duplicate object identity")]
    DuplicateInventoryObject,
    #[error("typed firewall inventory is ambiguous")]
    AmbiguousInventory,
    #[error("unsafe value cannot be represented in a UCI batch")]
    UnsafeValue,
    #[error("OpenWrt UCI cannot safely represent: {0}")]
    UnsupportedField(&'static str),
    #[error("failed to render the firewall staging artifact")]
    Output,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use agent_core::{
        FirewallInventory, FirewallMutation, FirewallRiskContext, firewall_object_digest,
        plan_firewall_mutations,
    };
    use agent_protocol::{
        FirewallAddressSet, FirewallConntrackState, FirewallDirection, FirewallFamily,
        FirewallFilterRule, FirewallForwarding, FirewallMatch, FirewallNatKind, FirewallNatRule,
        FirewallObject, FirewallProtocol, FirewallSetEntry, FirewallVerdict, FirewallZone,
        ObjectOwnership,
    };

    use super::*;
    use crate::firewall_inventory::inspect_openwrt_firewall_inventory;
    use crate::{
        FirewallCapabilities, InitSystem, NetworkDeviceModel, PackageManager, PlatformCapabilities,
    };

    #[test]
    fn selects_only_complete_platform_write_capabilities() {
        let mut openwrt = platform(
            PlatformKind::OpenWrt,
            FirewallBackend::Fw3,
            &["uci", "fw3", "iptables-save"],
        );
        assert_eq!(
            select_firewall_write_backend(&openwrt),
            Ok(FirewallWriteBackend::OpenWrtFw3)
        );

        openwrt.firewall.backend = FirewallBackend::Fw4;
        openwrt.available_commands = strings(&["uci", "fw4"]);
        assert_eq!(
            select_firewall_write_backend(&openwrt),
            Err(FirewallRenderError::BackendUnavailable)
        );
        openwrt.available_commands.push("nft".into());
        assert_eq!(
            select_firewall_write_backend(&openwrt),
            Ok(FirewallWriteBackend::OpenWrtFw4)
        );

        let linux = platform(
            PlatformKind::GenericLinux,
            FirewallBackend::Iptables,
            &[
                "iptables-save",
                "ip6tables-save",
                "iptables-restore",
                "ip6tables-restore",
            ],
        );
        assert_eq!(
            select_firewall_write_backend(&linux),
            Ok(FirewallWriteBackend::LinuxIptables)
        );
    }

    #[test]
    fn fw3_renders_bounded_mac_network_and_port_rule() {
        let object = FirewallObject::FilterRule(FirewallFilterRule {
            id: "block-camera".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Forward,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["lan".into()],
                destination_zones: vec!["wan".into()],
                source_networks: vec![network4([192, 168, 8, 0], 24)],
                source_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
                protocols: vec![FirewallProtocol::Tcp, FirewallProtocol::Udp],
                destination_ports: vec![PortRange {
                    start: 443,
                    end: 445,
                }],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order: 20,
        });
        let plan = create_plan(&base_inventory(), vec![object]);
        let stage =
            render_openwrt_firewall_stage(&plan, &[], FirewallBackend::Fw3).expect("render fw3");

        assert_eq!(
            stage.validations,
            vec![
                OpenWrtValidation::Fw3PrintIpv4,
                OpenWrtValidation::Fw3PrintIpv6
            ]
        );
        assert!(stage.uci_batch.contains("set firewall.mbed_r_"));
        assert!(stage.uci_batch.contains(".src='lan'"));
        assert!(stage.uci_batch.contains(".dest='wan'"));
        assert!(stage.uci_batch.contains(".proto='tcp udp'"));
        assert!(stage.uci_batch.contains(".src_ip='192.168.8.0/24'"));
        assert!(stage.uci_batch.contains(".src_mac='aa:bb:cc:dd:ee:ff'"));
        assert!(stage.uci_batch.contains(".dest_port='443-445'"));
        assert!(stage.uci_batch.ends_with("commit firewall\n"));
    }

    #[test]
    fn fw4_renders_address_set_and_reference_without_fw3_storage() {
        let set = FirewallObject::AddressSet(FirewallAddressSet {
            id: "blocked-nets".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: FirewallFamily::Ipv4,
            entries: vec![
                FirewallSetEntry::Network(network4([198, 51, 100, 0], 24)),
                FirewallSetEntry::Network(network4([203, 0, 113, 0], 24)),
            ],
        });
        let rule = FirewallObject::FilterRule(FirewallFilterRule {
            id: "block-set".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["wan".into()],
                source_sets: vec!["blocked-nets".into()],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order: 30,
        });
        let plan = create_plan(&base_inventory(), vec![set, rule]);
        let stage =
            render_openwrt_firewall_stage(&plan, &[], FirewallBackend::Fw4).expect("render fw4");

        assert_eq!(stage.validations, vec![OpenWrtValidation::Fw4Check]);
        assert!(stage.uci_batch.contains("=ipset\n"));
        assert!(stage.uci_batch.contains(".match='src_net'"));
        assert!(stage.uci_batch.contains(".entry='198.51.100.0/24'"));
        assert!(stage.uci_batch.contains(".ipset='blocked-nets src'"));
        assert!(!stage.uci_batch.contains(".storage="));
    }

    #[test]
    fn fresh_snapshot_reserves_even_a_conflicting_existing_managed_section() {
        let desired = FirewallObject::FilterRule(FirewallFilterRule {
            id: "new-rule".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch::default(),
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order: 10,
        });
        let digest = firewall_object_digest(&desired).expect("digest");
        let section = format!("mbed_r_{}", &digest[..16]);
        let show = format!(
            "firewall.{section}=rule\n\
             firewall.{section}.name='existing-rule'\n\
             firewall.{section}.enabled='1'\n\
             firewall.{section}.family='any'\n\
             firewall.{section}.target='DROP'\n"
        );
        let snapshot = inspect_openwrt_firewall_inventory(&show).expect("fresh snapshot");
        let plan = plan_firewall_mutations(
            snapshot.inventory(),
            &[FirewallMutation::Create(desired)],
            &FirewallRiskContext::default(),
        )
        .expect("plan");
        assert_eq!(
            render_openwrt_firewall_stage_from_snapshot(&plan, &snapshot, FirewallBackend::Fw4),
            Err(FirewallRenderError::DuplicateSection)
        );
        let mut forged = plan;
        forged.changes[0].diff.after_digest = Some("f".repeat(64));
        assert_eq!(
            render_openwrt_firewall_stage_from_snapshot(&forged, &snapshot, FirewallBackend::Fw4),
            Err(FirewallRenderError::PlanMismatch)
        );
    }

    #[test]
    fn updates_anonymous_zone_without_deleting_unknown_options() {
        let inventory = base_inventory();
        let before = inventory.objects[0].clone();
        let mut after = before.clone();
        let FirewallObject::Zone(zone) = &mut after else {
            panic!("zone fixture");
        };
        zone.input = FirewallVerdict::Drop;
        zone.networks.push("guest".into());
        let plan = plan_firewall_mutations(
            &inventory,
            &[FirewallMutation::Update {
                expected_digest: firewall_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &FirewallRiskContext::default(),
        )
        .expect("plan");
        let binding = OpenWrtObjectBinding {
            kind: "zone".into(),
            id: "lan".into(),
            section_type: "zone".into(),
            section: "@zone[0]".into(),
            present_options: strings(&["name", "network", "input", "vendor_extension"]),
        };
        let stage =
            render_openwrt_firewall_stage(&plan, &[binding], FirewallBackend::Fw4).expect("render");

        assert!(stage.uci_batch.contains("delete firewall.@zone[0].network"));
        assert!(stage.uci_batch.contains("delete firewall.@zone[0].input"));
        assert!(!stage.uci_batch.contains("delete firewall.@zone[0].vendor"));
        assert!(
            stage
                .uci_batch
                .contains("add_list firewall.@zone[0].network='guest'")
        );
    }

    #[test]
    fn resolves_bindings_from_fresh_uci_show_and_typed_inventory() {
        let mut inventory = base_inventory();
        inventory
            .objects
            .push(FirewallObject::FilterRule(FirewallFilterRule {
                id: "platform-rule-0".into(),
                ownership: ObjectOwnership::PlatformNative,
                enabled: true,
                direction: FirewallDirection::Input,
                matches: FirewallMatch::default(),
                verdict: FirewallVerdict::Drop,
                reject_with: None,
                rate_limit: None,
                log: None,
                order: 1,
            }));
        let show = "\
firewall.@defaults[0]=defaults
firewall.@defaults[0].input='REJECT'
firewall.custom_include=include
firewall.custom_include.path='/etc/firewall.user'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan' 'guest'
firewall.wan=zone
firewall.wan.name='wan'
firewall.wan.network='wan'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.@rule[0]=rule
firewall.@rule[0].target='DROP'
";
        let bindings = inspect_openwrt_object_bindings(show, &inventory).expect("inspect bindings");

        assert_eq!(bindings.len(), 4);
        let lan = bindings
            .iter()
            .find(|binding| binding.id == "lan")
            .expect("lan binding");
        assert_eq!(lan.section, "@zone[0]");
        assert_eq!(
            lan.present_options,
            strings(&["name", "network"]),
            "option names are deterministic"
        );
        assert!(
            bindings
                .iter()
                .any(|binding| binding.id == "lan-wan" && binding.section == "@forwarding[0]")
        );
        assert!(
            bindings
                .iter()
                .any(|binding| binding.id == "platform-rule-0" && binding.section == "@rule[0]")
        );
    }

    #[test]
    fn fails_closed_on_ambiguous_or_malformed_uci_inventory() {
        let ambiguous = "\
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.@forwarding[1]=forwarding
firewall.@forwarding[1].src='lan'
firewall.@forwarding[1].dest='wan'
";
        let inventory = FirewallInventory {
            objects: vec![base_inventory().objects[2].clone()],
        };
        assert_eq!(
            inspect_openwrt_object_bindings(ambiguous, &inventory),
            Err(FirewallRenderError::AmbiguousBinding)
        );
        assert_eq!(
            inspect_openwrt_object_bindings(
                "firewall.@zone[0];delete=zone\n",
                &FirewallInventory { objects: vec![] }
            ),
            Err(FirewallRenderError::MalformedUci)
        );
    }

    #[test]
    fn rejects_injected_or_wrong_type_section_bindings() {
        let before = base_inventory().objects[0].clone();
        let plan = delete_plan(&FirewallInventory {
            objects: vec![before.clone()],
        });
        let injected = OpenWrtObjectBinding {
            kind: "zone".into(),
            id: "lan".into(),
            section_type: "zone".into(),
            section: "@zone[0];delete firewall".into(),
            present_options: vec![],
        };
        assert_eq!(
            render_openwrt_firewall_stage(&plan, &[injected], FirewallBackend::Fw4),
            Err(FirewallRenderError::UnsafeBinding)
        );
        let wrong_type = OpenWrtObjectBinding {
            kind: "zone".into(),
            id: "lan".into(),
            section_type: "rule".into(),
            section: "@rule[0]".into(),
            present_options: vec![],
        };
        assert_eq!(
            render_openwrt_firewall_stage(&plan, &[wrong_type], FirewallBackend::Fw4),
            Err(FirewallRenderError::UnsafeBinding)
        );
    }

    #[test]
    fn renders_destination_and_source_nat_as_distinct_uci_sections() {
        let destination = FirewallObject::NatRule(FirewallNatRule {
            id: "https-to-server".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            kind: FirewallNatKind::DestinationNat,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                source_zones: vec!["wan".into()],
                destination_zones: vec!["lan".into()],
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
            order: 40,
        });
        let source = FirewallObject::NatRule(FirewallNatRule {
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
            order: 50,
        });
        let plan = create_plan(&base_inventory(), vec![destination, source]);
        let stage =
            render_openwrt_firewall_stage(&plan, &[], FirewallBackend::Fw4).expect("render NAT");

        assert!(stage.uci_batch.contains("=redirect\n"));
        assert!(stage.uci_batch.contains(".src_dport='8443'"));
        assert!(stage.uci_batch.contains(".dest_ip='192.168.1.10'"));
        assert!(stage.uci_batch.contains(".dest_port='443'"));
        assert!(stage.uci_batch.contains("=nat\n"));
        assert!(stage.uci_batch.contains(".snat_ip='203.0.113.8'"));
        assert!(stage.uci_batch.contains(".target='SNAT'"));
    }

    #[test]
    fn rejects_semantics_that_uci_cannot_preserve() {
        let object = FirewallObject::FilterRule(FirewallFilterRule {
            id: "stateful".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch {
                family: FirewallFamily::Ipv4,
                conntrack_states: vec![FirewallConntrackState::New],
                ..FirewallMatch::default()
            },
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order: 60,
        });
        let plan = create_plan(&base_inventory(), vec![object]);
        assert_eq!(
            render_openwrt_firewall_stage(&plan, &[], FirewallBackend::Fw4),
            Err(FirewallRenderError::UnsupportedField(
                "conntrack state requires an unmanaged raw expression"
            ))
        );
    }

    #[test]
    fn move_uses_only_the_fresh_bound_section() {
        let before = FirewallObject::FilterRule(FirewallFilterRule {
            id: "ordered".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            direction: FirewallDirection::Input,
            matches: FirewallMatch::default(),
            verdict: FirewallVerdict::Drop,
            reject_with: None,
            rate_limit: None,
            log: None,
            order: 10,
        });
        let mut after = before.clone();
        let FirewallObject::FilterRule(rule) = &mut after else {
            panic!("rule fixture");
        };
        rule.order = 3;
        let inventory = FirewallInventory {
            objects: vec![before.clone()],
        };
        let plan = plan_firewall_mutations(
            &inventory,
            &[FirewallMutation::Move {
                expected_digest: firewall_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &FirewallRiskContext::default(),
        )
        .expect("plan move");
        let binding = OpenWrtObjectBinding {
            kind: "filter_rule".into(),
            id: "ordered".into(),
            section_type: "rule".into(),
            section: "@rule[2]".into(),
            present_options: vec![],
        };
        let stage =
            render_openwrt_firewall_stage(&plan, &[binding], FirewallBackend::Fw3).expect("render");
        assert_eq!(
            stage.uci_batch,
            "reorder firewall.@rule[2]=3\ncommit firewall\n"
        );
    }

    fn create_plan(
        inventory: &FirewallInventory,
        objects: Vec<FirewallObject>,
    ) -> FirewallMutationPlan {
        let mutations: Vec<FirewallMutation> =
            objects.into_iter().map(FirewallMutation::Create).collect();
        plan_firewall_mutations(inventory, &mutations, &FirewallRiskContext::default())
            .expect("create plan")
    }

    fn delete_plan(inventory: &FirewallInventory) -> FirewallMutationPlan {
        let object = inventory.objects[0].clone();
        plan_firewall_mutations(
            inventory,
            &[FirewallMutation::Delete {
                kind: object.kind().into(),
                id: object.id().into(),
                expected_digest: firewall_object_digest(&object).expect("digest"),
            }],
            &FirewallRiskContext::default(),
        )
        .expect("delete plan")
    }

    fn base_inventory() -> FirewallInventory {
        FirewallInventory {
            objects: vec![
                FirewallObject::Zone(FirewallZone {
                    id: "lan".into(),
                    ownership: ObjectOwnership::PlatformNative,
                    enabled: true,
                    networks: vec!["lan".into()],
                    input: FirewallVerdict::Accept,
                    output: FirewallVerdict::Accept,
                    forward: FirewallVerdict::Accept,
                    masquerade: false,
                    mtu_fix: false,
                }),
                FirewallObject::Zone(FirewallZone {
                    id: "wan".into(),
                    ownership: ObjectOwnership::PlatformNative,
                    enabled: true,
                    networks: vec!["wan".into()],
                    input: FirewallVerdict::Drop,
                    output: FirewallVerdict::Accept,
                    forward: FirewallVerdict::Drop,
                    masquerade: true,
                    mtu_fix: true,
                }),
                FirewallObject::Forwarding(FirewallForwarding {
                    id: "lan-wan".into(),
                    ownership: ObjectOwnership::PlatformNative,
                    enabled: true,
                    source_zone: "lan".into(),
                    destination_zone: "wan".into(),
                }),
            ],
        }
    }

    fn network4(octets: [u8; 4], prefix_len: u8) -> IpNetwork {
        IpNetwork {
            address: IpAddr::V4(Ipv4Addr::from(octets)),
            prefix_len,
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    fn platform(
        kind: PlatformKind,
        backend: FirewallBackend,
        commands: &[&str],
    ) -> PlatformCapabilities {
        PlatformCapabilities {
            kind,
            release: None,
            release_supported: true,
            firewall: FirewallCapabilities {
                backend,
                has_iptables_save: commands.contains(&"iptables-save"),
                has_ip6tables_save: commands.contains(&"ip6tables-save"),
                has_nft: commands.contains(&"nft"),
                can_trace: false,
            },
            device_model: NetworkDeviceModel::Unknown,
            package_manager: PackageManager::Unknown,
            init_system: InitSystem::Unknown,
            has_ubus: false,
            has_uci: commands.contains(&"uci"),
            has_procd: false,
            available_commands: strings(commands),
            warnings: vec![],
        }
    }
}
