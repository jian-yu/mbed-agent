//! Bounded `OpenWrt` UCI inventory and staging for typed physical radios.
//!
//! This module never installs `/etc/config/wireless` and never reloads a radio. It reconstructs
//! a strict radio subset from one fresh `uci show wireless` result and renders an update batch for
//! a private staging directory under `/tmp`. Wireless interfaces, SSIDs, and credentials remain
//! outside this slice.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use agent_core::{
    WirelessInventory, WirelessMutationPlan, validate_wireless_object, wireless_object_digest,
};
use agent_protocol::{
    ChangeOperation, ObjectOwnership, RiskLevel, WirelessBand, WirelessChannel,
    WirelessChannelWidth, WirelessObject, WirelessRadioConfig,
};
use thiserror::Error;

use crate::firewall::FirewallRenderError;
use crate::firewall_uci::{UciSection, parse_uci_show_package, safe_uci_identifier, valid_section};
use crate::{PlatformCapabilities, PlatformKind};

const MAX_BINDINGS: usize = 64;
const MAX_PRESENT_OPTIONS: usize = 64;
const MAX_BATCH_BYTES: usize = 64 * 1024;
const MAX_UCI_VALUE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenWrtWirelessBandEncoding {
    Band,
    HwMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenWrtWirelessHtModeFamily {
    Ht,
    Vht,
    He,
    Eht,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtWirelessObjectBinding {
    pub id: String,
    pub section: String,
    pub present_options: Vec<String>,
    pub band_encoding: OpenWrtWirelessBandEncoding,
    pub band_value: String,
    pub htmode: Option<String>,
    pub htmode_family: Option<OpenWrtWirelessHtModeFamily>,
}

/// One bounded, internally consistent view of the current `OpenWrt` wireless package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtWirelessInventorySnapshot {
    inventory: WirelessInventory,
    bindings: Vec<OpenWrtWirelessObjectBinding>,
    occupied_sections: Vec<String>,
    read_only_sections: Vec<String>,
}

impl OpenWrtWirelessInventorySnapshot {
    #[must_use]
    pub fn inventory(&self) -> &WirelessInventory {
        &self.inventory
    }

    #[must_use]
    pub fn bindings(&self) -> &[OpenWrtWirelessObjectBinding] {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenWrtWirelessValidation {
    /// Parse and export the staged package with `uci -c <staging-dir> export wireless`.
    UciExport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenWrtWirelessStage {
    pub uci_batch: String,
    pub validations: Vec<OpenWrtWirelessValidation>,
    pub activation_program: &'static str,
    pub activation_argument: &'static str,
}

/// Selects staging only for supported `OpenWrt` releases with the UCI executable available.
///
/// # Errors
///
/// Returns an error for generic Linux, `OpenWrt` before 21, or a missing UCI command.
pub fn select_openwrt_wireless_staging(
    capabilities: &PlatformCapabilities,
) -> Result<(), WirelessRenderError> {
    let has_uci_command = capabilities
        .available_commands
        .iter()
        .any(|command| command == "uci");
    if capabilities.kind == PlatformKind::OpenWrt
        && capabilities.release_supported
        && capabilities.has_uci
        && has_uci_command
    {
        Ok(())
    } else {
        Err(WirelessRenderError::BackendUnavailable)
    }
}

/// Reconstructs supported radios and exact bindings from one fresh UCI snapshot.
///
/// Only named `wifi-device` sections using the mac80211 backend are writable candidates. Every
/// other section, including all `wifi-iface` sections, is reported as read-only and is never
/// included in the typed inventory.
///
/// # Errors
///
/// Returns an error for malformed or oversized UCI output, duplicate identities, or capacity
/// overflow. Unsupported vendor/device shapes remain read-only.
pub fn inspect_openwrt_wireless_inventory(
    uci_show: &str,
) -> Result<OpenWrtWirelessInventorySnapshot, WirelessRenderError> {
    let sections = parse_wireless(uci_show)?;
    let mut objects = Vec::new();
    let mut bindings = Vec::new();
    let mut read_only_sections = Vec::new();
    let mut identities = HashSet::new();

    for section in &sections {
        if section.section_type != "wifi-device"
            || section.selector.starts_with("mbed_")
            || section.options.contains_key("mbed_managed")
        {
            read_only_sections.push(section.selector.clone());
            continue;
        }
        let Some((object, band_encoding, band_value, htmode, htmode_family)) =
            decode_radio(section)
        else {
            read_only_sections.push(section.selector.clone());
            continue;
        };
        if validate_wireless_object(&object).is_err() {
            read_only_sections.push(section.selector.clone());
            continue;
        }
        if !identities.insert((object.kind().to_owned(), object.id().to_owned())) {
            return Err(WirelessRenderError::DuplicateInventoryObject);
        }
        if section.options.len() > MAX_PRESENT_OPTIONS {
            return Err(WirelessRenderError::Capacity);
        }
        let mut present_options: Vec<_> = section.options.keys().cloned().collect();
        present_options.sort_unstable();
        bindings.push(OpenWrtWirelessObjectBinding {
            id: object.id().to_owned(),
            section: section.selector.clone(),
            present_options,
            band_encoding,
            band_value,
            htmode,
            htmode_family,
        });
        objects.push(object);
    }
    if objects.len() > MAX_BINDINGS {
        return Err(WirelessRenderError::Capacity);
    }
    Ok(OpenWrtWirelessInventorySnapshot {
        inventory: WirelessInventory { objects },
        bindings,
        occupied_sections: sections
            .iter()
            .map(|section| section.selector.clone())
            .collect(),
        read_only_sections,
    })
}

/// Renders an approved radio update plan against the exact fresh UCI snapshot.
///
/// The output is input only for `uci -c <private-/tmp-dir> batch`. Unknown device options and all
/// wireless interface sections are preserved because the batch touches only the supported radio
/// fields on the exact bound section.
///
/// # Errors
///
/// Returns an error for stale plan content, unsafe bindings, unsupported band/PHY combinations,
/// invalid objects, or bounded output overflow.
pub fn render_openwrt_wireless_stage_from_snapshot(
    plan: &WirelessMutationPlan,
    snapshot: &OpenWrtWirelessInventorySnapshot,
) -> Result<OpenWrtWirelessStage, WirelessRenderError> {
    validate_plan_against_snapshot(plan, snapshot)?;
    let bindings = validate_bindings(snapshot.bindings())?;
    let mut batch = String::new();
    for change in &plan.changes {
        let key = (change.before.kind(), change.before.id());
        let binding = bindings
            .get(&key)
            .copied()
            .ok_or(WirelessRenderError::MissingBinding)?;
        render_radio_update(&mut batch, binding, &change.before, &change.after)?;
        if batch.len() > MAX_BATCH_BYTES {
            return Err(WirelessRenderError::Capacity);
        }
    }
    batch.push_str("commit wireless\n");
    Ok(OpenWrtWirelessStage {
        uci_batch: batch,
        validations: vec![OpenWrtWirelessValidation::UciExport],
        activation_program: "/sbin/wifi",
        activation_argument: "reload",
    })
}

fn parse_wireless(input: &str) -> Result<Vec<UciSection>, WirelessRenderError> {
    parse_uci_show_package(input, "wireless").map_err(|error| match error {
        FirewallRenderError::Capacity => WirelessRenderError::Capacity,
        _ => WirelessRenderError::MalformedUci,
    })
}

#[allow(clippy::type_complexity)]
fn decode_radio(
    section: &UciSection,
) -> Option<(
    WirelessObject,
    OpenWrtWirelessBandEncoding,
    String,
    Option<String>,
    Option<OpenWrtWirelessHtModeFamily>,
)> {
    if !safe_uci_identifier(&section.selector)
        || section.first("type") != Some("mac80211")
        || !supported_fields_are_scalar(section)
    {
        return None;
    }
    let (band, band_encoding, band_value) = match (section.first("band"), section.first("hwmode")) {
        (Some(raw), None) => (
            decode_band(raw)?,
            OpenWrtWirelessBandEncoding::Band,
            raw.to_owned(),
        ),
        (None, Some(raw)) => (
            decode_hwmode(raw)?,
            OpenWrtWirelessBandEncoding::HwMode,
            raw.to_owned(),
        ),
        _ => return None,
    };
    let htmode = section.first("htmode").map(str::to_owned);
    let (width, htmode_family) = match htmode.as_deref() {
        None => (WirelessChannelWidth::Auto, None),
        Some(raw) => decode_htmode(raw)?,
    };
    let channel = match section.first("channel") {
        None | Some("auto") => WirelessChannel::Auto,
        Some(raw) => WirelessChannel::Fixed {
            channel: raw.parse().ok()?,
        },
    };
    let radio = WirelessObject::Radio(WirelessRadioConfig {
        id: section.selector.clone(),
        ownership: ObjectOwnership::PlatformNative,
        enabled: !decode_disabled(section.first("disabled"))?,
        band,
        channel,
        width,
        country: section.first("country").map(str::to_owned),
        tx_power_dbm: section.first("txpower").map(str::parse).transpose().ok()?,
    });
    Some((radio, band_encoding, band_value, htmode, htmode_family))
}

fn supported_fields_are_scalar(section: &UciSection) -> bool {
    [
        "type", "disabled", "band", "hwmode", "channel", "htmode", "country", "txpower",
    ]
    .iter()
    .all(|name| {
        section
            .options
            .get(*name)
            .is_none_or(|values| values.len() == 1)
    })
}

fn decode_band(raw: &str) -> Option<WirelessBand> {
    match raw {
        "2g" => Some(WirelessBand::Ghz2),
        "5g" => Some(WirelessBand::Ghz5),
        "6g" => Some(WirelessBand::Ghz6),
        _ => None,
    }
}

fn decode_hwmode(raw: &str) -> Option<WirelessBand> {
    match raw {
        "11g" => Some(WirelessBand::Ghz2),
        "11a" => Some(WirelessBand::Ghz5),
        _ => None,
    }
}

fn decode_htmode(raw: &str) -> Option<(WirelessChannelWidth, Option<OpenWrtWirelessHtModeFamily>)> {
    let (family, suffix) = if let Some(value) = raw.strip_prefix("EHT") {
        (OpenWrtWirelessHtModeFamily::Eht, value)
    } else if let Some(value) = raw.strip_prefix("VHT") {
        (OpenWrtWirelessHtModeFamily::Vht, value)
    } else if let Some(value) = raw.strip_prefix("HT") {
        (OpenWrtWirelessHtModeFamily::Ht, value)
    } else if let Some(value) = raw.strip_prefix("HE") {
        (OpenWrtWirelessHtModeFamily::He, value)
    } else {
        return None;
    };
    let width = match suffix {
        "20" => WirelessChannelWidth::Mhz20,
        "40" | "40+" | "40-" => WirelessChannelWidth::Mhz40,
        "80" => WirelessChannelWidth::Mhz80,
        "160" => WirelessChannelWidth::Mhz160,
        _ => return None,
    };
    Some((width, Some(family)))
}

fn decode_disabled(raw: Option<&str>) -> Option<bool> {
    match raw {
        None | Some("0") => Some(false),
        Some("1") => Some(true),
        _ => None,
    }
}

fn validate_plan_against_snapshot(
    plan: &WirelessMutationPlan,
    snapshot: &OpenWrtWirelessInventorySnapshot,
) -> Result<(), WirelessRenderError> {
    if plan.risk != RiskLevel::R3 || plan.changes.is_empty() || plan.changes.len() > 16 {
        return Err(WirelessRenderError::PlanMismatch);
    }
    let inventory: HashMap<(&str, &str), &WirelessObject> = snapshot
        .inventory()
        .objects
        .iter()
        .map(|object| ((object.kind(), object.id()), object))
        .collect();
    if inventory.len() != snapshot.inventory().objects.len() {
        return Err(WirelessRenderError::DuplicateInventoryObject);
    }
    let mut touched = HashSet::new();
    for change in &plan.changes {
        let key = (change.before.kind(), change.before.id());
        validate_wireless_object(&change.before).map_err(|_| WirelessRenderError::InvalidObject)?;
        validate_wireless_object(&change.after).map_err(|_| WirelessRenderError::InvalidObject)?;
        let before_digest = wireless_object_digest(&change.before)
            .map_err(|_| WirelessRenderError::InvalidObject)?;
        let after_digest = wireless_object_digest(&change.after)
            .map_err(|_| WirelessRenderError::InvalidObject)?;
        if !touched.insert(key)
            || change.diff.object.domain != agent_protocol::ConfigDomain::Wireless
            || change.diff.object.kind != key.0
            || change.diff.object.id != key.1
            || change.diff.object.ownership != ObjectOwnership::PlatformNative
            || change.diff.object.expected_version.as_deref() != Some(before_digest.as_str())
            || change.diff.operation != ChangeOperation::Update
            || change.diff.before_digest.as_deref() != Some(before_digest.as_str())
            || change.diff.after_digest.as_deref() != Some(after_digest.as_str())
            || change.before.kind() != change.after.kind()
            || change.before.id() != change.after.id()
            || inventory.get(&key).copied() != Some(&change.before)
        {
            return Err(WirelessRenderError::PlanMismatch);
        }
    }
    Ok(())
}

fn validate_bindings(
    bindings: &[OpenWrtWirelessObjectBinding],
) -> Result<HashMap<(&str, &str), &OpenWrtWirelessObjectBinding>, WirelessRenderError> {
    if bindings.len() > MAX_BINDINGS {
        return Err(WirelessRenderError::Capacity);
    }
    let mut indexed = HashMap::new();
    let mut sections = HashSet::new();
    for binding in bindings {
        if !safe_uci_identifier(&binding.id)
            || !valid_section(&binding.section, "wifi-device")
            || binding.id != binding.section
            || binding.present_options.len() > MAX_PRESENT_OPTIONS
            || !binding
                .present_options
                .iter()
                .all(|option| safe_uci_identifier(option))
            || !safe_value(&binding.band_value)
            || binding
                .htmode
                .as_deref()
                .is_some_and(|value| !safe_value(value))
        {
            return Err(WirelessRenderError::UnsafeBinding);
        }
        if indexed
            .insert(("radio", binding.id.as_str()), binding)
            .is_some()
        {
            return Err(WirelessRenderError::DuplicateBinding);
        }
        if !sections.insert(binding.section.as_str()) {
            return Err(WirelessRenderError::DuplicateSection);
        }
    }
    Ok(indexed)
}

fn render_radio_update(
    batch: &mut String,
    binding: &OpenWrtWirelessObjectBinding,
    before: &WirelessObject,
    after: &WirelessObject,
) -> Result<(), WirelessRenderError> {
    let WirelessObject::Radio(before) = before;
    let WirelessObject::Radio(after) = after;
    validate_backend_semantics(binding, before, after)?;
    for option in &binding.present_options {
        if mutable_radio_options().contains(&option.as_str()) {
            writeln!(batch, "delete wireless.{}.{}", binding.section, option)
                .map_err(|_| WirelessRenderError::Output)?;
        }
    }
    let band_value = if before.band == after.band {
        binding.band_value.as_str()
    } else {
        encode_band(binding.band_encoding, after.band)?
    };
    let band_option = match binding.band_encoding {
        OpenWrtWirelessBandEncoding::Band => "band",
        OpenWrtWirelessBandEncoding::HwMode => "hwmode",
    };
    render_option(
        batch,
        &binding.section,
        "disabled",
        bool_value(!after.enabled),
    )?;
    render_option(batch, &binding.section, band_option, band_value)?;
    let channel = match after.channel {
        WirelessChannel::Auto => "auto".to_owned(),
        WirelessChannel::Fixed { channel } => channel.to_string(),
    };
    render_option(batch, &binding.section, "channel", &channel)?;
    if let Some(htmode) = encode_htmode(binding, before, after)? {
        render_option(batch, &binding.section, "htmode", &htmode)?;
    }
    if let Some(country) = &after.country {
        render_option(batch, &binding.section, "country", country)?;
    }
    if let Some(tx_power) = after.tx_power_dbm {
        render_option(batch, &binding.section, "txpower", &tx_power.to_string())?;
    }
    Ok(())
}

fn validate_backend_semantics(
    binding: &OpenWrtWirelessObjectBinding,
    before: &WirelessRadioConfig,
    after: &WirelessRadioConfig,
) -> Result<(), WirelessRenderError> {
    if before.id != binding.id
        || before.ownership != ObjectOwnership::PlatformNative
        || after.ownership != ObjectOwnership::PlatformNative
        || (binding.band_encoding == OpenWrtWirelessBandEncoding::HwMode
            && after.band == WirelessBand::Ghz6)
    {
        return Err(WirelessRenderError::UnsupportedSemantics);
    }
    if let Some(family) = binding.htmode_family {
        if !family_supports(family, after.band, after.width) {
            return Err(WirelessRenderError::UnsupportedSemantics);
        }
    }
    Ok(())
}

fn family_supports(
    family: OpenWrtWirelessHtModeFamily,
    band: WirelessBand,
    width: WirelessChannelWidth,
) -> bool {
    if width == WirelessChannelWidth::Auto {
        return true;
    }
    match family {
        OpenWrtWirelessHtModeFamily::Ht => {
            band != WirelessBand::Ghz6
                && matches!(
                    width,
                    WirelessChannelWidth::Mhz20 | WirelessChannelWidth::Mhz40
                )
        }
        OpenWrtWirelessHtModeFamily::Vht => band == WirelessBand::Ghz5,
        OpenWrtWirelessHtModeFamily::He | OpenWrtWirelessHtModeFamily::Eht => true,
    }
}

fn encode_band(
    encoding: OpenWrtWirelessBandEncoding,
    band: WirelessBand,
) -> Result<&'static str, WirelessRenderError> {
    match (encoding, band) {
        (OpenWrtWirelessBandEncoding::Band, WirelessBand::Ghz2) => Ok("2g"),
        (OpenWrtWirelessBandEncoding::Band, WirelessBand::Ghz5) => Ok("5g"),
        (OpenWrtWirelessBandEncoding::Band, WirelessBand::Ghz6) => Ok("6g"),
        (OpenWrtWirelessBandEncoding::HwMode, WirelessBand::Ghz2) => Ok("11g"),
        (OpenWrtWirelessBandEncoding::HwMode, WirelessBand::Ghz5) => Ok("11a"),
        (OpenWrtWirelessBandEncoding::HwMode, WirelessBand::Ghz6) => {
            Err(WirelessRenderError::UnsupportedSemantics)
        }
    }
}

fn encode_htmode(
    binding: &OpenWrtWirelessObjectBinding,
    before: &WirelessRadioConfig,
    after: &WirelessRadioConfig,
) -> Result<Option<String>, WirelessRenderError> {
    if after.width == WirelessChannelWidth::Auto {
        return Ok(None);
    }
    if before.width == after.width {
        if let Some(current) = &binding.htmode {
            return Ok(Some(current.clone()));
        }
    }
    let family = binding
        .htmode_family
        .unwrap_or_else(|| default_htmode_family(after.band));
    if !family_supports(family, after.band, after.width) {
        return Err(WirelessRenderError::UnsupportedSemantics);
    }
    let prefix = match family {
        OpenWrtWirelessHtModeFamily::Ht => "HT",
        OpenWrtWirelessHtModeFamily::Vht => "VHT",
        OpenWrtWirelessHtModeFamily::He => "HE",
        OpenWrtWirelessHtModeFamily::Eht => "EHT",
    };
    let width = match after.width {
        WirelessChannelWidth::Auto => return Ok(None),
        WirelessChannelWidth::Mhz20 => "20",
        WirelessChannelWidth::Mhz40 => "40",
        WirelessChannelWidth::Mhz80 => "80",
        WirelessChannelWidth::Mhz160 => "160",
    };
    Ok(Some(format!("{prefix}{width}")))
}

fn default_htmode_family(band: WirelessBand) -> OpenWrtWirelessHtModeFamily {
    match band {
        WirelessBand::Ghz2 => OpenWrtWirelessHtModeFamily::Ht,
        WirelessBand::Ghz5 => OpenWrtWirelessHtModeFamily::Vht,
        WirelessBand::Ghz6 => OpenWrtWirelessHtModeFamily::He,
    }
}

fn mutable_radio_options() -> &'static [&'static str] {
    &[
        "disabled", "band", "hwmode", "channel", "htmode", "country", "txpower",
    ]
}

fn render_option(
    batch: &mut String,
    section: &str,
    name: &str,
    value: &str,
) -> Result<(), WirelessRenderError> {
    if !safe_uci_identifier(section) || !safe_uci_identifier(name) || !safe_value(value) {
        return Err(WirelessRenderError::UnsupportedValue);
    }
    writeln!(batch, "set wireless.{section}.{name}='{value}'")
        .map_err(|_| WirelessRenderError::Output)
}

fn safe_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_UCI_VALUE_BYTES
        && !value
            .bytes()
            .any(|byte| byte == b'\'' || byte == b'\\' || byte.is_ascii_control())
}

const fn bool_value(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WirelessRenderError {
    #[error("OpenWrt wireless staging backend is unavailable")]
    BackendUnavailable,
    #[error("wireless UCI input is malformed")]
    MalformedUci,
    #[error("wireless inventory or stage exceeds its capacity")]
    Capacity,
    #[error("wireless inventory contains a duplicate typed object")]
    DuplicateInventoryObject,
    #[error("wireless bindings contain a duplicate object")]
    DuplicateBinding,
    #[error("wireless bindings contain a duplicate section")]
    DuplicateSection,
    #[error("wireless binding is unsafe")]
    UnsafeBinding,
    #[error("wireless plan has no exact fresh binding")]
    MissingBinding,
    #[error("wireless object is invalid")]
    InvalidObject,
    #[error("wireless plan does not match the fresh inventory")]
    PlanMismatch,
    #[error("wireless semantics are unsupported by the bound OpenWrt representation")]
    UnsupportedSemantics,
    #[error("wireless value cannot be represented safely in UCI")]
    UnsupportedValue,
    #[error("failed to render wireless UCI batch")]
    Output,
}

#[cfg(test)]
mod tests {
    use agent_core::{WirelessMutation, WirelessRiskContext, plan_wireless_mutations};

    use super::*;

    const OPENWRT_21_WIRELESS: &str = "wireless.radio0=wifi-device\n\
         wireless.radio0.type='mac80211'\n\
         wireless.radio0.path='platform/ahb/18100000.wmac'\n\
         wireless.radio0.hwmode='11a'\n\
         wireless.radio0.channel='36'\n\
         wireless.radio0.htmode='VHT80'\n\
         wireless.radio0.country='CN'\n\
         wireless.radio0.txpower='20'\n\
         wireless.default_radio0=wifi-iface\n\
         wireless.default_radio0.device='radio0'\n\
         wireless.default_radio0.network='lan'\n\
         wireless.default_radio0.mode='ap'\n\
         wireless.default_radio0.ssid='private-name'\n\
         wireless.default_radio0.encryption='psk2'\n\
         wireless.default_radio0.key='must-not-enter-inventory'\n";

    fn radio_config(object: &mut WirelessObject) -> &mut WirelessRadioConfig {
        let WirelessObject::Radio(value) = object;
        value
    }

    fn update_plan(
        snapshot: &OpenWrtWirelessInventorySnapshot,
        update: impl FnOnce(&mut WirelessRadioConfig),
    ) -> WirelessMutationPlan {
        let before = snapshot.inventory().objects[0].clone();
        let mut after = before.clone();
        update(radio_config(&mut after));
        plan_wireless_mutations(
            snapshot.inventory(),
            &[WirelessMutation::Update {
                expected_digest: wireless_object_digest(&before).expect("digest"),
                desired: after,
            }],
            &WirelessRiskContext::default(),
        )
        .expect("plan")
    }

    #[test]
    fn reconstructs_legacy_hwmode_radio_without_ssid_or_key() {
        let snapshot = inspect_openwrt_wireless_inventory(OPENWRT_21_WIRELESS).expect("inspect");
        assert_eq!(snapshot.inventory().objects.len(), 1);
        assert_eq!(snapshot.bindings().len(), 1);
        assert_eq!(snapshot.read_only_sections(), ["default_radio0"]);
        assert_eq!(
            snapshot.bindings()[0].band_encoding,
            OpenWrtWirelessBandEncoding::HwMode
        );
        let WirelessObject::Radio(radio) = &snapshot.inventory().objects[0];
        assert_eq!(radio.id, "radio0");
        assert_eq!(radio.band, WirelessBand::Ghz5);
        assert_eq!(radio.channel, WirelessChannel::Fixed { channel: 36 });
        assert_eq!(radio.width, WirelessChannelWidth::Mhz80);
        let encoded = serde_json::to_string(snapshot.inventory()).expect("encode");
        assert!(!encoded.contains("private-name"));
        assert!(!encoded.contains("must-not-enter-inventory"));
    }

    #[test]
    fn stages_exact_radio_update_and_preserves_unknown_device_options() {
        let snapshot = inspect_openwrt_wireless_inventory(OPENWRT_21_WIRELESS).expect("inspect");
        let plan = update_plan(&snapshot, |radio| {
            radio.channel = WirelessChannel::Fixed { channel: 40 };
            radio.country = Some("US".into());
            radio.tx_power_dbm = None;
        });
        let stage = render_openwrt_wireless_stage_from_snapshot(&plan, &snapshot).expect("stage");
        assert!(stage.uci_batch.contains("delete wireless.radio0.channel"));
        assert!(stage.uci_batch.contains("set wireless.radio0.channel='40'"));
        assert!(stage.uci_batch.contains("set wireless.radio0.hwmode='11a'"));
        assert!(
            stage
                .uci_batch
                .contains("set wireless.radio0.htmode='VHT80'")
        );
        assert!(!stage.uci_batch.contains("set wireless.radio0.txpower"));
        assert!(!stage.uci_batch.contains("delete wireless.radio0.path"));
        assert!(!stage.uci_batch.contains("default_radio0"));
        assert_eq!(stage.activation_program, "/sbin/wifi");
        assert_eq!(stage.activation_argument, "reload");
    }

    #[test]
    fn modern_band_and_he_width_round_trip() {
        let input = "wireless.radio1=wifi-device\n\
            wireless.radio1.type='mac80211'\n\
            wireless.radio1.band='6g'\n\
            wireless.radio1.channel='auto'\n\
            wireless.radio1.htmode='HE160'\n\
            wireless.radio1.disabled='1'\n";
        let snapshot = inspect_openwrt_wireless_inventory(input).expect("inspect");
        let WirelessObject::Radio(radio) = &snapshot.inventory().objects[0];
        assert_eq!(radio.band, WirelessBand::Ghz6);
        assert_eq!(radio.channel, WirelessChannel::Auto);
        assert_eq!(radio.width, WirelessChannelWidth::Mhz160);
        assert!(!radio.enabled);
        let plan = update_plan(&snapshot, |radio| {
            radio.enabled = true;
            radio.width = WirelessChannelWidth::Mhz80;
        });
        let stage = render_openwrt_wireless_stage_from_snapshot(&plan, &snapshot).expect("stage");
        assert!(stage.uci_batch.contains("set wireless.radio1.band='6g'"));
        assert!(
            stage
                .uci_batch
                .contains("set wireless.radio1.htmode='HE80'")
        );
        assert!(stage.uci_batch.contains("set wireless.radio1.disabled='0'"));
    }

    #[test]
    fn ambiguous_or_vendor_radio_is_read_only() {
        let input = "wireless.radio0=wifi-device\n\
            wireless.radio0.type='mac80211'\n\
            wireless.radio0.band='5g'\n\
            wireless.radio0.hwmode='11a'\n\
            wireless.radio0.channel='36'\n\
            wireless.radio1=wifi-device\n\
            wireless.radio1.type='vendor-driver'\n\
            wireless.radio1.band='2g'\n";
        let snapshot = inspect_openwrt_wireless_inventory(input).expect("inspect");
        assert!(snapshot.inventory().objects.is_empty());
        assert_eq!(snapshot.read_only_sections(), ["radio0", "radio1"]);
    }

    #[test]
    fn rejects_backend_incompatible_band_or_width_changes() {
        let snapshot = inspect_openwrt_wireless_inventory(OPENWRT_21_WIRELESS).expect("inspect");
        let invalid_band = update_plan(&snapshot, |radio| {
            radio.band = WirelessBand::Ghz2;
            radio.width = WirelessChannelWidth::Mhz40;
            radio.channel = WirelessChannel::Fixed { channel: 6 };
        });
        assert_eq!(
            render_openwrt_wireless_stage_from_snapshot(&invalid_band, &snapshot),
            Err(WirelessRenderError::UnsupportedSemantics)
        );

        let narrow_input = OPENWRT_21_WIRELESS.replace("VHT80", "HT20");
        let narrow = inspect_openwrt_wireless_inventory(&narrow_input).expect("inspect");
        let invalid_width = update_plan(&narrow, |radio| radio.width = WirelessChannelWidth::Mhz80);
        assert_eq!(
            render_openwrt_wireless_stage_from_snapshot(&invalid_width, &narrow),
            Err(WirelessRenderError::UnsupportedSemantics)
        );
    }

    #[test]
    fn rejects_stale_plan_or_tampered_binding() {
        let snapshot = inspect_openwrt_wireless_inventory(OPENWRT_21_WIRELESS).expect("inspect");
        let plan = update_plan(&snapshot, |radio| radio.enabled = false);
        let mut stale = snapshot.clone();
        radio_config(&mut stale.inventory.objects[0]).channel =
            WirelessChannel::Fixed { channel: 44 };
        assert_eq!(
            render_openwrt_wireless_stage_from_snapshot(&plan, &stale),
            Err(WirelessRenderError::PlanMismatch)
        );

        let mut tampered = snapshot.clone();
        tampered.bindings[0].section = "radio1".into();
        assert_eq!(
            render_openwrt_wireless_stage_from_snapshot(&plan, &tampered),
            Err(WirelessRenderError::UnsafeBinding)
        );
    }
}
