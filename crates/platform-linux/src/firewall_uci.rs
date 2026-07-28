use std::collections::HashMap;

use crate::firewall::FirewallRenderError;

pub(crate) const MAX_UCI_SHOW_BYTES: usize = 256 * 1024;
pub(crate) const MAX_UCI_SHOW_LINES: usize = 4_096;
pub(crate) const MAX_UCI_SECTIONS: usize = 256;
pub(crate) const MAX_UCI_OPTIONS: usize = 128;
const MAX_UCI_VALUES: usize = 64;
const MAX_UCI_VALUE_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UciSection {
    pub selector: String,
    pub section_type: String,
    pub options: HashMap<String, Vec<String>>,
    pub order: u32,
}

impl UciSection {
    pub fn first(&self, option: &str) -> Option<&str> {
        self.options
            .get(option)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    pub fn values(&self, option: &str) -> &[String] {
        self.options.get(option).map_or(&[], Vec::as_slice)
    }
}

pub(crate) fn parse_uci_show(uci_show: &str) -> Result<Vec<UciSection>, FirewallRenderError> {
    if uci_show.len() > MAX_UCI_SHOW_BYTES
        || uci_show.lines().count() > MAX_UCI_SHOW_LINES
        || uci_show.lines().any(|line| line.len() > 2_048)
    {
        return Err(FirewallRenderError::Capacity);
    }

    let mut sections = Vec::new();
    let mut indexes = HashMap::new();
    for line in uci_show.lines().filter(|line| !line.trim().is_empty()) {
        let (key, raw_value) = split_line(line)?;
        if key.contains('.') {
            continue;
        }
        let values = parse_uci_values(raw_value)?;
        if values.len() != 1 {
            return Err(FirewallRenderError::MalformedUci);
        }
        let section_type = values[0].clone();
        if !safe_uci_identifier(&section_type) || !valid_section(key, &section_type) {
            return Err(FirewallRenderError::MalformedUci);
        }
        if indexes.contains_key(key) {
            return Err(FirewallRenderError::MalformedUci);
        }
        if sections.len() >= MAX_UCI_SECTIONS {
            return Err(FirewallRenderError::Capacity);
        }
        let order = u32::try_from(sections.len()).map_err(|_| FirewallRenderError::Capacity)?;
        indexes.insert(key.to_owned(), sections.len());
        sections.push(UciSection {
            selector: key.to_owned(),
            section_type,
            options: HashMap::new(),
            order,
        });
    }

    for line in uci_show.lines().filter(|line| !line.trim().is_empty()) {
        let (key, raw_value) = split_line(line)?;
        let Some((selector, option)) = key.rsplit_once('.') else {
            continue;
        };
        if !safe_uci_identifier(option) {
            return Err(FirewallRenderError::MalformedUci);
        }
        let Some(index) = indexes.get(selector).copied() else {
            return Err(FirewallRenderError::MalformedUci);
        };
        let values = parse_uci_values(raw_value)?;
        let section = sections
            .get_mut(index)
            .ok_or(FirewallRenderError::MalformedUci)?;
        if section.options.len() >= MAX_UCI_OPTIONS
            || section.options.insert(option.to_owned(), values).is_some()
        {
            return Err(FirewallRenderError::MalformedUci);
        }
    }
    Ok(sections)
}

fn split_line(line: &str) -> Result<(&str, &str), FirewallRenderError> {
    let (key, value) = line
        .split_once('=')
        .ok_or(FirewallRenderError::MalformedUci)?;
    let key = key
        .strip_prefix("firewall.")
        .ok_or(FirewallRenderError::MalformedUci)?;
    if key.is_empty() || key.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(FirewallRenderError::MalformedUci);
    }
    Ok((key, value))
}

fn parse_uci_values(value: &str) -> Result<Vec<String>, FirewallRenderError> {
    let bytes = value.trim().as_bytes();
    let mut values = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }
        if values.len() >= MAX_UCI_VALUES {
            return Err(FirewallRenderError::Capacity);
        }
        let start;
        let end;
        if bytes[cursor] == b'\'' {
            cursor += 1;
            start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'\'' {
                if bytes[cursor] == b'\\' || bytes[cursor].is_ascii_control() {
                    return Err(FirewallRenderError::MalformedUci);
                }
                cursor += 1;
            }
            if cursor == bytes.len() {
                return Err(FirewallRenderError::MalformedUci);
            }
            end = cursor;
            cursor += 1;
            if cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
                return Err(FirewallRenderError::MalformedUci);
            }
        } else {
            start = cursor;
            while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
                if bytes[cursor] == b'\'' || bytes[cursor] == b'\\' {
                    return Err(FirewallRenderError::MalformedUci);
                }
                cursor += 1;
            }
            end = cursor;
        }
        if end.saturating_sub(start) > MAX_UCI_VALUE_BYTES {
            return Err(FirewallRenderError::Capacity);
        }
        let parsed = std::str::from_utf8(&bytes[start..end])
            .map_err(|_| FirewallRenderError::MalformedUci)?;
        if parsed.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(FirewallRenderError::MalformedUci);
        }
        values.push(parsed.to_owned());
    }
    if values.is_empty() {
        return Err(FirewallRenderError::MalformedUci);
    }
    Ok(values)
}

pub(crate) fn valid_section(section: &str, section_type: &str) -> bool {
    if safe_uci_identifier(section) {
        return true;
    }
    let Some(index) = section
        .strip_prefix('@')
        .and_then(|value| value.strip_prefix(section_type))
        .and_then(|value| value.strip_prefix('['))
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn safe_uci_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ordered_sections_and_multi_value_options_without_shell_evaluation() {
        let parsed = parse_uci_show(
            "firewall.@defaults[0]=defaults\n\
             firewall.@defaults[0].input='REJECT'\n\
             firewall.@zone[0]=zone\n\
             firewall.@zone[0].name='lan'\n\
             firewall.@zone[0].network='lan' 'guest'\n",
        )
        .expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].order, 1);
        assert_eq!(parsed[1].first("name"), Some("lan"));
        assert_eq!(parsed[1].values("network"), ["lan", "guest"]);
    }

    #[test]
    fn rejects_shell_escapes_duplicates_and_unbounded_values() {
        assert!(parse_uci_show("firewall.x=zone;touch /tmp/x\n").is_err());
        assert!(parse_uci_show("firewall.x=zone\nfirewall.x=zone\n").is_err());
        assert!(parse_uci_show("firewall.x=zone\nfirewall.x.name='a'\\''b'\n").is_err());
        let values = (0..=MAX_UCI_VALUES)
            .map(|index| format!("'{index}'"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            parse_uci_show(&format!("firewall.x=zone\nfirewall.x.network={values}\n")).is_err()
        );
    }
}
