use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const MINIMUM_OPENWRT_MAJOR: u32 = 21;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent discovered capabilities, not state flags.
pub struct PlatformCapabilities {
    pub kind: PlatformKind,
    pub release: Option<String>,
    pub release_supported: bool,
    pub firewall: FirewallCapabilities,
    pub device_model: NetworkDeviceModel,
    pub package_manager: PackageManager,
    pub has_ubus: bool,
    pub has_uci: bool,
    pub has_procd: bool,
    pub available_commands: Vec<String>,
    pub warnings: Vec<String>,
}

impl PlatformCapabilities {
    #[must_use]
    pub fn discover() -> Self {
        Discovery::new("/").discover()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    OpenWrt,
    GenericLinux,
    Unknown,
}

impl PlatformKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenWrt => "openwrt",
            Self::GenericLinux => "generic_linux",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent command capabilities reported to clients.
pub struct FirewallCapabilities {
    pub backend: FirewallBackend,
    pub has_iptables_save: bool,
    pub has_ip6tables_save: bool,
    pub has_nft: bool,
    pub can_trace: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    Fw3,
    Fw4,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDeviceModel {
    Dsa,
    Swconfig,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Opkg,
    Apk,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Discovery {
    root: PathBuf,
}

impl Discovery {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn discover(&self) -> PlatformCapabilities {
        let release_text = self.read("/etc/openwrt_release");
        let os_release = self.read("/etc/os-release");
        let kind = if release_text.is_some() {
            PlatformKind::OpenWrt
        } else if os_release.is_some() || self.exists("/proc/version") {
            PlatformKind::GenericLinux
        } else {
            PlatformKind::Unknown
        };
        let release = release_text
            .as_deref()
            .and_then(|text| release_value(text, "DISTRIB_RELEASE"));
        let release_supported = kind != PlatformKind::OpenWrt
            || release
                .as_deref()
                .and_then(release_major)
                .is_some_and(|major| major >= MINIMUM_OPENWRT_MAJOR);

        let commands = [
            "ubus",
            "uci",
            "fw3",
            "fw4",
            "iptables-save",
            "ip6tables-save",
            "nft",
            "swconfig",
            "opkg",
            "apk",
            "iwinfo",
            "ip",
        ];
        let available_commands: Vec<String> = commands
            .into_iter()
            .filter(|command| self.command_exists(command))
            .map(str::to_owned)
            .collect();
        let has = |name: &str| available_commands.iter().any(|command| command == name);

        let firewall_service = self.read("/etc/init.d/firewall");
        let backend = select_firewall_backend(has("fw3"), has("fw4"), firewall_service.as_deref());
        let device_model = if self.exists("/sys/class/net/br-lan/bridge/vlan_filtering") {
            NetworkDeviceModel::Dsa
        } else if has("swconfig") {
            NetworkDeviceModel::Swconfig
        } else {
            NetworkDeviceModel::Unknown
        };
        let package_manager = if has("apk") {
            PackageManager::Apk
        } else if has("opkg") {
            PackageManager::Opkg
        } else {
            PackageManager::Unknown
        };

        let mut warnings = Vec::new();
        if kind == PlatformKind::OpenWrt && !release_supported {
            warnings.push(format!(
                "OpenWrt {} is older than the minimum supported major version {MINIMUM_OPENWRT_MAJOR}",
                release.as_deref().unwrap_or("unknown")
            ));
        }
        if kind == PlatformKind::OpenWrt && backend == FirewallBackend::Unknown {
            warnings.push("unable to identify the active fw3/fw4 firewall backend".into());
        }
        if has("fw3") && has("fw4") && firewall_service.is_none() {
            warnings.push(
                "both fw3 and fw4 were found without readable firewall service evidence; using fw4 fallback"
                    .into(),
            );
        }
        if backend == FirewallBackend::Fw4 && !has("nft") {
            warnings.push("fw4 was found but nft is unavailable".into());
        }
        if backend == FirewallBackend::Fw3 && !has("iptables-save") {
            warnings.push("fw3 was found but iptables-save is unavailable".into());
        }

        PlatformCapabilities {
            kind,
            release,
            release_supported,
            firewall: FirewallCapabilities {
                backend,
                has_iptables_save: has("iptables-save"),
                has_ip6tables_save: has("ip6tables-save"),
                has_nft: has("nft"),
                can_trace: has("nft") && backend == FirewallBackend::Fw4,
            },
            device_model,
            package_manager,
            has_ubus: has("ubus"),
            has_uci: has("uci"),
            has_procd: self.exists("/sbin/procd"),
            available_commands,
            warnings,
        }
    }

    fn rooted(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn exists(&self, absolute: &str) -> bool {
        self.rooted(absolute).exists()
    }

    fn read(&self, absolute: &str) -> Option<String> {
        fs::read_to_string(self.rooted(absolute)).ok()
    }

    fn command_exists(&self, command: &str) -> bool {
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .into_iter()
            .map(|directory| Path::new(directory).join(command))
            .any(|path| self.rooted(path.to_string_lossy().as_ref()).is_file())
    }
}

fn select_firewall_backend(
    has_fw3: bool,
    has_fw4: bool,
    service_script: Option<&str>,
) -> FirewallBackend {
    if let Some(script) = service_script {
        if has_fw4
            && script
                .split(|character: char| !character.is_alphanumeric())
                .any(|word| word == "fw4")
        {
            return FirewallBackend::Fw4;
        }
        if has_fw3
            && script
                .split(|character: char| !character.is_alphanumeric())
                .any(|word| word == "fw3")
        {
            return FirewallBackend::Fw3;
        }
    }
    if has_fw4 {
        FirewallBackend::Fw4
    } else if has_fw3 {
        FirewallBackend::Fw3
    } else {
        FirewallBackend::Unknown
    }
}

fn release_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key).then(|| {
            value
                .trim()
                .trim_matches(|character| character == '\'' || character == '"')
                .to_owned()
        })
    })
}

fn release_major(release: &str) -> Option<u32> {
    release.split('.').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_quoted_openwrt_release() {
        let text = "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='21.02.7'\n";
        assert_eq!(
            release_value(text, "DISTRIB_RELEASE").as_deref(),
            Some("21.02.7")
        );
        assert_eq!(release_major("21.02.7"), Some(21));
    }

    #[test]
    fn rejects_pre_21_major() {
        assert!(release_major("19.07.10").is_some_and(|major| major < MINIMUM_OPENWRT_MAJOR));
    }

    #[test]
    fn discovers_openwrt_21_fw3_fixture() {
        let fixture = Fixture::new();
        fixture.write("etc/openwrt_release", "DISTRIB_RELEASE='21.02.7'\n");
        fixture.write("sbin/fw3", "");
        fixture.write("sbin/uci", "");
        fixture.write("sbin/ubus", "");
        fixture.write("usr/sbin/iptables-save", "");
        fixture.write("usr/bin/opkg", "");

        let capabilities = Discovery::new(&fixture.root).discover();
        assert_eq!(capabilities.kind, PlatformKind::OpenWrt);
        assert_eq!(capabilities.release.as_deref(), Some("21.02.7"));
        assert!(capabilities.release_supported);
        assert_eq!(capabilities.firewall.backend, FirewallBackend::Fw3);
        assert_eq!(capabilities.package_manager, PackageManager::Opkg);
    }

    #[test]
    fn mixed_install_uses_backend_referenced_by_firewall_service() {
        let fixture = Fixture::new();
        fixture.write("etc/openwrt_release", "DISTRIB_RELEASE='23.05.5'\n");
        fixture.write("sbin/fw3", "");
        fixture.write("sbin/fw4", "");
        fixture.write("usr/sbin/iptables-save", "");
        fixture.write("usr/sbin/nft", "");
        fixture.write("etc/init.d/firewall", "#!/bin/sh\n/usr/sbin/fw3 -q start\n");
        let capabilities = Discovery::new(&fixture.root).discover();
        assert_eq!(capabilities.firewall.backend, FirewallBackend::Fw3);
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "mbed-agent-platform-test-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create fixture root");
            Self { root }
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().expect("fixture parent"))
                .expect("create fixture directory");
            fs::write(path, content).expect("write fixture file");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove fixture root");
        }
    }
}
