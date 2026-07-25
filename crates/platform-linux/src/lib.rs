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
    pub init_system: InitSystem,
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
    Iptables,
    Nftables,
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
    Apt,
    Dnf,
    Pacman,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitSystem {
    Procd,
    Systemd,
    OpenRc,
    BusyBox,
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
            "apt-get",
            "dnf",
            "pacman",
            "systemctl",
            "openrc",
            "iwinfo",
            "ip",
            "ss",
            "netstat",
        ];
        let available_commands: Vec<String> = commands
            .into_iter()
            .filter(|command| self.command_exists(command))
            .map(str::to_owned)
            .collect();
        let has = |name: &str| available_commands.iter().any(|command| command == name);

        let firewall_service = self.read("/etc/init.d/firewall");
        let backend = if kind == PlatformKind::OpenWrt {
            select_openwrt_firewall_backend(has("fw3"), has("fw4"), firewall_service.as_deref())
        } else if has("nft") {
            FirewallBackend::Nftables
        } else if has("iptables-save") {
            FirewallBackend::Iptables
        } else {
            FirewallBackend::Unknown
        };
        let device_model = if self.exists("/sys/class/net/br-lan/bridge/vlan_filtering") {
            NetworkDeviceModel::Dsa
        } else if has("swconfig") {
            NetworkDeviceModel::Swconfig
        } else {
            NetworkDeviceModel::Unknown
        };
        let package_manager = self.detect_package_manager();
        let init_system = self.detect_init_system();

        let warnings = capability_warnings(&WarningContext {
            kind,
            release: release.as_deref(),
            release_supported,
            backend,
            has_fw3: has("fw3"),
            has_fw4: has("fw4"),
            has_nft: has("nft"),
            has_iptables_save: has("iptables-save"),
            has_firewall_service: firewall_service.is_some(),
        });

        PlatformCapabilities {
            kind,
            release,
            release_supported,
            firewall: FirewallCapabilities {
                backend,
                has_iptables_save: has("iptables-save"),
                has_ip6tables_save: has("ip6tables-save"),
                has_nft: has("nft"),
                can_trace: has("nft")
                    && matches!(backend, FirewallBackend::Fw4 | FirewallBackend::Nftables),
            },
            device_model,
            package_manager,
            init_system,
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

    fn detect_init_system(&self) -> InitSystem {
        if self.exists("/sbin/procd") {
            InitSystem::Procd
        } else if self.exists("/run/systemd/system") || self.command_exists("systemctl") {
            InitSystem::Systemd
        } else if self.exists("/run/openrc") || self.command_exists("openrc") {
            InitSystem::OpenRc
        } else if self.exists("/etc/inittab") && self.exists("/bin/busybox") {
            InitSystem::BusyBox
        } else {
            InitSystem::Unknown
        }
    }

    fn detect_package_manager(&self) -> PackageManager {
        if self.command_exists("apk") {
            PackageManager::Apk
        } else if self.command_exists("opkg") {
            PackageManager::Opkg
        } else if self.command_exists("apt-get") {
            PackageManager::Apt
        } else if self.command_exists("dnf") {
            PackageManager::Dnf
        } else if self.command_exists("pacman") {
            PackageManager::Pacman
        } else {
            PackageManager::Unknown
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
struct WarningContext<'a> {
    kind: PlatformKind,
    release: Option<&'a str>,
    release_supported: bool,
    backend: FirewallBackend,
    has_fw3: bool,
    has_fw4: bool,
    has_nft: bool,
    has_iptables_save: bool,
    has_firewall_service: bool,
}

fn capability_warnings(context: &WarningContext<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    if context.kind == PlatformKind::OpenWrt && !context.release_supported {
        warnings.push(format!(
            "OpenWrt {} is older than the minimum supported major version {MINIMUM_OPENWRT_MAJOR}",
            context.release.unwrap_or("unknown")
        ));
    }
    if context.backend == FirewallBackend::Unknown {
        warnings.push(if context.kind == PlatformKind::OpenWrt {
            "unable to identify the active fw3/fw4 firewall backend".into()
        } else {
            "unable to identify an nftables/iptables firewall backend".into()
        });
    }
    if context.has_fw3 && context.has_fw4 && !context.has_firewall_service {
        warnings.push(
            "both fw3 and fw4 were found without readable firewall service evidence; using fw4 fallback"
                .into(),
        );
    }
    if context.backend == FirewallBackend::Fw4 && !context.has_nft {
        warnings.push("fw4 was found but nft is unavailable".into());
    }
    if matches!(
        context.backend,
        FirewallBackend::Fw3 | FirewallBackend::Iptables
    ) && !context.has_iptables_save
    {
        warnings.push("iptables backend was found but iptables-save is unavailable".into());
    }
    warnings
}

fn select_openwrt_firewall_backend(
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

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

    #[test]
    fn generic_linux_detects_native_nftables_and_iptables() {
        let nft_fixture = Fixture::new();
        nft_fixture.write("etc/os-release", "ID=buildroot\n");
        nft_fixture.write("usr/sbin/nft", "");
        let nft = Discovery::new(&nft_fixture.root).discover();
        assert_eq!(nft.kind, PlatformKind::GenericLinux);
        assert_eq!(nft.firewall.backend, FirewallBackend::Nftables);

        let iptables_fixture = Fixture::new();
        iptables_fixture.write("etc/os-release", "ID=debian\n");
        iptables_fixture.write("usr/sbin/iptables-save", "");
        iptables_fixture.write("usr/bin/apt-get", "");
        iptables_fixture.write("usr/bin/systemctl", "");
        let iptables = Discovery::new(&iptables_fixture.root).discover();
        assert_eq!(iptables.kind, PlatformKind::GenericLinux);
        assert_eq!(iptables.firewall.backend, FirewallBackend::Iptables);
        assert_eq!(iptables.package_manager, PackageManager::Apt);
        assert_eq!(iptables.init_system, InitSystem::Systemd);
    }

    #[test]
    fn generic_linux_detects_openrc_and_busybox_init() {
        let openrc_fixture = Fixture::new();
        openrc_fixture.write("etc/os-release", "ID=alpine\n");
        openrc_fixture.write("sbin/openrc", "");
        openrc_fixture.write("sbin/apk", "");
        let openrc = Discovery::new(&openrc_fixture.root).discover();
        assert_eq!(openrc.init_system, InitSystem::OpenRc);
        assert_eq!(openrc.package_manager, PackageManager::Apk);

        let busybox_fixture = Fixture::new();
        busybox_fixture.write("etc/os-release", "ID=buildroot\n");
        busybox_fixture.write("etc/inittab", "::sysinit:/etc/init.d/rcS\n");
        busybox_fixture.write("bin/busybox", "");
        let busybox = Discovery::new(&busybox_fixture.root).discover();
        assert_eq!(busybox.init_system, InitSystem::BusyBox);
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let fixture_id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "mbed-agent-platform-test-{}-{fixture_id}",
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
