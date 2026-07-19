use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use agent_protocol::{
    ProbeEvidence, ProbeStatus, WanAssessment, WanDiagnosticReport, WanRoute, WanSummary,
};
use platform_openwrt::{FirewallBackend, PlatformCapabilities};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

const WAN_INTERFACE: &str = "wan";

#[derive(Debug, Clone)]
pub struct ToolRunner {
    root: PathBuf,
    command_dirs: Vec<PathBuf>,
    timeout: Duration,
    max_output_bytes: usize,
}

impl ToolRunner {
    #[must_use]
    pub fn system(timeout: Duration, max_output_bytes: usize) -> Self {
        Self {
            root: PathBuf::from("/"),
            command_dirs: ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            timeout,
            max_output_bytes,
        }
    }

    /// Runs the deterministic, read-only WAN evidence collectors.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector process cannot be spawned
    /// or its output pipes cannot be read. Missing commands are reported as
    /// `unavailable` evidence rather than errors.
    pub async fn diagnose_wan(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<WanDiagnosticReport> {
        let mut evidence = Vec::with_capacity(8);
        for probe in [
            Probe::UbusWan,
            Probe::IpLink,
            Probe::IpAddress,
            Probe::IpRoute,
            Probe::IpRule,
        ] {
            evidence.push(self.run(probe).await?);
        }
        evidence.push(self.read_file("network.dns.openwrt", "/tmp/resolv.conf.d/resolv.conf.auto"));
        evidence.push(self.read_file("network.dns.system", "/etc/resolv.conf"));
        evidence.push(firewall_evidence(platform));

        let summary = normalize(&evidence, platform);
        let findings = summarize(&summary, &evidence);
        let complete = summary.status_source.is_some()
            && !summary.addresses.is_empty()
            && !summary.default_routes.is_empty()
            && !summary.dns_servers.is_empty();
        Ok(WanDiagnosticReport {
            interface: WAN_INTERFACE.into(),
            summary,
            evidence,
            findings,
            complete,
        })
    }

    async fn run(&self, probe: Probe) -> io::Result<ProbeEvidence> {
        let Some(executable) = self.resolve(probe.command()) else {
            return Ok(ProbeEvidence {
                probe: probe.name().into(),
                source: probe.command().into(),
                status: ProbeStatus::Unavailable,
                output: String::new(),
                truncated: false,
                duration_ms: 0,
            });
        };
        let started = Instant::now();
        let mut child = Command::new(&executable)
            .args(probe.args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("collector stdout pipe is unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("collector stderr pipe is unavailable"))?;
        let stream_limit = self.max_output_bytes / 2;
        let stdout_task = tokio::spawn(read_limited(stdout, stream_limit));
        let stderr_task = tokio::spawn(read_limited(stderr, stream_limit));

        let (status, timed_out) = if let Ok(status) = timeout(self.timeout, child.wait()).await {
            (Some(status?), false)
        } else {
            child.kill().await?;
            let _ = child.wait().await;
            (None, true)
        };
        let (stdout, stdout_truncated) = stdout_task.await.map_err(io::Error::other)??;
        let (stderr, stderr_truncated) = stderr_task.await.map_err(io::Error::other)??;
        let mut output = String::from_utf8_lossy(&stdout).into_owned();
        if !stderr.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str("stderr: ");
            output.push_str(&String::from_utf8_lossy(&stderr));
        }
        let probe_status = if timed_out {
            ProbeStatus::TimedOut
        } else if status.is_some_and(|value| value.success()) {
            ProbeStatus::Ok
        } else {
            ProbeStatus::Failed
        };
        Ok(ProbeEvidence {
            probe: probe.name().into(),
            source: executable.display().to_string(),
            status: probe_status,
            output,
            truncated: stdout_truncated || stderr_truncated,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn read_file(&self, probe: &str, absolute: &str) -> ProbeEvidence {
        let path = self.rooted(absolute);
        let started = Instant::now();
        let mut bytes = Vec::with_capacity(self.max_output_bytes.min(4096));
        let result = fs::File::open(&path).and_then(|file| {
            file.take((self.max_output_bytes as u64).saturating_add(1))
                .read_to_end(&mut bytes)
        });
        let truncated = bytes.len() > self.max_output_bytes;
        bytes.truncate(self.max_output_bytes);
        ProbeEvidence {
            probe: probe.into(),
            source: path.display().to_string(),
            status: if result.is_ok() {
                ProbeStatus::Ok
            } else {
                ProbeStatus::Unavailable
            },
            output: String::from_utf8_lossy(&bytes).into_owned(),
            truncated,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }

    fn resolve(&self, command: &str) -> Option<PathBuf> {
        self.command_dirs
            .iter()
            .map(|directory| self.rooted_path(&directory.join(command)))
            .find(|path| path.is_file())
    }

    fn rooted(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn rooted_path(&self, absolute: &Path) -> PathBuf {
        self.rooted(absolute.to_string_lossy().as_ref())
    }
}

#[derive(Debug, Clone, Copy)]
enum Probe {
    UbusWan,
    IpLink,
    IpAddress,
    IpRoute,
    IpRule,
}

impl Probe {
    const fn name(self) -> &'static str {
        match self {
            Self::UbusWan => "openwrt.interface.wan",
            Self::IpLink => "network.interface.link",
            Self::IpAddress => "network.interface.address",
            Self::IpRoute => "network.route.list",
            Self::IpRule => "network.route.rules",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::UbusWan => "ubus",
            Self::IpLink | Self::IpAddress | Self::IpRoute | Self::IpRule => "ip",
        }
    }

    const fn args(self) -> &'static [&'static str] {
        match self {
            Self::UbusWan => &["call", "network.interface.wan", "status"],
            Self::IpLink => &["-j", "link", "show"],
            Self::IpAddress => &["-j", "address", "show"],
            Self::IpRoute => &["-j", "route", "show", "table", "all"],
            Self::IpRule => &["-j", "rule", "show"],
        }
    }
}

async fn read_limited<R>(mut reader: R, limit: usize) -> io::Result<(Vec<u8>, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut retained = Vec::with_capacity(limit.min(4096));
    let mut buffer = [0_u8; 2048];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let accepted = remaining.min(read);
        retained.extend_from_slice(&buffer[..accepted]);
        truncated |= accepted < read;
    }
    Ok((retained, truncated))
}

fn firewall_evidence(platform: &PlatformCapabilities) -> ProbeEvidence {
    let backend = match platform.firewall.backend {
        FirewallBackend::Fw3 => "fw3/iptables",
        FirewallBackend::Fw4 => "fw4/nftables",
        FirewallBackend::Unknown => "unknown",
    };
    ProbeEvidence {
        probe: "openwrt.firewall.backend".into(),
        source: "capability-discovery".into(),
        status: if platform.firewall.backend == FirewallBackend::Unknown {
            ProbeStatus::Unavailable
        } else {
            ProbeStatus::Ok
        },
        output: backend.into(),
        truncated: false,
        duration_ms: 0,
    }
}

fn normalize(evidence: &[ProbeEvidence], platform: &PlatformCapabilities) -> WanSummary {
    let mut summary = WanSummary {
        assessment: WanAssessment::InsufficientEvidence,
        status_source: None,
        up: None,
        available: None,
        pending: None,
        protocol: None,
        device: None,
        addresses: Vec::new(),
        default_routes: Vec::new(),
        dns_servers: Vec::new(),
        firewall_backend: match platform.firewall.backend {
            FirewallBackend::Fw3 => "fw3/iptables",
            FirewallBackend::Fw4 => "fw4/nftables",
            FirewallBackend::Unknown => "unknown",
        }
        .into(),
    };

    if let Some(output) = successful_output(evidence, "openwrt.interface.wan") {
        parse_ubus_wan(output, &mut summary);
    }
    if let Some(output) = successful_output(evidence, "network.route.list") {
        parse_ip_routes(output, &mut summary);
    }
    if let Some(output) = successful_output(evidence, "network.interface.address") {
        parse_ip_addresses(output, &mut summary);
    }
    if let Some(output) = successful_output(evidence, "network.interface.link") {
        parse_ip_link(output, &mut summary);
    }
    for probe in ["network.dns.openwrt", "network.dns.system"] {
        if let Some(output) = successful_output(evidence, probe) {
            parse_resolvers(output, &mut summary.dns_servers);
        }
    }
    summary.assessment = assess(&summary);
    summary
}

fn successful_output<'a>(evidence: &'a [ProbeEvidence], probe: &str) -> Option<&'a str> {
    evidence
        .iter()
        .find(|item| item.probe == probe && item.status == ProbeStatus::Ok)
        .map(|item| item.output.as_str())
}

fn parse_ubus_wan(output: &str, summary: &mut WanSummary) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(output) else {
        return;
    };
    summary.status_source = Some("ubus".into());
    summary.up = value.get("up").and_then(serde_json::Value::as_bool);
    summary.available = value.get("available").and_then(serde_json::Value::as_bool);
    summary.pending = value.get("pending").and_then(serde_json::Value::as_bool);
    summary.protocol = json_string(&value, "proto");
    summary.device = json_string(&value, "l3_device").or_else(|| json_string(&value, "device"));
    for (key, family) in [("ipv4-address", "ipv4"), ("ipv6-address", "ipv6")] {
        let Some(addresses) = value.get(key).and_then(serde_json::Value::as_array) else {
            continue;
        };
        for address in addresses {
            let Some(local) = address.get("address").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let prefix = address
                .get("mask")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(if family == "ipv4" { 32 } else { 128 });
            push_unique(&mut summary.addresses, format!("{local}/{prefix}"));
        }
    }
    if let Some(routes) = value.get("route").and_then(serde_json::Value::as_array) {
        for route in routes {
            let target = route
                .get("target")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let mask = route
                .get("mask")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX);
            if mask != 0 && target != "default" {
                continue;
            }
            let family = if target.contains(':') { "ipv6" } else { "ipv4" };
            push_route(
                &mut summary.default_routes,
                WanRoute {
                    family: family.into(),
                    gateway: json_string(route, "nexthop"),
                    device: summary.device.clone(),
                    source: json_string(route, "source"),
                    metric: route.get("metric").and_then(serde_json::Value::as_u64),
                },
            );
        }
    }
    if let Some(servers) = value
        .get("dns-server")
        .and_then(serde_json::Value::as_array)
    {
        for server in servers.iter().filter_map(serde_json::Value::as_str) {
            push_unique(&mut summary.dns_servers, server.into());
        }
    }
}

fn parse_ip_routes(output: &str, summary: &mut WanSummary) {
    let Ok(routes) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for route in routes {
        let destination = route
            .get("dst")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if destination != "default" && destination != "0.0.0.0/0" && destination != "::/0" {
            continue;
        }
        let device = json_string(&route, "dev");
        if summary.device.is_none() {
            summary.device.clone_from(&device);
        }
        let gateway = json_string(&route, "gateway");
        let family = if destination.contains(':')
            || gateway.as_deref().is_some_and(|value| value.contains(':'))
        {
            "ipv6"
        } else {
            "ipv4"
        };
        push_route(
            &mut summary.default_routes,
            WanRoute {
                family: family.into(),
                gateway,
                device,
                source: json_string(&route, "prefsrc"),
                metric: route.get("metric").and_then(serde_json::Value::as_u64),
            },
        );
    }
    if summary.status_source.is_none() && !summary.default_routes.is_empty() {
        summary.status_source = Some("kernel".into());
    }
}

fn parse_ip_addresses(output: &str, summary: &mut WanSummary) {
    let Some(expected_device) = summary.device.clone() else {
        return;
    };
    let Ok(interfaces) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for interface in interfaces {
        let name = interface.get("ifname").and_then(serde_json::Value::as_str);
        if Some(expected_device.as_str()) != name {
            continue;
        }
        let Some(addresses) = interface
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for address in addresses {
            let Some(local) = address.get("local").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let prefix = address
                .get("prefixlen")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| if local.contains(':') { 128 } else { 32 });
            push_unique(&mut summary.addresses, format!("{local}/{prefix}"));
        }
    }
}

fn parse_ip_link(output: &str, summary: &mut WanSummary) {
    let Some(device) = summary.device.as_deref() else {
        return;
    };
    let Ok(interfaces) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    let Some(interface) = interfaces
        .iter()
        .find(|item| item.get("ifname").and_then(serde_json::Value::as_str) == Some(device))
    else {
        return;
    };
    let operstate = interface
        .get("operstate")
        .and_then(serde_json::Value::as_str);
    if summary.up.is_none() {
        summary.up = operstate.map(|state| state.eq_ignore_ascii_case("up"));
    }
    if summary.available.is_none() {
        summary.available = summary.up;
    }
}

fn parse_resolvers(output: &str, servers: &mut Vec<String>) {
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("nameserver") {
            if let Some(server) = fields.next() {
                push_unique(servers, server.into());
            }
        }
    }
}

fn assess(summary: &WanSummary) -> WanAssessment {
    if summary.status_source.is_none() {
        WanAssessment::InsufficientEvidence
    } else if summary.available == Some(false) {
        WanAssessment::InterfaceUnavailable
    } else if summary.up == Some(false) {
        WanAssessment::LinkDown
    } else if summary.addresses.is_empty() {
        WanAssessment::AddressMissing
    } else if summary.default_routes.is_empty() {
        WanAssessment::DefaultRouteMissing
    } else if summary.dns_servers.is_empty() {
        WanAssessment::DnsMissing
    } else {
        WanAssessment::PrerequisitesReady
    }
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_route(routes: &mut Vec<WanRoute>, route: WanRoute) {
    if !routes.contains(&route) {
        routes.push(route);
    }
}

fn summarize(summary: &WanSummary, evidence: &[ProbeEvidence]) -> Vec<String> {
    let mut findings = Vec::new();
    let primary = match summary.assessment {
        WanAssessment::PrerequisitesReady => {
            "WAN address, default route, and DNS prerequisites are present; active connectivity is not yet tested"
        }
        WanAssessment::LinkDown => "WAN link or logical interface is down",
        WanAssessment::InterfaceUnavailable => "WAN interface is unavailable",
        WanAssessment::AddressMissing => "WAN has no usable IP address",
        WanAssessment::DefaultRouteMissing => "WAN has no default route",
        WanAssessment::DnsMissing => "WAN has no configured DNS resolver",
        WanAssessment::InsufficientEvidence => "WAN evidence is insufficient for a conclusion",
    };
    findings.push(primary.into());
    match summary.status_source.as_deref() {
        Some("kernel") => {
            findings.push("OpenWrt WAN status is unavailable; kernel evidence was used".into());
        }
        None => findings.push("OpenWrt and kernel WAN status evidence are unavailable".into()),
        _ => {}
    }
    if summary.firewall_backend == "unknown" {
        findings.push("active fw3/fw4 firewall backend could not be identified".into());
    }
    if evidence.iter().any(|item| item.truncated) {
        findings.push("one or more probe outputs reached the configured byte limit".into());
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_openwrt::{
        FirewallCapabilities, NetworkDeviceModel, PackageManager, PlatformKind,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn platform(backend: FirewallBackend) -> PlatformCapabilities {
        PlatformCapabilities {
            kind: PlatformKind::OpenWrt,
            release: Some("21.02.7".into()),
            release_supported: true,
            firewall: FirewallCapabilities {
                backend,
                has_iptables_save: backend == FirewallBackend::Fw3,
                has_ip6tables_save: backend == FirewallBackend::Fw3,
                has_nft: backend == FirewallBackend::Fw4,
                can_trace: backend == FirewallBackend::Fw4,
            },
            device_model: NetworkDeviceModel::Unknown,
            package_manager: PackageManager::Opkg,
            has_ubus: false,
            has_uci: false,
            has_procd: true,
            available_commands: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn reports_fw3_and_fw4_without_translating_rules() {
        assert_eq!(
            firewall_evidence(&platform(FirewallBackend::Fw3)).output,
            "fw3/iptables"
        );
        assert_eq!(
            firewall_evidence(&platform(FirewallBackend::Fw4)).output,
            "fw4/nftables"
        );
    }

    #[test]
    fn normalizes_openwrt_21_ubus_wan_status() {
        let evidence = vec![
            ok_evidence(
                "openwrt.interface.wan",
                r#"{
                    "up": true,
                    "available": true,
                    "pending": false,
                    "proto": "dhcp",
                    "l3_device": "eth0.2",
                    "ipv4-address": [{"address":"192.0.2.10","mask":24}],
                    "route": [{"target":"0.0.0.0","mask":0,"nexthop":"192.0.2.1","metric":10}],
                    "dns-server": ["192.0.2.53"]
                }"#,
            ),
            ok_evidence("network.route.list", "[]"),
        ];
        let summary = normalize(&evidence, &platform(FirewallBackend::Fw3));
        assert_eq!(summary.assessment, WanAssessment::PrerequisitesReady);
        assert_eq!(summary.status_source.as_deref(), Some("ubus"));
        assert_eq!(summary.device.as_deref(), Some("eth0.2"));
        assert_eq!(summary.addresses, ["192.0.2.10/24"]);
        assert_eq!(
            summary.default_routes[0].gateway.as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(summary.dns_servers, ["192.0.2.53"]);
        assert_eq!(summary.firewall_backend, "fw3/iptables");
    }

    #[test]
    fn normalizes_kernel_fallback_and_detects_missing_dns() {
        let evidence = vec![
            ok_evidence(
                "network.route.list",
                r#"[{"dst":"default","gateway":"198.51.100.1","dev":"wan0","prefsrc":"198.51.100.20"}]"#,
            ),
            ok_evidence(
                "network.interface.address",
                r#"[{"ifname":"wan0","addr_info":[{"family":"inet","local":"198.51.100.20","prefixlen":24}]}]"#,
            ),
            ok_evidence(
                "network.interface.link",
                r#"[{"ifname":"wan0","operstate":"UP"}]"#,
            ),
        ];
        let summary = normalize(&evidence, &platform(FirewallBackend::Fw4));
        assert_eq!(summary.assessment, WanAssessment::DnsMissing);
        assert_eq!(summary.status_source.as_deref(), Some("kernel"));
        assert_eq!(summary.up, Some(true));
        assert_eq!(summary.addresses, ["198.51.100.20/24"]);
        assert_eq!(summary.firewall_backend, "fw4/nftables");
    }

    #[test]
    fn does_not_infer_a_fault_when_status_evidence_is_absent() {
        let summary = normalize(&[], &platform(FirewallBackend::Unknown));
        assert_eq!(summary.assessment, WanAssessment::InsufficientEvidence);
        assert!(
            summarize(&summary, &[])
                .iter()
                .any(|finding| finding.contains("evidence are unavailable"))
        );
    }

    #[tokio::test]
    async fn bounded_reader_discards_excess_bytes() {
        let input = &b"123456789"[..];
        let (output, truncated) = read_limited(input, 4).await.expect("bounded read");
        assert_eq!(output, b"1234");
        assert!(truncated);
    }

    #[tokio::test]
    async fn openwrt_fixture_collects_dns_and_fw4_evidence() {
        let fixture = Fixture::new();
        fixture.write(
            "tmp/resolv.conf.d/resolv.conf.auto",
            "nameserver 192.0.2.53\n",
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![],
            timeout: Duration::from_millis(100),
            max_output_bytes: 1024,
        };
        let report = runner
            .diagnose_wan(&platform(FirewallBackend::Fw4))
            .await
            .expect("fixture diagnosis");
        assert!(report.evidence.iter().any(|item| {
            item.probe == "network.dns.openwrt" && item.output.contains("192.0.2.53")
        }));
        assert!(report.evidence.iter().any(|item| {
            item.probe == "openwrt.firewall.backend" && item.output == "fw4/nftables"
        }));
        assert_eq!(report.summary.dns_servers, ["192.0.2.53"]);
        assert_eq!(report.summary.firewall_backend, "fw4/nftables");
    }

    fn ok_evidence(probe: &str, output: &str) -> ProbeEvidence {
        ProbeEvidence {
            probe: probe.into(),
            source: "fixture".into(),
            status: ProbeStatus::Ok,
            output: output.into(),
            truncated: false,
            duration_ms: 0,
        }
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
            let root = std::env::temp_dir().join(format!("mbed-agent-tools-test-{nonce}"));
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
