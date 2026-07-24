use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use agent_protocol::{
    DnsDiagnosticReport, DnsSummary, FirewallZoneSummary, ProbeEvidence, ProbeStatus,
    RouteDiagnosticReport, RouteSummary, WanAssessment, WanDiagnosticReport, WanRoute, WanSummary,
};
use platform_linux::{FirewallBackend, PlatformCapabilities, PlatformKind};
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
        active: bool,
    ) -> io::Result<WanDiagnosticReport> {
        let mut evidence = self.collect_passive(platform, DiagnosticScope::Wan).await?;
        let passive_summary = normalize(&evidence, platform);
        if active && passive_summary.assessment == WanAssessment::PrerequisitesReady {
            if let Some(gateway) = passive_summary
                .default_routes
                .iter()
                .filter_map(|route| route.gateway.as_deref())
                .find(|gateway| gateway.parse::<IpAddr>().is_ok())
            {
                evidence.push(
                    self.run_command(
                        "network.connectivity.gateway",
                        "ping",
                        &["-c", "1", "-W", "2", gateway],
                    )
                    .await?,
                );
            }
            evidence.push(
                self.run_command(
                    "network.connectivity.public_ip",
                    "ping",
                    &["-c", "1", "-W", "2", "1.1.1.1"],
                )
                .await?,
            );
            evidence.push(
                self.run_command("network.connectivity.dns", "nslookup", &["example.com"])
                    .await?,
            );
        }

        Ok(build_wan_report(evidence, platform))
    }

    /// Runs the deterministic, passive DNS prerequisite runbook.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_dns(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<DnsDiagnosticReport> {
        let evidence = self.collect_passive(platform, DiagnosticScope::Dns).await?;
        Ok(build_dns_report(evidence, platform))
    }

    /// Runs the deterministic, passive default-route prerequisite runbook.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_routes(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<RouteDiagnosticReport> {
        let evidence = self
            .collect_passive(platform, DiagnosticScope::Routes)
            .await?;
        Ok(build_route_report(evidence, platform))
    }

    async fn collect_passive(
        &self,
        platform: &PlatformCapabilities,
        scope: DiagnosticScope,
    ) -> io::Result<Vec<ProbeEvidence>> {
        let mut evidence = Vec::with_capacity(12);
        if platform.kind == PlatformKind::OpenWrt {
            evidence.push(self.run(Probe::UbusWan).await?);
        }
        for probe in [Probe::IpLink, Probe::IpAddress, Probe::IpRoute] {
            evidence.push(self.run(probe).await?);
        }
        if scope != DiagnosticScope::Dns {
            evidence.push(self.run(Probe::IpRule).await?);
        }
        if scope == DiagnosticScope::Wan && platform.kind == PlatformKind::OpenWrt {
            evidence.push(self.run(Probe::UciFirewall).await?);
        }
        if scope != DiagnosticScope::Routes {
            evidence
                .push(self.read_file("network.dns.openwrt", "/tmp/resolv.conf.d/resolv.conf.auto"));
            evidence.push(self.read_file(
                "network.dns.systemd_resolved",
                "/run/systemd/resolve/resolv.conf",
            ));
            evidence.push(self.read_file(
                "network.dns.network_manager",
                "/run/NetworkManager/resolv.conf",
            ));
            evidence.push(self.read_file("network.dns.system", "/etc/resolv.conf"));
        }
        if scope == DiagnosticScope::Wan {
            evidence.push(firewall_evidence(platform));
        }
        Ok(evidence)
    }

    async fn run(&self, probe: Probe) -> io::Result<ProbeEvidence> {
        self.run_command(probe.name(), probe.command(), probe.args())
            .await
    }

    async fn run_command(
        &self,
        probe: &str,
        command: &str,
        args: &[&str],
    ) -> io::Result<ProbeEvidence> {
        let Some(executable) = self.resolve(command) else {
            return Ok(ProbeEvidence {
                probe: probe.into(),
                source: command.into(),
                status: ProbeStatus::Unavailable,
                output: String::new(),
                truncated: false,
                duration_ms: 0,
            });
        };
        let started = Instant::now();
        let mut child = Command::new(&executable)
            .args(args)
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
            probe: probe.into(),
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
    UciFirewall,
    IpLink,
    IpAddress,
    IpRoute,
    IpRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagnosticScope {
    Wan,
    Dns,
    Routes,
}

impl Probe {
    const fn name(self) -> &'static str {
        match self {
            Self::UbusWan => "openwrt.interface.wan",
            Self::UciFirewall => "openwrt.firewall.uci",
            Self::IpLink => "network.interface.link",
            Self::IpAddress => "network.interface.address",
            Self::IpRoute => "network.route.list",
            Self::IpRule => "network.route.rules",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::UbusWan => "ubus",
            Self::UciFirewall => "uci",
            Self::IpLink | Self::IpAddress | Self::IpRoute | Self::IpRule => "ip",
        }
    }

    const fn args(self) -> &'static [&'static str] {
        match self {
            Self::UbusWan => &["call", "network.interface.wan", "status"],
            Self::UciFirewall => &["-q", "show", "firewall"],
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
        FirewallBackend::Iptables => "iptables",
        FirewallBackend::Nftables => "nftables",
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
            FirewallBackend::Iptables => "iptables",
            FirewallBackend::Nftables => "nftables",
            FirewallBackend::Unknown => "unknown",
        }
        .into(),
        firewall_zone: None,
        active_attempted: false,
        gateway_reachable: None,
        internet_reachable: None,
        dns_reachable: None,
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
    if let Some(output) = successful_output(evidence, "openwrt.firewall.uci") {
        summary.firewall_zone = parse_wan_firewall_zone(output);
    }
    for probe in [
        "network.dns.openwrt",
        "network.dns.systemd_resolved",
        "network.dns.network_manager",
        "network.dns.system",
    ] {
        if let Some(output) = successful_output(evidence, probe) {
            parse_resolvers(output, &mut summary.dns_servers);
        }
    }
    summary.active_attempted = evidence
        .iter()
        .any(|item| item.probe.starts_with("network.connectivity."));
    summary.gateway_reachable = probe_reachability(evidence, "network.connectivity.gateway");
    summary.internet_reachable = probe_reachability(evidence, "network.connectivity.public_ip");
    summary.dns_reachable = probe_reachability(evidence, "network.connectivity.dns");
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

#[derive(Debug, Default)]
struct UciZone {
    section: String,
    name: Option<String>,
    networks: Vec<String>,
    input_policy: Option<String>,
    output_policy: Option<String>,
    forward_policy: Option<String>,
    masquerading: bool,
}

fn parse_wan_firewall_zone(output: &str) -> Option<FirewallZoneSummary> {
    let mut zones: Vec<UciZone> = Vec::new();
    for line in output.lines() {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let Some(key) = key.strip_prefix("firewall.") else {
            continue;
        };
        if !key.contains('.') {
            if strip_uci_scalar(raw_value) == "zone" {
                zones.push(UciZone {
                    section: key.into(),
                    ..UciZone::default()
                });
            }
            continue;
        }
        let Some((section, option)) = key.rsplit_once('.') else {
            continue;
        };
        let Some(zone) = zones.iter_mut().find(|zone| zone.section == section) else {
            continue;
        };
        match option {
            "name" => zone.name = Some(strip_uci_scalar(raw_value)),
            "network" => zone.networks = parse_uci_list(raw_value),
            "input" => zone.input_policy = Some(strip_uci_scalar(raw_value)),
            "output" => zone.output_policy = Some(strip_uci_scalar(raw_value)),
            "forward" => zone.forward_policy = Some(strip_uci_scalar(raw_value)),
            "masq" => {
                zone.masquerading = matches!(
                    strip_uci_scalar(raw_value).as_str(),
                    "1" | "true" | "yes" | "on"
                );
            }
            _ => {}
        }
    }
    let zone = zones.into_iter().find(|zone| {
        zone.name.as_deref() == Some("wan") || zone.networks.iter().any(|network| network == "wan")
    })?;
    Some(FirewallZoneSummary {
        name: zone.name.unwrap_or_else(|| "wan".into()),
        networks: zone.networks,
        input_policy: zone.input_policy,
        output_policy: zone.output_policy,
        forward_policy: zone.forward_policy,
        masquerading: zone.masquerading,
    })
}

fn strip_uci_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character| character == '\'' || character == '"')
        .into()
}

fn parse_uci_list(value: &str) -> Vec<String> {
    let quoted: Vec<String> = value
        .split('\'')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, item)| item.to_owned())
        .collect();
    if quoted.is_empty() {
        value.split_whitespace().map(strip_uci_scalar).collect()
    } else {
        quoted
    }
}

fn probe_reachability(evidence: &[ProbeEvidence], probe: &str) -> Option<bool> {
    evidence
        .iter()
        .find(|item| item.probe == probe)
        .and_then(|item| match item.status {
            ProbeStatus::Ok => Some(true),
            ProbeStatus::Failed | ProbeStatus::TimedOut => Some(false),
            ProbeStatus::Unavailable => None,
        })
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
    } else if summary.gateway_reachable == Some(false) {
        WanAssessment::GatewayProbeFailed
    } else if summary.internet_reachable == Some(false) {
        WanAssessment::PublicIpProbeFailed
    } else if summary.dns_reachable == Some(false) {
        WanAssessment::DnsProbeFailed
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

fn summarize(
    summary: &WanSummary,
    evidence: &[ProbeEvidence],
    platform_kind: PlatformKind,
) -> Vec<String> {
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
        WanAssessment::GatewayProbeFailed => {
            "the configured gateway did not answer the active ICMP probe"
        }
        WanAssessment::PublicIpProbeFailed => {
            "the public IP target did not answer the active ICMP probe"
        }
        WanAssessment::DnsProbeFailed => "the active DNS resolution probe failed",
        WanAssessment::InsufficientEvidence => "WAN evidence is insufficient for a conclusion",
    };
    findings.push(primary.into());
    match (platform_kind, summary.status_source.as_deref()) {
        (PlatformKind::OpenWrt, Some("kernel")) => {
            findings.push("OpenWrt WAN status is unavailable; kernel evidence was used".into());
        }
        (PlatformKind::OpenWrt, None) => {
            findings.push("OpenWrt and kernel WAN status evidence are unavailable".into());
        }
        (_, None) => findings.push("kernel WAN status evidence is unavailable".into()),
        _ => {}
    }
    if summary.firewall_backend == "unknown" {
        findings.push(if platform_kind == PlatformKind::OpenWrt {
            "active fw3/fw4 firewall backend could not be identified".into()
        } else {
            "nftables/iptables firewall backend could not be identified".into()
        });
    }
    if summary.firewall_backend != "unknown"
        && successful_output(evidence, "openwrt.firewall.uci").is_some()
        && summary.firewall_zone.is_none()
    {
        findings.push("no UCI firewall zone is assigned to logical network wan".into());
    }
    if summary.active_attempted
        && summary.gateway_reachable.is_none()
        && summary.internet_reachable.is_none()
        && summary.dns_reachable.is_none()
    {
        findings.push("active connectivity tools are unavailable on this image".into());
    }
    if evidence.iter().any(|item| item.truncated) {
        findings.push("one or more probe outputs reached the configured byte limit".into());
    }
    findings
}

fn build_wan_report(
    evidence: Vec<ProbeEvidence>,
    platform: &PlatformCapabilities,
) -> WanDiagnosticReport {
    let summary = normalize(&evidence, platform);
    let findings = summarize(&summary, &evidence, platform.kind);
    let complete = summary.status_source.is_some()
        && !summary.addresses.is_empty()
        && !summary.default_routes.is_empty()
        && !summary.dns_servers.is_empty();
    WanDiagnosticReport {
        interface: WAN_INTERFACE.into(),
        summary,
        evidence,
        findings,
        complete,
    }
}

fn build_dns_report(
    evidence: Vec<ProbeEvidence>,
    platform: &PlatformCapabilities,
) -> DnsDiagnosticReport {
    let wan = normalize(&evidence, platform);
    let assessment = assess_dns(&wan);
    let summary = DnsSummary {
        assessment,
        status_source: wan.status_source,
        device: wan.device,
        addresses: wan.addresses,
        default_routes: wan.default_routes,
        dns_servers: wan.dns_servers,
        dns_reachable: wan.dns_reachable,
    };
    let complete = summary.status_source.is_some()
        && !summary.addresses.is_empty()
        && !summary.default_routes.is_empty()
        && !summary.dns_servers.is_empty();
    let findings = focused_findings(
        assessment,
        &evidence,
        platform.kind,
        summary.status_source.as_deref(),
        "DNS resolver configuration prerequisites are present; no active DNS query was sent",
    );
    DnsDiagnosticReport {
        interface: WAN_INTERFACE.into(),
        summary,
        evidence,
        findings,
        complete,
    }
}

fn build_route_report(
    evidence: Vec<ProbeEvidence>,
    platform: &PlatformCapabilities,
) -> RouteDiagnosticReport {
    let wan = normalize(&evidence, platform);
    let assessment = assess_routes(&wan);
    let summary = RouteSummary {
        assessment,
        status_source: wan.status_source,
        device: wan.device,
        addresses: wan.addresses,
        default_routes: wan.default_routes,
    };
    let complete = summary.status_source.is_some()
        && !summary.addresses.is_empty()
        && !summary.default_routes.is_empty();
    let findings = focused_findings(
        assessment,
        &evidence,
        platform.kind,
        summary.status_source.as_deref(),
        "WAN address and default-route prerequisites are present",
    );
    RouteDiagnosticReport {
        interface: WAN_INTERFACE.into(),
        summary,
        evidence,
        findings,
        complete,
    }
}

fn assess_routes(summary: &WanSummary) -> WanAssessment {
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
    } else {
        WanAssessment::PrerequisitesReady
    }
}

fn assess_dns(summary: &WanSummary) -> WanAssessment {
    let route_assessment = assess_routes(summary);
    if route_assessment != WanAssessment::PrerequisitesReady {
        route_assessment
    } else if summary.dns_servers.is_empty() {
        WanAssessment::DnsMissing
    } else if summary.dns_reachable == Some(false) {
        WanAssessment::DnsProbeFailed
    } else {
        WanAssessment::PrerequisitesReady
    }
}

fn focused_findings(
    assessment: WanAssessment,
    evidence: &[ProbeEvidence],
    platform_kind: PlatformKind,
    status_source: Option<&str>,
    ready: &str,
) -> Vec<String> {
    let primary = match assessment {
        WanAssessment::PrerequisitesReady => ready,
        WanAssessment::LinkDown => "WAN link or logical interface is down",
        WanAssessment::InterfaceUnavailable => "WAN interface is unavailable",
        WanAssessment::AddressMissing => "WAN has no usable IP address",
        WanAssessment::DefaultRouteMissing => "WAN has no default route",
        WanAssessment::DnsMissing => "WAN has no configured DNS resolver",
        WanAssessment::DnsProbeFailed => "the active DNS resolution probe failed",
        WanAssessment::GatewayProbeFailed => "the active gateway probe failed",
        WanAssessment::PublicIpProbeFailed => "the active public-IP probe failed",
        WanAssessment::InsufficientEvidence => "network evidence is insufficient for a conclusion",
    };
    let mut findings = vec![primary.into()];
    match (platform_kind, status_source) {
        (PlatformKind::OpenWrt, Some("kernel")) => {
            findings.push("OpenWrt WAN status is unavailable; kernel evidence was used".into());
        }
        (PlatformKind::OpenWrt, None) => {
            findings.push("OpenWrt and kernel WAN status evidence are unavailable".into());
        }
        (_, None) => findings.push("kernel WAN status evidence is unavailable".into()),
        _ => {}
    }
    if evidence.iter().any(|item| item.truncated) {
        findings.push("one or more probe outputs reached the configured byte limit".into());
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_linux::{
        FirewallCapabilities, InitSystem, NetworkDeviceModel, PackageManager, PlatformKind,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

    fn platform(backend: FirewallBackend) -> PlatformCapabilities {
        PlatformCapabilities {
            kind: PlatformKind::OpenWrt,
            release: Some("21.02.7".into()),
            release_supported: true,
            firewall: FirewallCapabilities {
                backend,
                has_iptables_save: matches!(
                    backend,
                    FirewallBackend::Fw3 | FirewallBackend::Iptables
                ),
                has_ip6tables_save: matches!(
                    backend,
                    FirewallBackend::Fw3 | FirewallBackend::Iptables
                ),
                has_nft: matches!(backend, FirewallBackend::Fw4 | FirewallBackend::Nftables),
                can_trace: matches!(backend, FirewallBackend::Fw4 | FirewallBackend::Nftables),
            },
            device_model: NetworkDeviceModel::Unknown,
            package_manager: PackageManager::Opkg,
            init_system: InitSystem::Procd,
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
    fn normalizes_anonymous_fw3_wan_zone() {
        let zone = parse_wan_firewall_zone(
            "firewall.@zone[1]=zone\n\
             firewall.@zone[1].name='wan'\n\
             firewall.@zone[1].network='wan' 'wan6'\n\
             firewall.@zone[1].input='REJECT'\n\
             firewall.@zone[1].output='ACCEPT'\n\
             firewall.@zone[1].forward='REJECT'\n\
             firewall.@zone[1].masq='1'\n",
        )
        .expect("WAN zone");
        assert_eq!(zone.networks, ["wan", "wan6"]);
        assert_eq!(zone.input_policy.as_deref(), Some("REJECT"));
        assert!(zone.masquerading);
    }

    #[test]
    fn normalizes_named_fw4_wan_zone() {
        let zone = parse_wan_firewall_zone(
            "firewall.wan=zone\n\
             firewall.wan.name='external'\n\
             firewall.wan.network='wan'\n\
             firewall.wan.input='DROP'\n\
             firewall.wan.output='ACCEPT'\n\
             firewall.wan.forward='DROP'\n",
        )
        .expect("WAN zone");
        assert_eq!(zone.name, "external");
        assert_eq!(zone.forward_policy.as_deref(), Some("DROP"));
        assert!(!zone.masquerading);
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
    fn active_probe_failure_is_reported_without_claiming_root_cause() {
        let evidence = vec![
            ok_evidence(
                "openwrt.interface.wan",
                r#"{
                    "up":true,"available":true,"l3_device":"wan0",
                    "ipv4-address":[{"address":"192.0.2.10","mask":24}],
                    "route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.0.2.1"}],
                    "dns-server":["192.0.2.53"]
                }"#,
            ),
            status_evidence("network.connectivity.gateway", ProbeStatus::Failed),
        ];
        let summary = normalize(&evidence, &platform(FirewallBackend::Fw4));
        assert_eq!(summary.assessment, WanAssessment::GatewayProbeFailed);
        assert_eq!(summary.gateway_reachable, Some(false));
        assert!(
            summarize(&summary, &evidence, PlatformKind::OpenWrt)
                .first()
                .is_some_and(|finding| finding.contains("did not answer"))
        );
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
            summarize(&summary, &[], PlatformKind::OpenWrt)
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
            .diagnose_wan(&platform(FirewallBackend::Fw4), false)
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

    #[tokio::test]
    async fn generic_linux_uses_resolved_dns_without_openwrt_probes() {
        let fixture = Fixture::new();
        fixture.write(
            "run/systemd/resolve/resolv.conf",
            "nameserver 2001:db8::53\n",
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![],
            timeout: Duration::from_millis(100),
            max_output_bytes: 1024,
        };
        let mut generic = platform(FirewallBackend::Nftables);
        generic.kind = PlatformKind::GenericLinux;
        let report = runner
            .diagnose_wan(&generic, false)
            .await
            .expect("generic Linux diagnosis");
        assert_eq!(report.summary.dns_servers, ["2001:db8::53"]);
        assert_eq!(report.summary.firewall_backend, "nftables");
        assert!(!report.evidence.iter().any(|item| {
            matches!(
                item.probe.as_str(),
                "openwrt.interface.wan" | "openwrt.firewall.uci"
            )
        }));
    }

    #[tokio::test]
    async fn generic_linux_dns_runbook_collects_only_required_passive_evidence() {
        let fixture = Fixture::new();
        fixture.write(
            "run/systemd/resolve/resolv.conf",
            "nameserver 2001:db8::53\n",
        );
        fixture.executable(
            "bin/ip",
            r#"#!/bin/sh
printf '%s\n' '[{"dst":"default","gateway":"198.51.100.1","dev":"eth0","prefsrc":"198.51.100.20","ifname":"eth0","operstate":"UP","addr_info":[{"local":"198.51.100.20","prefixlen":24}]}]'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: Duration::from_secs(3),
            max_output_bytes: 4096,
        };
        let mut generic = platform(FirewallBackend::Nftables);
        generic.kind = PlatformKind::GenericLinux;
        let report = runner
            .diagnose_dns(&generic)
            .await
            .expect("generic DNS diagnosis");
        assert_eq!(report.summary.assessment, WanAssessment::PrerequisitesReady);
        assert_eq!(report.summary.status_source.as_deref(), Some("kernel"));
        assert_eq!(report.summary.dns_servers, ["2001:db8::53"]);
        assert!(report.complete);
        assert!(!report.evidence.iter().any(|item| {
            matches!(
                item.probe.as_str(),
                "network.route.rules" | "openwrt.firewall.uci" | "openwrt.firewall.backend"
            )
        }));
    }

    #[tokio::test]
    async fn openwrt_route_runbook_excludes_dns_and_firewall_collectors() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ubus",
            r#"#!/bin/sh
printf '%s\n' '{"up":true,"available":true,"l3_device":"wan0","ipv4-address":[{"address":"192.0.2.10","mask":24}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.0.2.1"}]}'
"#,
        );
        fixture.executable("bin/ip", "#!/bin/sh\nprintf '%s\\n' '[]'\n");
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: Duration::from_secs(3),
            max_output_bytes: 4096,
        };
        let report = runner
            .diagnose_routes(&platform(FirewallBackend::Fw3))
            .await
            .expect("OpenWrt route diagnosis");
        assert_eq!(report.summary.assessment, WanAssessment::PrerequisitesReady);
        assert_eq!(report.summary.status_source.as_deref(), Some("ubus"));
        assert!(report.complete);
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.probe == "network.route.rules")
        );
        assert!(!report.evidence.iter().any(|item| {
            item.probe.starts_with("network.dns.") || item.probe.starts_with("openwrt.firewall.")
        }));
    }

    #[tokio::test]
    async fn active_fixture_runs_only_typed_connectivity_commands() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ubus",
            r#"#!/bin/sh
printf '%s\n' '{"up":true,"available":true,"l3_device":"wan0","ipv4-address":[{"address":"192.0.2.10","mask":24}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.0.2.1"}],"dns-server":["192.0.2.53"]}'
"#,
        );
        fixture.executable("bin/ip", "#!/bin/sh\nprintf '%s\\n' '[]'\n");
        fixture.executable("bin/ping", "#!/bin/sh\nexit 0\n");
        fixture.executable(
            "bin/nslookup",
            "#!/bin/sh\nprintf '%s\\n' 'Address: 93.184.216.34'\n",
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: Duration::from_secs(3),
            max_output_bytes: 4096,
        };
        let report = runner
            .diagnose_wan(&platform(FirewallBackend::Fw4), true)
            .await
            .expect("active fixture diagnosis");
        assert!(report.summary.active_attempted, "{report:#?}");
        assert_eq!(report.summary.gateway_reachable, Some(true));
        assert_eq!(report.summary.internet_reachable, Some(true));
        assert_eq!(report.summary.dns_reachable, Some(true));
        assert_eq!(report.summary.assessment, WanAssessment::PrerequisitesReady);
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

    fn status_evidence(probe: &str, status: ProbeStatus) -> ProbeEvidence {
        ProbeEvidence {
            probe: probe.into(),
            source: "fixture".into(),
            status,
            output: String::new(),
            truncated: false,
            duration_ms: 1,
        }
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let fixture_id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "mbed-agent-tools-test-{}-{fixture_id}",
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

        fn executable(&self, relative: &str, content: &str) {
            self.write(relative, content);
            let path = self.root.join(relative);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("make fixture executable");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
