use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use agent_protocol::{
    ConntrackAssessment, ConntrackDiagnosticReport, ConntrackSummary, DhcpAssessment,
    DhcpDiagnosticReport, DhcpSummary, DnsDiagnosticReport, DnsSummary, FirewallAssessment,
    FirewallBaseChain, FirewallDiagnosticReport, FirewallRuntimeSummary, FirewallZoneSummary,
    InterfaceAssessment, InterfaceDiagnosticReport, InterfaceStatsAssessment,
    InterfaceStatsDiagnosticReport, InterfaceStatsEntry, InterfaceStatsSummary, InterfaceSummary,
    ListenerAssessment, ListenerDiagnosticReport, ListenerEntry, ListenerScope, ListenerSummary,
    NeighborAssessment, NeighborDiagnosticReport, NeighborEntry, NeighborSummary,
    NetworkInterfaceSummary, PolicyRoutingAssessment, PolicyRoutingDiagnosticReport,
    PolicyRoutingSummary, PolicyRule, ProbeEvidence, ProbeStatus, QdiscAssessment,
    QdiscDiagnosticReport, QdiscEntry, QdiscSummary, RouteDiagnosticReport, RouteSummary,
    RouteTableSummary, WanAssessment, WanDiagnosticReport, WanRoute, WanSummary,
    WirelessAssessment, WirelessDiagnosticReport, WirelessInterfaceSummary, WirelessRadioSummary,
    WirelessSummary,
};
use platform_linux::{FirewallBackend, PlatformCapabilities, PlatformKind};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

const WAN_INTERFACE: &str = "wan";
const MAX_INTERFACES: usize = 32;
const MAX_ADDRESSES_PER_INTERFACE: usize = 8;
const MAX_NEIGHBORS: usize = 64;
const MAX_NEIGHBOR_STATES: usize = 4;
const MAX_FIREWALL_BASE_CHAINS: usize = 32;
const MAX_POLICY_RULES: usize = 64;
const MAX_ROUTE_TABLES: usize = 32;
const MAX_LISTENERS: usize = 128;
const MAX_WIRELESS_RADIOS: usize = 16;
const MAX_WIRELESS_INTERFACES: usize = 32;
const MAX_INTERFACE_STATS: usize = 32;
const MAX_QDISCS: usize = 64;

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

    /// Runs the deterministic, passive DHCP state runbook.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_dhcp(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<DhcpDiagnosticReport> {
        let evidence = self
            .collect_passive(platform, DiagnosticScope::Dhcp)
            .await?;
        Ok(build_dhcp_report(evidence, platform))
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

    /// Inventories kernel network interfaces using bounded, passive collectors.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_interfaces(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<InterfaceDiagnosticReport> {
        let evidence = self
            .collect_passive(platform, DiagnosticScope::Interfaces)
            .await?;
        Ok(build_interface_report(evidence))
    }

    /// Inventories the bounded kernel ARP/NDP neighbor cache.
    ///
    /// # Errors
    ///
    /// Returns an error only when the resolved collector cannot be executed.
    pub async fn diagnose_neighbors(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<NeighborDiagnosticReport> {
        let evidence = self
            .collect_passive(platform, DiagnosticScope::Neighbors)
            .await?;
        Ok(build_neighbor_report(evidence))
    }

    /// Inspects the active firewall ruleset without exposing rule expressions.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_firewall(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<FirewallDiagnosticReport> {
        let evidence = match platform.firewall.backend {
            FirewallBackend::Fw4 | FirewallBackend::Nftables => vec![
                self.run_command(
                    "network.firewall.nftables",
                    "nft",
                    &["-j", "list", "ruleset"],
                )
                .await?,
            ],
            FirewallBackend::Fw3 | FirewallBackend::Iptables => {
                let mut evidence = vec![
                    self.run_command("network.firewall.iptables_ipv4", "iptables-save", &["-c"])
                        .await?,
                ];
                evidence.push(
                    self.run_command("network.firewall.iptables_ipv6", "ip6tables-save", &["-c"])
                        .await?,
                );
                evidence
            }
            FirewallBackend::Unknown => vec![ProbeEvidence {
                probe: "network.firewall.runtime".into(),
                source: "capability-discovery".into(),
                status: ProbeStatus::Unavailable,
                output: String::new(),
                truncated: false,
                duration_ms: 0,
            }],
        };
        Ok(build_firewall_report(evidence, platform.firewall.backend))
    }

    /// Inspects bounded policy rules and aggregate route-table state.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_policy_routing(&self) -> io::Result<PolicyRoutingDiagnosticReport> {
        let evidence = vec![
            self.run(Probe::IpRule).await?,
            self.run(Probe::IpRoute).await?,
        ];
        Ok(build_policy_routing_report(evidence))
    }

    /// Inspects bounded TCP/UDP listeners without collecting process identities.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_listeners(&self) -> io::Result<ListenerDiagnosticReport> {
        let evidence = if self.resolve("ss").is_some() {
            vec![
                self.run_command("network.socket.listeners", "ss", &["-H", "-lntu"])
                    .await?,
            ]
        } else {
            vec![
                self.run_command("network.socket.listeners", "netstat", &["-lntu"])
                    .await?,
            ]
        };
        Ok(build_listener_report(evidence))
    }

    /// Inspects bounded wireless radio and interface state without scanning.
    ///
    /// # Errors
    ///
    /// Returns an error only when a resolved collector cannot be executed.
    pub async fn diagnose_wireless(
        &self,
        platform: &PlatformCapabilities,
    ) -> io::Result<WirelessDiagnosticReport> {
        let mut evidence = Vec::with_capacity(2);
        if platform.kind == PlatformKind::OpenWrt && platform.has_ubus {
            evidence.push(
                self.run_command(
                    "openwrt.wireless.status",
                    "ubus",
                    &["call", "network.wireless", "status"],
                )
                .await?,
            );
        }
        if self.resolve("iw").is_some() {
            evidence.push(
                self.run_command("network.wireless.iw", "iw", &["dev"])
                    .await?,
            );
        } else {
            evidence.push(
                self.run_command("network.wireless.iwinfo", "iwinfo", &[])
                    .await?,
            );
        }
        Ok(build_wireless_report(evidence))
    }

    /// Inspects one bounded snapshot of kernel interface counters.
    ///
    /// # Errors
    ///
    /// Returns an error only when the resolved collector cannot be executed.
    pub async fn diagnose_interface_stats(&self) -> io::Result<InterfaceStatsDiagnosticReport> {
        let evidence = vec![self.run(Probe::IpLinkStats).await?];
        Ok(build_interface_stats_report(evidence))
    }

    /// Inspects the bounded kernel connection-tracking count and configured limit.
    #[must_use]
    pub fn diagnose_conntrack(&self) -> ConntrackDiagnosticReport {
        let evidence = vec![
            self.read_file(
                "network.conntrack.count",
                "/proc/sys/net/netfilter/nf_conntrack_count",
            ),
            self.read_file(
                "network.conntrack.limit",
                "/proc/sys/net/netfilter/nf_conntrack_max",
            ),
        ];
        build_conntrack_report(evidence)
    }

    /// Inspects one bounded snapshot of queueing-discipline counters.
    ///
    /// # Errors
    ///
    /// Returns an error only when the resolved collector cannot be executed.
    pub async fn diagnose_qdisc(&self) -> io::Result<QdiscDiagnosticReport> {
        let evidence = vec![self.run(Probe::TcQdiscStats).await?];
        Ok(build_qdisc_report(evidence))
    }

    async fn collect_passive(
        &self,
        platform: &PlatformCapabilities,
        scope: DiagnosticScope,
    ) -> io::Result<Vec<ProbeEvidence>> {
        if scope == DiagnosticScope::Neighbors {
            return Ok(vec![self.run(Probe::IpNeighbor).await?]);
        }
        let mut evidence = Vec::with_capacity(12);
        if platform.kind == PlatformKind::OpenWrt && scope != DiagnosticScope::Interfaces {
            evidence.push(self.run(Probe::UbusWan).await?);
        }
        for probe in [Probe::IpLink, Probe::IpAddress] {
            evidence.push(self.run(probe).await?);
        }
        if scope != DiagnosticScope::Interfaces {
            evidence.push(self.run(Probe::IpRoute).await?);
        }
        if matches!(scope, DiagnosticScope::Wan | DiagnosticScope::Routes) {
            evidence.push(self.run(Probe::IpRule).await?);
        }
        if scope == DiagnosticScope::Wan && platform.kind == PlatformKind::OpenWrt {
            evidence.push(self.run(Probe::UciFirewall).await?);
        }
        if matches!(scope, DiagnosticScope::Wan | DiagnosticScope::Dns) {
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
    IpNeighbor,
    IpLinkStats,
    TcQdiscStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagnosticScope {
    Wan,
    Dns,
    Dhcp,
    Routes,
    Interfaces,
    Neighbors,
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
            Self::IpNeighbor => "network.neighbor.list",
            Self::IpLinkStats => "network.interface.stats",
            Self::TcQdiscStats => "network.qdisc.stats",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::UbusWan => "ubus",
            Self::UciFirewall => "uci",
            Self::IpLink
            | Self::IpAddress
            | Self::IpRoute
            | Self::IpRule
            | Self::IpNeighbor
            | Self::IpLinkStats => "ip",
            Self::TcQdiscStats => "tc",
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
            Self::IpNeighbor => &["-j", "neighbor", "show"],
            Self::IpLinkStats => &["-j", "-s", "link", "show"],
            Self::TcQdiscStats => &["-j", "-s", "qdisc", "show"],
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
            let dynamic = address
                .get("dynamic")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || address
                    .get("flags")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|flags| {
                        flags.iter().any(|flag| {
                            flag.as_str()
                                .is_some_and(|flag| flag.eq_ignore_ascii_case("dynamic"))
                        })
                    });
            if dynamic && summary.protocol.is_none() {
                summary.protocol = Some("dhcp-inferred".into());
            }
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

fn build_dhcp_report(
    evidence: Vec<ProbeEvidence>,
    platform: &PlatformCapabilities,
) -> DhcpDiagnosticReport {
    let wan = normalize(&evidence, platform);
    let assessment = assess_dhcp(&wan);
    let summary = DhcpSummary {
        assessment,
        status_source: wan.status_source,
        protocol: wan.protocol,
        pending: wan.pending,
        device: wan.device,
        addresses: wan.addresses,
    };
    let primary = match assessment {
        DhcpAssessment::LeaseReady => {
            "a DHCP-derived WAN address is present; lease renewal was not attempted"
        }
        DhcpAssessment::Negotiating => "the WAN DHCP client is still negotiating a lease",
        DhcpAssessment::LeaseMissing => "the WAN is configured for DHCP but has no leased address",
        DhcpAssessment::NotDhcp => "the WAN protocol is not DHCP",
        DhcpAssessment::LinkDown => "the WAN link or logical interface is down",
        DhcpAssessment::InterfaceUnavailable => "the WAN interface is unavailable",
        DhcpAssessment::InsufficientEvidence => {
            "DHCP state evidence is insufficient for a conclusion"
        }
    };
    let mut findings = vec![primary.into()];
    match (platform.kind, summary.status_source.as_deref()) {
        (PlatformKind::OpenWrt, Some("kernel")) => {
            findings.push("OpenWrt WAN status is unavailable; kernel evidence was used".into());
        }
        (PlatformKind::OpenWrt, None) => {
            findings.push("OpenWrt and kernel WAN status evidence are unavailable".into());
        }
        (_, None) if summary.protocol.is_none() => findings
            .push("kernel evidence does not identify a dynamic address or WAN protocol".into()),
        (_, None) => findings.push(
            "WAN status source is unavailable; DHCP was inferred from kernel address metadata"
                .into(),
        ),
        _ => {}
    }
    if summary.protocol.as_deref() == Some("dhcp-inferred") {
        findings.push(
            "DHCP was inferred from a kernel dynamic-address flag; no client lease file was read"
                .into(),
        );
    }
    if evidence.iter().any(|item| item.truncated) {
        findings.push("one or more probe outputs reached the configured byte limit".into());
    }
    DhcpDiagnosticReport {
        interface: WAN_INTERFACE.into(),
        summary,
        evidence,
        findings,
        complete: assessment != DhcpAssessment::InsufficientEvidence,
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

fn build_interface_report(evidence: Vec<ProbeEvidence>) -> InterfaceDiagnosticReport {
    let mut interfaces = Vec::new();
    let mut truncated = false;
    if let Some(output) = successful_output(&evidence, "network.interface.link") {
        parse_interface_links(output, &mut interfaces, &mut truncated);
    }
    if let Some(output) = successful_output(&evidence, "network.interface.address") {
        parse_interface_addresses(output, &mut interfaces, &mut truncated);
    }
    interfaces.sort_by(|left, right| {
        left.index
            .unwrap_or(u64::MAX)
            .cmp(&right.index.unwrap_or(u64::MAX))
            .then_with(|| left.name.cmp(&right.name))
    });
    let has_link_evidence = successful_output(&evidence, "network.interface.link").is_some();
    let has_usable_interface = interfaces.iter().any(|interface| interface.name != "lo");
    let has_ready_interface = interfaces.iter().any(|interface| {
        interface.name != "lo"
            && (interface.up == Some(true)
                || interface.carrier == Some(true)
                || !interface.addresses.is_empty())
    });
    let assessment = if !has_link_evidence {
        InterfaceAssessment::InsufficientEvidence
    } else if !has_usable_interface {
        InterfaceAssessment::NoUsableInterfaces
    } else if has_ready_interface {
        InterfaceAssessment::InterfacesReady
    } else {
        InterfaceAssessment::LinksDown
    };
    let mut findings =
        vec![match assessment {
        InterfaceAssessment::InterfacesReady => {
            "one or more non-loopback interfaces are up, have carrier, or hold an IP address"
        }
        InterfaceAssessment::LinksDown => {
            "network interfaces were found, but no non-loopback interface is operational"
        }
        InterfaceAssessment::NoUsableInterfaces => {
            "only the loopback interface is present"
        }
        InterfaceAssessment::InsufficientEvidence => {
            "kernel interface evidence is unavailable"
        }
    }
    .into()];
    if truncated || evidence.iter().any(|item| item.truncated) {
        findings
            .push("interface inventory reached a configured byte or normalized-entry limit".into());
    }
    let complete = has_link_evidence
        && successful_output(&evidence, "network.interface.address").is_some()
        && !truncated
        && !evidence.iter().any(|item| item.truncated);
    InterfaceDiagnosticReport {
        summary: InterfaceSummary {
            assessment,
            interfaces,
            truncated,
        },
        evidence,
        findings,
        complete,
    }
}

fn parse_interface_links(
    output: &str,
    interfaces: &mut Vec<NetworkInterfaceSummary>,
    truncated: &mut bool,
) {
    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for item in items {
        let Some(name) = bounded_json_string(&item, "ifname", 64) else {
            continue;
        };
        if interfaces.len() >= MAX_INTERFACES {
            *truncated = true;
            break;
        }
        let flags = item.get("flags").and_then(serde_json::Value::as_array);
        let flag = |expected: &str| {
            flags.is_some_and(|flags| {
                flags.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
                })
            })
        };
        let operstate = bounded_json_string(&item, "operstate", 32);
        let up = if flag("UP") {
            Some(true)
        } else {
            operstate
                .as_deref()
                .map(|state| state.eq_ignore_ascii_case("up"))
        };
        let carrier = if flag("LOWER_UP") {
            Some(true)
        } else if flag("NO-CARRIER") {
            Some(false)
        } else {
            None
        };
        let kind = item
            .get("linkinfo")
            .and_then(|value| bounded_json_string(value, "info_kind", 64))
            .or_else(|| bounded_json_string(&item, "link_type", 64));
        interfaces.push(NetworkInterfaceSummary {
            name,
            index: item.get("ifindex").and_then(serde_json::Value::as_u64),
            kind,
            operstate,
            up,
            carrier,
            mtu: item.get("mtu").and_then(serde_json::Value::as_u64),
            master: bounded_json_string(&item, "master", 64),
            addresses: Vec::new(),
            dynamic_address: false,
        });
    }
}

fn parse_interface_addresses(
    output: &str,
    interfaces: &mut [NetworkInterfaceSummary],
    truncated: &mut bool,
) {
    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for item in items {
        let Some(name) = bounded_json_string(&item, "ifname", 64) else {
            continue;
        };
        let Some(interface) = interfaces
            .iter_mut()
            .find(|interface| interface.name == name)
        else {
            continue;
        };
        let Some(addresses) = item.get("addr_info").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for address in addresses {
            let Some(local) = address
                .get("local")
                .and_then(serde_json::Value::as_str)
                .filter(|local| local.parse::<IpAddr>().is_ok())
            else {
                continue;
            };
            if interface.addresses.len() >= MAX_ADDRESSES_PER_INTERFACE {
                *truncated = true;
                break;
            }
            let maximum_prefix = if local.contains(':') { 128 } else { 32 };
            let prefix = address
                .get("prefixlen")
                .and_then(serde_json::Value::as_u64)
                .filter(|prefix| *prefix <= maximum_prefix)
                .unwrap_or(maximum_prefix);
            push_unique(&mut interface.addresses, format!("{local}/{prefix}"));
            interface.dynamic_address |= address
                .get("dynamic")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || address
                    .get("flags")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|flags| {
                        flags.iter().any(|flag| {
                            flag.as_str()
                                .is_some_and(|flag| flag.eq_ignore_ascii_case("dynamic"))
                        })
                    });
        }
    }
}

fn bounded_json_string(value: &serde_json::Value, key: &str, limit: usize) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

fn build_neighbor_report(evidence: Vec<ProbeEvidence>) -> NeighborDiagnosticReport {
    let mut entries = Vec::new();
    let mut truncated = false;
    let has_evidence = successful_output(&evidence, "network.neighbor.list").is_some();
    if let Some(output) = successful_output(&evidence, "network.neighbor.list") {
        parse_neighbors(output, &mut entries, &mut truncated);
    }
    entries.sort_by(|left, right| {
        left.device
            .cmp(&right.device)
            .then_with(|| left.destination.cmp(&right.destination))
    });
    let has_failures = entries.iter().any(|entry| {
        entry
            .states
            .iter()
            .any(|state| matches!(state.as_str(), "FAILED" | "INCOMPLETE"))
    });
    let assessment = if !has_evidence {
        NeighborAssessment::InsufficientEvidence
    } else if has_failures {
        NeighborAssessment::ResolutionFailuresPresent
    } else if entries.is_empty() {
        NeighborAssessment::NoEntries
    } else {
        NeighborAssessment::NeighborsPresent
    };
    let mut findings = vec![match assessment {
        NeighborAssessment::NeighborsPresent => {
            "the kernel neighbor cache contains ARP/NDP entries; reachability beyond the cache was not tested"
        }
        NeighborAssessment::ResolutionFailuresPresent => {
            "one or more ARP/NDP entries are incomplete or failed; this does not by itself identify the root cause"
        }
        NeighborAssessment::NoEntries => {
            "the kernel neighbor cache is empty; no active traffic was generated to populate it"
        }
        NeighborAssessment::InsufficientEvidence => {
            "kernel ARP/NDP neighbor evidence is unavailable"
        }
    }
    .into()];
    if truncated || evidence.iter().any(|item| item.truncated) {
        findings
            .push("neighbor inventory reached a configured byte or normalized-entry limit".into());
    }
    NeighborDiagnosticReport {
        summary: NeighborSummary {
            assessment,
            entries,
            truncated,
        },
        complete: has_evidence && !truncated && !evidence.iter().any(|item| item.truncated),
        evidence,
        findings,
    }
}

fn parse_neighbors(output: &str, entries: &mut Vec<NeighborEntry>, truncated: &mut bool) {
    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for item in items {
        if entries.len() >= MAX_NEIGHBORS {
            *truncated = true;
            break;
        }
        let Some(destination) = item
            .get("dst")
            .and_then(serde_json::Value::as_str)
            .and_then(|destination| destination.parse::<IpAddr>().ok())
            .map(|destination| destination.to_string())
        else {
            continue;
        };
        let Some(device) = bounded_json_string(&item, "dev", 64) else {
            continue;
        };
        let mut states = Vec::new();
        if let Some(state) = item.get("state") {
            if let Some(state) = state.as_str() {
                push_neighbor_state(&mut states, state);
            } else if let Some(values) = state.as_array() {
                for state in values.iter().filter_map(serde_json::Value::as_str) {
                    if states.len() >= MAX_NEIGHBOR_STATES {
                        *truncated = true;
                        break;
                    }
                    push_neighbor_state(&mut states, state);
                }
            }
        }
        let link_address = bounded_json_string(&item, "lladdr", 64)
            .filter(|address| valid_link_address(address))
            .map(|address| address.to_ascii_lowercase());
        let entry = NeighborEntry {
            destination,
            device,
            link_address,
            states,
            router: item
                .get("router")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        };
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
}

fn push_neighbor_state(states: &mut Vec<String>, state: &str) {
    let state = state.to_ascii_uppercase();
    if matches!(
        state.as_str(),
        "NONE"
            | "INCOMPLETE"
            | "REACHABLE"
            | "STALE"
            | "DELAY"
            | "PROBE"
            | "FAILED"
            | "NOARP"
            | "PERMANENT"
    ) {
        push_unique(states, state);
    }
}

fn valid_link_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 64
        && address
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'-' | b'.'))
}

fn build_firewall_report(
    evidence: Vec<ProbeEvidence>,
    backend: FirewallBackend,
) -> FirewallDiagnosticReport {
    let mut summary = FirewallRuntimeSummary {
        assessment: FirewallAssessment::InsufficientEvidence,
        backend: firewall_backend_name(backend).into(),
        tables: 0,
        chains: 0,
        rules: 0,
        rules_with_counters: 0,
        base_chains: Vec::new(),
        truncated: false,
    };
    if let Some(output) = successful_output(&evidence, "network.firewall.nftables") {
        parse_nft_ruleset(output, &mut summary);
    }
    for (probe, family) in [
        ("network.firewall.iptables_ipv4", "ipv4"),
        ("network.firewall.iptables_ipv6", "ipv6"),
    ] {
        if let Some(output) = successful_output(&evidence, probe) {
            parse_iptables_save(output, family, &mut summary);
        }
    }
    let has_runtime_evidence = evidence.iter().any(|item| item.status == ProbeStatus::Ok);
    summary.assessment = if backend == FirewallBackend::Unknown || !has_runtime_evidence {
        FirewallAssessment::BackendUnavailable
    } else if summary.rules == 0 {
        FirewallAssessment::EmptyRuleset
    } else {
        FirewallAssessment::RuntimeRulesPresent
    };
    let mut findings = vec![match summary.assessment {
        FirewallAssessment::RuntimeRulesPresent => {
            "runtime firewall tables, chains, and rules are present; rule expressions were not normalized"
        }
        FirewallAssessment::EmptyRuleset => {
            "the detected firewall backend returned no runtime rules"
        }
        FirewallAssessment::BackendUnavailable => {
            "the runtime firewall backend or its read-only inspection command is unavailable"
        }
        FirewallAssessment::InsufficientEvidence => {
            "runtime firewall evidence is insufficient"
        }
    }
    .into()];
    if summary.truncated || evidence.iter().any(|item| item.truncated) {
        findings
            .push("firewall inspection reached a configured byte or normalized-entry limit".into());
    }
    FirewallDiagnosticReport {
        complete: has_runtime_evidence
            && !summary.truncated
            && !evidence.iter().any(|item| item.truncated),
        summary,
        evidence,
        findings,
    }
}

fn parse_nft_ruleset(output: &str, summary: &mut FirewallRuntimeSummary) {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(output) else {
        return;
    };
    let Some(objects) = root.get("nftables").and_then(serde_json::Value::as_array) else {
        return;
    };
    for object in objects {
        if object.get("table").is_some() {
            summary.tables = summary.tables.saturating_add(1);
        }
        let Some(chain) = object.get("chain") else {
            continue;
        };
        summary.chains = summary.chains.saturating_add(1);
        let hook = bounded_json_string(chain, "hook", 32);
        if hook.is_none() {
            continue;
        }
        push_firewall_base_chain(
            summary,
            FirewallBaseChain {
                family: bounded_json_string(chain, "family", 16)
                    .unwrap_or_else(|| "unknown".into()),
                table: bounded_json_string(chain, "table", 64).unwrap_or_else(|| "unknown".into()),
                name: bounded_json_string(chain, "name", 64).unwrap_or_else(|| "unknown".into()),
                hook,
                policy: bounded_json_string(chain, "policy", 16)
                    .map(|policy| policy.to_ascii_uppercase()),
                rules: 0,
            },
        );
    }
    for object in objects {
        let Some(rule) = object.get("rule") else {
            continue;
        };
        summary.rules = summary.rules.saturating_add(1);
        let has_counter = rule
            .get("expr")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|expressions| {
                expressions
                    .iter()
                    .any(|expression| expression.get("counter").is_some())
            });
        if has_counter {
            summary.rules_with_counters = summary.rules_with_counters.saturating_add(1);
        }
        let family = bounded_json_string(rule, "family", 16);
        let table = bounded_json_string(rule, "table", 64);
        let chain = bounded_json_string(rule, "chain", 64);
        if let Some(base) = summary.base_chains.iter_mut().find(|base| {
            Some(base.family.as_str()) == family.as_deref()
                && Some(base.table.as_str()) == table.as_deref()
                && Some(base.name.as_str()) == chain.as_deref()
        }) {
            base.rules = base.rules.saturating_add(1);
        }
    }
}

fn parse_iptables_save(output: &str, family: &str, summary: &mut FirewallRuntimeSummary) {
    let mut table = None;
    for line in output.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('*').filter(|name| {
            !name.is_empty() && name.len() <= 64 && !name.chars().any(char::is_control)
        }) {
            table = Some(name.to_owned());
            summary.tables = summary.tables.saturating_add(1);
            continue;
        }
        if let Some(chain) = line.strip_prefix(':') {
            let mut fields = chain.split_whitespace();
            let Some(name) = fields.next().filter(|name| name.len() <= 64) else {
                continue;
            };
            let policy = fields
                .next()
                .filter(|policy| *policy != "-")
                .map(str::to_ascii_uppercase);
            summary.chains = summary.chains.saturating_add(1);
            if policy.is_some() {
                push_firewall_base_chain(
                    summary,
                    FirewallBaseChain {
                        family: family.into(),
                        table: table.clone().unwrap_or_else(|| "unknown".into()),
                        name: name.into(),
                        hook: Some(name.to_ascii_lowercase()),
                        policy,
                        rules: 0,
                    },
                );
            }
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut appended_chain = None;
        while let Some(field) = fields.next() {
            if field == "-A" {
                appended_chain = fields.next();
                break;
            }
        }
        let Some(chain) = appended_chain.filter(|chain| chain.len() <= 64) else {
            continue;
        };
        summary.rules = summary.rules.saturating_add(1);
        if line.starts_with('[') {
            summary.rules_with_counters = summary.rules_with_counters.saturating_add(1);
        }
        if let Some(base) = summary.base_chains.iter_mut().find(|base| {
            base.family == family
                && Some(base.table.as_str()) == table.as_deref()
                && base.name == chain
        }) {
            base.rules = base.rules.saturating_add(1);
        }
    }
}

fn push_firewall_base_chain(summary: &mut FirewallRuntimeSummary, chain: FirewallBaseChain) {
    if summary.base_chains.len() >= MAX_FIREWALL_BASE_CHAINS {
        summary.truncated = true;
    } else if !summary.base_chains.contains(&chain) {
        summary.base_chains.push(chain);
    }
}

const fn firewall_backend_name(backend: FirewallBackend) -> &'static str {
    match backend {
        FirewallBackend::Fw3 => "fw3/iptables",
        FirewallBackend::Fw4 => "fw4/nftables",
        FirewallBackend::Iptables => "iptables",
        FirewallBackend::Nftables => "nftables",
        FirewallBackend::Unknown => "unknown",
    }
}

fn build_policy_routing_report(evidence: Vec<ProbeEvidence>) -> PolicyRoutingDiagnosticReport {
    let mut summary = PolicyRoutingSummary {
        assessment: PolicyRoutingAssessment::InsufficientEvidence,
        rules: Vec::new(),
        tables: Vec::new(),
        total_routes: 0,
        truncated: false,
    };
    let has_rule_evidence = successful_output(&evidence, "network.route.rules").is_some();
    let has_route_evidence = successful_output(&evidence, "network.route.list").is_some();
    if let Some(output) = successful_output(&evidence, "network.route.rules") {
        parse_policy_rules(output, &mut summary);
    }
    if let Some(output) = successful_output(&evidence, "network.route.list") {
        parse_route_tables(output, &mut summary);
    }
    let custom = summary.rules.iter().any(is_custom_policy_rule);
    summary.assessment = if !has_rule_evidence {
        PolicyRoutingAssessment::InsufficientEvidence
    } else if summary.rules.is_empty() {
        PolicyRoutingAssessment::NoRules
    } else if custom {
        PolicyRoutingAssessment::CustomPolicyPresent
    } else {
        PolicyRoutingAssessment::DefaultPolicyOnly
    };
    let mut findings = vec![
        match summary.assessment {
            PolicyRoutingAssessment::CustomPolicyPresent => {
                "custom policy-routing selectors or non-default route tables are present"
            }
            PolicyRoutingAssessment::DefaultPolicyOnly => {
                "only the conventional local, main, and default policy rules were normalized"
            }
            PolicyRoutingAssessment::NoRules => "no policy-routing rules were returned",
            PolicyRoutingAssessment::InsufficientEvidence => {
                "policy-routing rule evidence is unavailable"
            }
        }
        .into(),
    ];
    if !has_route_evidence {
        findings.push("aggregate route-table evidence is unavailable".into());
    }
    if summary.truncated || evidence.iter().any(|item| item.truncated) {
        findings.push(
            "policy-routing inspection reached a configured byte or normalized-entry limit".into(),
        );
    }
    PolicyRoutingDiagnosticReport {
        complete: has_rule_evidence
            && has_route_evidence
            && !summary.truncated
            && !evidence.iter().any(|item| item.truncated),
        summary,
        evidence,
        findings,
    }
}

fn parse_policy_rules(output: &str, summary: &mut PolicyRoutingSummary) {
    let Ok(rules) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for rule in rules {
        if summary.rules.len() >= MAX_POLICY_RULES {
            summary.truncated = true;
            break;
        }
        let table = json_scalar_string(&rule, "table", 32)
            .or_else(|| json_scalar_string(&rule, "lookup", 32))
            .map_or_else(
                || "unspecified".into(),
                |table| normalize_route_table(&table),
            );
        let source = normalized_route_selector(&rule, "src");
        let destination = normalized_route_selector(&rule, "dst");
        let fwmark = json_scalar_string(&rule, "fwmark", 32).filter(|mark| valid_fwmark(mark));
        summary.rules.push(PolicyRule {
            priority: rule.get("priority").and_then(serde_json::Value::as_u64),
            source,
            destination,
            table,
            action: bounded_json_string(&rule, "action", 32),
            fwmark,
            incoming_interface: bounded_json_string(&rule, "iifname", 64)
                .or_else(|| bounded_json_string(&rule, "iif", 64)),
            outgoing_interface: bounded_json_string(&rule, "oifname", 64)
                .or_else(|| bounded_json_string(&rule, "oif", 64)),
        });
    }
}

fn parse_route_tables(output: &str, summary: &mut PolicyRoutingSummary) {
    let Ok(routes) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for route in routes {
        let table = json_scalar_string(&route, "table", 32)
            .map_or_else(|| "main".into(), |table| normalize_route_table(&table));
        summary.total_routes = summary.total_routes.saturating_add(1);
        let position = summary
            .tables
            .iter()
            .position(|candidate| candidate.table == table);
        let table_summary = if let Some(position) = position {
            &mut summary.tables[position]
        } else {
            if summary.tables.len() >= MAX_ROUTE_TABLES {
                summary.truncated = true;
                continue;
            }
            summary.tables.push(RouteTableSummary {
                table: table.clone(),
                routes: 0,
                default_routes: 0,
                exceptional_routes: 0,
            });
            summary.tables.last_mut().expect("route table was inserted")
        };
        table_summary.routes = table_summary.routes.saturating_add(1);
        let destination = route
            .get("dst")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("default");
        if matches!(destination, "default" | "0.0.0.0/0" | "::/0") {
            table_summary.default_routes = table_summary.default_routes.saturating_add(1);
        }
        if route
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| matches!(kind, "blackhole" | "unreachable" | "prohibit" | "throw"))
        {
            table_summary.exceptional_routes = table_summary.exceptional_routes.saturating_add(1);
        }
    }
    summary
        .tables
        .sort_by(|left, right| left.table.cmp(&right.table));
}

fn json_scalar_string(value: &serde_json::Value, key: &str, limit: usize) -> Option<String> {
    let value = value.get(key)?;
    if let Some(value) = value.as_str() {
        return (!value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control))
            .then(|| value.to_owned());
    }
    value
        .as_u64()
        .map(|value| value.to_string())
        .filter(|value| value.len() <= limit)
}

fn normalized_route_selector(value: &serde_json::Value, key: &str) -> Option<String> {
    let selector = bounded_json_string(value, key, 64)?;
    if selector == "all" {
        return None;
    }
    if selector.parse::<IpAddr>().is_ok() {
        return Some(selector);
    }
    let (address, prefix) = selector.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    (prefix <= maximum).then_some(selector)
}

fn normalize_route_table(table: &str) -> String {
    match table {
        "255" => "local".into(),
        "254" => "main".into(),
        "253" => "default".into(),
        _ => table.to_owned(),
    }
}

fn valid_fwmark(mark: &str) -> bool {
    !mark.is_empty()
        && mark
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b'x' | b'X' | b'/'))
}

fn is_custom_policy_rule(rule: &PolicyRule) -> bool {
    !matches!(rule.table.as_str(), "local" | "main" | "default")
        || rule.source.is_some()
        || rule.destination.is_some()
        || rule.fwmark.is_some()
        || rule.incoming_interface.is_some()
        || rule.outgoing_interface.is_some()
        || rule
            .action
            .as_deref()
            .is_some_and(|action| !matches!(action, "lookup" | "to_tbl"))
}

fn build_listener_report(evidence: Vec<ProbeEvidence>) -> ListenerDiagnosticReport {
    let mut listeners = Vec::new();
    let mut truncated = false;
    let successful = evidence
        .iter()
        .find(|item| item.probe == "network.socket.listeners" && item.status == ProbeStatus::Ok);
    if let Some(item) = successful {
        let is_ss = Path::new(&item.source)
            .file_name()
            .and_then(|name| name.to_str())
            == Some("ss");
        parse_listeners(&item.output, is_ss, &mut listeners, &mut truncated);
    }
    listeners.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then_with(|| left.protocol.cmp(&right.protocol))
            .then_with(|| left.local_address.cmp(&right.local_address))
    });
    let assessment = if successful.is_none() {
        ListenerAssessment::CollectorUnavailable
    } else if listeners.is_empty() {
        ListenerAssessment::NoListeners
    } else {
        ListenerAssessment::ListenersPresent
    };
    let exposed = listeners
        .iter()
        .filter(|listener| listener.scope != ListenerScope::Loopback)
        .count();
    let mut findings = vec![match assessment {
        ListenerAssessment::ListenersPresent => {
            format!(
                "{} bounded TCP/UDP listeners were normalized; {exposed} are bound outside loopback",
                listeners.len()
            )
        }
        ListenerAssessment::NoListeners => {
            "the socket collector returned no TCP/UDP listeners".into()
        }
        ListenerAssessment::CollectorUnavailable => {
            "neither a usable ss nor netstat listener collector is available".into()
        }
    }];
    if truncated || evidence.iter().any(|item| item.truncated) {
        findings
            .push("listener inspection reached a configured byte or normalized-entry limit".into());
    }
    ListenerDiagnosticReport {
        summary: ListenerSummary {
            assessment,
            listeners,
            truncated,
        },
        complete: successful.is_some() && !truncated && !evidence.iter().any(|item| item.truncated),
        evidence,
        findings,
    }
}

fn parse_listeners(
    output: &str,
    is_ss: bool,
    listeners: &mut Vec<ListenerEntry>,
    truncated: &mut bool,
) {
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if listeners.len() >= MAX_LISTENERS {
            *truncated = true;
            break;
        }
        let parsed = if is_ss {
            parse_ss_listener(line)
        } else {
            parse_netstat_listener(line)
        };
        if let Some(listener) = parsed {
            if !listeners.contains(&listener) {
                listeners.push(listener);
            }
        }
    }
}

fn parse_ss_listener(line: &str) -> Option<ListenerEntry> {
    let mut fields = line.split_whitespace();
    let protocol = fields.next()?;
    let state = fields.next();
    let endpoint = line.split_whitespace().nth(4)?;
    listener_entry(protocol, endpoint, state)
}

fn parse_netstat_listener(line: &str) -> Option<ListenerEntry> {
    let mut fields = line.split_whitespace();
    let protocol = fields.next()?;
    if !matches!(protocol, "tcp" | "tcp6" | "udp" | "udp6") {
        return None;
    }
    let endpoint = line.split_whitespace().nth(3)?;
    let state = line
        .split_whitespace()
        .find(|field| matches!(*field, "LISTEN" | "UNCONN"));
    listener_entry(protocol, endpoint, state)
}

fn listener_entry(protocol: &str, endpoint: &str, state: Option<&str>) -> Option<ListenerEntry> {
    let protocol = match protocol {
        "tcp" | "tcp6" => "tcp",
        "udp" | "udp6" => "udp",
        _ => return None,
    };
    let (raw_address, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let normalized_address = if let Some(address) = raw_address.strip_prefix('[') {
        let (address, suffix) = address.split_once(']')?;
        format!("{address}{suffix}")
    } else {
        raw_address.into()
    };
    let raw_address = normalized_address.as_str();
    if raw_address.is_empty() || raw_address.len() > 64 || raw_address.chars().any(char::is_control)
    {
        return None;
    }
    let address_without_zone = raw_address.split('%').next().unwrap_or(raw_address);
    let parsed = address_without_zone.parse::<IpAddr>().ok();
    let scope = match (raw_address, parsed) {
        ("*" | "0.0.0.0" | "::", _) => ListenerScope::Wildcard,
        (_, Some(address)) if address.is_loopback() => ListenerScope::Loopback,
        (_, Some(IpAddr::V4(address))) if address.is_link_local() => ListenerScope::LinkLocal,
        (_, Some(IpAddr::V6(address))) if address.is_unicast_link_local() => {
            ListenerScope::LinkLocal
        }
        (_, Some(_)) => ListenerScope::Specific,
        _ => return None,
    };
    let family = parsed.map_or_else(
        || {
            if raw_address.contains(':') {
                "ipv6"
            } else {
                "ipv4"
            }
        },
        |address| {
            if address.is_ipv4() { "ipv4" } else { "ipv6" }
        },
    );
    Some(ListenerEntry {
        protocol: protocol.into(),
        family: family.into(),
        local_address: raw_address.into(),
        port,
        scope,
        state: state
            .filter(|state| state.len() <= 16)
            .map(str::to_ascii_uppercase),
    })
}

fn build_wireless_report(evidence: Vec<ProbeEvidence>) -> WirelessDiagnosticReport {
    let mut summary = WirelessSummary {
        assessment: WirelessAssessment::CollectorUnavailable,
        radios: Vec::new(),
        interfaces: Vec::new(),
        truncated: false,
    };
    if let Some(output) = successful_output(&evidence, "openwrt.wireless.status") {
        parse_ubus_wireless(output, &mut summary);
    }
    if let Some(output) = successful_output(&evidence, "network.wireless.iw") {
        parse_iw_dev(output, &mut summary);
    }
    if let Some(output) = successful_output(&evidence, "network.wireless.iwinfo") {
        parse_iwinfo(output, &mut summary);
    }
    summary
        .radios
        .sort_by(|left, right| left.name.cmp(&right.name));
    summary
        .interfaces
        .sort_by(|left, right| left.name.cmp(&right.name));
    let successful = evidence.iter().any(|item| item.status == ProbeStatus::Ok);
    let disabled_only = !summary.radios.is_empty()
        && summary
            .radios
            .iter()
            .all(|radio| radio.disabled == Some(true) || radio.up == Some(false));
    summary.assessment = if !successful {
        WirelessAssessment::CollectorUnavailable
    } else if disabled_only {
        WirelessAssessment::RadiosDisabled
    } else if summary.radios.is_empty() && summary.interfaces.is_empty() {
        WirelessAssessment::NoWireless
    } else {
        WirelessAssessment::WirelessPresent
    };
    let configured_ssids = summary
        .interfaces
        .iter()
        .filter(|interface| interface.ssid.is_some())
        .count();
    let mut findings = vec![match summary.assessment {
        WirelessAssessment::WirelessPresent => format!(
            "{} radios and {} wireless interfaces were normalized; {configured_ssids} interfaces have a local SSID value",
            summary.radios.len(),
            summary.interfaces.len()
        ),
        WirelessAssessment::RadiosDisabled => {
            "wireless radios were found, but all reported radios are disabled or down".into()
        }
        WirelessAssessment::NoWireless => {
            "the wireless collector returned no radios or interfaces".into()
        }
        WirelessAssessment::CollectorUnavailable => {
            "no usable ubus, iw, or iwinfo wireless evidence is available".into()
        }
    }];
    if summary.truncated || evidence.iter().any(|item| item.truncated) {
        findings
            .push("wireless inspection reached a configured byte or normalized-entry limit".into());
    }
    WirelessDiagnosticReport {
        complete: successful && !summary.truncated && !evidence.iter().any(|item| item.truncated),
        summary,
        evidence,
        findings,
    }
}

fn parse_ubus_wireless(output: &str, summary: &mut WirelessSummary) {
    let Ok(radios) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(output)
    else {
        return;
    };
    for (name, value) in radios {
        if !valid_bounded_text(&name, 64) {
            continue;
        }
        if summary.radios.len() >= MAX_WIRELESS_RADIOS {
            summary.truncated = true;
            break;
        }
        let config = value.get("config");
        let channel = config
            .and_then(|config| json_u32(config, "channel"))
            .or_else(|| json_u32(&value, "channel"));
        let disabled = json_boolish(&value, "disabled")
            .or_else(|| config.and_then(|config| json_boolish(config, "disabled")));
        push_wireless_radio(
            summary,
            WirelessRadioSummary {
                name: name.clone(),
                up: value.get("up").and_then(serde_json::Value::as_bool),
                pending: value.get("pending").and_then(serde_json::Value::as_bool),
                disabled,
                channel,
            },
        );
        let Some(interfaces) = value
            .get("interfaces")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for interface in interfaces {
            let config = interface.get("config");
            let ifname = bounded_json_string(interface, "ifname", 64)
                .or_else(|| bounded_json_string(interface, "section", 64));
            let Some(ifname) = ifname else {
                continue;
            };
            push_wireless_interface(
                summary,
                WirelessInterfaceSummary {
                    name: ifname,
                    radio: Some(name.clone()),
                    mode: config.and_then(|config| bounded_json_string(config, "mode", 32)),
                    ssid: config.and_then(|config| bounded_json_string(config, "ssid", 64)),
                    channel,
                    frequency_mhz: None,
                },
            );
        }
    }
}

fn parse_iw_dev(output: &str, summary: &mut WirelessSummary) {
    let mut current_radio = None;
    let mut current_interface = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(phy) = line.strip_prefix("phy#") {
            let name = format!("phy{phy}");
            if valid_bounded_text(&name, 64) {
                push_wireless_radio(
                    summary,
                    WirelessRadioSummary {
                        name: name.clone(),
                        up: None,
                        pending: None,
                        disabled: None,
                        channel: None,
                    },
                );
                current_radio = Some(name);
            }
            current_interface = None;
            continue;
        }
        if let Some(name) = line.strip_prefix("Interface ") {
            if !valid_bounded_text(name, 64) {
                continue;
            }
            push_wireless_interface(
                summary,
                WirelessInterfaceSummary {
                    name: name.into(),
                    radio: current_radio.clone(),
                    mode: None,
                    ssid: None,
                    channel: None,
                    frequency_mhz: None,
                },
            );
            current_interface = Some(name.to_owned());
            continue;
        }
        let Some(name) = current_interface.as_deref() else {
            continue;
        };
        let Some(interface) = summary
            .interfaces
            .iter_mut()
            .find(|interface| interface.name == name)
        else {
            continue;
        };
        if let Some(mode) = line
            .strip_prefix("type ")
            .filter(|mode| valid_bounded_text(mode, 32))
        {
            interface.mode = Some(mode.to_ascii_lowercase());
        } else if let Some(channel) = line.strip_prefix("channel ") {
            let mut fields = channel.split_whitespace();
            interface.channel = fields.next().and_then(|value| value.parse::<u32>().ok());
            interface.frequency_mhz = fields
                .next()
                .and_then(|value| value.trim_start_matches('(').parse::<u32>().ok());
        }
    }
}

fn parse_iwinfo(output: &str, summary: &mut WirelessSummary) {
    let mut current_interface = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some((prefix, raw_ssid)) = line.split_once("ESSID:") {
            let Some(name) = prefix.split_whitespace().next() else {
                continue;
            };
            if !valid_bounded_text(name, 64) {
                continue;
            }
            let ssid = raw_ssid.trim().trim_matches('"').to_owned();
            push_wireless_interface(
                summary,
                WirelessInterfaceSummary {
                    name: name.into(),
                    radio: None,
                    mode: None,
                    ssid: valid_bounded_text(&ssid, 64).then_some(ssid),
                    channel: None,
                    frequency_mhz: None,
                },
            );
            current_interface = Some(name.to_owned());
            continue;
        }
        let Some(name) = current_interface.as_deref() else {
            continue;
        };
        let Some(interface) = summary
            .interfaces
            .iter_mut()
            .find(|interface| interface.name == name)
        else {
            continue;
        };
        if let Some(mode) = value_after_label(line, "Mode:", 32) {
            interface.mode = Some(mode.to_ascii_lowercase());
        }
        if let Some(channel) = value_after_label(line, "Channel:", 8) {
            interface.channel = channel.parse::<u32>().ok();
        }
        if let Some(frequency) = frequency_ghz_mhz(line) {
            interface.frequency_mhz = Some(frequency);
        }
    }
}

fn push_wireless_radio(summary: &mut WirelessSummary, radio: WirelessRadioSummary) {
    if summary.radios.iter().any(|item| item.name == radio.name) {
        return;
    }
    if summary.radios.len() >= MAX_WIRELESS_RADIOS {
        summary.truncated = true;
    } else {
        summary.radios.push(radio);
    }
}

fn push_wireless_interface(summary: &mut WirelessSummary, interface: WirelessInterfaceSummary) {
    if let Some(existing) = summary
        .interfaces
        .iter_mut()
        .find(|item| item.name == interface.name)
    {
        if existing.radio.is_none() {
            existing.radio = interface.radio;
        }
        if existing.mode.is_none() {
            existing.mode = interface.mode;
        }
        if existing.ssid.is_none() {
            existing.ssid = interface.ssid;
        }
        if existing.channel.is_none() {
            existing.channel = interface.channel;
        }
        if existing.frequency_mhz.is_none() {
            existing.frequency_mhz = interface.frequency_mhz;
        }
    } else if summary.interfaces.len() >= MAX_WIRELESS_INTERFACES {
        summary.truncated = true;
    } else {
        summary.interfaces.push(interface);
    }
}

fn valid_bounded_text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn json_u32(value: &serde_json::Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .and_then(|value| u32::try_from(value).ok())
}

fn json_boolish(value: &serde_json::Value, key: &str) -> Option<bool> {
    let value = value.get(key)?;
    value
        .as_bool()
        .or_else(|| value.as_u64().map(|value| value != 0))
}

fn value_after_label(line: &str, label: &str, limit: usize) -> Option<String> {
    let (_, value) = line.split_once(label)?;
    let value = value.split_whitespace().next()?;
    valid_bounded_text(value, limit).then(|| value.to_owned())
}

fn frequency_ghz_mhz(line: &str) -> Option<u32> {
    let before = line.split("GHz").next()?;
    let value = before.split_whitespace().last()?.trim_start_matches('(');
    let (whole, fraction) = value.split_once('.')?;
    let whole = whole.parse::<u32>().ok()?;
    if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let width = fraction.len().min(3);
    let fraction = fraction.get(..width)?.parse::<u32>().ok()?;
    let scale = 10_u32.pow(u32::try_from(3 - width).ok()?);
    whole
        .checked_mul(1000)?
        .checked_add(fraction.checked_mul(scale)?)
}

fn build_conntrack_report(evidence: Vec<ProbeEvidence>) -> ConntrackDiagnosticReport {
    let count = successful_output(&evidence, "network.conntrack.count").and_then(parse_single_u64);
    let limit = successful_output(&evidence, "network.conntrack.limit").and_then(parse_single_u64);
    let utilization_percent = match (count, limit) {
        (Some(count), Some(limit)) if limit > 0 => {
            let percent = (u128::from(count) * 100 / u128::from(limit)).min(100);
            Some(u8::try_from(percent).unwrap_or(100))
        }
        _ => None,
    };
    let assessment = match (count, limit) {
        (None, None) => ConntrackAssessment::Unavailable,
        (Some(_), Some(0)) => ConntrackAssessment::InvalidLimit,
        (Some(count), Some(limit)) if count >= limit => ConntrackAssessment::AtCapacity,
        (Some(count), Some(limit)) if u128::from(count) * 10 >= u128::from(limit) * 9 => {
            ConntrackAssessment::NearCapacity
        }
        (Some(_), Some(_)) => ConntrackAssessment::Healthy,
        _ => ConntrackAssessment::PartialEvidence,
    };
    let findings = vec![match assessment {
        ConntrackAssessment::Healthy => format!(
            "connection tracking uses {}% of the configured capacity",
            utilization_percent.unwrap_or_default()
        ),
        ConntrackAssessment::NearCapacity => format!(
            "connection tracking is near capacity at {}%; new flows may fail if usage rises",
            utilization_percent.unwrap_or_default()
        ),
        ConntrackAssessment::AtCapacity => {
            "connection tracking has reached its configured capacity; new tracked flows may fail"
                .into()
        }
        ConntrackAssessment::PartialEvidence => {
            "only one connection-tracking capacity value is available".into()
        }
        ConntrackAssessment::InvalidLimit => {
            "the configured connection-tracking limit is zero".into()
        }
        ConntrackAssessment::Unavailable => {
            "kernel connection-tracking capacity files are unavailable".into()
        }
    }];
    ConntrackDiagnosticReport {
        complete: count.is_some() && limit.is_some() && !evidence.iter().any(|item| item.truncated),
        summary: ConntrackSummary {
            assessment,
            count,
            limit,
            utilization_percent,
        },
        evidence,
        findings,
    }
}

fn parse_single_u64(output: &str) -> Option<u64> {
    output.trim().parse().ok()
}

fn build_qdisc_report(evidence: Vec<ProbeEvidence>) -> QdiscDiagnosticReport {
    let mut summary = QdiscSummary {
        assessment: QdiscAssessment::CollectorUnavailable,
        qdiscs: Vec::new(),
        truncated: false,
    };
    let successful = successful_output(&evidence, "network.qdisc.stats");
    if let Some(output) = successful {
        parse_qdiscs(output, &mut summary);
    }
    summary.qdiscs.sort_by(|left, right| {
        left.device
            .cmp(&right.device)
            .then_with(|| left.parent.cmp(&right.parent))
            .then_with(|| left.handle.cmp(&right.handle))
    });
    summary.assessment = if successful.is_none() {
        QdiscAssessment::CollectorUnavailable
    } else if summary.qdiscs.is_empty() {
        QdiscAssessment::NoQdiscs
    } else if summary.qdiscs.iter().any(QdiscEntry::has_pressure_counters) {
        QdiscAssessment::PressureCountersPresent
    } else {
        QdiscAssessment::QdiscsPresent
    };
    let affected = summary
        .qdiscs
        .iter()
        .filter(|qdisc| qdisc.has_pressure_counters())
        .count();
    let mut findings = vec![match summary.assessment {
        QdiscAssessment::PressureCountersPresent => format!(
            "{affected} queueing disciplines have cumulative drop, overlimit, requeue, or backlog counters; one snapshot cannot establish a current rate"
        ),
        QdiscAssessment::QdiscsPresent => {
            "queueing-discipline counters are available with no retained pressure value above zero"
                .into()
        }
        QdiscAssessment::NoQdiscs => {
            "the collector returned no parseable queueing disciplines".into()
        }
        QdiscAssessment::CollectorUnavailable => {
            "queueing-discipline evidence is unavailable".into()
        }
    }];
    if summary.truncated || evidence.iter().any(|item| item.truncated) {
        findings.push("qdisc statistics reached a configured byte or entry limit".into());
    }
    QdiscDiagnosticReport {
        complete: successful.is_some()
            && !summary.truncated
            && !evidence.iter().any(|item| item.truncated),
        summary,
        evidence,
        findings,
    }
}

fn parse_qdiscs(output: &str, summary: &mut QdiscSummary) {
    let Ok(qdiscs) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for qdisc in qdiscs {
        if summary.qdiscs.len() >= MAX_QDISCS {
            summary.truncated = true;
            break;
        }
        let Some(device) = bounded_json_string(&qdisc, "dev", 64) else {
            continue;
        };
        let Some(kind) = bounded_json_string(&qdisc, "kind", 32) else {
            continue;
        };
        let stats = qdisc.get("stats");
        let stats2 = qdisc.get("stats2");
        summary.qdiscs.push(QdiscEntry {
            device,
            kind,
            handle: bounded_json_string(&qdisc, "handle", 32),
            parent: bounded_json_string(&qdisc, "parent", 32),
            root: qdisc
                .get("root")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            bytes: nested_u64(stats, "bytes").max(double_nested_u64(stats2, "basic", "bytes")),
            packets: nested_u64(stats, "packets")
                .max(double_nested_u64(stats2, "basic", "packets")),
            drops: nested_u64(stats, "drops").max(double_nested_u64(stats2, "queue", "drops")),
            overlimits: nested_u64(stats, "overlimits").max(double_nested_u64(
                stats2,
                "queue",
                "overlimits",
            )),
            requeues: nested_u64(stats, "requeues")
                .max(double_nested_u64(stats2, "queue", "requeues")),
            backlog_bytes: nested_u64(stats, "backlog")
                .max(double_nested_u64(stats2, "queue", "backlog")),
            queue_length: nested_u64(stats, "qlen").max(double_nested_u64(stats2, "queue", "qlen")),
        });
    }
}

fn double_nested_u64(value: Option<&serde_json::Value>, parent: &str, key: &str) -> u64 {
    value
        .and_then(|value| value.get(parent))
        .and_then(|value| value.get(key))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn build_interface_stats_report(evidence: Vec<ProbeEvidence>) -> InterfaceStatsDiagnosticReport {
    let mut summary = InterfaceStatsSummary {
        assessment: InterfaceStatsAssessment::CollectorUnavailable,
        interfaces: Vec::new(),
        truncated: false,
    };
    let successful = successful_output(&evidence, "network.interface.stats");
    if let Some(output) = successful {
        parse_interface_stats(output, &mut summary);
    }
    summary
        .interfaces
        .sort_by(|left, right| left.name.cmp(&right.name));
    summary.assessment = if successful.is_none() {
        InterfaceStatsAssessment::CollectorUnavailable
    } else if summary.interfaces.is_empty() {
        InterfaceStatsAssessment::NoCounters
    } else if summary
        .interfaces
        .iter()
        .any(InterfaceStatsEntry::has_errors_or_drops)
    {
        InterfaceStatsAssessment::ErrorsOrDropsPresent
    } else {
        InterfaceStatsAssessment::CountersPresent
    };
    let affected = summary
        .interfaces
        .iter()
        .filter(|interface| interface.has_errors_or_drops())
        .count();
    let mut findings = vec![match summary.assessment {
        InterfaceStatsAssessment::ErrorsOrDropsPresent => format!(
            "{affected} interfaces have cumulative kernel error or drop counters; one snapshot cannot establish a current rate"
        ),
        InterfaceStatsAssessment::CountersPresent => {
            "kernel interface counters are available with no retained error/drop value above zero"
                .into()
        }
        InterfaceStatsAssessment::NoCounters => {
            "the collector returned no parseable interface counters".into()
        }
        InterfaceStatsAssessment::CollectorUnavailable => {
            "kernel interface statistics evidence is unavailable".into()
        }
    }];
    if summary.truncated || evidence.iter().any(|item| item.truncated) {
        findings.push(
            "interface statistics reached a configured byte or normalized-entry limit".into(),
        );
    }
    InterfaceStatsDiagnosticReport {
        complete: successful.is_some()
            && !summary.truncated
            && !evidence.iter().any(|item| item.truncated),
        summary,
        evidence,
        findings,
    }
}

fn parse_interface_stats(output: &str, summary: &mut InterfaceStatsSummary) {
    let Ok(interfaces) = serde_json::from_str::<Vec<serde_json::Value>>(output) else {
        return;
    };
    for interface in interfaces {
        if summary.interfaces.len() >= MAX_INTERFACE_STATS {
            summary.truncated = true;
            break;
        }
        let Some(name) = bounded_json_string(&interface, "ifname", 64) else {
            continue;
        };
        let Some(stats) = interface.get("stats64").or_else(|| interface.get("stats")) else {
            continue;
        };
        let rx = stats.get("rx");
        let tx = stats.get("tx");
        summary.interfaces.push(InterfaceStatsEntry {
            name,
            operstate: bounded_json_string(&interface, "operstate", 32),
            rx_bytes: nested_u64(rx, "bytes"),
            rx_packets: nested_u64(rx, "packets"),
            rx_errors: nested_u64(rx, "errors"),
            rx_dropped: nested_u64(rx, "dropped"),
            tx_bytes: nested_u64(tx, "bytes"),
            tx_packets: nested_u64(tx, "packets"),
            tx_errors: nested_u64(tx, "errors"),
            tx_dropped: nested_u64(tx, "dropped"),
        });
    }
}

fn nested_u64(value: Option<&serde_json::Value>, key: &str) -> u64 {
    value
        .and_then(|value| value.get(key))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
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

fn assess_dhcp(summary: &WanSummary) -> DhcpAssessment {
    if summary.available == Some(false) {
        return DhcpAssessment::InterfaceUnavailable;
    }
    match summary.protocol.as_deref() {
        Some("dhcp" | "dhcpv6" | "dhcp-inferred") => {
            if summary.pending == Some(true) {
                DhcpAssessment::Negotiating
            } else if summary.addresses.is_empty() {
                DhcpAssessment::LeaseMissing
            } else {
                DhcpAssessment::LeaseReady
            }
        }
        Some(_) => DhcpAssessment::NotDhcp,
        None if summary.up == Some(false) => DhcpAssessment::LinkDown,
        None => DhcpAssessment::InsufficientEvidence,
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
    // Rust's parallel test runner can briefly starve local shell fixtures on
    // loaded CI hosts. Production probe timeouts remain configuration-bounded.
    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

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
    fn dhcp_assessment_does_not_misclassify_pppoe() {
        let evidence = vec![ok_evidence(
            "openwrt.interface.wan",
            r#"{
                "up":true,"available":true,"pending":false,"proto":"pppoe",
                "l3_device":"pppoe-wan","ipv4-address":[{"address":"192.0.2.10","mask":32}]
            }"#,
        )];
        let summary = normalize(&evidence, &platform(FirewallBackend::Fw4));
        assert_eq!(assess_dhcp(&summary), DhcpAssessment::NotDhcp);
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
            timeout: FIXTURE_TIMEOUT,
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
            timeout: FIXTURE_TIMEOUT,
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
    async fn openwrt_dhcp_runbook_reports_negotiation_without_renewing() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ubus",
            r#"#!/bin/sh
printf '%s\n' '{"up":false,"available":true,"pending":true,"proto":"dhcp","l3_device":"wan0","ipv4-address":[],"route":[]}'
"#,
        );
        fixture.executable("bin/ip", "#!/bin/sh\nprintf '%s\\n' '[]'\n");
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let report = runner
            .diagnose_dhcp(&platform(FirewallBackend::Fw4))
            .await
            .expect("OpenWrt DHCP diagnosis");
        assert_eq!(report.summary.assessment, DhcpAssessment::Negotiating);
        assert_eq!(report.summary.protocol.as_deref(), Some("dhcp"));
        assert_eq!(report.summary.pending, Some(true));
        assert!(report.complete);
        assert!(!report.evidence.iter().any(|item| {
            item.probe.starts_with("network.dns.")
                || item.probe == "network.route.rules"
                || item.probe.starts_with("openwrt.firewall.")
        }));
    }

    #[tokio::test]
    async fn generic_linux_dhcp_runbook_infers_dynamic_kernel_address() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ip",
            r#"#!/bin/sh
printf '%s\n' '[{"dst":"default","gateway":"198.51.100.1","dev":"eth0","ifname":"eth0","operstate":"UP","addr_info":[{"local":"198.51.100.20","prefixlen":24,"dynamic":true}]}]'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let mut generic = platform(FirewallBackend::Nftables);
        generic.kind = PlatformKind::GenericLinux;
        let report = runner
            .diagnose_dhcp(&generic)
            .await
            .expect("generic DHCP diagnosis");
        assert_eq!(report.summary.assessment, DhcpAssessment::LeaseReady);
        assert_eq!(report.summary.protocol.as_deref(), Some("dhcp-inferred"));
        assert_eq!(report.summary.addresses, ["198.51.100.20/24"]);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.contains("inferred"))
        );
    }

    #[tokio::test]
    async fn interface_runbook_normalizes_generic_linux_links_and_addresses() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ip",
            r#"#!/bin/sh
printf '%s\n' '[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","addr_info":[{"local":"192.0.2.10","prefixlen":24,"dynamic":true},{"local":"2001:db8::10","prefixlen":64}]}]'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let mut generic = platform(FirewallBackend::Nftables);
        generic.kind = PlatformKind::GenericLinux;
        let report = runner
            .diagnose_interfaces(&generic)
            .await
            .expect("interface diagnosis");
        assert_eq!(
            report.summary.assessment,
            InterfaceAssessment::InterfacesReady
        );
        assert!(report.complete);
        assert_eq!(report.evidence.len(), 2);
        assert!(
            report
                .evidence
                .iter()
                .all(|item| item.probe.starts_with("network.interface."))
        );
        let eth0 = report
            .summary
            .interfaces
            .iter()
            .find(|interface| interface.name == "eth0")
            .expect("eth0");
        assert_eq!(eth0.index, Some(2));
        assert_eq!(eth0.operstate.as_deref(), Some("UP"));
        assert_eq!(eth0.carrier, Some(true));
        assert_eq!(eth0.addresses, ["192.0.2.10/24", "2001:db8::10/64"]);
        assert!(eth0.dynamic_address);
    }

    #[tokio::test]
    async fn neighbor_runbook_normalizes_arp_and_ndp_without_active_probes() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ip",
            r#"#!/bin/sh
printf '%s\n' '[{"dst":"192.0.2.1","dev":"eth0","lladdr":"00:11:22:AA:BB:CC","state":["REACHABLE"]},{"dst":"2001:db8::1","dev":"eth0","state":["INCOMPLETE"],"router":true},{"dst":"not-an-ip","dev":"eth0","lladdr":"must-not-pass","state":["FAILED"]}]'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let report = runner
            .diagnose_neighbors(&platform(FirewallBackend::Nftables))
            .await
            .expect("neighbor diagnosis");
        assert_eq!(
            report.summary.assessment,
            NeighborAssessment::ResolutionFailuresPresent
        );
        assert!(report.complete);
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].probe, "network.neighbor.list");
        assert_eq!(report.summary.entries.len(), 2);
        assert_eq!(
            report.summary.entries[0].link_address.as_deref(),
            Some("00:11:22:aa:bb:cc")
        );
        assert!(report.summary.entries[1].router);
        assert_eq!(report.summary.entries[1].states, ["INCOMPLETE"]);
    }

    #[test]
    fn neighbor_inventory_caps_normalized_entries() {
        let neighbors: Vec<serde_json::Value> = (0..=MAX_NEIGHBORS)
            .map(|index| {
                serde_json::json!({
                    "dst": format!("192.0.2.{}", index % 254 + 1),
                    "dev": format!("eth{}", index / 254),
                    "state": ["STALE"]
                })
            })
            .collect();
        let report = build_neighbor_report(vec![ok_evidence(
            "network.neighbor.list",
            &serde_json::to_string(&neighbors).expect("neighbors"),
        )]);
        assert_eq!(report.summary.entries.len(), MAX_NEIGHBORS);
        assert!(report.summary.truncated);
        assert!(!report.complete);
    }

    #[test]
    fn normalizes_nftables_runtime_counts_and_base_chains() {
        let output = serde_json::json!({
            "nftables": [
                {"metainfo": {"version": "1.0"}},
                {"table": {"family": "inet", "name": "fw4"}},
                {"chain": {"family": "inet", "table": "fw4", "name": "input", "hook": "input", "policy": "drop"}},
                {"chain": {"family": "inet", "table": "fw4", "name": "helper"}},
                {"rule": {"family": "inet", "table": "fw4", "chain": "input", "expr": [{"counter": {"packets": 2, "bytes": 128}}]}},
                {"rule": {"family": "inet", "table": "fw4", "chain": "helper", "expr": [{"accept": null}]}}
            ]
        });
        let report = build_firewall_report(
            vec![ok_evidence(
                "network.firewall.nftables",
                &serde_json::to_string(&output).expect("nft JSON"),
            )],
            FirewallBackend::Fw4,
        );
        assert_eq!(
            report.summary.assessment,
            FirewallAssessment::RuntimeRulesPresent
        );
        assert_eq!(report.summary.backend, "fw4/nftables");
        assert_eq!(report.summary.tables, 1);
        assert_eq!(report.summary.chains, 2);
        assert_eq!(report.summary.rules, 2);
        assert_eq!(report.summary.rules_with_counters, 1);
        assert_eq!(report.summary.base_chains.len(), 1);
        assert_eq!(
            report.summary.base_chains[0].policy.as_deref(),
            Some("DROP")
        );
        assert_eq!(report.summary.base_chains[0].rules, 1);
        assert!(report.complete);
    }

    #[test]
    fn normalizes_custom_policy_rules_and_route_table_totals() {
        let rules = serde_json::json!([
            {"priority": 0, "src": "all", "table": "local"},
            {"priority": 1000, "src": "192.0.2.0/24", "fwmark": 1, "table": 100},
            {"priority": 32766, "src": "all", "table": 254}
        ]);
        let routes = serde_json::json!([
            {"dst": "default", "table": 100, "gateway": "192.0.2.1"},
            {"dst": "198.51.100.0/24", "table": 100},
            {"type": "blackhole", "dst": "203.0.113.0/24", "table": 100},
            {"dst": "default", "table": "main", "gateway": "198.51.100.1"}
        ]);
        let report = build_policy_routing_report(vec![
            ok_evidence(
                "network.route.rules",
                &serde_json::to_string(&rules).expect("rules"),
            ),
            ok_evidence(
                "network.route.list",
                &serde_json::to_string(&routes).expect("routes"),
            ),
        ]);
        assert_eq!(
            report.summary.assessment,
            PolicyRoutingAssessment::CustomPolicyPresent
        );
        assert_eq!(report.summary.rules.len(), 3);
        assert_eq!(report.summary.rules[1].table, "100");
        assert_eq!(
            report.summary.rules[1].source.as_deref(),
            Some("192.0.2.0/24")
        );
        assert_eq!(report.summary.rules[1].fwmark.as_deref(), Some("1"));
        assert_eq!(report.summary.total_routes, 4);
        let custom = report
            .summary
            .tables
            .iter()
            .find(|table| table.table == "100")
            .expect("custom table");
        assert_eq!(custom.routes, 3);
        assert_eq!(custom.default_routes, 1);
        assert_eq!(custom.exceptional_routes, 1);
        assert!(report.complete);
    }

    #[test]
    fn policy_rule_inventory_is_cardinality_bounded() {
        let rules: Vec<serde_json::Value> = (0..=MAX_POLICY_RULES)
            .map(|priority| {
                serde_json::json!({
                    "priority": priority,
                    "src": "all",
                    "table": "main"
                })
            })
            .collect();
        let report = build_policy_routing_report(vec![
            ok_evidence(
                "network.route.rules",
                &serde_json::to_string(&rules).expect("rules"),
            ),
            ok_evidence("network.route.list", "[]"),
        ]);
        assert_eq!(report.summary.rules.len(), MAX_POLICY_RULES);
        assert!(report.summary.truncated);
        assert!(!report.complete);
    }

    #[tokio::test]
    async fn listener_runbook_prefers_ss_and_classifies_binding_scope() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ss",
            r"#!/bin/sh
printf '%s\n' \
'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*' \
'tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*' \
'udp UNCONN 0 0 [fe80::1]%eth0:53 [::]:*' \
'raw UNKNOWN 0 0 0.0.0.0:1 0.0.0.0:*'
",
        );
        fixture.executable("bin/netstat", "#!/bin/sh\nexit 99\n");
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let report = runner.diagnose_listeners().await.expect("listeners");
        assert_eq!(report.summary.listeners.len(), 3);
        assert_eq!(
            report.summary.assessment,
            ListenerAssessment::ListenersPresent
        );
        assert!(
            report
                .evidence
                .first()
                .is_some_and(|item| item.source.ends_with("/ss"))
        );
        assert!(
            report
                .summary
                .listeners
                .iter()
                .any(|listener| listener.port == 22 && listener.scope == ListenerScope::Wildcard)
        );
        assert!(
            report
                .summary
                .listeners
                .iter()
                .any(|listener| listener.port == 8080 && listener.scope == ListenerScope::Loopback)
        );
        assert!(
            report
                .summary
                .listeners
                .iter()
                .any(|listener| listener.port == 53 && listener.scope == ListenerScope::LinkLocal)
        );
    }

    #[tokio::test]
    async fn listener_runbook_falls_back_to_busybox_netstat() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/netstat",
            r"#!/bin/sh
printf '%s\n' \
'Active Internet connections (only servers)' \
'Proto Recv-Q Send-Q Local Address Foreign Address State' \
'tcp 0 0 :::443 :::* LISTEN' \
'udp 0 0 0.0.0.0:67 0.0.0.0:*'
",
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let report = runner.diagnose_listeners().await.expect("listeners");
        assert!(report.complete);
        assert_eq!(report.summary.listeners.len(), 2);
        assert!(
            report
                .evidence
                .first()
                .is_some_and(|item| item.source.ends_with("/netstat"))
        );
    }

    #[test]
    fn listener_inventory_is_cardinality_bounded() {
        let output = (1..=MAX_LISTENERS + 1)
            .map(|port| format!("tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*"))
            .collect::<Vec<_>>()
            .join("\n");
        let report = build_listener_report(vec![ProbeEvidence {
            probe: "network.socket.listeners".into(),
            source: "/bin/ss".into(),
            status: ProbeStatus::Ok,
            output,
            truncated: false,
            duration_ms: 0,
        }]);
        assert_eq!(report.summary.listeners.len(), MAX_LISTENERS);
        assert!(report.summary.truncated);
        assert!(!report.complete);
    }

    #[tokio::test]
    async fn openwrt_wireless_runbook_normalizes_ubus_without_scanning() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ubus",
            r#"#!/bin/sh
printf '%s\n' '{"radio0":{"up":true,"pending":false,"disabled":false,"config":{"channel":"11"},"interfaces":[{"section":"default_radio0","ifname":"wlan0","config":{"mode":"ap","ssid":"Private SSID"}}]},"radio1":{"up":false,"disabled":true,"interfaces":[]}}'
"#,
        );
        fixture.executable("bin/iwinfo", "#!/bin/sh\nexit 0\n");
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let mut openwrt = platform(FirewallBackend::Fw4);
        openwrt.has_ubus = true;
        let report = runner.diagnose_wireless(&openwrt).await.expect("wireless");
        assert_eq!(
            report.summary.assessment,
            WirelessAssessment::WirelessPresent
        );
        assert_eq!(report.summary.radios.len(), 2);
        assert_eq!(report.summary.radios[0].channel, Some(11));
        assert_eq!(report.summary.interfaces.len(), 1);
        assert_eq!(
            report.summary.interfaces[0].ssid.as_deref(),
            Some("Private SSID")
        );
        assert_eq!(report.summary.interfaces[0].mode.as_deref(), Some("ap"));
        assert!(report.complete);
    }

    #[tokio::test]
    async fn generic_wireless_runbook_normalizes_iw_dev() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/iw",
            r"#!/bin/sh
printf '%s\n' \
'phy#0' \
'	Interface wlan0' \
'		ifindex 3' \
'		type managed' \
'		channel 36 (5180 MHz), width: 80 MHz'
",
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let mut generic = platform(FirewallBackend::Nftables);
        generic.kind = PlatformKind::GenericLinux;
        generic.has_ubus = false;
        let report = runner.diagnose_wireless(&generic).await.expect("wireless");
        assert_eq!(report.summary.radios[0].name, "phy0");
        assert_eq!(report.summary.interfaces[0].name, "wlan0");
        assert_eq!(
            report.summary.interfaces[0].mode.as_deref(),
            Some("managed")
        );
        assert_eq!(report.summary.interfaces[0].channel, Some(36));
        assert_eq!(report.summary.interfaces[0].frequency_mhz, Some(5180));
    }

    #[tokio::test]
    async fn wireless_runbook_falls_back_to_iwinfo() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/iwinfo",
            r#"#!/bin/sh
printf '%s\n' \
'wlan0     ESSID: "Guest"' \
'          Mode: Master  Channel: 6 (2.437 GHz)'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let mut generic = platform(FirewallBackend::Nftables);
        generic.kind = PlatformKind::GenericLinux;
        generic.has_ubus = false;
        let report = runner.diagnose_wireless(&generic).await.expect("wireless");
        assert_eq!(report.summary.interfaces[0].ssid.as_deref(), Some("Guest"));
        assert_eq!(report.summary.interfaces[0].mode.as_deref(), Some("master"));
        assert_eq!(report.summary.interfaces[0].channel, Some(6));
        assert_eq!(report.summary.interfaces[0].frequency_mhz, Some(2437));
    }

    #[tokio::test]
    async fn interface_stats_runbook_normalizes_stats64_errors_and_drops() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/ip",
            r#"#!/bin/sh
printf '%s\n' '[{"ifname":"eth0","operstate":"UP","stats64":{"rx":{"bytes":1000,"packets":10,"errors":2,"dropped":3},"tx":{"bytes":2000,"packets":20,"errors":0,"dropped":1}}},{"ifname":"lo","operstate":"UNKNOWN","stats64":{"rx":{"bytes":500,"packets":5,"errors":0,"dropped":0},"tx":{"bytes":500,"packets":5,"errors":0,"dropped":0}}}]'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let report = runner
            .diagnose_interface_stats()
            .await
            .expect("interface stats");
        assert_eq!(
            report.summary.assessment,
            InterfaceStatsAssessment::ErrorsOrDropsPresent
        );
        assert_eq!(report.summary.interfaces.len(), 2);
        let eth0 = report
            .summary
            .interfaces
            .iter()
            .find(|interface| interface.name == "eth0")
            .expect("eth0");
        assert_eq!(eth0.rx_bytes, 1000);
        assert_eq!(eth0.rx_errors, 2);
        assert_eq!(eth0.tx_dropped, 1);
        assert!(report.complete);
    }

    #[test]
    fn conntrack_capacity_uses_bounded_proc_values() {
        let fixture = Fixture::new();
        fixture.write("proc/sys/net/netfilter/nf_conntrack_count", "950\n");
        fixture.write("proc/sys/net/netfilter/nf_conntrack_max", "1000\n");
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 32,
        };
        let report = runner.diagnose_conntrack();
        assert_eq!(report.summary.assessment, ConntrackAssessment::NearCapacity);
        assert_eq!(report.summary.count, Some(950));
        assert_eq!(report.summary.limit, Some(1000));
        assert_eq!(report.summary.utilization_percent, Some(95));
        assert!(report.complete);
    }

    #[test]
    fn conntrack_capacity_rejects_zero_limit_and_reports_partial_evidence() {
        let zero_limit = build_conntrack_report(vec![
            ok_evidence("network.conntrack.count", "1\n"),
            ok_evidence("network.conntrack.limit", "0\n"),
        ]);
        assert_eq!(
            zero_limit.summary.assessment,
            ConntrackAssessment::InvalidLimit
        );
        let partial = build_conntrack_report(vec![
            ok_evidence("network.conntrack.count", "42\n"),
            status_evidence("network.conntrack.limit", ProbeStatus::Unavailable),
        ]);
        assert_eq!(
            partial.summary.assessment,
            ConntrackAssessment::PartialEvidence
        );
        assert!(!partial.complete);
    }

    #[tokio::test]
    async fn qdisc_runbook_normalizes_stats_and_stats2() {
        let fixture = Fixture::new();
        fixture.executable(
            "bin/tc",
            r#"#!/bin/sh
printf '%s\n' '[{"kind":"fq_codel","handle":"8001:","dev":"eth0","root":true,"stats":{"bytes":1000,"packets":10,"drops":2,"overlimits":3,"requeues":1,"backlog":128,"qlen":2}},{"kind":"cake","handle":"8002:","dev":"wan","parent":"1:1","stats2":{"basic":{"bytes":2000,"packets":20},"queue":{"drops":4,"overlimits":5,"requeues":2,"backlog":256,"qlen":3}}}]'
"#,
        );
        let runner = ToolRunner {
            root: fixture.root.clone(),
            command_dirs: vec![PathBuf::from("/bin")],
            timeout: FIXTURE_TIMEOUT,
            max_output_bytes: 4096,
        };
        let report = runner.diagnose_qdisc().await.expect("qdisc");
        assert_eq!(
            report.summary.assessment,
            QdiscAssessment::PressureCountersPresent
        );
        assert_eq!(report.summary.qdiscs.len(), 2);
        assert_eq!(report.summary.qdiscs[0].device, "eth0");
        assert_eq!(report.summary.qdiscs[0].drops, 2);
        assert_eq!(report.summary.qdiscs[1].device, "wan");
        assert_eq!(report.summary.qdiscs[1].backlog_bytes, 256);
        assert!(report.complete);
    }

    #[test]
    fn qdisc_normalization_caps_entries() {
        let qdiscs: Vec<serde_json::Value> = (0..=MAX_QDISCS)
            .map(|index| {
                serde_json::json!({
                    "kind": "fq_codel",
                    "dev": format!("if{index}"),
                    "stats": {"bytes": 0, "packets": 0, "drops": 0}
                })
            })
            .collect();
        let report = build_qdisc_report(vec![ok_evidence(
            "network.qdisc.stats",
            &serde_json::to_string(&qdiscs).expect("qdiscs"),
        )]);
        assert_eq!(report.summary.qdiscs.len(), MAX_QDISCS);
        assert!(report.summary.truncated);
        assert!(!report.complete);
    }

    #[test]
    fn interface_stats_supports_legacy_stats_and_caps_entries() {
        let interfaces: Vec<serde_json::Value> = (0..=MAX_INTERFACE_STATS)
            .map(|index| {
                serde_json::json!({
                    "ifname": format!("eth{index}"),
                    "stats": {
                        "rx": {"bytes": index, "packets": 1, "errors": 0, "dropped": 0},
                        "tx": {"bytes": index, "packets": 1, "errors": 0, "dropped": 0}
                    }
                })
            })
            .collect();
        let report = build_interface_stats_report(vec![ok_evidence(
            "network.interface.stats",
            &serde_json::to_string(&interfaces).expect("stats"),
        )]);
        assert_eq!(report.summary.interfaces.len(), MAX_INTERFACE_STATS);
        assert!(report.summary.truncated);
        assert!(!report.complete);
    }

    #[test]
    fn normalizes_fw3_ipv4_and_ipv6_rules_without_expressions() {
        let ipv4 = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n[2:128] -A INPUT -i lo -j ACCEPT\nCOMMIT\n";
        let ipv6 = "*filter\n:INPUT ACCEPT [0:0]\n[1:64] -A INPUT -p ipv6-icmp -j ACCEPT\nCOMMIT\n";
        let report = build_firewall_report(
            vec![
                ok_evidence("network.firewall.iptables_ipv4", ipv4),
                ok_evidence("network.firewall.iptables_ipv6", ipv6),
            ],
            FirewallBackend::Fw3,
        );
        assert_eq!(report.summary.tables, 2);
        assert_eq!(report.summary.chains, 3);
        assert_eq!(report.summary.rules, 2);
        assert_eq!(report.summary.rules_with_counters, 2);
        assert_eq!(report.summary.base_chains.len(), 3);
        assert!(
            report
                .summary
                .base_chains
                .iter()
                .any(|chain| chain.family == "ipv6" && chain.policy.as_deref() == Some("ACCEPT"))
        );
    }

    #[test]
    fn interface_inventory_caps_normalized_entries() {
        let links: Vec<serde_json::Value> = (0..=MAX_INTERFACES)
            .map(|index| {
                serde_json::json!({
                    "ifindex": index + 1,
                    "ifname": format!("eth{index}"),
                    "flags": ["BROADCAST"],
                    "operstate": "DOWN"
                })
            })
            .collect();
        let report = build_interface_report(vec![
            ok_evidence(
                "network.interface.link",
                &serde_json::to_string(&links).expect("links"),
            ),
            ok_evidence("network.interface.address", "[]"),
        ]);
        assert_eq!(report.summary.interfaces.len(), MAX_INTERFACES);
        assert!(report.summary.truncated);
        assert!(!report.complete);
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
            timeout: FIXTURE_TIMEOUT,
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
