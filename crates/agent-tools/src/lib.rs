use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use agent_protocol::{ProbeEvidence, ProbeStatus, WanDiagnosticReport};
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

        let findings = summarize(&evidence);
        let complete = evidence
            .iter()
            .any(|item| item.probe == "openwrt.interface.wan" && item.status == ProbeStatus::Ok)
            && evidence
                .iter()
                .any(|item| item.probe == "network.route.list" && item.status == ProbeStatus::Ok);
        Ok(WanDiagnosticReport {
            interface: WAN_INTERFACE.into(),
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

fn summarize(evidence: &[ProbeEvidence]) -> Vec<String> {
    let mut findings = Vec::new();
    if evidence
        .iter()
        .all(|item| item.probe != "openwrt.interface.wan" || item.status != ProbeStatus::Ok)
    {
        findings.push("OpenWrt WAN status is unavailable; using kernel-level evidence".into());
    }
    if evidence
        .iter()
        .all(|item| item.probe != "network.route.list" || item.status != ProbeStatus::Ok)
    {
        findings.push("route evidence is unavailable".into());
    }
    if evidence
        .iter()
        .all(|item| !item.probe.starts_with("network.dns.") || item.status != ProbeStatus::Ok)
    {
        findings.push("DNS resolver configuration is unavailable".into());
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
