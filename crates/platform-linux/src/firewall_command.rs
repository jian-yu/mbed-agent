//! Shell-free, bounded native firewall command execution.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

const COMMAND_DIRS: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Closed native operations used by firewall execution ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallCommand {
    UciShowFirewall,
    UciShowFirewallAt { staging_dir: PathBuf },
    UciShowNetwork,
    UciShowNetworkAt { staging_dir: PathBuf },
    UciExportNetworkAt { staging_dir: PathBuf },
    UciBatch { staging_dir: PathBuf },
    Fw3PrintIpv4 { staging_dir: PathBuf },
    Fw3PrintIpv6 { staging_dir: PathBuf },
    Fw4Check { staging_dir: PathBuf },
    OpenWrtFirewallReload,
    OpenWrtNetworkReload,
    IpJsonLink,
    IpJsonAddress,
    IpJsonRoute,
    NftListTables,
    NftListManagedTable,
    NftCheck { ruleset: PathBuf },
    NftLoad { ruleset: PathBuf },
    IptablesSave { ipv6: bool },
    IptablesRestoreTest { ipv6: bool },
    IptablesRestore { ipv6: bool },
}

/// Bounded process result. Output is diagnostic-only and never interpreted as authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallCommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub duration_ms: u64,
}

/// Minimal command capability consumed by typed native transactions.
pub trait FirewallCommandExecutor {
    /// Executes one closed firewall operation.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed command error.
    fn execute(
        &self,
        operation: &FirewallCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FirewallCommandOutput, FirewallCommandError>;
}

/// Executes only [`FirewallCommand`] values with a clean environment and no shell.
#[derive(Debug, Clone)]
pub struct FirewallCommandRunner {
    runtime_root: PathBuf,
    command_dirs: Vec<PathBuf>,
    timeout: Duration,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

impl FirewallCommandRunner {
    #[must_use]
    pub fn system(
        runtime_root: PathBuf,
        timeout: Duration,
        max_input_bytes: usize,
        max_output_bytes: usize,
    ) -> Self {
        Self {
            runtime_root,
            command_dirs: COMMAND_DIRS.iter().map(PathBuf::from).collect(),
            timeout,
            max_input_bytes,
            max_output_bytes,
        }
    }

    /// Executes one fixed operation.
    ///
    /// `stdin` is accepted only by UCI batch and iptables restore operations.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable executable, unsafe staging path, forbidden/oversized
    /// input, spawn/I/O failure, timeout, output overflow, or unsuccessful exit status.
    pub fn run(
        &self,
        operation: &FirewallCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FirewallCommandOutput, FirewallCommandError> {
        if self.timeout.is_zero() || self.max_input_bytes == 0 || self.max_output_bytes < 2 {
            return Err(FirewallCommandError::InvalidLimits);
        }
        let specification = self.specification(operation)?;
        let accepts_stdin = matches!(
            operation,
            FirewallCommand::UciBatch { .. }
                | FirewallCommand::IptablesRestoreTest { .. }
                | FirewallCommand::IptablesRestore { .. }
        );
        if stdin.is_some() != accepts_stdin {
            return Err(FirewallCommandError::UnexpectedInput);
        }
        let input = stdin.unwrap_or_default();
        if input.len() > self.max_input_bytes {
            return Err(FirewallCommandError::InputCapacity);
        }
        let executable = self.resolve(specification.program)?;
        let mut command = Command::new(executable);
        command
            .args(&specification.arguments)
            .env_clear()
            .stdin(if accepts_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(staging_dir) = specification.uci_config_dir {
            command.env("UCI_CONFIG_DIR", staging_dir);
        }
        let started = Instant::now();
        let mut child = command.spawn().map_err(FirewallCommandError::Io)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(FirewallCommandError::MissingPipe)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(FirewallCommandError::MissingPipe)?;
        let stream_limit = self.max_output_bytes / 2;
        let stdout_reader = thread::spawn(move || read_limited(stdout, stream_limit));
        let stderr_reader = thread::spawn(move || read_limited(stderr, stream_limit));
        if accepts_stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or(FirewallCommandError::MissingPipe)?;
            pipe.write_all(input).map_err(FirewallCommandError::Io)?;
        }
        let status = loop {
            if let Some(status) = child.try_wait().map_err(FirewallCommandError::Io)? {
                break status;
            }
            if started.elapsed() >= self.timeout {
                child.kill().map_err(FirewallCommandError::Io)?;
                let _ = child.wait();
                join_reader(stdout_reader)?;
                join_reader(stderr_reader)?;
                return Err(FirewallCommandError::TimedOut);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_truncated) = join_reader(stdout_reader)?;
        let (stderr, stderr_truncated) = join_reader(stderr_reader)?;
        if stdout_truncated || stderr_truncated {
            return Err(FirewallCommandError::OutputCapacity);
        }
        if !status.success() {
            return Err(FirewallCommandError::Unsuccessful);
        }
        Ok(FirewallCommandOutput {
            stdout,
            stderr,
            truncated: false,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    #[allow(clippy::too_many_lines)] // Closed operation mapping is intentionally centralized.
    fn specification(
        &self,
        operation: &FirewallCommand,
    ) -> Result<CommandSpecification, FirewallCommandError> {
        if matches!(
            operation,
            FirewallCommand::UciShowNetwork
                | FirewallCommand::UciShowNetworkAt { .. }
                | FirewallCommand::UciExportNetworkAt { .. }
                | FirewallCommand::OpenWrtNetworkReload
        ) {
            return self.network_specification(operation);
        }
        let spec = match operation {
            FirewallCommand::UciShowFirewall => spec("uci", &["-q", "show", "firewall"]),
            FirewallCommand::UciShowFirewallAt { staging_dir } => {
                let dir = self.validate_staging_dir(staging_dir)?;
                CommandSpecification {
                    program: "uci",
                    arguments: vec![
                        "-c".into(),
                        dir.as_os_str().into(),
                        "-q".into(),
                        "show".into(),
                        "firewall".into(),
                    ],
                    uci_config_dir: None,
                }
            }
            FirewallCommand::UciBatch { staging_dir } => {
                let dir = self.validate_staging_dir(staging_dir)?;
                CommandSpecification {
                    program: "uci",
                    arguments: vec!["-c".into(), dir.as_os_str().into(), "batch".into()],
                    uci_config_dir: None,
                }
            }
            FirewallCommand::Fw3PrintIpv4 { staging_dir } => spec_with_uci(
                "fw3",
                &["-4", "-q", "print"],
                self.validate_staging_dir(staging_dir)?,
            ),
            FirewallCommand::Fw3PrintIpv6 { staging_dir } => spec_with_uci(
                "fw3",
                &["-6", "-q", "print"],
                self.validate_staging_dir(staging_dir)?,
            ),
            FirewallCommand::Fw4Check { staging_dir } => spec_with_uci(
                "fw4",
                &["-q", "check"],
                self.validate_staging_dir(staging_dir)?,
            ),
            FirewallCommand::OpenWrtFirewallReload => spec("/etc/init.d/firewall", &["reload"]),
            FirewallCommand::IpJsonLink => spec("ip", &["-j", "link", "show"]),
            FirewallCommand::IpJsonAddress => spec("ip", &["-j", "address", "show"]),
            FirewallCommand::IpJsonRoute => spec("ip", &["-j", "route", "show", "table", "all"]),
            FirewallCommand::NftListTables => spec("nft", &["list", "tables"]),
            FirewallCommand::NftListManagedTable => {
                spec("nft", &["list", "table", "inet", "mbed_agent"])
            }
            FirewallCommand::NftCheck { ruleset } => {
                let file = self.validate_staging_file(ruleset)?;
                CommandSpecification {
                    program: "nft",
                    arguments: vec!["--check".into(), "--file".into(), file.as_os_str().into()],
                    uci_config_dir: None,
                }
            }
            FirewallCommand::NftLoad { ruleset } => {
                let file = self.validate_staging_file(ruleset)?;
                CommandSpecification {
                    program: "nft",
                    arguments: vec!["--file".into(), file.as_os_str().into()],
                    uci_config_dir: None,
                }
            }
            FirewallCommand::IptablesSave { ipv6 } => spec(
                if *ipv6 {
                    "ip6tables-save"
                } else {
                    "iptables-save"
                },
                &[],
            ),
            FirewallCommand::IptablesRestoreTest { ipv6 } => spec(
                if *ipv6 {
                    "ip6tables-restore"
                } else {
                    "iptables-restore"
                },
                &["--test", "--noflush"],
            ),
            FirewallCommand::IptablesRestore { ipv6 } => spec(
                if *ipv6 {
                    "ip6tables-restore"
                } else {
                    "iptables-restore"
                },
                &["--noflush"],
            ),
            FirewallCommand::UciShowNetwork
            | FirewallCommand::UciShowNetworkAt { .. }
            | FirewallCommand::UciExportNetworkAt { .. }
            | FirewallCommand::OpenWrtNetworkReload => unreachable!("handled above"),
        };
        Ok(spec)
    }

    fn network_specification(
        &self,
        operation: &FirewallCommand,
    ) -> Result<CommandSpecification, FirewallCommandError> {
        match operation {
            FirewallCommand::UciShowNetwork => Ok(spec("uci", &["-q", "show", "network"])),
            FirewallCommand::UciShowNetworkAt { staging_dir }
            | FirewallCommand::UciExportNetworkAt { staging_dir } => {
                let dir = self.validate_staging_dir(staging_dir)?;
                let action = if matches!(operation, FirewallCommand::UciShowNetworkAt { .. }) {
                    "show"
                } else {
                    "export"
                };
                Ok(CommandSpecification {
                    program: "uci",
                    arguments: vec![
                        "-c".into(),
                        dir.as_os_str().into(),
                        "-q".into(),
                        action.into(),
                        "network".into(),
                    ],
                    uci_config_dir: None,
                })
            }
            FirewallCommand::OpenWrtNetworkReload => Ok(spec("/etc/init.d/network", &["reload"])),
            _ => unreachable!("network operation checked by caller"),
        }
    }

    fn validate_staging_dir(&self, path: &Path) -> Result<PathBuf, FirewallCommandError> {
        let metadata = fs::symlink_metadata(path).map_err(FirewallCommandError::Io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(FirewallCommandError::UnsafePath);
        }
        self.canonical_runtime_path(path)
    }

    fn validate_staging_file(&self, path: &Path) -> Result<PathBuf, FirewallCommandError> {
        let metadata = fs::symlink_metadata(path).map_err(FirewallCommandError::Io)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > self.max_input_bytes as u64
        {
            return Err(FirewallCommandError::UnsafePath);
        }
        self.canonical_runtime_path(path)
    }

    fn canonical_runtime_path(&self, path: &Path) -> Result<PathBuf, FirewallCommandError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(FirewallCommandError::UnsafePath);
        }
        let root = fs::canonicalize(&self.runtime_root).map_err(FirewallCommandError::Io)?;
        let resolved = fs::canonicalize(path).map_err(FirewallCommandError::Io)?;
        if !resolved.starts_with(root) {
            return Err(FirewallCommandError::UnsafePath);
        }
        Ok(resolved)
    }

    fn resolve(&self, program: &str) -> Result<PathBuf, FirewallCommandError> {
        if matches!(program, "/etc/init.d/firewall" | "/etc/init.d/network") {
            return executable(Path::new(program));
        }
        self.command_dirs
            .iter()
            .map(|directory| directory.join(program))
            .find_map(|candidate| executable(&candidate).ok())
            .ok_or(FirewallCommandError::Unavailable)
    }
}

impl FirewallCommandExecutor for FirewallCommandRunner {
    fn execute(
        &self,
        operation: &FirewallCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FirewallCommandOutput, FirewallCommandError> {
        self.run(operation, stdin)
    }
}

struct CommandSpecification {
    program: &'static str,
    arguments: Vec<OsString>,
    uci_config_dir: Option<PathBuf>,
}

fn spec(program: &'static str, arguments: &[&str]) -> CommandSpecification {
    CommandSpecification {
        program,
        arguments: arguments.iter().map(OsString::from).collect(),
        uci_config_dir: None,
    }
}

fn spec_with_uci(
    program: &'static str,
    arguments: &[&str],
    staging_dir: PathBuf,
) -> CommandSpecification {
    CommandSpecification {
        program,
        arguments: arguments.iter().map(OsString::from).collect(),
        uci_config_dir: Some(staging_dir),
    }
}

fn executable(path: &Path) -> Result<PathBuf, FirewallCommandError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| FirewallCommandError::Unavailable)?;
    if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
        Ok(path.to_path_buf())
    } else {
        Err(FirewallCommandError::Unavailable)
    }
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut output = Vec::with_capacity(limit.min(4096));
    reader
        .by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut output)?;
    let truncated = output.len() > limit;
    output.truncate(limit);
    Ok((output, truncated))
}

fn join_reader(
    reader: thread::JoinHandle<Result<(Vec<u8>, bool), std::io::Error>>,
) -> Result<(Vec<u8>, bool), FirewallCommandError> {
    reader
        .join()
        .map_err(|_| FirewallCommandError::ReaderPanicked)?
        .map_err(FirewallCommandError::Io)
}

#[derive(Debug, Error)]
pub enum FirewallCommandError {
    #[error("firewall command runner limits are invalid")]
    InvalidLimits,
    #[error("fixed firewall executable is unavailable")]
    Unavailable,
    #[error("firewall command input is missing or forbidden")]
    UnexpectedInput,
    #[error("firewall command input exceeds its capacity")]
    InputCapacity,
    #[error("firewall command output exceeds its capacity")]
    OutputCapacity,
    #[error("firewall command staging path is unsafe")]
    UnsafePath,
    #[error("firewall command pipe is unavailable")]
    MissingPipe,
    #[error("firewall command timed out")]
    TimedOut,
    #[error("firewall command returned an unsuccessful status")]
    Unsuccessful,
    #[error("firewall command output reader failed")]
    ReaderPanicked,
    #[error("firewall command I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn fixed_runner_passes_bounded_stdin_without_a_shell() {
        let root = fixture_root();
        write_program(
            &root.join("bin/iptables-restore"),
            "#!/bin/sh\nwhile IFS= read -r line; do printf '%s\\n' \"$line\"; done\n",
        );
        let runner = test_runner(&root, Duration::from_secs(5), 32, 32);
        let output = runner
            .run(
                &FirewallCommand::IptablesRestoreTest { ipv6: false },
                Some(b"*filter\nCOMMIT\n"),
            )
            .expect("run");
        assert_eq!(output.stdout, b"*filter\nCOMMIT\n");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn timeout_kills_a_stuck_fixed_command() {
        let root = fixture_root();
        write_program(&root.join("bin/nft"), "#!/bin/sh\nwhile :; do :; done\n");
        let runner = test_runner(&root, Duration::from_millis(100), 32, 32);
        assert!(matches!(
            runner.run(&FirewallCommand::NftListManagedTable, None),
            Err(FirewallCommandError::TimedOut)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn staging_files_must_be_regular_bounded_and_below_runtime_root() {
        let root = fixture_root();
        write_program(&root.join("bin/nft"), "#!/bin/sh\nexit 0\n");
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime).expect("runtime");
        let runner = test_runner(&root, Duration::from_secs(1), 4, 32);
        let outside = root.join("outside.nft");
        fs::write(&outside, b"ok").expect("outside");
        assert!(matches!(
            runner.run(&FirewallCommand::NftCheck { ruleset: outside }, None),
            Err(FirewallCommandError::UnsafePath)
        ));
        let large = runtime.join("large.nft");
        fs::write(&large, b"12345").expect("large");
        assert!(matches!(
            runner.run(&FirewallCommand::NftCheck { ruleset: large }, None),
            Err(FirewallCommandError::UnsafePath)
        ));
        let escaped = root.join("escaped.nft");
        fs::write(&escaped, b"ok").expect("escaped");
        symlink(&root, runtime.join("escape")).expect("parent symlink");
        assert!(matches!(
            runner.run(
                &FirewallCommand::NftCheck {
                    ruleset: runtime.join("escape/escaped.nft")
                },
                None
            ),
            Err(FirewallCommandError::UnsafePath)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn network_uci_operations_have_fixed_package_and_staging_arguments() {
        let root = fixture_root();
        let runtime = root.join("runtime");
        let staging = runtime.join("staging/change-1");
        fs::create_dir_all(&staging).expect("staging");
        let runner = test_runner(&root, Duration::from_secs(5), 1024, 1024);
        let live = runner
            .specification(&FirewallCommand::UciShowNetwork)
            .expect("live specification");
        assert_eq!(live.program, "uci");
        assert_eq!(
            live.arguments,
            [
                OsString::from("-q"),
                OsString::from("show"),
                OsString::from("network")
            ]
        );
        let staged = runner
            .specification(&FirewallCommand::UciExportNetworkAt {
                staging_dir: staging,
            })
            .expect("staged specification");
        assert_eq!(staged.program, "uci");
        assert_eq!(staged.arguments[2], "-q");
        assert_eq!(staged.arguments[3], "export");
        assert_eq!(staged.arguments[4], "network");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn runtime_network_inventory_operations_are_fixed_and_read_only() {
        let root = fixture_root();
        let runner = test_runner(&root, Duration::from_secs(5), 1024, 1024);
        for (operation, expected) in [
            (FirewallCommand::IpJsonLink, vec!["-j", "link", "show"]),
            (
                FirewallCommand::IpJsonAddress,
                vec!["-j", "address", "show"],
            ),
            (
                FirewallCommand::IpJsonRoute,
                vec!["-j", "route", "show", "table", "all"],
            ),
        ] {
            let specification = runner.specification(&operation).expect("specification");
            assert_eq!(specification.program, "ip");
            assert_eq!(
                specification.arguments,
                expected.into_iter().map(OsString::from).collect::<Vec<_>>()
            );
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn fixture_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-firewall-command-{nonce}"));
        fs::create_dir_all(root.join("bin")).expect("bin");
        root
    }

    fn write_program(path: &Path, body: &str) {
        fs::write(path, body).expect("program");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("permissions");
    }

    fn test_runner(
        root: &Path,
        timeout: Duration,
        max_input_bytes: usize,
        max_output_bytes: usize,
    ) -> FirewallCommandRunner {
        FirewallCommandRunner {
            runtime_root: root.join("runtime"),
            command_dirs: vec![root.join("bin")],
            timeout,
            max_input_bytes,
            max_output_bytes,
        }
    }
}
