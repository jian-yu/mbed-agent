use std::error::Error;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_core::generate_password_hash;
use agent_protocol::{
    ClientRequest, Command, FirewallMutationRequest, PROTOCOL_VERSION, SensitiveString,
    ServerResponse,
};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

mod daemon;
mod firewall_execution;
mod logging;

#[derive(Debug, Parser)]
#[command(version, about = "Mbed Agent for embedded Linux and OpenWrt")]
struct Args {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Run the long-lived agent service.
    Daemon {
        #[arg(short, long, default_value = "/etc/mbed-agent/config.toml")]
        config: PathBuf,
    },
    /// Check whether the local daemon is responding.
    Ping {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Show runtime, platform, and storage status.
    Status {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Show discovered `OpenWrt` and Linux capabilities.
    Capabilities {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Ask the configured LLM through the local daemon.
    Ask {
        /// Prompt sent to the configured provider.
        prompt: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Run a deterministic, read-only diagnostic runbook.
    Diagnose {
        #[command(subcommand)]
        target: DiagnoseTarget,
    },
    /// Inspect volatile task metadata from this boot.
    Task {
        #[command(subcommand)]
        target: TaskTarget,
    },
    /// Configure or request local administrator authentication.
    Auth {
        #[command(subcommand)]
        target: AuthTarget,
    },
    /// Inspect and authorize bounded configuration changes.
    Change {
        #[command(subcommand)]
        target: ChangeTarget,
    },
    #[command(hide = true)]
    RollbackHelper {
        transaction_id: String,
        #[arg(short, long, default_value = "/etc/mbed-agent/config.toml")]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DiagnoseTarget {
    /// Collect WAN interface, route, DNS, and firewall evidence.
    Wan {
        /// Probe the gateway, a public IP, and DNS after passive checks pass.
        #[arg(long)]
        active: bool,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect DNS configuration and its passive network prerequisites.
    Dns {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect passive DHCP protocol, negotiation, and address state.
    Dhcp {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect WAN addressing and normalized IPv4/IPv6 default routes.
    Routes {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inventory bounded kernel interface, link, and address state.
    Interfaces {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect the bounded kernel ARP/NDP neighbor cache.
    Neighbors {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect bounded fw3/fw4, iptables, or nftables runtime state.
    Firewall {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect bounded policy rules and aggregate route tables.
    PolicyRouting {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect bounded TCP/UDP listeners without process identities.
    Listeners {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect bounded wireless radio and interface state without scanning.
    Wireless {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect one bounded snapshot of interface counters and errors.
    InterfaceStats {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect kernel connection-tracking count and capacity.
    Conntrack {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Inspect one bounded snapshot of queueing-discipline counters.
    Qdisc {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Show volatile diagnostic summaries from this boot.
    History {
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TaskTarget {
    /// Show bounded task outcomes without prompt or response content.
    History {
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AuthTarget {
    /// Read a password from stdin and print a salted configuration hash.
    HashPassword,
    /// Read a password from stdin and elevate the local CLI actor in daemon RAM.
    Elevate {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ChangeTarget {
    /// Show a fresh typed firewall inventory with exact object digests.
    FirewallInventory {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Read a typed firewall mutation array from stdin and create an approval-ready plan.
    FirewallPlan {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Show one typed plan and its current volatile state.
    Get {
        change_set_id: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Issue a one-use approval token for an exact plan as device-admin.
    Approve {
        change_set_id: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Consume a one-use approval token from stdin and execute its exact plan.
    Apply {
        change_set_id: String,
        #[arg(long)]
        approval_id: Option<String>,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Re-verify and confirm a high-risk change before its rollback deadline.
    Confirm {
        change_set_id: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Reject a pending plan owned by the local actor.
    Reject {
        change_set_id: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Args::parse().command {
        CliCommand::Daemon { config } => daemon::run(&config).await,
        CliCommand::Ping { socket } => run_client(&socket, Command::Ping).await,
        CliCommand::Status { socket } => run_client(&socket, Command::Status).await,
        CliCommand::Capabilities { socket } => run_client(&socket, Command::Capabilities).await,
        CliCommand::Ask { prompt, socket } => {
            run_client(&socket, Command::Complete { prompt }).await
        }
        CliCommand::Diagnose {
            target: DiagnoseTarget::Wan { active, socket },
        } => run_client(&socket, Command::DiagnoseWan { active }).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Dns { socket },
        } => run_client(&socket, Command::DiagnoseDns).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Dhcp { socket },
        } => run_client(&socket, Command::DiagnoseDhcp).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Routes { socket },
        } => run_client(&socket, Command::DiagnoseRoutes).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Interfaces { socket },
        } => run_client(&socket, Command::DiagnoseInterfaces).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Neighbors { socket },
        } => run_client(&socket, Command::DiagnoseNeighbors).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Firewall { socket },
        } => run_client(&socket, Command::DiagnoseFirewall).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::PolicyRouting { socket },
        } => run_client(&socket, Command::DiagnosePolicyRouting).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Listeners { socket },
        } => run_client(&socket, Command::DiagnoseListeners).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Wireless { socket },
        } => run_client(&socket, Command::DiagnoseWireless).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::InterfaceStats { socket },
        } => run_client(&socket, Command::DiagnoseInterfaceStats).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Conntrack { socket },
        } => run_client(&socket, Command::DiagnoseConntrack).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::Qdisc { socket },
        } => run_client(&socket, Command::DiagnoseQdisc).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::History { limit, socket },
        } => run_client(&socket, Command::DiagnosticHistory { limit }).await,
        CliCommand::Task {
            target: TaskTarget::History { limit, socket },
        } => run_client(&socket, Command::TaskHistory { limit }).await,
        CliCommand::Auth {
            target: AuthTarget::HashPassword,
        } => {
            let password = read_password_stdin()?;
            println!("{}", generate_password_hash(&password)?);
            Ok(())
        }
        CliCommand::Auth {
            target: AuthTarget::Elevate { socket },
        } => {
            let mut password = read_password_stdin()?;
            let password = match String::from_utf8(std::mem::take(&mut password)) {
                Ok(password) => password,
                Err(error) => {
                    let mut invalid = error.into_bytes();
                    invalid.zeroize();
                    return Err("administrator password must be valid UTF-8".into());
                }
            };
            run_client(
                &socket,
                Command::Elevate {
                    password: SensitiveString::new(password),
                },
            )
            .await
        }
        CliCommand::Change { target } => run_change_target(target).await,
        CliCommand::RollbackHelper {
            transaction_id,
            config,
        } => {
            let config = agent_core::AgentConfig::load(&config)?;
            let runtime_root = config
                .storage
                .path
                .parent()
                .ok_or("storage path has no runtime root")?;
            agent_core::run_rollback_helper(
                &runtime_root.join("rollback"),
                &transaction_id,
                config.storage.max_rollback_bytes,
            )?;
            Ok(())
        }
    }
}

async fn run_change_target(target: ChangeTarget) -> Result<(), Box<dyn Error>> {
    match target {
        ChangeTarget::FirewallInventory { socket } => {
            run_client(&socket, Command::FirewallInventory).await
        }
        ChangeTarget::FirewallPlan { socket } => {
            let input = read_bounded_stdin(60 * 1024, "firewall plan")?;
            let mutations: Vec<FirewallMutationRequest> = serde_json::from_slice(&input)?;
            run_client(&socket, Command::FirewallPlan { mutations }).await
        }
        ChangeTarget::Get {
            change_set_id,
            socket,
        } => run_client(&socket, Command::ChangeGet { change_set_id }).await,
        ChangeTarget::Approve {
            change_set_id,
            socket,
        } => run_client(&socket, Command::ChangeApprove { change_set_id }).await,
        ChangeTarget::Apply {
            change_set_id,
            approval_id,
            socket,
        } => {
            let (approval_id, token) = read_approval_stdin(&change_set_id, approval_id.as_deref())?;
            run_client(
                &socket,
                Command::ChangeApply {
                    change_set_id,
                    approval_id,
                    approval_token: SensitiveString::new(token),
                },
            )
            .await
        }
        ChangeTarget::Confirm {
            change_set_id,
            socket,
        } => run_client(&socket, Command::ChangeConfirm { change_set_id }).await,
        ChangeTarget::Reject {
            change_set_id,
            socket,
        } => run_client(&socket, Command::ChangeReject { change_set_id }).await,
    }
}

fn read_bounded_stdin(limit: usize, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut input)?;
    if input.len() > limit {
        return Err(format!("{label} exceeds {limit} bytes").into());
    }
    if input.is_empty() {
        return Err(format!("{label} must not be empty").into());
    }
    Ok(input)
}

fn read_password_stdin() -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    const MAX_PASSWORD_BYTES: usize = 1_024;
    let mut password = Zeroizing::new(Vec::with_capacity(128));
    io::stdin()
        .lock()
        .take(u64::try_from(MAX_PASSWORD_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut password)?;
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("administrator password exceeds 1024 bytes".into());
    }
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err("administrator password must not be empty".into());
    }
    Ok(password)
}

fn read_approval_stdin(
    change_set_id: &str,
    supplied_approval_id: Option<&str>,
) -> Result<(String, String), Box<dyn Error>> {
    let mut input = Zeroizing::new(read_bounded_stdin(8 * 1024, "change approval")?);
    parse_approval_input(change_set_id, supplied_approval_id, &mut input)
}

fn parse_approval_input(
    change_set_id: &str,
    supplied_approval_id: Option<&str>,
    input: &mut Zeroizing<Vec<u8>>,
) -> Result<(String, String), Box<dyn Error>> {
    if input.first() == Some(&b'{') {
        let response: ServerResponse = serde_json::from_slice(input)?;
        let Some(agent_protocol::ResponseData::ChangeApproval(approval)) = response.result else {
            return Err("stdin is not a successful change approval response".into());
        };
        if approval.change_set_id != change_set_id
            || supplied_approval_id.is_some_and(|value| value != approval.approval_id)
        {
            return Err("approval response does not match the requested ChangeSet".into());
        }
        return Ok((approval.approval_id, approval.token.into_inner()));
    }
    let approval_id = supplied_approval_id
        .ok_or("--approval-id is required when stdin contains only the raw token")?
        .to_owned();
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input.pop();
    }
    if input.is_empty() {
        return Err("approval token must not be empty".into());
    }
    let token = String::from_utf8(std::mem::take(input)).map_err(|error| {
        let mut invalid = error.into_bytes();
        invalid.zeroize();
        "approval token must be valid UTF-8"
    })?;
    Ok((approval_id, token))
}

async fn run_client(socket: &Path, command: Command) -> Result<(), Box<dyn Error>> {
    let mut stream = UnixStream::connect(socket).await?;
    let id = format!(
        "cli-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
    );
    let request = ClientRequest {
        protocol_version: PROTOCOL_VERSION,
        id,
        command,
    };
    let mut payload = Zeroizing::new(serde_json::to_vec(&request)?);
    payload.push(b'\n');
    stream.write_all(&payload).await?;

    let mut reader = BufReader::new(stream);
    let mut response = Zeroizing::new(String::new());
    reader.read_line(&mut response).await?;
    let response: ServerResponse = serde_json::from_str(&response)?;
    let rendered = Zeroizing::new(serde_json::to_string_pretty(&response)?);
    println!("{}", rendered.as_str());
    if response.ok {
        Ok(())
    } else {
        Err("daemon returned an error".into())
    }
}

#[cfg(test)]
mod cli_tests {
    use agent_protocol::{ChangeApprovalResponse, ResponseData};

    use super::*;

    #[test]
    fn complete_approval_response_can_flow_directly_to_apply() {
        let response = ServerResponse::success(
            "request-1",
            ResponseData::ChangeApproval(ChangeApprovalResponse {
                approval_id: "0123456789abcdef0123456789abcdef".into(),
                change_set_id: "change-1".into(),
                plan_digest: "a".repeat(64),
                token: SensitiveString::new("one-use-token".into()),
                expires_monotonic_ms: 1_000,
            }),
        );
        let mut input = Zeroizing::new(serde_json::to_vec_pretty(&response).expect("encode"));
        assert_eq!(
            parse_approval_input("change-1", None, &mut input).expect("parse"),
            (
                "0123456789abcdef0123456789abcdef".into(),
                "one-use-token".into()
            )
        );
    }
}
