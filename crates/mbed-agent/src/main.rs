use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_protocol::{ClientRequest, Command, PROTOCOL_VERSION, ServerResponse};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

mod daemon;
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
    /// Run a deterministic, read-only diagnostic runbook.
    Diagnose {
        #[command(subcommand)]
        target: DiagnoseTarget,
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
    /// Show volatile diagnostic summaries from this boot.
    History {
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
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
        CliCommand::Diagnose {
            target: DiagnoseTarget::Wan { active, socket },
        } => run_client(&socket, Command::DiagnoseWan { active }).await,
        CliCommand::Diagnose {
            target: DiagnoseTarget::History { limit, socket },
        } => run_client(&socket, Command::DiagnosticHistory { limit }).await,
    }
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
    let mut payload = serde_json::to_vec(&request)?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).await?;
    let response: ServerResponse = serde_json::from_str(&response)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    if response.ok {
        Ok(())
    } else {
        Err("daemon returned an error".into())
    }
}
