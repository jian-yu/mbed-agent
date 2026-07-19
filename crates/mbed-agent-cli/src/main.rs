use std::error::Error;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use agent_protocol::{ClientRequest, Command, PROTOCOL_VERSION, ServerResponse};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
#[command(version, about = "Control the local Mbed Agent daemon")]
struct Args {
    #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    Ping,
    Status,
    Capabilities,
}

impl From<CliCommand> for Command {
    fn from(value: CliCommand) -> Self {
        match value {
            CliCommand::Ping => Self::Ping,
            CliCommand::Status => Self::Status,
            CliCommand::Capabilities => Self::Capabilities,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut stream = UnixStream::connect(&args.socket).await?;
    let id = format!(
        "cli-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
    );
    let request = ClientRequest {
        protocol_version: PROTOCOL_VERSION,
        id,
        command: args.command.into(),
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
