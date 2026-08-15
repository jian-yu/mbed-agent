use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_core::{
    AgentConfig, SecretString, WeChatClawBotConfig, WeComBotConfig, generate_password_hash,
    parse_wechat_clawbot_base_url, parse_wecom_ws_url,
};
use agent_protocol::{
    ChangeSetState, ClientRequest, Command, FirewallMutationRequest, NetworkMutationRequest,
    PROTOCOL_VERSION, SensitiveString, ServerResponse,
};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

mod action_execution;
mod daemon;
mod firewall_execution;
mod logging;
mod mqtt_channel;
mod network_execution;
mod wechat_clawbot;
mod wecom_channel;

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
    /// Inspect configured channel lifecycle state.
    Channel {
        #[command(subcommand)]
        target: ChannelTarget,
    },
    /// List, reload, or execute declarative user/vendor actions.
    Action {
        #[command(subcommand)]
        target: ActionTarget,
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
enum ActionTarget {
    /// List actions available on the detected platform.
    List {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Reload action manifests after device-admin elevation.
    Reload {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Execute one read-only action with a bounded JSON input object.
    Run {
        action_id: String,
        #[arg(long, default_value = "{}")]
        inputs: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Expand one change template into the normal approval-ready typed `ChangeSet` path.
    Plan {
        action_id: String,
        #[arg(long, default_value = "{}")]
        inputs: String,
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ChannelTarget {
    /// Show whether each channel is disabled, connecting, online, or backing off.
    Status {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Bind the official `WeChat` `ClawBot` account by scanning a QR code.
    #[command(name = "bind-wechat-clawbot")]
    BindWechatClawbot {
        #[arg(long, default_value = "default")]
        account: String,
        #[arg(short, long, default_value = "/etc/mbed-agent/config.toml")]
        config: PathBuf,
    },
    /// Bind an official `WeCom` smart bot using Bot ID and a secret read from stdin.
    #[command(name = "bind-wecom")]
    BindWecom {
        #[arg(long)]
        bot_id: String,
        #[arg(long, default_value = "default")]
        account: String,
        #[arg(long, default_value = "wss://openws.work.weixin.qq.com")]
        ws_url: String,
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
    /// Immediately revoke the local CLI actor's in-memory device-admin capability.
    Deauth {
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
    /// Show a fresh typed L2/L3 inventory with exact object digests.
    NetworkInventory {
        #[arg(long, default_value = "/tmp/mbed-agent/agent.sock")]
        socket: PathBuf,
    },
    /// Read a typed `OpenWrt` L2/L3 mutation array from stdin and create an approval-ready plan.
    NetworkPlan {
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
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn Error>> {
    match Args::parse().command {
        CliCommand::Daemon { config } => daemon::run(&config).await,
        CliCommand::Ping { socket } => run_client(&socket, Command::Ping).await,
        CliCommand::Status { socket } => run_client(&socket, Command::Status).await,
        CliCommand::Capabilities { socket } => run_client(&socket, Command::Capabilities).await,
        CliCommand::Channel {
            target: ChannelTarget::Status { socket },
        } => run_client(&socket, Command::ChannelStatus).await,
        CliCommand::Channel {
            target: ChannelTarget::BindWechatClawbot { account, config },
        } => run_wechat_clawbot_bind(&account, &config).await,
        CliCommand::Channel {
            target:
                ChannelTarget::BindWecom {
                    bot_id,
                    account,
                    ws_url,
                    config,
                },
        } => run_wecom_bind(&bot_id, &account, &ws_url, &config),
        CliCommand::Action { target } => run_action_target(target).await,
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
        CliCommand::Auth {
            target: AuthTarget::Deauth { socket },
        } => run_client(&socket, Command::Deauth).await,
        CliCommand::Change { target } => run_change_target(target).await,
        CliCommand::RollbackHelper {
            transaction_id,
            config,
        } => run_rollback_helper_command(&config, &transaction_id),
    }
}

async fn run_action_target(target: ActionTarget) -> Result<(), Box<dyn Error>> {
    match target {
        ActionTarget::List { socket } => run_client(&socket, Command::ActionList).await,
        ActionTarget::Reload { socket } => run_client(&socket, Command::ActionReload).await,
        ActionTarget::Run {
            action_id,
            inputs,
            socket,
        } => {
            if inputs.len() > 16 * 1024 {
                return Err("action inputs exceed 16384 bytes".into());
            }
            let inputs = serde_json::from_str(&inputs)?;
            run_client(&socket, Command::ActionRun { action_id, inputs }).await
        }
        ActionTarget::Plan {
            action_id,
            inputs,
            socket,
        } => {
            if inputs.len() > 16 * 1024 {
                return Err("action inputs exceed 16384 bytes".into());
            }
            let inputs = serde_json::from_str(&inputs)?;
            run_client(&socket, Command::ActionPlan { action_id, inputs }).await
        }
    }
}

fn run_rollback_helper_command(
    config_path: &Path,
    transaction_id: &str,
) -> Result<(), Box<dyn Error>> {
    let config = agent_core::AgentConfig::load(config_path)?;
    let runtime_root = config
        .storage
        .path
        .parent()
        .ok_or("storage path has no runtime root")?;
    let rollback_root = runtime_root.join("rollback");
    let canonical = agent_core::runtime_rollback_canonical_state(
        &rollback_root,
        transaction_id,
        config.storage.max_rollback_bytes,
    )?;
    let helper_result = agent_core::run_rollback_helper(
        &rollback_root,
        transaction_id,
        config.storage.max_rollback_bytes,
    );
    let outcome = agent_core::rollback_outcome(&rollback_root, transaction_id);
    match outcome {
        Ok(agent_core::RollbackOutcome::RolledBack) => {
            if let Err(error) = restore_runtime_canonical(&config, canonical) {
                let _ = record_helper_rollback_state(
                    &config,
                    transaction_id,
                    ChangeSetState::RollbackFailed,
                );
                return Err(error);
            }
            record_helper_rollback_state(&config, transaction_id, ChangeSetState::RolledBack)?;
        }
        Ok(
            agent_core::RollbackOutcome::RestoreFailed | agent_core::RollbackOutcome::ReloadFailed,
        ) => {
            record_helper_rollback_state(&config, transaction_id, ChangeSetState::RollbackFailed)?;
        }
        Ok(agent_core::RollbackOutcome::Pending) | Err(_) => {}
    }
    helper_result?;
    Ok(())
}

fn record_helper_rollback_state(
    config: &agent_core::AgentConfig,
    transaction_id: &str,
    terminal: ChangeSetState,
) -> Result<(), Box<dyn Error>> {
    if !matches!(
        terminal,
        ChangeSetState::RolledBack | ChangeSetState::RollbackFailed
    ) {
        return Err("rollback helper terminal state is invalid".into());
    }
    let store = agent_store::Store::open(&config.storage.path, config.storage.max_database_bytes)?;
    let mut record = store
        .change_set(transaction_id)?
        .ok_or("rollback helper ChangeSet is unavailable")?;
    let now = record
        .rollback_deadline_monotonic_ms
        .unwrap_or(record.expires_monotonic_ms)
        .saturating_add(1);
    if matches!(
        record.state,
        ChangeSetState::RollbackArmed
            | ChangeSetState::Applying
            | ChangeSetState::Verifying
            | ChangeSetState::AwaitingConfirmation
    ) {
        store.transition_change_set(
            &record.id,
            record.state,
            ChangeSetState::RollingBack,
            &record.plan_digest,
            &record.boot_id,
            now,
        )?;
        record.state = ChangeSetState::RollingBack;
    }
    if record.state == ChangeSetState::RollingBack {
        store.transition_change_set(
            &record.id,
            ChangeSetState::RollingBack,
            terminal,
            &record.plan_digest,
            &record.boot_id,
            now,
        )?;
        return Ok(());
    }
    if record.state == terminal {
        return Ok(());
    }
    Err("rollback helper ChangeSet state is not reconcilable".into())
}

fn restore_runtime_canonical(
    config: &agent_core::AgentConfig,
    canonical: agent_core::RuntimeCanonicalSnapshot,
) -> Result<(), Box<dyn Error>> {
    let store = agent_store::Store::open(&config.storage.path, config.storage.max_database_bytes)?;
    match canonical {
        agent_core::RuntimeCanonicalSnapshot::Present(payload) => {
            store.replace_firewall_runtime_state(
                &payload,
                usize::try_from(config.storage.max_firewall_state_bytes)?,
            )?;
        }
        agent_core::RuntimeCanonicalSnapshot::Absent => store.clear_firewall_runtime_state()?,
        agent_core::RuntimeCanonicalSnapshot::NetworkPresent(payload) => {
            store.replace_network_runtime_state(
                &payload,
                usize::try_from(config.storage.max_network_state_bytes)?,
            )?;
        }
        agent_core::RuntimeCanonicalSnapshot::NetworkAbsent => {
            store.clear_network_runtime_state()?;
        }
        agent_core::RuntimeCanonicalSnapshot::NotRuntime => {}
    }
    Ok(())
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
        ChangeTarget::NetworkInventory { socket } => {
            run_client(&socket, Command::NetworkInventory).await
        }
        ChangeTarget::NetworkPlan { socket } => {
            let input = read_bounded_stdin(60 * 1024, "network plan")?;
            let mutations: Vec<NetworkMutationRequest> = serde_json::from_slice(&input)?;
            run_client(&socket, Command::NetworkPlan { mutations }).await
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

const WECHAT_CLAWBOT_LOGIN_BASE_URL: &str = "https://ilinkai.weixin.qq.com";
const WECHAT_CLAWBOT_MAX_HTTP_BYTES: usize = 32 * 1024;
const WECHAT_CLAWBOT_MAX_POLLS: usize = 180;

#[derive(Deserialize)]
struct WeChatQrCodeResponse {
    #[serde(default)]
    ret: Option<i32>,
    #[serde(default)]
    qrcode: Option<String>,
    #[serde(default)]
    qrcode_img_content: Option<String>,
    #[serde(default)]
    errmsg: Option<String>,
}

#[derive(Deserialize)]
struct WeChatQrCodeStatusResponse {
    #[serde(default)]
    ret: Option<i32>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    bot_token: Option<String>,
    #[serde(default, alias = "base_url")]
    baseurl: Option<String>,
    #[serde(default)]
    errmsg: Option<String>,
}

#[allow(clippy::too_many_lines)] // The QR state machine keeps the bounded flow visible.
async fn run_wechat_clawbot_bind(account: &str, config_path: &Path) -> Result<(), Box<dyn Error>> {
    if !valid_cli_identifier(account) {
        return Err(
            "WeChat ClawBot account must contain only letters, digits, '-', '_' or '.'".into(),
        );
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("MbedAgent/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let qr_endpoint =
        format!("{WECHAT_CLAWBOT_LOGIN_BASE_URL}/ilink/bot/get_bot_qrcode?bot_type=3");
    let qr: WeChatQrCodeResponse = get_json_bounded(&client, &qr_endpoint).await?;
    if qr.ret.is_some_and(|ret| ret != 0) {
        return Err(format!(
            "WeChat ClawBot QR request failed: {}",
            qr.errmsg
                .as_deref()
                .unwrap_or("official API returned an error")
        )
        .into());
    }
    let qr_code = qr
        .qrcode
        .filter(|value| !value.is_empty())
        .ok_or("official WeChat ClawBot QR response did not contain qrcode")?;
    let qr_display = qr
        .qrcode_img_content
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&qr_code);
    println!("请使用微信扫描官方二维码（二维码地址如下）：\n{qr_display}");

    let status_endpoint = format!("{WECHAT_CLAWBOT_LOGIN_BASE_URL}/ilink/bot/get_qrcode_status");
    let mut last_status = String::new();
    for _ in 0..WECHAT_CLAWBOT_MAX_POLLS {
        let status_url = format!(
            "{status_endpoint}?qrcode={}",
            percent_encode_query(qr_code.as_bytes())
        );
        let response: WeChatQrCodeStatusResponse = get_json_bounded(&client, &status_url).await?;
        if response.ret.is_some_and(|ret| ret != 0) {
            return Err(format!(
                "WeChat ClawBot QR polling failed: {}",
                response
                    .errmsg
                    .as_deref()
                    .unwrap_or("official API returned an error")
            )
            .into());
        }
        let status = response.status.as_deref().unwrap_or("wait");
        if status != last_status {
            println!("二维码状态：{status}");
            status.clone_into(&mut last_status);
        }
        match status.to_ascii_lowercase().as_str() {
            "confirmed" => {
                let token = response
                    .bot_token
                    .filter(|value| !value.is_empty())
                    .ok_or("WeChat ClawBot confirmation did not return bot_token")?;
                let base_url = response
                    .baseurl
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| WECHAT_CLAWBOT_LOGIN_BASE_URL.into());
                parse_wechat_clawbot_base_url(&base_url)?;
                if token.len() > 8192 || token.chars().any(char::is_control) {
                    return Err("WeChat ClawBot returned an invalid bot_token".into());
                }
                let mut config = AgentConfig::load_or_default(config_path)?;
                config.channels.wechat_clawbot = WeChatClawBotConfig {
                    enabled: true,
                    account: account.into(),
                    base_url,
                    bot_token: SecretString::new(token),
                    bot_agent: concat!("MbedAgent/", env!("CARGO_PKG_VERSION")).into(),
                    long_poll_timeout_secs: 35,
                    request_timeout_secs: 10,
                };
                config.validate()?;
                write_config_atomically(config_path, &config)?;
                println!(
                    "微信 ClawBot 已绑定，账号 {account} 的凭据已安全写入 {}；重启 daemon 后会自动连接。",
                    config_path.display()
                );
                return Ok(());
            }
            "expired" | "cancelled" | "canceled" => {
                return Err(format!("WeChat ClawBot QR code {status}").into());
            }
            "scanned" | "scaned" | "wait" | "" => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    Err("timed out waiting for WeChat ClawBot QR confirmation".into())
}

fn run_wecom_bind(
    bot_id: &str,
    account: &str,
    ws_url: &str,
    config_path: &Path,
) -> Result<(), Box<dyn Error>> {
    if !valid_cli_identifier(account) {
        return Err("WeCom account must contain only letters, digits, '-', '_' or '.'".into());
    }
    if bot_id.is_empty() || bot_id.len() > 256 || bot_id.chars().any(char::is_control) {
        return Err("WeCom bot_id is empty or exceeds its 256-byte bound".into());
    }
    parse_wecom_ws_url(ws_url)?;
    let secret = read_secret_stdin("WeCom bot secret", 8 * 1024)?;
    let mut config = AgentConfig::load_or_default(config_path)?;
    config.channels.wecom = WeComBotConfig {
        enabled: true,
        account: account.into(),
        bot_id: bot_id.into(),
        secret: SecretString::new(secret),
        ws_url: ws_url.into(),
        ..WeComBotConfig::default()
    };
    config.validate()?;
    write_config_atomically(config_path, &config)?;
    println!(
        "企业微信智能机器人已绑定，账号 {account} 的配置已写入 {}；重启 daemon 后会自动建立 WSS 连接。",
        config_path.display()
    );
    Ok(())
}

async fn get_json_bounded<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, Box<dyn Error>> {
    let response = client.get(url).send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > WECHAT_CLAWBOT_MAX_HTTP_BYTES as u64)
    {
        return Err("WeChat ClawBot response exceeds the 32 KiB bound".into());
    }
    let bytes = response.bytes().await?;
    if bytes.len() > WECHAT_CLAWBOT_MAX_HTTP_BYTES {
        return Err("WeChat ClawBot response exceeds the 32 KiB bound".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_config_atomically(path: &Path, config: &AgentConfig) -> Result<(), Box<dyn Error>> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!(
                "configuration path {} must be a regular file",
                path.display()
            )
            .into());
        }
    }
    let parent = path.parent().ok_or("configuration path has no parent")?;
    fs::create_dir_all(parent)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml"),
        std::process::id(),
        stamp
    ));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        let text = toml::to_string_pretty(config)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn valid_cli_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn percent_encode_query(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
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

fn read_secret_stdin(label: &str, limit: usize) -> Result<String, Box<dyn Error>> {
    let mut secret = Zeroizing::new(Vec::with_capacity(128));
    io::stdin()
        .lock()
        .take(u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut secret)?;
    if secret.len() > limit {
        return Err(format!("{label} exceeds {limit} bytes").into());
    }
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.is_empty() {
        return Err(format!("{label} must not be empty").into());
    }
    let bytes = std::mem::take(&mut *secret);
    String::from_utf8(bytes).map_err(|_| format!("{label} must be valid UTF-8").into())
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
    use agent_protocol::{ChangeApprovalResponse, ResponseData, RiskLevel};
    use agent_store::ChangeSetRecord;

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

    #[test]
    fn qr_query_values_are_percent_encoded_without_shell_interpolation() {
        assert_eq!(percent_encode_query(b"qr id/+~"), "qr%20id%2F%2B~");
    }

    #[test]
    fn official_qr_status_response_accepts_forward_compatible_fields() {
        let response: WeChatQrCodeStatusResponse = serde_json::from_str(
            r#"{"status":"confirmed","bot_token":"secret","baseurl":"https://ilinkai.weixin.qq.com","future":true}"#,
        )
        .expect("official response shape");
        assert_eq!(response.status.as_deref(), Some("confirmed"));
        assert_eq!(response.bot_token.as_deref(), Some("secret"));
    }

    #[test]
    fn rollback_helper_records_terminal_changeset_state() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-helper-state-{nonce}"));
        fs::create_dir(&root).expect("runtime root");
        let mut config = AgentConfig::default();
        config.storage.path = root.join("agent.db");
        let store =
            agent_store::Store::open(&config.storage.path, config.storage.max_database_bytes)
                .expect("store");
        let record = ChangeSetRecord {
            id: "helper-state".into(),
            plan_digest: "a".repeat(64),
            plan_payload: br#"{"schema_version":1}"#.to_vec(),
            state: ChangeSetState::Planned,
            actor_id: "cli/local".into(),
            boot_id: "boot-1".into(),
            risk: RiskLevel::R3,
            expires_monotonic_ms: 1_000,
            rollback_deadline_monotonic_ms: None,
            created_at: 0,
            updated_at: 0,
        };
        store
            .insert_change_set(&record, 4, 4_096, 1)
            .expect("insert ChangeSet");
        let mut state = ChangeSetState::Planned;
        for next in [
            ChangeSetState::AwaitingApproval,
            ChangeSetState::Approved,
            ChangeSetState::Staged,
            ChangeSetState::Validated,
        ] {
            store
                .transition_change_set(
                    &record.id,
                    state,
                    next,
                    &record.plan_digest,
                    &record.boot_id,
                    2,
                )
                .expect("advance ChangeSet");
            state = next;
        }
        store
            .arm_change_set_rollback(&record.id, &record.plan_digest, &record.boot_id, 2, 100)
            .expect("arm rollback");
        state = ChangeSetState::RollbackArmed;
        for next in [
            ChangeSetState::Applying,
            ChangeSetState::Verifying,
            ChangeSetState::AwaitingConfirmation,
        ] {
            store
                .transition_change_set(
                    &record.id,
                    state,
                    next,
                    &record.plan_digest,
                    &record.boot_id,
                    3,
                )
                .expect("advance armed ChangeSet");
            state = next;
        }
        drop(store);

        record_helper_rollback_state(&config, &record.id, ChangeSetState::RolledBack)
            .expect("record helper outcome");
        let store =
            agent_store::Store::open(&config.storage.path, config.storage.max_database_bytes)
                .expect("reopen store");
        assert_eq!(
            store
                .change_set(&record.id)
                .expect("read ChangeSet")
                .expect("ChangeSet")
                .state,
            ChangeSetState::RolledBack
        );
        drop(store);
        fs::remove_dir_all(root).expect("cleanup runtime root");
    }
}
