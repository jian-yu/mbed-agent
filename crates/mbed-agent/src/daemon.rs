use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_channels::{ChannelCommand, ChannelResponse, DiagnosticTarget, command_from_text};
use agent_core::{
    ActionChangeDomain, ActionMode, ActionRegistry, AdminPasswordVerifier, AgentConfig, AuthError,
    AuthManager, FirewallExecutionPlan, FirewallMutation, FirewallRiskContext,
    NetworkExecutionPlan, NetworkInventory, NetworkMutation, NetworkRiskContext, TmpBudget,
    confirm_awaiting_execution, execute_approved_change, firewall_object_digest,
    network_object_digest, plan_digest, plan_firewall_mutations, plan_network_mutations,
};
use agent_protocol::{
    ActionDescriptor, ActionReloadResponse, ChangeApprovalResponse, ChangePlan, ChangeSetResponse,
    ChangeSetState, ChannelStatusEntry, ClientRequest, Command, CompletionResponse, ConfigDomain,
    DiagnosticHistoryEntry, ErrorCode, FirewallInventoryEntry, FirewallInventoryResponse,
    FirewallMutationRequest, FirewallObject, NetworkInventoryEntry, NetworkInventoryResponse,
    NetworkMutationRequest, NetworkObject, ObjectOwnership, PROTOCOL_VERSION, ResponseData,
    SensitiveString, ServerResponse, StatusResponse, StoragePressure, StorageStatus,
    TaskHistoryEntry,
};
use agent_provider::{
    CompletionRequest, ModelMessage, OpenAiCompatibleConfig, OpenAiCompatibleProvider, ToolCall,
    ToolDefinition,
};
use agent_store::{
    ApprovalRecord, ChangeSetRecord, DiagnosticRecord, Store, StoreError, TaskRecord,
};
use agent_tools::ToolRunner;
use platform_linux::firewall_command::{
    FirewallCommand, FirewallCommandExecutor, FirewallCommandRunner,
};
use platform_linux::firewall_inventory::inspect_openwrt_firewall_inventory;
use platform_linux::firewall_runtime::{
    GenericFirewallInventorySnapshot, inspect_generic_iptables_inventory,
    inspect_generic_nftables_inventory,
};
use platform_linux::network_openwrt::{
    OpenWrtNetworkInventorySnapshot, inspect_openwrt_network_inventory_with_dhcp,
};
use platform_linux::network_runtime::{
    inspect_runtime_network_inventory, inspect_runtime_policy_inventory,
    reconcile_runtime_network_inventory,
};
use platform_linux::{FirewallBackend, PlatformCapabilities, PlatformKind};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use crate::action_execution::{ActionExecutionError, execute_action};
use crate::firewall_execution::{
    GenericIptablesExecutionPort, GenericIptablesExecutionPortConfig, GenericNftablesExecutionPort,
    GenericNftablesExecutionPortConfig, OpenWrtExecutionPort, OpenWrtExecutionPortConfig,
};
use crate::logging;
use crate::mqtt_channel::{self, MqttInbound};
use crate::network_execution::{
    GenericRuntimeRouteExecutionPort, GenericRuntimeRouteExecutionPortConfig,
    OpenWrtNetworkExecutionPort, OpenWrtNetworkExecutionPortConfig,
};
use crate::wechat_clawbot::{self, WeChatInbound};
use crate::wecom_channel::{self, WeComInbound};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const LOCAL_CLI_ACTOR: &str = "cli/local";

struct AppState {
    config: AgentConfig,
    config_path: std::path::PathBuf,
    platform: PlatformCapabilities,
    budget: TmpBudget,
    store: Arc<Store>,
    tools: ToolRunner,
    diagnostic_slots: Semaphore,
    llm: Option<OpenAiCompatibleProvider>,
    llm_slots: Semaphore,
    log_writer: logging::BoundedMakeWriter,
    started: Instant,
    auth: Arc<AuthManager>,
    configuration_lock: Mutex<()>,
    actions: RwLock<ActionRegistry>,
    action_slots: Semaphore,
    mqtt_status: Option<tokio::sync::watch::Receiver<agent_channels::ChannelLifecycle>>,
    wechat_status: Option<tokio::sync::watch::Receiver<agent_channels::ChannelLifecycle>>,
    wecom_status: Option<tokio::sync::watch::Receiver<agent_channels::ChannelLifecycle>>,
}

#[allow(clippy::too_many_lines)] // Startup keeps all bounded runtime resources visibly assembled.
pub async fn run(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = AgentConfig::load_or_default(config_path)?;
    ensure_secret_config_permissions(config_path, &config)?;
    let boot_id = discover_boot_id()?;
    let auth = Arc::new(if config.auth.enabled {
        AuthManager::new(
            AdminPasswordVerifier::parse(config.auth.admin_password_hash.expose())?,
            boot_id,
            config.auth.capability_ttl_secs,
            config.auth.max_failures,
            config.auth.lockout_secs,
        )
    } else {
        AuthManager::disabled(boot_id)
    });
    let log_writer = init_logging(&config)?;

    let budget = TmpBudget::new(config.storage.clone())?;
    fs::create_dir_all(budget.root().join("artifacts"))?;
    fs::create_dir_all(budget.root().join("rollback"))?;
    fs::create_dir_all(budget.root().join("log"))?;
    match budget.cleanup_artifacts() {
        Ok(report) if report.removed_files > 0 => info!(
            removed_files = report.removed_files,
            bytes_before = report.bytes_before,
            bytes_after = report.bytes_after,
            "pruned managed runtime artifacts during startup"
        ),
        Ok(_) => {}
        Err(error) => warn!(%error, "startup artifact cleanup failed"),
    }

    let store = Arc::new(Store::open(
        &config.storage.path,
        config.storage.max_database_bytes,
    )?);
    store.health_check()?;
    let platform = PlatformCapabilities::discover();
    for warning in &platform.warnings {
        warn!(warning = %warning, "platform capability warning");
    }
    let actions = ActionRegistry::load(&config.extensions)?;
    info!(
        loaded_actions = actions.len(),
        "loaded declarative action registry"
    );

    let tools = ToolRunner::system(
        Duration::from_secs(config.runtime.tool_timeout_secs),
        config.runtime.max_tool_output_bytes,
    );
    let diagnostic_slots = Semaphore::new(config.runtime.max_active_tasks);
    let action_slots = Semaphore::new(config.runtime.max_active_tasks);
    let llm = build_llm_provider(&config)?;
    let llm_slots = Semaphore::new(config.runtime.max_active_tasks);
    let listener = bind_socket(&config.server.socket_path, config.server.socket_mode)?;
    let mqtt_runtime = mqtt_channel::start(
        config.channels.mqtt.clone(),
        Arc::clone(&store),
        config.storage.max_channel_message_records,
        usize::try_from(config.storage.max_channel_payload_bytes)?,
    )?;
    let mqtt_status = mqtt_runtime.as_ref().map(|runtime| runtime.status.clone());
    let wechat_runtime = wechat_clawbot::start(
        config.channels.wechat_clawbot.clone(),
        Arc::clone(&store),
        config.storage.max_channel_message_records,
    )?;
    let wechat_status = wechat_runtime
        .as_ref()
        .map(|runtime| runtime.status.clone());
    let wecom_runtime = wecom_channel::start(
        config.channels.wecom.clone(),
        Arc::clone(&store),
        config.storage.max_channel_message_records,
    )?;
    let wecom_status = wecom_runtime.as_ref().map(|runtime| runtime.status.clone());
    let state = Arc::new(AppState {
        config,
        config_path: config_path.to_path_buf(),
        platform,
        budget,
        store,
        tools,
        diagnostic_slots,
        llm,
        llm_slots,
        log_writer,
        started: Instant::now(),
        auth,
        configuration_lock: Mutex::new(()),
        actions: RwLock::new(actions),
        action_slots,
        mqtt_status,
        wechat_status,
        wecom_status,
    });
    if let Some(mut runtime) = mqtt_runtime {
        let channel_state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(message) = runtime.inbound.recv().await {
                let state = Arc::clone(&channel_state);
                tokio::spawn(handle_mqtt_inbound(message, state));
            }
            warn!("MQTT inbound dispatcher stopped");
        });
    }
    if let Some(mut runtime) = wechat_runtime {
        let channel_state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(message) = runtime.inbound.recv().await {
                let state = Arc::clone(&channel_state);
                tokio::spawn(handle_wechat_inbound(message, state));
            }
            warn!("WeChat ClawBot inbound dispatcher stopped");
        });
    }
    if let Some(mut runtime) = wecom_runtime {
        let channel_state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(message) = runtime.inbound.recv().await {
                let state = Arc::clone(&channel_state);
                tokio::spawn(handle_wecom_inbound(message, state));
            }
            warn!("WeCom inbound dispatcher stopped");
        });
    }
    let mut cleanup_interval =
        tokio::time::interval(Duration::from_secs(state.budget.cleanup_interval_secs()));
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;
    info!(
        socket = %state.config.server.socket_path.display(),
        platform = state.platform.kind.as_str(),
        "mbed-agent daemon ready"
    );

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _address)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(error) = serve_connection(stream, state).await {
                                warn!(%error, "client connection ended with an error");
                            }
                        });
                    }
                    Err(error) => error!(%error, "failed to accept local client"),
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                info!("shutdown requested");
                break;
            }
            _ = cleanup_interval.tick() => {
                run_artifact_cleanup(&state).await;
            }
        }
    }

    let _ = fs::remove_file(&state.config.server.socket_path);
    Ok(())
}

fn ensure_secret_config_permissions(path: &Path, config: &AgentConfig) -> io::Result<()> {
    let mqtt_credentials =
        !config.channels.mqtt.username.is_empty() || !config.channels.mqtt.password.is_empty();
    let wechat_credentials = !config.channels.wechat_clawbot.bot_token.is_empty();
    let wecom_credentials =
        !config.channels.wecom.bot_id.is_empty() || !config.channels.wecom.secret.is_empty();
    if (!config.llm.enabled
        && !config.auth.enabled
        && !mqtt_credentials
        && !wechat_credentials
        && !wecom_credentials)
        || !path.exists()
    {
        return Ok(());
    }
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "configured credentials require {} to have mode 0600 or stricter",
                path.display()
            ),
        ));
    }
    Ok(())
}

async fn handle_mqtt_inbound(inbound: MqttInbound, state: Arc<AppState>) {
    let message_id = inbound.request.message_id.clone();
    let actor_id = inbound.request.actor_id.clone();
    let response = dispatch_channel_request("mqtt", inbound.request, &state).await;
    if inbound.respond_to.send(response).is_err() {
        warn!(%message_id, "MQTT response receiver disappeared");
    } else {
        info!(%message_id, %actor_id, "MQTT read-only request completed");
    }
}

async fn handle_wechat_inbound(inbound: WeChatInbound, state: Arc<AppState>) {
    let message_id = inbound.request.message_id.clone();
    let actor_id = inbound.request.actor_id.clone();
    let response = dispatch_channel_request("wechat_clawbot", inbound.request, &state).await;
    if inbound.respond_to.send(response).is_err() {
        warn!(%message_id, %actor_id, "WeChat ClawBot response receiver disappeared");
    } else {
        info!(%message_id, %actor_id, "WeChat ClawBot request completed");
    }
}

async fn handle_wecom_inbound(inbound: WeComInbound, state: Arc<AppState>) {
    let message_id = inbound.request.message_id.clone();
    let actor_id = inbound.request.actor_id.clone();
    let response = dispatch_channel_request("wecom", inbound.request, &state).await;
    if inbound.respond_to.send(response).is_err() {
        warn!(%message_id, %actor_id, "WeCom response receiver disappeared");
    } else {
        info!(%message_id, %actor_id, "WeCom request completed");
    }
}

#[allow(clippy::too_many_lines)]
async fn dispatch_channel_request(
    channel: &str,
    request: agent_channels::ChannelRequest,
    state: &AppState,
) -> ChannelResponse {
    let message_id = request.message_id;
    let actor_id = request.actor_id.clone();
    let internal_id = format!("{channel}:{message_id}");
    let response = match request.command {
        ChannelCommand::Ping => ServerResponse::success(
            internal_id,
            ResponseData::Pong {
                daemon_version: AGENT_VERSION.into(),
            },
        ),
        ChannelCommand::Status => ServerResponse::success(internal_id, status_response(state)),
        ChannelCommand::Elevate { password } => {
            handle_elevation(internal_id, password.into_inner(), actor_id, state).await
        }
        ChannelCommand::Deauth => handle_deauth(internal_id, actor_id, state).await,
        ChannelCommand::Ask { text } => match command_from_text(text) {
            ChannelCommand::Elevate { password } => {
                handle_elevation(internal_id, password.into_inner(), actor_id, state).await
            }
            ChannelCommand::Deauth => handle_deauth(internal_id, actor_id, state).await,
            ChannelCommand::Ask { text } => handle_completion(internal_id, text, state).await,
            _ => ServerResponse::error(
                internal_id,
                ErrorCode::InvalidRequest,
                "channel command is not supported in this context",
            ),
        },
        ChannelCommand::FirewallInventory => handle_firewall_inventory(internal_id, state).await,
        ChannelCommand::NetworkInventory => handle_network_inventory(internal_id, state).await,
        ChannelCommand::FirewallPlan { mutations_json } => {
            match serde_json::from_str::<Vec<FirewallMutationRequest>>(&mutations_json) {
                Ok(requests) => handle_firewall_plan(internal_id, requests, actor_id, state).await,
                Err(error) => ServerResponse::error(
                    internal_id,
                    ErrorCode::InvalidRequest,
                    format!("firewall mutation JSON is invalid: {error}"),
                ),
            }
        }
        ChannelCommand::NetworkPlan { mutations_json } => {
            match serde_json::from_str::<Vec<NetworkMutationRequest>>(&mutations_json) {
                Ok(requests) => handle_network_plan(internal_id, requests, actor_id, state).await,
                Err(error) => ServerResponse::error(
                    internal_id,
                    ErrorCode::InvalidRequest,
                    format!("network mutation JSON is invalid: {error}"),
                ),
            }
        }
        ChannelCommand::ChangeGet { change_set_id } => {
            handle_change_get(internal_id, change_set_id, actor_id, state).await
        }
        ChannelCommand::ChangeApprove { change_set_id } => {
            handle_change_approve(internal_id, change_set_id, actor_id, state).await
        }
        ChannelCommand::ChangeApply {
            change_set_id,
            approval_id,
            approval_token,
        } => {
            handle_change_apply(
                internal_id,
                change_set_id,
                approval_id,
                agent_protocol::SensitiveString::new(approval_token.into_inner()),
                actor_id,
                state,
            )
            .await
        }
        ChannelCommand::ChangeConfirm { change_set_id } => {
            handle_change_confirm(internal_id, change_set_id, actor_id, state).await
        }
        ChannelCommand::ChangeReject { change_set_id } => {
            handle_change_reject(internal_id, change_set_id, actor_id, state).await
        }
        ChannelCommand::ActionList => handle_action_list(internal_id, state).await,
        ChannelCommand::ActionReload => handle_action_reload(internal_id, actor_id, state).await,
        ChannelCommand::ActionRun {
            action_id,
            inputs_json,
        } => match serde_json::from_str::<serde_json::Value>(&inputs_json) {
            Ok(inputs) => handle_action_run(internal_id, action_id, inputs, state).await,
            Err(error) => ServerResponse::error(
                internal_id,
                ErrorCode::InvalidRequest,
                format!("action input JSON is invalid: {error}"),
            ),
        },
        ChannelCommand::ActionPlan {
            action_id,
            inputs_json,
        } => match serde_json::from_str::<serde_json::Value>(&inputs_json) {
            Ok(inputs) => handle_action_plan(internal_id, action_id, inputs, actor_id, state).await,
            Err(error) => ServerResponse::error(
                internal_id,
                ErrorCode::InvalidRequest,
                format!("action input JSON is invalid: {error}"),
            ),
        },
        ChannelCommand::Diagnose { target } => match target {
            DiagnosticTarget::Wan => handle_wan_diagnosis(internal_id, false, state).await,
            DiagnosticTarget::Dns => handle_dns_diagnosis(internal_id, state).await,
            DiagnosticTarget::Dhcp => handle_dhcp_diagnosis(internal_id, state).await,
            DiagnosticTarget::Routes => handle_route_diagnosis(internal_id, state).await,
            DiagnosticTarget::Interfaces => handle_interface_diagnosis(internal_id, state).await,
            DiagnosticTarget::Neighbors => handle_neighbor_diagnosis(internal_id, state).await,
            DiagnosticTarget::Firewall => handle_firewall_diagnosis(internal_id, state).await,
            DiagnosticTarget::PolicyRouting => {
                handle_policy_routing_diagnosis(internal_id, state).await
            }
            DiagnosticTarget::Listeners => handle_listener_diagnosis(internal_id, state).await,
            DiagnosticTarget::Wireless => handle_wireless_diagnosis(internal_id, state).await,
            DiagnosticTarget::InterfaceStats => {
                handle_interface_stats_diagnosis(internal_id, state).await
            }
            DiagnosticTarget::Conntrack => handle_conntrack_diagnosis(internal_id, state).await,
            DiagnosticTarget::Qdisc => handle_qdisc_diagnosis(internal_id, state).await,
        },
    };
    if response.ok {
        match response
            .result
            .and_then(|result| serde_json::to_value(result).ok())
        {
            Some(result) => ChannelResponse::success(message_id, result),
            None => ChannelResponse::error(
                message_id,
                "internal",
                "the device could not encode the response",
            ),
        }
    } else if let Some(error) = response.error {
        ChannelResponse::error(message_id, error.code.as_str(), &error.message)
    } else {
        ChannelResponse::error(message_id, "internal", "the device request failed")
    }
}

fn discover_boot_id() -> io::Result<String> {
    if let Ok(value) = fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        let value = value.trim();
        if !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Ok(value.to_ascii_lowercase());
        }
    }
    let mut random = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("operating system randomness is unavailable"))?;
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

fn build_llm_provider(
    config: &AgentConfig,
) -> Result<Option<OpenAiCompatibleProvider>, Box<dyn Error>> {
    if !config.llm.enabled {
        return Ok(None);
    }
    let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
        base_url: config.llm.base_url.clone(),
        api_key: config.llm.api_key.expose().to_owned(),
        model: config.llm.model.clone(),
        connect_timeout: Duration::from_secs(config.llm.connect_timeout_secs),
        request_timeout: Duration::from_secs(config.llm.request_timeout_secs),
        max_request_bytes: config.llm.max_request_bytes,
        max_response_bytes: config.llm.max_response_bytes,
        max_stream_event_bytes: config.llm.max_stream_event_bytes,
    })?;
    Ok(Some(provider))
}

async fn ensure_task_storage(state: &AppState) -> Result<(), String> {
    let mut pressure = inspect_storage_pressure(state).await?;
    if matches!(
        pressure,
        StoragePressure::Critical | StoragePressure::Emergency
    ) {
        run_artifact_cleanup(state).await;
        pressure = inspect_storage_pressure(state).await?;
    }
    match pressure {
        StoragePressure::Normal | StoragePressure::Pressure => Ok(()),
        StoragePressure::Critical | StoragePressure::Emergency => Err(format!(
            "runtime storage pressure is {pressure:?}; refusing to start a new task"
        )),
    }
}

async fn inspect_storage_pressure(state: &AppState) -> Result<StoragePressure, String> {
    let budget = state.budget.clone();
    tokio::task::spawn_blocking(move || {
        let managed = budget.managed_bytes()?;
        budget.pressure(managed)
    })
    .await
    .map_err(|error| format!("storage pressure worker failed: {error}"))?
    .map_err(|error| format!("runtime storage pressure cannot be inspected: {error}"))
}

async fn run_artifact_cleanup(state: &AppState) {
    let budget = state.budget.clone();
    match tokio::task::spawn_blocking(move || budget.cleanup_artifacts()).await {
        Ok(Ok(report)) if report.removed_files > 0 => info!(
            removed_files = report.removed_files,
            bytes_before = report.bytes_before,
            bytes_after = report.bytes_after,
            "pruned managed runtime artifacts"
        ),
        Ok(Ok(_)) => {}
        Ok(Err(error)) => warn!(%error, "managed artifact cleanup failed"),
        Err(error) => warn!(%error, "managed artifact cleanup worker failed"),
    }
}

fn init_logging(config: &AgentConfig) -> io::Result<logging::BoundedMakeWriter> {
    let mut filter = config.logging.level.clone();
    if !config.logging.directives.is_empty() {
        filter.push(',');
        filter.push_str(&config.logging.directives.join(","));
    }
    let writer = logging::BoundedMakeWriter::new(&config.logging)?;
    let filter = EnvFilter::try_new(filter).map_err(io::Error::other)?;
    match config.logging.format {
        agent_core::config::LogFormat::Compact => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(writer.clone())
            .compact()
            .init(),
        agent_core::config::LogFormat::JsonLines => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(writer.clone())
            .json()
            .init(),
    }
    Ok(writer)
}

fn bind_socket(path: &Path, mode: u32) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("refusing to replace non-socket path {}", path.display()),
            ));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

async fn serve_connection(stream: UnixStream, state: Arc<AppState>) -> io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    while let Some(frame) = read_frame(&mut reader, state.config.runtime.max_request_bytes).await? {
        let frame = Zeroizing::new(frame);
        let response = match serde_json::from_slice::<ClientRequest>(&frame) {
            Ok(request) => handle_request(request, &state).await,
            Err(error) => ServerResponse::error(
                "unknown",
                ErrorCode::InvalidRequest,
                format!("invalid JSON request: {error}"),
            ),
        };
        let mut encoded = Zeroizing::new(serde_json::to_vec(&response).map_err(io::Error::other)?);
        encoded.push(b'\n');
        write_half.write_all(&encoded).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Closed protocol dispatch remains auditable in one match.
async fn handle_request(request: ClientRequest, state: &AppState) -> ServerResponse {
    if request.protocol_version != PROTOCOL_VERSION {
        return ServerResponse::error(
            request.id,
            ErrorCode::UnsupportedProtocol,
            format!(
                "protocol version {} is unsupported; expected {PROTOCOL_VERSION}",
                request.protocol_version
            ),
        );
    }
    if !valid_request_id(&request.id) {
        return ServerResponse::error(
            request.id,
            ErrorCode::InvalidRequest,
            "request id must contain 1-128 bytes without control characters",
        );
    }

    let result = match request.command {
        Command::Ping => ResponseData::Pong {
            daemon_version: AGENT_VERSION.into(),
        },
        Command::Capabilities => match serde_json::to_value(&state.platform) {
            Ok(value) => ResponseData::Capabilities(value),
            Err(error) => {
                return ServerResponse::error(
                    request.id,
                    ErrorCode::Internal,
                    format!("failed to encode capabilities: {error}"),
                );
            }
        },
        Command::ActionList => {
            return handle_action_list(request.id, state).await;
        }
        Command::ChannelStatus => {
            return handle_channel_status(request.id, state);
        }
        Command::ActionReload => {
            return handle_action_reload(request.id, LOCAL_CLI_ACTOR.into(), state).await;
        }
        Command::ActionRun { action_id, inputs } => {
            return handle_action_run(request.id, action_id, inputs, state).await;
        }
        Command::ActionPlan { action_id, inputs } => {
            return handle_action_plan(
                request.id,
                action_id,
                inputs,
                LOCAL_CLI_ACTOR.into(),
                state,
            )
            .await;
        }
        Command::Status => status_response(state),
        Command::Elevate { password } => {
            return handle_elevation(
                request.id,
                password.into_inner(),
                LOCAL_CLI_ACTOR.into(),
                state,
            )
            .await;
        }
        Command::Deauth => {
            return handle_deauth(request.id, LOCAL_CLI_ACTOR.into(), state).await;
        }
        Command::ChangeGet { change_set_id } => {
            return handle_change_get(request.id, change_set_id, LOCAL_CLI_ACTOR.into(), state)
                .await;
        }
        Command::ChangeApprove { change_set_id } => {
            return handle_change_approve(request.id, change_set_id, LOCAL_CLI_ACTOR.into(), state)
                .await;
        }
        Command::FirewallPlan { mutations } => {
            return handle_firewall_plan(request.id, mutations, LOCAL_CLI_ACTOR.into(), state)
                .await;
        }
        Command::FirewallInventory => {
            return handle_firewall_inventory(request.id, state).await;
        }
        Command::NetworkPlan { mutations } => {
            return handle_network_plan(request.id, mutations, LOCAL_CLI_ACTOR.into(), state).await;
        }
        Command::NetworkInventory => {
            return handle_network_inventory(request.id, state).await;
        }
        Command::ChangeApply {
            change_set_id,
            approval_id,
            approval_token,
        } => {
            return handle_change_apply(
                request.id,
                change_set_id,
                approval_id,
                approval_token,
                LOCAL_CLI_ACTOR.into(),
                state,
            )
            .await;
        }
        Command::ChangeConfirm { change_set_id } => {
            return handle_change_confirm(request.id, change_set_id, LOCAL_CLI_ACTOR.into(), state)
                .await;
        }
        Command::ChangeReject { change_set_id } => {
            return handle_change_reject(request.id, change_set_id, LOCAL_CLI_ACTOR.into(), state)
                .await;
        }
        Command::DiagnoseWan { active } => {
            return handle_wan_diagnosis(request.id, active, state).await;
        }
        Command::DiagnoseDns => {
            return handle_dns_diagnosis(request.id, state).await;
        }
        Command::DiagnoseDhcp => {
            return handle_dhcp_diagnosis(request.id, state).await;
        }
        Command::DiagnoseRoutes => {
            return handle_route_diagnosis(request.id, state).await;
        }
        Command::DiagnoseInterfaces => {
            return handle_interface_diagnosis(request.id, state).await;
        }
        Command::DiagnoseNeighbors => {
            return handle_neighbor_diagnosis(request.id, state).await;
        }
        Command::DiagnoseFirewall => {
            return handle_firewall_diagnosis(request.id, state).await;
        }
        Command::DiagnosePolicyRouting => {
            return handle_policy_routing_diagnosis(request.id, state).await;
        }
        Command::DiagnoseListeners => {
            return handle_listener_diagnosis(request.id, state).await;
        }
        Command::DiagnoseWireless => {
            return handle_wireless_diagnosis(request.id, state).await;
        }
        Command::DiagnoseInterfaceStats => {
            return handle_interface_stats_diagnosis(request.id, state).await;
        }
        Command::DiagnoseConntrack => {
            return handle_conntrack_diagnosis(request.id, state).await;
        }
        Command::DiagnoseQdisc => {
            return handle_qdisc_diagnosis(request.id, state).await;
        }
        Command::DiagnosticHistory { limit } => {
            return handle_diagnostic_history(request.id, limit, state).await;
        }
        Command::TaskHistory { limit } => {
            return handle_task_history(request.id, limit, state).await;
        }
        Command::Complete { prompt } => {
            return handle_completion(request.id, prompt, state).await;
        }
    };
    ServerResponse::success(request.id, result)
}

async fn handle_action_list(id: String, state: &AppState) -> ServerResponse {
    let platform = state.platform.kind.as_str();
    let actions = state.actions.read().await;
    let descriptors = actions
        .available(platform)
        .into_iter()
        .map(|action| ActionDescriptor {
            id: action.id.clone(),
            description: action.description.clone(),
            mode: match action.mode {
                ActionMode::ReadOnly => "read_only".into(),
                ActionMode::Change => "change".into(),
            },
            llm_enabled: action.llm_enabled,
            platforms: action.platforms.clone(),
            input_schema: ActionRegistry::input_schema(action),
        })
        .collect();
    ServerResponse::success(id, ResponseData::ActionList(descriptors))
}

fn handle_channel_status(id: String, state: &AppState) -> ServerResponse {
    let enabled = state.config.channels.mqtt.enabled;
    let lifecycle = state
        .mqtt_status
        .as_ref()
        .map_or(agent_channels::ChannelLifecycle::Disabled, |status| {
            *status.borrow()
        });
    let lifecycle = match lifecycle {
        agent_channels::ChannelLifecycle::Unconfigured => "unconfigured",
        agent_channels::ChannelLifecycle::Bound => "bound",
        agent_channels::ChannelLifecycle::Connecting => "connecting",
        agent_channels::ChannelLifecycle::Online => "online",
        agent_channels::ChannelLifecycle::Backoff => "backoff",
        agent_channels::ChannelLifecycle::Offline => "offline",
        agent_channels::ChannelLifecycle::NeedsRebind => "needs_rebind",
        agent_channels::ChannelLifecycle::Disabled => "disabled",
    };
    let wechat = &state.config.channels.wechat_clawbot;
    let wechat_lifecycle = state.wechat_status.as_ref().map_or_else(
        || {
            if !wechat.enabled {
                agent_channels::ChannelLifecycle::Disabled
            } else if wechat.bot_token.is_empty() {
                agent_channels::ChannelLifecycle::Unconfigured
            } else {
                agent_channels::ChannelLifecycle::Bound
            }
        },
        |status| *status.borrow(),
    );
    let wechat_lifecycle = match wechat_lifecycle {
        agent_channels::ChannelLifecycle::Unconfigured => "unconfigured",
        agent_channels::ChannelLifecycle::Bound => "bound",
        agent_channels::ChannelLifecycle::Connecting => "connecting",
        agent_channels::ChannelLifecycle::Online => "online",
        agent_channels::ChannelLifecycle::Backoff => "backoff",
        agent_channels::ChannelLifecycle::Offline => "offline",
        agent_channels::ChannelLifecycle::NeedsRebind => "needs_rebind",
        agent_channels::ChannelLifecycle::Disabled => "disabled",
    };
    let wecom = &state.config.channels.wecom;
    let wecom_lifecycle = state.wecom_status.as_ref().map_or_else(
        || {
            if !wecom.enabled {
                agent_channels::ChannelLifecycle::Disabled
            } else if wecom.bot_id.is_empty() || wecom.secret.is_empty() {
                agent_channels::ChannelLifecycle::Unconfigured
            } else {
                agent_channels::ChannelLifecycle::Bound
            }
        },
        |status| *status.borrow(),
    );
    let wecom_lifecycle = match wecom_lifecycle {
        agent_channels::ChannelLifecycle::Unconfigured => "unconfigured",
        agent_channels::ChannelLifecycle::Bound => "bound",
        agent_channels::ChannelLifecycle::Connecting => "connecting",
        agent_channels::ChannelLifecycle::Online => "online",
        agent_channels::ChannelLifecycle::Backoff => "backoff",
        agent_channels::ChannelLifecycle::Offline => "offline",
        agent_channels::ChannelLifecycle::NeedsRebind => "needs_rebind",
        agent_channels::ChannelLifecycle::Disabled => "disabled",
    };
    ServerResponse::success(
        id,
        ResponseData::ChannelStatus(vec![
            ChannelStatusEntry {
                channel: "mqtt".into(),
                enabled,
                lifecycle: lifecycle.into(),
            },
            ChannelStatusEntry {
                channel: "wechat_clawbot".into(),
                enabled: wechat.enabled,
                lifecycle: wechat_lifecycle.into(),
            },
            ChannelStatusEntry {
                channel: "wecom".into(),
                enabled: wecom.enabled,
                lifecycle: wecom_lifecycle.into(),
            },
        ]),
    )
}

async fn handle_action_plan(
    id: String,
    action_id: String,
    inputs: serde_json::Value,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    let invocation = {
        let actions = state.actions.read().await;
        actions.change_invocation(
            &action_id,
            state.platform.kind.as_str(),
            &inputs,
            &state.config.extensions,
        )
    };
    let invocation = match invocation {
        Ok(invocation) => invocation,
        Err(error) => {
            return ServerResponse::error(
                id,
                ErrorCode::InvalidRequest,
                format!("action change request was rejected: {error}"),
            );
        }
    };
    info!(%action_id, domain = ?invocation.domain, "declarative action requested a typed change plan");
    match invocation.domain {
        ActionChangeDomain::Firewall => {
            match serde_json::from_value::<Vec<FirewallMutationRequest>>(invocation.mutations) {
                Ok(mutations) => handle_firewall_plan(id, mutations, actor_id.clone(), state).await,
                Err(error) => ServerResponse::error(
                    id,
                    ErrorCode::InvalidRequest,
                    format!("firewall action template is not a valid typed mutation: {error}"),
                ),
            }
        }
        ActionChangeDomain::Network => {
            match serde_json::from_value::<Vec<NetworkMutationRequest>>(invocation.mutations) {
                Ok(mutations) => handle_network_plan(id, mutations, actor_id, state).await,
                Err(error) => ServerResponse::error(
                    id,
                    ErrorCode::InvalidRequest,
                    format!("network action template is not a valid typed mutation: {error}"),
                ),
            }
        }
    }
}

async fn handle_action_reload(id: String, actor_id: String, state: &AppState) -> ServerResponse {
    let now = process_monotonic_ms(state);
    match state.auth.is_device_admin(&actor_id, now) {
        Ok(true) => {}
        Ok(false) => {
            return ServerResponse::error(
                id,
                ErrorCode::Unauthorized,
                "device-admin elevation is required to reload action manifests",
            );
        }
        Err(error) => {
            error!(%error, "administrator capability check failed for action reload");
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            );
        }
    }
    let config = state.config.extensions.clone();
    let loaded = tokio::task::spawn_blocking(move || ActionRegistry::load(&config)).await;
    let registry = match loaded {
        Ok(Ok(registry)) => registry,
        Ok(Err(error)) => {
            warn!(%error, "action registry reload was rejected");
            return ServerResponse::error(
                id,
                ErrorCode::Conflict,
                format!("action registry reload was rejected: {error}"),
            );
        }
        Err(error) => {
            error!(%error, "action registry reload worker failed");
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "action registry reload is unavailable",
            );
        }
    };
    let loaded_actions = registry.len();
    *state.actions.write().await = registry;
    info!(loaded_actions, "declarative action registry reloaded");
    ServerResponse::success(
        id,
        ResponseData::ActionReload(ActionReloadResponse { loaded_actions }),
    )
}

async fn handle_action_run(
    id: String,
    action_id: String,
    inputs: serde_json::Value,
    state: &AppState,
) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let invocation = {
        let actions = state.actions.read().await;
        actions.invocation(
            &action_id,
            state.platform.kind.as_str(),
            &inputs,
            &state.config.extensions,
        )
    };
    let invocation = match invocation {
        Ok(invocation) => invocation,
        Err(error) => {
            return ServerResponse::error(
                id,
                ErrorCode::InvalidRequest,
                format!("action request was rejected: {error}"),
            );
        }
    };
    let Ok(permit) = state.action_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "all action execution slots are busy",
        );
    };
    let started = Instant::now();
    let result = execute_action(
        action_id.clone(),
        invocation,
        state.config.extensions.trusted_executable_owner_uid,
        Duration::from_secs(state.config.extensions.timeout_secs),
        state.config.extensions.max_output_bytes,
    )
    .await;
    drop(permit);
    match result {
        Ok(output) => {
            persist_action_audit(&id, &action_id, "succeeded", started.elapsed(), None, state)
                .await;
            info!(%action_id, exit_code = ?output.exit_code, "declarative action completed");
            ServerResponse::success(id, ResponseData::ActionOutput(output))
        }
        Err(ActionExecutionError::TimedOut) => {
            persist_action_audit(
                &id,
                &action_id,
                "timed_out",
                started.elapsed(),
                Some(ErrorCode::ResourceExhausted),
                state,
            )
            .await;
            ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "action execution timed out",
            )
        }
        Err(error) => {
            persist_action_audit(
                &id,
                &action_id,
                "failed",
                started.elapsed(),
                Some(ErrorCode::Conflict),
                state,
            )
            .await;
            warn!(%action_id, %error, "declarative action execution failed");
            ServerResponse::error(id, ErrorCode::Conflict, "action execution failed")
        }
    }
}

async fn handle_elevation(
    id: String,
    password: String,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    let password = Zeroizing::new(password);
    let auth = Arc::clone(&state.auth);
    let actor_id_for_auth = actor_id.clone();
    let now_monotonic_ms = u64::try_from(state.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = tokio::task::spawn_blocking(move || {
        auth.elevate(&actor_id_for_auth, password.as_bytes(), now_monotonic_ms)
    })
    .await;
    match outcome {
        Ok(Ok(capability)) => {
            info!(
                actor_id = %actor_id,
                "device administrator capability granted"
            );
            ServerResponse::success(
                id,
                ResponseData::Elevation(agent_protocol::ElevationResponse {
                    actor_id: capability.actor_id,
                    role: "device-admin".into(),
                    boot_id: capability.boot_id,
                    expires_monotonic_ms: capability.expires_monotonic_ms,
                }),
            )
        }
        Ok(Err(AuthError::Disabled)) => ServerResponse::error(
            id,
            ErrorCode::Unavailable,
            "administrator authentication is not enabled",
        ),
        Ok(Err(AuthError::InvalidCredentials | AuthError::Locked)) => {
            warn!(
                actor_id = %actor_id,
                "device administrator authentication failed"
            );
            ServerResponse::error(
                id,
                ErrorCode::Unauthorized,
                "administrator authentication failed",
            )
        }
        Ok(Err(AuthError::InvalidActor | AuthError::EmptyPassword)) => ServerResponse::error(
            id,
            ErrorCode::InvalidRequest,
            "administrator authentication request is invalid",
        ),
        Ok(Err(error)) => {
            error!(%error, "administrator authentication state failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            )
        }
        Err(error) => {
            error!(%error, "administrator authentication worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            )
        }
    }
}

async fn handle_deauth(id: String, actor_id: String, state: &AppState) -> ServerResponse {
    let auth = Arc::clone(&state.auth);
    let actor_id_for_auth = actor_id.clone();
    match tokio::task::spawn_blocking(move || auth.deauth(&actor_id_for_auth)).await {
        Ok(Ok(())) => {
            info!(%actor_id, "device administrator capability revoked");
            ServerResponse::success(id, ResponseData::Deauthenticated { actor_id })
        }
        Ok(Err(AuthError::InvalidActor)) => ServerResponse::error(
            id,
            ErrorCode::InvalidRequest,
            "administrator revocation request is invalid",
        ),
        Ok(Err(error)) => {
            error!(%error, "administrator revocation failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            )
        }
        Err(error) => {
            error!(%error, "administrator revocation worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            )
        }
    }
}

async fn handle_change_get(
    id: String,
    change_set_id: String,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if !valid_change_set_id(&change_set_id) {
        return ServerResponse::error(id, ErrorCode::InvalidRequest, "invalid ChangeSet id");
    }
    let store = Arc::clone(&state.store);
    let lookup_id = change_set_id.clone();
    match tokio::task::spawn_blocking(move || store.change_set(&lookup_id)).await {
        Ok(Ok(Some(record))) => match change_set_response(record, &actor_id, state) {
            Ok(response) => ServerResponse::success(id, ResponseData::ChangeSet(response)),
            Err(response) => response.with_id(id),
        },
        Ok(Ok(None)) => ServerResponse::error(id, ErrorCode::NotFound, "ChangeSet not found"),
        Ok(Err(error)) => store_error_response(id, &error),
        Err(error) => {
            error!(%error, "ChangeSet lookup worker failed");
            ServerResponse::error(id, ErrorCode::Internal, "ChangeSet storage is unavailable")
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_firewall_plan(
    id: String,
    requests: Vec<FirewallMutationRequest>,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let backend = match firewall_write_backend(state) {
        Ok(backend) => backend,
        Err(error) => return error.with_id(id),
    };
    let _configuration_guard = state.configuration_lock.lock().await;
    let now = match boot_monotonic_ms() {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let snapshot = match inspect_firewall_for_planning(state).await {
        Ok(snapshot) => snapshot,
        Err(error) => return error.with_id(id),
    };
    let mutations = requests
        .into_iter()
        .map(firewall_mutation)
        .collect::<Vec<_>>();
    let context = conservative_firewall_risk_context(snapshot.inventory());
    let mut typed = match plan_firewall_mutations(snapshot.inventory(), &mutations, &context) {
        Ok(plan) => plan,
        Err(error) => {
            return ServerResponse::error(
                id,
                ErrorCode::InvalidRequest,
                format!("firewall mutation plan was rejected: {error}"),
            );
        }
    };
    typed.risk = typed.risk.max(agent_protocol::RiskLevel::R3);
    let plan_id = match random_hex(16) {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let expires_monotonic_ms =
        now.saturating_add(state.config.auth.capability_ttl_secs.saturating_mul(1_000));
    let plan = ChangePlan {
        schema_version: agent_protocol::CHANGE_PLAN_SCHEMA_VERSION,
        plan_id: plan_id.clone(),
        boot_id: state.auth.boot_id().to_owned(),
        actor_id: actor_id.clone(),
        created_monotonic_ms: now,
        expires_monotonic_ms,
        risk: typed.risk,
        changes: typed
            .changes
            .iter()
            .map(|change| change.diff.clone())
            .collect(),
        validation_checks: vec![firewall_validation_check(backend).into()],
        verification_checks: vec!["reconstruct and compare touched live firewall objects".into()],
        rollback_required: true,
    };
    let digest = match plan_digest(&plan) {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "locally generated firewall plan is invalid");
            return ServerResponse::error(id, ErrorCode::Internal, "firewall planner failed");
        }
    };
    let execution = FirewallExecutionPlan {
        schema_version: agent_core::FIREWALL_EXECUTION_PLAN_SCHEMA_VERSION,
        preview: plan.clone(),
        typed,
    };
    let execution_payload = match execution.encode() {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "firewall execution plan encoding failed");
            return ServerResponse::error(id, ErrorCode::Internal, "firewall planner failed");
        }
    };
    let plan_payload = match serde_json::to_vec(&plan) {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "firewall plan encoding failed");
            return ServerResponse::error(id, ErrorCode::Internal, "firewall planner failed");
        }
    };
    let record = ChangeSetRecord {
        id: plan_id.clone(),
        plan_digest: digest,
        plan_payload,
        state: ChangeSetState::Planned,
        actor_id: actor_id.clone(),
        boot_id: state.auth.boot_id().to_owned(),
        risk: plan.risk,
        expires_monotonic_ms,
        rollback_deadline_monotonic_ms: None,
        created_at: 0,
        updated_at: 0,
    };
    persist_firewall_change(
        id,
        plan_id,
        record,
        execution_payload,
        now,
        &actor_id,
        state,
    )
    .await
}

async fn handle_firewall_inventory(id: String, state: &AppState) -> ServerResponse {
    if let Err(error) = firewall_write_backend(state) {
        return error.with_id(id);
    }
    let _configuration_guard = state.configuration_lock.lock().await;
    let snapshot = match inspect_firewall_for_planning(state).await {
        Ok(snapshot) => snapshot,
        Err(error) => return error.with_id(id),
    };
    let objects = snapshot
        .inventory()
        .objects
        .iter()
        .map(|object| {
            firewall_object_digest(object).map(|digest| FirewallInventoryEntry {
                digest,
                object: object.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>();
    match objects {
        Ok(objects) => ServerResponse::success(
            id,
            ResponseData::FirewallInventory(FirewallInventoryResponse { objects }),
        ),
        Err(error) => {
            error!(%error, "fresh firewall inventory digest failed");
            ServerResponse::error(id, ErrorCode::Internal, "firewall inventory is unavailable")
        }
    }
}

#[allow(clippy::too_many_lines)] // Plan construction keeps visible and executable forms together.
async fn handle_network_plan(
    id: String,
    requests: Vec<NetworkMutationRequest>,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let backend = match network_write_backend(state) {
        Ok(backend) => backend,
        Err(error) => return error.with_id(id),
    };
    if backend == WritableNetworkBackend::GenericRuntimeRoutes
        && !requests.iter().all(generic_runtime_route_request)
    {
        return ServerResponse::error(
            id,
            ErrorCode::InvalidRequest,
            "generic Linux network writes support only enabled Agent-owned runtime routes and reserved policy rules",
        );
    }
    let _configuration_guard = state.configuration_lock.lock().await;
    let inventory = match inspect_network_for_write(backend, state).await {
        Ok(inventory) => inventory,
        Err(error) => return error.with_id(id),
    };
    let mutations = requests
        .into_iter()
        .map(network_mutation)
        .collect::<Vec<_>>();
    let mut typed =
        match plan_network_mutations(&inventory, &mutations, &NetworkRiskContext::default()) {
            Ok(plan) => plan,
            Err(error) => {
                return ServerResponse::error(
                    id,
                    ErrorCode::InvalidRequest,
                    format!("network mutation plan was rejected: {error}"),
                );
            }
        };
    // A native network reload can sever the approval channel even for an otherwise local object.
    typed.risk = typed.risk.max(agent_protocol::RiskLevel::R3);
    let now = match boot_monotonic_ms() {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let plan_id = match random_hex(16) {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let expires_monotonic_ms =
        now.saturating_add(state.config.auth.capability_ttl_secs.saturating_mul(1_000));
    let plan = ChangePlan {
        schema_version: agent_protocol::CHANGE_PLAN_SCHEMA_VERSION,
        plan_id: plan_id.clone(),
        boot_id: state.auth.boot_id().to_owned(),
        actor_id: actor_id.clone(),
        created_monotonic_ms: now,
        expires_monotonic_ms,
        risk: typed.risk,
        changes: typed
            .changes
            .iter()
            .map(|change| change.diff.clone())
            .collect(),
        validation_checks: vec![network_validation_check(backend).into()],
        verification_checks: vec![
            "reconstruct and compare touched live L2/L3 network objects".into(),
        ],
        rollback_required: true,
    };
    let digest = match plan_digest(&plan) {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "locally generated network plan is invalid");
            return ServerResponse::error(id, ErrorCode::Internal, "network planner failed");
        }
    };
    let execution = NetworkExecutionPlan {
        schema_version: agent_core::NETWORK_EXECUTION_PLAN_SCHEMA_VERSION,
        preview: plan.clone(),
        typed,
    };
    let execution_payload = match execution.encode() {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "network execution plan encoding failed");
            return ServerResponse::error(id, ErrorCode::Internal, "network planner failed");
        }
    };
    let plan_payload = match serde_json::to_vec(&plan) {
        Ok(value) => value,
        Err(error) => {
            error!(%error, "network plan encoding failed");
            return ServerResponse::error(id, ErrorCode::Internal, "network planner failed");
        }
    };
    let record = ChangeSetRecord {
        id: plan_id.clone(),
        plan_digest: digest,
        plan_payload,
        state: ChangeSetState::Planned,
        actor_id: actor_id.clone(),
        boot_id: state.auth.boot_id().to_owned(),
        risk: plan.risk,
        expires_monotonic_ms,
        rollback_deadline_monotonic_ms: None,
        created_at: 0,
        updated_at: 0,
    };
    persist_network_change(
        id,
        plan_id,
        record,
        execution_payload,
        now,
        &actor_id,
        state,
    )
    .await
}

async fn handle_network_inventory(id: String, state: &AppState) -> ServerResponse {
    let _configuration_guard = state.configuration_lock.lock().await;
    let inventory = match inspect_network_inventory(state).await {
        Ok(inventory) => inventory,
        Err(error) => return error.with_id(id),
    };
    let objects = inventory
        .objects
        .iter()
        .map(|object| {
            network_object_digest(object).map(|digest| NetworkInventoryEntry {
                digest,
                object: object.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>();
    match objects {
        Ok(objects) => ServerResponse::success(
            id,
            ResponseData::NetworkInventory(NetworkInventoryResponse { objects }),
        ),
        Err(error) => {
            error!(%error, "fresh network inventory digest failed");
            ServerResponse::error(id, ErrorCode::Internal, "network inventory is unavailable")
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn inspect_network_inventory(
    state: &AppState,
) -> Result<NetworkInventory, PendingResponseError> {
    match state.platform.kind {
        PlatformKind::OpenWrt => inspect_network_for_planning(state)
            .await
            .map(|snapshot| snapshot.inventory().clone()),
        PlatformKind::GenericLinux
            if state
                .platform
                .available_commands
                .iter()
                .any(|command| command == "ip") =>
        {
            let runner = firewall_command_runner(state);
            let store = Arc::clone(&state.store);
            let max_state_bytes = usize::try_from(state.config.storage.max_network_state_bytes)
                .map_err(|_| PendingResponseError::internal("network state limit is invalid"))?;
            let boot_id = state.auth.boot_id().to_owned();
            tokio::task::spawn_blocking(move || {
                let canonical = store
                    .network_runtime_state(max_state_bytes)
                    .map_err(|_| PendingResponseError::internal("network state is unavailable"))?;
                let links = runner
                    .execute(&FirewallCommand::IpJsonLink, None)
                    .map_err(|_| {
                        PendingResponseError::unavailable("live network inventory is unavailable")
                    })?
                    .stdout;
                let addresses = runner
                    .execute(&FirewallCommand::IpJsonAddress, None)
                    .map_err(|_| {
                        PendingResponseError::unavailable("live network inventory is unavailable")
                    })?
                    .stdout;
                let routes = runner
                    .execute(&FirewallCommand::IpJsonRoute, None)
                    .map_err(|_| {
                        PendingResponseError::unavailable("live network inventory is unavailable")
                    })?
                    .stdout;
                let rules = runner
                    .execute(&FirewallCommand::IpJsonRule, None)
                    .map_err(|_| {
                        PendingResponseError::unavailable("live network inventory is unavailable")
                    })?
                    .stdout;
                let mut inventory = inspect_runtime_network_inventory(
                    std::str::from_utf8(&links).map_err(|_| {
                        PendingResponseError::conflict("live network inventory is malformed")
                    })?,
                    std::str::from_utf8(&addresses).map_err(|_| {
                        PendingResponseError::conflict("live network inventory is malformed")
                    })?,
                    std::str::from_utf8(&routes).map_err(|_| {
                        PendingResponseError::conflict("live network inventory is malformed")
                    })?,
                )
                .map_err(|error| {
                    warn!(%error, "generic Linux network inventory is not safely representable");
                    PendingResponseError::conflict(
                        "live network inventory cannot be safely represented",
                    )
                })?;
                let policy = inspect_runtime_policy_inventory(std::str::from_utf8(&rules).map_err(
                    |_| PendingResponseError::conflict("live network inventory is malformed"),
                )?)
                .map_err(|error| {
                    warn!(%error, "generic Linux policy rule inventory is not safely representable");
                    PendingResponseError::conflict(
                        "live policy rule inventory cannot be safely represented",
                    )
                })?;
                inventory.objects.extend(policy.objects);
                let owned = reconcile_runtime_network_inventory(
                    std::str::from_utf8(&routes).map_err(|_| {
                        PendingResponseError::conflict("live network inventory is malformed")
                    })?,
                    std::str::from_utf8(&rules).map_err(|_| {
                        PendingResponseError::conflict("live network inventory is malformed")
                    })?,
                    canonical.as_deref(),
                    &boot_id,
                )
                .map_err(|error| {
                    warn!(%error, "generic Linux Agent-owned network objects cannot be reconciled");
                    PendingResponseError::conflict(
                        "live Agent-owned route inventory cannot be safely represented",
                    )
                })?;
                inventory
                    .objects
                    .extend(owned.inventory().objects.iter().cloned());
                if inventory.objects.len() > 256 {
                    return Err(PendingResponseError::conflict(
                        "live network inventory exceeds its safe bound",
                    ));
                }
                Ok(inventory)
            })
            .await
            .map_err(|_| PendingResponseError::internal("network inventory worker failed"))?
        }
        _ => Err(PendingResponseError::conflict(
            "no supported network inventory backend is available",
        )),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WritableNetworkBackend {
    OpenWrt,
    GenericRuntimeRoutes,
}

const fn network_validation_check(backend: WritableNetworkBackend) -> &'static str {
    match backend {
        WritableNetworkBackend::OpenWrt => {
            "reinspect live UCI and run native OpenWrt network validation"
        }
        WritableNetworkBackend::GenericRuntimeRoutes => {
            "reconcile Agent-owned protocol-186 routes/reserved policy rules and validate a fixed ip batch"
        }
    }
}

fn network_write_backend(state: &AppState) -> Result<WritableNetworkBackend, PendingResponseError> {
    if state.platform.kind == PlatformKind::OpenWrt && state.platform.release_supported {
        return Ok(WritableNetworkBackend::OpenWrt);
    }
    if state.platform.kind == PlatformKind::GenericLinux
        && state
            .platform
            .available_commands
            .iter()
            .any(|command| command == "ip")
    {
        return Ok(WritableNetworkBackend::GenericRuntimeRoutes);
    }
    Err(PendingResponseError::conflict(
        "no supported writable network backend is available",
    ))
}

fn generic_runtime_route_request(request: &NetworkMutationRequest) -> bool {
    match request {
        NetworkMutationRequest::Create { desired }
        | NetworkMutationRequest::Update { desired, .. } => match desired {
            NetworkObject::Route(route) => {
                route.ownership == ObjectOwnership::AgentOwned && route.enabled
            }
            NetworkObject::PolicyRule(rule) => {
                rule.ownership == ObjectOwnership::AgentOwned
                    && rule.enabled
                    && (32_000..=32_063).contains(&rule.priority)
            }
            _ => false,
        },
        NetworkMutationRequest::Delete { kind, .. } => {
            matches!(kind.as_str(), "route" | "policy_rule")
        }
        NetworkMutationRequest::Move { desired, .. } => matches!(
            desired,
            NetworkObject::PolicyRule(rule)
                if rule.ownership == ObjectOwnership::AgentOwned
                    && rule.enabled
                    && (32_000..=32_063).contains(&rule.priority)
        ),
    }
}

async fn inspect_network_for_write(
    backend: WritableNetworkBackend,
    state: &AppState,
) -> Result<NetworkInventory, PendingResponseError> {
    match backend {
        WritableNetworkBackend::OpenWrt => inspect_network_for_planning(state)
            .await
            .map(|snapshot| snapshot.inventory().clone()),
        WritableNetworkBackend::GenericRuntimeRoutes => inspect_generic_runtime_routes(state)
            .await
            .map(|snapshot| snapshot.inventory().clone()),
    }
}

async fn inspect_generic_runtime_routes(
    state: &AppState,
) -> Result<platform_linux::network_runtime::RuntimeRouteSnapshot, PendingResponseError> {
    let canonical = load_generic_network_state(state).await?;
    let runner = firewall_command_runner(state);
    let boot_id = state.auth.boot_id().to_owned();
    tokio::task::spawn_blocking(move || {
        let routes = runner
            .execute(&FirewallCommand::IpJsonRoute, None)
            .map_err(|_| PendingResponseError::unavailable("live route inventory is unavailable"))?
            .stdout;
        let rules = runner
            .execute(&FirewallCommand::IpJsonRule, None)
            .map_err(|_| {
                PendingResponseError::unavailable("live policy rule inventory is unavailable")
            })?
            .stdout;
        reconcile_runtime_network_inventory(
            std::str::from_utf8(&routes)
                .map_err(|_| PendingResponseError::conflict("live route inventory is malformed"))?,
            std::str::from_utf8(&rules).map_err(|_| {
                PendingResponseError::conflict("live policy rule inventory is malformed")
            })?,
            canonical.as_deref(),
            &boot_id,
        )
        .map_err(|error| {
            warn!(%error, "generic Linux Agent-owned routes cannot be safely planned");
            PendingResponseError::conflict(
                "live Agent-owned route inventory cannot be safely modified",
            )
        })
    })
    .await
    .map_err(|_| PendingResponseError::internal("network planner is unavailable"))?
}

fn openwrt_network_write_supported(state: &AppState) -> Result<(), PendingResponseError> {
    if state.platform.kind == PlatformKind::OpenWrt && state.platform.release_supported {
        Ok(())
    } else {
        Err(PendingResponseError::conflict(
            "writable L2/L3 network configuration requires supported OpenWrt 21.02+",
        ))
    }
}

async fn inspect_network_for_planning(
    state: &AppState,
) -> Result<OpenWrtNetworkInventorySnapshot, PendingResponseError> {
    openwrt_network_write_supported(state)?;
    let runner = firewall_command_runner(state);
    let (network_output, dhcp_output) = tokio::task::spawn_blocking(move || {
        let network = runner
            .execute(&FirewallCommand::UciShowNetwork, None)
            .map_err(|_| {
                PendingResponseError::unavailable("live network inventory is unavailable")
            })?
            .stdout;
        let dhcp = runner
            .execute(&FirewallCommand::UciShowDhcp, None)
            .map_err(|_| PendingResponseError::unavailable("live DHCP inventory is unavailable"))?
            .stdout;
        Ok::<_, PendingResponseError>((network, dhcp))
    })
    .await
    .map_err(|_| PendingResponseError::internal("network planner is unavailable"))??;
    let network = std::str::from_utf8(&network_output)
        .map_err(|_| PendingResponseError::conflict("live network inventory is malformed"))?;
    let dhcp = std::str::from_utf8(&dhcp_output)
        .map_err(|_| PendingResponseError::conflict("live DHCP inventory is malformed"))?;
    inspect_openwrt_network_inventory_with_dhcp(network, dhcp).map_err(|error| {
        warn!(%error, "live network inventory cannot be safely planned");
        PendingResponseError::conflict("live network inventory cannot be safely modified")
    })
}

fn network_mutation(request: NetworkMutationRequest) -> NetworkMutation {
    match request {
        NetworkMutationRequest::Create { desired } => NetworkMutation::Create(desired),
        NetworkMutationRequest::Update {
            expected_digest,
            desired,
        } => NetworkMutation::Update {
            expected_digest,
            desired,
        },
        NetworkMutationRequest::Delete {
            kind,
            id,
            expected_digest,
        } => NetworkMutation::Delete {
            kind,
            id,
            expected_digest,
        },
        NetworkMutationRequest::Move {
            expected_digest,
            desired,
        } => NetworkMutation::Move {
            expected_digest,
            desired,
        },
    }
}

async fn persist_network_change(
    id: String,
    plan_id: String,
    record: ChangeSetRecord,
    execution_payload: Vec<u8>,
    now: u64,
    actor_id: &str,
    state: &AppState,
) -> ServerResponse {
    let Ok(max_plan_bytes) = usize::try_from(state.config.storage.max_change_plan_bytes) else {
        return ServerResponse::error(id, ErrorCode::Internal, "plan limit is invalid");
    };
    let Ok(max_execution_bytes) =
        usize::try_from(state.config.storage.max_firewall_execution_plan_bytes)
    else {
        return ServerResponse::error(id, ErrorCode::Internal, "execution plan limit is invalid");
    };
    let store = Arc::clone(&state.store);
    let max_records = state.config.storage.max_change_set_records;
    let create = tokio::task::spawn_blocking(move || {
        store.create_network_change_set(
            &record,
            &execution_payload,
            max_records,
            max_plan_bytes,
            max_execution_bytes,
            now,
        )
    })
    .await;
    match create {
        Ok(Ok(_)) => {
            info!(change_set_id = %plan_id, "approval-ready network ChangeSet created");
            current_change_set_response(id, &plan_id, actor_id, state).await
        }
        Ok(Err(error)) => store_error_response(id, &error),
        Err(error) => {
            error!(%error, "network plan storage worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "network plan storage is unavailable",
            )
        }
    }
}

async fn inspect_firewall_for_planning(
    state: &AppState,
) -> Result<FirewallPlanningSnapshot, PendingResponseError> {
    let backend = firewall_write_backend(state)?;
    if matches!(
        backend,
        WritableFirewallBackend::GenericNftables | WritableFirewallBackend::GenericIptables
    ) {
        let max_state_bytes = usize::try_from(state.config.storage.max_firewall_state_bytes)
            .map_err(|_| PendingResponseError::internal("firewall state limit is invalid"))?;
        let store = Arc::clone(&state.store);
        let runner = firewall_command_runner(state);
        let boot_id = state.auth.boot_id().to_owned();
        return tokio::task::spawn_blocking(move || {
            let canonical = store
                .firewall_runtime_state(max_state_bytes)
                .map_err(|_| PendingResponseError::internal("firewall state is unavailable"))?;
            let snapshot = match backend {
                WritableFirewallBackend::GenericNftables => {
                    inspect_generic_nftables_inventory(&runner, canonical.as_deref(), &boot_id)
                }
                WritableFirewallBackend::GenericIptables => {
                    inspect_generic_iptables_inventory(&runner, canonical.as_deref(), &boot_id)
                }
                WritableFirewallBackend::OpenWrt(_) => unreachable!(),
            }
            .map_err(|error| {
                warn!(%error, "generic Linux firewall inventory cannot be safely planned");
                PendingResponseError::conflict(
                    "live generic Linux firewall inventory cannot be safely modified",
                )
            })?;
            Ok((backend, snapshot))
        })
        .await
        .map_err(|error| {
            error!(%error, "nftables planning inspection worker failed");
            PendingResponseError::internal("firewall planner is unavailable")
        })?
        .map(|(backend, snapshot)| match backend {
            WritableFirewallBackend::GenericNftables => {
                FirewallPlanningSnapshot::GenericNftables(snapshot)
            }
            WritableFirewallBackend::GenericIptables => {
                FirewallPlanningSnapshot::GenericIptables(snapshot)
            }
            WritableFirewallBackend::OpenWrt(_) => unreachable!(),
        });
    }
    let runner = firewall_command_runner(state);
    let output = tokio::task::spawn_blocking(move || {
        runner.execute(&FirewallCommand::UciShowFirewall, None)
    })
    .await
    .map_err(|error| {
        error!(%error, "firewall planning inspection worker failed");
        PendingResponseError::internal("firewall planner is unavailable")
    })?
    .map_err(|error| {
        error!(%error, "fresh firewall planning inspection failed");
        PendingResponseError::unavailable("live firewall inventory is unavailable")
    })?
    .stdout;
    let uci = std::str::from_utf8(&output)
        .map_err(|_| PendingResponseError::conflict("live firewall inventory is malformed"))?;
    inspect_openwrt_firewall_inventory(uci)
        .map(FirewallPlanningSnapshot::OpenWrt)
        .map_err(|error| {
            warn!(%error, "live firewall inventory cannot be safely planned");
            PendingResponseError::conflict("live firewall inventory cannot be safely modified")
        })
}

enum FirewallPlanningSnapshot {
    OpenWrt(platform_linux::firewall_inventory::OpenWrtFirewallInventorySnapshot),
    GenericNftables(GenericFirewallInventorySnapshot),
    GenericIptables(GenericFirewallInventorySnapshot),
}

impl FirewallPlanningSnapshot {
    fn inventory(&self) -> &agent_core::FirewallInventory {
        match self {
            Self::OpenWrt(snapshot) => snapshot.inventory(),
            Self::GenericNftables(snapshot) | Self::GenericIptables(snapshot) => {
                snapshot.inventory()
            }
        }
    }
}

async fn persist_firewall_change(
    id: String,
    plan_id: String,
    record: ChangeSetRecord,
    execution_payload: Vec<u8>,
    now: u64,
    actor_id: &str,
    state: &AppState,
) -> ServerResponse {
    let Ok(max_plan_bytes) = usize::try_from(state.config.storage.max_change_plan_bytes) else {
        return ServerResponse::error(id, ErrorCode::Internal, "plan limit is invalid");
    };
    let Ok(max_execution_bytes) =
        usize::try_from(state.config.storage.max_firewall_execution_plan_bytes)
    else {
        return ServerResponse::error(id, ErrorCode::Internal, "execution plan limit is invalid");
    };
    let store = Arc::clone(&state.store);
    let max_records = state.config.storage.max_change_set_records;
    let create = tokio::task::spawn_blocking(move || {
        store.create_firewall_change_set(
            &record,
            &execution_payload,
            max_records,
            max_plan_bytes,
            max_execution_bytes,
            now,
        )
    })
    .await;
    match create {
        Ok(Ok(_)) => {
            info!(change_set_id = %plan_id, "approval-ready firewall ChangeSet created");
            current_change_set_response(id, &plan_id, actor_id, state).await
        }
        Ok(Err(error)) => store_error_response(id, &error),
        Err(error) => {
            error!(%error, "firewall plan storage worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "firewall plan storage is unavailable",
            )
        }
    }
}

fn firewall_mutation(request: FirewallMutationRequest) -> FirewallMutation {
    match request {
        FirewallMutationRequest::Create { desired } => FirewallMutation::Create(desired),
        FirewallMutationRequest::Update {
            expected_digest,
            desired,
        } => FirewallMutation::Update {
            expected_digest,
            desired,
        },
        FirewallMutationRequest::Delete {
            kind,
            id,
            expected_digest,
        } => FirewallMutation::Delete {
            kind,
            id,
            expected_digest,
        },
        FirewallMutationRequest::Move {
            expected_digest,
            desired,
        } => FirewallMutation::Move {
            expected_digest,
            desired,
        },
    }
}

fn conservative_firewall_risk_context(
    inventory: &agent_core::FirewallInventory,
) -> FirewallRiskContext {
    let mut context = FirewallRiskContext::default();
    for object in &inventory.objects {
        match object {
            FirewallObject::Zone(zone) => {
                context.management_zones.push(zone.id.clone());
                context
                    .management_interfaces
                    .extend(zone.networks.iter().cloned());
            }
            FirewallObject::FilterRule(rule) => {
                context.management_rule_ids.push(rule.id.clone());
            }
            FirewallObject::NatRule(rule) => {
                context.management_rule_ids.push(rule.id.clone());
            }
            FirewallObject::Forwarding(_) | FirewallObject::AddressSet(_) => {}
        }
    }
    for values in [
        &mut context.management_rule_ids,
        &mut context.management_zones,
        &mut context.management_interfaces,
    ] {
        values.sort_unstable();
        values.dedup();
        values.truncate(32);
    }
    context
}

async fn handle_change_approve(
    id: String,
    change_set_id: String,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if !valid_change_set_id(&change_set_id) {
        return ServerResponse::error(id, ErrorCode::InvalidRequest, "invalid ChangeSet id");
    }
    let capability_now = process_monotonic_ms(state);
    match state.auth.is_device_admin(&actor_id, capability_now) {
        Ok(true) => {}
        Ok(false) => {
            return ServerResponse::error(
                id,
                ErrorCode::Unauthorized,
                "device-admin elevation is required",
            );
        }
        Err(error) => {
            error!(%error, "administrator capability check failed");
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            );
        }
    }
    let now = match boot_monotonic_ms() {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };

    let Some(record) = load_change_set(&id, &change_set_id, state).await else {
        return ServerResponse::error(id, ErrorCode::NotFound, "ChangeSet not found");
    };
    if let Err(response) = change_set_response(record.clone(), &actor_id, state) {
        return response.with_id(id);
    }
    if record.state != ChangeSetState::AwaitingApproval {
        return ServerResponse::error(
            id,
            ErrorCode::Conflict,
            "ChangeSet is not awaiting approval",
        );
    }
    if now >= record.expires_monotonic_ms {
        return ServerResponse::error(id, ErrorCode::Conflict, "ChangeSet plan has expired");
    }

    let approval_id = match random_hex(16) {
        Ok(value) => value,
        Err(response) => return response.with_id(id),
    };
    let token = match random_hex(32) {
        Ok(value) => value,
        Err(response) => return response.with_id(id),
    };
    let expires_monotonic_ms = now
        .saturating_add(state.config.auth.approval_ttl_secs.saturating_mul(1_000))
        .min(record.expires_monotonic_ms);
    let approval = ApprovalRecord {
        id: approval_id.clone(),
        change_set_id: record.id.clone(),
        actor_id: record.actor_id.clone(),
        plan_digest: record.plan_digest.clone(),
        boot_id: record.boot_id.clone(),
        token_digest: sha256_hex(token.as_bytes()),
        expires_monotonic_ms,
        consumed_monotonic_ms: None,
        created_at: 0,
    };
    let store = Arc::clone(&state.store);
    match tokio::task::spawn_blocking(move || store.issue_approval(&approval, now)).await {
        Ok(Ok(())) => {
            info!(
                change_set_id = %record.id,
                approval_id,
                "one-use configuration approval issued"
            );
            ServerResponse::success(
                id,
                ResponseData::ChangeApproval(ChangeApprovalResponse {
                    approval_id,
                    change_set_id: record.id,
                    plan_digest: record.plan_digest,
                    token: SensitiveString::new(token),
                    expires_monotonic_ms,
                }),
            )
        }
        Ok(Err(error)) => store_error_response(id, &error),
        Err(error) => {
            error!(%error, "approval storage worker failed");
            ServerResponse::error(id, ErrorCode::Internal, "approval storage is unavailable")
        }
    }
}

#[allow(clippy::too_many_lines)] // Domain dispatch remains inside the closed approval handler.
async fn handle_change_apply(
    id: String,
    change_set_id: String,
    approval_id: String,
    approval_token: SensitiveString,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if !valid_change_set_id(&change_set_id)
        || !valid_execution_transaction_id(&change_set_id)
        || !valid_approval_id(&approval_id)
    {
        return ServerResponse::error(id, ErrorCode::InvalidRequest, "invalid change approval");
    }
    let _configuration_guard = state.configuration_lock.lock().await;
    let now = match boot_monotonic_ms() {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let Some(record) = load_change_set(&id, &change_set_id, state).await else {
        return ServerResponse::error(id, ErrorCode::NotFound, "ChangeSet not found");
    };
    let response = match change_set_response(record.clone(), &actor_id, state) {
        Ok(response) => response,
        Err(error) => return error.with_id(id),
    };
    if record.state != ChangeSetState::AwaitingApproval || now >= record.expires_monotonic_ms {
        return ServerResponse::error(
            id,
            ErrorCode::Conflict,
            "ChangeSet is not awaiting a valid approval",
        );
    }
    if response
        .plan
        .changes
        .first()
        .is_some_and(|change| change.object.domain == ConfigDomain::Network)
    {
        return apply_network_change(
            id,
            approval_id,
            approval_token,
            record,
            response.plan,
            now,
            actor_id,
            state,
        )
        .await;
    }
    let execution = match load_firewall_execution_plan(&record, state).await {
        Ok(execution) if execution.preview == response.plan => execution,
        Ok(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "stored execution plan binding is invalid",
            );
        }
        Err(response) => return response.with_id(id),
    };
    let backend = match firewall_write_backend(state) {
        Ok(backend) => backend,
        Err(response) => return response.with_id(id),
    };
    if !state.config_path.is_file() {
        return ServerResponse::error(
            id,
            ErrorCode::Conflict,
            "daemon configuration must exist before arming the rollback helper",
        );
    }
    let generic_canonical_state = match canonical_for_backend(backend, state).await {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let token_digest = sha256_hex(approval_token.expose().as_bytes());
    if let Err(error) =
        consume_change_approval(approval_id, token_digest, record.clone(), now, state).await
    {
        return error.with_id(id);
    }
    drop(approval_token);

    let deadline = rollback_deadline(now, state);
    let confirmation_required = record.risk >= agent_protocol::RiskLevel::R3;
    let outcome = execute_firewall_change(
        backend,
        record.clone(),
        execution,
        generic_canonical_state,
        now,
        deadline,
        confirmation_required,
        state,
    )
    .await;
    match outcome {
        Ok(Ok(result)) => {
            info!(change_set_id = %record.id, ?result, "configuration change executed");
            current_change_set_response(id, &record.id, &actor_id, state).await
        }
        Ok(Err(_)) => {
            error!(change_set_id = %record.id, "configuration change execution failed");
            ServerResponse::error(
                id,
                ErrorCode::Conflict,
                "configuration execution failed; inspect the ChangeSet state",
            )
        }
        Err(error) => {
            error!(change_set_id = %record.id, %error, "configuration execution worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "configuration executor is unavailable",
            )
        }
    }
}

async fn consume_change_approval(
    approval_id: String,
    token_digest: String,
    record: ChangeSetRecord,
    now_monotonic_ms: u64,
    state: &AppState,
) -> Result<(), PendingResponseError> {
    let store = Arc::clone(&state.store);
    match tokio::task::spawn_blocking(move || {
        store.consume_approval(
            &agent_store::ApprovalConsumption {
                approval_id: &approval_id,
                change_set_id: &record.id,
                actor_id: &record.actor_id,
                plan_digest: &record.plan_digest,
                boot_id: &record.boot_id,
                token_digest: &token_digest,
            },
            now_monotonic_ms,
        )
    })
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(StoreError::ApprovalRejected)) => Err(PendingResponseError::conflict(
            "change approval is invalid, expired, or already consumed",
        )),
        Ok(Err(error)) => {
            error!(%error, "approval consumption failed");
            Err(PendingResponseError::internal(
                "approval storage is unavailable",
            ))
        }
        Err(error) => {
            error!(%error, "approval consumption worker failed");
            Err(PendingResponseError::internal(
                "approval storage is unavailable",
            ))
        }
    }
}

async fn handle_change_confirm(
    id: String,
    change_set_id: String,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if !valid_change_set_id(&change_set_id) || !valid_execution_transaction_id(&change_set_id) {
        return ServerResponse::error(id, ErrorCode::InvalidRequest, "invalid ChangeSet id");
    }
    let capability_now = process_monotonic_ms(state);
    match state.auth.is_device_admin(&actor_id, capability_now) {
        Ok(true) => {}
        Ok(false) => {
            return ServerResponse::error(
                id,
                ErrorCode::Unauthorized,
                "device-admin elevation is required",
            );
        }
        Err(error) => {
            error!(%error, "administrator capability check failed");
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "administrator authentication is unavailable",
            );
        }
    }
    let _configuration_guard = state.configuration_lock.lock().await;
    let now = match boot_monotonic_ms() {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let Some(record) = load_change_set(&id, &change_set_id, state).await else {
        return ServerResponse::error(id, ErrorCode::NotFound, "ChangeSet not found");
    };
    let response = match change_set_response(record.clone(), &actor_id, state) {
        Ok(response) => response,
        Err(error) => return error.with_id(id),
    };
    if record.state != ChangeSetState::AwaitingConfirmation
        || record
            .rollback_deadline_monotonic_ms
            .is_none_or(|deadline| now >= deadline)
    {
        return ServerResponse::error(
            id,
            ErrorCode::Conflict,
            "ChangeSet is not awaiting confirmation or its deadline passed",
        );
    }
    if response
        .plan
        .changes
        .first()
        .is_some_and(|change| change.object.domain == ConfigDomain::Network)
    {
        return confirm_network_change_request(id, record, response.plan, now, &actor_id, state)
            .await;
    }
    let execution = match load_firewall_execution_plan(&record, state).await {
        Ok(execution) => execution,
        Err(response) => return response.with_id(id),
    };
    let backend = match firewall_write_backend(state) {
        Ok(backend) => backend,
        Err(response) => return response.with_id(id),
    };
    let generic_canonical_state = match canonical_for_backend(backend, state).await {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let outcome = confirm_firewall_change(
        backend,
        record.clone(),
        execution,
        generic_canonical_state,
        now,
        state,
    )
    .await;
    match outcome {
        Ok(Ok(result)) => {
            info!(change_set_id = %record.id, ?result, "configuration change confirmed");
            current_change_set_response(id, &record.id, &actor_id, state).await
        }
        Ok(Err(_)) => {
            error!(change_set_id = %record.id, "configuration confirmation failed");
            ServerResponse::error(
                id,
                ErrorCode::Conflict,
                "configuration confirmation failed; inspect the ChangeSet state",
            )
        }
        Err(error) => {
            error!(change_set_id = %record.id, %error, "configuration confirmation worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "configuration executor is unavailable",
            )
        }
    }
}

async fn load_firewall_execution_plan(
    record: &ChangeSetRecord,
    state: &AppState,
) -> Result<FirewallExecutionPlan, PendingResponseError> {
    let max_bytes = usize::try_from(state.config.storage.max_firewall_execution_plan_bytes)
        .map_err(|_| PendingResponseError::internal("execution plan limit is invalid"))?;
    let store = Arc::clone(&state.store);
    let record = record.clone();
    let payload = tokio::task::spawn_blocking(move || {
        store.firewall_execution_plan(&record.id, &record.plan_digest, &record.boot_id, max_bytes)
    })
    .await
    .map_err(|_| PendingResponseError::internal("execution plan storage is unavailable"))?
    .map_err(|_| PendingResponseError::internal("execution plan storage is unavailable"))?
    .ok_or_else(|| PendingResponseError::conflict("ChangeSet has no executable firewall plan"))?;
    FirewallExecutionPlan::decode(&payload)
        .map_err(|_| PendingResponseError::internal("stored execution plan is invalid"))
}

async fn load_network_execution_plan(
    record: &ChangeSetRecord,
    state: &AppState,
) -> Result<NetworkExecutionPlan, PendingResponseError> {
    let max_bytes = usize::try_from(state.config.storage.max_firewall_execution_plan_bytes)
        .map_err(|_| PendingResponseError::internal("execution plan limit is invalid"))?;
    let store = Arc::clone(&state.store);
    let record = record.clone();
    let payload = tokio::task::spawn_blocking(move || {
        store.network_execution_plan(&record.id, &record.plan_digest, &record.boot_id, max_bytes)
    })
    .await
    .map_err(|_| PendingResponseError::internal("execution plan storage is unavailable"))?
    .map_err(|_| PendingResponseError::internal("execution plan storage is unavailable"))?
    .ok_or_else(|| PendingResponseError::conflict("ChangeSet has no executable network plan"))?;
    NetworkExecutionPlan::decode(&payload)
        .map_err(|_| PendingResponseError::internal("stored execution plan is invalid"))
}

#[allow(clippy::too_many_arguments)]
async fn apply_network_change(
    id: String,
    approval_id: String,
    approval_token: SensitiveString,
    record: ChangeSetRecord,
    preview: ChangePlan,
    now: u64,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    let backend = match network_write_backend(state) {
        Ok(backend) => backend,
        Err(error) => return error.with_id(id),
    };
    let execution = match load_network_execution_plan(&record, state).await {
        Ok(execution) if execution.preview == preview => execution,
        Ok(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "stored execution plan binding is invalid",
            );
        }
        Err(error) => return error.with_id(id),
    };
    if !state.config_path.is_file() {
        return ServerResponse::error(
            id,
            ErrorCode::Conflict,
            "daemon configuration must exist before arming the rollback helper",
        );
    }
    let canonical_state = match canonical_for_network_backend(backend, state).await {
        Ok(canonical) => canonical,
        Err(error) => return error.with_id(id),
    };
    let token_digest = sha256_hex(approval_token.expose().as_bytes());
    if let Err(error) =
        consume_change_approval(approval_id, token_digest, record.clone(), now, state).await
    {
        return error.with_id(id);
    }
    drop(approval_token);
    let deadline = rollback_deadline(now, state);
    let outcome = execute_network_change(
        backend,
        record.clone(),
        execution,
        canonical_state,
        now,
        deadline,
        state,
    )
    .await;
    execution_response(
        id,
        &record.id,
        &actor_id,
        outcome,
        "network configuration",
        state,
    )
    .await
}

async fn confirm_network_change_request(
    id: String,
    record: ChangeSetRecord,
    preview: ChangePlan,
    now: u64,
    actor_id: &str,
    state: &AppState,
) -> ServerResponse {
    let backend = match network_write_backend(state) {
        Ok(backend) => backend,
        Err(error) => return error.with_id(id),
    };
    let execution = match load_network_execution_plan(&record, state).await {
        Ok(execution) if execution.preview == preview => execution,
        Ok(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                "stored execution plan binding is invalid",
            );
        }
        Err(error) => return error.with_id(id),
    };
    let canonical_state = match canonical_for_network_backend(backend, state).await {
        Ok(canonical) => canonical,
        Err(error) => return error.with_id(id),
    };
    let outcome = confirm_network_change(
        backend,
        record.clone(),
        execution,
        canonical_state,
        now,
        state,
    )
    .await;
    execution_response(
        id,
        &record.id,
        actor_id,
        outcome,
        "network configuration confirmation",
        state,
    )
    .await
}

async fn execution_response(
    id: String,
    change_set_id: &str,
    actor_id: &str,
    outcome: ExecutionWorkerResult,
    operation: &str,
    state: &AppState,
) -> ServerResponse {
    match outcome {
        Ok(Ok(result)) => {
            info!(change_set_id, ?result, %operation, "configuration operation completed");
            current_change_set_response(id, change_set_id, actor_id, state).await
        }
        Ok(Err(_)) => {
            error!(change_set_id, %operation, "configuration operation failed");
            ServerResponse::error(
                id,
                ErrorCode::Conflict,
                "configuration operation failed; inspect the ChangeSet state",
            )
        }
        Err(error) => {
            error!(change_set_id, %operation, %error, "configuration worker failed");
            ServerResponse::error(
                id,
                ErrorCode::Internal,
                "configuration executor is unavailable",
            )
        }
    }
}

fn openwrt_network_port_config(
    record: ChangeSetRecord,
    execution: NetworkExecutionPlan,
    now_monotonic_ms: u64,
    state: &AppState,
) -> OpenWrtNetworkExecutionPortConfig {
    OpenWrtNetworkExecutionPortConfig {
        runner: firewall_command_runner(state),
        store: Arc::clone(&state.store),
        runtime_root: state.budget.root().to_path_buf(),
        config_path: state.config_path.clone(),
        change_set_id: record.id,
        plan_digest: record.plan_digest,
        boot_id: record.boot_id,
        now_monotonic_ms,
        rollback_timeout_secs: state.config.runtime.rollback_confirm_timeout_secs,
        max_rollback_bytes: state.config.storage.max_rollback_bytes,
        execution,
    }
}

fn generic_runtime_route_port_config(
    record: ChangeSetRecord,
    execution: NetworkExecutionPlan,
    canonical_state: Option<Vec<u8>>,
    now_monotonic_ms: u64,
    state: &AppState,
) -> GenericRuntimeRouteExecutionPortConfig {
    GenericRuntimeRouteExecutionPortConfig {
        runner: firewall_command_runner(state),
        execution,
        canonical_state,
        store: Arc::clone(&state.store),
        runtime_root: state.budget.root().to_path_buf(),
        config_path: state.config_path.clone(),
        change_set_id: record.id,
        plan_digest: record.plan_digest,
        boot_id: record.boot_id,
        now_monotonic_ms,
        rollback_timeout_secs: state.config.runtime.rollback_confirm_timeout_secs,
        max_rollback_bytes: state.config.storage.max_rollback_bytes,
        max_state_bytes: usize::try_from(state.config.storage.max_network_state_bytes)
            .unwrap_or(usize::MAX),
    }
}

async fn execute_network_change(
    backend: WritableNetworkBackend,
    record: ChangeSetRecord,
    execution: NetworkExecutionPlan,
    canonical_state: Option<Vec<u8>>,
    now: u64,
    deadline: u64,
    state: &AppState,
) -> ExecutionWorkerResult {
    match backend {
        WritableNetworkBackend::OpenWrt => {
            let config = openwrt_network_port_config(record, execution, now, state);
            tokio::task::spawn_blocking(move || {
                let mut port = OpenWrtNetworkExecutionPort::apply(config)?;
                execute_approved_change(&mut port, now, deadline, true)
                    .map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
        WritableNetworkBackend::GenericRuntimeRoutes => {
            let config =
                generic_runtime_route_port_config(record, execution, canonical_state, now, state);
            tokio::task::spawn_blocking(move || {
                let mut port = GenericRuntimeRouteExecutionPort::apply(config)?;
                execute_approved_change(&mut port, now, deadline, true)
                    .map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
    }
}

async fn confirm_network_change(
    backend: WritableNetworkBackend,
    record: ChangeSetRecord,
    execution: NetworkExecutionPlan,
    canonical_state: Option<Vec<u8>>,
    now: u64,
    state: &AppState,
) -> ExecutionWorkerResult {
    match backend {
        WritableNetworkBackend::OpenWrt => {
            let config = openwrt_network_port_config(record, execution, now, state);
            tokio::task::spawn_blocking(move || {
                let mut port = OpenWrtNetworkExecutionPort::confirmation(config);
                confirm_awaiting_execution(&mut port).map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
        WritableNetworkBackend::GenericRuntimeRoutes => {
            let config =
                generic_runtime_route_port_config(record, execution, canonical_state, now, state);
            tokio::task::spawn_blocking(move || {
                let mut port = GenericRuntimeRouteExecutionPort::confirmation(config);
                confirm_awaiting_execution(&mut port).map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
    }
}

#[derive(Clone, Copy)]
enum WritableFirewallBackend {
    OpenWrt(FirewallBackend),
    GenericNftables,
    GenericIptables,
}

const fn firewall_validation_check(backend: WritableFirewallBackend) -> &'static str {
    match backend {
        WritableFirewallBackend::OpenWrt(_) => {
            "reinspect live UCI and run native fw3/fw4 validation"
        }
        WritableFirewallBackend::GenericNftables => {
            "reconcile live owned nftables state and run nft --check"
        }
        WritableFirewallBackend::GenericIptables => {
            "reconcile both owned iptables families and run dual restore tests"
        }
    }
}

type ExecutionWorkerResult = Result<
    Result<agent_core::ExecutionOutcome, agent_core::ExecutionPortError>,
    tokio::task::JoinError,
>;

#[allow(clippy::too_many_arguments)] // Closed backend dispatcher keeps the request handler small.
async fn execute_firewall_change(
    backend: WritableFirewallBackend,
    record: ChangeSetRecord,
    execution: FirewallExecutionPlan,
    canonical_state: Option<Vec<u8>>,
    now: u64,
    deadline: u64,
    confirmation_required: bool,
    state: &AppState,
) -> ExecutionWorkerResult {
    match backend {
        WritableFirewallBackend::OpenWrt(backend) => {
            let port_config = openwrt_port_config(record, execution, backend, now, state);
            tokio::task::spawn_blocking(move || {
                let mut port = OpenWrtExecutionPort::apply(port_config)?;
                execute_approved_change(&mut port, now, deadline, confirmation_required)
                    .map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
        WritableFirewallBackend::GenericIptables => {
            let port_config =
                generic_iptables_port_config(record, execution, now, state, canonical_state);
            tokio::task::spawn_blocking(move || {
                let mut port = GenericIptablesExecutionPort::apply(port_config)?;
                execute_approved_change(&mut port, now, deadline, confirmation_required)
                    .map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
        WritableFirewallBackend::GenericNftables => {
            let port_config =
                generic_nftables_port_config(record, execution, now, state, canonical_state);
            tokio::task::spawn_blocking(move || {
                let mut port = GenericNftablesExecutionPort::apply(port_config)?;
                execute_approved_change(&mut port, now, deadline, confirmation_required)
                    .map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
    }
}

async fn confirm_firewall_change(
    backend: WritableFirewallBackend,
    record: ChangeSetRecord,
    execution: FirewallExecutionPlan,
    canonical_state: Option<Vec<u8>>,
    now: u64,
    state: &AppState,
) -> ExecutionWorkerResult {
    match backend {
        WritableFirewallBackend::OpenWrt(backend) => {
            let port_config = openwrt_port_config(record, execution, backend, now, state);
            tokio::task::spawn_blocking(move || {
                let mut port = OpenWrtExecutionPort::confirmation(port_config);
                confirm_awaiting_execution(&mut port).map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
        WritableFirewallBackend::GenericNftables => {
            let port_config =
                generic_nftables_port_config(record, execution, now, state, canonical_state);
            tokio::task::spawn_blocking(move || {
                let mut port = GenericNftablesExecutionPort::confirmation(port_config);
                confirm_awaiting_execution(&mut port).map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
        WritableFirewallBackend::GenericIptables => {
            let port_config =
                generic_iptables_port_config(record, execution, now, state, canonical_state);
            tokio::task::spawn_blocking(move || {
                let mut port = GenericIptablesExecutionPort::confirmation(port_config);
                confirm_awaiting_execution(&mut port).map_err(|_| agent_core::ExecutionPortError)
            })
            .await
        }
    }
}

fn firewall_write_backend(
    state: &AppState,
) -> Result<WritableFirewallBackend, PendingResponseError> {
    match (state.platform.kind, state.platform.firewall.backend) {
        (PlatformKind::OpenWrt, backend @ (FirewallBackend::Fw3 | FirewallBackend::Fw4))
            if state.platform.release_supported =>
        {
            Ok(WritableFirewallBackend::OpenWrt(backend))
        }
        (PlatformKind::GenericLinux, FirewallBackend::Nftables) => {
            Ok(WritableFirewallBackend::GenericNftables)
        }
        (PlatformKind::GenericLinux, FirewallBackend::Iptables) => {
            Ok(WritableFirewallBackend::GenericIptables)
        }
        (PlatformKind::OpenWrt, _) => Err(PendingResponseError::conflict(
            "no supported writable OpenWrt 21.02+ firewall backend is available",
        )),
        (PlatformKind::GenericLinux, _) => Err(PendingResponseError::conflict(
            "no supported writable generic Linux firewall backend is available",
        )),
        (PlatformKind::Unknown, _) => Err(PendingResponseError::conflict(
            "no supported writable firewall backend is available",
        )),
    }
}

fn openwrt_port_config(
    record: ChangeSetRecord,
    execution: FirewallExecutionPlan,
    backend: FirewallBackend,
    now_monotonic_ms: u64,
    state: &AppState,
) -> OpenWrtExecutionPortConfig {
    let runtime_root = state.budget.root().to_path_buf();
    OpenWrtExecutionPortConfig {
        runner: firewall_command_runner(state),
        store: Arc::clone(&state.store),
        runtime_root,
        config_path: state.config_path.clone(),
        change_set_id: record.id,
        plan_digest: record.plan_digest,
        boot_id: record.boot_id,
        now_monotonic_ms,
        rollback_timeout_secs: state.config.runtime.rollback_confirm_timeout_secs,
        max_rollback_bytes: state.config.storage.max_rollback_bytes,
        backend,
        execution,
    }
}

fn generic_nftables_port_config(
    record: ChangeSetRecord,
    execution: FirewallExecutionPlan,
    now_monotonic_ms: u64,
    state: &AppState,
    canonical_state: Option<Vec<u8>>,
) -> GenericNftablesExecutionPortConfig {
    let max_firewall_state_bytes =
        usize::try_from(state.config.storage.max_firewall_state_bytes).unwrap_or(usize::MAX);
    GenericNftablesExecutionPortConfig {
        runner: firewall_command_runner(state),
        store: Arc::clone(&state.store),
        runtime_root: state.budget.root().to_path_buf(),
        config_path: state.config_path.clone(),
        change_set_id: record.id,
        plan_digest: record.plan_digest,
        boot_id: record.boot_id,
        now_monotonic_ms,
        rollback_timeout_secs: state.config.runtime.rollback_confirm_timeout_secs,
        max_rollback_bytes: state.config.storage.max_rollback_bytes,
        max_firewall_state_bytes,
        canonical_state,
        execution,
    }
}

fn generic_iptables_port_config(
    record: ChangeSetRecord,
    execution: FirewallExecutionPlan,
    now_monotonic_ms: u64,
    state: &AppState,
    canonical_state: Option<Vec<u8>>,
) -> GenericIptablesExecutionPortConfig {
    let max_firewall_state_bytes =
        usize::try_from(state.config.storage.max_firewall_state_bytes).unwrap_or(usize::MAX);
    GenericIptablesExecutionPortConfig {
        runner: firewall_command_runner(state),
        store: Arc::clone(&state.store),
        runtime_root: state.budget.root().to_path_buf(),
        config_path: state.config_path.clone(),
        change_set_id: record.id,
        plan_digest: record.plan_digest,
        boot_id: record.boot_id,
        now_monotonic_ms,
        rollback_timeout_secs: state.config.runtime.rollback_confirm_timeout_secs,
        max_rollback_bytes: state.config.storage.max_rollback_bytes,
        max_firewall_state_bytes,
        canonical_state,
        execution,
    }
}

async fn load_generic_firewall_state(
    state: &AppState,
) -> Result<Option<Vec<u8>>, PendingResponseError> {
    let max_firewall_state_bytes =
        usize::try_from(state.config.storage.max_firewall_state_bytes)
            .map_err(|_| PendingResponseError::internal("firewall state limit is invalid"))?;
    let store = Arc::clone(&state.store);
    tokio::task::spawn_blocking(move || store.firewall_runtime_state(max_firewall_state_bytes))
        .await
        .map_err(|_| PendingResponseError::internal("firewall state is unavailable"))?
        .map_err(|_| PendingResponseError::internal("firewall state is unavailable"))
}

async fn canonical_for_backend(
    backend: WritableFirewallBackend,
    state: &AppState,
) -> Result<Option<Vec<u8>>, PendingResponseError> {
    if matches!(
        backend,
        WritableFirewallBackend::GenericNftables | WritableFirewallBackend::GenericIptables
    ) {
        load_generic_firewall_state(state).await
    } else {
        Ok(None)
    }
}

async fn load_generic_network_state(
    state: &AppState,
) -> Result<Option<Vec<u8>>, PendingResponseError> {
    let max_state_bytes = usize::try_from(state.config.storage.max_network_state_bytes)
        .map_err(|_| PendingResponseError::internal("network state limit is invalid"))?;
    let store = Arc::clone(&state.store);
    tokio::task::spawn_blocking(move || store.network_runtime_state(max_state_bytes))
        .await
        .map_err(|_| PendingResponseError::internal("network state is unavailable"))?
        .map_err(|_| PendingResponseError::internal("network state is unavailable"))
}

async fn canonical_for_network_backend(
    backend: WritableNetworkBackend,
    state: &AppState,
) -> Result<Option<Vec<u8>>, PendingResponseError> {
    if backend == WritableNetworkBackend::GenericRuntimeRoutes {
        load_generic_network_state(state).await
    } else {
        Ok(None)
    }
}

fn rollback_deadline(now_monotonic_ms: u64, state: &AppState) -> u64 {
    now_monotonic_ms.saturating_add(
        state
            .config
            .runtime
            .rollback_confirm_timeout_secs
            .saturating_mul(1_000),
    )
}

fn firewall_command_runner(state: &AppState) -> FirewallCommandRunner {
    FirewallCommandRunner::system(
        state.budget.root().to_path_buf(),
        Duration::from_secs(state.config.runtime.tool_timeout_secs),
        usize::try_from(state.config.storage.max_firewall_execution_plan_bytes)
            .unwrap_or(usize::MAX),
        state.config.runtime.max_tool_output_bytes,
    )
}

async fn current_change_set_response(
    id: String,
    change_set_id: &str,
    actor_id: &str,
    state: &AppState,
) -> ServerResponse {
    let Some(record) = load_change_set(&id, change_set_id, state).await else {
        return ServerResponse::error(id, ErrorCode::Internal, "ChangeSet state is unavailable");
    };
    match change_set_response(record, actor_id, state) {
        Ok(response) => ServerResponse::success(id, ResponseData::ChangeSet(response)),
        Err(error) => error.with_id(id),
    }
}

async fn handle_change_reject(
    id: String,
    change_set_id: String,
    actor_id: String,
    state: &AppState,
) -> ServerResponse {
    if !valid_change_set_id(&change_set_id) {
        return ServerResponse::error(id, ErrorCode::InvalidRequest, "invalid ChangeSet id");
    }
    let Some(record) = load_change_set(&id, &change_set_id, state).await else {
        return ServerResponse::error(id, ErrorCode::NotFound, "ChangeSet not found");
    };
    let mut response = match change_set_response(record.clone(), &actor_id, state) {
        Ok(response) => response,
        Err(error) => return error.with_id(id),
    };
    let now = match boot_monotonic_ms() {
        Ok(value) => value,
        Err(error) => return error.with_id(id),
    };
    let store = Arc::clone(&state.store);
    let record_for_transition = record.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        store.transition_change_set(
            &record_for_transition.id,
            record_for_transition.state,
            ChangeSetState::Rejected,
            &record_for_transition.plan_digest,
            &record_for_transition.boot_id,
            now,
        )
    })
    .await;
    match outcome {
        Ok(Ok(_)) => {
            response.state = ChangeSetState::Rejected;
            ServerResponse::success(id, ResponseData::ChangeSet(response))
        }
        Ok(Err(error)) => store_error_response(id, &error),
        Err(error) => {
            error!(%error, "ChangeSet rejection worker failed");
            ServerResponse::error(id, ErrorCode::Internal, "ChangeSet storage is unavailable")
        }
    }
}

async fn load_change_set(
    request_id: &str,
    change_set_id: &str,
    state: &AppState,
) -> Option<ChangeSetRecord> {
    let store = Arc::clone(&state.store);
    let change_set_id = change_set_id.to_owned();
    match tokio::task::spawn_blocking(move || store.change_set(&change_set_id)).await {
        Ok(Ok(record)) => record,
        Ok(Err(error)) => {
            error!(request_id, %error, "ChangeSet lookup failed");
            None
        }
        Err(error) => {
            error!(request_id, %error, "ChangeSet lookup worker failed");
            None
        }
    }
}

fn change_set_response(
    record: ChangeSetRecord,
    actor_id: &str,
    state: &AppState,
) -> Result<ChangeSetResponse, PendingResponseError> {
    validate_owned_change_set(&record, actor_id, state)?;
    let plan: ChangePlan = serde_json::from_slice(&record.plan_payload)
        .map_err(|_| PendingResponseError::internal("stored ChangeSet plan is corrupt"))?;
    let digest = plan_digest(&plan)
        .map_err(|_| PendingResponseError::internal("stored ChangeSet plan is invalid"))?;
    if digest != record.plan_digest
        || plan.plan_id != record.id
        || plan.actor_id != record.actor_id
        || plan.boot_id != record.boot_id
        || plan.risk != record.risk
        || plan.expires_monotonic_ms != record.expires_monotonic_ms
    {
        return Err(PendingResponseError::internal(
            "stored ChangeSet security binding is invalid",
        ));
    }
    Ok(ChangeSetResponse {
        change_set_id: record.id,
        plan_digest: record.plan_digest,
        plan,
        state: record.state,
        rollback_deadline_monotonic_ms: record.rollback_deadline_monotonic_ms,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

fn validate_owned_change_set(
    record: &ChangeSetRecord,
    actor_id: &str,
    state: &AppState,
) -> Result<(), PendingResponseError> {
    if record.actor_id != actor_id {
        return Err(PendingResponseError::not_found());
    }
    if record.boot_id != state.auth.boot_id() {
        return Err(PendingResponseError::conflict(
            "ChangeSet belongs to a previous device boot",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct PendingResponseError {
    code: ErrorCode,
    message: &'static str,
}

impl PendingResponseError {
    const fn internal(message: &'static str) -> Self {
        Self {
            code: ErrorCode::Internal,
            message,
        }
    }

    const fn not_found() -> Self {
        Self {
            code: ErrorCode::NotFound,
            message: "ChangeSet not found",
        }
    }

    const fn conflict(message: &'static str) -> Self {
        Self {
            code: ErrorCode::Conflict,
            message,
        }
    }

    const fn unavailable(message: &'static str) -> Self {
        Self {
            code: ErrorCode::Unavailable,
            message,
        }
    }

    fn with_id(self, id: String) -> ServerResponse {
        ServerResponse::error(id, self.code, self.message)
    }
}

fn valid_change_set_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn valid_approval_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_execution_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn process_monotonic_ms(state: &AppState) -> u64 {
    u64::try_from(state.started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn boot_monotonic_ms() -> Result<u64, PendingResponseError> {
    boot_monotonic_ms_platform()
}

#[cfg(target_os = "linux")]
fn boot_monotonic_ms_platform() -> Result<u64, PendingResponseError> {
    const MAX_UPTIME_BYTES: u64 = 128;
    let mut uptime = String::new();
    fs::File::open("/proc/uptime")
        .and_then(|file| {
            file.take(MAX_UPTIME_BYTES.saturating_add(1))
                .read_to_string(&mut uptime)
        })
        .map_err(|_| PendingResponseError::internal("system monotonic clock is unavailable"))?;
    if uptime.len() as u64 > MAX_UPTIME_BYTES {
        return Err(PendingResponseError::internal(
            "system monotonic clock is invalid",
        ));
    }
    let value = uptime
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| PendingResponseError::internal("system monotonic clock is invalid"))?;
    parse_uptime_ms(value)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn boot_monotonic_ms_platform() -> Result<u64, PendingResponseError> {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    Ok(u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX))
}

#[cfg(any(target_os = "linux", test))]
fn parse_uptime_ms(value: &str) -> Result<u64, PendingResponseError> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PendingResponseError::internal(
            "system monotonic clock is invalid",
        ));
    }
    let seconds = seconds
        .parse::<u64>()
        .map_err(|_| PendingResponseError::internal("system monotonic clock is invalid"))?;
    let mut milliseconds = 0_u64;
    let mut place = 100_u64;
    for digit in fraction.bytes().take(3) {
        milliseconds = milliseconds.saturating_add(u64::from(digit.saturating_sub(b'0')) * place);
        place /= 10;
    }
    Ok(seconds.saturating_mul(1_000).saturating_add(milliseconds))
}

fn random_hex(bytes: usize) -> Result<String, PendingResponseError> {
    let mut random = vec![0_u8; bytes];
    SystemRandom::new().fill(&mut random).map_err(|_| {
        PendingResponseError::internal("operating system randomness is unavailable")
    })?;
    let mut encoded = String::with_capacity(bytes.saturating_mul(2));
    for byte in random {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

fn sha256_hex(value: &[u8]) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, value);
    let mut encoded = String::with_capacity(64);
    for byte in hash.as_ref() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn store_error_response(id: String, error: &StoreError) -> ServerResponse {
    let (code, message) = match error {
        StoreError::ChangeSetConflict
        | StoreError::ChangeSetExpired
        | StoreError::ApprovalRejected
        | StoreError::InvalidTransition(_)
        | StoreError::RollbackDeadlineRequired
        | StoreError::InvalidRollbackDeadline => (ErrorCode::Conflict, error.to_string()),
        StoreError::ChangeSetCapacity | StoreError::PayloadTooLarge { .. } => {
            (ErrorCode::ResourceExhausted, error.to_string())
        }
        _ => {
            error!(%error, "configuration state storage failed");
            (
                ErrorCode::Internal,
                "configuration state storage is unavailable".into(),
            )
        }
    };
    ServerResponse::error(id, code, message)
}

fn status_response(state: &AppState) -> ResponseData {
    let database_bytes = state.store.database_bytes();
    let managed_bytes = state.budget.managed_bytes().unwrap_or(database_bytes);
    let available = state.budget.available_bytes().unwrap_or(0);
    let pressure = state
        .budget
        .pressure(managed_bytes)
        .unwrap_or(StoragePressure::Critical);
    let mut degraded_reasons = state.platform.warnings.clone();
    if pressure != StoragePressure::Normal {
        degraded_reasons.push(format!("runtime storage pressure is {pressure:?}"));
    }
    let logging_dropped_records = state.log_writer.dropped_records();
    if logging_dropped_records > 0 {
        degraded_reasons.push(format!(
            "logging rate limit dropped {logging_dropped_records} records"
        ));
    }
    ResponseData::Status(StatusResponse {
        daemon_version: AGENT_VERSION.into(),
        protocol_version: PROTOCOL_VERSION,
        uptime_secs: state.started.elapsed().as_secs(),
        profile: state.config.profile.as_str().into(),
        storage: StorageStatus {
            database_bytes,
            database_limit_bytes: state.store.max_database_bytes(),
            managed_bytes,
            total_budget_bytes: state.budget.total_limit_bytes(),
            tmp_available_bytes: available,
            pressure,
        },
        platform_kind: state.platform.kind.as_str().into(),
        llm_enabled: state.llm.is_some(),
        llm_provider: state.config.llm.provider.as_str().into(),
        llm_streaming: state.config.llm.streaming,
        logging_dropped_records,
        degraded_reasons,
    })
}

fn valid_request_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
}

async fn handle_completion(id: String, prompt: String, state: &AppState) -> ServerResponse {
    let Some(provider) = &state.llm else {
        return ServerResponse::error(
            id,
            ErrorCode::Unavailable,
            "LLM provider is not enabled in daemon configuration",
        );
    };
    if prompt.trim().is_empty() {
        return ServerResponse::error(id, ErrorCode::InvalidRequest, "prompt must not be empty");
    }
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.llm_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured LLM task limit has been reached",
        );
    };
    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        run_read_only_agent(provider, prompt, &id, state),
    )
    .await;
    match outcome {
        Ok(Ok(completion)) => {
            persist_task(
                &id,
                TaskAudit {
                    status: "succeeded",
                    model: &state.config.llm.model,
                    prompt_tokens: completion.prompt_tokens,
                    completion_tokens: completion.completion_tokens,
                    duration: started.elapsed(),
                    error_code: None,
                },
                state,
            )
            .await;
            ServerResponse::success(id, ResponseData::Completion(completion))
        }
        Ok(Err(failure)) => {
            persist_task(
                &id,
                TaskAudit {
                    status: "failed",
                    model: &state.config.llm.model,
                    prompt_tokens: failure.prompt_tokens,
                    completion_tokens: failure.completion_tokens,
                    duration: started.elapsed(),
                    error_code: Some(failure.code),
                },
                state,
            )
            .await;
            ServerResponse::error(id, failure.code, failure.message)
        }
        Err(_) => {
            persist_task(
                &id,
                TaskAudit {
                    status: "timed_out",
                    model: &state.config.llm.model,
                    prompt_tokens: None,
                    completion_tokens: None,
                    duration: started.elapsed(),
                    error_code: Some(ErrorCode::ResourceExhausted),
                },
                state,
            )
            .await;
            ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "Agent task exceeded the configured total task timeout",
            )
        }
    }
}

struct AgentLoopFailure {
    code: ErrorCode,
    message: String,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

impl AgentLoopFailure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            prompt_tokens: None,
            completion_tokens: None,
        }
    }

    fn with_usage(mut self, prompt_tokens: Option<u64>, completion_tokens: Option<u64>) -> Self {
        self.prompt_tokens = prompt_tokens;
        self.completion_tokens = completion_tokens;
        self
    }
}

async fn run_read_only_agent(
    provider: &OpenAiCompatibleProvider,
    prompt: String,
    request_id: &str,
    state: &AppState,
) -> Result<CompletionResponse, AgentLoopFailure> {
    let mut messages = vec![
        ModelMessage::Instruction(state.config.llm.system_prompt.clone()),
        ModelMessage::User(prompt),
    ];
    let tools = agent_tools(state).await;
    let mut snapshots = AgentSnapshots::default();
    let mut prompt_tokens = None;
    let mut completion_tokens = None;

    for step in 0..state.config.llm.max_agent_steps {
        let request = CompletionRequest {
            messages: messages.clone(),
            tools: tools.clone(),
            max_output_tokens: state.config.llm.max_output_tokens,
            streaming: state.config.llm.streaming,
        };
        let completion = match provider.complete(request).await {
            Ok(completion) => completion,
            Err(error) => {
                warn!(%error, step, "LLM provider request failed");
                return Err(AgentLoopFailure::new(
                    ErrorCode::Upstream,
                    format!("LLM provider request failed: {error}"),
                )
                .with_usage(prompt_tokens, completion_tokens));
            }
        };
        add_usage(&mut prompt_tokens, completion.prompt_tokens);
        add_usage(&mut completion_tokens, completion.completion_tokens);
        if completion.tool_calls.is_empty() {
            return Ok(CompletionResponse {
                text: completion.text,
                model: completion.model,
                finish_reason: completion.finish_reason,
                prompt_tokens,
                completion_tokens,
            });
        }
        if completion.tool_calls.len() != 1 {
            return Err(AgentLoopFailure::new(
                ErrorCode::Upstream,
                "model requested multiple tools in one step; this Agent profile permits one",
            )
            .with_usage(prompt_tokens, completion_tokens));
        }
        if !tool_step_available(step, state.config.llm.max_agent_steps) {
            return Err(AgentLoopFailure::new(
                ErrorCode::ResourceExhausted,
                "Agent loop reached max_agent_steps before a final answer",
            )
            .with_usage(prompt_tokens, completion_tokens));
        }
        let call = completion.tool_calls[0].clone();
        messages.push(ModelMessage::Assistant {
            content: completion.text,
            tool_calls: completion.tool_calls,
        });
        messages.push(
            execute_agent_tool(&call, request_id, state, &mut snapshots)
                .await
                .map_err(|failure| failure.with_usage(prompt_tokens, completion_tokens))?,
        );
    }
    Err(AgentLoopFailure::new(
        ErrorCode::ResourceExhausted,
        "Agent loop exhausted its configured step budget",
    )
    .with_usage(prompt_tokens, completion_tokens))
}

const fn tool_step_available(step: u8, max_agent_steps: u8) -> bool {
    step.saturating_add(1) < max_agent_steps
}

#[derive(Default)]
struct AgentSnapshots {
    wan: Option<agent_protocol::WanDiagnosticReport>,
    interfaces: Option<agent_protocol::InterfaceDiagnosticReport>,
    neighbors: Option<agent_protocol::NeighborDiagnosticReport>,
    firewall: Option<agent_protocol::FirewallDiagnosticReport>,
    policy_routing: Option<agent_protocol::PolicyRoutingDiagnosticReport>,
    listeners: Option<agent_protocol::ListenerDiagnosticReport>,
    wireless: Option<agent_protocol::WirelessDiagnosticReport>,
    interface_stats: Option<agent_protocol::InterfaceStatsDiagnosticReport>,
    conntrack: Option<agent_protocol::ConntrackDiagnosticReport>,
    qdisc: Option<agent_protocol::QdiscDiagnosticReport>,
}

async fn execute_agent_tool(
    call: &ToolCall,
    request_id: &str,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    if ReadOnlyAgentTool::from_name(&call.name).is_none() {
        return execute_extension_agent_tool(call, request_id, state).await;
    }
    let tool = validate_read_only_tool_call(call).map_err(|reason| {
        warn!(tool = %call.name, %reason, "model requested a rejected tool call");
        AgentLoopFailure::new(
            ErrorCode::Upstream,
            format!("model tool call was rejected: {reason}"),
        )
    })?;
    match tool {
        ReadOnlyAgentTool::InspectInterfaces => {
            execute_interface_agent_tool(call, request_id, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectNeighbors => {
            execute_neighbor_agent_tool(call, request_id, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectFirewallRuntime
        | ReadOnlyAgentTool::InspectFirewallBaseChains => {
            execute_firewall_agent_tool(call, request_id, tool, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectPolicyRules | ReadOnlyAgentTool::InspectRouteTables => {
            execute_policy_routing_agent_tool(call, request_id, tool, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectListeningPorts | ReadOnlyAgentTool::InspectExposedServices => {
            execute_listener_agent_tool(call, request_id, tool, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectWirelessRadios | ReadOnlyAgentTool::InspectWirelessInterfaces => {
            execute_wireless_agent_tool(call, request_id, tool, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectInterfaceCounters | ReadOnlyAgentTool::InspectInterfaceErrors => {
            execute_interface_stats_agent_tool(call, request_id, tool, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectConntrackCapacity => {
            execute_conntrack_agent_tool(call, request_id, state, snapshots).await
        }
        ReadOnlyAgentTool::InspectQdiscStats | ReadOnlyAgentTool::InspectQdiscPressure => {
            execute_qdisc_agent_tool(call, request_id, tool, state, snapshots).await
        }
        _ => execute_wan_agent_tool(call, request_id, tool, state, snapshots).await,
    }
}

#[allow(clippy::too_many_lines)] // Keeps dynamic schema admission and exact execution visibly joined.
async fn execute_extension_agent_tool(
    call: &ToolCall,
    request_id: &str,
    state: &AppState,
) -> Result<ModelMessage, AgentLoopFailure> {
    let action_id = call.name.strip_prefix("ext_").ok_or_else(|| {
        AgentLoopFailure::new(ErrorCode::Upstream, "model requested an unknown tool")
    })?;
    if call.arguments.len()
        > state
            .config
            .extensions
            .max_input_bytes
            .saturating_mul(state.config.extensions.max_inputs.max(1))
    {
        return Err(AgentLoopFailure::new(
            ErrorCode::ResourceExhausted,
            "extension action arguments exceed their configured bound",
        ));
    }
    let inputs: serde_json::Value = serde_json::from_str(&call.arguments).map_err(|_| {
        AgentLoopFailure::new(
            ErrorCode::Upstream,
            "extension action arguments are not valid JSON",
        )
    })?;
    let invocation = {
        let actions = state.actions.read().await;
        let action = actions
            .get(action_id, state.platform.kind.as_str())
            .filter(|action| action.llm_enabled)
            .ok_or_else(|| {
                AgentLoopFailure::new(
                    ErrorCode::Upstream,
                    "extension action is not enabled for the model",
                )
            })?;
        if action.mode != ActionMode::ReadOnly {
            return Err(AgentLoopFailure::new(
                ErrorCode::Unauthorized,
                "model-facing extension actions must be read-only",
            ));
        }
        actions
            .invocation(
                action_id,
                state.platform.kind.as_str(),
                &inputs,
                &state.config.extensions,
            )
            .map_err(|error| {
                AgentLoopFailure::new(
                    ErrorCode::Upstream,
                    format!("extension action arguments were rejected: {error}"),
                )
            })?
    };
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    let permit = state.action_slots.try_acquire().map_err(|_| {
        AgentLoopFailure::new(
            ErrorCode::ResourceExhausted,
            "all action execution slots are busy",
        )
    })?;
    let started = Instant::now();
    let result = execute_action(
        action_id.into(),
        invocation,
        state.config.extensions.trusted_executable_owner_uid,
        Duration::from_secs(state.config.extensions.timeout_secs),
        state.config.extensions.max_output_bytes,
    )
    .await;
    drop(permit);
    let audit_id = format!(
        "ext-{}",
        sha256_hex(format!("{request_id}:{}:{action_id}", call.id).as_bytes())
    );
    let output = match result {
        Ok(output) => {
            persist_action_audit(
                &audit_id,
                action_id,
                "succeeded",
                started.elapsed(),
                None,
                state,
            )
            .await;
            output
        }
        Err(ActionExecutionError::TimedOut) => {
            persist_action_audit(
                &audit_id,
                action_id,
                "timed_out",
                started.elapsed(),
                Some(ErrorCode::ResourceExhausted),
                state,
            )
            .await;
            return Err(AgentLoopFailure::new(
                ErrorCode::ResourceExhausted,
                "extension action execution timed out",
            ));
        }
        Err(_) => {
            persist_action_audit(
                &audit_id,
                action_id,
                "failed",
                started.elapsed(),
                Some(ErrorCode::Conflict),
                state,
            )
            .await;
            return Err(AgentLoopFailure::new(
                ErrorCode::Conflict,
                "extension action execution failed",
            ));
        }
    };
    let content = bounded_action_observation(output, state.config.llm.max_tool_context_bytes)
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_interface_agent_tool(
    call: &ToolCall,
    request_id: &str,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.interfaces.is_none() {
        let report = execute_agent_interface_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-interface-tool-snapshot"),
            "interfaces",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.interfaces = Some(report);
    }
    let report = snapshots.interfaces.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "interface snapshot cache is unavailable",
        )
    })?;
    let content = bounded_interface_observation(report, state.config.llm.max_tool_context_bytes)
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_neighbor_agent_tool(
    call: &ToolCall,
    request_id: &str,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.neighbors.is_none() {
        let report = execute_agent_neighbor_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-neighbor-tool-snapshot"),
            "neighbors",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.neighbors = Some(report);
    }
    let report = snapshots.neighbors.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "neighbor snapshot cache is unavailable",
        )
    })?;
    let content = bounded_neighbor_observation(report, state.config.llm.max_tool_context_bytes)
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_firewall_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.firewall.is_none() {
        let report = execute_agent_firewall_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-firewall-tool-snapshot"),
            "firewall",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.firewall = Some(report);
    }
    let report = snapshots.firewall.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "firewall snapshot cache is unavailable",
        )
    })?;
    let content =
        bounded_firewall_observation(tool, report, state.config.llm.max_tool_context_bytes)
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_policy_routing_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.policy_routing.is_none() {
        let report = execute_agent_policy_routing_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-policy-routing-tool-snapshot"),
            "policy-routing",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.policy_routing = Some(report);
    }
    let report = snapshots.policy_routing.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "policy-routing snapshot cache is unavailable",
        )
    })?;
    let content =
        bounded_policy_routing_observation(tool, report, state.config.llm.max_tool_context_bytes)
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_listener_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.listeners.is_none() {
        let report = execute_agent_listener_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-listener-tool-snapshot"),
            "listeners",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.listeners = Some(report);
    }
    let report = snapshots.listeners.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "listener snapshot cache is unavailable",
        )
    })?;
    let content =
        bounded_listener_observation(tool, report, state.config.llm.max_tool_context_bytes)
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_wireless_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.wireless.is_none() {
        let report = execute_agent_wireless_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-wireless-tool-snapshot"),
            "wireless",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.wireless = Some(report);
    }
    let report = snapshots.wireless.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "wireless snapshot cache is unavailable",
        )
    })?;
    let content =
        bounded_wireless_observation(tool, report, state.config.llm.max_tool_context_bytes)
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_interface_stats_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.interface_stats.is_none() {
        let report = execute_agent_interface_stats_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-interface-stats-tool-snapshot"),
            "interface-stats",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.interface_stats = Some(report);
    }
    let report = snapshots.interface_stats.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "interface statistics snapshot cache is unavailable",
        )
    })?;
    let content =
        bounded_interface_stats_observation(tool, report, state.config.llm.max_tool_context_bytes)
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_conntrack_agent_tool(
    call: &ToolCall,
    request_id: &str,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.conntrack.is_none() {
        let report = execute_agent_conntrack_diagnostic(state).map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-conntrack-tool-snapshot"),
            "conntrack",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.conntrack = Some(report);
    }
    let report = snapshots.conntrack.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(
            ErrorCode::Internal,
            "connection-tracking snapshot cache is unavailable",
        )
    })?;
    let content = encode_tool_observation(
        ReadOnlyAgentTool::InspectConntrackCapacity.name(),
        &report.summary,
        state.config.llm.max_tool_context_bytes,
    )
    .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_qdisc_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    ensure_task_storage(state)
        .await
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    if snapshots.qdisc.is_none() {
        let report = execute_agent_qdisc_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-qdisc-tool-snapshot"),
            "qdisc",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.qdisc = Some(report);
    }
    let report = snapshots.qdisc.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(ErrorCode::Internal, "qdisc snapshot cache is unavailable")
    })?;
    let content = bounded_qdisc_observation(tool, report, state.config.llm.max_tool_context_bytes)
        .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

async fn execute_wan_agent_tool(
    call: &ToolCall,
    request_id: &str,
    tool: ReadOnlyAgentTool,
    state: &AppState,
    snapshots: &mut AgentSnapshots,
) -> Result<ModelMessage, AgentLoopFailure> {
    if snapshots.wan.is_none() {
        ensure_task_storage(state)
            .await
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
        let report = execute_agent_wan_diagnostic(state)
            .await
            .map_err(agent_tool_failure)?;
        persist_diagnostic(
            &format!("{request_id}-tool-snapshot"),
            "wan",
            false,
            report.summary.assessment.as_str(),
            &report.summary,
            state,
        )
        .await;
        snapshots.wan = Some(report);
    }
    let report = snapshots.wan.as_ref().ok_or_else(|| {
        AgentLoopFailure::new(ErrorCode::Internal, "WAN snapshot cache is unavailable")
    })?;
    let content =
        bounded_tool_observation(tool, report, state.config.llm.max_tool_context_bytes)
            .map_err(|message| AgentLoopFailure::new(ErrorCode::ResourceExhausted, message))?;
    Ok(ModelMessage::Tool {
        tool_call_id: call.id.clone(),
        content,
    })
}

fn agent_tool_failure(error: AgentToolError) -> AgentLoopFailure {
    match error {
        AgentToolError::Busy => AgentLoopFailure::new(
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        ),
        AgentToolError::TimedOut => AgentLoopFailure::new(
            ErrorCode::ResourceExhausted,
            "Agent diagnostic exceeded the configured task timeout",
        ),
        AgentToolError::Failed(error) => AgentLoopFailure::new(
            ErrorCode::Internal,
            format!("Agent diagnostic failed: {error}"),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadOnlyAgentTool {
    DiagnoseWan,
    InspectDefaultRoutes,
    InspectDns,
    InspectDhcp,
    InspectWanFirewall,
    InspectInterfaces,
    InspectNeighbors,
    InspectFirewallRuntime,
    InspectFirewallBaseChains,
    InspectPolicyRules,
    InspectRouteTables,
    InspectListeningPorts,
    InspectExposedServices,
    InspectWirelessRadios,
    InspectWirelessInterfaces,
    InspectInterfaceCounters,
    InspectInterfaceErrors,
    InspectConntrackCapacity,
    InspectQdiscStats,
    InspectQdiscPressure,
}

impl ReadOnlyAgentTool {
    const ALL: [Self; 20] = [
        Self::DiagnoseWan,
        Self::InspectDefaultRoutes,
        Self::InspectDns,
        Self::InspectDhcp,
        Self::InspectWanFirewall,
        Self::InspectInterfaces,
        Self::InspectNeighbors,
        Self::InspectFirewallRuntime,
        Self::InspectFirewallBaseChains,
        Self::InspectPolicyRules,
        Self::InspectRouteTables,
        Self::InspectListeningPorts,
        Self::InspectExposedServices,
        Self::InspectWirelessRadios,
        Self::InspectWirelessInterfaces,
        Self::InspectInterfaceCounters,
        Self::InspectInterfaceErrors,
        Self::InspectConntrackCapacity,
        Self::InspectQdiscStats,
        Self::InspectQdiscPressure,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::DiagnoseWan => "diagnose_wan",
            Self::InspectDefaultRoutes => "inspect_default_routes",
            Self::InspectDns => "inspect_dns",
            Self::InspectDhcp => "inspect_dhcp",
            Self::InspectWanFirewall => "inspect_wan_firewall",
            Self::InspectInterfaces => "inspect_interfaces",
            Self::InspectNeighbors => "inspect_neighbors",
            Self::InspectFirewallRuntime => "inspect_firewall_runtime",
            Self::InspectFirewallBaseChains => "inspect_firewall_base_chains",
            Self::InspectPolicyRules => "inspect_policy_rules",
            Self::InspectRouteTables => "inspect_route_tables",
            Self::InspectListeningPorts => "inspect_listening_ports",
            Self::InspectExposedServices => "inspect_exposed_services",
            Self::InspectWirelessRadios => "inspect_wireless_radios",
            Self::InspectWirelessInterfaces => "inspect_wireless_interfaces",
            Self::InspectInterfaceCounters => "inspect_interface_counters",
            Self::InspectInterfaceErrors => "inspect_interface_errors",
            Self::InspectConntrackCapacity => "inspect_conntrack_capacity",
            Self::InspectQdiscStats => "inspect_qdisc_stats",
            Self::InspectQdiscPressure => "inspect_qdisc_pressure",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::DiagnoseWan => {
                "Collect a bounded, passive WAN diagnosis covering link, address, routes, DNS, and firewall."
            }
            Self::InspectDefaultRoutes => {
                "Inspect normalized IPv4 and IPv6 WAN default routes without changing the routing table."
            }
            Self::InspectDns => {
                "Inspect normalized WAN DNS servers and passive DNS readiness without sending network probes."
            }
            Self::InspectDhcp => {
                "Inspect normalized WAN protocol, DHCP negotiation state, and address evidence without renewing a lease."
            }
            Self::InspectWanFirewall => {
                "Inspect the detected firewall backend and normalized WAN zone policies without changing rules."
            }
            Self::InspectInterfaces => {
                "Inventory bounded kernel network interface, link, carrier, address, bridge/VLAN kind, and master state without changing devices."
            }
            Self::InspectNeighbors => {
                "Inspect bounded ARP and IPv6 NDP neighbor state without generating traffic; link-layer addresses are withheld from model context."
            }
            Self::InspectFirewallRuntime => {
                "Inspect bounded runtime firewall backend, table, chain, rule, and counter totals without exposing rule expressions."
            }
            Self::InspectFirewallBaseChains => {
                "Inspect bounded firewall base-chain hooks, policies, and rule counts without exposing individual rules."
            }
            Self::InspectPolicyRules => {
                "Inspect bounded policy-routing priorities, selectors, marks, interfaces, actions, and target tables without changing rules."
            }
            Self::InspectRouteTables => {
                "Inspect aggregate route counts, default routes, and exceptional routes per bounded routing table without exposing every route."
            }
            Self::InspectListeningPorts => {
                "Inspect bounded TCP/UDP listening ports and binding scope without collecting process identities or exposing exact addresses."
            }
            Self::InspectExposedServices => {
                "Inspect only non-loopback TCP/UDP listening ports that may be reachable from a link or wider network."
            }
            Self::InspectWirelessRadios => {
                "Inspect bounded wireless radio up, pending, disabled, and channel state without scanning."
            }
            Self::InspectWirelessInterfaces => {
                "Inspect bounded wireless interface, mode, channel, frequency, and SSID-presence metadata without exposing SSID values or AP addresses."
            }
            Self::InspectInterfaceCounters => {
                "Inspect one bounded snapshot of cumulative kernel RX/TX bytes, packets, errors, and drops without claiming a rate."
            }
            Self::InspectInterfaceErrors => {
                "Inspect only interfaces whose cumulative RX/TX error or drop counters are above zero."
            }
            Self::InspectConntrackCapacity => {
                "Inspect the kernel connection-tracking count, configured limit, and bounded utilization without exposing individual flows."
            }
            Self::InspectQdiscStats => {
                "Inspect one bounded snapshot of queueing-discipline packet, byte, drop, overlimit, requeue, backlog, and queue-length counters."
            }
            Self::InspectQdiscPressure => {
                "Inspect only queueing disciplines with cumulative drop, overlimit, requeue, or backlog counters above zero; one snapshot does not establish a rate."
            }
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }
}

fn read_only_agent_tools() -> Vec<ToolDefinition> {
    ReadOnlyAgentTool::ALL
        .into_iter()
        .map(|tool| ToolDefinition {
            name: tool.name().into(),
            description: tool.description().into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        })
        .collect()
}

async fn agent_tools(state: &AppState) -> Vec<ToolDefinition> {
    let mut tools = read_only_agent_tools();
    let actions = state.actions.read().await;
    tools.extend(
        actions
            .available(state.platform.kind.as_str())
            .into_iter()
            .filter(|action| action.llm_enabled && action.mode == ActionMode::ReadOnly)
            .map(|action| ToolDefinition {
                name: format!("ext_{}", action.id),
                description: action.description.clone(),
                parameters: ActionRegistry::input_schema(action),
            }),
    );
    tools
}

fn validate_read_only_tool_call(call: &ToolCall) -> Result<ReadOnlyAgentTool, &'static str> {
    let tool = ReadOnlyAgentTool::from_name(&call.name)
        .ok_or("tool name is not in the local allowlist")?;
    if call.arguments.len() > 256 {
        return Err("tool arguments exceed the local 256-byte limit");
    }
    let arguments: serde_json::Value =
        serde_json::from_str(&call.arguments).map_err(|_| "arguments are not valid JSON")?;
    let Some(arguments) = arguments.as_object() else {
        return Err("arguments must be a JSON object");
    };
    if !arguments.is_empty() {
        return Err("read-only inspection tools accept no arguments");
    }
    Ok(tool)
}

fn add_usage(total: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        *total = Some(total.unwrap_or(0).saturating_add(value));
    }
}

enum AgentToolError {
    Busy,
    TimedOut,
    Failed(io::Error),
}

async fn execute_agent_wan_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::WanDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_wan(&state.platform, false),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_interface_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::InterfaceDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_interfaces(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_neighbor_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::NeighborDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_neighbors(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_firewall_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::FirewallDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_firewall(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_policy_routing_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::PolicyRoutingDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_policy_routing(),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_listener_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::ListenerDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_listeners(),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_wireless_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::WirelessDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_wireless(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

async fn execute_agent_interface_stats_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::InterfaceStatsDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_interface_stats(),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

fn execute_agent_conntrack_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::ConntrackDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    Ok(state.tools.diagnose_conntrack())
}

async fn execute_agent_qdisc_diagnostic(
    state: &AppState,
) -> Result<agent_protocol::QdiscDiagnosticReport, AgentToolError> {
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return Err(AgentToolError::Busy);
    };
    match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_qdisc(),
    )
    .await
    {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(AgentToolError::Failed(error)),
        Err(_) => Err(AgentToolError::TimedOut),
    }
}

#[derive(serde::Serialize)]
struct WanObservation<'a> {
    interface: &'a str,
    summary: &'a agent_protocol::WanSummary,
    findings: &'a [String],
    complete: bool,
}

#[derive(serde::Serialize)]
struct RouteObservation<'a> {
    interface: &'a str,
    assessment: agent_protocol::WanAssessment,
    status_source: &'a Option<String>,
    default_routes: &'a [agent_protocol::WanRoute],
}

#[derive(serde::Serialize)]
struct DnsObservation<'a> {
    interface: &'a str,
    assessment: agent_protocol::WanAssessment,
    dns_servers: &'a [String],
    dns_reachable: Option<bool>,
}

#[derive(serde::Serialize)]
struct DhcpObservation<'a> {
    interface: &'a str,
    wan_assessment: agent_protocol::WanAssessment,
    status_source: &'a Option<String>,
    protocol: &'a Option<String>,
    pending: Option<bool>,
    up: Option<bool>,
    available: Option<bool>,
    device: &'a Option<String>,
    addresses: &'a [String],
}

#[derive(serde::Serialize)]
struct FirewallObservation<'a> {
    interface: &'a str,
    assessment: agent_protocol::WanAssessment,
    firewall_backend: &'a str,
    firewall_zone: &'a Option<agent_protocol::FirewallZoneSummary>,
}

#[derive(serde::Serialize)]
struct InterfaceObservation<'a> {
    assessment: agent_protocol::InterfaceAssessment,
    interfaces: &'a [agent_protocol::NetworkInterfaceSummary],
    truncated: bool,
    findings: &'a [String],
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct NeighborObservationEntry<'a> {
    destination: &'a str,
    device: &'a str,
    states: &'a [String],
    router: bool,
}

#[derive(serde::Serialize)]
struct NeighborObservation<'a> {
    assessment: agent_protocol::NeighborAssessment,
    entries: Vec<NeighborObservationEntry<'a>>,
    truncated: bool,
    findings: &'a [String],
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct FirewallRuntimeObservation<'a> {
    assessment: agent_protocol::FirewallAssessment,
    backend: &'a str,
    tables: u32,
    chains: u32,
    rules: u32,
    rules_with_counters: u32,
    truncated: bool,
    complete: bool,
}

#[derive(serde::Serialize)]
struct FirewallBaseChainObservation<'a> {
    assessment: agent_protocol::FirewallAssessment,
    backend: &'a str,
    base_chains: &'a [agent_protocol::FirewallBaseChain],
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct PolicyRuleObservation<'a> {
    assessment: agent_protocol::PolicyRoutingAssessment,
    rules: &'a [agent_protocol::PolicyRule],
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct RouteTableObservation<'a> {
    assessment: agent_protocol::PolicyRoutingAssessment,
    tables: &'a [agent_protocol::RouteTableSummary],
    total_routes: u32,
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct ListenerObservationEntry<'a> {
    protocol: &'a str,
    family: &'a str,
    port: u16,
    scope: agent_protocol::ListenerScope,
    state: &'a Option<String>,
}

#[derive(serde::Serialize)]
struct ListenerObservation<'a> {
    assessment: agent_protocol::ListenerAssessment,
    listeners: &'a [ListenerObservationEntry<'a>],
    source_entries: usize,
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct WirelessRadioObservation<'a> {
    assessment: agent_protocol::WirelessAssessment,
    radios: &'a [agent_protocol::WirelessRadioSummary],
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct WirelessInterfaceEntry<'a> {
    name: &'a str,
    radio: &'a Option<String>,
    mode: &'a Option<String>,
    ssid_configured: bool,
    channel: Option<u32>,
    frequency_mhz: Option<u32>,
}

#[derive(serde::Serialize)]
struct WirelessInterfaceObservation<'a> {
    assessment: agent_protocol::WirelessAssessment,
    interfaces: &'a [WirelessInterfaceEntry<'a>],
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct InterfaceStatsObservation<'a> {
    assessment: agent_protocol::InterfaceStatsAssessment,
    interfaces: &'a [&'a agent_protocol::InterfaceStatsEntry],
    source_entries: usize,
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

#[derive(serde::Serialize)]
struct QdiscObservation<'a> {
    assessment: agent_protocol::QdiscAssessment,
    qdiscs: &'a [&'a agent_protocol::QdiscEntry],
    source_entries: usize,
    truncated: bool,
    complete: bool,
    context_truncated: bool,
}

fn bounded_tool_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::WanDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    match tool {
        ReadOnlyAgentTool::DiagnoseWan => encode_tool_observation(
            tool.name(),
            &WanObservation {
                interface: &report.interface,
                summary: &report.summary,
                findings: &report.findings,
                complete: report.complete,
            },
            limit,
        ),
        ReadOnlyAgentTool::InspectDefaultRoutes => encode_tool_observation(
            tool.name(),
            &RouteObservation {
                interface: &report.interface,
                assessment: report.summary.assessment,
                status_source: &report.summary.status_source,
                default_routes: &report.summary.default_routes,
            },
            limit,
        ),
        ReadOnlyAgentTool::InspectDns => encode_tool_observation(
            tool.name(),
            &DnsObservation {
                interface: &report.interface,
                assessment: report.summary.assessment,
                dns_servers: &report.summary.dns_servers,
                dns_reachable: report.summary.dns_reachable,
            },
            limit,
        ),
        ReadOnlyAgentTool::InspectDhcp => encode_tool_observation(
            tool.name(),
            &DhcpObservation {
                interface: &report.interface,
                wan_assessment: report.summary.assessment,
                status_source: &report.summary.status_source,
                protocol: &report.summary.protocol,
                pending: report.summary.pending,
                up: report.summary.up,
                available: report.summary.available,
                device: &report.summary.device,
                addresses: &report.summary.addresses,
            },
            limit,
        ),
        ReadOnlyAgentTool::InspectWanFirewall => encode_tool_observation(
            tool.name(),
            &FirewallObservation {
                interface: &report.interface,
                assessment: report.summary.assessment,
                firewall_backend: &report.summary.firewall_backend,
                firewall_zone: &report.summary.firewall_zone,
            },
            limit,
        ),
        ReadOnlyAgentTool::InspectInterfaces => {
            Err("interface observations require an interface snapshot".into())
        }
        ReadOnlyAgentTool::InspectNeighbors => {
            Err("neighbor observations require a neighbor snapshot".into())
        }
        ReadOnlyAgentTool::InspectFirewallRuntime
        | ReadOnlyAgentTool::InspectFirewallBaseChains => {
            Err("firewall observations require a firewall snapshot".into())
        }
        ReadOnlyAgentTool::InspectPolicyRules | ReadOnlyAgentTool::InspectRouteTables => {
            Err("policy-routing observations require a policy-routing snapshot".into())
        }
        ReadOnlyAgentTool::InspectListeningPorts | ReadOnlyAgentTool::InspectExposedServices => {
            Err("listener observations require a listener snapshot".into())
        }
        ReadOnlyAgentTool::InspectWirelessRadios | ReadOnlyAgentTool::InspectWirelessInterfaces => {
            Err("wireless observations require a wireless snapshot".into())
        }
        ReadOnlyAgentTool::InspectInterfaceCounters | ReadOnlyAgentTool::InspectInterfaceErrors => {
            Err("interface statistics observations require an interface statistics snapshot".into())
        }
        ReadOnlyAgentTool::InspectConntrackCapacity => {
            Err("connection-tracking observations require a conntrack snapshot".into())
        }
        ReadOnlyAgentTool::InspectQdiscStats | ReadOnlyAgentTool::InspectQdiscPressure => {
            Err("qdisc observations require a qdisc snapshot".into())
        }
    }
}

fn bounded_qdisc_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::QdiscDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    let pressure_only = tool == ReadOnlyAgentTool::InspectQdiscPressure;
    let qdiscs: Vec<&agent_protocol::QdiscEntry> = report
        .summary
        .qdiscs
        .iter()
        .filter(|qdisc| !pressure_only || qdisc.has_pressure_counters())
        .collect();
    for retained in (0..=qdiscs.len()).rev() {
        let result = encode_tool_observation(
            tool.name(),
            &QdiscObservation {
                assessment: report.summary.assessment,
                qdiscs: &qdiscs[..retained],
                source_entries: report.summary.qdiscs.len(),
                truncated: report.summary.truncated,
                complete: report.complete,
                context_truncated: retained < qdiscs.len(),
            },
            limit,
        );
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        tool.name()
    ))
}

fn bounded_interface_stats_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::InterfaceStatsDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    let errors_only = tool == ReadOnlyAgentTool::InspectInterfaceErrors;
    let interfaces: Vec<&agent_protocol::InterfaceStatsEntry> = report
        .summary
        .interfaces
        .iter()
        .filter(|interface| !errors_only || interface.has_errors_or_drops())
        .collect();
    for retained in (0..=interfaces.len()).rev() {
        let result = encode_tool_observation(
            tool.name(),
            &InterfaceStatsObservation {
                assessment: report.summary.assessment,
                interfaces: &interfaces[..retained],
                source_entries: report.summary.interfaces.len(),
                truncated: report.summary.truncated,
                complete: report.complete,
                context_truncated: retained < interfaces.len(),
            },
            limit,
        );
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        tool.name()
    ))
}

fn bounded_wireless_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::WirelessDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    if tool == ReadOnlyAgentTool::InspectWirelessRadios {
        for retained in (0..=report.summary.radios.len()).rev() {
            let result = encode_tool_observation(
                tool.name(),
                &WirelessRadioObservation {
                    assessment: report.summary.assessment,
                    radios: &report.summary.radios[..retained],
                    truncated: report.summary.truncated,
                    complete: report.complete,
                    context_truncated: retained < report.summary.radios.len(),
                },
                limit,
            );
            if result.is_ok() {
                return result;
            }
        }
    } else {
        let interfaces: Vec<WirelessInterfaceEntry<'_>> = report
            .summary
            .interfaces
            .iter()
            .map(|interface| WirelessInterfaceEntry {
                name: &interface.name,
                radio: &interface.radio,
                mode: &interface.mode,
                ssid_configured: interface.ssid.is_some(),
                channel: interface.channel,
                frequency_mhz: interface.frequency_mhz,
            })
            .collect();
        for retained in (0..=interfaces.len()).rev() {
            let result = encode_tool_observation(
                tool.name(),
                &WirelessInterfaceObservation {
                    assessment: report.summary.assessment,
                    interfaces: &interfaces[..retained],
                    truncated: report.summary.truncated,
                    complete: report.complete,
                    context_truncated: retained < interfaces.len(),
                },
                limit,
            );
            if result.is_ok() {
                return result;
            }
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        tool.name()
    ))
}

fn bounded_listener_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::ListenerDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    let exposed_only = tool == ReadOnlyAgentTool::InspectExposedServices;
    let listeners: Vec<ListenerObservationEntry<'_>> = report
        .summary
        .listeners
        .iter()
        .filter(|listener| {
            !exposed_only || listener.scope != agent_protocol::ListenerScope::Loopback
        })
        .map(|listener| ListenerObservationEntry {
            protocol: &listener.protocol,
            family: &listener.family,
            port: listener.port,
            scope: listener.scope,
            state: &listener.state,
        })
        .collect();
    for retained in (0..=listeners.len()).rev() {
        let result = encode_tool_observation(
            tool.name(),
            &ListenerObservation {
                assessment: report.summary.assessment,
                listeners: &listeners[..retained],
                source_entries: report.summary.listeners.len(),
                truncated: report.summary.truncated,
                complete: report.complete,
                context_truncated: retained < listeners.len(),
            },
            limit,
        );
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        tool.name()
    ))
}

fn bounded_policy_routing_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::PolicyRoutingDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    let total = if tool == ReadOnlyAgentTool::InspectPolicyRules {
        report.summary.rules.len()
    } else {
        report.summary.tables.len()
    };
    for retained in (0..=total).rev() {
        let result = if tool == ReadOnlyAgentTool::InspectPolicyRules {
            encode_tool_observation(
                tool.name(),
                &PolicyRuleObservation {
                    assessment: report.summary.assessment,
                    rules: &report.summary.rules[..retained],
                    truncated: report.summary.truncated,
                    complete: report.complete,
                    context_truncated: retained < total,
                },
                limit,
            )
        } else {
            encode_tool_observation(
                tool.name(),
                &RouteTableObservation {
                    assessment: report.summary.assessment,
                    tables: &report.summary.tables[..retained],
                    total_routes: report.summary.total_routes,
                    truncated: report.summary.truncated,
                    complete: report.complete,
                    context_truncated: retained < total,
                },
                limit,
            )
        };
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        tool.name()
    ))
}

fn bounded_firewall_observation(
    tool: ReadOnlyAgentTool,
    report: &agent_protocol::FirewallDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    if tool == ReadOnlyAgentTool::InspectFirewallRuntime {
        return encode_tool_observation(
            tool.name(),
            &FirewallRuntimeObservation {
                assessment: report.summary.assessment,
                backend: &report.summary.backend,
                tables: report.summary.tables,
                chains: report.summary.chains,
                rules: report.summary.rules,
                rules_with_counters: report.summary.rules_with_counters,
                truncated: report.summary.truncated,
                complete: report.complete,
            },
            limit,
        );
    }
    for retained in (0..=report.summary.base_chains.len()).rev() {
        let result = encode_tool_observation(
            tool.name(),
            &FirewallBaseChainObservation {
                assessment: report.summary.assessment,
                backend: &report.summary.backend,
                base_chains: &report.summary.base_chains[..retained],
                truncated: report.summary.truncated,
                complete: report.complete,
                context_truncated: retained < report.summary.base_chains.len(),
            },
            limit,
        );
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        tool.name()
    ))
}

fn bounded_neighbor_observation(
    report: &agent_protocol::NeighborDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    for retained in (0..=report.summary.entries.len()).rev() {
        let entries = report.summary.entries[..retained]
            .iter()
            .map(|entry| NeighborObservationEntry {
                destination: &entry.destination,
                device: &entry.device,
                states: &entry.states,
                router: entry.router,
            })
            .collect();
        let result = encode_tool_observation(
            ReadOnlyAgentTool::InspectNeighbors.name(),
            &NeighborObservation {
                assessment: report.summary.assessment,
                entries,
                truncated: report.summary.truncated,
                findings: &report.findings,
                complete: report.complete,
                context_truncated: retained < report.summary.entries.len(),
            },
            limit,
        );
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        ReadOnlyAgentTool::InspectNeighbors.name()
    ))
}

fn bounded_interface_observation(
    report: &agent_protocol::InterfaceDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    for retained in (0..=report.summary.interfaces.len()).rev() {
        let context_truncated = retained < report.summary.interfaces.len();
        let result = encode_tool_observation(
            ReadOnlyAgentTool::InspectInterfaces.name(),
            &InterfaceObservation {
                assessment: report.summary.assessment,
                interfaces: &report.summary.interfaces[..retained],
                truncated: report.summary.truncated,
                findings: &report.findings,
                complete: report.complete,
                context_truncated,
            },
            limit,
        );
        if result.is_ok() {
            return result;
        }
    }
    Err(format!(
        "{} observation metadata exceeds llm.max_tool_context_bytes {limit}",
        ReadOnlyAgentTool::InspectInterfaces.name()
    ))
}

fn encode_tool_observation<T: serde::Serialize>(
    tool_name: &str,
    observation: &T,
    limit: usize,
) -> Result<String, String> {
    let encoded = serde_json::to_vec(observation)
        .map_err(|error| format!("failed to encode {tool_name} observation: {error}"))?;
    if encoded.len() > limit {
        return Err(format!(
            "{tool_name} observation is {} bytes, exceeding llm.max_tool_context_bytes {limit}",
            encoded.len()
        ));
    }
    String::from_utf8(encoded)
        .map_err(|error| format!("{tool_name} observation was not valid UTF-8: {error}"))
}

fn bounded_action_observation(
    mut output: agent_protocol::ActionOutputResponse,
    limit: usize,
) -> Result<String, String> {
    let payload_budget = limit.saturating_sub(512);
    let stdout_limit = payload_budget.saturating_mul(3) / 4;
    let stderr_limit = payload_budget.saturating_sub(stdout_limit);
    if output.stdout.len() > stdout_limit {
        truncate_utf8(&mut output.stdout, stdout_limit);
        output.output_truncated = true;
    }
    if output.stderr.len() > stderr_limit {
        truncate_utf8(&mut output.stderr, stderr_limit);
        output.output_truncated = true;
    }
    encode_tool_observation(&format!("ext_{}", output.action_id), &output, limit)
}

fn truncate_utf8(value: &mut String, limit: usize) {
    let mut boundary = limit.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

async fn handle_wan_diagnosis(id: String, active: bool, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_wan(&state.platform, active),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("WAN diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "WAN diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "wan",
        active,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::WanDiagnostic(Box::new(report)))
}

async fn handle_dns_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_dns(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("DNS diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "DNS diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "dns",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::DnsDiagnostic(Box::new(report)))
}

async fn handle_dhcp_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_dhcp(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("DHCP diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "DHCP diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "dhcp",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::DhcpDiagnostic(Box::new(report)))
}

async fn handle_route_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_routes(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("route diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "route diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "routes",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::RouteDiagnostic(Box::new(report)))
}

async fn handle_interface_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_interfaces(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("interface diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "interface diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "interfaces",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::InterfaceDiagnostic(Box::new(report)))
}

async fn handle_neighbor_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_neighbors(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("neighbor diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "neighbor diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "neighbors",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::NeighborDiagnostic(Box::new(report)))
}

async fn handle_firewall_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_firewall(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("firewall diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "firewall diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "firewall",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::FirewallDiagnostic(Box::new(report)))
}

async fn handle_policy_routing_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_policy_routing(),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("policy-routing diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "policy-routing diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "policy-routing",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::PolicyRoutingDiagnostic(Box::new(report)))
}

async fn handle_listener_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_listeners(),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("listener diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "listener diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "listeners",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::ListenerDiagnostic(Box::new(report)))
}

async fn handle_wireless_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_wireless(&state.platform),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("wireless diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "wireless diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "wireless",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::WirelessDiagnostic(Box::new(report)))
}

async fn handle_interface_stats_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_interface_stats(),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("interface statistics diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "interface statistics diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "interface-stats",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::InterfaceStatsDiagnostic(Box::new(report)))
}

async fn handle_conntrack_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = state.tools.diagnose_conntrack();
    persist_diagnostic(
        &id,
        "conntrack",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::ConntrackDiagnostic(Box::new(report)))
}

async fn handle_qdisc_diagnosis(id: String, state: &AppState) -> ServerResponse {
    if let Err(message) = ensure_task_storage(state).await {
        return ServerResponse::error(id, ErrorCode::ResourceExhausted, message);
    }
    let Ok(_permit) = state.diagnostic_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured diagnostic task limit has been reached",
        );
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(state.config.runtime.task_timeout_secs),
        state.tools.diagnose_qdisc(),
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => {
            return ServerResponse::error(
                id,
                ErrorCode::Internal,
                format!("qdisc diagnosis failed: {error}"),
            );
        }
        Err(_) => {
            return ServerResponse::error(
                id,
                ErrorCode::ResourceExhausted,
                "qdisc diagnosis exceeded the configured task timeout",
            );
        }
    };
    persist_diagnostic(
        &id,
        "qdisc",
        false,
        report.summary.assessment.as_str(),
        &report.summary,
        state,
    )
    .await;
    ServerResponse::success(id, ResponseData::QdiscDiagnostic(Box::new(report)))
}

async fn persist_diagnostic<T: serde::Serialize>(
    id: &str,
    kind: &str,
    active: bool,
    assessment: &str,
    summary: &T,
    state: &AppState,
) {
    let record = DiagnosticRecord {
        id: id.into(),
        kind: kind.into(),
        active,
        assessment: assessment.into(),
        payload: serde_json::to_vec(summary).unwrap_or_default(),
        created_at: 0,
    };
    let store = Arc::clone(&state.store);
    let max_records = state.config.storage.max_diagnostic_records;
    let max_payload =
        usize::try_from(state.config.storage.max_diagnostic_record_bytes).unwrap_or(usize::MAX);
    match tokio::task::spawn_blocking(move || {
        store.record_diagnostic(&record, max_records, max_payload)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(%error, "failed to persist diagnostic audit"),
        Err(error) => warn!(%error, "diagnostic audit worker failed"),
    }
}

async fn handle_diagnostic_history(id: String, limit: u16, state: &AppState) -> ServerResponse {
    let store = Arc::clone(&state.store);
    let result =
        tokio::task::spawn_blocking(move || store.diagnostic_history(limit.clamp(1, 100))).await;
    match result {
        Ok(Ok(records)) => ServerResponse::success(
            id,
            ResponseData::DiagnosticHistory(
                records
                    .into_iter()
                    .map(|record| DiagnosticHistoryEntry {
                        id: record.id,
                        kind: record.kind,
                        active: record.active,
                        assessment: record.assessment,
                        summary: serde_json::from_slice(&record.payload)
                            .unwrap_or(serde_json::Value::Null),
                        created_at: record.created_at,
                    })
                    .collect(),
            ),
        ),
        Ok(Err(error)) => ServerResponse::error(
            id,
            ErrorCode::Internal,
            format!("failed to read diagnostic history: {error}"),
        ),
        Err(error) => ServerResponse::error(
            id,
            ErrorCode::Internal,
            format!("diagnostic history worker failed: {error}"),
        ),
    }
}

struct TaskAudit<'a> {
    status: &'a str,
    model: &'a str,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    duration: Duration,
    error_code: Option<ErrorCode>,
}

async fn persist_task(id: &str, audit: TaskAudit<'_>, state: &AppState) {
    let record = TaskRecord {
        id: id.into(),
        kind: "ask".into(),
        status: audit.status.into(),
        provider: state.config.llm.provider.as_str().into(),
        model: audit.model.into(),
        prompt_tokens: audit.prompt_tokens,
        completion_tokens: audit.completion_tokens,
        duration_ms: u64::try_from(audit.duration.as_millis()).unwrap_or(u64::MAX),
        error_code: audit.error_code.map(|code| code.as_str().into()),
        created_at: 0,
    };
    let store = Arc::clone(&state.store);
    let max_records = state.config.storage.max_task_records;
    match tokio::task::spawn_blocking(move || store.record_task(&record, max_records)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(%error, "failed to persist task audit"),
        Err(error) => warn!(%error, "task audit worker failed"),
    }
}

async fn persist_action_audit(
    id: &str,
    action_id: &str,
    status: &str,
    duration: Duration,
    error_code: Option<ErrorCode>,
    state: &AppState,
) {
    let record = TaskRecord {
        id: id.into(),
        kind: format!("action:{action_id}"),
        status: status.into(),
        provider: "local".into(),
        model: String::new(),
        prompt_tokens: None,
        completion_tokens: None,
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        error_code: error_code.map(|code| code.as_str().into()),
        created_at: 0,
    };
    let store = Arc::clone(&state.store);
    let max_records = state.config.storage.max_task_records;
    match tokio::task::spawn_blocking(move || store.record_task(&record, max_records)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(%error, "failed to persist action audit"),
        Err(error) => warn!(%error, "action audit worker failed"),
    }
}

async fn handle_task_history(id: String, limit: u16, state: &AppState) -> ServerResponse {
    let store = Arc::clone(&state.store);
    let result = tokio::task::spawn_blocking(move || store.task_history(limit.clamp(1, 100))).await;
    match result {
        Ok(Ok(records)) => ServerResponse::success(
            id,
            ResponseData::TaskHistory(
                records
                    .into_iter()
                    .map(|record| TaskHistoryEntry {
                        id: record.id,
                        kind: record.kind,
                        status: record.status,
                        provider: record.provider,
                        model: record.model,
                        prompt_tokens: record.prompt_tokens,
                        completion_tokens: record.completion_tokens,
                        duration_ms: record.duration_ms,
                        error_code: record.error_code,
                        created_at: record.created_at,
                    })
                    .collect(),
            ),
        ),
        Ok(Err(error)) => ServerResponse::error(
            id,
            ErrorCode::Internal,
            format!("failed to read task history: {error}"),
        ),
        Err(error) => ServerResponse::error(
            id,
            ErrorCode::Internal,
            format!("task history worker failed: {error}"),
        ),
    }
}

async fn read_frame<R>(reader: &mut R, max_bytes: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::with_capacity(max_bytes.min(4096));
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Ok(Some(frame))
            };
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(buffer.len(), |position| position);
        if frame.len().saturating_add(take) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request exceeds configured max_request_bytes",
            ));
        }
        frame.extend_from_slice(&buffer[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn bounded_frame_reader_accepts_one_line() {
        let data = b"{\"type\":\"ping\"}\n";
        let mut reader = BufReader::new(&data[..]);
        let frame = read_frame(&mut reader, 64)
            .await
            .expect("read frame")
            .expect("one frame");
        assert_eq!(frame, b"{\"type\":\"ping\"}");
    }

    #[tokio::test]
    async fn bounded_frame_reader_rejects_oversize_line() {
        let data = b"123456789\n";
        let mut reader = BufReader::new(&data[..]);
        assert!(read_frame(&mut reader, 4).await.is_err());
    }

    #[test]
    fn linux_boot_uptime_parser_is_bounded_and_exact_to_milliseconds() {
        assert_eq!(parse_uptime_ms("123.45").expect("uptime"), 123_450);
        assert_eq!(parse_uptime_ms("7").expect("integer uptime"), 7_000);
        assert_eq!(parse_uptime_ms("1.2349").expect("truncate sub-ms"), 1_234);
        assert!(parse_uptime_ms("-1.0").is_err());
        assert!(parse_uptime_ms("not-a-clock").is_err());
    }

    #[test]
    fn generic_network_admission_accepts_only_enabled_owned_runtime_objects() {
        let route = agent_protocol::NetworkRoute {
            id: "agent-default".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            destination: agent_protocol::IpNetwork {
                address: "0.0.0.0".parse().expect("address"),
                prefix_len: 0,
            },
            gateway: Some("192.0.2.1".parse().expect("gateway")),
            output_interface: Some("eth0".into()),
            preferred_source: None,
            table: 254,
            metric: Some(100),
            route_type: agent_protocol::NetworkRouteType::Unicast,
        };
        assert!(generic_runtime_route_request(
            &NetworkMutationRequest::Create {
                desired: NetworkObject::Route(route.clone()),
            }
        ));

        let mut disabled = route.clone();
        disabled.enabled = false;
        assert!(!generic_runtime_route_request(
            &NetworkMutationRequest::Create {
                desired: NetworkObject::Route(disabled),
            }
        ));

        let mut native = route.clone();
        native.ownership = ObjectOwnership::PlatformNative;
        assert!(!generic_runtime_route_request(
            &NetworkMutationRequest::Update {
                expected_digest: "a".repeat(64),
                desired: NetworkObject::Route(native),
            }
        ));
        assert!(generic_runtime_route_request(
            &NetworkMutationRequest::Delete {
                kind: "route".into(),
                id: "agent-default".into(),
                expected_digest: "a".repeat(64),
            }
        ));
        assert!(!generic_runtime_route_request(
            &NetworkMutationRequest::Delete {
                kind: "interface".into(),
                id: "eth0".into(),
                expected_digest: "a".repeat(64),
            }
        ));
        assert!(!generic_runtime_route_request(
            &NetworkMutationRequest::Move {
                expected_digest: "a".repeat(64),
                desired: NetworkObject::Route(route),
            }
        ));

        let policy = agent_protocol::NetworkPolicyRule {
            id: "guest-policy".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            family: agent_protocol::NetworkFamily::Ipv4,
            priority: 32_000,
            source: None,
            destination: None,
            input_interface: None,
            output_interface: None,
            fwmark: Some(1),
            fwmark_mask: Some(255),
            table: 100,
            action: agent_protocol::NetworkPolicyAction::Lookup,
        };
        assert!(generic_runtime_route_request(
            &NetworkMutationRequest::Create {
                desired: NetworkObject::PolicyRule(policy.clone()),
            }
        ));
        assert!(generic_runtime_route_request(
            &NetworkMutationRequest::Move {
                expected_digest: "a".repeat(64),
                desired: NetworkObject::PolicyRule(policy),
            }
        ));
        assert!(!generic_runtime_route_request(
            &NetworkMutationRequest::Create {
                desired: NetworkObject::PolicyRule(agent_protocol::NetworkPolicyRule {
                    id: "foreign-priority".into(),
                    ownership: ObjectOwnership::AgentOwned,
                    enabled: true,
                    family: agent_protocol::NetworkFamily::Ipv4,
                    priority: 10_000,
                    source: None,
                    destination: None,
                    input_interface: None,
                    output_interface: None,
                    fwmark: None,
                    fwmark_mask: None,
                    table: 100,
                    action: agent_protocol::NetworkPolicyAction::Lookup,
                }),
            }
        ));
    }

    #[test]
    fn read_only_tool_calls_require_allowlisted_names_and_empty_objects() {
        for tool in ReadOnlyAgentTool::ALL {
            let valid = ToolCall {
                id: "call-1".into(),
                name: tool.name().into(),
                arguments: "{}".into(),
            };
            assert_eq!(validate_read_only_tool_call(&valid), Ok(tool));
        }

        let mut invalid = ToolCall {
            id: "call-1".into(),
            name: "shell".into(),
            arguments: "{}".into(),
        };
        assert_eq!(
            validate_read_only_tool_call(&invalid),
            Err("tool name is not in the local allowlist")
        );

        invalid.name = "inspect_dns".into();
        invalid.arguments = r#"{"active":true}"#.into();
        assert_eq!(
            validate_read_only_tool_call(&invalid),
            Err("read-only inspection tools accept no arguments")
        );

        invalid.arguments = format!(r#"{{"padding":"{}"}}"#, "x".repeat(300));
        assert_eq!(
            validate_read_only_tool_call(&invalid),
            Err("tool arguments exceed the local 256-byte limit")
        );
    }

    #[test]
    fn read_only_registry_exposes_closed_schemas() {
        let tools = read_only_agent_tools();
        assert_eq!(tools.len(), ReadOnlyAgentTool::ALL.len());
        for tool in tools {
            assert_eq!(tool.parameters["type"], "object");
            assert_eq!(tool.parameters["additionalProperties"], false);
        }
    }

    #[test]
    fn interface_tool_observation_shrinks_to_context_budget() {
        let interface = agent_protocol::NetworkInterfaceSummary {
            name: "eth0".into(),
            index: Some(2),
            kind: Some("ether".into()),
            operstate: Some("UP".into()),
            up: Some(true),
            carrier: Some(true),
            mtu: Some(1500),
            master: None,
            addresses: vec!["192.0.2.10/24".into()],
            dynamic_address: true,
        };
        let report = agent_protocol::InterfaceDiagnosticReport {
            summary: agent_protocol::InterfaceSummary {
                assessment: agent_protocol::InterfaceAssessment::InterfacesReady,
                interfaces: vec![interface; 16],
                truncated: false,
            },
            evidence: Vec::new(),
            findings: vec!["interfaces ready".into()],
            complete: true,
        };
        let encoded = bounded_interface_observation(&report, 1024).expect("bounded observation");
        assert!(encoded.len() <= 1024);
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["context_truncated"], true);
        assert!(
            value["interfaces"]
                .as_array()
                .is_some_and(|interfaces| interfaces.len() < 16)
        );
    }

    #[test]
    fn neighbor_tool_observation_withholds_mac_and_shrinks_to_budget() {
        let entries = (1..=20)
            .map(|host| agent_protocol::NeighborEntry {
                destination: format!("192.0.2.{host}"),
                device: "eth0".into(),
                link_address: Some("00:11:22:33:44:55".into()),
                states: vec!["REACHABLE".into()],
                router: host == 1,
            })
            .collect();
        let report = agent_protocol::NeighborDiagnosticReport {
            summary: agent_protocol::NeighborSummary {
                assessment: agent_protocol::NeighborAssessment::NeighborsPresent,
                entries,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: vec!["neighbors present".into()],
            complete: true,
        };
        let encoded = bounded_neighbor_observation(&report, 1024).expect("bounded observation");
        assert!(encoded.len() <= 1024);
        assert!(!encoded.contains("00:11:22:33:44:55"));
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["context_truncated"], true);
        assert!(
            value["entries"]
                .as_array()
                .is_some_and(|entries| entries.len() < 20)
        );
    }

    #[test]
    fn firewall_base_chain_observation_shrinks_without_rule_expressions() {
        let base_chains = (0..32)
            .map(|index| agent_protocol::FirewallBaseChain {
                family: "inet".into(),
                table: "fw4".into(),
                name: format!("input_{index}"),
                hook: Some("input".into()),
                policy: Some("DROP".into()),
                rules: 20,
            })
            .collect();
        let report = agent_protocol::FirewallDiagnosticReport {
            summary: agent_protocol::FirewallRuntimeSummary {
                assessment: agent_protocol::FirewallAssessment::RuntimeRulesPresent,
                backend: "fw4/nftables".into(),
                tables: 1,
                chains: 40,
                rules: 640,
                rules_with_counters: 640,
                base_chains,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            complete: true,
        };
        let encoded = bounded_firewall_observation(
            ReadOnlyAgentTool::InspectFirewallBaseChains,
            &report,
            1024,
        )
        .expect("bounded observation");
        assert!(encoded.len() <= 1024);
        assert!(!encoded.contains("expr"));
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["context_truncated"], true);
    }

    #[test]
    fn policy_rule_observation_shrinks_to_context_budget() {
        let rules = (0..64)
            .map(|priority| agent_protocol::PolicyRule {
                priority: Some(priority),
                source: Some("192.0.2.0/24".into()),
                destination: None,
                table: "100".into(),
                action: None,
                fwmark: Some("0x1/0xff".into()),
                incoming_interface: Some("eth0".into()),
                outgoing_interface: None,
            })
            .collect();
        let report = agent_protocol::PolicyRoutingDiagnosticReport {
            summary: agent_protocol::PolicyRoutingSummary {
                assessment: agent_protocol::PolicyRoutingAssessment::CustomPolicyPresent,
                rules,
                tables: vec![agent_protocol::RouteTableSummary {
                    table: "100".into(),
                    routes: 4,
                    default_routes: 1,
                    exceptional_routes: 0,
                }],
                total_routes: 4,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            complete: true,
        };
        let encoded = bounded_policy_routing_observation(
            ReadOnlyAgentTool::InspectPolicyRules,
            &report,
            1024,
        )
        .expect("bounded observation");
        assert!(encoded.len() <= 1024);
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["context_truncated"], true);
    }

    #[test]
    fn listener_observation_omits_addresses_and_filters_loopback() {
        let listeners = (0..100)
            .map(|index| agent_protocol::ListenerEntry {
                protocol: "tcp".into(),
                family: "ipv4".into(),
                local_address: if index % 2 == 0 {
                    "127.0.0.1".into()
                } else {
                    "192.0.2.1".into()
                },
                port: 1000 + index,
                scope: if index % 2 == 0 {
                    agent_protocol::ListenerScope::Loopback
                } else {
                    agent_protocol::ListenerScope::Specific
                },
                state: Some("LISTEN".into()),
            })
            .collect();
        let report = agent_protocol::ListenerDiagnosticReport {
            summary: agent_protocol::ListenerSummary {
                assessment: agent_protocol::ListenerAssessment::ListenersPresent,
                listeners,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            complete: true,
        };
        let encoded =
            bounded_listener_observation(ReadOnlyAgentTool::InspectExposedServices, &report, 1024)
                .expect("bounded observation");
        assert!(encoded.len() <= 1024);
        assert!(!encoded.contains("127.0.0.1"));
        assert!(!encoded.contains("192.0.2.1"));
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["source_entries"], 100);
        assert_eq!(value["context_truncated"], true);
        assert!(value["listeners"].as_array().is_some_and(|listeners| {
            listeners
                .iter()
                .all(|listener| listener["scope"] != "loopback")
        }));
    }

    #[test]
    fn wireless_interface_observation_omits_ssids_and_shrinks() {
        let interfaces = (0..32)
            .map(|index| agent_protocol::WirelessInterfaceSummary {
                name: format!("wlan{index}"),
                radio: Some(format!("phy{index}")),
                mode: Some("ap".into()),
                ssid: Some(format!("Private SSID {index}")),
                channel: Some(11),
                frequency_mhz: Some(2462),
            })
            .collect();
        let report = agent_protocol::WirelessDiagnosticReport {
            summary: agent_protocol::WirelessSummary {
                assessment: agent_protocol::WirelessAssessment::WirelessPresent,
                radios: Vec::new(),
                interfaces,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            complete: true,
        };
        let encoded = bounded_wireless_observation(
            ReadOnlyAgentTool::InspectWirelessInterfaces,
            &report,
            1024,
        )
        .expect("bounded observation");
        assert!(encoded.len() <= 1024);
        assert!(!encoded.contains("Private SSID"));
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["context_truncated"], true);
        assert!(value["interfaces"].as_array().is_some_and(|interfaces| {
            interfaces
                .iter()
                .all(|interface| interface["ssid_configured"] == true)
        }));
    }

    #[test]
    fn interface_error_observation_filters_zero_counters_and_shrinks() {
        let interfaces = (0..32)
            .map(|index| agent_protocol::InterfaceStatsEntry {
                name: format!("eth{index}"),
                operstate: Some("UP".into()),
                rx_bytes: 1_000_000 + index,
                rx_packets: 10_000 + index,
                rx_errors: index % 2,
                rx_dropped: 0,
                tx_bytes: 2_000_000 + index,
                tx_packets: 20_000 + index,
                tx_errors: 0,
                tx_dropped: u64::from(index % 3 == 0),
            })
            .collect();
        let report = agent_protocol::InterfaceStatsDiagnosticReport {
            summary: agent_protocol::InterfaceStatsSummary {
                assessment: agent_protocol::InterfaceStatsAssessment::ErrorsOrDropsPresent,
                interfaces,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            complete: true,
        };
        let encoded = bounded_interface_stats_observation(
            ReadOnlyAgentTool::InspectInterfaceErrors,
            &report,
            1024,
        )
        .expect("bounded observation");
        assert!(encoded.len() <= 1024);
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["source_entries"], 32);
        assert_eq!(value["context_truncated"], true);
        assert!(value["interfaces"].as_array().is_some_and(|interfaces| {
            interfaces.iter().all(|interface| {
                interface["rx_errors"].as_u64().unwrap_or_default() > 0
                    || interface["rx_dropped"].as_u64().unwrap_or_default() > 0
                    || interface["tx_errors"].as_u64().unwrap_or_default() > 0
                    || interface["tx_dropped"].as_u64().unwrap_or_default() > 0
            })
        }));
    }

    #[test]
    fn qdisc_pressure_observation_filters_idle_entries_and_shrinks() {
        let qdiscs = (0..64)
            .map(|index| agent_protocol::QdiscEntry {
                device: format!("if{index}"),
                kind: "fq_codel".into(),
                handle: Some(format!("{index}:")),
                parent: None,
                root: true,
                bytes: 1000 + index,
                packets: 100 + index,
                drops: u64::from(index % 2 == 0),
                overlimits: 0,
                requeues: 0,
                backlog_bytes: 0,
                queue_length: 0,
            })
            .collect();
        let report = agent_protocol::QdiscDiagnosticReport {
            summary: agent_protocol::QdiscSummary {
                assessment: agent_protocol::QdiscAssessment::PressureCountersPresent,
                qdiscs,
                truncated: false,
            },
            evidence: Vec::new(),
            findings: Vec::new(),
            complete: true,
        };
        let encoded =
            bounded_qdisc_observation(ReadOnlyAgentTool::InspectQdiscPressure, &report, 1024)
                .expect("bounded observation");
        assert!(encoded.len() <= 1024);
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("observation JSON");
        assert_eq!(value["source_entries"], 64);
        assert_eq!(value["context_truncated"], true);
        assert!(value["qdiscs"].as_array().is_some_and(|qdiscs| {
            qdiscs
                .iter()
                .all(|qdisc| qdisc["drops"].as_u64().unwrap_or_default() > 0)
        }));
    }

    #[test]
    fn usage_is_accumulated_safely() {
        let mut total = None;
        add_usage(&mut total, None);
        add_usage(&mut total, Some(u64::MAX));
        add_usage(&mut total, Some(1));
        assert_eq!(total, Some(u64::MAX));
    }

    #[test]
    fn last_agent_step_cannot_start_an_unanswered_tool_call() {
        assert!(tool_step_available(0, 2));
        assert!(!tool_step_available(1, 2));
        assert!(!tool_step_available(0, 1));
    }

    #[test]
    fn request_ids_are_bounded_before_audit_storage() {
        assert!(valid_request_id("cli-42-123"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("line\nbreak"));
        assert!(!valid_request_id(&"x".repeat(129)));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn elevation_is_boot_bound_and_does_not_persist_passwords() {
        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/elevation-test-{}-{test_id}",
            std::process::id()
        ));
        let mut config = AgentConfig::default();
        config.storage.path = root.join("agent.db");
        let budget = TmpBudget::new(config.storage.clone()).expect("budget");
        let store = Arc::new(
            Store::open(&config.storage.path, config.storage.max_database_bytes).expect("store"),
        );
        let encoded =
            agent_core::generate_password_hash(b"test administrator password").expect("hash");
        let auth = AuthManager::new(
            AdminPasswordVerifier::parse(&encoded).expect("verifier"),
            "test-boot".into(),
            300,
            3,
            60,
        );
        let state = AppState {
            platform: PlatformCapabilities::discover(),
            budget,
            store,
            tools: ToolRunner::system(Duration::from_millis(100), 4096),
            diagnostic_slots: Semaphore::new(1),
            llm: None,
            llm_slots: Semaphore::new(1),
            log_writer: test_log_writer(&root),
            started: Instant::now(),
            auth: Arc::new(auth),
            config_path: root.join("config.toml"),
            configuration_lock: Mutex::new(()),
            actions: RwLock::new(ActionRegistry::default()),
            action_slots: Semaphore::new(1),
            mqtt_status: None,
            wechat_status: None,
            wecom_status: None,
            config,
        };

        let rejected = handle_elevation(
            "wrong".into(),
            "wrong password".into(),
            LOCAL_CLI_ACTOR.into(),
            &state,
        )
        .await;
        assert_eq!(
            rejected.error.expect("unauthorized").code,
            ErrorCode::Unauthorized
        );
        let granted = handle_elevation(
            "correct".into(),
            "test administrator password".into(),
            LOCAL_CLI_ACTOR.into(),
            &state,
        )
        .await;
        let Some(ResponseData::Elevation(capability)) = granted.result else {
            panic!("expected elevation response");
        };
        assert_eq!(capability.actor_id, "cli/local");
        assert_eq!(capability.role, "device-admin");
        assert_eq!(capability.boot_id, "test-boot");
        assert!(
            state
                .auth
                .is_device_admin("cli/local", 1)
                .expect("auth state")
        );
        let channel_response = dispatch_channel_request(
            "wecom",
            agent_channels::ChannelRequest {
                schema_version: agent_channels::CHANNEL_MESSAGE_SCHEMA_VERSION,
                message_id: "wecom-elevate-1".into(),
                actor_id: "wecom:user-1".into(),
                conversation_id: "wecom:chat-1".into(),
                expires_unix_ms: i64::MAX,
                command: ChannelCommand::Elevate {
                    password: agent_channels::ChannelSecret::new("test administrator password"),
                },
            },
            &state,
        )
        .await;
        let channel_capability: agent_protocol::ElevationResponse = serde_json::from_value(
            channel_response
                .result
                .expect("channel elevation result")
                .get("data")
                .cloned()
                .expect("channel elevation payload"),
        )
        .expect("channel elevation response");
        assert_eq!(channel_capability.actor_id, "wecom:user-1");
        assert!(
            state
                .auth
                .is_device_admin("wecom:user-1", 1)
                .expect("channel auth state")
        );
        let deauth_response = dispatch_channel_request(
            "wecom",
            agent_channels::ChannelRequest {
                schema_version: agent_channels::CHANNEL_MESSAGE_SCHEMA_VERSION,
                message_id: "wecom-deauth-1".into(),
                actor_id: "wecom:user-1".into(),
                conversation_id: "wecom:chat-1".into(),
                expires_unix_ms: i64::MAX,
                command: ChannelCommand::Deauth,
            },
            &state,
        )
        .await;
        assert!(deauth_response.ok);
        assert_eq!(
            deauth_response.result.expect("channel deauth result")["data"]["actor_id"],
            "wecom:user-1"
        );
        assert!(
            !state
                .auth
                .is_device_admin("wecom:user-1", 1)
                .expect("channel auth state after deauth")
        );
        assert!(
            state
                .auth
                .is_device_admin("cli/local", 1)
                .expect("local auth remains isolated")
        );
        handle_deauth("local-deauth".into(), LOCAL_CLI_ACTOR.into(), &state).await;
        assert!(
            !state
                .auth
                .is_device_admin("cli/local", 1)
                .expect("local auth state after deauth")
        );
        let database = fs::read(&state.config.storage.path).expect("database bytes");
        assert!(
            !database
                .windows(b"test administrator password".len())
                .any(|window| window == b"test administrator password")
        );

        drop(state);
        fs::remove_dir_all(root).expect("remove test runtime");
    }

    fn approval_test_plan(now_monotonic_ms: u64) -> ChangePlan {
        ChangePlan {
            schema_version: agent_protocol::CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "change-approval-1".into(),
            boot_id: "test-boot".into(),
            actor_id: LOCAL_CLI_ACTOR.into(),
            created_monotonic_ms: now_monotonic_ms,
            expires_monotonic_ms: now_monotonic_ms.saturating_add(60_000),
            risk: agent_protocol::RiskLevel::R2,
            changes: vec![agent_protocol::ChangeDiff {
                object: agent_protocol::ConfigObjectRef {
                    domain: agent_protocol::ConfigDomain::Firewall,
                    kind: "rule".into(),
                    id: "managed-rule".into(),
                    expected_version: None,
                    ownership: agent_protocol::ObjectOwnership::AgentOwned,
                },
                operation: agent_protocol::ChangeOperation::Create,
                before_digest: None,
                after_digest: Some("a".repeat(64)),
                summary: "create a managed firewall rule".into(),
                sensitive_fields_redacted: false,
                risk_signals: agent_protocol::ChangeRiskSignals::default(),
            }],
            validation_checks: vec!["validate staged firewall".into()],
            verification_checks: vec!["verify managed firewall rule".into()],
            rollback_required: true,
        }
    }

    fn approval_test_state(root: &Path) -> (Arc<Store>, AppState) {
        let mut config = AgentConfig::default();
        config.storage.path = root.join("agent.db");
        disable_test_free_space_guard(&mut config);
        config.auth.enabled = true;
        let encoded =
            agent_core::generate_password_hash(b"test administrator password").expect("hash");
        let budget = TmpBudget::new(config.storage.clone()).expect("budget");
        let store = Arc::new(
            Store::open(&config.storage.path, config.storage.max_database_bytes).expect("store"),
        );
        let auth = AuthManager::new(
            AdminPasswordVerifier::parse(&encoded).expect("verifier"),
            "test-boot".into(),
            300,
            3,
            60,
        );
        let state = AppState {
            platform: PlatformCapabilities::discover(),
            budget,
            store: Arc::clone(&store),
            tools: ToolRunner::system(Duration::from_millis(100), 4096),
            diagnostic_slots: Semaphore::new(1),
            llm: None,
            llm_slots: Semaphore::new(1),
            log_writer: test_log_writer(root),
            started: Instant::now(),
            auth: Arc::new(auth),
            config_path: root.join("config.toml"),
            configuration_lock: Mutex::new(()),
            actions: RwLock::new(ActionRegistry::default()),
            action_slots: Semaphore::new(1),
            mqtt_status: None,
            wechat_status: None,
            wecom_status: None,
            config,
        };
        (store, state)
    }

    #[tokio::test]
    async fn declarative_action_runs_typed_argv_and_audits_without_output() {
        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/action-test-{}-{test_id}",
            std::process::id()
        ));
        let (store, mut state) = approval_test_state(&root);
        let actions_dir = root.join("actions.d");
        fs::create_dir(&actions_dir).expect("actions directory");
        let manifest = actions_dir.join("test.toml");
        fs::write(
            &manifest,
            r#"
schema_version = 1
[[actions]]
id = "echo_vendor"
description = "Echo one bounded vendor value"
llm_enabled = true
platforms = ["generic_linux"]
executable = "/bin/echo"
[[actions.argv]]
kind = "input"
name = "value"
[actions.inputs.value]
kind = "string"
max_bytes = 32
"#,
        )
        .expect("manifest");
        let extensions = agent_core::ExtensionsConfig {
            enabled: true,
            directories: vec![actions_dir],
            trusted_manifest_owner_uid: fs::metadata(&manifest).expect("manifest metadata").uid(),
            ..agent_core::ExtensionsConfig::default()
        };
        state.config.extensions = extensions.clone();
        state.platform.kind = PlatformKind::GenericLinux;
        state.actions = RwLock::new(ActionRegistry::load(&extensions).expect("registry"));
        let tools = agent_tools(&state).await;
        assert!(tools.iter().any(|tool| {
            tool.name == "ext_echo_vendor"
                && tool.parameters["required"] == serde_json::json!(["value"])
        }));

        let response = handle_action_run(
            "action-request".into(),
            "echo_vendor".into(),
            serde_json::json!({"value": "hello;not-a-shell"}),
            &state,
        )
        .await;
        let Some(ResponseData::ActionOutput(output)) = response.result else {
            panic!("action output expected");
        };
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout.trim(), "hello;not-a-shell");
        let tool_message = execute_extension_agent_tool(
            &ToolCall {
                id: "tool-call-1".into(),
                name: "ext_echo_vendor".into(),
                arguments: r#"{"value":"model-value"}"#.into(),
            },
            "ask-request",
            &state,
        )
        .await;
        let Ok(tool_message) = tool_message else {
            panic!("model action should succeed");
        };
        let ModelMessage::Tool { content, .. } = tool_message else {
            panic!("tool response expected");
        };
        assert!(content.contains("model-value"));
        let history = store.task_history(10).expect("task audit");
        assert!(
            history
                .iter()
                .filter(|entry| entry.kind == "action:echo_vendor")
                .count()
                >= 2
        );
        assert!(!format!("{history:?}").contains("hello;not-a-shell"));

        drop(state);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn mqtt_dispatch_surface_is_read_only_and_returns_channel_envelopes() {
        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/mqtt-dispatch-test-{}-{test_id}",
            std::process::id()
        ));
        let (_store, state) = approval_test_state(&root);
        let response = dispatch_channel_request(
            "mqtt",
            agent_channels::ChannelRequest {
                schema_version: agent_channels::CHANNEL_MESSAGE_SCHEMA_VERSION,
                message_id: "mqtt-message-1".into(),
                actor_id: "operator-1".into(),
                conversation_id: "conversation-1".into(),
                expires_unix_ms: i64::MAX,
                command: ChannelCommand::Ping,
            },
            &state,
        )
        .await;
        assert!(response.ok);
        assert_eq!(response.message_id, "mqtt-message-1");
        assert_eq!(response.result.expect("result")["type"], "pong");
        drop(state);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn change_approval_is_admin_actor_plan_and_boot_bound() {
        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/change-approval-test-{}-{test_id}",
            std::process::id()
        ));
        let (store, state) = approval_test_state(&root);
        let plan_now = boot_monotonic_ms().expect("boot monotonic clock");
        let plan = approval_test_plan(plan_now);
        let digest = plan_digest(&plan).expect("valid plan");
        store
            .insert_change_set(
                &ChangeSetRecord {
                    id: plan.plan_id.clone(),
                    plan_digest: digest.clone(),
                    plan_payload: serde_json::to_vec(&plan).expect("plan payload"),
                    state: ChangeSetState::Planned,
                    actor_id: plan.actor_id.clone(),
                    boot_id: plan.boot_id.clone(),
                    risk: plan.risk,
                    expires_monotonic_ms: plan.expires_monotonic_ms,
                    rollback_deadline_monotonic_ms: None,
                    created_at: 0,
                    updated_at: 0,
                },
                state.config.storage.max_change_set_records,
                usize::try_from(state.config.storage.max_change_plan_bytes).expect("plan limit"),
                plan_now,
            )
            .expect("insert ChangeSet");
        store
            .transition_change_set(
                &plan.plan_id,
                ChangeSetState::Planned,
                ChangeSetState::AwaitingApproval,
                &digest,
                &plan.boot_id,
                plan_now,
            )
            .expect("await approval");

        let denied = handle_change_approve(
            "approve-denied".into(),
            plan.plan_id.clone(),
            LOCAL_CLI_ACTOR.into(),
            &state,
        )
        .await;
        assert_eq!(
            denied.error.expect("admin required").code,
            ErrorCode::Unauthorized
        );
        handle_elevation(
            "elevate".into(),
            "test administrator password".into(),
            LOCAL_CLI_ACTOR.into(),
            &state,
        )
        .await;
        let approved = handle_change_approve(
            "approve".into(),
            plan.plan_id.clone(),
            LOCAL_CLI_ACTOR.into(),
            &state,
        )
        .await;
        let Some(ResponseData::ChangeApproval(approval)) = approved.result else {
            panic!("expected approval response");
        };
        assert_eq!(approval.change_set_id, plan.plan_id);
        assert_eq!(approval.plan_digest, digest);
        assert_eq!(approval.token.expose().len(), 64);
        let database = fs::read(&state.config.storage.path).expect("database bytes");
        assert!(
            !database
                .windows(approval.token.expose().len())
                .any(|window| window == approval.token.expose().as_bytes())
        );

        let now = boot_monotonic_ms().expect("boot monotonic clock");
        let consumption = agent_store::ApprovalConsumption {
            approval_id: &approval.approval_id,
            change_set_id: &approval.change_set_id,
            actor_id: LOCAL_CLI_ACTOR,
            plan_digest: &approval.plan_digest,
            boot_id: "test-boot",
            token_digest: &sha256_hex(approval.token.expose().as_bytes()),
        };
        assert_eq!(
            store
                .consume_approval(&consumption, now)
                .expect("consume approval"),
            ChangeSetState::Approved
        );
        assert!(matches!(
            store.consume_approval(&consumption, now),
            Err(StoreError::ApprovalRejected)
        ));

        drop(state);
        drop(store);
        fs::remove_dir_all(root).expect("remove test runtime");
    }

    #[tokio::test]
    async fn critical_managed_storage_rejects_new_tasks() {
        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/storage-admission-test-{}-{test_id}",
            std::process::id()
        ));
        let mut config = AgentConfig::default();
        config.storage.path = root.join("agent.db");
        config.storage.max_total_bytes = 1;
        let budget = TmpBudget::new(config.storage.clone()).expect("budget");
        let store = Arc::new(
            Store::open(&config.storage.path, config.storage.max_database_bytes).expect("store"),
        );
        let state = AppState {
            platform: PlatformCapabilities::discover(),
            budget,
            store,
            tools: ToolRunner::system(Duration::from_millis(100), 4096),
            diagnostic_slots: Semaphore::new(1),
            llm: None,
            llm_slots: Semaphore::new(1),
            log_writer: test_log_writer(&root),
            started: Instant::now(),
            auth: Arc::new(AuthManager::disabled("test-boot".into())),
            config_path: root.join("config.toml"),
            configuration_lock: Mutex::new(()),
            actions: RwLock::new(ActionRegistry::default()),
            action_slots: Semaphore::new(1),
            mqtt_status: None,
            wechat_status: None,
            wecom_status: None,
            config,
        };

        let error = ensure_task_storage(&state)
            .await
            .expect_err("storage admission must reject");
        assert!(error.contains("Emergency"));

        drop(state);
        fs::remove_dir_all(root).expect("remove test runtime");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn agent_loop_reuses_one_snapshot_across_multiple_tools() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("first accept");
            let first_request = read_http_request(&mut first).await;
            assert!(first_request.contains("\"name\":\"diagnose_wan\""));
            assert!(first_request.contains("\"name\":\"inspect_default_routes\""));
            assert!(first_request.contains("\"name\":\"inspect_dns\""));
            assert!(first_request.contains("\"name\":\"inspect_dhcp\""));
            assert!(first_request.contains("\"name\":\"inspect_wan_firewall\""));
            write_json_response(
                &mut first,
                r#"{"model":"mock","choices":[{"message":{"content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"inspect_dns","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}"#,
            )
            .await;

            let (mut second, _) = listener.accept().await.expect("second accept");
            let second_request = read_http_request(&mut second).await;
            assert!(second_request.contains("\"role\":\"tool\""));
            assert!(second_request.contains("\"tool_call_id\":\"call_1\""));
            assert!(second_request.contains("dns_servers"));
            write_json_response(
                &mut second,
                r#"{"model":"mock","choices":[{"message":{"content":null,"tool_calls":[{"id":"call_2","type":"function","function":{"name":"inspect_default_routes","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":8,"completion_tokens":2}}"#,
            )
            .await;

            let (mut third, _) = listener.accept().await.expect("third accept");
            let third_request = read_http_request(&mut third).await;
            assert!(third_request.contains("\"tool_call_id\":\"call_2\""));
            assert!(third_request.contains("default_routes"));
            write_json_response(
                &mut third,
                r#"{"model":"mock","choices":[{"message":{"content":"WAN analyzed"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":3}}"#,
            )
            .await;
        });

        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/agent-loop-test-{}-{test_id}",
            std::process::id()
        ));
        let mut config = AgentConfig::default();
        config.storage.path = root.join("agent.db");
        disable_test_free_space_guard(&mut config);
        config.llm.model = "mock".into();
        config.llm.streaming = false;
        config.llm.max_agent_steps = 4;
        let budget = TmpBudget::new(config.storage.clone()).expect("budget");
        let store = Arc::new(
            Store::open(&config.storage.path, config.storage.max_database_bytes).expect("store"),
        );
        let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
            base_url: format!("http://{address}/v1"),
            api_key: "test-key".into(),
            model: "mock".into(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
            max_request_bytes: config.llm.max_request_bytes,
            max_response_bytes: config.llm.max_response_bytes,
            max_stream_event_bytes: config.llm.max_stream_event_bytes,
        })
        .expect("provider");
        let state = AppState {
            platform: PlatformCapabilities::discover(),
            budget,
            store,
            tools: ToolRunner::system(Duration::from_millis(100), 4096),
            diagnostic_slots: Semaphore::new(1),
            llm: Some(provider),
            llm_slots: Semaphore::new(1),
            log_writer: test_log_writer(&root),
            started: Instant::now(),
            auth: Arc::new(AuthManager::disabled("test-boot".into())),
            config_path: root.join("config.toml"),
            configuration_lock: Mutex::new(()),
            actions: RwLock::new(ActionRegistry::default()),
            action_slots: Semaphore::new(1),
            mqtt_status: None,
            wechat_status: None,
            wecom_status: None,
            config,
        };
        let response = handle_completion("agent-loop".into(), "check WAN".into(), &state).await;
        assert!(response.ok, "unexpected Agent response: {response:?}");
        let Some(ResponseData::Completion(completion)) = response.result else {
            panic!("expected completion");
        };
        assert_eq!(completion.text, "WAN analyzed");
        assert_eq!(completion.prompt_tokens, Some(22));
        assert_eq!(completion.completion_tokens, Some(7));
        assert_eq!(
            state
                .store
                .diagnostic_history(10)
                .expect("diagnostic history")
                .len(),
            1
        );
        let task_history = state.store.task_history(10).expect("task history");
        assert_eq!(task_history.len(), 1);
        assert_eq!(task_history[0].id, "agent-loop");
        assert_eq!(task_history[0].status, "succeeded");
        assert_eq!(task_history[0].prompt_tokens, Some(22));
        assert_eq!(task_history[0].completion_tokens, Some(7));
        assert_eq!(task_history[0].error_code, None);
        server.await.expect("server");
        drop(state);
        fs::remove_dir_all(root).expect("remove test runtime");
    }

    #[tokio::test]
    async fn agent_total_timeout_is_audited_without_message_content() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
        });

        let test_id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/mbed-agent/agent-timeout-test-{}-{test_id}",
            std::process::id()
        ));
        let mut config = AgentConfig::default();
        config.storage.path = root.join("agent.db");
        disable_test_free_space_guard(&mut config);
        config.runtime.task_timeout_secs = 1;
        config.llm.model = "mock".into();
        config.llm.streaming = false;
        let budget = TmpBudget::new(config.storage.clone()).expect("budget");
        let store = Arc::new(
            Store::open(&config.storage.path, config.storage.max_database_bytes).expect("store"),
        );
        let provider = OpenAiCompatibleProvider::new(OpenAiCompatibleConfig {
            base_url: format!("http://{address}/v1"),
            api_key: "test-key".into(),
            model: "mock".into(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
            max_request_bytes: config.llm.max_request_bytes,
            max_response_bytes: config.llm.max_response_bytes,
            max_stream_event_bytes: config.llm.max_stream_event_bytes,
        })
        .expect("provider");
        let state = AppState {
            platform: PlatformCapabilities::discover(),
            budget,
            store,
            tools: ToolRunner::system(Duration::from_millis(100), 4096),
            diagnostic_slots: Semaphore::new(1),
            llm: Some(provider),
            llm_slots: Semaphore::new(1),
            log_writer: test_log_writer(&root),
            started: Instant::now(),
            auth: Arc::new(AuthManager::disabled("test-boot".into())),
            config_path: root.join("config.toml"),
            configuration_lock: Mutex::new(()),
            actions: RwLock::new(ActionRegistry::default()),
            action_slots: Semaphore::new(1),
            mqtt_status: None,
            wechat_status: None,
            wecom_status: None,
            config,
        };

        let secret_prompt = "private prompt must not be stored";
        let response =
            handle_completion("agent-timeout".into(), secret_prompt.into(), &state).await;
        assert!(!response.ok);
        assert_eq!(
            response.error.expect("timeout error").code,
            ErrorCode::ResourceExhausted
        );
        let history = state.store.task_history(10).expect("task history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, "timed_out");
        assert_eq!(
            history[0].error_code.as_deref(),
            Some(ErrorCode::ResourceExhausted.as_str())
        );
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", state.config.storage.path.display()));
            if let Ok(database) = fs::read(path) {
                assert!(
                    !database
                        .windows(secret_prompt.len())
                        .any(|window| window == secret_prompt.as_bytes())
                );
            }
        }

        server.abort();
        let _ = server.await;
        drop(state);
        fs::remove_dir_all(root).expect("remove test runtime");
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await.expect("read request");
            assert!(read > 0, "request ended before body");
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .expect("content length");
            if request.len() >= header_end.saturating_add(content_length) {
                return String::from_utf8(request).expect("UTF-8 request");
            }
        }
    }

    async fn write_json_response(stream: &mut tokio::net::TcpStream, body: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    }

    fn test_log_writer(root: &Path) -> logging::BoundedMakeWriter {
        let config = agent_core::config::LoggingConfig {
            path: root.join("test.log"),
            ..agent_core::config::LoggingConfig::default()
        };
        logging::BoundedMakeWriter::new(&config).expect("test log writer")
    }

    fn disable_test_free_space_guard(config: &mut AgentConfig) {
        config.storage.min_tmp_free_bytes = 0;
        config.storage.min_tmp_free_percent = 0;
    }
}
