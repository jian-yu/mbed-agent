use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_core::{AgentConfig, TmpBudget};
use agent_protocol::{
    ClientRequest, Command, CompletionResponse, DiagnosticHistoryEntry, ErrorCode,
    PROTOCOL_VERSION, ResponseData, ServerResponse, StatusResponse, StoragePressure, StorageStatus,
};
use agent_provider::{
    CompletionRequest, ModelMessage, OpenAiCompatibleConfig, OpenAiCompatibleProvider, ToolCall,
    ToolDefinition,
};
use agent_store::{DiagnosticRecord, Store};
use agent_tools::ToolRunner;
use platform_linux::PlatformCapabilities;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::logging;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

struct AppState {
    config: AgentConfig,
    platform: PlatformCapabilities,
    budget: TmpBudget,
    store: Arc<Store>,
    tools: ToolRunner,
    diagnostic_slots: Semaphore,
    llm: Option<OpenAiCompatibleProvider>,
    llm_slots: Semaphore,
    started: Instant,
}

pub async fn run(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = AgentConfig::load_or_default(config_path)?;
    ensure_secret_config_permissions(config_path, &config)?;
    init_logging(&config)?;

    let budget = TmpBudget::new(config.storage.clone())?;
    fs::create_dir_all(budget.root().join("artifacts"))?;
    fs::create_dir_all(budget.root().join("rollback"))?;
    fs::create_dir_all(budget.root().join("log"))?;

    let store = Arc::new(Store::open(
        &config.storage.path,
        config.storage.max_database_bytes,
    )?);
    store.health_check()?;
    let platform = PlatformCapabilities::discover();
    for warning in &platform.warnings {
        warn!(warning = %warning, "platform capability warning");
    }

    let tools = ToolRunner::system(
        Duration::from_secs(config.runtime.tool_timeout_secs),
        config.runtime.max_tool_output_bytes,
    );
    let diagnostic_slots = Semaphore::new(config.runtime.max_active_tasks);
    let llm = build_llm_provider(&config)?;
    let llm_slots = Semaphore::new(config.runtime.max_active_tasks);
    let listener = bind_socket(&config.server.socket_path, config.server.socket_mode)?;
    let state = Arc::new(AppState {
        config,
        platform,
        budget,
        store,
        tools,
        diagnostic_slots,
        llm,
        llm_slots,
        started: Instant::now(),
    });
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
        }
    }

    let _ = fs::remove_file(&state.config.server.socket_path);
    Ok(())
}

fn ensure_secret_config_permissions(path: &Path, config: &AgentConfig) -> io::Result<()> {
    if !config.llm.enabled || !path.exists() {
        return Ok(());
    }
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "LLM credentials require {} to have mode 0600 or stricter",
                path.display()
            ),
        ));
    }
    Ok(())
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

fn init_logging(config: &AgentConfig) -> io::Result<()> {
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
            .with_writer(writer)
            .compact()
            .init(),
        agent_core::config::LogFormat::JsonLines => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(writer)
            .json()
            .init(),
    }
    Ok(())
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
        let response = match serde_json::from_slice::<ClientRequest>(&frame) {
            Ok(request) => handle_request(request, &state).await,
            Err(error) => ServerResponse::error(
                "unknown",
                ErrorCode::InvalidRequest,
                format!("invalid JSON request: {error}"),
            ),
        };
        let mut encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
        encoded.push(b'\n');
        write_half.write_all(&encoded).await?;
    }
    Ok(())
}

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
        Command::Status => {
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
                degraded_reasons,
            })
        }
        Command::DiagnoseWan { active } => {
            return handle_wan_diagnosis(request.id, active, state).await;
        }
        Command::DiagnosticHistory { limit } => {
            return handle_diagnostic_history(request.id, limit, state).await;
        }
        Command::Complete { prompt } => {
            return handle_completion(request.id, prompt, state).await;
        }
    };
    ServerResponse::success(request.id, result)
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
    let Ok(_permit) = state.llm_slots.try_acquire() else {
        return ServerResponse::error(
            id,
            ErrorCode::ResourceExhausted,
            "the configured LLM task limit has been reached",
        );
    };
    match run_read_only_agent(provider, prompt, &id, state).await {
        Ok(completion) => ServerResponse::success(id, ResponseData::Completion(completion)),
        Err(failure) => ServerResponse::error(id, failure.code, failure.message),
    }
}

struct AgentLoopFailure {
    code: ErrorCode,
    message: String,
}

impl AgentLoopFailure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
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
    let tools = vec![wan_diagnostic_tool()];
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
                ));
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
            ));
        }
        if !tool_step_available(step, state.config.llm.max_agent_steps) {
            return Err(AgentLoopFailure::new(
                ErrorCode::ResourceExhausted,
                "Agent loop reached max_agent_steps before a final answer",
            ));
        }
        let call = completion.tool_calls[0].clone();
        messages.push(ModelMessage::Assistant {
            content: completion.text,
            tool_calls: completion.tool_calls,
        });
        messages.push(execute_agent_tool(&call, request_id, step, state).await?);
    }
    Err(AgentLoopFailure::new(
        ErrorCode::ResourceExhausted,
        "Agent loop exhausted its configured step budget",
    ))
}

const fn tool_step_available(step: u8, max_agent_steps: u8) -> bool {
    step.saturating_add(1) < max_agent_steps
}

async fn execute_agent_tool(
    call: &ToolCall,
    request_id: &str,
    step: u8,
    state: &AppState,
) -> Result<ModelMessage, AgentLoopFailure> {
    if let Err(reason) = validate_wan_tool_call(call) {
        warn!(tool = %call.name, %reason, "model requested a rejected tool call");
        return Err(AgentLoopFailure::new(
            ErrorCode::Upstream,
            format!("model tool call was rejected: {reason}"),
        ));
    }
    let report = execute_agent_wan_diagnostic(state)
        .await
        .map_err(agent_tool_failure)?;
    persist_diagnostic(&format!("{request_id}-tool-{step}"), false, &report, state).await;
    let content = bounded_wan_observation(&report, state.config.llm.max_tool_context_bytes)
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
            "Agent WAN diagnosis exceeded the configured task timeout",
        ),
        AgentToolError::Failed(error) => AgentLoopFailure::new(
            ErrorCode::Internal,
            format!("Agent WAN diagnosis failed: {error}"),
        ),
    }
}

fn wan_diagnostic_tool() -> ToolDefinition {
    ToolDefinition {
        name: "diagnose_wan".into(),
        description: "Collect bounded, read-only WAN link, address, route, DNS, and firewall evidence. This tool never changes device state and never performs active network probes.".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
    }
}

fn validate_wan_tool_call(call: &ToolCall) -> Result<(), &'static str> {
    if call.name != "diagnose_wan" {
        return Err("tool name is not in the local allowlist");
    }
    if call.arguments.len() > 256 {
        return Err("tool arguments exceed the local 256-byte limit");
    }
    let arguments: serde_json::Value =
        serde_json::from_str(&call.arguments).map_err(|_| "arguments are not valid JSON")?;
    let Some(arguments) = arguments.as_object() else {
        return Err("arguments must be a JSON object");
    };
    if !arguments.is_empty() {
        return Err("diagnose_wan accepts no arguments");
    }
    Ok(())
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

fn bounded_wan_observation(
    report: &agent_protocol::WanDiagnosticReport,
    limit: usize,
) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct WanObservation<'a> {
        interface: &'a str,
        summary: &'a agent_protocol::WanSummary,
        findings: &'a [String],
        complete: bool,
    }
    let observation = WanObservation {
        interface: &report.interface,
        summary: &report.summary,
        findings: &report.findings,
        complete: report.complete,
    };
    let encoded = serde_json::to_vec(&observation)
        .map_err(|error| format!("failed to encode WAN observation: {error}"))?;
    if encoded.len() > limit {
        return Err(format!(
            "WAN observation is {} bytes, exceeding llm.max_tool_context_bytes {limit}",
            encoded.len()
        ));
    }
    String::from_utf8(encoded)
        .map_err(|error| format!("WAN observation was not valid UTF-8: {error}"))
}

async fn handle_wan_diagnosis(id: String, active: bool, state: &AppState) -> ServerResponse {
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
    persist_diagnostic(&id, active, &report, state).await;
    ServerResponse::success(id, ResponseData::WanDiagnostic(Box::new(report)))
}

async fn persist_diagnostic(
    id: &str,
    active: bool,
    report: &agent_protocol::WanDiagnosticReport,
    state: &AppState,
) {
    let record = DiagnosticRecord {
        id: id.into(),
        kind: "wan".into(),
        active,
        assessment: report.summary.assessment.as_str().into(),
        payload: serde_json::to_vec(&report.summary).unwrap_or_default(),
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
    fn wan_tool_call_requires_allowlisted_name_and_empty_object() {
        let valid = ToolCall {
            id: "call-1".into(),
            name: "diagnose_wan".into(),
            arguments: "{}".into(),
        };
        assert!(validate_wan_tool_call(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.name = "shell".into();
        assert_eq!(
            validate_wan_tool_call(&invalid),
            Err("tool name is not in the local allowlist")
        );

        invalid.name = "diagnose_wan".into();
        invalid.arguments = r#"{"active":true}"#.into();
        assert_eq!(
            validate_wan_tool_call(&invalid),
            Err("diagnose_wan accepts no arguments")
        );

        invalid.arguments = format!(r#"{{"padding":"{}"}}"#, "x".repeat(300));
        assert_eq!(
            validate_wan_tool_call(&invalid),
            Err("tool arguments exceed the local 256-byte limit")
        );
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

    #[tokio::test]
    async fn agent_loop_executes_one_passive_wan_tool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("first accept");
            let first_request = read_http_request(&mut first).await;
            assert!(first_request.contains("\"name\":\"diagnose_wan\""));
            write_json_response(
                &mut first,
                r#"{"model":"mock","choices":[{"message":{"content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"diagnose_wan","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}"#,
            )
            .await;

            let (mut second, _) = listener.accept().await.expect("second accept");
            let second_request = read_http_request(&mut second).await;
            assert!(second_request.contains("\"role\":\"tool\""));
            assert!(second_request.contains("\"tool_call_id\":\"call_1\""));
            write_json_response(
                &mut second,
                r#"{"model":"mock","choices":[{"message":{"content":"WAN analyzed"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":3}}"#,
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
        config.llm.streaming = false;
        config.llm.max_agent_steps = 3;
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
            started: Instant::now(),
            config,
        };
        let response = handle_completion("agent-loop".into(), "check WAN".into(), &state).await;
        assert!(response.ok);
        let Some(ResponseData::Completion(completion)) = response.result else {
            panic!("expected completion");
        };
        assert_eq!(completion.text, "WAN analyzed");
        assert_eq!(completion.prompt_tokens, Some(12));
        assert_eq!(completion.completion_tokens, Some(5));
        server.await.expect("server");
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
}
