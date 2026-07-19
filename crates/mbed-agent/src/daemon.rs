use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_core::{AgentConfig, TmpBudget};
use agent_protocol::{
    ClientRequest, Command, DiagnosticHistoryEntry, ErrorCode, PROTOCOL_VERSION, ResponseData,
    ServerResponse, StatusResponse, StoragePressure, StorageStatus,
};
use agent_store::{DiagnosticRecord, Store};
use agent_tools::ToolRunner;
use platform_openwrt::PlatformCapabilities;
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
    started: Instant,
}

pub async fn run(config_path: &Path) -> Result<(), Box<dyn Error>> {
    let config = AgentConfig::load_or_default(config_path)?;
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
    let listener = bind_socket(&config.server.socket_path, config.server.socket_mode)?;
    let state = Arc::new(AppState {
        config,
        platform,
        budget,
        store,
        tools,
        diagnostic_slots,
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
                degraded_reasons,
            })
        }
        Command::DiagnoseWan { active } => {
            return handle_wan_diagnosis(request.id, active, state).await;
        }
        Command::DiagnosticHistory { limit } => {
            return handle_diagnostic_history(request.id, limit, state).await;
        }
    };
    ServerResponse::success(request.id, result)
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
    ServerResponse::success(id, ResponseData::WanDiagnostic(report))
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
}
