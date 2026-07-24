use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientRequest {
    pub protocol_version: u16,
    pub id: String,
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    Ping,
    Status,
    Capabilities,
    DiagnoseWan { active: bool },
    DiagnosticHistory { limit: u16 },
    Complete { prompt: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    pub protocol_version: u16,
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResponseData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

impl ServerResponse {
    #[must_use]
    pub fn success(id: impl Into<String>, result: ResponseData) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(id: impl Into<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            id: id.into(),
            ok: false,
            result: None,
            error: Some(ProtocolError {
                code,
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ResponseData {
    Pong { daemon_version: String },
    Status(StatusResponse),
    Capabilities(Value),
    WanDiagnostic(Box<WanDiagnosticReport>),
    DiagnosticHistory(Vec<DiagnosticHistoryEntry>),
    Completion(CompletionResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletionResponse {
    pub text: String,
    pub model: String,
    pub finish_reason: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticHistoryEntry {
    pub id: String,
    pub kind: String,
    pub active: bool,
    pub assessment: String,
    pub summary: Value,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WanDiagnosticReport {
    pub interface: String,
    pub summary: WanSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WanSummary {
    pub assessment: WanAssessment,
    pub status_source: Option<String>,
    pub up: Option<bool>,
    pub available: Option<bool>,
    pub pending: Option<bool>,
    pub protocol: Option<String>,
    pub device: Option<String>,
    pub addresses: Vec<String>,
    pub default_routes: Vec<WanRoute>,
    pub dns_servers: Vec<String>,
    pub firewall_backend: String,
    pub firewall_zone: Option<FirewallZoneSummary>,
    pub active_attempted: bool,
    pub gateway_reachable: Option<bool>,
    pub internet_reachable: Option<bool>,
    pub dns_reachable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallZoneSummary {
    pub name: String,
    pub networks: Vec<String>,
    pub input_policy: Option<String>,
    pub output_policy: Option<String>,
    pub forward_policy: Option<String>,
    pub masquerading: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WanAssessment {
    PrerequisitesReady,
    LinkDown,
    InterfaceUnavailable,
    AddressMissing,
    DefaultRouteMissing,
    DnsMissing,
    GatewayProbeFailed,
    PublicIpProbeFailed,
    DnsProbeFailed,
    InsufficientEvidence,
}

impl WanAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrerequisitesReady => "prerequisites_ready",
            Self::LinkDown => "link_down",
            Self::InterfaceUnavailable => "interface_unavailable",
            Self::AddressMissing => "address_missing",
            Self::DefaultRouteMissing => "default_route_missing",
            Self::DnsMissing => "dns_missing",
            Self::GatewayProbeFailed => "gateway_probe_failed",
            Self::PublicIpProbeFailed => "public_ip_probe_failed",
            Self::DnsProbeFailed => "dns_probe_failed",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WanRoute {
    pub family: String,
    pub gateway: Option<String>,
    pub device: Option<String>,
    pub source: Option<String>,
    pub metric: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeEvidence {
    pub probe: String,
    pub source: String,
    pub status: ProbeStatus,
    pub output: String,
    pub truncated: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Ok,
    Unavailable,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub daemon_version: String,
    pub protocol_version: u16,
    pub uptime_secs: u64,
    pub profile: String,
    pub storage: StorageStatus,
    pub platform_kind: String,
    pub llm_enabled: bool,
    pub llm_provider: String,
    pub llm_streaming: bool,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageStatus {
    pub database_bytes: u64,
    pub database_limit_bytes: u64,
    pub managed_bytes: u64,
    pub total_budget_bytes: u64,
    pub tmp_available_bytes: u64,
    pub pressure: StoragePressure,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StoragePressure {
    Normal,
    Pressure,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedProtocol,
    Internal,
    ResourceExhausted,
    Unavailable,
    Upstream,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_round_trip_is_stable() {
        let request = ClientRequest {
            protocol_version: PROTOCOL_VERSION,
            id: "test-1".into(),
            command: Command::DiagnoseWan { active: true },
        };

        let encoded = serde_json::to_string(&request).expect("serialize request");
        let decoded: ClientRequest = serde_json::from_str(&encoded).expect("deserialize request");
        assert_eq!(decoded, request);
    }
}
