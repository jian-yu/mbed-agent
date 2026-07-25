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
    DiagnoseDns,
    DiagnoseDhcp,
    DiagnoseRoutes,
    DiagnoseInterfaces,
    DiagnoseNeighbors,
    DiagnoseFirewall,
    DiagnosePolicyRouting,
    DiagnoseListeners,
    DiagnosticHistory { limit: u16 },
    TaskHistory { limit: u16 },
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
    DnsDiagnostic(Box<DnsDiagnosticReport>),
    DhcpDiagnostic(Box<DhcpDiagnosticReport>),
    RouteDiagnostic(Box<RouteDiagnosticReport>),
    InterfaceDiagnostic(Box<InterfaceDiagnosticReport>),
    NeighborDiagnostic(Box<NeighborDiagnosticReport>),
    FirewallDiagnostic(Box<FirewallDiagnosticReport>),
    PolicyRoutingDiagnostic(Box<PolicyRoutingDiagnosticReport>),
    ListenerDiagnostic(Box<ListenerDiagnosticReport>),
    DiagnosticHistory(Vec<DiagnosticHistoryEntry>),
    TaskHistory(Vec<TaskHistoryEntry>),
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
pub struct TaskHistoryEntry {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub provider: String,
    pub model: String,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub duration_ms: u64,
    pub error_code: Option<String>,
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
pub struct DnsDiagnosticReport {
    pub interface: String,
    pub summary: DnsSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsSummary {
    pub assessment: WanAssessment,
    pub status_source: Option<String>,
    pub device: Option<String>,
    pub addresses: Vec<String>,
    pub default_routes: Vec<WanRoute>,
    pub dns_servers: Vec<String>,
    pub dns_reachable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpDiagnosticReport {
    pub interface: String,
    pub summary: DhcpSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpSummary {
    pub assessment: DhcpAssessment,
    pub status_source: Option<String>,
    pub protocol: Option<String>,
    pub pending: Option<bool>,
    pub device: Option<String>,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DhcpAssessment {
    LeaseReady,
    Negotiating,
    LeaseMissing,
    NotDhcp,
    LinkDown,
    InterfaceUnavailable,
    InsufficientEvidence,
}

impl DhcpAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseReady => "lease_ready",
            Self::Negotiating => "negotiating",
            Self::LeaseMissing => "lease_missing",
            Self::NotDhcp => "not_dhcp",
            Self::LinkDown => "link_down",
            Self::InterfaceUnavailable => "interface_unavailable",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteDiagnosticReport {
    pub interface: String,
    pub summary: RouteSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteSummary {
    pub assessment: WanAssessment,
    pub status_source: Option<String>,
    pub device: Option<String>,
    pub addresses: Vec<String>,
    pub default_routes: Vec<WanRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceDiagnosticReport {
    pub summary: InterfaceSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceSummary {
    pub assessment: InterfaceAssessment,
    pub interfaces: Vec<NetworkInterfaceSummary>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterfaceSummary {
    pub name: String,
    pub index: Option<u64>,
    pub kind: Option<String>,
    pub operstate: Option<String>,
    pub up: Option<bool>,
    pub carrier: Option<bool>,
    pub mtu: Option<u64>,
    pub master: Option<String>,
    pub addresses: Vec<String>,
    pub dynamic_address: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceAssessment {
    InterfacesReady,
    LinksDown,
    NoUsableInterfaces,
    InsufficientEvidence,
}

impl InterfaceAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InterfacesReady => "interfaces_ready",
            Self::LinksDown => "links_down",
            Self::NoUsableInterfaces => "no_usable_interfaces",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeighborDiagnosticReport {
    pub summary: NeighborSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeighborSummary {
    pub assessment: NeighborAssessment,
    pub entries: Vec<NeighborEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeighborEntry {
    pub destination: String,
    pub device: String,
    pub link_address: Option<String>,
    pub states: Vec<String>,
    pub router: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeighborAssessment {
    NeighborsPresent,
    ResolutionFailuresPresent,
    NoEntries,
    InsufficientEvidence,
}

impl NeighborAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeighborsPresent => "neighbors_present",
            Self::ResolutionFailuresPresent => "resolution_failures_present",
            Self::NoEntries => "no_entries",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallDiagnosticReport {
    pub summary: FirewallRuntimeSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRuntimeSummary {
    pub assessment: FirewallAssessment,
    pub backend: String,
    pub tables: u32,
    pub chains: u32,
    pub rules: u32,
    pub rules_with_counters: u32,
    pub base_chains: Vec<FirewallBaseChain>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallBaseChain {
    pub family: String,
    pub table: String,
    pub name: String,
    pub hook: Option<String>,
    pub policy: Option<String>,
    pub rules: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAssessment {
    RuntimeRulesPresent,
    EmptyRuleset,
    BackendUnavailable,
    InsufficientEvidence,
}

impl FirewallAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeRulesPresent => "runtime_rules_present",
            Self::EmptyRuleset => "empty_ruleset",
            Self::BackendUnavailable => "backend_unavailable",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRoutingDiagnosticReport {
    pub summary: PolicyRoutingSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRoutingSummary {
    pub assessment: PolicyRoutingAssessment,
    pub rules: Vec<PolicyRule>,
    pub tables: Vec<RouteTableSummary>,
    pub total_routes: u32,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub priority: Option<u64>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub table: String,
    pub action: Option<String>,
    pub fwmark: Option<String>,
    pub incoming_interface: Option<String>,
    pub outgoing_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteTableSummary {
    pub table: String,
    pub routes: u32,
    pub default_routes: u32,
    pub exceptional_routes: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRoutingAssessment {
    CustomPolicyPresent,
    DefaultPolicyOnly,
    NoRules,
    InsufficientEvidence,
}

impl PolicyRoutingAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustomPolicyPresent => "custom_policy_present",
            Self::DefaultPolicyOnly => "default_policy_only",
            Self::NoRules => "no_rules",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerDiagnosticReport {
    pub summary: ListenerSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerSummary {
    pub assessment: ListenerAssessment,
    pub listeners: Vec<ListenerEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerEntry {
    pub protocol: String,
    pub family: String,
    pub local_address: String,
    pub port: u16,
    pub scope: ListenerScope,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListenerScope {
    Wildcard,
    Loopback,
    LinkLocal,
    Specific,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListenerAssessment {
    ListenersPresent,
    NoListeners,
    CollectorUnavailable,
}

impl ListenerAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListenersPresent => "listeners_present",
            Self::NoListeners => "no_listeners",
            Self::CollectorUnavailable => "collector_unavailable",
        }
    }
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
    pub logging_dropped_records: u64,
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

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::Internal => "internal",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unavailable => "unavailable",
            Self::Upstream => "upstream",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_round_trip_is_stable() {
        for command in [
            Command::DiagnoseWan { active: true },
            Command::DiagnoseDns,
            Command::DiagnoseDhcp,
            Command::DiagnoseRoutes,
            Command::DiagnoseInterfaces,
            Command::DiagnoseNeighbors,
            Command::DiagnoseFirewall,
            Command::DiagnosePolicyRouting,
            Command::DiagnoseListeners,
        ] {
            let request = ClientRequest {
                protocol_version: PROTOCOL_VERSION,
                id: "test-1".into(),
                command,
            };
            let encoded = serde_json::to_string(&request).expect("serialize request");
            let decoded: ClientRequest =
                serde_json::from_str(&encoded).expect("deserialize request");
            assert_eq!(decoded, request);
        }
    }
}
