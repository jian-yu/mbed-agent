use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

pub const PROTOCOL_VERSION: u16 = 1;
pub const CHANGE_PLAN_SCHEMA_VERSION: u16 = 1;

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
    ChannelStatus,
    ActionList,
    ActionReload,
    ActionRun {
        action_id: String,
        inputs: Value,
    },
    ActionPlan {
        action_id: String,
        inputs: Value,
    },
    DiagnoseWan {
        active: bool,
    },
    DiagnoseDns,
    DiagnoseDhcp,
    DiagnoseRoutes,
    DiagnoseInterfaces,
    DiagnoseNeighbors,
    DiagnoseFirewall,
    DiagnosePolicyRouting,
    DiagnoseListeners,
    DiagnoseWireless,
    DiagnoseInterfaceStats,
    DiagnoseConntrack,
    DiagnoseQdisc,
    Elevate {
        password: SensitiveString,
    },
    Deauth,
    ChangeGet {
        change_set_id: String,
    },
    ChangeApprove {
        change_set_id: String,
    },
    FirewallPlan {
        mutations: Vec<FirewallMutationRequest>,
    },
    FirewallInventory,
    NetworkPlan {
        mutations: Vec<NetworkMutationRequest>,
    },
    NetworkInventory,
    ChangeApply {
        change_set_id: String,
        approval_id: String,
        approval_token: SensitiveString,
    },
    ChangeConfirm {
        change_set_id: String,
    },
    ChangeReject {
        change_set_id: String,
    },
    DiagnosticHistory {
        limit: u16,
    },
    TaskHistory {
        limit: u16,
    },
    Complete {
        prompt: String,
    },
}

/// Closed, typed mutation request accepted by the firewall planner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum FirewallMutationRequest {
    Create {
        desired: FirewallObject,
    },
    Update {
        expected_digest: String,
        desired: FirewallObject,
    },
    Delete {
        kind: String,
        id: String,
        expected_digest: String,
    },
    Move {
        expected_digest: String,
        desired: FirewallObject,
    },
}

/// Closed, typed mutation request accepted by the L2/L3 network planner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkMutationRequest {
    Create {
        desired: NetworkObject,
    },
    Update {
        expected_digest: String,
        desired: NetworkObject,
    },
    Delete {
        kind: String,
        id: String,
        expected_digest: String,
    },
    Move {
        expected_digest: String,
        desired: NetworkObject,
    },
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
    ChannelStatus(Vec<ChannelStatusEntry>),
    ActionList(Vec<ActionDescriptor>),
    ActionReload(ActionReloadResponse),
    ActionOutput(ActionOutputResponse),
    WanDiagnostic(Box<WanDiagnosticReport>),
    DnsDiagnostic(Box<DnsDiagnosticReport>),
    DhcpDiagnostic(Box<DhcpDiagnosticReport>),
    RouteDiagnostic(Box<RouteDiagnosticReport>),
    InterfaceDiagnostic(Box<InterfaceDiagnosticReport>),
    NeighborDiagnostic(Box<NeighborDiagnosticReport>),
    FirewallDiagnostic(Box<FirewallDiagnosticReport>),
    PolicyRoutingDiagnostic(Box<PolicyRoutingDiagnosticReport>),
    ListenerDiagnostic(Box<ListenerDiagnosticReport>),
    WirelessDiagnostic(Box<WirelessDiagnosticReport>),
    InterfaceStatsDiagnostic(Box<InterfaceStatsDiagnosticReport>),
    ConntrackDiagnostic(Box<ConntrackDiagnosticReport>),
    QdiscDiagnostic(Box<QdiscDiagnosticReport>),
    Elevation(ElevationResponse),
    Deauthenticated { actor_id: String },
    ChangeSet(ChangeSetResponse),
    ChangeApproval(ChangeApprovalResponse),
    FirewallInventory(FirewallInventoryResponse),
    NetworkInventory(NetworkInventoryResponse),
    DiagnosticHistory(Vec<DiagnosticHistoryEntry>),
    TaskHistory(Vec<TaskHistoryEntry>),
    Completion(CompletionResponse),
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SensitiveString(String);

impl SensitiveString {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElevationResponse {
    pub actor_id: String,
    pub role: String,
    pub boot_id: String,
    pub expires_monotonic_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionDescriptor {
    pub id: String,
    pub description: String,
    pub mode: String,
    pub llm_enabled: bool,
    pub platforms: Vec<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelStatusEntry {
    pub channel: String,
    pub enabled: bool,
    pub lifecycle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionReloadResponse {
    pub loaded_actions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionOutputResponse {
    pub action_id: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub output_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeSetResponse {
    pub change_set_id: String,
    pub plan_digest: String,
    pub plan: ChangePlan,
    pub state: ChangeSetState,
    pub rollback_deadline_monotonic_ms: Option<u64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeApprovalResponse {
    pub approval_id: String,
    pub change_set_id: String,
    pub plan_digest: String,
    pub token: SensitiveString,
    pub expires_monotonic_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallInventoryResponse {
    pub objects: Vec<FirewallInventoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallInventoryEntry {
    pub digest: String,
    pub object: FirewallObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInventoryResponse {
    pub objects: Vec<NetworkInventoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInventoryEntry {
    pub digest: String,
    pub object: NetworkObject,
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
pub struct ChangePlan {
    pub schema_version: u16,
    pub plan_id: String,
    pub boot_id: String,
    pub actor_id: String,
    pub created_monotonic_ms: u64,
    pub expires_monotonic_ms: u64,
    pub risk: RiskLevel,
    pub changes: Vec<ChangeDiff>,
    pub validation_checks: Vec<String>,
    pub verification_checks: Vec<String>,
    pub rollback_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeDiff {
    pub object: ConfigObjectRef,
    pub operation: ChangeOperation,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub summary: String,
    pub sensitive_fields_redacted: bool,
    pub risk_signals: ChangeRiskSignals,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigObjectRef {
    pub domain: ConfigDomain,
    pub kind: String,
    pub id: String,
    pub expected_version: Option<String>,
    pub ownership: ObjectOwnership,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    R0,
    R1,
    R2,
    R3,
    R4,
}

impl RiskLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R0 => "r0",
            Self::R1 => "r1",
            Self::R2 => "r2",
            Self::R3 => "r3",
            Self::R4 => "r4",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "r0" => Some(Self::R0),
            "r1" => Some(Self::R1),
            "r2" => Some(Self::R2),
            "r3" => Some(Self::R3),
            "r4" => Some(Self::R4),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDomain {
    Firewall,
    Network,
    Dns,
    Dhcp,
    Wireless,
    Service,
    Qos,
    WireGuard,
    SystemNetwork,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOperation {
    Create,
    Update,
    Delete,
    Move,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectOwnership {
    PlatformNative,
    AgentOwned,
    Unmanaged,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChangeRiskSignals {
    pub affects_management_path: bool,
    pub widens_network_exposure: bool,
    pub disrupts_service: bool,
    pub changes_secret: bool,
    pub changes_device_authentication: bool,
    pub irreversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "spec", rename_all = "snake_case")]
pub enum FirewallObject {
    Zone(FirewallZone),
    Forwarding(FirewallForwarding),
    FilterRule(FirewallFilterRule),
    AddressSet(FirewallAddressSet),
    NatRule(FirewallNatRule),
}

impl FirewallObject {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Zone(value) => &value.id,
            Self::Forwarding(value) => &value.id,
            Self::FilterRule(value) => &value.id,
            Self::AddressSet(value) => &value.id,
            Self::NatRule(value) => &value.id,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Zone(_) => "zone",
            Self::Forwarding(_) => "forwarding",
            Self::FilterRule(_) => "filter_rule",
            Self::AddressSet(_) => "address_set",
            Self::NatRule(_) => "nat_rule",
        }
    }

    #[must_use]
    pub const fn ownership(&self) -> ObjectOwnership {
        match self {
            Self::Zone(value) => value.ownership,
            Self::Forwarding(value) => value.ownership,
            Self::FilterRule(value) => value.ownership,
            Self::AddressSet(value) => value.ownership,
            Self::NatRule(value) => value.ownership,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallZone {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub networks: Vec<String>,
    pub input: FirewallVerdict,
    pub output: FirewallVerdict,
    pub forward: FirewallVerdict,
    pub masquerade: bool,
    pub mtu_fix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallForwarding {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub source_zone: String,
    pub destination_zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallFilterRule {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub direction: FirewallDirection,
    pub matches: FirewallMatch,
    pub verdict: FirewallVerdict,
    pub reject_with: Option<FirewallRejectKind>,
    pub rate_limit: Option<FirewallRateLimit>,
    pub log: Option<FirewallLog>,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallAddressSet {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub family: FirewallFamily,
    pub entries: Vec<FirewallSetEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallNatRule {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub kind: FirewallNatKind,
    pub matches: FirewallMatch,
    pub translation_address: Option<IpAddr>,
    pub translation_port: Option<PortRange>,
    pub order: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallMatch {
    pub family: FirewallFamily,
    pub source_zones: Vec<String>,
    pub destination_zones: Vec<String>,
    pub input_interfaces: Vec<String>,
    pub output_interfaces: Vec<String>,
    pub source_networks: Vec<IpNetwork>,
    pub destination_networks: Vec<IpNetwork>,
    pub source_macs: Vec<String>,
    pub protocols: Vec<FirewallProtocol>,
    pub source_ports: Vec<PortRange>,
    pub destination_ports: Vec<PortRange>,
    pub icmp_types: Vec<u8>,
    pub conntrack_states: Vec<FirewallConntrackState>,
    pub source_sets: Vec<String>,
    pub destination_sets: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDirection {
    Input,
    Output,
    Forward,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallVerdict {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRejectKind {
    TcpReset,
    IcmpPortUnreachable,
    IcmpHostUnreachable,
    Icmp6PortUnreachable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Esp,
    Ah,
    Gre,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FirewallConntrackState {
    New,
    Established,
    Related,
    Invalid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallNatKind {
    Masquerade,
    SourceNat,
    DestinationNat,
    Redirect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FirewallSetEntry {
    Network(IpNetwork),
    Mac(String),
    Port(PortRange),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IpNetwork {
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRateLimit {
    pub packets_per_second: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallLog {
    pub prefix: String,
    pub level: FirewallLogLevel,
}

/// Platform-neutral L2/L3 configuration object. Platform adapters explicitly
/// advertise which variants and fields they can safely persist or apply at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "spec", rename_all = "snake_case")]
pub enum NetworkObject {
    Interface(NetworkInterfaceConfig),
    Bridge(NetworkBridge),
    Vlan(NetworkVlan),
    Bond(NetworkBond),
    Vrf(NetworkVrf),
    Route(NetworkRoute),
    PolicyRule(NetworkPolicyRule),
}

impl NetworkObject {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Interface(value) => &value.id,
            Self::Bridge(value) => &value.id,
            Self::Vlan(value) => &value.id,
            Self::Bond(value) => &value.id,
            Self::Vrf(value) => &value.id,
            Self::Route(value) => &value.id,
            Self::PolicyRule(value) => &value.id,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Interface(_) => "interface",
            Self::Bridge(_) => "bridge",
            Self::Vlan(_) => "vlan",
            Self::Bond(_) => "bond",
            Self::Vrf(_) => "vrf",
            Self::Route(_) => "route",
            Self::PolicyRule(_) => "policy_rule",
        }
    }

    #[must_use]
    pub const fn ownership(&self) -> ObjectOwnership {
        match self {
            Self::Interface(value) => value.ownership,
            Self::Bridge(value) => value.ownership,
            Self::Vlan(value) => value.ownership,
            Self::Bond(value) => value.ownership,
            Self::Vrf(value) => value.ownership,
            Self::Route(value) => value.ownership,
            Self::PolicyRule(value) => value.ownership,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterfaceConfig {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub device: String,
    pub ipv4_mode: NetworkAddressMode,
    pub ipv6_mode: NetworkAddressMode,
    pub addresses: Vec<IpNetwork>,
    pub mtu: Option<u32>,
    pub mac_override: Option<String>,
    /// Whether the platform may keep resolver addresses learned from the peer.
    #[serde(default = "default_peerdns")]
    pub peerdns: bool,
    /// Explicit resolver addresses for platforms that support interface DNS overrides.
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    /// Bounded DNS search suffixes for the interface.
    #[serde(default)]
    pub dns_search: Vec<String>,
    /// Optional DHCP client identifier for `OpenWrt` `clientid`.
    #[serde(default)]
    pub dhcp_client_id: Option<String>,
    /// Optional DHCP vendor identifier for `OpenWrt` `vendorid`.
    #[serde(default)]
    pub dhcp_vendor_id: Option<String>,
    /// Optional DHCP hostname sent to the server.
    #[serde(default)]
    pub dhcp_hostname: Option<String>,
    /// Bounded DHCP option codes requested from the server.
    #[serde(default)]
    pub dhcp_request_options: Vec<u16>,
    /// Whether the DHCP client must not send a release on stop.
    #[serde(default)]
    pub dhcp_no_release: bool,
    /// Optional IPv4 DHCP server configuration for this interface.
    #[serde(default)]
    pub dhcp_server: Option<NetworkDhcpServerConfig>,
}

const fn default_peerdns() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkDhcpServerConfig {
    /// Whether dnsmasq should serve leases on this interface.
    pub enabled: bool,
    /// IPv4 host offset of the first lease.
    pub start: u16,
    /// Maximum number of leases in the pool.
    pub limit: u16,
    /// `OpenWrt` lease duration such as `12h` or `1d`.
    pub lease_time: String,
    /// Whether the server may start even when no clients are detected.
    pub force: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAddressMode {
    Disabled,
    Static,
    Dhcp,
    Automatic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkBridge {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub ports: Vec<String>,
    pub stp: bool,
    pub vlan_filtering: bool,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkVlan {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub parent: String,
    pub vlan_id: u16,
    pub protocol: NetworkVlanProtocol,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkVlanProtocol {
    Ieee8021Q,
    Ieee8021Ad,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkBond {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub ports: Vec<String>,
    pub mode: NetworkBondMode,
    pub primary: Option<String>,
    pub monitor_interval_ms: u32,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkBondMode {
    ActiveBackup,
    BalanceRr,
    BalanceXor,
    Broadcast,
    Ieee8023Ad,
    BalanceTlb,
    BalanceAlb,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkVrf {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub table: u32,
    pub ports: Vec<String>,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRoute {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub destination: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub output_interface: Option<String>,
    pub preferred_source: Option<IpAddr>,
    pub table: u32,
    pub metric: Option<u32>,
    pub route_type: NetworkRouteType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRouteType {
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPolicyRule {
    pub id: String,
    pub ownership: ObjectOwnership,
    pub enabled: bool,
    pub family: NetworkFamily,
    pub priority: u32,
    pub source: Option<IpNetwork>,
    pub destination: Option<IpNetwork>,
    pub input_interface: Option<String>,
    pub output_interface: Option<String>,
    pub fwmark: Option<u32>,
    pub fwmark_mask: Option<u32>,
    pub table: u32,
    pub action: NetworkPolicyAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyAction {
    Lookup,
    Blackhole,
    Unreachable,
    Prohibit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallLogLevel {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSetState {
    Draft,
    Planned,
    AwaitingApproval,
    Approved,
    Staged,
    Validated,
    RollbackArmed,
    Applying,
    Verifying,
    AwaitingConfirmation,
    Confirmed,
    Rejected,
    Expired,
    ApplyFailed,
    RollingBack,
    RolledBack,
    RollbackFailed,
}

impl ChangeSetState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Planned => "planned",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Approved => "approved",
            Self::Staged => "staged",
            Self::Validated => "validated",
            Self::RollbackArmed => "rollback_armed",
            Self::Applying => "applying",
            Self::Verifying => "verifying",
            Self::AwaitingConfirmation => "awaiting_confirmation",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::ApplyFailed => "apply_failed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::RollbackFailed => "rollback_failed",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(Self::Draft),
            "planned" => Some(Self::Planned),
            "awaiting_approval" => Some(Self::AwaitingApproval),
            "approved" => Some(Self::Approved),
            "staged" => Some(Self::Staged),
            "validated" => Some(Self::Validated),
            "rollback_armed" => Some(Self::RollbackArmed),
            "applying" => Some(Self::Applying),
            "verifying" => Some(Self::Verifying),
            "awaiting_confirmation" => Some(Self::AwaitingConfirmation),
            "confirmed" => Some(Self::Confirmed),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            "apply_failed" => Some(Self::ApplyFailed),
            "rolling_back" => Some(Self::RollingBack),
            "rolled_back" => Some(Self::RolledBack),
            "rollback_failed" => Some(Self::RollbackFailed),
            _ => None,
        }
    }
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
pub struct WirelessDiagnosticReport {
    pub summary: WirelessSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirelessSummary {
    pub assessment: WirelessAssessment,
    pub radios: Vec<WirelessRadioSummary>,
    pub interfaces: Vec<WirelessInterfaceSummary>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirelessRadioSummary {
    pub name: String,
    pub up: Option<bool>,
    pub pending: Option<bool>,
    pub disabled: Option<bool>,
    pub channel: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirelessInterfaceSummary {
    pub name: String,
    pub radio: Option<String>,
    pub mode: Option<String>,
    pub ssid: Option<String>,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WirelessAssessment {
    WirelessPresent,
    RadiosDisabled,
    NoWireless,
    CollectorUnavailable,
}

impl WirelessAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WirelessPresent => "wireless_present",
            Self::RadiosDisabled => "radios_disabled",
            Self::NoWireless => "no_wireless",
            Self::CollectorUnavailable => "collector_unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceStatsDiagnosticReport {
    pub summary: InterfaceStatsSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceStatsSummary {
    pub assessment: InterfaceStatsAssessment,
    pub interfaces: Vec<InterfaceStatsEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceStatsEntry {
    pub name: String,
    pub operstate: Option<String>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

impl InterfaceStatsEntry {
    #[must_use]
    pub const fn has_errors_or_drops(&self) -> bool {
        self.rx_errors > 0 || self.rx_dropped > 0 || self.tx_errors > 0 || self.tx_dropped > 0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceStatsAssessment {
    ErrorsOrDropsPresent,
    CountersPresent,
    NoCounters,
    CollectorUnavailable,
}

impl InterfaceStatsAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ErrorsOrDropsPresent => "errors_or_drops_present",
            Self::CountersPresent => "counters_present",
            Self::NoCounters => "no_counters",
            Self::CollectorUnavailable => "collector_unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConntrackDiagnosticReport {
    pub summary: ConntrackSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConntrackSummary {
    pub assessment: ConntrackAssessment,
    pub count: Option<u64>,
    pub limit: Option<u64>,
    pub utilization_percent: Option<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConntrackAssessment {
    Healthy,
    NearCapacity,
    AtCapacity,
    PartialEvidence,
    InvalidLimit,
    Unavailable,
}

impl ConntrackAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::NearCapacity => "near_capacity",
            Self::AtCapacity => "at_capacity",
            Self::PartialEvidence => "partial_evidence",
            Self::InvalidLimit => "invalid_limit",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QdiscDiagnosticReport {
    pub summary: QdiscSummary,
    pub evidence: Vec<ProbeEvidence>,
    pub findings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QdiscSummary {
    pub assessment: QdiscAssessment,
    pub qdiscs: Vec<QdiscEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QdiscEntry {
    pub device: String,
    pub kind: String,
    pub handle: Option<String>,
    pub parent: Option<String>,
    pub root: bool,
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub overlimits: u64,
    pub requeues: u64,
    pub backlog_bytes: u64,
    pub queue_length: u64,
}

impl QdiscEntry {
    #[must_use]
    pub const fn has_pressure_counters(&self) -> bool {
        self.drops > 0 || self.overlimits > 0 || self.requeues > 0 || self.backlog_bytes > 0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QdiscAssessment {
    PressureCountersPresent,
    QdiscsPresent,
    NoQdiscs,
    CollectorUnavailable,
}

impl QdiscAssessment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PressureCountersPresent => "pressure_counters_present",
            Self::QdiscsPresent => "qdiscs_present",
            Self::NoQdiscs => "no_qdiscs",
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
    Unauthorized,
    NotFound,
    Conflict,
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
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
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
            Command::ChannelStatus,
            Command::DiagnoseWan { active: true },
            Command::DiagnoseDns,
            Command::DiagnoseDhcp,
            Command::DiagnoseRoutes,
            Command::DiagnoseInterfaces,
            Command::DiagnoseNeighbors,
            Command::DiagnoseFirewall,
            Command::DiagnosePolicyRouting,
            Command::DiagnoseListeners,
            Command::DiagnoseWireless,
            Command::DiagnoseInterfaceStats,
            Command::DiagnoseConntrack,
            Command::DiagnoseQdisc,
            Command::ActionList,
            Command::ActionReload,
            Command::ActionRun {
                action_id: "vendor_modem".into(),
                inputs: serde_json::json!({"modem_id": 1}),
            },
            Command::ActionPlan {
                action_id: "block_client".into(),
                inputs: serde_json::json!({"client_mac": "02:00:00:00:00:01"}),
            },
            Command::Elevate {
                password: SensitiveString::new("secret".into()),
            },
            Command::Deauth,
            Command::ChangeGet {
                change_set_id: "change-1".into(),
            },
            Command::ChangeApprove {
                change_set_id: "change-1".into(),
            },
            Command::FirewallPlan {
                mutations: Vec::new(),
            },
            Command::FirewallInventory,
            Command::NetworkPlan {
                mutations: Vec::new(),
            },
            Command::NetworkInventory,
            Command::ChangeApply {
                change_set_id: "change-1".into(),
                approval_id: "0123456789abcdef0123456789abcdef".into(),
                approval_token: SensitiveString::new("one-use-secret".into()),
            },
            Command::ChangeConfirm {
                change_set_id: "change-1".into(),
            },
            Command::ChangeReject {
                change_set_id: "change-1".into(),
            },
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

    #[test]
    fn firewall_mutation_requests_reject_unknown_fields() {
        let request = FirewallMutationRequest::Delete {
            kind: "filter_rule".into(),
            id: "guest-block".into(),
            expected_digest: "a".repeat(64),
        };
        let encoded = serde_json::to_vec(&request).expect("encode");
        assert_eq!(
            serde_json::from_slice::<FirewallMutationRequest>(&encoded).expect("decode"),
            request
        );
        assert!(
            serde_json::from_str::<FirewallMutationRequest>(
                r#"{"operation":"delete","kind":"filter_rule","id":"x","expected_digest":"abc","command":"iptables -F"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn network_mutation_and_object_round_trip_are_closed_and_typed() {
        let object = NetworkObject::Vlan(NetworkVlan {
            id: "eth0.100".into(),
            ownership: ObjectOwnership::AgentOwned,
            enabled: true,
            parent: "eth0".into(),
            vlan_id: 100,
            protocol: NetworkVlanProtocol::Ieee8021Q,
            mtu: Some(1500),
        });
        let request = NetworkMutationRequest::Create {
            desired: object.clone(),
        };
        let encoded = serde_json::to_vec(&request).expect("encode");
        assert_eq!(
            serde_json::from_slice::<NetworkMutationRequest>(&encoded).expect("decode"),
            request
        );
        assert_eq!(object.kind(), "vlan");
        assert_eq!(object.id(), "eth0.100");
        assert!(
            serde_json::from_str::<NetworkMutationRequest>(
                r#"{"operation":"delete","kind":"route","id":"x","expected_digest":"abc","argv":["ip","route","flush"]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn network_interface_dns_fields_are_backward_compatible() {
        let interface: NetworkInterfaceConfig = serde_json::from_str(
            r#"{
                "id":"lan",
                "ownership":"platform_native",
                "enabled":true,
                "device":"br-lan",
                "ipv4_mode":"static",
                "ipv6_mode":"disabled",
                "addresses":[{"address":"192.0.2.1","prefix_len":24}],
                "mtu":1500,
                "mac_override":null
            }"#,
        )
        .expect("decode legacy interface");
        assert!(interface.peerdns);
        assert!(interface.dns_servers.is_empty());
        assert!(interface.dns_search.is_empty());
        assert!(interface.dhcp_client_id.is_none());
        assert!(interface.dhcp_vendor_id.is_none());
        assert!(interface.dhcp_hostname.is_none());
        assert!(interface.dhcp_request_options.is_empty());
        assert!(!interface.dhcp_no_release);
        assert!(interface.dhcp_server.is_none());
    }

    #[test]
    fn change_plan_round_trip_preserves_security_fields() {
        let plan = ChangePlan {
            schema_version: CHANGE_PLAN_SCHEMA_VERSION,
            plan_id: "plan-1".into(),
            boot_id: "boot-1".into(),
            actor_id: "cli/root".into(),
            created_monotonic_ms: 100,
            expires_monotonic_ms: 200,
            risk: RiskLevel::R3,
            changes: vec![ChangeDiff {
                object: ConfigObjectRef {
                    domain: ConfigDomain::Firewall,
                    kind: "rule".into(),
                    id: "managed-rule".into(),
                    expected_version: None,
                    ownership: ObjectOwnership::AgentOwned,
                },
                operation: ChangeOperation::Create,
                before_digest: None,
                after_digest: Some("a".repeat(64)),
                summary: "create a managed firewall rule".into(),
                sensitive_fields_redacted: true,
                risk_signals: ChangeRiskSignals {
                    widens_network_exposure: true,
                    ..ChangeRiskSignals::default()
                },
            }],
            validation_checks: vec!["firewall schema validates".into()],
            verification_checks: vec!["management path remains reachable".into()],
            rollback_required: true,
        };
        let encoded = serde_json::to_string(&plan).expect("serialize change plan");
        let decoded: ChangePlan = serde_json::from_str(&encoded).expect("deserialize change plan");
        assert_eq!(decoded, plan);
    }

    #[test]
    fn sensitive_strings_are_redacted_from_debug_output() {
        let secret = SensitiveString::new("do-not-log".into());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn typed_firewall_object_round_trip_preserves_ownership_and_policy() {
        let object = FirewallObject::Zone(FirewallZone {
            id: "guest".into(),
            ownership: ObjectOwnership::PlatformNative,
            enabled: true,
            networks: vec!["guest".into()],
            input: FirewallVerdict::Reject,
            output: FirewallVerdict::Accept,
            forward: FirewallVerdict::Drop,
            masquerade: false,
            mtu_fix: true,
        });
        let encoded = serde_json::to_string(&object).expect("encode");
        let decoded: FirewallObject = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, object);
        assert_eq!(decoded.kind(), "zone");
        assert_eq!(decoded.id(), "guest");
    }
}
