use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::auth::AdminPasswordVerifier;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;
const LOG_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub schema_version: u32,
    pub profile: Profile,
    pub runtime: RuntimeConfig,
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub auth: AuthConfig,
    pub llm: LlmConfig,
    pub extensions: ExtensionsConfig,
    pub channels: ChannelsConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            profile: Profile::Tiny,
            runtime: RuntimeConfig::default(),
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            auth: AuthConfig::default(),
            llm: LlmConfig::default(),
            extensions: ExtensionsConfig::default(),
            channels: ChannelsConfig::default(),
        }
    }
}

impl AgentConfig {
    /// Loads and validates a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Loads a configuration file when present, or returns validated defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing file cannot be loaded or the resulting
    /// configuration is invalid.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        if path.exists() {
            Self::load(path)
        } else {
            let config = Self::default();
            config.validate()?;
            Ok(config)
        }
    }

    /// Validates schema compatibility, runtime paths, and resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or inconsistent limits.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ConfigError::Validation(format!(
                "unsupported schema_version {}; expected {CURRENT_SCHEMA_VERSION}",
                self.schema_version
            )));
        }

        validate_tmp_path(&self.server.socket_path, "server.socket_path")?;
        validate_tmp_path(&self.storage.path, "storage.path")?;
        validate_tmp_path(&self.logging.path, "logging.path")?;

        if self.runtime.max_active_tasks == 0
            || self.runtime.max_request_bytes < 1024
            || self.runtime.tool_timeout_secs == 0
            || self.runtime.max_tool_output_bytes < 1024
            || !(5..=600).contains(&self.runtime.rollback_confirm_timeout_secs)
        {
            return Err(ConfigError::Validation(
                "runtime limits must allow a task, a tool timeout, 1024-byte buffers, and a rollback confirmation timeout of 5-600 seconds".into(),
            ));
        }
        if self.server.socket_mode > 0o777 {
            return Err(ConfigError::Validation(
                "server.socket_mode must not contain bits above 0o777".into(),
            ));
        }
        if self.storage.max_database_bytes == 0 || self.storage.max_total_bytes == 0 {
            return Err(ConfigError::Validation(
                "storage limits must be greater than zero".into(),
            ));
        }
        if self.storage.max_artifact_files == 0 || self.storage.max_artifact_files > 4096 {
            return Err(ConfigError::Validation(
                "storage.max_artifact_files must be between 1 and 4096".into(),
            ));
        }
        if !storage_record_limits_valid(&self.storage) {
            return Err(ConfigError::Validation(
                "task, diagnostic, ChangeSet, firewall state, and execution plan limits must be non-zero and fit the database budget"
                    .into(),
            ));
        }
        if self.storage.min_tmp_free_percent > 100 {
            return Err(ConfigError::Validation(
                "storage.min_tmp_free_percent must be between 0 and 100".into(),
            ));
        }
        if self.storage.cleanup_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "storage.cleanup_interval_secs must be greater than zero".into(),
            ));
        }

        if !LOG_LEVELS.contains(&self.logging.level.as_str()) {
            return Err(ConfigError::Validation(format!(
                "logging.level must be one of {}",
                LOG_LEVELS.join(", ")
            )));
        }
        if self.logging.rate_limit_per_target_per_sec == 0 {
            return Err(ConfigError::Validation(
                "logging.rate_limit_per_target_per_sec must be greater than zero".into(),
            ));
        }

        self.auth.validate()?;
        self.llm.validate()?;
        self.extensions.validate()?;
        self.channels.validate()?;

        let allocated = self
            .storage
            .max_database_bytes
            .saturating_add(self.storage.max_artifacts_bytes)
            .saturating_add(self.storage.max_rollback_bytes)
            .saturating_add(self.storage.runtime_headroom_bytes)
            .saturating_add(self.logging.max_total_bytes);
        if allocated > self.storage.max_total_bytes {
            return Err(ConfigError::Validation(format!(
                "configured /tmp partitions total {allocated} bytes, exceeding max_total_bytes {}",
                self.storage.max_total_bytes
            )));
        }

        let log_capacity = self
            .logging
            .max_file_bytes
            .saturating_mul(u64::from(self.logging.max_files));
        if self.logging.max_files == 0
            || self.logging.max_line_bytes == 0
            || self.logging.max_line_bytes > self.logging.max_file_bytes
            || log_capacity > self.logging.max_total_bytes
        {
            return Err(ConfigError::Validation(
                "logging rotation limits are inconsistent".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionsConfig {
    pub enabled: bool,
    pub directories: Vec<PathBuf>,
    pub trusted_manifest_owner_uid: u32,
    pub trusted_executable_owner_uid: u32,
    pub max_manifests: usize,
    pub max_manifest_bytes: usize,
    pub max_actions: usize,
    pub max_argv: usize,
    pub max_inputs: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub timeout_secs: u64,
}

impl Default for ExtensionsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec![
                PathBuf::from("/usr/share/mbed-agent/actions.d"),
                PathBuf::from("/etc/mbed-agent/actions.d"),
            ],
            trusted_manifest_owner_uid: 0,
            trusted_executable_owner_uid: 0,
            max_manifests: 32,
            max_manifest_bytes: 32 * 1024,
            max_actions: 64,
            max_argv: 32,
            max_inputs: 16,
            max_input_bytes: 1024,
            max_output_bytes: 64 * 1024,
            timeout_secs: 5,
        }
    }
}

impl ExtensionsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.directories.len() > 8
            || self.max_manifests == 0
            || self.max_manifests > 256
            || self.max_manifest_bytes < 256
            || self.max_manifest_bytes > 256 * 1024
            || self.max_actions == 0
            || self.max_actions > 256
            || self.max_argv == 0
            || self.max_argv > 64
            || self.max_inputs > 32
            || self.max_input_bytes == 0
            || self.max_input_bytes > 16 * 1024
            || self.max_output_bytes < 256
            || self.max_output_bytes > 1024 * 1024
            || !(1..=60).contains(&self.timeout_secs)
        {
            return Err(ConfigError::Validation(
                "extension manifest, action, argv, input, output, and timeout limits are inconsistent"
                    .into(),
            ));
        }
        for directory in &self.directories {
            if !directory.is_absolute()
                || directory.starts_with("/tmp")
                || directory.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(ConfigError::Validation(
                    "extension directories must be absolute normalized persistent paths outside /tmp"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelsConfig {
    pub mqtt: MqttChannelConfig,
    pub wechat_clawbot: WeChatClawBotConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MqttChannelConfig {
    pub enabled: bool,
    pub broker: String,
    pub client_id: String,
    pub device_id: String,
    pub username: String,
    pub password: SecretString,
    pub keep_alive_secs: u64,
    pub reconnect_min_secs: u64,
    pub reconnect_max_secs: u64,
    pub max_inflight: u16,
    pub max_packet_bytes: usize,
}

impl Default for MqttChannelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            broker: "mqtts://localhost:8883".into(),
            client_id: "mbed-agent".into(),
            device_id: "device".into(),
            username: String::new(),
            password: SecretString::default(),
            keep_alive_secs: 30,
            reconnect_min_secs: 1,
            reconnect_max_secs: 60,
            max_inflight: 8,
            max_packet_bytes: 32 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WeChatClawBotConfig {
    pub enabled: bool,
    pub account: String,
    pub base_url: String,
    pub bot_token: SecretString,
    pub bot_agent: String,
    pub long_poll_timeout_secs: u64,
    pub request_timeout_secs: u64,
}

impl Default for WeChatClawBotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            account: "default".into(),
            base_url: "https://ilinkai.weixin.qq.com".into(),
            bot_token: SecretString::default(),
            bot_agent: "MbedAgent/0.1.0".into(),
            long_poll_timeout_secs: 35,
            request_timeout_secs: 10,
        }
    }
}

impl ChannelsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.mqtt.validate()?;
        self.wechat_clawbot.validate()
    }
}

impl MqttChannelConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(5..=300).contains(&self.keep_alive_secs)
            || self.reconnect_min_secs == 0
            || self.reconnect_min_secs > self.reconnect_max_secs
            || self.reconnect_max_secs > 300
            || self.max_inflight == 0
            || self.max_inflight > 64
            || !(1024..=32 * 1024).contains(&self.max_packet_bytes)
            || !valid_channel_identifier(&self.client_id)
            || !valid_channel_identifier(&self.device_id)
            || self.username.len() > 256
            || self.username.chars().any(char::is_control)
        {
            return Err(ConfigError::Validation(
                "MQTT channel identifiers, reconnect limits, inflight count, or packet size are invalid"
                    .into(),
            ));
        }
        let has_username = !self.username.is_empty();
        let has_password = !self.password.is_empty();
        if has_username != has_password {
            return Err(ConfigError::Validation(
                "MQTT username and password must either both be configured or both be empty".into(),
            ));
        }
        if self.enabled {
            parse_mqtts_broker(&self.broker)?;
        }
        Ok(())
    }
}

impl WeChatClawBotConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_channel_identifier(&self.account)
            || self.bot_agent.is_empty()
            || self.bot_agent.len() > 256
            || self.bot_agent.chars().any(char::is_control)
            || !(10..=60).contains(&self.long_poll_timeout_secs)
            || !(1..=60).contains(&self.request_timeout_secs)
            || self.bot_token.expose().len() > 8192
            || self.bot_token.expose().chars().any(char::is_control)
        {
            return Err(ConfigError::Validation(
                "WeChat ClawBot account, user-agent, token, and timeout limits are invalid".into(),
            ));
        }
        if self.enabled && self.bot_token.is_empty() {
            return Err(ConfigError::Validation(
                "enabled WeChat ClawBot requires bot_token".into(),
            ));
        }
        if self.enabled {
            parse_wechat_clawbot_base_url(&self.base_url)?;
        }
        Ok(())
    }
}

/// Parses the narrow HTTPS base URL used by the official `WeChat` `ClawBot` API.
///
/// The persisted value deliberately contains only a scheme and authority. API
/// paths are owned by the adapter so a configuration edit cannot redirect a
/// request to an arbitrary path or embed credentials in the URL.
///
/// # Errors
///
/// Returns an error when the value is not an HTTPS host-only URL.
pub fn parse_wechat_clawbot_base_url(value: &str) -> Result<&str, ConfigError> {
    let authority = value.strip_prefix("https://").ok_or_else(|| {
        ConfigError::Validation("WeChat ClawBot base_url must use https://".into())
    })?;
    if authority.is_empty()
        || authority.len() > 253
        || authority.chars().any(char::is_whitespace)
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@' | b':'))
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ConfigError::Validation(
            "WeChat ClawBot base_url must contain only an HTTPS host".into(),
        ));
    }
    Ok(authority)
}

/// Parses the deliberately narrow production MQTT broker form.
///
/// # Errors
///
/// Returns an error unless the value is `mqtts://host:port` without userinfo,
/// paths, queries, fragments, whitespace, or MQTT topic metacharacters.
pub fn parse_mqtts_broker(value: &str) -> Result<(&str, u16), ConfigError> {
    let authority = value.strip_prefix("mqtts://").ok_or_else(|| {
        ConfigError::Validation("enabled MQTT broker must use mqtts:// TLS".into())
    })?;
    if authority.is_empty()
        || authority.chars().any(char::is_whitespace)
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(ConfigError::Validation(
            "MQTT broker must contain only a host and explicit port".into(),
        ));
    }
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        ConfigError::Validation("MQTT broker must include an explicit port".into())
    })?;
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ConfigError::Validation(
            "MQTT broker host is invalid".into(),
        ));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::Validation("MQTT broker port is invalid".into()))?;
    Ok((host, port))
}

fn valid_channel_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn storage_record_limits_valid(storage: &StorageConfig) -> bool {
    storage.max_diagnostic_records > 0
        && storage.max_task_records > 0
        && storage.max_change_set_records > 0
        && storage.max_diagnostic_record_bytes > 0
        && storage.max_change_plan_bytes > 0
        && storage.max_firewall_state_bytes > 0
        && storage.max_network_state_bytes > 0
        && storage.max_firewall_execution_plan_bytes > 0
        && storage.max_channel_message_records > 0
        && storage.max_channel_message_records <= 4096
        && storage.max_channel_payload_bytes > 0
        && storage.max_channel_payload_bytes <= 32 * 1024
        && storage.max_diagnostic_record_bytes <= storage.max_database_bytes
        && storage.max_change_plan_bytes <= storage.max_database_bytes
        && storage.max_firewall_state_bytes <= storage.max_database_bytes
        && storage.max_network_state_bytes <= storage.max_database_bytes
        && storage.max_firewall_execution_plan_bytes <= storage.max_database_bytes
        && u64::from(storage.max_channel_message_records)
            .saturating_mul(storage.max_channel_payload_bytes)
            <= storage.max_database_bytes / 2
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub admin_password_hash: SecretString,
    pub capability_ttl_secs: u64,
    pub approval_ttl_secs: u64,
    pub max_failures: u8,
    pub lockout_secs: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            admin_password_hash: SecretString::default(),
            capability_ttl_secs: 300,
            approval_ttl_secs: 120,
            max_failures: 5,
            lockout_secs: 60,
        }
    }
}

impl AuthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(30..=900).contains(&self.capability_ttl_secs)
            || !(30..=300).contains(&self.approval_ttl_secs)
            || !(1..=20).contains(&self.max_failures)
            || !(1..=3_600).contains(&self.lockout_secs)
        {
            return Err(ConfigError::Validation(
                "auth limits are inconsistent: capability TTL must be 30-900 seconds, approval TTL 30-300 seconds, max failures 1-20, and lockout 1-3600 seconds".into(),
            ));
        }
        if self.enabled {
            AdminPasswordVerifier::parse(self.admin_password_hash.expose()).map_err(|_| {
                ConfigError::Validation(
                    "enabled auth requires a valid PBKDF2-SHA256 admin_password_hash".into(),
                )
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmConfig {
    pub enabled: bool,
    pub provider: LlmProviderKind,
    pub base_url: String,
    pub api_key: SecretString,
    pub model: String,
    pub system_prompt: String,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stream_event_bytes: usize,
    pub max_output_tokens: u32,
    pub streaming: bool,
    pub max_agent_steps: u8,
    pub max_tool_context_bytes: usize,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: LlmProviderKind::OpenAiCompatible,
            base_url: "https://api.openai.com/v1".into(),
            api_key: SecretString::default(),
            model: String::new(),
            system_prompt: "You are a professional Linux networking and OpenWrt engineer. Be precise, evidence-driven, and conservative about device changes.".into(),
            connect_timeout_secs: 10,
            request_timeout_secs: 60,
            max_request_bytes: 32 * 1024,
            max_response_bytes: 128 * 1024,
            max_stream_event_bytes: 16 * 1024,
            max_output_tokens: 1024,
            streaming: true,
            max_agent_steps: 4,
            max_tool_context_bytes: 16 * 1024,
        }
    }
}

impl LlmConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.connect_timeout_secs == 0
            || self.request_timeout_secs == 0
            || self.max_request_bytes < 1024
            || self.max_response_bytes < 1024
            || self.max_stream_event_bytes < 1024
            || self.max_stream_event_bytes > self.max_response_bytes
            || self.max_output_tokens == 0
            || self.max_agent_steps == 0
            || self.max_agent_steps > 16
            || self.max_tool_context_bytes < 1024
            || self.max_tool_context_bytes > self.max_request_bytes
        {
            return Err(ConfigError::Validation(
                "llm limits are inconsistent: buffers and steps must be non-zero, stream events must fit the response limit, tool context must fit a request, and agent steps must not exceed 16".into(),
            ));
        }
        if self.enabled {
            if !self.base_url.starts_with("https://")
                || self.base_url.chars().any(char::is_whitespace)
            {
                return Err(ConfigError::Validation(
                    "enabled llm.base_url must be an HTTPS URL without whitespace".into(),
                ));
            }
            if self.api_key.is_empty() || self.model.trim().is_empty() || self.model.len() > 128 {
                return Err(ConfigError::Validation(
                    "enabled LLM requires llm.api_key and a model name no longer than 128 bytes"
                        .into(),
                ));
            }
            if self.system_prompt.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "enabled LLM requires a non-empty llm.system_prompt".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LlmProviderKind {
    #[default]
    OpenAiCompatible,
}

impl LlmProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiCompatible => "open-ai-compatible",
        }
    }
}

fn validate_tmp_path(path: &Path, field: &str) -> Result<(), ConfigError> {
    if !path.is_absolute() || !path.starts_with("/tmp/mbed-agent") {
        return Err(ConfigError::Validation(format!(
            "{field} must be an absolute path below /tmp/mbed-agent"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Tiny,
    Standard,
    Full,
}

impl Profile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub max_active_tasks: usize,
    pub max_request_bytes: usize,
    pub task_timeout_secs: u64,
    pub tool_timeout_secs: u64,
    pub max_tool_output_bytes: usize,
    pub rollback_confirm_timeout_secs: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_active_tasks: 1,
            max_request_bytes: 64 * 1024,
            task_timeout_secs: 120,
            tool_timeout_secs: 3,
            max_tool_output_bytes: 64 * 1024,
            rollback_confirm_timeout_secs: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub socket_mode: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/tmp/mbed-agent/agent.sock"),
            socket_mode: 0o660,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub max_database_bytes: u64,
    pub max_artifacts_bytes: u64,
    pub max_artifact_files: u32,
    pub max_rollback_bytes: u64,
    pub max_total_bytes: u64,
    pub runtime_headroom_bytes: u64,
    pub min_tmp_free_bytes: u64,
    pub min_tmp_free_percent: u8,
    pub cleanup_interval_secs: u64,
    pub max_task_records: u32,
    pub max_diagnostic_records: u32,
    pub max_diagnostic_record_bytes: u64,
    pub max_change_set_records: u32,
    pub max_change_plan_bytes: u64,
    pub max_firewall_state_bytes: u64,
    pub max_network_state_bytes: u64,
    pub max_firewall_execution_plan_bytes: u64,
    pub max_channel_message_records: u32,
    pub max_channel_payload_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/tmp/mbed-agent/agent.db"),
            max_database_bytes: 8 * 1024 * 1024,
            max_artifacts_bytes: 8 * 1024 * 1024,
            max_artifact_files: 64,
            max_rollback_bytes: 4 * 1024 * 1024,
            max_total_bytes: 24 * 1024 * 1024,
            runtime_headroom_bytes: 2 * 1024 * 1024,
            min_tmp_free_bytes: 8 * 1024 * 1024,
            min_tmp_free_percent: 10,
            cleanup_interval_secs: 60,
            max_task_records: 256,
            max_diagnostic_records: 128,
            max_diagnostic_record_bytes: 32 * 1024,
            max_change_set_records: 32,
            max_change_plan_bytes: 64 * 1024,
            max_firewall_state_bytes: 256 * 1024,
            max_network_state_bytes: 256 * 1024,
            max_firewall_execution_plan_bytes: 256 * 1024,
            max_channel_message_records: 64,
            max_channel_payload_bytes: 32 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: String,
    pub directives: Vec<String>,
    pub path: PathBuf,
    pub format: LogFormat,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_files: u32,
    pub max_line_bytes: u64,
    pub rate_limit_per_target_per_sec: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            directives: vec![],
            path: PathBuf::from("/tmp/mbed-agent/log/agent.log"),
            format: LogFormat::Compact,
            max_total_bytes: 2 * 1024 * 1024,
            max_file_bytes: 256 * 1024,
            max_files: 8,
            max_line_bytes: 4096,
            rate_limit_per_target_per_sec: 20,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    #[default]
    Compact,
    JsonLines,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse configuration {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        AgentConfig::default().validate().expect("valid defaults");
    }

    #[test]
    fn persistent_database_path_is_rejected() {
        let mut config = AgentConfig::default();
        config.storage.path = PathBuf::from("/etc/mbed-agent/agent.db");
        assert!(config.validate().is_err());
    }

    #[test]
    fn aggregate_budget_is_enforced() {
        let mut config = AgentConfig::default();
        config.storage.max_total_bytes = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn enabled_llm_requires_https_and_credentials() {
        let mut config = AgentConfig::default();
        config.llm.enabled = true;
        assert!(config.validate().is_err());

        config.llm.base_url = "http://example.test/v1".into();
        config.llm.api_key = SecretString("secret".into());
        config.llm.model = "model".into();
        assert!(config.validate().is_err());

        config.llm.base_url = "https://example.test/v1".into();
        config.llm.model = "x".repeat(129);
        assert!(config.validate().is_err());
    }

    #[test]
    fn llm_key_is_redacted_from_debug_output() {
        let secret = SecretString("do-not-log".into());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn enabled_auth_requires_a_strong_encoded_password_hash() {
        let mut config = AgentConfig::default();
        config.auth.enabled = true;
        assert!(config.validate().is_err());

        config.auth.admin_password_hash = SecretString(
            "pbkdf2-sha256$100000$07070707070707070707070707070707$\
             ae1c044bd6cd0165f889325f36d0eaf0b1b166da6cb6a1cb7057a57a362be12a"
                .into(),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn stream_event_must_fit_response_budget() {
        let mut config = AgentConfig::default();
        config.llm.max_stream_event_bytes = config.llm.max_response_bytes + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn agent_loop_limits_are_bounded() {
        let mut config = AgentConfig::default();
        config.llm.max_agent_steps = 17;
        assert!(config.validate().is_err());

        config.llm.max_agent_steps = 4;
        config.llm.max_tool_context_bytes = config.llm.max_request_bytes + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn extension_registry_limits_and_paths_are_bounded() {
        let mut config = AgentConfig::default();
        config.extensions.enabled = true;
        config.extensions.max_actions = 0;
        assert!(config.validate().is_err());

        config.extensions.max_actions = 64;
        config.extensions.directories = vec![PathBuf::from("relative/actions.d")];
        assert!(config.validate().is_err());

        config.extensions.directories = vec![PathBuf::from("/etc/mbed-agent/actions.d")];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn enabled_mqtt_requires_narrow_tls_broker_and_bounded_identity() {
        let mut config = AgentConfig::default();
        config.channels.mqtt.enabled = true;
        config.channels.mqtt.broker = "mqtt://broker.example:1883".into();
        assert!(config.validate().is_err());

        config.channels.mqtt.broker = "mqtts://broker.example:8883".into();
        assert_eq!(
            parse_mqtts_broker(&config.channels.mqtt.broker).expect("broker"),
            ("broker.example", 8883)
        );
        assert!(config.validate().is_ok());

        config.channels.mqtt.device_id = "device/+/escape".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn enabled_wechat_clawbot_requires_https_and_a_token() {
        let mut config = AgentConfig::default();
        config.channels.wechat_clawbot.enabled = true;
        assert!(config.validate().is_err());

        config.channels.wechat_clawbot.bot_token = SecretString("token".into());
        config.channels.wechat_clawbot.base_url = "http://ilinkai.weixin.qq.com".into();
        assert!(config.validate().is_err());

        config.channels.wechat_clawbot.base_url = "https://ilinkai.weixin.qq.com".into();
        assert!(config.validate().is_ok());

        config.channels.wechat_clawbot.account = "bad/account".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn wechat_clawbot_base_url_rejects_embedded_credentials_and_paths() {
        assert!(parse_wechat_clawbot_base_url("https://user@example.test").is_err());
        assert!(parse_wechat_clawbot_base_url("https://example.test/api").is_err());
        assert_eq!(
            parse_wechat_clawbot_base_url("https://example.test").expect("host"),
            "example.test"
        );
    }

    #[test]
    fn shipped_configuration_example_remains_valid() {
        let config: AgentConfig =
            toml::from_str(include_str!("../../../config/mbed-agent.example.toml"))
                .expect("example config syntax");
        config.validate().expect("example config validation");
    }

    #[test]
    fn volatile_task_history_must_retain_at_least_one_record() {
        let mut config = AgentConfig::default();
        config.storage.max_task_records = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn volatile_change_sets_have_record_and_payload_bounds() {
        let mut config = AgentConfig::default();
        config.storage.max_change_set_records = 0;
        assert!(config.validate().is_err());

        config.storage.max_change_set_records = 1;
        config.storage.max_change_plan_bytes = config.storage.max_database_bytes + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn volatile_runtime_state_must_fit_database_budget() {
        let mut config = AgentConfig::default();
        config.storage.max_firewall_state_bytes = 0;
        assert!(config.validate().is_err());

        config.storage.max_firewall_state_bytes = config.storage.max_database_bytes + 1;
        assert!(config.validate().is_err());

        config.storage.max_firewall_state_bytes = 1024;
        config.storage.max_network_state_bytes = 0;
        assert!(config.validate().is_err());

        config.storage.max_network_state_bytes = config.storage.max_database_bytes + 1;
        assert!(config.validate().is_err());

        config.storage.max_network_state_bytes = 1024;
        config.storage.max_firewall_execution_plan_bytes = 0;
        assert!(config.validate().is_err());

        config.storage.max_firewall_execution_plan_bytes = config.storage.max_database_bytes + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn artifact_file_count_has_an_embedded_memory_bound() {
        let mut config = AgentConfig::default();
        config.storage.max_artifact_files = 4097;
        assert!(config.validate().is_err());
    }

    #[test]
    fn log_rate_limit_cannot_disable_all_runtime_logging() {
        let mut config = AgentConfig::default();
        config.logging.rate_limit_per_target_per_sec = 0;
        assert!(config.validate().is_err());
    }
}
