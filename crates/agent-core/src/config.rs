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

fn storage_record_limits_valid(storage: &StorageConfig) -> bool {
    storage.max_diagnostic_records > 0
        && storage.max_task_records > 0
        && storage.max_change_set_records > 0
        && storage.max_diagnostic_record_bytes > 0
        && storage.max_change_plan_bytes > 0
        && storage.max_firewall_state_bytes > 0
        && storage.max_network_state_bytes > 0
        && storage.max_firewall_execution_plan_bytes > 0
        && storage.max_diagnostic_record_bytes <= storage.max_database_bytes
        && storage.max_change_plan_bytes <= storage.max_database_bytes
        && storage.max_firewall_state_bytes <= storage.max_database_bytes
        && storage.max_network_state_bytes <= storage.max_database_bytes
        && storage.max_firewall_execution_plan_bytes <= storage.max_database_bytes
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
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
