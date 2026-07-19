use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
        {
            return Err(ConfigError::Validation(
                "runtime limits must allow a task, a tool timeout, and 1024-byte buffers".into(),
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
        if self.storage.max_diagnostic_records == 0
            || self.storage.max_diagnostic_record_bytes == 0
            || self.storage.max_diagnostic_record_bytes > self.storage.max_database_bytes
        {
            return Err(ConfigError::Validation(
                "diagnostic audit limits must be non-zero and fit the database budget".into(),
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
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_active_tasks: 1,
            max_request_bytes: 64 * 1024,
            task_timeout_secs: 120,
            tool_timeout_secs: 3,
            max_tool_output_bytes: 64 * 1024,
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
    pub max_rollback_bytes: u64,
    pub max_total_bytes: u64,
    pub runtime_headroom_bytes: u64,
    pub min_tmp_free_bytes: u64,
    pub min_tmp_free_percent: u8,
    pub cleanup_interval_secs: u64,
    pub max_diagnostic_records: u32,
    pub max_diagnostic_record_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/tmp/mbed-agent/agent.db"),
            max_database_bytes: 8 * 1024 * 1024,
            max_artifacts_bytes: 8 * 1024 * 1024,
            max_rollback_bytes: 4 * 1024 * 1024,
            max_total_bytes: 24 * 1024 * 1024,
            runtime_headroom_bytes: 2 * 1024 * 1024,
            min_tmp_free_bytes: 8 * 1024 * 1024,
            min_tmp_free_percent: 10,
            cleanup_interval_secs: 60,
            max_diagnostic_records: 128,
            max_diagnostic_record_bytes: 32 * 1024,
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
}
