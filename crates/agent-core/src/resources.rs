use std::fs;
use std::path::{Path, PathBuf};

use agent_protocol::StoragePressure;
use thiserror::Error;

use crate::config::StorageConfig;

#[derive(Debug, Clone)]
pub struct TmpBudget {
    root: PathBuf,
    config: StorageConfig,
}

impl TmpBudget {
    /// Creates the managed runtime directory and its budget tracker.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured path has no parent or the runtime
    /// directory cannot be created.
    pub fn new(config: StorageConfig) -> Result<Self, ResourceError> {
        let root = config
            .path
            .parent()
            .ok_or_else(|| ResourceError::InvalidPath(config.path.clone()))?
            .to_path_buf();
        fs::create_dir_all(&root).map_err(|source| ResourceError::Create {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root, config })
    }

    /// Returns currently available bytes on the runtime filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error when filesystem capacity cannot be inspected.
    pub fn available_bytes(&self) -> Result<u64, ResourceError> {
        fs2::available_space(&self.root).map_err(|source| ResourceError::Inspect {
            path: self.root.clone(),
            source,
        })
    }

    /// Classifies storage pressure using both managed usage and free-space reserves.
    ///
    /// # Errors
    ///
    /// Returns an error when filesystem capacity cannot be inspected.
    pub fn pressure(&self, managed_bytes: u64) -> Result<StoragePressure, ResourceError> {
        let available = self.available_bytes()?;
        let total = fs2::total_space(&self.root).map_err(|source| ResourceError::Inspect {
            path: self.root.clone(),
            source,
        })?;
        let used_percent = managed_bytes.saturating_mul(100) / self.config.max_total_bytes.max(1);
        let available_percent = available.saturating_mul(100) / total.max(1);
        let below_reserve = available < self.config.min_tmp_free_bytes
            || available_percent < u64::from(self.config.min_tmp_free_percent);

        Ok(
            if used_percent >= 95 || (below_reserve && available < 1024 * 1024) {
                StoragePressure::Emergency
            } else if used_percent >= 85 || below_reserve {
                StoragePressure::Critical
            } else if used_percent >= 70 {
                StoragePressure::Pressure
            } else {
                StoragePressure::Normal
            },
        )
    }

    /// Sums regular-file bytes below the managed runtime root.
    ///
    /// # Errors
    ///
    /// Returns an error when a managed directory or file cannot be inspected.
    pub fn managed_bytes(&self) -> Result<u64, ResourceError> {
        let mut total = 0_u64;
        let mut directories = vec![self.root.clone()];
        while let Some(directory) = directories.pop() {
            let entries = fs::read_dir(&directory).map_err(|source| ResourceError::Inspect {
                path: directory.clone(),
                source,
            })?;
            for entry in entries {
                let entry = entry.map_err(|source| ResourceError::Inspect {
                    path: directory.clone(),
                    source,
                })?;
                let path = entry.path();
                let metadata =
                    fs::symlink_metadata(&path).map_err(|source| ResourceError::Inspect {
                        path: path.clone(),
                        source,
                    })?;
                if metadata.is_dir() {
                    directories.push(path);
                } else if metadata.is_file() {
                    total = total.saturating_add(metadata.len());
                }
            }
        }
        Ok(total)
    }

    #[must_use]
    pub fn database_limit_bytes(&self) -> u64 {
        self.config.max_database_bytes
    }

    #[must_use]
    pub fn total_limit_bytes(&self) -> u64 {
        self.config.max_total_bytes
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("runtime path has no parent: {0}")]
    InvalidPath(PathBuf),
    #[error("failed to create runtime directory {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect runtime filesystem at {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
