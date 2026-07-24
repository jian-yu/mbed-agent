use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use agent_protocol::StoragePressure;
use thiserror::Error;

use crate::config::StorageConfig;

#[derive(Debug, Clone)]
pub struct TmpBudget {
    root: PathBuf,
    config: StorageConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub removed_files: u32,
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
        Ok(classify_pressure(
            managed_bytes,
            available,
            total,
            &self.config,
        ))
    }

    /// Removes oldest regular files from the managed artifacts directory until
    /// its configured byte limit is met.
    ///
    /// Symbolic links, non-regular files, and every path outside `artifacts/`
    /// are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifacts tree cannot be inspected or a
    /// selected regular file cannot be removed.
    pub fn cleanup_artifacts(&self) -> Result<CleanupReport, ResourceError> {
        let artifact_root = self.root.join("artifacts");
        fs::create_dir_all(&artifact_root).map_err(|source| ResourceError::Create {
            path: artifact_root.clone(),
            source,
        })?;
        let max_files = usize::try_from(self.config.max_artifact_files)
            .unwrap_or(4096)
            .clamp(1, 4096);
        let mut retained: BinaryHeap<Reverse<(SystemTime, PathBuf, u64)>> =
            BinaryHeap::with_capacity(max_files);
        let mut bytes_before = 0_u64;
        let mut bytes_after = 0_u64;
        let mut removed_files = 0_u32;
        let entries = fs::read_dir(&artifact_root).map_err(|source| ResourceError::Inspect {
            path: artifact_root.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| ResourceError::Inspect {
                path: artifact_root.clone(),
                source,
            })?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| ResourceError::Inspect {
                    path: path.clone(),
                    source,
                })?;
            if metadata.is_file() {
                bytes_before = bytes_before.saturating_add(metadata.len());
                let candidate = (
                    metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    path,
                    metadata.len(),
                );
                if retained.len() < max_files {
                    bytes_after = bytes_after.saturating_add(candidate.2);
                    retained.push(Reverse(candidate));
                } else if retained.peek().is_some_and(|oldest| candidate > oldest.0) {
                    if let Some(Reverse((_, oldest_path, oldest_bytes))) = retained.pop() {
                        remove_artifact(&oldest_path)?;
                        bytes_after = bytes_after.saturating_sub(oldest_bytes);
                        removed_files = removed_files.saturating_add(1);
                    }
                    bytes_after = bytes_after.saturating_add(candidate.2);
                    retained.push(Reverse(candidate));
                } else {
                    remove_artifact(&candidate.1)?;
                    removed_files = removed_files.saturating_add(1);
                }
            }
        }

        while bytes_after > self.config.max_artifacts_bytes {
            let Some(Reverse((_, path, bytes))) = retained.pop() else {
                break;
            };
            remove_artifact(&path)?;
            bytes_after = bytes_after.saturating_sub(bytes);
            removed_files = removed_files.saturating_add(1);
        }
        Ok(CleanupReport {
            bytes_before,
            bytes_after,
            removed_files,
        })
    }

    /// Returns the configured cleanup interval.
    #[must_use]
    pub const fn cleanup_interval_secs(&self) -> u64 {
        self.config.cleanup_interval_secs
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

fn remove_artifact(path: &Path) -> Result<(), ResourceError> {
    fs::remove_file(path).map_err(|source| ResourceError::Remove {
        path: path.to_path_buf(),
        source,
    })
}

fn classify_pressure(
    managed_bytes: u64,
    available: u64,
    total: u64,
    config: &StorageConfig,
) -> StoragePressure {
    let used_percent = managed_bytes.saturating_mul(100) / config.max_total_bytes.max(1);
    let available_percent = available.saturating_mul(100) / total.max(1);
    let below_reserve = available < config.min_tmp_free_bytes
        || available_percent < u64::from(config.min_tmp_free_percent);

    if used_percent >= 95 || (below_reserve && available < 1024 * 1024) {
        StoragePressure::Emergency
    } else if used_percent >= 85 || below_reserve {
        StoragePressure::Critical
    } else if used_percent >= 70 {
        StoragePressure::Pressure
    } else {
        StoragePressure::Normal
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
    #[error("failed to remove managed artifact {path}: {source}")]
    Remove {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn classifies_managed_limits_and_filesystem_reserves() {
        let mut config = StorageConfig {
            max_total_bytes: 100,
            min_tmp_free_bytes: 0,
            min_tmp_free_percent: 0,
            ..StorageConfig::default()
        };
        assert_eq!(
            classify_pressure(69, 100, 100, &config),
            StoragePressure::Normal
        );
        assert_eq!(
            classify_pressure(70, 100, 100, &config),
            StoragePressure::Pressure
        );
        assert_eq!(
            classify_pressure(85, 100, 100, &config),
            StoragePressure::Critical
        );
        assert_eq!(
            classify_pressure(95, 100, 100, &config),
            StoragePressure::Emergency
        );

        config.max_total_bytes = 1024 * 1024 * 100;
        config.min_tmp_free_percent = 10;
        assert_eq!(
            classify_pressure(0, 5 * 1024 * 1024, 100 * 1024 * 1024, &config),
            StoragePressure::Critical
        );
        assert_eq!(
            classify_pressure(0, 512 * 1024, 100 * 1024 * 1024, &config),
            StoragePressure::Emergency
        );
    }

    #[test]
    fn artifact_cleanup_is_bounded_to_regular_artifact_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-budget-test-{nonce}"));
        let config = StorageConfig {
            path: root.join("agent.db"),
            max_artifacts_bytes: 5,
            max_artifact_files: 2,
            ..StorageConfig::default()
        };
        let budget = TmpBudget::new(config).expect("budget");
        let artifacts = root.join("artifacts");
        let rollback = root.join("rollback");
        fs::create_dir_all(artifacts.join("nested")).expect("artifact directories");
        fs::create_dir_all(&rollback).expect("rollback directory");
        fs::write(artifacts.join("a.bin"), b"1234").expect("first artifact");
        fs::write(artifacts.join("b.bin"), b"5678").expect("second artifact");
        fs::write(artifacts.join("c.bin"), b"9012").expect("third artifact");
        fs::write(artifacts.join("nested/ignored.bin"), b"nested").expect("nested artifact");
        fs::write(rollback.join("keep.bin"), b"rollback").expect("rollback file");
        symlink(rollback.join("keep.bin"), artifacts.join("ignored-link"))
            .expect("artifact symlink");

        let report = budget.cleanup_artifacts().expect("cleanup artifacts");
        assert_eq!(report.bytes_before, 12);
        assert_eq!(report.bytes_after, 4);
        assert_eq!(report.removed_files, 2);
        assert!(rollback.join("keep.bin").exists());
        assert!(artifacts.join("ignored-link").is_symlink());
        assert!(artifacts.join("nested/ignored.bin").exists());

        fs::remove_dir_all(root).expect("remove budget test directory");
    }
}
