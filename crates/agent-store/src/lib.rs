use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, params};
use thiserror::Error;

pub struct Store {
    connection: Mutex<Connection>,
    path: PathBuf,
    max_database_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticRecord {
    pub id: String,
    pub kind: String,
    pub active: bool,
    pub assessment: String,
    pub payload: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
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

impl Store {
    /// Opens a `SQLite` runtime store and applies its hard page limit and migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be created, `SQLite` cannot be
    /// opened or configured, or a migration fails.
    pub fn open(path: &Path, max_database_bytes: u64) -> Result<Self, StoreError> {
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::InvalidPath(path.to_path_buf()))?;
        fs::create_dir_all(parent).map_err(|source| StoreError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;

        let connection = Connection::open(path).map_err(StoreError::Sqlite)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA temp_store=MEMORY;
                 PRAGMA auto_vacuum=INCREMENTAL;",
            )
            .map_err(StoreError::Sqlite)?;
        let page_size: u64 = connection
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .map_err(StoreError::Sqlite)?;
        let max_pages = max_database_bytes
            .checked_div(page_size)
            .unwrap_or(0)
            .max(1);
        connection
            .pragma_update(None, "max_page_count", max_pages)
            .map_err(StoreError::Sqlite)?;
        migrate(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
            path: path.to_path_buf(),
            max_database_bytes,
        })
    }

    /// Runs `SQLite`'s quick integrity check.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection cannot be locked, the check cannot
    /// execute, or `SQLite` reports an integrity problem.
    pub fn health_check(&self) -> Result<(), StoreError> {
        let connection = self.connection()?;
        let result: String = connection
            .pragma_query_value(None, "quick_check", |row| row.get(0))
            .map_err(StoreError::Sqlite)?;
        if result == "ok" {
            Ok(())
        } else {
            Err(StoreError::Integrity(result))
        }
    }

    /// Inserts one bounded diagnostic summary and prunes the oldest records.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload exceeds its limit or `SQLite` cannot
    /// complete the transaction.
    pub fn record_diagnostic(
        &self,
        record: &DiagnosticRecord,
        max_records: u32,
        max_payload_bytes: usize,
    ) -> Result<(), StoreError> {
        if record.payload.len() > max_payload_bytes {
            return Err(StoreError::PayloadTooLarge {
                actual: record.payload.len(),
                limit: max_payload_bytes,
            });
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO diagnostic_runs
                 (id, kind, active, assessment, payload, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())",
                params![
                    record.id,
                    record.kind,
                    record.active,
                    record.assessment,
                    record.payload
                ],
            )
            .map_err(StoreError::Sqlite)?;
        transaction
            .execute(
                "DELETE FROM diagnostic_runs WHERE rowid NOT IN
                 (SELECT rowid FROM diagnostic_runs ORDER BY created_at DESC, rowid DESC LIMIT ?1)",
                [max_records],
            )
            .map_err(StoreError::Sqlite)?;
        transaction.commit().map_err(StoreError::Sqlite)
    }

    /// Returns newest diagnostic summaries first.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection cannot be queried.
    pub fn diagnostic_history(&self, limit: u16) -> Result<Vec<DiagnosticRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, kind, active, assessment, payload, created_at
                 FROM diagnostic_runs ORDER BY created_at DESC, rowid DESC LIMIT ?1",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = statement
            .query_map([limit], |row| {
                Ok(DiagnosticRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    active: row.get(2)?,
                    assessment: row.get(3)?,
                    payload: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(StoreError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::Sqlite)
    }

    /// Inserts one metadata-only task audit record and prunes the oldest records.
    ///
    /// Prompts and model output are intentionally not accepted by this API.
    ///
    /// # Errors
    ///
    /// Returns an error when a metadata field exceeds its fixed bound or
    /// `SQLite` cannot complete the transaction.
    pub fn record_task(&self, record: &TaskRecord, max_records: u32) -> Result<(), StoreError> {
        validate_task_record(record)?;
        let prompt_tokens = record.prompt_tokens.map(u64_to_sql);
        let completion_tokens = record.completion_tokens.map(u64_to_sql);
        let duration_ms = u64_to_sql(record.duration_ms);
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO task_runs
                 (id, kind, status, provider, model, prompt_tokens, completion_tokens,
                  duration_ms, error_code, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, unixepoch())",
                params![
                    record.id,
                    record.kind,
                    record.status,
                    record.provider,
                    record.model,
                    prompt_tokens,
                    completion_tokens,
                    duration_ms,
                    record.error_code
                ],
            )
            .map_err(StoreError::Sqlite)?;
        transaction
            .execute(
                "DELETE FROM task_runs WHERE rowid NOT IN
                 (SELECT rowid FROM task_runs ORDER BY created_at DESC, rowid DESC LIMIT ?1)",
                [max_records],
            )
            .map_err(StoreError::Sqlite)?;
        transaction.commit().map_err(StoreError::Sqlite)
    }

    /// Returns newest metadata-only task audit records first.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection cannot be queried.
    pub fn task_history(&self, limit: u16) -> Result<Vec<TaskRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, kind, status, provider, model, prompt_tokens, completion_tokens,
                        duration_ms, error_code, created_at
                 FROM task_runs ORDER BY created_at DESC, rowid DESC LIMIT ?1",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = statement
            .query_map([limit], |row| {
                Ok(TaskRecord {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    status: row.get(2)?,
                    provider: row.get(3)?,
                    model: row.get(4)?,
                    prompt_tokens: sql_to_u64(row.get(5)?, 5)?,
                    completion_tokens: sql_to_u64(row.get(6)?, 6)?,
                    duration_ms: u64::try_from(row.get::<_, i64>(7)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    error_code: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })
            .map_err(StoreError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::Sqlite)
    }

    pub fn database_bytes(&self) -> u64 {
        file_len(&self.path)
            .saturating_add(file_len(&PathBuf::from(format!(
                "{}-wal",
                self.path.display()
            ))))
            .saturating_add(file_len(&PathBuf::from(format!(
                "{}-shm",
                self.path.display()
            ))))
    }

    #[must_use]
    pub const fn max_database_bytes(&self) -> u64 {
        self.max_database_bytes
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }
}

fn migrate(connection: &Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE TABLE IF NOT EXISTS app_state (
                 key TEXT PRIMARY KEY,
                 value BLOB NOT NULL,
                 updated_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE TABLE IF NOT EXISTS diagnostic_runs (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 active INTEGER NOT NULL,
                 assessment TEXT NOT NULL,
                 payload BLOB NOT NULL,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE INDEX IF NOT EXISTS diagnostic_runs_created_at
                 ON diagnostic_runs(created_at DESC);
             CREATE TABLE IF NOT EXISTS task_runs (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 status TEXT NOT NULL,
                 provider TEXT NOT NULL,
                 model TEXT NOT NULL,
                 prompt_tokens INTEGER,
                 completion_tokens INTEGER,
                 duration_ms INTEGER NOT NULL,
                 error_code TEXT,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE INDEX IF NOT EXISTS task_runs_created_at
                 ON task_runs(created_at DESC);
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1), (2), (3);",
        )
        .map_err(StoreError::Sqlite)
}

fn validate_task_record(record: &TaskRecord) -> Result<(), StoreError> {
    for (field, value, limit) in [
        ("id", record.id.as_str(), 128),
        ("kind", record.kind.as_str(), 32),
        ("status", record.status.as_str(), 32),
        ("provider", record.provider.as_str(), 64),
        ("model", record.model.as_str(), 128),
    ] {
        if value.len() > limit {
            return Err(StoreError::FieldTooLarge {
                field,
                actual: value.len(),
                limit,
            });
        }
    }
    if let Some(error_code) = &record.error_code {
        if error_code.len() > 32 {
            return Err(StoreError::FieldTooLarge {
                field: "error_code",
                actual: error_code.len(),
                limit: 32,
            });
        }
    }
    Ok(())
}

fn u64_to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn sql_to_u64(value: Option<i64>, column: usize) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database path has no parent: {0}")]
    InvalidPath(PathBuf),
    #[error("failed to create database directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("SQLite error: {0}")]
    Sqlite(#[source] rusqlite::Error),
    #[error("SQLite integrity check failed: {0}")]
    Integrity(String),
    #[error("SQLite connection lock is poisoned")]
    Poisoned,
    #[error("diagnostic payload is {actual} bytes, exceeding limit {limit}")]
    PayloadTooLarge { actual: usize, limit: usize },
    #[error("task field {field} is {actual} bytes, exceeding limit {limit}")]
    FieldTooLarge {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn creates_a_healthy_bounded_database() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-store-test-{nonce}"));
        let path = root.join("agent.db");
        let store = Store::open(&path, 1024 * 1024).expect("open store");
        store.health_check().expect("healthy store");
        assert_eq!(store.max_database_bytes(), 1024 * 1024);
        assert!(store.database_bytes() > 0);
        drop(store);
        fs::remove_dir_all(root).expect("remove store test directory");
    }

    #[test]
    fn bounds_diagnostic_payloads_and_prunes_oldest_records() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-audit-test-{nonce}"));
        let store = Store::open(&root.join("agent.db"), 1024 * 1024).expect("open store");
        for id in ["one", "two", "three"] {
            store
                .record_diagnostic(
                    &DiagnosticRecord {
                        id: id.into(),
                        kind: "wan".into(),
                        active: false,
                        assessment: "ready".into(),
                        payload: br#"{"complete":true}"#.to_vec(),
                        created_at: 0,
                    },
                    2,
                    1024,
                )
                .expect("record diagnostic");
        }
        let history = store.diagnostic_history(10).expect("read history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, "three");
        assert_eq!(history[1].id, "two");
        let oversized = DiagnosticRecord {
            id: "large".into(),
            kind: "wan".into(),
            active: false,
            assessment: "ready".into(),
            payload: vec![0; 5],
            created_at: 0,
        };
        assert!(matches!(
            store.record_diagnostic(&oversized, 2, 4),
            Err(StoreError::PayloadTooLarge { .. })
        ));
        drop(store);
        fs::remove_dir_all(root).expect("remove audit test directory");
    }

    #[test]
    fn stores_only_bounded_task_metadata_and_prunes_oldest_records() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-task-test-{nonce}"));
        let store = Store::open(&root.join("agent.db"), 1024 * 1024).expect("open store");
        for id in ["one", "two", "three"] {
            store
                .record_task(
                    &TaskRecord {
                        id: id.into(),
                        kind: "ask".into(),
                        status: "succeeded".into(),
                        provider: "open-ai-compatible".into(),
                        model: "test-model".into(),
                        prompt_tokens: Some(4),
                        completion_tokens: Some(2),
                        duration_ms: 12,
                        error_code: None,
                        created_at: 0,
                    },
                    2,
                )
                .expect("record task");
        }
        let history = store.task_history(10).expect("read history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, "three");
        assert_eq!(history[1].id, "two");
        assert_eq!(history[0].prompt_tokens, Some(4));
        assert_eq!(history[0].duration_ms, 12);

        let mut oversized = history[0].clone();
        oversized.id = "x".repeat(129);
        assert!(matches!(
            store.record_task(&oversized, 2),
            Err(StoreError::FieldTooLarge { field: "id", .. })
        ));
        drop(store);
        fs::remove_dir_all(root).expect("remove task test directory");
    }
}
