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
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1), (2);",
        )
        .map_err(StoreError::Sqlite)
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
}
