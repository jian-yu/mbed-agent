use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use agent_core::transition_change_set;
use agent_protocol::{ChangeSetState, RiskLevel};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

const FIREWALL_RUNTIME_STATE_KEY: &str = "firewall_runtime_state_v1";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSetRecord {
    pub id: String,
    pub plan_digest: String,
    pub plan_payload: Vec<u8>,
    pub state: ChangeSetState,
    pub actor_id: String,
    pub boot_id: String,
    pub risk: RiskLevel,
    pub expires_monotonic_ms: u64,
    pub rollback_deadline_monotonic_ms: Option<u64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub id: String,
    pub change_set_id: String,
    pub actor_id: String,
    pub plan_digest: String,
    pub boot_id: String,
    pub token_digest: String,
    pub expires_monotonic_ms: u64,
    pub consumed_monotonic_ms: Option<u64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ApprovalConsumption<'a> {
    pub approval_id: &'a str,
    pub change_set_id: &'a str,
    pub actor_id: &'a str,
    pub plan_digest: &'a str,
    pub boot_id: &'a str,
    pub token_digest: &'a str,
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

    /// Inserts one bounded, locally generated `ChangeSet` plan.
    ///
    /// Only the initial `planned` state is accepted. Active `ChangeSets` are never
    /// pruned to make room for a new record.
    ///
    /// # Errors
    ///
    /// Returns an error when fields or payload exceed their bounds, the active
    /// record limit is reached, or `SQLite` cannot commit the transaction.
    pub fn insert_change_set(
        &self,
        record: &ChangeSetRecord,
        max_records: u32,
        max_payload_bytes: usize,
        now_monotonic_ms: u64,
    ) -> Result<(), StoreError> {
        validate_change_set_record(record, max_payload_bytes)?;
        if record.expires_monotonic_ms <= now_monotonic_ms {
            return Err(StoreError::ChangeSetExpired);
        }
        if record.state != ChangeSetState::Planned {
            return Err(StoreError::ChangeSetConflict);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        let active: u32 = transaction
            .query_row(
                "SELECT count(*) FROM change_sets WHERE state NOT IN
                 ('confirmed', 'rejected', 'expired', 'rolled_back', 'rollback_failed')",
                [],
                |row| row.get(0),
            )
            .map_err(StoreError::Sqlite)?;
        if active >= max_records {
            return Err(StoreError::ChangeSetCapacity);
        }
        transaction
            .execute(
                "INSERT INTO change_sets
                 (id, plan_digest, plan_payload, state, actor_id, boot_id, risk,
                  expires_monotonic_ms, rollback_deadline_monotonic_ms, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, unixepoch(), unixepoch())",
                params![
                    record.id,
                    record.plan_digest,
                    record.plan_payload,
                    record.state.as_str(),
                    record.actor_id,
                    record.boot_id,
                    record.risk.as_str(),
                    u64_to_sql(record.expires_monotonic_ms),
                    record.rollback_deadline_monotonic_ms.map(u64_to_sql),
                ],
            )
            .map_err(StoreError::Sqlite)?;
        transaction
            .execute(
                "DELETE FROM change_sets WHERE id IN (
                   SELECT id FROM change_sets
                   WHERE state IN ('confirmed', 'rejected', 'expired', 'rolled_back', 'rollback_failed')
                   ORDER BY updated_at DESC, rowid DESC LIMIT -1 OFFSET ?1
                 )",
                [max_records],
            )
            .map_err(StoreError::Sqlite)?;
        transaction.commit().map_err(StoreError::Sqlite)
    }

    /// Returns one `ChangeSet` record by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot query the record or stored enums are
    /// corrupt.
    pub fn change_set(&self, id: &str) -> Result<Option<ChangeSetRecord>, StoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, plan_digest, plan_payload, state, actor_id, boot_id, risk,
                        expires_monotonic_ms, rollback_deadline_monotonic_ms,
                        created_at, updated_at
                 FROM change_sets WHERE id = ?1",
                [id],
                decode_change_set,
            )
            .optional()
            .map_err(StoreError::Sqlite)
    }

    /// Atomically advances a `ChangeSet` if its state, plan digest, and boot match.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state/digest/boot, expiration, unsafe state
    /// transitions, or attempts to arm rollback without a deadline.
    pub fn transition_change_set(
        &self,
        id: &str,
        expected: ChangeSetState,
        next: ChangeSetState,
        plan_digest: &str,
        boot_id: &str,
        now_monotonic_ms: u64,
    ) -> Result<ChangeSetState, StoreError> {
        if next == ChangeSetState::RollbackArmed {
            return Err(StoreError::RollbackDeadlineRequired);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        let Some((stored_state, expires)): Option<(String, i64)> = transaction
            .query_row(
                "SELECT state, expires_monotonic_ms FROM change_sets
                 WHERE id = ?1 AND plan_digest = ?2 AND boot_id = ?3",
                params![id, plan_digest, boot_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::Sqlite)?
        else {
            return Err(StoreError::ChangeSetConflict);
        };
        let stored_state =
            ChangeSetState::parse(&stored_state).ok_or(StoreError::CorruptChangeSet)?;
        if stored_state != expected {
            return Err(StoreError::ChangeSetConflict);
        }
        if state_requires_unexpired_plan(expected)
            && now_monotonic_ms >= sql_i64_to_u64(expires)?
            && next != ChangeSetState::Expired
        {
            return Err(StoreError::ChangeSetExpired);
        }
        transition_change_set(expected, next).map_err(StoreError::InvalidTransition)?;
        let changed = transaction
            .execute(
                "UPDATE change_sets SET state = ?1, updated_at = unixepoch()
                 WHERE id = ?2 AND state = ?3 AND plan_digest = ?4 AND boot_id = ?5",
                params![next.as_str(), id, expected.as_str(), plan_digest, boot_id],
            )
            .map_err(StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::ChangeSetConflict);
        }
        transaction.commit().map_err(StoreError::Sqlite)?;
        Ok(next)
    }

    /// Atomically records the rollback deadline and enters `rollback_armed`.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/expired plan, invalid deadline, or `SQLite`
    /// failure.
    pub fn arm_change_set_rollback(
        &self,
        id: &str,
        plan_digest: &str,
        boot_id: &str,
        now_monotonic_ms: u64,
        rollback_deadline_monotonic_ms: u64,
    ) -> Result<ChangeSetState, StoreError> {
        if rollback_deadline_monotonic_ms <= now_monotonic_ms {
            return Err(StoreError::InvalidRollbackDeadline);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        let changed = transaction
            .execute(
                "UPDATE change_sets
                 SET state = 'rollback_armed', rollback_deadline_monotonic_ms = ?1,
                     updated_at = unixepoch()
                 WHERE id = ?2 AND state = 'validated' AND plan_digest = ?3 AND boot_id = ?4",
                params![
                    u64_to_sql(rollback_deadline_monotonic_ms),
                    id,
                    plan_digest,
                    boot_id
                ],
            )
            .map_err(StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::ChangeSetConflict);
        }
        transaction.commit().map_err(StoreError::Sqlite)?;
        Ok(ChangeSetState::RollbackArmed)
    }

    /// Stores a token digest for a pending approval.
    ///
    /// Raw approval tokens are intentionally not accepted by the store.
    ///
    /// # Errors
    ///
    /// Returns an error when fields are invalid, the `ChangeSet` is not awaiting
    /// this actor's exact plan, or `SQLite` cannot commit.
    pub fn issue_approval(
        &self,
        record: &ApprovalRecord,
        now_monotonic_ms: u64,
    ) -> Result<(), StoreError> {
        validate_approval_record(record)?;
        if record.expires_monotonic_ms <= now_monotonic_ms {
            return Err(StoreError::ApprovalRejected);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        let matching: u32 = transaction
            .query_row(
                "SELECT count(*) FROM change_sets
                 WHERE id = ?1 AND state = 'awaiting_approval' AND actor_id = ?2
                   AND plan_digest = ?3 AND boot_id = ?4
                   AND expires_monotonic_ms >= ?5 AND expires_monotonic_ms > ?6",
                params![
                    record.change_set_id,
                    record.actor_id,
                    record.plan_digest,
                    record.boot_id,
                    u64_to_sql(record.expires_monotonic_ms),
                    u64_to_sql(now_monotonic_ms)
                ],
                |row| row.get(0),
            )
            .map_err(StoreError::Sqlite)?;
        if matching != 1 {
            return Err(StoreError::ApprovalRejected);
        }
        transaction
            .execute(
                "INSERT INTO approvals
                 (id, change_set_id, actor_id, plan_digest, boot_id, token_digest,
                  expires_monotonic_ms, consumed_monotonic_ms, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, unixepoch())",
                params![
                    record.id,
                    record.change_set_id,
                    record.actor_id,
                    record.plan_digest,
                    record.boot_id,
                    record.token_digest,
                    u64_to_sql(record.expires_monotonic_ms)
                ],
            )
            .map_err(StoreError::Sqlite)?;
        transaction.commit().map_err(StoreError::Sqlite)
    }

    /// Atomically consumes one approval and moves its exact `ChangeSet` to approved.
    ///
    /// # Errors
    ///
    /// Returns one generic rejection for expired, replayed, mismatched, or
    /// unknown approvals so callers do not gain a token oracle.
    pub fn consume_approval(
        &self,
        request: &ApprovalConsumption<'_>,
        now_monotonic_ms: u64,
    ) -> Result<ChangeSetState, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(StoreError::Sqlite)?;
        let approval_changed = transaction
            .execute(
                "UPDATE approvals SET consumed_monotonic_ms = ?1
                 WHERE id = ?2 AND change_set_id = ?3 AND actor_id = ?4
                   AND plan_digest = ?5 AND boot_id = ?6 AND token_digest = ?7
                   AND consumed_monotonic_ms IS NULL AND expires_monotonic_ms > ?1",
                params![
                    u64_to_sql(now_monotonic_ms),
                    request.approval_id,
                    request.change_set_id,
                    request.actor_id,
                    request.plan_digest,
                    request.boot_id,
                    request.token_digest
                ],
            )
            .map_err(StoreError::Sqlite)?;
        if approval_changed != 1 {
            return Err(StoreError::ApprovalRejected);
        }
        let change_set_changed = transaction
            .execute(
                "UPDATE change_sets SET state = 'approved', updated_at = unixepoch()
                 WHERE id = ?1 AND state = 'awaiting_approval' AND actor_id = ?2
                   AND plan_digest = ?3 AND boot_id = ?4
                   AND expires_monotonic_ms > ?5",
                params![
                    request.change_set_id,
                    request.actor_id,
                    request.plan_digest,
                    request.boot_id,
                    u64_to_sql(now_monotonic_ms)
                ],
            )
            .map_err(StoreError::Sqlite)?;
        if change_set_changed != 1 {
            return Err(StoreError::ApprovalRejected);
        }
        transaction.commit().map_err(StoreError::Sqlite)?;
        Ok(ChangeSetState::Approved)
    }

    /// Atomically replaces the boot-bound generic firewall canonical state.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload exceeds its configured cap or `SQLite` cannot write it.
    pub fn replace_firewall_runtime_state(
        &self,
        payload: &[u8],
        max_payload_bytes: usize,
    ) -> Result<(), StoreError> {
        if payload.is_empty() || payload.len() > max_payload_bytes {
            return Err(StoreError::PayloadTooLarge {
                actual: payload.len(),
                limit: max_payload_bytes,
            });
        }
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO app_state (key, value, updated_at)
                 VALUES (?1, ?2, unixepoch())
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                     updated_at = excluded.updated_at",
                params![FIREWALL_RUNTIME_STATE_KEY, payload],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    /// Loads the bounded boot-bound generic firewall canonical state.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored value exceeds its configured cap or `SQLite` cannot read.
    pub fn firewall_runtime_state(
        &self,
        max_payload_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let connection = self.connection()?;
        let payload: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM app_state WHERE key = ?1",
                [FIREWALL_RUNTIME_STATE_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::Sqlite)?;
        if payload
            .as_ref()
            .is_some_and(|value| value.len() > max_payload_bytes)
        {
            return Err(StoreError::PayloadTooLarge {
                actual: payload.as_ref().map_or(0, Vec::len),
                limit: max_payload_bytes,
            });
        }
        Ok(payload)
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
             CREATE TABLE IF NOT EXISTS change_sets (
                 id TEXT PRIMARY KEY,
                 plan_digest TEXT NOT NULL,
                 plan_payload BLOB NOT NULL,
                 state TEXT NOT NULL,
                 actor_id TEXT NOT NULL,
                 boot_id TEXT NOT NULL,
                 risk TEXT NOT NULL,
                 expires_monotonic_ms INTEGER NOT NULL,
                 rollback_deadline_monotonic_ms INTEGER,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                 updated_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE INDEX IF NOT EXISTS change_sets_updated_at
                 ON change_sets(updated_at DESC);
             CREATE TABLE IF NOT EXISTS approvals (
                 id TEXT PRIMARY KEY,
                 change_set_id TEXT NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
                 actor_id TEXT NOT NULL,
                 plan_digest TEXT NOT NULL,
                 boot_id TEXT NOT NULL,
                 token_digest TEXT NOT NULL UNIQUE,
                 expires_monotonic_ms INTEGER NOT NULL,
                 consumed_monotonic_ms INTEGER,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE INDEX IF NOT EXISTS approvals_change_set_id
                 ON approvals(change_set_id);
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1), (2), (3), (4);",
        )
        .map_err(StoreError::Sqlite)
}

fn decode_change_set(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChangeSetRecord> {
    let state: String = row.get(3)?;
    let risk: String = row.get(6)?;
    Ok(ChangeSetRecord {
        id: row.get(0)?,
        plan_digest: row.get(1)?,
        plan_payload: row.get(2)?,
        state: ChangeSetState::parse(&state).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                format!("unknown ChangeSet state {state}").into(),
            )
        })?,
        actor_id: row.get(4)?,
        boot_id: row.get(5)?,
        risk: RiskLevel::parse(&risk).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                format!("unknown ChangeSet risk {risk}").into(),
            )
        })?,
        expires_monotonic_ms: sql_i64_to_u64_row(row.get(7)?, 7)?,
        rollback_deadline_monotonic_ms: row
            .get::<_, Option<i64>>(8)?
            .map(|value| sql_i64_to_u64_row(value, 8))
            .transpose()?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn validate_change_set_record(
    record: &ChangeSetRecord,
    max_payload_bytes: usize,
) -> Result<(), StoreError> {
    for (field, value, limit) in [
        ("change_set.id", record.id.as_str(), 128),
        ("change_set.actor_id", record.actor_id.as_str(), 128),
        ("change_set.boot_id", record.boot_id.as_str(), 128),
    ] {
        validate_bounded_field(field, value, limit)?;
    }
    validate_digest_field("change_set.plan_digest", &record.plan_digest)?;
    if record.plan_payload.len() > max_payload_bytes {
        return Err(StoreError::PayloadTooLarge {
            actual: record.plan_payload.len(),
            limit: max_payload_bytes,
        });
    }
    if record.plan_payload.is_empty() {
        return Err(StoreError::FieldTooLarge {
            field: "change_set.plan_payload",
            actual: 0,
            limit: max_payload_bytes,
        });
    }
    if record.expires_monotonic_ms == 0 {
        return Err(StoreError::ChangeSetExpired);
    }
    Ok(())
}

fn validate_approval_record(record: &ApprovalRecord) -> Result<(), StoreError> {
    for (field, value) in [
        ("approval.id", record.id.as_str()),
        ("approval.change_set_id", record.change_set_id.as_str()),
        ("approval.actor_id", record.actor_id.as_str()),
        ("approval.boot_id", record.boot_id.as_str()),
    ] {
        validate_bounded_field(field, value, 128)?;
    }
    validate_digest_field("approval.plan_digest", &record.plan_digest)?;
    validate_digest_field("approval.token_digest", &record.token_digest)?;
    if record.expires_monotonic_ms == 0 || record.consumed_monotonic_ms.is_some() {
        return Err(StoreError::ApprovalRejected);
    }
    Ok(())
}

fn validate_bounded_field(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(StoreError::FieldTooLarge {
            field,
            actual: value.len(),
            limit,
        });
    }
    Ok(())
}

fn validate_digest_field(field: &'static str, value: &str) -> Result<(), StoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::FieldTooLarge {
            field,
            actual: value.len(),
            limit: 64,
        });
    }
    Ok(())
}

const fn state_requires_unexpired_plan(state: ChangeSetState) -> bool {
    matches!(
        state,
        ChangeSetState::Draft
            | ChangeSetState::Planned
            | ChangeSetState::AwaitingApproval
            | ChangeSetState::Approved
    )
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

fn sql_i64_to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptChangeSet)
}

fn sql_i64_to_u64_row(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
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
    #[error("bounded payload is {actual} bytes, exceeding limit {limit}")]
    PayloadTooLarge { actual: usize, limit: usize },
    #[error("bounded field {field} is {actual} bytes, exceeding limit {limit}")]
    FieldTooLarge {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("active ChangeSet capacity has been reached")]
    ChangeSetCapacity,
    #[error("ChangeSet state, digest, boot, or actor does not match")]
    ChangeSetConflict,
    #[error("ChangeSet plan has expired")]
    ChangeSetExpired,
    #[error("stored ChangeSet state is corrupt")]
    CorruptChangeSet,
    #[error("invalid ChangeSet state transition: {0}")]
    InvalidTransition(#[source] agent_core::ChangeTransitionError),
    #[error("rollback must be armed with an explicit future deadline")]
    RollbackDeadlineRequired,
    #[error("rollback deadline must be later than the current monotonic time")]
    InvalidRollbackDeadline,
    #[error("approval was rejected")]
    ApprovalRejected,
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
    fn replaces_and_bounds_volatile_firewall_state() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-firewall-state-{nonce}"));
        let store = Store::open(&root.join("agent.db"), 1024 * 1024).expect("open store");
        assert_eq!(store.firewall_runtime_state(16).expect("empty"), None);
        store
            .replace_firewall_runtime_state(b"first", 16)
            .expect("first state");
        store
            .replace_firewall_runtime_state(b"second", 16)
            .expect("replace state");
        assert_eq!(
            store.firewall_runtime_state(16).expect("load"),
            Some(b"second".to_vec())
        );
        assert!(matches!(
            store.replace_firewall_runtime_state(b"too-large", 4),
            Err(StoreError::PayloadTooLarge { .. })
        ));
        assert!(matches!(
            store.firewall_runtime_state(4),
            Err(StoreError::PayloadTooLarge { .. })
        ));
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

    const PLAN_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn change_set_record(id: &str, expires_monotonic_ms: u64) -> ChangeSetRecord {
        ChangeSetRecord {
            id: id.into(),
            plan_digest: PLAN_DIGEST.into(),
            plan_payload: br#"{"schema_version":1}"#.to_vec(),
            state: ChangeSetState::Planned,
            actor_id: "cli/root".into(),
            boot_id: "boot-1".into(),
            risk: RiskLevel::R3,
            expires_monotonic_ms,
            rollback_deadline_monotonic_ms: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn approval_record(change_set_id: &str, expires_monotonic_ms: u64) -> ApprovalRecord {
        ApprovalRecord {
            id: format!("approval-{change_set_id}"),
            change_set_id: change_set_id.into(),
            actor_id: "cli/root".into(),
            plan_digest: PLAN_DIGEST.into(),
            boot_id: "boot-1".into(),
            token_digest: TOKEN_DIGEST.into(),
            expires_monotonic_ms,
            consumed_monotonic_ms: None,
            created_at: 0,
        }
    }

    fn approval_consumption<'a>(
        approval_id: &'a str,
        change_set_id: &'a str,
        actor_id: &'a str,
    ) -> ApprovalConsumption<'a> {
        ApprovalConsumption {
            approval_id,
            change_set_id,
            actor_id,
            plan_digest: PLAN_DIGEST,
            boot_id: "boot-1",
            token_digest: TOKEN_DIGEST,
        }
    }

    #[test]
    fn approval_consumption_is_atomic_bound_and_one_use() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-change-approval-{nonce}"));
        let store = Store::open(&root.join("agent.db"), 1024 * 1024).expect("open store");
        store
            .insert_change_set(&change_set_record("change-1", 1000), 4, 4096, 100)
            .expect("insert ChangeSet");
        store
            .transition_change_set(
                "change-1",
                ChangeSetState::Planned,
                ChangeSetState::AwaitingApproval,
                PLAN_DIGEST,
                "boot-1",
                100,
            )
            .expect("await approval");
        store
            .issue_approval(&approval_record("change-1", 500), 100)
            .expect("issue approval");

        assert!(matches!(
            store.consume_approval(
                &approval_consumption("approval-change-1", "change-1", "mqtt/other"),
                200,
            ),
            Err(StoreError::ApprovalRejected)
        ));
        assert_eq!(
            store
                .consume_approval(
                    &approval_consumption("approval-change-1", "change-1", "cli/root"),
                    200,
                )
                .expect("consume approval"),
            ChangeSetState::Approved
        );
        assert!(matches!(
            store.consume_approval(
                &approval_consumption("approval-change-1", "change-1", "cli/root"),
                201,
            ),
            Err(StoreError::ApprovalRejected)
        ));
        assert_eq!(
            store
                .change_set("change-1")
                .expect("read ChangeSet")
                .expect("ChangeSet")
                .state,
            ChangeSetState::Approved
        );
        drop(store);
        fs::remove_dir_all(root).expect("remove ChangeSet approval test directory");
    }

    #[test]
    fn rollback_deadline_cannot_be_skipped() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-change-rollback-{nonce}"));
        let store = Store::open(&root.join("agent.db"), 1024 * 1024).expect("open store");
        store
            .insert_change_set(&change_set_record("change-2", 1000), 4, 4096, 100)
            .expect("insert ChangeSet");
        store
            .transition_change_set(
                "change-2",
                ChangeSetState::Planned,
                ChangeSetState::AwaitingApproval,
                PLAN_DIGEST,
                "boot-1",
                100,
            )
            .expect("await approval");
        store
            .issue_approval(&approval_record("change-2", 500), 100)
            .expect("issue approval");
        store
            .consume_approval(
                &approval_consumption("approval-change-2", "change-2", "cli/root"),
                200,
            )
            .expect("approve");
        store
            .transition_change_set(
                "change-2",
                ChangeSetState::Approved,
                ChangeSetState::Staged,
                PLAN_DIGEST,
                "boot-1",
                200,
            )
            .expect("stage");
        store
            .transition_change_set(
                "change-2",
                ChangeSetState::Staged,
                ChangeSetState::Validated,
                PLAN_DIGEST,
                "boot-1",
                200,
            )
            .expect("validate");
        assert!(matches!(
            store.transition_change_set(
                "change-2",
                ChangeSetState::Validated,
                ChangeSetState::RollbackArmed,
                PLAN_DIGEST,
                "boot-1",
                200,
            ),
            Err(StoreError::RollbackDeadlineRequired)
        ));
        store
            .arm_change_set_rollback("change-2", PLAN_DIGEST, "boot-1", 200, 800)
            .expect("arm rollback");
        let record = store
            .change_set("change-2")
            .expect("read ChangeSet")
            .expect("ChangeSet");
        assert_eq!(record.state, ChangeSetState::RollbackArmed);
        assert_eq!(record.rollback_deadline_monotonic_ms, Some(800));
        drop(store);
        fs::remove_dir_all(root).expect("remove ChangeSet rollback test directory");
    }

    #[test]
    fn expired_and_capacity_limited_change_sets_fail_closed() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-change-bounds-{nonce}"));
        let store = Store::open(&root.join("agent.db"), 1024 * 1024).expect("open store");
        store
            .insert_change_set(&change_set_record("change-3", 200), 1, 4096, 100)
            .expect("insert ChangeSet");
        assert!(matches!(
            store.insert_change_set(&change_set_record("change-4", 300), 1, 4096, 100),
            Err(StoreError::ChangeSetCapacity)
        ));
        assert!(matches!(
            store.transition_change_set(
                "change-3",
                ChangeSetState::Planned,
                ChangeSetState::AwaitingApproval,
                PLAN_DIGEST,
                "boot-1",
                200,
            ),
            Err(StoreError::ChangeSetExpired)
        ));
        assert_eq!(
            store
                .transition_change_set(
                    "change-3",
                    ChangeSetState::Planned,
                    ChangeSetState::Expired,
                    PLAN_DIGEST,
                    "boot-1",
                    200,
                )
                .expect("mark expired"),
            ChangeSetState::Expired
        );
        assert!(matches!(
            store.insert_change_set(&change_set_record("large", 300), 1, 4, 100),
            Err(StoreError::PayloadTooLarge { .. })
        ));
        drop(store);
        fs::remove_dir_all(root).expect("remove ChangeSet bounds test directory");
    }
}
