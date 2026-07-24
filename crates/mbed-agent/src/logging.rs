use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_core::config::LoggingConfig;
use tracing::Metadata;
use tracing_subscriber::fmt::MakeWriter;

const MAX_RATE_TARGETS: usize = 64;

#[derive(Clone)]
pub struct BoundedMakeWriter {
    state: Arc<Mutex<LogState>>,
    rate: Arc<Mutex<RateLimiter>>,
    dropped_records: Arc<AtomicU64>,
    max_line_bytes: usize,
}

impl BoundedMakeWriter {
    pub fn new(config: &LoggingConfig) -> io::Result<Self> {
        let parent = config
            .path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no parent"))?;
        fs::create_dir_all(parent)?;
        let max_line_bytes = usize::try_from(config.max_line_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "max_line_bytes is too large")
        })?;
        Ok(Self {
            state: Arc::new(Mutex::new(LogState {
                path: config.path.clone(),
                max_file_bytes: config.max_file_bytes,
                max_files: config.max_files,
            })),
            rate: Arc::new(Mutex::new(RateLimiter::new(
                config.rate_limit_per_target_per_sec,
            ))),
            dropped_records: Arc::new(AtomicU64::new(0)),
            max_line_bytes,
        })
    }

    #[must_use]
    pub fn dropped_records(&self) -> u64 {
        self.dropped_records.load(Ordering::Relaxed)
    }

    fn record_writer(&self, target: &str) -> RecordWriter {
        let allowed = self
            .rate
            .lock()
            .is_ok_and(|mut rate| rate.allow(target, Instant::now()));
        if !allowed {
            let _ =
                self.dropped_records
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        Some(value.saturating_add(1))
                    });
        }
        RecordWriter {
            state: Arc::clone(&self.state),
            bytes: Vec::with_capacity(if allowed {
                self.max_line_bytes.min(1024)
            } else {
                0
            }),
            max_line_bytes: self.max_line_bytes,
            truncated: false,
            allowed,
        }
    }
}

impl<'a> MakeWriter<'a> for BoundedMakeWriter {
    type Writer = RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.record_writer("__unknown__")
    }

    fn make_writer_for(&'a self, metadata: &Metadata<'_>) -> Self::Writer {
        self.record_writer(metadata.target())
    }
}

pub struct RecordWriter {
    state: Arc<Mutex<LogState>>,
    bytes: Vec<u8>,
    max_line_bytes: usize,
    truncated: bool,
    allowed: bool,
}

impl Write for RecordWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if !self.allowed {
            return Ok(buffer.len());
        }
        let remaining = self.max_line_bytes.saturating_sub(self.bytes.len());
        let accepted = remaining.min(buffer.len());
        self.bytes.extend_from_slice(&buffer[..accepted]);
        self.truncated |= accepted < buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RecordWriter {
    fn drop(&mut self) {
        const MARKER: &[u8] = b" [truncated]";
        if !self.allowed {
            return;
        }
        if self.truncated && self.max_line_bytes > MARKER.len() {
            self.bytes
                .truncate(self.max_line_bytes.saturating_sub(MARKER.len()));
            self.bytes.extend_from_slice(MARKER);
        }
        if !self.bytes.ends_with(b"\n") {
            if self.bytes.len() == self.max_line_bytes && !self.bytes.is_empty() {
                self.bytes.pop();
            }
            self.bytes.push(b'\n');
        }
        if let Ok(mut state) = self.state.lock() {
            let _ = state.append(&self.bytes);
        }
    }
}

struct RateLimiter {
    limit: u32,
    window_started: Instant,
    targets: HashMap<u64, u32>,
    overflow_count: u32,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            window_started: Instant::now(),
            targets: HashMap::with_capacity(MAX_RATE_TARGETS),
            overflow_count: 0,
        }
    }

    fn allow(&mut self, target: &str, now: Instant) -> bool {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.targets.clear();
            self.overflow_count = 0;
        }
        let key = target_key(target);
        if let Some(count) = self.targets.get_mut(&key) {
            if *count >= self.limit {
                return false;
            }
            *count = count.saturating_add(1);
            return true;
        }
        if self.targets.len() < MAX_RATE_TARGETS {
            self.targets.insert(key, 1);
            return self.limit > 0;
        }
        if self.overflow_count >= self.limit {
            false
        } else {
            self.overflow_count = self.overflow_count.saturating_add(1);
            true
        }
    }
}

fn target_key(target: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    hasher.finish()
}

struct LogState {
    path: PathBuf,
    max_file_bytes: u64,
    max_files: u32,
}

impl LogState {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let current_bytes = match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "refusing to write a non-regular log path",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        if current_bytes.saturating_add(bytes.len() as u64) > self.max_file_bytes {
            self.rotate()?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)
    }

    fn rotate(&self) -> io::Result<()> {
        if self.max_files <= 1 {
            return remove_if_exists(&self.path);
        }

        remove_if_exists(&rotated_path(&self.path, self.max_files - 1))?;
        for index in (1..self.max_files).rev() {
            let source = if index == 1 {
                self.path.clone()
            } else {
                rotated_path(&self.path, index - 1)
            };
            match fs::symlink_metadata(&source) {
                Ok(metadata) if metadata.is_file() => {
                    fs::rename(source, rotated_path(&self.path, index))?;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "refusing to rotate a non-regular log path",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn rotated_path(path: &Path, index: u32) -> PathBuf {
    PathBuf::from(format!("{}.{index}", path.display()))
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rotates_with_a_hard_file_count() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-log-test-{nonce}"));
        fs::create_dir_all(&root).expect("create log test directory");
        let mut state = LogState {
            path: root.join("agent.log"),
            max_file_bytes: 8,
            max_files: 2,
        };
        state.append(b"first\n").expect("first log record");
        state.append(b"second\n").expect("second log record");
        state.append(b"third\n").expect("third log record");

        assert!(state.path.exists());
        assert!(rotated_path(&state.path, 1).exists());
        assert!(!rotated_path(&state.path, 2).exists());
        fs::remove_dir_all(root).expect("remove log test directory");
    }

    #[test]
    fn rate_limits_records_and_exposes_drop_count() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-rate-test-{nonce}"));
        let config = LoggingConfig {
            path: root.join("agent.log"),
            rate_limit_per_target_per_sec: 2,
            ..LoggingConfig::default()
        };
        let writer = BoundedMakeWriter::new(&config).expect("writer");
        for message in ["one", "two", "three"] {
            let mut record = writer.make_writer();
            writeln!(record, "{message}").expect("write record");
        }
        assert_eq!(writer.dropped_records(), 1);
        let output = fs::read_to_string(&config.path).expect("read log");
        assert!(output.contains("one"));
        assert!(output.contains("two"));
        assert!(!output.contains("three"));
        assert_eq!(
            fs::metadata(&config.path)
                .expect("log metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        fs::remove_dir_all(root).expect("remove rate test directory");
    }

    #[test]
    fn refuses_to_follow_log_symlinks() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mbed-agent-log-link-test-{nonce}"));
        fs::create_dir_all(&root).expect("create root");
        let target = root.join("target");
        fs::write(&target, b"protected").expect("target");
        let log_path = root.join("agent.log");
        symlink(&target, &log_path).expect("symlink");
        let mut state = LogState {
            path: log_path,
            max_file_bytes: 1024,
            max_files: 2,
        };
        assert!(state.append(b"must-not-write\n").is_err());
        assert_eq!(fs::read(&target).expect("read target"), b"protected");
        fs::remove_dir_all(root).expect("remove symlink test directory");
    }
}
