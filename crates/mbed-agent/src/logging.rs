use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agent_core::config::LoggingConfig;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
pub struct BoundedMakeWriter {
    state: Arc<Mutex<LogState>>,
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
            max_line_bytes,
        })
    }
}

impl<'a> MakeWriter<'a> for BoundedMakeWriter {
    type Writer = RecordWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RecordWriter {
            state: Arc::clone(&self.state),
            bytes: Vec::with_capacity(self.max_line_bytes.min(1024)),
            max_line_bytes: self.max_line_bytes,
            truncated: false,
        }
    }
}

pub struct RecordWriter {
    state: Arc<Mutex<LogState>>,
    bytes: Vec<u8>,
    max_line_bytes: usize,
    truncated: bool,
}

impl Write for RecordWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
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

struct LogState {
    path: PathBuf,
    max_file_bytes: u64,
    max_files: u32,
}

impl LogState {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let current_bytes = fs::metadata(&self.path).map_or(0, |metadata| metadata.len());
        if current_bytes.saturating_add(bytes.len() as u64) > self.max_file_bytes {
            self.rotate()?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?
            .write_all(bytes)
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
            if source.exists() {
                fs::rename(source, rotated_path(&self.path, index))?;
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
}
