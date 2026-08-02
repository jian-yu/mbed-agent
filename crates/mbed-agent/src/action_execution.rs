use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use agent_core::ActionInvocation;
use agent_protocol::ActionOutputResponse;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

#[derive(Debug, Error)]
pub(crate) enum ActionExecutionError {
    #[error("action executable or script is unsafe")]
    UnsafeExecutable,
    #[error("action process I/O failed")]
    Io(#[from] io::Error),
    #[error("action timed out")]
    TimedOut,
}

pub(crate) async fn execute_action(
    action_id: String,
    invocation: ActionInvocation,
    trusted_owner_uid: u32,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ActionOutputResponse, ActionExecutionError> {
    validate_shell_script(&invocation.executable, &invocation.argv, trusted_owner_uid)?;
    let executable = secure_program(&invocation.executable, trusted_owner_uid)?;
    let stdout_limit = max_output_bytes.saturating_mul(3) / 4;
    let stderr_limit = max_output_bytes.saturating_sub(stdout_limit);
    let mut child = Command::new(executable)
        .args(&invocation.argv)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ActionExecutionError::Io(io::Error::other("stdout pipe is unavailable")))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| ActionExecutionError::Io(io::Error::other("stderr pipe is unavailable")))?;
    let started = Instant::now();
    let outcome = tokio::time::timeout(timeout, async {
        let status = child.wait();
        let stdout = read_bounded(&mut stdout, stdout_limit);
        let stderr = read_bounded(&mut stderr, stderr_limit);
        tokio::try_join!(status, stdout, stderr)
    })
    .await;
    let (status, stdout, stderr) = if let Ok(result) = outcome {
        result?
    } else {
        child.kill().await?;
        let _ = child.wait().await;
        return Err(ActionExecutionError::TimedOut);
    };
    Ok(ActionOutputResponse {
        action_id,
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        output_truncated: stdout.truncated || stderr.truncated,
    })
}

struct BoundedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn read_bounded(
    reader: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> io::Result<BoundedBytes> {
    let mut bytes = Vec::with_capacity(limit.min(4096));
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok(BoundedBytes { bytes, truncated })
}

fn secure_program(path: &Path, trusted_owner_uid: u32) -> Result<PathBuf, ActionExecutionError> {
    let path = fs::canonicalize(path).map_err(ActionExecutionError::Io)?;
    let metadata = fs::metadata(&path).map_err(ActionExecutionError::Io)?;
    if !path.is_absolute()
        || path.starts_with("/tmp")
        || !metadata.is_file()
        || metadata.uid() != trusted_owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(ActionExecutionError::UnsafeExecutable);
    }
    Ok(path)
}

fn validate_shell_script(
    executable: &Path,
    argv: &[String],
    trusted_owner_uid: u32,
) -> Result<(), ActionExecutionError> {
    let script_index = match executable.file_name().and_then(|value| value.to_str()) {
        Some("sh" | "ash" | "bash" | "dash") => Some(0),
        Some("busybox")
            if argv
                .first()
                .is_some_and(|value| value == "sh" || value == "ash") =>
        {
            Some(1)
        }
        _ => None,
    };
    if let Some(script_index) = script_index {
        let Some(script) = argv.get(script_index) else {
            return Err(ActionExecutionError::UnsafeExecutable);
        };
        secure_program(Path::new(script), trusted_owner_uid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn executes_fixed_argv_without_a_shell() {
        let output = execute_action(
            "echo_value".into(),
            ActionInvocation {
                executable: PathBuf::from("/bin/echo"),
                argv: vec!["hello;touch /tmp/not-executed".into()],
            },
            0,
            Duration::from_secs(1),
            1024,
        )
        .await
        .expect("execute");
        assert_eq!(output.exit_code, Some(0));
        assert!(output.stdout.contains("hello;touch /tmp/not-executed"));
    }

    #[tokio::test]
    async fn output_is_hard_bounded() {
        let output = execute_action(
            "bounded".into(),
            ActionInvocation {
                executable: PathBuf::from("/usr/bin/printf"),
                argv: vec!["%02048d".into(), "1".into()],
            },
            0,
            Duration::from_secs(1),
            256,
        )
        .await
        .expect("execute");
        assert!(output.output_truncated);
        assert!(output.stdout.len() <= 192);
    }
}
