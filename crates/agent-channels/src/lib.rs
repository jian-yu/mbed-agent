//! Bounded, provider-neutral channel messages and MQTT topic contracts.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroize;

pub const CHANNEL_MESSAGE_SCHEMA_VERSION: u16 = 1;
pub const MAX_CHANNEL_MESSAGE_BYTES: usize = 32 * 1024;
pub const MAX_CHANNEL_ID_BYTES: usize = 128;
pub const MAX_CHANNEL_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelLifecycle {
    Unconfigured,
    Bound,
    Connecting,
    Online,
    Backoff,
    Offline,
    NeedsRebind,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelRequest {
    pub schema_version: u16,
    pub message_id: String,
    pub actor_id: String,
    pub conversation_id: String,
    pub expires_unix_ms: i64,
    pub command: ChannelCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelCommand {
    Ping,
    Status,
    Ask { text: String },
    Elevate { password: ChannelSecret },
    Diagnose { target: DiagnosticTarget },
}

/// A channel-supplied administrator password that is redacted in debug output
/// and zeroized when the message leaves memory.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ChannelSecret(String);

impl ChannelSecret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        let mut value = self;
        std::mem::take(&mut value.0)
    }
}

impl std::fmt::Debug for ChannelSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED CHANNEL SECRET]")
    }
}

impl Drop for ChannelSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Converts the small, transport-neutral text command surface into a typed
/// channel command. Only `/elevate` is intercepted; all other text remains an
/// LLM prompt.
#[must_use]
pub fn command_from_text(mut text: String) -> ChannelCommand {
    if let Some(rest) = text.strip_prefix("/elevate") {
        if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
            let password = rest.trim().to_owned();
            text.zeroize();
            return ChannelCommand::Elevate {
                password: ChannelSecret::new(password),
            };
        }
    }
    ChannelCommand::Ask { text }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticTarget {
    Wan,
    Dns,
    Dhcp,
    Routes,
    Interfaces,
    Neighbors,
    Firewall,
    PolicyRouting,
    Listeners,
    Wireless,
    InterfaceStats,
    Conntrack,
    Qdisc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChannelResponse {
    pub schema_version: u16,
    pub message_id: String,
    pub ok: bool,
    pub result: Option<Value>,
    pub error: Option<ChannelErrorBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelErrorBody {
    pub code: String,
    pub message: String,
}

impl ChannelResponse {
    #[must_use]
    pub fn success(message_id: String, result: Value) -> Self {
        Self {
            schema_version: CHANNEL_MESSAGE_SCHEMA_VERSION,
            message_id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(message_id: String, code: &str, message: &str) -> Self {
        Self {
            schema_version: CHANNEL_MESSAGE_SCHEMA_VERSION,
            message_id,
            ok: false,
            result: None,
            error: Some(ChannelErrorBody {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelMessageError {
    #[error("channel message exceeds its byte limit")]
    Capacity,
    #[error("channel message JSON is invalid")]
    InvalidJson,
    #[error("channel message schema version is unsupported")]
    UnsupportedSchema,
    #[error("channel message field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("channel message has expired")]
    Expired,
}

/// Parses and validates one inbound request before it reaches the daemon.
///
/// # Errors
///
/// Returns an error for oversized, malformed, expired, or unbounded messages.
pub fn decode_request(
    payload: &[u8],
    now_unix_ms: i64,
) -> Result<ChannelRequest, ChannelMessageError> {
    if payload.is_empty() || payload.len() > MAX_CHANNEL_MESSAGE_BYTES {
        return Err(ChannelMessageError::Capacity);
    }
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| ChannelMessageError::InvalidJson)?;
    validate_command_shape(value.get("command"))?;
    let request: ChannelRequest =
        serde_json::from_value(value).map_err(|_| ChannelMessageError::InvalidJson)?;
    if request.schema_version != CHANNEL_MESSAGE_SCHEMA_VERSION {
        return Err(ChannelMessageError::UnsupportedSchema);
    }
    validate_id(&request.message_id, "message_id")?;
    validate_id(&request.actor_id, "actor_id")?;
    validate_id(&request.conversation_id, "conversation_id")?;
    if request.expires_unix_ms <= now_unix_ms {
        return Err(ChannelMessageError::Expired);
    }
    if request.expires_unix_ms.saturating_sub(now_unix_ms) > 10 * 60 * 1_000 {
        return Err(ChannelMessageError::InvalidField("expires_unix_ms"));
    }
    match &request.command {
        ChannelCommand::Ask { text } => {
            if text.trim().is_empty() || text.len() > MAX_CHANNEL_TEXT_BYTES || text.contains('\0')
            {
                return Err(ChannelMessageError::InvalidField("command.text"));
            }
        }
        ChannelCommand::Elevate { password } => {
            if password.0.is_empty()
                || password.0.len() > 1_024
                || password.0.chars().any(char::is_control)
            {
                return Err(ChannelMessageError::InvalidField("command.password"));
            }
        }
        ChannelCommand::Ping | ChannelCommand::Status | ChannelCommand::Diagnose { .. } => {}
    }
    Ok(request)
}

fn validate_command_shape(command: Option<&Value>) -> Result<(), ChannelMessageError> {
    let command = command
        .and_then(Value::as_object)
        .ok_or(ChannelMessageError::InvalidJson)?;
    let kind = command
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ChannelMessageError::InvalidJson)?;
    let expected = match kind {
        "ping" | "status" => ["type"].as_slice(),
        "ask" => ["text", "type"].as_slice(),
        "elevate" => ["password", "type"].as_slice(),
        "diagnose" => ["target", "type"].as_slice(),
        _ => return Err(ChannelMessageError::InvalidJson),
    };
    if command.len() != expected.len()
        || !command
            .keys()
            .all(|key| expected.binary_search(&key.as_str()).is_ok())
    {
        return Err(ChannelMessageError::InvalidJson);
    }
    Ok(())
}

/// Encodes a bounded response for transport publication.
///
/// # Errors
///
/// Returns an error when serialization fails or exceeds the channel limit.
pub fn encode_response(response: &ChannelResponse) -> Result<Vec<u8>, ChannelMessageError> {
    validate_id(&response.message_id, "message_id")?;
    let payload = serde_json::to_vec(response).map_err(|_| ChannelMessageError::InvalidJson)?;
    if payload.len() > MAX_CHANNEL_MESSAGE_BYTES {
        return Err(ChannelMessageError::Capacity);
    }
    Ok(payload)
}

/// Returns the fixed per-device MQTT request topic.
///
/// # Errors
///
/// Returns an error for an unsafe device identifier.
pub fn mqtt_request_topic(device_id: &str) -> Result<String, ChannelMessageError> {
    validate_topic_segment(device_id)?;
    Ok(format!("mbed-agent/v1/devices/{device_id}/requests"))
}

/// Returns the fixed response topic for one validated request.
///
/// # Errors
///
/// Returns an error for unsafe device or message identifiers.
pub fn mqtt_response_topic(
    device_id: &str,
    message_id: &str,
) -> Result<String, ChannelMessageError> {
    validate_topic_segment(device_id)?;
    validate_topic_segment(message_id)?;
    Ok(format!(
        "mbed-agent/v1/devices/{device_id}/responses/{message_id}"
    ))
}

fn validate_id(value: &str, field: &'static str) -> Result<(), ChannelMessageError> {
    if value.is_empty() || value.len() > MAX_CHANNEL_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(ChannelMessageError::InvalidField(field));
    }
    Ok(())
}

fn validate_topic_segment(value: &str) -> Result<(), ChannelMessageError> {
    validate_id(value, "mqtt topic segment")?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ChannelMessageError::InvalidField("mqtt topic segment"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_typed_bounded_and_expiring() {
        let payload = serde_json::to_vec(&ChannelRequest {
            schema_version: CHANNEL_MESSAGE_SCHEMA_VERSION,
            message_id: "message-1".into(),
            actor_id: "operator-1".into(),
            conversation_id: "conversation-1".into(),
            expires_unix_ms: 61_000,
            command: ChannelCommand::Diagnose {
                target: DiagnosticTarget::Dns,
            },
        })
        .expect("encode");
        assert_eq!(
            decode_request(&payload, 1_000).expect("request").message_id,
            "message-1"
        );
        assert_eq!(
            decode_request(&payload, 61_000),
            Err(ChannelMessageError::Expired)
        );
    }

    #[test]
    fn topic_segments_cannot_inject_wildcards_or_paths() {
        assert_eq!(
            mqtt_request_topic("router-1").expect("topic"),
            "mbed-agent/v1/devices/router-1/requests"
        );
        assert!(mqtt_request_topic("router/+/other").is_err());
        assert!(mqtt_response_topic("router-1", "message/#").is_err());
    }

    #[test]
    fn unknown_command_fields_are_rejected() {
        let payload = br#"{"schema_version":1,"message_id":"m","actor_id":"a","conversation_id":"c","expires_unix_ms":10000,"command":{"type":"ping","shell":"id"}}"#;
        assert_eq!(
            decode_request(payload, 1),
            Err(ChannelMessageError::InvalidJson)
        );
    }

    #[test]
    fn elevate_text_becomes_redacted_typed_command() {
        let command = command_from_text("/elevate correct horse".into());
        assert_eq!(
            command,
            ChannelCommand::Elevate {
                password: ChannelSecret::new("correct horse"),
            }
        );
        assert!(!format!("{command:?}").contains("correct horse"));

        assert!(matches!(
            command_from_text("/elevateX not-a-command".into()),
            ChannelCommand::Ask { .. }
        ));
    }

    #[test]
    fn elevate_payload_is_bounded_and_schema_checked() {
        let request = ChannelRequest {
            schema_version: CHANNEL_MESSAGE_SCHEMA_VERSION,
            message_id: "message-1".into(),
            actor_id: "wecom:user-1".into(),
            conversation_id: "wecom:chat-1".into(),
            expires_unix_ms: 10_000,
            command: ChannelCommand::Elevate {
                password: ChannelSecret::new("secret"),
            },
        };
        let payload = serde_json::to_vec(&request).expect("encode");
        assert!(decode_request(&payload, 1).is_ok());
        assert!(decode_request(
            br#"{"schema_version":1,"message_id":"m","actor_id":"a","conversation_id":"c","expires_unix_ms":10000,"command":{"type":"elevate","password":""}}"#,
            1
        )
        .is_err());
    }
}
