use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_channels::{
    CHANNEL_MESSAGE_SCHEMA_VERSION, ChannelLifecycle, ChannelRequest, ChannelResponse,
    decode_request,
};
use agent_core::{WeChatClawBotConfig, parse_wechat_clawbot_base_url};
use agent_store::{ChannelMessageClaim, Store};
use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::warn;

const CHANNEL_NAME: &str = "wechat_clawbot";
const INBOUND_CAPACITY: usize = 4;
const MAX_HTTP_BYTES: usize = 32 * 1024;
const MAX_CURSOR_BYTES: usize = 32 * 1024;
const MAX_MESSAGES_PER_RESPONSE: usize = 16;
const MAX_CONTEXT_TOKEN_BYTES: usize = 16 * 1024;
const MAX_REPLY_TEXT_BYTES: usize = 16 * 1024;
const MAX_RECONNECT_SECS: u64 = 60;
const APP_ID: &str = "bot";
static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct WeChatInbound {
    pub request: ChannelRequest,
    pub respond_to: oneshot::Sender<ChannelResponse>,
}

pub(crate) struct WeChatRuntime {
    pub inbound: mpsc::Receiver<WeChatInbound>,
    pub status: watch::Receiver<ChannelLifecycle>,
}

#[derive(Debug, Error)]
pub(crate) enum WeChatChannelError {
    #[error("WeChat ClawBot configuration is invalid")]
    InvalidConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct GetUpdatesResponse {
    #[serde(default)]
    ret: Option<i32>,
    #[serde(default)]
    errcode: Option<i32>,
    #[serde(default)]
    errmsg: Option<String>,
    #[serde(default)]
    msgs: Option<Vec<WeChatMessage>>,
    #[serde(default)]
    get_updates_buf: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WeChatMessage {
    #[serde(default)]
    message_id: Option<MessageId>,
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    from_user_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    message_type: Option<u8>,
    #[serde(default)]
    message_state: Option<u8>,
    #[serde(default)]
    item_list: Option<Vec<WeChatMessageItem>>,
    #[serde(default)]
    context_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum MessageId {
    Number(u64),
    Text(String),
}

impl MessageId {
    fn as_str(&self) -> Option<String> {
        match self {
            Self::Number(value) => Some(value.to_string()),
            Self::Text(value) if !value.is_empty() => Some(value.clone()),
            Self::Text(_) => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct WeChatMessageItem {
    #[serde(rename = "type", default)]
    item_type: Option<u8>,
    #[serde(default)]
    text_item: Option<WeChatTextItem>,
}

#[derive(Debug, Clone, Deserialize)]
struct WeChatTextItem {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Serialize)]
struct GetUpdatesRequest<'a> {
    get_updates_buf: &'a str,
    base_info: BaseInfo<'a>,
}

#[derive(Debug, Serialize)]
struct SendMessageRequest<'a> {
    msg: OutgoingMessage<'a>,
    base_info: BaseInfo<'a>,
}

#[derive(Debug, Serialize)]
struct BaseInfo<'a> {
    channel_version: &'a str,
    bot_agent: &'a str,
}

#[derive(Debug, Serialize)]
struct OutgoingMessage<'a> {
    message_id: u64,
    to_user_id: &'a str,
    message_type: u8,
    message_state: u8,
    item_list: [OutgoingMessageItem<'a>; 1],
    context_token: &'a str,
}

#[derive(Debug, Serialize)]
struct OutgoingMessageItem<'a> {
    #[serde(rename = "type")]
    item_type: u8,
    text_item: OutgoingTextItem<'a>,
}

#[derive(Debug, Serialize)]
struct OutgoingTextItem<'a> {
    text: &'a str,
}

pub(crate) fn start(
    config: WeChatClawBotConfig,
    store: Arc<Store>,
    max_records: u32,
) -> Result<Option<WeChatRuntime>, WeChatChannelError> {
    if !config.enabled {
        return Ok(None);
    }
    if config.bot_token.is_empty() || parse_wechat_clawbot_base_url(&config.base_url).is_err() {
        return Err(WeChatChannelError::InvalidConfig);
    }
    let request_timeout = Duration::from_secs(config.request_timeout_secs);
    let client = reqwest::Client::builder()
        .connect_timeout(request_timeout)
        .timeout(
            Duration::from_secs(config.long_poll_timeout_secs)
                .saturating_add(request_timeout)
                .saturating_add(Duration::from_secs(5)),
        )
        .build()
        .map_err(|_| WeChatChannelError::InvalidConfig)?;
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CAPACITY);
    let (status_tx, status_rx) = watch::channel(ChannelLifecycle::Connecting);
    tokio::spawn(run(
        config,
        store,
        client,
        inbound_tx,
        max_records,
        status_tx,
    ));
    Ok(Some(WeChatRuntime {
        inbound: inbound_rx,
        status: status_rx,
    }))
}

async fn run(
    config: WeChatClawBotConfig,
    store: Arc<Store>,
    client: reqwest::Client,
    inbound_tx: mpsc::Sender<WeChatInbound>,
    max_records: u32,
    status: watch::Sender<ChannelLifecycle>,
) {
    let mut cursor = String::new();
    let mut backoff_secs = 1;
    loop {
        match get_updates(&client, &config, &cursor).await {
            Ok(response) => {
                if response.ret == Some(-14) || response.errcode == Some(-14) {
                    cursor.clear();
                    warn!(
                        reason = response.errmsg.as_deref().unwrap_or("session expired"),
                        "WeChat ClawBot cursor expired; restarting from an empty cursor"
                    );
                    continue;
                }
                status.send_replace(ChannelLifecycle::Online);
                backoff_secs = 1;
                if let Some(next_cursor) = response.get_updates_buf {
                    if next_cursor.len() <= MAX_CURSOR_BYTES
                        && !next_cursor.chars().any(char::is_control)
                    {
                        cursor = next_cursor;
                    } else {
                        warn!("WeChat ClawBot cursor exceeded its bound; resetting cursor");
                        cursor.clear();
                    }
                }
                for message in response
                    .msgs
                    .unwrap_or_default()
                    .into_iter()
                    .take(MAX_MESSAGES_PER_RESPONSE)
                {
                    handle_message(
                        &client,
                        &config,
                        Arc::clone(&store),
                        &inbound_tx,
                        message,
                        max_records,
                    )
                    .await;
                }
            }
            Err(WeChatRequestError::NeedsRebind) => {
                status.send_replace(ChannelLifecycle::NeedsRebind);
                warn!("WeChat ClawBot token was rejected; rebind is required");
                break;
            }
            Err(error) => {
                status.send_replace(ChannelLifecycle::Backoff);
                warn!(%error, backoff_secs, "WeChat ClawBot long poll failed; reconnecting");
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = backoff_secs.saturating_mul(2).min(MAX_RECONNECT_SECS);
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // Keeps message validation, dedupe, and reply ownership together.
async fn handle_message(
    client: &reqwest::Client,
    config: &WeChatClawBotConfig,
    store: Arc<Store>,
    inbound_tx: &mpsc::Sender<WeChatInbound>,
    message: WeChatMessage,
    max_records: u32,
) {
    if message.message_type != Some(1) || message.message_state.is_some_and(|state| state != 0) {
        return;
    }
    let Some(from_user_id) = bounded_id(message.from_user_id.as_deref()) else {
        warn!("WeChat ClawBot message has no bounded sender id");
        return;
    };
    let Some(context_token) = bounded_context(message.context_token.as_deref()) else {
        warn!("WeChat ClawBot message has no bounded context token");
        return;
    };
    let text = message
        .item_list
        .as_deref()
        .and_then(extract_text)
        .and_then(|text| bounded_text(Some(text)))
        .map(str::to_owned);
    let Some(text) = text else {
        // Non-text messages are deliberately not passed into the LLM or shell
        // surface until their media bounds and official decryption path exist.
        return;
    };
    let raw_message_id = message
        .message_id
        .as_ref()
        .and_then(MessageId::as_str)
        .or_else(|| message.seq.map(|seq| seq.to_string()));
    let Some(raw_message_id) = raw_message_id else {
        warn!("WeChat ClawBot message has no stable id");
        return;
    };
    let message_id = format!("{}:{raw_message_id}", config.account);
    let conversation_id = message
        .group_id
        .as_deref()
        .and_then(|group| bounded_id(Some(group)))
        .map_or_else(|| from_user_id.clone(), |group| format!("group:{group}"));
    let now = unix_ms();
    let expires = now.saturating_add(9 * 60 * 1_000);
    let request = ChannelRequest {
        schema_version: CHANNEL_MESSAGE_SCHEMA_VERSION,
        message_id: message_id.clone(),
        actor_id: format!("wechat:{from_user_id}"),
        conversation_id: format!("wechat:{conversation_id}"),
        expires_unix_ms: expires,
        command: agent_channels::ChannelCommand::Ask { text },
    };
    if decode_request(&serde_json::to_vec(&request).unwrap_or_default(), now).is_err() {
        warn!(%message_id, "WeChat ClawBot message failed channel validation");
        return;
    }
    let store_for_claim = Arc::clone(&store);
    let claim_id = message_id.clone();
    let claim = tokio::task::spawn_blocking(move || {
        store_for_claim.claim_channel_message(CHANNEL_NAME, &claim_id, expires, now, max_records)
    })
    .await;
    if !matches!(claim, Ok(Ok(ChannelMessageClaim::New))) {
        return;
    }
    let to_user_id = from_user_id.clone();
    let reply_context_token = context_token.clone();
    let (respond_to, response_rx) = oneshot::channel();
    if inbound_tx
        .try_send(WeChatInbound {
            request,
            respond_to,
        })
        .is_err()
    {
        warn!(%message_id, "WeChat ClawBot inbound queue is full");
        let config = config.clone();
        let client = client.clone();
        let response =
            ChannelResponse::error(message_id, "busy", "the device channel queue is full");
        tokio::spawn(async move {
            if let Err(error) = send_response(
                &client,
                &config,
                &response,
                &to_user_id,
                &reply_context_token,
            )
            .await
            {
                warn!(%error, "WeChat ClawBot busy reply failed");
            }
        });
        return;
    }
    let client = client.clone();
    let config = config.clone();
    tokio::spawn(async move {
        let response = match tokio::time::timeout(Duration::from_secs(130), response_rx).await {
            Ok(Ok(response)) => response,
            _ => ChannelResponse::error(
                message_id,
                "timeout",
                "the device did not complete the channel request",
            ),
        };
        if let Err(error) = send_response(
            &client,
            &config,
            &response,
            &to_user_id,
            &reply_context_token,
        )
        .await
        {
            warn!(%error, "WeChat ClawBot reply failed");
        }
    });
}

fn extract_text(items: &[WeChatMessageItem]) -> Option<&str> {
    items.iter().find_map(|item| {
        if item.item_type == Some(1) {
            item.text_item.as_ref()?.text.as_deref()
        } else {
            None
        }
    })
}

fn bounded_id(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn bounded_context(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty()
        || value.len() > MAX_CONTEXT_TOKEN_BYTES
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn bounded_text(value: Option<&str>) -> Option<&str> {
    let value = value?;
    if value.trim().is_empty()
        || value.contains('\0')
        || value.len() > agent_channels::MAX_CHANNEL_TEXT_BYTES
    {
        return None;
    }
    Some(value)
}

async fn get_updates(
    client: &reqwest::Client,
    config: &WeChatClawBotConfig,
    cursor: &str,
) -> Result<GetUpdatesResponse, WeChatRequestError> {
    let request = GetUpdatesRequest {
        get_updates_buf: cursor,
        base_info: base_info(config),
    };
    post_json(
        client,
        config,
        "ilink/bot/getupdates",
        &request,
        config.long_poll_timeout_secs.saturating_add(5),
    )
    .await
}

async fn send_response(
    client: &reqwest::Client,
    config: &WeChatClawBotConfig,
    response: &ChannelResponse,
    to_user_id: &str,
    context_token: &str,
) -> Result<(), WeChatRequestError> {
    let text = response_text(response);
    let message_id = NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
    let request = SendMessageRequest {
        msg: OutgoingMessage {
            message_id,
            to_user_id,
            message_type: 2,
            message_state: 2,
            item_list: [OutgoingMessageItem {
                item_type: 1,
                text_item: OutgoingTextItem { text: &text },
            }],
            context_token,
        },
        base_info: base_info(config),
    };
    let _: Value = post_json(
        client,
        config,
        "ilink/bot/sendmessage",
        &request,
        config.request_timeout_secs,
    )
    .await?;
    Ok(())
}

fn response_text(response: &ChannelResponse) -> String {
    let mut text = if !response.ok {
        response.error.as_ref().map_or_else(
            || "request failed".to_owned(),
            |error| error.message.clone(),
        )
    } else if let Some(result) = &response.result {
        if result.get("type").and_then(Value::as_str) == Some("completion") {
            result
                .get("data")
                .and_then(|data| data.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("completed")
                .to_owned()
        } else {
            serde_json::to_string_pretty(result).unwrap_or_else(|_| "completed".to_owned())
        }
    } else {
        "completed".to_owned()
    };
    truncate_text(&mut text, MAX_REPLY_TEXT_BYTES);
    text
}

fn truncate_text(text: &mut String, limit: usize) {
    if text.len() <= limit {
        return;
    }
    let suffix = "\n[truncated]";
    let keep = limit.saturating_sub(suffix.len());
    let boundary = text
        .char_indices()
        .take_while(|(index, _)| *index <= keep)
        .last()
        .map_or(0, |(index, _)| index);
    text.truncate(boundary);
    text.push_str(suffix);
}

fn base_info(config: &WeChatClawBotConfig) -> BaseInfo<'_> {
    BaseInfo {
        channel_version: env!("CARGO_PKG_VERSION"),
        bot_agent: &config.bot_agent,
    }
}

async fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    config: &WeChatClawBotConfig,
    endpoint: &str,
    body: &T,
    timeout_secs: u64,
) -> Result<R, WeChatRequestError> {
    let base_url = config.base_url.trim_end_matches('/');
    let url = format!("{base_url}/{endpoint}");
    let response = client
        .post(url)
        .headers(build_headers(config.bot_token.expose())?)
        .json(body)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .map_err(|error| WeChatRequestError::Transport(error.to_string()))?;
    if response.status().as_u16() == 401 || response.status().as_u16() == 403 {
        return Err(WeChatRequestError::NeedsRebind);
    }
    let response = response
        .error_for_status()
        .map_err(|error| WeChatRequestError::Transport(error.to_string()))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_BYTES as u64)
    {
        return Err(WeChatRequestError::ResponseTooLarge);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| WeChatRequestError::Transport(error.to_string()))?;
    if bytes.len() > MAX_HTTP_BYTES {
        return Err(WeChatRequestError::ResponseTooLarge);
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| WeChatRequestError::Protocol(error.to_string()))?;
    validate_response(&value)?;
    serde_json::from_value(value).map_err(|error| WeChatRequestError::Protocol(error.to_string()))
}

fn validate_response(value: &Value) -> Result<(), WeChatRequestError> {
    let ret = value.get("ret").and_then(Value::as_i64).unwrap_or(0);
    let errcode = value.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if ret != 0 || errcode != 0 {
        let message = value
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("official API returned an error");
        // Session expiration can be recovered by restarting from an empty
        // cursor; only an HTTP auth failure requires re-binding.
        if ret == -14 || errcode == -14 {
            return Ok(());
        }
        return Err(WeChatRequestError::Protocol(message.to_owned()));
    }
    Ok(())
}

fn build_headers(token: &str) -> Result<HeaderMap, WeChatRequestError> {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert(
        "AuthorizationType",
        HeaderValue::from_static("ilink_bot_token"),
    );
    let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| WeChatRequestError::Transport("invalid authorization header".into()))?;
    headers.insert(AUTHORIZATION, authorization);
    headers.insert("iLink-App-Id", HeaderValue::from_static(APP_ID));
    headers.insert("iLink-App-ClientVersion", HeaderValue::from_static("65536"));
    let mut random = [0_u8; 4];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| WeChatRequestError::Transport("failed to generate X-WECHAT-UIN".into()))?;
    let uin =
        base64::engine::general_purpose::STANDARD.encode(u32::from_be_bytes(random).to_string());
    headers.insert(
        "X-WECHAT-UIN",
        HeaderValue::from_str(&uin)
            .map_err(|_| WeChatRequestError::Transport("invalid X-WECHAT-UIN header".into()))?,
    );
    Ok(headers)
}

#[derive(Debug, Error)]
enum WeChatRequestError {
    #[error("WeChat ClawBot authentication was rejected")]
    NeedsRebind,
    #[error("WeChat ClawBot transport failed: {0}")]
    Transport(String),
    #[error("WeChat ClawBot response exceeded its bound")]
    ResponseTooLarge,
    #[error("WeChat ClawBot response was invalid: {0}")]
    Protocol(String),
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_message_is_extracted_and_reply_is_bounded() {
        let items = vec![WeChatMessageItem {
            item_type: Some(1),
            text_item: Some(WeChatTextItem {
                text: Some("hello".into()),
            }),
        }];
        assert_eq!(extract_text(&items), Some("hello"));
        let response = ChannelResponse::success(
            "message".into(),
            serde_json::json!({
                "type": "completion",
                "data": {"text": "reply"}
            }),
        );
        assert_eq!(response_text(&response), "reply");
    }

    #[test]
    fn ids_context_and_text_are_bounded() {
        assert!(bounded_id(Some("user-1")).is_some());
        assert!(bounded_id(Some("bad\nuser")).is_none());
        assert!(bounded_context(Some("ctx")).is_some());
        assert!(bounded_text(Some(" ")).is_none());
        assert!(
            bounded_text(Some(
                &"x".repeat(agent_channels::MAX_CHANNEL_TEXT_BYTES + 1)
            ))
            .is_none()
        );
    }

    #[test]
    fn outgoing_message_matches_official_bot_shape() {
        let config = WeChatClawBotConfig::default();
        let body = SendMessageRequest {
            msg: OutgoingMessage {
                message_id: 1,
                to_user_id: "user-1",
                message_type: 2,
                message_state: 2,
                item_list: [OutgoingMessageItem {
                    item_type: 1,
                    text_item: OutgoingTextItem { text: "reply" },
                }],
                context_token: "ctx",
            },
            base_info: base_info(&config),
        };
        let value = serde_json::to_value(body).expect("encode");
        assert_eq!(value["msg"]["item_list"][0]["type"], 1);
        assert_eq!(value["msg"]["context_token"], "ctx");
        assert_eq!(value["base_info"]["bot_agent"], "MbedAgent/0.1.0");
    }
}
