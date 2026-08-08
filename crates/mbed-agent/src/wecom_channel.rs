use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_channels::{
    CHANNEL_MESSAGE_SCHEMA_VERSION, ChannelLifecycle, ChannelRequest, ChannelResponse,
    command_from_text, decode_request,
};
use agent_core::{WeComBotConfig, parse_wecom_ws_url};
use agent_store::{ChannelMessageClaim, Store};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::{info, warn};

const CHANNEL_NAME: &str = "wecom";
const MAX_REPLY_TEXT_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 128;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub(crate) struct WeComInbound {
    pub request: ChannelRequest,
    pub respond_to: oneshot::Sender<ChannelResponse>,
}

pub(crate) struct WeComRuntime {
    pub inbound: mpsc::Receiver<WeComInbound>,
    pub status: watch::Receiver<ChannelLifecycle>,
}

#[derive(Debug, Error)]
pub(crate) enum WeComChannelError {
    #[error("WeCom configuration is invalid")]
    InvalidConfig,
}

#[derive(Debug, Deserialize)]
struct Frame {
    #[serde(default)]
    cmd: Option<String>,
    #[serde(default)]
    headers: Headers,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    errcode: Option<i32>,
}

#[derive(Debug, Default, Deserialize)]
struct Headers {
    #[serde(default)]
    req_id: String,
}

#[derive(Debug, Deserialize)]
struct CallbackBody {
    #[serde(default)]
    msgid: Option<String>,
    #[serde(default)]
    chatid: Option<String>,
    #[serde(default)]
    from: Option<Sender>,
    #[serde(default)]
    msgtype: Option<String>,
    #[serde(default)]
    text: Option<TextBody>,
}

#[derive(Debug, Deserialize)]
struct Sender {
    #[serde(default)]
    userid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TextBody {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthFrame<'a> {
    cmd: &'static str,
    headers: OutHeaders<'a>,
    body: AuthBody<'a>,
}

#[derive(Debug, Serialize)]
struct AuthBody<'a> {
    bot_id: &'a str,
    secret: &'a str,
}

#[derive(Debug, Serialize)]
struct OutHeaders<'a> {
    req_id: &'a str,
}

#[derive(Debug, Serialize)]
struct PingFrame<'a> {
    cmd: &'static str,
    headers: OutHeaders<'a>,
}

#[derive(Debug, Serialize)]
struct ReplyFrame<'a> {
    cmd: &'static str,
    headers: OutHeaders<'a>,
    body: ReplyBody<'a>,
}

#[derive(Debug, Serialize)]
struct ReplyBody<'a> {
    msgtype: &'static str,
    stream: ReplyStream<'a>,
}

#[derive(Debug, Serialize)]
struct ReplyStream<'a> {
    id: String,
    finish: bool,
    content: &'a str,
}

struct Outbound {
    req_id: String,
    response: ChannelResponse,
}

pub(crate) fn start(
    config: WeComBotConfig,
    store: Arc<Store>,
    max_records: u32,
) -> Result<Option<WeComRuntime>, WeComChannelError> {
    if !config.enabled {
        return Ok(None);
    }
    if config.bot_id.is_empty()
        || config.secret.is_empty()
        || parse_wecom_ws_url(&config.ws_url).is_err()
    {
        return Err(WeComChannelError::InvalidConfig);
    }
    let (inbound_tx, inbound_rx) = mpsc::channel(usize::from(config.max_inflight));
    let (status_tx, status_rx) = watch::channel(ChannelLifecycle::Connecting);
    tokio::spawn(run(config, store, max_records, inbound_tx, status_tx));
    Ok(Some(WeComRuntime {
        inbound: inbound_rx,
        status: status_rx,
    }))
}

async fn run(
    config: WeComBotConfig,
    store: Arc<Store>,
    max_records: u32,
    inbound_tx: mpsc::Sender<WeComInbound>,
    status: watch::Sender<ChannelLifecycle>,
) {
    let mut backoff = config.reconnect_min_secs;
    let mut auth_failures = 0u8;
    loop {
        status.send_replace(ChannelLifecycle::Connecting);
        match connect_async(&config.ws_url).await {
            Ok((mut ws, _)) => {
                let auth_id = next_id("auth");
                if send_json(
                    &mut ws,
                    &AuthFrame {
                        cmd: "aibot_subscribe",
                        headers: OutHeaders { req_id: &auth_id },
                        body: AuthBody {
                            bot_id: &config.bot_id,
                            secret: config.secret.expose(),
                        },
                    },
                    config.max_frame_bytes,
                )
                .await
                .is_err()
                {
                    status.send_replace(ChannelLifecycle::Backoff);
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = backoff.saturating_mul(2).min(config.reconnect_max_secs);
                    continue;
                }
                match run_connection(
                    &config,
                    &store,
                    max_records,
                    &inbound_tx,
                    &mut ws,
                    &status,
                    &auth_id,
                )
                .await
                {
                    Ok(()) => {
                        auth_failures = 0;
                        backoff = config.reconnect_min_secs;
                    }
                    Err(ConnectionError::Auth) => {
                        auth_failures = auth_failures.saturating_add(1);
                        if auth_failures >= config.max_auth_failures {
                            status.send_replace(ChannelLifecycle::NeedsRebind);
                            warn!("WeCom authentication failed repeatedly; rebind is required");
                            break;
                        }
                    }
                    Err(ConnectionError::Closed { authenticated }) => {
                        if authenticated {
                            auth_failures = 0;
                            backoff = config.reconnect_min_secs;
                        }
                    }
                }
            }
            Err(error) => warn!(%error, "WeCom WSS connection failed"),
        }
        status.send_replace(ChannelLifecycle::Backoff);
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = backoff.saturating_mul(2).min(config.reconnect_max_secs);
    }
}

enum ConnectionError {
    Auth,
    Closed { authenticated: bool },
}

async fn run_connection(
    config: &WeComBotConfig,
    store: &Arc<Store>,
    max_records: u32,
    inbound_tx: &mpsc::Sender<WeComInbound>,
    ws: &mut Ws,
    status: &watch::Sender<ChannelLifecycle>,
    auth_id: &str,
) -> Result<(), ConnectionError> {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(config.heartbeat_secs));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut authenticated = false;
    let mut pending_heartbeats: HashMap<String, Instant> = HashMap::new();
    let mut pending_replies: HashMap<String, Instant> = HashMap::new();
    let (outbound_tx, rx) = mpsc::channel::<Outbound>(usize::from(config.max_inflight));
    let mut outbound_rx = rx;
    loop {
        tokio::select! {
            frame = ws.next() => {
                let Some(frame) = frame else { return Err(ConnectionError::Closed { authenticated }); };
                let Ok(frame) = frame else { return Err(ConnectionError::Closed { authenticated }) };
                match frame {
                    Message::Text(text) => {
                        if text.len() > config.max_frame_bytes { return Err(ConnectionError::Closed { authenticated }); }
                        let parsed: Frame = match serde_json::from_str(&text) { Ok(value) => value, Err(_) => continue };
                        if parsed.headers.req_id.starts_with(auth_id) {
                            if parsed.errcode.unwrap_or(0) != 0 { return Err(ConnectionError::Auth); }
                            authenticated = true;
                            status.send_replace(ChannelLifecycle::Online);
                            info!(account = %config.account, "WeCom smart-bot channel online");
                            continue;
                        }
                        if let Some(cmd) = parsed.cmd.as_deref() {
                            if cmd == "aibot_msg_callback" && authenticated {
                                handle_callback(config, store, max_records, inbound_tx, &outbound_tx, parsed).await;
                            }
                        } else if !parsed.headers.req_id.is_empty() {
                            pending_heartbeats.remove(&parsed.headers.req_id);
                            pending_replies.remove(&parsed.headers.req_id);
                        }
                    }
                    Message::Ping(payload) => { let _ = ws.send(Message::Pong(payload)).await; }
                    Message::Close(_) => return Err(ConnectionError::Closed { authenticated }),
                    _ => {}
                }
            }
            Some(outbound) = outbound_rx.recv(), if authenticated => {
                let content = render_response(&outbound.response);
                let frame = ReplyFrame { cmd: "aibot_respond_msg", headers: OutHeaders { req_id: &outbound.req_id }, body: ReplyBody { msgtype: "stream", stream: ReplyStream { id: next_id("stream"), finish: true, content: &content } } };
                if send_json(ws, &frame, config.max_frame_bytes).await.is_err() { return Err(ConnectionError::Closed { authenticated }); }
                pending_replies.insert(outbound.req_id, Instant::now());
            }
            _ = heartbeat.tick(), if authenticated => {
                let id = next_id("ping");
                if send_json(ws, &PingFrame { cmd: "ping", headers: OutHeaders { req_id: &id } }, config.max_frame_bytes).await.is_err() { return Err(ConnectionError::Closed { authenticated }); }
                pending_heartbeats.insert(id, Instant::now());
                if pending_heartbeats.values().any(|started| started.elapsed() > Duration::from_secs(config.heartbeat_secs.saturating_mul(2))) { return Err(ConnectionError::Closed { authenticated }); }
                pending_replies.retain(|req_id, started| {
                    let fresh = started.elapsed() <= Duration::from_secs(config.reply_ack_timeout_secs);
                    if !fresh { warn!(%req_id, "WeCom reply acknowledgement timed out"); }
                    fresh
                });
            }
        }
    }
}

async fn handle_callback(
    config: &WeComBotConfig,
    store: &Arc<Store>,
    max_records: u32,
    inbound_tx: &mpsc::Sender<WeComInbound>,
    outbound_tx: &mpsc::Sender<Outbound>,
    frame: Frame,
) {
    let Some(body) = frame.body else {
        return;
    };
    let Ok(body) = serde_json::from_value::<CallbackBody>(body) else {
        return;
    };
    if body.msgtype.as_deref() != Some("text") {
        return;
    }
    let Some(text) = body.text.and_then(|text| text.content) else {
        return;
    };
    if text.is_empty() || text.len() > MAX_REPLY_TEXT_BYTES {
        return;
    }
    let Some(user) = body.from.and_then(|sender| sender.userid) else {
        return;
    };
    let Some(msgid) = body.msgid.filter(|value| !value.is_empty()) else {
        return;
    };
    if frame.headers.req_id.len() > MAX_ID_BYTES
        || msgid.len() > MAX_ID_BYTES
        || user.len() > MAX_ID_BYTES
    {
        return;
    }
    let message_id = format!("{}:{msgid}", config.account);
    let now = unix_ms();
    let request = ChannelRequest {
        schema_version: CHANNEL_MESSAGE_SCHEMA_VERSION,
        message_id: message_id.clone(),
        actor_id: format!("wecom:{user}"),
        conversation_id: format!("wecom:{}", body.chatid.as_deref().unwrap_or(&user)),
        expires_unix_ms: now.saturating_add(9 * 60 * 1_000),
        command: command_from_text(text),
    };
    if decode_request(&serde_json::to_vec(&request).unwrap_or_default(), now).is_err() {
        return;
    }
    let expires = request.expires_unix_ms;
    let claim = tokio::task::spawn_blocking({
        let store = Arc::clone(store);
        let message_id = message_id.clone();
        move || store.claim_channel_message(CHANNEL_NAME, &message_id, expires, now, max_records)
    })
    .await;
    if !matches!(claim, Ok(Ok(ChannelMessageClaim::New))) {
        return;
    }
    let (respond_to, response_rx) = oneshot::channel();
    if inbound_tx
        .try_send(WeComInbound {
            request,
            respond_to,
        })
        .is_err()
    {
        let _ = outbound_tx.try_send(Outbound {
            req_id: frame.headers.req_id,
            response: ChannelResponse::error(
                message_id,
                "busy",
                "the device channel queue is full",
            ),
        });
        return;
    }
    let tx = outbound_tx.clone();
    let req_id = frame.headers.req_id;
    tokio::spawn(async move {
        let response = tokio::time::timeout(Duration::from_secs(130), response_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_else(|| ChannelResponse::error(message_id, "timeout", "request timed out"));
        let _ = tx.send(Outbound { req_id, response }).await;
    });
}

async fn send_json<T: Serialize>(ws: &mut Ws, value: &T, max_bytes: usize) -> Result<(), ()> {
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    if bytes.len() > max_bytes {
        return Err(());
    }
    ws.send(Message::Text(
        String::from_utf8(bytes).map_err(|_| ())?.into(),
    ))
    .await
    .map_err(|_| ())
}

fn render_response(response: &ChannelResponse) -> String {
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

fn next_id(prefix: &str) -> String {
    format!("{prefix}-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}
fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_frame_accepts_bounded_text_shape() {
        let frame: Frame = serde_json::from_str(
            r#"{"cmd":"aibot_msg_callback","headers":{"req_id":"req-1"},"body":{"msgid":"m-1","chatid":"c-1","from":{"userid":"u-1"},"msgtype":"text","text":{"content":"ping"}}}"#,
        )
        .expect("callback frame");
        assert_eq!(frame.cmd.as_deref(), Some("aibot_msg_callback"));
        let body: CallbackBody = serde_json::from_value(frame.body.expect("body")).expect("body");
        assert_eq!(body.msgid.as_deref(), Some("m-1"));
        assert_eq!(
            body.text.and_then(|text| text.content).as_deref(),
            Some("ping")
        );
    }

    #[test]
    fn response_truncation_preserves_utf8() {
        let mut value = "网".repeat(MAX_REPLY_TEXT_BYTES);
        truncate_text(&mut value, MAX_REPLY_TEXT_BYTES);
        assert!(value.is_char_boundary(value.len()));
        assert!(value.ends_with("[truncated]"));
    }
}
