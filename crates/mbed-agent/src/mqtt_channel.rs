use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_channels::{
    ChannelRequest, ChannelResponse, decode_request, encode_response, mqtt_request_topic,
    mqtt_response_topic,
};
use agent_core::{MqttChannelConfig, parse_mqtts_broker};
use agent_store::{ChannelMessageClaim, PendingChannelResponse, Store};
use rumqttc::Transport;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, Event, Incoming, MqttOptions};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

const CHANNEL_NAME: &str = "mqtt";
const RESPONSE_RETRY_SECS: i64 = 30;

pub(crate) struct MqttInbound {
    pub request: ChannelRequest,
    pub respond_to: oneshot::Sender<ChannelResponse>,
}

pub(crate) struct MqttRuntime {
    pub inbound: mpsc::Receiver<MqttInbound>,
    pub status: watch::Receiver<agent_channels::ChannelLifecycle>,
}

#[derive(Debug, Error)]
pub(crate) enum MqttChannelError {
    #[error("MQTT configuration is invalid")]
    InvalidConfig,
    #[error("MQTT TLS material is unavailable")]
    TlsMaterial,
}

pub(crate) fn start(
    config: MqttChannelConfig,
    store: Arc<Store>,
    max_records: u32,
    max_payload_bytes: usize,
) -> Result<Option<MqttRuntime>, MqttChannelError> {
    if !config.enabled {
        return Ok(None);
    }
    let (host, port) =
        parse_mqtts_broker(&config.broker).map_err(|_| MqttChannelError::InvalidConfig)?;
    let request_topic =
        mqtt_request_topic(&config.device_id).map_err(|_| MqttChannelError::InvalidConfig)?;
    let mut options = MqttOptions::new(&config.client_id, host, port);
    let transport = mqtt_transport(&config)?;
    options
        .set_keep_alive(Duration::from_secs(config.keep_alive_secs))
        .set_clean_start(false)
        .set_receive_maximum(Some(config.max_inflight))
        .set_outgoing_inflight_upper_limit(config.max_inflight)
        .set_max_packet_size(Some(
            u32::try_from(config.max_packet_bytes).map_err(|_| MqttChannelError::InvalidConfig)?,
        ))
        .set_transport(transport);
    if !config.username.is_empty() {
        options.set_credentials(&config.username, config.password.expose());
    }
    let capacity = usize::from(config.max_inflight);
    let (client, eventloop) = AsyncClient::new(options, capacity);
    let (inbound_tx, inbound_rx) = mpsc::channel(capacity);
    let (status_tx, status_rx) = watch::channel(agent_channels::ChannelLifecycle::Connecting);
    tokio::spawn(run(
        config,
        store,
        client,
        eventloop,
        request_topic,
        inbound_tx,
        max_records,
        max_payload_bytes,
        status_tx,
    ));
    Ok(Some(MqttRuntime {
        inbound: inbound_rx,
        status: status_rx,
    }))
}

const MAX_TLS_FILE_BYTES: u64 = 512 * 1024;

fn mqtt_transport(config: &MqttChannelConfig) -> Result<Transport, MqttChannelError> {
    let Some(ca_path) = config.ca_cert_path.as_deref() else {
        if config.client_cert_path.is_some() || config.client_key_path.is_some() {
            return Err(MqttChannelError::InvalidConfig);
        }
        return Ok(Transport::tls_with_default_config());
    };
    let ca = read_tls_file(ca_path)?;
    let client_auth = match (
        config.client_cert_path.as_deref(),
        config.client_key_path.as_deref(),
    ) {
        (Some(cert), Some(key)) => Some((read_tls_file(cert)?, read_tls_file(key)?)),
        (None, None) => None,
        _ => return Err(MqttChannelError::InvalidConfig),
    };
    Ok(Transport::tls(ca, client_auth, None))
}

fn read_tls_file(path: &Path) -> Result<Vec<u8>, MqttChannelError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| MqttChannelError::TlsMaterial)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_TLS_FILE_BYTES
    {
        return Err(MqttChannelError::TlsMaterial);
    }
    fs::read(path).map_err(|_| MqttChannelError::TlsMaterial)
}

#[allow(clippy::too_many_arguments)]
async fn run(
    config: MqttChannelConfig,
    store: Arc<Store>,
    client: AsyncClient,
    mut eventloop: rumqttc::v5::EventLoop,
    request_topic: String,
    inbound_tx: mpsc::Sender<MqttInbound>,
    max_records: u32,
    max_payload_bytes: usize,
    status: watch::Sender<agent_channels::ChannelLifecycle>,
) {
    let mut retry = tokio::time::interval(Duration::from_secs(RESPONSE_RETRY_SECS as u64));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut backoff_secs = config.reconnect_min_secs;
    loop {
        tokio::select! {
            event = eventloop.poll() => match event {
                Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                    status.send_replace(agent_channels::ChannelLifecycle::Online);
                    backoff_secs = config.reconnect_min_secs;
                    if let Err(error) = client.subscribe(&request_topic, QoS::AtLeastOnce).await {
                        warn!(%error, "MQTT request subscription could not be queued");
                    } else {
                        info!(device_id = %config.device_id, "MQTT channel online");
                    }
                }
                Ok(Event::Incoming(Incoming::Publish(publish)))
                    if publish.topic == request_topic =>
                {
                    handle_publish(
                        &config,
                        Arc::clone(&store),
                        client.clone(),
                        &inbound_tx,
                        &publish.payload,
                        max_records,
                        max_payload_bytes,
                    )
                    .await;
                }
                Ok(_) => {}
                Err(error) => {
                    status.send_replace(agent_channels::ChannelLifecycle::Backoff);
                    warn!(%error, backoff_secs, "MQTT channel offline; reconnecting");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = backoff_secs
                        .saturating_mul(2)
                        .min(config.reconnect_max_secs);
                }
            },
            _ = retry.tick() => {
                retry_pending(
                    Arc::clone(&store),
                    &client,
                    max_payload_bytes,
                    usize::from(config.max_inflight),
                ).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_publish(
    config: &MqttChannelConfig,
    store: Arc<Store>,
    client: AsyncClient,
    inbound_tx: &mpsc::Sender<MqttInbound>,
    payload: &[u8],
    max_records: u32,
    max_payload_bytes: usize,
) {
    let now = unix_ms();
    let request = match decode_request(payload, now) {
        Ok(request) => request,
        Err(error) => {
            warn!(%error, "MQTT request rejected before dispatch");
            return;
        }
    };
    let message_id = request.message_id.clone();
    let response_topic = match mqtt_response_topic(&config.device_id, &message_id) {
        Ok(topic) => topic,
        Err(error) => {
            warn!(%error, "MQTT response topic rejected");
            return;
        }
    };
    let store_for_claim = Arc::clone(&store);
    let claim_id = message_id.clone();
    let expires = request.expires_unix_ms;
    let claim = tokio::task::spawn_blocking(move || {
        store_for_claim.claim_channel_message(CHANNEL_NAME, &claim_id, expires, now, max_records)
    })
    .await;
    match claim {
        Ok(Ok(ChannelMessageClaim::New)) => {}
        Ok(Ok(ChannelMessageClaim::Completed {
            response_topic,
            response_payload,
        })) => {
            publish_response(
                &store,
                &client,
                &message_id,
                &response_topic,
                response_payload,
            )
            .await;
            return;
        }
        Ok(Ok(ChannelMessageClaim::Pending)) => return,
        Ok(Err(error)) => {
            warn!(%error, "MQTT request deduplication failed closed");
            return;
        }
        Err(error) => {
            warn!(%error, "MQTT request deduplication worker failed");
            return;
        }
    }

    let (respond_to, response_rx) = oneshot::channel();
    if inbound_tx
        .try_send(MqttInbound {
            request,
            respond_to,
        })
        .is_err()
    {
        let response = ChannelResponse::error(
            message_id.clone(),
            "busy",
            "the device channel queue is full",
        );
        store_and_publish(
            store,
            client,
            message_id,
            response_topic,
            response,
            max_payload_bytes,
        )
        .await;
        return;
    }
    tokio::spawn(async move {
        let response = match tokio::time::timeout(Duration::from_secs(130), response_rx).await {
            Ok(Ok(response)) => response,
            _ => ChannelResponse::error(
                message_id.clone(),
                "timeout",
                "the device did not complete the channel request",
            ),
        };
        store_and_publish(
            store,
            client,
            message_id,
            response_topic,
            response,
            max_payload_bytes,
        )
        .await;
    });
}

async fn store_and_publish(
    store: Arc<Store>,
    client: AsyncClient,
    message_id: String,
    response_topic: String,
    mut response: ChannelResponse,
    max_payload_bytes: usize,
) {
    let mut payload = encode_response(&response);
    if payload.is_err() {
        response = ChannelResponse::error(
            message_id.clone(),
            "response_too_large",
            "the device response exceeded the channel limit",
        );
        payload = encode_response(&response);
    }
    let Ok(payload) = payload else {
        warn!(%message_id, "MQTT response encoding failed closed");
        return;
    };
    let store_for_complete = Arc::clone(&store);
    let complete_id = message_id.clone();
    let complete_topic = response_topic.clone();
    let complete_payload = payload.clone();
    let now = unix_ms();
    let completed = tokio::task::spawn_blocking(move || {
        store_for_complete.complete_channel_message(
            CHANNEL_NAME,
            &complete_id,
            &complete_topic,
            &complete_payload,
            max_payload_bytes,
            now,
        )
    })
    .await;
    if !matches!(completed, Ok(Ok(()))) {
        warn!(%message_id, "MQTT response could not enter the bounded outbox");
        return;
    }
    publish_response(&store, &client, &message_id, &response_topic, payload).await;
}

async fn publish_response(
    store: &Arc<Store>,
    client: &AsyncClient,
    message_id: &str,
    response_topic: &str,
    payload: Vec<u8>,
) {
    if let Err(error) = client
        .publish(response_topic, QoS::AtLeastOnce, false, payload)
        .await
    {
        warn!(%error, %message_id, "MQTT response publication could not be queued");
        return;
    }
    record_attempt(Arc::clone(store), message_id.to_owned()).await;
}

async fn retry_pending(
    store: Arc<Store>,
    client: &AsyncClient,
    max_payload_bytes: usize,
    limit: usize,
) {
    let now = unix_ms();
    let store_for_query = Arc::clone(&store);
    let limit = u16::try_from(limit).unwrap_or(u16::MAX);
    let pending = tokio::task::spawn_blocking(move || {
        store_for_query.pending_channel_responses(CHANNEL_NAME, now, limit, max_payload_bytes)
    })
    .await;
    let Ok(Ok(records)) = pending else {
        warn!("MQTT outbox retry query failed");
        return;
    };
    for record in records {
        retry_one(&store, client, record).await;
    }
}

async fn retry_one(store: &Arc<Store>, client: &AsyncClient, record: PendingChannelResponse) {
    if let Err(error) = client
        .publish(
            &record.response_topic,
            QoS::AtLeastOnce,
            false,
            record.response_payload,
        )
        .await
    {
        warn!(%error, message_id = %record.message_id, "MQTT outbox retry could not be queued");
        return;
    }
    record_attempt(Arc::clone(store), record.message_id).await;
}

async fn record_attempt(store: Arc<Store>, message_id: String) {
    let next = unix_ms().saturating_add(RESPONSE_RETRY_SECS * 1_000);
    let result = tokio::task::spawn_blocking(move || {
        store.record_channel_response_attempt(CHANNEL_NAME, &message_id, next)
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        warn!("MQTT outbox attempt metadata could not be updated");
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}
