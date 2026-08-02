# ADR 0052: MQTT 5 read-only channel

- Status: Accepted
- Date: 2026-08-02

## Context

The daemon needs a low-overhead cloud channel that reconnects automatically and
does not turn broker messages into a remote root API. MQTT delivery is at least
once, so duplicate execution and unbounded offline buffering must be handled on
the device. Channel runtime state must remain volatile under `/tmp`.

## Decisions

1. Add a small `agent-channels` crate containing the provider-neutral lifecycle,
   closed request/response envelope, diagnostic target enum, hard message/text
   limits, expiration validation, and fixed MQTT topic construction.
2. Use `rumqttc` MQTT 5 with its bounded asynchronous request channel. Production
   configuration accepts only `mqtts://host:port`, uses TLS system trust roots,
   persistent sessions, QoS 1 request/response delivery, bounded packet size,
   bounded inflight count, keepalive, and capped exponential reconnect backoff.
3. Subscribe only to `mbed-agent/v1/devices/{device_id}/requests` and publish to
   `mbed-agent/v1/devices/{device_id}/responses/{message_id}`. Device and message
   identifiers cannot inject `/`, `+`, or `#` topic syntax.
4. The first public command set is intentionally read-only: ping, status,
   bounded diagnostics, and `ask`. There is no channel representation for
   Action execution, ChangeSet planning/apply/confirm, elevation, shell, argv,
   paths, or raw local protocol forwarding.
5. Atomically claim `(channel, message_id)` in the `/tmp` SQLite store before
   dispatch. A duplicate pending message is ignored and a completed duplicate
   reuses the exact bounded cached response. The response outbox has configurable
   record/payload limits, expiration, retry timestamps, and a fixed retry-count
   ceiling. No channel payload is written to Flash.
6. Start every enabled MQTT adapter with the daemon, keep local CLI available
   during broker failure, and expose `mbed-agent channel status`. Broker
   disconnects enter capped backoff and reconnect without daemon restart.
7. Username/password authentication is optional but paired. When present, the
   main configuration must be root-only. Mutual TLS identity and certificate
   rotation remain a subsequent slice; enabling MQTT without credentials assumes
   the broker authenticates the device by another deployment-controlled means.
8. Channel actor and conversation identifiers are retained in the normalized
   envelope, but this slice does not grant them authorization. Writable channel
   commands stay closed until actor identity is bound through the full
   device-admin and ChangeSet lifecycle.

## Consequences

The agent now has an actual reconnecting MQTT 5 channel suitable for remote
read-only operations and LLM requests. At-least-once duplicates are bounded and
do not repeat task execution. Remote configuration remains unavailable rather
than inheriting the local CLI actor implicitly.
