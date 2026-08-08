# ADR 0054: Bounded WeChat ClawBot long-poll text transport

## Status

Accepted for the text-only transport slice.

## Context

After QR binding, the daemon must reconnect directly to Tencent's official
WeChat ClawBot/iLink Bot API after every restart. Runtime cursors, deduplication,
context tokens, and message data must remain in memory or `/tmp` SQLite; no
runtime channel state may be written to Flash.

## Decision

The daemon starts one bounded Tokio task for each enabled account. It sends
`POST /ilink/bot/getupdates` with `get_updates_buf`, `base_info.channel_version`,
and the configured `bot_agent`. Requests carry the official bearer-token
headers, `iLink-App-Id=bot`, numeric client version, and a random base64
`X-WECHAT-UIN`. Response bodies are capped at 32 KiB; the cursor is kept in
memory and reset when the official session-expired code is returned.

Only new user text messages are converted to the existing provider-neutral
`ChannelRequest::Ask` path. A bounded `/tmp` SQLite claim keyed by account and
message id prevents duplicate dispatch during cursor replay. Replies are
rendered as bounded text and sent through `POST /ilink/bot/sendmessage` with
message type `BOT`, finish state, and the inbound `context_token`. HTTP 401/403
transitions the lifecycle to `needs_rebind`; transport errors use capped
exponential backoff. Media items, raw commands, ChangeSets, elevation, and
unbounded response payloads are rejected or deferred.

Reference behavior: [Tencent openclaw-weixin API implementation](https://github.com/Tencent/openclaw-weixin/blob/main/src/api/api.ts)
and [official protocol types](https://github.com/Tencent/openclaw-weixin/blob/main/src/api/types.ts).
