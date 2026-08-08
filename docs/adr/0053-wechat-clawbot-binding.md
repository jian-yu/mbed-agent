# ADR 0053: Official WeChat ClawBot QR binding

## Status

Accepted for the binding slice.

## Context

The device must bind the official Tencent WeChat ClawBot/iLink Bot capability
without a project cloud relay. Binding is an intentional configuration write,
while cursors, sessions, retries, and message data must remain volatile under
`/tmp`.

## Decision

`mbed-agent channel bind-wechat-clawbot` calls the official QR endpoints directly,
prints the returned QR URL for the operator to scan, and polls the official QR
status endpoint with a one-second interval and a three-minute bound. On
confirmation it validates the HTTPS base URL and token size/control-character
limits, loads the existing TOML configuration, and atomically replaces it with
mode `0600`. Symlink and non-regular configuration targets are rejected.

The token is never written to SQLite, passed as an argument, or emitted to logs.
The daemon-side lifecycle and text transport are specified separately in
[ADR 0054](0054-wechat-clawbot-long-poll.md).

Reference implementation: [Tencent openclaw-weixin](https://github.com/Tencent/openclaw-weixin).
