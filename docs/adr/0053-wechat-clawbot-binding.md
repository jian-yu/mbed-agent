# ADR 0053: Official WeChat ClawBot QR binding

## Status

Accepted for the binding slice; message transport is deferred.

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

The daemon only reports `disabled`, `unconfigured`, or `bound` for this slice;
it does not claim `online` until a Rust long-poll adapter owns a live lifecycle
state. The token is never written to SQLite, passed as an argument, or emitted
to logs. The adapter will follow Tencent's official `getupdates` and
`sendmessage` contract in a later ADR, including volatile cursor and context
token handling.

Reference implementation: [Tencent openclaw-weixin](https://github.com/Tencent/openclaw-weixin).
