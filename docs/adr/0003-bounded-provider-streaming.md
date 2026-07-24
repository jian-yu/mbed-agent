# ADR 0003: Bounded provider streaming

- Status: Accepted
- Date: 2026-07-24
- Supersedes: ADR 0002 decision 2 (non-streaming-only transport)

## Context

An embedded Agent needs incremental provider decoding so a long completion does
not require a second full response-body allocation. OpenAI-compatible Chat
Completions streams are Server-Sent Events, but TCP and HTTP chunk boundaries do
not align with SSE lines or JSON objects. A disconnected stream may also omit
its final usage block or completion marker.

## Decisions

1. Enable provider streaming by default and retain a configuration switch for
   compatible servers that only support non-streaming JSON.
2. Parse SSE with an incremental byte state machine that accepts LF or CRLF,
   comments, fragmented lines, and multi-line `data:` fields.
3. Apply separate hard limits to total wire bytes and one decoded SSE event.
   Never collect the complete wire response before parsing it.
4. Request the optional final usage chunk and accept its empty `choices` array.
5. Require `data: [DONE]`. Treat EOF before that marker as an interrupted
   upstream response rather than returning partial text as a successful answer.
6. Aggregate only choice index zero in this phase. Preserve the provider-neutral
   final completion DTO and local IPC response until incremental channel output
   is introduced.
7. Keep tool-call deltas out of this slice. Their IDs, names, and argument
   fragments require a separate accumulator and strict local schema validation
   before any typed tool can run.

## Consequences

The provider now has bounded incremental decoding and reliable interruption
detection without changing the CLI contract. First-token delivery to channels
is not implemented yet because the daemon currently aggregates deltas before
responding over its local Unix socket.
