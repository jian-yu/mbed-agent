# ADR 0015: Bounded listener exposure diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

Unexpected TCP/UDP listeners are a common cause of service reachability and
device exposure problems. OpenWrt images may have BusyBox `netstat` but no
`ss`; general Linux commonly has `ss`. Process names and exact binding addresses
are not required for the first model-level exposure assessment and can disclose
unnecessary device details.

## Decisions

1. Add `mbed-agent diagnose listeners` for OpenWrt and generic Linux.
2. Prefer `ss -H -lntu`; if `ss` is absent, use `netstat -lntu`. Both commands
   are fixed allowlist entries, execute without a shell, request numeric
   TCP/UDP listeners only, and never request process/PID information.
3. Normalize protocol, address family, local address, numeric port, socket state,
   and wildcard/loopback/link-local/specific binding scope.
4. Retain at most 128 unique listeners. Reject malformed protocols, addresses,
   ports, oversized endpoints, and control characters. Report output or
   cardinality truncation.
5. Add `inspect_listening_ports` and `inspect_exposed_services`, backed by one
   cached snapshot. The latter excludes loopback bindings.
6. Omit exact local addresses from both LLM projections. Preserve them in the
   immediate local CLI response and bounded volatile SQLite summary.
7. Shrink the sanitized listener list to `llm.max_tool_context_bytes` and set
   `context_truncated`.
8. Add `ss` and `netstat` to platform capability discovery without making
   either mandatory for daemon startup.

## Consequences

The Agent can identify wildcard or non-loopback service exposure on both full
Linux and small OpenWrt images without collecting process identities. Binding
scope does not prove firewall reachability or application health, so the report
must not claim that a port is externally reachable merely because it listens
outside loopback.
