# ADR 0001: Phase 0 runtime foundation

- Status: Accepted
- Date: 2026-07-19

## Context

Mbed Agent must run on OpenWrt 21.02+ and similarly constrained embedded Linux
systems. Runtime writes other than explicit configuration changes must not reach
Flash. The process also needs deterministic memory, request, database, and log
limits before LLM providers or remote channels are enabled.

## Decisions

1. Ship one `mbed-agent` executable. The `daemon` subcommand runs the long-lived
   service; local control operations such as `status` and `capabilities` use the
   same executable as Unix socket clients. Use one current-thread Tokio runtime.
   Blocking platform work will later run
   through a small, explicitly bounded worker pool rather than an unbounded task
   executor.
2. Keep the local control protocol versioned, newline-delimited JSON over a Unix
   socket. Every input frame has a configured byte limit.
3. Place the socket, SQLite database, WAL/SHM files, logs, artifacts, and rollback
   data below `/tmp/mbed-agent`. Configuration validation rejects runtime paths
   outside that directory.
4. Use SQLite as the only embedded database. Set a database page limit and also
   account for all managed files against a stricter total `/tmp` budget.
5. Rotate logs inside a fixed file count and total-byte budget. Log level, format,
   per-file size, line size, and rate-limit settings are configuration values.
6. Discover OpenWrt capabilities at runtime. OpenWrt 21.02/fw3/iptables and newer
   fw4/nftables systems are separate backends behind a future common firewall
   interface; the presence of one compatibility command must not be treated as
   proof of the active firewall backend.
7. Install under procd with a conservative file-descriptor limit and automatic
   restart. Runtime directories are recreated in tmpfs on every daemon start.
8. Compile release binaries for size (`opt-level = "z"`, LTO, one codegen unit,
   abort-on-panic, stripped symbols) and deny unsafe Rust in workspace crates.

## Explicitly deferred

- Typed read-only network tools and fw3/fw4 normalized inspection.
- UCI transaction, validation, confirmed-commit, and rollback execution.
- LLM provider adapters and prompt/tool orchestration.
- MQTT, WeCom, and WeChat ClawBot channel adapters and reconnect supervisors.
- Channel-independent administrator-password elevation.
- OpenWrt SDK feed Makefiles and target-architecture package artifacts.

These features must not be exposed as generic shell execution while their typed
schemas, authorization checks, and resource budgets are incomplete.

## Consequences

The current daemon is intentionally small and useful primarily as a verified
runtime substrate. It already reports platform and storage health, but cannot
modify device networking or open a remote control channel. Subsequent vertical
slices can add those capabilities without changing the storage and IPC safety
boundary.
