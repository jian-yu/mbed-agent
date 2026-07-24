# Mbed Agent

Mbed Agent is a resource-bounded network operations agent for OpenWrt 21.02+ and small embedded Linux systems. The current implementation is the Phase 0 runtime foundation described in [the architecture plan](docs/architecture-plan.zh-CN.md).

## Current scope

- One Rust executable: `mbed-agent daemon` runs the service, while the other
  subcommands act as its local CLI over a bounded Unix socket protocol.
- Strict configuration validation that keeps runtime state below `/tmp/mbed-agent`.
- A size-capped SQLite store intended only for volatile runtime state.
- A metadata-only `ask` task ledger with configurable retention. It records
  outcomes, provider/model, token usage, duration, and error code, but never
  prompts or model responses.
- Runtime discovery for OpenWrt version, fw3/iptables, fw4/nftables, swconfig/DSA, ubus/UCI/procd, and opkg/apk.
- First-class generic Linux discovery using iproute2, native nftables/iptables,
  systemd-resolved, NetworkManager, and `/etc/resolv.conf`, without attempting
  OpenWrt-only ubus/UCI probes.
- A deterministic `diagnose wan` runbook that gathers bounded, read-only ubus,
  interface, route, resolver, and firewall-backend evidence, normalizes it into
  one stable WAN model, including the UCI WAN firewall zone, and reports the
  first failed network prerequisite.
- OpenWrt procd and UCI configuration skeletons.
- A bounded OpenAI-compatible HTTPS provider, invoked through
  `mbed-agent ask`, with strict request/response limits, timeouts, disabled
  redirects, and redacted API-key configuration.
- A bounded read-only Agent loop with locally allowlisted `diagnose_wan`,
  `inspect_default_routes`, `inspect_dns`, and `inspect_wan_firewall` tools.
  Tool arguments are parsed and validated on-device, and the model can never
  request active probes or shell commands.

Provider routing, additional typed network tools, MQTT, WeCom, WeChat ClawBot,
administrator elevation, and configuration transactions are planned but are not
implemented yet.

The implemented and deferred Phase 0 decisions are recorded in
[ADR 0001](docs/adr/0001-runtime-foundation.md). This distinction is intentional:
the daemon foundation is usable now, while network-changing tools and remote
channels remain disabled until their permission and rollback boundaries exist.

## Build and test

The workspace is pinned to Rust 1.85.1.

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p mbed-agent
```

## Local smoke test

Use the example configuration so the daemon does not read `/etc`:

```sh
cargo run -p mbed-agent -- daemon --config config/mbed-agent.example.toml
cargo run -p mbed-agent -- status
cargo run -p mbed-agent -- capabilities
cargo run -p mbed-agent -- diagnose wan
cargo run -p mbed-agent -- diagnose wan --active
cargo run -p mbed-agent -- diagnose history --limit 20
cargo run -p mbed-agent -- task history --limit 20
```

To exercise an OpenAI-compatible endpoint, copy the example configuration,
enable `[llm]`, and set its HTTPS `base_url`, `api_key`, and `model`. Then restart
the daemon. A credential-bearing configuration must be mode `0600` (or stricter).
Then run:

```sh
cargo run -p mbed-agent -- ask "Explain the likely WAN fault from this symptom"
```

The daemon owns the provider credentials; the CLI never reads them. Provider
traffic uses bounded SSE streaming by default, although the current local IPC
returns one final completion to keep its protocol stable. Set `llm.streaming =
false` for compatible endpoints that only implement JSON responses. HTTP
redirects are disabled, and traffic is bounded by `llm.max_request_bytes`,
`llm.max_response_bytes`, `llm.max_stream_event_bytes`, the configured timeouts,
the whole-Agent `runtime.task_timeout_secs`, and the runtime concurrency limit.
Prompts and responses are not written to SQLite. `ask` task metadata is retained
only up to `storage.max_task_records` and is discarded with the rest of `/tmp`
state at reboot.
When the model requests WAN evidence, the daemon runs only the passive typed
diagnostic and sends the minimum normalized projection needed by the selected
tool. Multiple WAN tools in one `ask` reuse the same in-memory snapshot. Raw
probe output is excluded from model context; one bounded diagnostic summary is
retained in volatile SQLite for local audit history.

Diagnostic commands never invoke a shell. Their executable names and arguments
are compiled into a typed allowlist, and configuration limits each probe's time
and retained output as well as the number and total duration of diagnostic tasks.
Active mode is explicit and runs only after passive WAN prerequisites pass. It
uses a validated route gateway plus fixed public-IP and DNS canaries; an ICMP
failure is reported as a failed probe, not asserted to be the root cause.

Completed diagnostics store only the normalized summary in `/tmp` SQLite; raw
probe output is not persisted. History is bounded by configurable record-count
and per-record byte limits, and oldest entries are pruned transactionally.

All generated runtime state is placed below `/tmp/mbed-agent` and may be discarded at reboot.

## OpenWrt integration

The `openwrt/files` tree contains the initial procd service and UCI/config files.
It targets OpenWrt 21.02 and later and does not assume either fw3 or fw4; runtime
capability discovery selects the available firewall stack. A feed package
Makefile and per-architecture `.ipk`/`.apk` artifacts will be added only after
validation against real OpenWrt SDK images.

## Generic Linux integration

The `packaging/linux` tree contains service definitions for systemd, OpenRC, and
BusyBox init. Runtime discovery reports the active init system and common package
manager, but the agent never installs packages at runtime. The systemd unit
restricts writable paths to `/tmp/mbed-agent` and the explicit agent
configuration directory.
