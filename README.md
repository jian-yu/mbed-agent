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
- Runtime `/tmp` pressure admission and a bounded artifact cleaner. Critical
  pressure blocks new diagnostic/LLM tasks while status and history remain
  available.
- Runtime discovery for OpenWrt version, fw3/iptables, fw4/nftables, swconfig/DSA, ubus/UCI/procd, and opkg/apk.
- First-class generic Linux discovery using iproute2, native nftables/iptables,
  systemd-resolved, NetworkManager, and `/etc/resolv.conf`, without attempting
  OpenWrt-only ubus/UCI probes.
- Deterministic `diagnose wan`, `diagnose dns`, `diagnose dhcp`,
  `diagnose routes`, `diagnose interfaces`, and `diagnose neighbors` runbooks.
  The additional `diagnose firewall` runbook normalizes runtime fw3/fw4,
  iptables, and nftables counts; `diagnose policy-routing` normalizes policy
  selectors and aggregate route tables; `diagnose listeners` classifies bounded
  TCP/UDP binding exposure; `diagnose wireless` normalizes radio and interface
  state without scanning; `diagnose interface-stats` captures one bounded
  snapshot of cumulative kernel counters. All gather bounded, read-only evidence
  across OpenWrt and generic Linux. Focused runs execute only their required
  collectors; the WAN run also includes firewall-backend and UCI zone evidence.
- OpenWrt procd and UCI configuration skeletons.
- A bounded OpenAI-compatible HTTPS provider, invoked through
  `mbed-agent ask`, with strict request/response limits, timeouts, disabled
  redirects, and redacted API-key configuration.
- A bounded read-only Agent loop with locally allowlisted `diagnose_wan`,
  `inspect_default_routes`, `inspect_dns`, `inspect_dhcp`,
  `inspect_wan_firewall`, `inspect_interfaces`, and `inspect_neighbors` tools.
  Runtime firewall totals and base-chain policies are exposed through two more
  expression-free tools. Policy rules and aggregate route tables have separate
  bounded views backed by one snapshot. Listening ports and non-loopback
  exposure have address-free views; wireless tools omit SSID values and AP
  addresses. Interface counters and nonzero error/drop counters have separate
  views backed by one snapshot. Tool arguments are parsed and validated
  on-device, and the model can never request active probes or shell commands.

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
cargo run -p mbed-agent -- diagnose dns
cargo run -p mbed-agent -- diagnose dhcp
cargo run -p mbed-agent -- diagnose routes
cargo run -p mbed-agent -- diagnose interfaces
cargo run -p mbed-agent -- diagnose neighbors
cargo run -p mbed-agent -- diagnose firewall
cargo run -p mbed-agent -- diagnose policy-routing
cargo run -p mbed-agent -- diagnose listeners
cargo run -p mbed-agent -- diagnose wireless
cargo run -p mbed-agent -- diagnose interface-stats
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
The focused DNS and route commands are passive: `diagnose dns` reports resolver
configuration and its link/address/route prerequisites but does not claim that
an external DNS query succeeded.
`diagnose dhcp` never renews a lease. OpenWrt uses normalized ubus protocol and
pending state; generic Linux reports DHCP only when `ip -j` marks an address as
dynamic, otherwise it returns insufficient evidence instead of guessing.
`diagnose interfaces` uses only bounded kernel link/address collectors on both
OpenWrt and generic Linux. It retains at most 32 interfaces and eight validated
IP addresses per interface, reports inventory truncation explicitly, and does
not run route, DNS, firewall, or active-connectivity probes.
`diagnose neighbors` passively reads the kernel ARP/NDP cache, retains at most
64 validated entries, and distinguishes incomplete/failed resolution without
claiming a root cause. Link-layer addresses remain available to the local CLI
but are removed before an observation is sent to an LLM.
`diagnose firewall` selects nftables for fw4/native nft systems and
iptables-save/ip6tables-save for fw3/native iptables systems. It normalizes only
bounded table, chain, rule, counter, hook, and policy metadata. Raw rule
expressions remain local evidence and are never persisted or sent to an LLM.
`diagnose policy-routing` normalizes at most 64 `ip rule` entries and aggregates
at most 32 route tables. It recognizes conventional local/main/default rules,
validated CIDR selectors, marks and interface selectors, while individual
non-default route details remain outside model context and SQLite.
`diagnose listeners` prefers `ss` and falls back to BusyBox/full `netstat`.
It retains at most 128 TCP/UDP listeners without requesting process identities,
classifies wildcard/loopback/link-local/specific bindings, and omits exact local
addresses from every LLM observation.
`diagnose wireless` uses OpenWrt ubus status plus passive `iw dev` or `iwinfo`
fallback evidence. It retains at most 16 radios and 32 interfaces, never scans
or changes association state, and replaces local SSID values with a boolean
presence marker before sending observations to an LLM.
`diagnose interface-stats` runs one bounded `ip -j -s link show` collector on
OpenWrt and generic Linux. It accepts `stats64` and legacy `stats`, retains at
most 32 interfaces, and reports cumulative RX/TX bytes, packets, errors, and
drops. A single snapshot cannot establish a current traffic, loss, or error
rate, so the diagnostic never makes rate claims.

Completed diagnostics store only the normalized summary in `/tmp` SQLite; raw
probe output is not persisted. History is bounded by configurable record-count
and per-record byte limits, and oldest entries are pruned transactionally.

At startup and every `storage.cleanup_interval_secs`, the daemon prunes only
direct regular-file children of its managed `artifacts/` directory to
`storage.max_artifacts_bytes` and `storage.max_artifact_files`. It ignores
symlinks, subdirectories, and non-regular files, and never cleans rollback
state, SQLite, logs, sockets, or
configuration. Before starting a diagnostic or LLM task, the daemon checks both
managed usage and filesystem free-space reserves. Critical or emergency
pressure triggers one cleanup attempt and then rejects the new task if pressure
remains; `ping`, `status`, capabilities, and history queries remain usable.

Logging is bounded by level/filter, line bytes, file bytes, rotated file count,
total bytes, and `logging.rate_limit_per_target_per_sec`. The rate limiter keeps
at most 64 target counters and uses one shared overflow bucket. Dropped records
never allocate a line buffer or write a recursive warning; their cumulative
count is exposed as `logging_dropped_records` in `mbed-agent status`. Log files
are created as mode `0600` with `O_NOFOLLOW`, and non-regular paths are rejected.

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
