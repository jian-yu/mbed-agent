# Mbed Agent

Mbed Agent is a resource-bounded network operations agent for OpenWrt 21.02+ and small embedded Linux systems. The current implementation is the Phase 0 runtime foundation described in [the architecture plan](docs/architecture-plan.zh-CN.md).

## Current scope

- One Rust executable: `mbed-agent daemon` runs the service, while the other
  subcommands act as its local CLI over a bounded Unix socket protocol.
- Strict configuration validation that keeps runtime state below `/tmp/mbed-agent`.
- A size-capped SQLite store intended only for volatile runtime state.
- Runtime discovery for OpenWrt version, fw3/iptables, fw4/nftables, swconfig/DSA, ubus/UCI/procd, and opkg/apk.
- A deterministic `diagnose wan` runbook that gathers bounded, read-only ubus,
  interface, route, resolver, and firewall-backend evidence, normalizes it into
  one stable WAN model, and reports the first failed network prerequisite.
- OpenWrt procd and UCI configuration skeletons.

LLM providers, typed network tools, MQTT, WeCom, WeChat ClawBot, administrator elevation, and configuration transactions are planned but are not implemented yet.

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
```

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
