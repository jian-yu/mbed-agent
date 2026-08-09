# ADR 0069: OpenWrt feed package consumes a target binary

- Status: Accepted
- Date: 2026-08-09

## Context

OpenWrt 21.02 and later support many libc/target combinations. Building Rust
inside an arbitrary vendor SDK is not reproducible enough for the device and
would add a large toolchain footprint. The release pipeline already knows the
target tuple and can produce a stripped Rust binary with the pinned toolchain.

## Decisions

1. Ship an OpenWrt feed package Makefile under `openwrt/`. Its `Build/Compile`
   step requires `MBED_AGENT_BINARY` to point to a regular target-architecture
   binary; it never downloads sources, runs cargo, or compiles on the router.
2. Install the binary as `/usr/sbin/mbed-agent`, the procd service as
   `/etc/init.d/mbed-agent`, the UCI enable/config file as
   `/etc/config/mbed-agent`, and the TOML configuration under
   `/etc/mbed-agent/config.toml`.
3. Mark both configuration files as OpenWrt conffiles. Package upgrades do not
   overwrite administrator settings or channel credentials. Runtime SQLite,
   logs, rollback artifacts, and channel cursors remain under `/tmp` according
   to the existing configuration limits.
4. Depend only on the device CA bundle. Optional firewall, iproute2, wireless,
   and channel capabilities continue to be discovered at runtime; the package
   does not install packages or modify firewall/network state.

## Consequences

The same release artifact can be packaged for OpenWrt 21.02 fw3 and newer fw4
targets after target-specific cross compilation. SDK and architecture checks
remain release-pipeline responsibilities, while the router receives a small,
deterministic package with the existing procd lifecycle and no build-time
network access.
