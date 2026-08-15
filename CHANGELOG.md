# Changelog

## Unreleased — candidate for v0.2.0

This candidate keeps the package version at `0.1.0` until the external release gates
are complete. It is the engineering-delivery and reliability baseline for the next
version.

### Added

- Runtime capability reporting now distinguishes unsupported, read-only,
  runtime-writable, and confirmed-writable configuration domains.
- Bounded SQLite WAL maintenance, volatile-state cleanup, log rotation, artifact
  cleanup, binary footprint, RSS, and persistent-write-set checks are part of the
  release gates.
- OpenWrt 21.02–24.10 compatibility matrix with fw3/fw4 and Rust musl target
  validation.
- Reproducible official OpenWrt SDK package workflow with SDK checksum validation.
- OpenWrt 24.10 `.tar.zst` SDK support and a real-device-derived
  `bcm27xx/bcm2711` aarch64 matrix target.
- Pinned Zig 0.14.1/cargo-zigbuild 0.20.1 CI path for the bcm2711 aarch64 musl
  binary, plus a fail-closed SSH device read-only smoke runner.
- Bounded OpenWrt QEMU readiness smoke and release artifact preparation containing
  binary checksums, Cargo dependency graph, toolchain provenance, and manifest.
- Cargo, OpenWrt package, and configuration sample version consistency validation.

### Compatibility and safety

- OpenWrt 21.x remains fw3-compatible; OpenWrt 22.03 and newer remain fw4-based.
- Generic Linux and OpenWrt changes continue to use typed ChangeSets, fresh
  inventory, approval, confirmed activation, verification, and rollback.
- Runtime state remains volatile under `/tmp`; persistent writes remain limited to
  configuration and explicitly approved business configuration.

### Release gates still requiring external evidence

- At least one real SDK package build with a downloaded official SDK.
- OpenWrt fw3 and fw4 QEMU or device transactions.
- Linux nftables and iptables namespace/real-kernel transactions.
- Flash write-set snapshots on representative devices.
- 72-hour Channel reconnect, duplicate-message, and low-watermark soak.
