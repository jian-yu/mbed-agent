# Device integration evidence

This file records sanitized device evidence used by release gates. It must not contain
LAN addresses, credentials, tokens, SSIDs, public addresses, or customer identifiers.

## 2026-08-15 — OpenWrt 24.10.8 fw4 discovery

- Hardware: Raspberry Pi 4 Model B Rev 1.2.
- Kernel: Linux 6.6.144, aarch64.
- OpenWrt: 24.10.8, revision `r29233-443ec4032a`.
- Target: `bcm27xx/bcm2711`; package architecture `aarch64_cortex-a72`.
- Root filesystem: squashfs; musl loader `/lib/ld-musl-aarch64.so.1`.
- Volatile storage: `/tmp` tmpfs had approximately 1.9 GiB available at discovery.
- Firewall: `fw4 check` passed and the active nftables table was `inet fw4`.
- Agent state: `mbed-agent` was not installed.
- Persistent write check: aggregate SHA-256 snapshots of all regular files below
  `/etc/config` were identical before and after `fw4 check`, board discovery, and
  nftables table discovery.

Only read-only discovery and native firewall validation were executed. No package was
installed and no UCI, firewall, network, DHCP, persistent filesystem, or service state
was changed. Package installation, confirmed ChangeSet execution, rollback, and Flash
write-set evidence remain pending until an aarch64 OpenWrt package is available.
