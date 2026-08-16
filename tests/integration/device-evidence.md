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

### Volatile runtime smoke

- Binary: statically linked, stripped aarch64 musl ELF; 6,537,408 bytes; SHA-256
  `f1816e8a87c3fe2131655d71c1a14aa89093c110bd8d520c7d0b8ad811431063`.
- `mbed-agent --version`, daemon startup, CLI ping, status, and capabilities passed.
- Runtime discovery reported OpenWrt 24.10.8, fw4/nftables, procd, opkg, DSA, UCI,
  ubus, and confirmed-writable firewall/network capability.
- SQLite and WAL were created only below `/tmp/mbed-agent`; storage pressure was
  normal and no degraded reason was reported.
- Aggregate `/etc/config` SHA-256 snapshots were identical before and after the
  daemon smoke.
- The daemon process, binary, configuration copy, logs, SQLite files, socket, and
  both test directories were removed after the test; cleanup was verified over SSH.
- All 13 passive diagnostic commands passed: WAN, DNS, DHCP, routes, interfaces,
  neighbors, firewall, policy routing, listeners, wireless, interface statistics,
  conntrack, and qdisc. Response sizes ranged from 611 to 19,476 bytes.
- Typed firewall and network inventory both passed; their response sizes were 6,995
  and 1,621 bytes respectively. Response bodies remained in the volatile device test
  directory and were not copied into release evidence.

The same target also passed the real-device firewall confirmed-commit smoke: the
Agent-owned typed rule reached `awaiting_confirmation`, the independent helper rolled it
back after the bounded deadline, the `rolled_back` ChangeSet state was observed, and the
aggregate `/etc/config` SHA-256 returned to its pre-test value. No package was installed;
package installation and approved Flash write-set evidence remain pending.

## 2026-08-16 — OpenWrt 21.02.0 fw3 transactions

- Hardware: Raspberry Pi 4 Model B, `bcm2711`.
- Kernel: Linux 5.4.143, aarch64.
- OpenWrt: 21.02.0, revision `r16279-5cc0535800`.
- Firewall: native `fw3 -q print` validation passed.
- Firewall transaction: a typed Agent-owned rule passed device-admin elevation, R3
  approval, apply/reload, bounded timeout rollback, and `rolled_back` audit state.
- Network transaction: a disabled Agent-owned route passed UCI staging, netifd reload,
  bounded timeout rollback, ChangeSet state synchronization, and exact aggregate
  `/etc/config` SHA-256 restoration.
- The daemon, SQLite/WAL, socket, logs, test binary, configuration copy, and test roots
  were removed from `/tmp` after both transactions. No package was installed.
