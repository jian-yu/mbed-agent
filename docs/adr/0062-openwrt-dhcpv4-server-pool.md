# ADR 0062: OpenWrt DHCPv4 server pool subset

- Status: Implemented
- Date: 2026-08-09
- Scope: OpenWrt 21.02+ `network`/`dhcp` UCI packages

## Context

The DHCP server section lives in `/etc/config/dhcp`, while the serving
interface and its address live in `/etc/config/network`. Treating either file
as an isolated text edit could leave a pool attached to the wrong subnet or
leave a network change without its DHCP rollback. The existing typed network
ChangeSet already has the required digest, approval, staging, verification and
confirmed-commit lifecycle.

## Decision

`NetworkInterfaceConfig` optionally carries a bounded IPv4
`NetworkDhcpServerConfig`:

- `enabled` maps to `ignore`;
- `start` and `limit` describe the dnsmasq host-offset pool;
- `lease_time` accepts bounded durations such as `12h`, `1d`, or `infinite`;
- `force` maps to the dnsmasq `force` option.

The OpenWrt adapter reads `uci show network` and `uci show dhcp` together,
joins `dhcp.<section>.interface` to the typed interface, and records both the
network section and DHCP section binding. Unsupported DHCP options are preserved
on native sections; malformed or unrepresentable Agent-owned sections fail
closed. Creating an Agent-owned interface with a server creates a matching
Agent-owned DHCP section; updates rewrite only the bounded supported options.
Removing a native DHCP server is rejected instead of silently deleting vendor
configuration.

Staging copies both packages below `/tmp`, applies one fixed UCI batch with
separate `commit network` and `commit dhcp`, and validates both exports. The
native transaction compares both live UCI snapshots and both root-owned source
files before atomic installation, reloads network once, verifies the joined
typed state, and arms rollback targets for both `/etc/config/network` and
`/etc/config/dhcp`. Generic Linux remains read-only because its DHCP owner is
not known.

This slice intentionally excludes static leases, arbitrary `dhcp_option` text,
DHCPv6/RA mode, dnsmasq global tuning, and secret-bearing options. Those require
their own typed schema and cross-subnet validation.
