# ADR 0066: Generic Linux runtime static-address profiles

## Status

Accepted and implemented.

## Context

Generic Linux cannot safely infer whether a kernel interface is owned by
NetworkManager, systemd-networkd, distribution scripts, or a vendor supervisor.
Writing a platform-native interface or address would therefore risk fighting a
second network manager and could break the approval channel. The existing
generic runtime transaction already provides bounded `ip -batch` staging,
confirmed commit, independent rollback, and boot-bound SQLite state for routes
and policy rules.

## Decision

Add a narrow Agent-owned runtime interface profile:

1. The typed identity must use the `agent_` prefix and must not reuse the
   platform-native interface identity. Its `device` must name an existing
   kernel link discovered by `ip -j link show`.
2. Only static IPv4/IPv6 address add, update, and delete operations are
   supported. The profile cannot set MTU, MAC, link state, DHCP, resolver,
   bridge/VLAN, or network-manager configuration.
3. The renderer emits only fixed `ip -batch` lines of the form
   `address add|del <cidr> dev <device>`. Updates delete removed addresses
   before adding new addresses; rollback reverses that exact diff.
4. Canonical state schema 2 stores the Agent-owned profile alongside protocol
   186 routes and reserved policy rules. It is boot-bound and stored only in
   bounded `/tmp` SQLite; a reboot intentionally drops the state.
5. Fresh inspection verifies the device and every Agent-owned address. Missing
   devices, missing addresses, duplicate profile claims, canonical drift, and
   unknown objects fail closed. Platform-native interface objects remain
   visible in inventory but cannot be mutated by this backend.
6. The normal R3/device-admin/one-use approval/rollback-helper/live-verify/
   confirmed-commit lifecycle is unchanged. No shell, caller-supplied argv,
   raw `ip` text, or persistent file write is introduced.

## Consequences

This gives ordinary Linux a useful, explicitly bounded address capability while
preserving the ownership boundary around existing interfaces and persistent
network managers. Operators who need DHCP, MTU, MAC, bridge/VLAN, or persistent
interface changes still need a future identified network-manager adapter; they
are not silently approximated by this runtime profile.
