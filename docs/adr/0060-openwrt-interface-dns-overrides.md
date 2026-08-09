# ADR 0060: OpenWrt interface DNS overrides

- Status: Implemented
- Date: 2026-08-09
- Scope: OpenWrt 21.02+ `network` UCI interface objects

## Context

Network troubleshooting often needs an interface to stop accepting resolver
addresses learned from DHCP/RA, or to use a small explicit resolver set and
search suffix list. This must remain part of the existing typed network
ChangeSet; a free-form `uci` or `/etc/resolv.conf` command would bypass the
fresh-inventory, approval, rollback, and verification guarantees.

## Decision

`NetworkInterfaceConfig` now carries three bounded fields:

- `peerdns`: whether resolver addresses learned from the peer remain enabled;
- `dns_servers`: at most eight parsed unicast resolver addresses;
- `dns_search`: at most sixteen bounded search suffixes.

The OpenWrt UCI adapter reconstructs these fields from `peerdns`, list option
`dns`, and list option `dns_search`. Rendering uses only typed UCI batch
operations. Existing native options are preserved on update, while malformed or
unsupported Agent-owned sections fail closed. The fields are included in the
same object digest and therefore cannot be changed after approval without
invalidating the plan.

The existing OpenWrt transaction stages and exports the UCI package in `/tmp`,
compares the live snapshot, installs `/etc/config/network` atomically, reloads
netifd, verifies fresh typed state, and leaves the independent rollback helper
armed until confirmed commit. The change remains R3 under the existing
network/device-admin policy.

Generic Linux exposes empty/default resolver fields in its runtime inventory but
does not write `/etc/resolv.conf`, systemd-resolved, NetworkManager, or an
unknown network manager. Those adapters require a separate ownership and
rollback contract. DoH/DoT credentials are intentionally out of this slice and
must use the secret-handling design before being supported.

## Consequences

- Interface DNS overrides can be requested through the existing CLI/channel
  `network-plan` ChangeSet without adding a new command or shell escape hatch.
- Search suffix and resolver values are validated before staging; duplicates,
  unspecified/multicast addresses, control characters, and capacity overflow
  are rejected.
- Older plans that omit the fields remain compatible because serde defaults
  `peerdns` to `true` and both lists to empty.
