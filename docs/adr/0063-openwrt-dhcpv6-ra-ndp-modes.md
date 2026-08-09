# ADR 0063: OpenWrt DHCPv6, RA and NDP modes

- Status: Implemented
- Date: 2026-08-09
- Scope: OpenWrt 21+ `dhcp` UCI sections paired with typed network interfaces

## Context

The first OpenWrt network slice exposed a bounded DHCPv4 pool, but an IPv6-capable
router also needs explicit control of the DHCPv6, Router Advertisement (RA), and
Neighbor Discovery Proxy (NDP) modes in the same `dhcp.<interface>` section.
These values must participate in the existing typed plan, approval, snapshot
binding, native validation, confirmed commit, and paired `network`/`dhcp`
rollback flow. Generic Linux adapters do not have an equivalent portable UCI
surface and therefore remain read-only for this slice.

## Decision

1. Add a closed `NetworkDhcpMode` enum with `disabled`, `server`, `relay`, and
   `hybrid` values. `NetworkDhcpServerConfig` carries independent `dhcpv6_mode`,
   `ra_mode`, and `ndp_mode` fields.
2. Preserve compatibility with older plans and configurations by defaulting
   omitted fields to OpenWrt's effective defaults: DHCPv6 `server`, RA `server`,
   and NDP `hybrid`.
3. Parse only those four exact UCI values. Unknown values make a native section
   read-only; an Agent-owned section fails closed as unsupported rather than
   attempting to preserve or execute an untyped value.
4. Render only the fixed `dhcpv6`, `ra`, and `ndp` option names. Existing vendor
   options remain untouched, while managed drift is removed only for the fixed
   option set and then rewritten from the typed object.
5. Keep these fields inside the existing paired transaction. The stage includes
   both UCI batches, commits both packages, verifies both live files and typed
   snapshots, and arms the existing independent rollback target for
   `/etc/config/network` and `/etc/config/dhcp`.
6. Do not infer relay endpoints, RA lifetimes, prefix delegation, or odhcpd
   advanced options. Those require additional typed fields and capability checks
   before they can become writable.

## Consequences

- Channel and CLI callers get a stable, schema-checked representation without
  raw UCI or shell access.
- A single approved network change can configure IPv4 pool and IPv6 service
  modes atomically from the Agent's perspective, with the same R3 and
  management-path protections as other network changes.
- Native OpenWrt sections with unsupported mode values remain visible in the
  read-only inventory and cannot be silently claimed by the Agent.
- The implementation is intentionally limited to OpenWrt 21+ UCI semantics;
  generic Linux persistence and richer DHCP/RA policy are follow-up adapters.
