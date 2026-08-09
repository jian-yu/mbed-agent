# ADR 0065: Agent-owned OpenWrt IPv4 static leases

- Status: Implemented
- Date: 2026-08-09
- Scope: OpenWrt 21+ `dhcp` UCI `host` sections

## Context

OpenWrt stores static DHCP reservations in global `config host` sections. A
native host section does not carry a reliable pool/interface ownership field,
so guessing that every host whose address falls inside a subnet belongs to one
network interface could silently modify vendor or user configuration.

## Decision

1. Add a typed `NetworkDhcpStaticLease` nested under the interface DHCP server:
   stable ID, lowercase MAC, IPv4 address, optional hostname, and optional host
   lease time. The core validator bounds the list, rejects duplicate IDs/MACs/
   addresses, rejects network/broadcast/interface addresses, and rejects
   overlap with the dynamic pool.
2. Only Agent-owned host sections are writable. The marker is
   `mbed_managed='1'` and `mbed_id='<interface>/<lease-id>'`; no unsupported
   `interface` option is invented for the native host section.
3. Native host sections remain in the fresh occupied set and are reported as
   read-only. Managed sections with malformed markers or values fail closed.
4. Create/update/delete of an interface DHCP server reconciles its managed
   host sections in the same `/etc/config/network` + `/etc/config/dhcp`
   transaction. Unknown host options remain untouched; only the fixed typed
   options (`mbed_managed`, `mbed_id`, `mac`, `ip`, `name`, `leasetime`) are
   removed and rewritten.
5. Generic Linux has no equivalent portable UCI host adapter and is unchanged
   for this slice.

## Consequences

- Common IPv4 reservations can be created, updated, and removed through the
  existing approval, validation, verification, confirmation, and rollback path.
- Existing native reservations are never silently attributed to an interface or
  claimed by the Agent.
- IPv6 DUID/hostid reservations, multiple MAC values, tags, DNS flags, and
  vendor-specific host options require additional typed fields and remain
  read-only for now.
