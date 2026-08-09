# ADR 0064: Typed OpenWrt DHCP options

- Status: Implemented
- Date: 2026-08-09
- Scope: OpenWrt 21+ `dhcp.<interface>` sections

## Context

OpenWrt's dnsmasq configuration exposes DHCP options through a list-valued
`dhcp_option` UCI option. Treating that value as an arbitrary string would
reintroduce the raw UCI escape path that the typed network planner is designed
to prevent. At the same time, common router deployments need options such as
DNS servers (option 6), domain search (option 15), routers, and vendor-specific
values.

## Decision

1. Add `NetworkDhcpOption { code, value }` to the typed DHCP server object.
   The code is restricted to 1..=255; at most 16 entries are accepted.
2. Values are non-empty, at most 255 bytes, and cannot contain control bytes,
   quotes, backslashes, or commas. This keeps the one-code/one-value model
   unambiguous and safe for UCI quoting. Duplicate `(code, value)` pairs are
   rejected by the core validator.
3. OpenWrt inventory parses only the exact `code,value` list form. Malformed,
   over-capacity, or otherwise unrepresentable native options make the section
   read-only; the same drift on an Agent-owned section fails closed.
4. Rendering uses only `add_list dhcp.<section>.dhcp_option=<quoted typed value>`.
   The option is part of the fixed managed option set, so updates remove only
   previously modeled values and preserve unrelated vendor options.
5. The field is included in the existing network/dhcp paired transaction,
   digest-bound approval payload, native export validation, live verification,
   confirmed commit, and independent rollback. Generic Linux remains unchanged
   and read-only for this OpenWrt-specific UCI slice.

## Consequences

- Common DHCP behavior can be configured without raw UCI, shell, or executable
  injection.
- Legacy serialized plans remain compatible because omitted options decode as an
  empty list.
- Multi-value DHCP encodings, static lease `host` sections, and vendor-specific
  syntax requiring commas remain outside this slice until they receive their
  own typed schema and ownership binding.
