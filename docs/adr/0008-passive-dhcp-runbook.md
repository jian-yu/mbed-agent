# ADR 0008: Passive cross-platform DHCP runbook

- Status: Accepted
- Date: 2026-07-24

## Context

WAN address failures are often DHCP failures, but a diagnostic must distinguish
an actively negotiating client, a missing lease, a non-DHCP WAN protocol, and
insufficient evidence. Treating every missing address as DHCP would misdiagnose
PPPoE, static addressing, and generic Linux systems whose DHCP client state is
not exposed.

Renewing a lease is a state-changing R2 operation and does not belong in the
Phase 1 read-only runtime.

## Decisions

1. Add a typed `DhcpDiagnosticReport` and
   `mbed-agent diagnose dhcp`. Its assessment vocabulary is `lease_ready`,
   `negotiating`, `lease_missing`, `not_dhcp`, `link_down`,
   `interface_unavailable`, and `insufficient_evidence`.
2. On OpenWrt, use the existing allowlisted
   `ubus call network.interface.wan status` response for protocol, pending,
   availability, device, and address state.
3. On generic Linux, infer `dhcp-inferred` only when normalized `ip -j address`
   data explicitly marks the selected WAN address as dynamic. Do not infer a
   DHCP client merely because an address or default route exists.
4. Limit the focused collector set to OpenWrt WAN status when applicable plus
   kernel link, address, and route evidence. Do not read resolver files,
   firewall configuration, policy rules, or DHCP client lease files.
5. Never invoke renew, release, reload, restart, or any shell. The report states
   that no lease action was attempted and identifies kernel inference when
   authoritative client state is unavailable.
6. Add the closed-schema `inspect_dhcp` Agent tool. It reuses the request's
   single passive WAN snapshot and exposes only normalized protocol,
   negotiation, link, device, and address fields.
7. Persist only the normalized DHCP summary to volatile SQLite with history
   kind `dhcp`, under the existing record, page, total `/tmp`, semaphore, and
   timeout limits.

## Consequences

The four initial deterministic network runbook domains—WAN, DNS, DHCP, and
routes—are now callable without an LLM on OpenWrt and generic Linux. OpenWrt
receives authoritative logical-interface state; generic Linux remains
conservative. Lease lifetime parsing, DHCP client identification, DHCPv6
details, and renew/rebind operations require separate typed collectors and, for
changes, the Phase 2 approval and rollback policy.
