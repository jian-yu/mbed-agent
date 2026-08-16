# ADR 0027: Generic Linux isolated iptables staging

- Status: Accepted
- Date: 2026-07-27

## Context

Some small and older generic Linux systems expose iptables/ip6tables but not a
usable native nftables control plane. Replaying a complete `iptables-save`
snapshot would overwrite distribution or vendor rules, while individual
imperative commands are difficult to validate and can leave duplicate hooks.

`iptables-restore --noflush` retains unrelated chains and, when a user-defined
chain is declared, flushes and rebuilds only that chain. Its `--test` mode
constructs the ruleset without committing it. IPv4/IPv6 and individual tables
are still separate commits, so apply can partially succeed.

## Decisions

1. The adapter owns six fixed chains in each address family:
   `MBED_INPUT`, `MBED_OUTPUT`, `MBED_FORWARD`, `MBED_MANGLE_FORWARD`,
   `MBED_PREROUTING`, and `MBED_POSTROUTING`.
2. On first install it appends exactly one jump from the corresponding built-in
   filter, mangle, or nat chain. Every jump carries an exact
   `mbed-agent-owned:v1:<hook>` comment. Later renders redeclare only the six
   managed chains, relying on no-flush restore semantics to rebuild them while
   preserving all other chains and built-in rules.
3. A bounded `iptables-save`/`ip6tables-save` inspector requires all six chains
   and all six marked jumps to be either absent or present exactly once.
   Partial state, a duplicate/foreign jump, or a same-name foreign chain fails
   closed and is never adopted.
4. Only fresh, version-bound `AgentOwned` projected objects enter the chains.
   The shared projection gate rechecks plan shape, exact before objects, typed
   validation, ownership, and create/update/delete/move consistency for both
   nftables and iptables backends.
5. Filter rules cover zones/interfaces, IPv4/IPv6 CIDR, source MAC, TCP/UDP/
   ICMP/ICMPv6/ESP/AH/GRE, source/destination ports, ICMP types, conntrack
   states, rate limiting, logging, reject kinds, enablement, and order.
   Forwarding and zone policies are rendered after ordered explicit rules.
6. Homogeneous typed sets are expanded into bounded native rules instead of
   introducing a second ipset transaction. Network, source-MAC, and port sets
   can be combined as distinct match dimensions. Expansion is capped at 1024
   rules and total restore input at 256 KiB per family.
7. Rate limits are rejected when a typed rule expands into multiple native
   alternatives; duplicating a bucket per alternative would silently multiply
   the allowed rate. Destination MAC sets are rejected because the classic
   iptables MAC match exposes source MAC only. Other non-preserving combinations
   similarly fail explicitly.
8. Zone masquerade uses the owned nat postrouting chain. MTU fixing uses the
   owned mangle forward chain with `TCPMSS --clamp-mss-to-pmtu`, not a filter
   chain. SNAT, DNAT, redirect, IPv4/IPv6 translation endpoints, and port ranges
   are typed and bounded.
9. Logging emits a separate ownership-commented LOG rule with a fixed
   1/second, burst-5 safety limit and enforces the native 29-byte prefix bound.
   This prevents a remotely requested rule from exhausting the bounded logging
   path.
10. Validation is fixed to
    `iptables-restore --noflush --test` and
    `ip6tables-restore --noflush --test`; activation removes `--test`.
    Both validations must pass before either load. Because filter/mangle/nat and
    IPv4/IPv6 commits are not one transaction, independent rollback is always
    required and any partial failure must restore both `*-save` snapshots.
11. Hooks are appended, so pre-existing rules run first. If traffic reaches an
    Agent jump, Agent ACCEPT/DROP/REJECT is terminal for that iptables hook.
    This `AppendedTerminal` coexistence mode is exposed to risk and verification
    logic.

## Consequences

Generic Linux now has typed staging paths for both nftables and classic
iptables/ip6tables without rebuilding unknown host policy. The iptables path is
broader than a MAC blocker and covers the same main firewall objects, while
being honest about rule expansion and non-atomic multi-family apply.

This slice renders and golden-tests restore artifacts. The repository now also
provides a privileged Alpine Linux daemon smoke that executes real dual-stack
restore `--test`, apply, confirmed-commit timeout, watchdog rollback, and native
snapshot verification; the macOS development host remains read-only for native
iptables execution.
