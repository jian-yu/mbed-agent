# ADR 0025: OpenWrt fw3/fw4 firewall staging

- Status: Accepted
- Date: 2026-07-26

## Context

The typed firewall planner needs an OpenWrt 21.02+ adapter without exposing raw
UCI, iptables, nftables, command, environment, or path input to an LLM or
Channel. OpenWrt 21.02 commonly uses fw3/iptables while 22.03 and later use
fw4/nftables, but both consume `/etc/config/firewall`.

Updating anonymous UCI sections is especially sensitive. A model-provided
`@rule[N]` selector can become stale or target another administrator's object
after an unrelated reorder. Staging also must not write the live Flash-backed
configuration before native validation succeeds.

## Decisions

1. `platform-linux` selects a writable OpenWrt backend only when the discovered
   platform is OpenWrt and the complete command set exists: UCI plus fw3, or
   UCI plus fw4 and nft. Read capability does not imply write capability.
2. The adapter consumes only a validated `FirewallMutationPlan`. It renders
   zones, forwarding, filter rules, homogeneous address/MAC/port sets,
   masquerade, SNAT, DNAT, redirect, enablement, and rule ordering into a
   bounded UCI batch. It never executes the batch.
3. The daemon first copies the live firewall package to a private directory
   below `/tmp`. The fixed staging operation is `uci -c <staging-dir> batch`;
   the batch ends with `commit firewall`, which commits only inside that
   directory.
4. Existing object bindings are derived by joining a bounded, fresh
   `uci show firewall` snapshot with the fresh typed inventory. Named objects
   match their typed ID. Anonymous forwarding matches source/destination zones;
   unnamed rule/NAT objects use an explicit platform identity. Duplicate,
   ambiguous, malformed, oversized, or unsafe selectors fail closed.
5. Updates delete and replace only the adapter's compiled option allowlist.
   Unknown vendor or third-party options on a platform-native section remain
   untouched. Deletes and moves use the exact locally resolved section.
6. Agent-created sections receive a deterministic `mbed_<type>_<digest>`
   identifier. User data is allowed only as quoted typed values; controls,
   backslashes, quotes, oversized values, and arbitrary UCI syntax are rejected.
7. fw3 staging requires both `fw3 -4 -q print` and `fw3 -6 -q print` with
   `UCI_CONFIG_DIR` fixed by the executor. fw4 staging requires
   `fw4 -q check`, which renders and invokes nftables check mode. All checks
   must pass before an atomic live-file install.
8. Activation is compiled as `/etc/init.d/firewall reload`. The future
   ChangeSet executor may invoke it only after approval, bounded snapshot,
   validation, and rollback arming.
9. UCI features that cannot preserve the typed meaning fail explicitly.
   Current examples are raw conntrack expressions, multiple UCI-inexpressible
   zone/interface selectors, non-info per-rule log levels, and a requested
   per-rule reject code (fw3/fw4 UCI uses global reject-code defaults).

## Consequences

OpenWrt 21.02 fw3 and newer fw4 now share one typed desired-state path while
retaining backend-native validation. MAC restriction is one tested combination
of source MAC, CIDR, zones, protocol, ports, and verdict; address sets and NAT
are part of the same adapter rather than special commands.

This slice produces and validates staging artifacts but deliberately does not
install or activate them. Public firewall writes remain unavailable until the
ChangeSet executor connects approval, snapshot, native validation, apply,
verification, confirmed commit, and independent rollback.
