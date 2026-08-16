# ADR 0024: Typed firewall model and mutation planner

- Status: Accepted
- Date: 2026-07-26

## Context

The first writable domain must cover professional firewall configuration on
OpenWrt and generic Linux without exposing UCI expressions, nft statements,
iptables arguments, executables, or filesystem paths. A special command for
blocking one MAC address would not generalize to zones, forwarding, address
sets, NAT, ordering, or management-path protection.

Updates and deletes also need optimistic concurrency: a plan based on stale
firewall state must not overwrite a change made by another administrator.

## Decisions

1. Define one platform-neutral protocol model for zones, zone forwarding,
   filter rules, homogeneous address/MAC/port sets, and NAT rules.
2. Filter matches support address family, source/destination zones, input/output
   interfaces, canonical IP/CIDR prefixes, canonical MAC addresses, TCP/UDP/
   ICMP/ICMPv6/ESP/AH/GRE, source/destination ports, ICMP types, conntrack
   states, and typed set references. Rules additionally support accept/drop/
   reject, bounded rate limits, logging, enablement, and order.
3. NAT supports masquerade, SNAT, DNAT, and local redirect with typed
   translation addresses and ports. Invalid translation shapes fail before a
   backend is selected.
4. Reject duplicate values, mixed-type sets, non-canonical network prefixes,
   zero/reversed ports, family/protocol conflicts, invalid reject types,
   non-canonical MAC addresses, unknown identifiers, and every cardinality
   overflow.
5. Plan explicit create/update/delete/move mutations against a fresh bounded
   inventory. Update, delete, and move require the exact canonical SHA-256
   object digest. Create fails on collision; move may change only order.
6. Preserve ownership and reject every mutation of an unmanaged object.
   Platform-native objects are available to OpenWrt UCI adapters; Agent-owned
   objects are used by generic Linux isolated tables/chains.
7. Compute risk signals locally. Restrictive standalone rules can remain R2.
   Accept/NAT/forwarding creation, removal of restrictive rules, semantic
   updates, ordering changes, and anything intersecting the discovered
   management zone/interface/rule are R3.
8. Produce ordinary bounded `ChangeDiff` records so firewall changes use the
   existing ChangeSet digest, approval, persistence, rollback, and audit path.

## Consequences

MAC blocking is supported as one combination of typed match fields rather than
as a privileged special case. The same desired state can be rendered by
OpenWrt fw3/fw4 and generic Linux nftables/iptables adapters.

Backend-native validation and the full approval/rollback orchestration are now
connected for OpenWrt fw3/fw4 and generic Linux nftables/iptables. Public writes
remain capability-gated and fail closed for unsupported or third-party objects.
