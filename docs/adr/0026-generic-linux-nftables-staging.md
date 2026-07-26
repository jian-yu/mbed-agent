# ADR 0026: Generic Linux isolated nftables staging

- Status: Accepted
- Date: 2026-07-26

## Context

Generic Linux is a peer target, not an OpenWrt fallback. It cannot use UCI or
assume that firewalld, ufw, NetworkManager, or a vendor ruleset has a writable
schema. Rewriting an unknown host ruleset would violate the ownership boundary,
while a narrow MAC-only command would not satisfy the typed firewall domain.

nftables permits an independent table with its own base chains and an atomic
ruleset transaction. Coexistence still has important semantics: a drop verdict
is final, but an accept verdict can be superseded by another later base chain;
an earlier NAT chain can also establish the mapping before an Agent chain.

## Decisions

1. The generic nftables adapter owns exactly `table inet mbed_agent`, marked
   with table comment `mbed-agent-owned:v1`. An existing table without that
   exact marker is foreign and fails closed; the adapter never adopts it.
2. Only `AgentOwned` typed objects enter this table. Platform-native and
   unmanaged objects remain outside the adapter even if a caller constructs a
   plan for them.
3. Each render applies the mutation plan to the exact fresh inventory in
   memory, checking before-object equality again, and emits the complete
   projected table. If the owned table already exists, delete and recreation
   occur in the same nftables transaction.
4. The table has isolated input, output, and forward filter base chains,
   prerouting DNAT/redirect, and postrouting SNAT/masquerade chains. It supports
   zones mapped to typed interface names, forwarding, IPv4/IPv6 CIDR, MAC,
   protocol, ports/ranges, ICMP types, conntrack states, rate limits, all log
   levels, reject kinds, homogeneous network/MAC/port sets, NAT, enablement, and
   ordering.
5. Set names are deterministic fixed-format hashes of validated object IDs.
   Values are emitted only from validated typed fields; nft strings reject
   controls, quotes, backslashes, and oversized input. Rulesets and expansion
   are bounded.
6. Filter chains use policy accept and priority -5. This makes Agent drops
   immediate while avoiding replacement of the host policy. NAT chains use
   priorities -90 and 110, after conventional dstnat/srcnat priorities, so an
   existing host mapping wins.
7. The backend explicitly reports `IsolatedAdditive` coexistence. An Agent
   accept can permit traffic relative to an Agent zone policy but cannot promise
   to override a separate distribution-owned drop. NAT likewise applies only
   when an earlier mapping has not won. Callers and verification must expose
   this rather than claiming full host-policy ownership.
8. The only native operations are fixed `nft --check --file <stage>` and
   `nft --file <stage>`. The renderer invokes neither. The future ChangeSet
   executor supplies a private `/tmp` file and must bind inspection, check,
   snapshot, apply, verification, confirmation, and rollback.
9. Semantics that cannot currently be represented without ambiguity fail
   explicitly: mixed IPv4/IPv6 networks in one rule, transport ports mixed with
   non-transport protocols, family-mismatched address sets, multiple same-
   dimension set references that would otherwise become a silent intersection,
   DNAT destination zones in prerouting, and generic zone MTU fixing.

## Consequences

Generic Linux now has a broad, runtime-only nftables staging backend without
touching firewalld/ufw/vendor tables or Flash. It can impose reliable
restrictions and isolated NAT behavior, while allow behavior truthfully reports
coexistence limits.

The adapter is unit/golden tested and based on nftables-native syntax, but this
slice does not execute it on the current macOS development host. Linux
`nft --check`, namespace integration, fault injection, and rollback tests remain
mandatory before the public write API opens.
