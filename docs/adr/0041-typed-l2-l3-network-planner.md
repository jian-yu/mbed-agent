# ADR 0041: Typed L2/L3 network planning boundary

- Status: Accepted
- Date: 2026-08-01

## Context

The first writable domain established a complete ChangeSet, approval, native
validation, independent rollback, and confirmed-commit path for firewall
changes. L2/L3 configuration must reuse that safety substrate across OpenWrt
and generic Linux rather than exposing `ip`, `bridge`, UCI, netlink, or network
manager arguments to a model.

Network objects are more likely than additive firewall objects to disconnect
the active management session. Risk therefore depends on fresh interface,
address, default-route, and route-table context, not only the requested object
kind.

## Decisions

1. Define one platform-neutral typed model for interfaces and static/dynamic
   address modes, MTU and MAC override, bridges, VLANs, bonds, VRFs, routes,
   and policy rules.
2. Use explicit create, update, delete, and policy-priority move requests.
   Update, delete, and move bind the fresh canonical SHA-256 object digest.
3. Permit creation only for Agent-owned objects. Platform-native objects can be
   updated or deleted when a platform adapter advertises that exact operation;
   unmanaged objects remain read-only.
4. Validate address families and prefixes, MTU and VLAN bounds, aggregate
   membership, bond primary membership, VRF tables, route next-hop shapes,
   policy actions, fwmark masks, and unique active policy priorities locally.
5. Compute a minimum R2 risk. Any change touching a management interface or
   address, a default route, or a management route table is R3. Deleting or
   changing an enabled network object is also treated as potentially service
   disrupting and therefore R3.
6. Bind complete before/after typed objects to the exact user-visible
   `ChangePlan` in a bounded executable payload. Provide pure projection and
   post-apply verification functions so platform adapters share stale-state and
   desired-state semantics.
7. This ADR does not open host writes. OpenWrt UCI/netifd and generic Linux
   runtime/persistence adapters must first provide fresh inventory, capability
   field gating, native validation, bounded rollback artifacts, and independent
   confirmed-commit recovery.

## Consequences

The complete L2/L3 product schema and planner now exist without a raw command
escape hatch. Future platform slices implement the same object semantics while
explicitly narrowing unsupported fields. Until an adapter meets the transaction
contract, the daemon continues to expose that platform's network state as
read-only diagnostics.
