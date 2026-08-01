# ADR 0046: Generic Linux Agent-owned runtime route staging

- Status: Accepted
- Date: 2026-08-01

## Context

ADR 0045 established a safe typed view of generic Linux kernel network state,
but kernel state cannot identify which persistent network manager owns ordinary
routes. A first write slice needs an ownership boundary that neither edits Flash
nor mutates routes belonging to NetworkManager, systemd-networkd, distribution
scripts, or an operator.

## Decisions

1. Limit the first generic Linux write backend to enabled Agent-owned typed
   routes. Interfaces, links, addresses, policy rules, and platform-native
   routes remain unsupported by this backend.
2. Mark every native route with numeric route protocol 186. A protocol-186 route
   without boot-bound canonical state is orphaned and fails closed; it is never
   adopted or deleted.
3. Store the intended typed route inventory and boot ID in a bounded canonical
   representation designed for volatile SQLite. Reconciliation compares fresh
   native protocol-186 route semantics with that exact state while ignoring only
   native-lossy object IDs.
4. Render exact forward and reverse `ip -batch` artifacts from the approved typed
   plan. Update is delete-before-add; rollback reverses change order and removes
   new state before restoring old state. Family, route type, destination,
   gateway, interface, preferred source, table, protocol, and metric are emitted
   only from validated typed fields.
5. Add a fixed `IpBatch` native command whose file must be a bounded regular file
   under the private runtime root. Normal activation stops at the first error;
   rollback can select fixed `ip -force -batch` semantics so a missing partially
   applied object cannot prevent restoration of later objects. Do not expose it
   as an independent API.
6. Keep activation closed in this slice. The next transaction must re-observe
   source state, persist both rollback batch and old canonical state in `/tmp`,
   arm the independent helper, execute, verify, and atomically replace canonical
   state before daemon admission opens.

## Consequences

Generic Linux now has a narrow, auditable staging model for additive and
versioned volatile routes without writing persistent network configuration.
Protocol collision or lost volatile canonical state blocks writes instead of
claiming foreign routes. There is still no public generic Linux network apply
until independent rollback and post-apply verification are complete.
