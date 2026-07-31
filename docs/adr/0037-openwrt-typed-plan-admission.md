# ADR 0037: OpenWrt typed plan admission

- Status: Accepted
- Date: 2026-07-31

## Context

Confirmed execution was connected, but production clients still had no public
way to create the exact executable ChangeSet. A plan API must not accept raw
commands, caller-supplied before-state, or a second desired payload at apply
time.

## Decisions

1. Add a fresh typed inventory operation and a closed
   `FirewallMutationRequest` protocol enum for create, update, delete, and move.
   Inventory entries include the exact object digest required as
   `expected_digest`. The CLI reads its bounded JSON array from stdin so large
   typed objects do not enter process arguments.
2. Serialize planning with configuration execution and support this admission
   path only on discovered OpenWrt 21.02+ fw3/fw4 systems.
3. Reinspect live UCI through the bounded shell-free runner and reconstruct the
   full typed inventory before resolving any mutation. Update, delete, and move
   require the exact fresh object digest. New objects must be Agent-owned;
   callers cannot create a fake platform-native identity.
4. Conservatively classify every admitted OpenWrt firewall plan as at least R3,
   so it always requires confirmed commit. A bounded set of existing zones,
   zone networks, filter rules, and NAT rules is also supplied as management
   context for per-diff signals; exceeding that bounded context cannot lower
   the overall risk.
5. Generate the ID, boot/actor binding, monotonic lifetime, diffs, validation
   and verification promises in the daemon. Atomically insert the preview,
   executable payload, and `awaiting_approval` state in one SQLite transaction.

## Consequences

The documented CLI flow can now produce and execute real OpenWrt firewall
changes without test-only database insertion. The same protocol operation is
available to future authenticated Channels. Generic Linux planning remains
closed until its canonical runtime inventory and native execution ports are
connected to the same admission path.
