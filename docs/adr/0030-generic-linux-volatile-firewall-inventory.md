# ADR 0030: Generic Linux volatile firewall inventory

- Status: Accepted
- Date: 2026-07-28

## Context

The generic Linux renderers own an isolated nftables table or six fixed
iptables chains per address family. Native rule listings preserve executable
rules, but cannot losslessly reconstruct the Agent's typed identifiers,
references, ordering intent, and ownership metadata. Trusting caller-provided
inventory would allow stale plans, while adopting native rules after `/tmp`
loss would guess at state.

The runtime database must remain volatile and bounded. A daemon restart within
the same boot should recover its typed inventory; a device reboot must not
recover it from Flash.

## Decisions

1. Store one canonical typed inventory in the existing SQLite `app_state`
   table. The database path remains under `/tmp`; no generic firewall runtime
   state is written to persistent configuration.
2. Bind the record to schema version, backend, Linux boot ID, and a fresh
   SHA-256 fingerprint of the strictly Agent-owned native state.
3. For nftables, fingerprint the complete fixed `inet mbed_agent` table after
   normalizing blank lines and line-boundary whitespace.
4. For iptables, fingerprint only the six managed chain declarations, rules
   inside those chains, and exact ownership-marked hook jumps. Ignore unrelated
   distribution rules and volatile packet counters. IPv4 and IPv6 must both be
   absent or both be completely Agent-owned.
5. Permit first use only when both canonical and native Agent-owned state are
   absent. Native state without its canonical record is orphaned and fails
   closed; canonical/native digest disagreement is drift and also fails closed.
6. Expose immutable reconciled snapshots and snapshot-based staging entry
   points. Canonical state is encoded only after projecting the same typed plan
   and independently inspecting the post-apply native state.
7. Bound the canonical JSON to 256 KiB and 256 typed objects. Add
   `storage.max_firewall_state_bytes`, which must be non-zero and fit within
   `storage.max_database_bytes`; SQLite store reads and replacements enforce the
   configured payload cap.

## Consequences

A daemon restart can safely resume firewall management within the current boot
when SQLite and native rules agree. Manual edits, partial iptables application,
backend changes, database loss, or a boot-ID change block further writes
instead of silently adopting state. Distribution-owned firewall rules remain
outside the fingerprint and are not rewritten.

This slice does not execute native commands. The execution coordinator must
still perform a second pre-apply inspection, stage validation, rollback arming,
activation, post-apply inspection, verification, and explicit confirmation.
