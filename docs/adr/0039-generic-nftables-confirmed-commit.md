# ADR 0039: Generic Linux nftables confirmed commit

- Status: Accepted
- Date: 2026-07-31

## Context

Generic Linux must support the same typed firewall workflow as OpenWrt without
rewriting distribution or third-party rules. Runtime state is intentionally
volatile: native ownership is limited to `table inet mbed_agent`, while the
typed canonical inventory, staging data, and rollback artifacts live below
`/tmp`.

## Decisions

1. Admit generic writes only when capability discovery selects native
   nftables. The iptables dual-family transaction remains closed until its
   separate recovery protocol is complete.
2. Planning, apply, and confirmation each collect a fresh fixed-table
   observation and reconcile it with the boot-bound canonical SQLite state.
   Orphan state, foreign ownership, stale boot IDs, and native drift fail
   closed.
3. Render the complete Agent-owned table into a private `0600` staging file,
   run `nft --check --file`, recheck the exact source observation, then commit
   once with `nft --file`. No shell or caller-selected command is accepted.
4. Before activation, create a bounded rollback bundle containing a digest-
   bound runtime ruleset and the prior canonical state. The independent
   same-binary helper restores only the fixed owned table; it never writes a
   persistent nftables configuration file.
5. After live verification, atomically replace the canonical state in `/tmp`
   SQLite. Immediate rollback, confirmation failure, daemon exit, or watchdog
   timeout restores both native state and the prior canonical snapshot.
6. All generic firewall plans remain at least R3 and require explicit
   `device-admin` approval plus confirmed commit.

## Consequences

The existing `change firewall-inventory`, `change firewall-plan`, `change
apply`, and `change confirm` commands now work on supported OpenWrt and generic
Linux nftables systems through one policy and state machine. Generic nftables
changes do not add Flash writes. A device reboot intentionally discards the
canonical database; any surviving externally persisted owned table is treated
as orphaned rather than silently adopted.

