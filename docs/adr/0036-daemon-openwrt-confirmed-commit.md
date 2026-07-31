# ADR 0036: Daemon OpenWrt confirmed commit

- Status: Accepted
- Date: 2026-07-31

## Context

The native OpenWrt transaction, one-use approval records, durable rollback
bundles, and fail-closed coordinator existed independently. Exposing the write
primitive without one daemon-owned sequence would permit skipped approval,
unarmed writes, concurrent transactions, or confirmation without fresh live
verification.

## Decisions

1. Add `change apply` and `change confirm` to the existing single binary and
   local protocol. Approval tokens are read from stdin and represented as
   redacted, zeroizing values; they are never accepted as command-line
   arguments. The CLI may consume the complete approval response from stdin,
   verifies its ChangeSet and optional approval-ID binding, and extracts the
   one-use token without an intermediate file.
2. Serialize apply and confirm with one daemon configuration mutex. Accept only
   exact, boot-bound, actor-owned executable payloads and supported OpenWrt
   21.02+ fw3/fw4 capabilities.
3. Validate every non-secret prerequisite before atomically consuming the
   approval token. The SQLite transaction binds approval ID, ChangeSet ID,
   actor, plan digest, boot ID, token digest, lifetime, and one-use state while
   advancing the ChangeSet to `approved`.
4. Delegate the fixed sequence to the core coordinator. The execution port
   performs fresh inspection, `/tmp` staging, native validation, bounded
   rollback snapshot creation, independent same-binary helper spawning,
   SQLite transitions, atomic Flash activation, reload, and live verification.
5. Require R3/R4 changes to remain `awaiting_confirmation`. Confirmation
   requires a current device-admin capability, a future rollback deadline, and
   a fresh UCI inventory in which every touched object equals the approved
   after-state (or is absent for delete). Unrelated live objects do not make a
   valid confirmation stale.
6. Confirmation and recovery use the atomic first-decision-wins marker. Any
   failure after arming requests immediate helper recovery and waits for a
   durable outcome before recording `rolled_back` or `rollback_failed`.

## Consequences

Actual OpenWrt firewall writes are now reachable only through the complete
approval and confirmed-commit path. CLI and future Channels share the same
protocol commands and cannot submit replacement rule bodies at apply time.
Generic Linux nftables/iptables still remain closed until equivalent concrete
execution ports are connected.
