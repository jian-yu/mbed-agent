# ADR 0035: Atomic rollback decision

- Status: Accepted
- Date: 2026-07-31

## Context

The independent helper originally supported confirmation or deadline expiry.
When activation or verification fails, the daemon must request recovery
immediately rather than wait for the entire confirmation window. Confirmation
and failure handling may race across tasks or processes, so two independent
marker files are unsafe.

## Decisions

1. Add `request_rollback`, which accepts only the compiled rollback root and a
   validated bounded transaction ID. It cannot carry a path or command.
2. Use one immutable `decision` inode for both `confirm:<transaction-id>` and
   `rollback:<transaction-id>`. Write and fsync an action-specific temporary
   inode, then publish it with an atomic hard link. The first terminal decision
   wins; a conflicting later decision fails.
3. Treat repeating the exact same decision as idempotent. Never expose a
   partially written marker to the helper.
4. Make the helper poll the decision before its deadline. A rollback decision
   immediately invokes the same bounded digest-checked restore and typed reload
   used at timeout.
5. Add `rollback_outcome`, which reads only the durable `rolled-back`,
   `rollback-failed:restore`, or `rollback-failed:reload` state and otherwise
   reports pending.

## Consequences

The daemon execution port can synchronously request recovery after a failed
apply or verification while the watchdog remains independent of daemon health.
A late confirmation cannot override a recovery decision.
