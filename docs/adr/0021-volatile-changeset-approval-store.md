# ADR 0021: Volatile ChangeSet and approval storage

- Status: Accepted
- Date: 2026-07-25

## Context

ChangeSet state and one-use approval consumption must survive daemon restart
within the same boot and must be atomic under duplicate Channel messages. They
must not survive a device reboot or write Flash.

Storing raw approval tokens would turn a database disclosure into reusable
authorization. Separately updating an approval row and a ChangeSet state would
permit partial consumption or replay after a crash.

## Decisions

1. Add `change_sets` and `approvals` to the existing SQLite database under
   `/tmp/mbed-agent`. No second database or persistent journal is introduced.
2. Store the bounded redacted plan, plan digest, state, actor, boot id, risk,
   monotonic expiration, optional rollback deadline, and timestamps.
3. Store only a fixed lowercase-hex digest of an approval token. Raw tokens
   remain in memory and in the authorized response path.
4. Issue an approval only when the referenced ChangeSet is exactly
   `awaiting_approval` and actor, plan digest, boot id, and expiration match.
5. Consume an approval with one conditional update over approval id, ChangeSet
   id, actor, plan digest, boot id, token digest, expiration, and unused state.
   In the same SQLite transaction, conditionally move the exact ChangeSet from
   `awaiting_approval` to `approved`.
6. Return one generic rejection for unknown, expired, mismatched, or replayed
   approvals to avoid exposing a token oracle. A failed second update rolls the
   token-consumption update back.
7. Make state transitions compare expected state, plan digest, and boot id.
   Apply the core ChangeSet transition table before the conditional update.
8. Do not permit the generic transition API to enter `rollback_armed`. A
   dedicated transaction requires and stores a future monotonic rollback
   deadline.
9. Never prune active ChangeSets to admit a new plan. Bound active/retained
   records with `storage.max_change_set_records` and each serialized plan with
   `storage.max_change_plan_bytes`.

## Consequences

Duplicate MQTT or robot messages cannot approve a plan twice, and a token for a
different actor, boot, or diff cannot advance state. Daemon restart in the same
boot can recover the exact volatile state.

This slice does not issue approval tokens, authenticate administrators, arm an
external rollback helper, or execute configuration. Actual write APIs remain
unavailable until those safety components are connected.
