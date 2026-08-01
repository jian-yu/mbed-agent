# ADR 0047: Generic Linux runtime route native transaction

- Status: Accepted
- Date: 2026-08-01

## Context

ADR 0046 produced exact forward and reverse route batches but did not define
transaction ordering or execute them. Activation must not use a stale canonical
snapshot or a modified staging artifact, and successful command exit alone is
not sufficient verification.

## Decisions

1. Add a stateful generic runtime route transaction with the strict sequence
   inspect, stage, validate, rollback-armed activation, and verify.
2. Reconcile a fresh protocol-186 observation with boot-bound canonical state
   before rendering. Write forward and reverse batches as synced mode-0600 files
   in a private transaction directory below the runtime root.
3. Validation re-reads both staged artifacts and requires byte equality with the
   typed renderer. There is no claim that iproute2 provides a side-effect-free
   route validation operation.
4. Immediately before activation, collect and reconcile native state again and
   require the exact typed snapshot to remain unchanged. Execute only the fixed
   non-force `IpBatch` operation after the caller has armed rollback.
5. After activation, collect fresh native routes and reconcile them against the
   projected canonical payload. Only that verified payload may replace volatile
   SQLite canonical state.
6. Expose the exact reverse batch to the future execution port only while the
   transaction is staged or validated. Always remove staging on explicit discard
   or drop.
7. Keep daemon admission closed until the independent rollback manifest/helper
   can execute the reverse batch and restore the previous network canonical
   state after timeout, process death, or partial activation.

## Consequences

The native transaction now detects canonical drift, staged-file tampering,
concurrent protocol-owned route changes, partial command failure, and post-apply
semantic mismatch. It performs no Flash writes. Public generic Linux route
configuration remains one slice away: rollback helper integration and daemon
ChangeSet admission.
