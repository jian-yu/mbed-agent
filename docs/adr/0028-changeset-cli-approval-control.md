# ADR 0028: ChangeSet CLI approval control

- Status: Accepted
- Date: 2026-07-28

## Context

The volatile store already binds ChangeSets and approval-token digests to an
actor, boot, canonical plan digest, and monotonic expiration. Administrator
elevation also exists in daemon RAM. Without a protocol and CLI control surface,
however, an operator cannot inspect or authorize a locally planned change.

An approval endpoint must not become a way to submit caller-authored plans or
skip staging, native validation, rollback arming, apply verification, and
confirmed commit.

## Decisions

1. Add `change get`, `change approve`, and `change reject` to the existing
   `mbed-agent` executable. They communicate with the daemon over the existing
   bounded Unix-socket protocol.
2. Derive the actor from the authenticated transport. The local CLI is fixed to
   `cli/local`; request payloads cannot select another actor. Future Channels
   reuse these operations with actor IDs derived from their verified transport.
3. Before returning or approving a ChangeSet, decode its stored canonical
   `ChangePlan`, validate it again, recompute its SHA-256 digest, and compare all
   actor, boot, risk, identity, lifetime, and digest bindings with the row.
4. Hide another actor's ChangeSet as `not_found`. Reject records from a prior
   daemon/device boot as conflicts.
5. Require an unexpired, in-memory `device-admin` capability to approve. Generate
   a cryptographically random 256-bit token and a separate 128-bit approval ID.
   Return the raw token exactly once and store only its digest in volatile
   SQLite. Limit approval lifetime to the smaller of the configured approval TTL
   and the plan lifetime.
6. Measure persisted ChangeSet and approval deadlines against Linux boot uptime,
   not daemon-process uptime or adjustable wall time. A daemon restart in the
   same boot therefore cannot reset or extend an existing deadline.
7. `change reject` is allowed only for the owning actor and only where the core
   state machine permits the transition. It never requires elevated authority
   because it cannot cause a configuration write.
8. Approval issuance does not move the ChangeSet to `approved`. A future typed
   apply command must atomically consume the exact one-use token and perform the
   complete executor safety sequence.

## Consequences

Operators can now inspect and authorize daemon-created plans without exposing a
raw mutation API. Approval tokens cannot be replayed, substituted across
actors, boots, or plan digests, or recovered from SQLite. This slice deliberately
does not expose `apply`, `confirm`, or manual rollback until the firewall
executor and independent runtime rollback adapters are connected end to end.
