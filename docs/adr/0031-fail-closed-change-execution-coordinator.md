# ADR 0031: Fail-closed change execution coordinator

- Status: Accepted
- Date: 2026-07-28

## Context

Typed renderers, approval storage, and an independent rollback helper existed,
but a backend could still call them in an unsafe order. In particular,
activation must never precede a second inspection, native dry-run validation,
and successful rollback arming. Failures after activation must not depend on
the daemon continuing normally.

## Decisions

1. Define one small `ChangeExecutionPort` implemented by a platform adapter plus
   the volatile ChangeSet store. It exposes only typed inspection, staging,
   validation, rollback, activation, verification, confirmation, and exact
   conditional state transitions.
2. Centralize the only permitted order:
   `reinspect -> stage -> validated -> rollback armed -> applying -> verifying`.
3. Require a future monotonic rollback deadline before any operation.
4. Discard isolated staging on pre-apply failures. Record validation and
   rollback-arming failures through `apply_failed -> rolling_back ->
   rolled_back`, even though no native write occurred, so they do not consume
   active ChangeSet capacity indefinitely.
5. After rollback is armed, any activation, state-journal, or verification
   failure enters `rolling_back` and invokes the independent recovery path.
   Recovery success and failure are distinct terminal states.
6. R3 execution remains `awaiting_confirmation` with its watchdog armed.
   Confirmation performs a fresh inspection and verification before creating
   the confirmation marker. A marker failure remains retryable and never
   falsely records `confirmed`.
7. Adapter errors crossing this boundary are opaque. Bounded command details
   may be logged locally, but are not returned through channels.

## Consequences

Platform code cannot accidentally activate a staged firewall before native
validation and rollback protection. The coordinator is deterministic and
supports fault injection at every operation.

The next slice implements the concrete OpenWrt and generic Linux execution
ports, fixed command allowlists, subprocess time/output limits, and daemon/CLI
apply and confirm commands.
