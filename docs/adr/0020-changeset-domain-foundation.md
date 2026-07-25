# ADR 0020: ChangeSet domain foundation

- Status: Accepted
- Date: 2026-07-25

## Context

Every writable network domain needs the same bounded plan, semantic risk,
approval, validation, rollback, verification, and confirmation behavior.
Implementing these rules inside each firewall, network, or wireless command
would create inconsistent bypasses.

The initial foundation must be useful before execution is enabled, but it must
not accidentally expose a partially protected write path.

## Decisions

1. Define a provider- and channel-neutral `ChangePlan` protocol with a fixed
   schema version, plan/boot/actor identity, monotonic lifetime, computed risk,
   ordered typed object diffs, bounded validation and verification checks, and
   an explicit rollback requirement.
2. A diff contains only a typed domain/object reference, operation,
   before/after content digests, expected object version, redacted summary,
   ownership, and semantic risk signals. It never contains executable names,
   argv, raw UCI/nft/iptables expressions, arbitrary paths, or secret values.
3. Permit at most 32 objects, 32 validation checks, and 32 verification checks.
   Bound identifiers, summaries, checks, and canonical plan encoding to 64 KiB.
4. Reject unmanaged objects, duplicate object operations, invalid digest shapes,
   missing rollback, control characters, unsupported schema versions, and
   secret-changing summaries not explicitly marked redacted.
5. Compute a minimum R2 risk for every write. Management-path impact, exposure
   widening, service disruption, or secret changes raise risk to R3. Device
   authentication changes or irreversible operations raise it to R4. The
   declared risk must exactly match the locally computed risk. Domain planners
   derive these signals from fresh typed before/after objects; an LLM or Channel
   never supplies trusted risk signals.
6. Produce a SHA-256 digest over canonical typed JSON. The digest binds actor,
   boot, monotonic lifetime, object versions, ordered diff, checks, rollback
   requirement, and computed risk.
7. The digest is not authorization. A later slice will issue a keyed, one-use,
   short-lived approval token over this digest and store consumption state in
   volatile SQLite.
8. Enforce a closed ChangeSet state machine. Applying cannot begin before
   approval, staging, validation, and rollback arming. Confirmation cannot occur
   before verification. Failed apply paths must enter rollback, and
   `RollbackFailed` is terminal.
9. Do not expose any writable CLI, Agent tool, or backend in this slice.
   `ChangePlan` is daemon output and persisted state, not an execution request
   accepted from a model or remote caller.

## Consequences

All future configuration backends share one protocol and locally enforced
safety sequence. Models and Channels can describe candidate changes but cannot
lower risk or construct an authorized state.

This slice deliberately leaves the product read-only. The next slices must add
volatile ChangeSet persistence, channel-independent administrator elevation,
keyed one-use approvals, bounded rollback journals, and the independent helper
before the first firewall mutation becomes callable.
