# ADR 0033: Bound firewall execution payload

- Status: Accepted
- Date: 2026-07-28

## Context

A user-visible `ChangePlan` contains typed diffs and content digests, but not
the complete desired firewall objects needed by a platform renderer. Rebuilding
objects from summaries or allowing a Channel to submit them at apply time would
break the approved-plan binding.

## Decisions

1. Define a versioned `FirewallExecutionPlan` containing the exact public
   `ChangePlan` preview and the complete locally planned typed before/after
   objects.
2. On encode and decode, revalidate the preview's lifetime, semantic risk,
   ownership, operation shape, object identity, expected version, before/after
   SHA-256 digests, and every firewall object schema.
3. Require the preview diffs to equal the typed planner diffs byte-for-byte in
   their structured representation. A changed typed object without a matching
   approved digest fails closed.
4. Bound the canonical payload to 256 KiB and 32 mutations.
5. Store executable payloads in a dedicated volatile SQLite table keyed by
   ChangeSet ID, with duplicated plan-digest and boot-ID bindings. Attach once
   only while the ChangeSet is `planned`; replacements and stale bindings are
   rejected.
6. Keep the display plan in the existing ChangeSet record. This preserves the
   generic control-plane response and prevents executable objects from being
   returned accidentally through normal Channel responses.
7. Add `storage.max_firewall_execution_plan_bytes`; it must be non-zero and fit
   the total database budget. Both store and decoder enforce their limits.

## Consequences

Apply can load the exact locally generated desired objects after consuming an
approval token, then compare them with a fresh platform inventory. No rule is
inferred from natural-language summaries or hashes.

The next platform execution port will require both records and reject a
ChangeSet that has no matching executable payload.
