# ADR 0006: Bounded volatile task ledger

- Status: Accepted
- Date: 2026-07-24

## Context

The Agent loop returned completions and persisted normalized tool evidence, but
operators could not inspect whether recent model tasks succeeded, timed out, or
consumed an unusual number of tokens. Persisting prompts and answers would
increase flash-risk, privacy exposure, and database growth without being
necessary for runtime accounting.

The provider timeout applies to one HTTP request. A multi-step Agent loop can
make several such requests, so a request-level timeout alone does not enforce
the configured whole-task wall-clock budget.

## Decisions

1. Add a `task_runs` table to the `/tmp` SQLite database. Store only request ID,
   task kind, status, provider/model, aggregate token counts, duration, optional
   normalized error code, and creation time.
2. Do not give the task-store API fields for prompts, responses, tool
   arguments, or reasoning. Apply fixed byte limits to every text field.
3. Bound retention with `storage.max_task_records`; prune oldest rows in the
   same transaction as each insert. The existing SQLite page and total `/tmp`
   budgets remain the outer limits.
4. Expose metadata through `mbed-agent task history`, limited to 1–100 rows per
   request. Validate request IDs before they can become audit keys.
5. Wrap the complete multi-step Agent loop in
   `runtime.task_timeout_secs`. A deadline cancels the in-flight provider
   future, returns a resource-exhausted response, and records a `timed_out`
   outcome.
6. Audit successful, provider-failed, policy-rejected, resource-exhausted, and
   timed-out `ask` tasks. Preflight rejections that never start an Agent task
   remain ordinary protocol errors.

## Consequences

Operators can inspect bounded per-boot task health and token usage without
retaining conversation content. The total task deadline now caps cumulative
provider turns and local tool work, while individual provider and tool timeouts
remain narrower safeguards. The ledger is not durable audit storage and is
intentionally lost on daemon host reboot or `/tmp` cleanup.
