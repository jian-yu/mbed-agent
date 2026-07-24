# ADR 0010: Fixed-memory log rate limiting

- Status: Accepted
- Date: 2026-07-24

## Context

Log levels, line truncation, file rotation, and total byte limits were active,
but `logging.rate_limit_per_target_per_sec` was not enforced. A reconnect loop
or failing probe could therefore consume CPU and rotate the complete volatile
log history in seconds even though disk usage stayed within its cap.

The log path is under `/tmp`, where another local process could attempt to
replace it with a symbolic link. Following that link could violate the rule that
runtime logs never write to Flash or unrelated paths.

## Decisions

1. Apply a one-second fixed-window limit to tracing metadata targets before
   allocating the per-record line buffer.
2. Keep at most 64 hashed target counters. Additional targets share one bounded
   overflow bucket. Hash collisions only make the limit more conservative.
3. Require `logging.rate_limit_per_target_per_sec` to be greater than zero.
   The existing level `off` remains the explicit way to disable logging.
4. Silently discard over-limit records and increment an in-memory saturating
   counter. Do not emit a log about a dropped log, which could recurse.
5. Expose the cumulative counter as `logging_dropped_records` in daemon status
   and add a degraded reason after the first drop. Reset it only on daemon
   restart.
6. Open the active log with mode `0600` and `O_NOFOLLOW`; correct overly broad
   permissions through the opened file descriptor. Refuse active or rotated
   paths that are not regular files.
7. Preserve the existing line, file, rotation-count, total-directory, and
   `/tmp` aggregate limits. Rate limiting is an additional CPU/history
   protection, not a replacement for byte caps.

## Consequences

A single noisy module cannot monopolize log writes indefinitely, and target
accounting has a small fixed memory footprint. Operators can detect suppression
through `status` without creating more log traffic. The first implementation
does not provide a separate burst allowance or hot-reloadable counters; those
can be added only if Channel soak tests demonstrate a need.
