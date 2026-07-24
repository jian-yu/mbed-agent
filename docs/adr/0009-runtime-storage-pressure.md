# ADR 0009: Runtime storage pressure admission

- Status: Accepted
- Date: 2026-07-24

## Context

SQLite and logs already have independent hard limits, and configuration reserves
budgets for artifacts and rollback state. The daemon previously reported `/tmp`
pressure but did not act on it, and `storage.cleanup_interval_secs` did not drive
a cleanup loop. A constrained device could therefore continue accepting tasks
after unrelated processes or managed artifacts consumed the remaining tmpfs.

Cleanup must not endanger a pending rollback or follow attacker-controlled
symbolic links. Its own memory usage must remain bounded even if an artifact
directory contains unexpectedly many files.

## Decisions

1. Classify managed usage at 70% as `pressure`, 85% as `critical`, and 95% as
   `emergency`. A configured absolute or percentage free-space reserve also
   causes `critical`; reserve violation below 1 MiB is `emergency`.
2. Before starting an LLM or diagnostic task, inspect managed bytes and
   filesystem reserves in a blocking worker. Allow `normal` and `pressure`;
   reject new work at `critical` or `emergency`.
3. On critical admission, attempt artifact cleanup once and re-check pressure.
   Keep recovery/control requests—ping, status, capabilities, diagnostic
   history, and task history—available.
4. Run artifact cleanup before opening SQLite at daemon startup and then every
   `storage.cleanup_interval_secs`, skipping missed timer ticks.
5. Restrict deletion to direct regular-file children of the daemon-owned
   `/tmp/.../artifacts` directory. Ignore symlinks, subdirectories, and
   non-regular files. Never delete rollback state, SQLite/WAL/SHM, logs,
   sockets, or configuration.
6. Enforce both `storage.max_artifacts_bytes` and
   `storage.max_artifact_files`. Keep at most 4096 artifact candidates in a
   fixed-size heap and default to 64, so cleanup metadata memory is bounded.
   Prefer the newest files and remove older files first.
7. Re-check storage before the Agent's first local evidence snapshot, because
   external tmpfs usage may change while a provider request is in flight.

## Consequences

The daemon now degrades by refusing new work instead of consuming the final
tmpfs reserve. Operators can still inspect status and history to recover the
device. Artifact cleanup is intentionally narrow; it cannot solve pressure
caused by unrelated processes or protected rollback data, so admission remains
closed until pressure falls. Future artifact writers must treat files as
evictable runtime cache and remain within this same directory and budget.
