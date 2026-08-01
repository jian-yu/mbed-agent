# ADR 0048: Independent generic Linux runtime route rollback

- Status: Accepted
- Date: 2026-08-01

## Context

ADR 0047 completed the native route transaction but deliberately kept daemon
admission closed because its reverse batch was not yet executable by the
out-of-process watchdog. Recovery must also restore the correct network
canonical state without confusing it with generic firewall canonical state.

## Decisions

1. Add dedicated rollback targets for the generic Linux reverse route batch and
   network canonical snapshot, plus a `LinuxNetworkRoutesRuntime` recovery kind.
2. Create the bundle before activation with the exact reverse batch and optional
   prior network canonical payload. Store both as mode-0600 files below the
   private `/tmp` rollback directory with independent SHA-256 digests and an
   aggregate byte limit.
3. Treat route batch and network canonical artifacts as runtime-only. They are
   validated but never resolved to or installed at persistent filesystem paths.
4. After digest validation, the independent helper resolves only the fixed `ip`
   executable and runs `ip -force -batch <verified snapshot>`. Force mode lets
   recovery continue after a missing object caused by partial forward apply;
   non-zero final status still marks rollback failure.
5. Extend canonical recovery results with an explicit network domain. The helper
   restores or clears the separate `network_runtime_state_v1` SQLite key only
   after native rollback reports success. Firewall and network canonical keys
   cannot be substituted for one another.
6. Retain the existing first-decision-wins confirm/rollback markers, timeout,
   durable outcome, command timeout, clean environment, and immediate rollback
   behavior.

## Consequences

The generic Linux runtime route transaction now has an out-of-process recovery
artifact that survives daemon failure while the device remains booted. Neither
the native route state nor canonical state writes Flash. Daemon admission still
requires a final execution-port slice to atomically coordinate ChangeSet state,
canonical replacement, helper spawning, confirmation, and immediate rollback.
