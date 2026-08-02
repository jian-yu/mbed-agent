# ADR 0050: Declarative user and vendor extension actions

- Status: Accepted
- Date: 2026-08-02

## Context

Compiled typed commands provide a strong safety boundary but requiring a Rust
change for every vendor collector or user diagnostic makes device adaptation
unnecessarily slow. The extension boundary must remain resource-bounded and
must not turn model-generated text into an unrestricted root shell.

## Decisions

1. Add an optional ActionSpec registry loaded from direct `.toml` files in
   configured vendor and administrator directories. Missing directories are
   harmless; symlinked, incorrectly owned, or group/world-writable directories
   and manifests fail closed. File count, file size, action count, argv, input,
   output, and timeout limits are configuration-bound.
2. Each action declares an identifier, description, read-only mode, supported
   platforms, one absolute non-`/tmp` executable, a fixed argv template, and
   typed string/integer/boolean inputs. Unknown fields, duplicate identifiers,
   unused inputs, extra runtime inputs, type mismatches, and out-of-range values
   are rejected.
3. Expand inputs only into separate argv elements and execute without a shell,
   environment, stdin, or caller-selected working directory. Re-resolve the
   executable immediately before every run and reject incorrectly owned,
   writable, or `/tmp` targets. Manifest and executable trusted owner UIDs are
   separately configurable and default to root. Bound concurrency, runtime,
   stdout, and stderr.
4. Permit trusted shell scripts only as a fixed script path passed to a known
   shell executable. Reject `sh -c` and `sh -lc`; the model cannot provide a
   command string. Action inputs are explicitly non-secret because argv may be
   visible through the operating system.
5. Load manifests on daemon startup and provide an atomic device-admin reload.
   A failed reload leaves the existing in-memory registry active.
6. Expose list/run through the versioned local protocol and the same binary.
   Store only bounded execution metadata in volatile SQLite, never stdout,
   stderr, manifest bodies, or inputs.
7. Keep model exposure opt-in per manifest. Only read-only `llm_enabled`
   actions become dynamic `ext_*` tools; their JSON schema comes from the same
   input definition used for local validation, and returned context is bounded
   again by the LLM tool-context limit.
8. Do not accept writable extension actions in this slice. Future writes must
   produce typed plans and use the ChangeSet approval/validation/rollback
   lifecycle or an explicitly irreversible R4 break-glass boundary.

ADR 0051 subsequently adds declarative change templates that produce existing
typed firewall/network plans. It does not relax the external-program boundary
defined here.

## Consequences

Users and manufacturers can add bounded device-specific diagnostics without
rebuilding the agent. The trusted manifest author controls what program is
available, while runtime callers and the LLM control only typed arguments.
This improves adaptability without making raw shell the default execution API.
