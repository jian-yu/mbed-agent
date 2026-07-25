# ADR 0022: Boot-bound administrator elevation

- Status: Accepted
- Date: 2026-07-25

## Context

Every authenticated Channel actor must be able to request `device-admin`
authority without trusting the Channel type itself. Embedded OpenWrt images
often lack PAM, and reading system shadow data would couple the agent to
platform-specific account policy. Passwords and elevated capabilities must not
enter volatile SQLite, logs, model context, or telemetry.

Wall-clock time can move backwards on small devices before NTP converges.
Capabilities that survive a daemon restart would also outlive the process that
authenticated and authorized them.

## Decisions

1. Use an agent-specific administrator password verifier encoded as
   `pbkdf2-sha256$iterations$salt$digest`. Salt is 128 random bits, the digest is
   256 bits, and iteration counts below 100,000 or above 2,000,000 are rejected.
   The CLI generator currently uses 200,000 iterations.
2. Read passwords only from stdin. Passwords are never command-line arguments.
   Protocol secret values have redacted `Debug` output, and plaintext CLI,
   serialized IPC, daemon frame, and verification buffers are zeroized after
   use.
3. Require mode `0600` or stricter for any existing configuration that enables
   authentication or an LLM credential.
4. Bind a capability to the verified actor ID, daemon boot ID, and monotonic
   expiration. Keep capabilities only in daemon RAM; never store them in
   SQLite. A daemon or device restart therefore revokes every capability.
5. Count failures and lock out independently per actor. One malicious or broken
   Channel actor cannot deny local CLI or another Channel actor access.
6. Return one generic unauthorized response for wrong and temporarily locked
   credentials. Logs contain only the actor and success/failure outcome.
7. The local Unix-socket command derives the fixed actor `cli/local`; it does
   not accept a caller-supplied actor ID. Future Channel adapters must derive
   actor IDs from fields authenticated by their official transport.

## Consequences

OpenWrt 21.02+ and generic Linux share one small authentication implementation
without PAM or shadow-file dependencies. Changing the administrator password is
a deliberate configuration/Flash write, while authentication itself writes no
Flash and no database rows.

This slice grants and checks a boot-bound role but does not by itself authorize
a configuration mutation. ChangeSet approval-token issuance, rollback arming,
and typed execution backends remain mandatory before actual write APIs become
available.
