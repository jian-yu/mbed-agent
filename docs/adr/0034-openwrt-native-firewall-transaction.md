# ADR 0034: OpenWrt native firewall transaction

- Status: Accepted
- Date: 2026-07-31

## Context

OpenWrt typed inventory and UCI rendering were non-executing. A concrete
execution port must preserve vendor configuration, validate fw3/fw4 semantics,
detect concurrent writers, and ensure no persistent write occurs before the
independent rollback helper is armed.

## Decisions

1. Introduce one stateful native transaction with the closed order `new ->
   inspected -> staged -> validated -> activated -> verified`. Out-of-order
   methods fail closed.
2. Revalidate the complete executable plan, read the root-owned regular
   `/etc/config/firewall` file with `O_NOFOLLOW`, run fixed `uci -q show
   firewall`, reconstruct typed inventory, project the approved before/after
   objects, and render only from that fresh snapshot.
3. Create a private per-ChangeSet staging directory below the configured
   `/tmp` runtime root. Reject unsafe runtime roots and symlinked directories;
   never recursively create through an unchecked parent.
4. Copy the source file into staging, send the bounded generated batch directly
   to `uci -c <stage> batch`, inspect the staged package again, and require its
   typed inventory to equal the approved projection.
5. Run every declared `fw3 -4/-6 print` or `fw4 check` action against the
   staging directory through the closed command runner.
6. Expose activation only after native validation and name it
   `activate_after_rollback_armed`. Immediately before installation, compare
   both raw live UCI output and the source-file SHA-256 digest with the inspected
   values. Any concurrent drift aborts before a Flash write.
7. Install through a create-new same-directory temporary file, preserve mode,
   fsync file and directory, atomically rename, and invoke only the fixed
   firewall reload action. The execution coordinator is responsible for having
   armed the independent rollback helper first.
8. Reinspect live UCI after reload and compare normalized typed inventory with
   the approved projection. Always remove `/tmp` staging on discard or drop.

## Consequences

The OpenWrt backend now has a concrete path that can perform an actual atomic
configuration write, but it is not yet exposed directly to CLI or Channels.
The daemon execution port must first connect ChangeSet state persistence,
approval consumption, rollback-helper spawning, and confirmation to this
native transaction.
