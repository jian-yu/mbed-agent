# ADR 0023: Bounded independent rollback

- Status: Accepted
- Date: 2026-07-25

## Context

A network or firewall change can disconnect the session that requested it and
can also crash or stop the daemon. An in-process timer therefore cannot protect
the management path. Snapshot data must remain volatile and bounded, and a
privileged recovery process must not accept arbitrary paths or commands.

## Decisions

1. Store each rollback bundle below
   `/tmp/mbed-agent/rollback/<transaction-id>/`. Transaction IDs contain only
   bounded ASCII alphanumerics and hyphens. Directories are mode `0700`; journal,
   snapshot, confirmation, and outcome files are mode `0600`.
2. The manifest contains a schema version, exact transaction ID, 5-600 second
   timeout, at most eight typed targets, snapshot metadata, and one typed reload
   action. It never contains an executable or destination path.
3. Initially permit only the OpenWrt firewall UCI file and the generic Linux
   Agent-owned nftables file. Each target maps in compiled code to one fixed
   destination and one compatible fixed reload action. More domains require new
   enum variants and tests.
4. Enforce `storage.max_rollback_bytes` before a bundle is armed and again while
   the helper reads it. Refuse symlinks and non-regular files, use `O_NOFOLLOW`,
   hash every snapshot with SHA-256, and reject any digest, filename, target, or
   reload mismatch.
5. Write snapshots and the manifest with create-new semantics and `fsync`.
   Restore existing files through a same-directory temporary file, `fsync`, and
   atomic rename. If the target did not exist before the change, recovery
   removes only the exact compiled target.
6. Use the same executable in the hidden `rollback-helper` mode. It accepts only
   a transaction ID and validated agent configuration, waits independently of
   the daemon, and restores unless it sees the exact confirmation marker.
7. A confirmed transaction removes its volatile bundle. Recovery leaves either
   `rolled-back` or `rollback-failed`; a failed reload is distinguishable from a
   failed file restore. No rollback state is copied to Flash or SQLite.

## Consequences

The following firewall backend can arm a watchdog before its first persistent
write and remain protected if the main daemon exits. The helper is present but
is not spawned by any public write API yet; that API stays closed until typed
firewall planning and backend validation are connected.

The fixed target list intentionally prevents this mechanism from becoming a
general root file-replacement facility.
