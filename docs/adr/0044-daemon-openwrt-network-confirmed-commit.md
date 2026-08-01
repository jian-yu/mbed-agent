# ADR 0044: Daemon admission for OpenWrt network confirmed commit

- Status: Accepted
- Date: 2026-08-01

## Context

ADR 0043 completed the native OpenWrt network transaction and independent
rollback mechanics but deliberately left daemon and CLI admission closed. The
public boundary must preserve the existing exact-plan approval guarantees and
must not introduce a direct UCI or shell escape hatch.

## Decisions

1. Add `network-inventory` and `network-plan` to the same `mbed-agent` binary
   and versioned local protocol. Requests contain only closed typed mutations.
2. Admit writes only on supported OpenWrt 21.02+ systems. Generic Linux remains
   read-only for L2/L3 until an equally bounded native transaction exists.
3. Plan against a freshly reconstructed `uci show network` inventory. Bind the
   visible preview and typed executable payload to the exact plan digest and
   boot ID in volatile SQLite under a distinct `network` domain.
4. Elevate every public OpenWrt network write to R3. Device-admin elevation, an
   exact one-use approval, serialized execution, independent rollback, live
   typed verification, and explicit confirmation are therefore mandatory.
5. Reuse the fixed-command runner and the ADR 0043 transaction. No request can
   supply commands, arguments, paths, UCI text, or a replacement payload at
   apply time.
6. Upgrade the volatile execution-plan table to accept the `network` domain
   while preserving existing firewall records. No persistent migration data is
   written outside the configured `/tmp` SQLite database.

## Consequences

The daemon now exposes rollback-safe OpenWrt L2/L3 configuration through the
same authorization lifecycle as firewall changes. Daemon death, client loss,
reload failure, verification failure, and missed confirmation all retain a
recovery path independent of the daemon. Generic Linux write support remains a
separate backend task rather than an unsafe reuse of OpenWrt semantics.
