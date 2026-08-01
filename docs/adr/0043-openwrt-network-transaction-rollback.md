# ADR 0043: OpenWrt network transaction and independent rollback

- Status: Accepted
- Date: 2026-08-01

## Context

ADR 0042 deliberately stopped after generating a private UCI staging artifact.
Installing `/etc/config/network` is more dangerous than an additive firewall
change because a successful netifd reload can immediately remove the active
management address or route. Daemon process survival cannot be the recovery
mechanism.

OpenWrt does not expose a complete no-side-effect netifd reload for a private
configuration directory. The transaction must therefore combine bounded UCI
parsing, typed staged-state verification, source-drift checks, atomic file
replacement, live verification, and an already armed independent watchdog.

## Decisions

1. Add fixed shell-free commands for live/staged `uci show network`, staged
   `uci export network`, and `/etc/init.d/network reload`. Paths and arguments
   are constructed locally and staging paths must resolve below the configured
   private runtime root.
2. Reinspect the live UCI output and the bounded regular
   `/etc/config/network` file in one transaction. Bind the approved executable
   plan to the reconstructed typed inventory and retain both the raw UCI bytes
   and source-file SHA-256 digest.
3. Copy the source file to a mode-0700 transaction directory under `/tmp`, run
   the bounded UCI batch, reconstruct the staged typed inventory, and require it
   to equal the approved projection before native validation.
4. Run `uci -c <dir> -q export network` as the fixed native syntax check. No
   claim is made that this simulates a netifd reload.
5. Immediately before installation, re-read live UCI and the source file and
   reject either form of drift. Install with a synced same-directory temporary
   file, atomic rename, and parent-directory sync, then run the fixed network
   reload.
6. Reinspect live UCI after reload and require the complete supported typed
   inventory to equal the approved projection. A separate verification entry
   point checks only objects touched by the plan for confirmed commit.
7. Extend the independent helper with the exact
   `OpenWrtNetwork -> /etc/config/network` target and `OpenWrtNetwork` reload.
   Recovery verifies the volatile snapshot digest, atomically restores the
   file, syncs it, and only then reloads the network service. Confirmation and
   immediate rollback retain the existing first-decision-wins protocol.
8. Keep daemon and CLI network write admission closed in this slice. The caller
   may invoke activation only after the helper bundle is durable and the helper
   process is running. The next slice must connect this port to the common R3
   approval, failure-triggered rollback, timeout, and confirmation lifecycle.

## Consequences

The OpenWrt L2/L3 backend now has a complete native transaction port and a
compatible out-of-process recovery target. Source drift, staged semantic drift,
reload failure, verification failure, daemon death, and missing confirmation
can all be routed into the same recovery protocol once daemon admission is
connected. No runtime database or rollback artifact is written to Flash.
