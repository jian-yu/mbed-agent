# ADR 0049: Daemon admission for generic Linux runtime routes

- Status: Accepted
- Date: 2026-08-01

## Context

ADRs 0045–0048 established bounded generic Linux network inventory, isolated
protocol-186 route ownership, a fixed `ip -batch` transaction, and independent
rollback. The remaining boundary is public daemon admission through the same
approved ChangeSet state machine used by other writable backends.

## Decisions

1. Select the generic runtime-route backend only on generic Linux with iproute2.
   OpenWrt continues to use its native UCI/netifd backend.
2. Expose ordinary interfaces and routes as read-only platform-native inventory.
   Omit protocol-186 routes from that reconstruction and merge them back only
   after exact reconciliation with the boot-bound network canonical state.
3. Plan generic Linux writes against only the reconciled Agent-owned route
   inventory. Accept create/update desired objects only when they are enabled
   Agent-owned routes; delete is restricted to the route kind and the
   planner still requires its fresh digest and Agent ownership.
4. Elevate every admitted generic route plan to R3. Require device-admin,
   one-use exact-plan approval, serialized execution, an independently armed
   reverse batch, live typed verification, and explicit confirmed commit.
5. Persist verified canonical ownership only in the bounded SQLite database
   under `/tmp`, capped independently by `storage.max_network_state_bytes`. The
   helper restores the prior network canonical state after native rollback.
   Neither route state nor canonical metadata is restored across device reboot
   or written to Flash.
6. Keep generic Linux interfaces, addresses, policy rules, platform-native
   routes, and persistent NetworkManager/systemd-networkd/vendor configuration
   outside this writable backend. Requests cannot supply commands, argv, paths,
   batch text, or replacement payloads at apply time.

## Consequences

Generic Linux devices can now safely create, update, delete, and confirm
Agent-owned volatile routes through the public CLI/daemon protocol. Daemon loss,
channel loss, activation failure, verification failure, or confirmation timeout
uses the same independent recovery protocol. Persistent generic Linux network
configuration remains a separate future adapter rather than being inferred
from ambiguous kernel state.
