# ADR 0029: Fresh OpenWrt firewall inventory

- Status: Accepted
- Date: 2026-07-28

## Context

Typed mutation planning and UCI staging existed, but the planner still required a
trusted `FirewallInventory` supplied by its caller. A public apply path cannot
trust a caller-provided before-state: it must inspect the device immediately
before planning and again before applying. UCI output also contains anonymous
sections, list values, vendor extensions, and configuration objects outside the
Agent's typed model.

Using a shell parser or silently approximating unsupported rules would make
object digests and rollback decisions unreliable. Considering only typed
bindings would also allow a deterministic new section name to collide with an
unsupported vendor section.

## Decisions

1. Parse bounded `uci show firewall` output without invoking a shell. Limit the
   snapshot to 256 KiB, 4096 lines, 256 sections, 128 options per section, 64
   values per option, and 1024 bytes per value. Reject quoting escapes,
   duplicates, malformed anonymous selectors, control characters, and overflow.
2. Preserve declaration order and multi-value options. Reconstruct typed zones,
   forwardings, filter rules, address sets, redirects, source NAT, and
   masquerade rules using the same field semantics as the UCI renderer.
3. Resolve zone defaults from the single UCI `defaults` section. Multiple or
   malformed defaults are ambiguous and fail closed.
4. Classify sections created with the exact `mbed_<kind>_<16 hex>` marker as
   `AgentOwned`; represent compatible native sections as `PlatformNative`.
   Unsupported platform-native and vendor sections remain explicitly read-only.
   Any reserved `mbed_` section that cannot be represented exactly aborts the
   inspection as managed-state drift.
5. Produce typed inventory, exact section bindings, every occupied selector, and
   read-only selectors in one immutable snapshot. Its fields are private so an
   external executor cannot assemble or mutate a forged snapshot.
6. Expose only snapshot-based OpenWrt rendering outside platform internals. The
   renderer revalidates every plan before/after object and digest against the
   snapshot, rejects duplicate touches and stale or fabricated plans, and
   reserves every existing section name before deterministic create naming.
7. Preserve unknown options on supported existing sections. Updates remove and
   replace only the documented typed option set.

## Consequences

The future daemon planner can derive before-state and UCI identity from one
fresh device observation. Unsupported vendor configuration remains intact and
cannot be overwritten by a generated section collision. Manual drift of an
Agent-owned section blocks further writes until it is inspected and resolved.

This slice does not execute `uci`, write `/etc/config/firewall`, or reload the
firewall. The daemon execution coordinator, second pre-apply inspection,
rollback watchdog, verification, and confirmed commit remain mandatory.
