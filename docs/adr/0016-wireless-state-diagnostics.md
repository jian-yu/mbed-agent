# ADR 0016: Cross-platform wireless state diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

Wireless failures require radio, interface, mode, channel, and configured-SSID
evidence. OpenWrt exposes logical wireless state through ubus, while generic
Linux commonly exposes kernel wireless interfaces through `iw`. Small OpenWrt
images may provide only `iwinfo`. Active scanning would consume airtime and is
not an R0 operation.

SSID values and AP MAC addresses are unnecessary for the initial model-level
assessment and can identify a user or location.

## Decisions

1. Add `mbed-agent diagnose wireless` for OpenWrt and generic Linux.
2. On OpenWrt with ubus, collect `ubus call network.wireless status`. Add one
   passive fallback/augmentation collector: prefer `iw dev`, otherwise
   `iwinfo`. Generic Linux uses the same `iw`/`iwinfo` selection without ubus.
3. Never run scan, connect, disconnect, reload, or configuration commands.
4. Normalize at most 16 radios and 32 interfaces. Radio fields are up, pending,
   disabled, and channel. Interface fields are bounded name, radio, mode,
   locally retained SSID, channel, and frequency.
5. Add `inspect_wireless_radios` and `inspect_wireless_interfaces`, backed by
   one cached snapshot.
6. Omit SSID values and all AP/station MAC addresses from LLM observations.
   Expose only `ssid_configured` plus mode/channel/frequency. Preserve bounded
   SSID values only in the immediate local response and volatile SQLite summary.
7. Shrink model projections to `llm.max_tool_context_bytes` and mark
   `context_truncated`.
8. Add `iw` to platform capability discovery; neither `iw` nor `iwinfo` is a
   daemon startup requirement.

## Consequences

The Agent can distinguish missing, disabled, and configured wireless state on
OpenWrt 21+ and ordinary Linux without changing RF behavior. This slice does
not prove client connectivity, RF quality, authentication success, or internet
reachability; those require bounded station/link tools and explicit active
diagnostics in later slices.
