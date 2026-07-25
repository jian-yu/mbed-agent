# ADR 0012: Bounded ARP and NDP neighbor diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

Interface and route state cannot show whether a device resolved its next hop or
a same-link peer. The kernel neighbor cache is useful for diagnosing gateway,
ARP, and IPv6 NDP failures, but querying it must not generate traffic or expose
an unbounded number of entries on a constrained system.

Link-layer addresses are useful to a local administrator but are device
identifiers that are unnecessary for most model reasoning.

## Decisions

1. Add `mbed-agent diagnose neighbors` and the LLM-visible
   `inspect_neighbors` typed tool for both OpenWrt and generic Linux.
2. Run only the allowlisted `ip -j neighbor show` collector under the existing
   timeout and output-byte limits. Never ping, send an ARP/NDP probe, or
   otherwise populate the cache.
3. Accept only valid IPv4/IPv6 destinations, bounded interface names, validated
   link-layer address syntax, and known kernel neighbor states. Normalize state
   names to uppercase.
4. Retain at most 64 unique entries and four states per entry. Report collector
   or normalized truncation and do not claim the result is complete.
5. Report `resolution_failures_present` when any retained entry is `FAILED` or
   `INCOMPLETE`. This is evidence, not a root-cause claim; stale cache entries
   may be unrelated to the user's current traffic.
6. Preserve validated link-layer addresses in the local protocol and volatile
   SQLite summary, but omit them from LLM tool observations.
7. Cache a neighbor snapshot independently during one Agent task. If the
   sanitized observation exceeds `llm.max_tool_context_bytes`, remove trailing
   entries and set `context_truncated`.

## Consequences

Operators and the Agent can distinguish missing L2/L3 neighbor resolution from
route absence without active traffic. The feature has one bounded process and
fixed normalized cardinality. Minimal images without JSON-capable `ip` return
insufficient evidence; a future native netlink collector still requires
measured ROM/RSS justification.
