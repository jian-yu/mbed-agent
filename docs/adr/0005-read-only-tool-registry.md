# ADR 0005: Read-only network tool registry

- Status: Accepted
- Date: 2026-07-24
- Extends: ADR 0004

## Context

The first Agent loop exposed one broad WAN diagnostic. A network specialist
often needs a narrower route, DNS, or firewall answer. Running the same passive
collectors for each model tool would waste CPU, process slots, and context bytes
on small devices.

## Decisions

1. Replace the single-tool constructor with a closed read-only registry:
   `diagnose_wan`, `inspect_default_routes`, `inspect_dns`, and
   `inspect_wan_firewall`.
2. Give every tool an empty-object schema with `additionalProperties=false`.
   Continue to enforce the name, argument byte limit, JSON object shape, and
   empty argument set locally.
3. Collect at most one passive WAN report per Agent request. Cache it only in
   memory for the lifetime of that `ask` and reuse it across subsequent tool
   steps.
4. Project a different bounded observation for each tool:
   - WAN: normalized summary and findings.
   - Routes: normalized IPv4/IPv6 default routes and source.
   - DNS: normalized resolver addresses and passive readiness.
   - Firewall: detected backend and normalized WAN zone policies.
5. Never expose raw probe output in model context. Persist one normalized
   snapshot audit record in volatile SQLite regardless of how many registry
   tools reuse it.
6. Keep the registry semantic names deliberately narrow. Route inspection does
   not claim to return every route, and firewall inspection does not claim to
   return the full ruleset.

## Consequences

The model can ask focused follow-up questions without repeatedly spawning the
same collectors. The four tools remain passive and share the same timeout,
semaphore, context-size, Agent-step, and `/tmp` audit limits. Broader interface,
DHCP lease, neighbor, Wi-Fi, and full firewall-rule tools still require their
own normalized data models rather than exposing raw command output.
