# ADR 0014: Bounded policy-routing diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

Default-route inspection is insufficient for Multi-WAN, VPN, container, and
OpenWrt mwan3 failures. Linux policy rules may select alternate tables by
source, destination, mark, or interface. Sending every route to an LLM would
consume excessive context and disclose more topology than required.

## Decisions

1. Add `mbed-agent diagnose policy-routing` on OpenWrt and generic Linux.
2. Run only `ip -j rule show` and `ip -j route show table all` through the
   existing fixed executable allowlist, timeout, and output-byte limits.
3. Retain at most 64 policy rules. Normalize priority, validated source and
   destination selectors, target table, action, validated fwmark, and bounded
   incoming/outgoing interface names.
4. Aggregate at most 32 route tables by route count, default-route count, and
   exceptional blackhole/unreachable/prohibit/throw count. Do not retain
   individual non-default routes in the summary.
5. Normalize numeric Linux table IDs 255, 254, and 253 as local, main, and
   default. Report `custom_policy_present` only for non-default tables,
   selectors, marks, interfaces, or non-lookup actions.
6. Expose `inspect_policy_rules` and `inspect_route_tables` as separate Agent
   tools backed by one cached snapshot.
7. Store only the bounded summary in volatile SQLite. Shrink either model
   projection to `llm.max_tool_context_bytes` and mark `context_truncated`.

## Consequences

The Agent can detect policy-based routing that explains why a valid main-table
default route is not used. The report does not simulate kernel route selection,
resolve mwan3 configuration intent, or modify rules/tables. Those require
separate typed analysis and, for changes, the Phase 2 approval/rollback path.
