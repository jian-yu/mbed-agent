# ADR 0019: Conntrack and qdisc capacity diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

Routers can fail to establish new flows when the kernel connection-tracking
table is full. Queueing disciplines also retain drop, overlimit, requeue, and
backlog counters that help identify where performance investigation should
continue. Both signals matter on OpenWrt and generic Linux.

Enumerating conntrack tuples would expose addresses and ports and can be
expensive on a busy embedded gateway. Continuously sampling qdiscs would add
background CPU and state, while one cumulative snapshot cannot prove a current
rate.

## Decisions

1. Add `diagnose conntrack`, reading only the bounded procfs scalar files
   `nf_conntrack_count` and `nf_conntrack_max`. Never read or expose individual
   connection tuples.
2. Classify utilization below 90% as healthy, 90% through below the configured
   limit as near capacity, and count greater than or equal to the limit as at
   capacity. Report missing or invalid scalar evidence explicitly.
3. Add `diagnose qdisc` using one typed `tc -j -s qdisc show` collector.
   Normalize at most 64 entries and accept both `stats` and `stats2` layouts.
4. Retain only device, qdisc kind, bounded topology identifiers, and cumulative
   byte, packet, drop, overlimit, requeue, backlog, and queue-length counters.
5. Add `inspect_conntrack_capacity`, `inspect_qdisc_stats`, and
   `inspect_qdisc_pressure`. The pressure tool filters out qdiscs whose drop,
   overlimit, requeue, and backlog counters are all zero. Both qdisc tools share
   one in-memory snapshot per Agent request.
6. Apply `llm.max_tool_context_bytes` shrinking to qdisc observations. Persist
   only normalized summaries in volatile SQLite; raw collector output remains
   in the immediate local response.
7. Never infer a current loss, congestion, or requeue rate from one qdisc
   snapshot. A later active performance runbook may take explicitly bounded
   timed samples.

## Consequences

The read-only Agent registry reaches 20 typed tools and gains two low-cost
performance-degradation signals without background sampling or Flash writes.
Devices without conntrack or `tc` return structured unavailable evidence rather
than failing daemon startup.
