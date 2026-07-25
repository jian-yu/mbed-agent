# ADR 0017: Bounded interface counter diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

RX/TX byte, packet, error, and drop counters are basic evidence for network
fault diagnosis on both OpenWrt and generic Linux. They are cumulative kernel
counters, however, so one observation cannot establish a current throughput,
loss, or error rate. Periodic sampling would add scheduler, memory, storage, and
model-context costs that are not justified for the first read-only slice.

Small devices can also expose many virtual interfaces. Counter evidence must be
bounded before it reaches local IPC, volatile history, or an LLM.

## Decisions

1. Add `mbed-agent diagnose interface-stats` using exactly one typed
   `ip -j -s link show` collector. It is passive and valid on OpenWrt 21+ and
   generic Linux.
2. Parse `stats64` when present and fall back to legacy `stats`. Normalize at
   most 32 interfaces with name, operational state, and cumulative RX/TX bytes,
   packets, errors, and drops.
3. Treat any nonzero error/drop counter as evidence that such events occurred
   since the kernel counter was reset. Never infer that errors are occurring
   now or calculate a rate from one snapshot.
4. Add `inspect_interface_counters` and `inspect_interface_errors`. Both reuse
   one in-memory snapshot per Agent request; the latter includes only interfaces
   with nonzero cumulative error/drop counters.
5. Persist only the normalized bounded summary in `/tmp` SQLite. Raw `ip`
   output remains local to the immediate command and is never persisted.
6. Shrink model observations to `llm.max_tool_context_bytes`, report the
   original source count, and mark `context_truncated` when entries are removed.

## Consequences

The Agent gains low-cost counter evidence across the supported platform range
without creating background sampling state or writing Flash. It can identify
interfaces whose cumulative counters deserve investigation, but it cannot
diagnose present packet rate, utilization, burst loss, or counter deltas. Those
require an explicitly bounded multi-snapshot performance diagnostic in a later
slice.
