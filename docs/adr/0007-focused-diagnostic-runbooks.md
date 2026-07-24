# ADR 0007: Focused DNS and route diagnostic runbooks

- Status: Accepted
- Date: 2026-07-24

## Context

The first deterministic CLI runbook returned a comprehensive WAN report.
Operators still needed LLM interpretation or manual JSON inspection for narrow
DNS and default-route questions. Re-running every WAN collector for such a
question would waste process slots and I/O on constrained devices.

The same runbooks must work on OpenWrt 21.02+ and generic Linux without treating
OpenWrt-only commands as universal dependencies.

## Decisions

1. Add typed `DnsDiagnosticReport` and `RouteDiagnosticReport` protocol
   responses and expose them as `mbed-agent diagnose dns` and
   `mbed-agent diagnose routes`.
2. Keep both focused runbooks passive. DNS readiness means that link, address,
   default route, and resolver configuration prerequisites are present; it does
   not mean an external query succeeded.
3. Share normalization with the WAN runbook while selecting collectors by
   scope:
   - DNS: OpenWrt WAN status when available, link, addresses, routes, and known
     runtime resolver files.
   - Routes: OpenWrt WAN status when available, link, addresses, routes, and
     policy rules.
   - WAN: all of the above plus firewall/UCI evidence.
4. Never run OpenWrt ubus or UCI collectors on generic Linux. Generic Linux
   continues to use kernel `ip -j` evidence and the supported runtime resolver
   paths.
5. Apply the existing diagnostic semaphore, per-command timeout, whole-task
   timeout, output byte limits, and `/tmp` SQLite retention. Store only each
   focused normalized summary in history, with kinds `dns` and `routes`.
6. Continue to use `WanAssessment` for the shared prerequisite failure
   vocabulary, but recompute assessment per scope so absent DNS data cannot
   make a healthy route report fail.

## Consequences

DNS and route prerequisites can now be diagnosed locally when no LLM or remote
channel is available. Narrow commands spawn fewer collectors than the broad WAN
runbook and produce stable typed output. Active resolver testing, per-resolver
queries, DHCP lease analysis, and policy-rule normalization remain separate
future runbooks rather than being inferred from passive evidence.
