# ADR 0013: Cross-backend firewall runtime diagnostics

- Status: Accepted
- Date: 2026-07-25

## Context

Detecting fw3, fw4, iptables, or nftables does not prove that a runtime ruleset
is loaded. Operators need table, chain, policy, rule, and counter evidence, but
individual firewall expressions can contain private addresses, ports, comments,
third-party chains, and arbitrary extensions. The Agent must not translate or
send those expressions to a model.

## Decisions

1. Add `mbed-agent diagnose firewall` for OpenWrt and generic Linux.
2. Select `nft -j list ruleset` for fw4/native nftables, and
   `iptables-save -c` plus `ip6tables-save -c` for fw3/native iptables. Execute
   exact argument arrays without a shell, under existing timeout/output limits.
3. Normalize only backend, table/chain/rule totals, rules containing counters,
   and at most 32 base chains with family, table, name, hook, policy, and rule
   count. Never normalize or persist match/action expressions.
4. Treat missing backends or inspection commands as `backend_unavailable`.
   Treat a successful zero-rule response as `empty_ruleset`; do not infer that
   traffic is blocked or allowed from counts alone.
5. Expose `inspect_firewall_runtime` and `inspect_firewall_base_chains` as two
   closed-schema Agent tools backed by one cached snapshot.
6. Keep raw command output only in the immediate local CLI response. Store only
   the bounded summary in `/tmp` SQLite and send only the normalized projections
   to the LLM.
7. If base-chain metadata exceeds `llm.max_tool_context_bytes`, remove trailing
   chains and set `context_truncated`.

## Consequences

The same diagnostic distinguishes a missing runtime firewall from a populated
ruleset across OpenWrt 21+ and ordinary Linux while preserving fw3/fw4
differences. It does not claim semantic equivalence, evaluate arbitrary
expressions, or modify/reload the firewall. Full rule analysis remains a
separate bounded parser and security-review task.
