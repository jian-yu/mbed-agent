# ADR 0011: Bounded cross-platform interface inventory

- Status: Accepted
- Date: 2026-07-25

## Context

WAN-focused evidence does not show secondary uplinks, bridges, VLAN devices, or
other interfaces that often explain routing and service-binding faults. OpenWrt
and generic Linux both expose kernel link and address state, so this capability
does not need an OpenWrt-only control-plane dependency.

An unrestricted interface dump is unsuitable for a small device: containers,
network namespaces, or faulty software can create many virtual links and
addresses. Raw output also must not be copied into model context.

## Decisions

1. Add `mbed-agent diagnose interfaces` and the LLM-visible
   `inspect_interfaces` typed tool.
2. Collect only `ip -j link show` and `ip -j address show` through the existing
   executable allowlist, process timeout, and retained-output limit. Do not run
   a shell, active probe, route query, firewall query, DNS query, UCI, or ubus.
3. Normalize name, index, kind, operational state, UP/carrier flags, MTU,
   master, validated IP prefixes, and whether an address is marked dynamic.
   Do not expose raw evidence to the model.
4. Retain at most 32 interfaces and eight addresses per interface. Reject
   oversized/control-bearing names and invalid IP addresses. Report normalized
   or collector truncation rather than silently claiming completeness.
5. Ignore loopback when assessing whether a usable interface exists. Treat an
   UP link, carrier, or assigned address as ready evidence; do not claim
   end-to-end connectivity.
6. Cache interface and WAN snapshots independently during an Agent task.
   Persist only the bounded interface summary in volatile SQLite.
7. If a complete interface observation does not fit
   `llm.max_tool_context_bytes`, remove trailing interfaces until it fits and
   set `context_truncated`; never exceed the configured model-context budget.

## Consequences

The same passive command works on supported OpenWrt and ordinary Linux systems
and can explain multi-interface topology without adding a platform-specific
parser. Minimal images whose `ip` command lacks JSON support receive
insufficient evidence; a future capability ADR may add a bounded native netlink
collector after ROM/RSS measurements.
