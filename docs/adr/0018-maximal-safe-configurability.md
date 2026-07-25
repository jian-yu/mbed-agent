# ADR 0018: Maximal safe configurability

- Status: Accepted
- Date: 2026-07-25

## Context

The original roadmap described a small set of controlled OpenWrt changes. That
could lead to isolated commands such as “block one MAC address” while leaving
related firewall, network, DNS/DHCP, wireless, and generic-Linux operations
read-only or inconsistent.

Mbed Agent is intended to be a professional network operator. It should expose
as much useful configuration as the detected device can safely support, without
giving an LLM a root shell or raw configuration language.

## Decisions

1. Configuration is a cross-domain platform capability, not a collection of
   special-case commands. Supported domains target firewall, L2/L3 network,
   DNS, DHCP, wireless, controlled services, QoS, and WireGuard.
2. Each writable domain provides typed inspect, plan, create, update, delete,
   validate, verify, and rollback operations. Ordered objects also provide a
   typed move operation.
3. The effective writable surface is the intersection of the product schema,
   runtime platform capabilities, local policy, object ownership, resource
   budget, and actor authorization. Unsupported fields fail explicitly.
4. Risk is computed from the semantic diff and current management path. An LLM
   cannot specify or lower risk. Changes that widen exposure or may interrupt
   management are elevated to R3 and require a one-use, plan-bound
   `device-admin` approval.
5. OpenWrt changes use UCI and the native fw3/fw4, netifd, dnsmasq/odhcpd,
   hostapd, and service control planes. MAC restrictions are ordinary typed
   firewall matches, not a dedicated implementation.
6. Generic Linux changes use supported native adapters and objects explicitly
   owned by Mbed Agent. nftables tables/chains/sets, iptables chains/ipsets,
   network-manager fragments, service drop-ins, and `tc` objects not owned by
   the Agent are read-only by default.
7. All writes use the same ChangeSet lifecycle: fresh inspection, typed desired
   state, semantic diff, dynamic risk, bounded snapshot, staging, native
   validation, plan-bound approval, independently armed rollback, apply,
   verification, and confirmation.
8. If a device cannot provide safe validation, ownership isolation, or rollback
   for an operation, the Agent returns a structured unsupported-capability
   result and offers read-only guidance. It never falls back to raw shell, raw
   nft/iptables/UCI arguments, or arbitrary file editing.

## Consequences

The initial writable slice is larger because it must establish a reusable
authorization and transaction substrate before adding domain-specific backends.
After that foundation, new configuration domains share one safety model and can
be delivered as complete vertical slices.

The product can configure substantially more than a set of fixed buttons while
remaining predictable on small devices. “Maximum configurability” remains
bounded by explicit capabilities and recoverability; it does not mean arbitrary
root access or mutation of third-party managed state.
