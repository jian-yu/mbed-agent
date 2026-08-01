# ADR 0045: Generic Linux runtime network inventory boundary

- Status: Accepted
- Date: 2026-08-01

## Context

The OpenWrt UCI adapter can bind an object to an identifiable persistent
section. Generic Linux kernel state may instead be controlled by
NetworkManager, systemd-networkd, a distribution script, a vendor supervisor,
or manual commands. Reading netlink state does not establish which manager owns
the persistent configuration, so reusing the OpenWrt write path would be unsafe.

## Decisions

1. Extend `change network-inventory` to generic Linux when iproute2 is present.
   Collect only fixed, shell-free `ip -j link show`, `ip -j address show`, and
   `ip -j route show table all` observations with existing timeout and byte
   limits.
2. Reconstruct the safely representable interface and route subset as typed
   platform-native objects. Dynamic address flags determine DHCP/automatic
   modes, but dynamic lease addresses are not represented as desired static
   addresses. The current link-layer address is not claimed as a configured MAC
   override.
3. Give routes deterministic content-derived identities. Reject duplicate
   identities, malformed top-level observations, invalid typed objects, and
   capacity overflow. Omit ambiguous multipath and unsupported route types.
4. Keep generic Linux `network-plan` and apply closed. A write adapter must first
   identify a single controlling backend and define ownership, validation,
   activation, verification, and independent rollback semantics.

## Consequences

Ordinary Linux devices now expose the same fresh typed inventory and exact
object digests as OpenWrt without claiming unsafe write support. The inventory
is suitable for diagnosis, backend selection, and future stale-plan binding.
Persistent writes remain unavailable until a NetworkManager, systemd-networkd,
or explicitly volatile Agent-owned runtime adapter satisfies the full
confirmed-commit contract.
