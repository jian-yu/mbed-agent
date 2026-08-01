# ADR 0042: OpenWrt network fresh inventory and staging

- Status: Accepted
- Date: 2026-08-01

## Context

The platform-neutral L2/L3 planner cannot safely target OpenWrt by translating
objects from an old or independently collected inventory. Existing UCI sections
may be anonymous, include vendor extensions, or express semantics outside the
first writable subset. The `network` service also has no staging-mode reload
that can prove a candidate configuration without affecting live netifd state.

OpenWrt 21.02 introduced the current `config device` shape while deployments
still vary between DSA, swconfig, vendor extensions, and protocol packages.
Unsupported native syntax must remain visible but read-only.

## Decisions

1. Generalize the bounded UCI show parser to accept one fixed package name and
   reject mixed-package input, shell escapes, malformed quoting, duplicates,
   and size/cardinality overflow.
2. Reconstruct supported `interface`, `device` bridge, explicit 802.1Q/802.1ad
   VLAN device, `route`/`route6`, and `rule`/`rule6` objects and their exact UCI
   selectors from the same fresh `uci show network` snapshot.
3. Treat unknown or incompletely represented platform-native sections as
   read-only. An Agent-owned section that cannot be decoded exactly fails the
   entire inspection closed.
4. Mark Agent-owned sections with `mbed_managed=1` and retain a stable
   `mbed_id`. Updating a platform-native section does not add those markers and
   therefore cannot silently claim ownership. Unknown vendor options are not
   deleted during supported updates.
5. Bind update, delete, and policy-priority move to the exact fresh section and
   typed before-object digest. Reserve every occupied selector before deriving
   deterministic Agent section names, including unsupported sections.
6. Render only a bounded `uci -c <private-/tmp-dir> batch` artifact. Candidate
   syntax validation is fixed to `uci -c <dir> export network`; no executable,
   arguments, paths, or raw UCI fragments come from the caller.
7. Narrow OpenWrt routes to an explicit logical interface and tables at most
   65535. Options not represented by the product schema, including route
   `onlink`/MTU, advanced IP-rule selectors, interface delegation/table
   controls, protocol credentials, DSA `bridge-vlan`, and swconfig sections,
   remain read-only.
8. Do not install the staged file or reload the network service in this slice.
   Live admission requires semantic preflight, a bounded snapshot, independent
   rollback, verification, and confirmed commit capable of recovering a lost
   management path.

## Consequences

OpenWrt 21+ now has a tested fresh inventory and deterministic staging boundary
for the first L2/L3 subset without a raw command escape hatch. DSA bridge VLAN
membership, swconfig switch VLANs, bond, VRF, advanced DHCP/IPv6 delegation,
and live apply remain explicitly unavailable until their typed capabilities and
recovery contracts are implemented.

## References

- [OpenWrt network configuration](https://openwrt.org/docs/guide-user/network/network_configuration)
- [OpenWrt UCI networking options](https://openwrt.org/docs/guide-user/network/ucicheatsheet)
- [OpenWrt static routes](https://openwrt.org/docs/guide-user/network/routing/routes_configuration)
- [OpenWrt VLAN configuration](https://openwrt.org/docs/guide-user/network/vlan/switch_configuration)
