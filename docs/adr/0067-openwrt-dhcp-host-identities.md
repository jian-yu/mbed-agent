# ADR 0067: OpenWrt DHCP host identities and tags

## Status

Accepted and implemented.

## Decision

Extend the Agent-owned IPv4 static lease typed object with three bounded host
attributes:

1. `duid` is an optional bounded DHCPv6 client identifier.
2. `hostid` is an optional 1–32 character hexadecimal DHCPv6 host identifier.
3. `tags` is a deduplicated list of at most eight safe dnsmasq tag names.

The OpenWrt adapter reads and writes these values as `duid`, `hostid`, and
`tag` options in the marked `host` section. Updates delete and recreate only
these typed options; unknown vendor options remain untouched. Any malformed
managed value, duplicate tag, excessive list, or unsafe character fails closed
before staging. The fields use serde defaults so existing plans and `/tmp`
state remain backward compatible.

## Consequences

DHCP host matching can now cover common DHCPv6 clients and dnsmasq policy tags
without exposing raw UCI or shell input. The feature remains OpenWrt-native;
generic Linux DHCP configuration is unchanged and remains adapter-gated.
