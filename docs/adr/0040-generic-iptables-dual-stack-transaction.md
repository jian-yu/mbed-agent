# ADR 0040: Generic iptables dual-stack transaction boundary

- Status: Accepted
- Date: 2026-08-01

## Context

Unlike the nftables backend, `iptables-restore` and `ip6tables-restore` are two
independent commits. IPv4 can succeed before IPv6 fails. The daemon must not
advertise this backend as writable until an independent helper can recover
every absent/owned combination in both families.

Netfilter's restore implementation confirms that a user-defined chain
declaration flushes that chain even with `--noflush`. This lets the Agent
replace only its six fixed chains without flushing distribution tables or
replaying unrelated rules.

## Decisions

1. Collect `iptables-save` and `ip6tables-save` as one logical observation and
   reconcile both with one boot-bound canonical record. Partial ownership fails
   closed.
2. Render both no-flush artifacts, then run `--test --noflush` for both
   families before loading either family.
3. Immediately before activation, collect both families again and compare the
   Agent-owned fingerprints rather than unrelated distribution rules or packet
   counters.
4. Load IPv4 followed by IPv6 and explicitly model failure of the second load
   as partial activation requiring external recovery.
5. Tighten hook ownership to one exact unconditional rule. A marker-bearing
   hook with extra match conditions is foreign and cannot be adopted.
6. Build conditional rollback artifacts from fresh saves:
   - prior owned/current owned: flush and restore only managed chains;
   - prior owned/current absent: recreate chains plus exact hooks;
   - prior absent/current owned: delete exact hooks, flush, and delete chains;
   - prior absent/current absent: no operation.
7. Store all four conditional artifacts and prior canonical state in the
   bounded volatile rollback manifest. The helper freshly classifies both
   families, attempts both recoveries even if one fails, and restores canonical
   SQLite state after native recovery.
8. Admit iptables through the same R3 approval, one-use token, confirmed-commit,
   and daemon serialization path used by OpenWrt and nftables.

## Consequences

Generic Linux iptables now has a tested dual-stack transaction, bounded
conditional recovery, independent watchdog, canonical-state rollback, and
daemon admission. The public typed firewall commands select it only when
capability discovery reports the complete iptables/ip6tables backend.

## References

- [Netfilter iptables-restore source](https://git.netfilter.org/iptables/tree/iptables-restore.c)
- [Netfilter packet filtering HOWTO](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html)
