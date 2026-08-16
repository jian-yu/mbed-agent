#!/bin/sh
set -eu

required=${MBED_AGENT_LINUX_FIREWALL_SMOKE_REQUIRED:-0}
require_both=${MBED_AGENT_LINUX_FIREWALL_SMOKE_REQUIRE_BOTH:-0}

fail_or_skip() {
    message=$1
    if [ "$required" = 1 ]; then
        echo "$message" >&2
        exit 1
    fi
    echo "SKIP: $message"
    exit 0
}

command -v unshare >/dev/null 2>&1 || fail_or_skip "namespace smoke requires unshare"
command -v ip >/dev/null 2>&1 || fail_or_skip "namespace smoke requires ip"
unshare -n true 2>/dev/null || fail_or_skip "namespace smoke requires CAP_NET_ADMIN"

has_nft=0
if command -v nft >/dev/null 2>&1; then
    has_nft=1
fi
has_iptables=0
if command -v iptables >/dev/null 2>&1 \
    && command -v ip6tables >/dev/null 2>&1 \
    && command -v iptables-save >/dev/null 2>&1 \
    && command -v ip6tables-save >/dev/null 2>&1 \
    && command -v iptables-restore >/dev/null 2>&1 \
    && command -v ip6tables-restore >/dev/null 2>&1; then
    has_iptables=1
fi

if [ "$has_nft" -eq 0 ] && [ "$has_iptables" -eq 0 ]; then
    fail_or_skip "namespace smoke requires nftables or complete iptables dual-stack tools"
fi
if [ "$require_both" = 1 ] && { [ "$has_nft" -eq 0 ] || [ "$has_iptables" -eq 0 ]; }; then
    echo "namespace smoke requires both nftables and iptables dual-stack tools" >&2
    exit 1
fi

unshare -n sh -c '
set -eu
ip link set lo up

if [ "$1" = 1 ]; then
    nft_table=mbed_agent_smoke
    nft_before=$(nft list ruleset 2>/dev/null || true)
    cleanup_nft() {
        nft delete table inet "$nft_table" 2>/dev/null || true
    }
    trap cleanup_nft EXIT INT TERM

    nft -c -f - <<EOF
add table inet $nft_table
add chain inet $nft_table input { type filter hook input priority -300; policy accept; }
add rule inet $nft_table input counter
EOF
    nft -f - <<EOF
add table inet $nft_table
add chain inet $nft_table input { type filter hook input priority -300; policy accept; }
add rule inet $nft_table input counter
EOF
    nft list table inet "$nft_table" | grep -F "table inet $nft_table" >/dev/null
    nft delete table inet "$nft_table"
    nft_after=$(nft list ruleset 2>/dev/null || true)
    [ "$nft_before" = "$nft_after" ]
    trap - EXIT INT TERM
    echo "PASS: isolated nftables check/apply/cleanup restored the native snapshot"
fi

if [ "$2" = 1 ]; then
    iptables_chain=MBED_AGENT_SMOKE
    ip6tables_chain=MBED_AGENT_SMOKE
    # An empty Alpine namespace has no materialized filter table. Create and
    # remove one disposable chain first so the before/after snapshot includes
    # the same builtin chains that the transaction exercises.
    iptables -N MBED_AGENT_BOOTSTRAP
    iptables -X MBED_AGENT_BOOTSTRAP
    ip6tables -N MBED_AGENT_BOOTSTRAP
    ip6tables -X MBED_AGENT_BOOTSTRAP
    snapshot_root=/tmp/mbed-agent-linux-firewall-smoke.$$
    mkdir -m 0700 "$snapshot_root"
    iptables-save >"$snapshot_root/ipv4.before"
    ip6tables-save >"$snapshot_root/ipv6.before"
    cleanup_iptables() {
        iptables -D INPUT -j "$iptables_chain" 2>/dev/null || true
        iptables -F "$iptables_chain" 2>/dev/null || true
        iptables -X "$iptables_chain" 2>/dev/null || true
        ip6tables -D INPUT -j "$ip6tables_chain" 2>/dev/null || true
        ip6tables -F "$ip6tables_chain" 2>/dev/null || true
        ip6tables -X "$ip6tables_chain" 2>/dev/null || true
    }
    cleanup_runtime() {
        cleanup_iptables
        rm -rf "$snapshot_root"
    }
    trap cleanup_runtime EXIT INT TERM

    iptables-restore --test --noflush <"$snapshot_root/ipv4.before"
    ip6tables-restore --test --noflush <"$snapshot_root/ipv6.before"
    iptables -N "$iptables_chain"
    iptables -I INPUT 1 -j "$iptables_chain"
    ip6tables -N "$ip6tables_chain"
    ip6tables -I INPUT 1 -j "$ip6tables_chain"
    iptables-save | grep -F ":$iptables_chain -" >/dev/null
    iptables-save | grep -F -- "-A INPUT -j $iptables_chain" >/dev/null
    ip6tables-save | grep -F ":$ip6tables_chain -" >/dev/null
    ip6tables-save | grep -F -- "-A INPUT -j $ip6tables_chain" >/dev/null
    cleanup_iptables
    iptables-save >"$snapshot_root/ipv4.after"
    ip6tables-save >"$snapshot_root/ipv6.after"
    cmp -s "$snapshot_root/ipv4.before" "$snapshot_root/ipv4.after"
    cmp -s "$snapshot_root/ipv6.before" "$snapshot_root/ipv6.after"
    rm -rf "$snapshot_root"
    trap - EXIT INT TERM
    echo "PASS: isolated iptables/ip6tables check/apply/cleanup restored native snapshots"
fi
' sh "$has_nft" "$has_iptables"

echo "PASS: Linux firewall namespace smoke completed"
