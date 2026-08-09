#!/bin/sh
set -eu

required=${MBED_AGENT_NAMESPACE_SMOKE_REQUIRED:-0}
if ! command -v unshare >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
    if [ "$required" = 1 ]; then
        echo "namespace smoke requires unshare and ip" >&2
        exit 1
    fi
    echo "SKIP: namespace smoke requires unshare and ip"
    exit 0
fi

if ! unshare -n true 2>/dev/null; then
    if [ "$required" = 1 ]; then
        echo "namespace smoke requires CAP_NET_ADMIN" >&2
        exit 1
    fi
    echo "SKIP: namespace smoke requires CAP_NET_ADMIN"
    exit 0
fi

unshare -n sh -c '
    ip link set lo up
    ip -j link show lo >/dev/null
'
echo "PASS: isolated Linux network namespace smoke"
