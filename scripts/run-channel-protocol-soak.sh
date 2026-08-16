#!/bin/sh
set -eu

usage() {
    echo "usage: $0 [ITERATIONS]" >&2
    exit 2
}

[ "$#" -le 1 ] || usage
iterations=${1:-${MBED_AGENT_CHANNEL_SOAK_ITERS:-10000}}
case "$iterations" in
    ''|*[!0-9]*) echo "iterations must be a positive integer" >&2; exit 2 ;;
esac
[ "$iterations" -gt 0 ] || { echo "iterations must be greater than zero" >&2; exit 2; }

command -v cargo >/dev/null 2>&1
MBED_AGENT_CHANNEL_SOAK_ITERS="$iterations" \
    cargo +1.85.1 test --locked -p agent-channels \
    channel_protocol_soak_preserves_bounded_round_trips -- --nocapture
MBED_AGENT_CHANNEL_SOAK_ITERS="$iterations" \
    cargo +1.85.1 test --locked -p agent-store \
    channel_store_soak_keeps_dedup_and_capacity_bounded -- --nocapture
echo "PASS: channel protocol and volatile-store soak completed ($iterations iterations)"
