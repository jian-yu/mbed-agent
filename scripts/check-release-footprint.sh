#!/bin/sh
set -eu

binary=${1:-target/release/mbed-agent}
max_bytes=${MBED_AGENT_MAX_BINARY_BYTES:-8388608}
test -f "$binary"

size=$(stat -f '%z' "$binary" 2>/dev/null || stat -c '%s' "$binary")
if [ "$size" -gt "$max_bytes" ]; then
    echo "release binary is ${size} bytes, exceeding ${max_bytes}" >&2
    exit 1
fi
if [ "${MBED_AGENT_SKIP_BINARY_EXEC:-0}" != 1 ]; then
    "$binary" --version >/dev/null
fi
echo "PASS: release binary ${size} bytes (limit ${max_bytes})"
