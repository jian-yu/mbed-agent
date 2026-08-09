#!/bin/sh
set -eu

image=${1:?usage: run-openwrt-qemu-smoke.sh FIRMWARE_IMAGE}
test -f "$image"
command -v qemu-system-x86_64 >/dev/null 2>&1
command -v timeout >/dev/null 2>&1

timeout_secs=${MBED_AGENT_QEMU_TIMEOUT_SECS:-90}
ready_pattern=${MBED_AGENT_QEMU_READY_PATTERN:-'procd: - init complete'}
log_file=$(mktemp /tmp/mbed-agent-qemu-log.XXXXXX)
cleanup() {
    rm -f "$log_file"
}
trap cleanup EXIT INT TERM

set +e
timeout --signal=TERM "${timeout_secs}s" \
    qemu-system-x86_64 \
    -M pc -m 128 -nographic -monitor none -no-reboot -snapshot \
    -drive "file=$image,format=raw,if=virtio" \
    -serial "file=$log_file"
qemu_status=$?
set -e

if ! grep -E "$ready_pattern" "$log_file" >/dev/null 2>&1; then
    echo "OpenWrt QEMU did not emit readiness pattern: $ready_pattern" >&2
    sed -n '1,160p' "$log_file" >&2
    exit 1
fi
if [ "$qemu_status" -ne 0 ] && [ "$qemu_status" -ne 124 ] && [ "$qemu_status" -ne 143 ]; then
    echo "OpenWrt QEMU exited with status $qemu_status" >&2
    exit "$qemu_status"
fi
echo "PASS: OpenWrt QEMU emitted readiness pattern"
