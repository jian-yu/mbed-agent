#!/bin/sh
set -eu

prepare_script=${1:-scripts/prepare-release-artifacts.sh}
binary=${2:-target/release/mbed-agent}
test -f "$prepare_script"
test -f "$binary"
command -v sha256sum >/dev/null 2>&1

root=$(mktemp -d "${TMPDIR:-/tmp}/mbed-agent-release-test.XXXXXX")
cleanup() {
    rm -rf "$root"
}
trap cleanup EXIT HUP INT TERM

foreign_binary="$root/foreign.bin"
printf '%s\n' 'foreign binary fixture' >"$foreign_binary"

if MBED_AGENT_VERSION='1.2.3"bad' sh "$prepare_script" "$foreign_binary" "$root/rejected" \
    >"$root/rejected.log" 2>&1; then
    echo "release artifact script accepted an unsafe version" >&2
    exit 1
fi

output="$root/artifacts"
MBED_AGENT_METADATA_PLATFORM=${MBED_AGENT_METADATA_PLATFORM:-x86_64-unknown-linux-gnu} \
    MBED_AGENT_VERSION=9.8.7-rc.1 \
    sh "$prepare_script" "$foreign_binary" "$output"
grep -F '"version": "9.8.7-rc.1"' "$output/manifest.json" >/dev/null
expected_size=$(wc -c <"$foreign_binary" | tr -d '[:space:]')
manifest_size=$(awk -F': ' '/binary_size_bytes/ { gsub(/,/, "", $2); print $2 }' "$output/manifest.json")
test "$expected_size" -eq "$manifest_size"
(cd "$output" && sha256sum -c checksums.sha256 >/dev/null)

echo "PASS: release artifact script rejects unsafe versions and fingerprints foreign binaries"
