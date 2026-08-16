#!/bin/sh
set -eu

checker=${1:-scripts/check-persistent-write-set.sh}
snapshot_helper=${MBED_AGENT_SNAPSHOT_HELPER:-scripts/snapshot-persistent-tree.sh}
test -f "$checker"
test -f "$snapshot_helper"
root=$(mktemp -d "${TMPDIR:-/tmp}/mbed-agent-write-set-test.XXXXXX")
trap 'rm -rf "$root"' EXIT INT TERM

mkdir -p "$root/source/empty"
printf '%s\n' source >"$root/source/file"
ln -s file "$root/source/link"
sh "$snapshot_helper" "$root/source" "$root/snapshot"
test -f "$root/snapshot/file"
test -d "$root/snapshot/empty"
test "$(readlink "$root/snapshot/link")" = file

mkdir -p "$root/before/etc/config" "$root/after/etc/config"
printf '%s\n' stable >"$root/before/etc/config/network"
cp "$root/before/etc/config/network" "$root/after/etc/config/network"

# A changed approved configuration file is accepted.
printf '%s\n' changed >"$root/after/etc/config/network"
sh "$checker" "$root/before" "$root/after" etc/config/network >/dev/null

# A changed non-approved file is rejected.
printf '%s\n' secret >"$root/before/private"
printf '%s\n' changed >"$root/after/private"
if sh "$checker" "$root/before" "$root/after" etc/config/network >/dev/null 2>&1; then
    echo "checker accepted a forbidden file change" >&2
    exit 1
fi
rm -f "$root/before/private" "$root/after/private"

# Deletions, empty directories, and symlink target changes are part of the set.
mkdir -p "$root/before/empty" "$root/after/empty"
printf '%s\n' target-a >"$root/before/target"
printf '%s\n' target-b >"$root/before/target-b"
cp "$root/before/target" "$root/after/target"
cp "$root/before/target-b" "$root/after/target-b"
ln -s target "$root/before/link"
ln -s target-b "$root/after/link"
if "$checker" "$root/before" "$root/after" etc/config/network >/dev/null 2>&1; then
    echo "checker accepted a forbidden symlink change" >&2
    exit 1
fi
sh "$checker" "$root/before" "$root/after" etc/config/network link >/dev/null
rm -f "$root/before/link" "$root/after/link"
rm -rf "$root/after/empty"
if sh "$checker" "$root/before" "$root/after" etc/config/network >/dev/null 2>&1; then
    echo "checker accepted a forbidden directory deletion" >&2
    exit 1
fi
mkdir -p "$root/after/empty"
sh "$checker" "$root/before" "$root/after" etc/config/network empty >/dev/null

echo "PASS: persistent write-set checker detects files, directories, deletions, and symlinks"
