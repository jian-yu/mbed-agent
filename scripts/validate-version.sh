#!/bin/sh
set -eu

cargo_toml=${1:-Cargo.toml}
openwrt_makefile=${2:-openwrt/Makefile}
example_config=${3:-config/mbed-agent.example.toml}
openwrt_config=${4:-openwrt/files/etc/mbed-agent/config.toml}

test -f "$cargo_toml"
test -f "$openwrt_makefile"
test -f "$example_config"
test -f "$openwrt_config"

workspace_version=$(awk '
    $0 == "[workspace.package]" { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && $1 == "version" {
        gsub(/"/, "", $3)
        print $3
        exit
    }
' "$cargo_toml")
package_version=$(awk -F ':=' '$1 == "PKG_VERSION" { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$openwrt_makefile")
example_bot_agent=$(sed -n 's/^bot_agent = "MbedAgent\/\([0-9][^"]*\)"$/\1/p' "$example_config")
openwrt_bot_agent=$(sed -n 's/^bot_agent = "MbedAgent\/\([0-9][^"]*\)"$/\1/p' "$openwrt_config")

case "$workspace_version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "invalid workspace version: $workspace_version" >&2; exit 1 ;;
esac
[ "$workspace_version" = "$package_version" ] || {
    echo "Cargo workspace version $workspace_version != OpenWrt PKG_VERSION $package_version" >&2
    exit 1
}
[ "$workspace_version" = "$example_bot_agent" ] || {
    echo "Cargo workspace version $workspace_version != example bot_agent $example_bot_agent" >&2
    exit 1
}
[ "$workspace_version" = "$openwrt_bot_agent" ] || {
    echo "Cargo workspace version $workspace_version != OpenWrt bot_agent $openwrt_bot_agent" >&2
    exit 1
}
echo "PASS: release version is $workspace_version across Cargo, OpenWrt, and config samples"
