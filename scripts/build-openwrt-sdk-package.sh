#!/bin/sh
set -eu

usage() {
    echo "usage: $0 RELEASE TARGET SUBTARGET BINARY [OUTPUT_DIR]" >&2
    exit 2
}

[ "$#" -ge 4 ] || usage
release=$1
target=$2
subtarget=$3
binary=$4
output_dir=${5:-dist/openwrt}
matrix=openwrt/targets.tsv
test -f "$matrix"
test -f "$binary"
command -v curl >/dev/null 2>&1
command -v sha256sum >/dev/null 2>&1
command -v tar >/dev/null 2>&1
command -v ar >/dev/null 2>&1
command -v file >/dev/null 2>&1
command -v make >/dev/null 2>&1

row=$(awk -F '\t' -v release="$release" -v target="$target" -v subtarget="$subtarget" \
    'NR > 1 && $1 == release && $2 == target && $3 == subtarget { print; found++ }
     END { if (found != 1) exit 1 }' "$matrix") || {
    echo "target is absent or duplicated in $matrix: $release/$target/$subtarget" >&2
    exit 1
}
rust_target=$(printf '%s\n' "$row" | awk -F '\t' '{print $5}')
arch=$(printf '%s\n' "$row" | awk -F '\t' '{print $4}')
firewall=$(printf '%s\n' "$row" | awk -F '\t' '{print $6}')

test -x "$binary" || {
    echo "binary is not executable: $binary" >&2
    exit 1
}
binary_description=$(file -b "$binary")
case "$arch" in
    x86_64) expected_arch='x86-64' ;;
    armv7) expected_arch='ARM' ;;
    aarch64) expected_arch='ARM aarch64' ;;
    mipsel) expected_arch='MIPS' ;;
    *)
        echo "unsupported matrix architecture for binary validation: $arch" >&2
        exit 1
        ;;
esac
case "$binary_description" in
    ELF*"$expected_arch"*) ;;
    *)
        echo "binary architecture mismatch: expected ELF $expected_arch, got $binary_description" >&2
        exit 1
        ;;
esac

work_root=/tmp/mbed-agent-openwrt-sdk-build
build_root=$work_root/$release/$target/$subtarget
mkdir -p "$build_root" "$output_dir"
cleanup() {
    if [ "${MBED_AGENT_KEEP_SDK:-0}" != 1 ]; then
        rm -rf "$build_root"
    fi
}
trap cleanup EXIT INT TERM

base_url=https://downloads.openwrt.org/releases/$release/targets/$target/$subtarget
index=$build_root/index.html
checksums=$build_root/sha256sums
download() {
    curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
        --connect-timeout 20 --max-time 1800 "$1" -o "$2"
}
download "$base_url/" "$index"
download "$base_url/sha256sums" "$checksums"
sdk_name=$(sed -n 's/.*href="\(openwrt-sdk-[^"]*Linux-x86_64\.tar\.xz\)".*/\1/p' "$index" | head -n 1)
[ -n "$sdk_name" ] || {
    echo "SDK archive was not found in $base_url" >&2
    exit 1
}
expected=$(awk -v name="$sdk_name" '$2 == "*" name { print $1; found++ } END { if (found != 1) exit 1 }' "$checksums") || {
    echo "SDK checksum was not found for $sdk_name" >&2
    exit 1
}
archive=$build_root/$sdk_name
if [ -n "${MBED_AGENT_SDK_ARCHIVE:-}" ]; then
    test -f "$MBED_AGENT_SDK_ARCHIVE"
    cp "$MBED_AGENT_SDK_ARCHIVE" "$archive"
else
    download "$base_url/$sdk_name" "$archive"
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum -c -

tar -xJf "$archive" -C "$build_root"
sdk_dir=$(find "$build_root" -mindepth 1 -maxdepth 1 -type d -name 'openwrt-sdk-*' -print -quit)
[ -n "$sdk_dir" ] || {
    echo "extracted SDK directory was not found" >&2
    exit 1
}

package_dir=$sdk_dir/package/mbed-agent
mkdir -p "$package_dir"
cp openwrt/Makefile "$package_dir/Makefile"
cp -R openwrt/files "$package_dir/files"
make -C "$sdk_dir" package/mbed-agent/compile V=s MBED_AGENT_BINARY="$binary"

package=$(find "$sdk_dir/bin/packages" -type f \( -name 'mbed-agent_*.ipk' -o -name 'mbed-agent_*.apk' \) -print -quit)
[ -n "$package" ] || {
    echo "OpenWrt package was not produced" >&2
    exit 1
}
case "$package" in
    # An .ipk is an ar container; its data.tar member is the payload.
    *.ipk)
        data_member=$(ar t "$package" | awk '/^data\.tar/{print; exit}')
        [ -n "$data_member" ] || {
            echo "OpenWrt .ipk has no data.tar payload" >&2
            exit 1
        }
        ar p "$package" "$data_member" > "$build_root/data.tar"
        tar -tf "$build_root/data.tar" | grep -F './usr/sbin/mbed-agent' >/dev/null
        ;;
    *.apk) tar -tf "$package" | grep -F './usr/sbin/mbed-agent' >/dev/null ;;
esac
output="$output_dir/mbed-agent-$release-$target-$subtarget-$rust_target-$firewall"
mkdir -p "$output"
cp "$package" "$output/"
printf '%s  %s\n' "$expected" "$sdk_name" > "$output/sdk.sha256"
printf 'package=%s\nrelease=%s\ntarget=%s\nsubtarget=%s\nrust_target=%s\nfirewall=%s\n' \
    "$(basename "$package")" "$release" "$target" "$subtarget" "$rust_target" "$firewall" \
    > "$output/metadata.txt"
echo "PASS: OpenWrt package created at $output"
