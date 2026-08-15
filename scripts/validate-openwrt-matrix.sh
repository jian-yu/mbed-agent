#!/bin/sh
set -eu

matrix=${1:-openwrt/targets.tsv}
test -f "$matrix"

awk -F '\t' '
NR == 1 {
    if ($1 != "release" || $2 != "target" || $3 != "subtarget" || $4 != "arch" || $5 != "rust_target" || $6 != "firewall") {
        print "invalid OpenWrt matrix header" > "/dev/stderr"
        exit 1
    }
    next
}
NF != 6 {
    print "every matrix row must have six tab-separated fields" > "/dev/stderr"
    exit 1
}
$1 !~ /^([0-9]+)\.([0-9]+)\.[0-9]+$/ {
    print "invalid OpenWrt release: " $1 > "/dev/stderr"
    exit 1
}
$5 !~ /^[a-z0-9_]+-unknown-linux-musl(eabihf)?$/ {
    print "invalid Rust musl target: " $5 > "/dev/stderr"
    exit 1
}
$1 ~ /^21\./ && $6 != "fw3" {
    print "OpenWrt 21.x must use fw3 in the compatibility matrix" > "/dev/stderr"
    exit 1
}
$1 !~ /^21\./ && $6 != "fw4" {
    print "OpenWrt 22.x and newer must use fw4 in the compatibility matrix" > "/dev/stderr"
    exit 1
}
{
    seen[$1 SUBSEP $2 SUBSEP $3]++
    releases[$1] = 1
    arches[$4] = 1
    rows++
}
END {
    if (rows == 0 || !releases["21.02.7"] || !releases["22.03.7"] || !releases["23.05.5"] || !releases["24.10.8"]) {
        print "matrix must cover 21.02.7, 22.03.7, 23.05.5 and 24.10.8" > "/dev/stderr"
        exit 1
    }
    for (key in seen) if (seen[key] != 1) {
        print "duplicate OpenWrt matrix target: " key > "/dev/stderr"
        exit 1
    }
    if (!arches["x86_64"] || !arches["armv7"] || !arches["aarch64"] || !arches["mipsel"]) {
        print "matrix is missing one of x86_64, armv7, aarch64 or mipsel" > "/dev/stderr"
        exit 1
    }
}' "$matrix"
