#!/bin/sh
set -eu

before=${1:?usage: check-persistent-write-set.sh BEFORE AFTER [allowed-prefix ...]}
after=${2:?usage: check-persistent-write-set.sh BEFORE AFTER [allowed-prefix ...]}
shift 2
test -d "$before"
test -d "$after"

while IFS= read -r relative; do
    [ -n "$relative" ] || continue
    before_path=$before/$relative
    after_path=$after/$relative
    different=0
    before_type=missing
    after_type=missing
    if [ -L "$before_path" ]; then
        before_type=symlink
    elif [ -f "$before_path" ]; then
        before_type=file
    elif [ -d "$before_path" ]; then
        before_type=directory
    elif [ -e "$before_path" ]; then
        before_type=other
    fi
    if [ -L "$after_path" ]; then
        after_type=symlink
    elif [ -f "$after_path" ]; then
        after_type=file
    elif [ -d "$after_path" ]; then
        after_type=directory
    elif [ -e "$after_path" ]; then
        after_type=other
    fi
    if [ "$before_type" != "$after_type" ]; then
        different=1
    elif [ "$before_type" = file ] && ! cmp -s "$before_path" "$after_path"; then
        different=1
    elif [ "$before_type" = symlink ] && [ "$(readlink "$before_path")" != "$(readlink "$after_path")" ]; then
        different=1
    elif [ "$before_type" = other ]; then
        # Device nodes, FIFOs, and sockets are outside the supported snapshot
        # contract; fail closed instead of silently treating them as unchanged.
        different=1
    fi
    if [ "$different" -eq 1 ]; then
        permitted=0
        for prefix in "$@"; do
            case "$relative" in
                "$prefix"|"$prefix"/*) permitted=1 ;;
            esac
        done
        if [ "$permitted" -ne 1 ]; then
            echo "forbidden persistent write: $relative" >&2
            exit 1
        fi
    fi
done <<EOF
$(find "$before" "$after" -mindepth 1 -print | sed "s#^$before/##; s#^$after/##" | sort -u)
EOF
echo "PASS: persistent write set is within the configured allowlist"
