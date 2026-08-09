#!/bin/sh
set -eu

before=${1:?usage: check-persistent-write-set.sh BEFORE AFTER [allowed-prefix ...]}
after=${2:?usage: check-persistent-write-set.sh BEFORE AFTER [allowed-prefix ...]}
shift 2
test -d "$before"
test -d "$after"

while IFS= read -r relative; do
    before_path=$before/$relative
    after_path=$after/$relative
    different=0
    if [ ! -e "$before_path" ] || [ ! -e "$after_path" ]; then
        different=1
    elif ! cmp -s "$before_path" "$after_path"; then
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
$(find "$before" "$after" -type f -print | sed "s#^$before/##; s#^$after/##" | sort -u)
EOF
echo "PASS: persistent write set is within the configured allowlist"
