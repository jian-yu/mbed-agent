#!/bin/sh
set -eu

binary=${1:-target/release/mbed-agent}
config=${2:-config/mbed-agent.example.toml}
max_rss_kib=${MBED_AGENT_MAX_RSS_KIB:-65536}
test -x "$binary"
test -f "$config"

"$binary" daemon --config "$config" >/tmp/mbed-agent-rss.out 2>/tmp/mbed-agent-rss.err &
pid=$!
cleanup() {
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if kill -0 "$pid" 2>/dev/null; then
        ready=1
        sleep 1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "daemon exited before RSS measurement" >&2
    sed -n '1,80p' /tmp/mbed-agent-rss.err >&2 || true
    exit 1
fi

rss_kib=$(ps -o rss= -p "$pid" | awk '{print $1}')
case "$rss_kib" in
    ''|*[!0-9]*) echo "could not read daemon RSS" >&2; exit 1 ;;
esac
if [ "$rss_kib" -gt "$max_rss_kib" ]; then
    echo "daemon RSS ${rss_kib} KiB exceeds ${max_rss_kib} KiB" >&2
    exit 1
fi
echo "PASS: daemon RSS ${rss_kib} KiB (limit ${max_rss_kib} KiB)"
