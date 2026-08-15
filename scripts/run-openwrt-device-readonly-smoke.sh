#!/bin/sh
set -eu

usage() {
    echo "usage: $0 SSH_TARGET AARCH64_BINARY [CONFIG]" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage
ssh_target=$1
binary=$2
config=${3:-config/mbed-agent.example.toml}
remote_test_root=/tmp/mbed-agent-device-test
remote_runtime_root=/tmp/mbed-agent

case "$ssh_target" in
    ""|-*|*[!A-Za-z0-9_.:@-]*)
        echo "SSH target contains unsupported characters" >&2
        exit 1
        ;;
esac
test -x "$binary"
test -f "$config"
command -v ssh >/dev/null 2>&1
command -v scp >/dev/null 2>&1
command -v file >/dev/null 2>&1
case "$(file -b "$binary")" in
    ELF*"ARM aarch64"*) ;;
    *) echo "device smoke requires an aarch64 ELF binary" >&2; exit 1 ;;
esac
if grep -Eq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true' "$config"; then
    echo "device read-only smoke refuses configurations with enabled integrations" >&2
    exit 1
fi
storage_path=$(awk '
    $0 == "[storage]" { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && $1 == "path" { gsub(/"/, "", $3); print $3; exit }
' "$config")
socket_path=$(awk '
    $0 == "[server]" { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && $1 == "socket_path" { gsub(/"/, "", $3); print $3; exit }
' "$config")
log_path=$(awk '
    $0 == "[logging]" { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && $1 == "path" { gsub(/"/, "", $3); print $3; exit }
' "$config")
for volatile_path in "$storage_path" "$socket_path" "$log_path"; do
    case "$volatile_path" in
        /tmp/mbed-agent/*) ;;
        *) echo "device smoke requires storage, socket, and log paths below /tmp/mbed-agent" >&2; exit 1 ;;
    esac
done

created=0
cleanup_host() {
    if [ "$created" = 1 ]; then
        ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" \
            "pids=\$(pidof mbed-agent 2>/dev/null || true); [ -z \"\$pids\" ] || kill \$pids 2>/dev/null || true; rm -rf $remote_test_root $remote_runtime_root" >/dev/null 2>&1 || true
    fi
}
trap cleanup_host EXIT INT TERM

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" \
    "set -eu; [ ! -e $remote_test_root ]; [ ! -e $remote_runtime_root ]; ! pidof mbed-agent >/dev/null 2>&1; mkdir -m 0700 $remote_test_root"
created=1
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$binary" \
    "$ssh_target:$remote_test_root/mbed-agent"
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$config" \
    "$ssh_target:$remote_test_root/config.toml"

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" '
set -eu
test_root=/tmp/mbed-agent-device-test
runtime_root=/tmp/mbed-agent
pid=
cleanup_device() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf /tmp/mbed-agent-device-test /tmp/mbed-agent
}
trap cleanup_device EXIT INT TERM

before=$(find /etc/config -type f -exec sha256sum {} \; | sort | sha256sum | cut -d" " -f1)
cd "$test_root"
chmod 0700 mbed-agent
chmod 0600 config.toml
./mbed-agent --version
./mbed-agent daemon --config config.toml >daemon.log 2>&1 &
pid=$!
i=0
while [ ! -S "$runtime_root/agent.sock" ]; do
    kill -0 "$pid" 2>/dev/null || { cat daemon.log >&2; exit 1; }
    i=$((i + 1))
    [ "$i" -lt 20 ] || { cat daemon.log >&2; exit 1; }
    sleep 1
done

for command_name in ping status capabilities; do
    output="$test_root/$command_name.json"
    ./mbed-agent "$command_name" --socket "$runtime_root/agent.sock" >"$output"
    grep -q "\"ok\": true" "$output"
    printf "PASS %s bytes=%s\n" "$command_name" "$(wc -c <"$output")"
done
for diagnostic in wan dns dhcp routes interfaces neighbors firewall policy-routing listeners wireless interface-stats conntrack qdisc; do
    output="$test_root/diagnose-$diagnostic.json"
    ./mbed-agent diagnose "$diagnostic" --socket "$runtime_root/agent.sock" >"$output"
    grep -q "\"ok\": true" "$output"
    printf "PASS diagnose-%s bytes=%s\n" "$diagnostic" "$(wc -c <"$output")"
done
for inventory in firewall-inventory network-inventory; do
    output="$test_root/$inventory.json"
    ./mbed-agent change "$inventory" --socket "$runtime_root/agent.sock" >"$output"
    grep -q "\"ok\": true" "$output"
    printf "PASS %s bytes=%s\n" "$inventory" "$(wc -c <"$output")"
done

kill "$pid"
wait "$pid" || true
pid=
after=$(find /etc/config -type f -exec sha256sum {} \; | sort | sha256sum | cut -d" " -f1)
[ "$before" = "$after" ]
echo "PASS: persistent OpenWrt configuration unchanged"
'

created=0
ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" \
    "set -eu; [ ! -e $remote_test_root ]; [ ! -e $remote_runtime_root ]; ! pidof mbed-agent >/dev/null 2>&1"
echo "PASS: OpenWrt device read-only smoke completed and cleaned up"
