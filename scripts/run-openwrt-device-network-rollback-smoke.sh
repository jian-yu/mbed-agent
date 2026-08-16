#!/bin/sh
set -eu

usage() {
    echo "usage: MBED_AGENT_ALLOW_DEVICE_WRITES=YES $0 SSH_TARGET AARCH64_BINARY [CONFIG]" >&2
    exit 2
}

[ "${MBED_AGENT_ALLOW_DEVICE_WRITES:-}" = YES ] || {
    echo "refusing real device writes without MBED_AGENT_ALLOW_DEVICE_WRITES=YES" >&2
    exit 1
}
[ "$#" -ge 2 ] || usage
ssh_target=$1
binary=$2
config=${3:-config/mbed-agent.example.toml}
mutation=docs/examples/network-rollback-smoke.json
snapshot_helper=scripts/snapshot-persistent-tree.sh
write_set_checker=scripts/check-persistent-write-set.sh
remote_test_root=/tmp/mbed-agent-device-network-write-test
remote_runtime_root=/tmp/mbed-agent
smoke_route=mbed_agent_smoke_disabled_route

case "$ssh_target" in
    ""|-*|*[!A-Za-z0-9_.:@-]*) echo "SSH target contains unsupported characters" >&2; exit 1 ;;
esac
test -x "$binary"
test -f "$config"
test -f "$mutation"
test -f "$snapshot_helper"
test -f "$write_set_checker"
command -v ssh >/dev/null 2>&1
command -v scp >/dev/null 2>&1
command -v file >/dev/null 2>&1
command -v od >/dev/null 2>&1
case "$(file -b "$binary")" in
    ELF*"ARM aarch64"*) ;;
    *) echo "device network smoke requires an aarch64 ELF binary" >&2; exit 1 ;;
esac
if grep -Eq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true' "$config"; then
    echo "device network smoke refuses configurations with enabled integrations" >&2
    exit 1
fi

created=0
cleanup_host() {
    [ "$created" = 1 ] || return 0
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" '
test_root=/tmp/mbed-agent-device-network-write-test
runtime_root=/tmp/mbed-agent
route=mbed_agent_smoke_disabled_route
i=0
while uci -q show network 2>/dev/null | grep -F ".mbed_id=" | grep -F "$route" >/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 25 ] || break
    sleep 1
done
if uci -q show network 2>/dev/null | grep -F ".mbed_id=" | grep -F "$route" >/dev/null; then
    echo "WARNING: smoke route still exists; leaving daemon and rollback state intact" >&2
    exit 1
fi
if [ -f "$test_root/daemon.pid" ]; then
    pid=$(cat "$test_root/daemon.pid")
    case "$pid" in *[!0-9]*|"") pid= ;; esac
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
fi
rm -rf "$test_root" "$runtime_root"
' >/dev/null 2>&1 || true
}
trap cleanup_host EXIT INT TERM

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
[ ! -e '$remote_test_root' ]
[ ! -e '$remote_runtime_root' ]
! pidof mbed-agent >/dev/null 2>&1
command -v uci >/dev/null 2>&1
command -v jsonfilter >/dev/null 2>&1
! uci -q show network | grep -F \".mbed_id='$smoke_route'\" >/dev/null
mkdir -m 0700 '$remote_test_root'
find /etc/config -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1 >'$remote_test_root/before.sha256'
"
created=1
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$binary" "$ssh_target:$remote_test_root/mbed-agent"
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$config" "$ssh_target:$remote_test_root/config.toml"
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$mutation" "$ssh_target:$remote_test_root/mutation.json"
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$snapshot_helper" "$ssh_target:$remote_test_root/snapshot-persistent-tree.sh"
scp -O -o BatchMode=yes -o ConnectTimeout=8 "$write_set_checker" "$ssh_target:$remote_test_root/check-persistent-write-set.sh"

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
cd '$remote_test_root'
chmod 0600 snapshot-persistent-tree.sh check-persistent-write-set.sh
sh snapshot-persistent-tree.sh /etc/config persistent-before/etc/config
"

admin_password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$admin_password" | ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
cd '$remote_test_root'
chmod 0700 mbed-agent
chmod 0600 config.toml mutation.json
./mbed-agent auth hash-password >admin.hash
chmod 0600 admin.hash
hash=\$(tr -d '\r\n' <admin.hash)
awk -v hash=\"\$hash\" '
    /^\[runtime\]$/ { section = \"runtime\" }
    /^\[auth\]$/ { section = \"auth\" }
    /^\[/ && \$0 != \"[runtime]\" && \$0 != \"[auth]\" { section = \"\" }
    section == \"runtime\" && /^rollback_confirm_timeout_secs[[:space:]]*=/ { print \"rollback_confirm_timeout_secs = 5\"; next }
    section == \"auth\" && /^enabled[[:space:]]*=/ { print \"enabled = true\"; next }
    section == \"auth\" && /^admin_password_hash[[:space:]]*=/ { print \"admin_password_hash = \\\"\" hash \"\\\"\"; next }
    { print }
' config.toml >config.next
mv config.next config.toml
chmod 0600 config.toml
rm -f admin.hash
./mbed-agent daemon --config config.toml >daemon.log 2>&1 &
echo \$! >daemon.pid
"

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
test_root='$remote_test_root'
i=0
while [ ! -S '$remote_runtime_root/agent.sock' ]; do
    pid=\$(cat \"\$test_root/daemon.pid\")
    kill -0 \"\$pid\" 2>/dev/null || { cat \"\$test_root/daemon.log\" >&2; exit 1; }
    i=\$((i + 1))
    [ \"\$i\" -lt 20 ] || { cat \"\$test_root/daemon.log\" >&2; exit 1; }
    sleep 1
done
"

printf '%s\n' "$admin_password" | ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
cd '$remote_test_root'
if ! ./mbed-agent auth elevate --socket '$remote_runtime_root/agent.sock' >elevate.json; then
    cat elevate.json >&2
    exit 1
fi
grep -q '\"ok\": true' elevate.json
rm -f elevate.json
"
unset admin_password

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
cd '$remote_test_root'
socket='$remote_runtime_root/agent.sock'
if ! ./mbed-agent change network-plan --socket \"\$socket\" <mutation.json >plan.json; then
    cat plan.json >&2
    tail -n 80 daemon.log >&2 2>/dev/null || true
    tail -n 80 '$remote_runtime_root/log/agent.log' >&2 2>/dev/null || true
    exit 1
fi
grep -q '\"ok\": true' plan.json
change_set_id=\$(jsonfilter -i plan.json -e '@.result.data.change_set_id')
[ -n \"\$change_set_id\" ]
risk=\$(jsonfilter -i plan.json -e '@.result.data.plan.risk')
[ \"\$risk\" = r3 ]
if ! ./mbed-agent change approve \"\$change_set_id\" --socket \"\$socket\" >approval.json; then
    cat approval.json >&2
    exit 1
fi
chmod 0600 approval.json
if ! ./mbed-agent change apply \"\$change_set_id\" --socket \"\$socket\" <approval.json >apply.json; then
    rm -f approval.json
    cat apply.json >&2
    ./mbed-agent change get \"\$change_set_id\" --socket \"\$socket\" >failed-state.json 2>/dev/null || true
    cat failed-state.json >&2 2>/dev/null || true
    tail -n 80 daemon.log >&2 2>/dev/null || true
    tail -n 80 '$remote_runtime_root/log/agent.log' >&2 2>/dev/null || true
    exit 1
fi
rm -f approval.json
grep -q '\"ok\": true' apply.json
state=\$(jsonfilter -i apply.json -e '@.result.data.state')
[ \"\$state\" = awaiting_confirmation ]
sh snapshot-persistent-tree.sh /etc/config persistent-applied/etc/config
sh check-persistent-write-set.sh persistent-before persistent-applied etc/config/network
uci -q show network | grep -F \".mbed_id='$smoke_route'\" >/dev/null
echo \"PASS: R3 network change applied and awaits confirmation\"
"

ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
cd '$remote_test_root'
socket='$remote_runtime_root/agent.sock'
change_set_id=\$(jsonfilter -i plan.json -e '@.result.data.change_set_id')
i=0
state=
while [ \"\$state\" != rolled_back ]; do
    i=\$((i + 1))
    [ \"\$i\" -le 25 ] || { echo \"network rollback deadline did not complete\" >&2; exit 1; }
    sleep 1
    if ! ./mbed-agent change get \"\$change_set_id\" --socket \"\$socket\" >state.json; then
        cat state.json >&2
        exit 1
    fi
    state=\$(jsonfilter -i state.json -e '@.result.data.state')
done
! uci -q show network | grep -F \".mbed_id='$smoke_route'\" >/dev/null
sh snapshot-persistent-tree.sh /etc/config persistent-after/etc/config
sh check-persistent-write-set.sh persistent-before persistent-after
after=\$(find /etc/config -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
before=\$(cat before.sha256)
[ \"\$before\" = \"\$after\" ]
echo \"PASS: network rollback restored the exact persistent configuration snapshot\"

pid=\$(cat daemon.pid)
kill \"\$pid\"
wait \"\$pid\" 2>/dev/null || true
rm -rf '$remote_test_root' '$remote_runtime_root'
"

created=0
ssh -o BatchMode=yes -o ConnectTimeout=8 "$ssh_target" "
set -eu
[ ! -e '$remote_test_root' ]
[ ! -e '$remote_runtime_root' ]
! pidof mbed-agent >/dev/null 2>&1
! uci -q show network | grep -F \".mbed_id='$smoke_route'\" >/dev/null
"
echo "PASS: OpenWrt device network rollback smoke completed and cleaned up"
