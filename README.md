# Mbed Agent

Mbed Agent is a resource-bounded network operations agent for OpenWrt 21.02+
and small embedded Linux systems. The current implementation contains the
Phase 0 runtime foundation and an expanding Phase 1 read-only diagnostic set
described in [the architecture plan](docs/architecture-plan.zh-CN.md).

## Current scope

- One Rust executable: `mbed-agent daemon` runs the service, while the other
  subcommands act as its local CLI over a bounded Unix socket protocol.
- Strict configuration validation that keeps runtime state below `/tmp/mbed-agent`.
- A size-capped SQLite store intended only for volatile runtime state.
- An optional MQTT 5 read-only channel with TLS-only broker configuration,
  bounded inflight/packet sizes, automatic reconnect, fixed device topics, and
  `/tmp` SQLite request deduplication plus a bounded response outbox.
- A bounded declarative ActionSpec registry for user and vendor extensions.
  Trusted TOML manifests add read-only commands and typed inputs without a Rust
  rebuild. Execution uses exact argv, an empty environment, fixed concurrency,
  timeout and output limits; manifests may opt in to dynamic LLM tool exposure.
- A metadata-only `ask` task ledger with configurable retention. It records
  outcomes, provider/model, token usage, duration, and error code, but never
  prompts or model responses.
- Runtime `/tmp` pressure admission and a bounded artifact cleaner. Critical
  pressure blocks new diagnostic/LLM tasks while status and history remain
  available.
- The Phase 2 ChangeSet domain foundation: bounded typed object diffs, local
  semantic risk escalation, SHA-256 plan digests that bind actor/boot/version
  context, and a state machine that cannot skip approval, validation, rollback
  arming, or verification. Volatile SQLite now stores bounded plans and
  atomically binds one-use approval-token digests to the exact actor, boot, and
  plan while enforcing rollback deadlines.
- Local administrator authentication uses a salted PBKDF2-HMAC-SHA256 verifier
  from the root-only configuration. `mbed-agent auth elevate` grants only the
  authenticated actor a short-lived, daemon-RAM `device-admin` capability bound
  to the current boot ID and monotonic expiry. Password request buffers are
  redacted and zeroized; neither passwords nor capabilities enter SQLite.
  Approval-token issuance and the implemented firewall/network execution
  backends use this same boot-bound authorization boundary.
- Bounded rollback bundles now use typed, compiled target/reload mappings,
  SHA-256 snapshot verification, `O_NOFOLLOW`, durable atomic replacement, and
  a hidden independent `rollback-helper` mode in the same executable.
- The firewall domain now has a platform-neutral typed model and explicit CRUD
  planner for zones, forwarding, filter rules, homogeneous sets, and
  masquerade/SNAT/DNAT/redirect. Matches cover CIDR, MAC, protocol, ports,
  interfaces, zones, conntrack state, ICMP types, rate limiting, logging, and
  ordering. Updates/deletes/moves require fresh object digests; local semantic
  analysis raises exposure, management-path, and disruptive changes to R3.
- OpenWrt firewall staging now renders those plans into bounded UCI batches for
  both 21.02 fw3 and newer fw4 systems. Existing named/anonymous sections are
  resolved from a fresh local `uci show firewall` snapshot, unknown vendor
  options are preserved, unsafe selectors fail closed, and fixed native
  fw3 IPv4/IPv6 render checks or `fw4 check` must precede activation. This
  staging slice does not yet install or reload the live firewall.
- Generic Linux nftables staging now projects only Agent-owned objects into one
  fixed, ownership-marked `inet mbed_agent` table. It renders isolated filter,
  zone/forwarding, network/MAC/port sets, reject/log/rate/state matches, and
  masquerade/SNAT/DNAT/redirect state for fixed `nft --check` and atomic load
  operations. Existing host tables are never rewritten. Its explicit
  additive-coexistence capability notes that Agent drops are final while
  accepts cannot override a later distribution-owned drop.
- Generic Linux iptables/ip6tables staging now owns six fixed filter, mangle,
  and NAT chains per address family. It appends one ownership-marked hook,
  rebuilds only those chains through no-flush restore, expands typed
  network/MAC/port sets within hard limits, supports dual-stack filtering and
  NAT, and requires both restore `--test` checks plus independent rollback.
  Partial, duplicated, or foreign same-name chain state is never adopted.
- Runtime discovery for OpenWrt version, fw3/iptables, fw4/nftables, swconfig/DSA, ubus/UCI/procd, and opkg/apk.
- First-class generic Linux discovery using iproute2, native nftables/iptables,
  systemd-resolved, NetworkManager, and `/etc/resolv.conf`, without attempting
  OpenWrt-only ubus/UCI probes.
- Deterministic `diagnose wan`, `diagnose dns`, `diagnose dhcp`,
  `diagnose routes`, `diagnose interfaces`, and `diagnose neighbors` runbooks.
  The additional `diagnose firewall` runbook normalizes runtime fw3/fw4,
  iptables, and nftables counts; `diagnose policy-routing` normalizes policy
  selectors and aggregate route tables; `diagnose listeners` classifies bounded
  TCP/UDP binding exposure; `diagnose wireless` normalizes radio and interface
  state without scanning; `diagnose interface-stats` captures one bounded
  snapshot of cumulative kernel counters; `diagnose conntrack` reports kernel
  flow-table capacity without enumerating flows; `diagnose qdisc` normalizes
  bounded queueing counters. All gather bounded, read-only evidence across
  OpenWrt and generic Linux. Focused runs execute only their required collectors;
  the WAN run also includes firewall-backend and UCI zone evidence.
- OpenWrt procd and UCI configuration skeletons.
- A bounded OpenAI-compatible HTTPS provider, invoked through
  `mbed-agent ask`, with strict request/response limits, timeouts, disabled
  redirects, and redacted API-key configuration.
- A bounded read-only Agent loop with locally allowlisted `diagnose_wan`,
  `inspect_default_routes`, `inspect_dns`, `inspect_dhcp`,
  `inspect_wan_firewall`, `inspect_interfaces`, and `inspect_neighbors` tools.
  Runtime firewall totals and base-chain policies are exposed through two more
  expression-free tools. Policy rules and aggregate route tables have separate
  bounded views backed by one snapshot. Listening ports and non-loopback
  exposure have address-free views; wireless tools omit SSID values and AP
  addresses. Interface counters and nonzero error/drop counters have separate
  views backed by one snapshot. Conntrack capacity has a flow-free view, while
  qdisc totals and pressure counters have separate views backed by one snapshot.
The registry contains 20 built-in typed tools plus explicitly opted-in
read-only ActionSpec tools. ActionSpec change templates can also turn typed
inputs into the existing firewall or network mutation protocol without a Rust
rebuild. Tool arguments are parsed and validated on-device; model text cannot
become a shell command or bypass ChangeSet approval.

Provider routing, additional model-facing network tools, and MQTT mutual-TLS
identity remain deferred. WeChat ClawBot QR binding and the bounded official
text long-poll adapter are implemented. WeCom smart-bot WSS binding and the
bounded text callback adapter are also implemented; media remains deferred.
The channels support ping, status, read-only diagnostics, ask, and the bounded
typed ChangeSet plan/approval/apply/confirm flow. They never expose arbitrary
shell commands. Firewall
configuration execution is available through the bounded ChangeSet path on
supported OpenWrt fw3/fw4 and generic Linux nftables/iptables backends. The
L2/L3 typed object, validation, risk, projection, and execution-payload boundary
is implemented. OpenWrt 21+ has fresh UCI network inventory and confirmed writes
for the interface/Bridge/VLAN/route/policy-rule subset, including interface-level
`peerdns`, explicit resolver addresses, DNS search suffixes, and bounded DHCP
client options (`clientid`, `vendorid`, `hostname`, `reqopts`, `norelease`).
Generic Linux
with iproute2 has fresh interface/route/policy-rule inventory and confirmed
writes for enabled Agent-owned volatile routes and reserved-priority policy
rules. Routes use numeric protocol 186 and policy rules use preference range
32000-32063; neither writes persistent network-manager configuration. The local
CLI exposes
actor/boot/plan-bound ChangeSet inspection, rejection, device-admin approval,
apply, and confirmed commit for supported firewall and network backends. The
configuration roadmap is intentionally broader than a
few fixed operations: it targets capability-gated typed CRUD for firewall,
interfaces/addresses, bridges/VLANs, routes, DNS/DHCP, wireless, controlled
services, QoS, and WireGuard. OpenWrt will use UCI and its native fw3/fw4/netifd
control planes; generic Linux will use supported adapters and Agent-owned
nftables/iptables/network objects. Every write must pass plan/diff, dynamic risk,
approval, validation, bounded snapshot, verification, and confirmed rollback.
Unknown or unmanaged objects remain read-only; no LLM-controlled raw shell,
iptables, nft, UCI, or file-edit path is planned.
This scope and its safety boundary are recorded in
[ADR 0018](docs/adr/0018-maximal-safe-configurability.md).
The implemented ChangeSet domain boundary is recorded in
[ADR 0020](docs/adr/0020-changeset-domain-foundation.md).
Volatile ChangeSet and one-use approval storage is recorded in
[ADR 0021](docs/adr/0021-volatile-changeset-approval-store.md).
Boot-bound local administrator elevation is recorded in
[ADR 0022](docs/adr/0022-boot-bound-administrator-elevation.md).
Bounded snapshots and the independent rollback watchdog are recorded in
[ADR 0023](docs/adr/0023-bounded-independent-rollback.md).
The cross-platform typed firewall model and planner are recorded in
[ADR 0024](docs/adr/0024-typed-firewall-planner.md).
OpenWrt fw3/fw4 UCI staging and native validation are recorded in
[ADR 0025](docs/adr/0025-openwrt-firewall-staging.md).
Generic Linux isolated nftables staging is recorded in
[ADR 0026](docs/adr/0026-generic-linux-nftables-staging.md).
Generic Linux isolated iptables/ip6tables staging is recorded in
[ADR 0027](docs/adr/0027-generic-linux-iptables-staging.md).
The same-binary ChangeSet inspection and approval control surface is recorded in
[ADR 0028](docs/adr/0028-changeset-cli-approval-control.md).
Bounded fresh OpenWrt UCI inventory reconstruction and snapshot-bound rendering
are recorded in
[ADR 0029](docs/adr/0029-openwrt-firewall-fresh-inventory.md).
The platform-neutral L2/L3 schema, semantic risk, projection, and executable
payload boundary are recorded in
[ADR 0041](docs/adr/0041-typed-l2-l3-network-planner.md).
OpenWrt fresh network UCI inventory, ownership binding, capability narrowing,
and non-installing staging are recorded in
[ADR 0042](docs/adr/0042-openwrt-network-inventory-staging.md).
The OpenWrt network install/reload/verify transaction and independent rollback
target are recorded in
[ADR 0043](docs/adr/0043-openwrt-network-transaction-rollback.md).
OpenWrt network daemon admission and confirmed commit are recorded in
[ADR 0044](docs/adr/0044-daemon-openwrt-network-confirmed-commit.md).
Bounded generic Linux runtime network inventory is recorded in
[ADR 0045](docs/adr/0045-generic-linux-network-runtime-inventory.md).
Agent-owned generic Linux volatile route ownership and staging are recorded in
[ADR 0046](docs/adr/0046-generic-linux-runtime-route-staging.md).
The generic Linux runtime route native transaction is recorded in
[ADR 0047](docs/adr/0047-generic-linux-runtime-route-transaction.md).
Independent generic Linux runtime route recovery is recorded in
[ADR 0048](docs/adr/0048-generic-linux-runtime-route-rollback.md).
Generic Linux route daemon admission and confirmed commit are recorded in
[ADR 0049](docs/adr/0049-daemon-generic-linux-runtime-route-confirmed-commit.md).
Generic Linux Agent-owned policy-rule admission and reserved-priority
transaction support are recorded in
[ADR 0059](docs/adr/0059-generic-linux-policy-rules.md).
OpenWrt interface resolver overrides and their UCI transaction boundary are
recorded in
[ADR 0060](docs/adr/0060-openwrt-interface-dns-overrides.md).
OpenWrt interface DHCP client controls and their bounded UCI representation are
recorded in
[ADR 0061](docs/adr/0061-openwrt-interface-dhcp-client.md).
Declarative user/vendor actions and their bounded execution boundary are
recorded in [ADR 0050](docs/adr/0050-declarative-extension-actions.md).
Approval-bound change templates are recorded in
[ADR 0051](docs/adr/0051-declarative-action-change-templates.md).
The MQTT 5 read-only transport, deduplication, and bounded outbox are recorded in
[ADR 0052](docs/adr/0052-mqtt-read-only-channel.md).
The official WeChat ClawBot QR binding and atomic credential persistence are
recorded in [ADR 0053](docs/adr/0053-wechat-clawbot-binding.md).
The bounded `getupdates`/`sendmessage` text transport is recorded in
[ADR 0054](docs/adr/0054-wechat-clawbot-long-poll.md).
The official WeCom smart-bot WSS transport is recorded in
[ADR 0055](docs/adr/0055-wecom-aibot-websocket.md).
Typed Channel ChangeSet commands are recorded in
[ADR 0056](docs/adr/0056-channel-changeset-commands.md), and declarative
ActionSpec Channel commands in [ADR 0057](docs/adr/0057-channel-actionspec-commands.md).
Explicit actor-scoped capability revocation is recorded in
[ADR 0058](docs/adr/0058-explicit-capability-revocation.md).

The implemented and deferred Phase 0 decisions are recorded in
[ADR 0001](docs/adr/0001-runtime-foundation.md). This distinction is intentional:
the daemon foundation and bounded read-only channels are usable now, while
additional remote write capabilities remain disabled until their platform
transaction and rollback boundaries exist.

## Build and test

The workspace is pinned to Rust 1.85.1.

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p mbed-agent
```

## Local smoke test

Use the example configuration so the daemon does not read `/etc`:

```sh
cargo run -p mbed-agent -- daemon --config config/mbed-agent.example.toml
cargo run -p mbed-agent -- status
cargo run -p mbed-agent -- capabilities
cargo run -p mbed-agent -- diagnose wan
cargo run -p mbed-agent -- diagnose wan --active
cargo run -p mbed-agent -- diagnose dns
cargo run -p mbed-agent -- diagnose dhcp
cargo run -p mbed-agent -- diagnose routes
cargo run -p mbed-agent -- diagnose interfaces
cargo run -p mbed-agent -- diagnose neighbors
cargo run -p mbed-agent -- diagnose firewall
cargo run -p mbed-agent -- diagnose policy-routing
cargo run -p mbed-agent -- diagnose listeners
cargo run -p mbed-agent -- diagnose wireless
cargo run -p mbed-agent -- diagnose interface-stats
cargo run -p mbed-agent -- diagnose conntrack
cargo run -p mbed-agent -- diagnose qdisc
cargo run -p mbed-agent -- diagnose history --limit 20
cargo run -p mbed-agent -- task history --limit 20
cargo run -p mbed-agent -- action list
cargo run -p mbed-agent -- channel status
```

## MQTT channel

Set `[channels.mqtt].enabled = true` in the root-only daemon configuration and
provide a unique `client_id`, `device_id`, and `mqtts://host:port` broker. The
runtime uses the system TLS trust store, so the target image must include the CA
that signs the broker certificate. Username and password must either both be
set or both remain empty.

The daemon subscribes to
`mbed-agent/v1/devices/{device_id}/requests` and publishes bounded responses to
`mbed-agent/v1/devices/{device_id}/responses/{message_id}`. Requests are
versioned JSON with an expiry no more than ten minutes in the future; devices
therefore need a usable wall clock. The currently accepted command types are
`ping`, `status`, `ask`, and `diagnose`. MQTT cannot invoke Action runs,
ChangeSet planning/apply, elevation, or raw local protocol commands in this
slice.

```json
{
  "schema_version": 1,
  "message_id": "request-001",
  "actor_id": "operator-001",
  "conversation_id": "incident-001",
  "expires_unix_ms": 1785661800000,
  "command": { "type": "diagnose", "target": "dns" }
}
```

## WeChat ClawBot binding

The CLI uses the official Tencent QR login endpoint directly; it does not use a
project relay or store runtime cursors on Flash. Run the command on the device,
scan the displayed URL with WeChat, and confirm the login:

```sh
mbed-agent channel bind-wechat-clawbot --account default \
  --config /etc/mbed-agent/config.toml
mbed-agent channel status
```

After confirmation, the returned `bot_token` and HTTPS `base_url` are written
atomically to the root-only TOML configuration. The daemon automatically starts
the official `getupdates` long poll after restart, accepts bounded text messages,
dispatches them through the same local read-only Agent path, and replies through
`sendmessage` with the original `context_token`. Images, voice, files, and
remote changes are rejected until their own bounded adapters exist. A revoked
token is reported as `needs_rebind`.

## WeCom smart-bot binding

The official WeCom smart-bot long-connection mode uses a Bot ID and Secret;
there is no device-side QR flow for this protocol. Read the Secret from stdin
so it is not exposed in shell history, then restart (or start) the daemon:

```sh
printf '%s\n' "$WECOM_BOT_SECRET" | mbed-agent channel bind-wecom \
  --bot-id BOT_ID --account default \
  --config /etc/mbed-agent/config.toml
mbed-agent channel status
```

The command validates a host-only `wss://` endpoint and atomically writes the
root-only configuration. The daemon connects directly to the WeCom WSS service
after every restart, authenticates with `aibot_subscribe`, sends bounded
heartbeats, reconnects with backoff, deduplicates callback message IDs in the
volatile SQLite store, and replies with the official streaming response frame.
Only bounded text callbacks are dispatched to the Agent; events and media are
ignored until their bounded adapters are added. Repeated authentication failure
transitions the channel to `needs_rebind`.

All configured channels share the same bounded administrator elevation path. In
a verified one-to-one or approved group conversation, send `/elevate` followed
by the administrator password. The password is handled as a redacted typed
command, checked against the daemon's boot-bound verifier, and immediately
zeroized; it is never forwarded to the LLM, written to SQLite, or logged. The
resulting `device-admin` capability is scoped to that channel actor and the
current boot. Send `/deauth` from that same actor to revoke it immediately; the
equivalent local command is `mbed-agent auth deauth`.

After elevation, the same channel can use the typed ChangeSet flow without
shell interpolation:

```text
/firewall-inventory
/firewall-plan [{"operation":"create", ...}]
/change-get <change-set-id>
/change-approve <change-set-id>
/change-apply <change-set-id> <approval-id> <one-use-token>
/change-confirm <change-set-id>
```

Plans are still validated against a fresh firewall/network inventory; approval,
one-use tokens, rollback and confirmed commit remain mandatory for writes.

Declarative user/vendor actions are available through the same channel boundary:

```text
/action-list
/action-run <action-id> {"input":"value"}
/action-plan <change-action-id> {"input":"value"}
/action-reload
```

`action-run` only executes manifests declared read-only. `action-plan` expands a
trusted change template into the same typed ChangeSet path; `action-reload`
requires the channel actor's current `device-admin` capability.

## User and vendor actions

Set `extensions.enabled = true`, then place mode-0600/0644 TOML manifests
directly in `/etc/mbed-agent/actions.d` or
`/usr/share/mbed-agent/actions.d`. The directories and files must not be
symlinks or writable by group/other, and must match the configured trusted
manifest owner UID (root by default). Executables and fixed shell scripts must
likewise match the separately configured trusted executable UID. See
[the ActionSpec example](docs/examples/action-manifest.toml).

After daemon startup, list and execute an action through the same binary:

```sh
mbed-agent action list
mbed-agent action run vendor_modem_status --inputs '{"modem_id":1}'
mbed-agent action plan block_client_mac \
  --inputs '{"rule_id":"block_phone","client_mac":"02:00:00:00:00:01","order":100}'
```

Manifest changes can be loaded without restarting the daemon after obtaining a
device-admin capability:

```sh
mbed-agent action reload
```

An ActionSpec fixes the absolute executable and argv shape. Inputs are typed as
bounded strings, integers, or booleans and become individual argv elements;
they are never concatenated into a shell command. A trusted shell script is
supported by setting the executable to `/bin/sh` and the first literal argument
to an absolute, non-`/tmp` script path. `sh -c` and `sh -lc` are rejected. Do
not pass secrets through actions because process arguments can be visible to
the operating system. `llm_enabled` defaults to false and must be explicitly
enabled by the manifest owner before an action appears as an `ext_*` model tool.
Action output remains bounded and is not persisted; only execution metadata is
written to the volatile task ledger.

An action with `mode = "change"` has no executable or argv. Its bounded
`template_json` contains only a closed firewall or network mutation array and
exact `{"$input":"name"}` placeholders. `action plan` substitutes validated
JSON values (never string interpolation), deserializes the result into the
normal typed protocol, reads a fresh native inventory, and returns an
approval-ready ChangeSet. Apply and confirmation use the same device-admin,
one-use token, native validation, independent rollback helper, and live verify
path as built-in changes. Change templates are not currently exposed as LLM
tools; channels cannot silently cause a configuration write.

To enable local administrator elevation, generate a salted verifier without
placing the plaintext password in shell arguments:

```sh
printf '%s\n' 'replace-with-a-strong-password' \
  | cargo run -p mbed-agent -- auth hash-password
```

Copy the result to `auth.admin_password_hash`, set `auth.enabled = true`, make
the configuration mode `0600`, and restart the daemon. Elevate the local CLI
actor by sending the password over stdin:

```sh
printf '%s\n' 'replace-with-a-strong-password' \
  | cargo run -p mbed-agent -- auth elevate
```

The returned capability expires after `auth.capability_ttl_secs` and disappears
on daemon restart. Failed authentication is rate-limited per actor with
`auth.max_failures` and `auth.lockout_secs`. The same authenticator is designed
for verified MQTT, WeCom, and WeChat actors; channel adapters do not bypass local
policy. Revoke the local CLI actor without entering a password:

```sh
cargo run -p mbed-agent -- auth deauth
```

For a Channel actor, send `/deauth`; revocation is actor-scoped, immediate, and
stored only in daemon memory. Passwords are never accepted as command-line
arguments.

Typed firewall mutations can be planned, inspected, approved, executed, and
confirmed through the same binary. `firewall-plan` reads a JSON array of closed
`create`, `update`, `delete`, or `move` requests from stdin:

```sh
cargo run -p mbed-agent -- change firewall-inventory > firewall-inventory.json
cargo run -p mbed-agent -- change firewall-plan < docs/examples/firewall-create-zone.json
cargo run -p mbed-agent -- change get CHANGE_SET_ID
cargo run -p mbed-agent -- change approve CHANGE_SET_ID | \
  cargo run -p mbed-agent -- change apply CHANGE_SET_ID
cargo run -p mbed-agent -- change confirm CHANGE_SET_ID
cargo run -p mbed-agent -- change reject CHANGE_SET_ID
```

The example demonstrates the exact tagged JSON shape. `firewall-inventory`
returns every fresh typed object and its 64-character digest. Update, delete,
and move requests copy that value into `expected_digest`; stale digests are
rejected when planning and again immediately before execution.

Approval requires a current local `device-admin` elevation. Its response contains
the raw one-use token exactly once; only its digest is retained in `/tmp`
SQLite. Planning always uses a fresh live UCI inventory and persists the preview
and full executable payload atomically. `apply` cannot accept replacement rule
content: it consumes only the exact one-use approval token. OpenWrt fw3/fw4
execution then performs staging, native validation, independent rollback,
runtime verification, and risk-based confirmation.
`apply` accepts the complete approval response from stdin and checks its
ChangeSet/approval binding before extracting the secret. A raw token is also
accepted from stdin when `--approval-id` is supplied.

Fresh L2/L3 inventory is available on OpenWrt 21.02+ and generic Linux with
iproute2. OpenWrt changes use the same lifecycle and the same binary:

```sh
cargo run -p mbed-agent -- change network-inventory > network-inventory.json
cargo run -p mbed-agent -- change network-plan < network-mutations.json
cargo run -p mbed-agent -- change approve CHANGE_SET_ID | \
  cargo run -p mbed-agent -- change apply CHANGE_SET_ID
cargo run -p mbed-agent -- change confirm CHANGE_SET_ID
```

Network mutations are closed typed objects (interfaces, bridges, VLANs, routes,
and policy rules in the currently supported backend subset), never raw shell,
argv, UCI text, or `ip` text. Public network writes are always elevated to R3
and require confirmation. OpenWrt arms an independent `/etc/config/network`
rollback helper. Generic Linux accepts enabled Agent-owned routes and policy
rules only: routes carry protocol 186 and policy rules use preference range
32000-32063. Both store canonical ownership only in bounded `/tmp` SQLite and
arm an independent reverse `ip -force -batch` helper. Interface resolver
overrides are currently OpenWrt-only (`peerdns`, `dns`, `dns_search`, and the
bounded DHCP client options) and
use the same transaction; generic Linux resolver files and unknown
network-manager state remain read-only. Interfaces, addresses, ordinary
platform routes, and persistent generic Linux network-manager files remain
read-only.

To exercise an OpenAI-compatible endpoint, copy the example configuration,
enable `[llm]`, and set its HTTPS `base_url`, `api_key`, and `model`. Then restart
the daemon. A credential-bearing configuration must be mode `0600` (or stricter).
Then run:

```sh
cargo run -p mbed-agent -- ask "Explain the likely WAN fault from this symptom"
```

The daemon owns the provider credentials; the CLI never reads them. Provider
traffic uses bounded SSE streaming by default, although the current local IPC
returns one final completion to keep its protocol stable. Set `llm.streaming =
false` for compatible endpoints that only implement JSON responses. HTTP
redirects are disabled, and traffic is bounded by `llm.max_request_bytes`,
`llm.max_response_bytes`, `llm.max_stream_event_bytes`, the configured timeouts,
the whole-Agent `runtime.task_timeout_secs`, and the runtime concurrency limit.
Prompts and responses are not written to SQLite. `ask` task metadata is retained
only up to `storage.max_task_records` and is discarded with the rest of `/tmp`
state at reboot.
When the model requests WAN evidence, the daemon runs only the passive typed
diagnostic and sends the minimum normalized projection needed by the selected
tool. Multiple WAN tools in one `ask` reuse the same in-memory snapshot. Raw
probe output is excluded from model context; one bounded diagnostic summary is
retained in volatile SQLite for local audit history.

Diagnostic commands never invoke a shell. Their executable names and arguments
are compiled into a typed allowlist, and configuration limits each probe's time
and retained output as well as the number and total duration of diagnostic tasks.
Active mode is explicit and runs only after passive WAN prerequisites pass. It
uses a validated route gateway plus fixed public-IP and DNS canaries; an ICMP
failure is reported as a failed probe, not asserted to be the root cause.
The focused DNS and route commands are passive: `diagnose dns` reports resolver
configuration and its link/address/route prerequisites but does not claim that
an external DNS query succeeded.
`diagnose dhcp` never renews a lease. OpenWrt uses normalized ubus protocol and
pending state; generic Linux reports DHCP only when `ip -j` marks an address as
dynamic, otherwise it returns insufficient evidence instead of guessing.
`diagnose interfaces` uses only bounded kernel link/address collectors on both
OpenWrt and generic Linux. It retains at most 32 interfaces and eight validated
IP addresses per interface, reports inventory truncation explicitly, and does
not run route, DNS, firewall, or active-connectivity probes.
`diagnose neighbors` passively reads the kernel ARP/NDP cache, retains at most
64 validated entries, and distinguishes incomplete/failed resolution without
claiming a root cause. Link-layer addresses remain available to the local CLI
but are removed before an observation is sent to an LLM.
`diagnose firewall` selects nftables for fw4/native nft systems and
iptables-save/ip6tables-save for fw3/native iptables systems. It normalizes only
bounded table, chain, rule, counter, hook, and policy metadata. Raw rule
expressions remain local evidence and are never persisted or sent to an LLM.
`diagnose policy-routing` normalizes at most 64 `ip rule` entries and aggregates
at most 32 route tables. It recognizes conventional local/main/default rules,
validated CIDR selectors, marks and interface selectors, while individual
non-default route details remain outside model context and SQLite.
`diagnose listeners` prefers `ss` and falls back to BusyBox/full `netstat`.
It retains at most 128 TCP/UDP listeners without requesting process identities,
classifies wildcard/loopback/link-local/specific bindings, and omits exact local
addresses from every LLM observation.
`diagnose wireless` uses OpenWrt ubus status plus passive `iw dev` or `iwinfo`
fallback evidence. It retains at most 16 radios and 32 interfaces, never scans
or changes association state, and replaces local SSID values with a boolean
presence marker before sending observations to an LLM.
`diagnose interface-stats` runs one bounded `ip -j -s link show` collector on
OpenWrt and generic Linux. It accepts `stats64` and legacy `stats`, retains at
most 32 interfaces, and reports cumulative RX/TX bytes, packets, errors, and
drops. A single snapshot cannot establish a current traffic, loss, or error
rate, so the diagnostic never makes rate claims.
`diagnose conntrack` reads only `nf_conntrack_count` and `nf_conntrack_max`
from procfs. It reports capacity utilization and a 90% near-capacity threshold
without reading connection tuples, addresses, ports, or payload.
`diagnose qdisc` uses one bounded `tc -j -s qdisc show` snapshot, retains at
most 64 qdiscs, and reports packet, byte, drop, overlimit, requeue, backlog, and
queue-length counters. These counters are cumulative; one snapshot does not
establish a current loss or congestion rate.

Completed diagnostics store only the normalized summary in `/tmp` SQLite; raw
probe output is not persisted. History is bounded by configurable record-count
and per-record byte limits, and oldest entries are pruned transactionally.

At startup and every `storage.cleanup_interval_secs`, the daemon prunes only
direct regular-file children of its managed `artifacts/` directory to
`storage.max_artifacts_bytes` and `storage.max_artifact_files`. It ignores
symlinks, subdirectories, and non-regular files, and never cleans rollback
state, SQLite, logs, sockets, or
configuration. Before starting a diagnostic or LLM task, the daemon checks both
managed usage and filesystem free-space reserves. Critical or emergency
pressure triggers one cleanup attempt and then rejects the new task if pressure
remains; `ping`, `status`, capabilities, and history queries remain usable.

Logging is bounded by level/filter, line bytes, file bytes, rotated file count,
total bytes, and `logging.rate_limit_per_target_per_sec`. The rate limiter keeps
at most 64 target counters and uses one shared overflow bucket. Dropped records
never allocate a line buffer or write a recursive warning; their cumulative
count is exposed as `logging_dropped_records` in `mbed-agent status`. Log files
are created as mode `0600` with `O_NOFOLLOW`, and non-regular paths are rejected.

All generated runtime state is placed below `/tmp/mbed-agent` and may be discarded at reboot.

## OpenWrt integration

The `openwrt/files` tree contains the initial procd service and UCI/config files.
It targets OpenWrt 21.02 and later and does not assume either fw3 or fw4; runtime
capability discovery selects the available firewall stack. A feed package
Makefile and per-architecture `.ipk`/`.apk` artifacts will be added only after
validation against real OpenWrt SDK images.

## Generic Linux integration

The `packaging/linux` tree contains service definitions for systemd, OpenRC, and
BusyBox init. Runtime discovery reports the active init system and common package
manager, but the agent never installs packages at runtime. The systemd unit
restricts writable paths to `/tmp/mbed-agent` and the explicit agent
configuration directory.
