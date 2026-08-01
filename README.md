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
  Approval-token issuance and execution backends remain disabled until their
  following safety slices are complete.
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
  The registry now contains 20 typed tools. Tool arguments are parsed and
  validated on-device, and the model can never request active probes or shell
  commands.

Provider routing, additional model-facing network tools, MQTT, WeCom, WeChat
ClawBot, and Channel-facing elevation are not implemented yet. Firewall
configuration execution is available through the bounded ChangeSet path on
supported OpenWrt fw3/fw4 and generic Linux nftables/iptables backends. The
L2/L3 typed object, validation, risk, projection, and execution-payload boundary
is implemented. OpenWrt 21+ additionally has fresh UCI network inventory and
bounded `/tmp` staging for the initial interface/Bridge/VLAN/route/policy-rule
subset. The native OpenWrt network transaction and independent
`/etc/config/network` rollback target are implemented, but host network writes
remain closed at the public admission layer until daemon/CLI is connected to
the common R3 confirmed-commit lifecycle. The local CLI exposes
actor/boot/plan-bound ChangeSet inspection, rejection, device-admin approval,
apply, and confirmed commit for supported firewall backends. The configuration
roadmap is intentionally broader than a
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

The implemented and deferred Phase 0 decisions are recorded in
[ADR 0001](docs/adr/0001-runtime-foundation.md). This distinction is intentional:
the daemon foundation is usable now, while L2/L3 host-changing tools and remote
channels remain disabled until their platform transaction and rollback
boundaries exist.

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
```

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
for verified MQTT, WeCom, and WeChat actors, but those adapters are not connected
yet. Passwords are never accepted as command-line arguments.

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
