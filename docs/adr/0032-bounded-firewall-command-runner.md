# ADR 0032: Bounded firewall command runner

- Status: Accepted
- Date: 2026-07-28

## Context

The execution coordinator needs concrete native operations on OpenWrt and
generic Linux. Reusing a general shell or accepting caller-built argv would
turn typed configuration into arbitrary root command execution. Embedded
commands can also hang or produce unbounded output.

## Decisions

1. Expose a closed `FirewallCommand` enum for UCI inspection/batch, fw3/fw4
   checks, OpenWrt firewall reload, nftables inspection/check/load, and
   dual-stack iptables save/test/load.
2. Resolve only fixed executable names below `/usr/sbin`, `/usr/bin`, `/sbin`,
   and `/bin`. OpenWrt reload uses only `/etc/init.d/firewall`. Reject symlink
   executables and non-executable files.
3. Invoke `std::process::Command` directly with a cleared environment. Never
   invoke `sh -c`, parse user command text, or accept arbitrary environment
   variables. Only the internally validated `UCI_CONFIG_DIR` is set for fw3/fw4.
4. Accept stdin only for UCI batch and iptables restore operations. Enforce
   configured input limits before spawn.
5. Accept nftables files and UCI directories only when their canonical paths
   remain below the configured `/tmp` runtime root. Reject relative paths,
   parent traversal, final symlinks, parent-symlink escapes, wrong file types,
   and oversized files.
6. Drain stdout and stderr concurrently with independent bounded readers.
   Kill and reap timed-out children. Treat truncation and non-zero exit as
   failure; command output is diagnostic evidence, never authorization.

## Consequences

Concrete firewall adapters can now perform native inspection, dry-run, and
activation without gaining a generic command primitive. The same runner works
on OpenWrt 21+ and conventional Linux layouts.

The runner does not itself authorize a ChangeSet or choose a desired state. It
is usable for writes only through the execution port and coordinator.
