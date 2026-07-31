# ADR 0038: Generic nftables presence probe

- Status: Accepted
- Date: 2026-07-31

## Context

The fixed command `nft list table inet mbed_agent` exits unsuccessfully both
when the managed table is absent and for operational failures. Treating every
failure as first use would let execution overwrite an uninspected state or
hide a broken nftables control plane.

## Decisions

1. Add the closed, shell-free command `nft list tables`, retaining the existing
   timeout and output caps.
2. Strictly parse every non-empty output line as exactly `table <family>
   <name>`. Reject controls, oversized output, malformed lines, and duplicate
   declarations of the exact `table inet mbed_agent` identity.
3. Invoke `nft list table inet mbed_agent` only after the presence probe proves
   the table exists. If it does not exist, represent the observation explicitly
   as absent rather than inferring absence from a command error.
4. Reconcile the resulting owned/absent observation with the boot-bound
   volatile canonical state before returning a typed inventory. A present
   table without canonical state remains orphaned and read-only.

## Consequences

Generic Linux nftables transactions now have an unambiguous fresh-inspection
primitive for both first use and existing managed state. ADR 0039 builds the
native transaction, runtime-only rollback, and daemon admission on this probe.
