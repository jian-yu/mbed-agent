# ADR 0061: OpenWrt interface DHCP client controls

- Status: Implemented
- Date: 2026-08-09
- Scope: OpenWrt 21.02+ `network` UCI interface objects

## Context

DHCP client behavior is part of an interface's network contract. Operators
often need to control the client identifier, vendor identifier, hostname,
requested option codes, or release behavior when diagnosing a lease or identity
problem. These values must not become arbitrary UCI text or a shell command.

## Decision

`NetworkInterfaceConfig` carries five bounded, non-secret fields mapped to UCI:

- `dhcp_client_id` -> `clientid`;
- `dhcp_vendor_id` -> `vendorid`;
- `dhcp_hostname` -> `hostname`;
- `dhcp_request_options` (unique option codes 1..255, at most 16) -> `reqopts`;
- `dhcp_no_release` -> `norelease`.

The OpenWrt adapter accepts these options only when the whole interface section
is representable. Fresh inventory parses scalar and list values, validates them
with the same core object validator, and records all present options in the
snapshot binding. Staging deletes and recreates only the supported options,
preserving unrelated vendor options on native sections. The existing UCI export,
atomic install, netifd reload, fresh verification, independent rollback, and
confirmed-commit lifecycle remains unchanged.

Generic Linux exposes empty defaults in its runtime inventory but does not write
DHCP client configuration because the owning network manager is unknown. DHCP
credentials, secrets, and arbitrary option payloads are not part of this slice.

## Consequences

- Existing CLI/channel `network-plan` requests can change DHCP client behavior
  without adding a new command or bypassing device-admin/R3 approval.
- Text values reject empty/control/quote/backslash input and option lists reject
  duplicates, zero, and capacity overflow before any UCI staging.
- Older serialized plans remain compatible because all new fields use serde
  defaults.
