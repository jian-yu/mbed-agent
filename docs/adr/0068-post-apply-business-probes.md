# ADR 0068: Bounded post-apply network business probes

- Status: Accepted
- Date: 2026-08-09

## Context

Native typed verification proves that the requested objects exist after a
network transaction, but it does not prove that the device's WAN service still
works. A default-route or WAN interface change can therefore look correct while
breaking the actual management or Internet path.

## Decisions

1. A network ChangeSet that touches an interface whose id/device is `wan`, or a
   route with a zero-length destination prefix, runs one bounded active WAN
   diagnostic after native typed verification and before the user confirmation
   window is accepted.
2. The probe uses the existing shell-free `ToolRunner` and its configured
   timeout/output limits. It may collect the gateway, public-IP and DNS probes
   already used by `diagnose wan`; it never forwards raw probe output into the
   model or SQLite.
3. The probe requires a usable WAN address, default route, resolver, a
   successful DNS probe, and (when a gateway was discovered) a successful
   gateway probe. Missing prerequisites, unavailable collectors, malformed
   evidence, or a probe worker error fail closed. A public-IP ICMP failure is
   recorded but is not independently required because some networks block it.
4. A failed probe calls the same `AwaitingConfirmation → RollingBack` path as a
   native verification failure and requests the independently armed rollback
   helper. The ChangeSet is reported as rolled back (or rollback failed), never
   as an ordinary confirmation opportunity.
5. LAN-only address/profile, non-default route, policy-rule, firewall, and
   other network changes retain typed native verification without an unrelated
   WAN probe. This avoids false rollbacks for intentionally isolated devices.

## Consequences

WAN/default-route writes now validate a bounded business invariant before the
confirmation decision. The active probe adds at most one configured tool
timeout to the execution path and may reject a change when the target network
is intentionally offline; such changes must remain in the typed, non-WAN
configuration slices or be handled by a future explicit probe policy.
