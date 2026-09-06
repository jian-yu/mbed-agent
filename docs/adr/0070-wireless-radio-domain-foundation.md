# ADR 0070: Typed wireless radio configuration foundation

- Status: Accepted
- Date: 2026-09-06

## Context

The wireless diagnostic path already observes OpenWrt and generic Linux state,
but a writable wireless capability needs a platform-independent object model
before it can safely modify UCI, hostapd, or wpa_supplicant configuration.
Accepting raw UCI statements or shell fragments would bypass ownership,
validation, approval, verification, and rollback. Modeling SSIDs and credentials
at the same time would also mix the first non-secret radio transaction with a
separate secret-lifecycle problem.

## Decisions

1. The first wireless configuration slice models only a physical radio. Its
   closed typed fields are enabled state, band, channel mode/value, channel
   width, uppercase two-letter country code, and transmit power. The protocol
   rejects unknown fields and has no raw UCI, shell, SSID, encryption, or key
   escape hatch.
2. The core planner initially supports update only. It requires a fresh object
   digest, preserves the object id and platform-native ownership, rejects no-op
   and duplicate mutations, and binds the complete before/after objects to the
   public ChangeSet preview.
3. Every radio update is risk level R3 and carries a service-disruption signal.
   A radio identified as part of the management path also carries the management
   path signal. Platform-specific validation may raise or reject the operation;
   it may never lower this baseline.
4. Validation is intentionally stricter than permissive driver parsers: ids are
   bounded, country codes are canonical, transmit power is bounded, and fixed
   channels and widths must be compatible with the selected band. A backend
   must additionally validate the actual hardware and regulatory capabilities.
5. The execution payload is schema-versioned, bounded to 64 KiB, and revalidates
   the preview, typed objects, and SHA-256 digests after decoding. Unknown or
   third-party wireless objects remain read-only.
6. The runtime continues to report wireless as `read_only` until one complete
   backend supplies fresh inventory, isolated staging, native validation,
   activation, typed verification, confirmed commit, and independent rollback.
   Protocol and planner availability alone do not constitute writable support.
7. OpenWrt UCI radio transactions are the next backend slice. SSID/interface,
   encryption/key side-channel handling, network binding, isolation, and MAC
   policy follow as separate slices. Generic Linux becomes writable only for a
   recognized, transactionally managed hostapd/wpa_supplicant control plane.

## Consequences

The domain can evolve without adding a new hard-coded command for every radio
field, while LLM and extension input remains constrained to a reviewable typed
contract. No new user-visible write capability is advertised yet. Completing
the OpenWrt backend will require exact preservation of unknown UCI options,
hardware-aware validation, management-path confirmed commit, and volatile
rollback artifacts before the capability can change to `writable_confirmed`.
