<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-relay SPEC notes

## Decisions
The crate models protocol invariants separately from TLS/signature I/O. Counter zero and non-increasing counters are rejected; exhaustion never wraps. Claims stop at 50,000 pending imports or below 10% free capacity. Outbound policy is exact-endpoint allow-list; inbound application connections are denied.

## Security self-review
No source content, identifiers, filenames, times, sizes or free-text logging are accepted. No unsafe code or filesystem access. Firewall tests assert default-deny and relay-only initiation.

## Open items
Production transport wiring must perform the spec's pinned TLS 1.3 and Ed25519 request-signature checks and persist counters transactionally. Full AT-020..024 requires the release-candidate lab.
