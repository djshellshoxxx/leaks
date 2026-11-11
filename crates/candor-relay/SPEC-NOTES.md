<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-relay SPEC notes

## Decisions
The crate models protocol invariants separately from TLS/signature I/O. Counter zero and non-increasing counters are rejected; exhaustion never wraps. Claims stop at 50,000 pending imports or below 10% free capacity. Outbound policy is exact-endpoint allow-list; inbound application connections are denied.

## Security self-review
No source content, identifiers, filenames, times, sizes or free-text logging are accepted. No unsafe code or filesystem access. Firewall tests assert default-deny and relay-only initiation.

## Open items
Production transport wiring must perform the spec's pinned TLS 1.3 and Ed25519 request-signature checks and persist counters transactionally. Full AT-020..024 requires the release-candidate lab.

## Request authentication (07 §5.4; added 2026-11-11)

**Implementation decision: request signature layout.** The spec names the signed fields
(`method ‖ path ‖ sha256(body) ‖ req_counter`); this crate fixes the bytes so both sides agree
and no two requests share a message: `b"candor/relay-req/v1" ‖ u64be(len(method)) ‖ method ‖
u64be(len(path)) ‖ path ‖ sha256(body) ‖ u64be(counter)` (`request_signing_message`). The
length prefixes make the encoding injective; the label separates it from every other Candor
signature form. Verification is `candor_core::sig::verify_strict` (strict RFC 8032, audited in
RM-1) over the pinned public key; the verifier never holds a private key.

**Order of checks** (`RelayAuthenticator::verify`): shape (method 1–16 bytes, uppercase ASCII;
path ≤ 1024 bytes, leading `/`, ASCII graphic) → counter rule, not yet committed → signature →
commit. A forged or replayed request therefore never advances the counter and learns nothing
beyond the public counter rule. The counter rule is one function (`counter::check_counter`)
shared with `RelayGuard`: zero and non-increasing counters are replays; `u64::MAX` is terminal
(identity replacement, never a wrap).

**Persistence contract.** `last_counter()` is the value the transport adapter persists durably
*before* acting on the request and restores through `RelayAuthenticator::new` at start (07 §5.4:
persisted on both sides). Losing it reopens replay for the lost window; that is the adapter's
open item below.

**Backpressure.** `Backpressure::new(free_percent, pending_imports).must_stop()` applies the
default 07 §5.4 thresholds through the same predicate as `RelayGuard::may_claim`.

### Dependencies
- `candor-core` (path): SHA-256 and strict Ed25519 verification; no second implementation.
- `ed25519-dalek =3.0.0` (default features off, `fast`): only for the `VerifyingKey` type in
  `RelayAuthenticator::new`; already in the workspace lock and vet set.
- `proptest` (dev): sign/verify round trip and signature/body/counter mutation properties.

### Security self-review (delta)
- No secret material in the crate; the only key is public. `Debug` on the authenticator prints
  the public key and counter, nothing else.
- Hostile input is bounded before any hashing (method/path limits); the body is hashed as a
  slice, so its size cap is the transport's (07 §11) and must be enforced before the call.
- Tests cover tampering of each signed field, wrong key, malformed shape, counter zero,
  exhaustion, restart with a persisted counter, and a 128-case property test.
- Residual: pinned TLS 1.3, body-size caps, counter persistence and the time source stay in the
  transport adapter (unchanged open item).
