<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-relay

RM-3 core-side relay policy and state machine for C-09. It enforces strictly increasing request counters, import backpressure, and a single configured intake destination. The reference nftables fixture is default-deny and permits only the relay service to initiate the intake-link connection on TCP 7443.

`RelayAuthenticator` verifies the `Candor-Relay-Sig` request signature (Ed25519 over `method ‖ path ‖ sha256(body) ‖ req_counter`, strict verification from `candor-core`) and enforces the persisted monotonic counter; `Backpressure` applies the 07 §5.4 thresholds. Mutually pinned TLS, counter persistence and body caps belong to the transport adapter; this crate isolates the signature/replay/backpressure/network-policy invariants so they can be tested without sockets. The byte layout of the signed message is fixed in `SPEC-NOTES.md`.

Run `cargo test -p candor-relay` and `cargo clippy -p candor-relay --all-targets -- -D warnings`.
