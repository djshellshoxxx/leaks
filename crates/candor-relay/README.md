<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-relay

RM-3 core-side relay policy and state machine for C-09. It enforces strictly increasing request counters, import backpressure, and a single configured intake destination. The reference nftables fixture is default-deny and permits only the relay service to initiate the intake-link connection on TCP 7443.

Cryptographic request signatures and mutually pinned TLS belong to the transport adapter described in `specs/07-BACKEND.md`; this crate isolates the replay/backpressure/network-policy invariants so they can be tested without sockets.

Run `cargo test -p candor-relay` and `cargo clippy -p candor-relay --all-targets -- -D warnings`.
