<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-ekv

RM-3 Erasure Key Vault core. It issues opaque handles for per-case erasure keys, requires two distinct approvers before destruction, zeroizes key bytes at destruction, and makes destruction irreversible and retry-safe.

Run `cargo test -p candor-ekv` and `cargo clippy -p candor-ekv --all-targets -- -D warnings`.
