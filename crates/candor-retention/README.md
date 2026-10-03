<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-retention

RM-3 retention/disposal state machine. Due selection uses coarse day values and excludes legal holds. Disposal is ordered as checkpointed tombstone, erasure-key destruction, then content disposal; each transition is idempotent for retry safety.

Run `cargo test -p candor-retention` and `cargo clippy -p candor-retention --all-targets -- -D warnings`.
