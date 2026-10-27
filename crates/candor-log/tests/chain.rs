// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash chain, checkpoints, verification, timestamp policy, retention and
//! sinks (AUD-001..AUD-005, AUD-012, LOG-004, LOG-012, LOG-013, LOG-021),
//! plus the AUD-RM1-LOG-01/02/07/08/13 regressions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![allow(
    clippy::disallowed_methods,
    reason = "audit/verify tooling tests: build audit.* events from verification failures and reports (Seq::of_failure / SeqRange::within, AUD-RM1-LOG-26)"
)]

mod common;

mod chain {
    mod checkpoints;
    mod disposal;
    mod integrity;
    mod sinks;
    mod support;
    mod timestamps;
}
