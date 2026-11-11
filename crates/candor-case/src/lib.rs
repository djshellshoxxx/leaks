// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
//! Candor Case Service (C-10) core and the route-facing surface of the C-22 decision point.
//!
//! The authorization engine lives in `candor-authz::pdp` (one PDP, 15 §5.9); this crate
//! re-exports it so route handlers depend on one name space. The Case Service core keeps
//! unauthorized and nonexistent lookups indistinguishable (uniform 404, 15 §5.10).

mod service;

pub use candor_authz::pdp::{
    Action, AuthzContext, Decision, DenyCode, MAX_WRAP_RECIPIENTS, Obligation, Principal,
    ResourceRef, Role, WrapCandidate, WrapError, authorize, validate_key_wraps,
};
pub use service::{AuditCommit, AuditCommitFailed, CaseError, CaseService, ImportOutcome};
