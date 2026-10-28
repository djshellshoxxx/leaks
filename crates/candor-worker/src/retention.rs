// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case retention decision rules (data-retention §5.3, RET-007, RET-009).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionAction {
    Noop,
    ProposeDisposal,
    DisposeApprovedByPolicy,
}

/// Inputs to the retention decision for one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionCase {
    pub due: bool,
    pub legal_hold: bool,
    pub disposal_proposal_exists: bool,
    pub auto_dispose_after_grace: bool,
    pub grace_elapsed: bool,
}

impl RetentionCase {
    /// Legal hold always wins. Disposal is never silent: a due case first gets
    /// a proposal, and automatic disposal happens only when the explicit tenant
    /// option is on, a proposal exists, and the grace period has elapsed.
    #[must_use]
    pub const fn evaluate(&self) -> RetentionAction {
        if self.legal_hold || !self.due {
            return RetentionAction::Noop;
        }
        if !self.disposal_proposal_exists {
            return RetentionAction::ProposeDisposal;
        }
        if self.auto_dispose_after_grace && self.grace_elapsed {
            RetentionAction::DisposeApprovedByPolicy
        } else {
            RetentionAction::Noop
        }
    }
}
