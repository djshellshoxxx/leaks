// SPDX-License-Identifier: AGPL-3.0-or-later
//! Policy decision point (C-22; 15 §5.9): `authorize(principal, action, resource, context)`,
//! a pure function with no I/O over facts the Case Service loads in the same transaction.
//!
//! Evaluation order is the normative one from 15 §5.4:
//! (1) audience and tenant → (2) explicit deny (blinded COI tag, suspended) → (3) role
//! permission from the 15 §5.2 matrix → (4) relation (case ACL) → (6) obligations
//! (dual control, step-up, audited access). Everything not explicitly permitted is denied.
//! Attribute conditions (step 5: department scope, AAL, flags) are loaded by the route layer
//! into `ResourceRef::visible` / `member` and are not re-derived here.
//!
//! Denial codes never distinguish a COI exclusion from a missing ACL relation or a hidden case
//! (`DenyCode::NoRelation`, 15 §5.4, THR-020), so the Desk and the audit trail learn nothing
//! about whose blinded tag matched. The baseline invariants of 15 §5.9 are not overridable:
//! tenant isolation, COI deny-overrides, admin ∉ case content, dual control, no global read.

use crate::Audience;
use std::collections::BTreeSet;

/// Staff roles of 15 §5.1 (the columns of the §5.2 matrix).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Triager,
    Investigator,
    CaseLead,
    Reviewer,
    ChannelOwner,
    IdentityCustodian,
    Counsel,
    Oversight,
    RecordsCustodian,
    Auditor,
    Metrics,
    SecurityOfficer,
    SysAdmin,
    UserAdmin,
}

impl Role {
    /// Every role, for exhaustive tests.
    pub const ALL: [Role; 14] = [
        Role::Triager,
        Role::Investigator,
        Role::CaseLead,
        Role::Reviewer,
        Role::ChannelOwner,
        Role::IdentityCustodian,
        Role::Counsel,
        Role::Oversight,
        Role::RecordsCustodian,
        Role::Auditor,
        Role::Metrics,
        Role::SecurityOfficer,
        Role::SysAdmin,
        Role::UserAdmin,
    ];

    /// System-administration roles (15 §4.6 admin audience). A principal holding any of them
    /// never receives case content, whatever else it holds (ADR-015, 15 §5.7).
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(
            self,
            Role::SysAdmin | Role::UserAdmin | Role::SecurityOfficer
        )
    }
}

/// Case-scoped actions decided here (the 15 §5.2 rows that take a case as the resource).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// `case.import` (Triage Set members; OVERSIGHT canary as a silent member).
    Import,
    /// `case.read_content`.
    ReadContent,
    /// `case.transition`.
    Transition,
    /// `case.close/dismiss approve`.
    CloseApprove,
    /// `case.member_add`.
    MemberAdd,
    /// `evidence.open` (containment levels L1/L2).
    OpenEvidence,
    /// `evidence.export_rendition`.
    ExportRendition,
    /// `evidence.export_original`.
    ExportOriginal,
}

impl Action {
    /// Every action, for exhaustive tests.
    pub const ALL: [Action; 8] = [
        Action::Import,
        Action::ReadContent,
        Action::Transition,
        Action::CloseApprove,
        Action::MemberAdd,
        Action::OpenEvidence,
        Action::ExportRendition,
        Action::ExportOriginal,
    ];
}

/// What the route layer must still enforce after a permit (15 §5.9 obligations).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Obligation {
    /// Fresh step-up authentication within the 15 §4.7 window (`S` in the matrix).
    RequireStepUp,
    /// A second, distinct approver with permission on the same object (`D`, 15 §5.8).
    RequireSecondApprover,
    /// The access is permitted only as an audited OVERSIGHT read (`A (audited)`).
    AuditedAccess,
}

/// Why a request was denied. Returned to the Desk only as a uniform 404 on resource routes
/// (15 §5.9 "Explainability"); the full code goes to the SECURITY audit stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenyCode {
    /// The token's audience cannot reach case routes (ADR-029).
    Audience,
    /// Principal and resource belong to different tenants.
    Tenant,
    /// The account is not active (suspended, pending, missing authenticator).
    Suspended,
    /// No usable relation to the case: not a member, hidden, or COI-excluded (uniform on purpose).
    NoRelation,
    /// No held role grants the action, or an administrative role is held.
    Role,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Permitted, subject to every listed obligation.
    Permit(Vec<Obligation>),
    Deny(DenyCode),
}

impl Decision {
    #[must_use]
    pub const fn is_permit(&self) -> bool {
        matches!(self, Decision::Permit(_))
    }
}

/// The authenticated subject, as loaded by C-21/C-12 for this request (15 §5.3 subject
/// attributes). Never built from request input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub tenant_id: u128,
    pub user_id: u128,
    /// Person binding from enrollment (RVW-C-09); distinct from `user_id`.
    pub person_ref: u128,
    pub roles: BTreeSet<Role>,
    /// `account_state != ACTIVE` (suspension, pending enrollment, missing authenticator).
    pub suspended: bool,
}

/// The case facts the route layer derives for the principal (15 §5.3 object attributes),
/// loaded in the same transaction as the data access (no TOCTOU, 15 §5.9 PIP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceRef {
    pub tenant_id: u128,
    pub case_id: u128,
    /// The principal holds an ACL relation on the case (member, reviewer, counsel, oversight;
    /// for `Import`, Triage Set membership).
    pub member: bool,
    /// The principal is the case lead.
    pub lead: bool,
    /// The blinded COI tag check (`candor.coi_tag_present`) matched the principal (ADR-037(3)).
    pub coi_excluded: bool,
    /// The case is visible to the principal under triage-first visibility (ADR-037(2)).
    pub visible: bool,
}

/// Request environment facts (15 §5.3 environment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthzContext {
    /// Audience of the presented token. Case actions are reachable from `desk-api` only.
    pub audience: Audience,
}

impl Default for AuthzContext {
    fn default() -> Self {
        Self {
            audience: Audience::DeskApi,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relation {
    /// Any ACL relation (`member` or `lead`).
    Member,
    /// The lead relation only.
    Lead,
}

/// Matrix legend bits: `S` = step-up, `D` = dual control, `AUDITED` = audited access.
const S: u8 = 0b001;
const D: u8 = 0b010;
const AUDITED: u8 = 0b100;
/// Plain `A` in the matrix: relation required, no obligation.
const A: u8 = 0;

#[derive(Clone, Copy, Debug)]
struct Grant {
    role: Role,
    action: Action,
    relation: Relation,
    flags: u8,
}

impl Grant {
    const fn step_up(self) -> bool {
        self.flags & S != 0
    }

    const fn dual(self) -> bool {
        self.flags & D != 0
    }

    const fn audited(self) -> bool {
        self.flags & AUDITED != 0
    }
}

const fn grant(role: Role, action: Action, relation: Relation, flags: u8) -> Grant {
    Grant {
        role,
        action,
        relation,
        flags,
    }
}

use Action as Act;
use Relation::{Lead, Member};
use Role as R;

/// The 15 §5.2 matrix for case-scoped actions. A (role, action) pair absent here denies.
/// CASE_LEAD grants require the lead relation on the case (implementation decision, see
/// `SPEC-NOTES.md`); RECORDS_CUSTODIAN reads via an explicit ACL grant (15 §5.2 note).
const MATRIX: &[Grant] = &[
    // case.import
    grant(R::Triager, Act::Import, Member, A),
    grant(R::Oversight, Act::Import, Member, AUDITED),
    // case.read_content
    grant(R::Triager, Act::ReadContent, Member, A),
    grant(R::Investigator, Act::ReadContent, Member, A),
    grant(R::CaseLead, Act::ReadContent, Lead, A),
    grant(R::Reviewer, Act::ReadContent, Member, A),
    grant(R::ChannelOwner, Act::ReadContent, Member, A),
    grant(R::Counsel, Act::ReadContent, Member, A),
    grant(R::Oversight, Act::ReadContent, Member, AUDITED),
    grant(R::RecordsCustodian, Act::ReadContent, Member, A),
    // case.transition
    grant(R::Triager, Act::Transition, Member, A),
    grant(R::CaseLead, Act::Transition, Lead, A),
    grant(R::Reviewer, Act::Transition, Member, A),
    // case.close/dismiss approve
    grant(R::Reviewer, Act::CloseApprove, Member, S | D),
    // case.member_add
    grant(R::CaseLead, Act::MemberAdd, Lead, S),
    grant(R::ChannelOwner, Act::MemberAdd, Member, S),
    // evidence.open L1/L2
    grant(R::Triager, Act::OpenEvidence, Member, A),
    grant(R::Investigator, Act::OpenEvidence, Member, A),
    grant(R::CaseLead, Act::OpenEvidence, Lead, A),
    grant(R::Reviewer, Act::OpenEvidence, Member, A),
    grant(R::ChannelOwner, Act::OpenEvidence, Member, A),
    grant(R::Counsel, Act::OpenEvidence, Member, A),
    grant(R::Oversight, Act::OpenEvidence, Member, A),
    // evidence.export_rendition
    grant(R::Investigator, Act::ExportRendition, Member, S),
    grant(R::CaseLead, Act::ExportRendition, Lead, S),
    grant(R::Counsel, Act::ExportRendition, Member, S),
    // evidence.export_original (DC-01)
    grant(R::Investigator, Act::ExportOriginal, Member, S | D),
    grant(R::CaseLead, Act::ExportOriginal, Lead, S | D),
    grant(R::Counsel, Act::ExportOriginal, Member, S | D),
];

/// Decide one case-scoped request. Pure; deny by default.
#[must_use]
pub fn authorize(
    principal: &Principal,
    action: Action,
    resource: &ResourceRef,
    context: &AuthzContext,
) -> Decision {
    // (1) audience and tenant: before any fact about the case is consulted.
    if context.audience != Audience::DeskApi {
        return Decision::Deny(DenyCode::Audience);
    }
    if principal.tenant_id != resource.tenant_id {
        return Decision::Deny(DenyCode::Tenant);
    }
    // (2) explicit deny: suspension, then the blinded COI tag (deny overrides any ACL row).
    if principal.suspended {
        return Decision::Deny(DenyCode::Suspended);
    }
    if resource.coi_excluded {
        return Decision::Deny(DenyCode::NoRelation);
    }
    // (3) role permission. Administrative roles are a baseline deny for case content.
    if principal.roles.iter().any(|role| role.is_admin()) {
        return Decision::Deny(DenyCode::Role);
    }
    let granted: Vec<&Grant> = MATRIX
        .iter()
        .filter(|entry| entry.action == action && principal.roles.contains(&entry.role))
        .collect();
    if granted.is_empty() {
        return Decision::Deny(DenyCode::Role);
    }
    // (4) relation. A hidden case and a missing relation are the same denial.
    if !resource.visible {
        return Decision::Deny(DenyCode::NoRelation);
    }
    let satisfied: Vec<&Grant> = granted
        .into_iter()
        .filter(|entry| match entry.relation {
            Member => resource.member || resource.lead,
            Lead => resource.lead,
        })
        .collect();
    if satisfied.is_empty() {
        return Decision::Deny(DenyCode::NoRelation);
    }
    // (6) obligations: the union over the satisfying grants, so holding an extra role never
    // weakens what any one role would have required.
    let mut obligations = Vec::with_capacity(3);
    if satisfied.iter().any(|entry| entry.step_up()) {
        obligations.push(Obligation::RequireStepUp);
    }
    if satisfied.iter().any(|entry| entry.dual()) {
        obligations.push(Obligation::RequireSecondApprover);
    }
    if satisfied.iter().any(|entry| entry.audited()) {
        obligations.push(Obligation::AuditedAccess);
    }
    Decision::Permit(obligations)
}

/// Upper bound on wraps per case accepted in one request (hostile-input bound; a case has at
/// most a few dozen members).
pub const MAX_WRAP_RECIPIENTS: usize = 256;

/// One eligible recipient key from the C-22 candidate set (07 §5.5, DA-24).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WrapCandidate {
    /// Key-directory entry id of the Member Epoch Key.
    pub key_id: u128,
    pub user_id: u128,
    /// The entry is the user's current key-directory entry.
    pub current: bool,
    /// The user's blinded COI tag is present on this case.
    pub excluded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WrapError {
    /// `min_recipients` of 0 is not a policy (07 §7.3: 1 only as DANGEROUS, default 2).
    InvalidMinimum,
    TooManyRecipients,
    DuplicateRecipient,
    /// A key not in the candidate set (an extra wrap, THR-046).
    NotCandidate,
    /// The candidate set names the key under more than one user; refused rather than guessed.
    AmbiguousCandidate,
    /// The key belongs to a COI-excluded user.
    Excluded,
    /// The key is not the user's current key-directory entry.
    StaleKey,
    /// Fewer distinct users than `min_recipients` (ADR-044(2)).
    TooFewRecipients,
}

/// BE-018 / 07 §5.5: the wraps a Desk submits on case create, member add or re-key must be a
/// subset of the candidate set, each the user's current key, none excluded, and must cover at
/// least `min_recipients` distinct users. Any extra wrap rejects the whole request.
pub fn validate_key_wraps(
    key_ids: &[u128],
    candidates: &BTreeSet<WrapCandidate>,
    min_recipients: usize,
) -> Result<(), WrapError> {
    if min_recipients == 0 {
        return Err(WrapError::InvalidMinimum);
    }
    if key_ids.len() > MAX_WRAP_RECIPIENTS {
        return Err(WrapError::TooManyRecipients);
    }
    let mut seen_keys = BTreeSet::new();
    let mut users = BTreeSet::new();
    for key_id in key_ids {
        if !seen_keys.insert(*key_id) {
            return Err(WrapError::DuplicateRecipient);
        }
        let mut matching = candidates
            .iter()
            .filter(|candidate| candidate.key_id == *key_id)
            .peekable();
        let Some(first) = matching.peek().copied() else {
            return Err(WrapError::NotCandidate);
        };
        // Every row for this key must agree; any excluded or stale row fails the key.
        let mut excluded = false;
        let mut stale = false;
        let mut ambiguous = false;
        for candidate in matching {
            excluded |= candidate.excluded;
            stale |= !candidate.current;
            ambiguous |= candidate.user_id != first.user_id;
        }
        if ambiguous {
            return Err(WrapError::AmbiguousCandidate);
        }
        if excluded {
            return Err(WrapError::Excluded);
        }
        if stale {
            return Err(WrapError::StaleKey);
        }
        users.insert(first.user_id);
    }
    if users.len() < min_recipients {
        return Err(WrapError::TooFewRecipients);
    }
    Ok(())
}
