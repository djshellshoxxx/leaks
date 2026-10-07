// SPDX-License-Identifier: AGPL-3.0-or-later
//! Conflict-of-interest engine (ADR-037(3), ADR-052(3), 04 §9.11, 14 §8).
//!
//! C-22 holds, per case and case-key version, a padded set of blinded tags
//! and answers one question: "is this tag in the set?". It never learns a
//! user identity, the number of real exclusions or why a tag is present.
//! Membership is tested against every tag in constant time, so neither the
//! position of a match nor the presence of one changes the work done.
//!
//! Exclusion is evaluated *before* any key wrapping or visibility decision
//! ([`crate::engine`] step 2; [`verify_wraps`] for wraps), and an excluded
//! person is treated exactly as a person with no relation.

use subtle::{Choice, ConstantTimeEq};

use crate::ids::{ExclTag, KeyId};
use crate::model::WrapCandidate;

/// Padding granularity (04 §9.11: sets hold exactly `8·⌈max(1,x)/8⌉` tags).
pub const TAG_PAD: usize = 8;
/// Upper bound on a stored set (8 × 32 real exclusions); refuses absurd input.
pub const MAX_TAGS: usize = 256;

/// Typed, identity-free errors. None of them says *which* tag or user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoiError {
    /// Set size is zero, not a multiple of 8, or above [`MAX_TAGS`].
    BadSetShape,
    /// A wrap names a key that is not in the candidate set.
    WrapNotCandidate,
    /// The same key is wrapped twice.
    DuplicateWrap,
    /// Fewer wraps than `min_recipients` (ADR-044(2)).
    TooFewRecipients,
    /// A wrap targets an excluded person. Reported as a generic wrap
    /// failure class; the caller maps it to the same 400 as any wrap error.
    WrapSetRejected,
    /// A candidate list contains the same user or key twice.
    DuplicateCandidate,
}

/// The padded blinded tag set of one case (one key version).
#[derive(Clone, PartialEq, Eq)]
pub struct CoiTagSet {
    tags: Vec<ExclTag>,
}

impl core::fmt::Debug for CoiTagSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Even the count is not shown: it is a multiple of 8 but a smaller
        // set still bounds the number of real exclusions.
        f.write_str("CoiTagSet(..)")
    }
}

impl CoiTagSet {
    /// Build from stored tags. The shape must match 04 §9.11; a malformed set
    /// is a storage error and the case fails closed (no decision possible).
    pub fn new(tags: Vec<ExclTag>) -> Result<Self, CoiError> {
        if tags.is_empty() || tags.len() % TAG_PAD != 0 || tags.len() > MAX_TAGS {
            return Err(CoiError::BadSetShape);
        }
        Ok(Self { tags })
    }

    /// Constant-time membership test: touches every tag, no early exit.
    #[must_use]
    pub fn contains(&self, tag: &ExclTag) -> bool {
        let mut found = Choice::from(0u8);
        for t in &self.tags {
            found |= t.0.ct_eq(&tag.0);
        }
        bool::from(found)
    }

    /// Membership of an optional tag, computed in constant time over the set
    /// whether or not a tag was supplied (a dummy tag is tested when absent, so
    /// the work does not reveal whether the caller supplied one).
    #[must_use]
    pub fn contains_opt(&self, tag: Option<&ExclTag>) -> bool {
        let dummy = ExclTag([0u8; 32]);
        let present = Choice::from(u8::from(tag.is_some()));
        let probe = tag.unwrap_or(&dummy);
        let hit = Choice::from(u8::from(self.contains(probe)));
        bool::from(hit & present)
    }

    /// Stored tags (for persistence after a replacement).
    #[must_use]
    pub fn tags(&self) -> &[ExclTag] {
        &self.tags
    }

    /// Replace one tag (a padding tag chosen by the declaring Desk, DA-42
    /// `replaces_padding_tag`) with `new_tag`, keeping size and order so the
    /// stored row changes in exactly one slot regardless of which slot.
    /// If `replaced` is not present the set is left as is but the result is
    /// reported, so the caller can fail closed. Constant time over the set.
    #[must_use]
    pub fn replace(&self, replaced: &ExclTag, new_tag: ExclTag) -> (CoiTagSet, bool) {
        let mut out = Vec::with_capacity(self.tags.len());
        let mut replaced_any = Choice::from(0u8);
        for t in &self.tags {
            let hit = t.0.ct_eq(&replaced.0) & !replaced_any;
            let mut slot = [0u8; 32];
            for (i, b) in slot.iter_mut().enumerate() {
                let a = t.0.get(i).copied().unwrap_or(0);
                let n = new_tag.0.get(i).copied().unwrap_or(0);
                *b = u8::conditional_select(&a, &n, hit);
            }
            replaced_any |= hit;
            out.push(ExclTag(slot));
        }
        (CoiTagSet { tags: out }, bool::from(replaced_any))
    }
}

/// Self-declared conflict (DA-42).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declaration {
    NoConflict,
    /// The member's own tag and the padding tag it replaces.
    Conflict {
        own_tag: ExclTag,
        replaces_padding: ExclTag,
    },
}

/// What C-10 must persist after a self-declaration. The audit event is the
/// same generic `member_removed{REMOVED}` as every other removal (ADR-037(3)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationOutcome {
    /// New tag set to store atomically with the member's suspension.
    pub tags: CoiTagSet,
    /// Suspend the declaring member's ACL entry and set `HOLDER_SUSPENDED`.
    pub suspend_member: bool,
    /// Recommend a re-key on next open (14 §8.5(2)).
    pub rekey_recommended: bool,
}

/// Apply a self-declaration (14 §8.4(3), DA-42). `NoConflict` records
/// nothing. `Conflict` adds the member's tag in place of a padding tag; if
/// the padding tag is not present, the declaration fails closed
/// ([`CoiError::BadSetShape`]) rather than silently leaving the member in.
pub fn declare(set: &CoiTagSet, decl: Declaration) -> Result<DeclarationOutcome, CoiError> {
    match decl {
        Declaration::NoConflict => Ok(DeclarationOutcome {
            tags: set.clone(),
            suspend_member: false,
            rekey_recommended: false,
        }),
        Declaration::Conflict {
            own_tag,
            replaces_padding,
        } => {
            // Already excluded: idempotent, still suspend (fail closed).
            if set.contains(&own_tag) {
                return Ok(DeclarationOutcome {
                    tags: set.clone(),
                    suspend_member: true,
                    rekey_recommended: true,
                });
            }
            let (tags, ok) = set.replace(&replaces_padding, own_tag);
            if !ok {
                return Err(CoiError::BadSetShape);
            }
            Ok(DeclarationOutcome {
                tags,
                suspend_member: true,
                rekey_recommended: true,
            })
        }
    }
}

/// Blind grant check (04 §9.11, 15 §5.4): refuse a grant whose tag is in the
/// set. Constant time over the set.
#[must_use]
pub fn grant_permitted(set: &CoiTagSet, candidate_tag: &ExclTag) -> bool {
    !set.contains(candidate_tag)
}

/// Key-wrap verification on case create, member add and re-key (07 §5.5,
/// IMP-RM3-007, AT-069): every wrap ⊆ candidates, no duplicate, count ≥
/// `min_recipients`, and no wrapped candidate is excluded. Every element is
/// checked (INC-SL-08); the excluded-tag check runs over every wrap in
/// constant time so a rejection does not say which wrap was the problem.
pub fn verify_wraps(
    candidates: &[WrapCandidate],
    wraps: &[KeyId],
    min_recipients: usize,
    excluded: &CoiTagSet,
) -> Result<(), CoiError> {
    for (i, a) in candidates.iter().enumerate() {
        for b in candidates.iter().skip(i.saturating_add(1)) {
            if a.user == b.user || a.key == b.key {
                return Err(CoiError::DuplicateCandidate);
            }
        }
    }
    if wraps.len() < min_recipients || min_recipients == 0 {
        return Err(CoiError::TooFewRecipients);
    }
    for (i, w) in wraps.iter().enumerate() {
        if wraps.iter().skip(i.saturating_add(1)).any(|x| x == w) {
            return Err(CoiError::DuplicateWrap);
        }
    }
    let mut excluded_hit = Choice::from(0u8);
    for w in wraps {
        let Some(c) = candidates.iter().find(|c| c.key == *w) else {
            return Err(CoiError::WrapNotCandidate);
        };
        excluded_hit |= Choice::from(u8::from(excluded.contains(&c.excl_tag)));
    }
    if bool::from(excluded_hit) {
        return Err(CoiError::WrapSetRejected);
    }
    Ok(())
}
