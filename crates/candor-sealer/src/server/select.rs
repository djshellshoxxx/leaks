// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recipient selection and COI filter (04 §12.1 steps 4–8, §9.5; ADR-030,
//! ADR-036(2)/(4), ADR-037(1); 07 BE-051). Runs in RAM at `SEAL_FINISH` only,
//! against the verified snapshot, and fails closed.

use super::directory::{ChannelView, DirectorySnapshot};
use candor_core::hash::{KeyKind, key_id};
use candor_core::kem::KemPublicKey;
use candor_core::slots::SLOT_COUNT;

/// Why no envelope may be sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectError {
    /// No eligible Triage Set member with a valid current MEK (§12.1 step 7).
    NoEligible { alternative: Option<[u8; 16]> },
    /// Channel unknown or disabled, epoch undefined, or a C-14 invariant is
    /// violated (> 16 Triage Set members): intake unavailable (§12.6).
    Unavailable { alternative: Option<[u8; 16]> },
}

/// One recipient MEK.
#[derive(Debug, Clone)]
pub(crate) struct Recipient {
    pub user_id: [u8; 16],
    pub pk: KemPublicKey,
    pub key_id: [u8; 32],
}

/// The fixed recipient set of one envelope.
#[derive(Debug, Clone)]
pub(crate) struct Selection {
    pub channel_id: [u8; 16],
    pub epoch_id: u32,
    /// Sorted by MEK `key_id` (§13.4 key 16.2 "sorted").
    pub recipients: Vec<Recipient>,
    /// Eligible set after the COI filter (user ids, sorted), kept in `prefs_ct`
    /// for the follow-up rule (ADR-036(4)).
    pub eligible_user_ids: Vec<[u8; 16]>,
    /// Eligible members skipped for lack of a valid current MEK.
    pub skipped: u32,
    pub coi_policy_entry_hash: [u8; 32],
    pub roster_entry_hash: [u8; 32],
    pub roster_version: u64,
    pub tree_size: u64,
    pub root_hash: [u8; 32],
}

/// What the source chose.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Choice<'a> {
    /// Role labels the source flagged ("my report concerns …").
    pub flagged_labels: &'a [u16],
    /// Selected categories.
    pub categories: &'a [u16],
    /// Follow-up: the report's original eligible set (ADR-036(4)).
    pub original_eligible: Option<&'a [[u8; 16]]>,
}

fn active_coi<'c>(ch: &'c ChannelView, today: u32) -> Option<&'c super::directory::CoiPolicy> {
    ch.coi_policies
        .iter()
        .filter(|p| p.effective_day <= today)
        .max_by_key(|p| p.effective_day)
}

/// Compute the recipient set.
pub(crate) fn select(
    snap: &DirectorySnapshot,
    channel_id: &[u8; 16],
    today: u32,
    choice: Choice<'_>,
) -> Result<Selection, SelectError> {
    let ch = match snap.channel(channel_id) {
        Some(c) if c.enabled => c,
        Some(c) => {
            return Err(SelectError::Unavailable {
                alternative: c.independent_route,
            });
        }
        None => return Err(SelectError::Unavailable { alternative: None }),
    };
    let unavailable = SelectError::Unavailable {
        alternative: ch.independent_route,
    };
    let epoch_id = snap.epoch_for_day(today).ok_or(unavailable)?;
    // Step 4: Triage Set of the latest active roster; time-locked additions are
    // not yet active (ADR-036(2)).
    let triage: Vec<_> = ch
        .members
        .iter()
        .filter(|m| m.read_intake && m.effective_day <= today)
        .collect();
    if triage.len() > SLOT_COUNT {
        return Err(unavailable);
    }
    // Step 5: COI filter (source flags + active COI_POLICY for the categories).
    let policy = active_coi(ch, today);
    let mut excluded: Vec<u16> = choice.flagged_labels.to_vec();
    if let Some(p) = policy {
        for (cat, labels) in &p.categories {
            if choice.categories.contains(cat) {
                excluded.extend_from_slice(labels);
            }
        }
    }
    let mut eligible: Vec<[u8; 16]> = triage
        .iter()
        .filter(|m| !excluded.contains(&m.role_label))
        .filter(|m| choice.original_eligible.is_none_or(|o| o.contains(&m.user_id)))
        .map(|m| m.user_id)
        .collect();
    eligible.sort_unstable();
    eligible.dedup();
    // Step 6: a valid current MEK per member.
    let mut recipients = Vec::with_capacity(eligible.len());
    let mut skipped: u32 = 0;
    for uid in &eligible {
        let valid: Vec<_> = ch
            .meks
            .iter()
            .filter(|k| {
                &k.user_id == uid
                    && !k.revoked
                    && k.epoch_id == epoch_id
                    && k.valid_from_day <= today
                    && today < k.valid_until_day
            })
            .collect();
        // Exactly one valid entry; an ambiguous directory is treated as no key.
        let pk = match valid.as_slice() {
            [k] => KemPublicKey::from_bytes(snap.suite, &k.public_key).ok(),
            _ => None,
        };
        match pk {
            Some(pk) => {
                let key_id = key_id(snap.suite, KeyKind::Mek, &pk.to_bytes());
                recipients.push(Recipient {
                    user_id: *uid,
                    pk,
                    key_id,
                });
            }
            None => skipped = skipped.saturating_add(1),
        }
    }
    // Step 7: fail closed.
    if recipients.is_empty() {
        return Err(SelectError::NoEligible {
            alternative: ch.independent_route,
        });
    }
    recipients.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    Ok(Selection {
        channel_id: *channel_id,
        epoch_id,
        recipients,
        eligible_user_ids: eligible,
        skipped,
        coi_policy_entry_hash: policy.map_or([0u8; 32], |p| p.entry_hash),
        roster_entry_hash: ch.roster_entry_hash,
        roster_version: ch.roster_version,
        tree_size: snap.tree_size,
        root_hash: snap.root_hash,
    })
}
