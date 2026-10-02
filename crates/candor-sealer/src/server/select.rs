// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recipient selection and COI filter (04 §12.1 steps 4–8, §9.5; ADR-030,
//! ADR-036(2)/(4), ADR-037(1); 07 BE-051). Runs in RAM at `SEAL_FINISH` only,
//! against the verified snapshot, and fails closed.

use super::directory::DirectorySnapshot;
use candor_core::hash::{KeyKind, key_id};
use candor_core::kem::KemPublicKey;
use candor_core::slots::SLOT_COUNT;
use zeroize::Zeroizing;

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
#[derive(Clone)]
pub(crate) struct Recipient {
    pub pk: KemPublicKey,
    pub key_id: [u8; 32],
}

/// The fixed recipient set of one envelope. No `Debug`: the eligible set reveals
/// the source's COI ticks by difference (AUD-RM2-SEA-08).
pub(crate) struct Selection {
    pub channel_id: [u8; 16],
    pub epoch_id: u32,
    /// Sorted by MEK `key_id` (§13.4 key 16.2 "sorted").
    pub recipients: Vec<Recipient>,
    /// Eligible set after the COI filter (user ids, sorted), kept in `prefs_ct`
    /// for the follow-up rule (ADR-036(4)). Zeroized.
    pub eligible_user_ids: Zeroizing<Vec<[u8; 16]>>,
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
                alternative: c.independent_route(today),
            });
        }
        None => return Err(SelectError::Unavailable { alternative: None }),
    };
    let alternative = ch.independent_route(today);
    let unavailable = SelectError::Unavailable { alternative };
    let epoch_id = snap.epoch_for_day(today).ok_or(unavailable)?;
    // Step 4: Triage Set of the active roster (time-locked loosening entries
    // are not yet active, ADR-036(2)), restricted to members whose role label
    // carries a current independent ROLE_LABEL_CERT (ADR-036(3), §14.4 rule 5).
    // Persons, not roster entries, are counted: a user listed under several
    // labels is one Triage Set member.
    let roster = ch.active_roster(today).ok_or(unavailable)?;
    let mut triage: Zeroizing<Vec<[u8; 16]>> =
        Zeroizing::new(Vec::with_capacity(roster.members.len()));
    for m in &roster.members {
        let certified = m.label_certified_until.is_some_and(|u| today <= u);
        if m.read_intake && certified && !triage.contains(&m.user_id) {
            triage.push(m.user_id);
        }
    }
    if triage.len() > SLOT_COUNT {
        return Err(unavailable);
    }
    // Step 5: COI filter (source flags + active COI_POLICY for the categories),
    // applied per person (ADR-052(3), AUD-RM2-SEA-03): a user is excluded if ANY
    // of their roster entries — in any roster version, active or not, triage or
    // not — carries an excluded role label.
    let policy = ch.active_coi(today);
    // Sized once for the flags plus every label the policy can add, so the
    // zeroizing buffer never reallocates (AUD-RM2-SEA-08, SEA-24(d)).
    let policy_labels = policy.map_or(0, |p| {
        p.categories
            .iter()
            .filter(|(cat, _)| choice.categories.contains(cat))
            .fold(0usize, |a, (_, l)| a.saturating_add(l.len()))
    });
    let mut excluded: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(
        choice.flagged_labels.len().saturating_add(policy_labels),
    ));
    excluded.extend_from_slice(choice.flagged_labels);
    if let Some(p) = policy {
        for (cat, labels) in &p.categories {
            if choice.categories.contains(cat) {
                excluded.extend_from_slice(labels);
            }
        }
    }
    let member_count = ch
        .rosters
        .iter()
        .fold(0usize, |a, r| a.saturating_add(r.members.len()));
    let mut excluded_users: Zeroizing<Vec<[u8; 16]>> =
        Zeroizing::new(Vec::with_capacity(member_count));
    for m in ch.rosters.iter().flat_map(|r| r.members.iter()) {
        if excluded.contains(&m.role_label) && !excluded_users.contains(&m.user_id) {
            excluded_users.push(m.user_id);
        }
    }
    let mut eligible: Zeroizing<Vec<[u8; 16]>> = Zeroizing::new(Vec::with_capacity(triage.len()));
    for uid in triage.iter() {
        let allowed = !excluded_users.contains(uid)
            && choice.original_eligible.is_none_or(|o| o.contains(uid));
        if allowed {
            eligible.push(*uid);
        }
    }
    eligible.sort_unstable();
    // Step 6: a valid current MEK per member.
    let mut recipients = Vec::with_capacity(eligible.len());
    let mut skipped: u32 = 0;
    for uid in eligible.iter() {
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
                recipients.push(Recipient { pk, key_id });
            }
            None => skipped = skipped.saturating_add(1),
        }
    }
    // Step 7: fail closed.
    if recipients.is_empty() {
        return Err(SelectError::NoEligible { alternative });
    }
    recipients.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    Ok(Selection {
        channel_id: *channel_id,
        epoch_id,
        recipients,
        eligible_user_ids: eligible,
        skipped,
        coi_policy_entry_hash: policy.map_or([0u8; 32], |p| p.entry_hash),
        roster_entry_hash: roster.entry_hash,
        roster_version: roster.roster_version,
        tree_size: snap.tree_size,
        root_hash: snap.root_hash,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::server::directory::{
        ChannelView, CoiPolicy, MemberEpochKey, RosterMember, RosterVersion,
    };
    use candor_core::Suite;
    use candor_core::kem::KemKeyPair;

    const T: u32 = 1000;
    const CH: [u8; 16] = [1; 16];

    fn member(user: u8, role_label: u16, read_intake: bool) -> RosterMember {
        RosterMember {
            user_id: [user; 16],
            role_label,
            read_intake,
            label_certified_until: Some(T + 30),
        }
    }

    fn roster(members: Vec<RosterMember>, activation_day: u32) -> RosterVersion {
        RosterVersion {
            entry_hash: [2; 32],
            roster_version: 1,
            activation_day,
            independent_route: Some([5; 16]),
            members,
        }
    }

    fn members(s: &mut DirectorySnapshot) -> &mut Vec<RosterMember> {
        &mut s.channels[0].rosters[0].members
    }

    fn snap(n: u8) -> (DirectorySnapshot, Vec<KemKeyPair>) {
        let keys: Vec<KemKeyPair> = (0..n)
            .map(|_| KemKeyPair::generate(Suite::CandorStd1).unwrap())
            .collect();
        let members = (0..n)
            .map(|i| member(i + 1, u16::from(i) + 1, true))
            .collect();
        let meks = keys
            .iter()
            .enumerate()
            .map(|(i, k)| MemberEpochKey {
                user_id: [u8::try_from(i).unwrap() + 1; 16],
                epoch_id: 0,
                valid_from_day: T,
                valid_until_day: T + 7,
                revoked: false,
                public_key: k.public.to_bytes(),
            })
            .collect();
        let s = DirectorySnapshot {
            snapshot_version: 1,
            tree_size: 1,
            root_hash: [0; 32],
            issued_hour: u64::from(T) * 24,
            suite: Suite::CandorStd1,
            epoch_origin_day: T,
            custodian_pk: vec![],
            disposition_pk: vec![],
            channels: vec![ChannelView {
                channel_id: CH,
                enabled: true,
                rosters: vec![roster(members, 0)],
                coi_policies: vec![
                    CoiPolicy {
                        entry_hash: [3; 32],
                        effective_day: T - 5,
                        categories: vec![(9, vec![1])],
                    },
                    // Loosening not yet effective (time lock): ignored.
                    CoiPolicy {
                        entry_hash: [4; 32],
                        effective_day: T + 1,
                        categories: vec![],
                    },
                ],
                meks,
            }],
            user_keys: vec![],
        };
        (s, keys)
    }

    fn choice<'a>(f: &'a [u16], c: &'a [u16], o: Option<&'a [[u8; 16]]>) -> Choice<'a> {
        Choice {
            flagged_labels: f,
            categories: c,
            original_eligible: o,
        }
    }

    /// 07 BE-051 COI matrix: every subset of flags × category on a 3-member set.
    #[test]
    fn coi_matrix() {
        let (s, _) = snap(3);
        for mask in 0u8..8 {
            for cat in [None, Some(9u16)] {
                let flags: Vec<u16> = (1..=3u16).filter(|l| mask & (1 << (l - 1)) != 0).collect();
                let cats: Vec<u16> = cat.into_iter().collect();
                let mut expect: Vec<[u8; 16]> = (1..=3u8)
                    .filter(|i| !flags.contains(&u16::from(*i)))
                    .filter(|i| !(cat.is_some() && *i == 1))
                    .map(|i| [i; 16])
                    .collect();
                expect.sort_unstable();
                match select(&s, &CH, T, choice(&flags, &cats, None)) {
                    Ok(sel) => {
                        assert_eq!(*sel.eligible_user_ids, expect);
                        assert_eq!(sel.recipients.len(), expect.len());
                        assert_eq!(sel.coi_policy_entry_hash, [3; 32]);
                        let mut ids: Vec<_> = sel.recipients.iter().map(|r| r.key_id).collect();
                        let sorted = {
                            let mut v = ids.clone();
                            v.sort_unstable();
                            v
                        };
                        assert_eq!(ids, sorted);
                        ids.dedup();
                        assert_eq!(ids.len(), expect.len());
                    }
                    Err(e) => {
                        assert!(expect.is_empty());
                        assert_eq!(
                            e,
                            SelectError::NoEligible {
                                alternative: Some([5; 16])
                            }
                        );
                    }
                }
            }
        }
    }

    /// AUD-RM2-SEA-03 regression (ADR-052(3)): a user listed under two labels is
    /// excluded when either label is excluded — by a source tick or by the
    /// category COI_POLICY — and counts once toward the 16-member limit.
    #[test]
    fn coi_applies_per_person_not_per_roster_entry() {
        let (mut s, _) = snap(3);
        // User 1 (label 1) is additionally listed under label 9.
        members(&mut s).push(member(1, 9, true));
        // Category 9 excludes label 1: user 1 must be excluded although the
        // label-9 entry passes the filter.
        let sel = select(&s, &CH, T, choice(&[], &[9], None)).unwrap();
        assert_eq!(*sel.eligible_user_ids, vec![[2; 16], [3; 16]]);
        assert_eq!(sel.recipients.len(), 2);
        // Source ticks label 9 only: user 1 is excluded as a person.
        let sel = select(&s, &CH, T, choice(&[9], &[], None)).unwrap();
        assert_eq!(*sel.eligible_user_ids, vec![[2; 16], [3; 16]]);
        // An excluded label on a non-triage entry or in a not-yet-active
        // roster version also counts.
        let (mut s, _) = snap(3);
        let mut later = s.channels[0].rosters[0].clone();
        later.activation_day = T + 100;
        later.members.push(member(2, 42, false));
        s.channels[0].rosters.push(later);
        let sel = select(&s, &CH, T, choice(&[42], &[], None)).unwrap();
        assert_eq!(*sel.eligible_user_ids, vec![[1; 16], [3; 16]]);
        // Without exclusions the duplicated user is one recipient.
        let (mut s, _) = snap(3);
        members(&mut s).push(member(3, 30, true));
        let sel = select(&s, &CH, T, choice(&[], &[], None)).unwrap();
        assert_eq!(sel.recipients.len(), 3);
        // 16 distinct persons with duplicate entries stay within the limit.
        let (mut s, _) = snap(1);
        for i in 0..15u8 {
            for label in [60u16, 61] {
                members(&mut s).push(member(100 + i, label, true));
            }
        }
        assert!(select(&s, &CH, T, choice(&[], &[], None)).is_ok());
    }

    /// The latest active COI_POLICY applies; a later one with an earlier
    /// activation day (a tightening appended after a pending loosening) wins.
    #[test]
    fn latest_active_coi_policy_applies() {
        let (mut s, _) = snap(3);
        s.channels[0].coi_policies.push(CoiPolicy {
            entry_hash: [9; 32],
            effective_day: 0,
            categories: vec![(9, vec![1, 2])],
        });
        let sel = select(&s, &CH, T, choice(&[], &[9], None)).unwrap();
        assert_eq!(sel.coi_policy_entry_hash, [9; 32]);
        assert_eq!(*sel.eligible_user_ids, vec![[3; 16]]);
    }

    #[test]
    fn time_locks_validity_and_invariants() {
        let (mut s, _) = snap(3);
        // A time-locked addition (a roster version not yet active) is not yet
        // a recipient; the previous active version applies.
        let mut later = s.channels[0].rosters[0].clone();
        members(&mut s).pop();
        later.activation_day = T + 1;
        later.entry_hash = [7; 32];
        s.channels[0].rosters.push(later);
        let sel = select(&s, &CH, T, choice(&[], &[], None)).unwrap();
        assert_eq!(*sel.eligible_user_ids, vec![[1; 16], [2; 16]]);
        assert_eq!(sel.roster_entry_hash, [2; 32]);
        let sel = select(&s, &CH, T + 1, choice(&[], &[], None)).unwrap();
        assert_eq!(sel.eligible_user_ids.len(), 3);
        assert_eq!(sel.roster_entry_hash, [7; 32]);
        // An expired or non-independent role-label certificate removes the
        // member from the Triage Set (ADR-036(3)).
        let (mut s, _) = snap(3);
        members(&mut s)[0].label_certified_until = Some(T - 1);
        members(&mut s)[1].label_certified_until = None;
        let sel = select(&s, &CH, T, choice(&[], &[], None)).unwrap();
        assert_eq!(*sel.eligible_user_ids, vec![[3; 16]]);
        let (mut s, _) = snap(3);
        // A revoked or duplicated MEK counts as missing.
        s.channels[0].meks[0].revoked = true;
        s.channels[0].meks[2].revoked = true;
        let dup = s.channels[0].meks[1].clone();
        s.channels[0].meks.push(dup);
        let e = select(&s, &CH, T, choice(&[], &[], None));
        assert!(matches!(
            e,
            Err(SelectError::NoEligible { alternative: Some(a) }) if a == [5; 16]
        ));
        // Follow-up rule: intersection with the original set.
        let (s, _) = snap(3);
        let sel = select(&s, &CH, T, choice(&[], &[], Some(&[[2; 16], [9; 16]]))).unwrap();
        assert_eq!(*sel.eligible_user_ids, vec![[2; 16]]);
        // Disabled channel and > 16 Triage Set members: unavailable.
        let (mut s, _) = snap(3);
        s.channels[0].enabled = false;
        assert!(matches!(
            select(&s, &CH, T, choice(&[], &[], None)),
            Err(SelectError::Unavailable { .. })
        ));
        let (mut s, _) = snap(1);
        for i in 0..17u8 {
            members(&mut s).push(member(100 + i, 50, true));
        }
        assert!(matches!(
            select(&s, &CH, T, choice(&[], &[], None)),
            Err(SelectError::Unavailable { .. })
        ));
        // Before the epoch origin there is no epoch.
        let (s, _) = snap(1);
        assert!(select(&s, &CH, T - 1, choice(&[], &[], None)).is_err());
    }
}
