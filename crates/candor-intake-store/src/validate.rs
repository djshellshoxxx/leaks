// SPDX-License-Identifier: AGPL-3.0-or-later
//! Input validation and decision logic shared by both implementations, so that the
//! memory and PostgreSQL stores enforce byte-for-byte the same rules.

use std::collections::{BTreeMap, HashSet};

use subtle::ConstantTimeEq;

use crate::deletion::{DeletionEntry, SignedDeletionHead, verify_chain};
use crate::error::{Result, StoreError};
use crate::types::{
    BackupSnapshot, ClaimLimits, CommitEnvelope, CounterDelta, DISPOSITION_CT_LEN_STD, Day,
    GROUP_OBJECTS, IncomingReply, InstallOutcome, KdHighWater, MAX_CLAIM_BYTES, MAX_CLAIM_OBJECTS,
    MAX_PART_PADDED_SIZE, MAX_PREFS_CT, MAX_PUSHED_DELETION_LIST, MAX_RELEASE_OFFSET_DAYS,
    MAX_REPLY_CT, MAX_SNAPSHOT_BODY, MAX_SNAPSHOT_SIGNATURES, NewAccount, SLOT_BLOCK_LEN_STD,
    TenantId, VerifiedSnapshot, XWING_PK_LEN, reply_bucket_of_len,
};

pub(crate) fn has_duplicates<T: PartialEq>(v: &[T]) -> bool {
    v.iter()
        .enumerate()
        .any(|(i, a)| v.iter().skip(i.saturating_add(1)).any(|b| a == b))
}

/// Validate a `COMMIT_ENVELOPE` request: one fixed-shape group (ADR-052(1)).
pub(crate) fn commit(env: &CommitEnvelope) -> Result<()> {
    if env.disposition_ct.len() != DISPOSITION_CT_LEN_STD {
        return Err(StoreError::InvalidInput("disposition_ct size"));
    }
    if env.release_offset_days > MAX_RELEASE_OFFSET_DAYS {
        return Err(StoreError::InvalidInput("release offset"));
    }
    for (i, o) in env.objects.iter().enumerate() {
        if o.slot_block.len() != SLOT_BLOCK_LEN_STD {
            return Err(StoreError::InvalidInput("slot block size"));
        }
        if o.blob.padded_size == 0 || o.blob.padded_size > MAX_PART_PADDED_SIZE {
            return Err(StoreError::InvalidInput("part size"));
        }
        for q in env.objects.iter().skip(i.saturating_add(1)) {
            if q.blob.blob_id == o.blob.blob_id {
                return Err(StoreError::InvalidInput("duplicate blob id"));
            }
            if q.object_hash == o.object_hash {
                return Err(StoreError::InvalidInput("duplicate object hash"));
            }
        }
    }
    i32::try_from(env.epoch_index).map_err(|_| StoreError::InvalidInput("epoch index"))?;
    day_i32(env.received_date)?;
    day_i32(env.received_date.plus(u32::from(env.release_offset_days))?)?;
    Ok(())
}

/// Bytes a group contributes to `max_bytes`: three slot blocks and three blobs.
pub(crate) fn group_bytes(parts: &[u64]) -> u64 {
    let slots = u64::try_from(SLOT_BLOCK_LEN_STD.saturating_mul(GROUP_OBJECTS)).unwrap_or(u64::MAX);
    parts.iter().fold(slots, |a, p| a.saturating_add(*p))
}

pub(crate) fn new_account(a: &NewAccount) -> Result<()> {
    if a.xwing_pk.len() != XWING_PK_LEN {
        return Err(StoreError::InvalidInput("xwing_pk size"));
    }
    if a.prefs_ct.is_empty() || a.prefs_ct.len() > MAX_PREFS_CT {
        return Err(StoreError::InvalidInput("prefs_ct size"));
    }
    Ok(())
}

/// A monthly counter delta flushed at an import slot.
pub(crate) fn counter_delta(c: &CounterDelta) -> Result<()> {
    if !c.month.is_month_start() {
        return Err(StoreError::InvalidInput("month"));
    }
    day_i32(c.month)?;
    i32::try_from(c.delta).map_err(|_| StoreError::InvalidInput("counter overflow"))?;
    Ok(())
}

/// Structural checks of an RL-10 backup before anything is restored, so that the
/// restore never relies on a database constraint violation (AUD-RM2-STO-02).
pub(crate) fn backup(b: &BackupSnapshot) -> Result<()> {
    let mut ids = HashSet::new();
    let mut tags = HashSet::new();
    for a in &b.accounts {
        new_account(&NewAccount {
            lookup_tag: a.lookup_tag,
            auth_pk: a.auth_pk,
            xwing_pk: a.xwing_pk.clone(),
            prefs_ct: a.prefs_ct.clone(),
        })?;
        if !a.activity_month.is_month_start() {
            return Err(StoreError::InvalidInput("activity month"));
        }
        day_i32(a.activity_month)?;
        if !ids.insert(a.account_id) || !tags.insert(a.lookup_tag) {
            return Err(StoreError::InvalidInput("duplicate account in backup"));
        }
    }
    if b.deletion_list
        .windows(2)
        .any(|w| matches!(w, [x, y] if y.seq <= x.seq))
    {
        return Err(StoreError::DeletionList("unordered backup list"));
    }
    for e in &b.deletion_list {
        if e.seq == 0 || i64::try_from(e.seq).is_err() {
            return Err(StoreError::DeletionList("seq out of range"));
        }
        day_i32(e.del_day)?;
    }
    // The database accepts only chain-extending inserts (AUD-RM2-STO-21): the
    // backup list must be one contiguous, linked run.
    if b.deletion_list.windows(2).any(|w| match w {
        [x, y] => !links(x, y),
        _ => false,
    }) || b
        .deletion_list
        .first()
        .is_some_and(|e| e.seq == 1 && e.prev_hash != [0u8; 32])
    {
        return Err(StoreError::DeletionList("backup list not a chain"));
    }
    if let Some(h) = &b.meta.deletion_head {
        // Shape of a stored head (AUD-RM2-STO-24): seq ≥ 1, counter ≥ 1.
        if h.seq == 0
            || h.counter == 0
            || i64::try_from(h.seq).is_err()
            || i64::try_from(h.counter).is_err()
        {
            return Err(StoreError::DeletionList("backup head malformed"));
        }
        day_i32(h.day)?;
        let map: BTreeMap<u64, &DeletionEntry> =
            b.deletion_list.iter().map(|e| (e.seq, e)).collect();
        if !links_to_head(&map, h) {
            return Err(StoreError::DeletionList("backup head not in backup list"));
        }
    }
    if let Some(d) = b.meta.kd.checkpoint_day {
        day_i32(d)?;
    }
    for v in [
        b.meta.relay_req_counter,
        b.meta.last_batch_no,
        b.meta.kd.tree_size,
        b.meta.kd.directory_version,
    ] {
        i64::try_from(v).map_err(|_| StoreError::InvalidInput("value out of range"))?;
    }
    Ok(())
}

/// Day as an i32 for PostgreSQL date arithmetic (bounded to avoid overflow).
pub(crate) fn day_i32(d: crate::types::Day) -> Result<i32> {
    // Keep well inside PostgreSQL's date range.
    if d.0 > 2_000_000 {
        return Err(StoreError::InvalidInput("day out of range"));
    }
    i32::try_from(d.0).map_err(|_| StoreError::InvalidInput("day out of range"))
}

pub(crate) fn claim_limits(l: ClaimLimits) -> Result<()> {
    if l.max_objects == 0 || l.max_objects > MAX_CLAIM_OBJECTS {
        return Err(StoreError::InvalidInput("max_objects"));
    }
    if l.max_bytes == 0 || l.max_bytes > MAX_CLAIM_BYTES {
        return Err(StoreError::InvalidInput("max_bytes"));
    }
    Ok(())
}

/// Greedy batch fill: take objects in the given (random) order while within
/// limits. The first object is always taken so that an envelope larger than
/// `max_bytes` cannot block the queue forever (SPEC-NOTES).
pub(crate) fn fill_batch(sizes: &[u64], limits: ClaimLimits) -> Vec<usize> {
    let mut out = Vec::new();
    let mut bytes: u64 = 0;
    for (i, s) in sizes.iter().enumerate() {
        if out.len() >= usize::try_from(limits.max_objects).unwrap_or(usize::MAX) {
            break;
        }
        let next = bytes.saturating_add(*s);
        if !out.is_empty() && next > limits.max_bytes {
            continue;
        }
        bytes = next;
        out.push(i);
    }
    out
}

/// Structural check of a pushed reply (other than deletion-list drops). The
/// ciphertext must have the canonical length of its REPLY bucket, and the bucket
/// the caller reports must be the one [`reply_bucket_of_len`] derives, the same
/// function that sizes dummies (AUD-RM2-STO-20).
pub(crate) fn reply(r: &IncomingReply) -> bool {
    !r.reply_ct.is_empty()
        && r.reply_ct.len() <= MAX_REPLY_CT
        && reply_bucket_of_len(r.reply_ct.len()) == Some(r.size_bucket)
        && (r.mailbox_id.is_some() || r.account.is_none())
}

/// What to do with a snapshot install.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SnapshotDecision {
    Install,
    AlreadyInstalled,
}

/// Rollback protection (ADR-036(6); 09 `kd_tree_size_hwm`; BE-060; RL-06).
pub(crate) fn snapshot(
    hwm: &KdHighWater,
    current_body: Option<&[u8]>,
    snap: &VerifiedSnapshot,
) -> Result<SnapshotDecision> {
    if snap.body.is_empty() || snap.body.len() > MAX_SNAPSHOT_BODY {
        return Err(StoreError::InvalidInput("snapshot body size"));
    }
    if snap.signatures.is_empty() || snap.signatures.len() > MAX_SNAPSHOT_SIGNATURES {
        return Err(StoreError::InvalidInput("snapshot signature size"));
    }
    if snap.version == 0 || i64::try_from(snap.version).is_err() {
        return Err(StoreError::InvalidInput("snapshot version"));
    }
    if i64::try_from(snap.tree_size).is_err() || snap.tree_size == 0 {
        return Err(StoreError::InvalidInput("tree size"));
    }
    day_i32(snap.checkpoint_day)?;
    if snap.tree_size < hwm.tree_size {
        return Err(StoreError::Rollback("tree size below high-water mark"));
    }
    if let Some(d) = hwm.checkpoint_day
        && snap.checkpoint_day < d
    {
        return Err(StoreError::Rollback(
            "checkpoint older than high-water mark",
        ));
    }
    if snap.version < hwm.directory_version {
        return Err(StoreError::Rollback("version below current"));
    }
    if snap.version == hwm.directory_version {
        return match current_body {
            Some(b) if b == snap.body.as_slice() && snap.tree_size == hwm.tree_size => {
                Ok(SnapshotDecision::AlreadyInstalled)
            }
            _ => Err(StoreError::Rollback("same version, different snapshot")),
        };
    }
    if snap.tree_size > hwm.tree_size && snap.consistent_from != hwm.tree_size {
        return Err(StoreError::Rollback(
            "not consistency-proven from high-water mark",
        ));
    }
    if snap.tree_size == hwm.tree_size && snap.consistent_from != hwm.tree_size {
        return Err(StoreError::Rollback(
            "not consistency-proven from high-water mark",
        ));
    }
    Ok(SnapshotDecision::Install)
}

impl From<SnapshotDecision> for InstallOutcome {
    fn from(d: SnapshotDecision) -> Self {
        match d {
            SnapshotDecision::Install => InstallOutcome::Installed,
            SnapshotDecision::AlreadyInstalled => InstallOutcome::AlreadyInstalled,
        }
    }
}

/// RL-12 step 1 (outside any lock, AUD-RM2-STO-12/22/24): bound the size,
/// verify the Z-CORE head attestation under `core_pk` and its freshness
/// against `today`, and verify the pushed run's internal chain and every strict
/// Ed25519 signature under K31.
pub(crate) fn verify_pushed(
    pushed: &[DeletionEntry],
    k31_pk: &[u8; 32],
    head: &SignedDeletionHead,
    tenant: &TenantId,
    core_pk: &[u8; 32],
    today: Day,
) -> Result<()> {
    if pushed.len() > MAX_PUSHED_DELETION_LIST {
        return Err(StoreError::InvalidInput("deletion list too long"));
    }
    head.verify(tenant, core_pk)?;
    head.check_fresh(today)?;
    verify_chain(pushed, k31_pk, None)
}

pub(crate) fn links(prev: &DeletionEntry, next: &DeletionEntry) -> bool {
    prev.seq.checked_add(1) == Some(next.seq)
        && bool::from(prev.next_prev_hash().ct_eq(&next.prev_hash))
}

/// Whether the chain in `map` contains the head `h`: the entry at `h.seq`
/// hashes to `h.head_hash`, or (if that entry was pruned) its successor links to
/// it. `seq = 0` is the empty chain.
pub(crate) fn links_to_head(map: &BTreeMap<u64, &DeletionEntry>, h: &SignedDeletionHead) -> bool {
    if h.seq == 0 {
        return true;
    }
    if let Some(e) = map.get(&h.seq) {
        return bool::from(e.next_prev_hash().ct_eq(&h.head_hash));
    }
    h.seq
        .checked_add(1)
        .and_then(|s| map.get(&s))
        .is_some_and(|n| bool::from(n.prev_hash.ct_eq(&h.head_hash)))
}

/// RL-11 acknowledgement of a verified Z-CORE head (AUD-RM2-STO-21/24): the
/// head must not be older (by attestation counter) than the acknowledged head,
/// must lie within the local chain and match it. Returns `true` when the stored
/// acknowledged head must advance (a newer attestation, also of the same seq);
/// an identical re-acknowledgement and a seq-0 head change nothing.
pub(crate) fn ack_head(
    local: &[DeletionEntry],
    current: Option<&SignedDeletionHead>,
    head: &SignedDeletionHead,
) -> Result<bool> {
    if !head.newer_than(current)? || head.seq == 0 {
        return Ok(false);
    }
    if let Some(c) = current
        && head.seq == c.seq
    {
        return if bool::from(c.head_hash.ct_eq(&head.head_hash)) {
            Ok(true)
        } else {
            Err(StoreError::DeletionList(
                "head differs from acknowledged head",
            ))
        };
    }
    let local_head = local.last().map_or(0, |e| e.seq);
    if head.seq > local_head {
        return Err(StoreError::InvalidInput("head beyond local list"));
    }
    let map: BTreeMap<u64, &DeletionEntry> = local.iter().map(|e| (e.seq, e)).collect();
    if !links_to_head(&map, head) {
        return Err(StoreError::DeletionList("head does not match local chain"));
    }
    Ok(true)
}

/// RL-12 step 2 (under the row lock): merge an already verified pushed run
/// into the local list (AUD-RM2-STO-04/22). `local` is sorted by seq;
/// `verified` is the last Z-CORE head the store verified (kept across restore);
/// `head` is the verified Z-CORE head of this push. Fails closed on:
/// - a head older than the verified head (attestation counter, day or seq;
///   AUD-RM2-STO-24), or a different head with the same counter;
/// - a non-empty push that does not end exactly at the signed head (seq and
///   chain hash: truncation or a relay-claimed head);
/// - an empty push unless the local chain already contains the head;
/// - a gap between the local head and the pushed run;
/// - a run that neither links to a local entry nor overlaps the local list
///   (unanchored), unless the local list is empty;
/// - any overlapping entry that differs (fork), a filled hole that does not link
///   to its local successor, or a merged list that is not contiguous;
/// - a merged chain that does not contain the last verified head.
///
/// Returns the pushed entries that are new locally.
pub(crate) fn merge_pushed(
    local: &[DeletionEntry],
    verified: Option<&SignedDeletionHead>,
    pushed: &[DeletionEntry],
    head: &SignedDeletionHead,
) -> Result<Vec<DeletionEntry>> {
    if pushed.len() > MAX_PUSHED_DELETION_LIST {
        return Err(StoreError::InvalidInput("deletion list too long"));
    }
    head.newer_than(verified)?;
    let map: BTreeMap<u64, &DeletionEntry> = local.iter().map(|e| (e.seq, e)).collect();
    let Some(last) = pushed.last() else {
        return if links_to_head(&map, head) && verified.is_none_or(|v| links_to_head(&map, v)) {
            Ok(Vec::new())
        } else {
            Err(StoreError::DeletionList("empty push for non-empty list"))
        };
    };
    if last.seq != head.seq || !bool::from(last.next_prev_hash().ct_eq(&head.head_hash)) {
        return Err(StoreError::DeletionList("truncated push"));
    }
    // Internal contiguity again (cheap; signatures were verified before the lock).
    if pushed.windows(2).any(|w| match w {
        [a, b] => !links(a, b),
        _ => false,
    }) {
        return Err(StoreError::DeletionList("broken hash chain"));
    }
    let first = pushed.first().ok_or(StoreError::DeletionList("empty"))?;
    if first.seq == 1 && first.prev_hash != [0u8; 32] {
        return Err(StoreError::DeletionList("bad genesis link"));
    }
    if let Some((&local_head, _)) = map.last_key_value() {
        if first.seq > local_head.saturating_add(1) {
            return Err(StoreError::DeletionList("gap after local head"));
        }
        let anchored = first
            .seq
            .checked_sub(1)
            .and_then(|s| map.get(&s))
            .is_some_and(|a| links(a, first));
        let overlaps = pushed.iter().any(|p| map.contains_key(&p.seq));
        if !anchored && !overlaps {
            return Err(StoreError::DeletionList("unanchored push"));
        }
        if let Some(a) = first.seq.checked_sub(1).and_then(|s| map.get(&s))
            && !links(a, first)
        {
            return Err(StoreError::DeletionList("broken anchor link"));
        }
    }
    let mut new = Vec::new();
    for p in pushed {
        match map.get(&p.seq) {
            Some(l) => {
                if !l.same_signed(p) {
                    return Err(StoreError::DeletionList("fork with local list"));
                }
            }
            None => {
                let mut e = *p;
                e.relayed = false;
                new.push(e);
            }
        }
    }
    // A filled hole must link to its local successor.
    for n in &new {
        if let Some(succ) = n.seq.checked_add(1).and_then(|s| map.get(&s))
            && !links(n, succ)
        {
            return Err(StoreError::DeletionList("broken link to local successor"));
        }
    }
    // The merged list must be contiguous from its lowest retained seq.
    let mut merged = map;
    for n in &new {
        merged.insert(n.seq, n);
    }
    if merged
        .keys()
        .zip(merged.keys().skip(1))
        .any(|(a, b)| a.checked_add(1) != Some(*b))
    {
        return Err(StoreError::DeletionList("merged list not contiguous"));
    }
    // AUD-RM2-STO-22: the result must still contain the last verified head.
    if let Some(v) = verified
        && !links_to_head(&merged, v)
    {
        return Err(StoreError::DeletionList(
            "push does not chain to the verified head",
        ));
    }
    Ok(new)
}

/// Insertion order that keeps every insert chain-extending for the database
/// guard (AUD-RM2-STO-21): entries below the local list in descending order,
/// then entries above it in ascending order.
pub(crate) fn insertion_order(local_min: Option<u64>, new: &mut [DeletionEntry]) {
    new.sort_by_key(|e| match local_min {
        Some(m) if e.seq < m => (0u8, u64::MAX.saturating_sub(e.seq)),
        _ => (1u8, e.seq),
    });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
    use super::*;
    use crate::types::Day;

    fn snap(version: u64, tree: u64, day: u32, from: u64) -> VerifiedSnapshot {
        VerifiedSnapshot {
            version,
            tree_size: tree,
            checkpoint_day: Day(day),
            consistent_from: from,
            body: vec![version as u8; 8],
            signatures: vec![1; 64],
        }
    }

    /// BE-060 / RVW-A-04: rollback rejection matrix.
    #[test]
    fn rollback_matrix() {
        let hwm = KdHighWater {
            tree_size: 100,
            checkpoint_day: Some(Day(50)),
            directory_version: 5,
        };
        let body = vec![5u8; 8];
        assert_eq!(
            snapshot(&hwm, Some(&body), &snap(6, 120, 51, 100)).unwrap(),
            SnapshotDecision::Install
        );
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(6, 99, 51, 99)),
            Err(StoreError::Rollback(_))
        ));
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(6, 120, 49, 100)),
            Err(StoreError::Rollback(_))
        ));
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(4, 120, 51, 100)),
            Err(StoreError::Rollback(_))
        ));
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(6, 120, 51, 90)),
            Err(StoreError::Rollback(_))
        ));
        assert_eq!(
            snapshot(&hwm, Some(&body), &snap(5, 100, 50, 100)).unwrap(),
            SnapshotDecision::AlreadyInstalled
        );
        let mut other = snap(5, 100, 50, 100);
        other.body = vec![9; 8];
        assert!(snapshot(&hwm, Some(&body), &other).is_err());
        // First install from an empty high-water mark.
        let zero = KdHighWater::default();
        assert_eq!(
            snapshot(&zero, None, &snap(1, 10, 1, 0)).unwrap(),
            SnapshotDecision::Install
        );
    }

    fn chain_seed(n: usize, seed: u8) -> (Vec<DeletionEntry>, [u8; 32]) {
        use crate::deletion::{DeletionKind, Ed25519DeletionSigner, make_entry};
        let s = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[4u8; 32]));
        let mut v: Vec<DeletionEntry> = Vec::new();
        for i in 0..n {
            let e = make_entry(
                v.last(),
                DeletionKind::Account,
                [i as u8 ^ seed; 32],
                Day(9),
                &s,
            )
            .unwrap();
            v.push(e);
        }
        (v, s.verifying_key())
    }

    fn chain(n: usize) -> (Vec<DeletionEntry>, [u8; 32]) {
        chain_seed(n, 0)
    }

    const T: TenantId = TenantId([0x11; 16]);

    fn core_key() -> candor_core::sig::SigningKey {
        candor_core::sig::SigningKey::from_seed(&[0x7c; 32])
    }

    const HDAY: Day = Day(20_000);

    /// A Z-CORE head on day `HDAY` whose counter grows with the seq.
    fn head_of(e: Option<&DeletionEntry>) -> SignedDeletionHead {
        head_at(e, HDAY, e.map_or(0, |e| e.seq) + 1)
    }

    fn head_at(e: Option<&DeletionEntry>, day: Day, counter: u64) -> SignedDeletionHead {
        SignedDeletionHead::sign(&T, e, day, counter, &core_key())
    }

    /// AUD-RM2-STO-04/22: gapped, truncated, empty, unanchored and forked pushes
    /// are rejected; a push must end at the signed head and chain to the last
    /// verified head; a proper push merges.
    #[test]
    fn merge_rules() {
        let (all, pk) = chain(8);
        let cpk = core_key().verifying_key_bytes();
        let h8 = head_of(all.last());
        verify_pushed(&all, &pk, &h8, &T, &cpk, HDAY).unwrap();
        let local = &all[..2];
        // Gap: local [1,2] + pushed [5..=6].
        assert_eq!(
            merge_pushed(local, None, &all[4..6], &head_of(all.get(5))),
            Err(StoreError::DeletionList("gap after local head"))
        );
        // Empty push while Z-CORE has entries the local list lacks.
        assert!(merge_pushed(local, None, &[], &head_of(all.get(5))).is_err());
        // Empty push when Z-CORE has none: fine.
        assert_eq!(
            merge_pushed(local, None, &[], &head_of(None))
                .unwrap()
                .len(),
            0
        );
        // Empty push of a head the local list already holds: fine.
        assert_eq!(
            merge_pushed(local, None, &[], &head_of(all.get(1)))
                .unwrap()
                .len(),
            0
        );
        // Z-CORE head behind the verified head.
        assert!(merge_pushed(local, Some(&head_of(all.get(1))), &[], &head_of(None)).is_err());
        // Truncated: the run ends before the signed head.
        assert_eq!(
            merge_pushed(local, None, &all[..5], &h8),
            Err(StoreError::DeletionList("truncated push"))
        );
        // A head whose hash is not the run's chain hash.
        let mut bent = h8;
        bent.head_hash[0] ^= 1;
        assert!(merge_pushed(local, None, &all[2..], &bent).is_err());
        // Proper: anchored at 2, through the head.
        let new = merge_pushed(local, Some(&head_of(all.get(1))), &all[2..], &h8).unwrap();
        assert_eq!(
            new.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3, 4, 5, 6, 7, 8]
        );
        // Overlapping full copy.
        assert_eq!(merge_pushed(local, None, &all, &h8).unwrap().len(), 6);
        // Local list empty: unanchored suffix accepted (only option).
        assert_eq!(merge_pushed(&[], None, &all[3..], &h8).unwrap().len(), 5);
        // Unanchored with a local list: other chain's suffix.
        let (other, _) = chain_seed(4, 0x80);
        assert!(merge_pushed(local, None, &other[2..], &head_of(other.last())).is_err());
        // Fork on overlap.
        assert_eq!(
            merge_pushed(&all[..3], None, &other, &head_of(other.last())),
            Err(StoreError::DeletionList("fork with local list"))
        );
        // Local head beyond Z-CORE (unrelayed local entries) is accepted.
        assert_eq!(
            merge_pushed(&all[..6], None, &all[..4], &head_of(all.get(3)))
                .unwrap()
                .len(),
            0
        );
        // AUD-RM2-STO-22: the verified head (seq 2 of `all`) is the anchor; a
        // pushed chain that does not contain it is refused even on an empty
        // local list.
        let v2 = head_of(all.get(1));
        assert_eq!(
            merge_pushed(&[], Some(&v2), &other, &head_of(other.last())),
            Err(StoreError::DeletionList(
                "push does not chain to the verified head"
            ))
        );
        // ... and a run starting after a pruned verified head links via the
        // successor's prev_hash.
        assert_eq!(
            merge_pushed(&[], Some(&v2), &all[2..], &h8).unwrap().len(),
            6
        );
        assert!(merge_pushed(&[], Some(&v2), &all[3..], &h8).is_err());
    }

    /// The head attestation binds tenant, seq and hash to the Z-CORE key.
    #[test]
    fn head_signature_rules() {
        let (all, pk) = chain(3);
        let cpk = core_key().verifying_key_bytes();
        let h = head_of(all.last());
        h.verify(&T, &cpk).unwrap();
        assert!(h.verify(&TenantId([0x22; 16]), &cpk).is_err());
        assert!(h.verify(&T, &pk).is_err(), "K31 is not the Z-CORE key");
        let mut s = h;
        s.seq = 2;
        assert!(s.verify(&T, &cpk).is_err());
        let mut z = h;
        z.head_hash = [0; 32];
        assert!(z.verify(&T, &cpk).is_err());
        assert!(verify_pushed(&all, &pk, &s, &T, &cpk, HDAY).is_err());
        // Day and counter are signed (AUD-RM2-STO-24).
        let mut d = h;
        d.day = Day(HDAY.0 + 1);
        assert!(d.verify(&T, &cpk).is_err());
        let mut c = h;
        c.counter += 1;
        assert!(c.verify(&T, &cpk).is_err());
        assert!(head_at(all.last(), HDAY, 0).verify(&T, &cpk).is_err());
    }

    /// AUD-RM2-STO-24(b): RL-12 heads must be fresh (±1 day) and not older
    /// than the verified head by attestation counter; the same counter must
    /// carry the same attestation.
    #[test]
    fn head_freshness_and_monotonic_rules() {
        let (all, pk) = chain(6);
        let cpk = core_key().verifying_key_bytes();
        let h = head_at(all.last(), HDAY, 50);
        for (today, ok) in [
            (HDAY, true),
            (Day(HDAY.0 + 1), true),
            (Day(HDAY.0 - 1), true),
            (Day(HDAY.0 + 2), false),
            (Day(HDAY.0 - 2), false),
        ] {
            assert_eq!(
                verify_pushed(&all, &pk, &h, &T, &cpk, today).is_ok(),
                ok,
                "today {today:?}"
            );
        }
        // Replay of an older head after a newer one was verified.
        let v = head_at(all.get(3), HDAY, 40);
        let older = head_at(all.get(4), HDAY, 30);
        assert_eq!(
            merge_pushed(&all[..4], Some(&v), &all[4..5], &older),
            Err(StoreError::DeletionList(
                "Z-CORE head older than the verified head"
            ))
        );
        // Same counter, different content.
        let twin = head_at(all.get(4), HDAY, 40);
        assert_eq!(
            merge_pushed(&all[..4], Some(&v), &all[4..5], &twin),
            Err(StoreError::DeletionList("conflicting Z-CORE head"))
        );
        // Newer counter but an earlier day.
        let back = head_at(all.get(4), Day(HDAY.0 - 1), 41);
        assert!(merge_pushed(&all[..4], Some(&v), &all[4..5], &back).is_err());
        // Identical re-push and a newer attestation are accepted.
        assert!(merge_pushed(&all[..4], Some(&v), &[], &v).is_ok());
        assert_eq!(
            merge_pushed(&all[..4], Some(&v), &all[4..], &h).unwrap().len(),
            2
        );
    }

    /// AUD-RM2-STO-21: acknowledgement only of a head the local chain contains.
    #[test]
    fn ack_rules() {
        let (all, _) = chain(5);
        let h3 = head_of(all.get(2));
        assert_eq!(ack_head(&all, None, &h3), Ok(true));
        assert_eq!(ack_head(&all, Some(&h3), &h3), Ok(false));
        // An older attestation is refused (AUD-RM2-STO-24), a newer one of
        // the same head refreshes it, a newer one of a different hash fails.
        assert!(ack_head(&all, Some(&h3), &head_of(all.get(1))).is_err());
        assert_eq!(
            ack_head(&all, Some(&h3), &head_at(all.get(2), HDAY, 9)),
            Ok(true)
        );
        assert!(ack_head(&all, Some(&h3), &head_at(all.get(1), HDAY, 9)).is_err());
        assert!(ack_head(&all, Some(&h3), &head_at(all.get(2), Day(1), 9)).is_err());
        assert!(matches!(
            ack_head(&all[..2], None, &h3),
            Err(StoreError::InvalidInput(_))
        ));
        let (other, _) = chain_seed(5, 0x80);
        assert!(ack_head(&all, None, &head_of(other.get(2))).is_err());
        // Pruned prefix: the successor's link proves the head.
        assert_eq!(ack_head(&all[3..], None, &h3), Ok(true));
        assert!(ack_head(&all[4..], None, &h3).is_err());
    }

    #[test]
    fn insertion_order_keeps_chain_extending() {
        let (all, _) = chain(10);
        let mut new: Vec<DeletionEntry> = all[..3].iter().chain(&all[7..]).copied().collect();
        insertion_order(Some(4), &mut new);
        assert_eq!(
            new.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3, 2, 1, 8, 9, 10]
        );
    }

    #[test]
    fn fill_batch_limits() {
        let l = ClaimLimits {
            max_objects: 2,
            max_bytes: 100,
        };
        assert_eq!(fill_batch(&[10, 10, 10], l), vec![0, 1]);
        let l = ClaimLimits {
            max_objects: 10,
            max_bytes: 25,
        };
        assert_eq!(fill_batch(&[10, 20, 10], l), vec![0, 2]);
        let l = ClaimLimits {
            max_objects: 10,
            max_bytes: 5,
        };
        assert_eq!(fill_batch(&[10, 20], l), vec![0]);
    }
}
