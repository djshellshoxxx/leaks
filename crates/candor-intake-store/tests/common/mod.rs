// SPDX-License-Identifier: AGPL-3.0-or-later
//! `IntakeStore` conformance suite, run against both implementations
//! (tests/memory.rs, tests/pg.rs). Test IDs: 09 §5.1/§8, 07 BE-014/BE-056/BE-060/
//! BE-062/BE-063/BE-074, 08 RL-02..RL-12, SA-19/SA-20, API-037/040/047/054,
//! KEY-077, ADR-052, and the AUD-RM2-STO regression tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;
use std::future::Future;

use candor_intake_store::deaddrop::parse_page;
use candor_intake_store::deletion::{
    self, DeletionKind, Ed25519DeletionSigner, ReplyObjectHasher, verify_chain,
};
use candor_intake_store::*;

pub const TENANT: TenantId = TenantId([0x11; 16]);
pub const OTHER_TENANT: TenantId = TenantId([0x22; 16]);
pub const SALT: [u8; 32] = [0x5a; 32];
/// 2026-10-15.
pub const TODAY: Day = Day(20741);
/// Published-set configuration of the suite: one slot per day, K = 4 entries per
/// slot, 120 entries in the window -> 2 pages (128 entries, 8 padding). Dummy
/// buckets are uniform over k = 1..=4 except for the per-bucket floor that
/// covers every canonical bucket (AUD-RM2-STO-19/25 tests).
pub const TEST_DEADDROP: DeadDropConfig = DeadDropConfig {
    slots_per_day: 1,
    per_slot: 4,
    max_pending: 64,
    dummy_bucket_weights: [
        TEST_MAIN_WEIGHT,
        TEST_MAIN_WEIGHT,
        TEST_MAIN_WEIGHT,
        TEST_MAIN_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
        MIN_DUMMY_BUCKET_WEIGHT,
    ],
};
/// Weight of each of buckets 1..=4 in [`TEST_DEADDROP`].
pub const TEST_MAIN_WEIGHT: f64 = (1.0 - 12.0 * MIN_DUMMY_BUCKET_WEIGHT) / 4.0;

/// Group a 16-bucket histogram into the cells [1], [2], [3], [4], [5..=16].
pub fn grouped(h: &[usize; 16]) -> [usize; 5] {
    [h[0], h[1], h[2], h[3], h[4..].iter().sum()]
}

/// Cell probabilities of [`grouped`] under [`TEST_DEADDROP`].
pub const TEST_GROUPED_P: [f64; 5] = [
    TEST_MAIN_WEIGHT,
    TEST_MAIN_WEIGHT,
    TEST_MAIN_WEIGHT,
    TEST_MAIN_WEIGHT,
    12.0 * MIN_DUMMY_BUCKET_WEIGHT,
];

/// Both traits (the PG factory attaches a maintenance handle).
pub trait Store: IntakeStore + IntakeMaintenance {}
impl<T: IntakeStore + IntakeMaintenance> Store for T {}

pub fn signer() -> Ed25519DeletionSigner {
    Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[0x31; 32]))
}

/// The Z-CORE head key (AUD-RM2-STO-21/22).
pub fn core_key() -> candor_core::sig::SigningKey {
    candor_core::sig::SigningKey::from_seed(&[0xc0; 32])
}

pub fn core_pk() -> [u8; 32] {
    core_key().verifying_key_bytes()
}

/// Z-CORE's signed head over a copy of the list ending at `last`, attested on
/// [`TODAY`] with an attestation counter that grows with the seq.
pub fn zhead(last: Option<&DeletionEntry>) -> SignedDeletionHead {
    zhead_at(last, TODAY, last.map_or(0, |e| e.seq) + 1)
}

/// Z-CORE's signed head with an explicit day and counter (AUD-RM2-STO-24).
pub fn zhead_at(last: Option<&DeletionEntry>, day: Day, counter: u64) -> SignedDeletionHead {
    SignedDeletionHead::sign(&TENANT, last, day, counter, &core_key())
}

/// Test hasher: object hash = first 32 bytes of reply_ct.
pub struct PrefixHasher;
impl ReplyObjectHasher for PrefixHasher {
    fn object_hash(&self, ct: &[u8]) -> Option<[u8; 32]> {
        ct.get(..32)?.try_into().ok()
    }
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn uniq() -> u64 {
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub fn blob() -> BlobId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&uniq().to_be_bytes());
    b[8..].copy_from_slice(&std::process::id().to_be_bytes().repeat(2));
    BlobId(b)
}

pub fn slot(day: Day) -> ImportSlot {
    ImportSlot { day, index: 0 }
}

fn object(size: u64) -> GroupObject {
    let mut oh = [0x0b; 32];
    oh[..8].copy_from_slice(&uniq().to_be_bytes());
    oh[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    GroupObject {
        object_hash: oh,
        slot_block: vec![0x5b; SLOT_BLOCK_LEN_STD],
        blob: PartRef {
            blob_id: blob(),
            padded_size: size,
        },
    }
}

/// One fixed-shape group (main, bundle, identity), received TODAY.
pub fn envelope(offset: u8) -> CommitEnvelope {
    CommitEnvelope {
        channel_id: ChannelId([0xc1; 16]),
        objects: [object(65_536), object(262_144), object(65_536)],
        disposition_ct: vec![0xd0; DISPOSITION_CT_LEN_STD],
        epoch_index: 2963,
        received_date: TODAY,
        release_offset_days: offset,
    }
}

pub fn digest(e: &CommitEnvelope) -> [u8; 32] {
    group_digest(&e.objects.clone().map(|o| o.object_hash))
}

pub fn new_account(tag: u8) -> NewAccount {
    NewAccount {
        lookup_tag: LookupTag([tag; 32]),
        auth_pk: [tag; 32],
        xwing_pk: vec![tag; XWING_PK_LEN],
        prefs_ct: vec![tag; 200],
    }
}

/// A reply whose plaintext is about `plain` bytes: its ciphertext has the
/// canonical length of the REPLY bucket holding `plain` (AUD-RM2-STO-20).
pub fn reply(account: Option<AccountId>, mailbox: u8, plain: usize) -> IncomingReply {
    let k = u8::try_from(plain.div_ceil(REPLY_BUCKET_UNIT).clamp(1, 16)).unwrap();
    reply_bucket(account, mailbox, k)
}

/// A reply of REPLY bucket `k`.
pub fn reply_bucket(account: Option<AccountId>, mailbox: u8, k: u8) -> IncomingReply {
    let mut ct = vec![mailbox; reply_ct_len(k).unwrap()];
    ct[..8].copy_from_slice(&uniq().to_be_bytes());
    ct[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    let oh: [u8; 32] = ct[..32].try_into().unwrap();
    IncomingReply {
        account,
        mailbox_id: Some(MailboxId([mailbox; 32])),
        object_hash: oh,
        reply_ct: ct,
        size_bucket: k,
    }
}

pub fn snap(version: u64, tree: u64, day: u32, from: u64) -> VerifiedSnapshot {
    VerifiedSnapshot {
        version,
        tree_size: tree,
        checkpoint_day: Day(day),
        consistent_from: from,
        body: vec![version as u8; 64],
        signatures: vec![0xee; 128],
    }
}

pub async fn fresh<S, F, Fut>(mk: &F) -> S
where
    S: Store,
    F: Fn(TenantId) -> Fut,
    Fut: Future<Output = S>,
{
    let s = mk(TENANT).await;
    s.init(TENANT, SALT).await.unwrap();
    s
}

pub async fn account<S: Store>(s: &S, tag: u8) -> AccountId {
    s.create_account(new_account(tag), TODAY).await.unwrap()
}

/// All entry bodies of the current published set.
pub async fn published<S: Store>(s: &S) -> Vec<Vec<u8>> {
    let idx = s.reply_index().await.unwrap();
    let mut v = Vec::new();
    for p in 0..idx.page_count {
        let page = s.reply_page(p).await.unwrap();
        assert_eq!(page.len(), REPLY_PAGE_LEN);
        for e in parse_page(&page).unwrap() {
            v.push(e.to_vec());
        }
    }
    v
}

pub async fn init_and_meta<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = mk(TENANT).await;
    assert_eq!(s.tenant().await, Err(StoreError::NotInitialized));
    assert_eq!(s.pending_count().await, Err(StoreError::NotInitialized));
    assert_eq!(
        s.commit_envelope(envelope(0)).await,
        Err(StoreError::NotInitialized)
    );
    s.init(TENANT, SALT).await.unwrap();
    s.init(TENANT, SALT).await.unwrap();
    assert_eq!(
        s.init(OTHER_TENANT, SALT).await,
        Err(StoreError::TenantMismatch)
    );
    assert_eq!(s.tenant().await.unwrap(), TENANT);
    assert!(s.serving_allowed().await.unwrap());
    // 07 §5.4 anti-replay.
    s.accept_relay_counter(5).await.unwrap();
    assert_eq!(s.accept_relay_counter(5).await, Err(StoreError::Replay));
    assert_eq!(s.accept_relay_counter(4).await, Err(StoreError::Replay));
    s.accept_relay_counter(6).await.unwrap();
}

/// ADR-052(2): accounts are created and updated by their own operations; an
/// envelope never references or modifies an account (AUD-RM2-STO-01).
pub async fn accounts<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    assert_eq!(s.lookup_account(&LookupTag([1; 32])).await.unwrap(), None);
    let id = account(&s, 1).await;
    let a = s
        .lookup_account(&LookupTag([1; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.account_id, id);
    assert_eq!(a.auth_pk, [1; 32]);
    assert_eq!(a.xwing_pk.len(), XWING_PK_LEN);
    assert_eq!(a.activity_month, TODAY.month_start());
    assert_eq!(
        s.create_account(new_account(1), TODAY).await,
        Err(StoreError::AccountExists)
    );
    // Envelope commits do not touch accounts (no activity write per action).
    let mut later = envelope(0);
    later.received_date = TODAY.next_month_start();
    s.commit_envelope(later).await.unwrap();
    assert_eq!(
        s.lookup_account(&LookupTag([1; 32]))
            .await
            .unwrap()
            .unwrap()
            .activity_month,
        TODAY.month_start()
    );
    // Invalid new account fields.
    let mut bad = new_account(2);
    bad.xwing_pk.pop();
    assert!(matches!(
        s.create_account(bad, TODAY).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut bad = new_account(2);
    bad.prefs_ct = vec![0; 4097];
    assert!(matches!(
        s.create_account(bad, TODAY).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(s.lookup_account(&LookupTag([2; 32])).await.unwrap(), None);
    // Rotation (update) to a new tag; collisions and unknown ids refused.
    let other = account(&s, 3).await;
    s.update_account(id, new_account(4)).await.unwrap();
    assert_eq!(s.lookup_account(&LookupTag([1; 32])).await.unwrap(), None);
    let rotated = s
        .lookup_account(&LookupTag([4; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((rotated.account_id, rotated.auth_pk), (id, [4; 32]));
    assert_eq!(
        s.update_account(other, new_account(4)).await,
        Err(StoreError::AccountExists)
    );
    assert_eq!(
        s.update_account(AccountId([9; 16]), new_account(5)).await,
        Err(StoreError::NotFound)
    );
    // Same tag for the same account is a no-op rotation.
    s.update_account(id, new_account(4)).await.unwrap();
    // inactive_purge: 365 days after the start of the last activity month.
    assert_eq!(s.purge_inactive_accounts(TODAY).await.unwrap(), 0);
    let purge_day = TODAY.month_start().plus(365).unwrap();
    s.apply_replies(TODAY, vec![reply(Some(other), 3, 100)])
        .await
        .unwrap();
    assert_eq!(s.purge_inactive_accounts(purge_day).await.unwrap(), 2);
    assert_eq!(s.lookup_account(&LookupTag([4; 32])).await.unwrap(), None);
    assert!(s.mailbox_list(other).await.unwrap().is_empty());
}

/// Hostile/oversize envelope inputs are rejected without side effects; a
/// repeated group is `DuplicateEnvelope` (ADR-052(1)).
pub async fn envelope_validation<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let bad = |f: &dyn Fn(&mut CommitEnvelope)| {
        let mut e = envelope(0);
        f(&mut e);
        e
    };
    for e in [
        bad(&|e| e.objects[0].slot_block.push(0)),
        bad(&|e| e.objects[2].slot_block.pop().map(|_| ()).unwrap()),
        bad(&|e| e.disposition_ct.push(0)),
        bad(&|e| e.release_offset_days = 22),
        bad(&|e| e.objects[1].blob.blob_id = e.objects[0].blob.blob_id),
        bad(&|e| e.objects[2].object_hash = e.objects[1].object_hash),
        bad(&|e| e.objects[1].blob.padded_size = 0),
        bad(&|e| e.objects[1].blob.padded_size = (16 << 30) + 1),
        bad(&|e| e.epoch_index = u32::MAX),
    ] {
        assert!(matches!(
            s.commit_envelope(e).await,
            Err(StoreError::InvalidInput(_))
        ));
    }
    let e = envelope(0);
    s.commit_envelope(e.clone()).await.unwrap();
    // Replay of the same group (e.g. a sealer retry) with new blob ids.
    let mut dup = e.clone();
    for o in &mut dup.objects {
        o.blob.blob_id = blob();
    }
    assert_eq!(
        s.commit_envelope(dup).await,
        Err(StoreError::DuplicateEnvelope)
    );
    // Reused blob id in another envelope.
    let mut reuse = envelope(0);
    reuse.objects[1].blob = e.objects[1].blob;
    assert!(matches!(
        s.commit_envelope(reuse).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(s.pending_count().await.unwrap(), 1);
}

/// RL-02..RL-04, BE-014, BE-062, API-047.
pub async fn claim_ack<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let lim = ClaimLimits {
        max_objects: 500,
        max_bytes: MAX_CLAIM_BYTES,
    };
    assert!(s.claim_batch(TODAY, lim).await.unwrap().objects.is_empty());
    let e1 = envelope(0);
    let e2 = envelope(0);
    let held = envelope(2);
    s.commit_envelope(e1.clone()).await.unwrap();
    s.commit_envelope(e2.clone()).await.unwrap();
    s.commit_envelope(held.clone()).await.unwrap();
    assert_eq!(s.pending_count().await.unwrap(), 3);

    let b = s.claim_batch(TODAY, lim).await.unwrap();
    assert!(!b.replayed);
    assert_eq!(
        b.objects.len(),
        2,
        "delayed envelope not offered before release_day"
    );
    let d1 = digest(&e1);
    let o1 = b.objects.iter().find(|o| o.sha256 == d1).unwrap();
    assert_eq!(o1.channel_id, e1.channel_id);
    assert_eq!(o1.epoch_index, 2963);
    assert_eq!(o1.object_hashes, e1.objects.clone().map(|o| o.object_hash));
    assert_eq!(o1.parts, [65_536, 262_144, 65_536]);
    assert_eq!(o1.disposition_ct.len(), DISPOSITION_CT_LEN_STD);

    // Unacked batch is returned again (RL-02 conflict semantics).
    let again = s.claim_batch(TODAY, lim).await.unwrap();
    assert!(again.replayed);
    assert_eq!(again.batch_no, b.batch_no);
    assert_eq!(again.objects, b.objects);

    // RL-03.
    assert_eq!(
        s.batch_object(b.batch_no, o1.envelope_ref, PartSelector::SlotBlock(2))
            .await
            .unwrap(),
        ObjectData::Bytes(e1.objects[2].slot_block.clone())
    );
    assert_eq!(
        s.batch_object(b.batch_no, o1.envelope_ref, PartSelector::Object(1))
            .await
            .unwrap(),
        ObjectData::Blob(e1.objects[1].blob)
    );
    for sel in [PartSelector::Object(3), PartSelector::SlotBlock(3)] {
        assert_eq!(
            s.batch_object(b.batch_no, o1.envelope_ref, sel).await,
            Err(StoreError::NotFound)
        );
    }
    assert_eq!(
        s.batch_object(b.batch_no + 1, o1.envelope_ref, PartSelector::Object(0))
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        s.batch_object(b.batch_no, EnvelopeRef([0; 16]), PartSelector::Object(0))
            .await,
        Err(StoreError::NotFound)
    );

    // RL-04: unknown digest → nothing changes.
    assert!(matches!(
        s.ack_batch(b.batch_no, &[d1, [7; 32]]).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(s.pending_count().await.unwrap(), 3);
    assert_eq!(
        s.ack_batch(b.batch_no + 9, &[d1]).await,
        Err(StoreError::NotFound)
    );
    let ack = s.ack_batch(b.batch_no, &[d1]).await.unwrap();
    assert_eq!(ack.deleted, 1);
    assert_eq!(
        ack.blobs_to_delete,
        e1.objects
            .iter()
            .map(|o| o.blob.blob_id)
            .collect::<Vec<_>>()
    );
    assert_eq!(s.pending_count().await.unwrap(), 2);
    assert_eq!(
        s.ack_batch(b.batch_no, &[]).await,
        Err(StoreError::NotFound),
        "batch closed after ack"
    );

    // Unacked e2 is offered again in a new batch; the held one only from its release day.
    let b2 = s.claim_batch(TODAY, lim).await.unwrap();
    assert!(b2.batch_no > b.batch_no);
    assert_eq!(b2.objects.len(), 1);
    assert_eq!(b2.objects[0].sha256, digest(&e2));
    s.ack_batch(b2.batch_no, &[b2.objects[0].sha256])
        .await
        .unwrap();
    let b3 = s.claim_batch(TODAY.plus(2).unwrap(), lim).await.unwrap();
    assert_eq!(b3.objects.len(), 1);
    assert_eq!(b3.objects[0].sha256, digest(&held));
    s.ack_batch(b3.batch_no, &[b3.objects[0].sha256])
        .await
        .unwrap();
    assert_eq!(s.pending_count().await.unwrap(), 0);
}

/// RL-02 limits.
pub async fn claim_limits<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    for _ in 0..3 {
        s.commit_envelope(envelope(0)).await.unwrap();
    }
    for (o, b) in [(0, 1), (501, 1), (1, MAX_CLAIM_BYTES + 1)] {
        assert!(matches!(
            s.claim_batch(
                TODAY,
                ClaimLimits {
                    max_objects: o,
                    max_bytes: b
                }
            )
            .await,
            Err(StoreError::InvalidInput(_))
        ));
    }
    let b = s
        .claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 2,
                max_bytes: MAX_CLAIM_BYTES,
            },
        )
        .await
        .unwrap();
    assert_eq!(b.objects.len(), 2);
    s.ack_batch(b.batch_no, &[]).await.unwrap();
    // max_bytes smaller than one group: exactly one group (never starves).
    let b = s
        .claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 500,
                max_bytes: 10,
            },
        )
        .await
        .unwrap();
    assert_eq!(b.objects.len(), 1);
}

/// AUD-RM2-STO-16: under backlog the oldest released envelope is claimed first,
/// whatever its random ref.
pub async fn claim_fairness<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let mut old = envelope(0);
    old.received_date = TODAY.saturating_minus(5);
    let old_digest = digest(&old);
    for _ in 0..8 {
        s.commit_envelope(envelope(0)).await.unwrap();
    }
    s.commit_envelope(old).await.unwrap();
    let b = s
        .claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 1,
                max_bytes: MAX_CLAIM_BYTES,
            },
        )
        .await
        .unwrap();
    assert_eq!(b.objects.len(), 1);
    assert_eq!(b.objects[0].sha256, old_digest);
}

/// SA-19/SA-20, BE-063, API-037, API-040 and AUD-RM2-STO-06/07: fixed page
/// shape from the configuration; byte-identical pages; each publication adds
/// exactly K entries and expires exactly K, independent of the number of real
/// replies; real replies beyond K wait for the next slot; entries are never
/// regenerated; a repeated slot adds nothing.
pub async fn dead_drop<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let k = usize::from(TEST_DEADDROP.per_slot);
    let total = TEST_DEADDROP.total_entries().unwrap();
    let idx = s.reply_index().await.unwrap();
    assert_eq!(
        (idx.page_count, idx.page_size, idx.window_days),
        (2, 64, 30)
    );
    let acct = account(&s, 4).await;

    // Bootstrap publication back-fills the whole window with dummies.
    let mut day = TODAY;
    let idx = s.rebuild_published_set(slot(day)).await.unwrap();
    assert_eq!(idx.page_count, 2);
    assert_eq!(
        s.reply_index().await.unwrap(),
        idx,
        "stable between rebuilds"
    );
    for p in 0..idx.page_count {
        assert_eq!(
            s.reply_page(p).await.unwrap(),
            s.reply_page(p).await.unwrap(),
            "byte-identical for every requester"
        );
    }
    assert_eq!(
        s.reply_page(idx.page_count).await,
        Err(StoreError::NotFound)
    );
    let mut prev: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
    assert_eq!(prev.len(), total, "all entries distinct");

    let mut all_reals: Vec<Vec<u8>> = Vec::new();
    // Reals pushed per slot: 0, 3, 7 (> K: carried over), 0, 1 Tier W.
    for (step, n_real) in [0usize, 3, 7, 0, 2].into_iter().enumerate() {
        day = day.plus(1).unwrap();
        let mut batch: Vec<IncomingReply> = (0..n_real).map(|_| reply(None, 0x41, 1000)).collect();
        if step == 4 {
            batch = vec![reply(Some(acct), 0x42, 500), reply(Some(acct), 0x42, 600)];
        }
        all_reals.extend(batch.iter().map(|r| r.reply_ct.clone()));
        let res = s.apply_replies(day, batch).await.unwrap();
        assert_eq!(res.accepted as usize, n_real);
        let idx2 = s.rebuild_published_set(slot(day)).await.unwrap();
        assert_eq!(idx2.page_count, 2, "page count independent of replies");
        let next: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
        assert_eq!(next.len(), total);
        let added = next.difference(&prev).count();
        let removed = prev.difference(&next).count();
        assert_eq!(
            (added, removed),
            (k, k),
            "step {step}: diff reveals only K added / K expired"
        );
        prev = next;
    }
    // Every real reply is published exactly once by now (7 carried over: 4 + 3).
    let entries = published(&s).await;
    for r in &all_reals {
        assert_eq!(entries.iter().filter(|e| *e == r).count(), 1);
    }
    // Tier W replies also land in the fixed mailbox.
    let mb = s.mailbox_list(acct).await.unwrap();
    assert_eq!(mb.iter().map(|r| r.slot).collect::<Vec<_>>(), vec![0, 1]);
    // A repeated slot publishes nothing new; set_version still changes.
    let before: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
    let v1 = s.reply_index().await.unwrap().set_version;
    let v2 = s
        .rebuild_published_set(slot(day))
        .await
        .unwrap()
        .set_version;
    assert_ne!(v1, v2);
    let after: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
    assert_eq!(before, after, "entries are never regenerated");

    // A missed slot is back-filled with dummies: still K per generation.
    day = day.plus(2).unwrap();
    s.rebuild_published_set(slot(day)).await.unwrap();
    let next: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
    assert_eq!(next.difference(&after).count(), 2 * k);

    // reply_expiry (≤ 30 days, ADR-039) removes whole generations; the
    // padding pool stays.
    let expired = s
        .expire_replies(TODAY.plus(30).unwrap(), 365)
        .await
        .unwrap();
    assert!(expired >= k as u64);
    assert!(
        s.purge_replies_before(day.plus(31).unwrap()).await.unwrap() > 0,
        "everything dated is purged"
    );
    s.rebuild_published_set(slot(day.plus(31).unwrap()))
        .await
        .unwrap();
    assert_eq!(published(&s).await.len(), total);
}

/// χ² statistic of a 2 × c contingency table (homogeneity of two histograms).
pub fn chi2_two_sample(a: &[usize], b: &[usize]) -> f64 {
    let (na, nb) = (
        a.iter().sum::<usize>() as f64,
        b.iter().sum::<usize>() as f64,
    );
    let n = na + nb;
    a.iter()
        .zip(b)
        .filter(|(x, y)| **x + **y > 0)
        .map(|(x, y)| {
            let col = (*x + *y) as f64;
            let (ea, eb) = (na * col / n, nb * col / n);
            (*x as f64 - ea).powi(2) / ea + (*y as f64 - eb).powi(2) / eb
        })
        .sum()
}

/// χ² critical value for 3 degrees of freedom at p = 1e-4.
pub const CHI2_3DOF_P1E4: f64 = 21.11;
/// χ² critical value for 4 degrees of freedom at p = 1e-4.
pub const CHI2_4DOF_P1E4: f64 = 23.51;

/// χ² goodness of fit of `hist` against cell probabilities `p`.
pub fn chi2_fit(hist: &[usize], p: &[f64]) -> f64 {
    let n = hist.iter().sum::<usize>() as f64;
    hist.iter()
        .zip(p)
        .map(|(o, p)| {
            let e = p * n;
            (*o as f64 - e).powi(2) / e
        })
        .sum()
}

/// AUD-RM2-STO-19: every dummy's bucket is drawn from the configured public
/// distribution, independently of the real replies published in the same
/// generation. Each slot adds K entries; in half of the slots one of them is a
/// real bucket-16 reply. The dummies do not copy it (bucket 16 only at its
/// configured floor rate), follow the configured distribution in both kinds of
/// slot, and the two dummy histograms are statistically identical (pre-fix,
/// every dummy copied the real reply's length).
pub async fn dead_drop_sizes<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let mut day = TODAY;
    s.rebuild_published_set(slot(day)).await.unwrap();
    let mut prev: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
    let boot: Vec<u8> = prev
        .iter()
        .map(|e| reply_bucket_of_len(e.len()).expect("canonical dummy length"))
        .collect();
    assert!(boot.iter().all(|k| (1..=16).contains(k)));
    let (mut with_real, mut without) = ([0usize; 16], [0usize; 16]);
    for step in 0..48 {
        day = day.plus(1).unwrap();
        let reals: Vec<IncomingReply> = if step % 2 == 0 {
            vec![reply_bucket(None, 0x61, 16)]
        } else {
            Vec::new()
        };
        let real_cts: Vec<Vec<u8>> = reals.iter().map(|r| r.reply_ct.clone()).collect();
        s.apply_replies(day, reals).await.unwrap();
        s.rebuild_published_set(slot(day)).await.unwrap();
        let next: HashSet<Vec<u8>> = published(&s).await.into_iter().collect();
        let added: Vec<&Vec<u8>> = next.difference(&prev).collect();
        assert_eq!(added.len(), usize::from(TEST_DEADDROP.per_slot));
        for e in added {
            if real_cts.contains(e) {
                continue;
            }
            let k = reply_bucket_of_len(e.len()).expect("canonical dummy length");
            let h = if real_cts.is_empty() {
                &mut without
            } else {
                &mut with_real
            };
            h[usize::from(k) - 1] += 1;
        }
        prev = next;
    }
    assert_eq!(with_real.iter().sum::<usize>(), 24 * 3);
    assert_eq!(without.iter().sum::<usize>(), 24 * 4);
    // 72 dummies at p = 0.005: P(≥ 5 of bucket 16) < 1e-4 (copying gives 72).
    assert!(
        with_real[15] <= 4,
        "dummies copy the real reply's bucket: {with_real:?}"
    );
    for h in [&with_real, &without] {
        let c = chi2_fit(&grouped(h), &TEST_GROUPED_P);
        assert!(c < CHI2_4DOF_P1E4, "chi2 {c} for {h:?}");
    }
    let c = chi2_two_sample(&grouped(&with_real), &grouped(&without));
    assert!(
        c < CHI2_4DOF_P1E4,
        "dummy sizes depend on real volume: chi2 {c}"
    );
}

/// AUD-RM2-STO-07: the publication backlog is bounded; replies beyond it are
/// rejected (the relay retries) instead of growing the published set.
pub async fn reply_backlog<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let max = TEST_DEADDROP.max_pending as usize;
    let res = s
        .apply_replies(TODAY, (0..max + 6).map(|_| reply(None, 1, 40)).collect())
        .await
        .unwrap();
    assert_eq!(res.accepted as usize, max);
    assert_eq!(
        res.rejected,
        (max as u32..max as u32 + 6).collect::<Vec<_>>()
    );
    // Publication drains K per slot; the set never grows.
    let idx = s.rebuild_published_set(slot(TODAY)).await.unwrap();
    assert_eq!(idx.page_count, TEST_DEADDROP.page_count().unwrap());
    let res = s
        .apply_replies(TODAY, (0..8).map(|_| reply(None, 1, 40)).collect())
        .await
        .unwrap();
    assert_eq!(res.accepted, u32::from(TEST_DEADDROP.per_slot));
}

/// RL-05 rejections and ADR-047(9) drops.
pub async fn reply_rules<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let sg = signer();
    let acct = account(&s, 5).await;

    let mut empty = reply(None, 1, 40);
    empty.reply_ct.clear();
    let mut oversize = reply(None, 1, 40);
    oversize.reply_ct.resize(MAX_REPLY_CT + 1, 1);
    let mut bucket = reply(None, 1, 40);
    bucket.size_bucket = 0;
    let mut no_mailbox = reply(Some(acct), 1, 40);
    no_mailbox.mailbox_id = None;
    let unknown_account = reply(Some(AccountId([0x77; 16])), 1, 40);
    // AUD-RM2-STO-20: only canonical lengths, and the bucket must be the one
    // the store derives from the length (the function used for dummies).
    let mut odd_len = reply(None, 1, 40);
    odd_len.reply_ct.push(0);
    let mut wrong_bucket = reply(None, 1, 40);
    wrong_bucket.size_bucket = 2;
    let res = s
        .apply_replies(
            TODAY,
            vec![
                empty,
                oversize,
                bucket,
                no_mailbox,
                unknown_account,
                odd_len,
                wrong_bucket,
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        res,
        ApplyRepliesResult {
            accepted: 1,
            rejected: vec![0, 1, 2, 3, 5, 6]
        }
    );
    assert!(matches!(
        s.apply_replies(
            TODAY,
            (0..=MAX_REPLIES_PER_PUSH)
                .map(|_| reply(None, 1, 40))
                .collect()
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));

    // Fixed 32-slot mailbox: the 33rd reply is rejected (relay retries later).
    let full: Vec<IncomingReply> = (0..33).map(|_| reply(Some(acct), 2, 40)).collect();
    let res = s.apply_replies(TODAY, full).await.unwrap();
    assert_eq!(res.accepted, 32);
    assert_eq!(res.rejected, vec![32]);

    // Source deletes a mailbox and a reply: later pushes are dropped silently.
    let mb = s.mailbox_list(acct).await.unwrap();
    let r0 = mb[0].reply_ref;
    let r0_hash: [u8; 32] = mb[0].reply_ct[..32].try_into().unwrap();
    assert_eq!(
        s.delete_replies(acct, &[(r0, r0_hash)], TODAY, &sg)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        s.delete_replies(acct, &[(r0, r0_hash)], TODAY, &sg).await,
        Err(StoreError::NotFound)
    );
    let rest: Vec<ReplyRef> = s
        .mailbox_list(acct)
        .await
        .unwrap()
        .iter()
        .map(|r| r.reply_ref)
        .collect();
    assert!(matches!(
        s.delete_mailbox(acct, &MailboxId([2; 32]), &[rest[0], rest[0]], TODAY, &sg)
            .await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(
        s.delete_mailbox(acct, &MailboxId([2; 32]), &rest, TODAY, &sg)
            .await
            .unwrap(),
        31
    );
    assert!(s.mailbox_list(acct).await.unwrap().is_empty());

    let to_deleted_mailbox = reply(Some(acct), 2, 40);
    let mut deleted_hash = reply(None, 9, 40);
    deleted_hash.object_hash = r0_hash;
    let res = s
        .apply_replies(TODAY, vec![to_deleted_mailbox, deleted_hash])
        .await
        .unwrap();
    assert_eq!(
        res,
        ApplyRepliesResult {
            accepted: 2,
            rejected: vec![]
        }
    );
    assert!(s.mailbox_list(acct).await.unwrap().is_empty());
    s.rebuild_published_set(slot(TODAY)).await.unwrap();
    assert!(
        published(&s)
            .await
            .iter()
            .all(|e| e.get(..32) != Some(&r0_hash[..]))
    );

    // Another account cannot delete this account's replies.
    let other = account(&s, 6).await;
    s.apply_replies(TODAY, vec![reply(Some(acct), 3, 40)])
        .await
        .unwrap();
    let mine = s.mailbox_list(acct).await.unwrap()[0].reply_ref;
    assert_eq!(
        s.delete_replies(other, &[(mine, [0; 32])], TODAY, &sg)
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(s.mailbox_list(acct).await.unwrap().len(), 1);
}

/// ADR-047(9), KEY-077, RL-11, BE-074: signed chain, acknowledgement, prune by
/// the maintenance role only (AUD-RM2-STO-03/10).
pub async fn deletion_list<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let sg = signer();
    let acct = account(&s, 7).await;
    s.apply_replies(TODAY, vec![reply(Some(acct), 7, 100)])
        .await
        .unwrap();
    assert_eq!(
        s.delete_account(AccountId([0; 16]), TODAY, &sg).await,
        Err(StoreError::NotFound)
    );
    s.delete_account(acct, TODAY, &sg).await.unwrap();
    assert_eq!(s.lookup_account(&LookupTag([7; 32])).await.unwrap(), None);
    assert!(
        s.mailbox_list(acct).await.unwrap().is_empty(),
        "account replies deleted with the account"
    );

    // AUD-RM2-STO-10: `after` beyond the head is refused and acknowledges nothing.
    assert!(matches!(
        s.deletion_list_after(u64::MAX, 100).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.deletion_list_after(2, 100).await,
        Err(StoreError::InvalidInput(_))
    ));
    let list = s.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(list.len(), 1);
    let e = list[0];
    assert_eq!(
        (e.seq, e.kind, e.del_day, e.relayed),
        (1, DeletionKind::Account, TODAY, false)
    );
    assert_eq!(
        e.del_hash,
        deletion::account_del_hash(&TENANT, &LookupTag([7; 32]))
    );
    verify_chain(&list, &sg.verifying_key(), None).unwrap();
    // Nothing was acknowledged, so nothing can be pruned.
    assert_eq!(
        s.prune_deletion_list(TODAY.plus(100).unwrap())
            .await
            .unwrap(),
        0
    );

    // More entries, then the relay acknowledges through seq 2.
    let a8 = account(&s, 8).await;
    s.delete_mailbox(a8, &MailboxId([8; 32]), &[], TODAY, &sg)
        .await
        .unwrap();
    s.delete_account(a8, TODAY.plus(1).unwrap(), &sg)
        .await
        .unwrap();
    let all = s.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(all.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    verify_chain(&all, &sg.verifying_key(), None).unwrap();
    // Reading acknowledges nothing (AUD-RM2-STO-21).
    assert!(s.deletion_list_after(3, 100).await.unwrap().is_empty());
    assert!(
        s.deletion_list_after(0, 100)
            .await
            .unwrap()
            .iter()
            .all(|e| !e.relayed)
    );
    // AUD-RM2-STO-21: only a Z-CORE-signed head of the local chain is accepted.
    let k31_signed = SignedDeletionHead::sign(
        &TENANT,
        all.get(1),
        TODAY,
        3,
        &candor_core::sig::SigningKey::from_seed(&[0x31; 32]),
    );
    let mut forged = zhead(all.get(1));
    forged.seq = 3;
    let other_chain = {
        let e = deletion::make_entry(None, DeletionKind::Reply, [9; 32], TODAY, &sg).unwrap();
        let f = deletion::make_entry(Some(&e), DeletionKind::Reply, [8; 32], TODAY, &sg).unwrap();
        zhead(Some(&f))
    };
    let beyond = {
        let e = deletion::make_entry(all.last(), DeletionKind::Reply, [7; 32], TODAY, &sg).unwrap();
        zhead(Some(&e))
    };
    for (h, why) in [
        (k31_signed, "signed by K31, not Z-CORE"),
        (forged, "seq changed after signing"),
        (other_chain, "not the local chain"),
        (beyond, "beyond the local head"),
    ] {
        assert!(
            s.acknowledge_deletion_head(&h, &core_pk()).await.is_err(),
            "{why}"
        );
    }
    assert_eq!(
        s.prune_deletion_list(TODAY.plus(100).unwrap())
            .await
            .unwrap(),
        0,
        "rejected acknowledgements change nothing"
    );
    s.acknowledge_deletion_head(&zhead(all.get(1)), &core_pk())
        .await
        .unwrap();
    // An older attestation is refused and changes nothing (AUD-RM2-STO-24);
    // the identical one is a no-op.
    assert!(matches!(
        s.acknowledge_deletion_head(&zhead(all.first()), &core_pk())
            .await,
        Err(StoreError::DeletionList(_))
    ));
    s.acknowledge_deletion_head(&zhead(all.get(1)), &core_pk())
        .await
        .unwrap();
    let tail = s.deletion_list_after(2, 100).await.unwrap();
    assert_eq!(tail.len(), 1);
    assert!(!tail[0].relayed);
    assert_eq!(
        s.deletion_list_after(0, 1).await.unwrap().len(),
        1,
        "limit honoured"
    );
    let flags: Vec<bool> = s
        .deletion_list_after(0, 100)
        .await
        .unwrap()
        .iter()
        .map(|e| e.relayed)
        .collect();
    assert_eq!(
        flags,
        vec![true, true, false],
        "acknowledgement is monotonic"
    );

    // Prune: only acknowledged entries older than 35 days, never the head.
    assert_eq!(
        s.prune_deletion_list(TODAY.plus(30).unwrap())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        s.prune_deletion_list(TODAY.plus(100).unwrap())
            .await
            .unwrap(),
        2
    );
    let left = s.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(left.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3]);
    // The relay acknowledges the head; it is still never pruned.
    s.acknowledge_deletion_head(&zhead(all.get(2)), &core_pk())
        .await
        .unwrap();
    assert_eq!(
        s.prune_deletion_list(TODAY.plus(200).unwrap())
            .await
            .unwrap(),
        0
    );
    // The chain continues from the kept head.
    let a9 = account(&s, 9).await;
    s.delete_account(a9, TODAY.plus(100).unwrap(), &sg)
        .await
        .unwrap();
    let tail = s.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(tail.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4]);
    verify_chain(&tail, &sg.verifying_key(), None).unwrap();
    let mut head_only = all[2];
    head_only.relayed = true;
    verify_chain(&tail[1..], &sg.verifying_key(), Some(&head_only)).unwrap();
}

/// BE-060, RVW-A-04, RL-06: rollback rejection; current + previous only.
pub async fn kd_snapshots<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    assert_eq!(s.kd_high_water().await.unwrap(), KdHighWater::default());
    assert_eq!(s.current_directory_snapshot().await.unwrap(), None);
    assert_eq!(
        s.install_directory_snapshot(snap(1, 100, 20700, 0), TODAY)
            .await
            .unwrap(),
        InstallOutcome::Installed
    );
    assert_eq!(
        s.install_directory_snapshot(snap(1, 100, 20700, 0), TODAY)
            .await
            .unwrap(),
        InstallOutcome::AlreadyInstalled
    );
    assert_eq!(
        s.install_directory_snapshot(snap(2, 150, 20710, 100), TODAY)
            .await
            .unwrap(),
        InstallOutcome::Installed
    );
    let hwm = s.kd_high_water().await.unwrap();
    assert_eq!(
        hwm,
        KdHighWater {
            tree_size: 150,
            checkpoint_day: Some(Day(20710)),
            directory_version: 2
        }
    );

    for (bad, why) in [
        (snap(3, 149, 20711, 150), "smaller tree"),
        (snap(3, 160, 20709, 150), "older checkpoint"),
        (snap(1, 160, 20711, 150), "older version"),
        (snap(3, 160, 20711, 100), "not proven from hwm"),
        (snap(2, 150, 20710, 150), "same version different body"),
    ] {
        let mut bad = bad;
        if why == "same version different body" {
            bad.body = vec![0xff; 64];
        }
        assert!(
            matches!(
                s.install_directory_snapshot(bad, TODAY).await,
                Err(StoreError::Rollback(_))
            ),
            "{why}"
        );
    }
    let mut oversize = snap(3, 160, 20711, 150);
    oversize.body = vec![0; MAX_SNAPSHOT_BODY + 1];
    assert!(matches!(
        s.install_directory_snapshot(oversize, TODAY).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(
        s.kd_high_water().await.unwrap(),
        hwm,
        "rejections never move the high-water mark"
    );

    s.install_directory_snapshot(snap(3, 160, 20711, 150), TODAY)
        .await
        .unwrap();
    let (v, body, sigs) = s.current_directory_snapshot().await.unwrap().unwrap();
    assert_eq!((v, body, sigs), (3, vec![3u8; 64], vec![0xee; 128]));
}

/// ADR-046(5): monthly counters, flushed only by the import-slot rewrite, all
/// or nothing (AUD-RM2-STO-01).
pub async fn counters<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let m = TODAY.month_start();
    let ch = ChannelId([3; 16]);
    let d = |month: Day, name: CounterName, delta: u32| CounterDelta {
        month,
        channel_id: ch,
        name,
        delta,
    };
    // An invalid delta rejects the whole flush.
    assert!(matches!(
        s.uniform_rewrite(
            slot(TODAY),
            &[
                d(m, CounterName::SubmissionsReceived, 1),
                d(TODAY, CounterName::SubmissionsReceived, 1)
            ],
            &[]
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(s.counters_for_month(m).await.unwrap().is_empty());
    s.uniform_rewrite(
        slot(TODAY),
        &[
            d(m, CounterName::SubmissionsReceived, 2),
            d(m, CounterName::SubmissionsReceived, 3),
            d(m, CounterName::AccountsCreated, 1),
        ],
        &[],
    )
    .await
    .unwrap();
    assert!(matches!(
        s.uniform_rewrite(
            slot(TODAY),
            &[d(m, CounterName::AccountsCreated, u32::MAX)],
            &[]
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.uniform_rewrite(
            slot(TODAY),
            &[
                d(m, CounterName::AccountsCreated, i32::MAX as u32),
                d(m, CounterName::AccountsCreated, 1)
            ],
            &[]
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));
    let prev = Day(20697); // 2026-09-01
    s.uniform_rewrite(
        slot(TODAY),
        &[d(prev, CounterName::AccountDeletions, 4)],
        &[],
    )
    .await
    .unwrap();
    let cells = s.counters_for_month(m).await.unwrap();
    assert_eq!(cells.len(), 2);
    assert!(cells.contains(&CounterCell {
        channel_id: ch,
        name: CounterName::SubmissionsReceived,
        value: 5
    }));
    assert!(cells.contains(&CounterCell {
        channel_id: ch,
        name: CounterName::AccountsCreated,
        value: 1
    }));
    assert_eq!(s.prune_counters_before(m).await.unwrap(), 1);
    assert!(s.counters_for_month(prev).await.unwrap().is_empty());
}

/// AUD-RM2-STO-01: `activity_month` changes only at the import-slot rewrite:
/// the slot month for accounts the web recorded active, and the month of stored
/// replies; never later than the slot.
pub async fn activity_fold<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let a = account(&s, 10).await;
    let b = account(&s, 11).await;
    let c = account(&s, 12).await;
    let next = TODAY.next_month_start();
    s.apply_replies(next, vec![reply(Some(c), 12, 64)])
        .await
        .unwrap();
    let month = |t: u8| {
        let s = &s;
        async move {
            s.lookup_account(&LookupTag([t; 32]))
                .await
                .unwrap()
                .unwrap()
                .activity_month
        }
    };
    assert_eq!(
        month(12).await,
        TODAY.month_start(),
        "reply arrival alone writes nothing"
    );
    // A slot in the current month does not see the future-dated reply.
    s.uniform_rewrite(slot(TODAY), &[], &[]).await.unwrap();
    assert_eq!(month(12).await, TODAY.month_start());
    s.uniform_rewrite(slot(next), &[], &[a, AccountId([0xee; 16])])
        .await
        .unwrap();
    assert_eq!(month(10).await, next);
    assert_eq!(month(11).await, TODAY.month_start());
    assert_eq!(month(12).await, next);
    let _ = b;
}

/// BE-074 / AUD-RM2-STO-09: while restore-pending every source operation is
/// refused; relay operations continue.
pub async fn restore_pending_gate<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(
    mk: F,
) {
    let s = fresh(&mk).await;
    let sg = signer();
    let a = account(&s, 13).await;
    s.apply_replies(TODAY, vec![reply(Some(a), 13, 64)])
        .await
        .unwrap();
    let r = s.mailbox_list(a).await.unwrap()[0].reply_ref;
    s.commit_envelope(envelope(0)).await.unwrap();
    s.mark_restore_pending().await.unwrap();
    s.mark_restore_pending().await.unwrap();
    assert!(!s.serving_allowed().await.unwrap());
    let rp = Err(StoreError::RestorePending);
    assert_eq!(
        s.lookup_account(&LookupTag([13; 32])).await,
        rp.map(|()| None)
    );
    assert_eq!(s.delete_account(a, TODAY, &sg).await, rp);
    assert_eq!(
        s.delete_replies(a, &[(r, [0; 32])], TODAY, &sg).await,
        rp.map(|()| 0)
    );
    assert_eq!(
        s.delete_mailbox(a, &MailboxId([13; 32]), &[r], TODAY, &sg)
            .await,
        rp.map(|()| 0)
    );
    assert_eq!(s.mailbox_list(a).await, rp.map(|()| Vec::new()));
    assert_eq!(
        s.commit_envelope(envelope(0)).await,
        rp.map(|()| EnvelopeRef([0; 16]))
    );
    assert_eq!(
        s.apply_replies(TODAY, vec![reply(None, 1, 40)]).await,
        rp.map(|()| ApplyRepliesResult::default())
    );
    assert_eq!(
        s.create_account(new_account(14), TODAY).await,
        rp.map(|()| a)
    );
    assert_eq!(s.update_account(a, new_account(15)).await, rp);
    // Relay-side operations still work (the envelope is still relayed).
    let b = s
        .claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 10,
                max_bytes: MAX_CLAIM_BYTES,
            },
        )
        .await
        .unwrap();
    assert_eq!(b.objects.len(), 1);
    assert!(s.deletion_list_after(0, 10).await.unwrap().is_empty());
    // An empty Z-CORE list (signed empty head) confirms the empty local list.
    assert_eq!(
        s.apply_pushed_deletion_list(
            &[],
            &zhead(None),
            &core_pk(),
            &sg.verifying_key(),
            &PrefixHasher,
            TODAY
        )
        .await
        .unwrap(),
        0
    );
    assert!(s.serving_allowed().await.unwrap());
    assert!(
        s.lookup_account(&LookupTag([13; 32]))
            .await
            .unwrap()
            .is_some()
    );
}

/// BS-INTAKE restore + RL-12 push-back (BE-074, API-054, KEY-077,
/// AUD-RM2-STO-04/15): the restored store refuses to serve until the newest
/// verified list is applied; forged, gapped, truncated and empty pushes are
/// rejected and keep (or set) restore-pending; the KD high-water mark keeps the
/// higher value.
pub async fn backup_restore<S: Store, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let sg = signer();
    let pk = sg.verifying_key();
    let a = fresh(&mk).await;
    for t in [20u8, 21, 22, 23, 24] {
        account(&a, t).await;
    }
    a.install_directory_snapshot(snap(4, 400, 20720, 0), TODAY)
        .await
        .unwrap();
    let id = |t: u8| {
        let a = &a;
        async move {
            a.lookup_account(&LookupTag([t; 32]))
                .await
                .unwrap()
                .unwrap()
                .account_id
        }
    };
    a.delete_account(id(20).await, TODAY, &sg).await.unwrap();
    // The relay copied entry 1 to Z-CORE and handed back Z-CORE's signed head.
    let first = a.deletion_list_after(0, 10).await.unwrap();
    let h1 = zhead(first.last());
    a.acknowledge_deletion_head(&h1, &core_pk()).await.unwrap();
    let backup = a.export_backup().await.unwrap();
    assert_eq!(backup.accounts.len(), 4);
    assert_eq!(backup.deletion_list.len(), 1);
    assert_eq!(backup.meta.kd.tree_size, 400);
    assert_eq!(
        backup.meta.deletion_head,
        Some(h1),
        "backup carries the verified head"
    );

    // After the backup, the source deletes accounts 21, 23, 24 (only Z-CORE has
    // those entries now).
    for t in [21u8, 23, 24] {
        a.delete_account(id(t).await, TODAY.plus(1).unwrap(), &sg)
            .await
            .unwrap();
    }
    let core_copy = a.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(core_copy.len(), 4);

    let b = mk(TENANT).await;
    b.restore_backup(backup.clone()).await.unwrap();
    assert!(!b.serving_allowed().await.unwrap());
    assert_eq!(
        b.commit_envelope(envelope(0)).await,
        Err(StoreError::RestorePending)
    );
    assert_eq!(
        b.apply_replies(TODAY, vec![reply(None, 1, 40)]).await,
        Err(StoreError::RestorePending)
    );
    assert_eq!(
        b.restore_backup(backup.clone()).await,
        Err(StoreError::Conflict("restore target not empty"))
    );

    // Rejected pushes; the store keeps refusing.
    let h4 = zhead(core_copy.last());
    let cpk = core_pk();
    let mut forged = core_copy.clone();
    forged[1].del_hash[0] ^= 1;
    let wrong_key = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[1; 32]))
        .verifying_key();
    let relay_key = candor_core::sig::SigningKey::from_seed(&[0xaa; 32]);
    // AUD-RM2-STO-22 PoC: Z-CORE holds 1..4; the relay pushes 1..3 and claims
    // its own head 3, either unsigned (copied sig of another head) or signed
    // with a key that is not Z-CORE's.
    let mut claimed = h4;
    claimed.seq = 3;
    claimed.head_hash = core_copy[2].next_prev_hash();
    let self_signed = SignedDeletionHead::sign(&TENANT, core_copy.get(2), TODAY, 4, &relay_key);
    for (entries, head, key, why) in [
        (forged.clone(), h4, pk, "forged"),
        (core_copy.clone(), h4, wrong_key, "wrong key"),
        (core_copy[2..].to_vec(), h4, pk, "gap after local head"),
        (core_copy[..3].to_vec(), h4, pk, "truncated"),
        (Vec::new(), h4, pk, "empty"),
        (
            core_copy[..3].to_vec(),
            claimed,
            pk,
            "relay-claimed head, no signature",
        ),
        (
            core_copy[..3].to_vec(),
            self_signed,
            pk,
            "relay-signed head",
        ),
        (
            core_copy.clone(),
            zhead(None),
            pk,
            "head behind the verified head",
        ),
    ] {
        assert!(
            matches!(
                b.apply_pushed_deletion_list(&entries, &head, &cpk, &key, &PrefixHasher, TODAY)
                    .await,
                Err(StoreError::DeletionList(_))
            ),
            "{why}"
        );
        assert!(!b.serving_allowed().await.unwrap(), "{why}");
    }
    assert_eq!(b.export_backup().await.unwrap().accounts.len(), 4);

    assert_eq!(
        b.apply_pushed_deletion_list(&core_copy, &h4, &cpk, &pk, &PrefixHasher, TODAY)
            .await
            .unwrap(),
        4
    );
    assert!(b.serving_allowed().await.unwrap());
    assert_eq!(
        b.export_backup().await.unwrap().meta.deletion_head,
        Some(h4),
        "the confirmed head becomes the verified head"
    );
    for t in [21u8, 23, 24] {
        assert!(
            b.lookup_account(&LookupTag([t; 32]))
                .await
                .unwrap()
                .is_none(),
            "deleted after backup -> absent"
        );
    }
    assert!(
        b.lookup_account(&LookupTag([22; 32]))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(b.kd_high_water().await.unwrap().tree_size, 400);
    // Rollback still rejected after restore.
    assert!(matches!(
        b.install_directory_snapshot(snap(5, 300, 20725, 300), TODAY)
            .await,
        Err(StoreError::Rollback(_))
    ));
    // Idempotent re-push.
    assert_eq!(
        b.apply_pushed_deletion_list(&core_copy, &h4, &cpk, &pk, &PrefixHasher, TODAY)
            .await
            .unwrap(),
        4
    );
    // A bad push to a serving store puts it back into restore-pending; so does
    // a replay of the older head now that head 4 is verified.
    assert!(
        b.apply_pushed_deletion_list(&core_copy[..2], &h4, &cpk, &pk, &PrefixHasher, TODAY)
            .await
            .is_err()
    );
    assert!(!b.serving_allowed().await.unwrap());
    assert!(
        b.apply_pushed_deletion_list(&core_copy[..1], &h1, &cpk, &pk, &PrefixHasher, TODAY)
            .await
            .is_err()
    );
    b.apply_pushed_deletion_list(&core_copy, &h4, &cpk, &pk, &PrefixHasher, TODAY)
        .await
        .unwrap();
    // Chain continues locally after the merged entries.
    let a22 = b
        .lookup_account(&LookupTag([22; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
    b.delete_account(a22, TODAY.plus(2).unwrap(), &sg)
        .await
        .unwrap();
    verify_chain(&b.deletion_list_after(0, 100).await.unwrap(), &pk, None).unwrap();

    // Listed replies already on a recovered node are deleted by the push.
    let c = fresh(&mk).await;
    let r = reply(None, 0x55, 200);
    c.apply_replies(TODAY, vec![r.clone()]).await.unwrap();
    let entry = deletion::make_entry(
        None,
        DeletionKind::Reply,
        deletion::reply_del_hash(&TENANT, &r.object_hash),
        TODAY,
        &sg,
    )
    .unwrap();
    assert_eq!(
        c.apply_pushed_deletion_list(
            &[entry],
            &zhead(Some(&entry)),
            &core_pk(),
            &pk,
            &PrefixHasher,
            TODAY
        )
        .await
        .unwrap(),
        1
    );
    c.rebuild_published_set(slot(TODAY)).await.unwrap();
    assert!(published(&c).await.iter().all(|e| *e != r.reply_ct));

    // AUD-RM2-STO-15: a backup with another salt is refused by an initialised
    // empty store.
    let d = fresh(&mk).await;
    let mut other_salt = backup.clone();
    other_salt.meta.kdf_salt = [0x77; 32];
    assert_eq!(
        d.restore_backup(other_salt).await,
        Err(StoreError::Conflict("kdf salt differs"))
    );
}

/// AUD-RM2-STO-24(b): Z-CORE heads carry a day and a monotonic attestation
/// counter. A node restored from an old backup refuses the replay of a genuine
/// but older head (stale day) that would hide later deletions; a node restored
/// from a newer backup refuses any head with a lower counter than the head
/// recorded in the backup, and a different head with the same counter; the
/// acknowledgement path refuses older heads too. Pre-fix, the restored node
/// accepted the older head, cleared restore-pending and kept serving the
/// account deleted after it.
pub async fn head_replay_after_restore<
    S: Store,
    F: Fn(TenantId) -> Fut,
    Fut: Future<Output = S>,
>(
    mk: F,
) {
    let sg = signer();
    let pk = sg.verifying_key();
    let cpk = core_pk();
    let a = fresh(&mk).await;
    for t in [30u8, 31, 32, 33] {
        account(&a, t).await;
    }
    let id = |t: u8| {
        let a = &a;
        async move {
            a.lookup_account(&LookupTag([t; 32]))
                .await
                .unwrap()
                .unwrap()
                .account_id
        }
    };
    let d = |n: u32| TODAY.plus(n).unwrap();
    a.delete_account(id(30).await, TODAY, &sg).await.unwrap();
    let l1 = a.deletion_list_after(0, 10).await.unwrap();
    let h1 = zhead_at(l1.last(), TODAY, 10);
    a.acknowledge_deletion_head(&h1, &cpk).await.unwrap();
    let backup_old = a.export_backup().await.unwrap();
    a.delete_account(id(31).await, d(1), &sg).await.unwrap();
    let l2 = a.deletion_list_after(0, 10).await.unwrap();
    let h2 = zhead_at(l2.last(), d(1), 11);
    a.acknowledge_deletion_head(&h2, &cpk).await.unwrap();
    let backup_new = a.export_backup().await.unwrap();
    assert_eq!(backup_new.meta.deletion_head, Some(h2));
    // The acknowledgement path refuses an older attestation.
    assert!(matches!(
        a.acknowledge_deletion_head(&h1, &cpk).await,
        Err(StoreError::DeletionList(_))
    ));
    a.delete_account(id(32).await, d(2), &sg).await.unwrap();
    let l3 = a.deletion_list_after(0, 10).await.unwrap();
    assert_eq!(l3.len(), 3);
    let h3 = zhead_at(l3.last(), d(2), 12);
    let today = d(3);
    let h3_fresh = zhead_at(l3.last(), today, 13);

    // (1) Old backup (verified head h1); the relay replays the genuine older
    // head h2 with the matching list 1..2 (it hides deletion 3).
    let b = mk(TENANT).await;
    b.restore_backup(backup_old).await.unwrap();
    assert_eq!(
        b.apply_pushed_deletion_list(&l2, &h2, &cpk, &pk, &PrefixHasher, today)
            .await,
        Err(StoreError::DeletionList("stale Z-CORE head"))
    );
    assert!(!b.serving_allowed().await.unwrap());
    assert_eq!(
        b.apply_pushed_deletion_list(&l3, &h3_fresh, &cpk, &pk, &PrefixHasher, today)
            .await
            .unwrap(),
        3
    );
    assert!(b.serving_allowed().await.unwrap());
    assert!(
        b.lookup_account(&LookupTag([32; 32]))
            .await
            .unwrap()
            .is_none()
    );

    // (2) Newer backup (verified head h2, counter 11): a fresh head with a
    // lower counter, or a different head with the same counter, is refused.
    let c = mk(TENANT).await;
    c.restore_backup(backup_new).await.unwrap();
    for (h, why) in [
        (zhead_at(l3.last(), today, 10), "lower counter"),
        (zhead_at(l3.last(), today, 11), "same counter, other head"),
        (zhead_at(l1.last(), today, 20), "newer counter, older seq"),
    ] {
        assert!(
            matches!(
                c.apply_pushed_deletion_list(&l3, &h, &cpk, &pk, &PrefixHasher, today)
                    .await,
                Err(StoreError::DeletionList(_))
            ),
            "{why}"
        );
        assert!(!c.serving_allowed().await.unwrap(), "{why}");
    }
    assert_eq!(
        c.apply_pushed_deletion_list(&l3, &h3_fresh, &cpk, &pk, &PrefixHasher, today)
            .await
            .unwrap(),
        3
    );
    // (3) The genuine h3 (counter 12, still fresh) is now older than the
    // verified head: refused, and the store goes back to restore-pending.
    assert!(
        c.apply_pushed_deletion_list(&l3, &h3, &cpk, &pk, &PrefixHasher, today)
            .await
            .is_err()
    );
    assert!(!c.serving_allowed().await.unwrap());
    assert_eq!(
        c.export_backup().await.unwrap().meta.deletion_head,
        Some(h3_fresh)
    );
}

#[macro_export]
macro_rules! conformance_tests {
    ($mk:expr) => {
        $crate::conformance_tests!(@ $mk;
            conf_init_and_meta => init_and_meta,
            conf_accounts => accounts,
            conf_envelope_validation => envelope_validation,
            conf_claim_ack => claim_ack,
            conf_claim_limits => claim_limits,
            conf_claim_fairness => claim_fairness,
            conf_dead_drop => dead_drop,
            conf_dead_drop_sizes => dead_drop_sizes,
            conf_reply_backlog => reply_backlog,
            conf_reply_rules => reply_rules,
            conf_deletion_list => deletion_list,
            conf_kd_snapshots => kd_snapshots,
            conf_counters => counters,
            conf_activity_fold => activity_fold,
            conf_restore_pending_gate => restore_pending_gate,
            conf_backup_restore => backup_restore,
            conf_head_replay_after_restore => head_replay_after_restore
        );
    };
    (@ $mk:expr; $($name:ident => $f:ident),*) => {
        $(
            #[tokio::test]
            async fn $name() {
                if let Some(mk) = $mk {
                    common::$f(mk).await
                }
            }
        )*
    };
}
