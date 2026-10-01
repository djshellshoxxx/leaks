// SPDX-License-Identifier: AGPL-3.0-or-later
//! `IntakeStore` conformance suite, run against both implementations
//! (tests/memory.rs, tests/pg.rs). Test IDs: 09 §5.1/§8, 07 BE-014/BE-056/BE-060/
//! BE-062/BE-063/BE-064/BE-074, 08 RL-02..RL-12, SA-19/SA-20, API-037/040/047/054,
//! KEY-077.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

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

pub fn signer() -> Ed25519DeletionSigner {
    Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[0x31; 32]))
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

pub fn envelope(account: AccountLink, offset: u8, parts: usize) -> CommitEnvelope {
    let mut header = vec![0xa0; 300];
    header[..8].copy_from_slice(&uniq().to_be_bytes());
    CommitEnvelope {
        account,
        channel_id: ChannelId([0xc1; 16]),
        header_ct: header,
        manifest_ct: vec![0xb0; 500],
        disposition_ct: vec![0xd0; DISPOSITION_CT_LEN_STD],
        epoch_index: 2963,
        received_date: TODAY,
        release_offset_days: offset,
        parts: (0..parts)
            .map(|i| PartRef {
                blob_id: blob(),
                padded_size: 262_144 * (i as u64 + 1),
            })
            .collect(),
    }
}

pub fn new_account(tag: u8) -> NewAccount {
    NewAccount {
        lookup_tag: LookupTag([tag; 32]),
        auth_pk: [tag; 32],
        xwing_pk: vec![tag; XWING_PK_LEN],
        prefs_ct: vec![tag; 200],
    }
}

pub fn reply(account: Option<AccountId>, mailbox: u8, len: usize) -> IncomingReply {
    let mut ct = vec![mailbox; len];
    ct[..8].copy_from_slice(&uniq().to_be_bytes());
    let oh: [u8; 32] = ct[..32].try_into().unwrap();
    IncomingReply {
        account,
        mailbox_id: Some(MailboxId([mailbox; 32])),
        object_hash: oh,
        reply_ct: ct,
        size_bucket: 1,
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
    S: IntakeStore,
    F: Fn(TenantId) -> Fut,
    Fut: Future<Output = S>,
{
    let s = mk(TENANT).await;
    s.init(TENANT, SALT).await.unwrap();
    s
}

pub async fn init_and_meta<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = mk(TENANT).await;
    assert_eq!(s.tenant().await, Err(StoreError::NotInitialized));
    assert_eq!(s.pending_count().await, Err(StoreError::NotInitialized));
    assert_eq!(
        s.commit_envelope(envelope(AccountLink::None, 0, 0)).await,
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

/// ADR-034 / BE-056: account only with its first envelope; atomic on failure.
pub async fn accounts<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    assert_eq!(s.lookup_account(&LookupTag([1; 32])).await.unwrap(), None);
    s.commit_envelope(envelope(AccountLink::New(new_account(1)), 0, 1))
        .await
        .unwrap();
    let a = s
        .lookup_account(&LookupTag([1; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.auth_pk, [1; 32]);
    assert_eq!(a.xwing_pk.len(), XWING_PK_LEN);
    assert_eq!(a.activity_month, TODAY.month_start());
    assert_eq!(a.quota_bucket, 0);
    // Same tag again: rejected and the envelope is not stored either.
    let before = s.pending_count().await.unwrap();
    assert_eq!(
        s.commit_envelope(envelope(AccountLink::New(new_account(1)), 0, 0))
            .await,
        Err(StoreError::AccountExists)
    );
    assert_eq!(s.pending_count().await.unwrap(), before);
    // Follow-up by the existing account.
    s.commit_envelope(envelope(AccountLink::Existing(a.account_id), 0, 0))
        .await
        .unwrap();
    assert_eq!(
        s.commit_envelope(envelope(AccountLink::Existing(AccountId([9; 16])), 0, 0))
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(s.pending_count().await.unwrap(), 2);
    // Invalid new account fields.
    let mut bad = new_account(2);
    bad.xwing_pk.pop();
    assert!(matches!(
        s.commit_envelope(envelope(AccountLink::New(bad), 0, 0))
            .await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut bad = new_account(2);
    bad.prefs_ct = vec![0; 4097];
    assert!(matches!(
        s.commit_envelope(envelope(AccountLink::New(bad), 0, 0))
            .await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(s.lookup_account(&LookupTag([2; 32])).await.unwrap(), None);
}

/// Hostile/oversize envelope inputs are rejected without side effects.
pub async fn envelope_validation<
    S: IntakeStore,
    F: Fn(TenantId) -> Fut,
    Fut: Future<Output = S>,
>(
    mk: F,
) {
    let s = fresh(&mk).await;
    let mut e = envelope(AccountLink::None, 0, 0);
    e.header_ct = vec![1; MAX_HEADER_CT + 1];
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut e = envelope(AccountLink::None, 0, 0);
    e.header_ct.clear();
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut e = envelope(AccountLink::None, 0, 0);
    e.manifest_ct = vec![1; MAX_MANIFEST_CT + 1];
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut e = envelope(AccountLink::None, 0, 0);
    e.disposition_ct.push(0);
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.commit_envelope(envelope(AccountLink::None, 22, 0)).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.commit_envelope(envelope(AccountLink::None, 0, 33)).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut e = envelope(AccountLink::None, 0, 2);
    e.parts[1].blob_id = e.parts[0].blob_id;
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut e = envelope(AccountLink::None, 0, 1);
    e.parts[0].padded_size = 0;
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    let mut e = envelope(AccountLink::None, 0, 0);
    e.epoch_index = u32::MAX;
    assert!(matches!(
        s.commit_envelope(e).await,
        Err(StoreError::InvalidInput(_))
    ));
    let e = envelope(AccountLink::None, 0, 1);
    s.commit_envelope(e.clone()).await.unwrap();
    // Replay of the same header bytes (e.g. a captured Tier V envelope).
    let mut dup = e.clone();
    dup.parts = vec![PartRef {
        blob_id: blob(),
        padded_size: 262_144,
    }];
    assert_eq!(
        s.commit_envelope(dup).await,
        Err(StoreError::DuplicateEnvelope)
    );
    // Reused blob id in another envelope.
    let mut reuse = envelope(AccountLink::None, 0, 0);
    reuse.parts = e.parts.clone();
    assert!(matches!(
        s.commit_envelope(reuse).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(s.pending_count().await.unwrap(), 1);
}

/// RL-02..RL-04, BE-014, BE-062, API-047.
pub async fn claim_ack<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let lim = ClaimLimits {
        max_objects: 500,
        max_bytes: MAX_CLAIM_BYTES,
    };
    assert!(s.claim_batch(TODAY, lim).await.unwrap().objects.is_empty());
    let e1 = envelope(AccountLink::None, 0, 2);
    let e2 = envelope(AccountLink::New(new_account(3)), 0, 0);
    let held = envelope(AccountLink::None, 2, 1);
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
    let d1: [u8; 32] = sha(&e1.header_ct);
    let o1 = b.objects.iter().find(|o| o.sha256 == d1).unwrap();
    assert_eq!(o1.channel_id, e1.channel_id);
    assert_eq!(o1.epoch_index, 2963);
    assert_eq!(o1.header_len, 300);
    assert_eq!(o1.manifest_len, 500);
    assert_eq!(o1.parts, vec![262_144, 524_288]);
    assert_eq!(o1.disposition_ct.len(), DISPOSITION_CT_LEN_STD);

    // Unacked batch is returned again (RL-02 conflict semantics).
    let again = s.claim_batch(TODAY, lim).await.unwrap();
    assert!(again.replayed);
    assert_eq!(again.batch_no, b.batch_no);
    assert_eq!(again.objects, b.objects);

    // RL-03.
    assert_eq!(
        s.batch_object(b.batch_no, o1.envelope_ref, PartSelector::Header)
            .await
            .unwrap(),
        ObjectData::Bytes(e1.header_ct.clone())
    );
    assert_eq!(
        s.batch_object(b.batch_no, o1.envelope_ref, PartSelector::Manifest)
            .await
            .unwrap(),
        ObjectData::Bytes(e1.manifest_ct.clone())
    );
    assert_eq!(
        s.batch_object(b.batch_no, o1.envelope_ref, PartSelector::Part(1))
            .await
            .unwrap(),
        ObjectData::Blob(e1.parts[1])
    );
    assert_eq!(
        s.batch_object(b.batch_no, o1.envelope_ref, PartSelector::Part(2))
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        s.batch_object(b.batch_no + 1, o1.envelope_ref, PartSelector::Header)
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        s.batch_object(b.batch_no, EnvelopeRef([0; 16]), PartSelector::Header)
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
        vec![e1.parts[0].blob_id, e1.parts[1].blob_id]
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
    assert_eq!(b2.objects[0].sha256, sha(&e2.header_ct));
    s.ack_batch(b2.batch_no, &[b2.objects[0].sha256])
        .await
        .unwrap();
    let b3 = s.claim_batch(TODAY.plus(2).unwrap(), lim).await.unwrap();
    assert_eq!(b3.objects.len(), 1);
    assert_eq!(b3.objects[0].sha256, sha(&held.header_ct));
    s.ack_batch(b3.batch_no, &[b3.objects[0].sha256])
        .await
        .unwrap();
    assert_eq!(s.pending_count().await.unwrap(), 0);
}

/// RL-02 limits.
pub async fn claim_limits<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    for _ in 0..3 {
        s.commit_envelope(envelope(AccountLink::None, 0, 1))
            .await
            .unwrap();
    }
    assert!(matches!(
        s.claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 0,
                max_bytes: 1
            }
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 501,
                max_bytes: 1
            }
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        s.claim_batch(
            TODAY,
            ClaimLimits {
                max_objects: 1,
                max_bytes: MAX_CLAIM_BYTES + 1
            }
        )
        .await,
        Err(StoreError::InvalidInput(_))
    ));
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
    // max_bytes smaller than one object: exactly one object (never starves).
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

fn sha(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// SA-19/SA-20, BE-063, API-037, API-040: fixed page shape, byte-identical pages,
/// set_version changes only at rebuild, 30-day window.
pub async fn dead_drop<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let idx = s.reply_index().await.unwrap();
    assert_eq!(
        (idx.page_count, idx.page_size, idx.window_days),
        (1, 64, 30)
    );
    s.commit_envelope(envelope(AccountLink::New(new_account(4)), 0, 0))
        .await
        .unwrap();
    let acct = s
        .lookup_account(&LookupTag([4; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;

    let old_day = TODAY.saturating_minus(30);
    let old = vec![reply(None, 0x40, 1000)];
    assert_eq!(
        s.apply_replies(old_day, old.clone())
            .await
            .unwrap()
            .accepted,
        1
    );
    let mut batch: Vec<IncomingReply> = (0..70).map(|_| reply(None, 0x41, 4100)).collect();
    batch.push(reply(Some(acct), 0x42, MAX_REPLY_CT));
    batch.push(reply(Some(acct), 0x42, 500));
    let res = s.apply_replies(TODAY, batch.clone()).await.unwrap();
    assert_eq!(
        res,
        ApplyRepliesResult {
            accepted: 72,
            rejected: vec![]
        }
    );

    let mb = s.mailbox_list(acct).await.unwrap();
    assert_eq!(mb.iter().map(|r| r.slot).collect::<Vec<_>>(), vec![0, 1]);
    assert!(mb.iter().all(|r| r.available_day == TODAY));
    // Activity month refreshed by reply arrival (coarse, month only).
    assert_eq!(
        s.lookup_account(&LookupTag([4; 32]))
            .await
            .unwrap()
            .unwrap()
            .activity_month,
        TODAY.month_start()
    );

    let idx = s.rebuild_published_set(TODAY).await.unwrap();
    assert_eq!(
        idx.page_count, 2,
        "72 replies in window -> 2 pages (power of two)"
    );
    assert_eq!(
        s.reply_index().await.unwrap(),
        idx,
        "set_version stable between rebuilds"
    );
    let mut seen = Vec::new();
    for p in 0..idx.page_count {
        let a = s.reply_page(p).await.unwrap();
        let b = s.reply_page(p).await.unwrap();
        assert_eq!(a.len(), REPLY_PAGE_LEN);
        assert_eq!(a, b, "byte-identical for every requester");
        for e in parse_page(&a).unwrap() {
            seen.push(e.to_vec());
        }
    }
    assert_eq!(seen.len(), 128);
    for r in &batch {
        assert_eq!(seen.iter().filter(|e| **e == r.reply_ct).count(), 1);
    }
    assert!(
        !seen.contains(&old[0].reply_ct),
        "older than 30 days is not published"
    );
    assert_eq!(
        s.reply_page(idx.page_count).await,
        Err(StoreError::NotFound)
    );
    let idx2 = s.rebuild_published_set(TODAY).await.unwrap();
    assert_ne!(idx2.set_version, idx.set_version);

    // reply_expiry (≤ 30 days, ADR-039).
    assert_eq!(s.expire_replies(TODAY, 365).await.unwrap(), 1);
    assert_eq!(
        s.purge_replies_before(TODAY.plus(1).unwrap())
            .await
            .unwrap(),
        72
    );
    assert!(s.mailbox_list(acct).await.unwrap().is_empty());
}

/// RL-05 rejections and ADR-047(9) drops.
pub async fn reply_rules<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let sg = signer();
    s.commit_envelope(envelope(AccountLink::New(new_account(5)), 0, 0))
        .await
        .unwrap();
    let acct = s
        .lookup_account(&LookupTag([5; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;

    let mut empty = reply(None, 1, 40);
    empty.reply_ct.clear();
    let oversize = reply(None, 1, MAX_REPLY_CT + 1);
    let mut bucket = reply(None, 1, 40);
    bucket.size_bucket = 0;
    let mut no_mailbox = reply(Some(acct), 1, 40);
    no_mailbox.mailbox_id = None;
    let unknown_account = reply(Some(AccountId([0x77; 16])), 1, 40);
    let res = s
        .apply_replies(
            TODAY,
            vec![empty, oversize, bucket, no_mailbox, unknown_account],
        )
        .await
        .unwrap();
    assert_eq!(
        res,
        ApplyRepliesResult {
            accepted: 1,
            rejected: vec![0, 1, 2, 3]
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
    s.rebuild_published_set(TODAY).await.unwrap();
    let page = s.reply_page(0).await.unwrap();
    let entries = parse_page(&page).unwrap();
    // Only the earlier Tier V reply to an unknown account was dropped; nothing listed is published.
    assert!(entries.iter().all(|e| e.get(..32) != Some(&r0_hash[..])));

    // Another account cannot delete this account's replies.
    s.commit_envelope(envelope(AccountLink::New(new_account(6)), 0, 0))
        .await
        .unwrap();
    let other = s
        .lookup_account(&LookupTag([6; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
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

/// ADR-047(9), KEY-077, RL-11, BE-074: signed chain, relayed marking, prune.
pub async fn deletion_list<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let sg = signer();
    s.commit_envelope(envelope(AccountLink::New(new_account(7)), 0, 0))
        .await
        .unwrap();
    let acct = s
        .lookup_account(&LookupTag([7; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
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
    assert_eq!(
        s.pending_count().await.unwrap(),
        1,
        "pending envelope is still relayed, unlinked"
    );
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

    // More entries, then the relay acknowledges through seq 2.
    s.commit_envelope(envelope(AccountLink::New(new_account(8)), 0, 0))
        .await
        .unwrap();
    let a8 = s
        .lookup_account(&LookupTag([8; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
    s.delete_mailbox(a8, &MailboxId([8; 32]), &[], TODAY, &sg)
        .await
        .unwrap();
    s.delete_account(a8, TODAY.plus(1).unwrap(), &sg)
        .await
        .unwrap();
    let all = s.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(all.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    verify_chain(&all, &sg.verifying_key(), None).unwrap();
    assert_eq!(s.deletion_list_after(2, 100).await.unwrap().len(), 1);
    assert_eq!(
        s.deletion_list_after(0, 1).await.unwrap().len(),
        1,
        "limit honoured"
    );

    // Prune: only relayed entries older than 35 days, never the head.
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
    // The chain continues from the kept head.
    s.commit_envelope(envelope(AccountLink::New(new_account(9)), 0, 0))
        .await
        .unwrap();
    let a9 = s
        .lookup_account(&LookupTag([9; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
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
pub async fn kd_snapshots<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
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

/// BE-064: per-account daily quota, reset, no history.
pub async fn quota<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    s.commit_envelope(envelope(AccountLink::New(new_account(10)), 0, 0))
        .await
        .unwrap();
    let a = s
        .lookup_account(&LookupTag([10; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
    assert_eq!(s.quota_consume(a, 3, 5).await.unwrap(), 3);
    assert_eq!(s.quota_consume(a, 2, 5).await.unwrap(), 5);
    assert_eq!(
        s.quota_consume(a, 1, 5).await,
        Err(StoreError::QuotaExceeded)
    );
    assert_eq!(
        s.quota_consume(a, u16::MAX, u16::MAX).await,
        Err(StoreError::QuotaExceeded)
    );
    assert_eq!(
        s.quota_consume(AccountId([1; 16]), 1, 5).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(s.quota_reset().await.unwrap(), 1);
    assert_eq!(
        s.lookup_account(&LookupTag([10; 32]))
            .await
            .unwrap()
            .unwrap()
            .quota_bucket,
        0
    );
    assert_eq!(s.quota_reset().await.unwrap(), 0);
    assert_eq!(s.quota_consume(a, 5, 5).await.unwrap(), 5);
}

/// ADR-046(5): monthly counters only.
pub async fn counters<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(mk: F) {
    let s = fresh(&mk).await;
    let m = TODAY.month_start();
    let ch = ChannelId([3; 16]);
    assert!(matches!(
        s.counter_add(TODAY, ch, CounterName::SubmissionsReceived, 1)
            .await,
        Err(StoreError::InvalidInput(_))
    ));
    s.counter_add(m, ch, CounterName::SubmissionsReceived, 2)
        .await
        .unwrap();
    s.counter_add(m, ch, CounterName::SubmissionsReceived, 3)
        .await
        .unwrap();
    s.counter_add(m, ch, CounterName::AccountsCreated, 1)
        .await
        .unwrap();
    assert!(matches!(
        s.counter_add(m, ch, CounterName::AccountsCreated, u32::MAX)
            .await,
        Err(StoreError::InvalidInput(_))
    ));
    let prev = Day(20697); // 2026-09-01
    s.counter_add(prev, ch, CounterName::AccountDeletions, 4)
        .await
        .unwrap();
    let cells = s.counters_for_month(m).await.unwrap();
    assert_eq!(cells.len(), 2);
    assert!(cells.contains(&CounterCell {
        channel_id: ch,
        name: CounterName::SubmissionsReceived,
        value: 5
    }));
    assert_eq!(s.prune_counters_before(m).await.unwrap(), 1);
    assert!(s.counters_for_month(prev).await.unwrap().is_empty());
}

/// BS-INTAKE restore + RL-12 push-back (BE-074, API-054, KEY-077): the restored
/// store refuses to serve until the newest verified list is applied; a forged list
/// is rejected; the KD high-water mark keeps the higher value.
pub async fn backup_restore<S: IntakeStore, F: Fn(TenantId) -> Fut, Fut: Future<Output = S>>(
    mk: F,
) {
    let sg = signer();
    let pk = sg.verifying_key();
    let a = fresh(&mk).await;
    for t in [20u8, 21, 22] {
        a.commit_envelope(envelope(AccountLink::New(new_account(t)), 0, 0))
            .await
            .unwrap();
    }
    a.install_directory_snapshot(snap(4, 400, 20720, 0), TODAY)
        .await
        .unwrap();
    let a20 = a
        .lookup_account(&LookupTag([20; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
    a.delete_account(a20, TODAY, &sg).await.unwrap();
    let backup = a.export_backup().await.unwrap();
    assert_eq!(backup.accounts.len(), 2);
    assert_eq!(backup.deletion_list.len(), 1);
    assert_eq!(backup.meta.kd.tree_size, 400);

    // After the backup, the source deletes account 21 (only Z-CORE has that entry now).
    let a21 = a
        .lookup_account(&LookupTag([21; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
    a.delete_account(a21, TODAY.plus(1).unwrap(), &sg)
        .await
        .unwrap();
    let core_copy = a.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(core_copy.len(), 2);

    let b = mk(TENANT).await;
    b.restore_backup(backup.clone()).await.unwrap();
    assert!(!b.serving_allowed().await.unwrap());
    assert_eq!(
        b.commit_envelope(envelope(AccountLink::None, 0, 0)).await,
        Err(StoreError::RestorePending)
    );
    assert_eq!(
        b.apply_replies(TODAY, vec![reply(None, 1, 40)]).await,
        Err(StoreError::RestorePending)
    );
    assert!(
        b.lookup_account(&LookupTag([21; 32]))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        b.restore_backup(backup.clone()).await,
        Err(StoreError::Conflict("restore target not empty"))
    );

    // Forged and forked pushes are rejected; still not serving.
    let mut forged = core_copy.clone();
    forged[1].del_hash[0] ^= 1;
    assert!(matches!(
        b.apply_pushed_deletion_list(&forged, &pk, &PrefixHasher)
            .await,
        Err(StoreError::DeletionList(_))
    ));
    let wrong_key = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[1; 32]))
        .verifying_key();
    assert!(matches!(
        b.apply_pushed_deletion_list(&core_copy, &wrong_key, &PrefixHasher)
            .await,
        Err(StoreError::DeletionList(_))
    ));
    assert!(!b.serving_allowed().await.unwrap());
    assert!(
        b.lookup_account(&LookupTag([21; 32]))
            .await
            .unwrap()
            .is_some()
    );

    assert_eq!(
        b.apply_pushed_deletion_list(&core_copy, &pk, &PrefixHasher)
            .await
            .unwrap(),
        2
    );
    assert!(b.serving_allowed().await.unwrap());
    assert!(
        b.lookup_account(&LookupTag([21; 32]))
            .await
            .unwrap()
            .is_none(),
        "deleted after backup -> absent"
    );
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
        b.apply_pushed_deletion_list(&core_copy, &pk, &PrefixHasher)
            .await
            .unwrap(),
        2
    );
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
        c.apply_pushed_deletion_list(&[entry], &pk, &PrefixHasher)
            .await
            .unwrap(),
        1
    );
    c.rebuild_published_set(TODAY).await.unwrap();
    let page = c.reply_page(0).await.unwrap();
    assert!(
        parse_page(&page)
            .unwrap()
            .iter()
            .all(|e| *e != r.reply_ct.as_slice())
    );
}

#[macro_export]
macro_rules! conformance_tests {
    ($mk:expr) => {
        #[tokio::test]
        async fn conf_init_and_meta() {
            if let Some(mk) = $mk {
                common::init_and_meta(mk).await
            }
        }
        #[tokio::test]
        async fn conf_accounts() {
            if let Some(mk) = $mk {
                common::accounts(mk).await
            }
        }
        #[tokio::test]
        async fn conf_envelope_validation() {
            if let Some(mk) = $mk {
                common::envelope_validation(mk).await
            }
        }
        #[tokio::test]
        async fn conf_claim_ack() {
            if let Some(mk) = $mk {
                common::claim_ack(mk).await
            }
        }
        #[tokio::test]
        async fn conf_claim_limits() {
            if let Some(mk) = $mk {
                common::claim_limits(mk).await
            }
        }
        #[tokio::test]
        async fn conf_dead_drop() {
            if let Some(mk) = $mk {
                common::dead_drop(mk).await
            }
        }
        #[tokio::test]
        async fn conf_reply_rules() {
            if let Some(mk) = $mk {
                common::reply_rules(mk).await
            }
        }
        #[tokio::test]
        async fn conf_deletion_list() {
            if let Some(mk) = $mk {
                common::deletion_list(mk).await
            }
        }
        #[tokio::test]
        async fn conf_kd_snapshots() {
            if let Some(mk) = $mk {
                common::kd_snapshots(mk).await
            }
        }
        #[tokio::test]
        async fn conf_quota() {
            if let Some(mk) = $mk {
                common::quota(mk).await
            }
        }
        #[tokio::test]
        async fn conf_counters() {
            if let Some(mk) = $mk {
                common::counters(mk).await
            }
        }
        #[tokio::test]
        async fn conf_backup_restore() {
            if let Some(mk) = $mk {
                common::backup_restore(mk).await
            }
        }
    };
}
