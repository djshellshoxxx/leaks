// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory `IntakeStore` for tests of other crates. Same rules as the
//! PostgreSQL store (shared `validate` module; same conformance suite). Not for
//! production: nothing is durable.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::deaddrop::{self, DummyReplies, PublishedSet, RandomDummyReplies};
use crate::deletion::{
    DeletionEntry, DeletionKind, DeletionSigner, ReplyObjectHasher, account_del_hash,
    mailbox_del_hash, make_entry, reply_del_hash,
};
use crate::error::{Result, StoreError};
use crate::store::IntakeStore;
use crate::types::{
    AccountId, AccountLink, AckResult, ApplyRepliesResult, BackupSnapshot, BlobId, ChannelId,
    ClaimLimits, ClaimedBatch, ClaimedObject, CommitEnvelope, CounterCell, CounterName,
    DELETION_LIST_RETENTION_DAYS, Day, EnvelopeRef, IncomingReply, InstallOutcome, KdHighWater,
    LookupTag, MAILBOX_SLOTS, MAX_DELETION_LIST_PAGE, MAX_REPLIES_PER_PUSH, MailboxId,
    MetaSnapshot, ObjectData, PartRef, PartSelector, REPLY_WINDOW_DAYS, ReplyIndex, ReplyRef,
    SourceAccount, StoredReply, TenantId, VerifiedSnapshot, random_id16,
};
use crate::validate::{self, SnapshotDecision, has_duplicates};

#[derive(Clone)]
struct Meta {
    tenant: TenantId,
    kdf_salt: [u8; 32],
    relay_req_counter: u64,
    last_batch_no: u64,
    kd: KdHighWater,
    restore_pending: bool,
}

#[derive(Clone)]
struct EnvRow {
    channel_id: ChannelId,
    account: Option<AccountId>,
    header_ct: Vec<u8>,
    manifest_ct: Vec<u8>,
    header_sha256: [u8; 32],
    disposition_ct: Vec<u8>,
    epoch_index: u32,
    release_day: Day,
    batch_no: Option<u64>,
    parts: Vec<PartRef>,
}

#[derive(Clone)]
struct ReplyRow {
    account: Option<AccountId>,
    reply_ct: Vec<u8>,
    size_bucket: u8,
    available_day: Day,
    slot: Option<u8>,
}

#[derive(Default)]
struct State {
    meta: Option<Meta>,
    accounts: HashMap<AccountId, SourceAccount>,
    envelopes: BTreeMap<EnvelopeRef, EnvRow>,
    replies: BTreeMap<ReplyRef, ReplyRow>,
    deletion: BTreeMap<u64, DeletionEntry>,
    snapshots: BTreeMap<u64, (Vec<u8>, Vec<u8>, Day)>,
    counters: BTreeMap<(Day, ChannelId, CounterName), u32>,
}

impl State {
    fn meta(&self) -> Result<&Meta> {
        self.meta.as_ref().ok_or(StoreError::NotInitialized)
    }
    fn meta_mut(&mut self) -> Result<&mut Meta> {
        self.meta.as_mut().ok_or(StoreError::NotInitialized)
    }
    fn head(&self) -> Option<&DeletionEntry> {
        self.deletion.values().next_back()
    }
    fn append(
        &mut self,
        kind: DeletionKind,
        h: [u8; 32],
        day: Day,
        s: &dyn DeletionSigner,
    ) -> Result<()> {
        let e = make_entry(self.head(), kind, h, day, s)?;
        self.deletion.insert(e.seq, e);
        Ok(())
    }
    fn listed(&self, kind: DeletionKind, h: &[u8; 32]) -> bool {
        self.deletion
            .values()
            .any(|e| e.kind == kind && &e.del_hash == h)
    }
}

/// In-memory store.
pub struct MemoryStore {
    state: Mutex<State>,
    published: RwLock<Arc<PublishedSet>>,
    dummies: Box<dyn DummyReplies>,
}

impl core::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MemoryStore")
    }
}

impl MemoryStore {
    /// New empty store with random-byte dummy replies.
    pub fn new() -> Result<Self> {
        Self::with_dummies(Box::new(RandomDummyReplies))
    }

    /// New empty store with a caller-supplied dummy reply source.
    pub fn with_dummies(dummies: Box<dyn DummyReplies>) -> Result<Self> {
        let empty = deaddrop::empty(dummies.as_ref())?;
        Ok(Self {
            state: Mutex::new(State::default()),
            published: RwLock::new(Arc::new(empty)),
            dummies,
        })
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

fn delete_replies_where(st: &mut State, pred: impl Fn(&ReplyRow) -> bool) -> u64 {
    let before = st.replies.len();
    st.replies.retain(|_, r| !pred(r));
    u64::try_from(before.saturating_sub(st.replies.len())).unwrap_or(u64::MAX)
}

impl IntakeStore for MemoryStore {
    async fn init(&self, tenant: TenantId, kdf_salt: [u8; 32]) -> Result<()> {
        let mut st = self.state.lock().await;
        match &st.meta {
            Some(m) if m.tenant == tenant => Ok(()),
            Some(_) => Err(StoreError::TenantMismatch),
            None => {
                st.meta = Some(Meta {
                    tenant,
                    kdf_salt,
                    relay_req_counter: 0,
                    last_batch_no: 0,
                    kd: KdHighWater::default(),
                    restore_pending: false,
                });
                Ok(())
            }
        }
    }

    async fn tenant(&self) -> Result<TenantId> {
        Ok(self.state.lock().await.meta()?.tenant)
    }

    async fn accept_relay_counter(&self, counter: u64) -> Result<()> {
        i64::try_from(counter).map_err(|_| StoreError::InvalidInput("counter"))?;
        let mut st = self.state.lock().await;
        let m = st.meta_mut()?;
        if counter <= m.relay_req_counter {
            return Err(StoreError::Replay);
        }
        m.relay_req_counter = counter;
        Ok(())
    }

    async fn serving_allowed(&self) -> Result<bool> {
        Ok(!self.state.lock().await.meta()?.restore_pending)
    }

    async fn lookup_account(&self, tag: &LookupTag) -> Result<Option<SourceAccount>> {
        let st = self.state.lock().await;
        st.meta()?;
        Ok(st.accounts.values().find(|a| a.lookup_tag == *tag).cloned())
    }

    async fn delete_account(
        &self,
        account: AccountId,
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> Result<()> {
        validate::day_i32(today)?;
        let mut st = self.state.lock().await;
        let tenant = st.meta()?.tenant;
        let tag = st
            .accounts
            .get(&account)
            .ok_or(StoreError::NotFound)?
            .lookup_tag;
        st.append(
            DeletionKind::Account,
            account_del_hash(&tenant, &tag),
            today,
            signer,
        )?;
        st.accounts.remove(&account);
        delete_replies_where(&mut st, |r| r.account == Some(account));
        for e in st.envelopes.values_mut() {
            if e.account == Some(account) {
                e.account = None;
            }
        }
        Ok(())
    }

    async fn quota_consume(&self, account: AccountId, amount: u16, limit: u16) -> Result<u16> {
        let limit = limit.min(i16::MAX as u16);
        let mut st = self.state.lock().await;
        st.meta()?;
        let a = st.accounts.get_mut(&account).ok_or(StoreError::NotFound)?;
        let next = a
            .quota_bucket
            .checked_add(amount)
            .filter(|n| *n <= limit)
            .ok_or(StoreError::QuotaExceeded)?;
        a.quota_bucket = next;
        Ok(next)
    }

    async fn quota_reset(&self) -> Result<u64> {
        let mut st = self.state.lock().await;
        st.meta()?;
        let mut n = 0u64;
        for a in st.accounts.values_mut() {
            if a.quota_bucket != 0 {
                a.quota_bucket = 0;
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    async fn commit_envelope(&self, env: CommitEnvelope) -> Result<EnvelopeRef> {
        validate::commit(&env)?;
        let mut st = self.state.lock().await;
        if st.meta()?.restore_pending {
            return Err(StoreError::RestorePending);
        }
        let digest = sha256(&env.header_ct);
        if st.envelopes.values().any(|e| e.header_sha256 == digest) {
            return Err(StoreError::DuplicateEnvelope);
        }
        let blob_taken = |b: &BlobId| {
            st.envelopes
                .values()
                .any(|e| e.parts.iter().any(|p| p.blob_id == *b))
        };
        if env.parts.iter().any(|p| blob_taken(&p.blob_id)) {
            return Err(StoreError::InvalidInput("duplicate blob id"));
        }
        let month = env.received_date.month_start();
        let account = match env.account {
            AccountLink::None => None,
            AccountLink::Existing(id) => {
                let a = st.accounts.get_mut(&id).ok_or(StoreError::NotFound)?;
                a.activity_month = a.activity_month.max(month);
                Some(id)
            }
            AccountLink::New(n) => {
                if st.accounts.values().any(|a| a.lookup_tag == n.lookup_tag) {
                    return Err(StoreError::AccountExists);
                }
                let id = AccountId(random_id16()?);
                st.accounts.insert(
                    id,
                    SourceAccount {
                        account_id: id,
                        lookup_tag: n.lookup_tag,
                        auth_pk: n.auth_pk,
                        xwing_pk: n.xwing_pk,
                        prefs_ct: n.prefs_ct,
                        activity_month: month,
                        quota_bucket: 0,
                    },
                );
                Some(id)
            }
        };
        let r = EnvelopeRef(random_id16()?);
        st.envelopes.insert(
            r,
            EnvRow {
                channel_id: env.channel_id,
                account,
                header_ct: env.header_ct,
                manifest_ct: env.manifest_ct,
                header_sha256: digest,
                disposition_ct: env.disposition_ct,
                epoch_index: env.epoch_index,
                release_day: env.received_date.plus(u32::from(env.release_offset_days))?,
                batch_no: None,
                parts: env.parts,
            },
        );
        Ok(r)
    }

    async fn pending_count(&self) -> Result<u64> {
        let st = self.state.lock().await;
        st.meta()?;
        Ok(u64::try_from(st.envelopes.len()).unwrap_or(u64::MAX))
    }

    async fn claim_batch(&self, today: Day, limits: ClaimLimits) -> Result<ClaimedBatch> {
        validate::claim_limits(limits)?;
        let mut st = self.state.lock().await;
        st.meta()?;
        let describe = |r: &EnvelopeRef, e: &EnvRow| ClaimedObject {
            envelope_ref: *r,
            channel_id: e.channel_id,
            epoch_index: e.epoch_index,
            header_len: u32::try_from(e.header_ct.len()).unwrap_or(u32::MAX),
            manifest_len: u32::try_from(e.manifest_ct.len()).unwrap_or(u32::MAX),
            parts: e.parts.iter().map(|p| p.padded_size).collect(),
            sha256: e.header_sha256,
            disposition_ct: e.disposition_ct.clone(),
        };
        if let Some(b) = st.envelopes.values().find_map(|e| e.batch_no) {
            let objects = st
                .envelopes
                .iter()
                .filter(|(_, e)| e.batch_no == Some(b))
                .map(|(r, e)| describe(r, e))
                .collect();
            return Ok(ClaimedBatch {
                batch_no: b,
                replayed: true,
                objects,
            });
        }
        // Ordered by the random envelope_ref (same order as the PG store).
        let cands: Vec<(EnvelopeRef, u64)> = st
            .envelopes
            .iter()
            .filter(|(_, e)| e.release_day <= today)
            .take(usize::try_from(limits.max_objects).unwrap_or(usize::MAX))
            .map(|(r, e)| {
                let parts: Vec<u64> = e.parts.iter().map(|p| p.padded_size).collect();
                let len = |v: &Vec<u8>| u64::try_from(v.len()).unwrap_or(u64::MAX);
                (
                    *r,
                    validate::object_bytes(len(&e.header_ct), len(&e.manifest_ct), &parts),
                )
            })
            .collect();
        let sizes: Vec<u64> = cands.iter().map(|c| c.1).collect();
        let chosen = validate::fill_batch(&sizes, limits);
        if chosen.is_empty() {
            return Ok(ClaimedBatch {
                batch_no: 0,
                replayed: false,
                objects: Vec::new(),
            });
        }
        let m = st.meta_mut()?;
        let b = m
            .last_batch_no
            .checked_add(1)
            .ok_or(StoreError::Integrity("batch overflow"))?;
        m.last_batch_no = b;
        let mut objects = Vec::with_capacity(chosen.len());
        for i in chosen {
            let r = cands.get(i).ok_or(StoreError::Integrity("claim index"))?.0;
            let e = st
                .envelopes
                .get_mut(&r)
                .ok_or(StoreError::Integrity("claim row"))?;
            e.batch_no = Some(b);
            objects.push(describe(&r, e));
        }
        Ok(ClaimedBatch {
            batch_no: b,
            replayed: false,
            objects,
        })
    }

    async fn batch_object(
        &self,
        batch_no: u64,
        envelope: EnvelopeRef,
        part: PartSelector,
    ) -> Result<ObjectData> {
        let st = self.state.lock().await;
        st.meta()?;
        let e = st
            .envelopes
            .get(&envelope)
            .filter(|e| e.batch_no == Some(batch_no))
            .ok_or(StoreError::NotFound)?;
        Ok(match part {
            PartSelector::Header => ObjectData::Bytes(e.header_ct.clone()),
            PartSelector::Manifest => ObjectData::Bytes(e.manifest_ct.clone()),
            PartSelector::Part(i) => {
                ObjectData::Blob(*e.parts.get(usize::from(i)).ok_or(StoreError::NotFound)?)
            }
        })
    }

    async fn ack_batch(&self, batch_no: u64, committed: &[[u8; 32]]) -> Result<AckResult> {
        let mut st = self.state.lock().await;
        st.meta()?;
        let in_batch: Vec<EnvelopeRef> = st
            .envelopes
            .iter()
            .filter(|(_, e)| e.batch_no == Some(batch_no))
            .map(|(r, _)| *r)
            .collect();
        if in_batch.is_empty() {
            return Err(StoreError::NotFound);
        }
        for d in committed {
            if !in_batch
                .iter()
                .any(|r| st.envelopes.get(r).is_some_and(|e| &e.header_sha256 == d))
            {
                return Err(StoreError::InvalidInput("digest not in batch"));
            }
        }
        let mut res = AckResult {
            deleted: 0,
            blobs_to_delete: Vec::new(),
        };
        for r in in_batch {
            let acked = st
                .envelopes
                .get(&r)
                .is_some_and(|e| committed.contains(&e.header_sha256));
            if acked {
                if let Some(e) = st.envelopes.remove(&r) {
                    res.blobs_to_delete
                        .extend(e.parts.iter().map(|p| p.blob_id));
                    res.deleted = res.deleted.saturating_add(1);
                }
            } else if let Some(e) = st.envelopes.get_mut(&r) {
                e.batch_no = None;
            }
        }
        Ok(res)
    }

    async fn apply_replies(
        &self,
        today: Day,
        replies: Vec<IncomingReply>,
    ) -> Result<ApplyRepliesResult> {
        validate::day_i32(today)?;
        if replies.len() > MAX_REPLIES_PER_PUSH {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        let mut st = self.state.lock().await;
        if st.meta()?.restore_pending {
            return Err(StoreError::RestorePending);
        }
        let tenant = st.meta()?.tenant;
        let mut res = ApplyRepliesResult::default();
        for (i, r) in replies.into_iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            if !validate::reply(&r) {
                res.rejected.push(idx);
                continue;
            }
            let dropped =
                st.listed(
                    DeletionKind::Reply,
                    &reply_del_hash(&tenant, &r.object_hash),
                ) || r.mailbox_id.as_ref().is_some_and(|m| {
                    st.listed(DeletionKind::Mailbox, &mailbox_del_hash(&tenant, m))
                }) || r.account.is_some_and(|a| !st.accounts.contains_key(&a));
            if dropped {
                res.accepted = res.accepted.saturating_add(1);
                continue;
            }
            let slot = match r.account {
                None => None,
                Some(a) => {
                    let used: Vec<u8> = st
                        .replies
                        .values()
                        .filter(|x| x.account == Some(a))
                        .filter_map(|x| x.slot)
                        .collect();
                    match (0..MAILBOX_SLOTS).find(|s| !used.contains(s)) {
                        Some(s) => Some(s),
                        None => {
                            res.rejected.push(idx);
                            continue;
                        }
                    }
                }
            };
            if let Some(a) = r.account.and_then(|a| st.accounts.get_mut(&a)) {
                a.activity_month = a.activity_month.max(today.month_start());
            }
            st.replies.insert(
                ReplyRef(random_id16()?),
                ReplyRow {
                    account: r.account,
                    reply_ct: r.reply_ct,
                    size_bucket: r.size_bucket,
                    available_day: today,
                    slot,
                },
            );
            res.accepted = res.accepted.saturating_add(1);
        }
        Ok(res)
    }

    async fn mailbox_list(&self, account: AccountId) -> Result<Vec<StoredReply>> {
        let st = self.state.lock().await;
        st.meta()?;
        let mut v: Vec<StoredReply> = st
            .replies
            .iter()
            .filter(|(_, r)| r.account == Some(account))
            .map(|(k, r)| StoredReply {
                reply_ref: *k,
                slot: r.slot.unwrap_or(0),
                reply_ct: r.reply_ct.clone(),
                size_bucket: r.size_bucket,
                available_day: r.available_day,
            })
            .collect();
        v.sort_by_key(|r| r.slot);
        Ok(v)
    }

    async fn delete_replies(
        &self,
        account: AccountId,
        replies: &[(ReplyRef, [u8; 32])],
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> Result<u32> {
        validate::day_i32(today)?;
        if replies.len() > usize::from(MAILBOX_SLOTS) {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        let refs: Vec<ReplyRef> = replies.iter().map(|r| r.0).collect();
        if has_duplicates(&refs) {
            return Err(StoreError::InvalidInput("duplicate reply"));
        }
        let mut st = self.state.lock().await;
        let tenant = st.meta()?.tenant;
        if !st.accounts.contains_key(&account) {
            return Err(StoreError::NotFound);
        }
        if replies
            .iter()
            .any(|(r, _)| st.replies.get(r).is_none_or(|x| x.account != Some(account)))
        {
            return Err(StoreError::NotFound);
        }
        // Stage all entries before mutating (atomicity on signer failure).
        let mut staged = Vec::with_capacity(replies.len());
        let mut head = st.head().copied();
        for (_, h) in replies {
            let e = make_entry(
                head.as_ref(),
                DeletionKind::Reply,
                reply_del_hash(&tenant, h),
                today,
                signer,
            )?;
            head = Some(e);
            staged.push(e);
        }
        for e in staged {
            st.deletion.insert(e.seq, e);
        }
        for (r, _) in replies {
            st.replies.remove(r);
        }
        Ok(u32::try_from(replies.len()).unwrap_or(u32::MAX))
    }

    async fn delete_mailbox(
        &self,
        account: AccountId,
        mailbox: &MailboxId,
        replies: &[ReplyRef],
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> Result<u32> {
        validate::day_i32(today)?;
        if replies.len() > usize::from(MAILBOX_SLOTS) {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        if has_duplicates(replies) {
            return Err(StoreError::InvalidInput("duplicate reply"));
        }
        let mut st = self.state.lock().await;
        let tenant = st.meta()?.tenant;
        if !st.accounts.contains_key(&account) {
            return Err(StoreError::NotFound);
        }
        if replies
            .iter()
            .any(|r| st.replies.get(r).is_none_or(|x| x.account != Some(account)))
        {
            return Err(StoreError::NotFound);
        }
        st.append(
            DeletionKind::Mailbox,
            mailbox_del_hash(&tenant, mailbox),
            today,
            signer,
        )?;
        for r in replies {
            st.replies.remove(r);
        }
        Ok(u32::try_from(replies.len()).unwrap_or(u32::MAX))
    }

    async fn purge_replies_before(&self, cutoff: Day) -> Result<u64> {
        let mut st = self.state.lock().await;
        st.meta()?;
        Ok(delete_replies_where(&mut st, |r| r.available_day < cutoff))
    }

    async fn expire_replies(&self, today: Day, retention_days: u32) -> Result<u64> {
        let keep = retention_days.min(REPLY_WINDOW_DAYS);
        self.purge_replies_before(today.saturating_minus(keep).plus(1)?)
            .await
    }

    async fn rebuild_published_set(&self, today: Day) -> Result<ReplyIndex> {
        let cts: Vec<Vec<u8>> = {
            let st = self.state.lock().await;
            st.meta()?;
            st.replies
                .values()
                .filter(|r| deaddrop::in_window(r.available_day, today))
                .map(|r| r.reply_ct.clone())
                .collect()
        };
        let set = deaddrop::build(&cts, self.dummies.as_ref())?;
        let idx = set.index();
        *self.published.write().await = Arc::new(set);
        Ok(idx)
    }

    async fn reply_index(&self) -> Result<ReplyIndex> {
        Ok(self.published.read().await.index())
    }

    async fn reply_page(&self, n: u16) -> Result<Arc<[u8]>> {
        self.published.read().await.page(n)
    }

    async fn deletion_list_after(&self, after: u64, limit: u32) -> Result<Vec<DeletionEntry>> {
        let limit = usize::try_from(limit.min(MAX_DELETION_LIST_PAGE)).unwrap_or(0);
        let mut st = self.state.lock().await;
        st.meta()?;
        for e in st.deletion.values_mut().filter(|e| e.seq <= after) {
            e.relayed = true;
        }
        Ok(st
            .deletion
            .values()
            .filter(|e| e.seq > after)
            .take(limit)
            .copied()
            .collect())
    }

    async fn apply_pushed_deletion_list(
        &self,
        entries: &[DeletionEntry],
        k31_pk: &[u8; 32],
        hasher: &dyn ReplyObjectHasher,
    ) -> Result<u64> {
        let mut st = self.state.lock().await;
        let tenant = st.meta()?.tenant;
        let local: Vec<DeletionEntry> = st.deletion.values().copied().collect();
        let new = validate::merge_pushed(&local, entries, k31_pk)?;
        for e in new {
            st.deletion.insert(e.seq, e);
        }
        let acct: Vec<[u8; 32]> = st
            .deletion
            .values()
            .filter(|e| e.kind == DeletionKind::Account)
            .map(|e| e.del_hash)
            .collect();
        let reps: Vec<[u8; 32]> = st
            .deletion
            .values()
            .filter(|e| e.kind == DeletionKind::Reply)
            .map(|e| e.del_hash)
            .collect();
        let doomed: Vec<AccountId> = st
            .accounts
            .values()
            .filter(|a| acct.contains(&account_del_hash(&tenant, &a.lookup_tag)))
            .map(|a| a.account_id)
            .collect();
        for a in &doomed {
            st.accounts.remove(a);
            delete_replies_where(&mut st, |r| r.account == Some(*a));
            for e in st.envelopes.values_mut() {
                if e.account == Some(*a) {
                    e.account = None;
                }
            }
        }
        delete_replies_where(&mut st, |r| {
            hasher
                .object_hash(&r.reply_ct)
                .is_some_and(|h| reps.contains(&reply_del_hash(&tenant, &h)))
        });
        let through = st.head().map_or(0, |e| e.seq);
        st.meta_mut()?.restore_pending = false;
        Ok(through)
    }

    async fn prune_deletion_list(&self, today: Day) -> Result<u64> {
        let cutoff = today.saturating_minus(DELETION_LIST_RETENTION_DAYS);
        let mut st = self.state.lock().await;
        st.meta()?;
        let head = st.head().map_or(0, |e| e.seq);
        let before = st.deletion.len();
        st.deletion
            .retain(|s, e| !(e.relayed && e.del_day < cutoff && *s < head));
        Ok(u64::try_from(before.saturating_sub(st.deletion.len())).unwrap_or(u64::MAX))
    }

    async fn kd_high_water(&self) -> Result<KdHighWater> {
        Ok(self.state.lock().await.meta()?.kd)
    }

    async fn install_directory_snapshot(
        &self,
        snap: VerifiedSnapshot,
        today: Day,
    ) -> Result<InstallOutcome> {
        validate::day_i32(today)?;
        let mut st = self.state.lock().await;
        let hwm = st.meta()?.kd;
        let current = st
            .snapshots
            .get(&hwm.directory_version)
            .map(|s| s.0.clone());
        let d = validate::snapshot(&hwm, current.as_deref(), &snap)?;
        if d == SnapshotDecision::AlreadyInstalled {
            return Ok(InstallOutcome::AlreadyInstalled);
        }
        st.snapshots
            .insert(snap.version, (snap.body, snap.signatures, today));
        let m = st.meta_mut()?;
        m.kd = KdHighWater {
            tree_size: m.kd.tree_size.max(snap.tree_size),
            checkpoint_day: Some(
                m.kd.checkpoint_day
                    .map_or(snap.checkpoint_day, |d| d.max(snap.checkpoint_day)),
            ),
            directory_version: snap.version,
        };
        let keep_from = st.snapshots.keys().rev().nth(1).copied().unwrap_or(0);
        st.snapshots.retain(|v, _| *v >= keep_from);
        Ok(InstallOutcome::Installed)
    }

    async fn current_directory_snapshot(&self) -> Result<Option<crate::store::InstalledSnapshot>> {
        let st = self.state.lock().await;
        let v = st.meta()?.kd.directory_version;
        Ok(st
            .snapshots
            .get(&v)
            .map(|(b, s, _)| (v, b.clone(), s.clone())))
    }

    async fn counter_add(
        &self,
        month: Day,
        channel: ChannelId,
        name: CounterName,
        delta: u32,
    ) -> Result<()> {
        if !month.is_month_start() {
            return Err(StoreError::InvalidInput("month"));
        }
        validate::day_i32(month)?;
        let mut st = self.state.lock().await;
        st.meta()?;
        let c = st.counters.entry((month, channel, name)).or_insert(0);
        let next = c
            .checked_add(delta)
            .filter(|v| i32::try_from(*v).is_ok())
            .ok_or(StoreError::InvalidInput("counter overflow"))?;
        *c = next;
        Ok(())
    }

    async fn counters_for_month(&self, month: Day) -> Result<Vec<CounterCell>> {
        let st = self.state.lock().await;
        st.meta()?;
        Ok(st
            .counters
            .iter()
            .filter(|((m, _, _), _)| *m == month)
            .map(|((_, c, n), v)| CounterCell {
                channel_id: *c,
                name: *n,
                value: *v,
            })
            .collect())
    }

    async fn prune_counters_before(&self, month: Day) -> Result<u64> {
        let mut st = self.state.lock().await;
        st.meta()?;
        let before = st.counters.len();
        st.counters.retain(|(m, _, _), _| *m >= month);
        Ok(u64::try_from(before.saturating_sub(st.counters.len())).unwrap_or(u64::MAX))
    }

    async fn export_backup(&self) -> Result<BackupSnapshot> {
        let st = self.state.lock().await;
        let m = st.meta()?;
        let mut accounts: Vec<SourceAccount> = st.accounts.values().cloned().collect();
        accounts.sort_by_key(|a| a.account_id);
        Ok(BackupSnapshot {
            meta: MetaSnapshot {
                tenant_id: m.tenant,
                kdf_salt: m.kdf_salt,
                relay_req_counter: m.relay_req_counter,
                last_batch_no: m.last_batch_no,
                kd: m.kd,
            },
            accounts,
            deletion_list: st.deletion.values().copied().collect(),
        })
    }

    async fn restore_backup(&self, b: BackupSnapshot) -> Result<()> {
        let mut st = self.state.lock().await;
        if !st.accounts.is_empty()
            || !st.envelopes.is_empty()
            || !st.replies.is_empty()
            || !st.deletion.is_empty()
        {
            return Err(StoreError::Conflict("restore target not empty"));
        }
        let prior = st.meta.clone();
        if prior.as_ref().is_some_and(|p| p.tenant != b.meta.tenant_id) {
            return Err(StoreError::TenantMismatch);
        }
        for a in &b.accounts {
            validate::new_account(&crate::types::NewAccount {
                lookup_tag: a.lookup_tag,
                auth_pk: a.auth_pk,
                xwing_pk: a.xwing_pk.clone(),
                prefs_ct: a.prefs_ct.clone(),
            })?;
        }
        let pk_less_check: Vec<u64> = b.deletion_list.iter().map(|e| e.seq).collect();
        if pk_less_check
            .windows(2)
            .any(|w| matches!(w, [x, y] if y <= x))
        {
            return Err(StoreError::DeletionList("unordered backup list"));
        }
        let kd = prior
            .as_ref()
            .map_or(b.meta.kd, |p| merge_hwm(p.kd, b.meta.kd));
        st.meta = Some(Meta {
            tenant: b.meta.tenant_id,
            kdf_salt: b.meta.kdf_salt,
            relay_req_counter: prior
                .as_ref()
                .map_or(0, |p| p.relay_req_counter)
                .max(b.meta.relay_req_counter),
            last_batch_no: prior
                .as_ref()
                .map_or(0, |p| p.last_batch_no)
                .max(b.meta.last_batch_no),
            kd,
            restore_pending: true,
        });
        for a in b.accounts {
            st.accounts.insert(a.account_id, a);
        }
        for e in b.deletion_list {
            st.deletion.insert(e.seq, e);
        }
        Ok(())
    }
}

/// Restore keeps the higher of the two high-water marks (09 `kd_tree_size_hwm`).
pub(crate) fn merge_hwm(a: KdHighWater, b: KdHighWater) -> KdHighWater {
    KdHighWater {
        tree_size: a.tree_size.max(b.tree_size),
        checkpoint_day: a.checkpoint_day.max(b.checkpoint_day),
        directory_version: a.directory_version.max(b.directory_version),
    }
}
