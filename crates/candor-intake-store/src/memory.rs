// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-memory `IntakeStore` for tests of other crates. Same rules as the
//! PostgreSQL store (shared `validate` module; same conformance suite). Not for
//! production: nothing is durable.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use crate::deaddrop::{
    self, DEFAULT_DUMMY_BUCKET_WEIGHTS, DeadDropConfig, DummyReplies, PADDING_GENERATION,
    PageBuilder, PublishedSet, RandomDummyReplies,
};
use crate::deletion::{
    DeletionEntry, DeletionKind, DeletionSigner, ReplyObjectHasher, SignedDeletionHead,
    account_del_hash, mailbox_del_hash, make_entry, reply_del_hash,
};
use crate::error::{Result, StoreError};
use crate::store::{IntakeMaintenance, IntakeStore};
use crate::types::{
    AccountId, AckResult, ApplyRepliesResult, BackupSnapshot, BlobId, ChannelId, ClaimLimits,
    ClaimedBatch, ClaimedObject, CommitEnvelope, CounterCell, CounterDelta, CounterName,
    DELETION_LIST_RETENTION_DAYS, Day, EnvelopeRef, GROUP_OBJECTS, GroupObject,
    INACTIVE_PURGE_DAYS, ImportSlot, IncomingReply, InstallOutcome, KdHighWater, LookupTag,
    MAILBOX_SLOTS, MAX_DELETION_LIST_PAGE, MAX_REPLIES_PER_PUSH, MAX_SLOT_ACTIVE_ACCOUNTS,
    MailboxId, MetaSnapshot, NewAccount, ObjectData, PartSelector, REPLY_WINDOW_DAYS, ReplyIndex,
    ReplyRef, SourceAccount, StoredReply, TenantId, VerifiedSnapshot, group_digest, random_id16,
    reply_bucket_of_len,
};
use crate::validate::{self, SnapshotDecision, has_duplicates};

/// Published-set configuration used by [`MemoryStore::new`]: one slot per day,
/// two entries per slot (one page), a 64-reply backlog.
pub const MEMORY_DEADDROP_CONFIG: DeadDropConfig = DeadDropConfig {
    slots_per_day: 1,
    per_slot: 2,
    max_pending: 64,
    dummy_bucket_weights: DEFAULT_DUMMY_BUCKET_WEIGHTS,
};

#[derive(Clone)]
struct Meta {
    tenant: TenantId,
    kdf_salt: [u8; 32],
    relay_req_counter: u64,
    last_batch_no: u64,
    kd: KdHighWater,
    restore_pending: bool,
    /// Last verified Z-CORE head (AUD-RM2-STO-21/22).
    ack_head: Option<SignedDeletionHead>,
}

impl Meta {
    fn acked_seq(&self) -> u64 {
        self.ack_head.map_or(0, |h| h.seq)
    }
}

#[derive(Clone)]
struct EnvRow {
    channel_id: ChannelId,
    objects: [GroupObject; GROUP_OBJECTS],
    group_sha256: [u8; 32],
    disposition_ct: Vec<u8>,
    epoch_index: u32,
    release_day: Day,
    batch_no: Option<u64>,
}

#[derive(Clone)]
struct ReplyRow {
    account: Option<AccountId>,
    reply_ct: Vec<u8>,
    size_bucket: u8,
    available_day: Day,
    slot: Option<u8>,
    /// `None` = real reply awaiting publication; `Some(0)` = padding pool;
    /// `Some(g)` = published in generation `g`.
    pub_gen: Option<u64>,
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
    /// Source-facing operations refuse while a restore is pending (BE-074).
    fn serving(&self) -> Result<&Meta> {
        let m = self.meta()?;
        if m.restore_pending {
            return Err(StoreError::RestorePending);
        }
        Ok(m)
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
    fn with_relayed(&self, e: &DeletionEntry) -> DeletionEntry {
        let acked = self.meta.as_ref().map_or(0, Meta::acked_seq);
        let mut e = *e;
        e.relayed = e.relayed || e.seq <= acked;
        e
    }
}

/// In-memory store.
pub struct MemoryStore {
    state: Mutex<State>,
    published: RwLock<Arc<PublishedSet>>,
    dummies: Box<dyn DummyReplies>,
    cfg: DeadDropConfig,
}

impl core::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MemoryStore")
    }
}

impl MemoryStore {
    /// New empty store with random-byte dummy replies and
    /// [`MEMORY_DEADDROP_CONFIG`].
    pub fn new() -> Result<Self> {
        Self::with_config(MEMORY_DEADDROP_CONFIG, Box::new(RandomDummyReplies))
    }

    /// New empty store with a caller-supplied published-set configuration and
    /// dummy reply source.
    pub fn with_config(cfg: DeadDropConfig, dummies: Box<dyn DummyReplies>) -> Result<Self> {
        cfg.validate()?;
        let empty = deaddrop::empty(&cfg, dummies.as_ref())?;
        Ok(Self {
            state: Mutex::new(State::default()),
            published: RwLock::new(Arc::new(empty)),
            dummies,
            cfg,
        })
    }
}

fn delete_replies_where(st: &mut State, pred: impl Fn(&ReplyRow) -> bool) -> u64 {
    let before = st.replies.len();
    st.replies.retain(|_, r| !pred(r));
    u64::try_from(before.saturating_sub(st.replies.len())).unwrap_or(u64::MAX)
}

/// Fold `activity_month` at an import slot (AUD-RM2-STO-01): the slot's month
/// for the accounts recorded active, and the month of each stored reply dated
/// no later than the slot.
fn fold_activity(st: &mut State, slot_day: Day, active: &HashSet<AccountId>) {
    let mut best: HashMap<AccountId, Day> = HashMap::new();
    let slot_month = slot_day.month_start();
    for a in active {
        best.insert(*a, slot_month);
    }
    for r in st.replies.values() {
        if let Some(a) = r.account
            && r.available_day <= slot_day
        {
            let m = r.available_day.month_start();
            best.entry(a).and_modify(|x| *x = (*x).max(m)).or_insert(m);
        }
    }
    for (a, m) in best {
        if let Some(acc) = st.accounts.get_mut(&a) {
            acc.activity_month = acc.activity_month.max(m);
        }
    }
}

/// Owner of a mailbox (09 `mailbox_account`).
fn owner_of(st: &State, mailbox: &MailboxId) -> Option<AccountId> {
    st.accounts
        .values()
        .find(|a| a.mailbox_ids.contains(mailbox))
        .map(|a| a.account_id)
}

/// Any of `ids` mapped to an account other than `except`.
fn mailbox_taken(st: &State, ids: &[MailboxId], except: Option<AccountId>) -> bool {
    ids.iter()
        .any(|m| owner_of(st, m).is_some_and(|o| Some(o) != except))
}

fn sorted(mut v: Vec<MailboxId>) -> Vec<MailboxId> {
    v.sort();
    v
}

fn remove_account(st: &mut State, account: AccountId) {
    st.accounts.remove(&account);
    delete_replies_where(st, |r| r.account == Some(account));
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
                    ack_head: None,
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

    async fn mark_restore_pending(&self) -> Result<()> {
        self.state.lock().await.meta_mut()?.restore_pending = true;
        Ok(())
    }

    async fn lookup_account(&self, tag: &LookupTag) -> Result<Option<SourceAccount>> {
        let st = self.state.lock().await;
        st.serving()?;
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
        let tenant = st.serving()?.tenant;
        let mailboxes = st
            .accounts
            .get(&account)
            .ok_or(StoreError::NotFound)?
            .mailbox_ids
            .clone();
        // One `mailbox` entry per mailbox, then the `account` entry over the
        // stable id (ADR-057(1)); staged first so a signer failure changes
        // nothing (one transaction).
        let mut staged = Vec::with_capacity(mailboxes.len().saturating_add(1));
        let mut head = st.head().copied();
        for mb in &mailboxes {
            let e = make_entry(
                head.as_ref(),
                DeletionKind::Mailbox,
                mailbox_del_hash(&tenant, mb),
                today,
                signer,
            )?;
            head = Some(e);
            staged.push(e);
        }
        let e = make_entry(
            head.as_ref(),
            DeletionKind::Account,
            account_del_hash(&tenant, &account),
            today,
            signer,
        )?;
        staged.push(e);
        for e in staged {
            st.deletion.insert(e.seq, e);
        }
        remove_account(&mut st, account);
        Ok(())
    }

    async fn create_account(&self, account: NewAccount, today: Day) -> Result<AccountId> {
        validate::new_account(&account)?;
        validate::day_i32(today)?;
        let mut st = self.state.lock().await;
        st.serving()?;
        if st
            .accounts
            .values()
            .any(|a| a.lookup_tag == account.lookup_tag)
        {
            return Err(StoreError::AccountExists);
        }
        if mailbox_taken(&st, &account.mailbox_ids, None) {
            return Err(StoreError::InvalidInput("mailbox taken"));
        }
        let id = AccountId(random_id16()?);
        st.accounts.insert(
            id,
            SourceAccount {
                account_id: id,
                lookup_tag: account.lookup_tag,
                auth_pk: account.auth_pk,
                xwing_pk: account.xwing_pk,
                prefs_ct: account.prefs_ct,
                activity_month: today.month_start(),
                mailbox_ids: sorted(account.mailbox_ids),
            },
        );
        Ok(id)
    }

    async fn update_account(&self, account: AccountId, new: NewAccount) -> Result<()> {
        validate::new_account(&new)?;
        let mut st = self.state.lock().await;
        st.serving()?;
        if !st.accounts.contains_key(&account) {
            return Err(StoreError::NotFound);
        }
        if st
            .accounts
            .values()
            .any(|a| a.lookup_tag == new.lookup_tag && a.account_id != account)
        {
            return Err(StoreError::AccountExists);
        }
        if mailbox_taken(&st, &new.mailbox_ids, Some(account)) {
            return Err(StoreError::InvalidInput("mailbox taken"));
        }
        let a = st.accounts.get_mut(&account).ok_or(StoreError::NotFound)?;
        a.lookup_tag = new.lookup_tag;
        a.auth_pk = new.auth_pk;
        a.xwing_pk = new.xwing_pk;
        a.prefs_ct = new.prefs_ct;
        a.mailbox_ids = sorted(new.mailbox_ids);
        Ok(())
    }

    async fn purge_inactive_accounts(&self, today: Day) -> Result<u64> {
        validate::day_i32(today)?;
        let cutoff = today.saturating_minus(INACTIVE_PURGE_DAYS);
        let mut st = self.state.lock().await;
        st.meta()?;
        let doomed: Vec<AccountId> = st
            .accounts
            .values()
            .filter(|a| a.activity_month <= cutoff)
            .map(|a| a.account_id)
            .collect();
        for a in &doomed {
            remove_account(&mut st, *a);
        }
        Ok(u64::try_from(doomed.len()).unwrap_or(u64::MAX))
    }

    async fn commit_envelope(&self, env: CommitEnvelope) -> Result<EnvelopeRef> {
        validate::commit(&env)?;
        let mut st = self.state.lock().await;
        st.serving()?;
        let digest = group_digest(&env.objects.clone().map(|o| o.object_hash));
        if st.envelopes.values().any(|e| e.group_sha256 == digest) {
            return Err(StoreError::DuplicateEnvelope);
        }
        let blob_taken = |b: &BlobId| {
            st.envelopes
                .values()
                .any(|e| e.objects.iter().any(|o| o.blob.blob_id == *b))
        };
        if env.objects.iter().any(|o| blob_taken(&o.blob.blob_id)) {
            return Err(StoreError::InvalidInput("duplicate blob id"));
        }
        let r = EnvelopeRef(random_id16()?);
        st.envelopes.insert(
            r,
            EnvRow {
                channel_id: env.channel_id,
                group_sha256: digest,
                disposition_ct: env.disposition_ct,
                epoch_index: env.epoch_index,
                release_day: env.received_date.plus(u32::from(env.release_offset_days))?,
                batch_no: None,
                objects: env.objects,
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
            object_hashes: e.objects.clone().map(|o| o.object_hash),
            parts: e.objects.clone().map(|o| o.blob.padded_size),
            sha256: e.group_sha256,
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
        // Ordered by (release_day, random envelope_ref), same as the PG store:
        // the oldest released envelopes go first (AUD-RM2-STO-16).
        let mut eligible: Vec<(Day, EnvelopeRef)> = st
            .envelopes
            .iter()
            .filter(|(_, e)| e.release_day <= today)
            .map(|(r, e)| (e.release_day, *r))
            .collect();
        eligible.sort_unstable();
        let cands: Vec<(EnvelopeRef, u64)> = eligible
            .iter()
            .take(usize::try_from(limits.max_objects).unwrap_or(usize::MAX))
            .filter_map(|(_, r)| st.envelopes.get(r).map(|e| (*r, e)))
            .map(|(r, e)| {
                let parts: Vec<u64> = e.objects.iter().map(|o| o.blob.padded_size).collect();
                (r, validate::group_bytes(&parts))
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
        objects.sort_by_key(|o| o.envelope_ref);
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
            PartSelector::SlotBlock(i) => ObjectData::Bytes(
                e.objects
                    .get(usize::from(i))
                    .ok_or(StoreError::NotFound)?
                    .slot_block
                    .clone(),
            ),
            PartSelector::Object(i) => ObjectData::Blob(
                e.objects
                    .get(usize::from(i))
                    .ok_or(StoreError::NotFound)?
                    .blob,
            ),
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
                .any(|r| st.envelopes.get(r).is_some_and(|e| &e.group_sha256 == d))
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
                .is_some_and(|e| committed.contains(&e.group_sha256));
            if acked {
                if let Some(e) = st.envelopes.remove(&r) {
                    res.blobs_to_delete
                        .extend(e.objects.iter().map(|o| o.blob.blob_id));
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
        let tenant = st.serving()?.tenant;
        let max_pending = usize::try_from(self.cfg.max_pending).unwrap_or(usize::MAX);
        let mut pending = st.replies.values().filter(|r| r.pub_gen.is_none()).count();
        let mut res = ApplyRepliesResult::default();
        for (i, r) in replies.into_iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            if !validate::reply(&r) {
                res.rejected.push(idx);
                continue;
            }
            // ADR-057(2): route through `mailbox_account` when the caller
            // did not resolve the account.
            let routed = match (r.account, &r.mailbox_id) {
                (None, Some(mb)) => owner_of(&st, mb),
                (a, _) => a,
            };
            let r = IncomingReply {
                account: routed,
                ..r
            };
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
            if pending >= max_pending {
                res.rejected.push(idx);
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
            st.replies.insert(
                ReplyRef(random_id16()?),
                ReplyRow {
                    account: r.account,
                    size_bucket: reply_bucket_of_len(r.reply_ct.len())
                        .ok_or(StoreError::InvalidInput("reply length"))?,
                    reply_ct: r.reply_ct,
                    available_day: today,
                    slot,
                    pub_gen: None,
                },
            );
            pending = pending.saturating_add(1);
            res.accepted = res.accepted.saturating_add(1);
        }
        Ok(res)
    }

    async fn mailbox_list(&self, account: AccountId) -> Result<Vec<StoredReply>> {
        let st = self.state.lock().await;
        st.serving()?;
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

    async fn rewrap_replies(
        &self,
        account: AccountId,
        rewraps: &[([u8; 32], Vec<u8>)],
    ) -> Result<u32> {
        if rewraps.len() > 64 {
            return Err(StoreError::InvalidInput("too many rewraps"));
        }
        let mut st = self.state.lock().await;
        st.serving()?;
        if !st.accounts.contains_key(&account) {
            return Err(StoreError::NotFound);
        }
        let hasher = crate::deletion::CoreReplyHasher;
        let mut n = 0u32;
        for r in st
            .replies
            .values_mut()
            .filter(|r| r.account == Some(account))
        {
            let Some(h) = hasher.object_hash(&r.reply_ct) else {
                continue;
            };
            if let Some((_, stanza)) = rewraps.iter().find(|(oh, _)| *oh == h)
                && let Some(ct) = crate::store::rewrap_reply_ct(&r.reply_ct, stanza)
            {
                r.reply_ct = ct;
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    async fn reply(&self, account: AccountId, reply: ReplyRef) -> Result<Option<StoredReply>> {
        let st = self.state.lock().await;
        st.serving()?;
        Ok(st
            .replies
            .get(&reply)
            .filter(|r| r.account == Some(account))
            .map(|r| StoredReply {
                reply_ref: reply,
                slot: r.slot.unwrap_or(0),
                reply_ct: r.reply_ct.clone(),
                size_bucket: r.size_bucket,
                available_day: r.available_day,
            }))
    }

    async fn mailbox_owner(&self, mailbox: &MailboxId) -> Result<Option<AccountId>> {
        let st = self.state.lock().await;
        st.meta()?;
        Ok(owner_of(&st, mailbox))
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
        let tenant = st.serving()?.tenant;
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
        let tenant = st.serving()?.tenant;
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
        if let Some(a) = st.accounts.get_mut(&account) {
            a.mailbox_ids.retain(|m| m != mailbox);
        }
        Ok(u32::try_from(replies.len()).unwrap_or(u32::MAX))
    }

    async fn purge_replies_before(&self, cutoff: Day) -> Result<u64> {
        let mut st = self.state.lock().await;
        st.meta()?;
        Ok(delete_replies_where(&mut st, |r| {
            r.available_day < cutoff && r.pub_gen != Some(PADDING_GENERATION)
        }))
    }

    async fn expire_replies(&self, today: Day, retention_days: u32) -> Result<u64> {
        let keep = retention_days.min(REPLY_WINDOW_DAYS);
        self.purge_replies_before(today.saturating_minus(keep).plus(1)?)
            .await
    }

    async fn rebuild_published_set(&self, slot: ImportSlot) -> Result<ReplyIndex> {
        let cfg = self.cfg;
        let g = cfg.generation(slot)?;
        let k = usize::from(cfg.per_slot);
        let total = cfg.total_entries()?;
        let set = {
            let mut st = self.state.lock().await;
            st.meta()?;
            let last = st
                .replies
                .values()
                .filter_map(|r| r.pub_gen)
                .filter(|g| *g != PADDING_GENERATION)
                .max();
            for h in deaddrop::generations_to_publish(&cfg, last, g) {
                let day = cfg.day_of(h)?;
                let mut reals: Vec<(Day, ReplyRef)> = Vec::new();
                if h == g {
                    reals = st
                        .replies
                        .iter()
                        .filter(|(_, r)| r.pub_gen.is_none())
                        .map(|(k, r)| (r.available_day, *k))
                        .collect();
                    reals.sort_unstable();
                    reals.truncate(k);
                }
                for (_, r) in &reals {
                    if let Some(row) = st.replies.get_mut(r) {
                        row.pub_gen = Some(h);
                        row.available_day = day;
                    }
                }
                for _ in reals.len()..k {
                    let (body, bucket) = deaddrop::dummy_row(self.dummies.as_ref(), &cfg)?;
                    st.replies.insert(
                        ReplyRef(random_id16()?),
                        ReplyRow {
                            account: None,
                            reply_ct: body,
                            size_bucket: bucket,
                            available_day: day,
                            slot: None,
                            pub_gen: Some(h),
                        },
                    );
                }
            }
            // Padding pool: keep window + padding at exactly `total`.
            let lo = cfg.window_start(g);
            let in_window = |r: &ReplyRow| r.pub_gen.is_some_and(|p| p >= lo && p <= g);
            let window = st.replies.values().filter(|r| in_window(r)).count();
            let want = total.checked_sub(window).ok_or(StoreError::Capacity)?;
            let padding: Vec<ReplyRef> = st
                .replies
                .iter()
                .filter(|(_, r)| r.pub_gen == Some(PADDING_GENERATION))
                .map(|(k, _)| *k)
                .collect();
            for r in padding.iter().skip(want) {
                st.replies.remove(r);
            }
            for _ in padding.len()..want {
                let (body, bucket) = deaddrop::dummy_row(self.dummies.as_ref(), &cfg)?;
                st.replies.insert(
                    ReplyRef(random_id16()?),
                    ReplyRow {
                        account: None,
                        reply_ct: body,
                        size_bucket: bucket,
                        available_day: slot.day,
                        slot: None,
                        pub_gen: Some(PADDING_GENERATION),
                    },
                );
            }
            let mut b = PageBuilder::new(cfg.page_count()?)?;
            for r in st.replies.values() {
                if in_window(r) || r.pub_gen == Some(PADDING_GENERATION) {
                    b.push(&r.reply_ct)?;
                }
            }
            b.finish(self.dummies.as_ref(), &cfg)?
        };
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
        i64::try_from(after).map_err(|_| StoreError::InvalidInput("after"))?;
        let st = self.state.lock().await;
        st.meta()?;
        let head = st.head().map_or(0, |e| e.seq);
        if after > head {
            return Err(StoreError::InvalidInput("after beyond head"));
        }
        Ok(st
            .deletion
            .values()
            .filter(|e| e.seq > after)
            .take(limit)
            .map(|e| st.with_relayed(e))
            .collect())
    }

    async fn acknowledge_deletion_head(
        &self,
        head: &SignedDeletionHead,
        core_pk: &[u8; 32],
    ) -> Result<()> {
        let mut st = self.state.lock().await;
        let (tenant, current) = {
            let m = st.meta()?;
            (m.tenant, m.ack_head)
        };
        head.verify(&tenant, core_pk)?;
        let local: Vec<DeletionEntry> = st.deletion.values().copied().collect();
        if validate::ack_head(&local, current.as_ref(), head)? {
            st.meta_mut()?.ack_head = Some(*head);
        }
        Ok(())
    }

    async fn apply_pushed_deletion_list(
        &self,
        entries: &[DeletionEntry],
        head: &SignedDeletionHead,
        core_pk: &[u8; 32],
        k31_pk: &[u8; 32],
        hasher: &dyn ReplyObjectHasher,
        today: Day,
    ) -> Result<u64> {
        let mut st = self.state.lock().await;
        let (tenant, verified) = {
            let m = st.meta()?;
            (m.tenant, m.ack_head)
        };
        let local: Vec<DeletionEntry> = st.deletion.values().copied().collect();
        let merged = validate::verify_pushed(entries, k31_pk, head, &tenant, core_pk, today)
            .and_then(|()| validate::merge_pushed(&local, verified.as_ref(), entries, head));
        let new = match merged {
            Ok(n) => n,
            Err(e) => {
                // Fail closed: any rejected push leaves (or puts) the store in
                // restore-pending (AUD-RM2-STO-04).
                st.meta_mut()?.restore_pending = true;
                return Err(e);
            }
        };
        for e in new {
            st.deletion.insert(e.seq, e);
        }
        let acct: HashSet<[u8; 32]> = st
            .deletion
            .values()
            .filter(|e| e.kind == DeletionKind::Account)
            .map(|e| e.del_hash)
            .collect();
        let reps: HashSet<[u8; 32]> = st
            .deletion
            .values()
            .filter(|e| e.kind == DeletionKind::Reply)
            .map(|e| e.del_hash)
            .collect();
        let doomed: Vec<AccountId> = st
            .accounts
            .values()
            .filter(|a| acct.contains(&account_del_hash(&tenant, &a.account_id)))
            .map(|a| a.account_id)
            .collect();
        for a in &doomed {
            remove_account(&mut st, *a);
        }
        // Listed mailboxes: drop the mapping and the owner's replies.
        let mbs: HashSet<[u8; 32]> = st
            .deletion
            .values()
            .filter(|e| e.kind == DeletionKind::Mailbox)
            .map(|e| e.del_hash)
            .collect();
        let closed: Vec<AccountId> = st
            .accounts
            .values()
            .filter(|a| {
                a.mailbox_ids
                    .iter()
                    .any(|m| mbs.contains(&mailbox_del_hash(&tenant, m)))
            })
            .map(|a| a.account_id)
            .collect();
        for id in closed {
            if let Some(a) = st.accounts.get_mut(&id) {
                a.mailbox_ids
                    .retain(|m| !mbs.contains(&mailbox_del_hash(&tenant, m)));
            }
            delete_replies_where(&mut st, |r| r.account == Some(id));
        }
        delete_replies_where(&mut st, |r| {
            hasher
                .object_hash(&r.reply_ct)
                .is_some_and(|h| reps.contains(&reply_del_hash(&tenant, &h)))
        });
        let through = st.head().map_or(0, |e| e.seq);
        let m = st.meta_mut()?;
        // The pushed head is verified and contained in the merged chain: it is
        // the new acknowledged head when its attestation is newer (never
        // lowered; AUD-RM2-STO-24).
        if head.seq > 0 && m.ack_head.is_none_or(|v| v.counter < head.counter) {
            m.ack_head = Some(*head);
        }
        m.restore_pending = false;
        Ok(through)
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
        // applied_day is stored at month granularity (AUD-RM2-STO-01).
        st.snapshots.insert(
            snap.version,
            (snap.body, snap.signatures, today.month_start()),
        );
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

    async fn uniform_rewrite(
        &self,
        slot: ImportSlot,
        counters: &[CounterDelta],
        active_accounts: &[AccountId],
    ) -> Result<()> {
        validate::day_i32(slot.day)?;
        if active_accounts.len() > MAX_SLOT_ACTIVE_ACCOUNTS {
            return Err(StoreError::InvalidInput("too many active accounts"));
        }
        let active: HashSet<AccountId> = active_accounts.iter().copied().collect();
        let mut st = self.state.lock().await;
        st.meta()?;
        // Validate every delta (including the accumulated value) before writing.
        let mut next: BTreeMap<(Day, ChannelId, CounterName), u32> = BTreeMap::new();
        for c in counters {
            validate::counter_delta(c)?;
            let key = (c.month, c.channel_id, c.name);
            let cur = match next.get(&key) {
                Some(v) => *v,
                None => st.counters.get(&key).copied().unwrap_or(0),
            };
            let v = cur
                .checked_add(c.delta)
                .filter(|v| i32::try_from(*v).is_ok())
                .ok_or(StoreError::InvalidInput("counter overflow"))?;
            next.insert(key, v);
        }
        st.counters.extend(next);
        fold_activity(&mut st, slot.day, &active);
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
                deletion_head: m.ack_head,
            },
            accounts,
            deletion_list: st.deletion.values().map(|e| st.with_relayed(e)).collect(),
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
        if prior
            .as_ref()
            .is_some_and(|p| p.kdf_salt != b.meta.kdf_salt)
        {
            return Err(StoreError::Conflict("kdf salt differs"));
        }
        validate::backup(&b)?;
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
            ack_head: b.meta.deletion_head,
        });
        for a in b.accounts {
            st.accounts.insert(a.account_id, a);
        }
        for mut e in b.deletion_list {
            e.relayed = false;
            st.deletion.insert(e.seq, e);
        }
        Ok(())
    }
}

impl IntakeMaintenance for MemoryStore {
    async fn prune_deletion_list(&self, today: Day) -> Result<u64> {
        let cutoff = today.saturating_minus(DELETION_LIST_RETENTION_DAYS);
        let mut st = self.state.lock().await;
        let acked = st.meta()?.acked_seq();
        for e in st.deletion.values_mut().filter(|e| e.seq <= acked) {
            e.relayed = true;
        }
        let head = st.head().map_or(0, |e| e.seq);
        let before = st.deletion.len();
        st.deletion
            .retain(|s, e| !(e.relayed && e.del_day < cutoff && *s < head));
        Ok(u64::try_from(before.saturating_sub(st.deletion.len())).unwrap_or(u64::MAX))
    }

    async fn blob_referenced(&self, blob: BlobId) -> Result<bool> {
        let st = self.state.lock().await;
        // Fail closed like the PostgreSQL store (AUD-RM2-STO-28): an
        // uninitialised store is `NotInitialized`, never "unreferenced".
        st.meta()?;
        Ok(st
            .envelopes
            .values()
            .any(|e| e.objects.iter().any(|o| o.blob.blob_id == blob)))
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
