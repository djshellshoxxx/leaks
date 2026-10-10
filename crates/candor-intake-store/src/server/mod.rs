// SPDX-License-Identifier: AGPL-3.0-or-later
//! `istore.sock` server (feature `server`): serves the [`crate::proto`]
//! operations over an `AF_UNIX`/`SOCK_SEQPACKET` listener on top of any
//! [`IntakeStore`], the staged-bundle receiver of [`crate::staged`] and the
//! K31 deletion signer.
//!
//! * **Authentication:** `SO_PEERCRED` on accept; the uid selects the
//!   connection's [`Role`] (configured, no defaults); any other uid is
//!   closed without a reply. An op of another role answers `FORBIDDEN` and
//!   closes. Relay ops are reserved and refused the same way until RM-3.
//! * **Bounded:** at most [`ServerConfig::max_connections`] connections (the
//!   rest get one `BUSY` and are closed), one datagram buffer of
//!   [`MAX_FRAME_LEN`] + 1 per connection, `SO_RCVTIMEO` idle and
//!   `SO_SNDTIMEO` write deadlines, and [`ServerConfig::op_deadline`] on
//!   every store operation (a timed-out operation answers `UNAVAILABLE`).
//!   `accept()` errors (`EMFILE`, …) back off and never end the loop
//!   (ADR-052(4)).
//! * **Strict:** a datagram that is truncated, carries descriptors, fails to
//!   decode or exceeds the op's maximum answers `BAD_FRAME` and closes.
//! * **Deletion (04 §18.6, KEY-077):** `DELETE` runs the store's
//!   transactional, K31-signed deletions; nothing here is logged and no
//!   identifier reaches an error.
//! * **Hand-over (AUD-RM2-SEA-01):** after a `COMMIT_GROUP` is accepted the
//!   same connection performs the staged hand-over; a replayed group is a
//!   success without a second commit.
//!
//! The server never reads a wall clock itself: `today` (deletion days,
//! received-day check) and the slot for blob times come from the
//! integrator's [`StoreClock`]. Blocking: run [`IstoreServer::serve`] on a
//! dedicated thread; store futures run on the tokio runtime behind the
//! [`tokio::runtime::Handle`] passed in.

use std::future::Future;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use candor_safefs::SlotTime;
use rustix::net::SocketFlags;
use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_peercred};

use crate::deletion::{CoreReplyHasher, DeletionSigner, ReplyObjectHasher};
use crate::error::StoreError;
use crate::proto::{
    AccountInfo, AccountUpsert, CommitGroup, Delete, ErrorCode, MAX_FRAME_LEN, Op, Request,
    Response, Role, decode_request, encode_response,
};
use crate::sockio::{recv_datagram, send_bytes};
use crate::staged::StagedReceiver;
use crate::store::IntakeStore;
use crate::types::{
    AccountId, BlobId, ChannelId, CommitEnvelope, Day, GroupObject, LookupTag, MailboxId,
    NewAccount, PartRef, ReplyRef,
};

/// Day and slot source for the server (the integrator's independent time;
/// `None` = the check failed, the server fails closed with `UNAVAILABLE`).
pub trait StoreClock: Send + Sync {
    /// Today's UTC day.
    fn today(&self) -> Option<Day>;
    /// The current slot for blob file times (`candor-safefs`).
    fn slot(&self) -> Option<SlotTime>;
}

/// Server configuration. All uids are explicit; two roles may not share one.
/// Connection caps are per role (ADR-057(5), AUD-RM2-IPC-05): a flooding web
/// tier cannot starve the sealer.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UID of the web service (role `web`).
    pub web_uid: u32,
    /// UID of the sealer (role `sealer`).
    pub sealer_uid: u32,
    /// UID of the relay exporter (role `relay`, reserved); `None` = no relay peer.
    pub relay_uid: Option<u32>,
    /// Connection cap of the web role.
    pub max_connections_web: usize,
    /// Connection cap of the sealer role.
    pub max_connections_sealer: usize,
    /// Connection cap of the relay role.
    pub max_connections_relay: usize,
    /// Idle time without a request before the connection is closed.
    pub idle_timeout: Duration,
    /// Deadline for one datagram write.
    pub io_timeout: Duration,
    /// Deadline for one store operation.
    pub op_deadline: Duration,
}

/// Default web connection cap (the web pool is 8 per process; margin for
/// several web workers).
pub const DEFAULT_MAX_CONNECTIONS_WEB: usize = 64;
/// Default sealer connection cap (one sink connection plus retries).
pub const DEFAULT_MAX_CONNECTIONS_SEALER: usize = 16;
/// Default relay connection cap.
pub const DEFAULT_MAX_CONNECTIONS_RELAY: usize = 4;
/// Default idle deadline.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Default write deadline.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Default store-operation deadline (covers a PostgreSQL commit with `fsync`).
pub const DEFAULT_OP_DEADLINE: Duration = Duration::from_secs(30);
/// Smallest accepted deadline (zero would mean "forever").
pub const MIN_TIMEOUT: Duration = Duration::from_millis(10);

impl ServerConfig {
    /// Defaults with the given role uids.
    #[must_use]
    pub fn new(web_uid: u32, sealer_uid: u32, relay_uid: Option<u32>) -> Self {
        Self {
            web_uid,
            sealer_uid,
            relay_uid,
            max_connections_web: DEFAULT_MAX_CONNECTIONS_WEB,
            max_connections_sealer: DEFAULT_MAX_CONNECTIONS_SEALER,
            max_connections_relay: DEFAULT_MAX_CONNECTIONS_RELAY,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            op_deadline: DEFAULT_OP_DEADLINE,
        }
    }

    /// Distinct role uids, non-zero caps and deadlines ≥ [`MIN_TIMEOUT`].
    pub fn validate(&self) -> Result<(), StoreError> {
        let bad = StoreError::InvalidInput("server config");
        if self.web_uid == self.sealer_uid
            || self.relay_uid == Some(self.web_uid)
            || self.relay_uid == Some(self.sealer_uid)
            || self.max_connections_web == 0
            || self.max_connections_sealer == 0
            || self.max_connections_relay == 0
            || self.idle_timeout < MIN_TIMEOUT
            || self.io_timeout < MIN_TIMEOUT
            || self.op_deadline < MIN_TIMEOUT
        {
            return Err(bad);
        }
        Ok(())
    }

    fn cap(&self, role: Role) -> usize {
        match role {
            Role::Web => self.max_connections_web,
            Role::Sealer => self.max_connections_sealer,
            Role::Relay => self.max_connections_relay,
        }
    }

    fn role_of(&self, uid: u32) -> Option<Role> {
        if uid == self.web_uid {
            Some(Role::Web)
        } else if uid == self.sealer_uid {
            Some(Role::Sealer)
        } else if self.relay_uid == Some(uid) {
            Some(Role::Relay)
        } else {
            None
        }
    }
}

/// The server. Share it as an `Arc` between the accept loop and the
/// slot-boundary maintenance (which uses the same [`StagedReceiver`]).
pub struct IstoreServer<S: IntakeStore + 'static> {
    store: Arc<S>,
    receiver: Arc<StagedReceiver>,
    signer: Arc<dyn DeletionSigner>,
    clock: Arc<dyn StoreClock>,
    cfg: ServerConfig,
    rt: tokio::runtime::Handle,
    /// Live connections per role (web, sealer, relay).
    connections: [AtomicUsize; 3],
    accept_errors: AtomicU64,
    refused: AtomicU64,
}

fn role_index(role: Role) -> usize {
    match role {
        Role::Web => 0,
        Role::Sealer => 1,
        Role::Relay => 2,
    }
}

impl<S: IntakeStore + 'static> core::fmt::Debug for IstoreServer<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IstoreServer")
    }
}

const BACKOFF_MIN: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

fn map_err(e: StoreError) -> ErrorCode {
    match e {
        StoreError::NotFound => ErrorCode::NotFound,
        StoreError::InvalidInput(_)
        | StoreError::DuplicateEnvelope
        | StoreError::AccountExists
        | StoreError::TenantMismatch
        | StoreError::Replay
        | StoreError::Rollback(_)
        | StoreError::Conflict(_)
        | StoreError::DeletionList(_)
        | StoreError::QuotaExceeded => ErrorCode::Invalid,
        StoreError::RestorePending
        | StoreError::NotInitialized
        | StoreError::Backend
        | StoreError::Timeout => ErrorCode::Unavailable,
        StoreError::Capacity => ErrorCode::Busy,
        StoreError::Integrity(_) | StoreError::Rng | StoreError::Signer => ErrorCode::Internal,
    }
}

fn err(c: ErrorCode) -> Response {
    Response::Error(c)
}

/// What a connection does after a request.
enum After {
    Keep,
    Close,
    /// `COMMIT_GROUP` accepted: perform the hand-over next.
    HandOver(Box<CommitGroup>),
}

impl<S: IntakeStore + 'static> IstoreServer<S> {
    /// Build a server; `cfg` is validated.
    pub fn new(
        store: Arc<S>,
        receiver: Arc<StagedReceiver>,
        signer: Arc<dyn DeletionSigner>,
        clock: Arc<dyn StoreClock>,
        cfg: ServerConfig,
        rt: tokio::runtime::Handle,
    ) -> Result<Self, StoreError> {
        cfg.validate()?;
        Ok(Self {
            store,
            receiver,
            signer,
            clock,
            cfg,
            rt,
            connections: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            accept_errors: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        })
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// The hand-over receiver (for the integrator's slot-boundary sweep).
    #[must_use]
    pub fn receiver(&self) -> &Arc<StagedReceiver> {
        &self.receiver
    }

    /// Connections currently served (all roles).
    #[must_use]
    pub fn connections(&self) -> usize {
        self.connections
            .iter()
            .fold(0usize, |a, c| a.saturating_add(c.load(Ordering::Relaxed)))
    }

    /// Peer credentials and the role cap, checked before any thread is
    /// spawned or capacity consumed (ADR-057(5)): an unknown uid or a role
    /// over its cap is closed without a byte and counted in `refused`. On
    /// `Some`, the role's slot is taken and must be released with
    /// [`Self::release`].
    fn admit(&self, sock: &OwnedFd) -> Option<Role> {
        let role = socket_peercred(sock)
            .ok()
            .and_then(|c| self.cfg.role_of(c.uid.as_raw()))?;
        let counter = self.connections.get(role_index(role))?;
        let prev = counter.fetch_add(1, Ordering::AcqRel);
        if prev >= self.cfg.cap(role) {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(role)
    }

    fn release(&self, role: Role) {
        if let Some(c) = self.connections.get(role_index(role)) {
            c.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// `accept()` failures so far (health counter, no detail).
    #[must_use]
    pub fn accept_errors(&self) -> u64 {
        self.accept_errors.load(Ordering::Relaxed)
    }

    /// Connections refused (unknown uid or over the cap).
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Accept loop over a bound, listening `SOCK_SEQPACKET` descriptor
    /// (systemd `ListenSequentialPacket=`). Blocks; returns only if the
    /// listener itself is unusable in a non-transient way (never for `EMFILE`
    /// or `EAGAIN`-class errors, which back off).
    pub fn serve(self: &Arc<Self>, listener: OwnedFd) -> std::io::Result<()> {
        let mut backoff = BACKOFF_MIN;
        loop {
            let sock = match rustix::net::accept_with(&listener, SocketFlags::CLOEXEC) {
                Ok(s) => {
                    backoff = BACKOFF_MIN;
                    s
                }
                Err(rustix::io::Errno::BADF | rustix::io::Errno::INVAL) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
                }
                Err(_) => {
                    self.accept_errors.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(backoff);
                    backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
                    continue;
                }
            };
            // Peer check and role cap first: no thread for an unknown uid or
            // an over-cap peer (AUD-RM2-IPC-05).
            let Some(role) = self.admit(&sock) else {
                self.refused.fetch_add(1, Ordering::Relaxed);
                drop(sock);
                continue;
            };
            let me = Arc::clone(self);
            if std::thread::Builder::new()
                .spawn(move || me.serve_admitted(sock, role))
                .is_err()
            {
                self.release(role);
                self.accept_errors.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(backoff);
                backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
            }
        }
    }

    /// Serve one accepted connection to completion (blocking): peer check
    /// and role cap ([`Self::admit`]), then the request loop.
    pub fn serve_connection(&self, sock: OwnedFd) {
        let Some(role) = self.admit(&sock) else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.serve_admitted(sock, role);
    }

    /// The request loop of an admitted connection; releases the role slot.
    fn serve_admitted(&self, sock: OwnedFd, role: Role) {
        if set_socket_timeout(&sock, Timeout::Send, Some(self.cfg.io_timeout)).is_ok() {
            self.connection(&sock, role);
        }
        self.release(role);
    }

    fn connection(&self, sock: &OwnedFd, role: Role) {
        let mut buf = vec![0u8; MAX_FRAME_LEN.saturating_add(1)];
        // `MAILBOX_READ` budget, granted by `MAILBOX_LIST`: at most the listed
        // replies per list, so a page view costs one list plus ≤ 32 single-row
        // reads (AUD-RM2-IPC-07).
        let mut read_budget: u32 = 0;
        loop {
            if set_socket_timeout(sock, Timeout::Recv, Some(self.cfg.idle_timeout)).is_err() {
                return;
            }
            let n = match recv_datagram(sock.as_fd(), &mut buf) {
                Ok(Some(n)) => n,
                // EOF or idle timeout: close quietly.
                Ok(None) => return,
                Err(()) => {
                    let _ = send(sock, Op::ServingAllowed, 0, &err(ErrorCode::BadFrame));
                    return;
                }
            };
            let Some(data) = buf.get(..n) else { return };
            let Ok((rid, req)) = decode_request(data) else {
                let _ = send(sock, Op::ServingAllowed, 0, &err(ErrorCode::BadFrame));
                return;
            };
            let op = req.op();
            if op.role() != role || op.is_relay() {
                let _ = send(sock, op, rid, &err(ErrorCode::Forbidden));
                return;
            }
            let (resp, after) = self.handle(req, &mut read_budget);
            if send(sock, op, rid, &resp).is_err() {
                return;
            }
            match after {
                After::Keep => {}
                After::Close => return,
                After::HandOver(g) => {
                    if self.hand_over(sock, &g).is_err() {
                        return;
                    }
                }
            }
        }
    }

    fn block<T>(&self, fut: impl Future<Output = Result<T, StoreError>>) -> Result<T, StoreError> {
        let d = self.cfg.op_deadline;
        // The timer is created inside the runtime context (block_on enters it).
        self.rt
            .block_on(async { tokio::time::timeout(d, fut).await })
            .unwrap_or(Err(StoreError::Timeout))
    }

    fn handle(&self, req: Request, read_budget: &mut u32) -> (Response, After) {
        match req {
            Request::ServingAllowed => (
                match self.block(self.store.serving_allowed()) {
                    Ok(b) => Response::ServingAllowed(b),
                    Err(e) => err(map_err(e)),
                },
                After::Keep,
            ),
            Request::AccountLookup { tag } => (
                match self.block(self.store.lookup_account(&LookupTag(tag))) {
                    Ok(a) => Response::Account(a.map(|a| AccountInfo {
                        account_id: a.account_id.0,
                        auth_pk: a.auth_pk,
                        prefs_ct: a.prefs_ct,
                    })),
                    Err(e) => err(map_err(e)),
                },
                After::Keep,
            ),
            Request::MailboxList { account } => (
                match self.block(self.store.mailbox_list(AccountId(account))) {
                    Ok(v) => {
                        *read_budget = u32::try_from(v.len()).unwrap_or(u32::MAX);
                        Response::MailboxList(
                            v.iter()
                                .map(|r| crate::proto::ReplyHeader {
                                    reply_ref: r.reply_ref.0,
                                    slot: r.slot,
                                    size_bucket: r.size_bucket,
                                    available_day: r.available_day.0,
                                })
                                .collect(),
                        )
                    }
                    Err(e) => err(map_err(e)),
                },
                After::Keep,
            ),
            Request::MailboxRead { account, reply } => {
                if *read_budget == 0 {
                    return (err(ErrorCode::Busy), After::Keep);
                }
                *read_budget = read_budget.saturating_sub(1);
                (
                    match self.block(self.store.reply(AccountId(account), ReplyRef(reply))) {
                        Ok(Some(r)) => Response::ReplyCt(r.reply_ct),
                        Ok(None) => err(ErrorCode::NotFound),
                        Err(e) => err(map_err(e)),
                    },
                    After::Keep,
                )
            }
            Request::CommitGroup(g) => match self.check_group(&g) {
                Ok(()) => (Response::Empty, After::HandOver(g)),
                Err(c) => (err(c), After::Keep),
            },
            Request::AccountUpsert(a) => (
                match self.upsert(&a) {
                    Ok(()) => Response::Empty,
                    Err(c) => err(c),
                },
                After::Keep,
            ),
            Request::Delete(d) => (
                match self.delete(&d) {
                    Ok(n) => Response::Deleted(n),
                    Err(c) => err(c),
                },
                After::Keep,
            ),
            Request::Relay(_) => (err(ErrorCode::Forbidden), After::Close),
        }
    }

    /// Pre-checks before the bundle is accepted: the sealer's day must be
    /// within one day of ours (ADR-010: days only), the store must be serving.
    fn check_group(&self, g: &CommitGroup) -> Result<(), ErrorCode> {
        let today = self.clock.today().ok_or(ErrorCode::Unavailable)?;
        if today.0.abs_diff(g.received_day) > 1 {
            return Err(ErrorCode::Invalid);
        }
        match self.block(self.store.serving_allowed()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ErrorCode::Unavailable),
            Err(e) => Err(map_err(e)),
        }
    }

    /// The staged hand-over for an accepted group: receive the bundle, store
    /// the inline objects, commit, acknowledge. Any failure refuses (the
    /// receiver's `0x00`) and closes the connection; blobs left behind are
    /// swept at the slot boundary.
    fn hand_over(&self, sock: &OwnedFd, g: &CommitGroup) -> Result<(), ()> {
        let slot = self.clock.slot().ok_or(())?;
        let blob = self.receiver.receive(sock.as_fd(), slot).map_err(|_| ())?;
        if blob.len() != g.bundle.padded_size {
            let _ = self.receiver.refuse(sock.as_fd());
            return Err(());
        }
        let put = |bytes: &[u8]| -> Result<PartRef, ()> {
            let id = self
                .receiver
                .blobs()
                .put_random(bytes, slot)
                .map_err(|_| ())?;
            Ok(PartRef {
                blob_id: BlobId(*id.as_bytes()),
                padded_size: u64::try_from(bytes.len()).map_err(|_| ())?,
            })
        };
        let parts = (|| -> Result<(PartRef, PartRef), ()> {
            Ok((put(&g.main.bytes)?, put(&g.identity.bytes)?))
        })();
        let Ok((main_ref, identity_ref)) = parts else {
            let _ = self.receiver.refuse(sock.as_fd());
            return Err(());
        };
        let env = CommitEnvelope {
            channel_id: ChannelId(g.channel_id),
            objects: [
                GroupObject {
                    object_hash: g.main.object_hash,
                    slot_block: g.main.slot_block.clone(),
                    blob: main_ref,
                },
                GroupObject {
                    object_hash: g.bundle.object_hash,
                    slot_block: g.bundle.slot_block.clone(),
                    blob: PartRef {
                        blob_id: blob.blob_id(),
                        padded_size: blob.len(),
                    },
                },
                GroupObject {
                    object_hash: g.identity.object_hash,
                    slot_block: g.identity.slot_block.clone(),
                    blob: identity_ref,
                },
            ],
            disposition_ct: g.disposition_ct.clone(),
            epoch_index: g.epoch_index,
            received_date: Day(g.received_day),
            release_offset_days: g.release_offset_days,
        };
        let committed = self.block(self.receiver.commit_staged(&*self.store, env, blob));
        match committed {
            Ok(token) => self
                .receiver
                .acknowledge(sock.as_fd(), token)
                .map_err(|_| ()),
            Err(_) => {
                let _ = self.receiver.refuse(sock.as_fd());
                Err(())
            }
        }
    }

    /// Create or replace an account (idempotent on retry: a create whose tag
    /// exists, or a replacement whose old tag is gone while the new one
    /// exists, is a success), then the re-wrapped reply stanzas.
    fn upsert(&self, a: &AccountUpsert) -> Result<(), ErrorCode> {
        let today = self.clock.today().ok_or(ErrorCode::Unavailable)?;
        let new = NewAccount {
            lookup_tag: LookupTag(a.lookup_tag),
            auth_pk: a.auth_pk,
            xwing_pk: a.xwing_pk.clone(),
            prefs_ct: a.prefs_ct.clone(),
            mailbox_ids: a.mailbox_ids.iter().map(|m| MailboxId(*m)).collect(),
        };
        let lookup = |tag: [u8; 32]| self.block(self.store.lookup_account(&LookupTag(tag)));
        let account = match a.replaces {
            None => match self.block(self.store.create_account(new, today)) {
                Ok(id) => id,
                Err(StoreError::AccountExists) => {
                    lookup(a.lookup_tag)
                        .map_err(map_err)?
                        .ok_or(ErrorCode::Internal)?
                        .account_id
                }
                Err(e) => return Err(map_err(e)),
            },
            Some(old) => match lookup(old).map_err(map_err)? {
                Some(cur) => {
                    self.block(self.store.update_account(cur.account_id, new))
                        .map_err(map_err)?;
                    cur.account_id
                }
                // Already replaced by an earlier attempt (the new tag exists),
                // else there is nothing to replace.
                None => {
                    lookup(a.lookup_tag)
                        .map_err(map_err)?
                        .ok_or(ErrorCode::NotFound)?
                        .account_id
                }
            },
        };
        if !a.rewrapped.is_empty() {
            self.block(self.store.rewrap_replies(account, &a.rewrapped))
                .map_err(map_err)?;
        }
        Ok(())
    }

    /// K31-signed deletions (04 §18.6; 08 SW-14/SW-15). Returns the number
    /// of deletion-list entries appended.
    fn delete(&self, d: &Delete) -> Result<u32, ErrorCode> {
        let today = self.clock.today().ok_or(ErrorCode::Unavailable)?;
        let signer: &dyn DeletionSigner = &*self.signer;
        let account_of = |tag: &[u8; 32]| -> Result<AccountId, ErrorCode> {
            self.block(self.store.lookup_account(&LookupTag(*tag)))
                .map_err(map_err)?
                .map(|a| a.account_id)
                .ok_or(ErrorCode::NotFound)
        };
        match d {
            Delete::Account { lookup_tags } => {
                // Every tag that resolves (current and previous, ADR-057(3));
                // each account goes in one transaction with its `mailbox`
                // entries and the `account` entry (ADR-057(1)/(2)).
                let mut targets: Vec<(AccountId, u32)> = Vec::with_capacity(lookup_tags.len());
                for t in lookup_tags {
                    if let Some(a) = self
                        .block(self.store.lookup_account(&LookupTag(*t)))
                        .map_err(map_err)?
                        && !targets.iter().any(|(id, _)| *id == a.account_id)
                    {
                        let entries = u32::try_from(a.mailbox_ids.len().saturating_add(1))
                            .unwrap_or(u32::MAX);
                        targets.push((a.account_id, entries)); // safefs-lint: allow(Vec::push of an id tuple, no path)
                    }
                }
                if targets.is_empty() {
                    return Err(ErrorCode::NotFound);
                }
                let mut n = 0u32;
                for (account, entries) in targets {
                    self.block(self.store.delete_account(account, today, signer))
                        .map_err(map_err)?;
                    n = n.saturating_add(entries);
                }
                Ok(n)
            }
            Delete::Mailbox {
                lookup_tag,
                mailbox_id,
            } => {
                let account = account_of(lookup_tag)?;
                let refs: Vec<ReplyRef> = self
                    .block(self.store.mailbox_list(account))
                    .map_err(map_err)?
                    .iter()
                    .map(|r| r.reply_ref)
                    .collect();
                self.block(self.store.delete_mailbox(
                    account,
                    &MailboxId(*mailbox_id),
                    &refs,
                    today,
                    signer,
                ))
                .map_err(map_err)?;
                Ok(1)
            }
            Delete::Replies {
                lookup_tag,
                replies,
            } => {
                let account = account_of(lookup_tag)?;
                let mailbox = self
                    .block(self.store.mailbox_list(account))
                    .map_err(map_err)?;
                let mut pairs: Vec<(ReplyRef, [u8; 32])> = Vec::with_capacity(replies.len());
                for r in replies {
                    let Some(stored) = mailbox.iter().find(|s| s.reply_ref.0 == *r) else {
                        // Unknown or already deleted: nothing to do (idempotent).
                        continue;
                    };
                    if pairs.iter().any(|(p, _)| p.0 == *r) {
                        continue;
                    }
                    // The hash is what the deletion list carries; a reply
                    // whose SealedObject does not parse cannot be listed and
                    // is refused rather than deleted unlisted (fail closed).
                    let h = CoreReplyHasher
                        .object_hash(&stored.reply_ct)
                        .ok_or(ErrorCode::Internal)?;
                    pairs.push((stored.reply_ref, h));
                }
                if pairs.is_empty() {
                    return Ok(0);
                }
                self.block(self.store.delete_replies(account, &pairs, today, signer))
                    .map_err(map_err)
            }
        }
    }
}

fn send(sock: &OwnedFd, op: Op, rid: u32, resp: &Response) -> Result<(), ()> {
    let bytes = encode_response(op, rid, resp)
        .or_else(|_| encode_response(op, rid, &err(ErrorCode::Internal)))
        .map_err(|_| ())?;
    send_bytes(sock.as_fd(), &bytes)
}
