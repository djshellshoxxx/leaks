// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real sealer + real intake store over `istore.sock` (socketpairs): the
//! `IstoreSink` commits groups with the staged hand-over, writes accounts,
//! and runs `DELETE_REPLIES` / `CLOSE_MAILBOX` end to end against
//! `IstoreServer` over `MemoryStore` with the K31 signer (O-1/O-2 of the web
//! SPEC-NOTES). AUD-RM2-SEA-01 / WEB-13: a connection cut after the store's
//! "copied" acknowledgement is retried on a fresh connection and the already
//! landed commit is reported as success with exactly one envelope.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Test fixture only: a private 0700 temp root for candor-safefs.
    clippy::disallowed_methods
)]
mod common;

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use candor_intake_store::client::Connector;
use candor_intake_store::deletion::DeletionKind;
use candor_intake_store::server::{IstoreServer, ServerConfig, StoreClock};
use candor_intake_store::staged::{STAGED_ACK_COPIED, STAGED_ACK_LEN, StagedReceiver};
use candor_intake_store::{Day, IntakeStore, LookupTag, MemoryStore, RandomDummyReplies};
use candor_safefs::{RootPolicy, SafeRoot, SlotTime};
use candor_sealer::proto::*;
use candor_sealer::server::istore::IstoreSink;
use candor_sealer::server::sink::{DeleteOutcome, EnvelopeSink, SinkError};
use candor_sealer::server::{ChaffConfig, Limits};
use common::kdlog::MemberEpochKey;
use common::*;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, Shutdown, SocketFlags, SocketType,
};

const T: Duration = Duration::from_secs(2);
const TENANT_ID: candor_intake_store::TenantId = candor_intake_store::TenantId(TENANT);

struct Clock;
impl StoreClock for Clock {
    fn today(&self) -> Option<Day> {
        Some(Day(TODAY))
    }
    fn slot(&self) -> Option<SlotTime> {
        SlotTime::from_unix_secs(u64::from(TODAY) * 86_400).ok()
    }
}

fn pair() -> (OwnedFd, OwnedFd) {
    rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap()
}

/// Forward one datagram (with any descriptors) from `from` to `to`; returns
/// the bytes, or `None` at EOF/error.
fn forward(from: BorrowedFd<'_>, to: BorrowedFd<'_>) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 210_000];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let m = rustix::net::recvmsg(
        from,
        &mut [IoSliceMut::new(&mut buf)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .ok()?;
    if m.bytes == 0 {
        return None;
    }
    let mut fds: Vec<OwnedFd> = Vec::new();
    for c in control.drain() {
        if let RecvAncillaryMessage::ScmRights(r) = c {
            fds.extend(r);
        }
    }
    let data = buf[..m.bytes].to_vec();
    let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
    let mut sspace = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut sc = SendAncillaryBuffer::new(&mut sspace);
    if !borrowed.is_empty() {
        assert!(sc.push(SendAncillaryMessage::ScmRights(&borrowed)));
    }
    rustix::net::sendmsg(to, &[IoSlice::new(&data)], &mut sc, SendFlags::NOSIGNAL).ok()?;
    Some(data)
}

struct Env {
    _tmp: tempfile::TempDir,
    server: Arc<IstoreServer<MemoryStore>>,
    /// Cut the next connection right after the store's `0x02` (once).
    chaos: Arc<AtomicBool>,
    cuts: Arc<AtomicUsize>,
}

impl Env {
    async fn new() -> Env {
        use std::os::unix::fs::DirBuilderExt;
        let tmp = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(tmp.path()).unwrap().join("blobs");
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        let root = SafeRoot::open(&p, RootPolicy::BlobStore).unwrap();
        let me = rustix_uid();
        let mut cfg = ServerConfig::new(me.wrapping_add(1000), me, None);
        cfg.io_timeout = T;
        cfg.idle_timeout = Duration::from_secs(30);
        let rx = StagedReceiver::new(root, me, 64 << 20)
            .unwrap()
            .with_timeout(T);
        let store = Arc::new(
            MemoryStore::with_config(
                candor_intake_store::MEMORY_DEADDROP_CONFIG,
                Box::new(RandomDummyReplies),
            )
            .unwrap(),
        );
        store.init(TENANT_ID, [0x5a; 32]).await.unwrap();
        let signer = candor_intake_store::Ed25519DeletionSigner::new(
            candor_core::sig::SigningKey::from_seed(&[0x31; 32]),
        );
        let server = Arc::new(
            IstoreServer::new(
                store,
                Arc::new(rx),
                Arc::new(signer),
                Arc::new(Clock),
                cfg,
                tokio::runtime::Handle::current(),
            )
            .unwrap(),
        );
        Env {
            _tmp: tmp,
            server,
            chaos: Arc::new(AtomicBool::new(false)),
            cuts: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn store(&self) -> &Arc<MemoryStore> {
        self.server.store()
    }

    /// Connector: a direct socketpair to a server thread, or, while `chaos`
    /// is set, a proxy pair that cuts the sealer side after the first
    /// "copied" acknowledgement (the store then commits unobserved).
    fn connector(&self) -> Connector {
        let s = Arc::clone(&self.server);
        let chaos = Arc::clone(&self.chaos);
        let cuts = Arc::clone(&self.cuts);
        Arc::new(move || {
            let (a, b) = pair();
            let s2 = Arc::clone(&s);
            std::thread::spawn(move || s2.serve_connection(b));
            if !chaos.swap(false, Ordering::SeqCst) {
                return Ok(a);
            }
            // Proxy: sealer <-> p | q <-> server(a).
            let (p, q) = pair();
            let q = Arc::new(q);
            let a = Arc::new(a);
            let (q1, a1) = (Arc::clone(&q), Arc::clone(&a));
            std::thread::spawn(move || {
                while forward(q1.as_fd(), a1.as_fd()).is_some() {}
                let _ = rustix::net::shutdown(&*a1, Shutdown::Both);
            });
            let cuts = Arc::clone(&cuts);
            std::thread::spawn(move || {
                while let Some(d) = forward(a.as_fd(), q.as_fd()) {
                    if d.len() == STAGED_ACK_LEN && d[0] == STAGED_ACK_COPIED {
                        cuts.fetch_add(1, Ordering::SeqCst);
                        let _ = rustix::net::shutdown(&*q, Shutdown::Both);
                        // Keep the server side alive: the commit proceeds.
                        while forward(a.as_fd(), q.as_fd()).is_some() {}
                        return;
                    }
                }
            });
            Ok(p)
        })
    }
}

fn fixture_for(env: &Env) -> Fixture {
    let sink = Arc::new(
        IstoreSink::new(env.connector(), T).with_handover_deadlines(T, Duration::from_secs(5)),
    );
    fixture_with_sink(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
        rustix_uid(),
        Some(sink),
        |snap| {
            let ch = &mut snap.channels[0];
            let base: Vec<MemberEpochKey> = ch.meks.clone();
            for e in 1..=3u32 {
                for k in &base {
                    ch.meks.push(MemberEpochKey {
                        epoch_id: e,
                        valid_from_day: TODAY - 2 + 7 * e,
                        valid_until_day: TODAY - 2 + 7 * (e + 1),
                        ..k.clone()
                    });
                }
            }
        },
    )
}

/// Draft, generate and confirm; returns the passphrase.
async fn confirmed_phrase(f: &Fixture, s: SessionHandle) -> String {
    let sl = &f.sealer;
    ok(
        sl,
        Request::Hello {
            proto: PROTO_VERSION,
        },
    )
    .await;
    ok(
        sl,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    ok(
        sl,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new("report"),
            fields: vec![],
            identity: None,
            coi: None,
        }),
    )
    .await;
    let Response::Part { part } = ok(
        sl,
        Request::PartBegin {
            sess: s,
            declared_len: 3000,
            display_name: SecretText::new("a.bin"),
            media_type: SecretText::new("application/octet-stream"),
        },
    )
    .await
    else {
        panic!()
    };
    ok(
        sl,
        Request::PartChunk {
            sess: s,
            part,
            data: SecretBytes::from_slice(&[7u8; 3000]),
            last: true,
        },
    )
    .await;
    let Response::Words {
        words,
        confirm_positions,
    } = ok(sl, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
    let phrase = words_to_phrase(&words);
    let Response::Confirm { ok: true, .. } = ok(
        sl,
        Request::ConfirmPassphrase {
            sess: s,
            words: confirm_words(&words, confirm_positions),
        },
    )
    .await
    else {
        panic!()
    };
    phrase
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealer_commits_accounts_signals_and_deletions_through_the_store() {
    let env = Env::new().await;
    let f = fixture_for(&env);
    let store = env.store();
    let s = sess(1);
    let phrase = confirmed_phrase(&f, s).await;
    // SEA-01 / WEB-13: the first hand-over is cut after "copied"; the
    // sealer retries on a fresh connection; one envelope, reported sealed.
    env.chaos.store(true, Ordering::SeqCst);
    let Response::Sealed { .. } = ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(env.cuts.load(Ordering::SeqCst), 1);
    assert_eq!(store.pending_count().await.unwrap(), 1);
    // The account reaches the store with the batch flush.
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    // Log in through the real store row.
    let l = sess(2);
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: l,
            passphrase: SecretBytes::from_slice(phrase.as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    let row = store
        .lookup_account(&LookupTag(lookup_tag))
        .await
        .unwrap()
        .expect("account written through istore");
    assert_eq!(row.xwing_pk.len(), 1216);
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l,
            prefs_ct: row.prefs_ct.clone(),
        },
    )
    .await;
    // SW-14: a reply in the mailbox (pushed by the relay) is deleted with a
    // K31-signed entry.
    let (ct, _) = reply_ct_for(&row.account_id);
    store.apply_replies(Day(TODAY), vec![ct]).await.unwrap();
    let mb = store.mailbox_list(row.account_id).await.unwrap();
    assert_eq!(mb.len(), 1);
    let r = ok(
        &f.sealer,
        Request::DeleteReplies {
            sess: l,
            replies: vec![mb[0].reply_ref.0],
        },
    )
    .await;
    assert_eq!(r, Response::Deleted { count: 1 });
    assert!(store.mailbox_list(row.account_id).await.unwrap().is_empty());
    // SW-15: the mailbox-closed signal is committed, then the account goes
    // with `mailbox` + `account` entries; the session ends.
    let Response::Sealed {
        release_offset_days,
    } = ok(&f.sealer, Request::CloseMailbox { sess: l }).await
    else {
        panic!()
    };
    assert!((3..=21).contains(&release_offset_days));
    assert_eq!(store.pending_count().await.unwrap(), 2);
    assert!(
        store
            .lookup_account(&LookupTag(lookup_tag))
            .await
            .unwrap()
            .is_none()
    );
    let list = store.deletion_list_after(0, 100).await.unwrap();
    let kinds: Vec<DeletionKind> = list.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            DeletionKind::Reply,
            DeletionKind::Mailbox,
            DeletionKind::Account
        ]
    );
    candor_intake_store::deletion::verify_chain(
        &list,
        &candor_core::sig::SigningKey::from_seed(&[0x31; 32]).verifying_key_bytes(),
        None,
    )
    .unwrap();
    let r = f.sealer.handle(Request::Touch { sess: l }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
    // The old passphrase no longer logs in to anything.
    let Response::Locator { lookup_tag: again } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: sess(3),
            passphrase: SecretBytes::from_slice(phrase.as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(again, lookup_tag);
    assert!(
        store
            .lookup_account(&LookupTag(again))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_store_is_unavailable_and_commits_fail_closed() {
    let failing: Connector = Arc::new(|| Err(std::io::Error::from(std::io::ErrorKind::Other)));
    let sink = IstoreSink::new(failing, T);
    assert!(!sink.is_available());
    assert_eq!(sink.delete_replies([1; 32], &[]), Err(SinkError));
    assert_eq!(sink.delete_account(&[[1; 32]]), Err(SinkError));
    // A reachable store: available, and a deletion for an unknown account
    // is a NotFound the account path treats as done, the reply path not.
    let env = Env::new().await;
    let sink = IstoreSink::new(env.connector(), T);
    assert!(sink.is_available());
    assert_eq!(
        sink.delete_account(&[[1; 32], [2; 32]]),
        Ok(DeleteOutcome::NotFound)
    );
    assert_eq!(sink.delete_replies([1; 32], &[[3; 16]]), Err(SinkError));
    assert_eq!(
        env.store().deletion_list_after(0, 10).await.unwrap().len(),
        0
    );
}

/// A REPLY with a real SealedObject for `account` (bucket 1).
fn reply_ct_for(
    account: &candor_intake_store::AccountId,
) -> (candor_intake_store::IncomingReply, [u8; 32]) {
    use candor_core::header::ObjectType;
    use candor_core::object::{SealRequest, seal_bytes};
    let req = SealRequest {
        suite: candor_core::Suite::CandorStd1,
        object_type: ObjectType::Reply,
        tenant_id: TENANT,
        channel_id: [0; 16],
        epoch_id: 0,
        day_stamp: 0,
        recipients: None,
        padded_len: 4096,
    };
    let (_ck, obj) = seal_bytes(&req, &[1u8; 4096]).unwrap();
    let total = candor_intake_store::reply_ct_len(1).unwrap();
    let mut ct = obj.bytes.clone();
    ct.resize(total, 0xAA);
    (
        candor_intake_store::IncomingReply {
            account: Some(*account),
            mailbox_id: Some(candor_intake_store::MailboxId([1; 32])),
            object_hash: obj.object_hash,
            reply_ct: ct,
            size_bucket: 1,
        },
        obj.object_hash,
    )
}

// ---------------------------------------------------------------------------
// AUD-RM2-IPC-10/11 (round 2): a store outage never loses an account write.

/// Clear restore-pending on the store the way RL-12 does (empty verified push).
async fn clear_restore(store: &MemoryStore) {
    let core = candor_core::sig::SigningKey::from_seed(&[0x77; 32]);
    let head =
        candor_intake_store::SignedDeletionHead::sign(&TENANT_ID, None, Day(TODAY), 1, &core);
    store
        .apply_pushed_deletion_list(
            &[],
            &head,
            &core.verifying_key_bytes(),
            &candor_core::sig::SigningKey::from_seed(&[0x31; 32]).verifying_key_bytes(),
            &candor_intake_store::CoreReplyHasher,
            Day(TODAY),
        )
        .await
        .unwrap();
}

struct Counting {
    dropped: std::sync::atomic::AtomicU64,
    backlog: std::sync::atomic::AtomicU64,
}
impl candor_sealer::server::HealthSink for Counting {
    fn account_write_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
    fn account_backlog(&self, _queued: usize) {
        self.backlog.fetch_add(1, Ordering::SeqCst);
    }
}

/// IPC-10 (auditor's PoC, red → green): the store answers `UNAVAILABLE`
/// (restore-pending) for three flushes; the create stays queued with
/// backoff and a backlog health event, is never dead-lettered, and lands as
/// soon as the store serves again: the passphrase logs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_store_keeps_account_writes_queued() {
    let env = Env::new().await;
    let f = fixture_for(&env);
    let health = Arc::new(Counting {
        dropped: std::sync::atomic::AtomicU64::new(0),
        backlog: std::sync::atomic::AtomicU64::new(0),
    });
    f.sealer.set_health_sink(health.clone());
    let s = sess(1);
    let phrase = confirmed_phrase(&f, s).await;
    let Response::Sealed { .. } = ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(f.sealer.queued_accounts(), 1);
    env.store().mark_restore_pending().await.unwrap();
    // Three scheduled flushes during the outage: the first fails and starts
    // the backoff, the next is skipped, then another attempt fails.
    assert_eq!(f.sealer.flush_accounts(), Err(SinkError));
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    assert_eq!(f.sealer.flush_accounts(), Err(SinkError));
    assert_eq!(f.sealer.queued_accounts(), 1, "still queued");
    assert_eq!(f.sealer.dead_letters(), 0);
    assert_eq!(health.dropped.load(Ordering::SeqCst), 0);
    assert!(
        health.backlog.load(Ordering::SeqCst) >= 2,
        "backlog reported"
    );
    clear_restore(env.store()).await;
    // Backoff of two skipped flushes after the second failure, then it lands.
    let mut written = 0;
    for _ in 0..4 {
        written += f.sealer.flush_accounts().unwrap();
    }
    assert_eq!(written, 1);
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: sess(2),
            passphrase: SecretBytes::from_slice(phrase.as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    assert!(
        env.store()
            .lookup_account(&LookupTag(lookup_tag))
            .await
            .unwrap()
            .is_some(),
        "the account exists after the outage"
    );
}

/// IPC-11 (auditor's PoC, red → green): `DELETE_REPLIES` while the store is
/// restore-pending fails as "could not confirm" and leaves the queued create
/// in the queue (no silent drop, no dead letter); once the store serves, the
/// create is written and the passphrase logs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_during_outage_keeps_the_queued_create() {
    let env = Env::new().await;
    let f = fixture_for(&env);
    let health = Arc::new(Counting {
        dropped: std::sync::atomic::AtomicU64::new(0),
        backlog: std::sync::atomic::AtomicU64::new(0),
    });
    f.sealer.set_health_sink(health.clone());
    let s = sess(1);
    let phrase = confirmed_phrase(&f, s).await;
    ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await;
    env.store().mark_restore_pending().await.unwrap();
    // The session is AUTHENTICATED after SEAL_FINISH: a reply deletion and a
    // close both fail without confirming anything.
    let r = f
        .sealer
        .handle(Request::DeleteReplies {
            sess: s,
            replies: vec![],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    let r = f.sealer.handle(Request::CloseMailbox { sess: s }).await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    assert_eq!(f.sealer.queued_accounts(), 1, "create still queued");
    assert_eq!(f.sealer.dead_letters(), 0);
    assert_eq!(health.dropped.load(Ordering::SeqCst), 0);
    assert!(health.backlog.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        env.store().pending_count().await.unwrap(),
        1,
        "no signal sealed"
    );
    clear_restore(env.store()).await;
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: sess(2),
            passphrase: SecretBytes::from_slice(phrase.as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    assert!(
        env.store()
            .lookup_account(&LookupTag(lookup_tag))
            .await
            .unwrap()
            .is_some()
    );
    // The close now goes through: flush (nothing left), signal, deletion.
    let r = ok(&f.sealer, Request::CloseMailbox { sess: s }).await;
    assert!(matches!(r, Response::Sealed { .. }));
    assert!(
        env.store()
            .lookup_account(&LookupTag(lookup_tag))
            .await
            .unwrap()
            .is_none()
    );
}
