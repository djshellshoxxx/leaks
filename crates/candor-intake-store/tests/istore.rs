// SPDX-License-Identifier: AGPL-3.0-or-later
//! `istore` IPC end to end over `SOCK_SEQPACKET` socketpairs: the real
//! server (`IstoreServer` over `MemoryStore` + `StagedReceiver` + K31 signer)
//! and the real client (`Conn`, `IstoreClient`). Covers role authentication
//! (SO_PEERCRED), wrong-role and reserved ops, malformed/oversize/trailing
//! datagrams, the commit + hand-over path, the idempotent re-hand-over of an
//! already committed group (AUD-RM2-SEA-01 / WEB-13), account upserts with
//! re-wraps, and the K31 deletion op (04 §18.6, KEY-077; 08 SW-14/SW-15).
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

use std::io::{IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use candor_intake_store::client::{ClientError, Conn, Connector, IstoreClient};
use candor_intake_store::deletion::DeletionKind;
use candor_intake_store::proto::*;
use candor_intake_store::reads::StoreReads;
use candor_intake_store::server::{IstoreServer, ServerConfig, StoreClock};
use candor_intake_store::staged::{
    STAGED_ACK_COMMITTED, STAGED_ACK_COPIED, STAGED_ACK_LEN, StagedHeader, StagedReceiver,
    send_staged_bundle,
};
use candor_intake_store::*;
use candor_safefs::{RootPolicy, SafeRoot, SlotTime};
use rustix::net::{AddressFamily, RecvAncillaryBuffer, RecvFlags, SocketFlags, SocketType};
use sha2::{Digest, Sha256};

const T: Duration = Duration::from_millis(500);

struct Clock;
impl StoreClock for Clock {
    fn today(&self) -> Option<Day> {
        Some(common::TODAY)
    }
    fn slot(&self) -> Option<SlotTime> {
        SlotTime::from_unix_secs(1_790_000_100).ok()
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

fn my_uid() -> u32 {
    let (a, _b) = pair();
    rustix::net::sockopt::socket_peercred(&a)
        .unwrap()
        .uid
        .as_raw()
}

struct Env {
    _tmp: tempfile::TempDir,
    server: Arc<IstoreServer<MemoryStore>>,
}

impl Env {
    /// A server whose `role` uid is this process (the other roles get
    /// unrelated uids).
    async fn new(role: Role) -> Env {
        use std::os::unix::fs::DirBuilderExt;
        let tmp = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(tmp.path()).unwrap().join("blobs");
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        let root = SafeRoot::open(&p, RootPolicy::BlobStore).unwrap();
        let me = my_uid();
        let other = me.wrapping_add(1000);
        let (web, sealer) = match role {
            Role::Web => (me, other),
            Role::Sealer => (other, me),
            Role::Relay => (other, other.wrapping_add(1)),
        };
        let mut cfg = ServerConfig::new(web, sealer, (role == Role::Relay).then_some(me));
        cfg.idle_timeout = Duration::from_secs(2);
        cfg.io_timeout = T;
        cfg.op_deadline = Duration::from_secs(5);
        cfg.max_connections_web = 4;
        cfg.max_connections_sealer = 4;
        let rx = StagedReceiver::new(root, sealer, 8 << 20)
            .unwrap()
            .with_timeout(T);
        let store = Arc::new(
            MemoryStore::with_config(common::TEST_DEADDROP, Box::new(RandomDummyReplies)).unwrap(),
        );
        store.init(common::TENANT, common::SALT).await.unwrap();
        let server = Arc::new(
            IstoreServer::new(
                store,
                Arc::new(rx),
                Arc::new(common::signer()),
                Arc::new(Clock),
                cfg,
                tokio::runtime::Handle::current(),
            )
            .unwrap(),
        );
        Env { _tmp: tmp, server }
    }

    fn store(&self) -> &Arc<MemoryStore> {
        self.server.store()
    }

    /// A connector: each call makes a socketpair and serves one end on a
    /// thread.
    fn connector(&self) -> Connector {
        let s = Arc::clone(&self.server);
        Arc::new(move || {
            let (a, b) = pair();
            let s2 = Arc::clone(&s);
            std::thread::spawn(move || s2.serve_connection(b));
            Ok(a)
        })
    }

    fn conn(&self) -> Conn {
        Conn::new(self.connector(), T)
    }
}

fn sealed_memfd(data: &[u8]) -> OwnedFd {
    use rustix::fs::{MemfdFlags, SealFlags};
    let fd = rustix::fs::memfd_create(
        "t",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
    )
    .unwrap();
    let mut f = std::fs::File::from(fd);
    f.write_all(data).unwrap();
    let fd: OwnedFd = f.into();
    rustix::fs::fcntl_add_seals(
        &fd,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::EXEC | SealFlags::SEAL,
    )
    .unwrap();
    fd
}

fn group(seed: u8, bundle_len: u64) -> CommitGroup {
    let inline = |h: u8, n: usize| InlineObject {
        object_hash: [h; 32],
        slot_block: vec![h; SLOT_BLOCK_LEN_STD],
        bytes: vec![h; n],
    };
    CommitGroup {
        channel_id: [1; 16],
        epoch_index: 3,
        received_day: common::TODAY.0,
        release_offset_days: 2,
        disposition_ct: vec![seed; DISPOSITION_CT_LEN_STD],
        main: inline(seed, 70_000),
        bundle: BundleObject {
            object_hash: [seed.wrapping_add(1); 32],
            slot_block: vec![seed; SLOT_BLOCK_LEN_STD],
            padded_size: bundle_len,
        },
        identity: inline(seed.wrapping_add(2), 16_384),
    }
}

/// One acknowledgement datagram `code ‖ sha256`.
fn ack(sock: &OwnedFd) -> Option<(u8, [u8; 32])> {
    let mut data = [0u8; STAGED_ACK_LEN + 1];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let m = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut data)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .ok()?;
    if m.bytes != STAGED_ACK_LEN {
        return None;
    }
    Some((data[0], data[1..33].try_into().unwrap()))
}

/// The sealer side of a `COMMIT_GROUP`: frame, then hand-over, both acks.
fn commit(conn: &mut Conn, g: &CommitGroup, bundle: &[u8]) -> std::result::Result<(), ClientError> {
    match conn.call(&Request::CommitGroup(Box::new(g.clone())))? {
        Response::Empty => {}
        _ => return Err(ClientError::Transport),
    }
    let sha256: [u8; 32] = Sha256::digest(bundle).into();
    let fd = sealed_memfd(bundle);
    let sock = conn.socket().ok_or(ClientError::Transport)?;
    let hdr = StagedHeader {
        len: bundle.len() as u64,
        sha256,
    };
    send_staged_bundle(sock, &hdr, fd.as_fd()).map_err(|_| ClientError::Transport)?;
    let owned: OwnedFd = sock.try_clone_to_owned().unwrap();
    let a1 = ack(&owned).ok_or(ClientError::Transport)?;
    let a2 = ack(&owned).ok_or(ClientError::Transport)?;
    if a1 == (STAGED_ACK_COPIED, sha256) && a2 == (STAGED_ACK_COMMITTED, sha256) {
        Ok(())
    } else {
        conn.close();
        Err(ClientError::Transport)
    }
}

fn raw_send(conn: &Conn, bytes: &[u8]) {
    let sock = conn.socket().unwrap();
    let mut c = rustix::net::SendAncillaryBuffer::default();
    rustix::net::sendmsg(
        sock,
        &[std::io::IoSlice::new(bytes)],
        &mut c,
        rustix::net::SendFlags::NOSIGNAL,
    )
    .unwrap();
}

/// Expect a datagram and decode it as a response to `op`.
fn raw_recv(conn: &Conn, op: Op) -> Option<Response> {
    let sock = conn.socket().unwrap();
    let mut buf = vec![0u8; MAX_FRAME_LEN + 1];
    let mut c = rustix::net::RecvAncillaryBuffer::default();
    let m = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut buf)],
        &mut c,
        RecvFlags::empty(),
    )
    .ok()?;
    if m.bytes == 0 {
        return None;
    }
    decode_response(op, &buf[..m.bytes]).ok().map(|(_, r)| r)
}

fn closed(conn: &Conn) -> bool {
    raw_recv(conn, Op::ServingAllowed).is_none()
}

async fn account_with_replies(env: &Env, tag: u8, n: usize) -> (AccountId, Vec<[u8; 32]>) {
    let s = env.store();
    let acct = s
        .create_account(common::new_account(tag), common::TODAY)
        .await
        .unwrap();
    let mut hashes = Vec::new();
    let mut replies = Vec::new();
    for i in 0..n {
        let (r, h, _) = common::real_reply(acct, 0xA0 + i as u8);
        hashes.push(h);
        replies.push(r);
    }
    let res = s.apply_replies(common::TODAY, replies).await.unwrap();
    assert_eq!(res.accepted as usize, n);
    (acct, hashes)
}

// ----- web role -------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_reads_through_the_client() {
    let env = Env::new(Role::Web).await;
    let (acct, hashes) = account_with_replies(&env, 5, 3).await;
    let client = IstoreClient::new(env.connector(), 2, T);
    assert!(client.serving_allowed().await.unwrap());
    let tag5 = common::new_account(5).lookup_tag.0;
    let a = client.account(tag5).await.unwrap().unwrap();
    assert_eq!(a.account_id, acct);
    assert_eq!(a.auth_pk, common::new_account(5).auth_pk);
    assert!(client.account([0xEE; 32]).await.unwrap().is_none());
    let mb = client.mailbox(acct).await.unwrap();
    assert_eq!(mb.len(), 3);
    let direct = env.store().mailbox_list(acct).await.unwrap();
    assert_eq!(mb, direct);
    assert_eq!(hashes.len(), 3);
    // Unknown account: empty mailbox view (the store returns no rows).
    assert!(client.mailbox(AccountId([9; 16])).await.unwrap().is_empty());
    // Restore pending: the busy signal, no error detail.
    env.store().mark_restore_pending().await.unwrap();
    assert!(!client.serving_allowed().await.unwrap());
    assert!(client.account(tag5).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_role_reserved_and_malformed_requests_close() {
    let env = Env::new(Role::Web).await;
    // A sealer op from the web uid: FORBIDDEN, then closed.
    let mut c = env.conn();
    let d = Request::Delete(Delete::Mailbox {
        lookup_tag: [1; 32],
        mailbox_id: [2; 32],
    });
    assert_eq!(c.call(&d), Err(ClientError::Store(ErrorCode::Forbidden)));
    assert!(!c.is_open());
    // Reserved relay op from the web uid.
    let mut c = env.conn();
    assert_eq!(
        c.call(&Request::Relay(Op::RelayClaim)),
        Err(ClientError::Store(ErrorCode::Forbidden))
    );
    // Truncated datagram: BAD_FRAME + close.
    let mut c = env.conn();
    c.ensure().unwrap();
    raw_send(&c, &[PROTO_VERSION, Op::AccountLookup as u8, 0, 0, 0, 1, 7]);
    assert_eq!(
        raw_recv(&c, Op::AccountLookup),
        Some(Response::Error(ErrorCode::BadFrame))
    );
    assert!(closed(&c));
    // Trailing bytes.
    let mut c = env.conn();
    c.ensure().unwrap();
    let mut b = encode_request(1, &Request::ServingAllowed).unwrap();
    b.push(0);
    raw_send(&c, &b);
    assert_eq!(
        raw_recv(&c, Op::ServingAllowed),
        Some(Response::Error(ErrorCode::BadFrame))
    );
    assert!(closed(&c));
    // Unknown op and wrong version.
    for bad in [
        vec![PROTO_VERSION, 0x7f, 0, 0, 0, 1],
        vec![0x02, Op::ServingAllowed as u8, 0, 0, 0, 1],
        vec![],
    ] {
        let mut c = env.conn();
        c.ensure().unwrap();
        if bad.is_empty() {
            // A zero-length datagram reads as EOF: the server just closes.
            drop(c);
            continue;
        }
        raw_send(&c, &bad);
        assert_eq!(
            raw_recv(&c, Op::ServingAllowed),
            Some(Response::Error(ErrorCode::BadFrame))
        );
        assert!(closed(&c));
    }
    // Oversize datagram (above MAX_FRAME_LEN).
    let mut c = env.conn();
    c.ensure().unwrap();
    let mut big = vec![0u8; MAX_FRAME_LEN + 1];
    big[0] = PROTO_VERSION;
    big[1] = Op::ServingAllowed as u8;
    raw_send(&c, &big);
    assert_eq!(
        raw_recv(&c, Op::ServingAllowed),
        Some(Response::Error(ErrorCode::BadFrame))
    );
    assert!(closed(&c));
    // A datagram carrying a descriptor is refused too.
    let mut c = env.conn();
    c.ensure().unwrap();
    let hdr = StagedHeader {
        len: 1,
        sha256: [0; 32],
    };
    let fd = sealed_memfd(b"x");
    send_staged_bundle(c.socket().unwrap(), &hdr, fd.as_fd()).unwrap();
    assert_eq!(
        raw_recv(&c, Op::ServingAllowed),
        Some(Response::Error(ErrorCode::BadFrame))
    );
    assert!(closed(&c));
    // The connection survives ordinary errors (NotFound) and keeps serving.
    let mut c = env.conn();
    assert!(c.call(&Request::MailboxList { account: [1; 16] }).is_ok());
    assert!(matches!(
        c.call(&Request::MailboxRead {
            account: [1; 16],
            reply: [2; 16]
        }),
        Err(ClientError::Store(ErrorCode::Busy))
    ));
    let (acct, _) = account_with_replies(&env, 7, 1).await;
    assert!(c.call(&Request::MailboxList { account: acct.0 }).is_ok());
    assert!(matches!(
        c.call(&Request::MailboxRead {
            account: acct.0,
            reply: [2; 16]
        }),
        Err(ClientError::Store(ErrorCode::NotFound))
    ));
    assert!(c.is_open());
    assert!(matches!(
        c.call(&Request::ServingAllowed),
        Ok(Response::ServingAllowed(true))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_uid_is_dropped_without_a_reply() {
    // A server where no role has this process's uid: the connection is
    // closed without reading or writing anything.
    let env = Env::new(Role::Relay).await;
    let me = my_uid();
    let other = me.wrapping_add(7);
    let cfg = ServerConfig::new(other, other.wrapping_add(1), None);
    let s2 = Arc::new(
        IstoreServer::new(
            Arc::clone(env.server.store()),
            Arc::clone(env.server.receiver()),
            Arc::new(common::signer()),
            Arc::new(Clock),
            cfg,
            tokio::runtime::Handle::current(),
        )
        .unwrap(),
    );
    let (a, b) = pair();
    let s3 = Arc::clone(&s2);
    std::thread::spawn(move || s3.serve_connection(b))
        .join()
        .unwrap();
    let mut buf = [0u8; 8];
    let mut c = rustix::net::RecvAncillaryBuffer::default();
    let m = rustix::net::recvmsg(
        &a,
        &mut [IoSliceMut::new(&mut buf)],
        &mut c,
        RecvFlags::empty(),
    )
    .unwrap();
    assert_eq!(m.bytes, 0);
    assert_eq!(s2.refused(), 1);
    // A relay-uid connection is authenticated, but every relay op is refused
    // until RM-3 (uniformly, whatever the op).
    for op in [
        Op::RelayStatus,
        Op::RelayClaim,
        Op::RelayPushDeletionList,
        Op::RelayBackup,
    ] {
        let mut c = env.conn();
        assert_eq!(
            c.call(&Request::Relay(op)),
            Err(ClientError::Store(ErrorCode::Forbidden))
        );
        assert!(!c.is_open());
    }
    assert_eq!(env.server.refused(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_cap_answers_busy_and_distinct_uids_are_required() {
    let env = Env::new(Role::Web).await;
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut c = env.conn();
        assert!(c.call(&Request::ServingAllowed).is_ok());
        held.push(c);
    }
    // Over the role cap: closed before a thread is spawned or a byte is
    // read (ADR-057(5)); the client sees a transport failure.
    let mut c = env.conn();
    assert_eq!(c.call(&Request::ServingAllowed), Err(ClientError::Transport));
    assert_eq!(env.server.refused(), 1);
    drop(held);
    assert!(c.call(&Request::ServingAllowed).is_ok());
    let mut bad = ServerConfig::new(1, 2, Some(3));
    bad.max_connections_sealer = 0;
    assert!(bad.validate().is_err());
    assert!(ServerConfig::new(1, 1, None).validate().is_err());
    assert!(ServerConfig::new(1, 2, Some(2)).validate().is_err());
    let mut cfg = ServerConfig::new(1, 2, Some(3));
    cfg.op_deadline = Duration::from_millis(1);
    assert!(cfg.validate().is_err());
}

// ----- sealer role ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_group_hand_over_and_idempotent_replay() {
    let env = Env::new(Role::Sealer).await;
    let bundle = vec![0x42u8; 300_000];
    let g = group(0x10, bundle.len() as u64);
    let mut c = env.conn();
    commit(&mut c, &g, &bundle).unwrap();
    assert!(c.is_open());
    assert_eq!(env.store().pending_count().await.unwrap(), 1);
    // AUD-RM2-SEA-01 / WEB-13: the same group handed over again (as a retry
    // after a lost acknowledgement would) is acknowledged as committed and
    // nothing is committed twice — on the same and on a fresh connection.
    commit(&mut c, &g, &bundle).unwrap();
    let mut c2 = env.conn();
    commit(&mut c2, &g, &bundle).unwrap();
    assert_eq!(env.store().pending_count().await.unwrap(), 1);
    // A different bundle under an already committed digest is refused
    // (hash mismatch with the remembered first commit): refused + closed.
    let other = vec![0x43u8; 300_000];
    assert!(commit(&mut c2, &g, &other).is_err());
    assert!(!c2.is_open());
    assert_eq!(env.store().pending_count().await.unwrap(), 1);
    // A declared bundle length that differs from the handed-over file is
    // refused before anything is committed.
    let mut g2 = group(0x20, 10);
    let mut c3 = env.conn();
    assert!(commit(&mut c3, &g2, &bundle).is_err());
    assert_eq!(env.store().pending_count().await.unwrap(), 1);
    g2.bundle.padded_size = bundle.len() as u64;
    let mut c3 = env.conn();
    commit(&mut c3, &g2, &bundle).unwrap();
    assert_eq!(env.store().pending_count().await.unwrap(), 2);
    // The sealer's day must be within one day of the store's.
    let mut g3 = group(0x30, bundle.len() as u64);
    g3.received_day = common::TODAY.0 + 2;
    assert_eq!(
        c3.call(&Request::CommitGroup(Box::new(g3))),
        Err(ClientError::Store(ErrorCode::Invalid))
    );
    assert!(c3.is_open());
    // Web ops are forbidden on the sealer connection.
    assert_eq!(
        c3.call(&Request::ServingAllowed),
        Err(ClientError::Store(ErrorCode::Forbidden))
    );
    // Restore pending: the commit is refused before the hand-over.
    env.store().mark_restore_pending().await.unwrap();
    let mut c4 = env.conn();
    assert_eq!(
        c4.call(&Request::CommitGroup(Box::new(group(0x40, 5)))),
        Err(ClientError::Store(ErrorCode::Unavailable))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_commit_is_reported_by_the_retry_without_a_double_commit() {
    // The sealer gives up (closes) after sending the bundle but before the
    // acknowledgement; the store still commits. The retry on a fresh
    // connection must succeed as a replay with exactly one envelope.
    let env = Env::new(Role::Sealer).await;
    let bundle = vec![0x51u8; 100_000];
    let g = group(0x50, bundle.len() as u64);
    let mut c = env.conn();
    assert!(matches!(
        c.call(&Request::CommitGroup(Box::new(g.clone()))),
        Ok(Response::Empty)
    ));
    let sha256: [u8; 32] = Sha256::digest(&bundle).into();
    let fd = sealed_memfd(&bundle);
    send_staged_bundle(
        c.socket().unwrap(),
        &StagedHeader {
            len: bundle.len() as u64,
            sha256,
        },
        fd.as_fd(),
    )
    .unwrap();
    // Read "copied", then give up before "committed" (the sealer's commit
    // deadline expired); the store's commit still lands.
    let owned: OwnedFd = c.socket().unwrap().try_clone_to_owned().unwrap();
    assert_eq!(ack(&owned), Some((STAGED_ACK_COPIED, sha256)));
    drop(owned);
    c.close();
    // Wait until the store has committed.
    for _ in 0..200 {
        if env.store().pending_count().await.unwrap() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(env.store().pending_count().await.unwrap(), 1);
    let mut c2 = env.conn();
    commit(&mut c2, &g, &bundle).unwrap();
    assert_eq!(env.store().pending_count().await.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_upsert_is_idempotent_and_rewraps() {
    let env = Env::new(Role::Sealer).await;
    let mut c = env.conn();
    let mut a = AccountUpsert {
        replaces: None,
        lookup_tag: [0x61; 32],
        auth_pk: [0x62; 32],
        xwing_pk: vec![0x63; XWING_PK_LEN],
        prefs_ct: vec![0x64; 2048],
        mailbox_ids: vec![[0x65; 32]],
        rewrapped: vec![],
    };
    let req = |a: &AccountUpsert| Request::AccountUpsert(Box::new(a.clone()));
    assert!(matches!(c.call(&req(&a)), Ok(Response::Empty)));
    // Retry of the same create: success, still one account.
    assert!(matches!(c.call(&req(&a)), Ok(Response::Empty)));
    let acct = env
        .store()
        .lookup_account(&LookupTag([0x61; 32]))
        .await
        .unwrap()
        .unwrap();
    // Replies to re-wrap on rotation.
    let (r1, h1, st1) = common::real_reply(acct.account_id, 0xA1);
    env.store()
        .apply_replies(common::TODAY, vec![r1.clone()])
        .await
        .unwrap();
    let new_stanza = vec![0xB1u8; st1.len()];
    a.replaces = Some([0x61; 32]);
    a.lookup_tag = [0x71; 32];
    a.auth_pk = [0x72; 32];
    a.rewrapped = vec![(h1, new_stanza.clone())];
    assert!(matches!(c.call(&req(&a)), Ok(Response::Empty)));
    let rotated = env
        .store()
        .lookup_account(&LookupTag([0x71; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rotated.account_id, acct.account_id);
    assert_eq!(rotated.auth_pk, [0x72; 32]);
    assert!(
        env.store()
            .lookup_account(&LookupTag([0x61; 32]))
            .await
            .unwrap()
            .is_none()
    );
    let mb = env.store().mailbox_list(acct.account_id).await.unwrap();
    let sealed_len = r1.reply_ct.len() - st1.len();
    assert_eq!(&mb[0].reply_ct[sealed_len..], &new_stanza[..]);
    // Retry of the replacement (old tag gone, new one present): success.
    assert!(matches!(c.call(&req(&a)), Ok(Response::Empty)));
    // A replacement of a tag that never existed: NotFound.
    a.replaces = Some([0x99; 32]);
    a.lookup_tag = [0x98; 32];
    assert_eq!(
        c.call(&req(&a)),
        Err(ClientError::Store(ErrorCode::NotFound))
    );
    assert!(c.is_open());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deletions_append_k31_entries_and_are_idempotent() {
    let env = Env::new(Role::Sealer).await;
    let (acct, hashes) = account_with_replies(&env, 5, 3).await;
    let s = env.store();
    let mb = s.mailbox_list(acct).await.unwrap();
    let tag = common::new_account(5).lookup_tag.0;
    let mut c = env.conn();
    // SW-14: delete one reply (plus an unknown ref and a duplicate: ignored).
    let d = Request::Delete(Delete::Replies {
        lookup_tag: tag,
        replies: vec![mb[0].reply_ref.0, [9; 16], mb[0].reply_ref.0],
    });
    assert!(matches!(c.call(&d), Ok(Response::Deleted(1))));
    assert_eq!(s.mailbox_list(acct).await.unwrap().len(), 2);
    // Retry: nothing left, no new entry.
    assert!(matches!(c.call(&d), Ok(Response::Deleted(0))));
    let list = s.deletion_list_after(0, 100).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, DeletionKind::Reply);
    assert_eq!(
        list[0].del_hash,
        deletion::reply_del_hash(&common::TENANT, &hashes[0])
    );
    deletion::verify_chain(&list, &common::signer().verifying_key(), None).unwrap();
    // A reply of another account cannot be deleted through this tag.
    let (other, _) = account_with_replies(&env, 6, 1).await;
    let omb = s.mailbox_list(other).await.unwrap();
    let d = Request::Delete(Delete::Replies {
        lookup_tag: tag,
        replies: vec![omb[0].reply_ref.0],
    });
    assert!(matches!(c.call(&d), Ok(Response::Deleted(0))));
    assert_eq!(s.mailbox_list(other).await.unwrap().len(), 1);
    // MAILBOX_DELETE: one mailbox entry, the account's replies gone.
    let d = Request::Delete(Delete::Mailbox {
        lookup_tag: tag,
        mailbox_id: [0x33; 32],
    });
    assert!(matches!(c.call(&d), Ok(Response::Deleted(1))));
    assert!(s.mailbox_list(acct).await.unwrap().is_empty());
    // SW-15: the account's `mailbox_account` mailbox entry then the account
    // entry (hash of the stable account id, ADR-057(1)) in one transaction;
    // a stale previous tag beside the current one is ignored (ADR-057(3)).
    let d = Request::Delete(Delete::Account {
        lookup_tags: vec![[0xEE; 32], tag],
    });
    assert!(matches!(c.call(&d), Ok(Response::Deleted(2))));
    assert!(s.lookup_account(&LookupTag(tag)).await.unwrap().is_none());
    let list = s.deletion_list_after(0, 100).await.unwrap();
    let kinds: Vec<DeletionKind> = list.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            DeletionKind::Reply,
            DeletionKind::Mailbox,
            DeletionKind::Mailbox,
            DeletionKind::Account
        ]
    );
    assert_eq!(
        list[2].del_hash,
        deletion::mailbox_del_hash(&common::TENANT, &MailboxId([5; 32]))
    );
    assert_eq!(
        list[3].del_hash,
        deletion::account_del_hash(&common::TENANT, &acct)
    );
    deletion::verify_chain(&list, &common::signer().verifying_key(), None).unwrap();
    // Retry after the account is gone: uniform NotFound; nothing appended.
    assert_eq!(c.call(&d), Err(ClientError::Store(ErrorCode::NotFound)));
    assert_eq!(s.deletion_list_after(0, 100).await.unwrap().len(), 4);
    // Restore pending: deletions refuse (AUD-RM2-STO-09).
    s.mark_restore_pending().await.unwrap();
    let d = Request::Delete(Delete::Mailbox {
        lookup_tag: common::new_account(6).lookup_tag.0,
        mailbox_id: [1; 32],
    });
    assert_eq!(c.call(&d), Err(ClientError::Store(ErrorCode::Unavailable)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_closes_and_client_reconnects() {
    let env = Env::new(Role::Web).await;
    let mut c = env.conn();
    assert!(c.call(&Request::ServingAllowed).is_ok());
    std::thread::sleep(Duration::from_millis(2300));
    // The server closed the idle connection: the call fails as transport
    // and the connection is closed; the next call reconnects.
    assert_eq!(
        c.call(&Request::ServingAllowed),
        Err(ClientError::Transport)
    );
    assert!(!c.is_open());
    assert!(c.call(&Request::ServingAllowed).is_ok());
    assert!(c.is_open());
}

/// AUD-RM2-IPC-07: `MAILBOX_READ` is a single-row read whose budget is
/// granted by `MAILBOX_LIST` (at most the listed replies per list); reads
/// beyond it answer `BUSY` without touching the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_read_is_budgeted_by_the_list() {
    let env = Env::new(Role::Web).await;
    let (acct, _) = account_with_replies(&env, 5, 2).await;
    let mut c = env.conn();
    let mb = env.store().mailbox_list(acct).await.unwrap();
    let read = |c: &mut Conn, r: [u8; 16]| {
        c.call(&Request::MailboxRead {
            account: acct.0,
            reply: r,
        })
    };
    // No list yet: no budget.
    assert_eq!(
        read(&mut c, mb[0].reply_ref.0),
        Err(ClientError::Store(ErrorCode::Busy))
    );
    assert!(matches!(
        c.call(&Request::MailboxList { account: acct.0 }),
        Ok(Response::MailboxList(v)) if v.len() == 2
    ));
    assert!(
        matches!(read(&mut c, mb[0].reply_ref.0), Ok(Response::ReplyCt(ct)) if ct == mb[0].reply_ct)
    );
    // An unknown ref costs budget too and is NotFound.
    assert_eq!(
        read(&mut c, [9; 16]),
        Err(ClientError::Store(ErrorCode::NotFound))
    );
    assert_eq!(
        read(&mut c, mb[1].reply_ref.0),
        Err(ClientError::Store(ErrorCode::Busy))
    );
    assert!(c.is_open());
    // A foreign account's reply is NotFound even with budget.
    let (other, _) = account_with_replies(&env, 6, 1).await;
    let omb = env.store().mailbox_list(other).await.unwrap();
    assert!(c.call(&Request::MailboxList { account: acct.0 }).is_ok());
    assert_eq!(
        read(&mut c, omb[0].reply_ref.0),
        Err(ClientError::Store(ErrorCode::NotFound))
    );
}
