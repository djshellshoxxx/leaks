// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test harness: the web service on a real Unix socket, a scripted sealer
//! speaking the real `candor_sealer::proto` over its own Unix socket, an
//! in-memory `StoreReads`, and a raw HTTP/1.1 client that writes tor's PROXY
//! line first. Only localhost Unix sockets; no network (IMPL-00 §11).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Test fixture only: Unix socket paths in a private temp directory.
    clippy::disallowed_methods,
    clippy::type_complexity,
    clippy::field_reassign_with_default,
    dead_code
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use candor_core::passphrase::Wordlist;
use candor_intake_store::{AccountId, Day, ReplyRef, StoredReply};
use candor_intake_web::{
    AccountView, ChannelConfig, DayClock, SealerClient, SiteContent, StoreReads, StoreUnavailable,
    Web, WebConfig,
};
use candor_sealer::proto::{
    self as sp, DraftView, ErrorCode, PartView, ReplyView, Request, Response, SecretText,
    SecretWords, decode_request, encode_response, frame, frame_len,
};
use candor_source_ui::{ChannelOption, ChannelRoles, ChoiceOption, DeploymentInfo, Text};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

pub const HOST: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
pub const ORIGIN: &str = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
pub const CHANNEL: [u8; 16] = [0xc1; 16];
pub const TENANT: [u8; 16] = [0x11; 16];
pub const TODAY: u32 = 20_727; // 2026-10-01
pub const PREFS_OK: &[u8] = b"prefs-ok";
/// Positions the fake sealer asks for (0-based).
pub const POSITIONS: [u8; 3] = [0, 4, 9];
/// Word indices of every generated passphrase.
pub const WORDS: [u16; 10] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3];

// ------------------------------------------------------------------ fake sealer

#[derive(Default)]
pub struct Sess {
    pub phase: &'static str,
    pub mode: Option<sp::Mode>,
    pub message: String,
    pub fields: Vec<(u16, String)>,
    pub identity: Option<String>,
    pub coi: Option<(Vec<u16>, Vec<u16>)>,
    pub parts: Vec<([u8; 16], u64, u64)>, // id, declared, received
    pub confirmed: bool,
    pub failures: u8,
    pub key: Option<[u8; 32]>,
}

#[derive(Default)]
pub struct SealerState {
    pub sessions: Mutex<HashMap<[u8; 16], Sess>>,
    /// Every op seen, in order.
    pub ops: Mutex<Vec<sp::Op>>,
    /// Largest PART_CHUNK data seen.
    pub max_chunk: Mutex<usize>,
    pub sealed: AtomicU32,
    pub busy: AtomicBool,
    /// Seal fails with NO_ELIGIBLE_TRIAGE.
    pub no_reader: AtomicBool,
}

impl SealerState {
    pub fn ops(&self) -> Vec<sp::Op> {
        self.ops.lock().unwrap().clone()
    }

    pub fn count(&self, op: sp::Op) -> usize {
        self.ops().iter().filter(|o| **o == op).count()
    }
}

pub fn passphrase_words() -> Vec<String> {
    let l = Wordlist::eff_large().unwrap();
    WORDS
        .iter()
        .map(|i| l.get(usize::from(*i)).unwrap().to_owned())
        .collect()
}

pub fn login_tag(pw: &str) -> [u8; 32] {
    Sha256::digest([b"tag:".as_slice(), pw.as_bytes()].concat()).into()
}

pub fn login_key(pw: &str) -> candor_core::sig::SigningKey {
    let seed: [u8; 32] = Sha256::digest([b"auth:".as_slice(), pw.as_bytes()].concat()).into();
    candor_core::sig::SigningKey::from_seed(&seed)
}

fn err(code: ErrorCode) -> Response {
    Response::error(code)
}

fn handle(st: &SealerState, req: Request) -> Response {
    st.ops.lock().unwrap().push(req.op());
    if st.busy.load(Ordering::SeqCst) {
        return err(ErrorCode::Busy);
    }
    let mut m = st.sessions.lock().unwrap();
    match req {
        Request::Hello { .. } => err(ErrorCode::BadFrame),
        Request::SessionOpen { sess, channel_id } => {
            if channel_id != CHANNEL {
                return err(ErrorCode::Unavailable);
            }
            m.insert(
                sess.0,
                Sess {
                    phase: "drafting",
                    ..Sess::default()
                },
            );
            Response::Empty
        }
        Request::DraftSet(ds) => {
            let Some(s) = m.get_mut(&ds.sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            let total: usize = ds
                .fields
                .iter()
                .map(|(_, t)| t.expose().len())
                .sum::<usize>()
                + ds.message.expose().len();
            if total > sp::MAX_DRAFT_TEXT {
                return err(ErrorCode::Limit);
            }
            s.mode = Some(ds.mode);
            s.message = ds.message.expose().to_owned();
            s.fields = ds
                .fields
                .iter()
                .map(|(k, v)| (*k, v.expose().to_owned()))
                .collect();
            s.identity = if ds.mode == sp::Mode::Anonymous {
                None
            } else {
                ds.identity.as_ref().map(|t| t.expose().to_owned())
            };
            s.coi = ds
                .coi
                .as_ref()
                .map(|c| (c.excluded_labels.to_vec(), c.categories.to_vec()));
            Response::Empty
        }
        Request::DraftGet { sess } => {
            let Some(s) = m.get(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            Response::Draft(Box::new(DraftView {
                mode: s.mode.unwrap_or(sp::Mode::Anonymous),
                message: SecretText::new(&s.message),
                fields: s
                    .fields
                    .iter()
                    .map(|(k, v)| (*k, SecretText::new(v)))
                    .collect(),
                identity: s.identity.as_deref().map(SecretText::new),
                coi: s.coi.as_ref().map(|(l, c)| sp::Coi {
                    excluded_labels: Zeroizing::new(l.clone()),
                    categories: Zeroizing::new(c.clone()),
                }),
                parts: s
                    .parts
                    .iter()
                    .map(|(id, _, got)| PartView {
                        part: *id,
                        size_bucket: (*got).max(1).next_power_of_two().max(262_144),
                    })
                    .collect(),
            }))
        }
        Request::GenAccount { sess } | Request::RotatePassphrase { sess } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            s.confirmed = false;
            s.failures = 0;
            Response::Words {
                words: SecretWords(Zeroizing::new(WORDS.to_vec())),
                confirm_positions: POSITIONS,
            }
        }
        Request::ConfirmPassphrase { sess, words } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            let want: Vec<u16> = POSITIONS.iter().map(|p| WORDS[usize::from(*p)]).collect();
            if words.0.as_slice() == want.as_slice() {
                s.confirmed = true;
                return Response::Confirm {
                    ok: true,
                    confirm_positions: None,
                };
            }
            s.failures += 1;
            if s.failures >= 5 {
                m.remove(&sess.0);
                return Response::Confirm {
                    ok: false,
                    confirm_positions: None,
                };
            }
            Response::Confirm {
                ok: false,
                confirm_positions: Some(POSITIONS),
            }
        }
        Request::SealFinish { sess, .. } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            if st.no_reader.load(Ordering::SeqCst) {
                return Response::Error {
                    code: ErrorCode::NoEligibleTriage,
                    alternative_channel_id: Some([0xc2; 16]),
                };
            }
            if s.phase == "drafting" && !s.confirmed {
                return err(ErrorCode::NotConfirmed);
            }
            st.sealed.fetch_add(1, Ordering::SeqCst);
            s.message.clear();
            s.fields.clear();
            s.parts.clear();
            Response::Sealed {
                release_offset_days: 0,
            }
        }
        Request::SealAbort { sess } | Request::Zeroize { sess } => {
            m.remove(&sess.0);
            Response::Empty
        }
        Request::Touch { sess } => {
            if m.contains_key(&sess.0) {
                Response::Empty
            } else {
                err(ErrorCode::UnknownSession)
            }
        }
        Request::LoginDerive { sess, passphrase } => {
            let pw = String::from_utf8(passphrase.0.to_vec()).unwrap();
            m.insert(
                sess.0,
                Sess {
                    phase: "derived",
                    key: Some(Sha256::digest([b"auth:".as_slice(), pw.as_bytes()].concat()).into()),
                    ..Sess::default()
                },
            );
            Response::Locator {
                lookup_tag: login_tag(&pw),
            }
        }
        Request::LoginSign { sess, challenge } => {
            let Some(s) = m.get(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            let k = candor_core::sig::SigningKey::from_seed(&s.key.unwrap());
            let sig = candor_core::sig::sign_with_context(
                &k,
                candor_core::labels::SIG_SOURCE_AUTH,
                &[&challenge, &TENANT, b"source-web"],
            );
            Response::Signature { sig }
        }
        Request::LoadPrefs { sess, prefs_ct } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            if prefs_ct != PREFS_OK {
                return err(ErrorCode::Crypto);
            }
            s.phase = "authenticated";
            Response::Empty
        }
        Request::OpenReply { sess, entry } => {
            if !m.contains_key(&sess.0) {
                return err(ErrorCode::UnknownSession);
            }
            let ct = &entry[4..];
            match ct.strip_prefix(b"REPLY:") {
                Some(text) => Response::Reply(Some(ReplyView {
                    reply_seq: 1,
                    day: TODAY,
                    role_label: SecretText::new("Case team"),
                    body: SecretText::new(std::str::from_utf8(text).unwrap()),
                })),
                None => Response::Reply(None),
            }
        }
        Request::RotateFinish { sess, .. } => {
            if !m.contains_key(&sess.0) {
                return err(ErrorCode::UnknownSession);
            }
            Response::Locator {
                lookup_tag: [0x77; 32],
            }
        }
        Request::PartBegin {
            sess, declared_len, ..
        } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            let id = [s.parts.len() as u8 + 1; 16];
            s.parts.push((id, declared_len, 0));
            Response::Part { part: id }
        }
        Request::PartChunk {
            sess, part, data, ..
        } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            let mut mx = st.max_chunk.lock().unwrap();
            *mx = (*mx).max(data.0.len());
            let Some(p) = s.parts.iter_mut().find(|p| p.0 == part) else {
                return err(ErrorCode::BadState);
            };
            p.2 += data.0.len() as u64;
            if p.2 > p.1 {
                return err(ErrorCode::Limit);
            }
            Response::Empty
        }
        Request::PartDrop { sess, part } => {
            let Some(s) = m.get_mut(&sess.0) else {
                return err(ErrorCode::UnknownSession);
            };
            s.parts.retain(|p| p.0 != part);
            Response::Empty
        }
        Request::NoteReal { .. } | Request::Status => err(ErrorCode::BadState),
    }
}

async fn sealer_conn(st: Arc<SealerState>, mut s: UnixStream) {
    let mut first = true;
    loop {
        let mut p = [0u8; 4];
        if s.read_exact(&mut p).await.is_err() {
            return;
        }
        let Ok(n) = frame_len(p) else { return };
        let mut b = vec![0u8; n];
        if s.read_exact(&mut b).await.is_err() {
            return;
        }
        let Ok((rid, req)) = decode_request(&b) else {
            return;
        };
        let op = req.op();
        let resp = if first {
            first = false;
            match req {
                Request::Hello { proto } if proto == sp::PROTO_VERSION => Response::Hello {
                    proto: sp::PROTO_VERSION,
                    snapshot_version: 1,
                },
                _ => return,
            }
        } else {
            handle(&st, req)
        };
        let msg = encode_response(op, rid, &resp).unwrap();
        if s.write_all(&frame(&msg).unwrap()).await.is_err() {
            return;
        }
    }
}

pub async fn spawn_sealer(path: &Path) -> Arc<SealerState> {
    spawn_sealer_on(UnixListener::bind(path).unwrap())
}

/// The scripted sealer on an existing listener.
pub fn spawn_sealer_on(l: UnixListener) -> Arc<SealerState> {
    let st = Arc::new(SealerState::default());
    let st2 = Arc::clone(&st);
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(sealer_conn(Arc::clone(&st2), s));
        }
    });
    st
}

// ------------------------------------------------------------------- fake store

#[derive(Default)]
pub struct StoreState {
    pub accounts: Mutex<HashMap<[u8; 32], ([u8; 16], [u8; 32])>>,
    pub replies: Mutex<Vec<Vec<u8>>>,
    pub down: AtomicBool,
    pub restore_pending: AtomicBool,
    /// Panic inside the account lookup (handler panic path).
    pub panic: AtomicBool,
}

#[derive(Clone)]
pub struct FakeStore(pub Arc<StoreState>);

impl StoreReads for FakeStore {
    async fn serving_allowed(&self) -> Result<bool, StoreUnavailable> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(StoreUnavailable);
        }
        Ok(!self.0.restore_pending.load(Ordering::SeqCst))
    }

    async fn account(&self, tag: [u8; 32]) -> Result<Option<AccountView>, StoreUnavailable> {
        if self.0.panic.load(Ordering::SeqCst) {
            panic!("canary-panic-payload-5150");
        }
        if self.0.down.load(Ordering::SeqCst) {
            return Err(StoreUnavailable);
        }
        Ok(self
            .0
            .accounts
            .lock()
            .unwrap()
            .get(&tag)
            .map(|(id, pk)| AccountView {
                account_id: AccountId(*id),
                auth_pk: *pk,
                prefs_ct: PREFS_OK.to_vec(),
            }))
    }

    async fn mailbox(&self, _a: AccountId) -> Result<Vec<StoredReply>, StoreUnavailable> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(StoreUnavailable);
        }
        Ok(self
            .0
            .replies
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, ct)| StoredReply {
                reply_ref: ReplyRef([i as u8; 16]),
                slot: i as u8,
                reply_ct: ct.clone(),
                size_bucket: 1,
                available_day: Day(TODAY),
            })
            .collect())
    }
}

impl StoreState {
    /// Register the account a passphrase opens.
    pub fn add_account(&self, pw: &str) {
        self.accounts.lock().unwrap().insert(
            login_tag(pw),
            ([0xa1; 16], login_key(pw).verifying_key_bytes()),
        );
    }
}

// ------------------------------------------------------------------------ clock

pub struct Clock(pub AtomicBool);

impl DayClock for Clock {
    fn today(&self) -> Option<u32> {
        self.0.load(Ordering::SeqCst).then_some(TODAY)
    }
}

// ---------------------------------------------------------------------- harness

pub fn site() -> SiteContent {
    let option = ChannelOption {
        id: "c1".repeat(16),
        name: "Audit committee".into(),
        description: "Financial wrongdoing".into(),
        languages: "English".into(),
        triage: vec!["Triage lead".into()],
        allows_confidential: true,
        allows_identified: true,
        available: true,
        independent_route: false,
    };
    let mut d = DeploymentInfo::default();
    d.onion_address = HOST.into();
    d.info_site_address = "example.org".into();
    d.project_onion_address =
        "candorprojectxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion".into();
    d.custodian_label = "Identity custodian".into();
    d.ack_days = 7;
    d.passphrase_words = 10;
    d.intake_backup_days = Some(14);
    let mut s = SiteContent::default();
    s.org = "Example Org".into();
    s.deployment = d;
    s.landing.purpose = "Report wrongdoing safely.".into();
    s.status.channels = vec![ChannelRoles {
        channel: "Audit committee".into(),
        triage: vec!["Triage lead".into()],
        others: vec!["CFO".into()],
    }];
    s.channels = vec![ChannelConfig {
        id: CHANNEL,
        option,
        roles: vec![(1, "CFO".into()), (2, "HR lead".into())],
        categories: vec![(
            10,
            ChoiceOption {
                value: "fraud".into(),
                label: Text::Custom("Fraud".into()),
            },
        )],
    }];
    s
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub web_sock: PathBuf,
    pub sealer: Arc<SealerState>,
    pub store: Arc<StoreState>,
    pub clock: Arc<Clock>,
    pub web: Arc<Web<FakeStore>>,
}

pub async fn harness_with(f: impl FnOnce(&mut WebConfig)) -> Harness {
    build(f, true).await
}

/// A harness whose sealer socket has no listener (sealer down).
pub async fn harness_without_sealer() -> Harness {
    build(|_| (), false).await
}

async fn build(f: impl FnOnce(&mut WebConfig), with_sealer: bool) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let sealer_sock = dir.path().join("seal.sock"); // safefs-lint: allow(test socket path in own tempdir)
    let web_sock = dir.path().join("http.sock"); // safefs-lint: allow(test socket path in own tempdir)
    let sealer = if with_sealer {
        spawn_sealer(&sealer_sock).await
    } else {
        Arc::new(SealerState::default())
    };
    let store = Arc::new(StoreState::default());
    let clock = Arc::new(Clock(AtomicBool::new(true)));
    let mut cfg = WebConfig::new(HOST.into(), TENANT, site());
    cfg.max_file_bytes = 4 << 20;
    f(&mut cfg);
    let web = Web::new(
        cfg,
        SealerClient::new(sealer_sock),
        FakeStore(Arc::clone(&store)),
        Arc::clone(&clock) as Arc<dyn DayClock>,
    )
    .unwrap();
    let l = UnixListener::bind(&web_sock).unwrap();
    tokio::spawn(candor_intake_web::serve(Arc::clone(&web), l));
    Harness {
        dir,
        web_sock,
        sealer,
        store,
        clock,
        web,
    }
}

pub async fn harness() -> Harness {
    harness_with(|_| ()).await
}

// ----------------------------------------------------------------------- client

pub fn proxy_line(circuit: u32) -> String {
    format!(
        "PROXY TCP6 fc00:dead:beef:4dad::{:x}:{:x} ::1 {} 80\r\n",
        circuit >> 16,
        circuit & 0xffff,
        circuit & 0xffff
    )
}

/// Send raw bytes after the PROXY line and read the whole response (the
/// server closes after one response).
pub async fn raw(sock: &Path, circuit: u32, req: &[u8]) -> Vec<u8> {
    let mut s = UnixStream::connect(sock).await.unwrap();
    let mut all = proxy_line(circuit).into_bytes();
    all.extend_from_slice(req);
    let _ = s.write_all(&all).await;
    // Half-close: the request is complete (a short body ends here).
    let _ = s.shutdown().await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut out)).await;
    out
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub head: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, n: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The form token rendered into the page.
    pub fn csrf(&self) -> String {
        let t = self.text();
        let i = t
            .find("name=\"csrf\" value=\"")
            .expect("page has a csrf field")
            + 19;
        t[i..i + 64].to_owned()
    }

    /// `name=value` of the Set-Cookie header.
    pub fn cookie(&self) -> Option<String> {
        self.header("Set-Cookie")
            .map(|c| c.split(';').next().unwrap().to_owned())
    }
}

pub fn parse(raw: &[u8]) -> Resp {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("complete head")
        + 4;
    let head = raw[..end].to_vec();
    let text = String::from_utf8(head.clone()).unwrap();
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap();
    let status: u16 = status_line[9..12].parse().unwrap();
    let headers = lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (k, v) = l.split_once(": ").unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect();
    Resp {
        status,
        head,
        headers,
        body: raw[end..].to_vec(),
    }
}

pub fn get_req(path: &str, cookies: &[&str]) -> Vec<u8> {
    let mut s = format!(
        "GET {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: Mozilla/5.0 (canary-ua-31337)\r\nAccept-Language: en-US,en;q=0.5\r\n"
    );
    if !cookies.is_empty() {
        s.push_str(&format!("Cookie: {}\r\n", cookies.join("; ")));
    }
    s.push_str("\r\n");
    s.into_bytes()
}

pub fn post_req(path: &str, cookies: &[&str], body: &str, extra: &[&str]) -> Vec<u8> {
    let mut s = format!(
        "POST {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: Mozilla/5.0 (canary-ua-31337)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nOrigin: null\r\nSec-Fetch-Site: same-origin\r\n",
        body.len()
    );
    for e in extra {
        s.push_str(e);
        s.push_str("\r\n");
    }
    if !cookies.is_empty() {
        s.push_str(&format!("Cookie: {}\r\n", cookies.join("; ")));
    }
    s.push_str("\r\n");
    s.push_str(body);
    s.into_bytes()
}

impl Harness {
    pub async fn get(&self, path: &str, cookies: &[&str]) -> Resp {
        parse(&raw(&self.web_sock, 1, &get_req(path, cookies)).await)
    }

    pub async fn post(&self, path: &str, cookies: &[&str], body: &str) -> Resp {
        self.post_on(1, path, cookies, body).await
    }

    pub async fn post_on(&self, circuit: u32, path: &str, cookies: &[&str], body: &str) -> Resp {
        parse(&raw(&self.web_sock, circuit, &post_req(path, cookies, body, &[])).await)
    }

    /// Fetch the landing page for a pre-session cookie and token.
    pub async fn pre(&self) -> (String, String) {
        let r = self.get("/en/", &[]).await;
        (r.cookie().unwrap(), r.csrf())
    }

    /// Start a report (S04 → S04b). Returns the session cookie and the token.
    pub async fn start(&self, mode: &str) -> (String, String) {
        let (pre, tok) = self.pre().await;
        let body = format!("csrf={tok}&channel_id={}&mode={mode}", "c1".repeat(16));
        let r = self.post("/en/new", &[&pre], &body).await;
        assert_eq!(r.status, 200, "{}", r.text());
        let cookie = r.cookie().expect("session cookie");
        assert!(cookie.starts_with("__Host-cs="));
        (cookie, r.csrf())
    }
}

/// URL-encode a form value.
pub fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.*".contains(b) {
            o.push(*b as char);
        } else if *b == b' ' {
            o.push('+');
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}
