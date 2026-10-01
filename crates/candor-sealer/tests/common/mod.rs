// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared fixtures: a test clock, an in-memory intake store, a directory with
//! Desk-side keys, and a small generic CBOR reader/writer for inspecting the
//! sealed inner formats from the recipient side.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]
// Fixtures create and scan their own tempdirs and read procfs directly.
#![allow(clippy::disallowed_methods)] // safefs-lint: allow(test fixtures on own tempdir/procfs)

use std::os::unix::fs::PermissionsExt; // safefs-lint: allow(test fixture setup)
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use candor_core::Suite;
use candor_core::hash::{KeyKind, key_id, sha256};
use candor_core::header::ObjectType;
use candor_core::kem::KemKeyPair;
use candor_core::object;
use candor_core::passphrase::Wordlist;
use candor_core::secret::ContentKey;
use candor_core::sig::SigningKey;
use candor_core::slots::{RecipientListEntry, RecipientSlotBlock, SlotContext};
use candor_safefs::{RootPolicy, SafeRoot};
use candor_sealer::proto::{
    Coi, DraftSet, Mode, Request, Response, SecretText, SecretWords, SessionHandle,
};
use candor_sealer::server::clock::{Clock, ClockError};
use candor_sealer::server::directory::{DirectoryTrust, SnapshotBundle};

mod kdlog;
use candor_sealer::server::hardening::InsecureDevMode;
use candor_sealer::server::sink::{
    AccountUpsert, Blob, EnvelopeGroup, EnvelopeObject, EnvelopeSink, SinkError, StagedBundle,
};
use candor_sealer::server::{ChaffConfig, Limits, Sealer, SealerConfig, SnapshotError};
pub use kdlog::*;

pub const TENANT: [u8; 16] = [0x11; 16];
pub const CHANNEL: [u8; 16] = [0x22; 16];
pub const ALT_CHANNEL: [u8; 16] = [0x33; 16];
pub const SALT: [u8; 32] = [0x44; 32];
pub const TODAY: u32 = 20_000;
pub const CATEGORY_FRAUD: u16 = 7;

pub struct TestClock {
    pub day: AtomicU32,
    pub fail: AtomicBool,
}

impl Clock for TestClock {
    fn today(&self) -> Result<u32, ClockError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(ClockError)
        } else {
            Ok(self.day.load(Ordering::SeqCst))
        }
    }
}

/// A stored object: type, hash, slot block and blob bytes.
#[derive(Clone)]
pub struct StoredObject {
    pub object_type: ObjectType,
    pub object_hash: [u8; 32],
    pub slot_block: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct StoredEnvelope {
    pub channel_id: [u8; 16],
    /// Always `[main, bundle, identity]`.
    pub objects: Vec<StoredObject>,
    pub disposition_ct: Vec<u8>,
    pub epoch_id: u32,
    pub received_day: u32,
    pub release_offset_days: u8,
}

/// Store operations in order: `'A'` account upsert, `'G'` envelope group.
pub struct MemorySink {
    pub staging: &'static SafeRoot,
    pub envelopes: Mutex<Vec<StoredEnvelope>>,
    pub accounts: Mutex<Vec<AccountUpsert>>,
    pub ops: Mutex<Vec<char>>,
    pub fail: AtomicBool,
    /// Fail only account upserts.
    pub fail_accounts: AtomicBool,
    /// Sealed bundles as handed over (descriptor kept for hand-over tests).
    pub bundles: Mutex<Vec<StagedBundle>>,
}

impl MemorySink {
    fn take(&self, o: &EnvelopeObject) -> StoredObject {
        let bytes = match &o.blob {
            Blob::Inline(b) => b.clone(),
            Blob::Staged(b) => {
                let v = b.read_to_vec().unwrap();
                assert_eq!(v.len() as u64, b.len());
                self.bundles.lock().unwrap().push(b.clone());
                v
            }
        };
        StoredObject {
            object_type: o.object_type,
            object_hash: o.object_hash,
            slot_block: o.slot_block.clone(),
            bytes,
        }
    }

    pub fn envelopes(&self) -> Vec<StoredEnvelope> {
        self.envelopes.lock().unwrap().clone()
    }

    pub fn accounts(&self) -> Vec<AccountUpsert> {
        self.accounts.lock().unwrap().clone()
    }

    pub fn ops(&self) -> String {
        self.ops.lock().unwrap().iter().collect()
    }
}

impl EnvelopeSink for MemorySink {
    fn commit_envelope_group(
        &self,
        group: EnvelopeGroup,
        epoch_id: u32,
        received_day: u32,
        release_offset_days: u8,
    ) -> Result<(), SinkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SinkError);
        }
        let objects = group.objects().iter().map(|o| self.take(o)).collect();
        self.envelopes.lock().unwrap().push(StoredEnvelope {
            channel_id: group.channel_id,
            objects,
            disposition_ct: group.disposition_ct.clone(),
            epoch_id,
            received_day,
            release_offset_days,
        });
        self.ops.lock().unwrap().push('G');
        Ok(())
    }

    fn upsert_account(&self, op: AccountUpsert) -> Result<(), SinkError> {
        if self.fail.load(Ordering::SeqCst) || self.fail_accounts.load(Ordering::SeqCst) {
            return Err(SinkError);
        }
        self.accounts.lock().unwrap().push(op);
        self.ops.lock().unwrap().push('A');
        Ok(())
    }
}

/// A Triage Set member's Desk.
pub struct Member {
    pub user_id: [u8; 16],
    pub role_label: u16,
    pub read_intake: bool,
    pub mek: KemKeyPair,
    pub k08: SigningKey,
    pub entry_hash: [u8; 32],
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub staging_path: PathBuf,
    pub staging: &'static SafeRoot,
    pub clock: Arc<TestClock>,
    pub sink: Arc<MemorySink>,
    pub sealer: Sealer,
    pub members: Vec<Member>,
    pub custodian: KemKeyPair,
    pub disposition: KemKeyPair,
    pub k35: [u8; 32],
    pub snapshot: DirectorySnapshot,
    /// The test Key Directory log the sealer's snapshots come from.
    pub log: Mutex<TestLog>,
}

pub fn trust() -> DirectoryTrust {
    DirectoryTrust {
        tenant_id: TENANT,
        org_root_pk: k01().verifying_key_bytes(),
        epoch_origin_day: TODAY - 2,
        min_cosignatures: 0,
        min_external: 0,
    }
}

impl Fixture {
    /// Sync the log to `view` and install a bundle with a valid checkpoint and
    /// proof from the current mark.
    pub fn install(&self, view: DirectorySnapshot) -> Result<(), SnapshotError> {
        let b = self.bundle(&view);
        self.sealer.install_snapshot(b, |_| true)
    }

    /// Sync the log to `view` and return the bundle (not installed). The log
    /// keeps the new entries.
    pub fn bundle(&self, view: &DirectorySnapshot) -> SnapshotBundle {
        let from = self.sealer.high_water_mark().tree_size;
        let mut log = self.log.lock().unwrap();
        log.sync(view, &self.members);
        log.bundle(view, from)
    }

    /// Like [`Fixture::bundle`] on a scratch copy of the log (for bundles the
    /// sealer is expected to refuse, so the fixture log stays valid).
    pub fn scratch_bundle(&self, view: &DirectorySnapshot) -> (SnapshotBundle, TestLog) {
        let from = self.sealer.high_water_mark().tree_size;
        let mut log = self.log.lock().unwrap().clone();
        log.sync(view, &self.members);
        let b = log.bundle(view, from);
        (b, log)
    }

    /// The bundle of the current log (e.g. for a second sealer).
    pub fn current_bundle(&self) -> SnapshotBundle {
        let mut log = self.log.lock().unwrap();
        let v = self.snapshot.clone();
        log.bundle(&v, 0)
    }
}

/// The audit-logged developer override (tests run unhardened, as root, with
/// the client in the same process).
pub fn dev_mode() -> InsecureDevMode {
    use candor_log::codes::HostRole;
    use candor_log::ids::{AuditIdKey, TenantRef};
    let mut log = candor_log::AuditLog::new(
        TenantRef::derive(&AuditIdKey::new([3; 32]), b"tenant"),
        HostRole::Intake,
        candor_log::SoftwareSigner::from_seed(&zeroize::Zeroizing::new([9; 32])),
        candor_log::SystemClock,
        candor_log::CheckpointPolicy::DEFAULT,
    );
    log.set_primary_sink(Box::new(candor_log::sink::MemorySink::new()));
    InsecureDevMode::acknowledge(&mut log).unwrap()
}

pub fn config(chaff: ChaffConfig, limits: Limits, peer_uid: u32) -> SealerConfig {
    SealerConfig {
        tenant_id: TENANT,
        deployment_salt: SALT,
        suite: Suite::CandorStd1,
        allowed_peer_uid: peer_uid,
        limits,
        chaff,
        directory_trust: trust(),
        enable_note_real: false,
        insecure_dev: Some(dev_mode()),
    }
}

pub fn member(n: u8, role_label: u16, read_intake: bool) -> Member {
    let k08 = SigningKey::generate().unwrap();
    let entry_hash = sha256(&[b"user-keys", &[n]]);
    Member {
        user_id: [n; 16],
        role_label,
        read_intake,
        mek: KemKeyPair::generate(Suite::CandorStd1).unwrap(),
        k08,
        entry_hash,
    }
}

pub fn snapshot_for(
    members: &[Member],
    custodian: &KemKeyPair,
    disposition: &KemKeyPair,
    version: u64,
    issued_day: u32,
) -> DirectorySnapshot {
    DirectorySnapshot {
        snapshot_version: version,
        tree_size: 100 + version,
        issued_hour: u64::from(issued_day) * 24 + 3,
        suite: Suite::CandorStd1,
        custodian_pk: custodian.public.to_bytes(),
        disposition_pk: disposition.public.to_bytes(),
        channels: vec![ChannelView {
            channel_id: CHANNEL,
            enabled: true,
            members: members
                .iter()
                .map(|m| RosterMember {
                    user_id: m.user_id,
                    role_label: m.role_label,
                    read_intake: m.read_intake,
                    effective_day: TODAY - 30,
                })
                .collect(),
            coi_policies: vec![CoiPolicy {
                entry_hash: [0x66; 32],
                effective_day: TODAY - 10,
                categories: vec![(CATEGORY_FRAUD, vec![2])],
            }],
            meks: members
                .iter()
                .filter(|m| m.read_intake)
                .map(|m| MemberEpochKey {
                    user_id: m.user_id,
                    epoch_id: 0,
                    valid_from_day: TODAY - 2,
                    valid_until_day: TODAY + 5,
                    revoked: false,
                    public_key: m.mek.public.to_bytes(),
                })
                .collect(),
            independent_route: Some(ALT_CHANNEL),
        }],
    }
}

pub fn staging_root(dir: &Path) -> (PathBuf, &'static SafeRoot) {
    let p = dir.join("staging"); // safefs-lint: allow(test fixture path)
    std::fs::create_dir(&p).unwrap(); // safefs-lint: allow(test fixture setup)
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap(); // safefs-lint: allow(test fixture setup)
    let root = SafeRoot::open(&p, RootPolicy::Staging).unwrap();
    (p, Box::leak(Box::new(root)))
}

pub fn fixture_with(chaff: ChaffConfig, limits: Limits) -> Fixture {
    fixture_full(chaff, limits, rustix_uid())
}

pub fn fixture_full(chaff: ChaffConfig, limits: Limits, peer_uid: u32) -> Fixture {
    fixture_custom(chaff, limits, peer_uid, |_| {})
}

/// A fixture whose initial directory is first adjusted by `adjust` (initial
/// entries are not subject to the high-water-mark time lock).
pub fn fixture_custom(
    chaff: ChaffConfig,
    limits: Limits,
    peer_uid: u32,
    adjust: impl FnOnce(&mut DirectorySnapshot),
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap(); // safefs-lint: allow(test fixture setup)
    let (staging_path, staging) = staging_root(dir.path());
    let clock = Arc::new(TestClock {
        day: AtomicU32::new(TODAY),
        fail: AtomicBool::new(false),
    });
    let sink = Arc::new(MemorySink {
        staging,
        envelopes: Mutex::new(Vec::new()),
        accounts: Mutex::new(Vec::new()),
        ops: Mutex::new(Vec::new()),
        fail: AtomicBool::new(false),
        fail_accounts: AtomicBool::new(false),
        bundles: Mutex::new(Vec::new()),
    });
    // Triage Set: labels 1 (ombudsman), 2 (audit chair), 3 (counsel); label 4 is
    // a non-triage investigator.
    let members = vec![
        member(1, 1, true),
        member(2, 2, true),
        member(3, 3, true),
        member(4, 4, false),
    ];
    let custodian = KemKeyPair::generate(Suite::CandorStd1).unwrap();
    let disposition = KemKeyPair::generate(Suite::CandorStd1).unwrap();
    let k35 = [0x35; 32];
    let cfg = config(chaff, limits, peer_uid);
    let sealer = Sealer::new(
        cfg,
        SigningKey::from_seed(&k35),
        staging,
        clock.clone(),
        sink.clone(),
    )
    .unwrap();
    let mut members = members;
    let mut snapshot = snapshot_for(&members, &custodian, &disposition, 1, TODAY);
    adjust(&mut snapshot);
    let mut log = TestLog::new();
    log.sync(&snapshot, &members);
    for m in &mut members {
        m.entry_hash = log.user_hash[&m.user_id];
    }
    sealer
        .install_snapshot(log.bundle(&snapshot, 0), |_| true)
        .unwrap();
    Fixture {
        dir,
        staging_path,
        staging,
        clock,
        sink,
        sealer,
        members,
        custodian,
        disposition,
        k35,
        snapshot,
        log: Mutex::new(log),
    }
}

pub fn fixture() -> Fixture {
    fixture_with(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
    )
}

pub fn rustix_uid() -> u32 {
    // The test process's own uid, via /proc (no extra dependency).
    let status = std::fs::read_to_string("/proc/self/status").unwrap(); // safefs-lint: allow(test reads procfs)
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

pub fn sess(n: u8) -> SessionHandle {
    SessionHandle([n; 16])
}

pub fn words_to_phrase(words: &SecretWords) -> String {
    let l = Wordlist::eff_large().unwrap();
    words
        .0
        .iter()
        .map(|i| l.get(usize::from(*i)).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn confirm_words(words: &SecretWords, pos: [u8; 3]) -> SecretWords {
    SecretWords(zeroize::Zeroizing::new(
        pos.iter().map(|p| words.0[usize::from(*p)]).collect(),
    ))
}

/// Open a session, draft an anonymous report and confirm a fresh passphrase.
pub async fn confirmed(f: &Fixture, s: SessionHandle, coi: Option<Coi>) {
    let sl = &f.sealer;
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
            identity: Some(SecretText::new("dropped in anonymous mode")),
            coi,
        }),
    )
    .await;
    let Response::Words {
        words,
        confirm_positions,
    } = ok(sl, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
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
}

pub async fn ok(s: &Sealer, req: Request) -> Response {
    let r = s.handle(req).await;
    assert!(!matches!(r, Response::Error { .. }), "unexpected {r:?}");
    r
}

// ---------------------------------------------------------------------------
// Generic CBOR (test side only)

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    U(u64),
    B(Vec<u8>),
    T(String),
    A(Vec<Item>),
    M(Vec<(u64, Item)>),
    Bool(bool),
    Null,
}

impl Item {
    pub fn get(&self, k: u64) -> Option<&Item> {
        match self {
            Item::M(m) => m.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn u(&self) -> u64 {
        match self {
            Item::U(v) => *v,
            other => panic!("not uint: {other:?}"),
        }
    }
    pub fn b(&self) -> &[u8] {
        match self {
            Item::B(v) => v,
            other => panic!("not bytes: {other:?}"),
        }
    }
    pub fn t(&self) -> &str {
        match self {
            Item::T(v) => v,
            other => panic!("not text: {other:?}"),
        }
    }
    pub fn a(&self) -> &[Item] {
        match self {
            Item::A(v) => v,
            other => panic!("not array: {other:?}"),
        }
    }
}

fn head(b: &[u8], p: &mut usize) -> (u8, u64) {
    let x = b[*p];
    *p += 1;
    let info = x & 0x1f;
    let v = match info {
        0..=23 => u64::from(info),
        24 => {
            *p += 1;
            u64::from(b[*p - 1])
        }
        25 => {
            *p += 2;
            u64::from(u16::from_be_bytes([b[*p - 2], b[*p - 1]]))
        }
        26 => {
            *p += 4;
            u64::from(u32::from_be_bytes(b[*p - 4..*p].try_into().unwrap()))
        }
        27 => {
            *p += 8;
            u64::from_be_bytes(b[*p - 8..*p].try_into().unwrap())
        }
        _ => panic!("bad head"),
    };
    (x >> 5, v)
}

pub fn parse_item(b: &[u8], p: &mut usize) -> Item {
    let start = b[*p];
    if start == 0xf4 || start == 0xf5 || start == 0xf6 {
        *p += 1;
        return match start {
            0xf4 => Item::Bool(false),
            0xf5 => Item::Bool(true),
            _ => Item::Null,
        };
    }
    let (m, v) = head(b, p);
    let n = v as usize;
    match m {
        0 => Item::U(v),
        2 => {
            *p += n;
            Item::B(b[*p - n..*p].to_vec())
        }
        3 => {
            *p += n;
            Item::T(String::from_utf8(b[*p - n..*p].to_vec()).unwrap())
        }
        4 => Item::A((0..n).map(|_| parse_item(b, p)).collect()),
        5 => Item::M(
            (0..n)
                .map(|_| {
                    let k = parse_item(b, p).u();
                    (k, parse_item(b, p))
                })
                .collect(),
        ),
        _ => panic!("unsupported major {m}"),
    }
}

fn put_head(out: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    if v < 24 {
        out.push(m | v as u8);
    } else if v <= 0xff {
        out.push(m | 24);
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

pub fn encode_item(i: &Item, out: &mut Vec<u8>) {
    match i {
        Item::U(v) => put_head(out, 0, *v),
        Item::B(b) => {
            put_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Item::T(t) => {
            put_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Item::A(a) => {
            put_head(out, 4, a.len() as u64);
            a.iter().for_each(|x| encode_item(x, out));
        }
        Item::M(m) => {
            let mut m = m.clone();
            m.sort_by_key(|(k, _)| *k);
            put_head(out, 5, m.len() as u64);
            for (k, v) in &m {
                put_head(out, 0, *k);
                encode_item(v, out);
            }
        }
        Item::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Item::Null => out.push(0xf6),
    }
}

/// Parse `u32be(len) ‖ cbor ‖ zero padding`.
pub fn parse_padded(pt: &[u8]) -> (Item, Vec<u8>) {
    let len = u32::from_be_bytes(pt[..4].try_into().unwrap()) as usize;
    let cbor = pt[4..4 + len].to_vec();
    assert!(pt[4 + len..].iter().all(|b| *b == 0), "non-zero padding");
    let mut p = 0;
    let item = parse_item(&cbor, &mut p);
    assert_eq!(p, cbor.len());
    (item, cbor)
}

/// `H(cbor of all keys except `skip`)`.
pub fn hash_without(item: &Item, skip: &[u64]) -> [u8; 32] {
    let Item::M(m) = item else { panic!() };
    let kept = Item::M(
        m.iter()
            .filter(|(k, _)| !skip.contains(k))
            .cloned()
            .collect(),
    );
    let mut out = Vec::new();
    encode_item(&kept, &mut out);
    sha256(&[&out])
}

pub fn entries(item: &Item) -> Vec<RecipientListEntry> {
    item.a()
        .iter()
        .map(|e| RecipientListEntry::from_bytes(e.b()).unwrap())
        .collect()
}

/// Recipient side: open an intake object with a member MEK (or K13), verify the
/// slot block fully against `list`, and return the CK and plaintext.
pub fn open_intake(
    o: &StoredObject,
    ctx: SlotContext,
    sk: &candor_core::kem::KemPrivateKey,
) -> Option<(ContentKey, Vec<u8>)> {
    let parsed = object::parse(&o.bytes).unwrap();
    let block = RecipientSlotBlock::decode(&o.slot_block).unwrap();
    parsed.check_slot_block(&block).unwrap();
    let (ck, _) = block.trial_open(sk, &parsed.slot_binding(ctx)).ok()?;
    let pt = parsed.open(&ck).unwrap();
    Some((ck, pt.to_vec()))
}

pub fn verify_block(
    o: &StoredObject,
    ck: &ContentKey,
    ctx: SlotContext,
    list: &[RecipientListEntry],
    keys: &[(KeyKind, &KemKeyPair)],
) {
    let parsed = object::parse(&o.bytes).unwrap();
    let block = RecipientSlotBlock::decode(&o.slot_block).unwrap();
    block
        .verify_slot_block(ck, &parsed.slot_binding(ctx), list, |kid| {
            keys.iter()
                .find(|(kind, kp)| key_id(Suite::CandorStd1, *kind, &kp.public.to_bytes()) == *kid)
                .map(|(_, kp)| kp.public.clone())
        })
        .unwrap();
}

pub fn member_ctx(epoch: u32) -> SlotContext {
    SlotContext::MemberEpoch {
        tenant_id: TENANT,
        channel_id: CHANNEL,
        epoch_id: epoch,
    }
}

/// Recursively list every regular file below `dir` and return its bytes.
pub fn read_all_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).unwrap(); // safefs-lint: allow(test scans its own tempdir)
        for e in entries {
            let e = e.unwrap();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                out.push((e.path(), std::fs::read(e.path()).unwrap())); // safefs-lint: allow(test scans its own tempdir)
            }
        }
    }
    out
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
