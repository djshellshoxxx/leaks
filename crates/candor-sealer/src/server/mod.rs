// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Intake Sealer process (C-07): session table, operations, Argon2id gate,
//! chaff scheduler, Unix-socket listener and process hardening.
//!
//! Entry points: [`hardening::harden_process`] (main thread, before the tokio
//! runtime) → [`Sealer::new`] → [`Sealer::set_high_water_mark`] (persisted mark)
//! → [`Sealer::install_snapshot`] → [`Sealer::spawn_background`] →
//! [`Sealer::serve`] (refuses to serve unless the hardening self-check passes or
//! an audit-logged [`hardening::InsecureDevMode`] token is configured). See the
//! crate README for the systemd unit.

mod budget;
pub mod clock;
pub mod directory;
pub mod handover;
pub mod hardening;
pub mod kd;
pub mod merkle;
pub mod sink;

mod inner;
mod listener;
mod rand;
mod seal;
mod select;
mod session;

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use tokio::sync::{OwnedMutexGuard, Semaphore};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::proto::{
    DraftSet, DraftView, ErrorCode, Mode, PROTO_VERSION, PartView, PendingReply, ReplyView,
    Request, Response, SecretBytes, SecretText, SecretWords, SessionHandle,
};
use candor_core::hash::EvidenceHasher;
use candor_core::header::ObjectType;
use candor_core::kdf::ct_eq;
use candor_core::kem::KemPublicKey;
use candor_core::passphrase::{self, SourceKeys, Wordlist};
use candor_core::record::{RecordAad, open_record, seal_record};
use candor_core::secret::{AeadKey, Secret32, SessionKey};
use candor_core::sig::SigningKey;
use candor_core::{Suite, padding};
use candor_safefs::{SafeRoot, SlotTime};

pub use directory::SnapshotError;
pub use seal::{CHAFF_BUNDLE_MAX, ChaffBuckets};

use clock::Clock;
use directory::{DirectoryTrust, HighWaterMark, SnapshotBundle, VerifiedSnapshot};
use hardening::InsecureDevMode;
use inner::{MessageKind, Prefs, ReportPrefs};
use select::{Choice, SelectError, Selection};
use session::{PendingPhrase, Phase, Purpose, Session, StagedPart, Upload};
use sink::{AccountRecord, AccountUpsert, EnvelopeGroup, EnvelopeSink};

/// `prefs_ct` record key version and AAD `prefs_version` (04 §9.9).
const PREFS_VERSION: u32 = 1;
/// Audience bound into Tier W auth signatures (04 §11.5; SPEC-NOTES).
pub const AUTH_AUDIENCE: &[u8] = b"source-web";
/// Replay-detection memory per session.
const MAX_SEEN_REPLIES: usize = 4096;

/// Operational limits (07 §11, ADR-034, ADR-046(7)).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Concurrent sessions (07 §11: 64).
    pub max_sessions: usize,
    /// Idle timeout (ADR-034: 20 min).
    pub idle: Duration,
    /// Absolute timeout (ADR-034: 2 h).
    pub absolute: Duration,
    /// Concurrent Argon2id derivations (`ARGON2_MAX_CONCURRENT = 4`).
    pub argon_permits: usize,
    /// Queued derivations beyond the permits (07 §11: 32).
    pub argon_queue: usize,
    /// Maximum queue wait (07 §11: 30 s).
    pub argon_wait: Duration,
    /// Largest attachment (ADR-046(4): 4 GiB standard).
    pub max_file_bytes: u64,
    /// Largest total of attachments per envelope.
    pub max_bundle_bytes: u64,
    /// Files per envelope (07 §11: 20).
    pub max_parts: usize,
    /// Sealer-wide memory budget for staged parts plus sealed bundles, in
    /// bytes (AUD-RM2-SEA-26). Set it safely below the unit's `MemoryMax`
    /// minus the base working set; default 3,840 MiB (CE-SINGLE: 6,656 MiB −
    /// 2,560 MiB base − 256 MiB slack for chaff and empty bundles). A single
    /// upload needs about twice its size (part + bundle), so the largest
    /// accepted file is about half of this.
    pub memory_budget_bytes: u64,
    /// Confirmation attempts before the draft is zeroized (07 §5.2: 5).
    pub max_confirm_failures: u8,
    /// Passphrase (re)generations per session (SW-25: 5).
    pub max_phrase_generations: u8,
    /// Concurrent IPC connections (ADR-052(4)); ≥ the C-06 pool size.
    pub max_connections: usize,
    /// Time from connect to a complete `HELLO` frame.
    pub handshake_timeout: Duration,
    /// Time from a frame's length prefix to its last byte.
    pub frame_timeout: Duration,
    /// An established connection with no new frame for this long is closed.
    pub idle_timeout: Duration,
    /// Deadline for writing one response.
    pub write_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            idle: Duration::from_secs(20 * 60),
            absolute: Duration::from_secs(2 * 60 * 60),
            argon_permits: 4,
            argon_queue: 32,
            argon_wait: Duration::from_secs(30),
            max_file_bytes: 4 << 30,
            max_bundle_bytes: 4 << 30,
            max_parts: 20,
            memory_budget_bytes: 3_840 << 20,
            max_confirm_failures: 5,
            max_phrase_generations: 5,
            max_connections: 128,
            handshake_timeout: Duration::from_secs(5),
            frame_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(120),
            write_timeout: Duration::from_secs(5),
        }
    }
}

/// Chaff configuration (04 §12.7, ADR-047(3)).
#[derive(Debug, Clone)]
pub struct ChaffConfig {
    /// Run the per-channel Poisson schedule.
    pub enabled: bool,
    /// `intake.chaff.mean_interval` (default 2 h; HIGH may lower, never raise).
    pub mean_interval: Duration,
    /// `CHAFF_FOLLOWUP_SHARE` in permille (default 300).
    pub followup_share_permille: u16,
    /// Share of chaff envelopes given a delayed-delivery offset U{1,2,3}, in
    /// permille. Set it to the observed share of sources choosing delayed
    /// delivery, so the store's `release_day` column carries no signal
    /// (ADR-052(2)). Default 500.
    pub delayed_share_permille: u16,
    /// Bundle-size distribution.
    pub buckets: ChaffBuckets,
    /// Account writes (real and dummy) are batched and flushed at this fixed
    /// interval, independent of envelope commits (AUD-RM2-SEA-21). 1 min ..=
    /// 1 h; default 15 min.
    pub account_flush_interval: Duration,
    /// Share of chaff events that also rotate a dummy account (a synthetic
    /// passphrase rotation), in permille, so dummy accounts have the same
    /// lifecycle as real ones (SEA-21). Set by policy to the published share
    /// of real rotations; provisional default 50.
    pub dummy_rotation_permille: u16,
}

impl Default for ChaffConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mean_interval: Duration::from_secs(2 * 60 * 60),
            followup_share_permille: 300,
            delayed_share_permille: 500,
            buckets: ChaffBuckets::default(),
            account_flush_interval: Duration::from_secs(15 * 60),
            dummy_rotation_permille: 50,
        }
    }
}

/// Queued account writes are bounded; above this, new submissions get `BUSY`
/// until the store accepts a flush.
pub const MAX_QUEUED_ACCOUNTS: usize = 4096;
/// Dummy accounts remembered for synthetic rotations.
const MAX_DUMMY_TAGS: usize = 1024;

/// Account writes waiting for the next batch (AUD-RM2-SEA-21).
#[derive(Default)]
struct AccountQueue {
    pending: Vec<AccountUpsert>,
    /// Old lookup tags replaced by the batch being written right now.
    inflight_replaced: Vec<[u8; 32]>,
    /// Current lookup tags of dummy accounts (synthetic rotations pick one).
    dummies: std::collections::VecDeque<[u8; 32]>,
}

/// Sealer configuration. Secrets are not part of it: K35 is passed separately
/// (loaded by the integrator from a systemd credential, never an env var).
#[derive(Debug, Clone)]
pub struct SealerConfig {
    /// Tenant id.
    pub tenant_id: [u8; 16],
    /// Per-deployment salt from ORG_ROOT (04 §11.3).
    pub deployment_salt: [u8; 32],
    /// Suite.
    pub suite: Suite,
    /// UID of `candor-web`; any other peer is disconnected (SO_PEERCRED, 07 BE-006).
    pub allowed_peer_uid: u32,
    /// Limits.
    pub limits: Limits,
    /// Chaff.
    pub chaff: ChaffConfig,
    /// Directory trust anchors pinned at install (VR-1).
    pub directory_trust: DirectoryTrust,
    /// Serve `NOTE_REAL` (Tier V; off until RM-8, AUD-RM2-SEA-12).
    pub enable_note_real: bool,
    /// Developer override (tests only): serve without the hardening self-check,
    /// accept a same-UID peer and allow disabled chaff. Obtainable only through
    /// an audit-logged acknowledgement.
    pub insecure_dev: Option<InsecureDevMode>,
}

/// Start-up failure (the process must refuse to start).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// C-11 self-test failed (CRYPTO-034).
    SelfTest,
    /// Wordlist integrity failure.
    Wordlist,
    /// Unsupported suite or invalid configuration.
    Config,
    /// The staging root could not be emptied.
    Staging,
    /// The CSPRNG failed.
    Rng,
    /// A protection is disabled without [`hardening::InsecureDevMode`].
    Insecure,
}

impl core::fmt::Display for StartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::SelfTest => "crypto self-test failed",
            Self::Wordlist => "wordlist integrity check failed",
            Self::Config => "invalid sealer configuration",
            Self::Staging => "staging area could not be emptied",
            Self::Rng => "CSPRNG failure",
            Self::Insecure => "protection disabled without the developer override",
        })
    }
}

impl std::error::Error for StartError {}

struct Entry {
    sess: Arc<tokio::sync::Mutex<Session>>,
    created: Instant,
    last: Instant,
}

struct ArgonGate {
    sem: Arc<Semaphore>,
    waiting: std::sync::atomic::AtomicUsize,
    max_queue: usize,
    wait: Duration,
}

pub(crate) struct State {
    cfg: SealerConfig,
    sealer_key: SigningKey,
    staging: &'static SafeRoot,
    clock: Arc<dyn Clock>,
    sink: Arc<dyn EnvelopeSink>,
    snapshot: RwLock<Option<Arc<VerifiedSnapshot>>>,
    hwm: Mutex<HighWaterMark>,
    sessions: Mutex<HashMap<SessionHandle, Entry>>,
    argon: ArgonGate,
    chaff_seed: Secret32,
    chaff_counter: Mutex<u64>,
    chaff_cancels: Mutex<HashMap<[u8; 16], u32>>,
    accounts: Mutex<AccountQueue>,
    /// Attachment memory admission (SEA-26).
    mem: Arc<budget::Budget>,
    /// Serialises flushes (a batch completes before the next starts).
    flush_lock: Mutex<()>,
    accept_errors: Arc<AtomicU64>,
}

/// The sealer.
#[derive(Clone)]
pub struct Sealer {
    st: Arc<State>,
}

impl core::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sealer(<redacted>)")
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn err(code: ErrorCode) -> Response {
    Response::error(code)
}

fn select_err(e: SelectError) -> Response {
    match e {
        SelectError::NoEligible { alternative } => Response::Error {
            code: ErrorCode::NoEligibleTriage,
            alternative_channel_id: alternative,
        },
        SelectError::Unavailable { alternative } => Response::Error {
            code: ErrorCode::Unavailable,
            alternative_channel_id: alternative,
        },
    }
}

fn core_err(e: candor_core::Error) -> Response {
    match e {
        candor_core::Error::TooLarge | candor_core::Error::Length => err(ErrorCode::Limit),
        candor_core::Error::Authentication
        | candor_core::Error::Signature
        | candor_core::Error::SlotVerification => err(ErrorCode::Crypto),
        _ => err(ErrorCode::Internal),
    }
}

/// Length in bytes of the NFC form of `s`, counting only up to `cap + 1`.
fn nfc_len_capped(s: &str, cap: usize) -> usize {
    use unicode_normalization::UnicodeNormalization;
    let mut n = 0usize;
    for c in s.nfc() {
        n = n.saturating_add(c.len_utf8());
        if n > cap {
            break;
        }
    }
    n
}

/// The draft as it will be sealed fits the caps (`MAX_DRAFT_TEXT` for the
/// NFC message plus the answers, `MAX_IDENTITY_LEN` for the NFC identity).
fn draft_fits(ds: &DraftSet) -> bool {
    use crate::proto::{MAX_DRAFT_TEXT, MAX_IDENTITY_LEN};
    let answers = ds
        .fields
        .iter()
        .fold(0usize, |a, (_, t)| a.saturating_add(t.expose().len()));
    let Some(budget) = MAX_DRAFT_TEXT.checked_sub(answers) else {
        return false;
    };
    let identity_ok = ds
        .identity
        .as_ref()
        .is_none_or(|i| nfc_len_capped(i.expose(), MAX_IDENTITY_LEN) <= MAX_IDENTITY_LEN);
    identity_ok && nfc_len_capped(ds.message.expose(), budget) <= budget
}

/// Run blocking work on the blocking pool. In serve mode the work runs only on
/// a confined thread (AUD-RM2-SEA-20); otherwise the closure is dropped unrun
/// and the call fails like a panicked job.
async fn blocking<T, F>(f: F) -> Result<T, ()>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(move || hardening::guard().then(f)).await {
        Ok(Some(t)) => Ok(t),
        _ => Err(()),
    }
}

/// A fresh 256-bit secret from the CSPRNG. Callers never substitute a fixed
/// value on failure (AUD-RM2-SEA-05).
fn random_secret32() -> Result<Secret32, Response> {
    let mut k = Zeroizing::new([0u8; 32]);
    candor_core::fill_random(k.as_mut()).map_err(core_err)?;
    Ok(Secret32::from_bytes(*k))
}

/// A fresh K36 from the CSPRNG (never a fixed value on failure, SEA-05).
fn random_k36() -> Result<SessionKey, Response> {
    SessionKey::generate().map_err(core_err)
}

/// Map a generated passphrase back to word indices, scanning the whole list for
/// every word with constant-time compares.
fn word_indices(list: &Wordlist, phrase: &str) -> Result<Zeroizing<Vec<u16>>, Response> {
    use subtle::{ConditionallySelectable, ConstantTimeEq};
    let mut out = Zeroizing::new(Vec::with_capacity(list.word_count()));
    for tok in phrase.split(' ') {
        let mut idx = 0u16;
        let mut found = subtle::Choice::from(0u8);
        for i in 0..list.len() {
            let w = list.get(i).ok_or_else(|| err(ErrorCode::Internal))?;
            let i16 = u16::try_from(i).map_err(|_| err(ErrorCode::Internal))?;
            let eq = if w.len() == tok.len() {
                w.as_bytes().ct_eq(tok.as_bytes())
            } else {
                subtle::Choice::from(0u8)
            };
            idx.conditional_assign(&i16, eq);
            found |= eq;
        }
        if !bool::from(found) {
            return Err(err(ErrorCode::Internal));
        }
        out.push(idx);
    }
    if out.len() != list.word_count() {
        return Err(err(ErrorCode::Internal));
    }
    Ok(out)
}

/// Lossy UTF-8 decoding into a buffer sized once (each invalid byte becomes at
/// most one 3-byte U+FFFD), so no reallocation leaves a passphrase copy behind.
fn lossy_utf8(b: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(b.len().saturating_mul(3)));
    for chunk in b.utf8_chunks() {
        s.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            s.push(char::REPLACEMENT_CHARACTER);
        }
    }
    s
}

fn band(used: usize, max: usize) -> u8 {
    if max == 0 {
        return 4;
    }
    let q = used.saturating_mul(4).checked_div(max).unwrap_or(4);
    u8::try_from(q.min(4)).unwrap_or(4)
}

impl Sealer {
    /// Create the sealer. Runs the C-11 start-up self-test, checks the wordlist,
    /// and empties the staging root (no draft survives a restart, ADR-034).
    pub fn new(
        cfg: SealerConfig,
        sealer_key: SigningKey,
        staging: &'static SafeRoot,
        clock: Arc<dyn Clock>,
        sink: Arc<dyn EnvelopeSink>,
    ) -> Result<Self, StartError> {
        candor_core::selftest::self_test().map_err(|_| StartError::SelfTest)?;
        Wordlist::eff_large().map_err(|_| StartError::Wordlist)?;
        cfg.suite
            .require_supported()
            .map_err(|_| StartError::Config)?;
        if !cfg.chaff.buckets.is_valid()
            || cfg.chaff.mean_interval.is_zero()
            || cfg.chaff.mean_interval > Duration::from_secs(2 * 60 * 60)
            || cfg.chaff.followup_share_permille > 1000
            || cfg.chaff.delayed_share_permille > 1000
            || cfg.chaff.dummy_rotation_permille > 1000
            || cfg.chaff.account_flush_interval < Duration::from_secs(60)
            || cfg.chaff.account_flush_interval > Duration::from_secs(60 * 60)
            || cfg.limits.argon_permits == 0
            || cfg.limits.max_connections == 0
            || cfg.limits.memory_budget_bytes == 0
            || cfg.directory_trust.tenant_id != cfg.tenant_id
            || cfg.directory_trust.org_root_pk == [0u8; 32]
            || cfg.directory_trust.min_external > cfg.directory_trust.min_cosignatures
        {
            return Err(StartError::Config);
        }
        // Disabled chaff only with the audit-logged developer override (SEA-15).
        if !cfg.chaff.enabled && cfg.insecure_dev.is_none() {
            return Err(StartError::Insecure);
        }
        let slot = SlotTime::utc_day_start(0);
        staging
            .purge_incomplete(slot)
            .map_err(|_| StartError::Staging)?;
        for id in staging.list().map_err(|_| StartError::Staging)? {
            staging.remove(&id, slot).map_err(|_| StartError::Staging)?;
        }
        let chaff_seed = random_secret32().map_err(|_| StartError::Rng)?;
        let mem = budget::Budget::new(cfg.limits.memory_budget_bytes);
        let argon = ArgonGate {
            sem: Arc::new(Semaphore::new(cfg.limits.argon_permits)),
            waiting: std::sync::atomic::AtomicUsize::new(0),
            max_queue: cfg.limits.argon_queue,
            wait: cfg.limits.argon_wait,
        };
        Ok(Self {
            st: Arc::new(State {
                cfg,
                sealer_key,
                staging,
                clock,
                sink,
                snapshot: RwLock::new(None),
                hwm: Mutex::new(HighWaterMark::default()),
                sessions: Mutex::new(HashMap::new()),
                argon,
                chaff_seed,
                chaff_counter: Mutex::new(0),
                chaff_cancels: Mutex::new(HashMap::new()),
                accounts: Mutex::new(AccountQueue::default()),
                mem,
                flush_lock: Mutex::new(()),
                accept_errors: Arc::new(AtomicU64::new(0)),
            }),
        })
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.st.cfg.limits
    }

    /// `accept()` failures survived by the listener (health reporting).
    #[must_use]
    pub fn accept_errors(&self) -> u64 {
        self.st
            .accept_errors
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Restore the persisted high-water mark at start (09 owns its storage).
    /// A mark below the current one is ignored.
    pub fn set_high_water_mark(&self, hwm: HighWaterMark) {
        let mut h = lock(&self.st.hwm);
        if hwm.tree_size > h.tree_size {
            *h = hwm;
        }
    }

    /// The current high-water mark.
    #[must_use]
    pub fn high_water_mark(&self) -> HighWaterMark {
        *lock(&self.st.hwm)
    }

    /// Verify a snapshot bundle ([`VerifiedSnapshot::verify`] against the pinned
    /// trust and the current high-water mark), persist the new mark through
    /// `persist` **before** anything uses the snapshot, then swap it in
    /// atomically: sessions survive, and in-flight seals keep the snapshot they
    /// selected with (ADR-052(6)). Nothing changes on any error.
    pub fn install_snapshot(
        &self,
        bundle: SnapshotBundle,
        persist: impl FnOnce(&HighWaterMark) -> bool,
    ) -> Result<(), SnapshotError> {
        let mut h = lock(&self.st.hwm);
        let verified = VerifiedSnapshot::verify(
            bundle,
            &self.st.cfg.directory_trust,
            self.st.cfg.suite,
            &self.st.cfg.deployment_salt,
            &h,
        )?;
        if verified.base() != *h {
            return Err(SnapshotError::Stale);
        }
        let mark = verified.mark();
        if !persist(&mark) {
            return Err(SnapshotError::Persist);
        }
        *h = mark;
        let mut s = self
            .st
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *s = Some(Arc::new(verified));
        Ok(())
    }

    fn snapshot(&self) -> Option<Arc<VerifiedSnapshot>> {
        self.st
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Number of live sessions (for tests and the coarse `STATUS` band).
    #[must_use]
    pub fn session_count(&self) -> usize {
        lock(&self.st.sessions).len()
    }

    /// Drop every expired session now (also done by the background reaper).
    /// Expired entries are taken out under the table lock and dropped (zeroize,
    /// unlink staged files) after it is released (AUD-RM2-SEA-13).
    pub fn reap_expired(&self) {
        let now = Instant::now();
        let lim = &self.st.cfg.limits;
        let gone: Vec<Entry> = {
            let mut t = lock(&self.st.sessions);
            let dead: Vec<SessionHandle> = t
                .iter()
                .filter(|(_, e)| expired(e, now, lim))
                .map(|(h, _)| *h)
                .collect();
            dead.iter().filter_map(|h| t.remove(h)).collect()
        };
        drop(gone);
    }

    /// Handle one request.
    pub async fn handle(&self, req: Request) -> Response {
        // Serve mode: refuse on an unconfined thread (AUD-RM2-SEA-20).
        if !hardening::guard() {
            return err(ErrorCode::Internal);
        }
        match req {
            Request::Hello { proto } => {
                if proto != PROTO_VERSION {
                    return err(ErrorCode::BadFrame);
                }
                Response::Hello {
                    proto: PROTO_VERSION,
                    snapshot_version: self.snapshot().map_or(0, |s| s.snapshot_version),
                }
            }
            Request::SessionOpen { sess, channel_id } => self.session_open(sess, channel_id),
            Request::DraftSet(ds) => self.draft_set(ds).await,
            Request::DraftGet { sess } => self.draft_get(sess).await,
            Request::GenAccount { sess } => self.gen_phrase(sess, Purpose::NewAccount).await,
            Request::RotatePassphrase { sess } => self.gen_phrase(sess, Purpose::Rotation).await,
            Request::ConfirmPassphrase { sess, words } => self.confirm(sess, words).await,
            Request::LoginDerive { sess, passphrase } => self.login_derive(sess, passphrase).await,
            Request::LoginSign { sess, challenge } => self.login_sign(sess, challenge).await,
            Request::LoadPrefs { sess, prefs_ct } => self.load_prefs(sess, prefs_ct).await,
            Request::PartBegin {
                sess,
                declared_len,
                display_name,
                media_type,
            } => {
                self.part_begin(sess, declared_len, display_name, media_type)
                    .await
            }
            Request::PartChunk {
                sess,
                part,
                data,
                last,
            } => self.part_chunk(sess, part, data, last).await,
            Request::PartDrop { sess, part } => self.part_drop(sess, part).await,
            Request::SealFinish {
                sess,
                delayed_delivery,
            } => self.seal_finish(sess, delayed_delivery).await,
            Request::SealAbort { sess } => self.seal_abort(sess).await,
            Request::RotateFinish { sess, replies } => self.rotate_finish(sess, replies).await,
            Request::NoteReal {
                channel_id,
                first_object_hash,
            } => {
                if self.st.cfg.enable_note_real {
                    self.note_real(channel_id, first_object_hash)
                } else {
                    err(ErrorCode::BadState)
                }
            }
            Request::OpenReply { sess, entry } => self.open_reply(sess, entry).await,
            Request::Touch { sess } => match self.session(&sess) {
                Ok(_) => Response::Empty,
                Err(e) => e,
            },
            Request::Zeroize { sess } => {
                let removed = lock(&self.st.sessions).remove(&sess);
                drop(removed);
                Response::Empty
            }
            Request::Status => self.status(),
        }
    }

    // -- sessions ------------------------------------------------------------

    fn session(&self, h: &SessionHandle) -> Result<Arc<tokio::sync::Mutex<Session>>, Response> {
        let now = Instant::now();
        let lim = &self.st.cfg.limits;
        let mut t = lock(&self.st.sessions);
        let is_expired = match t.get(h) {
            None => return Err(err(ErrorCode::UnknownSession)),
            Some(e) => expired(e, now, lim),
        };
        if is_expired {
            let gone = t.remove(h);
            drop(t);
            drop(gone);
            return Err(err(ErrorCode::UnknownSession));
        }
        match t.get_mut(h) {
            Some(e) => {
                e.last = now;
                Ok(e.sess.clone())
            }
            None => Err(err(ErrorCode::UnknownSession)),
        }
    }

    async fn locked(&self, h: &SessionHandle) -> Result<OwnedMutexGuard<Session>, Response> {
        let s = self.session(h)?;
        Ok(s.lock_owned().await)
    }

    fn insert_session(&self, h: SessionHandle, s: Session) -> Result<(), Response> {
        let now = Instant::now();
        let mut t = lock(&self.st.sessions);
        if t.contains_key(&h) {
            return Err(err(ErrorCode::BadState));
        }
        if t.len() >= self.st.cfg.limits.max_sessions {
            return Err(err(ErrorCode::Busy));
        }
        t.insert(
            h,
            Entry {
                sess: Arc::new(tokio::sync::Mutex::new(s)),
                created: now,
                last: now,
            },
        );
        Ok(())
    }

    fn remove_session(&self, h: &SessionHandle) {
        let gone = lock(&self.st.sessions).remove(h);
        drop(gone);
    }

    fn session_open(&self, sess: SessionHandle, channel_id: [u8; 16]) -> Response {
        let known = self
            .snapshot()
            .and_then(|s| s.channel(&channel_id).map(|c| c.enabled))
            .unwrap_or(false);
        if !known {
            return err(ErrorCode::Unavailable);
        }
        let k36 = match random_k36() {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut s = Session::new(Phase::Drafting, k36);
        s.channel_id = Some(channel_id);
        match self.insert_session(sess, s) {
            Ok(()) => Response::Empty,
            Err(e) => e,
        }
    }

    // -- drafts --------------------------------------------------------------

    async fn draft_set(&self, ds: DraftSet) -> Response {
        let mut g = match self.locked(&ds.sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        match g.phase {
            Phase::Drafting => {}
            Phase::Authenticated => {
                // Follow-ups carry only a message (no identity, ticks or answers;
                // the follow-up rule fixes the recipients, ADR-036(4)).
                if ds.mode != Mode::Anonymous
                    || ds.identity.is_some()
                    || ds.coi.is_some()
                    || !ds.fields.is_empty()
                {
                    return err(ErrorCode::BadState);
                }
            }
            Phase::Derived => return err(ErrorCode::BadState),
        }
        // AUD-RM2-SEA-22: the SUBMISSION carries the NFC form of the message
        // (§13.4 key 13), which can be up to 3× longer than what was decoded.
        // Enforce the cap on what will be sealed, here, before any passphrase
        // or Argon2id work, so an unsealable draft is refused up front.
        if !draft_fits(&ds) {
            return err(ErrorCode::Limit);
        }
        g.draft.mode = Some(ds.mode);
        g.draft.message = ds.message;
        g.draft.fields = ds.fields;
        // Reverting to ANONYMOUS zeroizes a previous identity block (SW-05).
        g.draft.identity = if ds.mode == Mode::Anonymous {
            None
        } else {
            ds.identity
        };
        g.draft.coi = ds.coi;
        Response::Empty
    }

    async fn draft_get(&self, sess: SessionHandle) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        if g.phase == Phase::Derived {
            return err(ErrorCode::BadState);
        }
        // The source has now seen the draft as it is (SEA-26: attachments
        // dropped by a failed seal are no longer listed).
        g.parts_lost = false;
        Response::Draft(Box::new(DraftView {
            mode: g.draft.mode.unwrap_or(Mode::Anonymous),
            message: g.draft.message.clone(),
            fields: g.draft.fields.clone(),
            identity: g.draft.identity.clone(),
            coi: g.draft.coi.clone(),
            parts: g
                .parts
                .iter()
                .map(|p| PartView {
                    part: p.part_id,
                    size_bucket: p.padded_len,
                })
                .collect(),
        }))
    }

    // -- passphrases ---------------------------------------------------------

    async fn gen_phrase(&self, sess: SessionHandle, purpose: Purpose) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        let allowed = match purpose {
            Purpose::NewAccount => g.phase == Phase::Drafting && g.channel_id.is_some(),
            Purpose::Rotation => g.phase == Phase::Authenticated && g.prefs.is_some(),
        };
        if !allowed || g.pending.as_ref().is_some_and(|p| p.confirmed) {
            return err(ErrorCode::BadState);
        }
        if g.phrase_generations >= self.st.cfg.limits.max_phrase_generations {
            return err(ErrorCode::Limit);
        }
        let list = match Wordlist::eff_large() {
            Ok(l) => l,
            Err(_) => return err(ErrorCode::Internal),
        };
        // The previous pending passphrase (if any) is zeroized when replaced.
        g.pending = None;
        let phrase = match passphrase::generate(list) {
            Ok(p) => p,
            Err(e) => return core_err(e),
        };
        let words = match word_indices(list, phrase.expose()) {
            Ok(w) => w,
            Err(e) => return e,
        };
        let positions = match rand::confirm_positions(list.word_count()) {
            Ok(p) => p,
            Err(e) => return core_err(e),
        };
        let out = SecretWords(words.clone());
        g.pending = Some(PendingPhrase {
            phrase,
            words,
            positions,
            confirmed: false,
            purpose,
        });
        g.phrase_generations = g.phrase_generations.saturating_add(1);
        g.confirm_failures = 0;
        Response::Words {
            words: out,
            confirm_positions: positions,
        }
    }

    async fn confirm(&self, sess: SessionHandle, words: SecretWords) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        let Some(p) = g.pending.as_ref() else {
            return err(ErrorCode::BadState);
        };
        if p.confirmed {
            return err(ErrorCode::BadState);
        }
        let mut expected = Zeroizing::new([0u8; 6]);
        let mut given = Zeroizing::new([0u8; 6]);
        for (i, pos) in p.positions.iter().enumerate() {
            let e = p.words.get(usize::from(*pos)).copied().unwrap_or(u16::MAX);
            let w = words.0.get(i).copied().unwrap_or(u16::MAX);
            let at = i.saturating_mul(2);
            if let (Some(es), Some(gs)) = (
                expected.get_mut(at..at.saturating_add(2)),
                given.get_mut(at..at.saturating_add(2)),
            ) {
                es.copy_from_slice(&e.to_be_bytes());
                gs.copy_from_slice(&w.to_be_bytes());
            }
        }
        if ct_eq(expected.as_ref(), given.as_ref()) {
            if let Some(p) = g.pending.as_mut() {
                p.confirmed = true;
            }
            return Response::Confirm {
                ok: true,
                confirm_positions: None,
            };
        }
        g.confirm_failures = g.confirm_failures.saturating_add(1);
        if g.confirm_failures >= self.st.cfg.limits.max_confirm_failures {
            // After 5 failures the draft and passphrase are zeroized (07 §5.2).
            let purpose = g.pending.as_ref().map(|p| p.purpose);
            g.pending = None;
            if purpose == Some(Purpose::NewAccount) {
                drop(g);
                self.remove_session(&sess);
            }
            return Response::Confirm {
                ok: false,
                confirm_positions: None,
            };
        }
        let list_len = Wordlist::eff_large().map(Wordlist::word_count).unwrap_or(0);
        match rand::confirm_positions(list_len) {
            Ok(np) => {
                if let Some(p) = g.pending.as_mut() {
                    p.positions = np;
                }
                Response::Confirm {
                    ok: false,
                    confirm_positions: Some(np),
                }
            }
            Err(e) => core_err(e),
        }
    }

    // -- Argon2id ------------------------------------------------------------

    /// Run one derivation behind the semaphore (ADR-046(7), 07 §11): ≤ 4 active,
    /// ≤ 32 queued, ≤ 30 s wait; overflow and timeout give the uniform `BUSY`.
    async fn derive(&self, passphrase: Zeroizing<String>) -> Result<SourceKeys, Response> {
        use std::sync::atomic::Ordering;
        let gate = &self.st.argon;
        let queued = gate.waiting.fetch_add(1, Ordering::SeqCst);
        if queued >= gate.max_queue {
            gate.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(err(ErrorCode::Busy));
        }
        let permit = tokio::time::timeout(gate.wait, gate.sem.clone().acquire_owned()).await;
        gate.waiting.fetch_sub(1, Ordering::SeqCst);
        let permit = match permit {
            Ok(Ok(p)) => p,
            _ => return Err(err(ErrorCode::Busy)),
        };
        let suite = self.st.cfg.suite;
        let salt = self.st.cfg.deployment_salt;
        let tenant = self.st.cfg.tenant_id;
        let r = blocking(move || {
            let _permit = permit;
            let keys = SourceKeys::derive(suite, &passphrase, &salt, &tenant);
            drop(passphrase);
            keys
        })
        .await;
        match r {
            Ok(Ok(k)) => Ok(k),
            Ok(Err(e)) => Err(core_err(e)),
            Err(_) => Err(err(ErrorCode::Internal)),
        }
    }

    async fn login_derive(&self, sess: SessionHandle, passphrase: SecretBytes) -> Response {
        if lock(&self.st.sessions).len() >= self.st.cfg.limits.max_sessions {
            return err(ErrorCode::Busy);
        }
        // Invalid UTF-8 is derived like any other input (same work, no oracle).
        let text = lossy_utf8(&passphrase.0);
        drop(passphrase);
        let keys = match self.derive(text).await {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut lookup_tag = keys.lookup_tag();
        // SEA-28(a): a passphrase rotated away (replacement still queued or
        // being written) no longer logs in: the source gets a random locator,
        // which the store cannot find — exactly what a wrong passphrase gets.
        if replaced_pending(&self.st, &lookup_tag)
            && candor_core::fill_random(&mut lookup_tag).is_err()
        {
            return err(ErrorCode::Internal);
        }
        let k36 = match random_k36() {
            Ok(k) => k,
            Err(e) => return e,
        };
        let mut s = Session::new(Phase::Derived, k36);
        s.keys = Some(keys);
        match self.insert_session(sess, s) {
            Ok(()) => Response::Locator { lookup_tag },
            Err(e) => e,
        }
    }

    async fn login_sign(&self, sess: SessionHandle, challenge: [u8; 32]) -> Response {
        let g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        match (&g.phase, &g.keys) {
            (Phase::Derived | Phase::Authenticated, Some(k)) => Response::Signature {
                sig: k.sign_auth_challenge(&challenge, &self.st.cfg.tenant_id, AUTH_AUDIENCE),
            },
            _ => err(ErrorCode::BadState),
        }
    }

    fn prefs_aad(&self, lookup_tag: [u8; 32]) -> RecordAad {
        RecordAad::SourcePrefs {
            tenant_id: self.st.cfg.tenant_id,
            lookup_tag,
            prefs_version: PREFS_VERSION,
        }
    }

    async fn load_prefs(&self, sess: SessionHandle, prefs_ct: Vec<u8>) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        if g.phase != Phase::Derived {
            return err(ErrorCode::BadState);
        }
        let Some(keys) = g.keys.as_ref() else {
            return err(ErrorCode::BadState);
        };
        let pt = match open_record(
            keys.k_prefs(),
            &self.prefs_aad(keys.lookup_tag()),
            &prefs_ct,
        ) {
            Ok(pt) => pt,
            Err(_) => return err(ErrorCode::Crypto),
        };
        let prefs = match inner::decode_prefs(&pt) {
            Ok(p) if !p.reports.is_empty() => p,
            _ => return err(ErrorCode::Crypto),
        };
        g.channel_id = prefs.reports.first().map(|r| r.channel_id);
        g.prefs = Some(prefs);
        g.phase = Phase::Authenticated;
        Response::Empty
    }

    // -- attachment parts ----------------------------------------------------

    fn slot_today(&self) -> Result<(u32, SlotTime), Response> {
        let today = self
            .st
            .clock
            .today()
            .map_err(|_| err(ErrorCode::Unavailable))?;
        Ok((
            today,
            SlotTime::utc_day_start(u64::from(today).saturating_mul(86_400)),
        ))
    }

    async fn part_begin(
        &self,
        sess: SessionHandle,
        declared_len: u64,
        display_name: SecretText,
        media_type: SecretText,
    ) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        if g.phase == Phase::Derived || g.upload.is_some() {
            return err(ErrorCode::BadState);
        }
        let lim = &self.st.cfg.limits;
        let staged: u64 = g
            .parts
            .iter()
            .map(|p| p.real_len)
            .fold(0u64, u64::saturating_add);
        if g.parts.len() >= lim.max_parts
            || declared_len > lim.max_file_bytes
            || staged.saturating_add(declared_len) > lim.max_bundle_bytes
        {
            return err(ErrorCode::Limit);
        }
        let padded_len = match padding::bucket_for(ObjectType::AttachmentBundle, declared_len) {
            Ok(b) => b,
            Err(_) => return err(ErrorCode::Limit),
        };
        // SEA-26: reserve what this session's attachments can occupy at once
        // (every part's ciphertext plus the bundle for the declared total)
        // against the sealer-wide budget; refuse with the uniform BUSY.
        let Some(need) = attachment_need(&g.parts, padded_len, staged.saturating_add(declared_len))
        else {
            return err(ErrorCode::Limit);
        };
        let grant = g
            .mem
            .get_or_insert_with(|| budget::Grant::new(&self.st.mem));
        if !grant.grow_to(need) {
            return err(ErrorCode::Busy);
        }
        g.parts_lost = false;
        let fresh_part = match candor_core::stream::PartId::generate() {
            Ok(p) => p,
            Err(e) => return core_err(e),
        };
        let enc = match seal::staged_part_encryptor(&g.k36, &fresh_part, padded_len) {
            Ok(e) => e,
            Err(e) => return core_err(e),
        };
        let part_id = *fresh_part.as_bytes();
        let (object_id, pending) = match seal::stage_create(self.st.staging) {
            Ok(p) => p,
            // Staging full or unavailable: the uniform busy page (07 §5.3).
            Err(_) => return err(ErrorCode::Busy),
        };
        g.upload = Some(Upload {
            part_id,
            object_id,
            declared_len,
            padded_len,
            received: 0,
            sink: seal::StreamSink::new(enc, pending, padded_len),
            hasher: EvidenceHasher::new(),
            name: display_name,
            media_type,
        });
        Response::Part { part: part_id }
    }

    async fn part_chunk(
        &self,
        sess: SessionHandle,
        part: [u8; 16],
        data: SecretBytes,
        last: bool,
    ) -> Response {
        let g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        let slot = match self.slot_today() {
            Ok((_, s)) => s,
            Err(e) => return e,
        };
        let st = self.st.clone();
        let r = blocking(move || part_chunk_blocking(g, &st, part, &data, last, slot)).await;
        r.unwrap_or_else(|_| err(ErrorCode::Internal))
    }

    async fn part_drop(&self, sess: SessionHandle, part: [u8; 16]) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        if g.upload.as_ref().is_some_and(|u| u.part_id == part) {
            g.upload = None;
            return Response::Empty;
        }
        let before = g.parts.len();
        g.parts.retain(|p| p.part_id != part);
        if g.parts.len() == before {
            err(ErrorCode::BadState)
        } else {
            Response::Empty
        }
    }

    async fn seal_abort(&self, sess: SessionHandle) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        match random_k36() {
            Ok(k36) => {
                g.clear_draft(k36);
                g.pending = None;
                Response::Empty
            }
            Err(e) => {
                // Cannot re-key: drop the whole session instead (SEA-05).
                drop(g);
                self.remove_session(&sess);
                e
            }
        }
    }

    // -- sealing -------------------------------------------------------------

    /// Fail-closed preconditions for sealing (04 §12.6).
    fn seal_preconditions(
        &self,
        channel_id: &[u8; 16],
    ) -> Result<(Arc<VerifiedSnapshot>, u32, KemPublicKey, KemPublicKey), Response> {
        let (today, _) = self.slot_today()?;
        let snap = self.snapshot().ok_or_else(|| err(ErrorCode::Unavailable))?;
        let alt = snap
            .channel(channel_id)
            .and_then(|c| c.independent_route(today));
        let unavailable = Response::Error {
            code: ErrorCode::Unavailable,
            alternative_channel_id: alt,
        };
        if !snap.is_fresh(today) || snap.suite != self.st.cfg.suite {
            return Err(unavailable);
        }
        let custodian = KemPublicKey::from_bytes(snap.suite, &snap.custodian_pk)
            .map_err(|_| unavailable.clone())?;
        let disposition = KemPublicKey::from_bytes(snap.suite, &snap.disposition_pk)
            .map_err(|_| unavailable.clone())?;
        Ok((snap, today, custodian, disposition))
    }

    async fn seal_finish(&self, sess: SessionHandle, delayed: bool) -> Response {
        let mut g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        // A failed seal consumed the staged attachments: never submit without
        // them silently; the source must look at the draft again first.
        if g.upload.is_some() || g.parts_lost {
            return err(ErrorCode::BadState);
        }
        let initial = match g.phase {
            Phase::Drafting => {
                let ok = g
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.confirmed && p.purpose == Purpose::NewAccount);
                if !ok {
                    return err(ErrorCode::NotConfirmed);
                }
                true
            }
            Phase::Authenticated => {
                if g.pending.is_some() {
                    return err(ErrorCode::BadState);
                }
                false
            }
            Phase::Derived => return err(ErrorCode::BadState),
        };
        let Some(channel_id) = g.channel_id else {
            return err(ErrorCode::BadState);
        };
        let (snap, today, custodian, disposition) = match self.seal_preconditions(&channel_id) {
            Ok(v) => v,
            Err(e) => return e,
        };
        // Fix the recipient set now (ADR-034, RVW-A-07).
        let sel = {
            let coi = g.draft.coi.clone().unwrap_or_default();
            let report = g.prefs.as_ref().and_then(|p| p.reports.first());
            if !initial && report.is_none() {
                return err(ErrorCode::BadState);
            }
            // Follow-ups re-apply the active COI_POLICY for the report's
            // categories (AUD-RM2-SEA-10) within the original eligible set.
            let choice = match (initial, report) {
                (false, Some(r)) => Choice {
                    flagged_labels: &[],
                    categories: &r.categories,
                    original_eligible: Some(&r.original_eligible),
                },
                _ => Choice {
                    flagged_labels: &coi.excluded_labels,
                    categories: &coi.categories,
                    original_eligible: None,
                },
            };
            match select::select(&snap, &channel_id, today, choice) {
                Ok(s) => s,
                Err(e) => return select_err(e),
            }
        };
        let release_offset_days = if delayed {
            match rand::release_offset() {
                Ok(r) => r,
                Err(e) => return core_err(e),
            }
        } else {
            0
        };
        if initial {
            // Derive the new account's keys. The confirmed passphrase stays
            // pending until the commit succeeds (zeroized then), so a refusal
            // after derivation does not force a new passphrase (SEA-22).
            let phrase = match g.pending.as_ref() {
                Some(p) => Zeroizing::new(p.phrase.expose().to_owned()),
                None => return err(ErrorCode::NotConfirmed),
            };
            let keys = match self.derive(phrase).await {
                Ok(k) => k,
                Err(e) => return e,
            };
            g.keys = Some(keys);
        }
        let st = self.st.clone();
        let job = SealJob {
            snap,
            sel,
            today,
            custodian,
            disposition,
            release_offset_days,
            initial,
        };
        let r = blocking(move || seal_blocking(g, &st, job)).await;
        let (resp, drop_session) = r.unwrap_or_else(|_| (err(ErrorCode::Internal), false));
        if drop_session {
            // Committed, but K36 could not be replaced: the session ends (SEA-05).
            self.remove_session(&sess);
        }
        if matches!(resp, Response::Sealed { .. }) {
            self.cancel_next_chaff(channel_id);
        }
        resp
    }

    async fn rotate_finish(&self, sess: SessionHandle, replies: Vec<PendingReply>) -> Response {
        let g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        if g.phase != Phase::Authenticated || g.upload.is_some() {
            return err(ErrorCode::BadState);
        }
        let ok = g
            .pending
            .as_ref()
            .is_some_and(|p| p.confirmed && p.purpose == Purpose::Rotation);
        if !ok {
            return err(ErrorCode::NotConfirmed);
        }
        let Some(report) = g.prefs.as_ref().and_then(|p| p.reports.first()).cloned() else {
            return err(ErrorCode::BadState);
        };
        let (snap, today, custodian, disposition) =
            match self.seal_preconditions(&report.channel_id) {
                Ok(v) => v,
                Err(e) => return e,
            };
        // Follow-up rule (ADR-036(4)): if nobody of the original eligible set is
        // reachable, the case cannot learn the new key; rotation fails closed.
        let sel = match select::select(
            &snap,
            &report.channel_id,
            today,
            Choice {
                flagged_labels: &[],
                categories: &report.categories,
                original_eligible: Some(&report.original_eligible),
            },
        ) {
            Ok(s) => s,
            Err(e) => return select_err(e),
        };
        let phrase = match g.pending.as_ref() {
            Some(p) => Zeroizing::new(p.phrase.expose().to_owned()),
            None => return err(ErrorCode::NotConfirmed),
        };
        let new_keys = match self.derive(phrase).await {
            Ok(k) => k,
            Err(e) => return e,
        };
        let st = self.st.clone();
        let job = SealJob {
            snap,
            sel,
            today,
            custodian,
            disposition,
            release_offset_days: 0,
            initial: false,
        };
        let channel_id = report.channel_id;
        let r = blocking(move || rotate_blocking(g, &st, job, new_keys, &replies)).await;
        let resp = r.unwrap_or_else(|_| err(ErrorCode::Internal));
        if matches!(resp, Response::Locator { .. }) {
            self.cancel_next_chaff(channel_id);
        }
        resp
    }

    fn note_real(&self, channel_id: [u8; 16], first_object_hash: [u8; 32]) -> Response {
        let Some(snap) = self.snapshot() else {
            return err(ErrorCode::Unavailable);
        };
        if snap.channel(&channel_id).is_none() {
            return err(ErrorCode::Unavailable);
        }
        let Ok(k41) = KemPublicKey::from_bytes(snap.suite, &snap.disposition_pk) else {
            return err(ErrorCode::Unavailable);
        };
        match seal::disposition_ct(
            self.st.cfg.suite,
            &self.st.cfg.tenant_id,
            &k41,
            &first_object_hash,
            false,
        ) {
            Ok(d) => {
                self.cancel_next_chaff(channel_id);
                Response::Disposition { disposition_ct: d }
            }
            Err(e) => core_err(e),
        }
    }

    async fn open_reply(&self, sess: SessionHandle, entry: Vec<u8>) -> Response {
        let g = match self.locked(&sess).await {
            Ok(g) => g,
            Err(e) => return e,
        };
        if g.phase != Phase::Authenticated || g.keys.is_none() || g.prefs.is_none() {
            return err(ErrorCode::BadState);
        }
        let Some(snap) = self.snapshot() else {
            return err(ErrorCode::Unavailable);
        };
        let today = match self.slot_today() {
            Ok((d, _)) => d,
            Err(e) => return e,
        };
        let tenant = self.st.cfg.tenant_id;
        // Replies re-wrapped by a still-queued rotation open with the new key.
        let pending = g
            .keys
            .as_ref()
            .map(|k| pending_rewraps(&self.st, &k.lookup_tag()))
            .unwrap_or_default();
        let r = blocking(move || {
            let mut g = g;
            let opened = match (g.keys.as_ref(), g.prefs.as_ref()) {
                (Some(k), Some(p)) => {
                    seal::open_reply(&snap, tenant, k, p, &entry, today, &pending)
                }
                _ => None,
            };
            let Some((mailbox, inner)) = opened else {
                return Response::Reply(None);
            };
            if g.seen_replies
                .iter()
                .any(|(m, s)| *s == inner.reply_seq && ct_eq(m, &mailbox))
            {
                // A replayed reply is shown as "could not be verified".
                return Response::Reply(None);
            }
            if g.seen_replies.len() < MAX_SEEN_REPLIES {
                g.seen_replies.push((mailbox, inner.reply_seq));
            }
            Response::Reply(Some(ReplyView {
                reply_seq: inner.reply_seq,
                day: inner.day,
                role_label: SecretText(inner.role_label),
                body: SecretText(inner.body),
            }))
        })
        .await;
        r.unwrap_or_else(|_| err(ErrorCode::Internal))
    }

    fn status(&self) -> Response {
        use std::sync::atomic::Ordering;
        let lim = &self.st.cfg.limits;
        let sessions = lock(&self.st.sessions).len();
        let queued = self.st.argon.waiting.load(Ordering::SeqCst);
        Response::Status {
            sessions_band: band(sessions, lim.max_sessions),
            argon_queue_band: band(queued, lim.argon_queue),
            pool_free_band: 4,
        }
    }

    // -- chaff ---------------------------------------------------------------

    /// A real envelope was committed: cancel the channel's next scheduled chaff
    /// event (04 §12.7, 07 §5.2a).
    fn cancel_next_chaff(&self, channel_id: [u8; 16]) {
        let mut c = lock(&self.st.chaff_cancels);
        let n = c.entry(channel_id).or_insert(0);
        *n = n.saturating_add(1).min(64);
    }

    fn take_cancel(&self, channel_id: &[u8; 16]) -> bool {
        let mut c = lock(&self.st.chaff_cancels);
        match c.get_mut(channel_id) {
            Some(n) if *n > 0 => {
                *n = n.saturating_sub(1);
                true
            }
            _ => false,
        }
    }

    /// Build and commit one chaff envelope group for `channel_id` now (the
    /// scheduler calls this at each Poisson event). Fails closed (no write) on
    /// exactly the conditions under which real sealing refuses (SEA-15): no or
    /// stale snapshot, unknown or disabled channel, suite mismatch, invalid K13
    /// or K41, no independent time. Initial-shaped chaff also creates a dummy
    /// account and every chaff group draws a delivery delay like real ones
    /// (ADR-052(2)).
    pub async fn chaff_event(&self, channel_id: [u8; 16]) -> Result<(), ErrorCode> {
        let (today, _) = self.slot_today().map_err(|_| ErrorCode::Unavailable)?;
        let snap = self.snapshot().ok_or(ErrorCode::Unavailable)?;
        let enabled = snap.channel(&channel_id).is_some_and(|c| c.enabled);
        if !enabled || snap.suite != self.st.cfg.suite || !snap.is_fresh(today) {
            return Err(ErrorCode::Unavailable);
        }
        let epoch = snap.epoch_for_day(today).ok_or(ErrorCode::Unavailable)?;
        let custodian = KemPublicKey::from_bytes(snap.suite, &snap.custodian_pk)
            .map_err(|_| ErrorCode::Unavailable)?;
        let disposition = KemPublicKey::from_bytes(snap.suite, &snap.disposition_pk)
            .map_err(|_| ErrorCode::Unavailable)?;
        let chaff = &self.st.cfg.chaff;
        let followup = rand::bernoulli_permille(chaff.followup_share_permille)
            .map_err(|_| ErrorCode::Internal)?;
        let delay = if rand::bernoulli_permille(chaff.delayed_share_permille)
            .map_err(|_| ErrorCode::Internal)?
        {
            rand::release_offset().map_err(|_| ErrorCode::Internal)?
        } else {
            0
        };
        let st = self.st.clone();
        let r = blocking(move || {
            let ctx = seal::SealCtx {
                suite: st.cfg.suite,
                tenant_id: st.cfg.tenant_id,
                sealer_key: &st.sealer_key,
                staging: st.staging,
                custodian_pk: custodian,
                disposition_pk: disposition,
            };
            let account = if followup {
                None
            } else {
                Some(dummy_account(&st).map_err(|_| ErrorCode::Internal)?)
            };
            let group = {
                let mut counter = lock(&st.chaff_counter);
                seal::build_chaff(
                    &ctx,
                    channel_id,
                    epoch,
                    &st.chaff_seed,
                    &mut counter,
                    followup,
                    &st.cfg.chaff.buckets,
                )
                .map_err(|_| ErrorCode::Internal)?
            };
            // Same order and the same queue as a real initial submission:
            // the envelope now, the (dummy) account in the next shuffled batch.
            if account.is_some() && !queue_has_room(&st) {
                return Err(ErrorCode::Busy);
            }
            commit_group(st.sink.as_ref(), group, epoch, today, delay)?;
            if let Some(a) = account {
                let tag = a.account.lookup_tag;
                enqueue_account(&st, a);
                remember_dummy(&st, tag);
            }
            // Synthetic lifecycle: some chaff events also rotate a dummy.
            if rand::bernoulli_permille(st.cfg.chaff.dummy_rotation_permille)
                .map_err(|_| ErrorCode::Internal)?
            {
                rotate_dummy(&st).map_err(|_| ErrorCode::Internal)?;
            }
            Ok(())
        })
        .await;
        r.unwrap_or(Err(ErrorCode::Internal))
    }

    /// Write all queued account operations (real and dummy) to the store as one
    /// shuffled batch (AUD-RM2-SEA-21). Called at the fixed
    /// `account_flush_interval` by [`Sealer::spawn_background`]; the integrator
    /// also calls it at shutdown. Blocking. On a store error the unwritten
    /// operations stay queued (in order) for the next flush.
    pub fn flush_accounts(&self) -> Result<usize, sink::SinkError> {
        let _serial = lock(&self.st.flush_lock);
        let batch = {
            let mut q = lock(&self.st.accounts);
            let b = core::mem::take(&mut q.pending);
            q.inflight_replaced = b.iter().filter_map(|a| a.replaces).collect();
            b
        };
        let r = self.write_batch(batch);
        lock(&self.st.accounts).inflight_replaced.clear();
        r
    }

    fn write_batch(&self, batch: Vec<AccountUpsert>) -> Result<usize, sink::SinkError> {
        let batch = match shuffle_batch(batch.clone()) {
            Ok(b) => b,
            Err(_) => {
                requeue(&self.st, batch);
                return Err(sink::SinkError);
            }
        };
        let total = batch.len();
        let mut it = batch.into_iter();
        while let Some(a) = it.next() {
            if self.st.sink.upsert_account(a.clone()).is_err() {
                let mut rest = vec![a];
                rest.extend(it);
                requeue(&self.st, rest);
                return Err(sink::SinkError);
            }
        }
        Ok(total)
    }

    /// Graceful-shutdown flush (SEA-28(c)): queue 1–4 dummy account creates
    /// and write everything queued as one shuffled batch, so the last batch
    /// before a restart looks like any other. Blocking.
    pub fn shutdown_flush(&self) -> Result<usize, sink::SinkError> {
        let n = rand::uniform_below(4)
            .map_err(|_| sink::SinkError)?
            .saturating_add(1);
        for _ in 0..n {
            let a = dummy_account(&self.st).map_err(|_| sink::SinkError)?;
            let tag = a.account.lookup_tag;
            enqueue_account(&self.st, a);
            remember_dummy(&self.st, tag);
        }
        self.flush_accounts()
    }

    /// Install a SIGTERM handler (call inside the runtime, at start, so a
    /// failure is a start-up error) and return a task that, on SIGTERM, runs
    /// [`Sealer::shutdown_flush`] and then completes; the integrator awaits it
    /// and exits (SEA-28(c)).
    pub fn spawn_sigterm_flush(
        &self,
    ) -> std::io::Result<tokio::task::JoinHandle<Result<usize, sink::SinkError>>> {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let me = self.clone();
        Ok(tokio::spawn(async move {
            term.recv().await;
            let m = me.clone();
            blocking(move || m.shutdown_flush())
                .await
                .unwrap_or(Err(sink::SinkError))
        }))
    }

    /// Attachment memory reserved now (SEA-26; health reporting and tests).
    #[must_use]
    pub fn memory_reserved(&self) -> u64 {
        self.st.mem.used()
    }

    /// Number of queued account operations.
    #[must_use]
    pub fn queued_accounts(&self) -> usize {
        lock(&self.st.accounts).pending.len()
    }

    /// Spawn the session reaper, the account batch writer and (if enabled) the
    /// chaff scheduler. Must be called inside a tokio runtime.
    pub fn spawn_background(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut v = Vec::with_capacity(3);
        let me = self.clone();
        v.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(10));
            loop {
                iv.tick().await;
                // Unlinks happen off the async workers (AUD-RM2-SEA-13).
                let m = me.clone();
                let _ = blocking(move || m.reap_expired()).await;
            }
        }));
        let me = self.clone();
        v.push(tokio::spawn(async move {
            let every = me.st.cfg.chaff.account_flush_interval;
            let start = Instant::now()
                .checked_add(every)
                .unwrap_or_else(Instant::now);
            let mut iv = tokio::time::interval_at(start, every);
            loop {
                iv.tick().await;
                let m = me.clone();
                let _ = blocking(move || m.flush_accounts()).await;
            }
        }));
        if self.st.cfg.chaff.enabled {
            let me = self.clone();
            v.push(tokio::spawn(async move { me.chaff_loop().await }));
        }
        v
    }

    async fn chaff_loop(&self) {
        let mean = self.st.cfg.chaff.mean_interval.as_secs_f64();
        let draw = move || {
            rand::exponential_secs(mean)
                .ok()
                .and_then(|s| Duration::try_from_secs_f64(s).ok())
                .unwrap_or(Duration::from_secs_f64(mean))
        };
        let mut next: HashMap<[u8; 16], Instant> = HashMap::new();
        loop {
            let now = Instant::now();
            let channels: Vec<[u8; 16]> = self
                .snapshot()
                .map(|s| {
                    s.channels
                        .iter()
                        .filter(|c| c.enabled)
                        .map(|c| c.channel_id)
                        .collect()
                })
                .unwrap_or_default();
            next.retain(|c, _| channels.contains(c));
            for c in &channels {
                next.entry(*c).or_insert_with(|| later(now, draw()));
            }
            let due: Vec<[u8; 16]> = next
                .iter()
                .filter(|(_, t)| **t <= now)
                .map(|(c, _)| *c)
                .collect();
            for c in due {
                if !self.take_cancel(&c) {
                    // Failures leave no trace and are not retried (the schedule
                    // continues; no chaff state is persisted).
                    let _ = self.chaff_event(c).await;
                }
                next.insert(c, later(Instant::now(), draw()));
            }
            let wake = next
                .values()
                .min()
                .copied()
                .unwrap_or_else(|| later(now, Duration::from_secs(60)))
                .min(later(Instant::now(), Duration::from_secs(60)));
            tokio::time::sleep_until(wake).await;
        }
    }

    /// Serve the IPC protocol on an already bound listener (systemd socket or a
    /// socket in a 0700 RuntimeDirectory). Peers whose UID is not
    /// `allowed_peer_uid` are disconnected before any byte is read.
    ///
    /// Start-up self-check (ADR-052(5), AUD-RM2-SEA-06/18): unless an
    /// [`InsecureDevMode`] token is configured, refuses (`PermissionDenied`)
    /// before accepting anything when [`hardening::self_check`] fails or the
    /// peer UID is 0 or the sealer's own UID. Otherwise never returns.
    pub async fn serve(&self, listener: tokio::net::UnixListener) -> std::io::Result<()> {
        let enforce = self.st.cfg.insecure_dev.is_none();
        if enforce {
            let denied = |_| std::io::Error::from(std::io::ErrorKind::PermissionDenied);
            hardening::self_check().map_err(denied)?;
            hardening::check_peer_uid(self.st.cfg.allowed_peer_uid).map_err(denied)?;
            // From here on every thread doing sealer work is probed (SEA-20).
            hardening::enforce_threads();
        }
        listener::serve(
            self.clone(),
            listener,
            self.st.cfg.allowed_peer_uid,
            self.st.accept_errors.clone(),
        )
        .await
    }
}

fn later(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).unwrap_or(t)
}

fn expired(e: &Entry, now: Instant, lim: &Limits) -> bool {
    now.saturating_duration_since(e.created) >= lim.absolute
        || now.saturating_duration_since(e.last) >= lim.idle
}

fn part_chunk_blocking(
    mut g: OwnedMutexGuard<Session>,
    st: &State,
    part: [u8; 16],
    data: &SecretBytes,
    last: bool,
    slot: SlotTime,
) -> Response {
    let Some(up) = g.upload.as_mut() else {
        return err(ErrorCode::BadState);
    };
    if up.part_id != part {
        return err(ErrorCode::BadState);
    }
    let n = u64::try_from(data.0.len()).unwrap_or(u64::MAX);
    let within = up
        .received
        .checked_add(n)
        .is_some_and(|t| t <= up.declared_len);
    if !within {
        // Over the declared bound: abort the part (temp file removed on drop).
        g.upload = None;
        return err(ErrorCode::Limit);
    }
    up.hasher.update(&data.0);
    if up.sink.push(&data.0).is_err() {
        g.upload = None;
        return err(ErrorCode::Internal);
    }
    up.received = up.received.saturating_add(n);
    if !last {
        return Response::Empty;
    }
    let Some(up) = g.upload.take() else {
        return err(ErrorCode::Internal);
    };
    let Upload {
        part_id,
        object_id,
        padded_len,
        received,
        sink,
        hasher,
        name,
        media_type,
        ..
    } = up;
    let pending = match sink.finish() {
        Ok(p) => p,
        Err(_) => return err(ErrorCode::Internal),
    };
    let object = match seal::stage_commit(st.staging, pending, &object_id, slot) {
        Ok(id) => id,
        Err(_) => return err(ErrorCode::Busy),
    };
    g.parts.push(StagedPart {
        part_id,
        object,
        padded_len,
        real_len: received,
        name,
        media_type,
        hashes: session::PartHashes(hasher.finalize()),
        root: st.staging,
        slot,
    });
    Response::Empty
}

struct SealJob {
    snap: Arc<VerifiedSnapshot>,
    sel: Selection,
    today: u32,
    custodian: KemPublicKey,
    disposition: KemPublicKey,
    release_offset_days: u8,
    initial: bool,
}

fn seal_ctx<'a>(st: &'a State, job: &SealJob) -> seal::SealCtx<'a> {
    seal::SealCtx {
        suite: st.cfg.suite,
        tenant_id: st.cfg.tenant_id,
        sealer_key: &st.sealer_key,
        staging: st.staging,
        custodian_pk: job.custodian.clone(),
        disposition_pk: job.disposition.clone(),
    }
}

/// Hand an envelope group to the sink. The sealed bundle is an anonymous
/// memfd: whatever happens, it is freed when the group is dropped.
fn commit_group(
    sink: &dyn EnvelopeSink,
    group: EnvelopeGroup,
    epoch_id: u32,
    today: u32,
    release_offset_days: u8,
) -> Result<(), ErrorCode> {
    sink.commit_envelope_group(group, epoch_id, today, release_offset_days)
        .map_err(|_| ErrorCode::Internal)
}

/// `tag` is the old lookup tag of a replacement that is queued or being
/// written (SEA-28(a)).
fn replaced_pending(st: &State, tag: &[u8; 32]) -> bool {
    let q = lock(&st.accounts);
    q.pending
        .iter()
        .filter_map(|a| a.replaces.as_ref())
        .chain(q.inflight_replaced.iter())
        .any(|old| ct_eq(old, tag))
}

/// Re-wrapped reply stanzas still queued for the account `tag` (the latest
/// state of the account's replies, SEA-28(b)).
fn pending_rewraps(st: &State, tag: &[u8; 32]) -> Vec<([u8; 32], Vec<u8>)> {
    lock(&st.accounts)
        .pending
        .iter()
        .find(|a| ct_eq(&a.account.lookup_tag, tag))
        .map(|a| a.rewrapped_replies.clone())
        .unwrap_or_default()
}

/// Put unwritten operations back at the front of the queue.
fn requeue(st: &State, mut ops: Vec<AccountUpsert>) {
    let mut q = lock(&st.accounts);
    ops.append(&mut q.pending);
    q.pending = ops;
}

/// Upper bound on the bytes a session's attachments occupy at once: the
/// STREAM ciphertext of every staged part and of the new one, plus the sealed
/// bundle for `declared_total` real bytes (SEA-26).
fn attachment_need(parts: &[StagedPart], new_padded: u64, declared_total: u64) -> Option<u64> {
    use candor_core::header::{HEADER_LEN, HEADER_MAC_LEN};
    let mut sum = candor_core::stream::ciphertext_len(new_padded).ok()?;
    for p in parts {
        sum = sum.checked_add(candor_core::stream::ciphertext_len(p.padded_len).ok()?)?;
    }
    let bundle =
        padding::bucket_for(ObjectType::AttachmentBundle, declared_total.checked_add(8)?).ok()?;
    let bundle_ct = candor_core::stream::ciphertext_len(bundle)
        .ok()?
        .checked_add(u64::try_from(HEADER_LEN + HEADER_MAC_LEN).ok()?)?;
    sum.checked_add(bundle_ct)
}

/// Room for one more queued account write.
fn queue_has_room(st: &State) -> bool {
    lock(&st.accounts).pending.len() < MAX_QUEUED_ACCOUNTS
}

/// Queue an account write for the next batch. A replacement of an account
/// whose create (or earlier replacement) is still queued is merged into that
/// entry, so causal order survives the shuffle of the batch.
fn enqueue_account(st: &State, a: AccountUpsert) {
    let mut q = lock(&st.accounts);
    if let Some(old) = a.replaces
        && let Some(prev) = q
            .pending
            .iter_mut()
            .find(|p| ct_eq(&p.account.lookup_tag, &old))
    {
        // SEA-28(b): merge re-wrapped replies by object hash; the newer wrap
        // (to the newest key) wins, a wrap that was not redone is kept.
        prev.account = a.account;
        for (h, stanza) in a.rewrapped_replies {
            match prev
                .rewrapped_replies
                .iter_mut()
                .find(|(ph, _)| ct_eq(ph, &h))
            {
                Some(slot) => slot.1 = stanza,
                None => prev.rewrapped_replies.push((h, stanza)),
            }
        }
        return;
    }
    q.pending.push(a);
}

fn remember_dummy(st: &State, tag: [u8; 32]) {
    let mut q = lock(&st.accounts);
    if q.dummies.len() >= MAX_DUMMY_TAGS {
        q.dummies.pop_front();
    }
    q.dummies.push_back(tag);
}

/// A synthetic passphrase rotation of a random dummy account (SEA-21): the
/// same store operation as a real rotation (replace by old `lookup_tag`).
fn rotate_dummy(st: &State) -> Result<(), candor_core::Error> {
    let len = lock(&st.accounts).dummies.len();
    let Ok(n) = u32::try_from(len) else {
        return Ok(());
    };
    if n == 0 {
        return Ok(());
    }
    let i = usize::try_from(rand::uniform_below(n)?).map_err(|_| candor_core::Error::Internal)?;
    let mut fresh = dummy_account(st)?;
    let new_tag = fresh.account.lookup_tag;
    let old = {
        let mut q = lock(&st.accounts);
        let Some(slot) = q.dummies.get_mut(i) else {
            return Ok(());
        };
        core::mem::replace(slot, new_tag)
    };
    fresh.replaces = Some(old);
    enqueue_account(st, fresh);
    Ok(())
}

/// Order a batch: creates in a uniformly random order (CSPRNG Fisher–Yates),
/// then replacements in queue order (a replacement may target an account
/// created earlier in the same batch).
fn shuffle_batch(batch: Vec<AccountUpsert>) -> Result<Vec<AccountUpsert>, candor_core::Error> {
    let (mut creates, replaces): (Vec<_>, Vec<_>) =
        batch.into_iter().partition(|a| a.replaces.is_none());
    let mut i = creates.len();
    while i > 1 {
        let n = u32::try_from(i).map_err(|_| candor_core::Error::Internal)?;
        let j =
            usize::try_from(rand::uniform_below(n)?).map_err(|_| candor_core::Error::Internal)?;
        i = i.saturating_sub(1);
        creates.swap(i, j);
    }
    creates.extend(replaces);
    Ok(creates)
}

/// A dummy account for initial-shaped chaff (ADR-052(2)): random `lookup_tag`
/// and mailbox id, a real Ed25519 `auth_pk`, and a `prefs_ct` of the real fixed
/// length under a random key that is dropped at once. The store expires it like
/// an abandoned account.
fn dummy_account(st: &State) -> Result<AccountUpsert, candor_core::Error> {
    let mut lookup_tag = [0u8; 32];
    candor_core::fill_random(&mut lookup_tag)?;
    let mut mailbox = [0u8; 32];
    candor_core::fill_random(&mut mailbox)?;
    let auth = SigningKey::generate()?;
    let mut k = Zeroizing::new([0u8; 32]);
    candor_core::fill_random(k.as_mut())?;
    let key = AeadKey::from_bytes(*k);
    let pt = inner::length_prefixed_pad_to(&[], inner::PREFS_PADDED_LEN)?;
    let prefs_ct = seal_record(
        &key,
        PREFS_VERSION,
        &RecordAad::SourcePrefs {
            tenant_id: st.cfg.tenant_id,
            lookup_tag,
            prefs_version: PREFS_VERSION,
        },
        &pt,
    )?;
    Ok(AccountUpsert {
        replaces: None,
        account: AccountRecord {
            lookup_tag,
            auth_pk: auth.verifying_key_bytes(),
            prefs_ct,
            mailbox_ids: vec![mailbox],
        },
        rewrapped_replies: Vec::new(),
    })
}

fn prefs_ct(st: &State, keys: &SourceKeys, prefs: &Prefs) -> Result<Vec<u8>, candor_core::Error> {
    let pt = inner::encode_prefs(prefs)?;
    seal_record(
        keys.k_prefs(),
        PREFS_VERSION,
        &RecordAad::SourcePrefs {
            tenant_id: st.cfg.tenant_id,
            lookup_tag: keys.lookup_tag(),
            prefs_version: PREFS_VERSION,
        },
        &pt,
    )
}

/// After a commit: drop the draft and install a fresh K36. If the CSPRNG fails,
/// the draft is still dropped, K36 is left as it was (never a fixed value) and
/// `true` asks the caller to remove the whole session (AUD-RM2-SEA-05).
fn rekey_after_commit(
    sess: &mut Session,
    rng: impl FnOnce() -> Result<SessionKey, Response>,
) -> bool {
    match rng() {
        Ok(fresh) => {
            sess.clear_draft(fresh);
            false
        }
        Err(_) => {
            sess.clear_draft_contents();
            true
        }
    }
}

/// Returns the response and whether the session must be removed (SEA-05).
fn seal_blocking(mut g: OwnedMutexGuard<Session>, st: &State, job: SealJob) -> (Response, bool) {
    let ctx = seal_ctx(st, &job);
    let sel = &job.sel;
    let sess = &mut *g;
    let Some(keys) = sess.keys.as_ref() else {
        return (err(ErrorCode::BadState), false);
    };
    let coi = sess.draft.coi.clone().unwrap_or_default();
    let identity = sess.draft.identity.as_ref().map(|t| t.expose().to_owned());
    let identity = identity.map(Zeroizing::new);
    // SEA-26: the bundle is built part by part and each staged part is
    // removed as soon as it is written, so the parts leave the session now;
    // if this seal then fails, the attachments are gone and the session must
    // re-show its draft before sealing again (`parts_lost`).
    let parts = core::mem::take(&mut sess.parts);
    sess.parts_lost = !parts.is_empty();
    let (group, account) = if job.initial {
        let draft = seal::DraftInput {
            mode: sess.draft.mode.unwrap_or(Mode::Anonymous),
            message: sess.draft.message.expose(),
            fields: &sess.draft.fields,
            identity: identity.as_ref().map(|s| s.as_str()),
            flagged_labels: &coi.excluded_labels,
            categories: &coi.categories,
        };
        let (group, sub_hash) =
            match seal::seal_initial(&ctx, sel, keys, 0, &draft, &parts, &sess.k36) {
                Ok(v) => v,
                Err(e) => return (core_err(e), false),
            };
        let mailbox_id = match keys.mailbox_id(0) {
            Ok(m) => m,
            Err(e) => {
                return (core_err(e), false);
            }
        };
        let prefs = Prefs {
            reports: vec![ReportPrefs {
                report_index: 0,
                mailbox_id,
                original_eligible: sel.eligible_user_ids.clone(),
                roster_version: sel.roster_version,
                channel_id: sel.channel_id,
                original_submission_hash: sub_hash,
                categories: coi.categories.clone(),
            }],
        };
        let ct = match prefs_ct(st, keys, &prefs) {
            Ok(c) => c,
            Err(e) => {
                return (core_err(e), false);
            }
        };
        let account = AccountUpsert {
            replaces: None,
            account: AccountRecord {
                lookup_tag: keys.lookup_tag(),
                auth_pk: keys.auth_key().verifying_key_bytes(),
                prefs_ct: ct,
                mailbox_ids: vec![mailbox_id],
            },
            rewrapped_replies: Vec::new(),
        };
        sess.prefs = Some(prefs);
        (group, Some(account))
    } else {
        let Some(report) = sess.prefs.as_ref().and_then(|p| p.reports.first()) else {
            return (err(ErrorCode::BadState), false);
        };
        let sm = seal::SourceMessageInput {
            keys,
            report,
            kind: MessageKind::Message,
            message: sess.draft.message.expose(),
            new_keys: None,
        };
        match seal::seal_source_message(&ctx, sel, &sm, &parts, &sess.k36) {
            Ok(o) => (o, None),
            Err(e) => return (core_err(e), false),
        }
    };
    let disposition_ct = match seal::disposition_ct(
        ctx.suite,
        &ctx.tenant_id,
        &ctx.disposition_pk,
        &group.main.object_hash,
        false,
    ) {
        Ok(d) => d,
        Err(e) => {
            return (core_err(e), false);
        }
    };
    let group = group.into_group(sel.channel_id, disposition_ct);
    // ADR-052(2): the account is a separate store operation, written first so a
    // "received" answer implies both are durable. An account left behind by a
    // failed envelope commit is indistinguishable from a chaff dummy account.
    // AUD-RM2-SEA-21: the envelope is committed now; the account goes into the
    // next shuffled batch with dummy accounts, written at a fixed interval, so
    // the store sees no account write next to this envelope.
    if account.is_some() && !queue_has_room(st) {
        if job.initial {
            sess.prefs = None;
            sess.keys = None;
        }
        return (err(ErrorCode::Busy), false);
    }
    let committed = commit_group(
        st.sink.as_ref(),
        group,
        sel.epoch_id,
        job.today,
        job.release_offset_days,
    );
    if let Err(code) = committed {
        if job.initial {
            // Not committed: the source must restart (§11.1).
            sess.prefs = None;
            sess.keys = None;
        }
        return (err(code), false);
    }
    if let Some(a) = account {
        enqueue_account(st, a);
    }
    // Committed and fsynced: zeroize K36, the draft and staged parts (§9.13).
    // On CSPRNG failure the draft is still dropped and the whole session is
    // removed; a fixed key is never installed (AUD-RM2-SEA-05).
    let drop_session = rekey_after_commit(sess, random_k36);
    if job.initial {
        // Committed: the passphrase is no longer needed (§11.1).
        sess.pending = None;
        sess.phase = Phase::Authenticated;
    }
    // Keep the snapshot alive until here (selection consistency).
    drop(job.snap);
    (
        Response::Sealed {
            release_offset_days: job.release_offset_days,
        },
        drop_session,
    )
}

fn rotate_blocking(
    mut g: OwnedMutexGuard<Session>,
    st: &State,
    job: SealJob,
    new_keys: SourceKeys,
    replies: &[PendingReply],
) -> Response {
    let ctx = seal_ctx(st, &job);
    let sess = &mut *g;
    let (Some(old), Some(prefs)) = (sess.keys.as_ref(), sess.prefs.as_ref()) else {
        return err(ErrorCode::BadState);
    };
    // Entries that do not open (corrupt, foreign or planted by a compromised
    // store) are skipped: they stay unreadable and cannot block the source's
    // recovery action (AUD-RM2-SEA-14).
    // SEA-28(b): a rotation within the batch window starts from the latest
    // pending state: a reply already re-wrapped to the current key by a queued
    // rotation is re-wrapped from that stanza, not from the stale one the store
    // still holds, and queued re-wraps the caller did not resend are redone.
    let queued = pending_rewraps(st, &old.lookup_tag());
    let mut inputs: Vec<PendingReply> = replies
        .iter()
        .map(|r| PendingReply {
            object_hash: r.object_hash,
            stanza: queued
                .iter()
                .find(|(h, _)| ct_eq(h, &r.object_hash))
                .map_or_else(|| r.stanza.clone(), |(_, s)| s.clone()),
        })
        .collect();
    for (h, s) in &queued {
        if !inputs.iter().any(|r| ct_eq(&r.object_hash, h)) {
            inputs.push(PendingReply {
                object_hash: *h,
                stanza: s.clone(),
            });
        }
    }
    let mut rewrapped = Vec::with_capacity(inputs.len());
    for r in &inputs {
        if let Ok(s) = seal::rewrap_reply(
            st.cfg.suite,
            st.cfg.tenant_id,
            old,
            new_keys.kem_public_key(),
            prefs,
            r,
        ) {
            rewrapped.push((r.object_hash, s));
        }
    }
    let mut groups = Vec::with_capacity(prefs.reports.len());
    for report in &prefs.reports {
        let sm = seal::SourceMessageInput {
            keys: old,
            report,
            kind: MessageKind::KeyRotation,
            message: "",
            new_keys: Some(&new_keys),
        };
        let group = match seal::seal_source_message(&ctx, &job.sel, &sm, &[], &sess.k36) {
            Ok(o) => o,
            Err(e) => {
                return core_err(e);
            }
        };
        match seal::disposition_ct(
            ctx.suite,
            &ctx.tenant_id,
            &ctx.disposition_pk,
            &group.main.object_hash,
            false,
        ) {
            Ok(d) => groups.push(group.into_group(report.channel_id, d)),
            Err(e) => {
                return core_err(e);
            }
        }
    }
    let new_prefs = prefs.clone();
    let ct = match prefs_ct(st, &new_keys, &new_prefs) {
        Ok(c) => c,
        Err(e) => {
            return core_err(e);
        }
    };
    let upsert = AccountUpsert {
        replaces: Some(old.lookup_tag()),
        account: AccountRecord {
            lookup_tag: new_keys.lookup_tag(),
            auth_pk: new_keys.auth_key().verifying_key_bytes(),
            prefs_ct: ct,
            mailbox_ids: new_prefs.reports.iter().map(|r| r.mailbox_id).collect(),
        },
        rewrapped_replies: rewrapped,
    };
    // KEY_ROTATION groups first, then the account (ADR-052(2)). The account
    // replacement is queued for the next batch (SEA-21); until it is written
    // the old passphrase keeps working.
    if !queue_has_room(st) {
        return err(ErrorCode::Busy);
    }
    for group in groups {
        if commit_group(st.sink.as_ref(), group, job.sel.epoch_id, job.today, 0).is_err() {
            return err(ErrorCode::Internal);
        }
    }
    // Queued like every account write (SEA-21); coalesced with a not yet
    // flushed create of the same account.
    enqueue_account(st, upsert);
    let lookup_tag = new_keys.lookup_tag();
    // The old keys and the new passphrase are zeroized here.
    sess.keys = Some(new_keys);
    sess.pending = None;
    drop(job.snap);
    Response::Locator { lookup_tag }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn upsert(tag: u8, replaces: Option<u8>) -> AccountUpsert {
        AccountUpsert {
            replaces: replaces.map(|r| [r; 32]),
            account: AccountRecord {
                lookup_tag: [tag; 32],
                auth_pk: [0; 32],
                prefs_ct: vec![],
                mailbox_ids: vec![],
            },
            rewrapped_replies: vec![],
        }
    }

    /// AUD-RM2-SEA-21: a batch is a uniformly shuffled permutation of the
    /// creates followed by the replacements in queue order (a replacement may
    /// target an account created in the same batch).
    #[test]
    fn account_batches_are_shuffled_creates_then_replacements() {
        let mut queue: Vec<AccountUpsert> = (0..20u8).map(|t| upsert(t, None)).collect();
        queue.push(upsert(100, Some(3)));
        queue.push(upsert(101, Some(100)));
        let out = shuffle_batch(queue.clone()).unwrap();
        assert_eq!(out.len(), 22);
        let tags: Vec<u8> = out.iter().map(|a| a.account.lookup_tag[0]).collect();
        let mut creates = tags[..20].to_vec();
        assert_ne!(creates, (0..20u8).collect::<Vec<_>>(), "1/20! chance");
        creates.sort_unstable();
        assert_eq!(creates, (0..20u8).collect::<Vec<_>>());
        assert_eq!(&tags[20..], &[100, 101]);
    }

    #[test]
    fn lossy_utf8_never_reallocates() {
        let input = b"abc\xff\xfe def\xc3";
        let s = lossy_utf8(input);
        assert_eq!(s.as_str(), String::from_utf8_lossy(input));
        assert_eq!(s.capacity(), input.len() * 3);
        let s = lossy_utf8(b"plain words");
        assert_eq!(s.as_str(), "plain words");
    }

    /// AUD-RM2-SEA-05 regression: a CSPRNG failure after a commit never installs
    /// a fixed K36; the draft is dropped and the session is marked for removal.
    #[test]
    fn rng_failure_after_commit_never_installs_a_fixed_key() {
        let mut s = Session::new(Phase::Drafting, SessionKey::from_bytes([7; 32]));
        s.draft.message = SecretText::new("draft");
        let drop = rekey_after_commit(&mut s, || Err(err(ErrorCode::Internal)));
        assert!(drop);
        assert_eq!(s.k36.expose(), &[7; 32]);
        assert!(s.draft.message.expose().is_empty());
        let drop = rekey_after_commit(&mut s, || Ok(SessionKey::from_bytes([9; 32])));
        assert!(!drop);
        assert_eq!(s.k36.expose(), &[9; 32]);
    }

    #[test]
    fn bands_are_coarse() {
        assert_eq!(band(0, 64), 0);
        assert_eq!(band(63, 64), 3);
        assert_eq!(band(64, 64), 4);
        assert_eq!(band(1000, 64), 4);
        assert_eq!(band(1, 0), 4);
    }

    #[test]
    fn word_indices_round_trip() {
        let list = Wordlist::eff_large().unwrap();
        let p = passphrase::generate(list).unwrap();
        let idx = word_indices(list, p.expose()).unwrap();
        let back: Vec<&str> = idx
            .iter()
            .map(|i| list.get(usize::from(*i)).unwrap())
            .collect();
        assert_eq!(back.join(" "), p.expose());
        assert!(word_indices(list, "notaword").is_err());
    }
}
