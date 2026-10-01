// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealer IPC protocol (07 §5.2), owned by `candor-sealer` and usable without the
//! `server` feature (only `zeroize` is needed). `candor-web` (C-06) links this
//! module to talk to the sealer; nothing here touches the network, disk or clock.
//!
//! # Framing
//! `u32be(len) ‖ CBOR`, `1 ≤ len ≤` [`MAX_FRAME_LEN`] (128 KiB, 07 §5.2). The CBOR
//! is one deterministic map `{"v": 1, "op": u8, "rid": u32, "body": map}` in
//! canonical key order (`v`, `op`, `rid`, `body`). Responses use the same shape
//! and echo `op` and `rid`; an error response has `op = 0` ([`OP_ERROR`]).
//! Decoding is strict: unknown ops, unknown or misordered keys, oversize fields,
//! non-canonical CBOR and trailing bytes are rejected ([`ProtoError`]); the
//! server then answers `ERR{BAD_FRAME}` and closes the connection (07 BE-006).
//!
//! # Body keys
//! Bodies use unsigned integer keys. Key 1 is always the session handle `sess`
//! (16 bytes) for session operations. The per-operation layout is documented on
//! each [`Request`] / [`Response`] variant as `{key: field}`.

pub mod cbor;

use cbor::{CborError, Dec, Enc, MapKeys};
use zeroize::{Zeroize, Zeroizing};

/// Envelope version (`"v"`).
pub const ENVELOPE_VERSION: u64 = 1;
/// Protocol version exchanged in `HELLO` (07 §5.2: `proto: 2`).
pub const PROTO_VERSION: u64 = 2;
/// Maximum CBOR frame length (07 §5.2: 128 KiB).
pub const MAX_FRAME_LEN: usize = 131_072;
/// Maximum login passphrase bytes (07 §5.2 `LOGIN_DERIVE`).
pub const MAX_PASSPHRASE_LEN: usize = 256;
/// Maximum total draft text (message + answers), bytes. Lower than the 96 KiB of
/// 07 §5.2 so that every SUBMISSION fits its 64 KiB maximum bucket (SPEC-NOTES).
pub const MAX_DRAFT_TEXT: usize = 40_960;
/// Maximum number of questionnaire answers.
pub const MAX_FIELDS: usize = 64;
/// Maximum identity block bytes (07 §5.2).
pub const MAX_IDENTITY_LEN: usize = 4096;
/// Maximum COI role-label ticks (07 §5.2).
pub const MAX_COI_LABELS: usize = 16;
/// Maximum COI categories (07 §5.2).
pub const MAX_COI_CATEGORIES: usize = 8;
/// Maximum plaintext bytes per `PART_CHUNK` (one STREAM chunk).
pub const MAX_CHUNK_LEN: usize = 65_536;
/// Maximum display-name bytes (04 §13.4 key 18).
pub const MAX_DISPLAY_NAME_LEN: usize = 255;
/// Maximum claimed media type bytes.
pub const MAX_MEDIA_TYPE_LEN: usize = 127;
/// Maximum `prefs_ct` bytes (07 §5.2).
pub const MAX_PREFS_CT_LEN: usize = 4096;
/// Maximum dead-drop entry bytes for `OPEN_REPLY` (07 §5.2: 70,000).
pub const MAX_REPLY_ENTRY_LEN: usize = 70_000;
/// Maximum pending replies re-wrapped per `ROTATE_FINISH`.
pub const MAX_ROTATE_REPLIES: usize = 64;
/// Maximum Wrap Stanza bytes accepted for re-wrapping (HPKE_BASE is 1,242 B).
pub const MAX_STANZA_LEN: usize = 2048;
/// Maximum passphrase word count (any list with N ≥ 2048 needs ≤ 12 words).
pub const MAX_WORDS: usize = 16;
/// Words re-typed at confirmation (04 §11.1).
pub const CONFIRM_WORDS: usize = 3;
/// Maximum staged parts listed in `DRAFT_GET` (07 §11: max 32 files).
pub const MAX_PARTS: usize = 32;
/// Maximum reply body bytes (04 §13.5: 60 KiB).
pub const MAX_REPLY_BODY_LEN: usize = 61_440;
/// Maximum reply role label bytes.
pub const MAX_ROLE_LABEL_LEN: usize = 255;

/// Opaque web-session handle (random 128-bit value from C-06). A bearer value:
/// `Debug` is redacted.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionHandle(pub [u8; 16]);

impl core::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionHandle(<redacted>)")
    }
}

/// Secret bytes (passphrase, attachment data): zeroized on drop, redacted `Debug`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretBytes(pub Zeroizing<Vec<u8>>);

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl SecretBytes {
    /// Copy from a slice.
    #[must_use]
    pub fn from_slice(b: &[u8]) -> Self {
        Self(Zeroizing::new(b.to_vec()))
    }
}

/// Secret text (draft text, names, reply bodies): zeroized on drop, redacted `Debug`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretText(pub Zeroizing<String>);

impl core::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretText(<redacted>)")
    }
}

impl SecretText {
    /// Copy from a `&str`.
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self(Zeroizing::new(s.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Passphrase word indices (into the shipped wordlist): zeroized, redacted.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretWords(pub Zeroizing<Vec<u16>>);

impl core::fmt::Debug for SecretWords {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretWords(<redacted>)")
    }
}

/// Submission mode (04 §13.4 key 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// ANONYMOUS.
    Anonymous = 0,
    /// CONFIDENTIAL (identity block sealed to custodians).
    Confidential = 1,
    /// IDENTIFIED.
    Identified = 2,
}

impl Mode {
    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(Self::Anonymous),
            1 => Ok(Self::Confidential),
            2 => Ok(Self::Identified),
            _ => Err(ProtoError::Field),
        }
    }
}

/// COI ticks (ADR-030/037): role labels the source flagged and report categories.
/// Both strictly ascending. Draft-sensitive: zeroized, redacted.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Coi {
    /// Flagged role-label ids (≤ 16).
    pub excluded_labels: Zeroizing<Vec<u16>>,
    /// Selected category ids (≤ 8).
    pub categories: Zeroizing<Vec<u16>>,
}

impl core::fmt::Debug for Coi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Coi(<redacted>)")
    }
}

/// `DRAFT_SET` body: `{1: sess, 2: mode, 3: message, 4: [[field_id, text]…],
/// 5: identity | null, 6: {1: [label…], 2: [category…]} | null}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSet {
    /// Session.
    pub sess: SessionHandle,
    /// Mode.
    pub mode: Mode,
    /// Free-text message.
    pub message: SecretText,
    /// Questionnaire answers, strictly ascending by field id.
    pub fields: Vec<(u16, SecretText)>,
    /// Identity block (CONFIDENTIAL / IDENTIFIED only).
    pub identity: Option<SecretText>,
    /// COI ticks.
    pub coi: Option<Coi>,
}

/// A staged part as listed by `DRAFT_GET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartView {
    /// Part id.
    pub part: [u8; 16],
    /// Padded size bucket (ADR-011), never the exact size.
    pub size_bucket: u64,
}

/// `DRAFT_GET` response body: `{1: mode, 2: message, 3: fields, 4: identity | null,
/// 5: coi | null, 6: [[part, size_bucket]…]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftView {
    /// Mode.
    pub mode: Mode,
    /// Message.
    pub message: SecretText,
    /// Answers.
    pub fields: Vec<(u16, SecretText)>,
    /// Identity block.
    pub identity: Option<SecretText>,
    /// COI ticks.
    pub coi: Option<Coi>,
    /// Staged parts.
    pub parts: Vec<PartView>,
}

/// A pending reply to re-wrap at rotation: `[object_hash, stanza]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReply {
    /// `object_hash` of the REPLY object.
    pub object_hash: [u8; 32],
    /// Its stanza (1) (HPKE_BASE to the source).
    pub stanza: Vec<u8>,
}

/// A verified reply for rendering: `{1: reply_seq, 2: day, 3: role_label, 4: body}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyView {
    /// Per-mailbox sequence number.
    pub reply_seq: u64,
    /// UTC day (day granularity only).
    pub day: u32,
    /// Signer's roster role label.
    pub role_label: SecretText,
    /// Body.
    pub body: SecretText,
}

/// Operation codes (07 §5.2; `PART_*`, `ROTATE_FINISH` and `TOUCH` are this
/// implementation's, see SPEC-NOTES).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// 0x01
    Hello = 0x01,
    /// 0x02
    SessionOpen = 0x02,
    /// 0x03
    DraftSet = 0x03,
    /// 0x04
    DraftGet = 0x04,
    /// 0x10
    GenAccount = 0x10,
    /// 0x11
    LoginDerive = 0x11,
    /// 0x12
    LoginSign = 0x12,
    /// 0x13
    LoadPrefs = 0x13,
    /// 0x14
    ConfirmPassphrase = 0x14,
    /// 0x15
    RotatePassphrase = 0x15,
    /// 0x16
    RotateFinish = 0x16,
    /// 0x20
    PartBegin = 0x20,
    /// 0x21
    PartChunk = 0x21,
    /// 0x22
    SealFinish = 0x22,
    /// 0x23
    SealAbort = 0x23,
    /// 0x24
    PartDrop = 0x24,
    /// 0x25
    NoteReal = 0x25,
    /// 0x30
    OpenReply = 0x30,
    /// 0x40
    Zeroize = 0x40,
    /// 0x41
    Touch = 0x41,
    /// 0x7F
    Status = 0x7f,
}

/// Error responses use this op value.
pub const OP_ERROR: u8 = 0x00;

impl Op {
    /// Parse an op code.
    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x01 => Self::Hello,
            0x02 => Self::SessionOpen,
            0x03 => Self::DraftSet,
            0x04 => Self::DraftGet,
            0x10 => Self::GenAccount,
            0x11 => Self::LoginDerive,
            0x12 => Self::LoginSign,
            0x13 => Self::LoadPrefs,
            0x14 => Self::ConfirmPassphrase,
            0x15 => Self::RotatePassphrase,
            0x16 => Self::RotateFinish,
            0x20 => Self::PartBegin,
            0x21 => Self::PartChunk,
            0x22 => Self::SealFinish,
            0x23 => Self::SealAbort,
            0x24 => Self::PartDrop,
            0x25 => Self::NoteReal,
            0x30 => Self::OpenReply,
            0x40 => Self::Zeroize,
            0x41 => Self::Touch,
            0x7f => Self::Status,
            _ => return Err(ProtoError::UnknownOp),
        })
    }
}

/// Requests from `candor-web`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `{1: proto}` → [`Response::Hello`]. First message on every connection.
    Hello {
        /// Protocol version (must be [`PROTO_VERSION`]).
        proto: u64,
    },
    /// `{1: sess, 2: channel_id}` → [`Response::Empty`]. RAM-only drafting session
    /// with a fresh K36.
    SessionOpen {
        /// Session.
        sess: SessionHandle,
        /// Channel.
        channel_id: [u8; 16],
    },
    /// Replace the RAM draft → [`Response::Empty`].
    DraftSet(DraftSet),
    /// `{1: sess}` → [`Response::Draft`].
    DraftGet {
        /// Session.
        sess: SessionHandle,
    },
    /// `{1: sess}` → [`Response::Words`]. Generates (or regenerates, SW-25) the
    /// passphrase of a new account.
    GenAccount {
        /// Session.
        sess: SessionHandle,
    },
    /// `{1: sess, 2: passphrase}` → [`Response::Locator`]. Creates a session.
    LoginDerive {
        /// New session.
        sess: SessionHandle,
        /// Passphrase bytes (≤ 256).
        passphrase: SecretBytes,
    },
    /// `{1: sess, 2: challenge}` → [`Response::Signature`].
    LoginSign {
        /// Session.
        sess: SessionHandle,
        /// Store challenge.
        challenge: [u8; 32],
    },
    /// `{1: sess, 2: prefs_ct}` → [`Response::Empty`]. Unlocks the inbox.
    LoadPrefs {
        /// Session.
        sess: SessionHandle,
        /// `prefs_ct` from the store.
        prefs_ct: Vec<u8>,
    },
    /// `{1: sess, 2: [w_a, w_b, w_c]}` → [`Response::Confirm`].
    ConfirmPassphrase {
        /// Session.
        sess: SessionHandle,
        /// The three re-typed words as list indices, in position order.
        words: SecretWords,
    },
    /// `{1: sess}` → [`Response::Words`]. Starts a rotation (AUTHENTICATED).
    RotatePassphrase {
        /// Session.
        sess: SessionHandle,
    },
    /// `{1: sess, 2: [[object_hash, stanza]…]}` → [`Response::Locator`] (new tag).
    RotateFinish {
        /// Session.
        sess: SessionHandle,
        /// Pending replies to re-wrap (≤ 64).
        replies: Vec<PendingReply>,
    },
    /// `{1: sess, 2: declared_len, 3: display_name, 4: media_type}` →
    /// [`Response::Part`]. `declared_len` is an upper bound of the part's size
    /// (the web's request length); the part is padded to its bucket.
    PartBegin {
        /// Session.
        sess: SessionHandle,
        /// Upper bound of the part size.
        declared_len: u64,
        /// Display name (metadata only, never a path, ADR-027).
        display_name: SecretText,
        /// Claimed media type.
        media_type: SecretText,
    },
    /// `{1: sess, 2: part, 3: data, 4: last}` → [`Response::Empty`].
    PartChunk {
        /// Session.
        sess: SessionHandle,
        /// Part id from `PART_BEGIN`.
        part: [u8; 16],
        /// Plaintext (≤ 64 KiB).
        data: SecretBytes,
        /// Last chunk of the part.
        last: bool,
    },
    /// `{1: sess, 2: delayed_delivery}` → [`Response::Sealed`]. The only step that
    /// seals to recipients (ADR-034).
    SealFinish {
        /// Session.
        sess: SessionHandle,
        /// Source opted into delayed delivery (ADR-038(4)).
        delayed_delivery: bool,
    },
    /// `{1: sess}` → [`Response::Empty`].
    SealAbort {
        /// Session.
        sess: SessionHandle,
    },
    /// `{1: sess, 2: part}` → [`Response::Empty`].
    PartDrop {
        /// Session.
        sess: SessionHandle,
        /// Part id.
        part: [u8; 16],
    },
    /// `{1: channel_id, 2: first_object_hash}` → [`Response::Disposition`] (Tier V).
    NoteReal {
        /// Channel.
        channel_id: [u8; 16],
        /// `object_hash` of the envelope's first object.
        first_object_hash: [u8; 32],
    },
    /// `{1: sess, 2: entry}` → [`Response::Reply`].
    OpenReply {
        /// Session.
        sess: SessionHandle,
        /// Dead-drop entry `u32 entry_len ‖ SealedObject ‖ stanza(1)`.
        entry: Vec<u8>,
    },
    /// `{1: sess}` → [`Response::Empty`]; idempotent.
    Zeroize {
        /// Session.
        sess: SessionHandle,
    },
    /// `{1: sess}` → [`Response::Empty`]; resets the idle timer only (SW-21).
    Touch {
        /// Session.
        sess: SessionHandle,
    },
    /// `{}` → [`Response::Status`].
    Status,
}

impl Request {
    /// The request's op.
    #[must_use]
    pub fn op(&self) -> Op {
        match self {
            Self::Hello { .. } => Op::Hello,
            Self::SessionOpen { .. } => Op::SessionOpen,
            Self::DraftSet(_) => Op::DraftSet,
            Self::DraftGet { .. } => Op::DraftGet,
            Self::GenAccount { .. } => Op::GenAccount,
            Self::LoginDerive { .. } => Op::LoginDerive,
            Self::LoginSign { .. } => Op::LoginSign,
            Self::LoadPrefs { .. } => Op::LoadPrefs,
            Self::ConfirmPassphrase { .. } => Op::ConfirmPassphrase,
            Self::RotatePassphrase { .. } => Op::RotatePassphrase,
            Self::RotateFinish { .. } => Op::RotateFinish,
            Self::PartBegin { .. } => Op::PartBegin,
            Self::PartChunk { .. } => Op::PartChunk,
            Self::SealFinish { .. } => Op::SealFinish,
            Self::SealAbort { .. } => Op::SealAbort,
            Self::PartDrop { .. } => Op::PartDrop,
            Self::NoteReal { .. } => Op::NoteReal,
            Self::OpenReply { .. } => Op::OpenReply,
            Self::Zeroize { .. } => Op::Zeroize,
            Self::Touch { .. } => Op::Touch,
            Self::Status => Op::Status,
        }
    }
}

/// Error codes (07 §5.2 plus `BAD_STATE` and `UNAVAILABLE`, see SPEC-NOTES).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Malformed frame; the connection is closed.
    BadFrame = 1,
    /// Unknown or expired session.
    UnknownSession = 2,
    /// Capacity (sessions, Argon2id queue, staging). Uniform for all causes.
    Busy = 3,
    /// No eligible Triage Set member (fail closed, ADR-037(1)).
    NoEligibleTriage = 4,
    /// `SEAL_FINISH` / `ROTATE_FINISH` before a successful confirmation.
    NotConfirmed = 5,
    /// A size or count limit.
    Limit = 6,
    /// Authentication or cryptographic failure.
    Crypto = 7,
    /// Internal failure; nothing was released or committed.
    Internal = 8,
    /// Operation not allowed in the session's state.
    BadState = 9,
    /// Intake unavailable for the channel (stale directory, clock, suite; 04 §12.6).
    Unavailable = 10,
}

impl ErrorCode {
    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            1 => Self::BadFrame,
            2 => Self::UnknownSession,
            3 => Self::Busy,
            4 => Self::NoEligibleTriage,
            5 => Self::NotConfirmed,
            6 => Self::Limit,
            7 => Self::Crypto,
            8 => Self::Internal,
            9 => Self::BadState,
            10 => Self::Unavailable,
            _ => return Err(ProtoError::Field),
        })
    }
}

/// Responses from the sealer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `{1: proto, 2: snapshot_version}`.
    Hello {
        /// Protocol version.
        proto: u64,
        /// Installed directory snapshot version (0 if none).
        snapshot_version: u64,
    },
    /// `{}`.
    Empty,
    /// Draft view.
    Draft(DraftView),
    /// `{1: [word…], 2: [p_a, p_b, p_c]}`: the passphrase (as list indices) and the
    /// confirmation positions.
    Words {
        /// Word indices.
        words: SecretWords,
        /// Positions to confirm, ascending.
        confirm_positions: [u8; 3],
    },
    /// `{1: lookup_tag}`.
    Locator {
        /// `lookup_tag` (04 §11.4).
        lookup_tag: [u8; 32],
    },
    /// `{1: sig}`.
    Signature {
        /// Ed25519 signature.
        sig: [u8; 64],
    },
    /// `{1: ok, 2: positions | null}`.
    Confirm {
        /// Match.
        ok: bool,
        /// New positions after a mismatch (absent after the last attempt).
        confirm_positions: Option<[u8; 3]>,
    },
    /// `{1: part}`.
    Part {
        /// Part id.
        part: [u8; 16],
    },
    /// `{1: release_offset_days}`: committed and `fsync`ed.
    Sealed {
        /// Delayed-delivery offset in days (0..=3).
        release_offset_days: u8,
    },
    /// `{1: disposition_ct}`.
    Disposition {
        /// Real-kind disposition marker (04 §12.7).
        disposition_ct: Vec<u8>,
    },
    /// `{1: reply | null}`: `null` for an entry that is not for this source or
    /// does not verify (indistinguishable).
    Reply(Option<ReplyView>),
    /// `{1: sessions_band, 2: argon_queue_band, 3: pool_free_band}` (coarse bands).
    Status {
        /// Sessions band 0..=4.
        sessions_band: u8,
        /// Argon2id queue band 0..=4.
        argon_queue_band: u8,
        /// Free pool band 0..=4.
        pool_free_band: u8,
    },
    /// `{1: code, 2: alternative_channel_id | null}` with `op = 0`.
    Error {
        /// Code.
        code: ErrorCode,
        /// The channel's independent route (NO_ELIGIBLE_TRIAGE / UNAVAILABLE).
        alternative_channel_id: Option<[u8; 16]>,
    },
}

impl Response {
    /// An error without alternative channel.
    #[must_use]
    pub fn error(code: ErrorCode) -> Self {
        Self::Error {
            code,
            alternative_channel_id: None,
        }
    }
}

/// Protocol decoding/encoding failure. Carries no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// CBOR-level failure.
    Cbor(CborError),
    /// Frame length outside `1..=MAX_FRAME_LEN`.
    FrameLength,
    /// Envelope version or protocol shape mismatch.
    Version,
    /// Unknown op code.
    UnknownOp,
    /// A field value is out of range or violates ordering/uniqueness.
    Field,
    /// The response op does not match the request.
    Mismatch,
    /// I/O failure while reading or writing a frame.
    Io,
}

impl From<CborError> for ProtoError {
    fn from(e: CborError) -> Self {
        Self::Cbor(e)
    }
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cbor(e) => write!(f, "{e}"),
            Self::FrameLength => f.write_str("frame length out of range"),
            Self::Version => f.write_str("protocol version mismatch"),
            Self::UnknownOp => f.write_str("unknown op"),
            Self::Field => f.write_str("field out of range"),
            Self::Mismatch => f.write_str("response does not match request"),
            Self::Io => f.write_str("frame I/O failure"),
        }
    }
}

impl std::error::Error for ProtoError {}

// ---------------------------------------------------------------------------
// Envelope

fn envelope(op: u8, rid: u32, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut e = Enc::with_capacity(body.len().saturating_add(32));
    e.map(4);
    e.text("v").uint(ENVELOPE_VERSION);
    e.text("op").uint(u64::from(op));
    e.text("rid").uint(u64::from(rid));
    e.text("body").raw(body);
    e.into_bytes()
}

fn open_envelope(bytes: &[u8]) -> Result<(u8, u32, Dec<'_>, MapKeys), ProtoError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_LEN {
        return Err(ProtoError::FrameLength);
    }
    let mut d = Dec::new(bytes);
    let mut m = d.map(4)?;
    d.text_key(&mut m, "v")?;
    if d.uint()? != ENVELOPE_VERSION {
        return Err(ProtoError::Version);
    }
    d.text_key(&mut m, "op")?;
    let op = d.u8()?;
    d.text_key(&mut m, "rid")?;
    let rid = d.u32()?;
    d.text_key(&mut m, "body")?;
    d.end_map(m)?;
    let body = d.map(16)?;
    Ok((op, rid, d, body))
}

fn sess(d: &mut Dec<'_>, m: &mut MapKeys) -> Result<SessionHandle, ProtoError> {
    d.req(m, 1)?;
    Ok(SessionHandle(d.bytes_n::<16>()?))
}

fn put_sess(e: &mut Enc, s: &SessionHandle) {
    e.uint(1).bytes(&s.0);
}

fn secret_text(d: &mut Dec<'_>, max: usize) -> Result<SecretText, ProtoError> {
    Ok(SecretText::new(d.text(max)?))
}

fn strictly_ascending(v: &[u16]) -> bool {
    v.windows(2).all(|w| matches!(w, [a, b] if a < b))
}

fn u16_list(d: &mut Dec<'_>, max: usize) -> Result<Zeroizing<Vec<u16>>, ProtoError> {
    let n = d.array(max)?;
    let mut v = Zeroizing::new(Vec::with_capacity(n));
    for _ in 0..n {
        v.push(d.u16()?);
    }
    if !strictly_ascending(&v) {
        return Err(ProtoError::Field);
    }
    Ok(v)
}

fn put_u16_list(e: &mut Enc, v: &[u16]) {
    e.array(v.len());
    for x in v {
        e.uint(u64::from(*x));
    }
}

fn dec_fields(d: &mut Dec<'_>, budget: &mut usize) -> Result<Vec<(u16, SecretText)>, ProtoError> {
    let n = d.array(MAX_FIELDS)?;
    let mut out: Vec<(u16, SecretText)> = Vec::with_capacity(n);
    for _ in 0..n {
        d.array_exact(2)?;
        let id = d.u16()?;
        let t = d.text(*budget)?;
        *budget = budget.checked_sub(t.len()).ok_or(ProtoError::Field)?;
        if out.last().is_some_and(|(prev, _)| *prev >= id) {
            return Err(ProtoError::Field);
        }
        out.push((id, SecretText::new(t)));
    }
    Ok(out)
}

fn put_fields(e: &mut Enc, fields: &[(u16, SecretText)]) {
    e.array(fields.len());
    for (id, t) in fields {
        e.array(2).uint(u64::from(*id)).text(t.expose());
    }
}

fn dec_coi(d: &mut Dec<'_>) -> Result<Option<Coi>, ProtoError> {
    if d.null()? {
        return Ok(None);
    }
    let mut m = d.map(2)?;
    d.req(&mut m, 1)?;
    let excluded_labels = u16_list(d, MAX_COI_LABELS)?;
    d.req(&mut m, 2)?;
    let categories = u16_list(d, MAX_COI_CATEGORIES)?;
    d.end_map(m)?;
    Ok(Some(Coi {
        excluded_labels,
        categories,
    }))
}

fn put_coi(e: &mut Enc, c: &Option<Coi>) {
    match c {
        None => {
            e.null();
        }
        Some(c) => {
            e.map(2).uint(1);
            put_u16_list(e, &c.excluded_labels);
            e.uint(2);
            put_u16_list(e, &c.categories);
        }
    }
}

fn opt_text(d: &mut Dec<'_>, max: usize) -> Result<Option<SecretText>, ProtoError> {
    if d.null()? {
        Ok(None)
    } else {
        Ok(Some(secret_text(d, max)?))
    }
}

fn put_opt_text(e: &mut Enc, t: &Option<SecretText>) {
    match t {
        None => e.null(),
        Some(t) => e.text(t.expose()),
    };
}

fn positions(d: &mut Dec<'_>) -> Result<[u8; 3], ProtoError> {
    d.array_exact(CONFIRM_WORDS)?;
    let p = [d.u8()?, d.u8()?, d.u8()?];
    if !(p[0] < p[1] && p[1] < p[2]) || usize::from(p[2]) >= MAX_WORDS {
        return Err(ProtoError::Field);
    }
    Ok(p)
}

fn put_positions(e: &mut Enc, p: &[u8; 3]) {
    e.array(3);
    for x in p {
        e.uint(u64::from(*x));
    }
}

fn words(d: &mut Dec<'_>, exact: Option<usize>) -> Result<SecretWords, ProtoError> {
    let n = d.array(MAX_WORDS)?;
    if exact.is_some_and(|x| x != n) || n == 0 {
        return Err(ProtoError::Field);
    }
    let mut v = Zeroizing::new(Vec::with_capacity(n));
    for _ in 0..n {
        v.push(d.u16()?);
    }
    Ok(SecretWords(v))
}

fn put_words(e: &mut Enc, w: &SecretWords) {
    e.array(w.0.len());
    for x in w.0.iter() {
        e.uint(u64::from(*x));
    }
}

// ---------------------------------------------------------------------------
// Requests

/// Encode a request (without the length prefix).
pub fn encode_request(rid: u32, req: &Request) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    let mut e = Enc::with_capacity(MAX_FRAME_LEN);
    match req {
        Request::Hello { proto } => {
            e.map(1).uint(1).uint(*proto);
        }
        Request::SessionOpen { sess, channel_id } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bytes(channel_id);
        }
        Request::DraftSet(ds) => {
            e.map(6);
            put_sess(&mut e, &ds.sess);
            e.uint(2).uint(ds.mode as u64);
            e.uint(3).text(ds.message.expose());
            e.uint(4);
            put_fields(&mut e, &ds.fields);
            e.uint(5);
            put_opt_text(&mut e, &ds.identity);
            e.uint(6);
            put_coi(&mut e, &ds.coi);
        }
        Request::DraftGet { sess }
        | Request::GenAccount { sess }
        | Request::RotatePassphrase { sess }
        | Request::SealAbort { sess }
        | Request::Zeroize { sess }
        | Request::Touch { sess } => {
            e.map(1);
            put_sess(&mut e, sess);
        }
        Request::LoginDerive { sess, passphrase } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bytes(&passphrase.0);
        }
        Request::LoginSign { sess, challenge } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bytes(challenge);
        }
        Request::LoadPrefs { sess, prefs_ct } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bytes(prefs_ct);
        }
        Request::ConfirmPassphrase { sess, words } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2);
            put_words(&mut e, words);
        }
        Request::RotateFinish { sess, replies } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).array(replies.len());
            for r in replies {
                e.array(2).bytes(&r.object_hash).bytes(&r.stanza);
            }
        }
        Request::PartBegin {
            sess,
            declared_len,
            display_name,
            media_type,
        } => {
            e.map(4);
            put_sess(&mut e, sess);
            e.uint(2).uint(*declared_len);
            e.uint(3).text(display_name.expose());
            e.uint(4).text(media_type.expose());
        }
        Request::PartChunk {
            sess,
            part,
            data,
            last,
        } => {
            e.map(4);
            put_sess(&mut e, sess);
            e.uint(2).bytes(part);
            e.uint(3).bytes(&data.0);
            e.uint(4).bool(*last);
        }
        Request::SealFinish {
            sess,
            delayed_delivery,
        } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bool(*delayed_delivery);
        }
        Request::PartDrop { sess, part } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bytes(part);
        }
        Request::NoteReal {
            channel_id,
            first_object_hash,
        } => {
            e.map(2);
            e.uint(1).bytes(channel_id);
            e.uint(2).bytes(first_object_hash);
        }
        Request::OpenReply { sess, entry } => {
            e.map(2);
            put_sess(&mut e, sess);
            e.uint(2).bytes(entry);
        }
        Request::Status => {
            e.map(0);
        }
    }
    let out = envelope(req.op() as u8, rid, e.as_slice());
    if out.len() > MAX_FRAME_LEN {
        return Err(ProtoError::FrameLength);
    }
    Ok(out)
}

/// Decode a request strictly (without the length prefix). Returns `(rid, request)`.
pub fn decode_request(bytes: &[u8]) -> Result<(u32, Request), ProtoError> {
    let (op, rid, mut dec, mut body) = open_envelope(bytes)?;
    let op = Op::from_u8(op)?;
    let d = &mut dec;
    let m = &mut body;
    let req = match op {
        Op::Hello => {
            d.req(m, 1)?;
            Request::Hello { proto: d.uint()? }
        }
        Op::SessionOpen => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::SessionOpen {
                sess,
                channel_id: d.bytes_n()?,
            }
        }
        Op::DraftSet => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            let mode = Mode::from_u8(d.u8()?)?;
            let mut budget = MAX_DRAFT_TEXT;
            d.req(m, 3)?;
            let message = secret_text(d, budget)?;
            budget = budget
                .checked_sub(message.0.len())
                .ok_or(ProtoError::Field)?;
            d.req(m, 4)?;
            let fields = dec_fields(d, &mut budget)?;
            d.req(m, 5)?;
            let identity = opt_text(d, MAX_IDENTITY_LEN)?;
            d.req(m, 6)?;
            let coi = dec_coi(d)?;
            Request::DraftSet(DraftSet {
                sess,
                mode,
                message,
                fields,
                identity,
                coi,
            })
        }
        Op::DraftGet => Request::DraftGet { sess: sess(d, m)? },
        Op::GenAccount => Request::GenAccount { sess: sess(d, m)? },
        Op::RotatePassphrase => Request::RotatePassphrase { sess: sess(d, m)? },
        Op::SealAbort => Request::SealAbort { sess: sess(d, m)? },
        Op::Zeroize => Request::Zeroize { sess: sess(d, m)? },
        Op::Touch => Request::Touch { sess: sess(d, m)? },
        Op::LoginDerive => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::LoginDerive {
                sess,
                passphrase: SecretBytes::from_slice(d.bytes(MAX_PASSPHRASE_LEN)?),
            }
        }
        Op::LoginSign => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::LoginSign {
                sess,
                challenge: d.bytes_n()?,
            }
        }
        Op::LoadPrefs => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::LoadPrefs {
                sess,
                prefs_ct: d.bytes(MAX_PREFS_CT_LEN)?.to_vec(),
            }
        }
        Op::ConfirmPassphrase => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::ConfirmPassphrase {
                sess,
                words: words(d, Some(CONFIRM_WORDS))?,
            }
        }
        Op::RotateFinish => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            let n = d.array(MAX_ROTATE_REPLIES)?;
            let mut replies = Vec::with_capacity(n);
            for _ in 0..n {
                d.array_exact(2)?;
                let object_hash = d.bytes_n()?;
                let stanza = d.bytes(MAX_STANZA_LEN)?.to_vec();
                replies.push(PendingReply {
                    object_hash,
                    stanza,
                });
            }
            Request::RotateFinish { sess, replies }
        }
        Op::PartBegin => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            let declared_len = d.uint()?;
            d.req(m, 3)?;
            let display_name = secret_text(d, MAX_DISPLAY_NAME_LEN)?;
            d.req(m, 4)?;
            let media_type = secret_text(d, MAX_MEDIA_TYPE_LEN)?;
            Request::PartBegin {
                sess,
                declared_len,
                display_name,
                media_type,
            }
        }
        Op::PartChunk => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            let part = d.bytes_n()?;
            d.req(m, 3)?;
            let data = SecretBytes::from_slice(d.bytes(MAX_CHUNK_LEN)?);
            d.req(m, 4)?;
            Request::PartChunk {
                sess,
                part,
                data,
                last: d.bool()?,
            }
        }
        Op::SealFinish => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::SealFinish {
                sess,
                delayed_delivery: d.bool()?,
            }
        }
        Op::PartDrop => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::PartDrop {
                sess,
                part: d.bytes_n()?,
            }
        }
        Op::NoteReal => {
            d.req(m, 1)?;
            let channel_id = d.bytes_n()?;
            d.req(m, 2)?;
            Request::NoteReal {
                channel_id,
                first_object_hash: d.bytes_n()?,
            }
        }
        Op::OpenReply => {
            let sess = sess(d, m)?;
            d.req(m, 2)?;
            Request::OpenReply {
                sess,
                entry: d.bytes(MAX_REPLY_ENTRY_LEN)?.to_vec(),
            }
        }
        Op::Status => Request::Status,
    };
    dec.end_map(body)?;
    dec.finish()?;
    Ok((rid, req))
}

// ---------------------------------------------------------------------------
// Responses

/// Encode a response to a request with `op` (use [`OP_ERROR`] semantics
/// automatically for [`Response::Error`]).
pub fn encode_response(op: Op, rid: u32, resp: &Response) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    let mut e = Enc::with_capacity(MAX_FRAME_LEN);
    let mut wire_op = op as u8;
    match resp {
        Response::Hello {
            proto,
            snapshot_version,
        } => {
            e.map(2).uint(1).uint(*proto).uint(2).uint(*snapshot_version);
        }
        Response::Empty => {
            e.map(0);
        }
        Response::Draft(v) => {
            e.map(6);
            e.uint(1).uint(v.mode as u64);
            e.uint(2).text(v.message.expose());
            e.uint(3);
            put_fields(&mut e, &v.fields);
            e.uint(4);
            put_opt_text(&mut e, &v.identity);
            e.uint(5);
            put_coi(&mut e, &v.coi);
            e.uint(6).array(v.parts.len());
            for p in &v.parts {
                e.array(2).bytes(&p.part).uint(p.size_bucket);
            }
        }
        Response::Words {
            words,
            confirm_positions,
        } => {
            e.map(2).uint(1);
            put_words(&mut e, words);
            e.uint(2);
            put_positions(&mut e, confirm_positions);
        }
        Response::Locator { lookup_tag } => {
            e.map(1).uint(1).bytes(lookup_tag);
        }
        Response::Signature { sig } => {
            e.map(1).uint(1).bytes(sig);
        }
        Response::Confirm {
            ok,
            confirm_positions,
        } => {
            e.map(2).uint(1).bool(*ok).uint(2);
            match confirm_positions {
                Some(p) => put_positions(&mut e, p),
                None => {
                    e.null();
                }
            }
        }
        Response::Part { part } => {
            e.map(1).uint(1).bytes(part);
        }
        Response::Sealed {
            release_offset_days,
        } => {
            e.map(1).uint(1).uint(u64::from(*release_offset_days));
        }
        Response::Disposition { disposition_ct } => {
            e.map(1).uint(1).bytes(disposition_ct);
        }
        Response::Reply(r) => {
            e.map(1).uint(1);
            match r {
                None => {
                    e.null();
                }
                Some(r) => {
                    e.map(4);
                    e.uint(1).uint(r.reply_seq);
                    e.uint(2).uint(u64::from(r.day));
                    e.uint(3).text(r.role_label.expose());
                    e.uint(4).text(r.body.expose());
                }
            }
        }
        Response::Status {
            sessions_band,
            argon_queue_band,
            pool_free_band,
        } => {
            e.map(3);
            e.uint(1).uint(u64::from(*sessions_band));
            e.uint(2).uint(u64::from(*argon_queue_band));
            e.uint(3).uint(u64::from(*pool_free_band));
        }
        Response::Error {
            code,
            alternative_channel_id,
        } => {
            wire_op = OP_ERROR;
            e.map(2).uint(1).uint(*code as u64).uint(2);
            match alternative_channel_id {
                Some(c) => e.bytes(c),
                None => e.null(),
            };
        }
    }
    let out = envelope(wire_op, rid, e.as_slice());
    if out.len() > MAX_FRAME_LEN {
        return Err(ProtoError::FrameLength);
    }
    Ok(out)
}

/// Decode a response to a request with op `expected` (without the length
/// prefix). Returns `(rid, response)`.
pub fn decode_response(expected: Op, bytes: &[u8]) -> Result<(u32, Response), ProtoError> {
    let (op, rid, mut dec, mut body) = open_envelope(bytes)?;
    let d = &mut dec;
    let m = &mut body;
    let resp = if op == OP_ERROR {
        d.req(m, 1)?;
        let code = ErrorCode::from_u8(d.u8()?)?;
        d.req(m, 2)?;
        let alternative_channel_id = if d.null()? {
            None
        } else {
            Some(d.bytes_n()?)
        };
        Response::Error {
            code,
            alternative_channel_id,
        }
    } else {
        if op != expected as u8 {
            return Err(ProtoError::Mismatch);
        }
        match expected {
            Op::Hello => {
                d.req(m, 1)?;
                let proto = d.uint()?;
                d.req(m, 2)?;
                Response::Hello {
                    proto,
                    snapshot_version: d.uint()?,
                }
            }
            Op::SessionOpen
            | Op::DraftSet
            | Op::LoadPrefs
            | Op::PartChunk
            | Op::SealAbort
            | Op::PartDrop
            | Op::Zeroize
            | Op::Touch => Response::Empty,
            Op::DraftGet => {
                d.req(m, 1)?;
                let mode = Mode::from_u8(d.u8()?)?;
                d.req(m, 2)?;
                let mut budget = MAX_DRAFT_TEXT;
                let message = secret_text(d, budget)?;
                budget = budget
                    .checked_sub(message.0.len())
                    .ok_or(ProtoError::Field)?;
                d.req(m, 3)?;
                let fields = dec_fields(d, &mut budget)?;
                d.req(m, 4)?;
                let identity = opt_text(d, MAX_IDENTITY_LEN)?;
                d.req(m, 5)?;
                let coi = dec_coi(d)?;
                d.req(m, 6)?;
                let n = d.array(MAX_PARTS)?;
                let mut parts = Vec::with_capacity(n);
                for _ in 0..n {
                    d.array_exact(2)?;
                    let part = d.bytes_n()?;
                    parts.push(PartView {
                        part,
                        size_bucket: d.uint()?,
                    });
                }
                Response::Draft(DraftView {
                    mode,
                    message,
                    fields,
                    identity,
                    coi,
                    parts,
                })
            }
            Op::GenAccount | Op::RotatePassphrase => {
                d.req(m, 1)?;
                let words = words(d, None)?;
                d.req(m, 2)?;
                Response::Words {
                    words,
                    confirm_positions: positions(d)?,
                }
            }
            Op::LoginDerive | Op::RotateFinish => {
                d.req(m, 1)?;
                Response::Locator {
                    lookup_tag: d.bytes_n()?,
                }
            }
            Op::LoginSign => {
                d.req(m, 1)?;
                Response::Signature { sig: d.bytes_n()? }
            }
            Op::ConfirmPassphrase => {
                d.req(m, 1)?;
                let ok = d.bool()?;
                d.req(m, 2)?;
                let confirm_positions = if d.null()? {
                    None
                } else {
                    Some(positions(d)?)
                };
                Response::Confirm {
                    ok,
                    confirm_positions,
                }
            }
            Op::PartBegin => {
                d.req(m, 1)?;
                Response::Part {
                    part: d.bytes_n()?,
                }
            }
            Op::SealFinish => {
                d.req(m, 1)?;
                let release_offset_days = d.u8()?;
                if release_offset_days > 3 {
                    return Err(ProtoError::Field);
                }
                Response::Sealed {
                    release_offset_days,
                }
            }
            Op::NoteReal => {
                d.req(m, 1)?;
                Response::Disposition {
                    disposition_ct: d.bytes(4096)?.to_vec(),
                }
            }
            Op::OpenReply => {
                d.req(m, 1)?;
                if d.null()? {
                    Response::Reply(None)
                } else {
                    let mut r = d.map(4)?;
                    d.req(&mut r, 1)?;
                    let reply_seq = d.uint()?;
                    d.req(&mut r, 2)?;
                    let day = d.u32()?;
                    d.req(&mut r, 3)?;
                    let role_label = secret_text(d, MAX_ROLE_LABEL_LEN)?;
                    d.req(&mut r, 4)?;
                    let body = secret_text(d, MAX_REPLY_BODY_LEN)?;
                    d.end_map(r)?;
                    Response::Reply(Some(ReplyView {
                        reply_seq,
                        day,
                        role_label,
                        body,
                    }))
                }
            }
            Op::Status => {
                d.req(m, 1)?;
                let sessions_band = d.u8()?;
                d.req(m, 2)?;
                let argon_queue_band = d.u8()?;
                d.req(m, 3)?;
                Response::Status {
                    sessions_band,
                    argon_queue_band,
                    pool_free_band: d.u8()?,
                }
            }
        }
    };
    dec.end_map(body)?;
    dec.finish()?;
    Ok((rid, resp))
}

// ---------------------------------------------------------------------------
// Framing

/// Prefix a CBOR message with its `u32be` length.
pub fn frame(msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    if msg.is_empty() || msg.len() > MAX_FRAME_LEN {
        return Err(ProtoError::FrameLength);
    }
    let len = u32::try_from(msg.len()).map_err(|_| ProtoError::FrameLength)?;
    let mut out = Zeroizing::new(Vec::with_capacity(msg.len().saturating_add(4)));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg);
    Ok(out)
}

/// Validate a length prefix.
pub fn frame_len(prefix: [u8; 4]) -> Result<usize, ProtoError> {
    let n = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ProtoError::FrameLength)?;
    if n == 0 || n > MAX_FRAME_LEN {
        return Err(ProtoError::FrameLength);
    }
    Ok(n)
}

/// Blocking: read one frame body (zeroized buffer). `Ok(None)` on clean EOF
/// before a prefix.
pub fn read_frame<R: std::io::Read>(r: &mut R) -> Result<Option<Zeroizing<Vec<u8>>>, ProtoError> {
    let mut prefix = [0u8; 4];
    match r.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(ProtoError::Io),
    }
    let n = frame_len(prefix)?;
    let mut buf = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut buf).map_err(|_| ProtoError::Io)?;
    Ok(Some(buf))
}

/// Blocking: write one framed message.
pub fn write_frame<W: std::io::Write>(w: &mut W, msg: &[u8]) -> Result<(), ProtoError> {
    let f = frame(msg)?;
    w.write_all(&f).map_err(|_| ProtoError::Io)?;
    w.flush().map_err(|_| ProtoError::Io)
}

/// Blocking client call: send `req`, read and decode the matching response.
pub fn call<S: std::io::Read + std::io::Write>(
    s: &mut S,
    rid: u32,
    req: &Request,
) -> Result<Response, ProtoError> {
    let msg = encode_request(rid, req)?;
    write_frame(s, &msg)?;
    let body = read_frame(s)?.ok_or(ProtoError::Io)?;
    let (got, resp) = decode_response(req.op(), &body)?;
    if got != rid {
        return Err(ProtoError::Mismatch);
    }
    Ok(resp)
}

impl Zeroize for SecretWords {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn rt(req: Request) {
        let b = encode_request(7, &req).unwrap();
        let (rid, got) = decode_request(&b).unwrap();
        assert_eq!(rid, 7);
        assert_eq!(got, req);
    }

    #[test]
    fn request_round_trips() {
        let s = SessionHandle([3; 16]);
        rt(Request::Hello { proto: 2 });
        rt(Request::Status);
        rt(Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Confidential,
            message: SecretText::new("hello"),
            fields: vec![(1, SecretText::new("a")), (9, SecretText::new("b"))],
            identity: Some(SecretText::new("me")),
            coi: Some(Coi {
                excluded_labels: Zeroizing::new(vec![1, 4]),
                categories: Zeroizing::new(vec![2]),
            }),
        }));
        rt(Request::ConfirmPassphrase {
            sess: s,
            words: SecretWords(Zeroizing::new(vec![1, 2, 3])),
        });
        rt(Request::RotateFinish {
            sess: s,
            replies: vec![PendingReply {
                object_hash: [1; 32],
                stanza: vec![9; 40],
            }],
        });
    }

    #[test]
    fn rejects_unsorted_fields_and_unknown_keys() {
        let s = SessionHandle([3; 16]);
        let mut ds = DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new(""),
            fields: vec![(9, SecretText::new("a")), (1, SecretText::new("b"))],
            identity: None,
            coi: None,
        };
        let b = encode_request(1, &Request::DraftSet(ds.clone())).unwrap();
        assert_eq!(decode_request(&b), Err(ProtoError::Field));
        ds.fields.clear();
        // Append an unknown body key by hand: {1: sess, 7: 0}
        let mut e = Enc::new();
        e.map(2).uint(1).bytes(&[0; 16]).uint(7).uint(0);
        let b = envelope(Op::DraftGet as u8, 1, e.as_slice());
        assert!(decode_request(&b).is_err());
    }

    #[test]
    fn redacted_debug() {
        let r = Request::LoginDerive {
            sess: SessionHandle([1; 16]),
            passphrase: SecretBytes::from_slice(b"correct horse"),
        };
        let s = format!("{r:?}");
        assert!(!s.contains("horse") && !s.contains("[1, 1"));
    }
}
