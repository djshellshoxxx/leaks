// SPDX-License-Identifier: AGPL-3.0-or-later
//! `istore` IPC protocol (07 §5.3; IMPL-RM2 §2.3 "matching `istore` protocol
//! types in the store crate"), owned by `candor-intake-store` and usable
//! without the `server` or `client` features (no dependency beyond `std`).
//!
//! # Transport
//! One `AF_UNIX`/`SOCK_SEQPACKET` socket (`istore.sock`); one request or
//! response per datagram, so framing is the kernel's message boundary and a
//! truncated datagram (`MSG_TRUNC`) is a protocol violation. Every connection
//! is authenticated with `SO_PEERCRED` against the configured UID of one
//! [`Role`]; each [`Op`] belongs to exactly one role.
//!
//! # Encoding
//! A deterministic, positional binary layout (no self-describing format, so
//! there are no unknown or duplicate fields to accept by mistake):
//!
//! ```text
//! request  = u8 version (=1) ‖ u8 op ‖ u32be rid ‖ body(op)
//! response = u8 version (=1) ‖ u32be rid ‖ u8 code ‖ body(op)   (body only if code = 0)
//! ```
//!
//! Variable-length fields carry a `u16be` or `u32be` length prefix and have an
//! explicit maximum; fixed fields have an exact length; trailing bytes, unknown
//! ops, out-of-range values and a datagram above the op's maximum
//! ([`max_request_len`], [`max_response_len`]) are rejected with
//! [`ProtoError`], which carries no input data. Responses are decoded against
//! the op of the request they answer ([`decode_response`]).
//!
//! # Datagram bound
//! [`MAX_FRAME_LEN`] (200,000 B) is below the default `AF_UNIX` datagram
//! bound (`net.core.wmem_default` = 212,992 B minus overhead); a deployment
//! must not lower it (deploy note in SPEC-NOTES). Mailbox contents are read
//! one reply per datagram (`MAILBOX_READ`) for the same reason.
//!
//! # Hand-over
//! `COMMIT_GROUP` carries the inline objects (main, IDENTITY), the three slot
//! blocks and the disposition marker; its `Ok` response means "send the
//! ATTACHMENT_BUNDLE now": the client then performs the staged hand-over of
//! [`crate::staged`] (protocol 2: 41-byte message with one sealed descriptor;
//! `0x02 ‖ h` copied, `0x01 ‖ h` committed) on the same socket. A re-sent
//! group whose digest is already committed is acknowledged as a success
//! without a second commit (AUD-RM2-SEA-01, WEB-13).

use core::fmt;

/// Protocol version byte.
pub const PROTO_VERSION: u8 = 1;
/// Largest datagram in either direction (see module docs).
pub const MAX_FRAME_LEN: usize = 200_000;
/// Request header: version, op, rid.
pub const REQUEST_HEADER_LEN: usize = 1 + 1 + 4;
/// Response header: version, rid, code.
pub const RESPONSE_HEADER_LEN: usize = 1 + 4 + 1;
/// Largest inline sealed object (SUBMISSION / SOURCE_MESSAGE / IDENTITY at
/// their maximum bucket plus the SealedObject overhead; 07 §5.2's 70,000 B
/// bound for a 64 KiB-bucket object).
pub const MAX_INLINE_OBJECT: usize = 70_000;
/// Largest `reply_ct` ([`crate::REPLY_ENTRY_LEN`] minus the entry length prefix).
pub const MAX_REPLY_CT: usize = crate::MAX_REPLY_CT;
/// Mailbox ids per account (one per report; v1 uses one).
pub const MAX_MAILBOX_IDS: usize = 16;
/// Re-wrapped reply stanzas per rotation (sealer `MAX_ROTATE_REPLIES`).
pub const MAX_REWRAPS: usize = 64;
/// Largest Wrap Stanza accepted (HPKE_BASE is 1,242 B).
pub const MAX_STANZA_LEN: usize = 2048;
/// Replies per mailbox ([`crate::MAILBOX_SLOTS`]).
pub const MAX_MAILBOX_REPLIES: usize = crate::MAILBOX_SLOTS as usize;

/// Peer roles, each bound to one configured UID (no defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// C-06: read-only (`StoreReads`).
    Web,
    /// C-07: envelope groups, account upserts, deletion requests.
    Sealer,
    /// C-09 relay export (RM-3): every op is refused until then.
    Relay,
}

/// Operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// `{}` → `{u8 allowed}` (web).
    ServingAllowed = 0x01,
    /// `{tag 32}` → `{u8 present ‖ [account_id 16 ‖ auth_pk 32 ‖ u16 len ‖ prefs_ct]}` (web).
    AccountLookup = 0x02,
    /// `{account 16}` → `{u8 n ‖ n × (reply_ref 16 ‖ slot u8 ‖ bucket u8 ‖ day u32)}` (web).
    MailboxList = 0x03,
    /// `{account 16 ‖ reply_ref 16}` → `{u32 len ‖ reply_ct}` (web).
    MailboxRead = 0x04,
    /// Envelope group commit, then the staged bundle hand-over (sealer).
    CommitGroup = 0x10,
    /// Create or replace a Tier W account (sealer).
    AccountUpsert = 0x11,
    /// K31-signed deletion (account, mailbox or replies) (sealer).
    Delete = 0x12,
    /// RL-01 (relay, reserved).
    RelayStatus = 0x20,
    /// RL-02 (relay, reserved).
    RelayClaim = 0x21,
    /// RL-03 (relay, reserved).
    RelayObject = 0x22,
    /// RL-04 (relay, reserved).
    RelayAck = 0x23,
    /// RL-05 (relay, reserved).
    RelayPushReplies = 0x24,
    /// RL-06 (relay, reserved).
    RelayInstallSnapshot = 0x25,
    /// RL-11 (relay, reserved).
    RelayDeletionList = 0x26,
    /// RL-11 acknowledgement (relay, reserved).
    RelayAckDeletionHead = 0x27,
    /// RL-12 (relay, reserved).
    RelayPushDeletionList = 0x28,
    /// RL-09 (relay, reserved).
    RelayCounters = 0x29,
    /// RL-10 (relay, reserved).
    RelayBackup = 0x2a,
}

impl Op {
    /// Parse an op byte.
    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x01 => Self::ServingAllowed,
            0x02 => Self::AccountLookup,
            0x03 => Self::MailboxList,
            0x04 => Self::MailboxRead,
            0x10 => Self::CommitGroup,
            0x11 => Self::AccountUpsert,
            0x12 => Self::Delete,
            0x20 => Self::RelayStatus,
            0x21 => Self::RelayClaim,
            0x22 => Self::RelayObject,
            0x23 => Self::RelayAck,
            0x24 => Self::RelayPushReplies,
            0x25 => Self::RelayInstallSnapshot,
            0x26 => Self::RelayDeletionList,
            0x27 => Self::RelayAckDeletionHead,
            0x28 => Self::RelayPushDeletionList,
            0x29 => Self::RelayCounters,
            0x2a => Self::RelayBackup,
            _ => return Err(ProtoError::UnknownOp),
        })
    }

    /// The role allowed to issue this op.
    #[must_use]
    pub fn role(self) -> Role {
        match self {
            Self::ServingAllowed | Self::AccountLookup | Self::MailboxList | Self::MailboxRead => {
                Role::Web
            }
            Self::CommitGroup | Self::AccountUpsert | Self::Delete => Role::Sealer,
            _ => Role::Relay,
        }
    }

    /// Reserved relay op (refused until RM-3).
    #[must_use]
    pub fn is_relay(self) -> bool {
        self.role() == Role::Relay
    }
}

/// Uniform error codes. No code reveals whether an identifier exists beyond
/// what the operation's contract requires (`NotFound` is the uniform
/// "no such / not yours" of 08 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Malformed datagram; the connection is closed.
    BadFrame = 1,
    /// The op is not allowed for the connection's role (or is reserved).
    Forbidden = 2,
    /// Uniform "does not exist / not in scope".
    NotFound = 3,
    /// The request violates a size, range or state rule.
    Invalid = 4,
    /// Restore pending or backend failure: nothing changed, try later.
    Unavailable = 5,
    /// Capacity (connections, in-flight hand-overs); nothing changed.
    Busy = 6,
    /// Internal failure; nothing is known to be committed.
    Internal = 7,
}

impl ErrorCode {
    /// Parse a code byte (`0` is not an error).
    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            1 => Self::BadFrame,
            2 => Self::Forbidden,
            3 => Self::NotFound,
            4 => Self::Invalid,
            5 => Self::Unavailable,
            6 => Self::Busy,
            7 => Self::Internal,
            _ => return Err(ProtoError::Field),
        })
    }
}

/// Decoding failure. Carries no input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// Wrong version byte.
    Version,
    /// Unknown op.
    UnknownOp,
    /// Truncated input.
    Short,
    /// Trailing bytes.
    Trailing,
    /// A field is out of range or over its maximum.
    Field,
    /// The datagram exceeds the op's maximum.
    TooLong,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "protocol version",
            Self::UnknownOp => "unknown op",
            Self::Short => "truncated",
            Self::Trailing => "trailing bytes",
            Self::Field => "field",
            Self::TooLong => "datagram too long",
        })
    }
}

impl std::error::Error for ProtoError {}

/// Inline sealed object of a group (main or IDENTITY).
#[derive(Clone, PartialEq, Eq)]
pub struct InlineObject {
    /// `object_hash`.
    pub object_hash: [u8; 32],
    /// Encoded RecipientSlotBlock (exactly [`crate::SLOT_BLOCK_LEN_STD`]).
    pub slot_block: Vec<u8>,
    /// SealedObject bytes (1 ..= [`MAX_INLINE_OBJECT`]).
    pub bytes: Vec<u8>,
}

impl fmt::Debug for InlineObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InlineObject(<redacted>)")
    }
}

/// The ATTACHMENT_BUNDLE object: its bytes follow as a staged hand-over.
#[derive(Clone, PartialEq, Eq)]
pub struct BundleObject {
    /// `object_hash`.
    pub object_hash: [u8; 32],
    /// Encoded RecipientSlotBlock.
    pub slot_block: Vec<u8>,
    /// Exact length of the sealed bundle (1 ..= [`crate::staged::STAGED_MAX_BUNDLE_LEN`]).
    pub padded_size: u64,
}

impl fmt::Debug for BundleObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BundleObject(<redacted>)")
    }
}

/// `COMMIT_GROUP` body (ADR-052(1)/(2): fixed shape, no account reference).
#[derive(Clone, PartialEq, Eq)]
pub struct CommitGroup {
    /// Channel.
    pub channel_id: [u8; 16],
    /// Sealing epoch.
    pub epoch_index: u32,
    /// The sealer's `today` (the store checks it against its own day ± 1).
    pub received_day: u32,
    /// 0 ..= [`crate::MAX_RELEASE_OFFSET_DAYS`].
    pub release_offset_days: u8,
    /// Exactly [`crate::DISPOSITION_CT_LEN_STD`] bytes.
    pub disposition_ct: Vec<u8>,
    /// SUBMISSION or SOURCE_MESSAGE.
    pub main: InlineObject,
    /// ATTACHMENT_BUNDLE (handed over after the `Ok`).
    pub bundle: BundleObject,
    /// IDENTITY.
    pub identity: InlineObject,
}

impl fmt::Debug for CommitGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommitGroup(<redacted>)")
    }
}

/// `ACCOUNT_UPSERT` body (ADR-052(2); ADR-046(7) rotation).
#[derive(Clone, PartialEq, Eq)]
pub struct AccountUpsert {
    /// `None`: create; `Some(old_tag)`: replace the account with that tag.
    pub replaces: Option<[u8; 32]>,
    /// New `lookup_tag`.
    pub lookup_tag: [u8; 32],
    /// Ed25519 `auth_pk`.
    pub auth_pk: [u8; 32],
    /// X-Wing public key (exactly [`crate::XWING_PK_LEN`]).
    pub xwing_pk: Vec<u8>,
    /// `prefs_ct` (1 ..= [`crate::MAX_PREFS_CT`]).
    pub prefs_ct: Vec<u8>,
    /// Mailbox ids (≤ [`MAX_MAILBOX_IDS`]); carried for the relay mapping.
    pub mailbox_ids: Vec<[u8; 32]>,
    /// Rotation: `(reply object_hash, new stanza(1))`, ≤ [`MAX_REWRAPS`].
    pub rewrapped: Vec<([u8; 32], Vec<u8>)>,
}

impl fmt::Debug for AccountUpsert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountUpsert(<redacted>)")
    }
}

/// `DELETE` body: a source-initiated deletion (04 §18.6, KEY-077), identified
/// by the account's `lookup_tag` (the sealer knows no `AccountId`).
#[derive(Clone, PartialEq, Eq)]
pub enum Delete {
    /// SW-15: one `mailbox` entry per listed mailbox, then the `account` entry
    /// and the account with all its replies.
    Account {
        /// `lookup_tag`.
        lookup_tag: [u8; 32],
        /// The account's mailbox ids (≤ [`MAX_MAILBOX_IDS`]).
        mailbox_ids: Vec<[u8; 32]>,
    },
    /// `MAILBOX_DELETE`: one `mailbox` entry; the account's replies are deleted.
    Mailbox {
        /// `lookup_tag`.
        lookup_tag: [u8; 32],
        /// Mailbox id.
        mailbox_id: [u8; 32],
    },
    /// SW-14: one `reply` entry per listed reply of the account (≤ 32).
    Replies {
        /// `lookup_tag`.
        lookup_tag: [u8; 32],
        /// Reply refs (unknown or foreign refs are ignored: idempotent).
        replies: Vec<[u8; 16]>,
    },
}

impl fmt::Debug for Delete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Account { .. } => "Delete::Account(<redacted>)",
            Self::Mailbox { .. } => "Delete::Mailbox(<redacted>)",
            Self::Replies { .. } => "Delete::Replies(<redacted>)",
        })
    }
}

/// A request. `Debug` prints only the op.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// [`Op::ServingAllowed`].
    ServingAllowed,
    /// [`Op::AccountLookup`].
    AccountLookup {
        /// `lookup_tag`.
        tag: [u8; 32],
    },
    /// [`Op::MailboxList`].
    MailboxList {
        /// Account id.
        account: [u8; 16],
    },
    /// [`Op::MailboxRead`].
    MailboxRead {
        /// Account id.
        account: [u8; 16],
        /// Reply ref.
        reply: [u8; 16],
    },
    /// [`Op::CommitGroup`].
    CommitGroup(Box<CommitGroup>),
    /// [`Op::AccountUpsert`].
    AccountUpsert(Box<AccountUpsert>),
    /// [`Op::Delete`].
    Delete(Delete),
    /// A reserved relay op with an empty body.
    Relay(Op),
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Request({:?})", self.op())
    }
}

impl Request {
    /// The op.
    #[must_use]
    pub fn op(&self) -> Op {
        match self {
            Self::ServingAllowed => Op::ServingAllowed,
            Self::AccountLookup { .. } => Op::AccountLookup,
            Self::MailboxList { .. } => Op::MailboxList,
            Self::MailboxRead { .. } => Op::MailboxRead,
            Self::CommitGroup(_) => Op::CommitGroup,
            Self::AccountUpsert(_) => Op::AccountUpsert,
            Self::Delete(_) => Op::Delete,
            Self::Relay(op) => *op,
        }
    }
}

/// Account as returned to the web (verifier-side values only).
#[derive(Clone, PartialEq, Eq)]
pub struct AccountInfo {
    /// Intake-local account id.
    pub account_id: [u8; 16],
    /// `auth_pk`.
    pub auth_pk: [u8; 32],
    /// `prefs_ct`.
    pub prefs_ct: Vec<u8>,
}

impl fmt::Debug for AccountInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountInfo(<redacted>)")
    }
}

/// One mailbox entry header (`MAILBOX_LIST`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReplyHeader {
    /// Reply ref.
    pub reply_ref: [u8; 16],
    /// Slot 0..=31.
    pub slot: u8,
    /// Size bucket 1..=16.
    pub size_bucket: u8,
    /// Day the reply became available.
    pub available_day: u32,
}

impl fmt::Debug for ReplyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplyHeader(<redacted>)")
    }
}

/// A response. `Debug` prints only the variant.
#[derive(Clone, PartialEq, Eq)]
pub enum Response {
    /// An error.
    Error(ErrorCode),
    /// `{}`: `COMMIT_GROUP` (send the bundle now) and `ACCOUNT_UPSERT`.
    Empty,
    /// `SERVING_ALLOWED`.
    ServingAllowed(bool),
    /// `ACCOUNT_LOOKUP`.
    Account(Option<AccountInfo>),
    /// `MAILBOX_LIST`.
    MailboxList(Vec<ReplyHeader>),
    /// `MAILBOX_READ`.
    ReplyCt(Vec<u8>),
    /// `DELETE`: entries appended.
    Deleted(u32),
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(c) => write!(f, "Response::Error({c:?})"),
            Self::Empty => f.write_str("Response::Empty"),
            Self::ServingAllowed(_) => f.write_str("Response::ServingAllowed"),
            Self::Account(_) => f.write_str("Response::Account"),
            Self::MailboxList(_) => f.write_str("Response::MailboxList"),
            Self::ReplyCt(_) => f.write_str("Response::ReplyCt"),
            Self::Deleted(_) => f.write_str("Response::Deleted"),
        }
    }
}

// ----- limits ---------------------------------------------------------------

const SLOT_BLOCK: usize = crate::SLOT_BLOCK_LEN_STD;

const REQ_COMMIT_GROUP: usize = 16
    + 4
    + 4
    + 1
    + 2
    + crate::DISPOSITION_CT_LEN_STD
    + 2 * (32 + 2 + SLOT_BLOCK + 4 + MAX_INLINE_OBJECT)
    + (32 + 2 + SLOT_BLOCK + 8);
const REQ_ACCOUNT_UPSERT: usize = 1
    + 32
    + 32
    + 32
    + 2
    + crate::XWING_PK_LEN
    + 2
    + crate::MAX_PREFS_CT
    + 1
    + 32 * MAX_MAILBOX_IDS
    + 1
    + MAX_REWRAPS * (32 + 2 + MAX_STANZA_LEN);
const REQ_DELETE: usize = 1 + 32 + 32 + 1 + 32 * MAX_MAILBOX_IDS + 16 * MAX_MAILBOX_REPLIES;
const RESP_ACCOUNT: usize = 1 + 16 + 32 + 2 + crate::MAX_PREFS_CT;
const RESP_MAILBOX_LIST: usize = 1 + MAX_MAILBOX_REPLIES * (16 + 1 + 1 + 4);
const RESP_REPLY: usize = 4 + MAX_REPLY_CT;
const _: () = assert!(REQUEST_HEADER_LEN + REQ_COMMIT_GROUP <= MAX_FRAME_LEN);
const _: () = assert!(REQUEST_HEADER_LEN + REQ_ACCOUNT_UPSERT <= MAX_FRAME_LEN);
const _: () = assert!(RESPONSE_HEADER_LEN + RESP_REPLY <= MAX_FRAME_LEN);

/// Largest request datagram for `op`.
#[must_use]
pub fn max_request_len(op: Op) -> usize {
    let body = match op {
        Op::ServingAllowed => 0,
        Op::AccountLookup => 32,
        Op::MailboxList => 16,
        Op::MailboxRead => 32,
        Op::CommitGroup => REQ_COMMIT_GROUP,
        Op::AccountUpsert => REQ_ACCOUNT_UPSERT,
        Op::Delete => REQ_DELETE,
        _ => 0,
    };
    REQUEST_HEADER_LEN.saturating_add(body).min(MAX_FRAME_LEN)
}

/// Largest response datagram for `op`.
#[must_use]
pub fn max_response_len(op: Op) -> usize {
    let body = match op {
        Op::ServingAllowed => 1,
        Op::AccountLookup => RESP_ACCOUNT,
        Op::MailboxList => RESP_MAILBOX_LIST,
        Op::MailboxRead => RESP_REPLY,
        Op::Delete => 4,
        _ => 0,
    };
    RESPONSE_HEADER_LEN.saturating_add(body).min(MAX_FRAME_LEN)
}

// ----- codec ---------------------------------------------------------------

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    fn var16(&mut self, b: &[u8]) -> Result<&mut Self, ProtoError> {
        let n = u16::try_from(b.len()).map_err(|_| ProtoError::Field)?;
        Ok(self.u16(n).fixed(b))
    }
    fn var32(&mut self, b: &[u8]) -> Result<&mut Self, ProtoError> {
        let n = u32::try_from(b.len()).map_err(|_| ProtoError::Field)?;
        Ok(self.u32(n).fixed(b))
    }
}

/// Strict positional reader: every read is bounds-checked; `finish` rejects
/// trailing bytes.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::Short)?;
        let s = self.buf.get(self.pos..end).ok_or(ProtoError::Short)?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(*self.take(1)?.first().ok_or(ProtoError::Short)?)
    }
    fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_be_bytes(self.fixed::<2>()?))
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_be_bytes(self.fixed::<4>()?))
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_be_bytes(self.fixed::<8>()?))
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        self.take(N)?.try_into().map_err(|_| ProtoError::Short)
    }
    fn bool(&mut self) -> Result<bool, ProtoError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtoError::Field),
        }
    }
    /// `u16` length-prefixed bytes, `min ..= max`.
    fn var16(&mut self, min: usize, max: usize) -> Result<&'a [u8], ProtoError> {
        let n = usize::from(self.u16()?);
        if n < min || n > max {
            return Err(ProtoError::Field);
        }
        self.take(n)
    }
    /// `u32` length-prefixed bytes, `min ..= max`.
    fn var32(&mut self, min: usize, max: usize) -> Result<&'a [u8], ProtoError> {
        let n = usize::try_from(self.u32()?).map_err(|_| ProtoError::Field)?;
        if n < min || n > max {
            return Err(ProtoError::Field);
        }
        self.take(n)
    }
    /// `u8` count, `≤ max`.
    fn count8(&mut self, max: usize) -> Result<usize, ProtoError> {
        let n = usize::from(self.u8()?);
        if n > max {
            return Err(ProtoError::Field);
        }
        Ok(n)
    }
    fn finish(&self) -> Result<(), ProtoError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(ProtoError::Trailing)
        }
    }
}

fn put_inline(w: &mut Writer, o: &InlineObject) -> Result<(), ProtoError> {
    if o.slot_block.len() != SLOT_BLOCK || o.bytes.is_empty() || o.bytes.len() > MAX_INLINE_OBJECT {
        return Err(ProtoError::Field);
    }
    w.fixed(&o.object_hash)
        .var16(&o.slot_block)?
        .var32(&o.bytes)?;
    Ok(())
}

fn get_inline(r: &mut Reader<'_>) -> Result<InlineObject, ProtoError> {
    let object_hash = r.fixed()?;
    let slot_block = r.var16(SLOT_BLOCK, SLOT_BLOCK)?.to_vec();
    let bytes = r.var32(1, MAX_INLINE_OBJECT)?.to_vec();
    Ok(InlineObject {
        object_hash,
        slot_block,
        bytes,
    })
}

/// Encode a request datagram.
pub fn encode_request(rid: u32, req: &Request) -> Result<Vec<u8>, ProtoError> {
    let op = req.op();
    let mut w = Writer(Vec::with_capacity(64));
    w.u8(PROTO_VERSION).u8(op as u8).u32(rid);
    match req {
        Request::ServingAllowed | Request::Relay(_) => {}
        Request::AccountLookup { tag } => {
            w.fixed(tag);
        }
        Request::MailboxList { account } => {
            w.fixed(account);
        }
        Request::MailboxRead { account, reply } => {
            w.fixed(account).fixed(reply);
        }
        Request::CommitGroup(g) => {
            if g.disposition_ct.len() != crate::DISPOSITION_CT_LEN_STD
                || g.release_offset_days > crate::MAX_RELEASE_OFFSET_DAYS
                || g.bundle.slot_block.len() != SLOT_BLOCK
                || g.bundle.padded_size == 0
                || g.bundle.padded_size > crate::staged::STAGED_MAX_BUNDLE_LEN
            {
                return Err(ProtoError::Field);
            }
            w.fixed(&g.channel_id)
                .u32(g.epoch_index)
                .u32(g.received_day)
                .u8(g.release_offset_days)
                .var16(&g.disposition_ct)?;
            put_inline(&mut w, &g.main)?;
            w.fixed(&g.bundle.object_hash)
                .var16(&g.bundle.slot_block)?
                .u64(g.bundle.padded_size);
            put_inline(&mut w, &g.identity)?;
        }
        Request::AccountUpsert(a) => {
            if a.xwing_pk.len() != crate::XWING_PK_LEN
                || a.prefs_ct.is_empty()
                || a.prefs_ct.len() > crate::MAX_PREFS_CT
                || a.mailbox_ids.len() > MAX_MAILBOX_IDS
                || a.rewrapped.len() > MAX_REWRAPS
                || a.rewrapped
                    .iter()
                    .any(|(_, s)| s.is_empty() || s.len() > MAX_STANZA_LEN)
            {
                return Err(ProtoError::Field);
            }
            match a.replaces {
                None => {
                    w.u8(0).fixed(&[0u8; 32]);
                }
                Some(old) => {
                    w.u8(1).fixed(&old);
                }
            }
            w.fixed(&a.lookup_tag)
                .fixed(&a.auth_pk)
                .var16(&a.xwing_pk)?
                .var16(&a.prefs_ct)?;
            w.u8(u8::try_from(a.mailbox_ids.len()).map_err(|_| ProtoError::Field)?);
            for m in &a.mailbox_ids {
                w.fixed(m);
            }
            w.u8(u8::try_from(a.rewrapped.len()).map_err(|_| ProtoError::Field)?);
            for (h, s) in &a.rewrapped {
                w.fixed(h).var16(s)?;
            }
        }
        Request::Delete(d) => match d {
            Delete::Account {
                lookup_tag,
                mailbox_ids,
            } => {
                if mailbox_ids.len() > MAX_MAILBOX_IDS {
                    return Err(ProtoError::Field);
                }
                w.u8(1).fixed(lookup_tag);
                w.u8(u8::try_from(mailbox_ids.len()).map_err(|_| ProtoError::Field)?);
                for m in mailbox_ids {
                    w.fixed(m);
                }
            }
            Delete::Mailbox {
                lookup_tag,
                mailbox_id,
            } => {
                w.u8(2).fixed(lookup_tag).fixed(mailbox_id);
            }
            Delete::Replies {
                lookup_tag,
                replies,
            } => {
                if replies.len() > MAX_MAILBOX_REPLIES {
                    return Err(ProtoError::Field);
                }
                w.u8(3).fixed(lookup_tag);
                w.u8(u8::try_from(replies.len()).map_err(|_| ProtoError::Field)?);
                for r in replies {
                    w.fixed(r);
                }
            }
        },
    }
    if w.0.len() > max_request_len(op) {
        return Err(ProtoError::TooLong);
    }
    Ok(w.0)
}

/// Decode a request datagram: `(rid, request)`.
pub fn decode_request(bytes: &[u8]) -> Result<(u32, Request), ProtoError> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(ProtoError::TooLong);
    }
    let mut r = Reader::new(bytes);
    if r.u8()? != PROTO_VERSION {
        return Err(ProtoError::Version);
    }
    let op = Op::from_u8(r.u8()?)?;
    if bytes.len() > max_request_len(op) {
        return Err(ProtoError::TooLong);
    }
    let rid = r.u32()?;
    let req = match op {
        Op::ServingAllowed => Request::ServingAllowed,
        Op::AccountLookup => Request::AccountLookup { tag: r.fixed()? },
        Op::MailboxList => Request::MailboxList {
            account: r.fixed()?,
        },
        Op::MailboxRead => Request::MailboxRead {
            account: r.fixed()?,
            reply: r.fixed()?,
        },
        Op::CommitGroup => {
            let channel_id = r.fixed()?;
            let epoch_index = r.u32()?;
            let received_day = r.u32()?;
            let release_offset_days = r.u8()?;
            if release_offset_days > crate::MAX_RELEASE_OFFSET_DAYS {
                return Err(ProtoError::Field);
            }
            let disposition_ct = r
                .var16(crate::DISPOSITION_CT_LEN_STD, crate::DISPOSITION_CT_LEN_STD)?
                .to_vec();
            let main = get_inline(&mut r)?;
            let object_hash = r.fixed()?;
            let slot_block = r.var16(SLOT_BLOCK, SLOT_BLOCK)?.to_vec();
            let padded_size = r.u64()?;
            if padded_size == 0 || padded_size > crate::staged::STAGED_MAX_BUNDLE_LEN {
                return Err(ProtoError::Field);
            }
            let identity = get_inline(&mut r)?;
            Request::CommitGroup(Box::new(CommitGroup {
                channel_id,
                epoch_index,
                received_day,
                release_offset_days,
                disposition_ct,
                main,
                bundle: BundleObject {
                    object_hash,
                    slot_block,
                    padded_size,
                },
                identity,
            }))
        }
        Op::AccountUpsert => {
            let has_old = r.bool()?;
            let old: [u8; 32] = r.fixed()?;
            if !has_old && old != [0u8; 32] {
                return Err(ProtoError::Field);
            }
            let lookup_tag = r.fixed()?;
            let auth_pk = r.fixed()?;
            let xwing_pk = r.var16(crate::XWING_PK_LEN, crate::XWING_PK_LEN)?.to_vec();
            let prefs_ct = r.var16(1, crate::MAX_PREFS_CT)?.to_vec();
            let n = r.count8(MAX_MAILBOX_IDS)?;
            let mut mailbox_ids = Vec::with_capacity(n);
            for _ in 0..n {
                mailbox_ids.push(r.fixed()?);
            }
            let n = r.count8(MAX_REWRAPS)?;
            let mut rewrapped = Vec::with_capacity(n);
            for _ in 0..n {
                let h = r.fixed()?;
                let s = r.var16(1, MAX_STANZA_LEN)?.to_vec();
                rewrapped.push((h, s));
            }
            Request::AccountUpsert(Box::new(AccountUpsert {
                replaces: has_old.then_some(old),
                lookup_tag,
                auth_pk,
                xwing_pk,
                prefs_ct,
                mailbox_ids,
                rewrapped,
            }))
        }
        Op::Delete => {
            let kind = r.u8()?;
            let lookup_tag = r.fixed()?;
            Request::Delete(match kind {
                1 => {
                    let n = r.count8(MAX_MAILBOX_IDS)?;
                    let mut mailbox_ids = Vec::with_capacity(n);
                    for _ in 0..n {
                        mailbox_ids.push(r.fixed()?);
                    }
                    Delete::Account {
                        lookup_tag,
                        mailbox_ids,
                    }
                }
                2 => Delete::Mailbox {
                    lookup_tag,
                    mailbox_id: r.fixed()?,
                },
                3 => {
                    let n = r.count8(MAX_MAILBOX_REPLIES)?;
                    let mut replies = Vec::with_capacity(n);
                    for _ in 0..n {
                        replies.push(r.fixed()?);
                    }
                    Delete::Replies {
                        lookup_tag,
                        replies,
                    }
                }
                _ => return Err(ProtoError::Field),
            })
        }
        relay => Request::Relay(relay),
    };
    r.finish()?;
    Ok((rid, req))
}

/// Encode a response datagram for a request of `op`.
pub fn encode_response(op: Op, rid: u32, resp: &Response) -> Result<Vec<u8>, ProtoError> {
    let mut w = Writer(Vec::with_capacity(32));
    w.u8(PROTO_VERSION).u32(rid);
    match (op, resp) {
        (_, Response::Error(c)) => {
            w.u8(*c as u8);
        }
        (Op::CommitGroup | Op::AccountUpsert, Response::Empty) => {
            w.u8(0);
        }
        (Op::ServingAllowed, Response::ServingAllowed(b)) => {
            w.u8(0).u8(u8::from(*b));
        }
        (Op::AccountLookup, Response::Account(a)) => {
            w.u8(0);
            match a {
                None => {
                    w.u8(0);
                }
                Some(a) => {
                    if a.prefs_ct.is_empty() || a.prefs_ct.len() > crate::MAX_PREFS_CT {
                        return Err(ProtoError::Field);
                    }
                    w.u8(1)
                        .fixed(&a.account_id)
                        .fixed(&a.auth_pk)
                        .var16(&a.prefs_ct)?;
                }
            }
        }
        (Op::MailboxList, Response::MailboxList(v)) => {
            if v.len() > MAX_MAILBOX_REPLIES {
                return Err(ProtoError::Field);
            }
            w.u8(0)
                .u8(u8::try_from(v.len()).map_err(|_| ProtoError::Field)?);
            for h in v {
                if h.slot >= crate::MAILBOX_SLOTS
                    || h.size_bucket == 0
                    || h.size_bucket > crate::REPLY_BUCKETS
                {
                    return Err(ProtoError::Field);
                }
                w.fixed(&h.reply_ref)
                    .u8(h.slot)
                    .u8(h.size_bucket)
                    .u32(h.available_day);
            }
        }
        (Op::MailboxRead, Response::ReplyCt(ct)) => {
            if ct.is_empty() || ct.len() > MAX_REPLY_CT {
                return Err(ProtoError::Field);
            }
            w.u8(0).var32(ct)?;
        }
        (Op::Delete, Response::Deleted(n)) => {
            w.u8(0).u32(*n);
        }
        _ => return Err(ProtoError::Field),
    }
    if w.0.len() > max_response_len(op) {
        return Err(ProtoError::TooLong);
    }
    Ok(w.0)
}

/// Decode a response to a request of `expected`: `(rid, response)`.
pub fn decode_response(expected: Op, bytes: &[u8]) -> Result<(u32, Response), ProtoError> {
    if bytes.len() > max_response_len(expected) {
        return Err(ProtoError::TooLong);
    }
    let mut r = Reader::new(bytes);
    if r.u8()? != PROTO_VERSION {
        return Err(ProtoError::Version);
    }
    let rid = r.u32()?;
    let code = r.u8()?;
    if code != 0 {
        let c = ErrorCode::from_u8(code)?;
        r.finish()?;
        return Ok((rid, Response::Error(c)));
    }
    let resp = match expected {
        Op::CommitGroup | Op::AccountUpsert => Response::Empty,
        Op::ServingAllowed => Response::ServingAllowed(r.bool()?),
        Op::AccountLookup => {
            if r.bool()? {
                let account_id = r.fixed()?;
                let auth_pk = r.fixed()?;
                let prefs_ct = r.var16(1, crate::MAX_PREFS_CT)?.to_vec();
                Response::Account(Some(AccountInfo {
                    account_id,
                    auth_pk,
                    prefs_ct,
                }))
            } else {
                Response::Account(None)
            }
        }
        Op::MailboxList => {
            let n = r.count8(MAX_MAILBOX_REPLIES)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let h = ReplyHeader {
                    reply_ref: r.fixed()?,
                    slot: r.u8()?,
                    size_bucket: r.u8()?,
                    available_day: r.u32()?,
                };
                if h.slot >= crate::MAILBOX_SLOTS
                    || h.size_bucket == 0
                    || h.size_bucket > crate::REPLY_BUCKETS
                {
                    return Err(ProtoError::Field);
                }
                v.push(h);
            }
            Response::MailboxList(v)
        }
        Op::MailboxRead => Response::ReplyCt(r.var32(1, MAX_REPLY_CT)?.to_vec()),
        Op::Delete => Response::Deleted(r.u32()?),
        // Relay ops have no success body (refused until RM-3).
        _ => return Err(ProtoError::Field),
    };
    r.finish()?;
    Ok((rid, resp))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    pub(crate) fn sample_group() -> CommitGroup {
        let inline = |h: u8, b: u8, n: usize| InlineObject {
            object_hash: [h; 32],
            slot_block: vec![b; SLOT_BLOCK],
            bytes: vec![b; n],
        };
        CommitGroup {
            channel_id: [1; 16],
            epoch_index: 7,
            received_day: 20_741,
            release_offset_days: 3,
            disposition_ct: vec![9; crate::DISPOSITION_CT_LEN_STD],
            main: inline(2, 3, MAX_INLINE_OBJECT),
            bundle: BundleObject {
                object_hash: [4; 32],
                slot_block: vec![5; SLOT_BLOCK],
                padded_size: 262_144,
            },
            identity: inline(6, 7, 1),
        }
    }

    pub(crate) fn sample_requests() -> Vec<Request> {
        vec![
            Request::ServingAllowed,
            Request::AccountLookup { tag: [1; 32] },
            Request::MailboxList { account: [2; 16] },
            Request::MailboxRead {
                account: [2; 16],
                reply: [3; 16],
            },
            Request::CommitGroup(Box::new(sample_group())),
            Request::AccountUpsert(Box::new(AccountUpsert {
                replaces: Some([8; 32]),
                lookup_tag: [9; 32],
                auth_pk: [10; 32],
                xwing_pk: vec![11; crate::XWING_PK_LEN],
                prefs_ct: vec![12; crate::MAX_PREFS_CT],
                mailbox_ids: vec![[13; 32]; MAX_MAILBOX_IDS],
                rewrapped: vec![([14; 32], vec![15; MAX_STANZA_LEN]); MAX_REWRAPS],
            })),
            Request::AccountUpsert(Box::new(AccountUpsert {
                replaces: None,
                lookup_tag: [9; 32],
                auth_pk: [10; 32],
                xwing_pk: vec![11; crate::XWING_PK_LEN],
                prefs_ct: vec![12; 1],
                mailbox_ids: vec![],
                rewrapped: vec![],
            })),
            Request::Delete(Delete::Account {
                lookup_tag: [1; 32],
                mailbox_ids: vec![[2; 32]],
            }),
            Request::Delete(Delete::Mailbox {
                lookup_tag: [1; 32],
                mailbox_id: [2; 32],
            }),
            Request::Delete(Delete::Replies {
                lookup_tag: [1; 32],
                replies: vec![[3; 16]; MAX_MAILBOX_REPLIES],
            }),
            Request::Relay(Op::RelayClaim),
        ]
    }

    #[test]
    fn requests_round_trip_within_limits() {
        for req in sample_requests() {
            let b = encode_request(5, &req).unwrap();
            assert!(b.len() <= max_request_len(req.op()));
            let (rid, back) = decode_request(&b).unwrap();
            assert_eq!(rid, 5);
            assert!(back == req);
            // Trailing byte, truncation and a wrong version are refused.
            let mut t = b.clone();
            t.push(0);
            assert!(matches!(
                decode_request(&t),
                Err(ProtoError::Trailing | ProtoError::TooLong)
            ));
            assert!(decode_request(&b[..b.len() - 1]).is_err());
            let mut v = b.clone();
            v[0] = 2;
            assert_eq!(decode_request(&v), Err(ProtoError::Version));
        }
        let mut b = encode_request(1, &Request::ServingAllowed).unwrap();
        b[1] = 0x7f;
        assert_eq!(decode_request(&b), Err(ProtoError::UnknownOp));
    }

    #[test]
    fn responses_round_trip() {
        let cases = vec![
            (Op::CommitGroup, Response::Empty),
            (Op::AccountUpsert, Response::Empty),
            (Op::ServingAllowed, Response::ServingAllowed(true)),
            (Op::AccountLookup, Response::Account(None)),
            (
                Op::AccountLookup,
                Response::Account(Some(AccountInfo {
                    account_id: [1; 16],
                    auth_pk: [2; 32],
                    prefs_ct: vec![3; 4096],
                })),
            ),
            (
                Op::MailboxList,
                Response::MailboxList(vec![
                    ReplyHeader {
                        reply_ref: [4; 16],
                        slot: 31,
                        size_bucket: 16,
                        available_day: 20_000,
                    };
                    MAX_MAILBOX_REPLIES
                ]),
            ),
            (Op::MailboxRead, Response::ReplyCt(vec![5; MAX_REPLY_CT])),
            (Op::Delete, Response::Deleted(3)),
            (Op::Delete, Response::Error(ErrorCode::NotFound)),
            (Op::RelayClaim, Response::Error(ErrorCode::Forbidden)),
        ];
        for (op, resp) in cases {
            let b = encode_response(op, 9, &resp).unwrap();
            assert!(b.len() <= max_response_len(op));
            let (rid, back) = decode_response(op, &b).unwrap();
            assert_eq!(rid, 9);
            assert!(back == resp);
            let mut t = b.clone();
            t.push(0);
            assert!(decode_response(op, &t).is_err());
        }
        // A body of the wrong op is refused.
        let b = encode_response(Op::Delete, 1, &Response::Deleted(1)).unwrap();
        assert!(decode_response(Op::ServingAllowed, &b).is_err());
        assert!(encode_response(Op::Delete, 1, &Response::Empty).is_err());
        assert!(decode_response(Op::RelayClaim, &[PROTO_VERSION, 0, 0, 0, 1, 0]).is_err());
    }

    #[test]
    fn field_limits_are_enforced() {
        let mut g = sample_group();
        g.release_offset_days = 22;
        assert!(encode_request(1, &Request::CommitGroup(Box::new(g))).is_err());
        let mut g = sample_group();
        g.bundle.padded_size = 0;
        assert!(encode_request(1, &Request::CommitGroup(Box::new(g))).is_err());
        let mut g = sample_group();
        g.main.bytes = vec![0; MAX_INLINE_OBJECT + 1];
        assert!(encode_request(1, &Request::CommitGroup(Box::new(g))).is_err());
        // Decoder side: a "no replacement" flag with a non-zero old tag.
        let a = AccountUpsert {
            replaces: None,
            lookup_tag: [9; 32],
            auth_pk: [10; 32],
            xwing_pk: vec![11; crate::XWING_PK_LEN],
            prefs_ct: vec![12; 1],
            mailbox_ids: vec![],
            rewrapped: vec![],
        };
        let mut b = encode_request(1, &Request::AccountUpsert(Box::new(a))).unwrap();
        b[REQUEST_HEADER_LEN + 1] = 1;
        assert_eq!(decode_request(&b), Err(ProtoError::Field));
        // Unknown delete kind.
        let d = Request::Delete(Delete::Mailbox {
            lookup_tag: [1; 32],
            mailbox_id: [2; 32],
        });
        let mut b = encode_request(1, &d).unwrap();
        b[REQUEST_HEADER_LEN] = 4;
        assert_eq!(decode_request(&b), Err(ProtoError::Field));
        // Relay ops take no body.
        let mut b = encode_request(1, &Request::Relay(Op::RelayBackup)).unwrap();
        b.push(1);
        assert_eq!(decode_request(&b), Err(ProtoError::TooLong));
        // Oversize datagram for the op.
        let b = vec![0u8; max_request_len(Op::ServingAllowed) + 1];
        let mut b2 = b;
        b2[0] = PROTO_VERSION;
        b2[1] = Op::ServingAllowed as u8;
        assert_eq!(decode_request(&b2), Err(ProtoError::TooLong));
    }

    #[test]
    fn roles_and_debug() {
        assert_eq!(Op::MailboxRead.role(), Role::Web);
        assert_eq!(Op::Delete.role(), Role::Sealer);
        assert!(Op::RelayBackup.is_relay());
        let s = format!("{:?}", Request::AccountLookup { tag: [7; 32] });
        assert!(!s.contains('7'));
        assert_eq!(
            format!("{:?}", Response::Account(None)),
            "Response::Account"
        );
    }

    proptest::proptest! {
        /// Decoding arbitrary bytes never panics; whatever decodes re-encodes
        /// byte-identically (canonical layout).
        #[test]
        fn decode_total(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            if let Ok((rid, req)) = decode_request(&data) {
                proptest::prop_assert_eq!(encode_request(rid, &req).unwrap(), data.clone());
            }
            for op in [Op::ServingAllowed, Op::AccountLookup, Op::MailboxList, Op::MailboxRead,
                       Op::CommitGroup, Op::AccountUpsert, Op::Delete, Op::RelayClaim] {
                if let Ok((rid, resp)) = decode_response(op, &data) {
                    proptest::prop_assert_eq!(encode_response(op, rid, &resp).unwrap(), data.clone());
                }
            }
        }
    }
}
