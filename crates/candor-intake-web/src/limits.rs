// SPDX-License-Identifier: AGPL-3.0-or-later
//! Named input and resource limits (IMPL-00 §4.3, §7; 07 §5.1, §11; 08 §4;
//! 11 §5.6, §5.7). Every external input is checked against one of these
//! before anything is allocated for it.

use std::time::Duration;

/// Longest PROXY protocol v1 line, CRLF included (HAProxy spec: 107 bytes).
pub const MAX_PROXY_LINE: usize = 107;
/// Request line limit (07 §5.1: ≤ 4 KiB).
pub const MAX_REQUEST_LINE: usize = 4096;
/// Whole request head limit, request line and headers (07 §5.1: ≤ 16 KiB).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Header field count limit (07 §5.1: ≤ 50).
pub const MAX_HEADERS: usize = 50;
/// Longest request path we route (`/en/rotate/confirm` and the well-known
/// paths are far shorter); anything longer is the uniform 404.
pub const MAX_PATH: usize = 64;
/// URL-encoded form body limit (07 §11: 112 KiB).
pub const MAX_FORM_BODY: usize = 112 * 1024;
/// Fields per URL-encoded form (S05 with every option ticked stays below 64;
/// the S06 description form has one field per file, ≤ 32).
pub const MAX_FORM_FIELDS: usize = 128;
/// Short text: characters (11 §5.7).
pub const MAX_SHORT_CHARS: usize = 500;
/// Long text: characters (11 §5.7).
pub const MAX_LONG_CHARS: usize = 60_000;
/// Long text: UTF-8 bytes (11 §5.7, 07 §11: 64 KiB).
pub const MAX_LONG_BYTES: usize = 65_536;
/// Identity name and role fields (S05b `maxlength="200"`).
pub const MAX_NAME_CHARS: usize = 200;
/// A single confirmation word or login box (`maxlength="64"`).
pub const MAX_WORD_BYTES: usize = 64;
/// Opaque token-like values (csrf, piece references, allow-listed choices).
pub const MAX_TOKEN_BYTES: usize = 160;
/// Multipart: parts per request (csrf, file, neutral_names, action; 07 §5.1
/// says 3, the S06/S12 form carries one more control, SPEC-NOTES).
pub const MAX_MULTIPART_PARTS: usize = 4;
/// Multipart: header block of one part (07 §5.1: ≤ 1 KiB).
pub const MAX_PART_HEADER: usize = 1024;
/// Multipart: filename bytes (07 §5.1: ≤ 255).
pub const MAX_FILENAME_BYTES: usize = 255;
/// Multipart: claimed media type bytes (sealer `MAX_MEDIA_TYPE_LEN`).
pub const MAX_MEDIA_TYPE_BYTES: usize = 127;
/// Multipart: the value of a non-file part.
pub const MAX_PART_VALUE: usize = 160;
/// Multipart boundary length (RFC 2046 §5.1.1: 1..=70).
pub const MAX_BOUNDARY: usize = 70;
/// Plaintext bytes per `PART_CHUNK` (sealer `MAX_CHUNK_LEN`).
pub const UPLOAD_CHUNK: usize = 65_536;
/// Largest file per request (07 §11 `intake.max_file_bytes` ≤ 4 GiB).
pub const MAX_FILE_BYTES_CEILING: u64 = 4 << 30;
/// Files per envelope (07 §11: 20, max 32).
pub const MAX_FILES_CEILING: u32 = 32;

/// Header read timeout from accept, PROXY line included (07 §11: 10 s).
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Body idle timeout between reads (07 §11: 60 s, Tor-friendly).
pub const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Total time for one Tier W upload request (07 §11: 4 h). The effective
/// deadline is shorter for smaller bodies: [`UPLOAD_GRACE`] plus
/// `Content-Length` / [`MIN_UPLOAD_RATE`] (AUD-RM2-WEB-07).
pub const UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
/// Upload start-up allowance before the minimum rate applies (Tor circuit
/// warm-up, file picker latency in the browser is before the request).
pub const UPLOAD_GRACE: Duration = Duration::from_secs(30);
/// Minimum average upload rate after [`UPLOAD_GRACE`], in bytes per second
/// (AUD-RM2-WEB-07: a slot cannot be held for less than this bandwidth;
/// Tor circuits sustain well over 50 KB/s, so 1 KiB/s only cuts trickles).
pub const MIN_UPLOAD_RATE: u64 = 1024;
/// Uploads in progress at once, service-wide (AUD-RM2-WEB-07): uploads can
/// hold at most this many of the [`MAX_CONNECTIONS`] serving slots. One per
/// session on top (`WebSession::uploading`).
pub const MAX_CONCURRENT_UPLOADS: usize = 128;
/// Total time for a URL-encoded body (112 KiB over Tor at 256 kbit/s takes
/// about 4 s; this bounds slow-POST abuse, ST-101).
pub const FORM_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Response write deadline.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// After the response: how long unread request bytes are drained before
/// the socket is closed (so the response is not lost to a reset).
pub const LINGER_TIMEOUT: Duration = Duration::from_secs(2);
/// After the response: how many unread bytes are drained at most.
pub const LINGER_BYTES: usize = 1 << 20;

/// Connections served at once (07 §11: 512).
pub const MAX_CONNECTIONS: usize = 512;
/// Further connections whose head is read only to answer with the busy page
/// in the correct size class; beyond both, a connection is closed unread.
pub const MAX_OVERFLOW_CONNECTIONS: usize = 512;
/// Web sessions (07 §11: 10,000; oldest idle evicted).
pub const MAX_SESSIONS: usize = 10_000;
/// `T_IDLE` (11 §5.6, ADR-034; not configurable).
pub const SESSION_IDLE: Duration = Duration::from_secs(20 * 60);
/// `T_ABS` (11 §5.6, ADR-034; not configurable).
pub const SESSION_ABSOLUTE: Duration = Duration::from_secs(2 * 3600);
/// Pre-session cookie lifetime (11 §5.6: 15 min).
pub const PRE_SESSION_LIFETIME_SECS: u64 = 15 * 60;
/// Pre-session token epoch: tokens are valid in their epoch and the next two
/// (10 to 15 minutes, never more than the cookie lifetime).
pub const PRE_SESSION_EPOCH_SECS: u64 = 5 * 60;

/// `T_LOGIN_FLOOR` default (07 §11 `intake.login_floor`: 3 s).
pub const LOGIN_FLOOR_DEFAULT: Duration = Duration::from_secs(3);
/// SAFE range of the login floor (11 §5.4 rule 7: 2–6 s).
pub const LOGIN_FLOOR_MIN: Duration = Duration::from_secs(2);
/// SAFE range of the login floor (11 §5.4 rule 7: 2–6 s).
pub const LOGIN_FLOOR_MAX: Duration = Duration::from_secs(6);
/// Jitter added after the floor: U(0, 250 ms) (07 §11).
pub const LOGIN_JITTER_MS: u64 = 250;

/// Inbox entries opened per render, real ones plus dummies (08 §3.8:
/// `N_fixed = 32`), so the sealer work does not depend on the reply count.
pub const INBOX_FIXED: usize = 32;
/// Rate-limit entries per circuit are evicted after this idle time (NET-013).
pub const CIRCUIT_IDLE: Duration = Duration::from_secs(10 * 60);
/// Circuit entries kept at most (beyond it, new circuits get the busy page).
pub const MAX_CIRCUITS: usize = 65_536;

/// Sealer IPC: connect timeout.
pub const SEALER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Sealer IPC: ordinary operation timeout.
pub const SEALER_OP_TIMEOUT: Duration = Duration::from_secs(15);
/// Sealer IPC: Argon2id operations (the sealer queues up to 30 s, 07 §11).
pub const SEALER_KDF_TIMEOUT: Duration = Duration::from_secs(45);
/// Sealer IPC: `SEAL_FINISH` / `ROTATE_FINISH` (Argon2id + sealing + the
/// store hand-over: copy deadline for the 4 GiB cap plus the 60 s commit).
pub const SEALER_SEAL_TIMEOUT: Duration = Duration::from_secs(300);
/// Sealer IPC: pooled connections.
pub const SEALER_POOL: usize = 64;
