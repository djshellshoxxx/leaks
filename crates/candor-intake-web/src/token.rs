// SPDX-License-Identifier: AGPL-3.0-or-later
//! Session cookie, session handle and CSRF tokens (11 §5.6, §5.7; 08 §3.7;
//! ADR-051(4); AUD-RM1-SUI-06; ST-066, ST-071).
//!
//! * `cs`: 256 random bits (OS CSPRNG), sent as `__Host-cs` (64 hex chars).
//!   The server never stores it: the sealer handle is
//!   `h = HKDF-SHA256(ikm = cs, info = "candor/src/handle")` truncated to the
//!   sealer's 16 bytes, and the web session table is keyed by `SHA-256(h)`.
//! * Session CSRF token: 256 random bits per session (rotated whenever the
//!   session's authority changes), compared in constant time.
//! * Pre-session token (forms before a session exists: login, new report,
//!   leave): `HMAC-SHA256(K_pre, "candor/web/pre" ‖ cpre ‖ epoch)` where
//!   `cpre` is the random `__Host-cpre` cookie and `epoch` a 5-minute
//!   monotonic counter; valid in its epoch and the next two. No server state.
//! * Origin: absent, `null` or exactly the onion origin (08 §3.7); and
//!   `Sec-Fetch-Site`: absent or `same-origin` (IMPL-RM2 tightening). Both are
//!   checked on every POST before the body is read.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::http::{FetchSite, OriginHeader};
use crate::limits::{PRE_SESSION_EPOCH_SECS, PRE_SESSION_LIFETIME_SECS};

/// The OS CSPRNG failed (fail closed: the request gets the error page).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

/// Fill `buf` from the OS CSPRNG (candor-core health-checked wrapper).
pub fn random(buf: &mut [u8]) -> Result<(), RngError> {
    candor_core::fill_random(buf).map_err(|_| RngError)
}

/// Lowercase hex (secrets go into a zeroizing string of exact size).
#[must_use]
pub fn hex(b: &[u8]) -> Zeroizing<String> {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = Zeroizing::new(String::with_capacity(b.len().saturating_mul(2)));
    for x in b {
        for n in [x >> 4, x & 0x0f] {
            if let Some(c) = D.get(usize::from(n)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}

/// Decode 64 lowercase hex characters into 32 bytes.
#[must_use]
pub fn unhex32(s: &str) -> Option<Zeroizing<[u8; 32]>> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, o) in out.iter_mut().enumerate() {
        let hi = b.get(i.checked_mul(2)?).copied().and_then(nibble)?;
        let lo = b
            .get(i.checked_mul(2)?.checked_add(1)?)
            .copied()
            .and_then(nibble)?;
        *o = hi.checked_mul(16)?.checked_add(lo)?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// Keys derived from one `cs` value.
pub struct SessionKeys {
    /// Sealer session handle (16 bytes of `h`).
    pub sealer: candor_sealer::proto::SessionHandle,
    /// Web session table key `SHA-256(h)`.
    pub table: [u8; 32],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

/// `h = HKDF(cs, "candor/src/handle")` (11 §5.6) and the two values derived
/// from it. `cs` is consumed by reference and never stored.
#[must_use]
pub fn session_keys(cs: &[u8; 32]) -> SessionKeys {
    let hk = hkdf::Hkdf::<Sha256>::new(None, cs);
    let mut h = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's 8160-byte limit: cannot fail.
    if hk.expand(b"candor/src/handle", h.as_mut()).is_err() {
        h.fill(0);
    }
    let mut sealer = [0u8; 16];
    sealer.copy_from_slice(h.get(..16).unwrap_or(&[0u8; 16]));
    let table: [u8; 32] = Sha256::digest(h.as_ref()).into();
    SessionKeys {
        sealer: candor_sealer::proto::SessionHandle(sealer),
        table,
    }
}

/// Constant-time comparison of a posted token with the expected one (hex).
#[must_use]
pub fn token_eq(posted: &str, expected: &str) -> bool {
    posted.len() == expected.len() && bool::from(posted.as_bytes().ct_eq(expected.as_bytes()))
}

const PRE_LABEL: &[u8] = b"candor/web/pre";
const LEAVE_LABEL: &[u8] = b"candor/web/leave";

/// Pre-session token key (per process, random; a restart invalidates every
/// pre-session form, which only costs a reload).
pub struct PreSessionKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for PreSessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PreSessionKey(<redacted>)")
    }
}

impl PreSessionKey {
    /// A fresh random key.
    pub fn generate() -> Result<Self, RngError> {
        let mut k = Zeroizing::new([0u8; 32]);
        random(k.as_mut())?;
        Ok(Self(k))
    }

    fn mac(&self, label: &[u8], cpre: &str, epoch: u64) -> Zeroizing<String> {
        let Ok(mut m) = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_ref()) else {
            return Zeroizing::new(String::new());
        };
        m.update(label);
        m.update(cpre.as_bytes());
        m.update(&epoch.to_be_bytes());
        let tag: [u8; 32] = m.finalize().into_bytes().into();
        hex(&tag)
    }

    /// The token for forms rendered now (`secs` = monotonic seconds since
    /// process start).
    #[must_use]
    pub fn token(&self, cpre: &str, secs: u64) -> Zeroizing<String> {
        self.mac(
            PRE_LABEL,
            cpre,
            secs.checked_div(PRE_SESSION_EPOCH_SECS).unwrap_or(0),
        )
    }

    /// Check `posted` against `cpre` for the current and the two previous
    /// epochs (all three are computed, constant work).
    #[must_use]
    pub fn verify(&self, cpre: &str, posted: &str, secs: u64) -> bool {
        self.verify_label(PRE_LABEL, cpre, posted, secs)
    }

    /// The token of the Leave form on the cookie-clearing screens (S10s,
    /// Leave, discarded, closed, signed out): those screens send
    /// `Clear-Site-Data`, so the Leave POST carries no cookie to bind to.
    /// Domain-separated from the pre-session token, same epochs. It
    /// authorises nothing but the Leave page (which changes no state).
    #[must_use]
    pub fn leave_token(&self, secs: u64) -> Zeroizing<String> {
        self.mac(
            LEAVE_LABEL,
            "",
            secs.checked_div(PRE_SESSION_EPOCH_SECS).unwrap_or(0),
        )
    }

    /// Check a leave token (current and two previous epochs, constant work).
    #[must_use]
    pub fn verify_leave(&self, posted: &str, secs: u64) -> bool {
        self.verify_label(LEAVE_LABEL, "", posted, secs)
    }

    fn verify_label(&self, label: &[u8], cpre: &str, posted: &str, secs: u64) -> bool {
        let now = secs.checked_div(PRE_SESSION_EPOCH_SECS).unwrap_or(0);
        let mut ok = false;
        for back in 0..3u64 {
            let e = now.saturating_sub(back);
            let valid_epoch = now >= back;
            ok |= valid_epoch && token_eq(posted, &self.mac(label, cpre, e));
        }
        ok
    }
}

/// `Set-Cookie` for a new session: session-only (no `Expires`/`Max-Age`).
#[must_use]
pub fn session_set_cookie(cs_hex: &str) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(160));
    s.push_str(crate::http::SESSION_COOKIE);
    s.push('=');
    s.push_str(cs_hex);
    s.push_str("; Path=/; Secure; HttpOnly; SameSite=Strict");
    s
}

/// `Set-Cookie` for the pre-session cookie (15 minutes).
#[must_use]
pub fn pre_set_cookie(cpre_hex: &str) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(160));
    s.push_str(crate::http::PRE_SESSION_COOKIE);
    s.push('=');
    s.push_str(cpre_hex);
    s.push_str("; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=");
    s.push_str(&PRE_SESSION_LIFETIME_SECS.to_string());
    s
}

/// Request-origin checks for a POST (08 §3.7 plus the IMPL-RM2 tightening):
/// `Origin` absent, `null` or exactly `onion_origin`; `Sec-Fetch-Site`
/// absent or `same-origin`.
#[must_use]
pub fn origin_ok(origin: &OriginHeader, fetch: FetchSite, onion_origin: &str) -> bool {
    match origin {
        // Lead decision 2: `null` only together with `Sec-Fetch-Site:
        // same-origin` (08 §3.7 does not allow `none`; a missing header is
        // not enough to vouch for an opaque origin).
        OriginHeader::Null => fetch == FetchSite::SameOrigin,
        OriginHeader::Absent => matches!(fetch, FetchSite::Absent | FetchSite::SameOrigin),
        OriginHeader::Value(v) => {
            v == onion_origin && matches!(fetch, FetchSite::Absent | FetchSite::SameOrigin)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff].repeat(8);
        let h = hex(&b);
        assert_eq!(h.len(), 64);
        assert_eq!(unhex32(&h).unwrap().as_slice(), b.as_slice());
        assert!(unhex32(&h.to_uppercase()).is_none());
        assert!(unhex32("00").is_none());
    }

    #[test]
    fn handle_derivation_is_stable_and_separated() {
        let a = session_keys(&[1; 32]);
        let b = session_keys(&[1; 32]);
        let c = session_keys(&[2; 32]);
        assert_eq!(a.sealer, b.sealer);
        assert_eq!(a.table, b.table);
        assert_ne!(a.table, c.table);
        // The table key is not the handle or cs.
        assert_ne!(&a.table[..16], &a.sealer.0);
    }

    #[test]
    fn pre_session_tokens_expire() {
        let k = PreSessionKey::generate().unwrap();
        let cpre = "c".repeat(64);
        let t = k.token(&cpre, 1000);
        assert!(k.verify(&cpre, &t, 1000));
        assert!(k.verify(&cpre, &t, 1000 + 2 * PRE_SESSION_EPOCH_SECS));
        assert!(!k.verify(&cpre, &t, 1000 + 3 * PRE_SESSION_EPOCH_SECS));
        // Bound to the cookie and the key.
        assert!(!k.verify(&"d".repeat(64), &t, 1000));
        let k2 = PreSessionKey::generate().unwrap();
        assert!(!k2.verify(&cpre, &t, 1000));
        assert!(!k.verify(&cpre, "", 1000));
    }

    #[test]
    fn origin_matrix() {
        // ST-071 CSRF matrix (headers part).
        let o = "http://x.onion";
        let v = |s: &str| OriginHeader::Value(s.to_owned());
        assert!(origin_ok(&OriginHeader::Absent, FetchSite::Absent, o));
        // `null`: only with same-origin (lead decision 2).
        assert!(origin_ok(&OriginHeader::Null, FetchSite::SameOrigin, o));
        assert!(!origin_ok(&OriginHeader::Null, FetchSite::Absent, o));
        assert!(!origin_ok(&OriginHeader::Null, FetchSite::Other, o));
        assert!(origin_ok(&v(o), FetchSite::SameOrigin, o));
        assert!(!origin_ok(&v("http://y.onion"), FetchSite::SameOrigin, o));
        assert!(!origin_ok(&v("https://x.onion"), FetchSite::Absent, o));
        assert!(!origin_ok(&v("http://x.onion:80"), FetchSite::Absent, o));
        assert!(!origin_ok(&OriginHeader::Absent, FetchSite::Other, o));
    }

    #[test]
    fn cookies_have_the_contract_attributes() {
        let c = session_set_cookie(&"a".repeat(64));
        assert!(c.starts_with("__Host-cs="));
        assert!(c.ends_with("; Path=/; Secure; HttpOnly; SameSite=Strict"));
        assert!(!c.contains("Max-Age") && !c.contains("Expires") && !c.contains("Domain"));
        let p = pre_set_cookie(&"b".repeat(64));
        assert!(p.starts_with("__Host-cpre=") && p.ends_with("Max-Age=900"));
        assert!(c.len() <= candor_source_ui::MAX_SET_COOKIE_BYTES);
        assert!(p.len() <= candor_source_ui::MAX_SET_COOKIE_BYTES);
    }
}
