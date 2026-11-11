// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay request authentication (07 §5.4; 08 §4 `Candor-Relay-Sig`).
//!
//! Every relay request carries `ed25519(relay_key, method ‖ path ‖ sha256(body) ‖ req_counter)`
//! and a strictly increasing `req_counter` that both sides persist; replays are rejected. This
//! module is the transport-independent verifier: it holds the pinned *public* key only, never
//! signs, and does no I/O. Strict RFC 8032 verification and SHA-256 come from `candor-core`
//! (audited in RM-1) so there is no second implementation of either.

use crate::counter::{CounterError, check_counter};

/// Domain-separation label prepended to the signed request message. The spec names the signed
/// fields; this crate fixes the byte layout (see `SPEC-NOTES.md`, "Request signature layout").
pub const REQUEST_SIGNING_LABEL: &[u8] = b"candor/relay-req/v1";
/// Longest HTTP method the verifier accepts (the longest relay method, `DELETE`, is 6 bytes).
pub const MAX_METHOD_LEN: usize = 16;
/// Longest request path the verifier accepts (every 08 §4 relay route is far shorter).
pub const MAX_PATH_LEN: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayAuthError {
    /// Method or path violates the length or character rules; nothing was verified.
    Malformed,
    /// Counter is zero, or not strictly greater than the last accepted counter.
    Replay,
    /// The last accepted counter is `u64::MAX`; the relay identity must be replaced, never wrapped.
    CounterExhausted,
    /// The signature does not verify over the canonical message under the pinned key.
    BadSignature,
}

fn method_ok(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= MAX_METHOD_LEN
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn path_ok(path: &str) -> bool {
    path.len() <= MAX_PATH_LEN
        && path.starts_with('/')
        && path.bytes().all(|byte| byte.is_ascii_graphic())
}

fn length_prefix(len: usize) -> [u8; 8] {
    u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes()
}

/// The canonical byte string both sides sign and verify:
/// `label ‖ len(method) ‖ method ‖ len(path) ‖ path ‖ sha256(body) ‖ counter`, with 8-byte
/// big-endian lengths and counter. Length prefixes make the encoding injective, so no choice of
/// method/path/body can collide with another request.
#[must_use]
pub fn request_signing_message(method: &str, path: &str, body: &[u8], counter: u64) -> Vec<u8> {
    let body_hash = candor_core::hash::sha256(&[body]);
    let capacity = REQUEST_SIGNING_LABEL
        .len()
        .saturating_add(method.len())
        .saturating_add(path.len())
        .saturating_add(8 + 8 + 32 + 8);
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(REQUEST_SIGNING_LABEL);
    message.extend_from_slice(&length_prefix(method.len()));
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&length_prefix(path.len()));
    message.extend_from_slice(path.as_bytes());
    message.extend_from_slice(&body_hash);
    message.extend_from_slice(&counter.to_be_bytes());
    message
}

/// Verifier for one pinned relay identity. Keeps the last accepted counter, which the caller
/// persists durably (07 §5.4) before acting on the request and restores on start.
#[derive(Debug)]
pub struct RelayAuthenticator {
    key: [u8; 32],
    last_counter: u64,
}

impl RelayAuthenticator {
    /// `last_counter` is the persisted high-water mark (0 for a fresh identity).
    #[must_use]
    pub fn new(key: ed25519_dalek::VerifyingKey, last_counter: u64) -> Self {
        Self {
            key: key.to_bytes(),
            last_counter,
        }
    }

    /// Verify one request. Order: shape → counter (not yet committed) → signature → commit.
    /// The counter advances only after the signature verifies, so a forged request can neither
    /// burn counters nor learn anything beyond the public counter rule.
    pub fn verify(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        counter: u64,
        signature: &[u8; 64],
    ) -> Result<(), RelayAuthError> {
        if !method_ok(method) || !path_ok(path) {
            return Err(RelayAuthError::Malformed);
        }
        check_counter(self.last_counter, counter).map_err(|error| match error {
            CounterError::Exhausted => RelayAuthError::CounterExhausted,
            CounterError::Replay => RelayAuthError::Replay,
        })?;
        let message = request_signing_message(method, path, body, counter);
        candor_core::sig::verify_strict(&self.key, &message, signature)
            .map_err(|_| RelayAuthError::BadSignature)?;
        self.last_counter = counter;
        Ok(())
    }

    /// The counter to persist after a successful `verify`.
    #[must_use]
    pub const fn last_counter(&self) -> u64 {
        self.last_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_and_path_rules() {
        assert!(method_ok("GET"));
        assert!(method_ok("DELETE"));
        assert!(!method_ok(""));
        assert!(!method_ok("get"));
        assert!(!method_ok("GET "));
        assert!(!method_ok(&"A".repeat(MAX_METHOD_LEN + 1)));
        assert!(path_ok("/"));
        assert!(path_ok("/relay/v1/batches/claim"));
        assert!(!path_ok(""));
        assert!(!path_ok("relay/v1/health"));
        assert!(!path_ok("/relay/v1/\u{0}"));
        assert!(!path_ok("/relay v1"));
        assert!(!path_ok(&format!("/{}", "a".repeat(MAX_PATH_LEN))));
    }

    #[test]
    fn message_layout_is_injective_across_field_boundaries() {
        assert_ne!(
            request_signing_message("AB", "/C", b"", 1),
            request_signing_message("A", "/BC", b"", 1)
        );
        assert_ne!(
            request_signing_message("GET", "/a", b"b", 1),
            request_signing_message("GET", "/ab", b"", 1)
        );
        assert_ne!(
            request_signing_message("GET", "/a", b"", 1),
            request_signing_message("GET", "/a", b"", 2)
        );
        let message = request_signing_message("GET", "/a", b"body", 7);
        assert!(message.starts_with(REQUEST_SIGNING_LABEL));
        assert!(message.ends_with(&7_u64.to_be_bytes()));
        assert_eq!(
            message.len(),
            REQUEST_SIGNING_LABEL.len() + 8 + 3 + 8 + 2 + 32 + 8
        );
    }
}
