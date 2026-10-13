// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

//! Staff session primitives (C-21). Reuses the independently maintained,
//! deny-by-default session-expiry logic from candor-authz rather than duplicating
//! cryptographic token or expiry policy. This is not a complete authenticator:
//! callers must verify the staff identity and token before constructing a session.

use core::fmt;

pub use candor_authz::{Audience, SessionError, SessionToken, StaffClass};

/// The subject-bound session held by the trusted authentication service.
/// Never build from client-provided person references without authentication.
#[derive(Clone)]
pub struct Session {
    subject_ref: u128,
    inner: candor_authz::Session,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Session([redacted])")
    }
}

impl Session {
    /// Construct after authenticating the staff subject in the trusted service.
    #[must_use]
    pub const fn new(
        token: SessionToken,
        subject_ref: u128,
        class: StaffClass,
        audience: Audience,
        issued_at: u64,
    ) -> Self {
        Self {
            subject_ref,
            inner: candor_authz::Session::new(token, class, audience, issued_at),
        }
    }

    /// Apply the audience, idle, absolute and revocation checks atomically
    /// with last-activity updates. Errors never extend a session.
    pub fn validate(&mut self, audience: Audience, now: u64) -> Result<(), SessionError> {
        self.inner.validate(audience, now)
    }

    /// Revoke this in-memory session immediately.
    pub fn revoke(&mut self) {
        self.inner.revoke();
    }

    /// Return the opaque credential for the trusted service to compare.
    #[must_use]
    pub const fn token(&self) -> SessionToken {
        self.inner.token()
    }

    /// Subject already bound by the trusted authenticator.
    #[must_use]
    pub const fn subject_ref(&self) -> u128 {
        self.subject_ref
    }
}
