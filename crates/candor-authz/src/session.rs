// SPDX-License-Identifier: AGPL-3.0-or-later

use core::fmt;

const RECIPIENT_IDLE_SECONDS: u64 = 15 * 60;
const RECIPIENT_ABSOLUTE_SECONDS: u64 = 8 * 60 * 60;
const ADMIN_IDLE_SECONDS: u64 = 10 * 60;
const ADMIN_ABSOLUTE_SECONDS: u64 = 2 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionToken([u8; 32]);

impl SessionToken {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    DeskApi,
    AdminApi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaffClass {
    Recipient,
    Admin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    Audience,
    IdleExpired,
    AbsoluteExpired,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct Session {
    token: SessionToken,
    class: StaffClass,
    audience: Audience,
    issued_at: u64,
    last_activity: u64,
    revoked: bool,
}

impl Session {
    #[must_use]
    pub const fn new(
        token: SessionToken,
        class: StaffClass,
        audience: Audience,
        issued_at: u64,
    ) -> Self {
        Self {
            token,
            class,
            audience,
            issued_at,
            last_activity: issued_at,
            revoked: false,
        }
    }

    pub const fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&mut self, audience: Audience, now: u64) -> Result<(), SessionError> {
        if self.revoked {
            return Err(SessionError::Revoked);
        }
        if audience != self.audience {
            return Err(SessionError::Audience);
        }

        let (idle_limit, absolute_limit) = match self.class {
            StaffClass::Recipient => (RECIPIENT_IDLE_SECONDS, RECIPIENT_ABSOLUTE_SECONDS),
            StaffClass::Admin => (ADMIN_IDLE_SECONDS, ADMIN_ABSOLUTE_SECONDS),
        };

        if now.saturating_sub(self.issued_at) > absolute_limit {
            return Err(SessionError::AbsoluteExpired);
        }
        if now.saturating_sub(self.last_activity) > idle_limit {
            return Err(SessionError::IdleExpired);
        }

        self.last_activity = now;
        Ok(())
    }

    #[must_use]
    pub const fn token(&self) -> SessionToken {
        self.token
    }
}
