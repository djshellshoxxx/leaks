// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_authz::{Audience, Session, SessionError, SessionToken, StaffClass};

fn token(byte: u8) -> SessionToken {
    SessionToken::from_bytes([byte; 32])
}

#[test]
fn st_rm3_staff_token_is_256_bit_opaque_and_redacted() {
    let value = token(7);
    assert_eq!(value.as_bytes().len(), 32);
    assert_eq!(format!("{value:?}"), "SessionToken([redacted])");
}

#[test]
fn st_rm3_cross_audience_replay_is_rejected() {
    let mut session = Session::new(token(1), StaffClass::Recipient, Audience::DeskApi, 1_000);
    assert_eq!(
        session.validate(Audience::AdminApi, 1_001),
        Err(SessionError::Audience)
    );
}

#[test]
fn st_rm3_recipient_session_enforces_idle_and_absolute_limits() {
    let mut idle = Session::new(token(2), StaffClass::Recipient, Audience::DeskApi, 1_000);
    assert_eq!(idle.validate(Audience::DeskApi, 1_899), Ok(()));
    assert_eq!(
        idle.validate(Audience::DeskApi, 2_800),
        Err(SessionError::IdleExpired)
    );

    // Keep the session active inside the 15-minute idle window so only the absolute
    // 8-hour limit is under test (AUTH-017: idle 15 min / absolute 8 h).
    let mut absolute = Session::new(token(3), StaffClass::Recipient, Audience::DeskApi, 1_000);
    let mut now = 1_000;
    while now + 900 < 29_800 {
        now += 900;
        assert_eq!(absolute.validate(Audience::DeskApi, now), Ok(()));
    }
    assert_eq!(absolute.validate(Audience::DeskApi, 29_800), Ok(()));
    assert_eq!(
        absolute.validate(Audience::DeskApi, 29_801),
        Err(SessionError::AbsoluteExpired)
    );
}

#[test]
fn st_rm3_admin_session_enforces_stricter_limits() {
    let mut idle = Session::new(token(4), StaffClass::Admin, Audience::AdminApi, 1_000);
    assert_eq!(idle.validate(Audience::AdminApi, 1_599), Ok(()));
    assert_eq!(
        idle.validate(Audience::AdminApi, 2_200),
        Err(SessionError::IdleExpired)
    );

    // Keep the session active inside the 10-minute idle window so only the absolute
    // 2-hour limit is under test (AUTH-017: idle 10 min / absolute 2 h).
    let mut absolute = Session::new(token(5), StaffClass::Admin, Audience::AdminApi, 1_000);
    let mut now = 1_000;
    while now + 600 < 8_200 {
        now += 600;
        assert_eq!(absolute.validate(Audience::AdminApi, now), Ok(()));
    }
    assert_eq!(absolute.validate(Audience::AdminApi, 8_200), Ok(()));
    assert_eq!(
        absolute.validate(Audience::AdminApi, 8_201),
        Err(SessionError::AbsoluteExpired)
    );
}

#[test]
fn st_rm3_revocation_is_synchronous() {
    let mut session = Session::new(token(6), StaffClass::Recipient, Audience::DeskApi, 1_000);
    session.revoke();
    assert_eq!(
        session.validate(Audience::DeskApi, 1_001),
        Err(SessionError::Revoked)
    );
}
