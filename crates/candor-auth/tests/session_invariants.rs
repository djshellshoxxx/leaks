// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_auth::{Audience, Session, SessionError, SessionToken, StaffClass};

fn token(byte: u8) -> SessionToken {
    SessionToken::from_bytes([byte; 32])
}

#[test]
fn st_rm3_staff_tokens_are_256_bit_opaque_values() {
    let t = token(7);
    assert_eq!(t.as_bytes().len(), 32);
    assert_eq!(format!("{t:?}"), "SessionToken([redacted])");
}

#[test]
fn st_rm3_cross_audience_replay_is_rejected() {
    let mut session = Session::new(
        token(1),
        77,
        StaffClass::Recipient,
        Audience::DeskApi,
        1_000,
    );
    assert_eq!(
        session.validate(Audience::AdminApi, 1_001),
        Err(SessionError::Audience)
    );
}

#[test]
fn st_rm3_recipient_session_has_15_min_idle_and_8_hour_absolute_limits() {
    let mut idle = Session::new(
        token(2),
        77,
        StaffClass::Recipient,
        Audience::DeskApi,
        1_000,
    );
    assert_eq!(idle.validate(Audience::DeskApi, 1_899), Ok(()));
    assert_eq!(
        idle.validate(Audience::DeskApi, 2_800),
        Err(SessionError::IdleExpired)
    );

    let mut absolute = Session::new(
        token(3),
        77,
        StaffClass::Recipient,
        Audience::DeskApi,
        1_000,
    );
    assert_eq!(absolute.validate(Audience::DeskApi, 29_800), Ok(()));
    assert_eq!(
        absolute.validate(Audience::DeskApi, 29_801),
        Err(SessionError::AbsoluteExpired)
    );
}

#[test]
fn st_rm3_admin_session_has_10_min_idle_and_2_hour_absolute_limits() {
    let mut idle = Session::new(token(4), 77, StaffClass::Admin, Audience::AdminApi, 1_000);
    assert_eq!(idle.validate(Audience::AdminApi, 1_599), Ok(()));
    assert_eq!(
        idle.validate(Audience::AdminApi, 2_200),
        Err(SessionError::IdleExpired)
    );

    let mut absolute = Session::new(token(5), 77, StaffClass::Admin, Audience::AdminApi, 1_000);
    assert_eq!(absolute.validate(Audience::AdminApi, 8_200), Ok(()));
    assert_eq!(
        absolute.validate(Audience::AdminApi, 8_201),
        Err(SessionError::AbsoluteExpired)
    );
}

#[test]
fn st_rm3_revocation_is_synchronous() {
    let mut session = Session::new(
        token(6),
        77,
        StaffClass::Recipient,
        Audience::DeskApi,
        1_000,
    );
    session.revoke();
    assert_eq!(
        session.validate(Audience::DeskApi, 1_001),
        Err(SessionError::Revoked)
    );
}

#[test]
fn st_rm3_validation_never_refreshes_beyond_absolute_lifetime() {
    let mut session = Session::new(
        token(8),
        77,
        StaffClass::Recipient,
        Audience::DeskApi,
        1_000,
    );
    for now in [
        1_800_u64, 2_600, 3_400, 4_200, 5_000, 5_800, 6_600, 7_400, 8_200, 9_000,
    ] {
        assert_eq!(session.validate(Audience::DeskApi, now), Ok(()));
    }
    assert_eq!(
        session.validate(Audience::DeskApi, 29_801),
        Err(SessionError::AbsoluteExpired)
    );
}
