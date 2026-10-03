// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_relay::{IntakeEndpoint, RelayError, RelayGuard};

const INTAKE: IntakeEndpoint = IntakeEndpoint {
    address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 20, 30, 40],
    port: 7443,
};

#[test]
fn counters_are_strictly_monotonic() {
    let mut guard = RelayGuard::new(INTAKE, 50_000);
    assert_eq!(guard.accept_counter(1), Ok(()));
    assert_eq!(guard.last_counter(), 1);
    assert_eq!(guard.accept_counter(1), Err(RelayError::Replay));
    assert_eq!(guard.accept_counter(0), Err(RelayError::Replay));
    assert_eq!(guard.accept_counter(2), Ok(()));
}

#[test]
fn zero_counter_is_never_accepted() {
    let mut guard = RelayGuard::new(INTAKE, 50_000);
    assert_eq!(guard.accept_counter(0), Err(RelayError::Replay));
}

#[test]
fn exhausted_counter_fails_closed() {
    let mut guard = RelayGuard::new(INTAKE, 50_000);
    assert_eq!(guard.accept_counter(u64::MAX), Ok(()));
    assert_eq!(
        guard.accept_counter(u64::MAX),
        Err(RelayError::CounterExhausted)
    );
}

#[test]
fn import_backpressure_stops_claiming() {
    let guard = RelayGuard::new(INTAKE, 50_000);
    assert_eq!(guard.may_claim(49_999, 10), Ok(()));
    assert_eq!(guard.may_claim(50_000, 10), Err(RelayError::Backpressure));
    assert_eq!(guard.may_claim(1, 9), Err(RelayError::Backpressure));
}

#[test]
fn transport_policy_only_allows_configured_intake_endpoint() {
    let guard = RelayGuard::new(INTAKE, 50_000);
    assert_eq!(guard.allow_outbound(INTAKE), Ok(()));
    let other_port = IntakeEndpoint {
        port: 443,
        ..INTAKE
    };
    assert_eq!(
        guard.allow_outbound(other_port),
        Err(RelayError::DestinationDenied)
    );
    let other_host = IntakeEndpoint {
        address: [1; 16],
        port: 7443,
    };
    assert_eq!(
        guard.allow_outbound(other_host),
        Err(RelayError::DestinationDenied)
    );
    assert_eq!(guard.allow_inbound(), Err(RelayError::InboundDenied));
}
