// SPDX-License-Identifier: AGPL-3.0-or-later
//! Negative and property tests for the relay request authenticator (07 §5.4; ST-092 origin
//! pinning, ST-096 hostile intake, the B-SD-20 replay lesson). The spec contract itself is in
//! `relay_invariants.rs`.

use candor_relay::{
    Backpressure, MAX_METHOD_LEN, MAX_PATH_LEN, RelayAuthError, RelayAuthenticator,
    request_signing_message,
};
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;

const CLAIM: &str = "/relay/v1/batches/claim";

fn sign(key: &SigningKey, method: &str, path: &str, body: &[u8], counter: u64) -> [u8; 64] {
    key.sign(&request_signing_message(method, path, body, counter))
        .to_bytes()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn tampering_any_signed_field_fails_and_leaves_the_counter_untouched() {
    let signing = key(1);
    let mut auth = RelayAuthenticator::new(signing.verifying_key(), 10);
    let sig = sign(&signing, "POST", CLAIM, b"claim", 11);

    assert_eq!(
        auth.verify("GET", CLAIM, b"claim", 11, &sig),
        Err(RelayAuthError::BadSignature)
    );
    assert_eq!(
        auth.verify("POST", "/relay/v1/batches/ack", b"claim", 11, &sig),
        Err(RelayAuthError::BadSignature)
    );
    assert_eq!(
        auth.verify("POST", CLAIM, b"claim!", 11, &sig),
        Err(RelayAuthError::BadSignature)
    );
    assert_eq!(
        auth.verify("POST", CLAIM, b"claim", 12, &sig),
        Err(RelayAuthError::BadSignature)
    );
    // A forged request must not burn the counter: the genuine request still lands.
    assert_eq!(auth.last_counter(), 10);
    assert_eq!(auth.verify("POST", CLAIM, b"claim", 11, &sig), Ok(()));
    assert_eq!(auth.last_counter(), 11);
}

#[test]
fn a_different_relay_key_is_rejected() {
    let signing = key(2);
    let other = key(3);
    let mut auth = RelayAuthenticator::new(signing.verifying_key(), 0);
    let sig = sign(&other, "GET", "/relay/v1/health", b"", 1);
    assert_eq!(
        auth.verify("GET", "/relay/v1/health", b"", 1, &sig),
        Err(RelayAuthError::BadSignature)
    );
    assert_eq!(auth.last_counter(), 0);
}

#[test]
fn malformed_method_or_path_is_refused_before_any_verification() {
    let signing = key(4);
    let mut auth = RelayAuthenticator::new(signing.verifying_key(), 0);
    let long_method = "A".repeat(MAX_METHOD_LEN + 1);
    let long_path = format!("/{}", "a".repeat(MAX_PATH_LEN));
    for (method, path) in [
        ("get", CLAIM),
        ("", CLAIM),
        ("POST ", CLAIM),
        (long_method.as_str(), CLAIM),
        ("POST", ""),
        ("POST", "relay/v1/batches/claim"),
        ("POST", "/relay/v1/batches claim"),
        ("POST", "/relay/v1/\u{7f}"),
        ("POST", long_path.as_str()),
    ] {
        let sig = sign(&signing, method, path, b"", 1);
        assert_eq!(
            auth.verify(method, path, b"", 1, &sig),
            Err(RelayAuthError::Malformed),
            "method {method:?} path {path:?}"
        );
    }
    assert_eq!(auth.last_counter(), 0);
    let ok_path = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
    let sig = sign(&signing, "POST", &ok_path, b"", 1);
    assert_eq!(auth.verify("POST", &ok_path, b"", 1, &sig), Ok(()));
}

#[test]
fn counter_zero_is_never_accepted_and_exhaustion_fails_closed() {
    let signing = key(5);
    let mut auth = RelayAuthenticator::new(signing.verifying_key(), 0);
    let sig = sign(&signing, "GET", "/relay/v1/health", b"", 0);
    assert_eq!(
        auth.verify("GET", "/relay/v1/health", b"", 0, &sig),
        Err(RelayAuthError::Replay)
    );

    let mut exhausted = RelayAuthenticator::new(signing.verifying_key(), u64::MAX);
    let sig = sign(&signing, "GET", "/relay/v1/health", b"", u64::MAX);
    assert_eq!(
        exhausted.verify("GET", "/relay/v1/health", b"", u64::MAX, &sig),
        Err(RelayAuthError::CounterExhausted)
    );
    assert_eq!(exhausted.last_counter(), u64::MAX);
}

#[test]
fn persisted_counter_survives_a_restart_of_the_verifier() {
    let signing = key(6);
    let mut auth = RelayAuthenticator::new(signing.verifying_key(), 0);
    let sig = sign(&signing, "GET", "/relay/v1/health", b"", 5);
    assert_eq!(auth.verify("GET", "/relay/v1/health", b"", 5, &sig), Ok(()));
    let persisted = auth.last_counter();

    let mut restarted = RelayAuthenticator::new(signing.verifying_key(), persisted);
    assert_eq!(
        restarted.verify("GET", "/relay/v1/health", b"", 5, &sig),
        Err(RelayAuthError::Replay)
    );
    let next = sign(&signing, "GET", "/relay/v1/health", b"", 6);
    assert_eq!(
        restarted.verify("GET", "/relay/v1/health", b"", 6, &next),
        Ok(())
    );
}

#[test]
fn backpressure_boundaries() {
    assert!(!Backpressure::new(10, 50_000).must_stop());
    assert!(!Backpressure::new(100, 0).must_stop());
    assert!(Backpressure::new(9, 50_000).must_stop());
    assert!(Backpressure::new(10, 50_001).must_stop());
    assert!(Backpressure::new(0, u64::MAX).must_stop());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A correctly signed request verifies once; any single-byte change to the signature, a
    /// different counter, or any change to the body is refused and leaves the counter alone.
    #[test]
    fn sign_then_verify_round_trip_and_mutations(
        seed in any::<u8>(),
        method in "[A-Z]{1,16}",
        path in "/[a-z0-9/_.-]{0,80}",
        body in proptest::collection::vec(any::<u8>(), 0..256),
        last in 0_u64..(u64::MAX - 2),
        step in 1_u64..1_000,
        flip in 0_usize..64,
        bit in 0_u8..8,
    ) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let counter = last.saturating_add(step);
        let sig = sign(&signing, &method, &path, &body, counter);

        let mut auth = RelayAuthenticator::new(signing.verifying_key(), last);
        let mut flipped = sig;
        flipped[flip] ^= 1 << bit;
        prop_assert_eq!(
            auth.verify(&method, &path, &body, counter, &flipped),
            Err(RelayAuthError::BadSignature)
        );
        prop_assert_eq!(
            auth.verify(&method, &path, &body, counter.saturating_add(1), &sig),
            Err(RelayAuthError::BadSignature)
        );
        let mut other_body = body.clone();
        other_body.push(0);
        prop_assert_eq!(
            auth.verify(&method, &path, &other_body, counter, &sig),
            Err(RelayAuthError::BadSignature)
        );
        prop_assert_eq!(auth.last_counter(), last);

        prop_assert_eq!(auth.verify(&method, &path, &body, counter, &sig), Ok(()));
        prop_assert_eq!(auth.last_counter(), counter);
        prop_assert_eq!(
            auth.verify(&method, &path, &body, counter, &sig),
            Err(RelayAuthError::Replay)
        );
    }
}
