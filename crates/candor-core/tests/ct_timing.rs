// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-026 / AUD-RM1-CORE-05(d): dudect-style statistical timing test for the
//! constant-time comparisons (separate test target `ct_timing`).
//!
//! Method (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", 2017):
//! two input classes that differ only in *where* (or whether) secret data differs are
//! measured in random interleaved order; the timing distributions are cropped at a
//! percentile to remove scheduler outliers and compared with Welch's t-test. A
//! comparison that exits early shows |t| in the hundreds; dudect treats |t| > 10 as
//! "definitely not constant time". The threshold here is CI-tolerant (|t| < 10) and a
//! positive control (a non-constant-time comparison) proves the harness detects leaks.
//!
//! Set `CANDOR_SKIP_CT_TIMING=1` to skip on machines too noisy for timing (e.g. heavily
//! shared CI runners); the skip is printed.
#![allow(clippy::disallowed_macros, clippy::disallowed_methods)] // test harness: prints timing statistics to stdout for CI diagnosis; not trust-path code
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use candor_core::Suite;
use candor_core::header::{CoreHeader, ObjectType};
use candor_core::kdf::ct_eq;
use candor_core::kem::{KemKeyPair, open_base, seal_base};
use candor_core::passphrase::Wordlist;
use candor_core::secret::ContentKey;
use candor_core::stream::{CHUNK_SIZE, StreamDecryptor};
use std::hint::black_box;
use std::time::Instant;

/// |t| above this fails the constant-time checks (dudect: > 10 = definitely leaky).
const T_FAIL: f64 = 10.0;
/// The positive control must exceed dudect's "probably leaky" threshold.
const T_CONTROL: f64 = 4.5;

/// xorshift64* for the class schedule (not security relevant).
struct Sched(u64);
impl Sched {
    fn bit(&mut self) -> bool {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 63 == 1
    }
}

/// Measure `samples` timings of `reps` calls of `f(class)` in random class order.
fn measure(
    samples: usize,
    reps: usize,
    seed: u64,
    mut f: impl FnMut(bool),
) -> (Vec<f64>, Vec<f64>) {
    let mut s = Sched(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    let (mut a, mut b) = (Vec::with_capacity(samples), Vec::with_capacity(samples));
    // Warm-up.
    for i in 0..(samples / 10).max(4) {
        f(i % 2 == 0);
    }
    for _ in 0..samples * 2 {
        let class = s.bit();
        let t0 = Instant::now();
        for _ in 0..reps {
            f(class);
        }
        let dt = t0.elapsed().as_nanos() as f64;
        if class { a.push(dt) } else { b.push(dt) }
    }
    (a, b)
}

/// Keep values at or below the given percentile of the pooled distribution.
fn crop(a: &[f64], b: &[f64], pct: f64) -> (Vec<f64>, Vec<f64>) {
    let mut all: Vec<f64> = a.iter().chain(b).copied().collect();
    all.sort_by(f64::total_cmp);
    let cut = all[((all.len() as f64 - 1.0) * pct) as usize];
    (
        a.iter().copied().filter(|x| *x <= cut).collect(),
        b.iter().copied().filter(|x| *x <= cut).collect(),
    )
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let m = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (n - 1.0);
        (n, m, var)
    };
    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    let den = (va / na + vb / nb).sqrt();
    if den == 0.0 { 0.0 } else { (ma - mb) / den }
}

/// Max |t| over several crop levels (dudect reports the most significant one).
fn max_t(a: &[f64], b: &[f64]) -> f64 {
    [0.5, 0.75, 0.9, 0.99]
        .iter()
        .map(|p| {
            let (ca, cb) = crop(a, b, *p);
            welch_t(&ca, &cb).abs()
        })
        .fold(0.0, f64::max)
}

/// A timing difference is only reported when it reproduces in every one of this many
/// independent measurements (dudect practice: confirm before concluding). A genuine
/// data-dependent timing difference is stable and exceeds the threshold every time;
/// scheduler or co-tenant noise on a shared runner (one run of `kdf::ct_eq` reached
/// |t| = 18 on a GitHub runner although earlier and later runs were clean) does not.
const CONFIRM_RUNS: usize = 3;

/// Runs up to `CONFIRM_RUNS` independent measurements. Returns `(confirmed_leak, last_t)`;
/// stops at the first clean measurement.
fn confirmed_leak(name: &str, samples: usize, reps: usize, mut f: impl FnMut(bool)) -> (bool, f64) {
    let mut last = 0.0;
    for attempt in 0..CONFIRM_RUNS {
        let (a, b) = measure(samples, reps, attempt as u64, &mut f);
        let t = max_t(&a, &b);
        println!(
            "ct_timing {name}: run {}/{CONFIRM_RUNS} max |t| = {t:.2} ({} + {} samples)",
            attempt + 1,
            a.len(),
            b.len()
        );
        if t < T_FAIL {
            return (false, t);
        }
        last = t;
    }
    (true, last)
}

fn check_ct(name: &str, samples: usize, reps: usize, f: impl FnMut(bool)) {
    let (leak, t) = confirmed_leak(name, samples, reps, f);
    assert!(
        !leak,
        "{name}: timing depends on secret data (|t| >= {T_FAIL} in all {CONFIRM_RUNS} independent runs; last |t| = {t:.2})"
    );
}

#[test]
fn constant_time_comparisons() {
    if std::env::var("CANDOR_SKIP_CT_TIMING").is_ok_and(|v| v == "1") {
        println!("ct_timing skipped (CANDOR_SKIP_CT_TIMING=1)");
        return;
    }
    // All sub-tests run sequentially in one test so they never compete for the CPU.

    // Positive control: a short-circuiting comparison must be detected.
    let x = vec![0x5Au8; 4096];
    // One shared buffer for both classes: separate allocations differ in address,
    // alignment and cache-set placement, which gives a stable, data-independent timing
    // offset (a harness artefact, not a leak). Only the mismatch position changes.
    let y = std::cell::RefCell::new(x.clone());
    let with_mismatch = |c: bool, f: &mut dyn FnMut(&[u8])| {
        let i = if c { 0 } else { 4095 };
        let mut y = y.borrow_mut();
        y[i] ^= 1;
        f(black_box(&y[..]));
        y[i] ^= 1;
    };
    let (a, b) = measure(2000, 16, 0, |c| {
        with_mismatch(c, &mut |y| {
            black_box(black_box(&x[..]) == black_box(y));
        });
    });
    let t = max_t(&a, &b);
    println!("ct_timing positive control (==): max |t| = {t:.2}");
    assert!(
        t > T_CONTROL,
        "harness failed to detect a leaky comparison (|t| = {t:.2})"
    );

    // The confirmation procedure must still flag a real leak: the short-circuiting
    // comparison reproduces |t| > T_FAIL in every one of the independent runs.
    let (leak, t) = confirmed_leak("leaky == (must be flagged)", 2000, 16, |c| {
        with_mismatch(c, &mut |y| {
            black_box(black_box(&x[..]) == black_box(y));
        });
    });
    assert!(
        leak,
        "confirmation procedure failed to flag a real leak (last |t| = {t:.2})"
    );

    // kdf::ct_eq (MACs, tags, bound hashes, slots): mismatch at the first vs last byte.
    check_ct("kdf::ct_eq", 2000, 16, |c| {
        with_mismatch(c, &mut |y| {
            black_box(ct_eq(black_box(&x), black_box(y)));
        });
    });

    // header_mac verification: wrong MAC differing at byte 0 vs byte 31.
    let ck = ContentKey::from_bytes([7; 32]);
    let h = CoreHeader {
        object_type: ObjectType::Reply,
        suite: Suite::CandorStd1,
        tenant_id: [1; 16],
        channel_id: [0; 16],
        epoch_id: 0,
        slot_block_hash: [0; 32],
        object_id: [2; 16],
        day_stamp: 0,
        padded_plaintext_len: 4096,
        payload_nonce: [3; 16],
    };
    let mac = h.header_mac(&ck).unwrap();
    let (mut m0, mut m31) = (mac, mac);
    m0[0] ^= 1;
    m31[31] ^= 1;
    check_ct("CoreHeader::verify_header_mac", 1500, 8, |c| {
        let m = if c { &m0 } else { &m31 };
        black_box(h.verify_header_mac(&ck, black_box(m)).is_err());
    });

    // STREAM chunk tag verification: tag wrong at byte 0 vs byte 15 (both rejected).
    let len = 1024u64;
    let ck2 = ContentKey::from_bytes([4; 32]);
    let (enc, nonce) =
        candor_core::stream::StreamEncryptor::for_payload(Suite::CandorStd1, &ck2, len).unwrap();
    let ct = enc.encrypt_all(&[0u8; 1024]).unwrap();
    assert!(ct.len() < CHUNK_SIZE);
    let (mut t0, mut t15) = (ct.clone(), ct.clone());
    let tag = ct.len() - 16;
    t0[tag] ^= 1;
    t15[tag + 15] ^= 1;
    check_ct("STREAM chunk tag check", 1500, 8, |c| {
        let x = if c { &t0 } else { &t15 };
        let mut d = StreamDecryptor::for_payload(Suite::CandorStd1, &ck2, &nonce, len).unwrap();
        black_box(d.decrypt_chunk(black_box(x)).is_err());
    });

    // X-Wing decapsulation inside HPKE open: a valid encapsulation vs one whose ML-KEM
    // ciphertext is corrupted (implicit rejection); the AEAD tag is wrong in both, so
    // both calls fail and only the decapsulation path differs.
    let kp = KemKeyPair::derive(Suite::CandorStd1, &[0x31; 32]).unwrap();
    let (enc, mut hct) = seal_base(&kp.public, b"info", b"aad", &[0u8; 32]).unwrap();
    *hct.last_mut().unwrap() ^= 1;
    let mut enc_bad = enc.clone();
    enc_bad[0] ^= 1;
    check_ct("X-Wing decapsulation (implicit rejection)", 400, 1, |c| {
        let e = if c { &enc } else { &enc_bad };
        black_box(open_base(&kp.private, black_box(e), b"info", b"aad", &hct).is_err());
    });

    // Wordlist::check (AUD-RM1-CORE-08): the first word matches the list's first entry
    // vs no word matches (an early-exit scan would differ by the whole list).
    let words: Vec<String> = (0..2048).map(|i| format!("w{i:04}")).collect();
    let list = Wordlist::from_words(&words).unwrap();
    let hit = vec!["w0000"; list.word_count()].join(" ");
    let miss = vec!["zzzzz"; list.word_count()].join(" ");
    check_ct("Wordlist::check", 150, 1, |c| {
        let p = if c { &hit } else { &miss };
        black_box(list.check(black_box(p)));
    });
}
