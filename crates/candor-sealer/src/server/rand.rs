// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sampling helpers over the single OS CSPRNG of `candor-core` (§23.4). Every
//! failure propagates (fail closed); nothing falls back to a weaker source.

use candor_core::{Error, fill_random};

/// Uniform integer in `0..n` by rejection sampling (no modulo bias).
pub(crate) fn uniform_below(n: u32) -> Result<u32, Error> {
    if n == 0 {
        return Err(Error::Internal);
    }
    // Largest multiple of n that fits in u32's range: accept x < zone.
    let zone = u32::MAX
        .checked_sub(u32::MAX.checked_rem(n).ok_or(Error::Internal)?)
        .ok_or(Error::Internal)?;
    for _ in 0..128 {
        let mut b = [0u8; 4];
        fill_random(&mut b)?;
        let x = u32::from_be_bytes(b);
        if x < zone {
            return x.checked_rem(n).ok_or(Error::Internal);
        }
    }
    Err(Error::Rng)
}

/// Three distinct positions in `0..word_count`, ascending (04 §11.1).
pub(crate) fn confirm_positions(word_count: usize) -> Result<[u8; 3], Error> {
    let n = u32::try_from(word_count).map_err(|_| Error::Internal)?;
    if !(3..=u32::from(u8::MAX)).contains(&n) {
        return Err(Error::Internal);
    }
    let mut picked: Vec<u8> = Vec::with_capacity(3);
    while picked.len() < 3 {
        let p = u8::try_from(uniform_below(n)?).map_err(|_| Error::Internal)?;
        if !picked.contains(&p) {
            picked.push(p);
        }
    }
    picked.sort_unstable();
    match picked.as_slice() {
        [a, b, c] => Ok([*a, *b, *c]),
        _ => Err(Error::Internal),
    }
}

/// Delayed delivery offset U{1,2,3} days (ADR-038(4)).
pub(crate) fn release_offset() -> Result<u8, Error> {
    let x = uniform_below(3)?;
    u8::try_from(x.checked_add(1).ok_or(Error::Internal)?).map_err(|_| Error::Internal)
}

/// Uniform `f64` in `(0, 1]` with 53 random bits.
fn unit_open_closed() -> Result<f64, Error> {
    let mut b = [0u8; 8];
    fill_random(&mut b)?;
    let x = u64::from_be_bytes(b) >> 11; // 53 bits
    // (x + 1) / 2^53 ∈ (0, 1]
    #[allow(clippy::cast_precision_loss)]
    let v = (x as f64 + 1.0) / 9_007_199_254_740_992.0;
    Ok(v)
}

/// Exponential inter-arrival time with mean `mean_secs` (04 §12.7), capped at
/// 64 × the mean so the value is always representable.
pub(crate) fn exponential_secs(mean_secs: f64) -> Result<f64, Error> {
    let u = unit_open_closed()?;
    let d = -mean_secs * u.ln();
    if d.is_finite() && d >= 0.0 {
        Ok(d.min(mean_secs * 64.0))
    } else {
        Err(Error::Internal)
    }
}

/// Bernoulli trial with probability `permille / 1000`.
pub(crate) fn bernoulli_permille(permille: u16) -> Result<bool, Error> {
    Ok(uniform_below(1000)? < u32::from(permille))
}

/// Draw an index from a weighted table.
pub(crate) fn weighted<T: Copy>(table: &[(T, u32)]) -> Result<T, Error> {
    let total = table
        .iter()
        .try_fold(0u32, |acc, (_, w)| acc.checked_add(*w))
        .ok_or(Error::Internal)?;
    let mut x = uniform_below(total)?;
    for (v, w) in table {
        if x < *w {
            return Ok(*v);
        }
        x = x.checked_sub(*w).ok_or(Error::Internal)?;
    }
    Err(Error::Internal)
}

/// 16 random bytes.
pub(crate) fn random16() -> Result<[u8; 16], Error> {
    let mut b = [0u8; 16];
    fill_random(&mut b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn uniform_in_range_and_positions_distinct() {
        for _ in 0..1000 {
            assert!(uniform_below(7).unwrap() < 7);
            let p = confirm_positions(10).unwrap();
            assert!(p[0] < p[1] && p[1] < p[2] && p[2] < 10);
            let r = release_offset().unwrap();
            assert!((1..=3).contains(&r));
        }
        assert!(uniform_below(0).is_err());
    }

    #[test]
    fn exponential_mean_is_plausible() {
        let n = 20_000;
        let mean: f64 = (0..n)
            .map(|_| exponential_secs(100.0).unwrap())
            .sum::<f64>()
            / n as f64;
        assert!((90.0..110.0).contains(&mean), "{mean}");
    }

    #[test]
    fn weighted_respects_zero_weights() {
        for _ in 0..200 {
            assert_eq!(weighted(&[(1u8, 0), (2u8, 5)]).unwrap(), 2);
        }
    }
}
