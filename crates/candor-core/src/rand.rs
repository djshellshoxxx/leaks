// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Randomness (§23.4, CRYPTO-033). The only production source is `getrandom(2)`.
//!
//! Internally every randomized function is written against [`RandomSource`] so the
//! crate's own unit tests can generate deterministic test vectors; the only
//! implementation reachable from the public API is [`OsRandom`].

use crate::error::{Error, Result};
use hpke::rand_core::{TryCryptoRng, TryRng, utils};
use zeroize::Zeroize;

/// Source of random bytes.
pub(crate) trait RandomSource {
    /// Fill `buf` with random bytes or fail closed.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// The operating-system CSPRNG (`getrandom(2)`, blocking until seeded).
#[derive(Debug, Default)]
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        fill(buf)
    }
}

/// Fill `buf` from the OS CSPRNG with a health check: a request of ≥ 16 bytes that
/// returns all zeros is treated as an RNG failure (§23.4 "non-zero" health check).
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)?;
    if buf.len() >= 16 && buf.iter().all(|b| *b == 0) {
        return Err(Error::Rng);
    }
    Ok(())
}

/// Uniform integer in `[0, n)` by rejection sampling over 32-bit draws (no modulo bias).
pub(crate) fn uniform_below(rng: &mut dyn RandomSource, n: u32) -> Result<u32> {
    if n == 0 {
        return Err(Error::Internal);
    }
    // limit = largest multiple of n that fits in 2^32; accept x < limit.
    let limit: u64 = (1u64 << 32) / u64::from(n) * u64::from(n);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b)?;
        let x = u64::from(u32::from_be_bytes(b));
        if x < limit {
            return u32::try_from(x % u64::from(n)).map_err(|_| Error::Internal);
        }
    }
}

/// Uniformly random permutation of `0..n` (Fisher–Yates with rejection sampling).
pub(crate) fn permutation(rng: &mut dyn RandomSource, n: usize) -> Result<Vec<usize>> {
    let mut v: Vec<usize> = (0..n).collect();
    let mut i = n;
    while i > 1 {
        i -= 1;
        let bound = u32::try_from(i.checked_add(1).ok_or(Error::Internal)?).map_err(|_| Error::Internal)?;
        let j = usize::try_from(uniform_below(rng, bound)?).map_err(|_| Error::Internal)?;
        v.swap(i, j);
    }
    Ok(v)
}

/// An RNG adaptor that serves exactly the pre-drawn bytes it was given, used to feed
/// HPKE encapsulation randomness so that all randomness comes from a fallible,
/// checked source. Over-consumption sets a flag; callers check [`ExactBytesRng::check`]
/// and discard the output if the KEM consumed a different amount than expected.
pub(crate) struct ExactBytesRng {
    buf: [u8; 64],
    pos: usize,
    overrun: bool,
}

impl ExactBytesRng {
    pub(crate) fn new(buf: [u8; 64]) -> Self {
        Self { buf, pos: 0, overrun: false }
    }

    /// `Ok` iff exactly all 64 bytes were consumed and nothing more.
    pub(crate) fn check(&self) -> Result<()> {
        if self.overrun || self.pos != self.buf.len() {
            return Err(Error::Internal);
        }
        Ok(())
    }
}

impl Drop for ExactBytesRng {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl TryRng for ExactBytesRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        let end = self.pos.checked_add(dest.len());
        match end.and_then(|e| self.buf.get(self.pos..e).map(|s| (e, s))) {
            Some((e, src)) => {
                dest.copy_from_slice(src);
                self.pos = e;
            }
            None => {
                // Never invent randomness: mark failure; the caller discards the output.
                self.overrun = true;
                dest.zeroize();
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for ExactBytesRng {}

/// Deterministic generator for this crate's unit tests and test-vector generation only.
#[cfg(test)]
pub(crate) struct TestRng(rand_chacha::ChaCha20Rng);

#[cfg(test)]
impl TestRng {
    pub(crate) fn new(seed: u8) -> Self {
        use rand_chacha::rand_core::SeedableRng;
        Self(rand_chacha::ChaCha20Rng::from_seed([seed; 32]))
    }
}

#[cfg(test)]
impl RandomSource for TestRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        use rand_chacha::rand_core::Rng;
        self.0.fill_bytes(buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn uniform_below_in_range_and_covers() {
        let mut r = TestRng::new(1);
        let mut seen = [false; 7];
        for _ in 0..1000 {
            let x = uniform_below(&mut r, 7).unwrap_or(99);
            assert!(x < 7);
            seen[x as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn permutation_is_permutation() {
        let mut r = TestRng::new(2);
        let mut p = permutation(&mut r, 16).unwrap_or_default();
        p.sort_unstable();
        assert_eq!(p, (0..16).collect::<Vec<_>>());
    }

    struct StuckRng;
    impl RandomSource for StuckRng {
        fn fill(&mut self, _buf: &mut [u8]) -> Result<()> {
            Err(Error::Rng)
        }
    }

    #[test]
    fn rng_failure_propagates() {
        // ST-028: stuck RNG ⇒ fail closed.
        assert_eq!(uniform_below(&mut StuckRng, 10), Err(Error::Rng));
    }

    #[test]
    fn exact_bytes_rng_detects_overrun() {
        let mut r = ExactBytesRng::new([1; 64]);
        let mut a = [0u8; 64];
        r.try_fill_bytes(&mut a).ok();
        assert!(r.check().is_ok());
        let mut b = [0u8; 1];
        r.try_fill_bytes(&mut b).ok();
        assert!(r.check().is_err());
        let r2 = ExactBytesRng::new([1; 64]);
        assert!(r2.check().is_err(), "under-consumption must be detected too");
    }

    #[test]
    fn os_fill_works() {
        let mut a = [0u8; 32];
        assert!(fill(&mut a).is_ok());
    }
}
