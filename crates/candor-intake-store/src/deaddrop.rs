// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fetch-all published reply set (ADR-039; 07 §5.3, BE-063; 08 SA-19/SA-20, §3.8,
//! API-037/API-040; 04 §13.5).
//!
//! Every page holds exactly 64 entries of exactly 70,000 bytes; each entry is
//! `u32be entry_len ‖ body ‖ random fill`. Real and dummy entries are placed in
//! uniformly random positions over all pages, and the page count is the next power
//! of two (≥ 1). Pages are built once per rebuild and served byte-identically to
//! every requester until the next rebuild; no access state is recorded.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::error::{Result, StoreError};
use crate::types::{
    MAX_REPLY_CT, REPLY_ENTRY_LEN, REPLY_PAGE_ENTRIES, REPLY_PAGE_LEN, REPLY_WINDOW_DAYS,
    ReplyIndex,
};

/// Fallback dummy body length when no real reply exists (approximately one
/// 4096-byte REPLY bucket plus header, MAC, STREAM tag and an X-Wing stanza).
pub const DEFAULT_DUMMY_BODY_LEN: usize = 5_440;
/// Largest page count we build (u16 page numbers; bounds memory).
pub const MAX_PAGE_COUNT: usize = 1 << 15;

/// Produces dummy entry bodies. Production deployments should supply bodies that
/// are structurally real REPLY objects sealed to a random key (08 §3.8 "dummy reply
/// ciphertexts under a random key"); [`RandomDummyReplies`] is the fallback.
pub trait DummyReplies: Send + Sync {
    /// Return a dummy body of about `len_hint` bytes (≤ `MAX_REPLY_CT`).
    fn dummy_body(&self, len_hint: usize) -> Result<Vec<u8>>;
}

/// CSPRNG bytes of exactly `len_hint` length. Size-indistinguishable from real
/// entries (API-037); structurally distinguishable (no CoreHeader magic), which
/// reveals only the number of real replies in the window (SPEC-NOTES residual).
#[derive(Debug, Default, Clone, Copy)]
pub struct RandomDummyReplies;

impl DummyReplies for RandomDummyReplies {
    fn dummy_body(&self, len_hint: usize) -> Result<Vec<u8>> {
        let mut v = vec![0u8; len_hint.min(MAX_REPLY_CT)];
        fill_random(&mut v)?;
        Ok(v)
    }
}

/// A built published set.
#[derive(Clone)]
pub struct PublishedSet {
    index: ReplyIndex,
    pages: Vec<Arc<[u8]>>,
}

impl core::fmt::Debug for PublishedSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublishedSet")
            .field("page_count", &self.index.page_count)
            .finish()
    }
}

impl PublishedSet {
    /// SA-19 index.
    #[must_use]
    pub fn index(&self) -> ReplyIndex {
        self.index
    }

    /// SA-20 page `n` (uniform `NotFound` when out of range).
    pub fn page(&self, n: u16) -> Result<Arc<[u8]>> {
        self.pages
            .get(usize::from(n))
            .cloned()
            .ok_or(StoreError::NotFound)
    }
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    // crate::rng::fill rejects an all-zero result for requests ≥ 16 bytes;
    // fill in chunks so that a huge buffer is one health-checked request each.
    for chunk in buf.chunks_mut(1 << 16) {
        crate::rng::fill(chunk).map_err(|_| StoreError::Rng)?;
    }
    Ok(())
}

fn random_u64() -> Result<u64> {
    let mut b = [0u8; 8];
    crate::rng::fill(&mut b).map_err(|_| StoreError::Rng)?;
    Ok(u64::from_le_bytes(b))
}

/// Uniform integer in `[0, n)` (rejection sampling, no modulo bias).
fn uniform_below(n: usize) -> Result<usize> {
    let n64 = u64::try_from(n).map_err(|_| StoreError::InvalidInput("range"))?;
    if n64 == 0 {
        return Err(StoreError::InvalidInput("empty range"));
    }
    let rem = u64::MAX
        .checked_rem(n64)
        .ok_or(StoreError::InvalidInput("range"))?;
    let zone = u64::MAX
        .checked_sub(rem)
        .ok_or(StoreError::InvalidInput("range"))?;
    loop {
        let x = random_u64()?;
        if x < zone {
            let v = x
                .checked_rem(n64)
                .ok_or(StoreError::InvalidInput("range"))?;
            return usize::try_from(v).map_err(|_| StoreError::InvalidInput("range"));
        }
    }
}

/// Fisher–Yates shuffle with the OS CSPRNG.
pub(crate) fn shuffle<T>(v: &mut [T]) -> Result<()> {
    let mut i = v.len();
    while i > 1 {
        let j = uniform_below(i)?;
        i = i.saturating_sub(1);
        v.swap(i, j);
    }
    Ok(())
}

/// Write one entry (`u32be len ‖ body ‖ random`) into `out` (exactly 70,000 B).
fn write_entry(out: &mut [u8], body: &[u8]) -> Result<()> {
    if out.len() != REPLY_ENTRY_LEN || body.len() > MAX_REPLY_CT {
        return Err(StoreError::InvalidInput("entry size"));
    }
    let len = u32::try_from(body.len()).map_err(|_| StoreError::InvalidInput("entry size"))?;
    let (l, rest) = out.split_at_mut(4);
    l.copy_from_slice(&len.to_be_bytes());
    let (b, pad) = rest.split_at_mut(body.len());
    b.copy_from_slice(body);
    fill_random(pad)
}

/// Whether a reply available on `available_day` is in the published window on
/// `today` (`today - available_day < 30`).
#[must_use]
pub fn in_window(available_day: crate::types::Day, today: crate::types::Day) -> bool {
    today.0.saturating_sub(available_day.0) < REPLY_WINDOW_DAYS
}

/// Build the published set from the reply ciphertexts in the window.
pub fn build(reply_cts: &[Vec<u8>], dummies: &dyn DummyReplies) -> Result<PublishedSet> {
    let n = reply_cts.len();
    let pages_needed = n.div_ceil(REPLY_PAGE_ENTRIES).max(1);
    let page_count = pages_needed
        .checked_next_power_of_two()
        .filter(|c| *c <= MAX_PAGE_COUNT)
        .ok_or(StoreError::InvalidInput("published set too large"))?;
    let total = page_count
        .checked_mul(REPLY_PAGE_ENTRIES)
        .ok_or(StoreError::InvalidInput("published set too large"))?;

    // Positions: Some(i) = real reply i, None = dummy; randomly permuted.
    let mut slots: Vec<Option<usize>> = (0..total).map(|i| (i < n).then_some(i)).collect();
    shuffle(&mut slots)?;

    let mut pages = Vec::with_capacity(page_count);
    for page_slots in slots.chunks(REPLY_PAGE_ENTRIES) {
        let mut page = vec![0u8; REPLY_PAGE_LEN];
        for (entry, slot) in page.chunks_mut(REPLY_ENTRY_LEN).zip(page_slots) {
            match slot {
                Some(i) => {
                    let body = reply_cts
                        .get(*i)
                        .ok_or(StoreError::Integrity("reply index"))?;
                    write_entry(entry, body)?;
                }
                None => {
                    let hint = if n == 0 {
                        DEFAULT_DUMMY_BODY_LEN
                    } else {
                        reply_cts
                            .get(uniform_below(n)?)
                            .map_or(DEFAULT_DUMMY_BODY_LEN, Vec::len)
                    };
                    let body = Zeroizing::new(dummies.dummy_body(hint)?);
                    write_entry(entry, &body)?;
                }
            }
        }
        pages.push(Arc::<[u8]>::from(page));
    }
    let index = ReplyIndex {
        set_version: random_u64()?,
        page_count: u16::try_from(page_count).map_err(|_| StoreError::InvalidInput("pages"))?,
        page_size: REPLY_PAGE_ENTRIES as u16,
        window_days: REPLY_WINDOW_DAYS as u16,
    };
    Ok(PublishedSet { index, pages })
}

/// An empty set (one dummy page), used before the first rebuild.
pub fn empty(dummies: &dyn DummyReplies) -> Result<PublishedSet> {
    build(&[], dummies)
}

/// Parse a page into its 64 entry bodies (test and client helper).
pub fn parse_page(page: &[u8]) -> Result<Vec<&[u8]>> {
    if page.len() != REPLY_PAGE_LEN {
        return Err(StoreError::InvalidInput("page size"));
    }
    page.chunks(REPLY_ENTRY_LEN)
        .map(|e| {
            let (l, rest) = e
                .split_at_checked(4)
                .ok_or(StoreError::InvalidInput("entry"))?;
            let len = u32::from_be_bytes(
                l.try_into()
                    .map_err(|_| StoreError::InvalidInput("entry"))?,
            );
            let len = usize::try_from(len).map_err(|_| StoreError::InvalidInput("entry"))?;
            rest.get(..len)
                .ok_or(StoreError::InvalidInput("entry length"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use proptest::prelude::*;

    /// BE-063 / API-037: page shape for 0, 1, 64, 65, 200 replies.
    #[test]
    fn page_shape() {
        for (n, expect_pages) in [(0usize, 1u16), (1, 1), (64, 1), (65, 2), (129, 4), (200, 4)] {
            let cts: Vec<Vec<u8>> = (0..n).map(|i| vec![(i % 251) as u8; 100 + i]).collect();
            let set = build(&cts, &RandomDummyReplies).unwrap();
            assert_eq!(set.index().page_count, expect_pages, "n={n}");
            assert_eq!(set.index().page_size, 64);
            assert_eq!(set.index().window_days, 30);
            let mut found = Vec::new();
            for p in 0..set.index().page_count {
                let page = set.page(p).unwrap();
                assert_eq!(page.len(), REPLY_PAGE_LEN);
                let entries = parse_page(&page).unwrap();
                assert_eq!(entries.len(), 64);
                for e in entries {
                    if let Some(i) = cts.iter().position(|c| c.as_slice() == e) {
                        found.push(i);
                    }
                }
            }
            found.sort_unstable();
            assert_eq!(
                found,
                (0..n).collect::<Vec<_>>(),
                "every real reply exactly once"
            );
            assert_eq!(set.page(set.index().page_count), Err(StoreError::NotFound));
        }
    }

    #[test]
    fn oversize_body_rejected() {
        let cts = vec![vec![0u8; MAX_REPLY_CT + 1]];
        assert!(build(&cts, &RandomDummyReplies).is_err());
    }

    #[test]
    fn set_version_changes_per_build() {
        let a = build(&[], &RandomDummyReplies).unwrap().index().set_version;
        let b = build(&[], &RandomDummyReplies).unwrap().index().set_version;
        assert_ne!(a, b);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        /// parse_page never panics on arbitrary input.
        #[test]
        fn parse_page_total(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_page(&data);
        }

        #[test]
        fn shuffle_is_permutation(mut v in proptest::collection::vec(any::<u32>(), 0..200)) {
            let mut sorted = v.clone();
            sorted.sort_unstable();
            shuffle(&mut v).unwrap();
            v.sort_unstable();
            prop_assert_eq!(v, sorted);
        }
    }
}
