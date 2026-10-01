// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fetch-all published reply set (ADR-039; 07 §5.3, BE-063; 08 SA-19/SA-20, §3.8,
//! API-037/API-040; 04 §13.5).
//!
//! Every page holds exactly 64 entries of exactly 70,000 bytes; each entry is
//! `u32be entry_len ‖ body ‖ random fill`. Pages are built once per rebuild and
//! served byte-identically to every requester until the next rebuild; no access
//! state is recorded.
//!
//! **Generations (AUD-RM2-STO-06).** The set is a persistent sequence of
//! *generations*, one per fixed import slot. Each publication adds exactly
//! `per_slot` (K) entries: up to K pending real replies (oldest first), topped up
//! with fresh dummies; excess real replies wait for the next slot (bounded by
//! `max_pending`). Real and dummy entries are stored the same way, live exactly
//! the 30-day window and are never regenerated, so two rebuilds differ by exactly
//! K added and K expired entries whatever the real reply volume. Missed slots are
//! back-filled with dummy generations (the first publication back-fills the whole
//! window), so the entry count is a constant of the configuration and the page
//! count never depends on the reply count (AUD-RM2-STO-07). A persistent padding
//! pool fills the last page.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::error::{Result, StoreError};
use crate::types::{
    Day, ImportSlot, MAX_REPLY_CT, REPLY_BUCKETS, REPLY_ENTRY_LEN, REPLY_PAGE_ENTRIES,
    REPLY_PAGE_LEN, REPLY_WINDOW_DAYS, ReplyIndex, reply_bucket_of_len, reply_ct_len,
};

/// Default public distribution of dummy REPLY buckets (weights for k = 1..=16,
/// AUD-RM2-STO-19). Text-only replies (≤ 60 KiB body, 04 §13.5) are mostly short,
/// so small buckets dominate. Implementation decision: deployments should set
/// [`DeadDropConfig::dummy_bucket_weights`] to the long-run bucket distribution
/// of their real replies (a public, slowly changing profile constant); every
/// dummy's bucket is drawn independently from it and never from a real reply.
pub const DEFAULT_DUMMY_BUCKET_WEIGHTS: [u16; REPLY_BUCKETS as usize] =
    [400, 200, 120, 80, 50, 35, 25, 20, 15, 12, 10, 8, 7, 6, 6, 6];
/// Hard upper bound on the published page count (08 SA-19 EE figure: 128 pages ≈
/// 573 MB). With the double buffer during a rebuild, peak RAM is bounded by
/// 2 × 128 × 4.48 MB (AUD-RM2-STO-07).
pub const HARD_MAX_PAGES: u16 = 128;
/// Hard upper bound on the backlog of real replies awaiting publication.
pub const HARD_MAX_PENDING: u32 = 100_000;
/// Generation number reserved for the padding pool.
pub const PADDING_GENERATION: u64 = 0;

/// Produces dummy entry bodies. Production deployments supply bodies that are
/// structurally real REPLY objects sealed to a random key (08 §3.8 "dummy reply
/// ciphertexts under a random key"); [`RandomDummyReplies`] is for tests.
pub trait DummyReplies: Send + Sync {
    /// Return a dummy body for REPLY bucket `size_bucket` (1..=16). It must be
    /// exactly [`reply_ct_len`]`(size_bucket)` bytes; the store refuses any
    /// other length (AUD-RM2-STO-20).
    fn dummy_body(&self, size_bucket: u8) -> Result<Vec<u8>>;
}

/// CSPRNG bytes of the canonical length of the bucket. Size-indistinguishable
/// from real entries (API-037) but structurally distinguishable (no CoreHeader
/// magic): for tests and the in-memory store only. The PostgreSQL store requires
/// an explicit [`DummyReplies`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RandomDummyReplies;

impl DummyReplies for RandomDummyReplies {
    fn dummy_body(&self, size_bucket: u8) -> Result<Vec<u8>> {
        let len = reply_ct_len(size_bucket).ok_or(StoreError::InvalidInput("bucket"))?;
        let mut v = vec![0u8; len];
        fill_random(&mut v)?;
        Ok(v)
    }
}

/// Deployment configuration of the published set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeadDropConfig {
    /// Fixed import slots per day (ADR-038(1): 4 by default, 1 for HIGH/GOV).
    pub slots_per_day: u8,
    /// Entries added per slot (K).
    pub per_slot: u16,
    /// Largest backlog of real replies awaiting publication; further pushes are
    /// rejected (the relay keeps them and retries, like a full mailbox).
    pub max_pending: u32,
    /// Public distribution of dummy REPLY buckets: relative weight of bucket
    /// `k = index + 1` (AUD-RM2-STO-19). Each dummy's bucket is drawn
    /// independently from it with the CSPRNG.
    pub dummy_bucket_weights: [u16; REPLY_BUCKETS as usize],
}

impl DeadDropConfig {
    /// Validate the configuration against the hard memory bounds.
    pub fn validate(&self) -> Result<()> {
        if !(1..=24).contains(&self.slots_per_day) {
            return Err(StoreError::InvalidInput("slots_per_day"));
        }
        if self.per_slot == 0 {
            return Err(StoreError::InvalidInput("per_slot"));
        }
        if self.max_pending < u32::from(self.per_slot) || self.max_pending > HARD_MAX_PENDING {
            return Err(StoreError::InvalidInput("max_pending"));
        }
        if self.dummy_bucket_weights.iter().all(|w| *w == 0) {
            return Err(StoreError::InvalidInput("dummy bucket weights"));
        }
        let pages = self.pages_needed()?;
        if pages > usize::from(HARD_MAX_PAGES) {
            return Err(StoreError::Capacity);
        }
        Ok(())
    }

    /// Generations in the 30-day window.
    #[must_use]
    pub fn window_generations(&self) -> u64 {
        u64::from(REPLY_WINDOW_DAYS).saturating_mul(u64::from(self.slots_per_day))
    }

    /// Entries in the window (K × generations).
    pub fn window_entries(&self) -> Result<usize> {
        usize::try_from(self.window_generations())
            .ok()
            .and_then(|g| g.checked_mul(usize::from(self.per_slot)))
            .ok_or(StoreError::Capacity)
    }

    fn pages_needed(&self) -> Result<usize> {
        self.window_entries()?
            .div_ceil(REPLY_PAGE_ENTRIES)
            .max(1)
            .checked_next_power_of_two()
            .ok_or(StoreError::Capacity)
    }

    /// Page count (power of two; a constant of the configuration).
    pub fn page_count(&self) -> Result<u16> {
        u16::try_from(self.pages_needed()?).map_err(|_| StoreError::Capacity)
    }

    /// Entries in the whole set (`page_count × 64`).
    pub fn total_entries(&self) -> Result<usize> {
        self.pages_needed()?
            .checked_mul(REPLY_PAGE_ENTRIES)
            .ok_or(StoreError::Capacity)
    }

    /// Generation number of a slot (`day × slots_per_day + index`, ≥ 1 for day ≥ 1).
    pub fn generation(&self, slot: ImportSlot) -> Result<u64> {
        if slot.index >= self.slots_per_day || slot.day.0 == 0 {
            return Err(StoreError::InvalidInput("import slot"));
        }
        u64::from(slot.day.0)
            .checked_mul(u64::from(self.slots_per_day))
            .and_then(|g| g.checked_add(u64::from(slot.index)))
            .ok_or(StoreError::InvalidInput("import slot"))
    }

    /// Day of a generation.
    pub fn day_of(&self, generation: u64) -> Result<Day> {
        let d = generation
            .checked_div(u64::from(self.slots_per_day))
            .ok_or(StoreError::InvalidInput("slots_per_day"))?;
        u32::try_from(d)
            .map(Day)
            .map_err(|_| StoreError::InvalidInput("generation"))
    }

    /// Draw one dummy bucket from [`Self::dummy_bucket_weights`] (CSPRNG,
    /// independent of every real reply).
    pub fn draw_dummy_bucket(&self) -> Result<u8> {
        draw_bucket(&self.dummy_bucket_weights)
    }

    /// Lowest generation still in the window when `current` is the newest.
    #[must_use]
    pub fn window_start(&self, current: u64) -> u64 {
        current
            .saturating_add(1)
            .saturating_sub(self.window_generations())
            .max(1)
    }
}

/// Generations to create when publishing generation `current`, given the newest
/// generation already published (`None` before the first publication). Missed
/// slots inside the window are back-filled; nothing is created when `current`
/// was already published (idempotent per slot). Bounded by the window length.
pub(crate) fn generations_to_publish(
    cfg: &DeadDropConfig,
    last: Option<u64>,
    current: u64,
) -> Vec<u64> {
    let start = cfg.window_start(current);
    let start = match last {
        Some(l) if l >= current => return Vec::new(),
        Some(l) => start.max(l.saturating_add(1)),
        None => start,
    };
    (start..=current).collect()
}

/// Weighted draw of a bucket `k = index + 1` (uniform over the total weight).
pub(crate) fn draw_bucket(weights: &[u16; REPLY_BUCKETS as usize]) -> Result<u8> {
    let total: usize = weights.iter().map(|w| usize::from(*w)).sum();
    let mut x = uniform_below(total)?;
    for (i, w) in weights.iter().enumerate() {
        let w = usize::from(*w);
        if x < w {
            return u8::try_from(i)
                .ok()
                .and_then(|i| i.checked_add(1))
                .ok_or(StoreError::InvalidInput("bucket"));
        }
        x = x.saturating_sub(w);
    }
    Err(StoreError::InvalidInput("dummy bucket weights"))
}

/// A dummy row (AUD-RM2-STO-19/20): its bucket drawn from the configured public
/// distribution, never from a real reply; the stored `size_bucket` is derived
/// from the body length by [`reply_bucket_of_len`], the same function as for
/// real replies. A body of the wrong length is refused (fail closed).
pub(crate) fn dummy_row(dummies: &dyn DummyReplies, cfg: &DeadDropConfig) -> Result<(Vec<u8>, u8)> {
    let k = cfg.draw_dummy_bucket()?;
    let body = dummies.dummy_body(k)?;
    if body.len() > MAX_REPLY_CT || reply_bucket_of_len(body.len()) != Some(k) {
        return Err(StoreError::InvalidInput("dummy body size"));
    }
    Ok((body, k))
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
pub(crate) fn uniform_below(n: usize) -> Result<usize> {
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

/// Streaming page builder (AUD-RM2-STO-07): the page buffers are reserved up
/// front with fallible allocation for the configured page count, entries are
/// written straight into a uniformly random position, and nothing else is
/// materialised. More entries than positions is a typed `Capacity` error.
pub struct PageBuilder {
    pages: Vec<Vec<u8>>,
    positions: Vec<u32>,
    next: usize,
}

impl core::fmt::Debug for PageBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PageBuilder")
    }
}

impl PageBuilder {
    /// Reserve `page_count` pages (≤ [`HARD_MAX_PAGES`]).
    pub fn new(page_count: u16) -> Result<Self> {
        if page_count == 0 || page_count > HARD_MAX_PAGES {
            return Err(StoreError::Capacity);
        }
        let n = usize::from(page_count);
        let mut pages: Vec<Vec<u8>> = Vec::new();
        pages
            .try_reserve_exact(n)
            .map_err(|_| StoreError::Capacity)?;
        for _ in 0..n {
            let mut p: Vec<u8> = Vec::new();
            p.try_reserve_exact(REPLY_PAGE_LEN)
                .map_err(|_| StoreError::Capacity)?;
            p.resize(REPLY_PAGE_LEN, 0);
            pages.push(p);
        }
        let total = n
            .checked_mul(REPLY_PAGE_ENTRIES)
            .ok_or(StoreError::Capacity)?;
        let mut positions: Vec<u32> = Vec::new();
        positions
            .try_reserve_exact(total)
            .map_err(|_| StoreError::Capacity)?;
        for i in 0..total {
            positions.push(u32::try_from(i).map_err(|_| StoreError::Capacity)?);
        }
        shuffle(&mut positions)?;
        Ok(Self {
            pages,
            positions,
            next: 0,
        })
    }

    /// Entries written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.next
    }

    /// Whether nothing was written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next == 0
    }

    /// Positions left.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.positions.len().saturating_sub(self.next)
    }

    /// Write the next entry at its random position.
    pub fn push(&mut self, body: &[u8]) -> Result<()> {
        let pos = *self.positions.get(self.next).ok_or(StoreError::Capacity)?;
        let pos = usize::try_from(pos).map_err(|_| StoreError::Capacity)?;
        let (p, e) = (pos / REPLY_PAGE_ENTRIES, pos % REPLY_PAGE_ENTRIES);
        let page = self.pages.get_mut(p).ok_or(StoreError::Capacity)?;
        let start = e.checked_mul(REPLY_ENTRY_LEN).ok_or(StoreError::Capacity)?;
        let end = start
            .checked_add(REPLY_ENTRY_LEN)
            .ok_or(StoreError::Capacity)?;
        let slot = page.get_mut(start..end).ok_or(StoreError::Capacity)?;
        write_entry(slot, body)?;
        self.next = self.next.saturating_add(1);
        Ok(())
    }

    /// Fill any remaining positions with ephemeral dummies (only after a
    /// restart, early deletions or a concurrent purge; see SPEC-NOTES), sized
    /// from the configured distribution, and freeze the pages under a fresh
    /// random `set_version`.
    pub fn finish(
        mut self,
        dummies: &dyn DummyReplies,
        cfg: &DeadDropConfig,
    ) -> Result<PublishedSet> {
        while self.remaining() > 0 {
            let (body, _) = dummy_row(dummies, cfg)?;
            let body = Zeroizing::new(body);
            self.push(&body)?;
        }
        let page_count =
            u16::try_from(self.pages.len()).map_err(|_| StoreError::InvalidInput("pages"))?;
        let pages = self.pages.into_iter().map(Arc::<[u8]>::from).collect();
        let index = ReplyIndex {
            set_version: random_u64()?,
            page_count,
            page_size: REPLY_PAGE_ENTRIES as u16,
            window_days: REPLY_WINDOW_DAYS as u16,
        };
        Ok(PublishedSet { index, pages })
    }
}

/// The set served before the first rebuild after start: the configured page
/// count, all ephemeral dummies (source routes are busy until the store has
/// synchronised and rebuilt, BE-074).
pub fn empty(cfg: &DeadDropConfig, dummies: &dyn DummyReplies) -> Result<PublishedSet> {
    PageBuilder::new(cfg.page_count()?)?.finish(dummies, cfg)
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
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use proptest::prelude::*;

    fn cfg(spd: u8, k: u16) -> DeadDropConfig {
        DeadDropConfig {
            slots_per_day: spd,
            per_slot: k,
            max_pending: 1000,
            dummy_bucket_weights: DEFAULT_DUMMY_BUCKET_WEIGHTS,
        }
    }

    /// BE-063 / API-037: page shape is fixed by the configuration only.
    #[test]
    fn page_shape_from_config() {
        for (spd, k, pages) in [
            (1u8, 1u16, 1u16),
            (1, 2, 1),
            (1, 3, 2),
            (4, 16, 32),
            (4, 8, 16),
        ] {
            let c = cfg(spd, k);
            c.validate().unwrap();
            assert_eq!(c.page_count().unwrap(), pages, "spd={spd} k={k}");
            let set = empty(&c, &RandomDummyReplies).unwrap();
            assert_eq!(set.index().page_count, pages);
            assert_eq!(set.index().page_size, 64);
            assert_eq!(set.index().window_days, 30);
            for p in 0..pages {
                let page = set.page(p).unwrap();
                assert_eq!(page.len(), REPLY_PAGE_LEN);
                assert_eq!(parse_page(&page).unwrap().len(), 64);
            }
            assert_eq!(set.page(pages), Err(StoreError::NotFound));
        }
    }

    /// AUD-RM2-STO-07: configurations beyond the hard page bound are refused
    /// with a typed error; the builder never exceeds its reservation.
    #[test]
    fn capacity_bounds() {
        assert_eq!(cfg(24, 100).validate(), Err(StoreError::Capacity));
        assert!(cfg(4, 64).validate().is_ok()); // 7,680 entries -> 128 pages
        assert_eq!(cfg(4, 69).validate(), Err(StoreError::Capacity));
        assert!(cfg(0, 1).validate().is_err());
        assert!(cfg(1, 0).validate().is_err());
        assert!(
            DeadDropConfig {
                slots_per_day: 1,
                per_slot: 4,
                max_pending: HARD_MAX_PENDING + 1,
                dummy_bucket_weights: DEFAULT_DUMMY_BUCKET_WEIGHTS,
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            PageBuilder::new(HARD_MAX_PAGES + 1).unwrap_err(),
            StoreError::Capacity
        );
        let mut b = PageBuilder::new(1).unwrap();
        for _ in 0..64 {
            b.push(&[1, 2, 3]).unwrap();
        }
        assert_eq!(b.push(&[1]), Err(StoreError::Capacity));
    }

    /// Every pushed body appears exactly once; the rest is filled.
    #[test]
    fn builder_places_each_entry_once() {
        let mut b = PageBuilder::new(2).unwrap();
        let cts: Vec<Vec<u8>> = (0..100).map(|i| vec![(i % 251) as u8; 100 + i]).collect();
        for c in &cts {
            b.push(c).unwrap();
        }
        let set = b.finish(&RandomDummyReplies, &cfg(1, 1)).unwrap();
        let mut found = Vec::new();
        for p in 0..2 {
            for e in parse_page(&set.page(p).unwrap()).unwrap() {
                if let Some(i) = cts.iter().position(|c| c.as_slice() == e) {
                    found.push(i);
                }
            }
        }
        found.sort_unstable();
        assert_eq!(found, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn oversize_body_rejected() {
        let mut b = PageBuilder::new(1).unwrap();
        assert!(b.push(&vec![0u8; MAX_REPLY_CT + 1]).is_err());
    }

    #[test]
    fn set_version_changes_per_build() {
        let c = cfg(1, 1);
        let a = empty(&c, &RandomDummyReplies).unwrap().index().set_version;
        let b = empty(&c, &RandomDummyReplies).unwrap().index().set_version;
        assert_ne!(a, b);
    }

    /// Generation planning: bootstrap back-fills the window, a missed slot is
    /// back-filled, a repeated slot creates nothing.
    #[test]
    fn generation_plan() {
        let c = cfg(4, 2);
        let g = c
            .generation(ImportSlot {
                day: Day(100),
                index: 3,
            })
            .unwrap();
        assert_eq!(g, 403);
        assert!(
            c.generation(ImportSlot {
                day: Day(100),
                index: 4
            })
            .is_err()
        );
        assert_eq!(c.day_of(403).unwrap(), Day(100));
        let boot = generations_to_publish(&c, None, g);
        assert_eq!(boot.len(), 120);
        assert_eq!(*boot.first().unwrap(), 284);
        assert_eq!(generations_to_publish(&c, Some(401), g), vec![402, 403]);
        assert!(generations_to_publish(&c, Some(403), g).is_empty());
        assert_eq!(generations_to_publish(&c, Some(1), g).len(), 120);
    }

    /// AUD-RM2-STO-19: dummy buckets follow the configured distribution
    /// (χ² goodness of fit) and every dummy has the canonical length of its
    /// bucket; zero-weight buckets never occur; all-zero weights are refused.
    #[test]
    fn dummy_buckets_follow_distribution() {
        let mut c = cfg(1, 1);
        c.dummy_bucket_weights = [0; 16];
        assert!(c.validate().is_err());
        c.dummy_bucket_weights[0] = 1;
        c.dummy_bucket_weights[3] = 2;
        c.dummy_bucket_weights[15] = 1;
        let n = 4000usize;
        let mut hist = [0usize; 16];
        for _ in 0..n {
            let (body, k) = dummy_row(&RandomDummyReplies, &c).unwrap();
            assert_eq!(Some(body.len()), reply_ct_len(k));
            hist[usize::from(k) - 1] += 1;
        }
        let exp = [(0usize, 0.25f64), (3, 0.5), (15, 0.25)];
        assert_eq!(
            hist.iter().sum::<usize>(),
            exp.iter().map(|(i, _)| hist[*i]).sum::<usize>()
        );
        let chi2: f64 = exp
            .iter()
            .map(|(i, p)| {
                let e = p * n as f64;
                (hist[*i] as f64 - e).powi(2) / e
            })
            .sum();
        // 2 degrees of freedom, p = 1e-4.
        assert!(chi2 < 18.42, "chi2 = {chi2}, hist = {hist:?}");
    }

    /// A dummy source returning a non-canonical length is refused.
    #[test]
    fn wrong_length_dummy_refused() {
        struct Bad;
        impl DummyReplies for Bad {
            fn dummy_body(&self, _k: u8) -> Result<Vec<u8>> {
                Ok(vec![1; 5_440])
            }
        }
        assert!(dummy_row(&Bad, &cfg(1, 1)).is_err());
        assert!(empty(&cfg(1, 1), &Bad).is_err());
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

        /// The plan never exceeds the window and is strictly increasing.
        #[test]
        fn plan_bounded(spd in 1u8..=24, last in proptest::option::of(0u64..100_000), cur in 1u64..100_000) {
            let c = cfg(spd, 1);
            let v = generations_to_publish(&c, last, cur);
            prop_assert!(v.len() as u64 <= c.window_generations());
            prop_assert!(v.windows(2).all(|w| w[0] < w[1]));
            if let Some(l) = last { prop_assert!(v.iter().all(|g| *g > l)); }
        }
    }
}
