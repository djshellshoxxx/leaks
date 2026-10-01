// SPDX-License-Identifier: AGPL-3.0-or-later
//! SOURCE-SENSITIVE counters and the 24 §TEL release regime
//! (ADR-016, ADR-046(5), LOG-011, LOG-025, TEL-010/011/015/016/020).
//!
//! * Counters exist only as in-memory per-channel, per-calendar-month
//!   values (current and previous month only); they are never events.
//! * A month is released once, after it closes (tumbling, frozen); the raw
//!   values are dropped when taken for release.
//! * Release applies k = 10 (configurable upward only), primary and
//!   complementary suppression with marginals withheld where needed, the
//!   per-channel rule (≥ 3 cases and declared population ≥ 50, otherwise
//!   folded into a channel group of ≥ 2 channels), and an exact rational
//!   linear-programming disclosure audit (AUD-RM1-LOG-05) across every
//!   table released for the same period. The attacker model includes the
//!   published cells and margins **and** the knowledge that every
//!   primary-suppressed cell is < k and every complementary cell is ≥ k;
//!   every protected quantity must keep a feasible range at least k − 1
//!   wide (a primary cell stays anywhere in `[0, k-1]`).
//! * Release history (facts, attacker priors, protections, magnitude
//!   populations) is persisted through a caller-provided
//!   [`ReleaseHistory`], so the differencing defence survives restarts
//!   (AUD-RM1-LOG-06); a history that cannot be read or written fails the
//!   release closed.
//! * Magnitude statistics only through the registry, only when every
//!   contributing cell is ≥ k; percentiles only for p ∈ [10, 90]; a
//!   population differing from an earlier one of the same period by fewer
//!   than k members is refused (mean/median differencing).

use std::collections::{BTreeMap, BTreeSet};

use crate::ids::{ChannelId, MonthStamp};

/// The 24 §TEL minimum cell size (registry `metrics_k_threshold`).
pub const K_MIN: u64 = 10;
/// Minimum cases for a channel to appear as its own dimension (TEL-016).
pub const CHANNEL_MIN_CASES: u64 = 3;
/// Minimum declared population for a channel dimension (TEL-016).
pub const CHANNEL_MIN_POPULATION: u64 = 50;
/// M3 rounding base.
pub const M3_ROUNDING: u64 = 5;

/// Minimum cell size; can only be raised (TEL-011).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KThreshold(u64);

impl KThreshold {
    /// Default k = 10.
    pub const DEFAULT: Self = Self(K_MIN);
    /// `None` if `k < 10`.
    pub fn new(k: u64) -> Option<Self> {
        (k >= K_MIN).then_some(Self(k))
    }
    /// Value.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for KThreshold {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The intake counters (24 §9.4: exactly these three).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum IntakeCounter {
    /// Real submissions (never chaff, ADR-047(3)).
    Submissions,
    /// Accounts created.
    AccountsCreated,
    /// Account deletions.
    AccountDeletions,
}

impl IntakeCounter {
    /// All counters in column order.
    pub const ALL: [Self; 3] = [
        Self::Submissions,
        Self::AccountsCreated,
        Self::AccountDeletions,
    ];
    /// Name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Submissions => "submissions",
            Self::AccountsCreated => "accounts_created",
            Self::AccountDeletions => "account_deletions",
        }
    }
    const fn ordinal(self) -> u16 {
        match self {
            Self::Submissions => 0,
            Self::AccountsCreated => 1,
            Self::AccountDeletions => 2,
        }
    }
}

/// Counter errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CounterError {
    /// Increment for a month other than the current or next one.
    StaleMonth,
    /// The requested month is not the closed previous month.
    NotClosed,
}

type MonthCounts = BTreeMap<(ChannelId, IntakeCounter), u64>;

/// In-memory monthly aggregation (C-08 `counter_month`). No `Debug` of values.
pub struct CounterAggregator {
    current: MonthStamp,
    cur: MonthCounts,
    prev: Option<(MonthStamp, MonthCounts)>,
}

impl core::fmt::Debug for CounterAggregator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CounterAggregator")
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl CounterAggregator {
    /// Start aggregating at `month`.
    pub fn new(month: MonthStamp) -> Self {
        Self {
            current: month,
            cur: BTreeMap::new(),
            prev: None,
        }
    }

    fn roll_to(&mut self, month: MonthStamp) -> Result<(), CounterError> {
        if month == self.current {
            return Ok(());
        }
        if month == self.current.next() {
            let old = core::mem::take(&mut self.cur);
            // Only current and previous month are held (09): an unreleased
            // older month is discarded.
            self.prev = Some((self.current, old));
            self.current = month;
            return Ok(());
        }
        Err(CounterError::StaleMonth)
    }

    /// Increment a counter for a real commit in `month` (never for chaff).
    pub fn increment(
        &mut self,
        month: MonthStamp,
        channel: ChannelId,
        counter: IntakeCounter,
    ) -> Result<(), CounterError> {
        self.roll_to(month)?;
        let c = self.cur.entry((channel, counter)).or_insert(0);
        *c = c.saturating_add(1);
        Ok(())
    }

    /// Advance the clock (month close) without an increment.
    pub fn advance(&mut self, month: MonthStamp) -> Result<(), CounterError> {
        self.roll_to(month)
    }

    /// Take the closed previous month for release; raw values leave memory.
    pub fn take_closed(&mut self, month: MonthStamp) -> Result<ClosedMonth, CounterError> {
        match self.prev.take() {
            Some((m, counts)) if m == month => Ok(ClosedMonth { month: m, counts }),
            other => {
                self.prev = other;
                Err(CounterError::NotClosed)
            }
        }
    }
}

/// A closed month's raw counters. Not printable; consumed by release.
pub struct ClosedMonth {
    month: MonthStamp,
    counts: MonthCounts,
}

impl core::fmt::Debug for ClosedMonth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClosedMonth")
            .field("month", &self.month)
            .finish_non_exhaustive()
    }
}

impl ClosedMonth {
    /// Build from raw counts (RL-09 import path).
    pub fn from_counts(
        month: MonthStamp,
        counts: impl IntoIterator<Item = ((ChannelId, IntakeCounter), u64)>,
    ) -> Self {
        Self {
            month,
            counts: counts.into_iter().collect(),
        }
    }
    /// Month.
    pub fn month(&self) -> MonthStamp {
        self.month
    }
    fn get(&self, c: ChannelId, k: IntakeCounter) -> u64 {
        self.counts.get(&(c, k)).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------
// Tables and suppression
// ---------------------------------------------------------------------

/// Identifier of an underlying micro-cell (entity bytes, attribute).
/// Two tables of the same period referring to the same micro-cell must use
/// the same key so the differencing audit sees the overlap.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MicroKey(pub [u8; 16], pub u16);

/// A table cell: its value and the micro-cells it sums.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TableCell {
    /// True value (sum of the micro-cells).
    pub value: u64,
    /// Micro-cells summed.
    pub members: Vec<MicroKey>,
}

/// A two-dimensional table (row-major) with implied row/column/grand totals.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Table {
    /// Rows.
    pub rows: usize,
    /// Columns.
    pub cols: usize,
    /// Cells, row-major, `rows * cols` long.
    pub cells: Vec<TableCell>,
    /// Values of individual micro-cells (needed for the audit).
    pub micro: BTreeMap<MicroKey, u64>,
    /// Extra functionals that must not become derivable (e.g., micro-cells
    /// of channels folded under the per-channel rule).
    pub protected: Vec<Vec<MicroKey>>,
}

/// A published figure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Published {
    /// Value.
    Value(u64),
    /// Primary or complementary suppressed cell.
    Suppressed,
    /// Marginal withheld to prevent recovery.
    Withheld,
}

impl Published {
    /// Display string for audience M2/M3. Every hidden figure renders as
    /// `"suppressed"`: never a range such as "0–9", which would be false for
    /// complementary cells and would tell primary and complementary cells
    /// apart (AUD-RM1-LOG-05).
    pub fn display(&self) -> String {
        match self {
            Self::Value(v) => v.to_string(),
            Self::Suppressed | Self::Withheld => "suppressed".to_owned(),
        }
    }
}

/// A released table.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Released {
    /// Rows.
    pub rows: usize,
    /// Columns.
    pub cols: usize,
    /// Cells, row-major.
    pub cells: Vec<Published>,
    /// Row totals.
    pub row_totals: Vec<Published>,
    /// Column totals.
    pub col_totals: Vec<Published>,
    /// Grand total.
    pub grand_total: Published,
}

/// Table shape errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReleaseError {
    /// `cells.len() != rows * cols` or empty table.
    Shape,
    /// Period not closed yet (no intra-period / month-to-date figures).
    PeriodNotClosed,
    /// This report was already released for the period (frozen periods).
    AlreadyReleased,
    /// Channel group configuration invalid (< 2 channels, unknown channel).
    BadGroups,
    /// Even full suppression would make a protected quantity derivable
    /// together with earlier releases of the period (fail closed).
    DisclosureRisk,
    /// The release history could not be read, decoded or written (fail
    /// closed: nothing is released).
    History,
    /// Statistic parameters out of range (e.g. percentile outside 10..=90).
    BadStatistic,
}

struct Lines {
    rows: Vec<Vec<usize>>,
    cols: Vec<Vec<usize>>,
}

fn lines(rows: usize, cols: usize) -> Option<Lines> {
    let mut r = Vec::with_capacity(rows);
    for i in 0..rows {
        let mut v = Vec::with_capacity(cols);
        for j in 0..cols {
            v.push(i.checked_mul(cols)?.checked_add(j)?);
        }
        r.push(v);
    }
    let mut c = Vec::with_capacity(cols);
    for j in 0..cols {
        let mut v = Vec::with_capacity(rows);
        for i in 0..rows {
            v.push(i.checked_mul(cols)?.checked_add(j)?);
        }
        c.push(v);
    }
    Some(Lines { rows: r, cols: c })
}

/// Suppression state for a table.
#[derive(Clone, Debug)]
struct Plan {
    sup: Vec<bool>,
    row_pub: Vec<bool>,
    col_pub: Vec<bool>,
    grand_pub: bool,
}

/// Greedy primary + complementary suppression (24 §9.3), starting from
/// `sup` (primary cells and any extra complementary choices).
fn greedy(values: &[u64], ln: &Lines, k: u64, mut sup: Vec<bool>) -> Plan {
    let mut row_pub = vec![true; ln.rows.len()];
    let mut col_pub = vec![true; ln.cols.len()];
    loop {
        let mut changed = false;
        for (line, published) in ln
            .rows
            .iter()
            .zip(row_pub.iter_mut())
            .chain(ln.cols.iter().zip(col_pub.iter_mut()))
        {
            if !*published {
                continue;
            }
            let mut n_sup: usize = 0;
            let mut sum_sup: u64 = 0;
            for &i in line {
                if sup.get(i).copied().unwrap_or(false) {
                    n_sup = n_sup.saturating_add(1);
                    sum_sup = sum_sup.saturating_add(values.get(i).copied().unwrap_or(0));
                }
            }
            // A published marginal reveals the sum of the suppressed cells of
            // its line: it must cover ≥ 2 cells and sum to ≥ k.
            if n_sup == 0 || (n_sup >= 2 && sum_sup >= k) {
                continue;
            }
            let next = line
                .iter()
                .copied()
                .filter(|&i| !sup.get(i).copied().unwrap_or(true))
                .min_by_key(|&i| (values.get(i).copied().unwrap_or(u64::MAX), i));
            match next {
                Some(i) => {
                    if let Some(s) = sup.get_mut(i) {
                        *s = true;
                    }
                }
                None => *published = false,
            }
            changed = true;
        }
        if !changed {
            break;
        }
    }
    Plan {
        sup,
        row_pub,
        col_pub,
        grand_pub: true,
    }
}

// ---------------------------------------------------------------------
// Disclosure audit (exact rational linear programming)
// ---------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Q {
    n: i128,
    d: i128,
}

fn gcd(mut a: i128, mut b: i128) -> i128 {
    a = a.checked_abs().unwrap_or(0);
    b = b.checked_abs().unwrap_or(0);
    while b != 0 {
        let t = a.checked_rem(b).unwrap_or(0);
        a = b;
        b = t;
    }
    a
}

impl Q {
    const ZERO: Self = Self { n: 0, d: 1 };
    const ONE: Self = Self { n: 1, d: 1 };
    fn int(n: i128) -> Self {
        Self { n, d: 1 }
    }
    fn norm(n: i128, d: i128) -> Option<Self> {
        if d == 0 {
            return None;
        }
        let g = gcd(n, d).max(1);
        let (mut n, mut d) = (n.checked_div(g)?, d.checked_div(g)?);
        if d < 0 {
            n = n.checked_neg()?;
            d = d.checked_neg()?;
        }
        Some(Self { n, d })
    }
    fn is_zero(self) -> bool {
        self.n == 0
    }
    fn is_neg(self) -> bool {
        self.n < 0
    }
    fn is_pos(self) -> bool {
        self.n > 0
    }
    fn add(self, o: Self) -> Option<Self> {
        Self::norm(
            self.n
                .checked_mul(o.d)?
                .checked_add(o.n.checked_mul(self.d)?)?,
            self.d.checked_mul(o.d)?,
        )
    }
    fn sub(self, o: Self) -> Option<Self> {
        Self::norm(
            self.n
                .checked_mul(o.d)?
                .checked_sub(o.n.checked_mul(self.d)?)?,
            self.d.checked_mul(o.d)?,
        )
    }
    fn mul(self, o: Self) -> Option<Self> {
        Self::norm(self.n.checked_mul(o.n)?, self.d.checked_mul(o.d)?)
    }
    fn div(self, o: Self) -> Option<Self> {
        Self::norm(self.n.checked_mul(o.d)?, self.d.checked_mul(o.n)?)
    }
    fn neg(self) -> Option<Self> {
        Some(Self {
            n: self.n.checked_neg()?,
            d: self.d,
        })
    }
    /// `self < o`.
    fn lt(self, o: Self) -> Option<bool> {
        Some(self.sub(o)?.is_neg())
    }
}

/// A published linear fact: sum of micro-cells = value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fact {
    /// Micro-cells summed.
    pub members: BTreeSet<MicroKey>,
    /// Published value.
    pub value: u64,
}

/// Attacker prior knowledge: `lo ≤ Σ members ≤ hi` (`hi = None`: no upper
/// bound). A primary-suppressed cell gives `[0, k-1]`, a complementary
/// cell `[k, ∞)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Prior {
    /// Micro-cells summed.
    pub members: BTreeSet<MicroKey>,
    /// Lower bound.
    pub lo: u64,
    /// Upper bound.
    pub hi: Option<u64>,
}

/// Dense simplex tableau in standard form `A x = b, x ≥ 0`, rows in
/// canonical form for `basis`. Exact rationals; any overflow yields `None`
/// (callers fail closed).
#[derive(Clone)]
struct Tableau {
    rows: Vec<Vec<Q>>,
    rhs: Vec<Q>,
    basis: Vec<usize>,
    ncols: usize,
}

const MAX_PIVOTS: usize = 20_000;

impl Tableau {
    fn pivot(&mut self, r: usize, c: usize) -> Option<()> {
        let pv = *self.rows.get(r)?.get(c)?;
        let prow: Vec<Q> = self.rows.get(r)?.iter().map(|q| q.div(pv)).collect::<Option<_>>()?;
        let prhs = self.rhs.get(r)?.div(pv)?;
        for i in 0..self.rows.len() {
            if i == r {
                continue;
            }
            let f = *self.rows.get(i)?.get(c)?;
            if f.is_zero() {
                continue;
            }
            let row = self.rows.get_mut(i)?;
            for (x, y) in row.iter_mut().zip(prow.iter()) {
                *x = x.sub(f.mul(*y)?)?;
            }
            let rr = self.rhs.get_mut(i)?;
            *rr = rr.sub(f.mul(prhs)?)?;
        }
        *self.rows.get_mut(r)? = prow;
        *self.rhs.get_mut(r)? = prhs;
        *self.basis.get_mut(r)? = c;
        Some(())
    }

    /// Minimise `cost · x` over columns `< allowed` (Bland's rule). Returns
    /// `Some(None)` if unbounded below.
    fn minimise(&mut self, cost: &[Q], allowed: usize) -> Option<Option<Q>> {
        for _ in 0..MAX_PIVOTS {
            // Reduced costs r_j = c_j − Σ_i c_{B_i} T_ij.
            let mut entering = None;
            for j in 0..allowed {
                if self.basis.contains(&j) {
                    continue;
                }
                let mut r = cost.get(j).copied().unwrap_or(Q::ZERO);
                for (i, &b) in self.basis.iter().enumerate() {
                    let cb = cost.get(b).copied().unwrap_or(Q::ZERO);
                    if cb.is_zero() {
                        continue;
                    }
                    r = r.sub(cb.mul(*self.rows.get(i)?.get(j)?)?)?;
                }
                if r.is_neg() {
                    entering = Some(j);
                    break;
                }
            }
            let Some(c) = entering else {
                let mut v = Q::ZERO;
                for (i, &b) in self.basis.iter().enumerate() {
                    let cb = cost.get(b).copied().unwrap_or(Q::ZERO);
                    v = v.add(cb.mul(*self.rhs.get(i)?)?)?;
                }
                return Some(Some(v));
            };
            let mut best: Option<(usize, Q)> = None;
            for i in 0..self.rows.len() {
                let a = *self.rows.get(i)?.get(c)?;
                if !a.is_pos() {
                    continue;
                }
                let ratio = self.rhs.get(i)?.div(a)?;
                best = match best {
                    None => Some((i, ratio)),
                    Some((bi, br)) => {
                        let better = ratio.lt(br)?
                            || (ratio == br && self.basis.get(i)? < self.basis.get(bi)?);
                        Some(if better { (i, ratio) } else { (bi, br) })
                    }
                };
            }
            let (r, _) = match best {
                Some(b) => b,
                None => return Some(None),
            };
            self.pivot(r, c)?;
        }
        None
    }
}

/// Feasible region of the attacker's knowledge, ready for range queries.
struct Region {
    t: Tableau,
    nstruct: usize,
    index: BTreeMap<MicroKey, usize>,
}

impl Region {
    /// Phase 1 of the two-phase simplex. `None` on overflow or if the
    /// system is infeasible (cannot happen for true data; fail closed).
    fn new(facts: &[Fact], priors: &[Prior], keys: &BTreeSet<MicroKey>) -> Option<Self> {
        let index: BTreeMap<MicroKey, usize> =
            keys.iter().copied().enumerate().map(|(i, k)| (k, i)).collect();
        let n = index.len();
        // Constraint list: (members, kind, rhs) with kind 0 '=', 1 '≤', 2 '≥'.
        let mut cons: Vec<(Vec<usize>, u8, u64)> = Vec::new();
        let idx = |m: &BTreeSet<MicroKey>| -> Vec<usize> {
            m.iter().filter_map(|k| index.get(k).copied()).collect()
        };
        for f in facts {
            cons.push((idx(&f.members), 0, f.value));
        }
        for p in priors {
            if p.lo > 0 {
                cons.push((idx(&p.members), 2, p.lo));
            }
            if let Some(h) = p.hi {
                cons.push((idx(&p.members), 1, h));
            }
        }
        let m = cons.len();
        let nslack = cons.iter().filter(|c| c.1 != 0).count();
        let ncols = n.checked_add(nslack)?.checked_add(m)?;
        let mut rows = Vec::with_capacity(m);
        let mut rhs = Vec::with_capacity(m);
        let mut basis = Vec::with_capacity(m);
        let mut slack = n;
        for (i, (members, kind, v)) in cons.iter().enumerate() {
            let mut row = vec![Q::ZERO; ncols];
            for &j in members {
                *row.get_mut(j)? = Q::ONE;
            }
            match kind {
                1 => {
                    *row.get_mut(slack)? = Q::ONE;
                    slack = slack.checked_add(1)?;
                }
                2 => {
                    *row.get_mut(slack)? = Q::int(-1);
                    slack = slack.checked_add(1)?;
                }
                _ => {}
            }
            let art = n.checked_add(nslack)?.checked_add(i)?;
            *row.get_mut(art)? = Q::ONE;
            rows.push(row);
            rhs.push(Q::int(i128::from(*v)));
            basis.push(art);
        }
        let mut t = Tableau {
            rows,
            rhs,
            basis,
            ncols,
        };
        let art0 = n.checked_add(nslack)?;
        let mut cost = vec![Q::ZERO; ncols];
        for c in cost.iter_mut().skip(art0) {
            *c = Q::ONE;
        }
        let v = t.minimise(&cost, ncols)??;
        if !v.is_zero() {
            return None;
        }
        // Drive artificial variables out of the basis; drop redundant rows.
        let mut i = 0;
        while i < t.rows.len() {
            if *t.basis.get(i)? >= art0 {
                let col = (0..art0).find(|&j| t.rows.get(i).and_then(|r| r.get(j)).is_some_and(|q| !q.is_zero()));
                match col {
                    Some(j) => t.pivot(i, j)?,
                    None => {
                        t.rows.remove(i);
                        t.rhs.remove(i);
                        t.basis.remove(i);
                        continue;
                    }
                }
            }
            i = i.checked_add(1)?;
        }
        for r in &mut t.rows {
            r.truncate(art0);
        }
        t.ncols = art0;
        Some(Self {
            t,
            nstruct: n,
            index,
        })
    }

    /// `(min, max)` of `Σ members`; `max = None` means unbounded.
    fn range(&self, members: &BTreeSet<MicroKey>) -> Option<(Q, Option<Q>)> {
        let mut c = vec![Q::ZERO; self.t.ncols];
        for k in members {
            let j = *self.index.get(k)?;
            if j < self.nstruct {
                *c.get_mut(j)? = Q::ONE;
            }
        }
        let lo = self.t.clone().minimise(&c, self.t.ncols)??;
        let neg: Vec<Q> = c.iter().map(|q| q.neg()).collect::<Option<_>>()?;
        let hi = match self.t.clone().minimise(&neg, self.t.ncols)? {
            Some(v) => Some(v.neg()?),
            None => None,
        };
        Some((lo, hi))
    }
}

/// Exact disclosure audit: `true` iff every protected functional keeps a
/// feasible range at least `width` wide given the published `facts` and
/// the attacker's `priors`. Arithmetic overflow ⇒ `false` (fail closed).
pub fn audit(facts: &[Fact], priors: &[Prior], protected: &[BTreeSet<MicroKey>], width: u64) -> bool {
    first_failure(facts, priors, protected, width) == Some(None)
}

/// `Some(None)` if safe, `Some(Some(i))` with the index of the first
/// unprotected functional, `None` on overflow.
fn first_failure(
    facts: &[Fact],
    priors: &[Prior],
    protected: &[BTreeSet<MicroKey>],
    width: u64,
) -> Option<Option<usize>> {
    let mut keys: BTreeSet<MicroKey> = BTreeSet::new();
    for f in facts {
        keys.extend(f.members.iter().copied());
    }
    for p in priors {
        keys.extend(p.members.iter().copied());
    }
    for p in protected {
        keys.extend(p.iter().copied());
    }
    let region = Region::new(facts, priors, &keys)?;
    let w = Q::int(i128::from(width));
    for (i, p) in protected.iter().enumerate() {
        if p.is_empty() {
            continue;
        }
        let (lo, hi) = region.range(p)?;
        if let Some(hi) = hi
            && hi.sub(lo)?.lt(w)?
        {
            return Some(Some(i));
        }
    }
    Some(None)
}

fn facts_of(table: &Table, plan: &Plan, ln: &Lines) -> Vec<Fact> {
    let set = |idx: &[usize]| -> BTreeSet<MicroKey> {
        idx.iter()
            .filter_map(|&i| table.cells.get(i))
            .flat_map(|c| c.members.iter().copied())
            .collect()
    };
    let total = |idx: &[usize]| -> u64 {
        idx.iter()
            .filter_map(|&i| table.cells.get(i))
            .map(|c| c.value)
            .fold(0, u64::saturating_add)
    };
    let mut out = Vec::new();
    for (i, c) in table.cells.iter().enumerate() {
        if !plan.sup.get(i).copied().unwrap_or(true) {
            out.push(Fact {
                members: c.members.iter().copied().collect(),
                value: c.value,
            });
        }
    }
    for (line, p) in ln
        .rows
        .iter()
        .zip(&plan.row_pub)
        .chain(ln.cols.iter().zip(&plan.col_pub))
    {
        if *p {
            out.push(Fact {
                members: set(line),
                value: total(line),
            });
        }
    }
    if plan.grand_pub {
        let all: Vec<usize> = (0..table.cells.len()).collect();
        out.push(Fact {
            members: set(&all),
            value: total(&all),
        });
    }
    out
}

/// Attacker priors from the suppression pattern (worst case: the attacker
/// knows which suppressed cells are primary and which complementary).
fn priors_of(table: &Table, plan: &Plan, k: u64) -> Vec<Prior> {
    let mut out = Vec::new();
    for (i, c) in table.cells.iter().enumerate() {
        if !plan.sup.get(i).copied().unwrap_or(false) {
            continue;
        }
        let members: BTreeSet<MicroKey> = c.members.iter().copied().collect();
        out.push(if c.value < k {
            Prior {
                members,
                lo: 0,
                hi: Some(k.saturating_sub(1)),
            }
        } else {
            Prior {
                members,
                lo: k,
                hi: None,
            }
        });
    }
    out
}

fn protected_of(table: &Table, plan: &Plan, ln: &Lines, k: u64) -> Vec<BTreeSet<MicroKey>> {
    let mut out: Vec<BTreeSet<MicroKey>> = Vec::new();
    // Every primary-suppressed cell (complementary cells are ≥ k).
    for (i, c) in table.cells.iter().enumerate() {
        if plan.sup.get(i).copied().unwrap_or(false) && c.value < k {
            out.push(c.members.iter().copied().collect());
        }
    }
    // Every micro-cell below k (a single contribution of a small cell).
    for (key, v) in &table.micro {
        if *v < k {
            out.push(BTreeSet::from([*key]));
        }
    }
    // Sums of suppressed cells along a line when that sum is below k.
    for line in ln.rows.iter().chain(ln.cols.iter()) {
        let sup: Vec<&TableCell> = line
            .iter()
            .filter(|&&i| plan.sup.get(i).copied().unwrap_or(false))
            .filter_map(|&i| table.cells.get(i))
            .collect();
        let sum = sup.iter().map(|c| c.value).fold(0, u64::saturating_add);
        if !sup.is_empty() && sum < k {
            out.push(sup.iter().flat_map(|c| c.members.iter().copied()).collect());
        }
    }
    for p in &table.protected {
        out.push(p.iter().copied().collect());
    }
    out
}

fn finish(table: &Table, plan: &Plan, ln: &Lines) -> Released {
    let cell = |i: usize| -> Published {
        match table.cells.get(i) {
            Some(c) if !plan.sup.get(i).copied().unwrap_or(true) => Published::Value(c.value),
            _ => Published::Suppressed,
        }
    };
    let total = |idx: &[usize]| -> u64 {
        idx.iter()
            .filter_map(|&i| table.cells.get(i))
            .map(|c| c.value)
            .fold(0, u64::saturating_add)
    };
    let all: Vec<usize> = (0..table.cells.len()).collect();
    let marg = |lines: &[Vec<usize>], pubs: &[bool]| -> Vec<Published> {
        lines
            .iter()
            .zip(pubs)
            .map(|(l, p)| {
                if *p {
                    Published::Value(total(l))
                } else {
                    Published::Withheld
                }
            })
            .collect()
    };
    Released {
        rows: table.rows,
        cols: table.cols,
        cells: (0..table.cells.len()).map(cell).collect(),
        row_totals: marg(&ln.rows, &plan.row_pub),
        col_totals: marg(&ln.cols, &plan.col_pub),
        grand_total: if plan.grand_pub {
            Published::Value(total(&all))
        } else {
            Published::Withheld
        },
    }
}

fn check_shape(table: &Table) -> Result<Lines, ReleaseError> {
    if table.rows == 0
        || table.cols == 0
        || table.rows.checked_mul(table.cols) != Some(table.cells.len())
    {
        return Err(ReleaseError::Shape);
    }
    lines(table.rows, table.cols).ok_or(ReleaseError::Shape)
}

/// Everything one release adds to the period's history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Disclosed {
    facts: Vec<Fact>,
    priors: Vec<Prior>,
    protected: Vec<BTreeSet<MicroKey>>,
}

/// Choose an extra complementary cell for the first unprotected functional
/// `failing`: the smallest unsuppressed cell of a line with a published
/// marginal that contains a suppressed cell overlapping it.
fn extra_complementary(
    table: &Table,
    plan: &Plan,
    ln: &Lines,
    failing: &BTreeSet<MicroKey>,
) -> Option<usize> {
    let touches = |i: usize| {
        plan.sup.get(i).copied().unwrap_or(false)
            && table
                .cells
                .get(i)
                .is_some_and(|c| c.members.iter().any(|m| failing.contains(m)))
    };
    ln.rows
        .iter()
        .zip(&plan.row_pub)
        .chain(ln.cols.iter().zip(&plan.col_pub))
        .filter(|(line, p)| **p && line.iter().any(|&i| touches(i)))
        .flat_map(|(line, _)| line.iter().copied())
        .filter(|&i| !plan.sup.get(i).copied().unwrap_or(true))
        .min_by_key(|&i| (table.cells.get(i).map_or(u64::MAX, |c| c.value), i))
}

/// Suppress and audit one table against `prior` releases of the same
/// period. Adds complementary cells while that helps, then escalates
/// (withhold grand total → withhold all marginals → suppress everything);
/// if even that is unsafe with the earlier releases, refuses.
fn suppress_with(
    table: &Table,
    k: KThreshold,
    prior: &Disclosed,
) -> Result<(Released, Disclosed), ReleaseError> {
    let ln = check_shape(table)?;
    let kv = k.get();
    let width = kv.saturating_sub(1);
    let values: Vec<u64> = table.cells.iter().map(|c| c.value).collect();
    let primary: Vec<bool> = values.iter().map(|v| *v < kv).collect();
    let mut plan = greedy(&values, &ln, kv, primary);
    let mut stage = 0u8;
    let mut extra_rounds = values.len();
    loop {
        let mine = Disclosed {
            facts: facts_of(table, &plan, &ln),
            priors: priors_of(table, &plan, kv),
            protected: protected_of(table, &plan, &ln, kv),
        };
        let mut f = prior.facts.clone();
        f.extend(mine.facts.iter().cloned());
        let mut pr = prior.priors.clone();
        pr.extend(mine.priors.iter().cloned());
        let mut pt = prior.protected.clone();
        pt.extend(mine.protected.iter().cloned());
        let failing = match first_failure(&f, &pr, &pt, width) {
            Some(None) => return Ok((finish(table, &plan, &ln), mine)),
            Some(Some(i)) => pt.get(i).cloned(),
            None => None,
        };
        if stage == 3 {
            return Err(ReleaseError::DisclosureRisk);
        }
        if stage == 0 && extra_rounds > 0 {
            extra_rounds = extra_rounds.saturating_sub(1);
            if let Some(i) = failing.and_then(|fs| extra_complementary(table, &plan, &ln, &fs)) {
                let mut sup = plan.sup.clone();
                if let Some(s) = sup.get_mut(i) {
                    *s = true;
                }
                let grand = plan.grand_pub;
                plan = greedy(&values, &ln, kv, sup);
                plan.grand_pub = grand;
                continue;
            }
        }
        match stage {
            0 => plan.grand_pub = false,
            1 => {
                plan.row_pub.iter_mut().for_each(|p| *p = false);
                plan.col_pub.iter_mut().for_each(|p| *p = false);
            }
            _ => {
                plan.sup.iter_mut().for_each(|s| *s = true);
                plan.row_pub.iter_mut().for_each(|p| *p = false);
                plan.col_pub.iter_mut().for_each(|p| *p = false);
                plan.grand_pub = false;
            }
        }
        stage = stage.saturating_add(1);
    }
}

/// Suppress a single table in isolation (no prior releases).
pub fn suppress(table: &Table, k: KThreshold) -> Result<Released, ReleaseError> {
    suppress_with(table, k, &Disclosed::default()).map(|(r, _)| r)
}

// ---------------------------------------------------------------------
// Persistent release history (differencing defence across restarts)
// ---------------------------------------------------------------------

/// Release-history store error (no data echoed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HistoryError;

/// Durable per-period release history, provided by the caller (C-10 DB in
/// production). `store` must be durable before returning `Ok`. The
/// registry treats every error as fatal for the release (fail closed).
pub trait ReleaseHistory {
    /// The stored state of `period`, if any.
    fn load(&self, period: MonthStamp) -> Result<Option<Vec<u8>>, HistoryError>;
    /// Replace the stored state of `period`.
    fn store(&mut self, period: MonthStamp, state: &[u8]) -> Result<(), HistoryError>;
}

/// In-memory [`ReleaseHistory`] (tests; cloning it simulates a restart
/// with the same durable store).
#[derive(Clone, Debug, Default)]
pub struct MemoryReleaseHistory {
    periods: BTreeMap<MonthStamp, Vec<u8>>,
}

impl MemoryReleaseHistory {
    /// Empty history.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReleaseHistory for MemoryReleaseHistory {
    fn load(&self, period: MonthStamp) -> Result<Option<Vec<u8>>, HistoryError> {
        Ok(self.periods.get(&period).cloned())
    }
    fn store(&mut self, period: MonthStamp, state: &[u8]) -> Result<(), HistoryError> {
        self.periods.insert(period, state.to_vec());
        Ok(())
    }
}

/// Everything released for one period.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PeriodState {
    reports: BTreeSet<String>,
    disclosed: Disclosed,
    /// Populations of released magnitude statistics.
    magnitudes: Vec<BTreeSet<MicroKey>>,
}

mod state_codec {
    //! Canonical CBOR encoding of [`PeriodState`] (strict, bounded decode).
    use super::*;
    use crate::cbor::{self, MapBuilder, Value};

    const MAX_ITEMS: usize = 1 << 16;

    fn key_v(k: &MicroKey) -> Value {
        Value::Array(vec![Value::Bytes(k.0.to_vec()), Value::Uint(u64::from(k.1))])
    }
    fn set_v(s: &BTreeSet<MicroKey>) -> Value {
        Value::Array(s.iter().map(key_v).collect())
    }
    fn arr(v: &Value) -> Option<&[Value]> {
        match v {
            Value::Array(a) if a.len() <= MAX_ITEMS => Some(a),
            _ => None,
        }
    }
    fn key_of(v: &Value) -> Option<MicroKey> {
        match arr(v)? {
            [b, n] => Some(MicroKey(
                b.as_bytes()?.try_into().ok()?,
                u16::try_from(n.as_u64()?).ok()?,
            )),
            _ => None,
        }
    }
    fn set_of(v: &Value) -> Option<BTreeSet<MicroKey>> {
        arr(v)?.iter().map(key_of).collect()
    }

    pub(super) fn encode(s: &PeriodState) -> Option<Vec<u8>> {
        let mut m = MapBuilder::new();
        m.put("v", Value::Uint(1))
            .put(
                "reports",
                Value::Array(s.reports.iter().map(|r| Value::Text(r.clone())).collect()),
            )
            .put(
                "facts",
                Value::Array(
                    s.disclosed
                        .facts
                        .iter()
                        .map(|f| Value::Array(vec![set_v(&f.members), Value::Uint(f.value)]))
                        .collect(),
                ),
            )
            .put(
                "priors",
                Value::Array(
                    s.disclosed
                        .priors
                        .iter()
                        .map(|p| {
                            Value::Array(vec![
                                set_v(&p.members),
                                Value::Uint(p.lo),
                                p.hi.map_or(Value::Null, Value::Uint),
                            ])
                        })
                        .collect(),
                ),
            )
            .put(
                "protected",
                Value::Array(s.disclosed.protected.iter().map(set_v).collect()),
            )
            .put(
                "magnitudes",
                Value::Array(s.magnitudes.iter().map(set_v).collect()),
            );
        cbor::encode(&m.build()).ok()
    }

    pub(super) fn decode(b: &[u8]) -> Option<PeriodState> {
        let v = cbor::decode(b).ok()?;
        if v.get("v")?.as_u64()? != 1 || !matches!(&v, Value::Map(m) if m.len() == 6) {
            return None;
        }
        let reports = arr(v.get("reports")?)?
            .iter()
            .map(|r| r.as_text().map(str::to_owned))
            .collect::<Option<BTreeSet<_>>>()?;
        let facts = arr(v.get("facts")?)?
            .iter()
            .map(|f| match arr(f)? {
                [m, x] => Some(Fact {
                    members: set_of(m)?,
                    value: x.as_u64()?,
                }),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        let priors = arr(v.get("priors")?)?
            .iter()
            .map(|p| match arr(p)? {
                [m, lo, hi] => Some(Prior {
                    members: set_of(m)?,
                    lo: lo.as_u64()?,
                    hi: match hi {
                        Value::Null => None,
                        h => Some(h.as_u64()?),
                    },
                }),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        let protected = arr(v.get("protected")?)?
            .iter()
            .map(set_of)
            .collect::<Option<Vec<_>>>()?;
        let magnitudes = arr(v.get("magnitudes")?)?
            .iter()
            .map(set_of)
            .collect::<Option<Vec<_>>>()?;
        Some(PeriodState {
            reports,
            disclosed: Disclosed {
                facts,
                priors,
                protected,
            },
            magnitudes,
        })
    }
}

/// A magnitude statistic (TEL-015).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Magnitude {
    /// Median (nearest rank).
    Median,
    /// Nearest-rank percentile `p`, only for `p ∈ 10..=90` (a 0th/100th
    /// percentile would be one case's exact minimum/maximum).
    Percentile(u8),
    /// Mean (floor).
    Mean,
    /// Median duration in whole weeks (input in days, half up).
    MedianDurationWeeks,
}

/// Registry of releases per tumbling monthly period: refuses open periods
/// and re-releases (frozen periods), and audits every new table jointly
/// with everything already released for the period (24 §9.5
/// differencing). State lives in the caller's [`ReleaseHistory`].
#[derive(Debug)]
pub struct PeriodRegistry<H: ReleaseHistory> {
    history: H,
}

impl<H: ReleaseHistory> PeriodRegistry<H> {
    /// Registry over a durable history (a restarted process passes the
    /// same store and keeps every earlier release's protection).
    pub fn new(history: H) -> Self {
        Self { history }
    }

    /// The underlying history.
    pub fn history(&self) -> &H {
        &self.history
    }

    fn load(&self, period: MonthStamp) -> Result<PeriodState, ReleaseError> {
        match self.history.load(period).map_err(|_| ReleaseError::History)? {
            None => Ok(PeriodState::default()),
            Some(b) => state_codec::decode(&b).ok_or(ReleaseError::History),
        }
    }

    fn save(&mut self, period: MonthStamp, st: &PeriodState) -> Result<(), ReleaseError> {
        let b = state_codec::encode(st).ok_or(ReleaseError::History)?;
        self.history
            .store(period, &b)
            .map_err(|_| ReleaseError::History)
    }

    fn open(
        &self,
        period: MonthStamp,
        current: MonthStamp,
        report: &str,
    ) -> Result<PeriodState, ReleaseError> {
        if period >= current {
            return Err(ReleaseError::PeriodNotClosed);
        }
        let st = self.load(period)?;
        if st.reports.contains(report) {
            return Err(ReleaseError::AlreadyReleased);
        }
        Ok(st)
    }

    /// Release `table` as catalog report `report` for `period`, given the
    /// current month (`period` must be strictly earlier). The history is
    /// written before the release is returned.
    pub fn release(
        &mut self,
        period: MonthStamp,
        current: MonthStamp,
        report: &'static str,
        table: &Table,
        k: KThreshold,
    ) -> Result<Released, ReleaseError> {
        let mut st = self.open(period, current, report)?;
        let (rel, mine) = suppress_with(table, k, &st.disclosed)?;
        st.reports.insert(report.to_owned());
        st.disclosed.facts.extend(mine.facts);
        st.disclosed.priors.extend(mine.priors);
        st.disclosed.protected.extend(mine.protected);
        self.save(period, &st)?;
        Ok(rel)
    }

    /// Release a magnitude statistic over `population` (one value per
    /// contributing case, keyed consistently across reports). `Ok(None)`
    /// ("suppressed") unless n ≥ k and the population differs from every
    /// earlier magnitude population of the period by 0 or ≥ k members
    /// (blocks mean/median differencing such as n = 10 vs n = 11).
    pub fn release_magnitude(
        &mut self,
        period: MonthStamp,
        current: MonthStamp,
        report: &'static str,
        stat: Magnitude,
        population: &[(MicroKey, u64)],
        k: KThreshold,
    ) -> Result<Option<u64>, ReleaseError> {
        if let Magnitude::Percentile(p) = stat
            && !(10..=90).contains(&p)
        {
            return Err(ReleaseError::BadStatistic);
        }
        let mut st = self.open(period, current, report)?;
        let keys: BTreeSet<MicroKey> = population.iter().map(|(k, _)| *k).collect();
        let n = u64::try_from(keys.len()).map_err(|_| ReleaseError::Shape)?;
        if keys.len() != population.len() {
            return Err(ReleaseError::Shape);
        }
        let kv = k.get();
        let differs_safely = st.magnitudes.iter().all(|prev| {
            let d = u64::try_from(prev.symmetric_difference(&keys).count()).unwrap_or(u64::MAX);
            d == 0 || d >= kv
        });
        let values: Vec<u64> = population.iter().map(|(_, v)| *v).collect();
        let out = if n >= kv && differs_safely {
            match stat {
                Magnitude::Median => percentile(&values, 50),
                Magnitude::Percentile(p) => percentile(&values, p),
                Magnitude::Mean => mean(&values),
                Magnitude::MedianDurationWeeks => {
                    percentile(&values, 50).map(|d| d.saturating_add(3) / 7)
                }
            }
        } else {
            None
        };
        st.reports.insert(report.to_owned());
        if out.is_some() {
            st.magnitudes.push(keys);
        }
        self.save(period, &st)?;
        Ok(out)
    }

    /// Release a ratio `num/den` as per-mille: only if both contributing
    /// cells (`num` and `den − num`) are ≥ k (TEL-015, AUD-RM1-LOG-06).
    pub fn release_ratio(
        &mut self,
        period: MonthStamp,
        current: MonthStamp,
        report: &'static str,
        num: u64,
        den: u64,
        k: KThreshold,
    ) -> Result<Option<u64>, ReleaseError> {
        let mut st = self.open(period, current, report)?;
        let out = ratio_permille(num, den, k);
        st.reports.insert(report.to_owned());
        self.save(period, &st)?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Channel folding (TEL-016) and the counter report
// ---------------------------------------------------------------------

/// Declared channel groups (each ≥ 2 channels) and population estimates.
#[derive(Clone, Debug, Default)]
pub struct ChannelGroups {
    groups: Vec<Vec<ChannelId>>,
    population: BTreeMap<ChannelId, u64>,
}

impl ChannelGroups {
    /// Validate: every group ≥ 2 channels, no channel in two groups.
    pub fn new(
        groups: Vec<Vec<ChannelId>>,
        population: BTreeMap<ChannelId, u64>,
    ) -> Result<Self, ReleaseError> {
        let mut seen = BTreeSet::new();
        for g in &groups {
            if g.len() < 2 {
                return Err(ReleaseError::BadGroups);
            }
            for c in g {
                if !seen.insert(*c) {
                    return Err(ReleaseError::BadGroups);
                }
            }
        }
        Ok(Self { groups, population })
    }
}

/// A row of the counter report.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RowLabel {
    /// A channel shown individually.
    Channel(ChannelId),
    /// A declared channel group (index) containing folded channels.
    Group(usize),
}

/// Released monthly counter report (M2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CounterReport {
    /// Period.
    pub month: MonthStamp,
    /// Row labels.
    pub rows: Vec<RowLabel>,
    /// Columns (counters).
    pub cols: [IntakeCounter; 3],
    /// Suppressed table.
    pub table: Released,
}

fn mk(channel: &ChannelId, c: IntakeCounter) -> MicroKey {
    MicroKey(*channel.as_bytes(), c.ordinal())
}

/// Build the RL-09 counter table for a closed month (TEL-016 folding).
pub fn counter_table(
    closed: &ClosedMonth,
    groups: &ChannelGroups,
) -> Result<(Vec<RowLabel>, Table), ReleaseError> {
    // Every channel with data must belong to a declared group.
    let grouped: BTreeSet<ChannelId> = groups.groups.iter().flatten().copied().collect();
    for (c, _) in closed.counts.keys() {
        if !grouped.contains(c) {
            return Err(ReleaseError::BadGroups);
        }
    }
    let mut rows: Vec<(RowLabel, Vec<ChannelId>)> = Vec::new();
    for (gi, g) in groups.groups.iter().enumerate() {
        let small = |c: &ChannelId| {
            closed.get(*c, IntakeCounter::Submissions) < CHANNEL_MIN_CASES
                || groups.population.get(c).copied().unwrap_or(0) < CHANNEL_MIN_POPULATION
        };
        let mut folded: Vec<ChannelId> = g.iter().copied().filter(|c| small(c)).collect();
        let mut shown: Vec<ChannelId> = g.iter().copied().filter(|c| !small(c)).collect();
        if folded.len() == 1 {
            // A group row of one channel would expose it: fold the smallest
            // shown channel too.
            shown.sort_by_key(|c| (closed.get(*c, IntakeCounter::Submissions), *c));
            if !shown.is_empty() {
                folded.push(shown.remove(0));
            }
        }
        for c in shown {
            rows.push((RowLabel::Channel(c), vec![c]));
        }
        if !folded.is_empty() {
            rows.push((RowLabel::Group(gi), folded));
        }
    }
    let mut cells = Vec::new();
    let mut micro = BTreeMap::new();
    let mut protected = Vec::new();
    for (label, members) in &rows {
        for counter in IntakeCounter::ALL {
            let mut keys = Vec::new();
            let mut v: u64 = 0;
            for ch in members {
                let key = mk(ch, counter);
                let x = closed.get(*ch, counter);
                micro.insert(key, x);
                keys.push(key);
                v = v.saturating_add(x);
                if matches!(label, RowLabel::Group(_)) {
                    // Folded channels must not become individually derivable.
                    protected.push(vec![key]);
                }
            }
            cells.push(TableCell {
                value: v,
                members: keys,
            });
        }
    }
    let labels: Vec<RowLabel> = rows.into_iter().map(|(l, _)| l).collect();
    let table = Table {
        rows: labels.len(),
        cols: 3,
        cells,
        micro,
        protected,
    };
    Ok((labels, table))
}

/// Release a closed month's counters (RL-09 → AS-13) through `registry`.
pub fn release_counters<H: ReleaseHistory>(
    closed: ClosedMonth,
    groups: &ChannelGroups,
    registry: &mut PeriodRegistry<H>,
    current: MonthStamp,
    k: KThreshold,
) -> Result<CounterReport, ReleaseError> {
    let (rows, table) = counter_table(&closed, groups)?;
    if rows.is_empty() {
        return Err(ReleaseError::Shape);
    }
    let rel = registry.release(closed.month, current, "rl09.intake_counters", &table, k)?;
    Ok(CounterReport {
        month: closed.month,
        rows,
        cols: IntakeCounter::ALL,
        table: rel,
    })
}

/// Release the instance-wide `intake.coi_exhausted` monthly total (M2).
pub fn release_scalar<H: ReleaseHistory>(
    registry: &mut PeriodRegistry<H>,
    period: MonthStamp,
    current: MonthStamp,
    report: &'static str,
    value: u64,
    k: KThreshold,
) -> Result<Published, ReleaseError> {
    let key = MicroKey([0xff; 16], u16::MAX);
    let table = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell {
            value,
            members: vec![key],
        }],
        micro: BTreeMap::from([(key, value)]),
        protected: Vec::new(),
    };
    let rel = registry.release(period, current, report, &table, k)?;
    Ok(rel.cells.first().copied().unwrap_or(Published::Suppressed))
}

/// M3: round published values to the nearest 5 (deterministic, ties up).
pub fn round_m3(p: Published) -> Published {
    match p {
        Published::Value(v) => {
            let r = v % M3_ROUNDING;
            let down = v.saturating_sub(r);
            Published::Value(if r.saturating_mul(2) >= M3_ROUNDING {
                down.saturating_add(M3_ROUNDING)
            } else {
                down
            })
        }
        other => other,
    }
}

// ---------------------------------------------------------------------
// Magnitude statistics (TEL-015)
// ---------------------------------------------------------------------

/// Nearest-rank percentile `p` (0..=100) of a non-empty slice.
fn percentile(values: &[u64], p: u8) -> Option<u64> {
    let n = u64::try_from(values.len()).ok()?;
    if n == 0 || p > 100 {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    // nearest rank: ceil(p/100 * n), at least 1
    let rank = (u64::from(p).checked_mul(n)?.checked_add(99)? / 100).max(1);
    v.get(usize::try_from(rank.checked_sub(1)?).ok()?).copied()
}

/// Mean (floor) of a non-empty slice.
fn mean(values: &[u64]) -> Option<u64> {
    let n = u64::try_from(values.len()).ok()?;
    let s = values.iter().try_fold(0u64, |a, b| a.checked_add(*b))?;
    s.checked_div(n)
}

/// Ratio `num/den` as per-mille, only if `num ≥ k` and `den − num ≥ k`
/// (every contributing cell ≥ k).
fn ratio_permille(num: u64, den: u64, k: KThreshold) -> Option<u64> {
    let rest = den.checked_sub(num)?;
    if num < k.get() || rest < k.get() {
        return None;
    }
    num.checked_mul(1000)?.checked_div(den)
}
