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
//!   folded into a channel group of ≥ 2 channels), and an exact
//!   linear-algebra + bound-propagation disclosure audit across every
//!   table released for the same period (differencing defence, 24 §9.6).
//! * Magnitude statistics only for n ≥ k; ratios only for denominator ≥ k
//!   and numerator ∉ {0, denominator}.

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
    pub const ALL: [Self; 3] = [Self::Submissions, Self::AccountsCreated, Self::AccountDeletions];
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
    /// Primary or complementary suppressed cell ("<10"; M2/M3 "0–9").
    Suppressed,
    /// Marginal withheld to prevent recovery.
    Withheld,
}

impl Published {
    /// Display string for audience M2/M3.
    pub fn display(&self) -> String {
        match self {
            Self::Value(v) => v.to_string(),
            Self::Suppressed => "0\u{2013}9".to_owned(),
            Self::Withheld => "\u{2014}".to_owned(),
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

/// Greedy primary + complementary suppression (24 §9.3).
fn greedy(values: &[u64], ln: &Lines, k: u64) -> Plan {
    let mut sup: Vec<bool> = values.iter().map(|v| *v < k).collect();
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
// Disclosure audit (exact rational elimination)
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
    fn sub(self, o: Self) -> Option<Self> {
        Self::norm(
            self.n.checked_mul(o.d)?.checked_sub(o.n.checked_mul(self.d)?)?,
            self.d.checked_mul(o.d)?,
        )
    }
    fn mul(self, o: Self) -> Option<Self> {
        Self::norm(self.n.checked_mul(o.n)?, self.d.checked_mul(o.d)?)
    }
    fn div(self, o: Self) -> Option<Self> {
        Self::norm(self.n.checked_mul(o.d)?, self.d.checked_mul(o.n)?)
    }
}

/// Reduced row-echelon basis of published functionals.
struct Rref {
    rows: Vec<Vec<Q>>,
    pivots: Vec<usize>,
}

fn rref(mut m: Vec<Vec<Q>>, ncols: usize) -> Option<Rref> {
    let mut pivots = Vec::new();
    let mut r: usize = 0;
    for c in 0..ncols {
        let Some(p) = (r..m.len()).find(|&i| m.get(i).and_then(|row| row.get(c)).is_some_and(|q| !q.is_zero()))
        else {
            continue;
        };
        m.swap(r, p);
        let pv = *m.get(r)?.get(c)?;
        let prow: Vec<Q> = m.get(r)?.iter().map(|q| q.div(pv)).collect::<Option<_>>()?;
        for (i, row) in m.iter_mut().enumerate() {
            if i == r {
                continue;
            }
            let f = *row.get(c)?;
            if f.is_zero() {
                continue;
            }
            for (x, y) in row.iter_mut().zip(prow.iter()) {
                *x = x.sub(f.mul(*y)?)?;
            }
        }
        if let Some(slot) = m.get_mut(r) {
            *slot = prow;
        }
        pivots.push(c);
        r = r.checked_add(1)?;
        if r >= m.len() {
            break;
        }
    }
    m.truncate(r);
    Some(Rref { rows: m, pivots })
}

/// `Some(true)` if `v` is in the row space.
fn in_row_space(b: &Rref, v: &[Q]) -> Option<bool> {
    let mut v = v.to_vec();
    for (row, &pc) in b.rows.iter().zip(b.pivots.iter()) {
        let f = *v.get(pc)?;
        if f.is_zero() {
            continue;
        }
        for (x, y) in v.iter_mut().zip(row.iter()) {
            *x = x.sub(f.mul(*y)?)?;
        }
    }
    Some(v.iter().all(|q| q.is_zero()))
}

/// A published linear fact: sum of micro-cells = value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fact {
    /// Micro-cells summed.
    pub members: BTreeSet<MicroKey>,
    /// Published value.
    pub value: u64,
}

/// Exact disclosure audit: returns `true` iff no protected functional is
/// linearly derivable from `facts` and none is pinned by non-negativity
/// bound propagation. Arithmetic overflow ⇒ `false` (fail closed).
pub fn audit(facts: &[Fact], protected: &[BTreeSet<MicroKey>]) -> bool {
    audit_inner(facts, protected).unwrap_or(false)
}

fn audit_inner(facts: &[Fact], protected: &[BTreeSet<MicroKey>]) -> Option<bool> {
    let mut keys: BTreeSet<MicroKey> = BTreeSet::new();
    for f in facts {
        keys.extend(f.members.iter().copied());
    }
    for p in protected {
        keys.extend(p.iter().copied());
    }
    let index: BTreeMap<MicroKey, usize> = keys.iter().copied().enumerate().map(|(i, k)| (k, i)).collect();
    let n = index.len();
    let vec_of = |s: &BTreeSet<MicroKey>| -> Vec<Q> {
        let mut v = vec![Q::ZERO; n];
        for k in s {
            if let Some(slot) = index.get(k).and_then(|&i| v.get_mut(i)) {
                *slot = Q::int(1);
            }
        }
        v
    };
    let basis = rref(facts.iter().map(|f| vec_of(&f.members)).collect(), n)?;
    for p in protected {
        if p.is_empty() {
            continue;
        }
        if in_row_space(&basis, &vec_of(p))? {
            return Some(false);
        }
    }
    // Non-negativity bound propagation (catches e.g. a zero remainder).
    let mut lo = vec![0u128; n];
    let mut hi = vec![u128::MAX; n];
    let fidx: Vec<(Vec<usize>, u128)> = facts
        .iter()
        .map(|f| {
            (
                f.members.iter().filter_map(|k| index.get(k).copied()).collect(),
                u128::from(f.value),
            )
        })
        .collect();
    for _ in 0..n.saturating_add(2).min(64) {
        let mut changed = false;
        for (members, v) in &fidx {
            let sum_lo: u128 = members.iter().map(|&i| lo.get(i).copied().unwrap_or(0)).fold(0, u128::saturating_add);
            let sum_hi: u128 = members.iter().map(|&i| hi.get(i).copied().unwrap_or(u128::MAX)).fold(0, u128::saturating_add);
            for &i in members {
                let (l, h) = (lo.get(i).copied()?, hi.get(i).copied()?);
                let others_lo = sum_lo.saturating_sub(l);
                let new_h = v.saturating_sub(others_lo).min(h);
                let new_l = if sum_hi == u128::MAX {
                    l
                } else {
                    v.saturating_sub(sum_hi.saturating_sub(h)).max(l)
                };
                if new_h != h || new_l != l {
                    *hi.get_mut(i)? = new_h;
                    *lo.get_mut(i)? = new_l;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    for p in protected {
        if p.is_empty() {
            continue;
        }
        let (mut l, mut h) = (0u128, 0u128);
        for k in p {
            let i = *index.get(k)?;
            l = l.saturating_add(*lo.get(i)?);
            h = h.saturating_add(*hi.get(i)?);
        }
        if l == h {
            return Some(false);
        }
    }
    Some(true)
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
    for (line, p) in ln.rows.iter().zip(&plan.row_pub).chain(ln.cols.iter().zip(&plan.col_pub)) {
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

fn protected_of(table: &Table, plan: &Plan, ln: &Lines, k: u64) -> Vec<BTreeSet<MicroKey>> {
    let mut out: Vec<BTreeSet<MicroKey>> = Vec::new();
    // Every suppressed cell.
    for (i, c) in table.cells.iter().enumerate() {
        if plan.sup.get(i).copied().unwrap_or(false) {
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
    Released {
        rows: table.rows,
        cols: table.cols,
        cells: (0..table.cells.len()).map(cell).collect(),
        row_totals: ln
            .rows
            .iter()
            .zip(&plan.row_pub)
            .map(|(l, p)| if *p { Published::Value(total(l)) } else { Published::Withheld })
            .collect(),
        col_totals: ln
            .cols
            .iter()
            .zip(&plan.col_pub)
            .map(|(l, p)| if *p { Published::Value(total(l)) } else { Published::Withheld })
            .collect(),
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

/// Result of suppressing one table: release, its facts, its protections.
type Suppressed = (Released, Vec<Fact>, Vec<BTreeSet<MicroKey>>);

/// Suppress and audit one table against `prior` facts/protections of the
/// same period. Escalates (withhold grand total → withhold all marginals
/// → suppress everything) until the audit passes.
fn suppress_with(
    table: &Table,
    k: KThreshold,
    prior_facts: &[Fact],
    prior_protected: &[BTreeSet<MicroKey>],
) -> Result<Suppressed, ReleaseError> {
    let ln = check_shape(table)?;
    let values: Vec<u64> = table.cells.iter().map(|c| c.value).collect();
    let mut plan = greedy(&values, &ln, k.get());
    let mut stage = 0u8;
    loop {
        let facts = facts_of(table, &plan, &ln);
        let protected = protected_of(table, &plan, &ln, k.get());
        let mut all_f = prior_facts.to_vec();
        all_f.extend(facts.iter().cloned());
        let mut all_p = prior_protected.to_vec();
        all_p.extend(protected.iter().cloned());
        if audit(&all_f, &all_p) {
            return Ok((finish(table, &plan, &ln), facts, protected));
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
                let facts = Vec::new();
                let protected = protected_of(table, &plan, &ln, k.get());
                return Ok((finish(table, &plan, &ln), facts, protected));
            }
        }
        stage = stage.saturating_add(1);
    }
}

/// Suppress a single table in isolation (no prior releases).
pub fn suppress(table: &Table, k: KThreshold) -> Result<Released, ReleaseError> {
    suppress_with(table, k, &[], &[]).map(|(r, _, _)| r)
}

#[derive(Default, Debug)]
struct PeriodState {
    reports: BTreeSet<&'static str>,
    facts: Vec<Fact>,
    protected: Vec<BTreeSet<MicroKey>>,
}

/// Registry of releases per tumbling monthly period: refuses open periods
/// and re-releases (frozen periods), and audits every new table jointly
/// with everything already released for the period (24 §9.5 differencing).
#[derive(Default, Debug)]
pub struct PeriodRegistry {
    periods: BTreeMap<MonthStamp, PeriodState>,
}

impl PeriodRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Release `table` as catalog report `report` for `period`, given the
    /// current month (`period` must be strictly earlier).
    pub fn release(
        &mut self,
        period: MonthStamp,
        current: MonthStamp,
        report: &'static str,
        table: &Table,
        k: KThreshold,
    ) -> Result<Released, ReleaseError> {
        if period >= current {
            return Err(ReleaseError::PeriodNotClosed);
        }
        let st = self.periods.entry(period).or_default();
        if st.reports.contains(report) {
            return Err(ReleaseError::AlreadyReleased);
        }
        let (rel, facts, protected) = suppress_with(table, k, &st.facts, &st.protected)?;
        st.reports.insert(report);
        st.facts.extend(facts);
        st.protected.extend(protected);
        Ok(rel)
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
            cells.push(TableCell { value: v, members: keys });
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
pub fn release_counters(
    closed: ClosedMonth,
    groups: &ChannelGroups,
    registry: &mut PeriodRegistry,
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
pub fn release_scalar(
    registry: &mut PeriodRegistry,
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

/// Median, only for n ≥ k (otherwise `None`, displayed "—").
pub fn median(values: &[u64], k: KThreshold) -> Option<u64> {
    percentile(values, 50, k)
}

/// Nearest-rank percentile `p` (0..=100), only for n ≥ k.
pub fn percentile(values: &[u64], p: u8, k: KThreshold) -> Option<u64> {
    let n = u64::try_from(values.len()).ok()?;
    if n < k.get() || p > 100 {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    // nearest rank: ceil(p/100 * n), at least 1
    let rank = (u64::from(p).checked_mul(n)?.checked_add(99)? / 100).max(1);
    v.get(usize::try_from(rank.checked_sub(1)?).ok()?).copied()
}

/// Mean (floor), only for n ≥ k.
pub fn mean(values: &[u64], k: KThreshold) -> Option<u64> {
    let n = u64::try_from(values.len()).ok()?;
    if n < k.get() {
        return None;
    }
    let s = values.iter().try_fold(0u64, |a, b| a.checked_add(*b))?;
    s.checked_div(n)
}

/// Median duration in whole weeks (rounded half up), only for n ≥ k.
pub fn median_duration_weeks(durations_days: &[u64], k: KThreshold) -> Option<u64> {
    median(durations_days, k).map(|d| d.saturating_add(3) / 7)
}

/// Ratio `num/den` as per-mille, only if `den ≥ k` and `num ∉ {0, den}`.
pub fn ratio_permille(num: u64, den: u64, k: KThreshold) -> Option<u64> {
    if den < k.get() || num == 0 || num >= den {
        return None;
    }
    num.checked_mul(1000)?.checked_div(den)
}
