// SPDX-License-Identifier: AGPL-3.0-or-later
//! 24 §TEL metrics regime: k = 10, complementary suppression, tumbling
//! monthly periods, per-channel rule, magnitude rules, and the §9.6
//! `stats-inference` differencing cases (TEL-010/011/015/016/020, LOG-011,
//! LOG-025).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use candor_log::ids::{ChannelId, MonthStamp};
use candor_log::metrics::*;
use proptest::prelude::*;

fn k() -> KThreshold {
    KThreshold::DEFAULT
}

fn m(y: i32, mo: u32) -> MonthStamp {
    MonthStamp::new(y, mo).unwrap()
}

/// Table whose cells are independent micro-cells (key = cell index).
fn simple(rows: usize, cols: usize, vals: &[u64]) -> Table {
    let mut cells = Vec::new();
    let mut micro = BTreeMap::new();
    for (i, v) in vals.iter().enumerate() {
        let key = MicroKey([0; 16], i as u16);
        micro.insert(key, *v);
        cells.push(TableCell {
            value: *v,
            members: vec![key],
        });
    }
    Table {
        rows,
        cols,
        cells,
        micro,
        protected: vec![],
    }
}

/// Equations an attacker reads off a released table over the micro-cells
/// `0..r*c` of a `simple` table: published cells, row/column/grand totals.
fn equations(rel: &Released) -> Vec<(Vec<usize>, u64)> {
    let (r, c) = (rel.rows, rel.cols);
    let mut eqs: Vec<(Vec<usize>, u64)> = Vec::new();
    for i in 0..r * c {
        if let Published::Value(v) = rel.cells[i] {
            eqs.push((vec![i], v));
        }
    }
    for i in 0..r {
        if let Published::Value(t) = rel.row_totals[i] {
            eqs.push(((0..c).map(|j| i * c + j).collect(), t));
        }
    }
    for j in 0..c {
        if let Published::Value(t) = rel.col_totals[j] {
            eqs.push(((0..r).map(|i| i * c + j).collect(), t));
        }
    }
    if let Published::Value(t) = rel.grand_total {
        eqs.push(((0..r * c).collect(), t));
    }
    eqs
}

/// Independent brute-force attacker with prior knowledge (AUD-RM1-LOG-05):
/// it knows every published figure (`eqs`, possibly from several releases),
/// that each primary-suppressed cell is < k and each other cell ≥ k
/// (worst case: it knows which is which). It enumerates every integer
/// completion and returns the primary cells whose feasible set is not the
/// whole `0..k`, i.e. about which it learned anything.
fn exposed(n: usize, vals: &[u64], eqs: &[(Vec<usize>, u64)]) -> Vec<usize> {
    exposed_with(n, vals, eqs, &[])
}

/// As [`exposed`], plus interval knowledge `lo ≤ Σ cells ≤ hi` (e.g. "this
/// suppressed cell of another release is < k").
fn exposed_with(
    n: usize,
    vals: &[u64],
    eqs: &[(Vec<usize>, u64)],
    ranges: &[(Vec<usize>, u64, u64)],
) -> Vec<usize> {
    let k = 10u64;
    let fixed: BTreeMap<usize, u64> = eqs
        .iter()
        .filter(|(e, _)| e.len() == 1)
        .map(|(e, v)| (e[0], *v))
        .collect();
    let unknown: Vec<usize> = (0..n).filter(|i| !fixed.contains_key(i)).collect();
    let primary: Vec<usize> = unknown.iter().copied().filter(|&i| vals[i] < k).collect();
    // Per-cell prior range: primary [0, k-1], others [k, smallest total].
    let range = |cell: usize| -> (u64, u64) {
        if let Some(v) = fixed.get(&cell) {
            return (*v, *v);
        }
        if vals[cell] < k {
            (0, k - 1)
        } else {
            let b = eqs
                .iter()
                .filter(|(e, _)| e.contains(&cell))
                .map(|(_, t)| *t)
                .min()
                .unwrap_or(k + 40);
            (k, b.max(k))
        }
    };
    /// Depth-first search for one completion, with interval pruning on
    /// every equation (sum of assigned + bounds of unassigned must bracket
    /// the published total).
    fn feasible(
        idx: usize,
        cells: &[usize],
        assign: &mut BTreeMap<usize, u64>,
        eqs: &[(Vec<usize>, u64)],
        ranges: &[(Vec<usize>, u64, u64)],
        range: &dyn Fn(usize) -> (u64, u64),
    ) -> bool {
        for (e, rlo, rhi) in ranges {
            let (mut lo, mut hi) = (0u64, 0u64);
            for &i in e {
                let (a, b) = assign.get(&i).map_or_else(|| range(i), |v| (*v, *v));
                lo += a;
                hi += b;
            }
            if lo > *rhi || hi < *rlo {
                return false;
            }
        }
        for (e, t) in eqs {
            let (mut lo, mut hi) = (0u64, 0u64);
            for &i in e {
                match assign.get(&i) {
                    Some(v) => {
                        lo += v;
                        hi += v;
                    }
                    None => {
                        let (a, b) = range(i);
                        lo += a;
                        hi += b;
                    }
                }
            }
            if lo > *t || hi < *t {
                return false;
            }
        }
        if idx == cells.len() {
            return true;
        }
        let cell = cells[idx];
        if assign.contains_key(&cell) {
            return feasible(idx + 1, cells, assign, eqs, ranges, range);
        }
        let (lo, hi) = range(cell);
        for v in lo..=hi {
            assign.insert(cell, v);
            if feasible(idx + 1, cells, assign, eqs, ranges, range) {
                assign.remove(&cell);
                return true;
            }
            assign.remove(&cell);
        }
        false
    }
    let mut out = Vec::new();
    for &p in &primary {
        for v in 0..k {
            let mut assign = fixed.clone();
            assign.insert(p, v);
            if !feasible(0, &unknown, &mut assign, eqs, ranges, &range) {
                out.push(p);
                break;
            }
        }
    }
    out
}

fn pinned_cells(rel: &Released, vals: &[u64]) -> Vec<usize> {
    exposed(rel.rows * rel.cols, vals, &equations(rel))
}

fn reg() -> PeriodRegistry<MemoryReleaseHistory> {
    PeriodRegistry::new(MemoryReleaseHistory::new())
}

#[test]
fn k_is_configurable_upward_only() {
    // TEL-011
    assert!(KThreshold::new(9).is_none());
    assert!(KThreshold::new(0).is_none());
    assert_eq!(KThreshold::new(10).unwrap().get(), 10);
    assert_eq!(KThreshold::new(25).unwrap().get(), 25);
    assert_eq!(KThreshold::default().get(), K_MIN);
}

#[test]
fn single_small_cell_fully_hidden() {
    let rel = suppress(&simple(1, 1, &[4]), k()).unwrap();
    assert_eq!(rel.cells[0], Published::Suppressed);
    assert_eq!(rel.grand_total, Published::Withheld);
    assert_eq!(rel.row_totals[0], Published::Withheld);
    assert_eq!(rel.cells[0].display(), "suppressed");
    assert_eq!(rel.grand_total.display(), "suppressed");
    let rel = suppress(&simple(1, 1, &[14]), k()).unwrap();
    assert_eq!(rel.cells[0], Published::Value(14));
}

#[test]
fn complementary_suppression_row_with_one_small_cell() {
    // 24 §9.3: a row with exactly one primary-suppressed cell gets the
    // next-smallest non-zero cell suppressed too.
    let vals = [3, 20, 30, 15, 25, 40];
    let t = simple(2, 3, &vals);
    let rel = suppress(&t, k()).unwrap();
    assert_eq!(rel.cells[0], Published::Suppressed);
    assert_eq!(
        rel.cells[1],
        Published::Suppressed,
        "next-smallest in row 0"
    );
    assert!(pinned_cells(&rel, &vals).is_empty(), "{rel:?}");
    // Published row totals never allow recovery of the 3.
    let row0_known: u64 = (0..3)
        .filter_map(|j| match rel.cells[j] {
            Published::Value(v) => Some(v),
            _ => None,
        })
        .sum();
    if let Published::Value(t) = rel.row_totals[0] {
        assert!(t - row0_known >= 10);
    }
}

#[test]
fn zero_remainder_cannot_reveal_zeros() {
    // Zeros are suppressed like "<10" (merged "0–9"); a published total equal
    // to the published cells would reveal them exactly.
    let t = simple(1, 3, &[0, 0, 50]);
    let rel = suppress(&t, k()).unwrap();
    assert!(pinned_cells(&rel, &[0, 0, 50]).is_empty(), "{rel:?}");
    assert_eq!(rel.cells[0], Published::Suppressed);
    assert_eq!(rel.cells[1], Published::Suppressed);
}

#[test]
fn no_small_cell_derivable_two_by_two_rectangle() {
    // Classic: suppressing a 2×2 rectangle with all marginals published is
    // ambiguous linearly, but non-negativity can pin it.
    let t = simple(2, 2, &[0, 11, 12, 13]);
    let rel = suppress(&t, k()).unwrap();
    assert!(pinned_cells(&rel, &[0, 11, 12, 13]).is_empty(), "{rel:?}");
}

// AUD-RM1-LOG-05 regression (the audit PoC; the old audit passed it and
// labelled the 50 and 60 "0–9"): row 0 = [0, 10, 100] with all margins
// published let an attacker who knows "primary < k ≤ complementary" pin
// the 0 exactly.
#[test]
fn primary_cell_not_narrowed_by_attacker_priors() {
    let vals = [0, 10, 100, 50, 60, 70];
    let rel = suppress(&simple(2, 3, &vals), k()).unwrap();
    assert_eq!(rel.cells[0], Published::Suppressed);
    assert!(pinned_cells(&rel, &vals).is_empty(), "{rel:?}");
    for p in rel
        .cells
        .iter()
        .chain(&rel.row_totals)
        .chain(&rel.col_totals)
    {
        let d = p.display();
        assert!(d == "suppressed" || d.parse::<u64>().is_ok(), "{d}");
    }
}

// 24 §9.5 "Differencing (filters)": totals with and without one channel.
#[test]
fn differencing_attack_across_reports_is_blocked() {
    let c = |n: u8| MicroKey([n; 16], 0);
    let micro = BTreeMap::from([(c(1), 12), (c(2), 13), (c(3), 4)]);
    let all = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell {
            value: 29,
            members: vec![c(1), c(2), c(3)],
        }],
        micro: micro.clone(),
        protected: vec![],
    };
    let without3 = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell {
            value: 25,
            members: vec![c(1), c(2)],
        }],
        micro: micro.clone(),
        protected: vec![],
    };
    // In isolation each table looks safe: the attack is real.
    assert_eq!(suppress(&all, k()).unwrap().cells[0], Published::Value(29));
    assert_eq!(
        suppress(&without3, k()).unwrap().cells[0],
        Published::Value(25)
    );
    // Through the period registry, the second release cannot complete the
    // subtraction 29 − 25 = 4.
    let mut reg = reg();
    let a = reg
        .release(m(2026, 8), m(2026, 10), "report.all", &all, k())
        .unwrap();
    let b = reg
        .release(m(2026, 8), m(2026, 10), "report.without3", &without3, k())
        .unwrap();
    assert_eq!(a.cells[0], Published::Value(29));
    assert_eq!(b.cells[0], Published::Suppressed);
    assert_eq!(b.grand_total, Published::Withheld);
    assert_eq!(b.row_totals[0], Published::Withheld);
}

// Differencing via a second table's marginals.
#[test]
fn differencing_via_marginals_is_blocked() {
    // Report 1: by channel (rows) × one column: c1=12, c2=4 (small), c3=15.
    let key = |n: u8| MicroKey([n; 16], 0);
    let micro = BTreeMap::from([(key(1), 12), (key(2), 4), (key(3), 15)]);
    let by_channel = Table {
        rows: 3,
        cols: 1,
        cells: vec![
            TableCell {
                value: 12,
                members: vec![key(1)],
            },
            TableCell {
                value: 4,
                members: vec![key(2)],
            },
            TableCell {
                value: 15,
                members: vec![key(3)],
            },
        ],
        micro: micro.clone(),
        protected: vec![],
    };
    // Report 2: the grand total alone.
    let total = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell {
            value: 31,
            members: vec![key(1), key(2), key(3)],
        }],
        micro,
        protected: vec![],
    };
    let mut reg = reg();
    let r1 = reg
        .release(m(2026, 8), m(2026, 9), "by_channel", &by_channel, k())
        .unwrap();
    let r2 = reg
        .release(m(2026, 8), m(2026, 9), "total", &total, k())
        .unwrap();
    // c2 must stay hidden: 31 − 12 − 15 would reveal it.
    assert_eq!(r1.cells[1], Published::Suppressed);
    let published_sum: u64 = r1
        .cells
        .iter()
        .filter_map(|p| {
            if let Published::Value(v) = p {
                Some(*v)
            } else {
                None
            }
        })
        .sum();
    if let Published::Value(t) = r2.cells[0] {
        assert!(
            t - published_sum >= 10 || published_sum < 27,
            "c2 derivable"
        );
        // The only way t is published is if published cells exclude ≥ 2 values.
        let hidden = r1
            .cells
            .iter()
            .filter(|p| **p == Published::Suppressed)
            .count();
        assert!(hidden >= 2);
    }
}

// 24 §9.5 "Differencing (windows)" and "Rolling/cumulative displays".
#[test]
fn tumbling_frozen_periods() {
    let mut reg = reg();
    let t = simple(1, 1, &[40]);
    // No month-to-date figures.
    assert_eq!(
        reg.release(m(2026, 10), m(2026, 10), "r", &t, k())
            .unwrap_err(),
        ReleaseError::PeriodNotClosed
    );
    reg.release(m(2026, 9), m(2026, 10), "r", &t, k()).unwrap();
    // Frozen: no revision of a released period.
    let t2 = simple(1, 1, &[41]);
    assert_eq!(
        reg.release(m(2026, 9), m(2026, 11), "r", &t2, k())
            .unwrap_err(),
        ReleaseError::AlreadyReleased
    );
}

// LOG-011: counters only per month, current + previous; raw values leave
// memory when released; before/after one submission across periods.
#[test]
fn counter_aggregation_and_release() {
    let ch: Vec<ChannelId> = (1..=4)
        .map(|n| ChannelId::derive(&candor_log::ids::AuditIdKey::new([1; 32]), &[n]))
        .collect();
    let mut agg = CounterAggregator::new(m(2026, 9));
    let sub = IntakeCounter::Submissions;
    for _ in 0..14 {
        agg.increment(m(2026, 9), ch[0], sub).unwrap();
        agg.increment(m(2026, 9), ch[0], IntakeCounter::AccountsCreated)
            .unwrap();
    }
    for _ in 0..12 {
        agg.increment(m(2026, 9), ch[1], sub).unwrap();
        agg.increment(m(2026, 9), ch[1], IntakeCounter::AccountsCreated)
            .unwrap();
    }
    // ch[2]: 2 submissions (< 3 cases → folded); ch[3]: 20 but population < 50.
    for _ in 0..2 {
        agg.increment(m(2026, 9), ch[2], sub).unwrap();
    }
    for _ in 0..20 {
        agg.increment(m(2026, 9), ch[3], sub).unwrap();
    }
    // The open month cannot be taken (no month-to-date).
    assert_eq!(
        agg.take_closed(m(2026, 9)).unwrap_err(),
        CounterError::NotClosed
    );
    agg.increment(m(2026, 10), ch[0], sub).unwrap();
    // Stale months are rejected.
    assert_eq!(
        agg.increment(m(2026, 8), ch[0], sub).unwrap_err(),
        CounterError::StaleMonth
    );
    let closed = agg.take_closed(m(2026, 9)).unwrap();
    // Taken once: raw values are gone.
    assert!(agg.take_closed(m(2026, 9)).is_err());
    assert!(!format!("{closed:?}").contains("14"));

    let pop = BTreeMap::from([(ch[0], 500), (ch[1], 500), (ch[2], 500), (ch[3], 20)]);
    let groups = ChannelGroups::new(vec![vec![ch[0], ch[1]], vec![ch[2], ch[3]]], pop).unwrap();
    let mut reg = reg();
    let rep = release_counters(closed, &groups, &mut reg, m(2026, 10), k()).unwrap();
    // ch[2], ch[3] folded into group 1; ch[0], ch[1] shown individually.
    assert_eq!(
        rep.rows,
        vec![
            RowLabel::Channel(ch[0]),
            RowLabel::Channel(ch[1]),
            RowLabel::Group(1)
        ]
    );
    // Group row is [22, 0, 0]: its two zero cells sum to 0 < k, so the row
    // total would reveal them; complementary suppression hides the 22 too.
    assert_eq!(rep.table.cells[6], Published::Suppressed);
    assert_eq!(rep.table.cells[7], Published::Suppressed);
    assert_eq!(rep.table.cells[2], Published::Suppressed);
    let vals = [14, 14, 0, 12, 12, 0, 22, 0, 0];
    assert!(
        pinned_cells(&rep.table, &vals).is_empty(),
        "{:?}",
        rep.table
    );
}

#[test]
fn group_with_one_folded_channel_absorbs_another() {
    let ch: Vec<ChannelId> = (1..=3)
        .map(|n| ChannelId::derive(&candor_log::ids::AuditIdKey::new([1; 32]), &[n]))
        .collect();
    let pop = BTreeMap::from([(ch[0], 500), (ch[1], 500), (ch[2], 500)]);
    let groups = ChannelGroups::new(vec![ch.clone()], pop).unwrap();
    let closed = ClosedMonth::from_counts(
        m(2026, 9),
        [
            ((ch[0], IntakeCounter::Submissions), 30),
            ((ch[1], IntakeCounter::Submissions), 15),
            ((ch[2], IntakeCounter::Submissions), 1),
        ],
    );
    let (rows, _t) = counter_table(&closed, &groups).unwrap();
    // ch[2] alone would form a one-channel group row: ch[1] (smallest) joins it.
    assert_eq!(rows, vec![RowLabel::Channel(ch[0]), RowLabel::Group(0)]);
    // Groups must have ≥ 2 channels and be disjoint.
    assert!(ChannelGroups::new(vec![vec![ch[0]]], BTreeMap::new()).is_err());
    assert!(
        ChannelGroups::new(
            vec![vec![ch[0], ch[1]], vec![ch[1], ch[2]]],
            BTreeMap::new()
        )
        .is_err()
    );
    // Channels outside any group are refused.
    let lone = ClosedMonth::from_counts(
        m(2026, 9),
        [(
            (
                ChannelId::derive(&candor_log::ids::AuditIdKey::new([1; 32]), &[9]),
                IntakeCounter::Submissions,
            ),
            50,
        )],
    );
    assert!(counter_table(&lone, &groups).is_err());
}

#[test]
fn folded_channel_not_recoverable_from_second_report() {
    // A later report showing the group's other channel individually must not
    // reveal the folded small channel by subtraction.
    let ch: Vec<ChannelId> = (1..=2)
        .map(|n| ChannelId::derive(&candor_log::ids::AuditIdKey::new([1; 32]), &[n]))
        .collect();
    let pop = BTreeMap::from([(ch[0], 500), (ch[1], 10)]);
    let groups = ChannelGroups::new(vec![ch.clone()], pop).unwrap();
    let closed = ClosedMonth::from_counts(
        m(2026, 9),
        [
            ((ch[0], IntakeCounter::Submissions), 40),
            ((ch[1], IntakeCounter::Submissions), 12),
        ],
    );
    let mut reg = reg();
    let rep = release_counters(closed, &groups, &mut reg, m(2026, 10), k()).unwrap();
    assert_eq!(rep.rows, vec![RowLabel::Group(0)]);
    // Attacker-chosen second table: ch[0] alone.
    let single = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell {
            value: 40,
            members: vec![MicroKey(*ch[0].as_bytes(), 0)],
        }],
        micro: BTreeMap::from([(MicroKey(*ch[0].as_bytes(), 0), 40)]),
        protected: vec![],
    };
    let r = reg
        .release(m(2026, 9), m(2026, 10), "single", &single, k())
        .unwrap();
    assert_eq!(r.cells[0], Published::Suppressed);
}

#[test]
fn scalar_coi_exhausted_release() {
    let mut reg = reg();
    assert_eq!(
        release_scalar(&mut reg, m(2026, 9), m(2026, 10), "coi_exhausted", 3, k()).unwrap(),
        Published::Suppressed
    );
    assert_eq!(
        release_scalar(&mut reg, m(2026, 8), m(2026, 10), "coi_exhausted", 11, k()).unwrap(),
        Published::Value(11)
    );
}

// AUD-RM1-LOG-18 regression: magnitude statistics were removed from the
// API (the round-2 PoC combined four released means into one case's
// value); `tests/ui/no_magnitude_api.rs` shows the calls no longer
// compile. Here: a release history written by the old magnitude-aware
// version (v1, with a `magnitudes` field) is refused, never silently
// reinterpreted (fail closed).
#[test]
fn magnitude_era_history_is_refused() {
    use candor_log::cbor::{MapBuilder, Value, encode};
    let mut mb = MapBuilder::new();
    mb.put("v", Value::Uint(1))
        .put("reports", Value::Array(vec![]))
        .put("facts", Value::Array(vec![]))
        .put("priors", Value::Array(vec![]))
        .put("protected", Value::Array(vec![]))
        .put("magnitudes", Value::Array(vec![]));
    let mut h = MemoryReleaseHistory::new();
    h.store(m(2026, 8), &encode(&mb.build()).unwrap()).unwrap();
    let mut r = PeriodRegistry::new(h);
    let t = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell {
            value: 40,
            members: vec![MicroKey([1; 16], 0)],
        }],
        micro: BTreeMap::from([(MicroKey([1; 16], 0), 40)]),
        protected: vec![],
    };
    assert_eq!(
        r.release(m(2026, 8), m(2026, 10), "t", &t, k())
            .unwrap_err(),
        ReleaseError::History
    );
}

// AUD-RM1-LOG-06 regression: the differencing defence survives a restart
// (the old in-memory registry forgot report.all and published 25).
#[test]
fn differencing_blocked_across_restart() {
    let c = |n: u8| MicroKey([n; 16], 0);
    let micro = BTreeMap::from([(c(1), 12), (c(2), 13), (c(3), 4)]);
    let one = |v: u64, members: Vec<MicroKey>| Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell { value: v, members }],
        micro: micro.clone(),
        protected: vec![],
    };
    let mut r = reg();
    let a = r
        .release(
            m(2026, 8),
            m(2026, 10),
            "report.all",
            &one(29, vec![c(1), c(2), c(3)]),
            k(),
        )
        .unwrap();
    assert_eq!(a.cells[0], Published::Value(29));
    let history = r.history().clone();
    drop(r);
    let mut restarted = PeriodRegistry::new(history);
    let b = restarted
        .release(
            m(2026, 8),
            m(2026, 10),
            "report.without3",
            &one(25, vec![c(1), c(2)]),
            k(),
        )
        .unwrap();
    assert_eq!(b.cells[0], Published::Suppressed);
    // Frozen across restarts too.
    assert_eq!(
        restarted
            .release(
                m(2026, 8),
                m(2026, 10),
                "report.all",
                &one(29, vec![c(1), c(2), c(3)]),
                k()
            )
            .unwrap_err(),
        ReleaseError::AlreadyReleased
    );
}

/// History that fails on demand.
struct BrokenHistory {
    load_fails: bool,
}

impl ReleaseHistory for BrokenHistory {
    fn load(&self, _: candor_log::ids::MonthStamp) -> Result<Option<Vec<u8>>, HistoryError> {
        if self.load_fails {
            Err(HistoryError)
        } else {
            Ok(Some(vec![0xff, 0x00]))
        }
    }
    fn store(&mut self, _: candor_log::ids::MonthStamp, _: &[u8]) -> Result<(), HistoryError> {
        Err(HistoryError)
    }
}

// AUD-RM1-LOG-06: an unreadable, corrupt or unwritable history fails the
// release closed.
#[test]
fn history_errors_fail_closed() {
    let t = simple(1, 1, &[40]);
    for load_fails in [true, false] {
        let mut r = PeriodRegistry::new(BrokenHistory { load_fails });
        assert_eq!(
            r.release(m(2026, 8), m(2026, 9), "x", &t, k()).unwrap_err(),
            ReleaseError::History
        );
    }
    struct WriteFails(MemoryReleaseHistory);
    impl ReleaseHistory for WriteFails {
        fn load(&self, p: candor_log::ids::MonthStamp) -> Result<Option<Vec<u8>>, HistoryError> {
            self.0.load(p)
        }
        fn store(&mut self, _: candor_log::ids::MonthStamp, _: &[u8]) -> Result<(), HistoryError> {
            Err(HistoryError)
        }
    }
    let mut r = PeriodRegistry::new(WriteFails(MemoryReleaseHistory::new()));
    assert_eq!(
        r.release(m(2026, 8), m(2026, 9), "x", &t, k()).unwrap_err(),
        ReleaseError::History
    );
}

#[test]
fn m3_rounding() {
    assert_eq!(round_m3(Published::Value(12)), Published::Value(10));
    assert_eq!(round_m3(Published::Value(13)), Published::Value(15));
    assert_eq!(round_m3(Published::Value(15)), Published::Value(15));
    assert_eq!(round_m3(Published::Suppressed), Published::Suppressed);
}

#[test]
fn shape_errors() {
    let mut t = simple(2, 2, &[1, 2, 3]);
    assert_eq!(suppress(&t, k()).unwrap_err(), ReleaseError::Shape);
    t.rows = 0;
    assert_eq!(suppress(&t, k()).unwrap_err(), ReleaseError::Shape);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // stats-inference (24 §9.6): for random small tables no primary cell is
    // narrowed below [0, k-1] by a completion attacker with prior
    // knowledge, and every published cell is ≥ k.
    #[test]
    fn no_suppressed_cell_is_derivable(
        shape in prop_oneof![Just((1usize, 3usize)), Just((2, 2)), Just((2, 3)), Just((3, 2)), Just((3, 3))],
        vals in proptest::collection::vec(prop_oneof![0u64..10, 10u64..18], 9),
    ) {
        let (r, c) = shape;
        let vals = &vals[..r * c];
        let t = simple(r, c, vals);
        let rel = suppress(&t, k()).unwrap();
        for p in &rel.cells {
            if let Published::Value(v) = p {
                prop_assert!(*v >= 10);
            }
        }
        for (i, v) in vals.iter().enumerate() {
            if *v < 10 {
                prop_assert_eq!(rel.cells[i], Published::Suppressed);
            }
        }
        prop_assert!(pinned_cells(&rel, vals).is_empty(), "{:?} {:?}", vals, rel);
    }

    // Attacker test (AUD-RM1-LOG-05/06): margin arithmetic plus
    // differencing across two releases of the same period, with a process
    // restart in between (history persisted), using all published figures
    // of both releases and the prior knowledge.
    #[test]
    fn margins_and_differencing_across_releases_and_restarts(
        shape in prop_oneof![Just((2usize, 2usize)), Just((2, 3)), Just((3, 2))],
        vals in proptest::collection::vec(prop_oneof![0u64..10, 10u64..16], 6),
        second_rows in any::<bool>(),
    ) {
        let (r, c) = shape;
        let vals = &vals[..r * c];
        let full = simple(r, c, vals);
        let mut first = reg();
        let rel1 = first.release(m(2026, 8), m(2026, 9), "full", &full, k()).unwrap();
        // Restart: a new registry over the same durable history.
        let mut second = PeriodRegistry::new(first.history().clone());
        // Second report: the same micro-cells collapsed along one dimension.
        let (lines, n2): (Vec<Vec<usize>>, usize) = if second_rows {
            ((0..r).map(|i| (0..c).map(|j| i * c + j).collect()).collect(), r)
        } else {
            ((0..c).map(|j| (0..r).map(|i| i * c + j).collect()).collect(), c)
        };
        let coarse = Table {
            rows: 1,
            cols: n2,
            cells: lines
                .iter()
                .map(|l| TableCell {
                    value: l.iter().map(|&i| vals[i]).sum(),
                    members: l.iter().map(|&i| MicroKey([0; 16], i as u16)).collect(),
                })
                .collect(),
            micro: full.micro.clone(),
            protected: vec![],
        };
        let rel2 = second.release(m(2026, 8), m(2026, 9), "coarse", &coarse, k()).unwrap();
        let mut eqs = equations(&rel1);
        for (j, p) in rel2.cells.iter().enumerate() {
            if let Published::Value(v) = p {
                eqs.push((lines[j].clone(), *v));
            }
        }
        if let Published::Value(t) = rel2.grand_total {
            eqs.push(((0..r * c).collect(), t));
        }
        // Prior knowledge from the second release's suppression pattern
        // (unless it is the value-independent "everything hidden" pattern).
        let hidden = |p: &Published| !matches!(p, Published::Value(_));
        let blind = rel2.cells.iter().all(hidden)
            && hidden(&rel2.grand_total)
            && rel2.row_totals.iter().all(hidden)
            && rel2.col_totals.iter().all(hidden);
        let mut ranges = Vec::new();
        if !blind {
            for (j, p) in rel2.cells.iter().enumerate() {
                if *p == Published::Suppressed {
                    let v: u64 = lines[j].iter().map(|&i| vals[i]).sum();
                    ranges.push(if v < 10 { (lines[j].clone(), 0, 9) } else { (lines[j].clone(), 10, u64::MAX / 4) });
                }
            }
        }
        prop_assert!(exposed_with(r * c, vals, &eqs, &ranges).is_empty(), "{:?} {:?} {:?}", vals, rel1, rel2);
    }
}

// AUD-RM1-LOG-22 regression: with priors on sums the LP relaxation can be
// wider than what an integer attacker can rule out. Two "triangles" of
// pair-sum priors (each pair ≤ 1): the LP lets the six-cell total reach 3
// (all cells 1/2), but integer cells give at most 2. With width 3 the old
// LP audit passed; the integer audit must flag it.
#[test]
fn integer_attacker_narrower_than_lp_is_caught() {
    use std::collections::BTreeSet;
    let c = |n: u8| MicroKey([n; 16], 0);
    let pair = |a: u8, b: u8| Prior {
        members: BTreeSet::from([c(a), c(b)]),
        lo: 0,
        hi: Some(1),
    };
    let priors = vec![
        pair(1, 2),
        pair(2, 3),
        pair(1, 3),
        pair(4, 5),
        pair(5, 6),
        pair(4, 6),
    ];
    let total: BTreeSet<MicroKey> = (1..=6).map(c).collect();
    assert!(!audit(&[], &priors, std::slice::from_ref(&total), 3));
    assert!(audit(&[], &priors, std::slice::from_ref(&total), 2));
    // One triangle alone: LP max 1.5, integer max 1.
    let tri: BTreeSet<MicroKey> = (1..=3).map(c).collect();
    assert!(audit(&[], &priors, std::slice::from_ref(&tri), 1));
    assert!(!audit(&[], &priors, &[tri], 2));
}
