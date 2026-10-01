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

use std::collections::{BTreeMap, BTreeSet};

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
        cells.push(TableCell { value: *v, members: vec![key] });
    }
    Table { rows, cols, cells, micro, protected: vec![] }
}

/// Independent brute-force attacker: enumerates every non-negative integer
/// completion of the suppressed cells consistent with the published cells
/// and totals, and returns the suppressed cells whose value is pinned.
fn pinned_cells(rel: &Released) -> Vec<usize> {
    let (r, c) = (rel.rows, rel.cols);
    let sup: Vec<usize> = (0..r * c).filter(|&i| rel.cells[i] == Published::Suppressed).collect();
    let known = |i: usize| match rel.cells[i] {
        Published::Value(v) => Some(v),
        _ => None,
    };
    // Equations: (cell indices, total).
    let mut eqs: Vec<(Vec<usize>, u64)> = Vec::new();
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
    let bound = |cell: usize| -> Option<u64> {
        eqs.iter().filter(|(e, _)| e.contains(&cell)).map(|(_, t)| *t).min()
    };
    // Cells in no equation are free (never pinned).
    let constrained: Vec<usize> = sup.iter().copied().filter(|&i| bound(i).is_some()).collect();
    let mut seen: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
    let mut assign: BTreeMap<usize, u64> = BTreeMap::new();
    fn rec(
        idx: usize,
        cells: &[usize],
        assign: &mut BTreeMap<usize, u64>,
        eqs: &[(Vec<usize>, u64)],
        known: &dyn Fn(usize) -> Option<u64>,
        bound: &dyn Fn(usize) -> Option<u64>,
        seen: &mut BTreeMap<usize, BTreeSet<u64>>,
    ) {
        // Prune: partial sums must not exceed totals; complete lines must match.
        for (e, t) in eqs {
            let mut s = 0u64;
            let mut complete = true;
            for &i in e {
                if let Some(v) = known(i).or_else(|| assign.get(&i).copied()) {
                    s += v;
                } else {
                    complete = false;
                }
            }
            if s > *t || (complete && s != *t) {
                return;
            }
        }
        if idx == cells.len() {
            for (&i, &v) in assign.iter() {
                seen.entry(i).or_default().insert(v);
            }
            return;
        }
        let cell = cells[idx];
        for v in 0..=bound(cell).unwrap_or(0) {
            assign.insert(cell, v);
            rec(idx + 1, cells, assign, eqs, known, bound, seen);
            assign.remove(&cell);
            // Early exit: everything already shown ambiguous.
            if cells.iter().all(|c| seen.get(c).is_some_and(|s| s.len() >= 2)) {
                return;
            }
        }
    }
    rec(0, &constrained, &mut assign, &eqs, &known, &bound, &mut seen);
    constrained
        .into_iter()
        .filter(|i| seen.get(i).is_none_or(|s| s.len() < 2))
        .collect()
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
    assert_eq!(rel.cells[0].display(), "0\u{2013}9");
    let rel = suppress(&simple(1, 1, &[14]), k()).unwrap();
    assert_eq!(rel.cells[0], Published::Value(14));
}

#[test]
fn complementary_suppression_row_with_one_small_cell() {
    // 24 §9.3: a row with exactly one primary-suppressed cell gets the
    // next-smallest non-zero cell suppressed too.
    let t = simple(2, 3, &[3, 20, 30, 15, 25, 40]);
    let rel = suppress(&t, k()).unwrap();
    assert_eq!(rel.cells[0], Published::Suppressed);
    assert_eq!(rel.cells[1], Published::Suppressed, "next-smallest in row 0");
    assert!(pinned_cells(&rel).is_empty(), "{rel:?}");
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
    assert!(pinned_cells(&rel).is_empty(), "{rel:?}");
    assert_eq!(rel.cells[0], Published::Suppressed);
    assert_eq!(rel.cells[1], Published::Suppressed);
}

#[test]
fn no_small_cell_derivable_two_by_two_rectangle() {
    // Classic: suppressing a 2×2 rectangle with all marginals published is
    // ambiguous linearly, but non-negativity can pin it.
    let t = simple(2, 2, &[0, 11, 12, 13]);
    let rel = suppress(&t, k()).unwrap();
    assert!(pinned_cells(&rel).is_empty(), "{rel:?}");
}

// 24 §9.5 "Differencing (filters)": totals with and without one channel.
#[test]
fn differencing_attack_across_reports_is_blocked() {
    let c = |n: u8| MicroKey([n; 16], 0);
    let micro = BTreeMap::from([(c(1), 12), (c(2), 13), (c(3), 4)]);
    let all = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell { value: 29, members: vec![c(1), c(2), c(3)] }],
        micro: micro.clone(),
        protected: vec![],
    };
    let without3 = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell { value: 25, members: vec![c(1), c(2)] }],
        micro: micro.clone(),
        protected: vec![],
    };
    // In isolation each table looks safe: the attack is real.
    assert_eq!(suppress(&all, k()).unwrap().cells[0], Published::Value(29));
    assert_eq!(suppress(&without3, k()).unwrap().cells[0], Published::Value(25));
    // Through the period registry, the second release cannot complete the
    // subtraction 29 − 25 = 4.
    let mut reg = PeriodRegistry::new();
    let a = reg.release(m(2026, 8), m(2026, 10), "report.all", &all, k()).unwrap();
    let b = reg.release(m(2026, 8), m(2026, 10), "report.without3", &without3, k()).unwrap();
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
            TableCell { value: 12, members: vec![key(1)] },
            TableCell { value: 4, members: vec![key(2)] },
            TableCell { value: 15, members: vec![key(3)] },
        ],
        micro: micro.clone(),
        protected: vec![],
    };
    // Report 2: the grand total alone.
    let total = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell { value: 31, members: vec![key(1), key(2), key(3)] }],
        micro,
        protected: vec![],
    };
    let mut reg = PeriodRegistry::new();
    let r1 = reg.release(m(2026, 8), m(2026, 9), "by_channel", &by_channel, k()).unwrap();
    let r2 = reg.release(m(2026, 8), m(2026, 9), "total", &total, k()).unwrap();
    // c2 must stay hidden: 31 − 12 − 15 would reveal it.
    assert_eq!(r1.cells[1], Published::Suppressed);
    let published_sum: u64 = r1
        .cells
        .iter()
        .filter_map(|p| if let Published::Value(v) = p { Some(*v) } else { None })
        .sum();
    if let Published::Value(t) = r2.cells[0] {
        assert!(t - published_sum >= 10 || published_sum < 27, "c2 derivable");
        // The only way t is published is if published cells exclude ≥ 2 values.
        let hidden = r1.cells.iter().filter(|p| **p == Published::Suppressed).count();
        assert!(hidden >= 2);
    }
}

// 24 §9.5 "Differencing (windows)" and "Rolling/cumulative displays".
#[test]
fn tumbling_frozen_periods() {
    let mut reg = PeriodRegistry::new();
    let t = simple(1, 1, &[40]);
    // No month-to-date figures.
    assert_eq!(
        reg.release(m(2026, 10), m(2026, 10), "r", &t, k()).unwrap_err(),
        ReleaseError::PeriodNotClosed
    );
    reg.release(m(2026, 9), m(2026, 10), "r", &t, k()).unwrap();
    // Frozen: no revision of a released period.
    let t2 = simple(1, 1, &[41]);
    assert_eq!(
        reg.release(m(2026, 9), m(2026, 11), "r", &t2, k()).unwrap_err(),
        ReleaseError::AlreadyReleased
    );
}

// LOG-011: counters only per month, current + previous; raw values leave
// memory when released; before/after one submission across periods.
#[test]
fn counter_aggregation_and_release() {
    let ch: Vec<ChannelId> = (1..=4).map(|n| ChannelId::from_bytes([n; 16])).collect();
    let mut agg = CounterAggregator::new(m(2026, 9));
    let sub = IntakeCounter::Submissions;
    for _ in 0..14 {
        agg.increment(m(2026, 9), ch[0], sub).unwrap();
        agg.increment(m(2026, 9), ch[0], IntakeCounter::AccountsCreated).unwrap();
    }
    for _ in 0..12 {
        agg.increment(m(2026, 9), ch[1], sub).unwrap();
        agg.increment(m(2026, 9), ch[1], IntakeCounter::AccountsCreated).unwrap();
    }
    // ch[2]: 2 submissions (< 3 cases → folded); ch[3]: 20 but population < 50.
    for _ in 0..2 {
        agg.increment(m(2026, 9), ch[2], sub).unwrap();
    }
    for _ in 0..20 {
        agg.increment(m(2026, 9), ch[3], sub).unwrap();
    }
    // The open month cannot be taken (no month-to-date).
    assert_eq!(agg.take_closed(m(2026, 9)).unwrap_err(), CounterError::NotClosed);
    agg.increment(m(2026, 10), ch[0], sub).unwrap();
    // Stale months are rejected.
    assert_eq!(agg.increment(m(2026, 8), ch[0], sub).unwrap_err(), CounterError::StaleMonth);
    let closed = agg.take_closed(m(2026, 9)).unwrap();
    // Taken once: raw values are gone.
    assert!(agg.take_closed(m(2026, 9)).is_err());
    assert!(!format!("{closed:?}").contains("14"));

    let pop = BTreeMap::from([(ch[0], 500), (ch[1], 500), (ch[2], 500), (ch[3], 20)]);
    let groups = ChannelGroups::new(vec![vec![ch[0], ch[1]], vec![ch[2], ch[3]]], pop).unwrap();
    let mut reg = PeriodRegistry::new();
    let rep = release_counters(closed, &groups, &mut reg, m(2026, 10), k()).unwrap();
    // ch[2], ch[3] folded into group 1; ch[0], ch[1] shown individually.
    assert_eq!(
        rep.rows,
        vec![RowLabel::Channel(ch[0]), RowLabel::Channel(ch[1]), RowLabel::Group(1)]
    );
    // Group row is [22, 0, 0]: its two zero cells sum to 0 < k, so the row
    // total would reveal them; complementary suppression hides the 22 too.
    assert_eq!(rep.table.cells[6], Published::Suppressed);
    assert_eq!(rep.table.cells[7], Published::Suppressed);
    assert_eq!(rep.table.cells[2], Published::Suppressed);
    assert!(pinned_cells(&rep.table).is_empty(), "{:?}", rep.table);
}

#[test]
fn group_with_one_folded_channel_absorbs_another() {
    let ch: Vec<ChannelId> = (1..=3).map(|n| ChannelId::from_bytes([n; 16])).collect();
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
    assert!(ChannelGroups::new(vec![vec![ch[0], ch[1]], vec![ch[1], ch[2]]], BTreeMap::new()).is_err());
    // Channels outside any group are refused.
    let lone = ClosedMonth::from_counts(m(2026, 9), [((ChannelId::from_bytes([9; 16]), IntakeCounter::Submissions), 50)]);
    assert!(counter_table(&lone, &groups).is_err());
}

#[test]
fn folded_channel_not_recoverable_from_second_report() {
    // A later report showing the group's other channel individually must not
    // reveal the folded small channel by subtraction.
    let ch: Vec<ChannelId> = (1..=2).map(|n| ChannelId::from_bytes([n; 16])).collect();
    let pop = BTreeMap::from([(ch[0], 500), (ch[1], 10)]);
    let groups = ChannelGroups::new(vec![ch.clone()], pop).unwrap();
    let closed = ClosedMonth::from_counts(
        m(2026, 9),
        [((ch[0], IntakeCounter::Submissions), 40), ((ch[1], IntakeCounter::Submissions), 12)],
    );
    let mut reg = PeriodRegistry::new();
    let rep = release_counters(closed, &groups, &mut reg, m(2026, 10), k()).unwrap();
    assert_eq!(rep.rows, vec![RowLabel::Group(0)]);
    // Attacker-chosen second table: ch[0] alone.
    let single = Table {
        rows: 1,
        cols: 1,
        cells: vec![TableCell { value: 40, members: vec![MicroKey(*ch[0].as_bytes(), 0)] }],
        micro: BTreeMap::from([(MicroKey(*ch[0].as_bytes(), 0), 40)]),
        protected: vec![],
    };
    let r = reg.release(m(2026, 9), m(2026, 10), "single", &single, k()).unwrap();
    assert_eq!(r.cells[0], Published::Suppressed);
}

#[test]
fn scalar_coi_exhausted_release() {
    let mut reg = PeriodRegistry::new();
    assert_eq!(
        release_scalar(&mut reg, m(2026, 9), m(2026, 10), "coi_exhausted", 3, k()).unwrap(),
        Published::Suppressed
    );
    assert_eq!(
        release_scalar(&mut reg, m(2026, 8), m(2026, 10), "coi_exhausted", 11, k()).unwrap(),
        Published::Value(11)
    );
}

// TEL-015 magnitude statistics.
#[test]
fn magnitude_rules() {
    let nine: Vec<u64> = (1..=9).collect();
    let ten: Vec<u64> = (1..=10).collect();
    assert_eq!(median(&nine, k()), None);
    assert_eq!(median(&ten, k()), Some(5));
    assert_eq!(percentile(&ten, 90, k()), Some(9));
    assert_eq!(mean(&nine, k()), None);
    assert_eq!(mean(&ten, k()), Some(5));
    assert_eq!(median_duration_weeks(&[10; 9], k()), None);
    assert_eq!(median_duration_weeks(&[10; 10], k()), Some(1));
    assert_eq!(median_duration_weeks(&[11; 10], k()), Some(2));
    // Ratios: denominator ≥ k, numerator ∉ {0, denominator}.
    assert_eq!(ratio_permille(1, 1, k()), None);
    assert_eq!(ratio_permille(3, 9, k()), None);
    assert_eq!(ratio_permille(0, 20, k()), None);
    assert_eq!(ratio_permille(20, 20, k()), None);
    assert_eq!(ratio_permille(5, 20, k()), Some(250));
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
    #![proptest_config(ProptestConfig::with_cases(512))]

    // stats-inference (24 §9.6): for random small tables no suppressed cell
    // is pinned by any completion-based attacker, and every published cell
    // is ≥ k.
    #[test]
    fn no_suppressed_cell_is_derivable(
        shape in prop_oneof![Just((1usize, 3usize)), Just((2, 2)), Just((2, 3)), Just((3, 2)), Just((3, 3))],
        vals in proptest::collection::vec(prop_oneof![0u64..10, 10u64..18], 9),
    ) {
        let (r, c) = shape;
        let t = simple(r, c, &vals[..r * c]);
        let rel = suppress(&t, k()).unwrap();
        for p in &rel.cells {
            if let Published::Value(v) = p {
                prop_assert!(*v >= 10);
            }
        }
        for (i, v) in vals[..r * c].iter().enumerate() {
            if *v < 10 {
                prop_assert_eq!(rel.cells[i], Published::Suppressed);
            }
        }
        prop_assert!(pinned_cells(&rel).is_empty(), "{:?} {:?}", vals, rel);
    }
}
