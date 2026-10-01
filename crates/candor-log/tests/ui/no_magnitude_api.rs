// SPDX-License-Identifier: AGPL-3.0-or-later
// AUD-RM1-LOG-18: no magnitude statistics (mean/median/percentile/ratio)
// can be released; only k-thresholded counts exist in the API.
use candor_log::ids::MonthStamp;
use candor_log::metrics::{KThreshold, Magnitude, MemoryReleaseHistory, MicroKey, PeriodRegistry};

fn main() {
    let mut r = PeriodRegistry::new(MemoryReleaseHistory::new());
    let p = MonthStamp::new(2026, 9).unwrap();
    let c = MonthStamp::new(2026, 10).unwrap();
    let pop = [(MicroKey([1; 16], 0), 2027u64)];
    let _ = r.release_magnitude(p, c, "a", Magnitude::Mean, &pop, KThreshold::DEFAULT);
    let _ = r.release_ratio(p, c, "b", 10, 20, KThreshold::DEFAULT);
}
