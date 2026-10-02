// SPDX-License-Identifier: AGPL-3.0-or-later
// AUD-RM1-LOG-03: registry codes come from constants only; counters,
// sequence numbers and timers have no public raw constructors.
use candor_log::codes::{Code, ConfigKey};
use candor_log::field::{Count, Seq, StaffTimer};
use candor_log::ids::UtcMillis;

fn main() {
    let port: u16 = std::env::args().count() as u16;
    let _a = Code::<ConfigKey>::new(port);
    let _b = Code::<ConfigKey>::of::<port>();
    let _c = Count(4096);
    let _d = Seq(1);
    let _e = StaffTimer(UtcMillis(1));
}
