// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `candor-safe-read` - race-free input reader for config-check (AUD-RM2-DEP-24/26).
//!
//! ```text
//! candor-safe-read ABS-PATH OUT MAX-BYTES OWNERS DENY-MODE   3< WORK-DIR
//!     copy one input to OUT; the exit status is the result (0, 10..15, 2)
//! candor-safe-read --md5 OUT MAX-BYTES OWNERS DENY-MODE ABS-PATH...   3< WORK-DIR
//!     write one line per path to OUT: "OK <md5 hex>" or "ERR <status>"
//! ```
//! OUT is a relative name beneath the private (no group/other bits) work directory open on
//! fd 3; it must not exist yet (O_EXCL|O_NOFOLLOW|O_NONBLOCK, openat2 BENEATH|NO_SYMLINKS;
//! AUD-RM2-DEP-30). The tool prints nothing at all (no stdout/stderr; LOG-001): results are
//! the exit status and the OUT file (0600). No path or content is ever echoed.

use candor_safe_read::{Policy, Status, copy, out_dir_from_fd3, write_md5_report};
use std::process::ExitCode;

fn run(args: &[String]) -> Status {
    let result = match args {
        [flag, out, max, owners, deny, paths @ ..] if flag == "--md5" => {
            Policy::parse(max, owners, deny)
                .and_then(|p| out_dir_from_fd3().and_then(|d| write_md5_report(&d, out, paths, &p)))
        }
        [path, out, max, owners, deny] => Policy::parse(max, owners, deny)
            .and_then(|p| out_dir_from_fd3().and_then(|d| copy(path, &d, out, &p))),
        _ => Err(Status::Usage),
    };
    match result {
        Ok(()) => Status::Ok,
        Err(s) => s,
    }
}

fn main() -> ExitCode {
    // Non-UTF-8 arguments are a usage error (config-check never passes them).
    let args: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().ok())
        .collect();
    let st = match args {
        Some(a) => run(&a),
        None => Status::Usage,
    };
    ExitCode::from(st.code())
}
