// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process hardening (07 §4.4, BE-003; R7 SI-A-05, SI-B-03), with safe wrappers
//! only (`unsafe_code` is forbidden workspace-wide):
//!
//! * `prctl(PR_SET_DUMPABLE, 0)` — no core dumps, no same-UID ptrace or
//!   `/proc/<pid>/mem` access (`rustix::process::set_dumpable_behavior`);
//! * `RLIMIT_CORE = 0` (`rustix::process::setrlimit`);
//! * `mlockall(MCL_CURRENT | MCL_FUTURE)` — nothing is swapped
//!   (`rustix::mm::mlockall`; needs `LimitMEMLOCK`);
//! * Landlock — filesystem access only beneath the staging root, and (ABI ≥ 4)
//!   no TCP bind/connect (`landlock` crate).
//!
//! Not possible without `unsafe` in this crate and therefore delegated to
//! systemd (see README): `madvise(MADV_DONTDUMP | MADV_WIPEONFORK)` on secret
//! arenas, and the seccomp allow-list of 07 §4.3 (`SystemCallFilter=`). Call
//! [`harden_process`] on the main thread **before** the tokio runtime starts, so
//! every runtime thread inherits the Landlock domain; refuse to start on error.

use std::path::Path;

/// Which hardening step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningError {
    /// `PR_SET_DUMPABLE` failed.
    Dumpable,
    /// `RLIMIT_CORE` failed.
    CoreLimit,
    /// `mlockall` failed (raise `LimitMEMLOCK`).
    Mlock,
    /// Landlock could not be applied at the required level.
    Landlock,
}

impl core::fmt::Display for HardeningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Dumpable => "PR_SET_DUMPABLE failed",
            Self::CoreLimit => "RLIMIT_CORE failed",
            Self::Mlock => "mlockall failed",
            Self::Landlock => "Landlock restriction failed",
        })
    }
}

impl std::error::Error for HardeningError {}

/// How strictly Landlock must apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockLevel {
    /// Do not apply Landlock (tests only).
    Off,
    /// Apply what the kernel supports; succeed even if not enforced (dev).
    BestEffort,
    /// Require full enforcement (production).
    Required,
}

/// Disable core dumps and ptrace-ability: `PR_SET_DUMPABLE = 0`, `RLIMIT_CORE = 0`.
pub fn disable_core_dumps() -> Result<(), HardeningError> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| HardeningError::Dumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| HardeningError::CoreLimit)
}

/// Lock all current and future pages in RAM (no swap).
pub fn lock_memory() -> Result<(), HardeningError> {
    use rustix::mm::{MlockAllFlags, mlockall};
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_err(|_| HardeningError::Mlock)
}

/// Restrict the calling thread (and threads it creates afterwards) to the
/// staging root with Landlock. Returns whether the ruleset is fully enforced.
pub fn restrict_filesystem(staging: &Path, level: LandlockLevel) -> Result<bool, HardeningError> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
    };
    if level == LandlockLevel::Off {
        return Ok(false);
    }
    let abi = ABI::V4;
    let compat = match level {
        LandlockLevel::Required => CompatLevel::HardRequirement,
        _ => CompatLevel::BestEffort,
    };
    let status = Ruleset::default()
        .set_compatibility(compat)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules([staging], AccessFs::from_all(abi))))
        .and_then(|r| r.restrict_self())
        .map_err(|_| HardeningError::Landlock)?;
    let full = status.ruleset == RulesetStatus::FullyEnforced;
    if level == LandlockLevel::Required && !full {
        return Err(HardeningError::Landlock);
    }
    Ok(full)
}

/// Apply all in-process hardening in order: no dumps, memory locked, Landlock.
pub fn harden_process(staging: &Path, landlock: LandlockLevel) -> Result<bool, HardeningError> {
    disable_core_dumps()?;
    lock_memory()?;
    restrict_filesystem(staging, landlock)
}
