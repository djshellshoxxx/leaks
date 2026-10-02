// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-process hardening of the web process (07 §4.1, §4.4; IMPL-00 §9;
//! ADR-052(5); IMPL-RM2 §2.2), with safe wrappers only (`unsafe_code` is
//! forbidden workspace-wide):
//!
//! * `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0`: no core dumps, no
//!   same-UID ptrace or `/proc/<pid>/mem` (request buffers hold source text);
//! * `mlockall(MCL_CURRENT | MCL_FUTURE)`: request buffers never reach swap
//!   (07 §4.1 "mlockall of heap"; the unit sets `LimitMEMLOCK=1G`);
//! * Landlock: **no** filesystem access at all (the web reads and writes no
//!   file after start), no TCP bind/connect (ABI ≥ 4), and scoping of
//!   abstract Unix sockets and signals (ABI 6). Connecting to the sealer's
//!   *pathname* socket is not a Landlock-controlled access and keeps working;
//!   the listening socket is inherited from systemd before hardening.
//!
//! Call [`harden_process`] on the main thread before the tokio runtime is
//! built, so every runtime thread inherits the Landlock domain, and refuse to
//! start on error. seccomp is applied by systemd (`SystemCallFilter=`, see
//! SPEC-NOTES "Required privileges"), because an in-process filter needs
//! `unsafe` or a new dependency.

/// How strictly Landlock must apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockLevel {
    /// Full enforcement at ABI 6 or refuse (production, IMPL-RM2 §2.2).
    Required,
    /// Apply what the kernel supports (development and CI kernels only).
    BestEffort,
}

/// What [`harden_process`] achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` applied.
    pub core_dumps_disabled: bool,
    /// `mlockall` applied.
    pub memory_locked: bool,
    /// Landlock fully enforced at the requested ABI.
    pub landlock_enforced: bool,
}

/// Hardening failure (start must be refused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningError {
    /// Not called on the main thread outside a runtime.
    NotMainThread,
    /// `PR_SET_DUMPABLE` failed.
    Dumpable,
    /// `RLIMIT_CORE` failed.
    CoreLimit,
    /// `mlockall` failed (check `LimitMEMLOCK`).
    Mlock,
    /// Landlock not (fully) enforced.
    Landlock,
}

impl core::fmt::Display for HardeningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotMainThread => "hardening must run on the main thread before the runtime",
            Self::Dumpable => "PR_SET_DUMPABLE failed",
            Self::CoreLimit => "RLIMIT_CORE failed",
            Self::Mlock => "mlockall failed",
            Self::Landlock => "Landlock not enforced",
        })
    }
}

impl std::error::Error for HardeningError {}

fn disable_core_dumps() -> Result<(), HardeningError> {
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

fn lock_memory() -> Result<(), HardeningError> {
    use rustix::mm::{MlockAllFlags, mlockall};
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_err(|_| HardeningError::Mlock)
}

fn landlock(level: LandlockLevel) -> Result<bool, HardeningError> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
        RulesetStatus, Scope,
    };
    let abi = ABI::V6;
    let compat = match level {
        LandlockLevel::Required => CompatLevel::HardRequirement,
        LandlockLevel::BestEffort => CompatLevel::BestEffort,
    };
    // No rule is added: every handled filesystem and network access is denied.
    let status = Ruleset::default()
        .set_compatibility(compat)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.scope(Scope::from_all(abi)))
        .and_then(landlock::Ruleset::create)
        .and_then(|r| r.restrict_self())
        .map_err(|_| HardeningError::Landlock)?;
    let full = status.ruleset == RulesetStatus::FullyEnforced;
    if level == LandlockLevel::Required && !full {
        return Err(HardeningError::Landlock);
    }
    Ok(full)
}

fn on_main_thread() -> bool {
    rustix::thread::gettid() == rustix::process::getpid()
        && tokio::runtime::Handle::try_current().is_err()
}

/// Apply all in-process hardening in order: no dumps, memory locked,
/// Landlock. Must run on the main thread before any runtime or helper thread
/// exists. With [`LandlockLevel::Required`] any shortfall is an error.
pub fn harden_process(level: LandlockLevel) -> Result<HardeningReport, HardeningError> {
    if !on_main_thread() {
        return Err(HardeningError::NotMainThread);
    }
    disable_core_dumps()?;
    lock_memory()?;
    let landlock_enforced = landlock(level)?;
    Ok(HardeningReport {
        core_dumps_disabled: true,
        memory_locked: true,
        landlock_enforced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off the main thread (the unit-test harness thread) it refuses before
    /// changing anything.
    #[test]
    fn refuses_off_the_main_thread() {
        let r = std::thread::spawn(|| harden_process(LandlockLevel::BestEffort))
            .join()
            .ok();
        assert_eq!(r, Some(Err(HardeningError::NotMainThread)));
    }
}
