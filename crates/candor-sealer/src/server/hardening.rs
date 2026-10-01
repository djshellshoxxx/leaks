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
//!
//! **Enforced (ADR-052(5), AUD-RM2-SEA-06).** [`crate::server::Sealer::serve`]
//! runs [`self_check`] before accepting the first connection and refuses to
//! serve unless [`harden_process`] succeeded with Landlock fully enforced and the
//! process is still non-dumpable with `RLIMIT_CORE = 0`. The only bypass is an
//! [`InsecureDevMode`] token, which can be obtained only by emitting a typed
//! `candor-log` event ([`InsecureDevMode::acknowledge`]).

use std::path::Path;
use std::sync::OnceLock;

/// What [`harden_process`] achieved (recorded once per process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` applied.
    pub core_dumps_disabled: bool,
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` applied.
    pub memory_locked: bool,
    /// Landlock ruleset fully enforced.
    pub landlock_enforced: bool,
}

static REPORT: OnceLock<HardeningReport> = OnceLock::new();

/// The recorded hardening state, if [`harden_process`] succeeded.
#[must_use]
pub fn report() -> Option<HardeningReport> {
    REPORT.get().copied()
}

/// Start-up self-check (07 BE-003, ADR-052(5)): hardening was applied by
/// [`harden_process`] with Landlock fully enforced, and the process is (still)
/// non-dumpable with a zero core limit.
pub fn self_check() -> Result<HardeningReport, HardeningError> {
    use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};
    let r = report().ok_or(HardeningError::NotApplied)?;
    if !r.core_dumps_disabled || !r.memory_locked {
        return Err(HardeningError::NotApplied);
    }
    if !r.landlock_enforced {
        return Err(HardeningError::Landlock);
    }
    if dumpable_behavior().map_err(|_| HardeningError::Dumpable)? != DumpableBehavior::NotDumpable {
        return Err(HardeningError::Dumpable);
    }
    let core = getrlimit(Resource::Core);
    if core.current != Some(0) || core.maximum != Some(0) {
        return Err(HardeningError::CoreLimit);
    }
    Ok(r)
}

/// Explicit developer override: run without enforced hardening (and with
/// test-only configuration such as disabled chaff or a same-UID peer). Never
/// used in production; obtaining it always leaves a typed audit record.
#[derive(Clone)]
pub struct InsecureDevMode {
    _private: (),
}

impl core::fmt::Debug for InsecureDevMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InsecureDevMode")
    }
}

impl InsecureDevMode {
    /// Emit the typed `sys.health` event (service `upload`, status `DEGRADED`,
    /// check `READINESS`; candor-log has no sealer service code yet, see
    /// SPEC-NOTES) and return the token only if the event was accepted.
    pub fn acknowledge<S, C>(log: &mut candor_log::AuditLog<S, C>) -> Result<Self, HardeningError>
    where
        S: candor_log::chain::CheckpointSigner,
        C: candor_log::chain::AuditClock,
    {
        use candor_log::codes::{HealthCheck, HealthStatus, Service};
        log.emit(
            candor_log::EventContext::system(Service::Upload),
            candor_log::AuditEvent::SysHealth {
                service: Service::Upload,
                status: HealthStatus::Degraded,
                check_code: HealthCheck::Readiness,
            },
        )
        .map_err(|_| HardeningError::DevFlagNotLogged)?;
        Ok(Self { _private: () })
    }
}

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
    /// [`harden_process`] has not (successfully) run in this process.
    NotApplied,
    /// The configured peer UID is 0 or the sealer's own UID.
    PeerUid,
    /// The developer override could not be audit-logged.
    DevFlagNotLogged,
}

impl core::fmt::Display for HardeningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Dumpable => "PR_SET_DUMPABLE failed",
            Self::CoreLimit => "RLIMIT_CORE failed",
            Self::Mlock => "mlockall failed",
            Self::Landlock => "Landlock restriction failed",
            Self::NotApplied => "process hardening not applied",
            Self::PeerUid => "peer UID must not be root or the sealer's own UID",
            Self::DevFlagNotLogged => "insecure developer mode could not be audit-logged",
        })
    }
}

impl std::error::Error for HardeningError {}

/// How strictly Landlock must apply. Anything but `Required` makes
/// [`self_check`] fail, so the sealer will not serve without [`InsecureDevMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockLevel {
    /// Do not apply Landlock (development only).
    Off,
    /// Apply what the kernel supports; succeed even if not enforced (development).
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
/// The result is recorded for [`self_check`] (first successful call only).
pub fn harden_process(staging: &Path, landlock: LandlockLevel) -> Result<bool, HardeningError> {
    disable_core_dumps()?;
    lock_memory()?;
    let full = restrict_filesystem(staging, landlock)?;
    let _ = REPORT.set(HardeningReport {
        core_dumps_disabled: true,
        memory_locked: true,
        landlock_enforced: full,
    });
    Ok(full)
}

/// SEA-18: the peer must be a distinct, unprivileged UID.
pub(crate) fn check_peer_uid(peer: u32) -> Result<(), HardeningError> {
    let own = rustix::process::getuid().as_raw();
    if peer == 0 || peer == own {
        return Err(HardeningError::PeerUid);
    }
    Ok(())
}
