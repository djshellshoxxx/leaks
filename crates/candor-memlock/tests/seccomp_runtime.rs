// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-DEP-33 regression: a tokio multi-thread runtime built with the `signal` feature
//! (the sealer's configuration; feature unification gives it to every daemon binary) must
//! start under each daemon's exact deploy allow-set. The sets are read from the release
//! baseline (`deploy/tools/config-check.baseline`, kinds `scf|`, `scf-web|`, `scf-store|`),
//! turned into a seccomp filter (`SystemCallErrorNumber=EPERM` semantics: every call outside
//! the set fails with `EPERM`) and applied to a fresh thread, which then builds and uses the
//! runtime. A control run with `socketpair` removed must fail, proving the filter bites.
//!
//! x86_64 only: syscall numbers come from `libc::SYS_*` of this target; names that exist
//! only on other ABIs (`mmap2`, `*_time64`, `*32`, `riscv_hwprobe`, ...) are skipped.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

const BASELINE: &str = include_str!("../../../deploy/tools/config-check.baseline");

/// Syscalls the daemons need before and while the runtime starts (the "too narrow" direction).
const STARTUP_REQUIRED: &[&str] = &[
    "socketpair",
    "eventfd2",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "clone3",
    "clone",
    "mmap",
    "mprotect",
    "munmap",
    "futex",
    "rseq",
    "prlimit64",
    "mlockall",
    "prctl",
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    "getrandom",
    "sched_getaffinity",
    "rt_sigaction",
    "rt_sigprocmask",
    "sigaltstack",
    "set_robust_list",
];

macro_rules! table {
    ($($n:ident),* $(,)?) => { &[ $( (stringify!($n), libc::$n as i64) ),* ] };
}

/// name -> number for every allow-set member that exists on x86_64 Linux.
fn number(name: &str) -> Option<i64> {
    const T: &[(&str, i64)] = table![
        SYS_read,
        SYS_write,
        SYS_readv,
        SYS_writev,
        SYS_pread64,
        SYS_pwrite64,
        SYS_preadv,
        SYS_pwritev,
        SYS_lseek,
        SYS_recvmsg,
        SYS_sendmsg,
        SYS_recvfrom,
        SYS_sendto,
        SYS_accept,
        SYS_accept4,
        SYS_socket,
        SYS_socketpair,
        SYS_connect,
        SYS_getsockopt,
        SYS_setsockopt,
        SYS_getsockname,
        SYS_getpeername,
        SYS_shutdown,
        SYS_close,
        SYS_close_range,
        SYS_fcntl,
        SYS_ioctl,
        SYS_memfd_create,
        SYS_dup,
        SYS_dup3,
        SYS_epoll_create,
        SYS_epoll_create1,
        SYS_epoll_ctl,
        SYS_epoll_wait,
        SYS_epoll_pwait,
        SYS_epoll_pwait2,
        SYS_eventfd2,
        SYS_poll,
        SYS_ppoll,
        SYS_futex,
        SYS_futex_waitv,
        SYS_mmap,
        SYS_munmap,
        SYS_mremap,
        SYS_madvise,
        SYS_mprotect,
        SYS_brk,
        SYS_mlock,
        SYS_mlock2,
        SYS_mlockall,
        SYS_munlock,
        SYS_membarrier,
        SYS_rt_sigreturn,
        SYS_rt_sigprocmask,
        SYS_rt_sigaction,
        SYS_sigaltstack,
        SYS_tgkill,
        SYS_tkill,
        SYS_getpid,
        SYS_gettid,
        SYS_clock_gettime,
        SYS_clock_getres,
        SYS_clock_nanosleep,
        SYS_nanosleep,
        SYS_gettimeofday,
        SYS_time,
        SYS_getrandom,
        SYS_exit,
        SYS_exit_group,
        SYS_restart_syscall,
        SYS_sched_yield,
        SYS_sched_getaffinity,
        SYS_clone,
        SYS_clone3,
        SYS_set_robust_list,
        SYS_get_robust_list,
        SYS_rseq,
        SYS_set_tid_address,
        SYS_arch_prctl,
        SYS_execve,
        SYS_prctl,
        SYS_prlimit64,
        SYS_getrlimit,
        SYS_fstat,
        SYS_newfstatat,
        SYS_statx,
        SYS_fstatfs,
        SYS_openat,
        SYS_openat2,
        SYS_unlinkat,
        SYS_renameat2,
        SYS_linkat,
        SYS_mkdirat,
        SYS_fsync,
        SYS_fdatasync,
        SYS_fchmod,
        SYS_fchmodat,
        SYS_utimensat,
        SYS_getdents64,
        SYS_readlinkat,
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_uname,
        SYS_sysinfo,
        SYS_access,
        SYS_faccessat,
        SYS_faccessat2,
        SYS_landlock_create_ruleset,
        SYS_landlock_add_rule,
        SYS_landlock_restrict_self,
        SYS_seccomp,
    ];
    let key = format!("SYS_{name}");
    T.iter().find(|(n, _)| *n == key).map(|(_, v)| *v)
}

fn allow_set(kind: &str) -> BTreeSet<String> {
    let prefix = format!("{kind}|");
    let set: BTreeSet<String> = BASELINE
        .lines()
        .filter_map(|l| l.strip_prefix(&prefix))
        .map(str::to_owned)
        .collect();
    assert!(set.len() > 100, "baseline kind {kind} missing or truncated");
    for need in STARTUP_REQUIRED {
        assert!(
            set.contains(*need),
            "{kind}: start-up syscall {need} is not in the allow-set"
        );
    }
    set
}

fn never_list() -> BTreeSet<String> {
    BASELINE
        .lines()
        .filter_map(|l| l.strip_prefix("scf-never|"))
        .map(str::to_owned)
        .collect()
}

fn program(set: &BTreeSet<String>) -> BpfProgram {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = set
        .iter()
        .filter_map(|n| number(n))
        .map(|nr| (nr, Vec::new()))
        .collect();
    assert!(
        rules.len() > 90,
        "too few x86_64 numbers resolved: {}",
        rules.len()
    );
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .unwrap();
    filter.try_into().unwrap()
}

/// Applies `prog` on a fresh thread and builds + drives a multi-thread runtime there.
fn runtime_under(prog: BpfProgram) -> std::io::Result<()> {
    std::thread::spawn(move || {
        seccompiler::apply_filter(&prog).expect("apply seccomp filter");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        rt.block_on(async {
            let h = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                7u8
            });
            assert_eq!(h.await.unwrap(), 7);
            // The hand-over path: an in-process AF_UNIX pair (what tokio's signal driver
            // and SCM_RIGHTS tests use).
            let (_a, _b) = tokio::net::UnixStream::pair()?;
            Ok::<(), std::io::Error>(())
        })?;
        drop(rt);
        Ok(())
    })
    .join()
    .expect("thread")
}

#[test]
fn baseline_never_list_does_not_contain_startup_calls() {
    let never = never_list();
    assert!(never.len() >= 30);
    for need in STARTUP_REQUIRED {
        assert!(
            !never.contains(*need),
            "{need} is on scf-never (AUD-RM2-DEP-33)"
        );
    }
}

#[test]
fn runtime_with_signal_feature_starts_under_each_daemon_allow_set() {
    for kind in ["scf", "scf-web", "scf-store"] {
        let set = allow_set(kind);
        runtime_under(program(&set)).unwrap_or_else(|e| panic!("{kind}: runtime failed: {e}"));
    }
}

#[test]
fn filter_is_effective_without_socketpair() {
    // tokio initialises its signal driver globals once per process (the socketpair is made
    // on the first runtime build only), so the negative control cannot build a second
    // runtime; it proves the filter bites by calling socketpair directly under the sealer
    // set minus socketpair, which must fail with EPERM.
    let mut set = allow_set("scf");
    assert!(set.remove("socketpair"));
    let prog = program(&set);
    let r = std::thread::spawn(move || {
        seccompiler::apply_filter(&prog).expect("apply seccomp filter");
        rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map(|_| ())
    })
    .join()
    .expect("thread");
    assert_eq!(
        r,
        Err(rustix::io::Errno::PERM),
        "socketpair must be refused by the filter"
    );
    // And the same thread model with socketpair present succeeds.
    let full = program(&allow_set("scf"));
    let ok = std::thread::spawn(move || {
        seccompiler::apply_filter(&full).expect("apply seccomp filter");
        rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map(|_| ())
    })
    .join()
    .expect("thread");
    assert_eq!(ok, Ok(()));
}
