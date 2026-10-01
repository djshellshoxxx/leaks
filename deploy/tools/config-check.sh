#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# config-check.sh - configuration checker for the Candor intake host (Z-INTAKE).
#
# Implements the subset of `candorctl check` (18-DEPLOYMENT.md §14; rules from
# 32-OPERATIONS.md §5.2/§7, 16-TOR-I2P.md §7.4 lint, 17-INFRASTRUCTURE.md §4.3/§5,
# 09-DATABASE.md §10, 20-LOGGING-AUDITING.md §11 and LOG-005/007/008) for deploy/intake:
# torrc, nftables, PostgreSQL, systemd units, journald, kernel baseline, resolv.conf and the
# AppArmor profiles.
#
# Usage:
#   config-check.sh [--dir DIR] [--profile ce-single|ce-hardened]   static check of a tree
#   config-check.sh --host [--root DIR] [--pg-db NAME]              installed host (ST-120)
#   --pg-db NAME  a provisioned tenant database (candor_intake_*): --host then checks the
#                 maintenance role's memberships and ownerships through the running server
#                 (required whenever the server's socket exists)
#   --only LIST   comma list of sections: tor,nft,pg,units,journald,kernel,dns,apparmor,host
#                 (an unknown name, or a selection that runs no check, is a usage error: exit 2)
#   --emit-baseline   (maintainers) print the effective units/nft/tor/security values of the
#                     tree as baseline lines for review; performs no check
#   --work-base DIR  private work base instead of /run/candor-config-check (root-owned 0700,
#                 not a symlink; validators use one per run, AUD-RM2-DEP-27). Every ancestor
#                 up to / must be a root-owned directory, not a symlink and not group- or
#                 world-writable (a sticky /tmp is refused too; AUD-RM2-DEP-30), else exit 2
#   -q            print only failures, skips and the summary
#
# Every check evaluates EFFECTIVE configuration, never names in a file (AUD-RM2-DEP-01/02/03):
#   tor       the real tor binary canonicalises the torrc (--verify-config, --dump-config
#             short/full; abbreviations, '+'/'/' prefixes and includes resolved) and every
#             effective non-default option must be on the allow-list with its required value.
#   nftables  the ruleset is loaded into a throw-away network namespace (unshare -n) and the
#             loaded rules (nft -j list ruleset) must equal the release template rule for rule,
#             in order; only the elements of the three site address sets may differ.
#   systemd   systemd itself resolves fragment + every drop-in (prefix, template, type,
#             system.control, /run, /usr/local/lib ...); the merged, section-aware result must
#             equal the per-unit allow-list in config-check.baseline (unknown or extra
#             directives fail), `systemd-analyze verify` must be clean and
#             `systemd-analyze security` must stay within budget. --host adds `systemctl show`.
#   PostgreSQL every key of the conf file must be on the allow-list with its value; pg_hba.conf
#             and pg_ident.conf must equal the release files line by line; --host also asks the
#             server binary for the effective values (postgres -C, includes postgresql.auto.conf).
#   AppArmor  every profile must equal the release profile statement by statement; rule classes
#             (any include, variables other than the two pinned ones, exec transitions, broad
#             write globs, network, capabilities, change_profile, complain/other flags) are
#             also rejected individually. Profiles are self-contained (AUD-RM2-DEP-23): no
#             include, only `abi <abi/3.0>`, whose file digest is pinned. --host adds
#             disable/force-complain links, foreign profiles using the names, empty snippet
#             directories (abstractions/*.d, tunables/*.d, local/), and compares the policy
#             compiled from the installed file against the system tree with the policy
#             compiled from the release statements in isolation (--base = a private directory
#             holding only the pinned abi file, empty parser config); live also the enforce
#             state and the loaded raw policy against that isolated compile.
# --host without --root also reads live state (/proc/sys, loaded nft ruleset, systemctl show,
# AppArmor). With --root (offline image or tests) live-only checks are reported as SKIP; only
# `--host` without --root is the ST-120 gate.
#
# Requirements (fail closed if missing): root, bash, awk, jq, tor, nft, unshare, setpriv,
# systemd-analyze, sha256sum, dd, timeout and the compiled reader candor-safe-read next to
# this script (crates/candor-safe-read; no interpreter, ADR-055(3)); --host additionally the
# PostgreSQL 16 server binary (psql with --pg-db) and apparmor_parser.
# Input hygiene (AUD-RM2-DEP-17/24): an input that is a symlink, or whose path has a symlinked
# component below the tree / --root, is refused and never read; every input is copied once by
# candor-safe-read (openat2 RESOLVE_NO_SYMLINKS|BENEATH from /, O_NOFOLLOW|O_NONBLOCK|O_NOCTTY,
# fstat: regular file, one link, allowed owner, no group/world write on a host, size cap; under
# `timeout`) into a private 0700 work directory and only the copy is used. The reader creates
# each copy O_EXCL|O_NOFOLLOW|O_NONBLOCK beneath that directory's fd 3 (openat2 BENEATH|
# NO_SYMLINKS; AUD-RM2-DEP-30), never through a path from /. --root paths are
# resolved inside the root only.
# Output: "HOST RULE CLASS STATUS DETAIL" table (18 §14). Details never contain file contents:
# only rule names, counts, line/statement numbers, baseline values and sanitised, length-capped
# option/key names (AUD-RM2-DEP-17).
# Policy integrity (AUD-RM2-DEP-21): config-check.manifest (sha256 pinned below) lists the
# sha256 of config-check.baseline and of the candor-safe-read binary (reproducible build,
# tools/build-safe-read.sh); all are verified before any check runs.
# Exit codes (18 §14): 0 = all OK; 30 = baseline failure (any FAIL, including a policy digest
# mismatch); 2 = usage / missing input / no check selected.

# AUD-RM2-DEP-31: a failing stage fails the pipeline; every comparison substitution checks
# its status (tool_err), every "FAIL if it matches" test uses nomatch, and the text tools pass
# a self-test before any check runs. Matches are tested on here-strings, not "| grep -q",
# so an early-exiting grep cannot turn a SIGPIPE in the writer into "no match".
set -u -o pipefail
LC_ALL=C
export LC_ALL
umask 077
tool_selftest() {
  local r
  r=$(printf 'b\na\na\n' | sort | uniq -d) && [ "$r" = a ] || return 1
  r=$(printf 'a\nb\n' | comm -23 - <(printf 'b\n')) && [ "$r" = a ] || return 1
  r=$(printf 'x\ty\n' | cut -f1 | tr x z | sed 's/z/w/' | awk '{print $1}') && [ "$r" = w ] || return 1
  r=$(printf 'b\na\nb\n' | sort -u | wc -l | tr -d ' ') && [ "$r" = 2 ] || return 1
  grep -qx q <<< q || return 1
  grep -qx r <<< q; [ $? -eq 1 ] || return 1
  r=$(printf 'q\n\nq\n' | grep -c .) && [ "$r" = 2 ] || return 1
}
tool_selftest || { echo "config-check: core text tools (sort, uniq, comm, cut, tr, sed, awk, grep, wc) fail their self-test (AUD-RM2-DEP-31)" >&2; exit 2; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
BASE="$SCRIPT_DIR/config-check.baseline"
MANIFEST="$SCRIPT_DIR/config-check.manifest"
# sha256 of config-check.manifest (release-pinned; update together with the manifest).
MANIFEST_SHA256=297a77cd8d0bd10310bd18872dad889ddd6f97f1a394f4b4869fd9d4131f45db
SECTIONS="tor nft pg units journald kernel dns apparmor host"
MODE=static
DIR="$SCRIPT_DIR/../intake"
ROOT=""
PROFILE=""
ONLY=""
PGDB=""
WBASE_OPT=""
QUIET=0
EMIT=0
FAILS=0
CHECKS=0
SKIPS=0

usage() {
  sed -n '4,25p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || usage; DIR=$2; shift 2 ;;
    --host) MODE=host; shift ;;
    --root) [ $# -ge 2 ] || usage; ROOT=${2%/}; shift 2 ;;
    --profile) [ $# -ge 2 ] || usage; PROFILE=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || usage; ONLY=$2; shift 2 ;;
    --pg-db) [ $# -ge 2 ] || usage; PGDB=$2; shift 2 ;;
    --work-base) [ $# -ge 2 ] || usage; WBASE_OPT=$2; shift 2 ;;
    --emit-baseline) EMIT=1; shift ;;
    -q) QUIET=1; shift ;;
    -h|--help) usage ;;
    *) echo "config-check: unknown argument" >&2; usage ;;
  esac
done
case "$ONLY" in *[!a-z,]*) echo "config-check: invalid --only" >&2; exit 2 ;; esac
# AUD-RM2-DEP-21: a mistyped section name must never turn into a green run of zero checks.
if [ -n "$ONLY" ]; then
  for _s in $(printf '%s' "$ONLY" | tr ',' ' '); do
    case " $SECTIONS " in *" $_s "*) ;; *) echo "config-check: unknown --only section (known: $SECTIONS)" >&2; exit 2 ;; esac
  done
  [ -n "$(printf '%s' "$ONLY" | tr -d ',')" ] || { echo "config-check: empty --only" >&2; exit 2; }
fi
case "$PGDB" in "") ;; candor_intake_*) case "$PGDB" in *[!a-z0-9_]*) echo "config-check: invalid --pg-db" >&2; exit 2 ;; esac
  [ "${#PGDB}" -le 63 ] || { echo "config-check: invalid --pg-db" >&2; exit 2; } ;;
  *) echo "config-check: --pg-db must name a candor_intake_* database" >&2; exit 2 ;; esac
if [ ! -f "$BASE" ] || [ ! -r "$BASE" ]; then echo "config-check: baseline file missing" >&2; exit 2; fi
is_root() { [ "$(id -u)" -eq 0 ]; }

# Private work directory (AUD-RM2-DEP-17): 0700, below a root-owned 0700 directory when run as
# root (/run is not world-writable); removed on every exit path.
if is_root; then
  WBASE=${WBASE_OPT:-/run/candor-config-check}
  case "$WBASE" in /*) ;; *) echo "config-check: --work-base must be absolute" >&2; exit 2 ;; esac
  [ -n "$WBASE_OPT" ] || mkdir -m 0700 "$WBASE" 2>/dev/null
  if [ -L "$WBASE" ] || [ ! -d "$WBASE" ] || [ "$(stat -c '%u %a' -- "$WBASE")" != "0 700" ]; then
    echo "config-check: unsafe work directory base $WBASE (must be root 0700, not a symlink)" >&2; exit 2
  fi
  # AUD-RM2-DEP-30: nobody but root may rename or replace the base or any ancestor.
  case "/$WBASE/" in */./*|*/../*) echo "config-check: unsafe work directory base $WBASE (no . or .. components)" >&2; exit 2 ;; esac
  wb_a=$WBASE
  while [ "$wb_a" != / ]; do
    wb_a=$(dirname -- "$wb_a")
    wb_s=$(stat -c '%u %a %F' -- "$wb_a" 2>/dev/null) || wb_s="? 0 missing"
    wb_m=${wb_s#* }; wb_m=${wb_m%% *}
    if [ -L "$wb_a" ] || [ "${wb_s%% *}" != 0 ] || [ "${wb_s#* * }" != directory ] || [ $((8#$wb_m & 8#1022)) -ne 0 ]; then
      echo "config-check: unsafe work directory base $WBASE: ancestor $wb_a must be a root-owned directory, not a symlink, not group/world-writable and not sticky" >&2; exit 2
    fi
  done
else [ -z "$WBASE_OPT" ] || { echo "config-check: --work-base needs root" >&2; exit 2; }; WBASE=/tmp; fi
WORK=$(mktemp -d "$WBASE/run.XXXXXXXX") || exit 2
chmod 0700 "$WORK" || exit 2
# The reader creates its outputs beneath fd 3 = $WORK, opened for that one child only
# (AUD-RM2-DEP-32: no other child inherits a descriptor of the work directory). The path is
# safe to reopen: $WORK and every ancestor are root-only (DEP-30) or, unprivileged, the
# caller's own 0700 directory under a sticky /tmp.
trap 'rm -rf -- "$WORK"' EXIT
trap 'exit 2' INT TERM HUP

LIVE=0
if [ "$MODE" = host ]; then
  if [ -n "$ROOT" ]; then
    [ -d "$ROOT" ] || { echo "config-check: --root is not a directory" >&2; exit 2; }
    ROOT=$(realpath -e -- "$ROOT") || exit 2
    [ "$ROOT" = / ] && ROOT=""
    [ -n "$ROOT" ] || LIVE=1
  else LIVE=1; fi
  INPREFIX=$ROOT
  [ -z "$PROFILE" ] || { echo "config-check: --profile is static-mode only (a host has its drop-ins installed)" >&2; exit 2; }
  # Inputs on a host: owned by root, no group/world write (AUD-RM2-DEP-24).
  OWNERS=0; DENYMODE=022
  TORRC="$ROOT/etc/tor/instances/candor-intake/torrc"
  NFT="$ROOT/etc/nftables.conf"
  PGCONF="$ROOT/etc/candor/intake/postgresql/candor-intake.conf"
  PGHBA="$ROOT/etc/candor/intake/postgresql/pg_hba.conf"
  JNS="$ROOT/etc/systemd/journald@candor-intake.conf"
  JHOST="$ROOT/etc/systemd/journald.conf.d/50-candor-intake.conf"
  SYSCTL="$ROOT/etc/sysctl.d/90-candor-intake.conf"
  COREDUMP="$ROOT/etc/systemd/coredump.conf.d/50-candor-intake.conf"
  RESOLV="$ROOT/etc/resolv.conf"
  PGIDENT="$ROOT/etc/candor/intake/postgresql/pg_ident.conf"
else
  [ -d "$DIR" ] || { echo "config-check: no such directory" >&2; exit 2; }
  DIR=$(realpath -e -- "$DIR") || exit 2
  INPREFIX=$DIR
  # Inputs of a tree: owned by root or the tree's owner, not world-writable (AUD-RM2-DEP-24).
  OWNERS="0,$(stat -c %u -- "$DIR")"; DENYMODE=002
  [ -z "$PGDB" ] || { echo "config-check: --pg-db is --host only" >&2; exit 2; }
  case "$PROFILE" in ""|ce-single|ce-hardened) ;; *) echo "config-check: unknown profile" >&2; exit 2 ;; esac
  if [ -n "$PROFILE" ] && [ ! -d "$DIR/profiles/$PROFILE" ]; then echo "config-check: profile directory missing" >&2; exit 2; fi
  TORRC="$DIR/torrc"
  NFT="$DIR/nftables.conf"
  PGCONF="$DIR/postgresql/candor-intake.conf"
  PGHBA="$DIR/postgresql/pg_hba.conf"
  JNS="$DIR/journald/journald@candor-intake.conf"
  JHOST="$DIR/journald/candor-intake-host.conf"
  SYSCTL="$DIR/sysctl.d/90-candor-intake.conf"
  COREDUMP="$DIR/coredump.conf.d/50-candor-intake.conf"
  RESOLV="$DIR/resolv.conf"
  PGIDENT="$DIR/postgresql/pg_ident.conf"
fi

report() { # rule class status detail
  CHECKS=$((CHECKS + 1))
  case "$3" in FAIL) FAILS=$((FAILS + 1)) ;; SKIP) SKIPS=$((SKIPS + 1)) ;; esac
  if [ "$EMIT" -eq 0 ] && { [ "$QUIET" -eq 0 ] || [ "$3" != OK ]; }; then
    # Details may echo values from (possibly tampered) config files: printable ASCII only, so
    # no terminal control sequence can reach the operator's terminal.
    printf '%-7s %-48s %-9s %-6s %s\n' intake "$1" "$2" "$3" "$(printf '%s' "$4" | tr -c '[:print:]' '?' | cut -c1-400)"
  fi
}
ok()   { report "$1" baseline OK "${2:-}"; }
fail() { report "$1" baseline FAIL "${2:-}"; }
tool_err() { fail "$1" "comparison failed: a text tool exited non-zero (fail closed, AUD-RM2-DEP-31)"; }
# nomatch CMD...: 0 only on a definite "no match" (exit 1); a match (0) or a tool error (>= 2)
# returns 1, so "if ! nomatch ...; then fail" fails closed.
nomatch() { "$@"; [ $? -eq 1 ]; }
skip() { report "$1" baseline SKIP "${2:-}"; }
# Feed "STATUS<TAB>rule<TAB>detail" lines (from awk/jq helpers) into report().
report_lines() { local st r d; while IFS="$(printf '\t')" read -r st r d; do case "$st" in OK) ok "$r" "$d" ;; SKIP) skip "$r" "$d" ;; *) fail "$r" "$d" ;; esac; done; }

want() { [ -z "$ONLY" ] || case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
have() { command -v "$1" >/dev/null 2>&1; }
# Names taken from inputs (option, key, directive, user names) are the only input-derived text
# a report may carry: reduced to a name alphabet, 48 characters each, at most 8 (DEP-17).
san_names() { # stdin: names separated by blanks/newlines
  tr -s ' \t' '\n' | awk 'NF { t=$0; gsub(/[^A-Za-z0-9_.@:+\/-]/, "?", t); t=substr(t, 1, 48); n++; if (n <= 8) out=out (n>1 ? " " : "") t }
    END { if (n > 8) out=out " (+" n-8 " more)"; print out }'
}
# First symlinked (or '.'/'..') component of path below prefix; prefix itself was resolved.
symlinked_component() { # prefix path -> prints the component, returns 0 if there is one
  local cur=$1 rest comp
  case "$2" in "$1"/*) rest=${2#"$1"/} ;; *) printf '%s' "(outside the checked tree)"; return 0 ;; esac
  while [ -n "$rest" ]; do
    comp=${rest%%/*}
    if [ "$comp" = "$rest" ]; then rest=""; else rest=${rest#*/}; fi
    case "$comp" in "") continue ;; .|..) printf '%s' "${cur#"$1"}/$comp"; return 0 ;; esac
    cur="$cur/$comp"
    if [ -L "$cur" ]; then printf '%s' "${cur#"$1"}"; return 0; fi
  done
  return 1
}
# Copy one input into the work directory without following symlinks (AUD-RM2-DEP-17/24).
MAXIN=1048576
SNAP=""
SAFE_READ="$SCRIPT_DIR/candor-safe-read"
SAFE_OK=0
safe_copy() { # abs-path out-under-$WORK [extra-owner-uid] -> candor-safe-read status (see there); never prints content
  [ "$SAFE_OK" -eq 1 ] || return 15
  case "$2" in "$WORK"/?*) ;; *) return 15 ;; esac
  rm -f -- "$2"   # the reader creates OUT with O_EXCL
  timeout -k 2 20 "$SAFE_READ" "$1" "${2#"$WORK"/}" "$MAXIN" "$OWNERS${3:+,$3}" "$DENYMODE" </dev/null >/dev/null 2>&1 3<"$WORK"
}
snap() { # rule path name [extra-owner-uid] -> SNAP=copy; FAIL + return 1 when refused
  local r=$1 p=$2 l rc
  SNAP="$WORK/in/$3"
  mkdir -p "$WORK/in" || { fail "$r" "work directory"; return 1; }
  # Early, readable refusal; the race-free open in candor-safe-read is the authoritative check.
  if l=$(symlinked_component "$INPREFIX" "$p"); then fail "$r" "refused: symlinked path component $l (inputs are never followed)"; return 1; fi
  safe_copy "$p" "$SNAP" "${4:-}"; rc=$?
  case "$rc" in
    0) return 0 ;;
    10) fail "$r" "refused: symlinked or swapped path component (inputs are never followed): ${p#"$INPREFIX"}" ;;
    11|12) fail "$r" "missing or not a regular file: ${p#"$INPREFIX"}" ;;
    13) fail "$r" "refused: owner, mode (group/world write) or link count not allowed: ${p#"$INPREFIX"}" ;;
    14) fail "$r" "larger than $MAXIN bytes: ${p#"$INPREFIX"}" ;;
    124|137) fail "$r" "read timed out: ${p#"$INPREFIX"}" ;;
    *) fail "$r" "unreadable: ${p#"$INPREFIX"}" ;;
  esac
  rm -f -- "$SNAP"
  return 1
}
# Optional input: absent -> empty copy; present -> as snap.
snap_opt() { # rule path name [extra-owner-uid]
  if [ ! -e "$2" ] && [ ! -L "$2" ] && ! symlinked_component "$INPREFIX" "$2" >/dev/null; then
    mkdir -p "$WORK/in"; SNAP="$WORK/in/$3"; : > "$SNAP"; return 0
  fi
  snap "$@"
}
need_tools() { # rule tool... ; FAIL (fail closed) when a tool or root is missing
  local r=$1 t; shift
  is_root || { fail "$r" "must run as root (uses unshare/setpriv)"; return 1; }
  for t in "$@"; do have "$t" || { fail "$r" "required tool missing: $t"; return 1; }; done
  return 0
}
trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
base() { awk -F'|' -v k="$1" '$1==k' "$BASE"; } # baseline lines of one kind
run_as() { # user cmd... (unprivileged, no new privileges, no supplementary groups)
  local u=$1; shift
  setpriv --reuid="$u" --regid="$(id -g "$u")" --clear-groups --no-new-privs -- "$@"
}

# =============================================================================== policy integrity
# AUD-RM2-DEP-21: the baseline is the policy. The manifest's digest is pinned in this script
# (both ship in the same signed release package); the manifest pins the baseline. The verified
# copy in the private work directory is the only one read afterwards.
verify_policy() {
  local got want name extra
  if [ -L "$MANIFEST" ] || [ ! -f "$MANIFEST" ] || [ -L "$BASE" ]; then fail tool.baseline_integrity "manifest or baseline missing or a symlink"; return 1; fi
  have sha256sum || { fail tool.baseline_integrity "sha256sum missing"; return 1; }
  got=$(sha256sum < "$MANIFEST" | cut -c1-64)
  if [ "$got" != "$MANIFEST_SHA256" ]; then fail tool.baseline_integrity "config-check.manifest digest differs from the release pin"; return 1; fi
  dd if="$BASE" of="$WORK/baseline" iflag=nofollow bs=65536 count=64 status=none 2>/dev/null || { fail tool.baseline_integrity "baseline unreadable"; return 1; }
  want=$(awk '$2=="config-check.baseline" && $1 ~ /^[0-9a-f]{64}$/ {print $1}' "$MANIFEST") || want=""
  extra=$(awk '$2!="config-check.baseline" && $2!="candor-safe-read" && NF' "$MANIFEST" | wc -l) || extra=1
  got=$(sha256sum < "$WORK/baseline" | cut -c1-64)
  if [ -z "$want" ] || [ "$extra" -ne 0 ] || [ "$got" != "$want" ]; then fail tool.baseline_integrity "config-check.baseline digest differs from the manifest"; return 1; fi
  # The input reader (AUD-RM2-DEP-24) is policy too: pinned by the manifest, run from a copy.
  # Compiled reader (ADR-055(3)): copied, then the copy's digest checked and only the copy run.
  want=$(awk '$2=="candor-safe-read" && $1 ~ /^[0-9a-f]{64}$/ {print $1}' "$MANIFEST")
  if [ -L "$SAFE_READ" ] || ! dd if="$SAFE_READ" of="$WORK/candor-safe-read" iflag=nofollow bs=65536 count=64 status=none 2>/dev/null ||
     [ -z "$want" ] || [ "$(sha256sum < "$WORK/candor-safe-read" | cut -c1-64)" != "$want" ]; then
    fail tool.baseline_integrity "candor-safe-read missing or its digest differs from the manifest (build: tools/build-safe-read.sh)"; return 1
  fi
  chmod 0700 "$WORK/candor-safe-read" || { fail tool.baseline_integrity "reader copy"; return 1; }
  SAFE_READ="$WORK/candor-safe-read"; SAFE_OK=1
  have timeout || { fail tool.baseline_integrity "timeout missing"; return 1; }
  BASE="$WORK/baseline"
  name=$(sha256sum < "$BASE" | cut -c1-12)
  ok tool.baseline_integrity "baseline sha256 ${name}... matches the pinned manifest"
}

# =============================================================================== torrc
TOR_USER=_tor-candor-intake

tor_canon() { # snapshot -> $WORK/tor/{verify,short,full}.out ; returns non-zero on any failure
  local d="$WORK/tor" g
  g=$(id -g "$TOR_USER") || return 1
  # The working copy is private (AUD-RM2-DEP-17): directory 0700 and file 0600, owned by the
  # instance user, inside the root-only work directory. tor reaches it through a bind mount
  # in its own mount namespace, never through a world-traversable path.
  mkdir -m 0700 "$d" && cp -- "$1" "$d/torrc" && chown "$TOR_USER:$g" "$d" "$d/torrc" && chmod 0600 "$d/torrc" || return 1
  # Private mount namespace: tmpfs over /var/lib and /run so the canonicalisation never touches
  # the real tor state, keys or sockets; tor itself runs unprivileged as the instance user.
  # shellcheck disable=SC2016 # expanded by the inner shell
  unshare -m --propagation private /bin/sh -c '
    set -e
    umask 077
    mount -t tmpfs -o mode=0755,size=16m tmpfs /var/lib
    mkdir -m 0700 /var/lib/.cc
    mount --bind "$1" /var/lib/.cc
    mount -t tmpfs -o mode=0755,size=16m tmpfs /run
    mkdir -m 0755 /var/lib/tor-instances
    mkdir -m 0700 /var/lib/tor-instances/candor-intake
    chown "$2:$3" /var/lib/tor-instances/candor-intake
    chmod 0700 /var/lib/tor-instances/candor-intake
    for m in verify short full; do
      case $m in verify) a=--verify-config ;; short) a="--dump-config short" ;; full) a="--dump-config full" ;; esac
      # shellcheck disable=SC2086
      timeout 60 setpriv --reuid="$2" --regid="$3" --clear-groups --no-new-privs -- \
        tor --defaults-torrc /dev/null -f /var/lib/.cc/torrc --hush $a > "/var/lib/.cc/$m.raw" 2>/dev/null </dev/null || exit 3
      # tor prints log lines on stdout before its own Log option applies; keep option lines only.
      grep -vE "^[A-Z][a-z]{2} [0-9]{2} [0-9:.]+ \[" "/var/lib/.cc/$m.raw" > "/var/lib/.cc/$m.out" || true
    done' sh "$d" "$TOR_USER" "$g"
}

check_torrc() {
  snap tor.file "$TORRC" torrc || return
  local TORRC=$SNAP
  # ---- raw text: no continuation, no %include, no '+'/'/' line prefixes, every key a full
  # option name from the template (tor accepts abbreviations and case variants), no repeats.
  if grep -qE '\\[[:space:]]*$' "$TORRC"; then fail tor.raw.no_continuation "line continuation used"; else ok tor.raw.no_continuation; fi
  sed -e 's/#.*$//' "$TORRC" | trim | grep -v '^$' > "$WORK/torrc.clean"
  if grep -qiE '^%' "$WORK/torrc.clean"; then fail tor.raw.no_include "%include or other % directive present"; else ok tor.raw.no_include; fi
  if grep -qE '^[+/]' "$WORK/torrc.clean"; then fail tor.raw.no_prefix "'+Option' (append) or '/Option' (reset) line present"; else ok tor.raw.no_prefix; fi
  local unknown dup
  # Counts only, never the tokens (AUD-RM2-DEP-24): a first token of an arbitrary file could
  # carry secret material.
  unknown=$(awk 'NR==FNR { if ($1=="tor-raw") ok[tolower($2)]=1; next } !(tolower($1) in ok) { print tolower($1) }' FS='|' "$BASE" FS=' ' "$WORK/torrc.clean" | sort -u | wc -l) || { tool_err tor.raw.allowed_keys; unknown=-1; }
  if [ "$unknown" -lt 0 ]; then :
  elif [ "$unknown" -gt 0 ]; then fail tor.raw.allowed_keys "$unknown option name(s) not in the template (abbreviations are rejected too; names not shown)"; else ok tor.raw.allowed_keys; fi
  dup=$(awk '{ print tolower($1) }' "$WORK/torrc.clean" | sort | uniq -d | wc -l) || { tool_err tor.raw.no_duplicates; dup=-1; }
  [ "$dup" -ne 0 ] || dup=""
  [ -z "$dup" ] || [ "$dup" -lt 0 ] || dup="$dup option name(s) (names not shown)"
  if [ "$dup" = -1 ]; then :
  elif [ -n "$dup" ]; then fail tor.raw.no_duplicates "repeated option(s): $dup"; else ok tor.raw.no_duplicates; fi
  # Never hand an %include line to tor (it could make tor read an arbitrary file).
  if grep -qiE '^%' "$WORK/torrc.clean"; then fail tor.effective "not canonicalised: % directive present"; return; fi

  # ---- effective configuration, as tor itself parses it
  need_tools tor.effective tor unshare setpriv timeout || return
  getent passwd "$TOR_USER" >/dev/null || { fail tor.effective "user $TOR_USER missing"; return; }
  if ! tor_canon "$TORRC"; then fail tor.effective "tor --verify-config / --dump-config rejected the file (details suppressed)"; return; fi
  ok tor.verify_config "tor --verify-config: valid"
  # Short dump = every option that differs from tor's default. Each must be on the allow-list
  # with its required value (or within its tunable range), and each allow-listed option must
  # be present exactly once.
  awk -F'|' '
    FNR==NR { if ($1=="tor") { mode[$2]=$3; val[$2]=$4; order[++n]=$2 } next }
    function nm(x) { gsub(/[^A-Za-z0-9_]/, "?", x); return substr(x, 1, 48) }
    { k=$1; v=$0; sub(/^[^ ]+ ?/, "", v); cnt[k]++; got[k]=v
      if (!(k in mode)) { printf "FAIL\ttor.effective.%s\tnot allowed (effective non-default option)\n", nm(k); next } }
    END {
      for (i=1; i<=n; i++) { k=order[i]
        if (cnt[k]==0) { printf "FAIL\ttor.effective.%s\tmissing (required: %s)\n", k, val[k]; continue }
        if (cnt[k]>1) { printf "FAIL\ttor.effective.%s\tset %d times\n", k, cnt[k]; continue }
        v=got[k]
        if (mode[k]=="=") { if (v==val[k]) printf "OK\ttor.effective.%s\t%s\n", k, v; else printf "FAIL\ttor.effective.%s\texpected [%s], effective value differs\n", k, val[k] }
        else if (mode[k]=="int") { split(val[k], r, " ")
          if (v ~ /^[0-9]+$/ && length(v) <= 10 && v+0 >= r[1]+0 && v+0 <= r[2]+0) printf "OK\ttor.effective.%s\t%s\n", k, v
          else printf "FAIL\ttor.effective.%s\texpected an integer in [%s, %s]\n", k, r[1], r[2] }
      } }' "$BASE" FS=' ' "$WORK/tor/short.out" > "$WORK/rl"; report_lines < "$WORK/rl"
  # Options whose required value is tor's default (so they never appear in the short dump),
  # plus the path-selection options an attacker would use (checked in the full dump).
  awk -F'|' '
    FNR==NR { if ($1=="tor-full") { want[$2]=$3; order[++n]=$2 } next }
    { k=$1; v=$0; sub(/^[^ ]+ ?/, "", v); if (k in want) { cnt[k]++; got[k]=v } }
    END { for (i=1; i<=n; i++) { k=order[i]
      if (cnt[k]!=1) printf "FAIL\ttor.full.%s\texpected exactly one effective value [%s], found %d\n", k, want[k], cnt[k]
      else if (got[k]!=want[k]) printf "FAIL\ttor.full.%s\texpected [%s], effective value differs\n", k, want[k]
      else printf "OK\ttor.full.%s\t%s\n", k, got[k] } }' "$BASE" FS=' ' "$WORK/tor/full.out" > "$WORK/rl"; report_lines < "$WORK/rl"
  # No control interface of any kind (AUD-RM2-DEP-04; NET-009).
  if ! nomatch grep -qE '^(ControlSocket|ControlPort|__ControlPort|__OwningControllerProcess|HashedControlPassword) [^0]' "$WORK/tor/full.out"; then
    fail tor.no_control_interface "a control listener or password is configured"
  else ok tor.no_control_interface; fi
}

# =============================================================================== nftables
UIDMAP="{}"
nft_uidmap() { # JSON {"uid":"name"} for the users the template names
  local u n m="" first=1
  for n in _tor-candor-intake _tor-candor-update candor-health _chrony; do
    u=$(id -u "$n" 2>/dev/null) || continue
    if [ "$first" -eq 1 ]; then first=0; else m="$m,"; fi
    m="$m\"$u\":\"$n\""
  done
  printf '{%s}' "$m"
}

cat > "$WORK/nft.jq" <<'JQ'
# Canonical text of one rule: expressions only (no handle, no comment), anonymous counter
# values dropped, skuid numbers mapped to names.
def canon($u):
  .expr
  | walk(if type=="object" and has("counter") and (.counter|type)=="object" then {"counter":{}} else . end)
  | walk(if type=="object" and has("match") and (.match|type)=="object"
            and (.match.left|type)=="object" and (.match.left.meta|type)=="object"
            and .match.left.meta.key=="skuid"
         then .match.right |= (if type=="number" then ($u[tostring] // tostring)
                               elif type=="object" and has("set") then .set |= map(if type=="number" then ($u[tostring] // tostring) else . end)
                               else . end)
         else . end)
  | tojson;
def setcanon: {type: .type, flags: (.flags // []), elem: (.elem // [])} | tojson;
def line($st; $r; $d): "\($st)\t\($r)\t\($d)";
# Names from the ruleset are reported only as sanitised, capped names (AUD-RM2-DEP-17).
def nm: tostring | gsub("[^A-Za-z0-9_.-]"; "?") | .[0:32];
def nms: map(nm) | (.[0:8] | join(" ")) + (if length > 8 then " (+\(length - 8) more)" else "" end);
# Site address sets: plain unicast host addresses only (AUD-RM2-DEP-22): no 0.0.0.0/8, loopback,
# link-local, multicast, reserved or broadcast addresses.
def hostaddr: type=="string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")
  and ((split(".") | map(tonumber)) as $o | ($o | all(. <= 255)) and $o[0] != 0 and $o[0] != 127
       and $o[0] < 224 and (($o[0] == 169 and $o[1] == 254) | not));

($base | split("\n") | map(select(length>0) | split("|"))) as $b
| ($b | map(select(.[0]=="nft-rule") | {chain: .[1], c: (.[2:] | join("|"))})) as $exp
| ($b | map(select(.[0]=="nft-set") | {(.[1]): (.[2:] | join("|"))}) | add // {}) as $expsets
| [.nftables[]] as $all
| ($all | map(select(.rule) | .rule | {chain: .chain, table: .table, family: .family, c: canon($u), accept: ([.expr[] | has("accept")] | any)})) as $rules
| ($all | map(keys[0]) | unique) as $types
| ($all | map(select(.table) | .table)) as $tables
| ($all | map(select(.chain) | .chain)) as $chains
| ($all | map(select(.set) | .set)) as $sets
| ($all | map(select(.counter) | .counter.name) | sort) as $counters
| ("nft." + $label) as $p
| (
  ( if ($types - ["metainfo","table","chain","rule","set","counter"]) == [] then line("OK"; $p+".object_types"; "table/chain/rule/set/counter only")
    else line("FAIL"; $p+".object_types"; "unexpected object type(s): \($types - ["metainfo","table","chain","rule","set","counter"] | nms)") end ),
  ( if ($tables | map("\(.family) \(.name)")) == ["inet candor_intake"] then line("OK"; $p+".single_table"; "inet candor_intake")
    else line("FAIL"; $p+".single_table"; "expected only 'table inet candor_intake', found: \($tables | map("\(.family)/\(.name)") | nms)") end ),
  ( ["input","output","forward"][] as $c
    | ($chains | map(select(.name==$c and .table=="candor_intake"))) as $m
    | if ($m|length)==1 and $m[0].type=="filter" and $m[0].hook==$c and $m[0].prio==0 and $m[0].policy=="drop"
      then line("OK"; $p+".policy_drop."+$c; "filter hook \($c) priority 0 policy drop")
      else line("FAIL"; $p+".policy_drop."+$c; "chain \($c) must be the only 'type filter hook \($c) priority filter; policy drop;'") end ),
  ( if ($chains | map(.name) | sort) == ["forward","input","output"] then line("OK"; $p+".only_filter_chains"; "")
    else line("FAIL"; $p+".only_filter_chains"; "extra or missing chain(s): \($chains | map(.name) | nms)") end ),
  ( ([$rules[] | .c | fromjson | .. | objects | keys[]] | unique) as $k
    | ($k - ($k - ["log","queue","dup","fwd","jump","goto","notrack","snat","dnat","masquerade","redirect","tproxy","synproxy","mangle"])) as $badk
    | if $badk == [] then line("OK"; $p+".no_log_queue_jump"; "")
      else line("FAIL"; $p+".no_log_queue_jump"; "forbidden statement(s): \($badk | join(" "))") end ),
  ( ($exp | map(select(.c | fromjson | map(has("accept")) | any) | .chain + "|" + .c)) as $okacc
    | ($rules | map(select(.accept) | .chain + "|" + .c) | map(select(. as $x | $okacc | index($x) | not))) as $extra
    | if $extra == [] then line("OK"; $p+".accept_rules"; "only the template accepts (E1-E4, I1-I2)")
      else line("FAIL"; $p+".accept_rules"; "\($extra|length) non-template accept rule(s) (rule text not shown)") end ),
  # Safety drops (metadata, non-public destinations for tor UIDs) precede every UID accept.
  ( ($exp | map(select(.chain=="output")) | map(.c)) as $eo
    | ($eo | to_entries | map(select(.value | test("skuid") and test("accept"))) | .[0].key) as $firstacc
    | ($eo[0:$firstacc] | map(select(test("\"drop\"") and (test("169.254") or test("fd00:ec2") or test("non_public"))))) as $safety
    | ($rules | map(select(.chain=="output")) | map(.c)) as $ro
    | ([$ro | to_entries[] | select(.value | test("skuid") and test("accept")) | .key] | min // 1e9) as $ra
    | ([$safety[] as $s | ($ro | index($s)) // 1e9] | max // 1e9) as $rs
    | if ($safety|length) == 4 and $rs < $ra then line("OK"; $p+".safety_drops_first"; "metadata and non-public drops precede all UID accepts")
      else line("FAIL"; $p+".safety_drops_first"; "a UID accept rule precedes (or replaces) the metadata/non-public drops") end ),
  ( ["input","output","forward"][] as $c
    | ($exp | map(select(.chain==$c) | .c)) as $e
    | ($rules | map(select(.chain==$c) | .c)) as $r
    | if $e == $r then line("OK"; $p+".template."+$c; "\($r|length) rules equal the release template, in order")
      else ([range(0; ([$e,$r]|map(length)|max))] | map(select($e[.] != $r[.])) | .[0]) as $i
        | line("FAIL"; $p+".template."+$c; "differs from the release template at rule \($i + 1) (expected \($e|length) rules, found \($r|length))") end ),
  ( if ($sets | map(.name) | sort) == ["admin_jump","core_relay","mon_hosts","non_public4","non_public6"] then line("OK"; $p+".sets"; "")
    else line("FAIL"; $p+".sets"; "unexpected set list: \($sets | map(.name) | nms)") end ),
  ( ["non_public4","non_public6"][] as $n
    | ($sets | map(select(.name==$n)) | .[0]) as $s
    | if $s != null and ($s | setcanon) == $expsets[$n] then line("OK"; $p+".set."+$n; "elements equal the template")
      else line("FAIL"; $p+".set."+$n; "type, flags or elements differ from the template") end ),
  ( ["mon_hosts","admin_jump","core_relay"][] as $n
    | ($sets | map(select(.name==$n)) | .[0]) as $s
    | if $s != null and $s.type=="ipv4_addr" and (($s.flags // []) == []) and (($s.elem // []) | all(hostaddr))
         and ($n != "core_relay" or (($s.elem // []) | length) <= 1)
      then line("OK"; $p+".set."+$n; "\(($s.elem // []) | length) plain unicast IPv4 address(es)")
      else line("FAIL"; $p+".set."+$n; "must be 'type ipv4_addr' with plain unicast host addresses only (no 0/8, 127/8, 169.254/16, multicast, reserved or broadcast; core_relay: at most one)") end ),
  ( if $counters == ["forward_dropped","input_dropped","output_dropped"] then line("OK"; $p+".counters"; "")
    else line("FAIL"; $p+".counters"; "unexpected counters: \($counters | nms)") end )
)
JQ

nft_analyze() { # json-file label
  jq -r --argjson u "$UIDMAP" --arg label "$2" --rawfile base "$BASE" -f "$WORK/nft.jq" "$1" 2>/dev/null > "$WORK/nft.$2.res" ||
    { fail "nft.$2.parse" "could not analyse the loaded ruleset"; return; }
  report_lines < "$WORK/nft.$2.res"
}

CORE_RELAY_ELEMS=""
NFT_LOADED=0
check_nft() {
  snap nft.file "$NFT" nftables.conf || return
  local NFT=$SNAP
  # Text-level: a host loads this file on top of the kernel's ruleset, so it must flush first.
  # include/define/variables are rejected before the file is handed to nft (an include could
  # also make the root-run checker read an arbitrary file).
  local body
  body=$(grep -vE '^[[:space:]]*(#|$)' "$NFT")
  local first; first=$(head -n 1 <<< "$body" | trim) || first=""
  if [ "$first" = 'flush ruleset' ]; then ok nft.flush_ruleset; else fail nft.flush_ruleset "first statement must be 'flush ruleset'"; fi
  if ! nomatch grep -qE '(^|[^[:alnum:]_])(include|define|undefine|redefine)([^[:alnum:]_]|$)|\$' <<< "$body"; then
    fail nft.no_include_define "include/define/\$variable present (ruleset must be self-contained)"; return
  fi
  ok nft.no_include_define
  need_tools nft.load nft jq unshare || return
  UIDMAP=$(nft_uidmap)
  # Load into a throw-away network namespace: nft resolves everything exactly as on boot, and
  # the result is read back from the kernel (rule order included). nft's own error text is
  # suppressed (it may quote file content).
  # shellcheck disable=SC2016 # expanded by the inner shell
  if ! unshare -n /bin/sh -c 'nft -f "$1" >/dev/null 2>&1 || exit 3; nft -j list ruleset' sh "$NFT" > "$WORK/nft.file.json" 2>/dev/null; then
    fail nft.load "nft could not load the ruleset (details suppressed)"; return
  fi
  ok nft.load "loaded in a private network namespace"
  NFT_LOADED=1
  nft_analyze "$WORK/nft.file.json" file
  CORE_RELAY_ELEMS=$(jq -r '.nftables[] | select(.set and .set.name=="core_relay") | (.set.elem // [])[] | tostring' "$WORK/nft.file.json" 2>/dev/null | tr '\n' ' ')
  if [ "$LIVE" -eq 1 ]; then
    if nft -j list ruleset > "$WORK/nft.live.json" 2>/dev/null; then
      nft_analyze "$WORK/nft.live.json" live
      local lr
      lr=$(jq -r '.nftables[] | select(.set and .set.name=="core_relay") | (.set.elem // [])[] | tostring' "$WORK/nft.live.json" 2>/dev/null | tr '\n' ' ')
      if [ "$lr" = "$CORE_RELAY_ELEMS" ]; then ok nft.live.core_relay_matches_file; else fail nft.live.core_relay_matches_file "loaded @core_relay differs from /etc/nftables.conf"; fi
    else fail nft.live.load "cannot read the loaded ruleset"; fi
  elif [ "$MODE" = host ]; then skip nft.live "offline root: loaded ruleset not checked"; fi
}

# =============================================================================== PostgreSQL
pg_norm() { # postgresql.conf -> "key<TAB>value" (comments stripped, quotes removed, lowercase key)
  awk '
    {
      line=$0; out=""; q=0
      for (i=1; i<=length(line); i++) { ch=substr(line,i,1)
        if (ch=="\047") q=!q
        if (ch=="#" && !q) break
        out=out ch }
      gsub(/^[ \t]+|[ \t]+$/, "", out)
      if (out=="") next
      eq=index(out, "=")
      if (eq==0) { split(out, a, /[ \t]+/); k=a[1]; v=substr(out, length(k)+1) }
      else { k=substr(out,1,eq-1); v=substr(out,eq+1) }
      gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (v ~ /^\047.*\047$/) v=substr(v,2,length(v)-2)
      print tolower(k) "\t" v
    }' "$1"
}
pg_bool() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in on|true|yes|1) echo on ;; off|false|no|0) echo off ;; *) echo "$1" ;; esac; }

check_pg() {
  snap pg.file "$PGCONF" pg.conf || return
  local conf=$SNAP norm dup unknown
  norm=$(pg_norm "$conf") || { tool_err pg.conf_parse; return; }
  local keys
  keys=$(cut -f1 <<< "$norm") || { tool_err pg.conf_parse; return; }
  if ! nomatch grep -qE '^(include|include_dir|include_if_exists)$' <<< "$keys"; then
    fail pg.no_include "include directive present (effective config must be this file)"
  else ok pg.no_include; fi
  if ! dup=$(sort <<< "$keys" | uniq -d | san_names); then tool_err pg.no_duplicates
  elif [ -n "$dup" ]; then fail pg.no_duplicates "duplicate keys: $dup"; else ok pg.no_duplicates; fi
  # Allow-list (AUD-RM2-DEP-19): every key in the file must be a pg| key of the baseline.
  local pgallow
  if ! pgallow=$(base pg | cut -d'|' -f2 | sort -u) || [ -z "$pgallow" ]; then tool_err pg.allowed_keys
  elif ! unknown=$(sed '/^$/d' <<< "$keys" | sort -u | comm -23 - <(printf '%s\n' "$pgallow") | san_names); then tool_err pg.allowed_keys
  elif [ -n "$unknown" ]; then fail pg.allowed_keys "key(s) not in the baseline: $unknown"; else ok pg.allowed_keys "every key is on the allow-list"; fi

  # Values (pg|key|kind|value; kind b = boolean, s = case-insensitive string). Found values
  # are never echoed (AUD-RM2-DEP-17).
  local key kind want got
  while IFS='|' read -r _ key kind want; do
    if ! grep -qx -- "$key" <<< "$keys"; then fail "pg.$key" "not set explicitly (expected '$want')"; continue; fi
    got=$(printf '%s\n' "$norm" | awk -F'\t' -v k="$key" '$1==k {print $2}')
    if [ "$kind" = b ]; then got=$(pg_bool "$got"); else got=$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]'); fi
    if [ "$got" = "$want" ]; then ok "pg.$key" "'$want'"; else fail "pg.$key" "expected '$want', file value differs"; fi
  done < <(base pg)

  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="log_line_prefix" {print $2}')
  local llp
  llp=$(sed 's/%%//g; s/%e//g' <<< "$got") || llp=%
  if ! grep -qx log_line_prefix <<< "$keys"; then fail pg.log_line_prefix "not set (PG default contains %m and %p)"
  elif [[ "$llp" == *%* ]]; then fail pg.log_line_prefix "only %e allowed"
  else ok pg.log_line_prefix "only %e"; fi
  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="unix_socket_permissions" {print $2}')
  case "$got" in 0770|0750|0700|770|750|700) ok pg.unix_socket_permissions "$got" ;;
    *) fail pg.unix_socket_permissions "no world access allowed" ;; esac

  # pg_hba / pg_ident: Unix-socket peer only, reject last (09 §10, DB-022, R7 SI-E-01), and
  # exactly the release lines (AUD-RM2-DEP-19; ADR-052(9): the migration user's single line).
  if snap pg.hba_conf "$PGHBA" pg_hba.conf; then
    local hba last
    hba=$(sed -e 's/#.*$//' "$SNAP" | trim | tr -s ' \t' '  ' | grep -v '^$')
    # shellcheck disable=SC2016 # awk program
    if ! nomatch awk '$1 != "local" {bad=1} END {exit bad?0:1}' <<< "$hba"; then fail pg.hba_local_only "non-local (TCP) line present"; else ok pg.hba_local_only; fi
    # shellcheck disable=SC2016 # awk program
    if ! nomatch awk '$1=="include" || $1=="include_dir" || $1=="include_if_exists" || $0 ~ /@/ {bad=1} END {exit bad?0:1}' <<< "$hba"; then fail pg.hba_no_include "include or @file reference present"; else ok pg.hba_no_include; fi
    # shellcheck disable=SC2016 # awk program
    if ! nomatch awk '{m=$4} m!="peer" && m!="reject" {bad=1} END {exit bad?0:1}' <<< "$hba"; then fail pg.hba_methods "only peer/reject allowed"; else ok pg.hba_methods; fi
    # shellcheck disable=SC2016 # awk program
    if ! nomatch awk '$3 ~ /(^|,)\+?(postgres|all)(,|$)/ && $4!="reject" {bad=1} END {exit bad?0:1}' <<< "$hba"; then fail pg.hba_no_superuser "a postgres/all line other than reject is present (09 s10, D-11)"; else ok pg.hba_no_superuser; fi
    last=$(printf '%s\n' "$hba" | tail -n 1)
    if [ "$last" = "local all all reject" ]; then ok pg.hba_reject_last; else fail pg.hba_reject_last "last line must be 'local all all reject'"; fi
    # ADR-054 / AUD-RM2-DEP-25: every peer line names the same single database, exactly. The
    # release tree carries the installer placeholder; an installed host must have a real name
    # (and the --pg-db name, when given).
    local hdb
    local nhdb
    hdb=$(awk '$4 != "reject" {print $2}' <<< "$hba" | sort -u) || hdb=""
    nhdb=$(grep -c . <<< "$hdb") || nhdb=0
    if [ "$nhdb" -ne 1 ]; then fail pg.hba_database "peer lines must name one and the same database"; hdb=""
    elif [ "$MODE" = static ] && [ "$hdb" = candor_intake_TENANT ]; then ok pg.hba_database "installer placeholder candor_intake_TENANT"
    elif ! grep -qxE 'candor_intake_[a-z0-9_]{1,49}' <<< "$hdb"; then fail pg.hba_database "database field must be one exact candor_intake_<tenant> name (no regex, list, all or placeholder)"; hdb=""
    elif [ -n "$PGDB" ] && [ "$hdb" != "$PGDB" ]; then fail pg.hba_database "pg_hba names another database than --pg-db"; hdb=""
    else ok pg.hba_database "exactly one intake database"; fi
    pg_exact pg.hba_exact hba "$hba" "${hdb:-<invalid>}"
  fi
  if snap pg.ident_conf "$PGIDENT" pg_ident.conf; then
    pg_exact pg.ident_exact ident "$(sed -e 's/#.*$//' "$SNAP" | trim | tr -s ' \t' '  ' | grep -v '^$')"
  fi

  [ "$MODE" = host ] || return
  # ---- effective settings as the server computes them (AUD-RM2-DEP-03(1)): includes
  # postgresql.auto.conf (ALTER SYSTEM). Command-line -c options are pinned by the unit check.
  local pgbin=/usr/lib/postgresql/16/bin/postgres dd owner l
  dd=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="data_directory" {print $2}')
  case "$dd" in /*) ;; *) fail pg.effective "data_directory is not an absolute path"; return ;; esac
  # Resolved inside --root only: no symlinked component (AUD-RM2-DEP-17).
  if l=$(symlinked_component "$INPREFIX" "$ROOT$dd"); then fail pg.effective "data directory path has a symlinked component: $l"; return; fi
  if [ ! -d "$ROOT$dd" ]; then fail pg.effective "data directory missing"; return; fi
  # Cumulative statistics never on disk (AUD-RM2-STO-11): pg_stat is a symlink to the RAM-only
  # /run/candor/intake-pg-stat (the link is read, never followed).
  if [ -L "$ROOT$dd/pg_stat" ] && [ "$(readlink -- "$ROOT$dd/pg_stat")" = /run/candor/intake-pg-stat ]; then
    if [ "$LIVE" -eq 1 ] && { [ -L /run/candor/intake-pg-stat ] || [ "$(stat -f -c %T /run/candor/intake-pg-stat 2>/dev/null)" != tmpfs ]; }; then
      fail pg.stats_in_ram "/run/candor/intake-pg-stat is not a tmpfs directory"
    else ok pg.stats_in_ram "pg_stat -> /run/candor/intake-pg-stat"; fi
  else fail pg.stats_in_ram "data_directory/pg_stat must be a symlink to /run/candor/intake-pg-stat (stats file would persist on disk)"; fi
  if snap_opt pg.auto_conf_empty "$ROOT$dd/postgresql.auto.conf" pg.auto.conf "$(stat -c %u -- "$ROOT$dd")"; then
    if [ -n "$(pg_norm "$SNAP")" ]; then fail pg.auto_conf_empty "postgresql.auto.conf contains settings (ALTER SYSTEM)"; else ok pg.auto_conf_empty; fi
  fi
  [ -x "$pgbin" ] || { fail pg.effective "PostgreSQL 16 server binary missing"; return; }
  if ! is_root || ! have setpriv; then fail pg.effective "must run as root with setpriv"; return; fi
  owner=$(stat -c %U -- "$ROOT$dd")
  if [ "$owner" = root ]; then fail pg.effective "data directory owned by root"; return; fi
  if [ "$LIVE" -eq 1 ] && [ "$owner" != postgres ]; then fail pg.datadir_owner "data directory must be owned by postgres, found $(printf '%s' "$owner" | san_names)"; fi
  local -a extra=()
  [ -n "$ROOT" ] && extra=(-c "data_directory=$ROOT$dd")
  local g w v
  while IFS='|' read -r _ g w; do
    if ! v=$(run_as "$owner" "$pgbin" -C "$g" -c "config_file=$PGCONF" "${extra[@]}" 2>/dev/null); then fail "pg.effective.$g" "postgres -C failed"; continue; fi
    if [ "$v" = "$w" ]; then ok "pg.effective.$g" "'$w'"; else fail "pg.effective.$g" "expected '$w', effective value differs"; fi
  done < <(base pgc)
  pg_maint_role "$norm"
}
# Maintenance role (lead decision 2026-10-01; replaces D-34's SET ROLE design): VACUUM and
# VACUUM FULL run as candor_intake_maint, the OWNER OF THE DATABASE (PostgreSQL 16 lets the
# database owner vacuum every non-shared table). The role must own no table, schema, function
# or type, must not be a member of any role except pg_checkpoint (granted INHERIT TRUE, SET
# FALSE, no ADMIN) - in particular never of the schema owner candor_intake_migrator - must have
# no member, and no SUPERUSER/CREATEROLE/CREATEDB/REPLICATION/BYPASSRLS, NOINHERIT.
# Asked through the running server, connected exactly as the maintenance jobs connect
# (OS user candor-imaint with the socket group, peer map "maint"); catalog reads only.
pg_maint_role() { # normalised-conf
  local sockdir sock out ug sg psql=/usr/lib/postgresql/16/bin/psql
  sockdir=$(printf '%s\n' "$1" | awk -F'\t' '$1=="unix_socket_directories" {print $2}')
  case "$sockdir" in /*) ;; *) fail pg.maint_role "unix_socket_directories is not one absolute path"; return ;; esac
  sock="$ROOT$sockdir/.s.PGSQL.5432"
  if [ -z "$PGDB" ]; then
    if [ -S "$sock" ]; then fail pg.maint_role "the server is running: pass --pg-db <tenant database> so the maintenance role is checked"
    else skip pg.maint_role "server not running and no --pg-db: role memberships not checked"; fi
    return
  fi
  [ -S "$sock" ] || { fail pg.maint_role "--pg-db given but no server socket in the configured directory"; return; }
  [ -x "$psql" ] || psql=$(command -v psql) || { fail pg.maint_role "psql missing"; return; }
  if ! { ug=$(id -g candor-imaint 2>/dev/null) && sg=$(getent group candor-istore | cut -d: -f3) && [ -n "$sg" ]; }; then fail pg.maint_role "users candor-imaint/candor-istore missing"; return; fi
  out=$(timeout 30 env -i PATH=/usr/bin:/bin setpriv --reuid=candor-imaint --regid="$ug" --groups="$sg" --no-new-privs -- \
        "$psql" -X -w -q -A -t -F '|' -h "$ROOT$sockdir" -U candor_intake_maint -d "$PGDB" -c "SELECT
      (SELECT coalesce(string_agg(pg_catalog.pg_get_userbyid(m.roleid) || ':' || m.admin_option::text || ':' || m.inherit_option::text || ':' || m.set_option::text, ' ' ORDER BY 1), '') FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid),
      (SELECT count(*) FROM pg_catalog.pg_auth_members m WHERE m.roleid = r.oid),
      (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)::text,
      (SELECT pg_catalog.pg_get_userbyid(d.datdba) FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()),
      (SELECT count(*) FROM pg_catalog.pg_class WHERE relowner = r.oid) + (SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspowner = r.oid)
        + (SELECT count(*) FROM pg_catalog.pg_proc WHERE proowner = r.oid) + (SELECT count(*) FROM pg_catalog.pg_type WHERE typowner = r.oid),
      (SELECT count(*) FROM pg_catalog.pg_database WHERE NOT datistemplate AND datname <> 'postgres'),
      (SELECT d.datconnlimit FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()),
      r.rolconnlimit,
      (SELECT count(*) FROM pg_catalog.pg_db_role_setting s WHERE s.setrole = 0),
      (SELECT count(*) FROM pg_catalog.pg_db_role_setting s CROSS JOIN LATERAL pg_catalog.unnest(s.setconfig) AS c(kv)
         WHERE s.setrole <> 0 AND (s.setdatabase = 0 OR pg_catalog.split_part(c.kv, '=', 1) NOT IN
           ('search_path', 'statement_timeout', 'idle_in_transaction_session_timeout', 'temp_file_limit', 'default_transaction_read_only')))
      FROM pg_catalog.pg_roles r WHERE r.rolname = current_user" </dev/null 2>/dev/null) || { fail pg.maint_role "cannot connect as candor_intake_maint (peer map maint) to --pg-db"; return; }
  local mem nmem attr dba own ndb dcl rcl dbset rset
  IFS='|' read -r mem nmem attr dba own ndb dcl rcl dbset rset <<< "$out"
  # ADR-054 / AUD-RM2-DEP-25: one intake database per cluster, and none of the owner's DoS
  # levers in use (connection limits, ALTER DATABASE ... SET, other role settings).
  if [ "$ndb" = 1 ]; then ok pg.maint_role.single_database "the cluster holds exactly one intake database"; else fail pg.maint_role.single_database "the cluster holds $ndb databases besides postgres and the templates (ADR-054: exactly one)"; fi
  if [ "$dcl" = -1 ]; then ok pg.maint_role.db_connlimit "no CONNECTION LIMIT on the database"; else fail pg.maint_role.db_connlimit "ALTER DATABASE ... CONNECTION LIMIT set"; fi
  if [ "$rcl" = -1 ]; then ok pg.maint_role.role_connlimit "no CONNECTION LIMIT on candor_intake_maint"; else fail pg.maint_role.role_connlimit "CONNECTION LIMIT set on candor_intake_maint"; fi
  if [ "$dbset" = 0 ]; then ok pg.maint_role.no_database_settings "no ALTER DATABASE ... SET"; else fail pg.maint_role.no_database_settings "$dbset database-wide setting row(s) (ALTER DATABASE ... SET)"; fi
  if [ "$rset" = 0 ]; then ok pg.maint_role.role_settings "role settings only per database and on the store's allow-list"; else fail pg.maint_role.role_settings "$rset role setting(s) global or outside the allow-list"; fi
  case "$mem" in ""|"pg_checkpoint:false:true:false") ok pg.maint_role.memberships "member of pg_checkpoint only (no schema owner, no SET)" ;;
    *) fail pg.maint_role.memberships "candor_intake_maint is a member of another role (e.g. the schema owner), or with ADMIN/SET: $(printf '%s' "$mem" | tr ' ' '\n' | cut -d: -f1 | san_names)" ;; esac
  if [ "$nmem" = 0 ]; then ok pg.maint_role.no_members; else fail pg.maint_role.no_members "$nmem role(s) are members of candor_intake_maint"; fi
  if [ "$attr" = false ]; then ok pg.maint_role.attributes "NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS NOINHERIT"; else fail pg.maint_role.attributes "privileged attribute or INHERIT set"; fi
  if [ "$dba" = candor_intake_maint ]; then ok pg.maint_role.db_owner "owns the tenant database"; else fail pg.maint_role.db_owner "tenant database is not owned by candor_intake_maint"; fi
  if [ "$own" = 0 ]; then ok pg.maint_role.owns_no_objects; else fail pg.maint_role.owns_no_objects "owns $own table/schema/function/type object(s) in the tenant database"; fi
}
pg_exact() { # rule kind text [db]: normalised lines must equal the baseline's <kind>| lines, in order ({DB} -> db)
  local n
  printf '%s\n' "$3" | grep -v '^$' > "$WORK/$2.got"
  awk -F'|' -v k="$2" -v db="${4:-}" '$1==k { l=substr($0, length(k)+2); if (db != "") gsub(/\{DB\}/, db, l); print l }' "$BASE" > "$WORK/$2.want"
  if cmp -s "$WORK/$2.got" "$WORK/$2.want"; then ok "$1" "$(wc -l < "$WORK/$2.want") line(s) equal the release file"
  else
    n=$(awk 'NR==FNR { a[FNR]=$0; na=FNR; next } { nb=FNR; if (!(FNR in a) || a[FNR]!=$0) { print FNR; f=1; exit } } END { if (!f) print (nb < na ? nb+1 : na+1) }' "$WORK/$2.want" "$WORK/$2.got")
    fail "$1" "differs from the release file at line $n (expected $(wc -l < "$WORK/$2.want"), found $(wc -l < "$WORK/$2.got") line(s))"
  fi
}

# =============================================================================== systemd units
ALL_UNITS="tor@candor-intake.service candor-intake-web.service candor-sealer.service candor-intake-store.service
candor-intake-pg.service candor-intake-web.socket candor-sealer.socket candor-intake-store.socket
candor-intake-store-relay.socket run-candor-staging.mount candor-intake-vacuum.service candor-intake-vacuum.timer
candor-intake-maint.service candor-intake-maint.timer"
SERVICES="tor@candor-intake.service:15 candor-intake-web.service:5 candor-sealer.service:5 candor-intake-store.service:5 candor-intake-pg.service:5 candor-intake-vacuum.service:5 candor-intake-maint.service:5"

SR=""
units_root() { # static: a scratch root holding the tree (+ profile drop-ins) as /etc/systemd/system
  if [ "$MODE" = host ]; then SR=${ROOT:-/}; return 0; fi
  SR="$WORK/sroot"
  # No symlink anywhere in the unit tree (AUD-RM2-DEP-17): systemd would follow it, and so
  # would the merge below.
  local l
  if l=$(symlinked_component "$INPREFIX" "$DIR/systemd/x") || [ -n "$(find "$DIR/systemd" -type l -print -quit 2>/dev/null)" ] ||
     { [ -n "$PROFILE" ] && { l=$(symlinked_component "$INPREFIX" "$DIR/profiles/$PROFILE/x") || [ -n "$(find "$DIR/profiles/$PROFILE" -type l -print -quit 2>/dev/null)" ]; }; }; then
    fail unit.no_symlinks "symlink in the unit tree (refused, not followed)"; return 1
  fi
  mkdir -p "$SR/etc/systemd/system" && cp -a "$DIR/systemd/." "$SR/etc/systemd/system/" || return 1
  if [ -n "$PROFILE" ]; then
    local d
    for d in "$DIR/profiles/$PROFILE"/*.d; do
      [ -d "$d" ] || continue
      mkdir -p "$SR/etc/systemd/system/$(basename "$d")" && cp -a "$d/." "$SR/etc/systemd/system/$(basename "$d")/" || return 1
    done
  fi
  # The copy is checked again (AUD-RM2-DEP-24): an entry swapped for a symlink, FIFO or device
  # between the check above and cp is copied as such (cp -a never follows or reads it) and is
  # refused here, before systemd or the merge could open it.
  if [ -n "$(find "$SR" ! -type f ! -type d -print -quit 2>/dev/null)" ]; then
    fail unit.no_symlinks "symlink or special file in the unit tree (refused, not followed)"; return 1
  fi
}
rootopt() { if [ "$SR" != / ]; then printf -- '--root=%s' "$SR"; else printf -- '--root=/'; fi; }

# Merge fragment + drop-ins (in systemd's order) into "Section|Key|v1 ;; v2 ;; ..." lines.
# An empty assignment is kept as an empty element, so a reset is always visible.
unit_merge() { # files... -> stdout (callers checked every path for symlinks; read race-free)
  local f
  for f in "$@"; do
    printf '#@@FILE\n'
    # An unreadable or refused file becomes a directive no baseline has, so the unit fails.
    if safe_copy "$f" "$WORK/um.tmp"; then cat -- "$WORK/um.tmp"; else printf '[X-Candor-Refused]\nUnreadableOrUnsafeFile=1\n'; fi
    rm -f -- "$WORK/um.tmp"; printf '\n'
  done | awk '
    function flush_line(l,   k, v, e, id) {
      sub(/^[ \t]+/, "", l); sub(/[ \t]+$/, "", l)
      if (l == "" || l ~ /^[#;]/) return
      if (l ~ /^\[.*\]$/) { sect=substr(l, 2, length(l)-2); return }
      e=index(l, "="); if (e == 0) { k=l; v="<no-assignment>" } else { k=substr(l, 1, e-1); v=substr(l, e+1) }
      sub(/[ \t]+$/, "", k); sub(/^[ \t]+/, "", v)
      id=sect "|" k
      if (!(id in cnt)) { keys[++nk]=id; cnt[id]=0 }
      if (v == "") { val[id]=""; cnt[id]=1 }
      else if (cnt[id] == 0) { val[id]=v; cnt[id]=1 }
      else { val[id]=val[id] " ;; " v; cnt[id]++ }
    }
    /^#@@FILE$/ { if (cont != "") flush_line(cont); cont=""; sect=""; next }
    { line=$0
      if (cont == "" && line ~ /^[ \t]*[#;]/) next
      if (line ~ /\\$/) { cont=cont substr(line, 1, length(line)-1) " "; next }
      flush_line(cont line); cont="" }
    END { if (cont != "") flush_line(cont); for (i=1; i<=nk; i++) print keys[i] "|" val[keys[i]] }'
}

check_units() {
  need_tools unit.tools systemd-analyze jq || return
  units_root || { fail unit.root "cannot prepare the unit tree"; return; }
  local ro u frag
  ro=$(rootopt)
  # systemd's own resolution of fragment and drop-in paths (unit dump at debug level).
  # shellcheck disable=SC2086 # ALL_UNITS is a fixed word list
  SYSTEMD_LOG_LEVEL=debug systemd-analyze verify "$ro" --man=no --recursive-errors=no $ALL_UNITS > "$WORK/verify.dbg" 2>&1
  awk -v units=" $(printf '%s' "$ALL_UNITS" | tr '\n' ' ') " '
    /^\t-> Unit [^ ]+:$/ { u=$3; sub(/:$/, "", u); take=(index(units, " " u " ") > 0 && !(u in done)); if (take) done[u]=1; next }
    /^\t-> / { take=0 }
    take && /^\t\tFragment Path: / { print u "\tF\t" substr($0, index($0, ": ")+2) }
    take && /^\t\tDropIn Path: / { print u "\tD\t" substr($0, index($0, ": ")+2) }' "$WORK/verify.dbg" > "$WORK/unitpaths"
  # Diagnostics (unknown keys/sections, parse errors, ...). Static mode tolerates only the
  # missing executables of a host that is not installed.
  # shellcheck disable=SC2086 # ALL_UNITS is a fixed word list
  SYSTEMD_LOG_LEVEL=notice systemd-analyze verify "$ro" --man=no --recursive-errors=no $ALL_UNITS 2>&1 |
    grep -v '^$' > "$WORK/verify.out"
  if [ "$MODE" = static ]; then grep -vE ': Command /[^ ]+ is not executable: No such file or directory$' "$WORK/verify.out" > "$WORK/verify.f"; else cp "$WORK/verify.out" "$WORK/verify.f"; fi
  # Diagnostics can quote file content: only their number is reported (AUD-RM2-DEP-17).
  if [ -s "$WORK/verify.f" ]; then fail unit.verify "systemd-analyze verify: $(wc -l < "$WORK/verify.f") diagnostic line(s) (text suppressed; run systemd-analyze verify)"; else ok unit.verify "systemd-analyze verify clean"; fi

  local -a files
  local f l lnk
  mkdir -p "$WORK/eff"
  for u in $ALL_UNITS; do
    frag=$(awk -F'\t' -v u="$u" '$1==u && $2=="F" {print $3}' "$WORK/unitpaths")
    if [ "$frag" != "${SR%/}/etc/systemd/system/$u" ] || [ -L "$frag" ] || [ ! -f "$frag" ]; then
      fail "unit.$u.fragment" "unit must load from /etc/systemd/system/$u (found '$(printf '%s' "${frag#"${SR%/}"}" | san_names)')"; continue
    fi
    files=("$frag")
    while IFS= read -r f; do files+=("$f"); done < <(awk -F'\t' -v u="$u" '$1==u && $2=="D" {print $3}' "$WORK/unitpaths")
    # Never follow a symlinked fragment, drop-in or drop-in directory (AUD-RM2-DEP-17).
    lnk=""
    for f in "${files[@]}"; do if l=$(symlinked_component "${SR%/}" "$f"); then lnk=$l; break; fi; done
    if [ -n "$lnk" ]; then fail "unit.$u.fragment" "refused: symlinked unit/drop-in path component $(printf '%s' "$lnk" | san_names)"; continue; fi
    ok "unit.$u.fragment" "$(( ${#files[@]} - 1 )) drop-in(s) applied"
    unit_merge "${files[@]}" > "$WORK/eff/$u"
    # Effective, section-aware directives against the per-unit allow-list (exact values).
    awk -v u="$u" '
      FNR==NR { if (split($0, a, "|") >= 5 && a[1]=="unit" && a[2]==u) {
                  k=a[3] "|" a[4]; v=substr($0, length(a[1] a[2] a[3] a[4] a[5])+6)
                  if (!(k in mode)) { order[++n]=k; mode[k]=a[5]; ex[k]=v }
                  else if (a[5]=="=") ex[k]=ex[k] " ;; " v } next }
      { e=index($0, "|"); s=substr($0, 1, e-1); r=substr($0, e+1); e=index(r, "|"); k=s "|" substr(r, 1, e-1); got[k]=substr(r, e+1); seen[k]=1
        if (!(k in mode)) { dk=k; gsub(/[^A-Za-z0-9_|]/, "?", dk); dk=substr(dk, 1, 64); sub(/\|/, ".", dk); printf "FAIL\tunit.%s.%s\tdirective not allowed (value not shown)\n", u, dk } }
      END { for (i=1; i<=n; i++) { k=order[i]; m=mode[k]; dk=k; sub(/\|/, ".", dk)
        if (m=="*") { if (k in seen) printf "OK\tunit.%s.%s\t(semantic check)\n", u, dk; else printf "FAIL\tunit.%s.%s\tmissing\n", u, dk; continue }
        g=(k in seen) ? got[k] : ""
        if (m=="=") { if (!(k in seen)) printf "FAIL\tunit.%s.%s\tmissing (expected %s)\n", u, dk, ex[k]
                      else if (g==ex[k]) printf "OK\tunit.%s.%s\t%s\n", u, dk, (g=="" ? "<empty>" : g)
                      else printf "FAIL\tunit.%s.%s\texpected [%s], effective value differs\n", u, dk, ex[k] }
        else if (m=="~") { if (g ~ ex[k]) printf "OK\tunit.%s.%s\tmatches %s\n", u, dk, ex[k]
                           else printf "FAIL\tunit.%s.%s\teffective value does not match %s\n", u, dk, ex[k] } } }' "$BASE" "$WORK/eff/$u" > "$WORK/rl" 2>/dev/null ||
      printf 'FAIL\tunit.%s.allow_list\tevaluation failed (awk error; fail closed)\n' "$u" >> "$WORK/rl"
    report_lines < "$WORK/rl"
  done

  # Sealer syscall filter (AUD-RM2-DEP-16): the assignment lines are pinned exactly above; here
  # the EFFECTIVE allow-set (systemd's group expansion, allow-list minus '~' lines plus re-adds,
  # in order) must equal the release set, and the explicitly denied calls must stay denied.
  [ -f "$WORK/eff/candor-sealer.service" ] && check_sealer_syscalls "$WORK/eff/candor-sealer.service"
  check_sealer_memory "$WORK/eff/candor-sealer.service" "$WORK/eff/run-candor-staging.mount"
  # Relay socket: an IPAddressAllow drop-in must name exactly the single @core_relay address.
  local allow
  allow=$(awk -F'|' '$1=="Socket" && $2=="IPAddressAllow" {print substr($0, length($1 $2)+3)}' "$WORK/eff/candor-intake-store-relay.socket" 2>/dev/null)
  if [ -z "$allow" ]; then ok unit.relay_ip_allow "none (fail closed until the site drop-in exists)"
  elif [ "$NFT_LOADED" -eq 1 ] && [ "$allow" = "$(printf '%s' "$CORE_RELAY_ELEMS" | trim)/32" ]; then ok unit.relay_ip_allow "equals @core_relay/32"
  else fail unit.relay_ip_allow "IPAddressAllow must be exactly <@core_relay element>/32"; fi

  # systemd's exposure assessment of the effective unit: within budget, and only the
  # documented residual items may score (17 §5.3, R7 SI-B-01; D-25).
  local spec thr name
  local -a sopt
  if [ "$LIVE" -eq 1 ]; then sopt=(); else sopt=(--offline=true "$ro"); fi
  for spec in $SERVICES; do
    name=${spec%%:*}; thr=${spec##*:}
    if systemd-analyze security "${sopt[@]}" --threshold="$thr" --json=short --no-pager "$name" > "$WORK/sec.json" 2>/dev/null; then
      ok "unit.$name.security_threshold" "exposure within $((thr / 10)).$((thr % 10))"
    else fail "unit.$name.security_threshold" "exposure over budget $((thr / 10)).$((thr % 10)) (or assessment failed)"; fi
    local extra secrc=0
    jq -r '.[] | select(.exposure != null and (.exposure|tostring|tonumber) > 0) | .name' "$WORK/sec.json" 2>/dev/null | sort > "$WORK/sec.bad" || secrc=1
    awk -F'|' -v u="$name" '$1=="sec" && $2==u {print substr($0, length($1 $2)+3)}' "$BASE" | sort > "$WORK/sec.ok" || secrc=1
    extra=$(comm -23 "$WORK/sec.bad" "$WORK/sec.ok" | tr '\n' ' ') || secrc=1
    if [ ! -s "$WORK/sec.json" ]; then fail "unit.$name.security_items" "no assessment"
    elif [ "$secrc" -ne 0 ]; then tool_err "unit.$name.security_items"
    elif [ -n "$extra" ]; then fail "unit.$name.security_items" "new exposure item(s): $(printf '%s' "$extra" | san_names)"
    else ok "unit.$name.security_items" "only documented residual items"; fi
  done

  [ "$MODE" = host ] || return
  # Units or drop-ins in places systemd-analyze verify does not read (transient, generators).
  local d bad=""
  for d in "$ROOT/run/systemd/transient" "$ROOT/run/systemd/generator" "$ROOT/run/systemd/generator.early" "$ROOT/run/systemd/generator.late"; do
    [ -d "$d" ] || continue
    bad="$bad$(find "$d" -mindepth 1 -maxdepth 1 \( -name 'candor*' -o -name 'tor@*' -o -name 'tor-*' -o -name 'run-candor*' -o -name 'service.d' -o -name 'socket.d' -o -name 'mount.d' \) -printf '%f ' 2>/dev/null)"
  done
  if [ -n "$bad" ]; then fail unit.no_transient_or_generated "transient/generated unit configuration present: $(printf '%s' "$bad" | san_names)"; else ok unit.no_transient_or_generated; fi
  [ "$LIVE" -eq 1 ] || { skip unit.live "offline root: systemctl show not checked"; return; }
  check_units_live
}

# Sealer memory (lead decision after round 5): from the EFFECTIVE units (base + drop-ins, so a
# profile is checked with its own MemoryMax and mount size), the last
# CANDOR_SEALER_MEMORY_BUDGET_MIB must exist and satisfy
#   (a) budget <= MemoryMax - 1024 MiB (base working set + slack outside the budget);
#   (b) staging tmpfs size= >= budget (staged parts are budget-counted, so the budget and not
#       ENOSPC refuses an upload);
#   CANDOR_SEALER_SESSION_UPLOAD_MIB present and <= budget / 2 (the shared pool);
#   CANDOR_SEALER_UPLOAD_SLOTS present, an integer in 16..4096;
#   CANDOR_SEALER_MAX_SESSIONS present, 16..65536, and <= UPLOAD_SLOTS (ADR-056);
#   guaranteed slice (budget / 2) / UPLOAD_SLOTS >= 1 MiB.
# Environment= is evaluated with systemd semantics: last assignment per variable wins, an
# empty assignment clears all.
# Unparseable values (infinity, %, missing size=) fail.
check_sealer_memory() { # eff-sealer eff-mount
  local res
  res=$(awk -F'|' '
    function bytes(v,   n, u) {
      if (v !~ /^[0-9]+[KkMmGgTt]?$/) return -1
      n=v; sub(/[KkMmGgTt]$/, "", n); u=toupper(substr(v, length(v)))
      if (u == "K") return n * 1024; if (u == "M") return n * 1048576
      if (u == "G") return n * 1073741824; if (u == "T") return n * 1099511627776
      return n + 0 }
    function last(v,   a, k) { k=split(v, a, / ;; /); return a[k] }
    function num(k) { return ((k in env) && env[k] ~ /^[1-9][0-9]*$/ && length(env[k]) <= 7) ? env[k] + 0 : -1 }
    FNR==NR { if ($1=="Service" && $2=="MemoryMax") mm=last(substr($0, length($1 $2)+3))
              if ($1=="Service" && $2=="Environment") { v=substr($0, length($1 $2)+3); if (v == "") delete env
                k=split(v, a, / ;; /); for (i=1; i<=k; i++) { if (a[i] == "") { delete env; continue }
                  e=index(a[i], "="); if (e > 0) env[substr(a[i], 1, e-1)]=substr(a[i], e+1) } }
              next }
    $1=="Mount" && $2=="Options" { o=last(substr($0, length($1 $2)+3)); k=split(o, a, ","); for (i=1; i<=k; i++) if (a[i] ~ /^size=/) sz=substr(a[i], 6) }
    END {
      mib=1048576; b=num("CANDOR_SEALER_MEMORY_BUDGET_MIB")
      if (b < 0) print "FAIL\tunit.candor-sealer.memory_budget\tCANDOR_SEALER_MEMORY_BUDGET_MIB missing or invalid"
      else {
        m=bytes(mm); s=bytes(sz)
        if (m < 0) print "FAIL\tunit.candor-sealer.memory_budget\tMemoryMax missing or not an absolute size"
        else if (b * mib > m - 1024 * mib) printf "FAIL\tunit.candor-sealer.memory_budget\tbudget %d MiB > MemoryMax %d MiB - 1024 MiB\n", b, m / mib
        else printf "OK\tunit.candor-sealer.memory_budget\tbudget %d MiB <= MemoryMax %d MiB - 1024 MiB\n", b, m / mib
        if (s < 0) print "FAIL\tunit.candor-sealer.staging_vs_budget\tstaging tmpfs size= missing or not an absolute size"
        else if (s < b * mib) printf "FAIL\tunit.candor-sealer.staging_vs_budget\tstaging tmpfs %d MiB < budget %d MiB (ENOSPC before the budget)\n", s / mib, b
        else printf "OK\tunit.candor-sealer.staging_vs_budget\tstaging tmpfs %d MiB >= budget %d MiB\n", s / mib, b }
      q=num("CANDOR_SEALER_SESSION_UPLOAD_MIB")
      if (q < 0) print "FAIL\tunit.candor-sealer.session_upload\tCANDOR_SEALER_SESSION_UPLOAD_MIB missing or invalid"
      else if (b < 0 || 2 * q > b) printf "FAIL\tunit.candor-sealer.session_upload\tper-draft quota %d MiB > half the budget\n", q
      else printf "OK\tunit.candor-sealer.session_upload\tper-draft quota %d MiB <= budget %d MiB / 2\n", q, b
      n=num("CANDOR_SEALER_UPLOAD_SLOTS")
      if (n < 16 || n > 4096) print "FAIL\tunit.candor-sealer.upload_slots\tCANDOR_SEALER_UPLOAD_SLOTS missing or not an integer in 16..4096"
      else printf "OK\tunit.candor-sealer.upload_slots\t%d upload slots (16..4096)\n", n
      x=num("CANDOR_SEALER_MAX_SESSIONS")
      if (x < 16 || x > 65536) print "FAIL\tunit.candor-sealer.max_sessions\tCANDOR_SEALER_MAX_SESSIONS missing or not an integer in 16..65536"
      else if (n < x) printf "FAIL\tunit.candor-sealer.max_sessions\tUPLOAD_SLOTS < MAX_SESSIONS %d (ADR-056)\n", x
      else printf "OK\tunit.candor-sealer.max_sessions\t%d sessions <= upload slots\n", x
      if (b < 0 || n < 16 || b < 2 * n) print "FAIL\tunit.candor-sealer.upload_slice\t(budget / 2) / UPLOAD_SLOTS < 1 MiB"
      else printf "OK\tunit.candor-sealer.upload_slice\t(budget %d MiB / 2) / %d slots >= 1 MiB\n", b, n }' "$1" "$2" 2>/dev/null)
  if [ -z "$res" ]; then fail unit.candor-sealer.memory_budget "effective sealer/staging units not available"; return; fi
  report_lines <<< "$res"
}

# Effective sealer syscall allow-set (AUD-RM2-DEP-16). systemd semantics: the first non-empty
# assignment selects the mode (must be allow-list); an empty assignment resets; later plain
# entries add, '~' entries remove; '@group' names expand recursively; ':errno' suffixes do not
# change membership. Groups come from this host's systemd (`systemd-analyze syscall-filter`), so
# a systemd upgrade that grows a group shows up as a FAIL until the release re-pins scf| lines.
check_sealer_syscalls() { # effective-unit-file
  local seq
  seq=$(awk -F'|' '$1=="Service" && $2=="SystemCallFilter" {print substr($0, length($1 $2)+3)}' "$1")
  if [ -z "$seq" ]; then fail unit.candor-sealer.syscall_set "no SystemCallFilter"; return; fi
  if ! systemd-analyze syscall-filter --no-pager 2>/dev/null | tr -cd '\11\12\40-\176' | sed 's/\[[0-9;]*m//g' > "$WORK/scf.groups" ||
     ! grep -q '^@system-service$' "$WORK/scf.groups"; then
    fail unit.candor-sealer.syscall_set "cannot expand syscall groups (systemd-analyze syscall-filter)"; return
  fi
  printf '%s\n' "$seq" | awk '
    FNR==NR { if ($0 ~ /^@/) { g=$1; next }
              t=$0; gsub(/^[ \t]+|[ \t]+$/, "", t); if (t == "" || t ~ /^#/) next
              mem[g]=mem[g] " " t; next }
    function expand(n, depth,   a, i, k) {
      if (n !~ /^@/) { out[n]=1; return }
      if (depth > 16 || !(n in mem)) { unknown=1; return }
      k=split(mem[n], a, " "); for (i=1; i<=k; i++) expand(a[i], depth+1)
    }
    { k=split($0, asg, / ;; /)
      for (j=1; j<=k; j++) {
        v=asg[j]; gsub(/^[ \t]+|[ \t]+$/, "", v)
        if (v == "") { delete set; mode=""; continue }
        inv=0; if (substr(v, 1, 1) == "~") { inv=1; v=substr(v, 2) }
        if (mode == "") mode=(inv ? "deny" : "allow")
        nt=split(v, toks, /[ \t]+/)
        for (i=1; i<=nt; i++) { t=toks[i]; sub(/:.*$/, "", t); if (t == "") continue
          delete out; expand(t, 0)
          for (x in out) { if ((mode == "allow") != (inv == 1)) set[x]=1; else delete set[x] } }
      } }
    END { if (mode != "allow") print "!MODE"; if (unknown) print "!UNKNOWN"; for (x in set) print x }' "$WORK/scf.groups" - | sort > "$WORK/scf.eff"
  if grep -q '^!MODE$' "$WORK/scf.eff"; then fail unit.candor-sealer.syscall_set "SystemCallFilter is not in allow-list mode"; return; fi
  if grep -q '^!UNKNOWN$' "$WORK/scf.eff"; then fail unit.candor-sealer.syscall_set "unknown syscall group referenced"; return; fi
  local extra missing never
  if ! base scf | cut -d'|' -f2 | sort -u > "$WORK/scf.want" || [ ! -s "$WORK/scf.want" ] ||
     ! extra=$(comm -13 "$WORK/scf.want" "$WORK/scf.eff" | san_names) ||
     ! missing=$(comm -23 "$WORK/scf.want" "$WORK/scf.eff" | san_names); then tool_err unit.candor-sealer.syscall_set
  elif [ -z "$extra" ] && [ -z "$missing" ]; then ok unit.candor-sealer.syscall_set "$(wc -l < "$WORK/scf.eff") syscalls, equal to the release allow-set"
  else fail unit.candor-sealer.syscall_set "effective allow-set differs from the release set; extra: [${extra}] missing: [${missing}]"; fi
  if ! never=$(base scf-never | cut -d'|' -f2 | sort -u | comm -12 - "$WORK/scf.eff" | san_names); then tool_err unit.candor-sealer.syscall_never
  elif [ -n "$never" ]; then fail unit.candor-sealer.syscall_never "explicitly denied syscall(s) allowed: $never"
  else ok unit.candor-sealer.syscall_never "$(base scf-never | wc -l) explicitly denied syscalls (io_uring, userfaultfd, ptrace, ...) stay denied"; fi
}

# Distribution units the intake's protection depends on (AUD-RM2-DEP-18): nftables.service
# loads the ruleset at boot, systemd-sysctl.service applies the kernel baseline. Fragment from
# /usr/lib, exactly the listed drop-ins, pinned keys, enabled and not masked.
check_host_units() {
  local r=${ROOT:-/} u frag want got l f
  local -a files
  SYSTEMD_LOG_LEVEL=debug systemd-analyze verify "--root=$r" --man=no --recursive-errors=no nftables.service systemd-sysctl.service > "$WORK/hverify.dbg" 2>&1
  awk '
    /^\t-> Unit [^ ]+:$/ { u=$3; sub(/:$/, "", u); take=((u=="nftables.service" || u=="systemd-sysctl.service") && !(u in done)); if (take) done[u]=1; next }
    /^\t-> / { take=0 }
    take && /^\t\tFragment Path: / { print u "\tF\t" substr($0, index($0, ": ")+2) }
    take && /^\t\tDropIn Path: / { print u "\tD\t" substr($0, index($0, ": ")+2) }' "$WORK/hverify.dbg" > "$WORK/hunitpaths"
  for u in nftables.service systemd-sysctl.service; do
    frag=$(awk -F'\t' -v u="$u" '$1==u && $2=="F" {print $3}' "$WORK/hunitpaths")
    if [ "$frag" != "$ROOT/usr/lib/systemd/system/$u" ] || [ ! -f "$frag" ] || l=$(symlinked_component "$INPREFIX" "$frag"); then
      fail "host.unit.$u.fragment" "must load from /usr/lib/systemd/system/$u (missing, masked or overridden)"; continue
    fi
    if ! got=$(awk -F'\t' -v u="$u" '$1==u && $2=="D" {print $3}' "$WORK/hunitpaths" | sed "s|^$ROOT||" | sort | tr '\n' ' ') ||
       ! want=$(awk -F'|' -v u="$u" '$1=="hdropin" && $2==u {print $3}' "$BASE" | sort | tr '\n' ' '); then tool_err "host.unit.$u.dropins"; continue; fi
    if [ "$got" != "$want" ]; then fail "host.unit.$u.dropins" "drop-ins differ from the release set (expected: ${want:-none})"; continue; fi
    ok "host.unit.$u.dropins" "${want:-none}"
    files=("$frag")
    while IFS= read -r f; do files+=("$f"); done < <(awk -F'\t' -v u="$u" '$1==u && $2=="D" {print $3}' "$WORK/hunitpaths")
    for f in "${files[@]}"; do if l=$(symlinked_component "$INPREFIX" "$f"); then fail "host.unit.$u.fragment" "refused: symlinked drop-in path"; continue 2; fi; done
    unit_merge "${files[@]}" > "$WORK/eff.$u"
    awk -v u="$u" '
      FNR==NR { if (split($0, a, "|") >= 5 && a[1]=="hunit" && a[2]==u) { k=a[3] "|" a[4]; order[++n]=k; mode[k]=a[5]; ex[k]=substr($0, length(a[1] a[2] a[3] a[4] a[5])+6) } next }
      { e=index($0, "|"); s=substr($0, 1, e-1); r=substr($0, e+1); e=index(r, "|"); kk=substr(r, 1, e-1); k=s "|" kk; got[k]=substr(r, e+1); seen[k]=1
        # A condition or assertion can silently skip the unit: only pinned ones are allowed.
        if (kk ~ /^(Condition|Assert)/ && !(k in mode)) { gsub(/[^A-Za-z0-9]/, "?", kk); printf "FAIL\thost.unit.%s.%s\tunpinned condition/assertion\n", u, substr(kk, 1, 48) } }
      END { for (i=1; i<=n; i++) { k=order[i]; dk=k; sub(/\|/, ".", dk)
        if (mode[k]=="absent") { if (k in seen) printf "FAIL\thost.unit.%s.%s\tmust not be set\n", u, dk; else printf "OK\thost.unit.%s.%s\tabsent\n", u, dk }
        else if (!(k in seen)) printf "FAIL\thost.unit.%s.%s\tmissing (expected %s)\n", u, dk, ex[k]
        else if (got[k]==ex[k]) printf "OK\thost.unit.%s.%s\t%s\n", u, dk, ex[k]
        else printf "FAIL\thost.unit.%s.%s\texpected [%s], effective value differs\n", u, dk, ex[k] } }' "$BASE" "$WORK/eff.$u" > "$WORK/rl"; report_lines < "$WORK/rl"
  done
  # Enabled at boot: nftables via a .wants link of the admin, systemd-sysctl statically (vendor).
  if [ -n "$(find "$ROOT/etc/systemd/system" -mindepth 2 -maxdepth 2 -path '*.wants/nftables.service' -print -quit 2>/dev/null)" ]; then ok host.unit.nftables.service.enabled
  else fail host.unit.nftables.service.enabled "nftables.service is not enabled (no .wants link)"; fi
  if [ -e "$ROOT/usr/lib/systemd/system/sysinit.target.wants/systemd-sysctl.service" ]; then ok host.unit.systemd-sysctl.service.enabled "pulled in by sysinit.target"
  else fail host.unit.systemd-sysctl.service.enabled "not pulled in by sysinit.target"; fi
  if [ "$LIVE" -eq 1 ] && have systemctl; then
    got=$(systemctl is-enabled nftables.service 2>/dev/null)
    if [ "$got" = enabled ]; then ok host.unit.nftables.service.live_enabled; else fail host.unit.nftables.service.live_enabled "systemctl is-enabled: not 'enabled'"; fi
    got=$(systemctl is-enabled systemd-sysctl.service 2>/dev/null)
    if [ "$got" = static ]; then ok host.unit.systemd-sysctl.service.live_enabled; else fail host.unit.systemd-sysctl.service.live_enabled "systemctl is-enabled: not 'static' (masked?)"; fi
  fi
}

# Live properties of the loaded units (systemctl show; AUD-RM2-DEP-03(4)).
check_units_live() {
  have systemctl || { fail unit.live "systemctl missing"; return; }
  local u spec kind p want got
  for spec in tor@candor-intake.service:tor candor-intake-web.service:candor candor-sealer.service:candor candor-intake-store.service:candor candor-intake-pg.service:pg candor-intake-vacuum.service:candor candor-intake-maint.service:candor; do
    u=${spec%%:*}; kind=${spec##*:}
    if ! systemctl show --no-pager "$u" > "$WORK/show" 2>/dev/null || [ ! -s "$WORK/show" ]; then fail "unit.$u.live" "systemctl show failed"; continue; fi
    # Drop-ins actually loaded must be the ones systemd-analyze verify found.
    if ! got=$(sed -n 's/^DropInPaths=//p' "$WORK/show" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ') ||
       ! want=$(awk -F'\t' -v u="$u" '$1==u && $2=="D" {print $3}' "$WORK/unitpaths" | sort | tr '\n' ' '); then tool_err "unit.$u.live.dropins"
    elif [ "$got" = "$want" ]; then ok "unit.$u.live.dropins"; else fail "unit.$u.live.dropins" "loaded drop-ins differ from the files (transient, control or generated drop-in?)"; fi
    while IFS='|' read -r _ kinds p want; do
      case ",$kinds," in *",all,"*|*",$kind,"*) ;; *) continue ;; esac
      got=$(sed -n "s/^$p=//p" "$WORK/show" | head -n 1)
      if [ "$got" = "$want" ]; then ok "unit.$u.live.$p" "$want"; else fail "unit.$u.live.$p" "expected '$want', loaded value differs"; fi
    done < <(base show)
  done
}

# =============================================================================== journald
journald_eff() { # label file catconfig-name -> "Key=Value" last-wins of [Journal]
  if [ "$MODE" = host ]; then
    systemd-analyze "--root=${ROOT:-/}" cat-config "$3" 2>/dev/null
  else cat -- "$SNAP"; fi | awk '
    /^[ \t]*[#;]/ || /^[ \t]*$/ { next }
    /^\[/ { s=$0; next }
    s=="[Journal]" { e=index($0, "="); k=substr($0, 1, e-1); v=substr($0, e+1); gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v); val[k]=v }
    END { for (k in val) print k "=" val[k] }'
}
to_seconds() { # systemd time span (subset) -> seconds, or empty if unparseable
  printf '%s' "$1" | awk '
    { s=$0; total=0; ok=1
      while (length(s) > 0) {
        if (match(s, /^[ ]*[0-9]+[ ]*(s|sec|m|min|h|hr|d|day|days|w)?/)) {
          tok=substr(s, RSTART, RLENGTH); s=substr(s, RLENGTH+1)
          n=tok; gsub(/[^0-9]/, "", n); u=tok; gsub(/[0-9 ]/, "", u)
          mult = (u=="" || u=="s" || u=="sec") ? 1 : (u=="m" || u=="min") ? 60 : (u=="h" || u=="hr") ? 3600 : (u=="d" || u=="day" || u=="days") ? 86400 : (u=="w") ? 604800 : -1
          if (mult < 0) { ok=0; break }
          total += n * mult
        } else { ok=0; break }
      }
      if (ok) print total }'
}
check_journald() { # rule file catconfig-name ns(0|1)
  if [ "$MODE" = static ]; then snap "$1.file" "$2" "journald.$1" || return; fi
  [ "$MODE" = static ] || have systemd-analyze || { fail "$1" "systemd-analyze missing"; return; }
  local e k w g s
  e=$(journald_eff "$1" "$2" "$3")
  [ -n "$e" ] || { fail "$1.effective" "no effective [Journal] configuration found"; return; }
  for k in Storage=volatile ForwardToSyslog=no ForwardToKMsg=no ForwardToConsole=no ForwardToWall=no Audit=no; do
    w=${k#*=}; k=${k%%=*}
    g=$(printf '%s\n' "$e" | sed -n "s/^$k=//p")
    if [ "$g" = "$w" ]; then ok "$1.$k" "$w"; else fail "$1.$k" "expected '$w', effective value differs"; fi
  done
  for k in MaxRetentionSec:86400 MaxFileSec:3600; do
    w=${k#*:}; k=${k%%:*}
    g=$(printf '%s\n' "$e" | sed -n "s/^$k=//p"); s=$(to_seconds "$g")
    if [ -n "$s" ] && [ "$s" -gt 0 ] && [ "$s" -le "$w" ]; then ok "$1.$k" "${s}s"; else fail "$1.$k" "must be set and <= ${w}s"; fi
  done
  if [ "$4" -eq 1 ]; then
    g=$(printf '%s\n' "$e" | sed -n 's/^MaxLevelStore=//p')
    case "$g" in emerg|alert|crit|0|1|2) ok "$1.MaxLevelStore" "$g" ;; *) fail "$1.MaxLevelStore" "must be crit or lower" ;; esac
  fi
}

# =============================================================================== kernel baseline
check_kernel() {
  local k w g src
  # ---- sysctl (20 §11.4, 17 sysctl row; AUD-RM2-DEP-09)
  if [ "$LIVE" -eq 1 ]; then src=live
  elif [ "$MODE" = host ]; then src=offline
  else src="file"; if snap kernel.sysctl.file "$SYSCTL" sysctl.conf; then local SYSCTL=$SNAP; else src="none"; fi; fi
  if [ "$src" = file ]; then
    local extra
    extra=$(awk -F'|' 'NR==FNR { if ($1=="sysctl") ok[$2]=1; next }
      /^[ \t]*[#;]/ || /^[ \t]*$/ { next }
      { l=$0; sub(/^[ \t]*-?/, "", l); e=index(l, "="); k=substr(l, 1, e-1); gsub(/[ \t]+$/, "", k); if (!(k in ok)) print k }' "$BASE" "$SYSCTL" | san_names) || extra=ERR
    if [ "$extra" = ERR ]; then tool_err kernel.sysctl.allowed_keys
    elif [ -n "$extra" ]; then fail kernel.sysctl.allowed_keys "keys not in the baseline: $extra"; else ok kernel.sysctl.allowed_keys; fi
  fi
  # Offline precedence = systemd-sysctl's (AUD-RM2-DEP-18): sysctl.d only, in systemd's order;
  # /etc/sysctl.conf counts only through Debian's 99-sysctl.conf link inside sysctl.d.
  if [ "$src" = file ] || [ "$src" = offline ]; then
    { if [ "$src" = file ]; then cat -- "$SYSCTL"; else systemd-analyze "--root=$ROOT" cat-config sysctl.d 2>/dev/null; fi; } |
      awk '/^[ \t]*[#;]/ || /^[ \t]*$/ { next } { l=$0; sub(/^[ \t]*-?/, "", l); e=index(l, "="); k=substr(l, 1, e-1); v=substr(l, e+1)
        gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v); gsub(/[ \t]+/, " ", v); val[k]=v }
        END { for (k in val) print k "\t" val[k] }' > "$WORK/sysctl.eff"
  fi
  if [ "$src" != none ]; then
    while IFS='|' read -r _ k w; do
      if [ "$src" = live ]; then
        if [ -r "/proc/sys/$(printf '%s' "$k" | tr . /)" ]; then g=$(tr -s ' \t' '  ' < "/proc/sys/$(printf '%s' "$k" | tr . /)" | trim); else g="<absent>"; fi
      else g=$(awk -F'\t' -v k="$k" '$1==k {print $2}' "$WORK/sysctl.eff"); fi
      if [ "$g" = "$w" ]; then ok "kernel.sysctl.$k" "$w"; else fail "kernel.sysctl.$k" "expected '$w', effective value differs"; fi
    done < <(base sysctl)
  fi
  # ---- systemd-coredump stores nothing (20 §11.4, REQ-H-58)
  local cd
  if [ "$MODE" = host ]; then cd=$(systemd-analyze "--root=${ROOT:-/}" cat-config systemd/coredump.conf 2>/dev/null)
  elif snap kernel.coredump.file "$COREDUMP" coredump.conf; then cd=$(cat -- "$SNAP"); else cd=""; fi
  for k in Storage=none ProcessSizeMax=0; do
    w=${k#*=}; k=${k%%=*}
    g=$(printf '%s\n' "$cd" | awk -v k="$k" '/^\[/ { s=$0; next } s=="[Coredump]" { e=index($0, "="); kk=substr($0, 1, e-1); gsub(/[ \t]/, "", kk); if (kk==k) { v=substr($0, e+1); gsub(/^[ \t]+|[ \t]+$/, "", v) } } END { print v }')
    if [ "$g" = "$w" ]; then ok "kernel.coredump.$k" "$w"; else fail "kernel.coredump.$k" "expected '$w', effective value differs"; fi
  done
  [ "$MODE" = host ] || return
  local sock="$ROOT/etc/systemd/system/systemd-coredump.socket"
  if [ ! -e "$ROOT/usr/lib/systemd/system/systemd-coredump.socket" ] || [ "$(readlink "$sock" 2>/dev/null)" = /dev/null ]; then ok kernel.coredump_socket_masked
  else fail kernel.coredump_socket_masked "systemd-coredump.socket installed and not masked"; fi
  # ---- swap: none, or dm-crypt swap with a fresh random key per boot (20 §11.4)
  local dev name line bad="" ct
  snap_opt kernel.swap "$ROOT/etc/crypttab" crypttab || return
  ct=$SNAP
  if [ "$LIVE" -eq 1 ]; then
    while read -r dev _; do
      case "$dev" in Filename) continue ;; /dev/dm-*) name=$(cat "/sys/block/${dev#/dev/}/dm/name" 2>/dev/null) ;; /dev/mapper/*) name=${dev#/dev/mapper/} ;; *) bad="$bad $dev"; continue ;; esac
      line=$(awk -v n="$name" '$1==n' "$ct" 2>/dev/null)
      printf '%s\n' "$line" | awk '$3=="/dev/urandom" && $4 ~ /(^|,)swap(,|$)/ {f=1} END {exit f?0:1}' || bad="$bad $dev"
    done < /proc/swaps
  else
    snap_opt kernel.swap "$ROOT/etc/fstab" fstab || return
    while read -r dev _ typ _; do
      [ "$typ" = swap ] || continue
      case "$dev" in /dev/mapper/*) name=${dev#/dev/mapper/} ;; *) bad="$bad $dev"; continue ;; esac
      line=$(awk -v n="$name" '$1==n' "$ct" 2>/dev/null)
      printf '%s\n' "$line" | awk '$3=="/dev/urandom" && $4 ~ /(^|,)swap(,|$)/ {f=1} END {exit f?0:1}' || bad="$bad $dev"
    done < <(grep -vE '^[[:space:]]*(#|$)' "$SNAP" 2>/dev/null)
  fi
  if [ -n "$bad" ]; then fail kernel.swap "$(printf '%s' "$bad" | wc -w) swap device(s) that are not random-key dm-crypt"; else ok kernel.swap "none, or random-key encrypted only"; fi
}

# =============================================================================== DNS
check_resolv() {
  snap dns.resolv "$RESOLV" resolv.conf || return
  local ns
  ns=$(sed -e 's/#.*$//' "$SNAP" | awk '$1=="nameserver" {print $2}' | sort -u | tr '\n' ' ') || ns=ERR
  if [ "$ns" = "127.0.0.1 " ] || [ "$ns" = "::1 " ]; then ok dns.no_resolver "nameserver $ns(nothing listens)"; else fail dns.no_resolver "only a loopback nameserver allowed"; fi
}

# =============================================================================== host-only
group_members() { awk -F: -v g="$1" '$1==g {print $4}' "$GROUPF" 2>/dev/null; }
# Kernel floor for H-INTAKE (Platform Manifest, 17 §4.5): Linux >= 6.3 for vm.memfd_noexec,
# MFD_NOEXEC_SEAL and F_SEAL_EXEC (ADR-055(1), AUD-RM2-DEP-29). Debian 13 ships 6.12.
KERNEL_FLOOR_MAJOR=6 KERNEL_FLOOR_MINOR=3
check_kernel_floor() {
  local rel maj min
  if [ "$LIVE" -eq 1 ]; then rel=$(uname -r)
  elif [ -e "$ROOT/proc/sys/kernel/osrelease" ] || [ -L "$ROOT/proc/sys/kernel/osrelease" ]; then
    snap host.kernel_floor "$ROOT/proc/sys/kernel/osrelease" osrelease || return
    rel=$(head -n 1 -- "$SNAP" | cut -c1-64)
  else skip host.kernel_floor "offline root without proc/sys/kernel/osrelease: kernel not checked"; return; fi
  if [[ "$rel" =~ ^([0-9]{1,3})\.([0-9]{1,3})([^0-9]|$) ]]; then maj=${BASH_REMATCH[1]}; min=${BASH_REMATCH[2]}
  else fail host.kernel_floor "kernel release not parseable"; return; fi
  if [ "$((10#$maj))" -gt "$KERNEL_FLOOR_MAJOR" ] || { [ "$((10#$maj))" -eq "$KERNEL_FLOOR_MAJOR" ] && [ "$((10#$min))" -ge "$KERNEL_FLOOR_MINOR" ]; }; then
    ok host.kernel_floor "Linux $((10#$maj)).$((10#$min)) >= $KERNEL_FLOOR_MAJOR.$KERNEL_FLOOR_MINOR"
  else fail host.kernel_floor "Linux $((10#$maj)).$((10#$min)) is below the floor $KERNEL_FLOOR_MAJOR.$KERNEL_FLOOR_MINOR (memfd_noexec, MFD_NOEXEC_SEAL, F_SEAL_EXEC)"; fi
}

check_host() {
  local v g
  check_kernel_floor
  if [ "$LIVE" -eq 1 ]; then
    if ! have tor; then fail host.tor_installed "tor binary not found"
    else
      v=$(tor --list-modules 2>/dev/null) || v=""
      if grep -qx 'pow: yes' <<< "$v"; then ok host.tor_pow_module "pow: yes"; else fail host.tor_pow_module "tor built without PoW (R7 SI-D-01)"; fi
      v=$(tor --version 2>/dev/null | head -n 1 | sed -n 's/^Tor version \([0-9][0-9.]*\).*/\1/p')
      if [ -n "$v" ] && [ "$(printf '%s\n0.4.8\n' "$v" | sort -V | head -n 1)" = 0.4.8 ]; then ok host.tor_version_floor ">= 0.4.8"; else fail host.tor_version_floor "tor >= 0.4.8 required (NET-003)"; fi
    fi
  else skip host.tor_binary "offline root: tor binary not checked"; fi
  if [ -e "$ROOT/run/systemd/resolve/stub-resolv.conf" ] && [ -S "$ROOT/run/systemd/resolve/io.systemd.Resolve" ]; then
    fail host.no_resolved "systemd-resolved appears to be running (17 §4.5: masked on H-INTAKE)"
  else ok host.no_resolved; fi
  # A second, unchecked tor on the host (Debian's tor@default / tor.service; AUD-RM2-DEP-14).
  for v in tor.service tor@default.service; do
    if [ "$(readlink "$ROOT/etc/systemd/system/$v" 2>/dev/null)" = /dev/null ] ||
       { [ ! -e "$ROOT/usr/lib/systemd/system/$v" ] && [ ! -e "$ROOT/usr/lib/systemd/system/tor@.service" ]; }; then ok "host.masked.$v"
    else fail "host.masked.$v" "must be masked (ln -s /dev/null /etc/systemd/system/$v)"; fi
  done
  # No tor control group and nobody else in tor's group (AUD-RM2-DEP-04); journal readers are
  # root only (the journal files are group-readable by systemd-journal and adm).
  if snap host.groups "$ROOT/etc/group" group && GROUPF=$SNAP && snap host.groups "$ROOT/etc/passwd" passwd; then
    if grep -q '^_candor-torctl:' "$GROUPF"; then fail host.no_torctl_group "group _candor-torctl exists"; else ok host.no_torctl_group; fi
    for g in _tor-candor-intake systemd-journal adm; do
      v=$(group_members "$g")
      if [ -z "$v" ]; then ok "host.group_empty.$g"; else fail "host.group_empty.$g" "members: $(printf '%s' "$v" | tr ',' ' ' | san_names)"; fi
    done
    v=$(awk -F: 'NR==FNR { if ($1=="_tor-candor-intake") g=$3; next } $4==g && $1!="_tor-candor-intake" {print $1}' "$GROUPF" "$SNAP" 2>/dev/null | san_names)
    if [ -z "$v" ]; then ok host.tor_group_primary_only; else fail host.tor_group_primary_only "other users with tor's primary group: $v"; fi
  fi
  # ---- AUD-RM2-DEP-18: paths outside the unit set that would undo the confinement
  # Library injection into every process: /etc/ld.so.preload must not exist at all.
  if [ -e "$ROOT/etc/ld.so.preload" ] || [ -L "$ROOT/etc/ld.so.preload" ]; then fail host.no_ld_so_preload "/etc/ld.so.preload exists"
  else ok host.no_ld_so_preload; fi
  # Manager environment handed to every unit (LD_PRELOAD, LD_LIBRARY_PATH, ...).
  local env
  env=$(systemd-analyze "--root=${ROOT:-/}" cat-config systemd/system.conf 2>/dev/null | awk '
    /^[ \t]*[#;]/ || /^[ \t]*$/ { next } /^\[/ { s=$0; next }
    s=="[Manager]" { e=index($0, "="); k=substr($0, 1, e-1); gsub(/[ \t]/, "", k)
      if (k=="DefaultEnvironment" || k=="ManagerEnvironment") { v=substr($0, e+1); gsub(/^[ \t]+|[ \t]+$/, "", v); val[k]=v } }
    END { for (k in val) if (val[k] != "") print k }' | san_names)
  if [ -n "$env" ]; then fail host.manager_environment "set in system.conf(.d): $env (values not shown)"; else ok host.manager_environment "DefaultEnvironment/ManagerEnvironment unset"; fi
  if [ "$LIVE" -eq 1 ]; then
    if have systemctl; then
      env=$(systemctl show --property=Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^\([^=]*\)=.*/\1/p' | grep -vxE 'PATH|LANG|LANGUAGE|LC_[A-Z]+' | san_names)
      if [ -n "$env" ]; then fail host.manager_environment_live "service manager environment carries: $env"; else ok host.manager_environment_live; fi
    else fail host.manager_environment_live "systemctl missing"; fi
  fi
  if have systemd-analyze; then check_host_units; else fail host.unit "systemd-analyze missing"; fi
}

# =============================================================================== AppArmor
AA_PROFILES="candor-tor-intake candor-web candor-sealer candor-intake-store candor-intake-pg candor-intake-maint"
# Normalised statements: comments and blank lines dropped, whitespace collapsed. '#include'
# (an include, not a comment, for the parser) is turned into a line that never matches.
aa_norm() {
  awk '{ l=$0
    if (l ~ /#[ \t]*include/) { print "!HASH-INCLUDE"; next }
    sub(/^[ \t]*#.*$/, "", l); sub(/[ \t\r\f\v]#.*$/, "", l)
    gsub(/[ \t\r\f\v]+/, " ", l); sub(/^ /, "", l); sub(/ $/, "", l)
    if (l != "") print l }' "$1"
}
# Rule classes that must never appear in an allow rule (AUD-RM2-DEP-15). Independent of the
# exact comparison, so a mistaken baseline edit is still caught. Statements are split at ','
# and at block braces outside (...) and path globs {a,b}.
aa_classes() { # profile normalised-file inet-allowed(0|1) caps-allowed(space list)
  awk -v p="$1" -v inet="$3" -v caps=" $4 " '
    function stmt(t,   w, n, i, perm, path, deny, kw, f) {
      gsub(/^ +| +$/, "", t); if (t == "") return
      ns++
      n=split(t, w, " ")
      i=1; deny=0
      while (i <= n && (w[i]=="audit" || w[i]=="quiet" || w[i]=="owner" || w[i]=="allow" || w[i]=="deny" || w[i] ~ /^priority=/ || w[i]=="other")) { if (w[i]=="deny") deny=1; i++ }
      kw=w[i]
      if (t ~ /^profile / || t ~ /^\// && hdr) {
        if (match(t, /\(.*\)/)) { f=substr(t, RSTART+1, RLENGTH-2); gsub(/flags *= */, "", f); gsub(/[ ,]+/, " ", f); gsub(/^ | $/, "", f)
          if (f != "attach_disconnected") bad["flags"]=bad["flags"] " " f }
        return }
      # Self-contained profiles (AUD-RM2-DEP-23): the only file reference is the pinned ABI;
      # no include of any kind ("include", "include if exists", "#include").
      if (kw=="abi") { if (t != "abi <abi/3.0>") bad["abi"]=bad["abi"] " " ns; return }
      if (kw=="include" || kw=="#include" || kw=="!HASH-INCLUDE") { bad["include"]=bad["include"] " " ns; return }
      # Variables: only @{PROC} and @{pid}, defined once each, outside the profile, never "+=".
      if (t ~ /^@\{[^}]*\} *\+?=/) {
        vn=t; sub(/\}.*$/, "", vn); sub(/^@\{/, "", vn)
        if (t ~ /^@\{[^}]*\} *\+=/ || depth > 0 || (vn != "PROC" && vn != "pid") || (vn in vseen)) bad["variable"]=bad["variable"] " " ns
        vseen[vn]=1; return }
      if (deny) return
      if (kw ~ /^(change_profile|change_hat|pivot_root|mount|remount|umount|ptrace|userns|io_uring|mqueue|dbus|all|file|set|link|rlimit|unconfined|alias|hat)$/ || kw ~ /^\^/) { bad["forbidden_rule"]=bad["forbidden_rule"] " " kw; return }
      if (kw=="capability") { if (i == n) bad["capability"]=bad["capability"] " all"; for (j=i+1; j<=n; j++) if (index(caps, " " w[j] " ") == 0) bad["capability"]=bad["capability"] " " w[j]; return }
      if (kw=="network") {
        if (!(n == i+2 && (w[i+1]=="unix" && w[i+2] ~ /^(stream|dgram|seqpacket)$/ || w[i+1]=="inet" && w[i+2]=="stream" && inet==1)))
          bad["network"]=bad["network"] " " ns
        return }
      if (kw=="signal" || kw=="unix") return
      # path rule: [file] <path> <perms> [-> target] or <perms> <path>
      perm=""; path=""
      for (j=i; j<=n; j++) { if (w[j] ~ /^(\/|@\{|")/) path=w[j]; else if (w[j] ~ /^[rwaklmixuUpPcCD]+$/) perm=perm w[j]; else if (w[j]=="->") bad["exec"]=bad["exec"] " " ns }
      if (path == "") { bad["unknown_rule"]=bad["unknown_rule"] " " ns; return }
      if (perm ~ /[xX]/) bad["exec"]=bad["exec"] " " ns
      if (perm ~ /[wal]/ && (path=="/" || path ~ /^\/(\*|\{|\?|\[)/)) bad["broad_write"]=bad["broad_write"] " " ns
    }
    { line=$0; cur=""; par=0; gl=0
      if (line ~ /^profile / || line ~ /^\/[^ ]* .*\{$/ || line ~ /^\/[^ ]* *\{$/) hdr=1; else hdr=0
      for (c=1; c<=length(line); c++) { ch=substr(line, c, 1)
        if (ch=="(") par++; else if (ch==")" && par>0) par--
        if (ch=="{") { if (c>1 && substr(line, c-1, 1) != " ") { gl++; cur=cur ch; continue } stmt(cur); hdr=0; cur=""; depth++; continue }
        if (ch=="}") { if (gl>0) { gl--; cur=cur ch; continue } stmt(cur); cur=""; if (depth > 0) depth--; continue }
        if (ch=="," && par==0 && gl==0) { stmt(cur); cur=""; continue }
        cur=cur ch }
      stmt(cur) }
    END { n=split("flags abi include variable forbidden_rule capability network exec broad_write unknown_rule", cls, " ")
      for (i=1; i<=n; i++) { c=cls[i]
        if (c in bad) { d=bad[c]; gsub(/[^A-Za-z0-9_ ]/, "?", d); printf "FAIL\tapparmor.%s.%s\t%s at statement(s)/name(s):%s\n", p, c, c, substr(d, 1, 200) }
        else printf "OK\tapparmor.%s.%s\tnone\n", p, c } }' "$2"
}
aa_dist_conffiles() {
  # Distribution AppArmor files (AUD-RM2-DEP-23): every conffile of the installed apparmor
  # package under abi/, abstractions/ and tunables/ that is present must still have the
  # digest dpkg recorded at installation (what `dpkg --verify apparmor` reports). Candor
  # profiles include none of them; a rewritten abstraction still means the host's other
  # policy is no longer the distribution's, and the ST-120 gate fails closed on it.
  local MAXIN=67108864 st i n=0 bad=0 path
  snap apparmor.dist_conffiles "$ROOT/var/lib/dpkg/status" dpkg.status || return
  st=$SNAP
  awk 'BEGIN { RS=""; FS="\n" }
    { pkg=""; s=""; for (i=1; i<=NF; i++) { if ($i ~ /^Package: /) pkg=substr($i, 10); if ($i ~ /^Status: /) s=substr($i, 9) }
      if (pkg != "apparmor" || s != "install ok installed") next
      c=0
      for (i=1; i<=NF; i++) {
        if ($i ~ /^Conffiles:/) { c=1; continue }
        if (c && $i ~ /^ /) { split(substr($i, 2), a, " ")
          if (a[1] ~ /^\/etc\/apparmor\.d\/(abi|abstractions|tunables)\/[A-Za-z0-9._\/-]+$/ && a[2] ~ /^[0-9a-f]{32}$/ && a[3] != "obsolete") print a[1] " " a[2] }
        else c=0 } }' "$st" > "$WORK/aa.conff"
  if [ ! -s "$WORK/aa.conff" ]; then fail apparmor.dist_conffiles "no installed apparmor package with conffiles in the dpkg status"; return; fi
  local -a paths=() sums=() got=()
  while read -r path i; do
    if [ -e "$ROOT$path" ] || [ -L "$ROOT$path" ]; then paths+=("$ROOT$path"); sums+=("$i"); fi
  done < "$WORK/aa.conff"
  [ "${#paths[@]}" -gt 0 ] || { fail apparmor.dist_conffiles "none of the apparmor conffiles is present"; return; }
  rm -f -- "$WORK/aa.md5"
  if [ "$SAFE_OK" -eq 1 ]; then timeout -k 2 60 "$SAFE_READ" --md5 aa.md5 "$MAXIN" "$OWNERS" "$DENYMODE" "${paths[@]}" </dev/null >/dev/null 2>&1 3<"$WORK"; fi
  mapfile -t got < <(cat -- "$WORK/aa.md5" 2>/dev/null)
  for i in "${!paths[@]}"; do
    n=$((n + 1))
    [ "${got[$i]:-ERR}" = "OK ${sums[$i]}" ] || bad=$((bad + 1))
  done
  if [ "$bad" -gt 0 ]; then fail apparmor.dist_conffiles "$bad of $n apparmor conffile(s) under abi/, abstractions/, tunables/ differ from the dpkg digest, or are unsafe (symlink, owner, mode)"
  else ok apparmor.dist_conffiles "$n apparmor conffile(s) under abi/, abstractions/, tunables/ equal the dpkg digests"; fi
}
check_apparmor() {
  local p f n want got l
  for p in $AA_PROFILES; do
    if [ "$MODE" = host ]; then f="$ROOT/etc/apparmor.d/$p"; else f="$DIR/apparmor/$p"; fi
    snap "apparmor.$p.file" "$f" "aa.$p" || continue
    aa_norm "$SNAP" > "$WORK/aa.$p.got"
    awk -F'|' -v p="$p" '$1=="aa" && $2==p {print substr($0, length($1 $2)+3)}' "$BASE" > "$WORK/aa.$p.want"
    want=$(wc -l < "$WORK/aa.$p.want"); got=$(wc -l < "$WORK/aa.$p.got")
    if [ "$want" -gt 0 ] && cmp -s "$WORK/aa.$p.want" "$WORK/aa.$p.got"; then ok "apparmor.$p.content" "$got statements equal the release profile"
    else
      n=$(awk 'NR==FNR { a[FNR]=$0; na=FNR; next } { nb=FNR; if (!(FNR in a) || a[FNR]!=$0) { print FNR; f=1; exit } } END { if (!f) print (nb < na ? nb+1 : na+1) }' "$WORK/aa.$p.want" "$WORK/aa.$p.got")
      fail "apparmor.$p.content" "differs from the release profile at statement line $n (expected $want, found $got; text not shown)"
    fi
    aa_classes "$p" "$WORK/aa.$p.got" "$(awk -F'|' -v p="$p" '$1=="aa-inet" && $2==p {f=1} END {print f+0}' "$BASE")" "$(awk -F'|' -v p="$p" '$1=="aa-cap" && $2==p {print $3}' "$BASE" | tr '\n' ' ')" > "$WORK/rl"
    report_lines < "$WORK/rl"
  done
  [ "$MODE" = host ] || return
  # Not disabled or forced to complain mode by the distribution's mechanisms, and no other file
  # in /etc/apparmor.d defines or attaches a profile under a Candor name or binary.
  local AAD="$ROOT/etc/apparmor.d"
  for p in $AA_PROFILES; do
    if [ -e "$AAD/disable/$p" ] || [ -L "$AAD/disable/$p" ] ||
       [ -e "$AAD/force-complain/$p" ] || [ -L "$AAD/force-complain/$p" ]; then
      fail "apparmor.$p.not_disabled" "disable/ or force-complain/ entry present"
    else ok "apparmor.$p.not_disabled"; fi
  done
  if [ -d "$AAD" ] && ! l=$(symlinked_component "$INPREFIX" "$AAD"); then
    n=$(grep -rlIE --exclude-dir=disable --exclude-dir=force-complain 'candor-(tor-intake|web|sealer|intake-store|intake-pg|intake-maint)([^A-Za-z0-9_-]|$)|/usr/lib/candor/' "$AAD" 2>/dev/null |
        grep -cvxE "$(printf '%s' "$AAD/" | sed 's/[][\.*^$]/\\&/g')($(printf '%s' "$AA_PROFILES" | tr ' ' '|'))")
    if [ "$n" -gt 0 ]; then fail apparmor.no_foreign_profiles "$n other file(s) in /etc/apparmor.d name a Candor profile or binary"; else ok apparmor.no_foreign_profiles; fi
  else fail apparmor.no_foreign_profiles "/etc/apparmor.d missing or behind a symlink"; return; fi
  # AUD-RM2-DEP-23: the snippet directories the distribution's base abstraction and global
  # tunables pull in ("include if exists <abstractions/base.d>", "<tunables/global.d>") and the
  # local/ overrides must be empty. Candor profiles include none of them; this keeps the host's
  # other policy free of silent widening too (local/ may hold the empty placeholder files
  # packages create, and a README).
  n=0
  for l in "$AAD/abstractions/base.d" "$AAD/tunables/global.d"; do
    if [ -L "$l" ] || { [ -e "$l" ] && [ ! -d "$l" ]; } || [ -n "$(find "$l" -mindepth 1 -print -quit 2>/dev/null)" ]; then n=$((n + 1)); fi
  done
  if [ -L "$AAD/local" ]; then n=$((n + 1)); else n=$((n + $(find "$AAD/local" -mindepth 1 \( ! -type f -o -size +0c \) ! \( -type f -name README \) 2>/dev/null | wc -l))); fi
  if [ "$n" -gt 0 ]; then fail apparmor.snippet_dirs_empty "$n non-empty snippet location(s): abstractions/base.d, tunables/global.d, local/"
  else ok apparmor.snippet_dirs_empty "abstractions/base.d, tunables/global.d empty; local/ only empty files"; fi
  aa_dist_conffiles
  # The only distribution file the profiles reference is the ABI: pinned digest, and the
  # isolated compile below uses this verified copy.
  local abi aab="$WORK/aabase" sysconf rc
  abi=$(awk -F'|' '$1=="aa-abi" && $2=="3.0" {print $3}' "$BASE")
  mkdir -p "$aab/abi" && : > "$aab/parser.conf"
  if snap apparmor.abi "$AAD/abi/3.0" aa.abi; then
    if [ -n "$abi" ] && [ "$(sha256sum < "$SNAP" | cut -c1-64)" = "$abi" ]; then ok apparmor.abi "abi/3.0 equals the pinned digest"; cp -- "$SNAP" "$aab/abi/3.0"
    else fail apparmor.abi "abi/3.0 differs from the pinned digest (re-pin only with the Platform-Manifest apparmor package)"; fi
  fi
  have apparmor_parser || { fail apparmor.compiled "apparmor_parser missing"; return; }
  # Parser configuration the system would use (--root: the root's, read from a safe copy).
  if [ "$LIVE" -eq 1 ]; then sysconf=/etc/apparmor/parser.conf; [ -e "$sysconf" ] || sysconf="$aab/parser.conf"
  elif snap_opt apparmor.parser_conf "$ROOT/etc/apparmor/parser.conf" aa.parser.conf; then sysconf=$SNAP
  else return; fi
  # Isolated compile of the release statements (aa| lines) vs. the installed file compiled the
  # way the host would compile it (its /etc/apparmor.d as --base, its parser.conf).
  for p in $AA_PROFILES; do
    if [ ! -s "$WORK/aa.$p.want" ] || [ ! -f "$WORK/in/aa.$p" ]; then fail "apparmor.$p.compiled" "profile not checked"; continue; fi
    if [ ! -f "$aab/abi/3.0" ]; then fail "apparmor.$p.compiled" "no verified abi file"; continue; fi
    timeout 60 apparmor_parser --config-file="$aab/parser.conf" --base "$aab" -QTK -S "$WORK/aa.$p.want" > "$WORK/aa.$p.iso" 2>/dev/null; rc=$?
    if [ "$rc" -ne 0 ] || [ ! -s "$WORK/aa.$p.iso" ]; then fail "apparmor.$p.compiled" "release profile does not compile in isolation"; continue; fi
    if timeout 60 apparmor_parser --config-file="$sysconf" --base "$AAD" -QTK -S "$WORK/in/aa.$p" > "$WORK/aa.$p.sys" 2>/dev/null &&
       cmp -s "$WORK/aa.$p.iso" "$WORK/aa.$p.sys"; then ok "apparmor.$p.compiled" "host compile equals the isolated compile of the release profile"
    else fail "apparmor.$p.compiled" "host compile differs from the isolated compile of the release profile (system files change it)"; fi
  done
  [ "$LIVE" -eq 1 ] || { skip apparmor.live "offline root: load state not checked"; return; }
  # Live: enforce mode, and the loaded policy is the isolated compile of the release profile (a
  # weakened parser cache, a tampered tree at load time or a manual `apparmor_parser -r` of
  # another file shows up here).
  local d raw
  for p in $AA_PROFILES; do
    if grep -qx "$p (enforce)" /sys/kernel/security/apparmor/profiles 2>/dev/null; then ok "apparmor.$p.enforce" enforce; else fail "apparmor.$p.enforce" "profile not loaded in enforce mode"; fi
    raw=""
    for d in /sys/kernel/security/apparmor/policy/profiles/*; do
      [ "$(cat "$d/name" 2>/dev/null)" = "$p" ] && raw="$d/raw_data" && break
    done
    if [ -z "$raw" ] || [ ! -r "$raw" ]; then fail "apparmor.$p.loaded_policy" "loaded raw policy not readable (kernel must export it)"; continue; fi
    if [ -s "$WORK/aa.$p.iso" ] && [ "$(sha256sum < "$WORK/aa.$p.iso" | cut -c1-64)" = "$(sha256sum < "$raw" | cut -c1-64)" ]; then ok "apparmor.$p.loaded_policy" "loaded policy equals the isolated compile of the release profile"
    else fail "apparmor.$p.loaded_policy" "loaded policy differs from the isolated compile of the release profile"; fi
  done
}

# =============================================================================== baseline emitter
emit_baseline() { # maintainers only: print effective values of the tree for review
  units_root || exit 2
  local ro u f
  ro=$(rootopt)
  # shellcheck disable=SC2086 # ALL_UNITS is a fixed word list
  SYSTEMD_LOG_LEVEL=debug systemd-analyze verify "$ro" --man=no --recursive-errors=no $ALL_UNITS > "$WORK/verify.dbg" 2>&1
  for u in $ALL_UNITS; do
    mapfile -t f < <(awk -v u="$u" '/^\t-> Unit / {t=($3==u":")} t && /^\t\t(Fragment|DropIn) Path: / {print substr($0, index($0, ": ")+2)}' "$WORK/verify.dbg")
    unit_merge "${f[@]}" | while IFS= read -r l; do
      s=${l%%|*}; r=${l#*|}; k=${r%%|*}; v=${r#*|}
      printf '%s\n' "$v" | awk -v p="unit|$u|$s|$k|=|" 'BEGIN { RS="\001" } { n=split($0, a, / ;; /); for (i=1; i<=n; i++) { sub(/\n$/, "", a[i]); print p a[i] } }'
    done
  done
  # shellcheck disable=SC2016 # expanded by the inner shell
  if unshare -n /bin/sh -c 'nft -f "$1" >/dev/null 2>&1 && nft -j list ruleset' sh "$NFT" > "$WORK/n.json"; then
    UIDMAP=$(nft_uidmap)
    jq -r --argjson u "$UIDMAP" '
      def canon($u): .expr
        | walk(if type=="object" and has("counter") and (.counter|type)=="object" then {"counter":{}} else . end)
        | walk(if type=="object" and has("match") and (.match|type)=="object" and (.match.left|type)=="object" and (.match.left.meta|type)=="object" and .match.left.meta.key=="skuid"
               then .match.right |= (if type=="number" then ($u[tostring] // tostring) elif type=="object" and has("set") then .set |= map(if type=="number" then ($u[tostring] // tostring) else . end) else . end) else . end)
        | tojson;
      (.nftables[] | select(.rule) | .rule | "nft-rule|\(.chain)|\(canon($u))"),
      (.nftables[] | select(.set) | .set | select(.name|startswith("non_public")) | "nft-set|\(.name)|\({type: .type, flags: (.flags // []), elem: (.elem // [])} | tojson)")' "$WORK/n.json"
  fi
  local spec name
  for spec in $SERVICES; do
    name=${spec%%:*}
    systemd-analyze security --offline=true "$ro" --json=short --no-pager "$name" 2>/dev/null |
      jq -r --arg u "$name" '.[] | select(.exposure != null and (.exposure|tostring|tonumber) > 0) | "sec|\($u)|\(.name)"'
  done
}

if [ "$EMIT" -eq 1 ]; then emit_baseline; exit 0; fi
if ! verify_policy; then
  printf 'config-check: policy integrity check FAILED; no check run (exit=30)\n'
  exit 30
fi
PRECHECKS=$CHECKS

want tor && check_torrc
want nft && check_nft
want pg && check_pg
want units && check_units
want journald && { check_journald journald.ns "$JNS" systemd/journald@candor-intake.conf 1; check_journald journald.host "$JHOST" systemd/journald.conf 0; }
want kernel && check_kernel
want dns && check_resolv
want apparmor && check_apparmor
[ "$MODE" = host ] && want host && check_host

if [ "$CHECKS" -eq "$PRECHECKS" ]; then
  echo "config-check: the selection ran no check (exit=2)" >&2
  exit 2
fi
if [ "$FAILS" -gt 0 ]; then
  printf 'config-check: %d of %d checks FAILED, %d skipped (exit=30)\n' "$FAILS" "$CHECKS" "$SKIPS"
  exit 30
fi
printf 'config-check: all %d checks OK, %d skipped (exit=0)\n' "$((CHECKS - SKIPS))" "$SKIPS"
exit 0
