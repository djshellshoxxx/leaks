#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# check-placement.sh - verify the Secret Placement Manifest (ADR-028) on an intake host.
#
# 18-DEPLOYMENT.md §15, 17-INFRASTRUCTURE.md §4.9, 32-OPERATIONS.md `secret.placement` and
# `perm.secrets`, 16-TOR-I2P.md NET-016/NET-019/NET-043. The set of secret-bearing files found
# must equal the active manifest entries; every entry must have the exact owner, group, mode,
# parent-directory mode, no symlink and no extra hard link.
#
# Usage:
#   check-placement.sh [--manifest FILE] [--flags a,b] [--mode light|full] [--root DIR] [-q]
#     --manifest  default /usr/share/candor/manifests/intake.toml
#     --flags     enabled feature flags (e.g. sshd,ssh_onion); "always" is implicit
#     --mode      light = manifest light_roots (5-min check), full = whole filesystem (daily)
#     --root      treat DIR as the filesystem root (offline image / tests); default /
#                 (with --root the encrypted-volume check is reported as SKIP)
#
# Must run as root on a host (it reads every file). Output: "RULE STATUS DETAIL" lines. Paths
# of misplaced files are printed so the operator can act; file contents never are.
# Exit: 0 = placement equals manifest; 30 = violation (18 §14 baseline failure);
#       2 = usage error or manifest parse error (fail closed).
# Uses only bash, coreutils, findutils, grep and awk (no interpreter on H-INTAKE, 17 §5.1).

set -u
LC_ALL=C
export LC_ALL
umask 077

MANIFEST=/usr/share/candor/manifests/intake.toml
FLAGS=""
SCANMODE=light
ROOT=""
QUIET=0
FAILS=0

usage() { sed -n '4,22p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) [ $# -ge 2 ] || usage; MANIFEST=$2; shift 2 ;;
    --flags) [ $# -ge 2 ] || usage; FLAGS=$2; shift 2 ;;
    --mode) [ $# -ge 2 ] || usage; SCANMODE=$2; shift 2 ;;
    --root) [ $# -ge 2 ] || usage; ROOT=${2%/}; shift 2 ;;
    -q) QUIET=1; shift ;;
    -h|--help) usage ;;
    *) echo "check-placement: unknown argument" >&2; usage ;;
  esac
done
case "$SCANMODE" in light|full) ;; *) usage ;; esac
case "$FLAGS" in *[!a-z0-9_,]*) echo "check-placement: invalid --flags" >&2; exit 2 ;; esac
if [ -n "$ROOT" ] && [ ! -d "$ROOT" ]; then echo "check-placement: --root is not a directory" >&2; exit 2; fi
if [ ! -f "$MANIFEST" ] || [ ! -r "$MANIFEST" ]; then echo "check-placement: manifest not readable" >&2; exit 2; fi

report() {
  if [ "$2" = FAIL ]; then FAILS=$((FAILS + 1)); fi
  # Paths are attacker-influenced: printable ASCII only (no terminal control sequences).
  if [ "$QUIET" -eq 0 ] || [ "$2" = FAIL ]; then printf '%-44s %-5s %s\n' "$1" "$2" "$(printf '%s' "${3:-}" | tr -c '[:print:]' '?')"; fi
}

WORK=$(mktemp -d) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

# ------------------------------------------------------------------ strict TOML-subset parser
# Emits: T<TAB>key<TAB>value | S<TAB>n<TAB>key<TAB>value | C<TAB>key<TAB>value | F<TAB>key<TAB>value
# Arrays are emitted comma-joined (strings may not contain commas, quotes or backslashes).
if ! awk '
  function err(msg) { printf "check-placement: manifest line %d: %s\n", NR, msg > "/dev/stderr"; bad=1; exit 2 }
  BEGIN { sect="T"; n=0
    allowed["T"]=" manifest_version role profiles "
    allowed["S"]=" id key path owner group mode parent_mode pattern provenance backup_set flags required "
    allowed["C"]=" roots light_roots exclude name_only_blobs name_only_staging max_file_kib patterns "
    allowed["F"]=" ids " }
  /^[ \t]*(#.*)?$/ { next }
  /^\[\[secret\]\][ \t]*$/ { sect="S"; n++; delete seen; next }
  /^\[scan\][ \t]*$/ { if (scan_seen++) err("duplicate [scan]"); sect="C"; delete seen; next }
  /^\[forbidden\][ \t]*$/ { if (forb_seen++) err("duplicate [forbidden]"); sect="F"; delete seen; next }
  {
    line=$0
    if (!match(line, /^[a-z_]+ = /)) err("expected key = value")
    k=substr(line, 1, RLENGTH-3); rest=substr(line, RLENGTH+1)
    if (index(allowed[sect], " " k " ")==0) err("unknown key " k)
    if (seen[k]++) err("duplicate key " k)
    S="\"[^\"\\\\,\t]*\""
    if (match(rest, "^" S)) { v=substr(rest, 2, RLENGTH-2); rest=substr(rest, RLENGTH+1) }
    else if (match(rest, "^\\[[ ]*(" S "([ ]*,[ ]*" S ")*)?[ ]*\\]")) {
      raw=substr(rest, 2, RLENGTH-2); rest=substr(rest, RLENGTH+1)
      gsub(/[ ]*"[ ]*/, "", raw); v=raw }
    else if (match(rest, /^(-?[0-9]+|true|false)/)) { v=substr(rest, 1, RLENGTH); rest=substr(rest, RLENGTH+1) }
    else err("bad value for " k)
    if (rest !~ /^[ \t]*(#.*)?$/) err("trailing data after " k)
    if (sect=="S") printf "S\t%d\t%s\t%s\n", n, k, v
    else printf "%s\t%s\t%s\n", sect, k, v
  }
  END { if (bad) exit 2 }' "$MANIFEST" > "$WORK/parsed"; then
  echo "check-placement: manifest parse failed (fail closed)" >&2
  exit 2
fi

top()  { awk -F'\t' -v k="$1" '$1=="T" && $2==k {print $3}' "$WORK/parsed"; }
scan() { awk -F'\t' -v k="$1" '$1=="C" && $2==k {print $3}' "$WORK/parsed"; }
sec()  { awk -F'\t' -v n="$1" -v k="$2" '$1=="S" && $2==n && $3==k {print $4}' "$WORK/parsed"; }

[ "$(top manifest_version)" = 1 ] || { echo "check-placement: unsupported manifest_version" >&2; exit 2; }
[ "$(top role)" = intake ] || { echo "check-placement: manifest role is not intake" >&2; exit 2; }

valid_path() { # absolute, no "..", conservative charset
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *..*|*//*) return 1 ;; esac
  case "$1" in *[!A-Za-z0-9._/@:+-]*) return 1 ;; esac
  return 0
}

# Built-in pattern table (the manifest names patterns; regexes are not taken from input).
pattern_regex() {
  case "$1" in
    pem_private_key)         printf '%s' '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' ;;
    openssh_private_key)     printf '%s' '-----BEGIN OPENSSH PRIVATE KEY-----' ;;
    # File format, and the control-port/ADD_ONION export format (AUD-RM2-DEP-10).
    tor_hs_secret_key)       printf '%s' '== ed25519v1-secret: type0 ==|ED25519-V3:[A-Za-z0-9+/]{86}==' ;;
    tor_client_auth_private) printf '%s' '[a-z2-7]{56}:descriptor:x25519:[A-Z2-7]{52}' ;;
    age_or_hpke_identity)    printf '%s' 'AGE-SECRET-KEY-1[0-9A-Z]{58}' ;;
    openpgp_secret_packet)   printf '%s' '-----BEGIN PGP PRIVATE KEY BLOCK-----' ;;
    jwk_private|pkcs12)      printf '%s' '' ;;   # handled specially below
    *) return 1 ;;
  esac
}

# Any path component below ROOT that is a symlink (AUD-RM2-DEP-10): a symlinked parent
# directory can move a secret to another (unencrypted) disk while the leaf looks correct.
symlinked_component() { # absolute-path -> prints the first symlinked component, if any
  local rest=${1#/} cur="" comp
  while [ -n "$rest" ]; do
    comp=${rest%%/*}
    if [ "$comp" = "$rest" ]; then rest=""; else rest=${rest#*/}; fi
    cur="$cur/$comp"
    if [ -L "$ROOT$cur" ]; then printf '%s' "$cur"; return 0; fi
  done
  return 1
}

# The onion key must sit on a dm-crypt backed filesystem (IMPL-RM2 A15, 09 §10 LUKS volume).
on_encrypted_fs() { # path -> 0 if the backing block device stack contains a crypt device
  local src
  src=$(findmnt -n -o SOURCE -T "$1" 2>/dev/null | head -n 1)
  case "$src" in /dev/*) ;; *) return 1 ;; esac
  lsblk -n -s -o TYPE -- "$src" 2>/dev/null | grep -qx crypt
}

# ------------------------------------------------------------------ [forbidden]
# A manifest entry whose id is forbidden on any server is itself a violation (AUD-RM2-DEP-10).
FORBIDDEN=$(awk -F'\t' '$1=="F" && $2=="ids" {print $3}' "$WORK/parsed")
if [ -z "$FORBIDDEN" ]; then echo "check-placement: [forbidden] ids missing (fail closed)" >&2; exit 2; fi
nforb=0
while IFS= read -r fid; do
  case ",$FORBIDDEN," in *",$fid,"*) report manifest.forbidden FAIL "entry id is forbidden on servers: $fid"; nforb=$((nforb + 1)) ;; esac
done < <(awk -F'\t' '$1=="S" && $3=="id" {print $4}' "$WORK/parsed")
[ "$nforb" -eq 0 ] && report manifest.forbidden OK "no forbidden id among the entries"

# ------------------------------------------------------------------ active entries
NSEC=$(awk -F'\t' '$1=="S" {n=$2} END {print n+0}' "$WORK/parsed")
: > "$WORK/allowed"
enabled=",always,${FLAGS},"
i=1
while [ "$i" -le "$NSEC" ]; do
  id=$(sec "$i" id); path=$(sec "$i" path); owner=$(sec "$i" owner); group=$(sec "$i" group)
  mode=$(sec "$i" mode); pmode=$(sec "$i" parent_mode); pat=$(sec "$i" pattern)
  flags=$(sec "$i" flags); req=$(sec "$i" required)
  i=$((i + 1))
  for v in "$id" "$path" "$owner" "$group" "$mode" "$pmode" "$pat" "$flags" "$req"; do
    if [ -z "$v" ]; then echo "check-placement: secret entry $((i - 1)) lacks a required key" >&2; exit 2; fi
  done
  valid_path "$path" || { echo "check-placement: invalid path in entry $id" >&2; exit 2; }
  case "$mode$pmode" in *[!0-7]*) echo "check-placement: invalid mode in entry $id" >&2; exit 2 ;; esac
  case "$req" in true|false) ;; *) echo "check-placement: invalid required in entry $id" >&2; exit 2 ;; esac
  if [ "$pat" != none ] && ! pattern_regex "$pat" >/dev/null; then echo "check-placement: unknown pattern in $id" >&2; exit 2; fi

  active=1
  oldifs=$IFS; IFS=,
  for fl in $flags; do case "$enabled" in *",$fl,"*) ;; *) active=0 ;; esac; done
  IFS=$oldifs
  if [ "$active" -eq 0 ]; then report "entry.$id" OK "inactive (flags: $flags)"; continue; fi
  printf '%s\n' "$path" >> "$WORK/allowed"

  f="$ROOT$path"
  if [ -L "$f" ]; then report "entry.$id" FAIL "is a symlink: $path"; continue; fi
  if lnk=$(symlinked_component "$path"); then report "entry.$id" FAIL "path component is a symlink: $lnk"; continue; fi
  if [ ! -e "$f" ]; then
    if [ "$req" = true ]; then report "entry.$id" FAIL "missing: $path"; else report "entry.$id" OK "absent (optional)"; fi
    continue
  fi
  if [ ! -f "$f" ]; then report "entry.$id" FAIL "not a regular file: $path"; continue; fi
  read -r so sg sm sh <<EOF
$(stat -c '%U %G %a %h' -- "$f")
EOF
  read -r pm <<EOF
$(stat -c '%a' -- "$(dirname -- "$f")")
EOF
  want_m=$(printf '%s' "$mode" | sed 's/^0*//'); want_p=$(printf '%s' "$pmode" | sed 's/^0*//')
  problems=""
  [ "$so" = "$owner" ] || problems="$problems owner=$so(want $owner)"
  [ "$sg" = "$group" ] || problems="$problems group=$sg(want $group)"
  [ "$sm" = "$want_m" ] || problems="$problems mode=$sm(want $mode)"
  [ "$pm" = "$want_p" ] || problems="$problems parent_mode=$pm(want $pmode)"
  [ "$sh" = 1 ] || problems="$problems links=$sh(want 1)"
  if [ "$pat" != none ] && ! grep -qaE -- "$(pattern_regex "$pat")" "$f"; then problems="$problems content!=$pat"; fi
  if [ -n "$problems" ]; then report "entry.$id" FAIL "$path:$problems"; else report "entry.$id" OK "$path"; fi
  if [ "$pat" = tor_hs_secret_key ]; then
    if [ -n "$ROOT" ]; then report "entry.$id.encrypted_volume" SKIP "offline root: backing device not checked"
    elif on_encrypted_fs "$f"; then report "entry.$id.encrypted_volume" OK "dm-crypt backed"
    else report "entry.$id.encrypted_volume" FAIL "$path is not on a dm-crypt (LUKS) backed filesystem"; fi
  fi
done

# ------------------------------------------------------------------ scan
if [ "$SCANMODE" = full ]; then roots=$(scan roots); else roots=$(scan light_roots); fi
excl=$(scan exclude); blobs=$(scan name_only_blobs); staging=$(scan name_only_staging)
maxk=$(scan max_file_kib); pats=$(scan patterns)
case "$maxk" in ''|*[!0-9]*) echo "check-placement: bad max_file_kib" >&2; exit 2 ;; esac
if [ -z "$roots" ] || [ -z "$pats" ]; then echo "check-placement: [scan] incomplete" >&2; exit 2; fi

prune=()
oldifs=$IFS; IFS=,
for p in $excl $blobs $staging; do
  valid_path "$p" || { IFS=$oldifs; echo "check-placement: invalid scan path" >&2; exit 2; }
  prune+=( -path "$ROOT$p" -o )
done
rootargs=()
for r in $roots; do
  valid_path "$r" || { IFS=$oldifs; echo "check-placement: invalid scan root" >&2; exit 2; }
  if [ -d "$ROOT$r" ]; then rootargs+=( "$ROOT$r" ); fi
done
IFS=$oldifs
prune+=( -fstype proc -o -fstype sysfs -o -fstype devtmpfs -o -fstype cgroup2 -o -fstype debugfs -o -fstype securityfs )

if [ "${#rootargs[@]}" -eq 0 ]; then report scan.roots FAIL "no scan root exists"; else
  # Regular files only (find -P never follows symlinks), size-capped; secrets are small.
  find "${rootargs[@]}" \( "${prune[@]}" \) -prune -o -type f -size -"$((maxk + 1))"k -print0 2>/dev/null > "$WORK/files"
  : > "$WORK/hits"
  oldifs=$IFS; IFS=,
  for p in $pats; do
    IFS=$oldifs
    if ! pattern_regex "$p" >/dev/null; then echo "check-placement: unknown scan pattern $p" >&2; exit 2; fi
    case "$p" in
      jwk_private)
        xargs -0 -r grep -l -a -s -E -- '"kty"[[:space:]]*:' < "$WORK/files" | tr '\n' '\0' |
          xargs -0 -r grep -l -a -s -E -- '"d"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_-]{16,}"' |
          sed "s/\$/	$p/" >> "$WORK/hits" ;;
      pkcs12)
        tr '\0' '\n' < "$WORK/files" | grep -iE '\.(p12|pfx)$' | sed "s/\$/	$p/" >> "$WORK/hits" ;;
      *)
        xargs -0 -r grep -l -a -s -E -- "$(pattern_regex "$p")" < "$WORK/files" | sed "s/\$/	$p/" >> "$WORK/hits" ;;
    esac
    # tor client-auth private keys are also recognised by name (17 §4.9).
    if [ "$p" = tor_client_auth_private ]; then
      tr '\0' '\n' < "$WORK/files" | grep -E '\.auth_private$' | sed "s/\$/	$p/" >> "$WORK/hits"
    fi
    IFS=,
  done
  IFS=$oldifs

  # A newline in a file name could split one hit into several report lines; such names are
  # never legitimate on H-INTAKE, so they are violations in themselves.
  nl=$(tr '\0' '\n' < "$WORK/files" | grep -c '^' || true)
  nf=$(tr -cd '\0' < "$WORK/files" | wc -c)
  if [ "$nl" -ne "$nf" ]; then report scan.newline_in_name FAIL "a scanned file name contains a newline"; else report scan.newline_in_name OK; fi
  sort -u "$WORK/hits" > "$WORK/hits.s"
  nscanned=$(tr -cd '\0' < "$WORK/files" | wc -c)
  unlisted=0
  while IFS="$(printf '\t')" read -r hp hpat; do
    rel=${hp#"$ROOT"}
    if grep -qxF -- "$rel" "$WORK/allowed"; then continue; fi
    unlisted=$((unlisted + 1))
    report scan.unlisted_secret FAIL "$rel ($hpat)"
  done < "$WORK/hits.s"
  if [ "$unlisted" -eq 0 ]; then report scan.unlisted_secret OK "$SCANMODE scan of $nscanned files: no secret outside the manifest"; fi

  # NET-043 / ADR-032: exactly one source onion key copy on a single-host profile.
  nonion=$(awk -F'\t' '$2=="tor_hs_secret_key"' "$WORK/hits.s" | grep -c '^' || true)
  nonion_allowed=$(grep -c '/hs_ed25519_secret_key$' "$WORK/allowed" || true)
  if [ "$nonion" -gt "$nonion_allowed" ]; then
    report scan.onion_key_copies FAIL "$nonion onion secret keys found, $nonion_allowed allowed"
  else
    report scan.onion_key_copies OK "$nonion"
  fi
fi

# ------------------------------------------------------------------ name-only directories
check_names() { # rule dir sharded(0|1)
  local d="$ROOT$2" bad
  if [ ! -d "$d" ]; then report "$1" OK "absent"; return; fi
  if [ "$3" -eq 1 ]; then
    bad=$(cd "$d" && find . -mindepth 1 \( -type d -regextype posix-extended ! -regex '\./[a-z2-7]{2}' \) -print -o \
          \( ! -type d -regextype posix-extended ! -regex '\./([a-z2-7]{2}/[a-z2-7]{26}|\.tmp-[a-z2-7]{26})' \) -print -o \
          \( ! -type d ! -type f \) -print 2>/dev/null | head -n 5 | tr '\n' ' ')
  else
    bad=$(cd "$d" && find . -mindepth 1 \( -type d -o ! -type f \) -print -o \
          \( -regextype posix-extended ! -regex '\./(\.tmp-)?[a-z2-7]{26}' \) -print 2>/dev/null | head -n 5 | tr '\n' ' ')
  fi
  if [ -n "$bad" ]; then report "$1" FAIL "unexpected entries (not read): $bad"; else report "$1" OK "names match layout"; fi
}
[ -n "$blobs" ] && check_names scan.name_only_blobs "$blobs" 1
[ -n "$staging" ] && check_names scan.name_only_staging "$staging" 0

if [ "$FAILS" -gt 0 ]; then
  printf 'check-placement: %d violation(s) (exit=30)\n' "$FAILS"
  exit 30
fi
echo 'check-placement: placement equals manifest (exit=0)'
exit 0
