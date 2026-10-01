#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# config-check.sh - configuration checker for the Candor intake host (Z-INTAKE).
#
# Implements the subset of `candorctl check` (18-DEPLOYMENT.md §14; rules from
# 32-OPERATIONS.md §5.2/§7, 16-TOR-I2P.md §7.4 lint, 17-INFRASTRUCTURE.md §4.3/§5,
# 09-DATABASE.md §10, 20-LOGGING-AUDITING.md §11 and LOG-005/007/008) for deploy/intake:
# torrc, nftables, PostgreSQL, systemd units, journald, kernel baseline and resolv.conf.
#
# Usage:
#   config-check.sh [--dir DIR] [--profile ce-single|ce-hardened]   static check of a tree
#   config-check.sh --host [--root DIR]                             installed host (ST-120)
#   --only LIST   comma list of sections: tor,nft,pg,units,journald,kernel,dns,host
#   --emit-baseline   (maintainers) print the effective units/nft/tor/security values of the
#                     tree as baseline lines for review; performs no check
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
#   PostgreSQL the conf file is checked statically; --host also asks the server binary for the
#             effective values (postgres -C, includes postgresql.auto.conf).
# --host without --root also reads live state (/proc/sys, loaded nft ruleset, systemctl show,
# AppArmor). With --root (offline image or tests) live-only checks are reported as SKIP; only
# `--host` without --root is the ST-120 gate.
#
# Requirements (fail closed if missing): root, bash, awk, jq, tor, nft, unshare, setpriv,
# systemd-analyze; --host additionally the PostgreSQL 16 server binary.
# Output: "HOST RULE CLASS STATUS DETAIL" table (18 §14). Details never contain secrets, file
# contents of unrelated files or source-related data; values are reduced to printable ASCII.
# Exit codes (18 §14): 0 = all OK; 30 = baseline failure (any FAIL); 2 = usage / missing input.

set -u
LC_ALL=C
export LC_ALL
umask 077

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BASE="$SCRIPT_DIR/config-check.baseline"
MODE=static
DIR="$SCRIPT_DIR/../intake"
ROOT=""
PROFILE=""
ONLY=""
QUIET=0
EMIT=0
FAILS=0
CHECKS=0
SKIPS=0

usage() {
  sed -n '4,41p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || usage; DIR=$2; shift 2 ;;
    --host) MODE=host; shift ;;
    --root) [ $# -ge 2 ] || usage; ROOT=${2%/}; shift 2 ;;
    --profile) [ $# -ge 2 ] || usage; PROFILE=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || usage; ONLY=$2; shift 2 ;;
    --emit-baseline) EMIT=1; shift ;;
    -q) QUIET=1; shift ;;
    -h|--help) usage ;;
    *) echo "config-check: unknown argument" >&2; usage ;;
  esac
done
case "$ONLY" in *[!a-z,]*) echo "config-check: invalid --only" >&2; exit 2 ;; esac
if [ ! -f "$BASE" ] || [ ! -r "$BASE" ]; then echo "config-check: baseline file missing: $BASE" >&2; exit 2; fi

LIVE=0
if [ "$MODE" = host ]; then
  if [ -n "$ROOT" ]; then [ -d "$ROOT" ] || { echo "config-check: --root is not a directory" >&2; exit 2; }; else LIVE=1; fi
  [ -z "$PROFILE" ] || { echo "config-check: --profile is static-mode only (a host has its drop-ins installed)" >&2; exit 2; }
  TORRC="$ROOT/etc/tor/instances/candor-intake/torrc"
  NFT="$ROOT/etc/nftables.conf"
  PGCONF="$ROOT/etc/candor/intake/postgresql/candor-intake.conf"
  PGHBA="$ROOT/etc/candor/intake/postgresql/pg_hba.conf"
  JNS="$ROOT/etc/systemd/journald@candor-intake.conf"
  JHOST="$ROOT/etc/systemd/journald.conf.d/50-candor-intake.conf"
  SYSCTL="$ROOT/etc/sysctl.d/90-candor-intake.conf"
  COREDUMP="$ROOT/etc/systemd/coredump.conf.d/50-candor-intake.conf"
  RESOLV="$ROOT/etc/resolv.conf"
else
  [ -d "$DIR" ] || { echo "config-check: no such directory: $DIR" >&2; exit 2; }
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
fi

# /tmp (not $TMPDIR): the tor canonicalisation hides /run and /var/lib in its mount namespace.
WORK=$(mktemp -d /tmp/candor-config-check.XXXXXX) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

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
skip() { report "$1" baseline SKIP "${2:-}"; }
# Feed "STATUS<TAB>rule<TAB>detail" lines (from awk/jq helpers) into report().
report_lines() { local st r d; while IFS="$(printf '\t')" read -r st r d; do case "$st" in OK) ok "$r" "$d" ;; SKIP) skip "$r" "$d" ;; *) fail "$r" "$d" ;; esac; done; }

want() { [ -z "$ONLY" ] || case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }
need_file() { # rule file
  if [ ! -f "$2" ] || [ ! -r "$2" ]; then fail "$1" "missing or unreadable: $(basename "$2")"; return 1; fi
  return 0
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

# =============================================================================== torrc
TOR_USER=_tor-candor-intake

tor_canon() { # -> $WORK/tor/{verify,short,full}.out ; returns non-zero on any failure
  local d="$WORK/tor"
  mkdir -p "$d" && chmod 0755 "$WORK" "$d" && cp "$TORRC" "$d/torrc" && chmod 0644 "$d/torrc" || return 1
  # Private mount namespace: tmpfs over /var/lib and /run so the canonicalisation never touches
  # the real tor state, keys or sockets; tor itself runs unprivileged as the instance user.
  # shellcheck disable=SC2016 # expanded by the inner shell
  unshare -m --propagation private /bin/sh -c '
    set -e
    mount -t tmpfs -o mode=0755,size=16m tmpfs /var/lib
    mount -t tmpfs -o mode=0755,size=16m tmpfs /run
    mkdir -p /var/lib/tor-instances/candor-intake
    chown "$2:$3" /var/lib/tor-instances/candor-intake
    chmod 0700 /var/lib/tor-instances/candor-intake
    for m in verify short full; do
      case $m in verify) a=--verify-config ;; short) a="--dump-config short" ;; full) a="--dump-config full" ;; esac
      # shellcheck disable=SC2086
      timeout 60 setpriv --reuid="$2" --regid="$3" --clear-groups --no-new-privs -- \
        tor --defaults-torrc /dev/null -f "$1/torrc" --hush $a > "$1/$m.raw" 2>/dev/null </dev/null || exit 3
      # tor prints log lines on stdout before its own Log option applies; keep option lines only.
      grep -vE "^[A-Z][a-z]{2} [0-9]{2} [0-9:.]+ \[" "$1/$m.raw" > "$1/$m.out" || true
    done' sh "$d" "$TOR_USER" "$(id -g "$TOR_USER")"
}

check_torrc() {
  need_file tor.file "$TORRC" || return
  # ---- raw text: no continuation, no %include, no '+'/'/' line prefixes, every key a full
  # option name from the template (tor accepts abbreviations and case variants), no repeats.
  if grep -qE '\\[[:space:]]*$' "$TORRC"; then fail tor.raw.no_continuation "line continuation used"; else ok tor.raw.no_continuation; fi
  sed -e 's/#.*$//' "$TORRC" | trim | grep -v '^$' > "$WORK/torrc.clean"
  if grep -qiE '^%' "$WORK/torrc.clean"; then fail tor.raw.no_include "%include or other % directive present"; else ok tor.raw.no_include; fi
  if grep -qE '^[+/]' "$WORK/torrc.clean"; then fail tor.raw.no_prefix "'+Option' (append) or '/Option' (reset) line present"; else ok tor.raw.no_prefix; fi
  local unknown dup
  unknown=$(awk 'NR==FNR { if ($1=="tor-raw") ok[tolower($2)]=1; next } !(tolower($1) in ok) { print $1 }' FS='|' "$BASE" FS=' ' "$WORK/torrc.clean" | sort -u | tr '\n' ' ')
  if [ -n "$unknown" ]; then fail tor.raw.allowed_keys "option(s) not in the template (abbreviations are rejected too): $unknown"; else ok tor.raw.allowed_keys; fi
  dup=$(awk '{ print tolower($1) }' "$WORK/torrc.clean" | sort | uniq -d | tr '\n' ' ')
  if [ -n "$dup" ]; then fail tor.raw.no_duplicates "repeated option(s): $dup"; else ok tor.raw.no_duplicates; fi
  # Never hand an %include line to tor (it could make tor read an arbitrary file).
  if grep -qiE '^%' "$WORK/torrc.clean"; then fail tor.effective "not canonicalised: % directive present"; return; fi

  # ---- effective configuration, as tor itself parses it
  need_tools tor.effective tor unshare setpriv timeout || return
  getent passwd "$TOR_USER" >/dev/null || { fail tor.effective "user $TOR_USER missing"; return; }
  if ! tor_canon; then fail tor.effective "tor --verify-config / --dump-config rejected the file (details suppressed)"; return; fi
  ok tor.verify_config "tor --verify-config: valid"
  # Short dump = every option that differs from tor's default. Each must be on the allow-list
  # with its required value (or within its tunable range), and each allow-listed option must
  # be present exactly once.
  awk -F'|' '
    FNR==NR { if ($1=="tor") { mode[$2]=$3; val[$2]=$4; order[++n]=$2 } next }
    { k=$1; v=$0; sub(/^[^ ]+ ?/, "", v); cnt[k]++; got[k]=v
      if (!(k in mode)) { printf "FAIL\ttor.effective.%s\tnot allowed (effective non-default option): %s %s\n", k, k, v; next } }
    END {
      for (i=1; i<=n; i++) { k=order[i]
        if (cnt[k]==0) { printf "FAIL\ttor.effective.%s\tmissing (required: %s)\n", k, val[k]; continue }
        if (cnt[k]>1) { printf "FAIL\ttor.effective.%s\tset %d times\n", k, cnt[k]; continue }
        v=got[k]
        if (mode[k]=="=") { if (v==val[k]) printf "OK\ttor.effective.%s\t%s\n", k, v; else printf "FAIL\ttor.effective.%s\texpected [%s], found [%s]\n", k, val[k], v }
        else if (mode[k]=="int") { split(val[k], r, " ")
          if (v ~ /^[0-9]+$/ && length(v) <= 10 && v+0 >= r[1]+0 && v+0 <= r[2]+0) printf "OK\ttor.effective.%s\t%s\n", k, v
          else printf "FAIL\ttor.effective.%s\texpected an integer in [%s, %s], found [%s]\n", k, r[1], r[2], v }
      } }' "$BASE" FS=' ' "$WORK/tor/short.out" | report_lines
  # Options whose required value is tor's default (so they never appear in the short dump),
  # plus the path-selection options an attacker would use (checked in the full dump).
  awk -F'|' '
    FNR==NR { if ($1=="tor-full") { want[$2]=$3; order[++n]=$2 } next }
    { k=$1; v=$0; sub(/^[^ ]+ ?/, "", v); if (k in want) { cnt[k]++; got[k]=v } }
    END { for (i=1; i<=n; i++) { k=order[i]
      if (cnt[k]!=1) printf "FAIL\ttor.full.%s\texpected exactly one effective value [%s], found %d\n", k, want[k], cnt[k]
      else if (got[k]!=want[k]) printf "FAIL\ttor.full.%s\texpected [%s], found [%s]\n", k, want[k], got[k]
      else printf "OK\ttor.full.%s\t%s\n", k, got[k] } }' "$BASE" FS=' ' "$WORK/tor/full.out" | report_lines
  # No control interface of any kind (AUD-RM2-DEP-04; NET-009).
  if grep -qE '^(ControlSocket|ControlPort|__ControlPort|__OwningControllerProcess|HashedControlPassword) [^0]' "$WORK/tor/full.out"; then
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
    else line("FAIL"; $p+".object_types"; "unexpected object type(s): \($types - ["metainfo","table","chain","rule","set","counter"] | join(" "))") end ),
  ( if ($tables | map("\(.family) \(.name)")) == ["inet candor_intake"] then line("OK"; $p+".single_table"; "inet candor_intake")
    else line("FAIL"; $p+".single_table"; "expected only 'table inet candor_intake', found: \($tables | map("\(.family) \(.name)") | join(", "))") end ),
  ( ["input","output","forward"][] as $c
    | ($chains | map(select(.name==$c and .table=="candor_intake"))) as $m
    | if ($m|length)==1 and $m[0].type=="filter" and $m[0].hook==$c and $m[0].prio==0 and $m[0].policy=="drop"
      then line("OK"; $p+".policy_drop."+$c; "filter hook \($c) priority 0 policy drop")
      else line("FAIL"; $p+".policy_drop."+$c; "chain \($c) must be the only 'type filter hook \($c) priority filter; policy drop;'") end ),
  ( if ($chains | map(.name) | sort) == ["forward","input","output"] then line("OK"; $p+".only_filter_chains"; "")
    else line("FAIL"; $p+".only_filter_chains"; "extra or missing chain(s): \($chains | map(.name) | join(" "))") end ),
  ( ([$rules[] | .c | fromjson | .. | objects | keys[]] | unique) as $k
    | ($k - ($k - ["log","queue","dup","fwd","jump","goto","notrack","snat","dnat","masquerade","redirect","tproxy","synproxy","mangle"])) as $badk
    | if $badk == [] then line("OK"; $p+".no_log_queue_jump"; "")
      else line("FAIL"; $p+".no_log_queue_jump"; "forbidden statement(s): \($badk | join(" "))") end ),
  ( ($exp | map(select(.c | fromjson | map(has("accept")) | any) | .chain + "|" + .c)) as $okacc
    | ($rules | map(select(.accept) | .chain + "|" + .c) | map(select(. as $x | $okacc | index($x) | not))) as $extra
    | if $extra == [] then line("OK"; $p+".accept_rules"; "only the template accepts (E1-E4, I1-I2)")
      else line("FAIL"; $p+".accept_rules"; "\($extra|length) non-template accept rule(s): \($extra[0] | .[0:240])") end ),
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
    else line("FAIL"; $p+".sets"; "unexpected set list: \($sets | map(.name) | join(" "))") end ),
  ( ["non_public4","non_public6"][] as $n
    | ($sets | map(select(.name==$n)) | .[0]) as $s
    | if $s != null and ($s | setcanon) == $expsets[$n] then line("OK"; $p+".set."+$n; "elements equal the template")
      else line("FAIL"; $p+".set."+$n; "type, flags or elements differ from the template") end ),
  ( ["mon_hosts","admin_jump","core_relay"][] as $n
    | ($sets | map(select(.name==$n)) | .[0]) as $s
    | if $s != null and $s.type=="ipv4_addr" and (($s.flags // []) == []) and (($s.elem // []) | all(type=="string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")))
         and ($n != "core_relay" or (($s.elem // []) | length) <= 1)
      then line("OK"; $p+".set."+$n; "\(($s.elem // []) | length) plain IPv4 address(es)")
      else line("FAIL"; $p+".set."+$n; "must be 'type ipv4_addr' with plain addresses only (core_relay: at most one)") end ),
  ( if $counters == ["forward_dropped","input_dropped","output_dropped"] then line("OK"; $p+".counters"; "")
    else line("FAIL"; $p+".counters"; "unexpected counters: \($counters | join(" "))") end )
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
  need_file nft.file "$NFT" || return
  # Text-level: a host loads this file on top of the kernel's ruleset, so it must flush first.
  # include/define/variables are rejected before the file is handed to nft (an include could
  # also make the root-run checker read an arbitrary file).
  local body
  body=$(grep -vE '^[[:space:]]*(#|$)' "$NFT")
  if printf '%s\n' "$body" | head -n 1 | trim | grep -qx 'flush ruleset'; then ok nft.flush_ruleset; else fail nft.flush_ruleset "first statement must be 'flush ruleset'"; fi
  if printf '%s\n' "$body" | grep -qE '(^|[^[:alnum:]_])(include|define|undefine|redefine)([^[:alnum:]_]|$)|\$'; then
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
  need_file pg.file "$PGCONF" || return
  local norm dup
  norm=$(pg_norm "$PGCONF")
  if printf '%s\n' "$norm" | cut -f1 | grep -qE '^(include|include_dir|include_if_exists)$'; then
    fail pg.no_include "include directive present (effective config must be this file)"
  else ok pg.no_include; fi
  dup=$(printf '%s\n' "$norm" | cut -f1 | sort | uniq -d | tr '\n' ' ')
  if [ -n "$dup" ]; then fail pg.no_duplicates "duplicate keys: $dup"; else ok pg.no_duplicates; fi

  # Static values (pg|key|kind|value; kind b = boolean, s = case-insensitive string).
  local key kind want got
  while IFS='|' read -r _ key kind want; do
    if ! printf '%s\n' "$norm" | cut -f1 | grep -qx -- "$key"; then fail "pg.$key" "not set explicitly (expected '$want')"; continue; fi
    got=$(printf '%s\n' "$norm" | awk -F'\t' -v k="$key" '$1==k {print $2}')
    if [ "$kind" = b ]; then got=$(pg_bool "$got"); else got=$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]'); fi
    if [ "$got" = "$want" ]; then ok "pg.$key" "'$want'"; else fail "pg.$key" "expected '$want', found '$got'"; fi
  done < <(base pg)

  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="log_line_prefix" {print $2}')
  if ! printf '%s\n' "$norm" | cut -f1 | grep -qx log_line_prefix; then fail pg.log_line_prefix "not set (PG default contains %m and %p)"
  elif printf '%s' "$got" | sed 's/%%//g; s/%e//g' | grep -q '%'; then fail pg.log_line_prefix "only %e allowed: '$got'"
  else ok pg.log_line_prefix "'$got'"; fi
  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="unix_socket_permissions" {print $2}')
  case "$got" in 0770|0750|0700|770|750|700) ok pg.unix_socket_permissions "$got" ;;
    *) fail pg.unix_socket_permissions "no world access allowed, found '$got'" ;; esac

  # pg_hba: Unix-socket peer only, reject last (09 §10, DB-022, R7 SI-E-01).
  if need_file pg.hba_file "$PGHBA"; then
    local hba last
    hba=$(sed -e 's/#.*$//' "$PGHBA" | trim | tr -s ' \t' '  ' | grep -v '^$')
    if printf '%s\n' "$hba" | awk '$1 != "local" {bad=1} END {exit bad?0:1}'; then fail pg.hba_local_only "non-local (TCP) line present"; else ok pg.hba_local_only; fi
    if printf '%s\n' "$hba" | awk '$1=="include" || $1=="include_dir" || $1=="include_if_exists" || $0 ~ /@/ {bad=1} END {exit bad?0:1}'; then fail pg.hba_no_include "include or @file reference present"; else ok pg.hba_no_include; fi
    if printf '%s\n' "$hba" | awk '{m=$4} m!="peer" && m!="reject" {bad=1} END {exit bad?0:1}'; then fail pg.hba_methods "only peer/reject allowed"; else ok pg.hba_methods; fi
    last=$(printf '%s\n' "$hba" | tail -n 1)
    if [ "$last" = "local all all reject" ]; then ok pg.hba_reject_last; else fail pg.hba_reject_last "last line must be 'local all all reject'"; fi
  fi

  [ "$MODE" = host ] || return
  # ---- effective settings as the server computes them (AUD-RM2-DEP-03(1)): includes
  # postgresql.auto.conf (ALTER SYSTEM). Command-line -c options are pinned by the unit check.
  local pgbin=/usr/lib/postgresql/16/bin/postgres dd owner auto
  dd=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="data_directory" {print $2}')
  case "$dd" in /*) ;; *) fail pg.effective "data_directory is not an absolute path"; return ;; esac
  if [ ! -d "$ROOT$dd" ]; then fail pg.effective "data directory missing"; return; fi
  auto="$ROOT$dd/postgresql.auto.conf"
  if [ -e "$auto" ] && [ -n "$(pg_norm "$auto")" ]; then fail pg.auto_conf_empty "postgresql.auto.conf contains settings (ALTER SYSTEM)"; else ok pg.auto_conf_empty; fi
  [ -x "$pgbin" ] || { fail pg.effective "PostgreSQL 16 server binary missing"; return; }
  if ! is_root || ! have setpriv; then fail pg.effective "must run as root with setpriv"; return; fi
  owner=$(stat -c %U -- "$ROOT$dd")
  if [ "$owner" = root ]; then fail pg.effective "data directory owned by root"; return; fi
  if [ "$LIVE" -eq 1 ] && [ "$owner" != postgres ]; then fail pg.datadir_owner "data directory must be owned by postgres, found $owner"; fi
  local -a extra=()
  [ -n "$ROOT" ] && extra=(-c "data_directory=$ROOT$dd")
  local g w v
  while IFS='|' read -r _ g w; do
    if ! v=$(run_as "$owner" "$pgbin" -C "$g" -c "config_file=$PGCONF" "${extra[@]}" 2>/dev/null); then fail "pg.effective.$g" "postgres -C failed"; continue; fi
    if [ "$v" = "$w" ]; then ok "pg.effective.$g" "'$w'"; else fail "pg.effective.$g" "expected '$w', effective '$v'"; fi
  done < <(base pgc)
}

# =============================================================================== systemd units
ALL_UNITS="tor@candor-intake.service candor-intake-web.service candor-sealer.service candor-intake-store.service
candor-intake-pg.service candor-intake-web.socket candor-sealer.socket candor-intake-store.socket
candor-intake-store-relay.socket run-candor-staging.mount"
SERVICES="tor@candor-intake.service:15 candor-intake-web.service:5 candor-sealer.service:5 candor-intake-store.service:5 candor-intake-pg.service:5"

SR=""
units_root() { # static: a scratch root holding the tree (+ profile drop-ins) as /etc/systemd/system
  if [ "$MODE" = host ]; then SR=${ROOT:-/}; return 0; fi
  SR="$WORK/sroot"
  mkdir -p "$SR/etc/systemd/system" && cp -a "$DIR/systemd/." "$SR/etc/systemd/system/" || return 1
  if [ -n "$PROFILE" ]; then
    local d
    for d in "$DIR/profiles/$PROFILE"/*.d; do
      [ -d "$d" ] || continue
      mkdir -p "$SR/etc/systemd/system/$(basename "$d")" && cp -a "$d/." "$SR/etc/systemd/system/$(basename "$d")/" || return 1
    done
  fi
}
rootopt() { if [ "$SR" != / ]; then printf -- '--root=%s' "$SR"; else printf -- '--root=/'; fi; }

# Merge fragment + drop-ins (in systemd's order) into "Section|Key|v1 ;; v2 ;; ..." lines.
# An empty assignment is kept as an empty element, so a reset is always visible.
unit_merge() { # files... -> stdout
  local f
  for f in "$@"; do printf '#@@FILE\n'; cat -- "$f"; printf '\n'; done | awk '
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
  if [ -s "$WORK/verify.f" ]; then fail unit.verify "systemd-analyze verify: $(head -n 2 "$WORK/verify.f" | sed "s|$SR||g" | tr '\n' ' ')"; else ok unit.verify "systemd-analyze verify clean"; fi

  local -a files
  mkdir -p "$WORK/eff"
  for u in $ALL_UNITS; do
    frag=$(awk -F'\t' -v u="$u" '$1==u && $2=="F" {print $3}' "$WORK/unitpaths")
    if [ "$frag" != "${SR%/}/etc/systemd/system/$u" ] || [ -L "$frag" ] || [ ! -f "$frag" ]; then
      fail "unit.$u.fragment" "unit must load from /etc/systemd/system/$u (found '${frag#"${SR%/}"}')"; continue
    fi
    files=("$frag")
    while IFS= read -r f; do files+=("$f"); done < <(awk -F'\t' -v u="$u" '$1==u && $2=="D" {print $3}' "$WORK/unitpaths")
    ok "unit.$u.fragment" "$(( ${#files[@]} - 1 )) drop-in(s) applied"
    unit_merge "${files[@]}" > "$WORK/eff/$u"
    # Effective, section-aware directives against the per-unit allow-list (exact values).
    awk -v u="$u" '
      FNR==NR { if (split($0, a, "|") >= 5 && a[1]=="unit" && a[2]==u) {
                  k=a[3] "|" a[4]; v=substr($0, length(a[1] a[2] a[3] a[4] a[5])+6)
                  if (!(k in mode)) { order[++n]=k; mode[k]=a[5]; exp[k]=v }
                  else if (a[5]=="=") exp[k]=exp[k] " ;; " v } next }
      { e=index($0, "|"); s=substr($0, 1, e-1); r=substr($0, e+1); e=index(r, "|"); k=s "|" substr(r, 1, e-1); got[k]=substr(r, e+1); seen[k]=1
        if (!(k in mode)) printf "FAIL\tunit.%s.%s\tdirective not allowed: [%s] %s=%s\n", u, k, s, substr(r, 1, e-1), got[k] }
      END { for (i=1; i<=n; i++) { k=order[i]; m=mode[k]
        if (m=="*") { if (k in seen) printf "OK\tunit.%s.%s\t(semantic check)\n", u, k; else printf "FAIL\tunit.%s.%s\tmissing\n", u, k; continue }
        g=(k in seen) ? got[k] : ""
        if (m=="=") { if (!(k in seen)) printf "FAIL\tunit.%s.%s\tmissing (expected %s)\n", u, k, exp[k]
                      else if (g==exp[k]) printf "OK\tunit.%s.%s\t%s\n", u, k, (g=="" ? "<empty>" : g)
                      else printf "FAIL\tunit.%s.%s\texpected [%s], effective [%s]\n", u, k, exp[k], g }
        else if (m=="~") { if (g ~ exp[k]) printf "OK\tunit.%s.%s\t%s\n", u, k, (k in seen ? g : "<absent>")
                           else printf "FAIL\tunit.%s.%s\teffective [%s] does not match %s\n", u, k, g, exp[k] } } }' "$BASE" "$WORK/eff/$u" | report_lines
  done

  # Sealer syscall filter (its lines are owned by the sealer work, AUD-RM2-SEA-06): allow-list
  # mode, never reset; the deny groups are verified by systemd-analyze security below.
  if [ -f "$WORK/eff/candor-sealer.service" ]; then
    local scf
    scf=$(awk -F'|' '$1=="Service" && $2=="SystemCallFilter" {print substr($0, length($1 $2)+3)}' "$WORK/eff/candor-sealer.service")
    if [ -z "$scf" ] || printf '%s' "$scf" | grep -qE '^~|^ ;; | ;; $| ;;  ;; '; then
      fail unit.candor-sealer.syscall_allow_list "SystemCallFilter must start in allow-list mode and never be reset"
    else ok unit.candor-sealer.syscall_allow_list; fi
  fi
  # Relay socket: an IPAddressAllow drop-in must name exactly the single @core_relay address.
  local allow
  allow=$(awk -F'|' '$1=="Socket" && $2=="IPAddressAllow" {print substr($0, length($1 $2)+3)}' "$WORK/eff/candor-intake-store-relay.socket" 2>/dev/null)
  if [ -z "$allow" ]; then ok unit.relay_ip_allow "none (fail closed until the site drop-in exists)"
  elif [ "$NFT_LOADED" -eq 1 ] && [ "$allow" = "$(printf '%s' "$CORE_RELAY_ELEMS" | trim)/32" ]; then ok unit.relay_ip_allow "$allow = @core_relay"
  else fail unit.relay_ip_allow "IPAddressAllow must be exactly <@core_relay element>/32, found '$allow'"; fi

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
    jq -r '.[] | select(.exposure != null and (.exposure|tostring|tonumber) > 0) | .name' "$WORK/sec.json" 2>/dev/null | sort > "$WORK/sec.bad"
    base sec | awk -F'|' -v u="$name" '$2==u {print $3}' | sort > "$WORK/sec.ok"
    local extra
    extra=$(comm -23 "$WORK/sec.bad" "$WORK/sec.ok" | tr '\n' ' ')
    if [ ! -s "$WORK/sec.json" ]; then fail "unit.$name.security_items" "no assessment"
    elif [ -n "$extra" ]; then fail "unit.$name.security_items" "new exposure item(s): $extra"
    else ok "unit.$name.security_items" "only documented residual items"; fi
  done

  [ "$MODE" = host ] || return
  # Units or drop-ins in places systemd-analyze verify does not read (transient, generators).
  local d bad=""
  for d in "$ROOT/run/systemd/transient" "$ROOT/run/systemd/generator" "$ROOT/run/systemd/generator.early" "$ROOT/run/systemd/generator.late"; do
    [ -d "$d" ] || continue
    bad="$bad$(find "$d" -mindepth 1 -maxdepth 1 \( -name 'candor*' -o -name 'tor@*' -o -name 'tor-*' -o -name 'run-candor*' -o -name 'service.d' -o -name 'socket.d' -o -name 'mount.d' \) -printf '%f ' 2>/dev/null)"
  done
  if [ -n "$bad" ]; then fail unit.no_transient_or_generated "transient/generated unit configuration present: $bad"; else ok unit.no_transient_or_generated; fi
  [ "$LIVE" -eq 1 ] || { skip unit.live "offline root: systemctl show not checked"; return; }
  check_units_live
}

# Live properties of the loaded units (systemctl show; AUD-RM2-DEP-03(4)).
check_units_live() {
  have systemctl || { fail unit.live "systemctl missing"; return; }
  local u spec kind p want got
  for spec in tor@candor-intake.service:tor candor-intake-web.service:candor candor-sealer.service:candor candor-intake-store.service:candor candor-intake-pg.service:pg; do
    u=${spec%%:*}; kind=${spec##*:}
    if ! systemctl show --no-pager "$u" > "$WORK/show" 2>/dev/null || [ ! -s "$WORK/show" ]; then fail "unit.$u.live" "systemctl show failed"; continue; fi
    # Drop-ins actually loaded must be the ones systemd-analyze verify found.
    got=$(sed -n 's/^DropInPaths=//p' "$WORK/show" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' ')
    want=$(awk -F'\t' -v u="$u" '$1==u && $2=="D" {print $3}' "$WORK/unitpaths" | sort | tr '\n' ' ')
    if [ "$got" = "$want" ]; then ok "unit.$u.live.dropins"; else fail "unit.$u.live.dropins" "loaded drop-ins differ from the files (transient, control or generated drop-in?)"; fi
    while IFS='|' read -r _ kinds p want; do
      case ",$kinds," in *",all,"*|*",$kind,"*) ;; *) continue ;; esac
      got=$(sed -n "s/^$p=//p" "$WORK/show" | head -n 1)
      if [ "$got" = "$want" ]; then ok "unit.$u.live.$p" "$want"; else fail "unit.$u.live.$p" "expected '$want', loaded '$got'"; fi
    done < <(base show)
  done
}

# =============================================================================== journald
journald_eff() { # label file catconfig-name -> "Key=Value" last-wins of [Journal]
  if [ "$MODE" = host ]; then
    systemd-analyze "--root=${ROOT:-/}" cat-config "$3" 2>/dev/null
  else cat -- "$2"; fi | awk '
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
  if [ "$MODE" = static ]; then need_file "$1.file" "$2" || return; fi
  [ "$MODE" = static ] || have systemd-analyze || { fail "$1" "systemd-analyze missing"; return; }
  local e k w g s
  e=$(journald_eff "$1" "$2" "$3")
  [ -n "$e" ] || { fail "$1.effective" "no effective [Journal] configuration found"; return; }
  for k in Storage=volatile ForwardToSyslog=no ForwardToKMsg=no ForwardToConsole=no ForwardToWall=no Audit=no; do
    w=${k#*=}; k=${k%%=*}
    g=$(printf '%s\n' "$e" | sed -n "s/^$k=//p")
    if [ "$g" = "$w" ]; then ok "$1.$k" "$w"; else fail "$1.$k" "expected '$w', effective '$g'"; fi
  done
  for k in MaxRetentionSec:86400 MaxFileSec:3600; do
    w=${k#*:}; k=${k%%:*}
    g=$(printf '%s\n' "$e" | sed -n "s/^$k=//p"); s=$(to_seconds "$g")
    if [ -n "$s" ] && [ "$s" -gt 0 ] && [ "$s" -le "$w" ]; then ok "$1.$k" "$g"; else fail "$1.$k" "must be set and <= ${w}s, effective '$g'"; fi
  done
  if [ "$4" -eq 1 ]; then
    g=$(printf '%s\n' "$e" | sed -n 's/^MaxLevelStore=//p')
    case "$g" in emerg|alert|crit|0|1|2) ok "$1.MaxLevelStore" "$g" ;; *) fail "$1.MaxLevelStore" "must be crit or lower, effective '$g'" ;; esac
  fi
}

# =============================================================================== kernel baseline
check_kernel() {
  local k w g src
  # ---- sysctl (20 §11.4, 17 sysctl row; AUD-RM2-DEP-09)
  if [ "$LIVE" -eq 1 ]; then src=live
  elif [ "$MODE" = host ]; then src=offline
  else src="file"; need_file kernel.sysctl.file "$SYSCTL" || src="none"; fi
  if [ "$src" = file ]; then
    local extra
    extra=$(awk -F'|' 'NR==FNR { if ($1=="sysctl") ok[$2]=1; next }
      /^[ \t]*[#;]/ || /^[ \t]*$/ { next }
      { l=$0; sub(/^[ \t]*-?/, "", l); e=index(l, "="); k=substr(l, 1, e-1); gsub(/[ \t]+$/, "", k); if (!(k in ok)) print k }' "$BASE" "$SYSCTL" | tr '\n' ' ')
    if [ -n "$extra" ]; then fail kernel.sysctl.allowed_keys "keys not in the baseline: $extra"; else ok kernel.sysctl.allowed_keys; fi
  fi
  if [ "$src" = file ] || [ "$src" = offline ]; then
    { if [ "$src" = file ]; then cat -- "$SYSCTL"; else systemd-analyze "--root=$ROOT" cat-config sysctl.d 2>/dev/null; [ -f "$ROOT/etc/sysctl.conf" ] && cat -- "$ROOT/etc/sysctl.conf"; fi; } |
      awk '/^[ \t]*[#;]/ || /^[ \t]*$/ { next } { l=$0; sub(/^[ \t]*-?/, "", l); e=index(l, "="); k=substr(l, 1, e-1); v=substr(l, e+1)
        gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v); gsub(/[ \t]+/, " ", v); val[k]=v }
        END { for (k in val) print k "\t" val[k] }' > "$WORK/sysctl.eff"
  fi
  if [ "$src" != none ]; then
    while IFS='|' read -r _ k w; do
      if [ "$src" = live ]; then
        if [ -r "/proc/sys/$(printf '%s' "$k" | tr . /)" ]; then g=$(tr -s ' \t' '  ' < "/proc/sys/$(printf '%s' "$k" | tr . /)" | trim); else g="<absent>"; fi
      else g=$(awk -F'\t' -v k="$k" '$1==k {print $2}' "$WORK/sysctl.eff"); fi
      if [ "$g" = "$w" ]; then ok "kernel.sysctl.$k" "$w"; else fail "kernel.sysctl.$k" "expected '$w', found '$g'"; fi
    done < <(base sysctl)
  fi
  # ---- systemd-coredump stores nothing (20 §11.4, REQ-H-58)
  local cd
  if [ "$MODE" = host ]; then cd=$(systemd-analyze "--root=${ROOT:-/}" cat-config systemd/coredump.conf 2>/dev/null)
  elif need_file kernel.coredump.file "$COREDUMP"; then cd=$(cat -- "$COREDUMP"); else cd=""; fi
  for k in Storage=none ProcessSizeMax=0; do
    w=${k#*=}; k=${k%%=*}
    g=$(printf '%s\n' "$cd" | awk -v k="$k" '/^\[/ { s=$0; next } s=="[Coredump]" { e=index($0, "="); kk=substr($0, 1, e-1); gsub(/[ \t]/, "", kk); if (kk==k) { v=substr($0, e+1); gsub(/^[ \t]+|[ \t]+$/, "", v) } } END { print v }')
    if [ "$g" = "$w" ]; then ok "kernel.coredump.$k" "$w"; else fail "kernel.coredump.$k" "expected '$w', effective '$g'"; fi
  done
  [ "$MODE" = host ] || return
  local sock="$ROOT/etc/systemd/system/systemd-coredump.socket"
  if [ ! -e "$ROOT/usr/lib/systemd/system/systemd-coredump.socket" ] || [ "$(readlink "$sock" 2>/dev/null)" = /dev/null ]; then ok kernel.coredump_socket_masked
  else fail kernel.coredump_socket_masked "systemd-coredump.socket installed and not masked"; fi
  # ---- swap: none, or dm-crypt swap with a fresh random key per boot (20 §11.4)
  local dev name line bad=""
  if [ "$LIVE" -eq 1 ]; then
    while read -r dev _; do
      case "$dev" in Filename) continue ;; /dev/dm-*) name=$(cat "/sys/block/${dev#/dev/}/dm/name" 2>/dev/null) ;; /dev/mapper/*) name=${dev#/dev/mapper/} ;; *) bad="$bad $dev"; continue ;; esac
      line=$(awk -v n="$name" '$1==n' "$ROOT/etc/crypttab" 2>/dev/null)
      printf '%s\n' "$line" | awk '$3=="/dev/urandom" && $4 ~ /(^|,)swap(,|$)/ {f=1} END {exit f?0:1}' || bad="$bad $dev"
    done < /proc/swaps
  else
    while read -r dev _ typ _; do
      [ "$typ" = swap ] || continue
      case "$dev" in /dev/mapper/*) name=${dev#/dev/mapper/} ;; *) bad="$bad $dev"; continue ;; esac
      line=$(awk -v n="$name" '$1==n' "$ROOT/etc/crypttab" 2>/dev/null)
      printf '%s\n' "$line" | awk '$3=="/dev/urandom" && $4 ~ /(^|,)swap(,|$)/ {f=1} END {exit f?0:1}' || bad="$bad $dev"
    done < <(grep -vE '^[[:space:]]*(#|$)' "$ROOT/etc/fstab" 2>/dev/null)
  fi
  if [ -n "$bad" ]; then fail kernel.swap "swap that is not random-key dm-crypt:$bad"; else ok kernel.swap "none, or random-key encrypted only"; fi
}

# =============================================================================== DNS
check_resolv() {
  need_file dns.resolv "$RESOLV" || return
  local ns
  ns=$(sed -e 's/#.*$//' "$RESOLV" | awk '$1=="nameserver" {print $2}' | sort -u | tr '\n' ' ')
  if [ "$ns" = "127.0.0.1 " ] || [ "$ns" = "::1 " ]; then ok dns.no_resolver "nameserver $ns(nothing listens)"; else fail dns.no_resolver "only a loopback nameserver allowed, found '$ns'"; fi
}

# =============================================================================== host-only
group_members() { awk -F: -v g="$1" '$1==g {print $4}' "$ROOT/etc/group" 2>/dev/null; }
check_host() {
  local v g
  if [ "$LIVE" -eq 1 ]; then
    if ! have tor; then fail host.tor_installed "tor binary not found"
    else
      if tor --list-modules 2>/dev/null | grep -qx 'pow: yes'; then ok host.tor_pow_module "pow: yes"; else fail host.tor_pow_module "tor built without PoW (R7 SI-D-01)"; fi
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
  if [ -r "$ROOT/etc/group" ]; then
    if grep -q '^_candor-torctl:' "$ROOT/etc/group"; then fail host.no_torctl_group "group _candor-torctl exists"; else ok host.no_torctl_group; fi
    for g in _tor-candor-intake systemd-journal adm; do
      v=$(group_members "$g")
      if [ -z "$v" ]; then ok "host.group_empty.$g"; else fail "host.group_empty.$g" "members: $v"; fi
    done
    v=$(awk -F: 'NR==FNR { if ($1=="_tor-candor-intake") g=$3; next } $4==g && $1!="_tor-candor-intake" {print $1}' "$ROOT/etc/group" "$ROOT/etc/passwd" 2>/dev/null | tr '\n' ' ')
    if [ -z "$v" ]; then ok host.tor_group_primary_only; else fail host.tor_group_primary_only "other users with tor's primary group: $v"; fi
  else fail host.groups "cannot read /etc/group"; fi
  # AppArmor profiles loaded in enforce mode (17 §5.2; AUD-RM2-DEP-08).
  local p
  for p in candor-tor-intake candor-web candor-sealer candor-intake-store candor-intake-pg; do
    if [ "$LIVE" -eq 1 ]; then
      if grep -qx "$p (enforce)" /sys/kernel/security/apparmor/profiles 2>/dev/null; then ok "host.apparmor.$p" enforce; else fail "host.apparmor.$p" "profile not loaded in enforce mode"; fi
    elif [ -f "$ROOT/etc/apparmor.d/$p" ]; then ok "host.apparmor.$p" "installed (offline root: load state not checked)"
    else fail "host.apparmor.$p" "profile file missing"; fi
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

want tor && check_torrc
want nft && check_nft
want pg && check_pg
want units && check_units
want journald && { check_journald journald.ns "$JNS" systemd/journald@candor-intake.conf 1; check_journald journald.host "$JHOST" systemd/journald.conf 0; }
want kernel && check_kernel
want dns && check_resolv
[ "$MODE" = host ] && want host && check_host

if [ "$FAILS" -gt 0 ]; then
  printf 'config-check: %d of %d checks FAILED, %d skipped (exit=30)\n' "$FAILS" "$CHECKS" "$SKIPS"
  exit 30
fi
printf 'config-check: all %d checks OK, %d skipped (exit=0)\n' "$((CHECKS - SKIPS))" "$SKIPS"
exit 0
