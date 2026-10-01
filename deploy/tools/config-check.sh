#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# config-check.sh - static configuration checker for the Candor intake host (Z-INTAKE).
#
# Implements the subset of `candorctl check` (18-DEPLOYMENT.md §14; rules from
# 32-OPERATIONS.md §5.2/§7, 16-TOR-I2P.md §7.4 lint, 17-INFRASTRUCTURE.md §4.3/§5,
# 09-DATABASE.md §10, 20-LOGGING-AUDITING.md LOG-005/007/008) that applies to the artefacts in
# deploy/intake/: torrc, nftables.conf, PostgreSQL config + pg_hba, systemd units, journald
# configuration and resolv.conf.
#
# Usage:
#   config-check.sh [--dir DIR]          check a deploy/intake-style tree (default: the tree
#                                        next to this script)
#   config-check.sh --host [--root DIR]  check the installed files on an intake host
#                                        (+ host-only checks: tor version/PoW module, nft -c)
#   -q   print only failures and the summary
#
# Output: "HOST RULE CLASS STATUS DETAIL" table (18 §14). Details never contain secrets or
# source-related data - only file names, option names and expected values.
# Exit codes (18 §14): 0 = all OK; 30 = baseline failure (any FAIL); 2 = usage / missing input.
# The checker fails closed: an unreadable or missing input file is a FAIL, not a skip.

set -u
LC_ALL=C
export LC_ALL

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODE=static
DIR="$SCRIPT_DIR/../intake"
ROOT=""
QUIET=0
FAILS=0
CHECKS=0

usage() {
  sed -n '4,20p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || usage; DIR=$2; shift 2 ;;
    --host) MODE=host; shift ;;
    --root) [ $# -ge 2 ] || usage; ROOT=$2; shift 2 ;;
    -q) QUIET=1; shift ;;
    -h|--help) usage ;;
    *) echo "config-check: unknown argument" >&2; usage ;;
  esac
done

if [ "$MODE" = host ]; then
  TORRC="$ROOT/etc/tor/instances/candor-intake/torrc"
  NFT="$ROOT/etc/nftables.conf"
  PGCONF="$ROOT/etc/candor/intake/postgresql/candor-intake.conf"
  PGHBA="$ROOT/etc/candor/intake/postgresql/pg_hba.conf"
  UNITDIR="$ROOT/etc/systemd/system"
  JNS="$ROOT/etc/systemd/journald@candor-intake.conf"
  JHOST="$ROOT/etc/systemd/journald.conf.d/50-candor-intake.conf"
  RESOLV="$ROOT/etc/resolv.conf"
else
  [ -d "$DIR" ] || { echo "config-check: no such directory: $DIR" >&2; exit 2; }
  TORRC="$DIR/torrc"
  NFT="$DIR/nftables.conf"
  PGCONF="$DIR/postgresql/candor-intake.conf"
  PGHBA="$DIR/postgresql/pg_hba.conf"
  UNITDIR="$DIR/systemd"
  JNS="$DIR/journald/journald@candor-intake.conf"
  JHOST="$DIR/journald/candor-intake-host.conf"
  RESOLV="$DIR/resolv.conf"
fi

report() { # rule class status detail
  CHECKS=$((CHECKS + 1))
  if [ "$3" = FAIL ]; then FAILS=$((FAILS + 1)); fi
  if [ "$QUIET" -eq 0 ] || [ "$3" != OK ]; then
    printf '%-7s %-40s %-9s %-6s %s\n' intake "$1" "$2" "$3" "$4"
  fi
}
ok()   { report "$1" baseline OK "${2:-}"; }
fail() { report "$1" baseline FAIL "${2:-}"; }

need_file() { # rule file
  if [ ! -f "$2" ] || [ ! -r "$2" ]; then
    fail "$1" "missing or unreadable: $(basename "$2")"
    return 1
  fi
  return 0
}

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

# =============================================================================== torrc
# torrc keys are case-insensitive; values compared exactly. Comments start at '#'.
tor_clean() { sed -e 's/#.*$//' "$TORRC" | trim | grep -v '^$'; }
tor_vals() { # key -> one value per occurrence
  tor_clean | awk -v k="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" '
    { key=tolower($1); if (key==k) { $1=""; sub(/^[ \t]+/, ""); print } }'
}

check_torrc() {
  need_file tor.file "$TORRC" || return

  if grep -qE '\\[[:space:]]*$' "$TORRC"; then fail tor.no_continuation "line continuation used"; else ok tor.no_continuation; fi
  if tor_clean | grep -qiE '^%include'; then fail tor.no_include "%include present"; else ok tor.no_include; fi

  # Exact single-valued settings (16 §7.1, §7.4; NET-005/006/007/008/009/010/011; LOG-005).
  local spec key want vals n
  for spec in \
    "RunAsDaemon 0" "Sandbox 1" "DisableDebuggerAttachment 1" "CompiledProofOfWorkHash 0" \
    "SocksPort 0" "TransPort 0" "NATDPort 0" "DNSPort 0" "HTTPTunnelPort 0" \
    "ORPort 0" "DirPort 0" "ExitRelay 0" "BridgeRelay 0" "PublishServerDescriptor 0" \
    "ControlPort 0" "CookieAuthentication 1" \
    "SafeLogging 1" "LogMessageDomains 0" "HiddenServiceStatistics 0" \
    "UseEntryGuards 1" "VanguardsLiteEnabled 1" \
    "ConnectionPadding 1" "ReducedConnectionPadding 0" "CircuitPadding 1" "ReducedCircuitPadding 0" \
    "HiddenServiceVersion 3" "HiddenServiceAllowUnknownPorts 0" "HiddenServiceDirGroupReadable 0" \
    "HiddenServiceMaxStreamsCloseCircuit 1" \
    "HiddenServiceSingleHopMode 0" "HiddenServiceNonAnonymousMode 0" \
    "HiddenServicePoWDefensesEnabled 1" "HiddenServiceEnableIntroDoSDefense 1"; do
    key=${spec% *}; want=${spec#* }
    vals=$(tor_vals "$key")
    n=$(printf '%s' "$vals" | grep -c '^' || true)
    if [ "$n" -ne 1 ]; then
      fail "tor.$key" "expected exactly one '$key $want', found $n"
    elif [ "$vals" != "$want" ]; then
      fail "tor.$key" "expected '$want', found '$vals'"
    else
      ok "tor.$key" "$want"
    fi
  done

  # Every *Port option other than HiddenServicePort must be 0: no clearnet or client listener
  # (NET-002, NET-011, NET-045; 16 §7.4) - catches MetricsPort, ExtORPort, etc.
  local bad
  bad=$(tor_clean | awk '{k=tolower($1)} k ~ /port$/ && k != "hiddenserviceport" && $2 != "0" {print $1}' | sort -u | tr '\n' ' ')
  if [ -n "$bad" ]; then fail tor.no_listeners "non-zero listener option(s): $bad"; else ok tor.no_listeners "all *Port = 0"; fi

  # Options that must never appear (proxies would route tor itself elsewhere; bridges/PTs and
  # password control auth are not part of the template; `User` would need root start).
  bad=$(tor_clean | awk '{k=tolower($1)}
    k ~ /^(hashedcontrolpassword|socks4proxy|socks5proxy|httpproxy|httpsproxy|tcpproxy|bridge|usebridges|clienttransportplugin|servertransportplugin|outboundbindaddress.*|user|datadirectorygroupreadable|cachedirectorygroupreadable|testingtornetwork|metricsport|metricsportpolicy|extorport|hiddenserviceonionbalanceinstance|disablenetwork|__.*)$/ {print $1}' | sort -u | tr '\n' ' ')
  if [ -n "$bad" ]; then fail tor.forbidden_options "present: $bad"; else ok tor.forbidden_options; fi

  # Logging: at least one Log line; every Log line warn/err to stderr or syslog, never a file
  # (NET-008, LOG-005, 32 tor.log_level; owner OPSEC bar: no log files on Z-INTAKE).
  local logs
  logs=$(tor_vals Log)
  if [ -z "$logs" ]; then
    fail tor.log "no Log line (tor would log at notice to stdout)"
  elif printf '%s\n' "$logs" | awk '
      { sev=$1; dst=$2; extra=$3 }
      !(sev=="warn" || sev=="err" || sev=="warn-err") { bad=1 }
      !(dst=="stderr" || dst=="syslog") { bad=1 }
      extra != "" { bad=1 }
      END { exit bad ? 0 : 1 }'; then
    fail tor.log "Log must be 'warn|err stderr|syslog' (no file, no notice/info/debug): $(printf '%s' "$logs" | tr '\n' ';')"
  else
    ok tor.log "$(printf '%s' "$logs" | tr '\n' ';')"
  fi

  # Exactly one onion service, exactly one HiddenServicePort, Unix-socket target (16 §7.4).
  n=$(tor_vals HiddenServiceDir | grep -c '^' || true)
  if [ "$n" -ne 1 ]; then fail tor.hs_dir "expected 1 HiddenServiceDir, found $n"; else ok tor.hs_dir; fi
  local hsp
  hsp=$(tor_vals HiddenServicePort)
  n=$(printf '%s' "$hsp" | grep -c '^' || true)
  if [ "$n" -ne 1 ]; then
    fail tor.hs_port "expected exactly 1 HiddenServicePort, found $n"
  elif ! printf '%s\n' "$hsp" | grep -qE '^(80|443)[[:space:]]+unix:/[^[:space:]]+$'; then
    fail tor.hs_port "HiddenServicePort must be '80|443 unix:/path' (no TCP target): $hsp"
  else
    ok tor.hs_port "$hsp"
  fi

  local cs
  cs=$(tor_vals ControlSocket)
  if [ -n "$cs" ] && ! printf '%s\n' "$cs" | grep -qE '^(unix:)?/[^[:space:]]+$'; then
    fail tor.control_socket "ControlSocket must be a Unix path: $cs"
  else
    ok tor.control_socket "${cs:-none}"
  fi

  local ecid
  ecid=$(tor_vals HiddenServiceExportCircuitID)
  case "$ecid" in ""|haproxy|none) ok tor.export_circuit_id "${ecid:-unset}" ;;
    *) fail tor.export_circuit_id "only haproxy (in-memory rate limiting, 16 §7.1) allowed: $ecid" ;; esac

  # Numeric DoS tunables: present, positive integers, within tor's limits.
  for spec in "HiddenServicePoWQueueRate 1 1000000" "HiddenServicePoWQueueBurst 1 10000000" \
              "HiddenServiceEnableIntroDoSRatePerSec 1 2147483647" \
              "HiddenServiceEnableIntroDoSBurstPerSec 1 2147483647" \
              "HiddenServiceMaxStreams 1 65535" "HiddenServiceNumIntroductionPoints 3 20"; do
    local okey lo hi vals_ok
    read -r okey lo hi <<EOF2
$spec
EOF2
    vals=$(tor_vals "$okey")
    # exactly one value, digits only (a newline from a duplicate line is not a digit)
    case "$vals" in ''|*[!0-9]*) vals_ok=0 ;; *) vals_ok=1 ;; esac
    if [ "$vals_ok" -eq 0 ] || [ "${#vals}" -gt 10 ] || [ "$vals" -lt "$lo" ] || [ "$vals" -gt "$hi" ]; then
      fail "tor.$okey" "expected one integer in [$lo, $hi], found '$vals'"
    else
      ok "tor.$okey" "$vals"
    fi
  done
}

# =============================================================================== nftables
nft_clean() { sed -e 's/#.*$//' "$NFT" | trim | tr -s ' \t' '  ' | grep -v '^$'; }

check_nft() {
  need_file nft.file "$NFT" || return

  if nft_clean | head -n 1 | grep -qx 'flush ruleset'; then ok nft.flush_ruleset; else fail nft.flush_ruleset "first statement must be 'flush ruleset'"; fi

  local tables
  tables=$(nft_clean | grep -E '^table ' || true)
  if [ "$tables" = "table inet candor_intake {" ]; then ok nft.single_table; else fail nft.single_table "expected only 'table inet candor_intake'"; fi

  # Exactly the three filter chains, each with policy drop; no other hook, no NAT/route chain.
  local ch
  for ch in input output forward; do
    if nft_clean | awk -v c="$ch" '
        $0 ~ "^chain "c" \\{" { inch=1; next }
        inch && /^type filter hook/ { if ($0 == "type filter hook "c" priority filter; policy drop;" || $0 == "type filter hook "c" priority 0; policy drop;") good=1; inch=0 }
        END { exit good ? 0 : 1 }'; then
      ok "nft.policy_drop.$ch"
    else
      fail "nft.policy_drop.$ch" "chain $ch must be 'type filter hook $ch ... policy drop;'"
    fi
  done
  local hooks
  hooks=$(nft_clean | grep -cE '(^| )hook ' || true)
  if [ "$hooks" -ne 3 ] || nft_clean | grep -qE 'policy accept|type (nat|route)|hook (prerouting|postrouting|ingress|egress)'; then
    fail nft.only_filter_chains "extra base chain, nat/route chain or accept policy present"
  else
    ok nft.only_filter_chains
  fi

  # LOG-007: no LOG/NFLOG targets (drops are only counted); no packet copying or queueing;
  # no jumps (an accept could hide in a jumped-to chain).
  if nft_clean | grep -qE '(^|[ ;])(log|queue|dup|fwd|jump|goto)( |;|$)'; then
    fail nft.no_log_queue_jump "log/queue/dup/fwd/jump/goto statement present"
  else
    ok nft.no_log_queue_jump
  fi

  # Every accept rule must be one of the template rules (17 §4.3.1 E1-E4, 16 §14.2 I1/I2).
  # Only the address-set *elements* are site-specific, so the accept lines are fixed.
  local allowed unexpected
  allowed=$(cat <<'EOF'
input|iif "lo" accept
input|ct state established,related accept
input|iifname "relay0" ip saddr @core_relay tcp dport 7443 ct state new accept
input|iifname "mgmt0" ip saddr @admin_jump tcp dport 22 ct state new accept
output|oif "lo" accept
output|ct state established,related accept
output|oifname "ext0" meta skuid "_tor-candor-intake" meta l4proto tcp ct state new accept
output|oifname "ext0" meta skuid "_tor-candor-update" meta l4proto tcp ct state new accept
output|oifname "mgmt0" meta skuid "candor-health" ip daddr @mon_hosts tcp dport 8514 ct state new accept
output|oifname "mgmt0" meta skuid "_chrony" ip daddr @mon_hosts udp dport 123 accept
output|oifname "mgmt0" meta skuid "_chrony" ip daddr @mon_hosts tcp dport 4460 ct state new accept
EOF
)
  unexpected=$(nft_clean | awk '
      /^chain [a-z_]+ \{/ { c=$2; next }
      /accept/ { print c "|" $0 }' | while IFS= read -r line; do
        printf '%s\n' "$allowed" | grep -qxF -- "$line" || printf '%s\n' "$line"
      done)
  if [ -n "$unexpected" ]; then
    fail nft.accept_rules "non-template accept rule(s): $(printf '%s' "$unexpected" | tr '\n' ';')"
  else
    ok nft.accept_rules "only E1-E4 / I1-I2 template accepts"
  fi
  # The two tor UIDs are the only ones allowed out of ext0 (17 §4.3; NET-031).
  if nft_clean | grep -E 'oifname "ext0"' | grep -E 'accept' | grep -vqE 'meta skuid "_tor-candor-(intake|update)" meta l4proto tcp'; then
    fail nft.ext0_tor_only "ext0 accept without a tor UID"
  else
    ok nft.ext0_tor_only
  fi
  # Cloud metadata and non-public destinations dropped (NET-041).
  if nft_clean | grep -qF 'ip daddr 169.254.0.0/16 counter name "output_dropped" drop' &&
     nft_clean | grep -qF 'ip6 daddr fd00:ec2::254 counter name "output_dropped" drop'; then
    ok nft.metadata_blocked
  else
    fail nft.metadata_blocked "169.254.0.0/16 and fd00:ec2::254 drops missing"
  fi
  # No RA processing (NET-041).
  if nft_clean | grep -qF 'icmpv6 type { nd-router-advert, nd-redirect } drop'; then ok nft.ra_blocked; else fail nft.ra_blocked "router advertisement drop missing"; fi

  # Syntax / semantic check by nft itself (needs the service users to exist and CAP_NET_ADMIN).
  if command -v nft >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    local err
    if err=$(nft -c -f "$NFT" 2>&1); then ok nft.syntax "nft -c"; else fail nft.syntax "nft -c failed: $(printf '%s' "$err" | head -n 2 | tr '\n' ' ')"; fi
  elif [ "$MODE" = host ]; then
    fail nft.syntax "nft not available or not root (host mode requires it)"
  else
    report nft.syntax baseline SKIP "nft unavailable or not root (static mode)"
  fi
}

# =============================================================================== PostgreSQL
pg_norm() { # postgresql.conf -> "key<TAB>value" (comments stripped, quotes removed, lowercase key)
  awk '
    {
      line=$0; out=""; q=0
      for (i=1; i<=length(line); i++) { ch=substr(line,i,1)
        if (ch=="\x27") q=!q
        if (ch=="#" && !q) break
        out=out ch }
      gsub(/^[ \t]+|[ \t]+$/, "", out)
      if (out=="") next
      eq=index(out, "=")
      if (eq==0) { split(out, a, /[ \t]+/); k=a[1]; v=substr(out, length(k)+1) }
      else { k=substr(out,1,eq-1); v=substr(out,eq+1) }
      gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (v ~ /^\x27.*\x27$/) v=substr(v,2,length(v)-2)
      print tolower(k) "\t" v
    }' "$PGCONF"
}
pg_bool() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in on|true|yes|1) echo on ;; off|false|no|0) echo off ;; *) echo "$1" ;; esac; }

check_pg() {
  need_file pg.file "$PGCONF" || return
  local norm dup
  norm=$(pg_norm)
  if printf '%s\n' "$norm" | cut -f1 | grep -qE '^(include|include_dir|include_if_exists)$'; then
    fail pg.no_include "include directive present (effective config must be this file)"
  else
    ok pg.no_include
  fi
  dup=$(printf '%s\n' "$norm" | cut -f1 | sort | uniq -d | tr '\n' ' ')
  if [ -n "$dup" ]; then fail pg.no_duplicates "duplicate keys: $dup"; else ok pg.no_duplicates; fi

  local spec key want got kind
  # kind b = boolean, s = string/enum/number compared case-insensitively
  for spec in \
    "listen_addresses s " "wal_level s minimal" "archive_mode b off" "max_wal_senders s 0" \
    "max_replication_slots s 0" "track_commit_timestamp b off" "fsync b on" "full_page_writes b on" \
    "ssl b off" "jit b off" "shared_preload_libraries s " "update_process_title b off" \
    "logging_collector b off" "log_destination s stderr" "log_statement s none" \
    "log_min_error_statement s panic" "log_error_verbosity s terse" \
    "log_connections b off" "log_disconnections b off" "log_duration b off" "log_hostname b off" \
    "log_min_duration_statement s -1" "log_min_duration_sample s -1" \
    "log_checkpoints b off" "log_autovacuum_min_duration s -1" "log_lock_waits b off" \
    "log_temp_files s -1" "log_replication_commands b off" \
    "log_parameter_max_length s 0" "log_parameter_max_length_on_error s 0" \
    "debug_print_parse b off" "debug_print_rewritten b off" "debug_print_plan b off" \
    "log_statement_stats b off" "log_parser_stats b off" "log_planner_stats b off" "log_executor_stats b off" \
    "unix_socket_directories s /run/candor/intake-pg"; do
    key=$(printf '%s' "$spec" | cut -d' ' -f1); kind=$(printf '%s' "$spec" | cut -d' ' -f2)
    want=$(printf '%s' "$spec" | cut -d' ' -f3-)
    if ! printf '%s\n' "$norm" | cut -f1 | grep -qx "$key"; then
      fail "pg.$key" "not set explicitly (expected '$want')"; continue
    fi
    got=$(printf '%s\n' "$norm" | awk -F'\t' -v k="$key" '$1==k {print $2}')
    if [ "$kind" = b ]; then got=$(pg_bool "$got"); else got=$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]'); fi
    if [ "$got" = "$want" ]; then ok "pg.$key" "'$want'"; else fail "pg.$key" "expected '$want', found '$got'"; fi
  done

  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="log_min_messages" {print tolower($2)}')
  case "$got" in warning|error|log|fatal|panic) ok pg.log_min_messages "$got" ;;
    *) fail pg.log_min_messages "must be warning or higher, found '$got'" ;; esac

  # log_line_prefix: no client/session/time identifiers (DB-021; LOG-004). Only %e / %% allowed.
  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="log_line_prefix" {print $2}')
  if ! printf '%s\n' "$norm" | cut -f1 | grep -qx log_line_prefix; then
    fail pg.log_line_prefix "not set (PG default contains %m and %p)"
  elif printf '%s' "$got" | sed 's/%%//g; s/%e//g' | grep -q '%'; then
    fail pg.log_line_prefix "only %e allowed (no %h %r %u %d %a %p %m %t ...): '$got'"
  else
    ok pg.log_line_prefix "'$got'"
  fi

  got=$(printf '%s\n' "$norm" | awk -F'\t' '$1=="unix_socket_permissions" {print $2}')
  case "$got" in 0770|0750|0700|770|750|700) ok pg.unix_socket_permissions "$got" ;;
    *) fail pg.unix_socket_permissions "no world access allowed, found '$got'" ;; esac

  # pg_hba: Unix-socket peer only, reject last (09 §10, DB-022, R7 SI-E-01).
  if need_file pg.hba_file "$PGHBA"; then
    local hba last
    hba=$(sed -e 's/#.*$//' "$PGHBA" | trim | tr -s ' \t' '  ' | grep -v '^$')
    if printf '%s\n' "$hba" | awk '$1 != "local" {bad=1} END {exit bad?0:1}'; then
      fail pg.hba_local_only "non-local (TCP) line present"
    else
      ok pg.hba_local_only
    fi
    if printf '%s\n' "$hba" | awk '{m=$4} m!="peer" && m!="reject" {bad=1} END {exit bad?0:1}'; then
      fail pg.hba_methods "only peer/reject allowed"
    else
      ok pg.hba_methods
    fi
    last=$(printf '%s\n' "$hba" | tail -n 1)
    if [ "$last" = "local all all reject" ]; then ok pg.hba_reject_last; else fail pg.hba_reject_last "last line must be 'local all all reject'"; fi
  fi
}

# =============================================================================== systemd units
unit_vals() { # file key -> values of every occurrence (systemd: '#'/';' comments at line start only)
  grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" | sed -E "s/^[[:space:]]*$2[[:space:]]*=//" | trim
}
unit_expect() { # rule-prefix file key value  (all occurrences must equal value, at least one)
  local vals n
  vals=$(unit_vals "$2" "$3")
  n=$(printf '%s' "$vals" | grep -c '^' || true)
  if [ "$n" -eq 0 ] && [ -n "$4" ]; then
    fail "$1.$3" "missing ($3=$4)"
  elif [ "$n" -eq 0 ] && [ -z "$4" ] && ! grep -qE "^[[:space:]]*$3[[:space:]]*=" "$2"; then
    fail "$1.$3" "missing ($3= empty)"
  elif printf '%s\n' "$vals" | grep -qvxF -- "$4"; then
    fail "$1.$3" "expected '$4', found '$(printf '%s' "$vals" | tr '\n' ' ')'"
  else
    ok "$1.$3" "${4:-<empty>}"
  fi
}

COMMON_KEYS="NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes PrivateDevices=yes
PrivateIPC=yes PrivateMounts=yes ProtectKernelTunables=yes ProtectKernelModules=yes ProtectKernelLogs=yes
ProtectControlGroups=yes ProtectClock=yes ProtectHostname=yes ProtectProc=invisible RestrictNamespaces=yes
RestrictRealtime=yes RestrictSUIDSGID=yes LockPersonality=yes MemoryDenyWriteExecute=yes RemoveIPC=yes
UMask=0077 CapabilityBoundingSet= AmbientCapabilities= KeyringMode=private DevicePolicy=closed
SystemCallArchitectures=native LimitCORE=0 NoExecPaths=/ ExecPaths=/usr SocketBindDeny=any
StandardOutput=null StandardError=journal LogNamespace=candor-intake LogLevelMax=warning"

check_service() { # unit-file kind(tor|candor|pg) user
  local f="$UNITDIR/$1" p="unit.${1%.service}" kv k v
  need_file "$p.file" "$f" || return
  for kv in $COMMON_KEYS; do
    k=${kv%%=*}; v=${kv#*=}
    unit_expect "$p" "$f" "$k" "$v"
  done
  unit_expect "$p" "$f" User "$3"
  if ! unit_vals "$f" Requires | grep -qw nftables.service; then fail "$p.requires_nftables" "Requires= must include nftables.service"; else ok "$p.requires_nftables"; fi

  # Secrets never via environment; credentials only TPM-sealed (ADR-028; R7 SI-B-01).
  if grep -qE '^[[:space:]]*(Environment|EnvironmentFile|PassEnvironment|LoadCredential|SetCredential|SetCredentialEncrypted|ImportCredential)[[:space:]]*=' "$f"; then
    fail "$p.no_env_secrets" "Environment*/plain credential directive present (use LoadCredentialEncrypted=)"
  else
    ok "$p.no_env_secrets"
  fi
  # No privileged command prefixes ('+', '!', '!!') that bypass the sandbox.
  if grep -qE '^[[:space:]]*Exec[A-Za-z]*[[:space:]]*=[[:space:]]*[-@:]*[+!]' "$f"; then
    fail "$p.no_privileged_exec" "Exec line with + or ! prefix"
  else
    ok "$p.no_privileged_exec"
  fi

  # Syscall filter: allow-list mode based on @system-service, with the 07 §4.2 deny groups;
  # only a fixed set of individual syscalls may be re-added.
  local scf first denyl readd
  scf=$(unit_vals "$f" SystemCallFilter)
  first=$(printf '%s\n' "$scf" | head -n 1)
  denyl=$(printf '%s\n' "$scf" | grep '^~' | tr '\n' ' ')
  readd=$(printf '%s\n' "$scf" | tail -n +2 | grep -v '^~' | tr ' ' '\n' | grep -v '^$' | grep -vxE 'seccomp|setrlimit|fchown|fchownat|chown' | tr '\n' ' ')
  if [ "$first" != "@system-service" ]; then
    fail "$p.syscall_filter" "first SystemCallFilter= must be @system-service"
  elif [ -n "$readd" ]; then
    fail "$p.syscall_filter" "unexpected re-allowed syscalls: $readd"
  else
    local g miss=""
    for g in @privileged @mount @debug @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock @setuid @keyring @resources; do
      printf '%s' "$denyl" | grep -qw -- "$g" || miss="$miss $g"
    done
    if [ -n "$miss" ]; then fail "$p.syscall_filter" "deny list lacks:$miss"; else ok "$p.syscall_filter"; fi
  fi

  case "$2" in
    tor)
      local raf
      raf=$(unit_vals "$f" RestrictAddressFamilies | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
      if [ "$raf" = "AF_INET AF_UNIX " ] || [ "$raf" = "AF_INET AF_INET6 AF_UNIX " ]; then
        ok "$p.RestrictAddressFamilies" "$raf"
      else
        fail "$p.RestrictAddressFamilies" "tor may use only AF_UNIX AF_INET [AF_INET6], found '$raf'"
      fi
      if unit_vals "$f" IPAddressDeny | grep -qE '10\.0\.0\.0/8' && unit_vals "$f" IPAddressDeny | grep -qE '169\.254\.0\.0/16' &&
         ! grep -qE '^[[:space:]]*IPAddressAllow[[:space:]]*=' "$f"; then
        ok "$p.IPAddressDeny" "non-public ranges denied"
      else
        fail "$p.IPAddressDeny" "tor unit must deny non-public ranges and have no IPAddressAllow"
      fi
      if unit_vals "$f" ExecStart | grep -qE -- '--defaults-torrc /dev/null -f /etc/tor/instances/candor-intake/torrc$'; then
        ok "$p.exec" "defaults-torrc /dev/null"
      else
        fail "$p.exec" "ExecStart must be tor --defaults-torrc /dev/null -f /etc/tor/instances/candor-intake/torrc"
      fi
      ;;
    candor|pg)
      unit_expect "$p" "$f" PrivateNetwork yes
      unit_expect "$p" "$f" RestrictAddressFamilies AF_UNIX
      unit_expect "$p" "$f" IPAddressDeny any
      unit_expect "$p" "$f" ProcSubset pid
      unit_expect "$p" "$f" MemorySwapMax 0
      if grep -qE '^[[:space:]]*IPAddressAllow[[:space:]]*=' "$f"; then fail "$p.no_ip_allow" "IPAddressAllow present"; else ok "$p.no_ip_allow"; fi
      ;;
  esac
  if [ "$2" = candor ]; then
    local aa
    aa=$(unit_vals "$f" AppArmorProfile)
    case "$aa" in candor-*) ok "$p.apparmor" "$aa (fail-closed, no '-' prefix)" ;;
      *) fail "$p.apparmor" "AppArmorProfile=candor-* without '-' prefix required, found '$aa'" ;; esac
  fi
}

check_units() {
  if [ ! -d "$UNITDIR" ]; then fail unit.dir "missing unit directory"; return; fi
  check_service tor@candor-intake.service tor _tor-candor-intake
  check_service candor-intake-web.service candor candor-web
  check_service candor-sealer.service candor candor-sealer
  check_service candor-intake-store.service candor candor-istore
  check_service candor-intake-pg.service pg postgres

  # Sealer: no writable path at all (07 §4.2), mlock budget, no capabilities.
  local s="$UNITDIR/candor-sealer.service"
  if [ -f "$s" ]; then
    if grep -qE '^[[:space:]]*(ReadWritePaths|BindPaths|StateDirectory|CacheDirectory|LogsDirectory|RuntimeDirectory)[[:space:]]*=' "$s"; then
      fail unit.candor-sealer.no_writable_paths "writable path directive present"
    else
      ok unit.candor-sealer.no_writable_paths
    fi
    unit_expect unit.candor-sealer "$s" LimitMEMLOCK 2G
  fi

  # Sockets: Unix sockets 0660 owned per 07 §4.1; web socket path = torrc onion target.
  local sk mode
  for sk in candor-intake-web.socket candor-sealer.socket candor-intake-store.socket; do
    if need_file "unit.${sk%.socket}.file" "$UNITDIR/$sk"; then
      mode=$(unit_vals "$UNITDIR/$sk" SocketMode)
      if [ "$mode" = 0660 ] || [ "$mode" = 0600 ]; then ok "unit.$sk.mode" "$mode"; else fail "unit.$sk.mode" "SocketMode must be 0660/0600, found '$mode'"; fi
      if grep -qE '^[[:space:]]*Listen(Stream|SequentialPacket|Datagram)[[:space:]]*=[[:space:]]*[^/[:space:]]' "$UNITDIR/$sk"; then
        fail "unit.$sk.unix_only" "non-path listener in a Unix socket unit"
      else
        ok "unit.$sk.unix_only"
      fi
    fi
  done
  if [ -f "$UNITDIR/candor-intake-web.socket" ] && [ -f "$TORRC" ]; then
    local target listen
    target=$(tor_vals HiddenServicePort | awk '{print $2}' | sed 's/^unix://')
    listen=$(unit_vals "$UNITDIR/candor-intake-web.socket" ListenStream)
    if [ -n "$target" ] && [ "$target" = "$listen" ]; then ok unit.onion_target_match "$listen"; else fail unit.onion_target_match "torrc target '$target' != web socket '$listen'"; fi
  fi
  local r="$UNITDIR/candor-intake-store-relay.socket"
  if need_file unit.candor-intake-store-relay.file "$r"; then
    if [ "$(unit_vals "$r" ListenStream)" = "0.0.0.0:7443" ] && [ "$(unit_vals "$r" BindToDevice)" = relay0 ] &&
       [ "$(unit_vals "$r" IPAddressDeny)" = any ]; then
      ok unit.relay_socket "0.0.0.0:7443 on relay0, IPAddressDeny=any"
    else
      fail unit.relay_socket "relay socket must be ListenStream=0.0.0.0:7443, BindToDevice=relay0, IPAddressDeny=any"
    fi
  fi
  local m="$UNITDIR/run-candor-staging.mount"
  if need_file unit.staging_mount.file "$m"; then
    local o miss="" w
    o=$(unit_vals "$m" Options | tail -n 1)
    for w in noswap nosuid nodev noexec mode=0700 X-mount.mode=0700 X-mount.owner=candor-istore; do
      printf ',%s,' "$o" | grep -qF ",$w," || miss="$miss $w"
    done
    if [ "$(unit_vals "$m" Type)" = tmpfs ] && [ -z "$miss" ]; then ok unit.staging_mount "tmpfs RAM-only 0700"; else fail unit.staging_mount "tmpfs with$miss required"; fi
  fi
}

# =============================================================================== journald / DNS
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

check_journald_file() { # rule file
  need_file "$1.file" "$2" || return
  unit_expect "$1" "$2" Storage volatile
  unit_expect "$1" "$2" ForwardToSyslog no
  unit_expect "$1" "$2" ForwardToKMsg no
  unit_expect "$1" "$2" ForwardToConsole no
  unit_expect "$1" "$2" ForwardToWall no
  local r s
  r=$(unit_vals "$2" MaxRetentionSec | tail -n 1)
  s=$(to_seconds "$r")
  if [ -n "$s" ] && [ "$s" -gt 0 ] && [ "$s" -le 86400 ]; then ok "$1.MaxRetentionSec" "$r"; else fail "$1.MaxRetentionSec" "must be set and <= 24h, found '$r'"; fi
}

check_resolv() {
  need_file dns.resolv "$RESOLV" || return
  local ns
  ns=$(sed -e 's/#.*$//' "$RESOLV" | awk '$1=="nameserver" {print $2}' | sort -u | tr '\n' ' ')
  if [ "$ns" = "127.0.0.1 " ] || [ "$ns" = "::1 " ]; then ok dns.no_resolver "nameserver $ns(nothing listens)"; else fail dns.no_resolver "only a loopback nameserver allowed, found '$ns'"; fi
}

# =============================================================================== host-only
check_host() {
  local v
  if ! command -v tor >/dev/null 2>&1; then fail host.tor_installed "tor binary not found"; return; fi
  if tor --list-modules 2>/dev/null | grep -qx 'pow: yes'; then ok host.tor_pow_module "pow: yes"; else fail host.tor_pow_module "tor built without PoW (R7 SI-D-01)"; fi
  v=$(tor --version 2>/dev/null | head -n 1 | sed -n 's/^Tor version \([0-9][0-9.]*\).*/\1/p')
  if [ -n "$v" ] && [ "$(printf '%s\n0.4.8\n' "$v" | sort -V | head -n 1)" = 0.4.8 ]; then
    ok host.tor_version_floor ">= 0.4.8"
  else
    fail host.tor_version_floor "tor >= 0.4.8 required (NET-003)"
  fi
  if [ -e "$ROOT/run/systemd/resolve/stub-resolv.conf" ] && [ -S "$ROOT/run/systemd/resolve/io.systemd.Resolve" ]; then
    fail host.no_resolved "systemd-resolved appears to be running (17 §4.5: masked on H-INTAKE)"
  else
    ok host.no_resolved
  fi
  if [ -r "$ROOT/proc/swaps" ] && [ "$(grep -c '^' "$ROOT/proc/swaps")" -gt 1 ]; then
    fail host.no_swap "swap active (17 §5.1)"
  else
    ok host.no_swap
  fi
}

check_torrc
check_nft
check_pg
check_units
check_journald_file journald.ns "$JNS"
check_journald_file journald.host "$JHOST"
check_resolv
[ "$MODE" = host ] && check_host

if [ "$FAILS" -gt 0 ]; then
  printf 'config-check: %d of %d checks FAILED (exit=30)\n' "$FAILS" "$CHECKS"
  exit 30
fi
printf 'config-check: all %d checks OK (exit=0)\n' "$CHECKS"
exit 0
