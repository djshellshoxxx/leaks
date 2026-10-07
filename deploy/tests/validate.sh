#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# validate.sh - CI / developer validation of the Z-INTAKE deployment artefacts (deploy/intake).
#
#   1. shellcheck + bash -n on deploy/tools and deploy/tests
#   2. config-check.sh on the shipped tree (must pass) and on deliberately broken copies
#      (every mutation must fail with exit 30): static tree mutations, plus --host --root
#      mutations on a synthetic installed host (drop-ins in system.control, /usr/lib, prefix
#      and template directories, transient units, sysctl.d/journald.conf.d overrides, ...)
#   3. systemd-analyze verify (--man=no) on every unit; only the documented expected messages
#      (missing Candor binaries at their future install paths) are tolerated
#   4. systemd-analyze security --offline --threshold per unit (R7 SI-B-01): achieved scores
#      are printed; budgets: Candor services and PostgreSQL <= 0.5, tor <= 1.5 (17 §5.3)
#   5. nft -c -f nftables.conf          (needs root and the users from sysusers.d)
#   6. apparmor_parser -Q -K profiles   (parse/compile only, nothing loaded; exit status checked)
#   7. tor --verify-config on the torrc (as _tor-candor-intake when that user exists)
#   8. check-placement.sh positive and negative cases on a synthetic root (needs root + users)
#   9. PostgreSQL: start a throw-away cluster with candor-intake.conf, check effective settings
#      and peer-only access, and config-check's `postgres -C` path (postgresql.auto.conf) -
#      only when CANDOR_TEST_PG is set (needs root, the users, initdb)
# Tools that are absent are reported as SKIP; any executed check that fails makes the script
# exit 1. Nothing is installed or changed on the host; temporary files live in a mktemp dir.

set -u
LC_ALL=C
export LC_ALL
HERE=$(cd "$(dirname "$0")" && pwd)
DEPLOY=$(cd "$HERE/.." && pwd)
INTAKE="$DEPLOY/intake"
TOOLS="$DEPLOY/tools"
T=$(mktemp -d /var/tmp/candor-validate.XXXXXX) || exit 1
chmod 0755 "$T"
trap 'rm -rf "$T"' EXIT INT TERM
# AUD-RM2-DEP-27: a per-run work base for config-check, so concurrent validator runs never
# share (or assert on) /run/candor-config-check.
# DEP-30: every ancestor must be root-owned and not group/world-writable or sticky, so the base
# lives under /run (not under $T in the sticky /var/tmp).
CC_WB=()
WB=""
if [ "$(id -u)" -eq 0 ]; then
  WB=$(mktemp -d /run/candor-validate-wb.XXXXXX) && chmod 0700 "$WB" && CC_WB=(--work-base "$WB")
  trap 'rm -rf "$T" ${WB:+"$WB"}' EXIT INT TERM
fi
cc() { "$TOOLS/config-check.sh" "${CC_WB[@]}" "$@"; }
FAIL=0
pass() { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; FAIL=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }
users_exist() { local u; for u in _tor-candor-intake _tor-candor-update candor-web candor-sealer candor-istore candor-imaint candor-health _chrony postgres; do getent passwd "$u" >/dev/null || return 1; done; }

# ------------------------------------------------------------------------- 1. shell lint
if have shellcheck; then
  if shellcheck -x "$TOOLS"/*.sh "$HERE"/*.sh; then pass "shellcheck"; else bad "shellcheck"; fi
else skip "shellcheck not installed"; fi
for s in "$TOOLS"/*.sh "$HERE"/*.sh; do bash -n "$s" || bad "bash -n $s"; done

# ------------------------------------------------------------------------- 2. config-check
# The compiled reader (ADR-055(3)); its digest is pinned in config-check.manifest.
if have cargo; then
  if "$TOOLS/build-safe-read.sh" >/dev/null 2>"$T/build.err"; then pass "candor-safe-read reproducible build"; else bad "build-safe-read.sh: $(head -c 300 "$T/build.err")"; fi
elif [ -x "$TOOLS/candor-safe-read" ]; then skip "cargo missing: using the existing candor-safe-read"
else bad "cargo missing and no candor-safe-read binary"; fi
if [ -x "$TOOLS/candor-safe-read" ] && [ "$(sha256sum < "$TOOLS/candor-safe-read" | cut -c1-64)" = "$(awk '$2=="candor-safe-read" {print $1}' "$TOOLS/config-check.manifest")" ]; then
  pass "candor-safe-read digest equals the manifest pin"
else bad "candor-safe-read digest differs from config-check.manifest (re-pin after a reviewed change)"; fi
for prof in "" ce-single ce-hardened; do
  if cc -q --dir "$INTAKE" ${prof:+--profile "$prof"} >/dev/null; then pass "config-check: shipped files ${prof:-(base)}"
  else bad "config-check: shipped files must pass ${prof:-(base)}"; fi
done

# mutate <name> <relative file> <sed-expression | +append-text | - (delete)> [config-check args...]
# Each mutation runs config-check on its own copy of the tree, in parallel (bounded).
# hmutate does the same on a copy of the synthetic installed host root ($HR, --host --root).
MUTN=0
JOBS=$( (nproc 2>/dev/null || echo 2) | head -n 1)
run_case() { # dir name base rel expr args...
  local d=$1 name=$2 src=$3 rel=$4 expr=$5
  shift 5
  cp -a "$src" "$d"
  printf '%s\n' "$name" > "$d.name"
  case "$expr" in
    -)  if [ -e "$d/$rel" ] || [ -L "$d/$rel" ]; then rm -f "$d/$rel"; else echo nochange > "$d.rc"; return; fi ;;
    +*) mkdir -p "$(dirname "$d/$rel")"; printf '%s\n' "${expr#+}" >> "$d/$rel" ;;
    @*) # replace by a symlink; the original moves out of the tree (next to the copy)
        mkdir -p "$(dirname "$d/$rel")"
        if [ -e "$d/$rel" ] || [ -L "$d/$rel" ]; then mv -- "$d/$rel" "$d.orig"; fi
        ln -s "${expr#@}" "$d/$rel" ;;
    *)  sed -i -e "$expr" "$d/$rel" ;;
  esac
  case "$expr" in -|@*) ;; *) if [ -f "$src/$rel" ] && cmp -s "$src/$rel" "$d/$rel"; then echo nochange > "$d.rc"; return; fi ;; esac
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  ( cc -q "$@" > "$d.out" 2>&1; echo $? > "$d.rc" ) &
}
mutate() { local name=$1 rel=$2 expr=$3; shift 3; MUTN=$((MUTN + 1)); run_case "$T/mut.$MUTN" "$name" "$INTAKE" "$rel" "$expr" --dir "$T/mut.$MUTN" "$@"; }
hmutate() { local name=$1 rel=$2 expr=$3; MUTN=$((MUTN + 1)); run_case "$T/mut.$MUTN" "host: $name" "$HR" "$rel" "$expr" --host --root "$T/mut.$MUTN" --only "$HONLY"; }
mutate_results() {
  wait
  local i rc name
  for i in $(seq 1 "$MUTN"); do
    name=$(cat "$T/mut.$i.name"); rc=$(cat "$T/mut.$i.rc" 2>/dev/null || echo none)
    if [ "$rc" = nochange ]; then bad "mutation '$name' did not change its file (test bug)"
    elif grep -q CANDORLEAKMARKER "$T/mut.$i.out"; then bad "config-check printed content of a file it must not read: $name"
    elif [ "$rc" = 30 ]; then pass "config-check rejects: $name ($(grep -c ' FAIL ' "$T/mut.$i.out") rule(s))"
    else bad "config-check accepted broken copy: $name (exit $rc)"; fi
  done
}
# An nft file for the include bypass (AUD-RM2-DEP-02): would open egress for every UID.
printf 'insert rule inet candor_intake output accept\n' > "$T/extra.nft"
# Files a symlinked input points at (AUD-RM2-DEP-17): their content must never be read or
# printed (mutate_results fails on the marker in any report).
printf 'CANDORLEAKMARKER 1\n_apt:CANDORLEAKMARKER:20501:0:99999:7:::\n' > "$T/secret"
printf '[Service]\nCANDORLEAKMARKER=1\n' > "$T/secret.conf"
mkdir -p "$T/tordir/candor-intake"; cp "$INTAKE/torrc" "$T/tordir/candor-intake/torrc"
FP=0123456789ABCDEF0123456789ABCDEF01234567
# torrc (16 §7.1/§7.4, NET-002/005/006/008/009/011, LOG-005)
mutate "tor log to file"               torrc 's|^Log warn stderr$|Log notice file /var/log/tor/notices.log|'
mutate "tor extra log file"            torrc '+Log warn file /var/log/tor/warn.log'
mutate "tor log level debug"           torrc 's|^Log warn stderr$|Log debug stderr|'
mutate "SafeLogging 0"                 torrc 's|^SafeLogging 1$|SafeLogging 0|'
mutate "SafeLogging duplicated"        torrc '+SafeLogging 0'
mutate "SocksPort clearnet listener"   torrc 's|^SocksPort 0$|SocksPort 9050|'
mutate "ControlPort TCP"               torrc 's|^ControlPort 0$|ControlPort 9051|'
mutate "MetricsPort"                   torrc '+MetricsPort 127.0.0.1:9035'
mutate "ORPort relay"                  torrc 's|^ORPort 0$|ORPort 9001|'
mutate "second HiddenServicePort"      torrc '+HiddenServicePort 22 unix:/run/sshd.sock'
mutate "TCP onion target"              torrc 's|^HiddenServicePort 80 unix:.*$|HiddenServicePort 80 127.0.0.1:8080|'
mutate "PoW disabled"                  torrc 's|^HiddenServicePoWDefensesEnabled 1$|HiddenServicePoWDefensesEnabled 0|'
mutate "intro DoS defence off"         torrc 's|^HiddenServiceEnableIntroDoSDefense 1$|HiddenServiceEnableIntroDoSDefense 0|'
mutate "single hop mode"               torrc 's|^HiddenServiceSingleHopMode 0$|HiddenServiceSingleHopMode 1|'
mutate "non-anonymous mode"            torrc 's|^HiddenServiceNonAnonymousMode 0$|HiddenServiceNonAnonymousMode 1|'
mutate "Sandbox removed"               torrc '/^Sandbox 1$/d'
mutate "vanguards-lite off"            torrc 's|^VanguardsLiteEnabled 1$|VanguardsLiteEnabled 0|'
mutate "PoW JIT (breaks MDWE)"         torrc 's|^CompiledProofOfWorkHash 0$|CompiledProofOfWorkHash 1|'
mutate "%include"                      torrc '+%include /etc/tor/torrc.d/'
mutate "Socks5Proxy"                   torrc '+Socks5Proxy 192.0.2.1:1080'
mutate "PoW queue rate not a number"   torrc 's|^HiddenServicePoWQueueRate 250$|HiddenServicePoWQueueRate fast|'
mutate "MaxStreams duplicated"         torrc '+HiddenServiceMaxStreams 64'
mutate "lower-case key override"       torrc '+safelogging 0'
# nftables (17 §4.3, NET-031/041, LOG-007)
mutate "nft output policy accept"      nftables.conf 's|type filter hook output priority filter; policy drop;|type filter hook output priority filter; policy accept;|'
mutate "nft LOG target"                nftables.conf 's|counter name "output_dropped" drop$|log prefix "deny " counter name "output_dropped" drop|'
mutate "nft web egress"                nftables.conf 's|^    # E5 (Tang|    oifname "ext0" meta skuid "candor-web" accept\n    # E5 (Tang|'
mutate "nft clearnet DNS"              nftables.conf 's|^    # E5 (Tang|    udp dport 53 accept\n    # E5 (Tang|'
mutate "nft inbound HTTP"              nftables.conf 's|^    counter name "input_dropped" drop$|    tcp dport 80 accept\n    counter name "input_dropped" drop|'
mutate "nft no flush ruleset"          nftables.conf '/^flush ruleset$/d'
mutate "nft jump"                      nftables.conf 's|^    oif "lo" accept$|    oif "lo" accept\n    jump extra|'
mutate "nft tor UDP"                   nftables.conf 's|meta skuid "_tor-candor-intake" meta l4proto tcp ct state new accept|meta skuid "_tor-candor-intake" ct state new accept|'
mutate "nft metadata not blocked"      nftables.conf '/169.254.0.0\/16 counter/d'
mutate "nft extra nat table"           nftables.conf '+table ip nat { chain post { type nat hook postrouting priority 100; masquerade; } }'
# PostgreSQL (09 §10, ADR-046(1), DB-021/022, LOG-008)
mutate "pg wal_level replica"          postgresql/candor-intake.conf 's|^wal_level = minimal|wal_level = replica|'
mutate "pg archive_mode on"            postgresql/candor-intake.conf 's|^archive_mode = off|archive_mode = on|'
mutate "pg commit timestamps"          postgresql/candor-intake.conf 's|^track_commit_timestamp = off|track_commit_timestamp = on|'
mutate "pg log_connections"            postgresql/candor-intake.conf 's|^log_connections = off|log_connections = on|'
mutate "pg log_statement all"          postgresql/candor-intake.conf "s|^log_statement = 'none'|log_statement = 'all'|"
mutate "pg prefix with host/user"      postgresql/candor-intake.conf "s|^log_line_prefix = '%e '|log_line_prefix = '%m [%p] %u@%d %h '|"
mutate "pg TCP listener"               postgresql/candor-intake.conf "s|^listen_addresses = ''|listen_addresses = '*'|"
mutate "pg include"                    postgresql/candor-intake.conf "+include_if_exists = '/etc/candor/local.conf'"
mutate "pg duplicate key"              postgresql/candor-intake.conf "+log_min_duration_statement = 0"
mutate "pg log_checkpoints"            postgresql/candor-intake.conf 's|^log_checkpoints = off|log_checkpoints = on|'
mutate "pg log_min_messages error"     postgresql/candor-intake.conf 's|^log_min_messages = panic|log_min_messages = error|'
mutate "pg stderr to journal"          systemd/candor-intake-pg.service 's|^StandardError=null$|StandardError=journal|'
mutate "pg logging_collector"          postgresql/candor-intake.conf 's|^logging_collector = off|logging_collector = on|'
mutate "pg world socket"               postgresql/candor-intake.conf 's|^unix_socket_permissions = 0770|unix_socket_permissions = 0777|'
mutate "pg_hba host line"              postgresql/pg_hba.conf 's|^local   all               all             reject|host all all 0.0.0.0/0 scram-sha-256\nlocal   all               all             reject|'
mutate "pg_hba trust"                  postgresql/pg_hba.conf 's|candor_istore   peer map=candor|candor_istore   trust|'
# systemd units (07 §4.2, 16 §7.3, 17 §5.3, R7 SI-B-01)
mutate "web PrivateNetwork removed"    systemd/candor-intake-web.service '/^PrivateNetwork=yes$/d'
mutate "web ProtectSystem=full"        systemd/candor-intake-web.service 's|^ProtectSystem=strict$|ProtectSystem=full|'
mutate "sealer secret in Environment"  systemd/candor-sealer.service 's|^User=candor-sealer$|User=candor-sealer\nEnvironment=SALT=abc|'
mutate "istore plain LoadCredential"   systemd/candor-intake-store.service 's|^LoadCredentialEncrypted=routing_key:|LoadCredential=routing_key:|'
mutate "sealer AF_INET"                systemd/candor-sealer.service 's|^RestrictAddressFamilies=AF_UNIX$|RestrictAddressFamilies=AF_UNIX AF_INET|'
mutate "sealer writable path"          systemd/candor-sealer.service 's|^User=candor-sealer$|User=candor-sealer\nReadWritePaths=/var/lib/candor|'
mutate "tor AF_NETLINK"                systemd/tor@candor-intake.service 's|^RestrictAddressFamilies=AF_UNIX AF_INET$|RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK|'
mutate "tor MDWE off"                  systemd/tor@candor-intake.service 's|^MemoryDenyWriteExecute=yes$|MemoryDenyWriteExecute=no|'
mutate "tor runs as root"              systemd/tor@candor-intake.service 's|^User=_tor-candor-intake$|User=root|'
mutate "tor distro defaults"           systemd/tor@candor-intake.service 's|^ExecStart=/usr/bin/tor --defaults-torrc /dev/null |ExecStart=/usr/bin/tor |'
mutate "pg core dumps"                 systemd/candor-intake-pg.service 's|^LimitCORE=0$|LimitCORE=infinity|'
mutate "privileged ExecStartPre"       systemd/candor-intake-web.service 's|^ExecStart=|ExecStartPre=+/bin/true\nExecStart=|'
mutate "AppArmor soft-fail"            systemd/candor-intake-web.service 's|^AppArmorProfile=candor-web$|AppArmorProfile=-candor-web|'
mutate "stdout to journal"             systemd/candor-sealer.service 's|^StandardOutput=null$|StandardOutput=journal|'
mutate "no log namespace"              systemd/candor-intake-store.service '/^LogNamespace=candor-intake$/d'
# (retargeted from the sealer to web: the sealer's syscall lines are owned by AUD-RM2-SEA-06)
mutate "syscall re-allow ptrace"       systemd/candor-intake-web.service 's|^SystemCallFilter=seccomp landlock|SystemCallFilter=ptrace seccomp landlock|'
mutate "sealer hides own credentials"  systemd/candor-sealer.service 's|^InaccessiblePaths=-/run/candor/source-web$|InaccessiblePaths=-/run/candor/source-web -/run/credentials/candor-sealer.service|'
mutate "capability granted"            systemd/candor-sealer.service 's|^CapabilityBoundingSet=$|CapabilityBoundingSet=CAP_IPC_LOCK|'
mutate "no nftables dependency"        systemd/candor-intake-web.service 's|^Requires=candor-intake-web.socket nftables.service$|Requires=candor-intake-web.socket|'
mutate "IP allow on istore"            systemd/candor-intake-store.service 's|^IPAddressDeny=any$|IPAddressDeny=any\nIPAddressAllow=10.20.0.3|'
mutate "world-writable socket"         systemd/candor-intake-web.socket 's|^SocketMode=0660$|SocketMode=0666|'
mutate "web socket path != onion"      systemd/candor-intake-web.socket 's|^ListenStream=/run/candor/source-web/http.sock$|ListenStream=/run/candor/source-web/other.sock|'
mutate "relay on all interfaces"       systemd/candor-intake-store-relay.socket '/^BindToDevice=relay0$/d'
mutate "drop-in resets syscall filter" systemd/candor-sealer.service.d/zz-local.conf $'+[Service]\nSystemCallFilter='
mutate "drop-in re-enables network"    systemd/candor-intake-web.service.d/zz-local.conf $'+[Service]\nPrivateNetwork=no'
mutate "profile drop-in allows swap"   profiles/ce-hardened/run-candor-staging.mount.d/50-profile.conf 's|,noswap,|,|' --profile ce-hardened
# Sealer memory budget (lead decision after round 5): (a) budget <= MemoryMax - 1024 MiB,
# (b) staging tmpfs size >= budget, each with the profile's own values (c). Every case must
# exit 30 AND name the expected rule; the hardened profile also gets one accepted case.
MEMN=0; SU=systemd/candor-sealer.service; HD=profiles/ce-hardened/candor-sealer.service.d/50-profile.conf
memcase() { # name want-rule(s, |-separated, or "OK") file sed-expr [--profile p]
  local name=$1 want=$2 file=$3 expr=$4 rc; shift 4
  MEMN=$((MEMN + 1)); local d="$T/mem.$MEMN"; cp -a "$INTAKE" "$d"
  sed -i "$expr" "$d/$file"
  if cmp -s "$INTAKE/$file" "$d/$file"; then bad "memory case '$name' did not change its file (test bug)"; return; fi
  cc -q --dir "$d" --only units "$@" > "$d.out" 2>&1; rc=$?
  if [ "$want" = OK ]; then
    if [ "$rc" -eq 0 ]; then pass "config-check accepts: $name"; else bad "config-check rejected: $name (exit $rc)"; fi
  elif [ "$rc" -eq 30 ] && grep -qE "unit\.candor-sealer\.(service\.Service\.)?($want) .* FAIL " "$d.out"; then pass "config-check rejects: $name (exit 30, $want)"
  else bad "memory case '$name': exit $rc or rule $want did not fail"; fi
}
memcase "sealer budget > MemoryMax - 1024 MiB"       memory_budget       "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=5700|'
memcase "staging tmpfs smaller than the budget"     staging_vs_budget   "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=4200|'
memcase "budget variable missing"                   memory_budget       "$SU" '/^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=/d'
memcase "budget reset by an empty Environment="     memory_budget       "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|&\nEnvironment=|'
memcase "budget not a number"                       memory_budget       "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=4G|'
memcase "budget of 8 digits"                        memory_budget       "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=10000000|'
memcase "another variable in Environment="          Environment         "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|&\nEnvironment=LD_PRELOAD=/tmp/x.so|'
memcase "MemoryMax infinity"                        "MemoryMax|memory_budget" "$SU" 's|^MemoryMax=6656M$|MemoryMax=infinity|'
memcase "hardened: budget > its MemoryMax - 1024"   memory_budget       "$HD" 's|^MemoryMax=10752M$|&\nEnvironment=CANDOR_SEALER_MEMORY_BUDGET_MIB=9800|' --profile ce-hardened
memcase "hardened: staging smaller than budget"     staging_vs_budget   "$HD" 's|^MemoryMax=10752M$|&\nEnvironment=CANDOR_SEALER_MEMORY_BUDGET_MIB=8500|' --profile ce-hardened
memcase "hardened: budget 8000 within its limits"   OK                  "$HD" 's|^MemoryMax=10752M$|&\nEnvironment=CANDOR_SEALER_MEMORY_BUDGET_MIB=8000|' --profile ce-hardened
memcase "upload slots missing"                      upload_slots        "$SU" '/^Environment=CANDOR_SEALER_UPLOAD_SLOTS=/d'
memcase "upload slots 15 (< 16)"                    upload_slots        "$SU" 's|^Environment=CANDOR_SEALER_UPLOAD_SLOTS=512$|Environment=CANDOR_SEALER_UPLOAD_SLOTS=15|'
memcase "upload slots 4097 (> 4096)"                upload_slots        "$SU" 's|^Environment=CANDOR_SEALER_UPLOAD_SLOTS=512$|Environment=CANDOR_SEALER_UPLOAD_SLOTS=4097|'
memcase "upload slots not an integer"               upload_slots        "$SU" 's|^Environment=CANDOR_SEALER_UPLOAD_SLOTS=512$|Environment=CANDOR_SEALER_UPLOAD_SLOTS=64k|'
memcase "upload slots 1920 accepted (slice 1 MiB)"   OK                  "$SU" 's|^Environment=CANDOR_SEALER_UPLOAD_SLOTS=512$|Environment=CANDOR_SEALER_UPLOAD_SLOTS=1920|'
memcase "max sessions missing"                      max_sessions        "$SU" '/^Environment=CANDOR_SEALER_MAX_SESSIONS=/d'
memcase "max sessions 15 (< 16)"                    max_sessions        "$SU" 's|^Environment=CANDOR_SEALER_MAX_SESSIONS=512$|Environment=CANDOR_SEALER_MAX_SESSIONS=15|'
memcase "max sessions 65537 (> 65536)"              max_sessions        "$SU" 's|^Environment=CANDOR_SEALER_MAX_SESSIONS=512$|Environment=CANDOR_SEALER_MAX_SESSIONS=65537|'
memcase "upload slots < max sessions"               max_sessions        "$SU" 's|^Environment=CANDOR_SEALER_MAX_SESSIONS=512$|Environment=CANDOR_SEALER_MAX_SESSIONS=513|'
memcase "guaranteed slice < 1 MiB"                  upload_slice        "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=1023|'
memcase "slice exactly 1 MiB accepted"              OK                  "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=1536|;s|^Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=768$|Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=512|;s|^Environment=CANDOR_SEALER_UPLOAD_SLOTS=512$|Environment=CANDOR_SEALER_UPLOAD_SLOTS=768|'
memcase "per-draft quota missing"                   session_upload      "$SU" '/^Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=/d'
memcase "per-draft quota > half the budget"         session_upload      "$SU" 's|^Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=768$|Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=1921|'
memcase "per-draft quota = half the budget accepted" OK                 "$SU" 's|^Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=768$|Environment=CANDOR_SEALER_SESSION_UPLOAD_MIB=1920|'
memcase "hardened: quota over half its own budget"  session_upload      "$HD" 's|^MemoryMax=10752M$|&\nEnvironment=CANDOR_SEALER_MEMORY_BUDGET_MIB=1500|' --profile ce-hardened
memcase "ce-single: budget 4200 over its staging"   staging_vs_budget   "$SU" 's|^Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=3840$|Environment=CANDOR_SEALER_MEMORY_BUDGET_MIB=4200|' --profile ce-single
mutate "staging may swap"              systemd/run-candor-staging.mount 's|,noswap,|,|'
# journald / DNS (NET-008, LOG-007, 17 §4.5/§5.5)
mutate "journald persistent"           journald/journald@candor-intake.conf 's|^Storage=volatile$|Storage=persistent|'
mutate "journald 7 days"               journald/journald@candor-intake.conf 's|^MaxRetentionSec=24h$|MaxRetentionSec=7d|'
mutate "journald forwards to syslog"   journald/candor-intake-host.conf 's|^ForwardToSyslog=no$|ForwardToSyslog=yes|'
mutate "public DNS resolver"           resolv.conf 's|^nameserver 127.0.0.1$|nameserver 9.9.9.9|'
# ---- AUD-RM2-DEP-01: torrc forms that a name denylist missed (tor accepts all of them)
mutate "DEP-01 /Sandbox reset"         torrc '+/Sandbox'
mutate "DEP-01 /CookieAuthentication"  torrc '+/CookieAuthentication'
mutate "DEP-01 abbreviation SafeLog 0" torrc '+SafeLog 0'
mutate "DEP-01 +Log info stderr"       torrc '++Log info stderr'
mutate "DEP-01 HiddenServicePor TCP"   torrc '+HiddenServicePor 81 127.0.0.1:8080'
mutate "DEP-01 HSLayer2Nodes pinned"   torrc "+HSLayer2Nodes $FP"
mutate "DEP-01 HSLayer3Nodes pinned"   torrc "+HSLayer3Nodes $FP"
mutate "DEP-01 StrictNodes 1"          torrc '+StrictNodes 1'
mutate "DEP-01 AlternateDirAuthority"  torrc "+AlternateDirAuthority evil orport=9001 no-v2 198.51.100.7:9030 $FP"
mutate "DEP-01 DirAuthority"           torrc "+DirAuthority evil orport=9001 no-v2 v3ident=$FP 198.51.100.7:9030 $FP"
mutate "DEP-01 ExcludeNodes"           torrc '+ExcludeNodes {de},{nl}'
mutate "DEP-01 Sandbox 0"              torrc 's|^Sandbox 1$|Sandbox 0|'
mutate "DEP-04 control socket back"    torrc '+ControlSocket /run/tor-instances/candor-intake/control.sock'
mutate "DEP-04 control socket no auth" torrc 's|^CookieAuthentication 1$|ControlSocket /run/tor-instances/candor-intake/control.sock\nCookieAuthentication 0|'
mutate "DEP-05 tor Log err file"       torrc 's|^Log warn stderr$|Log err file /var/lib/tor-instances/candor-intake/err.log|'
# ---- AUD-RM2-DEP-02: include, and template accept moved above the safety drops
mutate "DEP-02 nft include accept-all" nftables.conf "+include \"$T/extra.nft\""
mutate "DEP-02 nft define"             nftables.conf 's|^flush ruleset$|flush ruleset\ndefine EXT = "ext0"|'
mutate "DEP-02 E1 above safety drops"  nftables.conf '/^    oifname "ext0" meta skuid "_tor-candor-intake"/d; s|^    ip daddr 169.254.0.0/16|    oifname "ext0" meta skuid "_tor-candor-intake" meta l4proto tcp ct state new accept\n    ip daddr 169.254.0.0/16|'
mutate "nft extra drop rule order"     nftables.conf 's|^    ct state invalid drop$|    ct state invalid drop\n    tcp dport 25 drop|'
mutate "nft core_relay as interval"    nftables.conf 's|^  set core_relay { type ipv4_addr; }|  set core_relay { type ipv4_addr; flags interval; elements = { 0.0.0.0/0 } }|'
mutate "nft non_public4 element gone"  nftables.conf 's|10.0.0.0/8, ||'
# ---- AUD-RM2-DEP-03: effective unit configuration
mutate "DEP-03 pg ExecStart -c logging" systemd/candor-intake-pg.service.d/zz.conf $'+[Service]\nExecStart=\nExecStart=/usr/lib/postgresql/16/bin/postgres -c config_file=/etc/candor/intake/postgresql/candor-intake.conf -c logging_collector=on -c log_statement=all'
mutate "DEP-03 pg Environment PGOPTIONS" systemd/candor-intake-pg.service.d/zz.conf $'+[Service]\nEnvironment=PGOPTIONS=-c log_statement=all'
mutate "DEP-03 sealer keys in [Install]" systemd/candor-sealer.service '/^PrivateNetwork=yes$/d; /^RestrictAddressFamilies=AF_UNIX$/d; s|^WantedBy=multi-user.target$|WantedBy=multi-user.target\nPrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX|'
mutate "DEP-03 ReadWritePaths=/"       systemd/candor-intake-web.service.d/zz.conf $'+[Service]\nReadWritePaths=/'
mutate "DEP-03 BindReadOnlyPaths tor"  systemd/candor-intake-web.service.d/zz.conf $'+[Service]\nBindReadOnlyPaths=/var/lib/tor-instances'
mutate "DEP-03 SupplementaryGroups"    systemd/candor-intake-store.service 's|^Group=candor-istore$|Group=candor-istore\nSupplementaryGroups=_tor-candor-intake postgres|'
mutate "DEP-03 DeviceAllow /dev/mem"   systemd/candor-sealer.service.d/zz.conf $'+[Service]\nDeviceAllow=/dev/mem rw'
mutate "DEP-03 SocketBindAllow"        systemd/candor-intake-web.service.d/zz.conf $'+[Service]\nSocketBindAllow=any'
mutate "DEP-03 Group= removed"         systemd/candor-intake-web.service '/^Group=candor-web$/d'
mutate "DEP-03 TemporaryFileSystem rm" systemd/candor-sealer.service '/^TemporaryFileSystem=/d'
mutate "DEP-03 InaccessiblePaths rm"   systemd/candor-intake-web.service '/^InaccessiblePaths=-\/run\/tor-instances/d'
mutate "DEP-03 sealer wrong AppArmor"  systemd/candor-sealer.service 's|^AppArmorProfile=candor-sealer$|AppArmorProfile=candor-intake-store|'
mutate "DEP-03 SocketGroup users"      systemd/candor-sealer.socket 's|^SocketGroup=candor-web$|SocketGroup=users|'
mutate "DEP-03 SocketUser users"       systemd/candor-intake-store.socket 's|^SocketUser=candor-istore$|SocketUser=users|'
mutate "DEP-03 relay IPAddressAllow=any" systemd/candor-intake-store-relay.socket.d/site.conf $'+[Socket]\nIPAddressAllow=any'
mutate "DEP-03 relay allow != core_relay" systemd/candor-intake-store-relay.socket.d/site.conf $'+[Socket]\nIPAddressAllow=192.0.2.10/32'
mutate "DEP-03 prefix drop-in candor-" systemd/candor-.service.d/zz.conf $'+[Service]\nPrivateNetwork=no\nRestrictAddressFamilies=\nAppArmorProfile='
mutate "DEP-03 template drop-in tor@"  systemd/tor@.service.d/zz.conf $'+[Service]\nIPAddressDeny='
mutate "DEP-03 type drop-in service.d" systemd/service.d/zz.conf $'+[Service]\nMemoryDenyWriteExecute=no'
mutate "DEP-03 ExecStartPre added"     systemd/candor-sealer.service.d/zz.conf $'+[Service]\nExecStartPre=/usr/bin/true'
mutate "DEP-03 sealer filter deny-list" systemd/candor-sealer.service.d/zz.conf $'+[Service]\nSystemCallFilter=\nSystemCallFilter=~@mount'
mutate "DEP-03 line continuation"      systemd/candor-intake-web.service 's|^PrivateNetwork=yes$|PrivateNetwork=\\\nno|'
mutate "unknown key"                   systemd/candor-intake-web.service.d/zz.conf $'+[Service]\nPrivateNetwrok=yes'
# ---- AUD-RM2-DEP-05..09/11/12 and new artefacts
mutate "DEP-05 tor stderr to journal"  systemd/tor@candor-intake.service 's|^StandardError=null$|StandardError=journal|'
mutate "DEP-05 web stderr to journal"  systemd/candor-intake-web.service 's|^StandardError=null$|StandardError=journal|'
mutate "DEP-06 web LogLevelMax"        systemd/candor-intake-web.service 's|^LogLevelMax=emerg$|LogLevelMax=warning|'
mutate "DEP-06 host journal no MaxFileSec" journald/candor-intake-host.conf '/^MaxFileSec=/d'
mutate "DEP-06 host journal Audit=yes" journald/candor-intake-host.conf 's|^Audit=no$|Audit=yes|'
mutate "DEP-06 ns journal stores warning" journald/journald@candor-intake.conf 's|^MaxLevelStore=crit$|MaxLevelStore=warning|'
mutate "DEP-07 pg max_wal_size 1GB"    postgresql/candor-intake.conf "s|^max_wal_size = '256MB'|max_wal_size = '1GB'|"
mutate "DEP-07 pg wal_recycle on"      postgresql/candor-intake.conf 's|^wal_recycle = off|wal_recycle = on|'
mutate "DEP-08 tor without AppArmor"   systemd/tor@candor-intake.service '/^AppArmorProfile=candor-tor-intake$/d'
mutate "DEP-08 pg AppArmor soft-fail"  systemd/candor-intake-pg.service 's|^AppArmorProfile=candor-intake-pg$|AppArmorProfile=-candor-intake-pg|'
mutate "DEP-09 ptrace_scope 1"         sysctl.d/90-candor-intake.conf 's|^kernel.yama.ptrace_scope = 3$|kernel.yama.ptrace_scope = 1|'
mutate "DEP-09 core_pattern pipe"      sysctl.d/90-candor-intake.conf 's#^kernel.core_pattern = |/bin/false$#kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P#'
mutate "DEP-09 tcp_timestamps on"      sysctl.d/90-candor-intake.conf 's|^net.ipv4.tcp_timestamps = 0$|net.ipv4.tcp_timestamps = 1|'
mutate "DEP-09 sysctl key dropped"     sysctl.d/90-candor-intake.conf '/^kernel.dmesg_restrict/d'
mutate "DEP-09 sysctl extra key"       sysctl.d/90-candor-intake.conf '+kernel.unprivileged_userns_clone = 1'
mutate "DEP-09 coredump stored"        coredump.conf.d/50-candor-intake.conf 's|^Storage=none$|Storage=external|'
mutate "DEP-11 tor group torctl"       systemd/tor@candor-intake.service 's|^Group=_tor-candor-intake$|Group=_candor-torctl|'
mutate "DEP-12 tor /var/tmp visible"   systemd/tor@candor-intake.service '/^InaccessiblePaths=-\/var\/tmp$/d'

# ---- AUD-RM2-DEP round 2 (DEP-15..22), AUD-RM2-SEA-16, lead additions for STO-08/11/23/24
mutate "DEP-15 sealer /** rwlkix + network," apparmor/candor-sealer 's|^  deny network inet,$|  /** rwlkix,\n  network,|'
mutate "DEP-15 tor /usr/bin/** ux"          apparmor/candor-tor-intake 's|^  /usr/bin/tor mr,$|  /usr/bin/tor mr,\n  /usr/bin/** ux,|'
mutate "DEP-15 web flags=(complain)"        apparmor/candor-web 's|^profile candor-web /usr/lib/candor/source-web/candor-web {$|profile candor-web /usr/lib/candor/source-web/candor-web flags=(complain) {|'
mutate "DEP-15 pg capability sys_admin"     apparmor/candor-intake-pg 's|^  deny capability,$|  capability sys_admin,|'
mutate "DEP-15 store change_profile"        apparmor/candor-intake-store 's|^  deny capability,$|  deny capability,\n  change_profile -> unconfined,|'
mutate "DEP-15 maint pux transition"        apparmor/candor-intake-maint 's|^  /run/candor/config/ r,$|  /run/candor/config/ r,\n  /usr/bin/** pux,|'
mutate "DEP-15 web #include local"          apparmor/candor-web 's|^  /dev/null rw,$|  /dev/null rw,\n  #include <local/candor-web>|'
# AUD-RM2-DEP-23: self-contained profiles - no include of any kind, pinned variables and ABI.
mutate "DEP-23 sealer re-includes abstractions/base" apparmor/candor-sealer 's|^  /dev/null rw,$|  /dev/null rw,\n  include <abstractions/base>|'
mutate "DEP-23 web include <tunables/global>"  apparmor/candor-web 's|^abi <abi/3.0>,$|abi <abi/3.0>,\ninclude <tunables/global>|'
mutate "DEP-23 store include if exists <local/...>" apparmor/candor-intake-store 's|^  /dev/null rw,$|  /dev/null rw,\n  include if exists <local/candor-intake-store>|'
mutate "DEP-23 tor #include abstractions/openssl" apparmor/candor-tor-intake 's|^  /etc/ssl/openssl.cnf r,$|  /etc/ssl/openssl.cnf r,\n#include <abstractions/openssl>|'
mutate "DEP-23 pg @{PROC}+=/ "                apparmor/candor-intake-pg 's|^@{PROC}=/proc/$|@{PROC}=/proc/\n@{PROC}+=/|'
mutate "DEP-23 maint extra variable @{x}=/**"  apparmor/candor-intake-maint 's|^@{PROC}=/proc/$|@{PROC}=/proc/\n@{x}=/**|'
mutate "DEP-23 sealer abi <abi/4.0>"           apparmor/candor-sealer 's|^abi <abi/3.0>,$|abi <abi/4.0>,|'
mutate "DEP-15 tor network inet (any type)" apparmor/candor-tor-intake 's|^  network inet stream,$|  network inet,|'
mutate "DEP-15 sealer deny rule removed"    apparmor/candor-sealer '/^  deny ptrace,$/d'
# ---- W1-D (D-36): web and store syscall allow-lists pinned like the sealer's; store LimitMEMLOCK
mutate "D-36 web narrowing line removed"        systemd/candor-intake-web.service '/^SystemCallFilter=~_newselect/d'
mutate "D-36 store narrowing line removed"      systemd/candor-intake-store.service '/^SystemCallFilter=~_newselect/d'
mutate "D-36 web re-adds io_uring_setup"        systemd/candor-intake-web.service 's|^SystemCallFilter=seccomp landlock_create_ruleset landlock_add_rule landlock_restrict_self$|& io_uring_setup|'
mutate "D-36 store re-adds memfd_create"        systemd/candor-intake-store.service 's|^SystemCallFilter=seccomp landlock_create_ruleset landlock_add_rule landlock_restrict_self$|& memfd_create|'
mutate "D-36 web re-adds openat2 + unlinkat"    systemd/candor-intake-web.service 's|^SystemCallFilter=seccomp landlock_create_ruleset landlock_add_rule landlock_restrict_self$|& openat2 unlinkat|'
mutate "D-36 store drops ptrace from deny"      systemd/candor-intake-store.service 's|^SystemCallFilter=~@privileged @resources @mount @debug |SystemCallFilter=~@privileged @resources @mount |'
mutate "D-36 sealer denies openat2 again"       systemd/candor-sealer.service 's|^SystemCallFilter=seccomp landlock_create_ruleset landlock_add_rule landlock_restrict_self$|&\nSystemCallFilter=~openat2|'
mutate "D-36 store drop-in re-allows bind"      systemd/candor-intake-store.service.d/zz.conf $'+[Service]\nSystemCallFilter=bind listen'
mutate "D-36 web drop-in resets the filter"     systemd/candor-intake-web.service.d/zz.conf $'+[Service]\nSystemCallFilter=\nSystemCallFilter=@system-service'
mutate "D-36 store LimitMEMLOCK removed"        systemd/candor-intake-store.service '/^LimitMEMLOCK=512M$/d'
mutate "D-36 store LimitMEMLOCK infinity"       systemd/candor-intake-store.service 's|^LimitMEMLOCK=512M$|LimitMEMLOCK=infinity|'
mutate "DEP-16 sealer drop-in re-allows io_uring" systemd/candor-sealer.service.d/zz.conf $'+[Service]\nSystemCallFilter=io_uring_setup io_uring_enter io_uring_register'
mutate "DEP-16 sealer deny line drops userfaultfd" systemd/candor-sealer.service 's| userfaultfd | |'
mutate "DEP-16 sealer re-add line widened"  systemd/candor-sealer.service 's|^SystemCallFilter=seccomp landlock_create_ruleset|SystemCallFilter=seccomp bpf landlock_create_ruleset|'
mutate "DEP-17 torrc is a symlink"          torrc "@$T/secret"
mutate "DEP-17 pg conf is a symlink"        postgresql/candor-intake.conf "@$T/secret"
mutate "DEP-17 pg_hba is a symlink"         postgresql/pg_hba.conf "@$T/secret"
mutate "DEP-17 AppArmor profile symlink"    apparmor/candor-web "@$T/secret"
mutate "DEP-17 unit drop-in is a symlink"   systemd/candor-intake-web.service.d/zz.conf "@$T/secret.conf"
mutate "DEP-17 sysctl file is a symlink"    sysctl.d/90-candor-intake.conf "@$T/secret"
mutate "DEP-19 pg_hba postgres peer line"   postgresql/pg_hba.conf 's|^local   candor_intake_TENANT  candor_istore |local all postgres peer\n&|'
mutate "DEP-19 pg_hba migrator to all dbs"  postgresql/pg_hba.conf 's|^local   candor_intake_TENANT  candor_intake_migrator|local   all               candor_intake_migrator|'
# AUD-RM2-DEP-25 / ADR-054: one exactly named intake database, no regex or second database.
mutate "DEP-25 pg_hba regex database"        postgresql/pg_hba.conf 's|^local   candor_intake_TENANT  candor_istore |local   /^candor_intake_  candor_istore |'
mutate "DEP-25 pg_hba maint to another db"   postgresql/pg_hba.conf 's|^local   candor_intake_TENANT  candor_intake_maint|local   candor_intake_other   candor_intake_maint|'
mutate "DEP-25 pg_hba database list"         postgresql/pg_hba.conf 's|^local   candor_intake_TENANT  candor_intake_migrator|local   candor_intake_TENANT,candor_intake_b  candor_intake_migrator|'
mutate "DEP-19 pg_ident extra mapping"      postgresql/pg_ident.conf '+candor     root             candor_istore'
mutate "DEP-19 pg key not on allow-list"    postgresql/candor-intake.conf "+session_replication_role = 'replica'"
mutate "DEP-19 pg unix_socket_group"        postgresql/candor-intake.conf "s|^unix_socket_group = 'candor-istore'|unix_socket_group = 'candor-web'|"
mutate "DEP-19 pg dynamic_library_path"     postgresql/candor-intake.conf "s|^dynamic_library_path = '\$libdir'|dynamic_library_path = '/tmp:\$libdir'|"
mutate "STO-08 temp_file_limit unlimited"   postgresql/candor-intake.conf "s|^temp_file_limit = '256MB'|temp_file_limit = -1|"
mutate "STO-08 idle-in-transaction off"     postgresql/candor-intake.conf "s|^idle_in_transaction_session_timeout = '60s'|idle_in_transaction_session_timeout = 0|"
mutate "STO-11 track_counts on"             postgresql/candor-intake.conf 's|^track_counts = off|track_counts = on|'
mutate "STO-11 track_activities on"         postgresql/candor-intake.conf 's|^track_activities = off|track_activities = on|'
mutate "STO-11 autovacuum on"               postgresql/candor-intake.conf 's|^autovacuum = off|autovacuum = on|'
mutate "STO-11 pg stats dir not writable"   systemd/candor-intake-pg.service 's|^ReadWritePaths=/run/candor/intake-pg /run/candor/intake-pg-stat$|ReadWritePaths=/run/candor/intake-pg|'
mutate "STO-23 vacuum timer hourly"         systemd/candor-intake-vacuum.timer 's|^OnCalendar=.*|OnCalendar=hourly|'
mutate "STO-23 maint timer randomised"      systemd/candor-intake-maint.timer 's|^RandomizedDelaySec=0$|RandomizedDelaySec=1h|'
mutate "STO-23 maint timer catch-up"        systemd/candor-intake-maint.timer 's|^Persistent=false$|Persistent=true|'
mutate "STO-23 maint timer removed"         systemd/candor-intake-maint.timer -
mutate "STO-24 maint runs as candor-istore" systemd/candor-intake-maint.service 's|^User=candor-imaint$|User=candor-istore|'
mutate "STO-24 vacuum with network"         systemd/candor-intake-vacuum.service 's|^PrivateNetwork=yes$|PrivateNetwork=no|'
mutate "STO-24 maint output to journal"     systemd/candor-intake-maint.service 's|^StandardError=null$|StandardError=journal|'
mutate "STO-24 maint unconfined"            systemd/candor-intake-maint.service '/^AppArmorProfile=candor-intake-maint$/d'
mutate "DEP-20 exception-trace on"          sysctl.d/90-candor-intake.conf 's|^debug.exception-trace = 0$|debug.exception-trace = 1|'
mutate "DEP-29 memfd_noexec 0"              sysctl.d/90-candor-intake.conf 's|^vm.memfd_noexec = 2$|vm.memfd_noexec = 0|'
mutate "DEP-29 memfd_noexec removed"        sysctl.d/90-candor-intake.conf '/^vm.memfd_noexec/d'
mutate "DEP-22 mon_hosts 0.0.0.0 + broadcast" nftables.conf 's|^  set mon_hosts  { type ipv4_addr; }|  set mon_hosts  { type ipv4_addr; elements = { 0.0.0.0, 255.255.255.255 } }|'
mutate "DEP-22 admin_jump loopback"         nftables.conf 's|^  set admin_jump { type ipv4_addr; }|  set admin_jump { type ipv4_addr; elements = { 127.0.0.1 } }|'
mutate "DEP-22 core_relay multicast"        nftables.conf 's|^  set core_relay { type ipv4_addr; }|  set core_relay { type ipv4_addr; elements = { 224.0.0.1 } }|'
mutate "SEA-16 sealer socket SEQPACKET"     systemd/candor-sealer.socket 's|^ListenStream=|ListenSequentialPacket=|'
mutate "SEA-16 sealer loses staging"        systemd/candor-sealer.service '/^ReadWritePaths=\/run\/candor\/staging$/d'
mutate "SEA-16 store writes staging"        systemd/candor-intake-store.service 's|^ReadWritePaths=/run/candor/directory$|ReadWritePaths=/run/candor/staging /run/candor/directory|'
mutate "SEA-16 staging owned by istore"     systemd/run-candor-staging.mount 's|X-mount.owner=candor-sealer|X-mount.owner=candor-istore|'
mutate "SEA-16 store AppArmor staging rw"   apparmor/candor-intake-store 's|^  /var/lib/candor/intake/ r,$|  /var/lib/candor/intake/ r,\n  /run/candor/staging/** rw,|'
mutate "SEA-16 sealer MemoryMax w/o staging" systemd/candor-sealer.service 's|^MemoryMax=6656M$|MemoryMax=2560M|'

# ---- --host --root: a synthetic installed host (README install layout, CE-SINGLE)
HONLY=tor,nft,units,journald,kernel,dns,apparmor,host
HR="$T/hostroot"
mkhost() {
  local r=$1 u d
  mkdir -p "$r/etc/tor/instances/candor-intake" "$r/etc/systemd/system" "$r/etc/systemd/journald.conf.d" \
           "$r/etc/systemd/coredump.conf.d" "$r/etc/sysctl.d" "$r/etc/apparmor.d" "$r/etc/candor/intake/postgresql" \
           "$r/usr/lib/systemd/system" "$r/run/systemd/system"
  cp "$INTAKE/torrc" "$r/etc/tor/instances/candor-intake/torrc"
  cp "$INTAKE/nftables.conf" "$r/etc/nftables.conf"
  cp -a "$INTAKE/systemd/." "$r/etc/systemd/system/"
  for d in "$INTAKE/profiles/ce-single"/*.d; do mkdir -p "$r/etc/systemd/system/$(basename "$d")"; cp "$d"/* "$r/etc/systemd/system/$(basename "$d")/"; done
  cp "$INTAKE/journald/journald@candor-intake.conf" "$r/etc/systemd/journald@candor-intake.conf"
  cp "$INTAKE/journald/candor-intake-host.conf" "$r/etc/systemd/journald.conf.d/50-candor-intake.conf"
  cp "$INTAKE/coredump.conf.d/50-candor-intake.conf" "$r/etc/systemd/coredump.conf.d/"
  cp "$INTAKE/sysctl.d/90-candor-intake.conf" "$r/etc/sysctl.d/"
  cp "$INTAKE/apparmor/"* "$r/etc/apparmor.d/"
  # The distribution's AppArmor tree and its dpkg record (AUD-RM2-DEP-23): this container's
  # apparmor package, as an installed host has it.
  cp -R /etc/apparmor.d/abi /etc/apparmor.d/abstractions /etc/apparmor.d/tunables "$r/etc/apparmor.d/"
  mkdir -p "$r/etc/apparmor.d/local" "$r/var/lib/dpkg"; : > "$r/etc/apparmor.d/local/candor-placeholder"
  awk 'BEGIN { RS=""; ORS="\n\n" } /(^|\n)Package: apparmor\n/' /var/lib/dpkg/status > "$r/var/lib/dpkg/status"
  cp "$INTAKE/postgresql/"* "$r/etc/candor/intake/postgresql/"
  cp "$INTAKE/resolv.conf" "$r/etc/resolv.conf"
  # Kernel release as /proc shows it (the --root stand-in for uname -r; floor 6.3).
  mkdir -p "$r/proc/sys/kernel"; printf '6.12.38+deb13-amd64\n' > "$r/proc/sys/kernel/osrelease"
  : > "$r/etc/fstab"; : > "$r/etc/crypttab"
  # Debian: /etc/sysctl.conf is read by systemd-sysctl only through this link (AUD-RM2-DEP-18).
  printf 'kernel.yama.ptrace_scope = 3\n' > "$r/etc/sysctl.conf"; ln -s ../sysctl.conf "$r/etc/sysctl.d/99-sysctl.conf"
  # Distribution units the baseline depends on (Debian 13 content), nftables enabled.
  printf '[Unit]\nDescription=nftables\nWants=network-pre.target\nBefore=network-pre.target shutdown.target\nConflicts=shutdown.target\nDefaultDependencies=no\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nStandardInput=null\nProtectSystem=full\nProtectHome=true\nExecStart=/usr/sbin/nft -f /etc/nftables.conf\nExecReload=/usr/sbin/nft -f /etc/nftables.conf\nExecStop=/usr/sbin/nft flush ruleset\n\n[Install]\nWantedBy=sysinit.target\n' > "$r/usr/lib/systemd/system/nftables.service"
  printf '[Unit]\nDescription=Apply Kernel Variables\nDefaultDependencies=no\nConflicts=shutdown.target\nAfter=systemd-modules-load.service\nBefore=sysinit.target shutdown.target\nConditionPathIsReadWrite=/proc/sys/net/\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/lib/systemd/systemd-sysctl\nTimeoutSec=90s\n' > "$r/usr/lib/systemd/system/systemd-sysctl.service"
  mkdir -p "$r/usr/lib/systemd/system/sysinit.target.wants" "$r/etc/systemd/system/sysinit.target.wants"
  ln -s ../systemd-sysctl.service "$r/usr/lib/systemd/system/sysinit.target.wants/systemd-sysctl.service"
  ln -s /usr/lib/systemd/system/nftables.service "$r/etc/systemd/system/sysinit.target.wants/nftables.service"
  # Distribution units that must be masked (AUD-RM2-DEP-09/14).
  for u in tor.service tor@.service systemd-coredump.socket; do : > "$r/usr/lib/systemd/system/$u"; done
  for u in tor.service tor@default.service systemd-coredump.socket; do ln -s /dev/null "$r/etc/systemd/system/$u"; done
  # Account databases: the container's, without the removed control group and with empty
  # journal-reader groups (as on a correctly installed host).
  grep -v '^_candor-torctl:' /etc/group | awk -F: 'BEGIN {OFS=":"} $1=="systemd-journal" || $1=="adm" || $1=="_tor-candor-intake" {$4=""} {print}' > "$r/etc/group"
  cp /etc/passwd "$r/etc/passwd"
}
if is_root && users_exist && have tor && have nft && have jq && have apparmor_parser && [ -d /etc/apparmor.d/abstractions ] && grep -qx 'Package: apparmor' /var/lib/dpkg/status 2>/dev/null; then
  mkhost "$HR"
  if cc -q --host --root "$HR" --only "$HONLY" > "$T/host.out" 2>&1; then pass "config-check --host --root: synthetic installed host passes"
  else bad "config-check --host --root on the synthetic host: $(grep ' FAIL ' "$T/host.out" | head -n 3 | tr -s ' ')"; fi
  hmutate "system.control drop-in resets IPAddressDeny" etc/systemd/system.control/candor-sealer.service.d/50-IPAddressDeny.conf $'+[Service]\nIPAddressDeny='
  hmutate "/run drop-in re-enables network"   run/systemd/system/candor-intake-web.service.d/zz.conf $'+[Service]\nPrivateNetwork=no'
  hmutate "/usr/lib prefix drop-in"            usr/lib/systemd/system/candor-.service.d/zz.conf $'+[Service]\nSystemCallFilter=\nAppArmorProfile='
  hmutate "/usr/local/lib template drop-in"   usr/local/lib/systemd/system/tor@.service.d/zz.conf $'+[Service]\nRestrictAddressFamilies=AF_NETLINK'
  hmutate "transient unit"                     run/systemd/transient/candor-sealer.service.d/50-x.conf $'+[Service]\nPrivateNetwork=no'
  hmutate "generator drop-in"                  run/systemd/generator.late/candor-intake-pg.service.d/x.conf $'+[Service]\nStandardError=journal'
  hmutate "later sysctl.d overrides ptrace"    etc/sysctl.d/99-zlocal.conf '+kernel.yama.ptrace_scope = 0'
  hmutate "/etc/sysctl.conf enables forwarding" etc/sysctl.conf '+net.ipv4.ip_forward = 1'
  hmutate "journald.conf.d persistent"         etc/systemd/journald.conf.d/99-local.conf $'+[Journal]\nStorage=persistent'
  hmutate "journald@ns drop-in forwards"       etc/systemd/journald@candor-intake.conf.d/99-local.conf $'+[Journal]\nForwardToSyslog=yes'
  hmutate "coredump.conf.d stores cores"       etc/systemd/coredump.conf.d/99-local.conf $'+[Coredump]\nStorage=external'
  hmutate "coredump socket unmasked"           etc/systemd/system/systemd-coredump.socket -
  hmutate "tor@default not masked"             etc/systemd/system/tor@default.service -
  hmutate "health agent in tor group"          etc/group 's|^\(_tor-candor-intake:[^:]*:[0-9]*:\)$|\1candor-health|'
  hmutate "admin in systemd-journal"           etc/group 's|^\(systemd-journal:[^:]*:[0-9]*:\)$|\1root|'
  hmutate "control group recreated"            etc/group '+_candor-torctl:x:4242:candor-health'
  hmutate "plain swap in fstab"                etc/fstab '+/dev/sda3 none swap sw 0 0'
  hmutate "AppArmor profile file missing"      etc/apparmor.d/candor-tor-intake -
  hmutate "torrc edited on host"               etc/tor/instances/candor-intake/torrc '+/SafeLogging'
  hmutate "site relay drop-in IPAddressAllow=any" etc/systemd/system/candor-intake-store-relay.socket.d/site.conf $'+[Socket]\nIPAddressAllow=any'
  # AUD-RM2-DEP round 2 on the installed host
  hmutate "DEP-15 web flags=(complain)"        etc/apparmor.d/candor-web 's|^profile candor-web /usr/lib/candor/source-web/candor-web {$|profile candor-web /usr/lib/candor/source-web/candor-web flags=(complain) {|'
  hmutate "DEP-15 sealer /** rwlkix + network," etc/apparmor.d/candor-sealer 's|^  deny network inet,$|  /** rwlkix,\n  network,|'
  hmutate "DEP-15 tor /usr/bin/** ux"          etc/apparmor.d/candor-tor-intake 's|^  /usr/bin/tor mr,$|  /usr/bin/tor mr,\n  /usr/bin/** ux,|'
  hmutate "DEP-15 profile disabled"            etc/apparmor.d/disable/candor-sealer @/etc/apparmor.d/candor-sealer
  hmutate "DEP-15 profile forced to complain"  etc/apparmor.d/force-complain/candor-tor-intake @/etc/apparmor.d/candor-tor-intake
  hmutate "DEP-15 foreign file redefines profile" etc/apparmor.d/zz-local '+profile candor-sealer /usr/lib/candor/sealer/candor-sealer { /** rwlkix, }'
  # AUD-RM2-DEP-23: the round-3 bypasses (snippet directories, rewritten distribution files).
  hmutate "DEP-23 abstractions/base.d snippet"  etc/apparmor.d/abstractions/base.d/zz $'+/** rwlkix,\nnetwork,\ncapability,'
  hmutate "DEP-23 tunables/global.d snippet"    etc/apparmor.d/tunables/global.d/zz '+@{PROC}+=/'
  hmutate "DEP-23 local/ override for sealer"   etc/apparmor.d/local/candor-sealer '+/** rwlkix,'
  hmutate "DEP-23 rewritten abstractions/openssl" etc/apparmor.d/abstractions/openssl '+/** rwlkix,'
  hmutate "DEP-23 rewritten abstractions/base"  etc/apparmor.d/abstractions/base 's|^  /dev/random                    r,$|  /** rwlkix,|'
  hmutate "DEP-23 rewritten tunables/proc"      etc/apparmor.d/tunables/proc 's|^@{PROC}=/proc/$|@{PROC}=/|'
  hmutate "DEP-23 rewritten abi/3.0"            etc/apparmor.d/abi/3.0 '/network/d'
  hmutate "DEP-23 sealer re-includes abstractions/base" etc/apparmor.d/candor-sealer 's|^  /dev/null rw,$|  /dev/null rw,\n  include <abstractions/base>|'
  hmutate "DEP-23 parser.conf downgrades the feature set" etc/apparmor/parser.conf '+features-file=/etc/apparmor.d/abi/kernel-5.4-vanilla'
  hmutate "DEP-16 sealer drop-in re-allows io_uring" etc/systemd/system/candor-sealer.service.d/zz.conf $'+[Service]\nSystemCallFilter=io_uring_setup io_uring_enter io_uring_register'
  hmutate "DEP-17 torrc symlink to a secret"   etc/tor/instances/candor-intake/torrc "@$T/secret"
  hmutate "DEP-17 torrc parent dir symlinked"  etc/tor/instances "@$T/tordir"
  hmutate "DEP-17 drop-in symlink to a secret" etc/systemd/system/candor-intake-web.service.d/zz.conf "@$T/secret.conf"
  hmutate "DEP-17 /etc/group symlink"          etc/group "@$T/secret"
  hmutate "DEP-17 nftables.conf symlink"       etc/nftables.conf "@$T/secret"
  hmutate "DEP-18 DefaultEnvironment LD_PRELOAD" etc/systemd/system.conf.d/zz.conf $'+[Manager]\nDefaultEnvironment=LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libx.so'
  hmutate "DEP-18 ManagerEnvironment"          etc/systemd/system.conf.d/zz.conf $'+[Manager]\nManagerEnvironment=LD_LIBRARY_PATH=/opt/x'
  hmutate "DEP-18 /etc/ld.so.preload"          etc/ld.so.preload '+/usr/lib/x86_64-linux-gnu/libx.so'
  hmutate "DEP-18 sysctl.conf ok, 99-zz overrides" etc/sysctl.d/99-zz.conf '+kernel.yama.ptrace_scope = 0'
  hmutate "DEP-18 nftables drop-in /bin/true"  etc/systemd/system/nftables.service.d/zz.conf $'+[Service]\nExecStart=\nExecStart=/bin/true'
  hmutate "DEP-18 nftables loads another file" etc/systemd/system/nftables.service.d/candor-intake.conf $'+[Service]\nExecStart=\nExecStart=/usr/sbin/nft -f /etc/other.nft'
  hmutate "DEP-18 nftables not enabled"        etc/systemd/system/sysinit.target.wants/nftables.service -
  hmutate "DEP-18 nftables masked at runtime"  run/systemd/system/nftables.service @/dev/null
  hmutate "DEP-18 systemd-sysctl masked"       etc/systemd/system/systemd-sysctl.service @/dev/null
  hmutate "DEP-18 systemd-sysctl condition"    etc/systemd/system/systemd-sysctl.service.d/zz.conf $'+[Unit]\nConditionPathExists=/nonexistent'
  hmutate "DEP-20 exception-trace on (sysctl.d)" etc/sysctl.d/99-local.conf '+debug.exception-trace = 1'
  hmutate "DEP-29 memfd_noexec lowered (sysctl.d)" etc/sysctl.d/99-local.conf '+vm.memfd_noexec = 1'
  hmutate "kernel 6.1 below the 6.3 floor"     proc/sys/kernel/osrelease 's/^.*$/6.1.0-28-amd64/'
  hmutate "kernel 6.2.16 below the 6.3 floor"  proc/sys/kernel/osrelease 's/^.*$/6.2.16/'
  hmutate "kernel release unparseable"         proc/sys/kernel/osrelease 's/^.*$/linux-next/'
  hmutate "DEP-22 site set 0.0.0.0 + broadcast" etc/nftables.conf 's|^  set mon_hosts  { type ipv4_addr; }|  set mon_hosts  { type ipv4_addr; elements = { 0.0.0.0, 255.255.255.255 } }|'
  hmutate "STO-23 maint timer drop-in moves time" etc/systemd/system/candor-intake-maint.timer.d/zz.conf $'+[Timer]\nOnCalendar=\nOnCalendar=hourly'
else skip "config-check --host --root cases (need root, users, tor, nft, jq, apparmor_parser and a dpkg-installed apparmor)"; fi
mutate_results

# ---- AUD-RM2-DEP-24/26: race-free input reader (compiled candor-safe-read), directly and under
# live races.
if [ -x "$TOOLS/candor-safe-read" ] && have timeout && have mkfifo; then
  D="$T/sr"; mkdir -p "$D/real" "$D/secretdir" "$D/o"; chmod 0755 "$D" "$D/real" "$D/secretdir"; chmod 0700 "$D/o"
  printf 'ok\n' > "$D/real/f"; printf 'CANDORLEAKMARKER\n' > "$D/secretdir/f"; chmod 0644 "$D/real/f" "$D/secretdir/f"
  ln -s "$D/secretdir" "$D/link"; ln -s "$D/secretdir/f" "$D/real/l"; mkfifo "$D/real/fifo"
  me=$(id -u)
  srcase() { # name want-status args...
    local name=$1 want=$2 rc; shift 2
    rm -f "$D/o/out"
    timeout -k 1 10 "$TOOLS/candor-safe-read" "$@" > "$D/stdout" 2>&1 3<"$D/o"; rc=$?
    if [ "$rc" -ne "$want" ]; then bad "candor-safe-read: $name: status $rc, want $want"
    elif [ -s "$D/stdout" ] || { [ "$want" -ne 0 ] && [ -e "$D/o/out" ]; }; then bad "candor-safe-read: $name: printed output or left a copy"
    else pass "candor-safe-read: $name (status $rc)"; fi
  }
  srcase "regular file copied"                0  "$D/real/f" out 4096 "$me" 002
  if cmp -s "$D/real/f" "$D/o/out"; then pass "candor-safe-read: copy equals the input"; else bad "candor-safe-read: copy differs"; fi
  srcase "symlinked parent directory refused" 10 "$D/link/f" out 4096 "0,$me" 002
  srcase "symlink as last component refused"  10 "$D/real/l" out 4096 "0,$me" 002
  srcase "'..' component refused"             10 "$D/real/../secretdir/f" out 4096 "0,$me" 002
  srcase "FIFO refused without blocking"      12 "$D/real/fifo" out 4096 "0,$me" 002
  srcase "device node refused"                12 /dev/null out 4096 "0,$me" 002
  srcase "directory refused"                  12 "$D/real" out 4096 "0,$me" 002
  srcase "owner not allowed"                  13 "$D/real/f" out 4096 4242 002
  chmod o+w "$D/real/f"; srcase "world-writable input refused" 13 "$D/real/f" out 4096 "0,$me" 002; chmod o-w "$D/real/f"
  ln "$D/real/f" "$D/real/hard"; srcase "hard-linked input refused" 13 "$D/real/f" out 4096 "0,$me" 002; rm -f "$D/real/hard"
  srcase "larger than the cap refused"        14 "$D/real/f" out 2 "0,$me" 002
  srcase "missing input"                      11 "$D/real/nope" out 4096 "0,$me" 002
  timeout 10 "$TOOLS/candor-safe-read" --md5 md5 4096 "0,$me" 002 "$D/real/f" "$D/link/f" "$D/real/fifo" > "$D/stdout" 2>&1 3<"$D/o"
  [ -s "$D/stdout" ] && bad "candor-safe-read --md5 printed output"
  got=$(tr '\n' ';' < "$D/o/md5")
  if [ "$got" = "OK $(md5sum < "$D/real/f" | cut -c1-32);ERR 10;ERR 12;" ]; then pass "safe-read --md5: digest of a safe file, status only for refused ones"
  else bad "safe-read --md5: unexpected output"; fi
  # AUD-RM2-DEP-30: OUT is created new (O_EXCL|O_NOFOLLOW|O_NONBLOCK) beneath the private fd 3.
  srout() { # name want-status out-name [fd3-dir]
    local rc
    timeout -k 1 10 "$TOOLS/candor-safe-read" "$D/real/f" "$3" 4096 "0,$me" 002 > "$D/stdout" 2>&1 3<"${4:-$D/o}"; rc=$?
    if [ "$rc" -eq "$2" ] && [ ! -s "$D/stdout" ]; then pass "candor-safe-read output: $1 (status $rc)"; else bad "candor-safe-read output: $1: status $rc, want $2"; fi
  }
  printf 'keep\n' > "$D/o/exists"; srout "existing OUT not overwritten" 15 exists
  if [ "$(cat "$D/o/exists")" = keep ]; then pass "candor-safe-read output: existing file kept"; else bad "candor-safe-read output: existing file changed"; fi
  ln -sf "$D/victim" "$D/o/sl"; srout "symlinked OUT refused" 15 sl
  if [ ! -e "$D/victim" ]; then pass "candor-safe-read output: symlink target not created"; else bad "candor-safe-read output: wrote through a symlink"; fi
  ln -sfn "$D/secretdir" "$D/o/sd"; srout "OUT beneath a symlinked directory refused" 15 sd/x
  mkfifo "$D/o/ff"; srout "FIFO at OUT refused without blocking" 15 ff
  srout "absolute OUT is a usage error" 2 "$D/o/abs"
  srout "'..' in OUT is a usage error" 2 ../escape
  srout "fd 3 not private (0755) refused" 15 out "$D/real"
  timeout -k 1 10 "$TOOLS/candor-safe-read" "$D/real/f" out 4096 "0,$me" 002 > "$D/stdout" 2>&1 3<&-; rc=$?
  if [ "$rc" -eq 15 ] && [ ! -e "$D/o/out" ]; then pass "candor-safe-read output: no fd 3, nothing written (status 15)"; else bad "candor-safe-read output: without fd 3: status $rc"; fi
  rm -f "$D/o/out" "$D/o/ff" "$D/o/sl" "$D/o/sd" "$D/o/exists"
  # AUD-RM2-DEP-31: a failing comm/uniq must never read as "no difference". Shims ahead of
  # PATH: "always" exits 2 (caught by the start-up self-test: exit 2), "late" works for the
  # self-test and fails afterwards (caught by the per-site status checks: exit 30). The
  # tree carries a pg key that only the comm allow-list comparison reports.
  SH="$T/shim"; mkdir -p "$SH"; RD="$T/dep31"; cp -a "$INTAKE" "$RD"
  printf "cluster_name = 'x'\n" >> "$RD/postgresql/candor-intake.conf"
  for tool in comm uniq; do
    real=$(command -v "$tool")
    for kind in always late; do
      rm -f "$SH"/*; printf '0\n' > "$T/shim.cnt"
      # shellcheck disable=SC2016 # shim script text
      if [ "$kind" = always ]; then printf '#!/bin/sh\nexit 2\n' > "$SH/$tool"
      else printf '#!/bin/sh\nn=$(cat "%s"); n=$((n + 1)); echo "$n" > "%s"\n[ "$n" -le 1 ] && exec %s "$@"\nexit 2\n' "$T/shim.cnt" "$T/shim.cnt" "$real" > "$SH/$tool"; fi
      chmod 0755 "$SH/$tool"
      PATH="$SH:$PATH" "$TOOLS/config-check.sh" "${CC_WB[@]}" -q --dir "$RD" > "$T/dep31.out" 2>&1; rc=$?
      if [ "$kind" = always ] && { [ "$rc" -eq 2 ] || [ "$rc" -eq 30 ]; }; then pass "DEP-31: $tool always exiting 2: config-check exit $rc (never 0)"
      elif [ "$kind" = late ] && [ "$rc" -eq 30 ] && grep -q 'comparison failed' "$T/dep31.out"; then pass "DEP-31: $tool failing after the self-test: exit 30, comparison reported as failed"
      else bad "DEP-31: $tool shim ($kind): exit $rc"; fi
    done
  done
  # DEP-32: only the reader gets a descriptor of the work directory. A tr shim records the
  # descriptors every tr child inherits.
  rm -f "$SH"/*; real=$(command -v tr)
  printf '#!/bin/sh\nls -l /proc/$$/fd/ >> "%s" 2>/dev/null\nexec %s "$@"\n' "$T/fds.log" "$real" > "$SH/tr"; chmod 0755 "$SH/tr"; : > "$T/fds.log"
  PATH="$SH:$PATH" "$TOOLS/config-check.sh" "${CC_WB[@]}" -q --dir "$INTAKE" > "$T/dep32.out" 2>&1; rc=$?
  if [ "$rc" -eq 0 ] && [ -s "$T/fds.log" ] && ! grep -qE -- '-> (/run/candor-validate-wb|/tmp/tmp\.|/run/candor-config-check)[^ ]*/run\.[A-Za-z0-9]+$' "$T/fds.log"; then
    pass "DEP-32: no non-reader child inherits the work-directory descriptor"
  else bad "DEP-32: work-directory descriptor leaked to a child, or run failed (exit $rc)"; fi
  rm -rf "$SH" "$RD"
  # DEP-30: --work-base ancestors must be root-owned, not group/world-writable, not sticky.
  if is_root; then
    wbcase() { # name base
      "$TOOLS/config-check.sh" -q --work-base "$2" --dir "$INTAKE" --only tor > "$T/wb.out" 2>&1; rc=$?
      if [ "$rc" -eq 2 ] && grep -q 'unsafe work directory base' "$T/wb.out"; then pass "config-check --work-base: $1 refused (exit 2)"; else bad "config-check --work-base: $1: exit $rc"; fi
    }
    install -d -m 0700 "$T/wbt/sub" && chmod 0755 "$T/wbt"
    wbcase "sticky world-writable ancestor (/var/tmp)" "$T/wbt/sub"
    WBN=$(mktemp -d /run/candor-validate-wbn.XXXXXX); chmod 0755 "$WBN"; install -d -m 0700 "$WBN/sub"
    chown nobody "$WBN"; wbcase "ancestor owned by another user" "$WBN/sub"
    chown 0 "$WBN"; chmod 0775 "$WBN"; wbcase "group-writable ancestor" "$WBN/sub"
    chmod 0755 "$WBN"; ln -s "$WBN" "$WBN.l"; wbcase "symlinked ancestor" "$WBN.l/sub"
    wbcase "'..' in the base" "$WBN/sub/../sub"
    "$TOOLS/config-check.sh" -q --work-base "$WBN/sub" --dir "$INTAKE" --only tor > "$T/wb.out" 2>&1; rc=$?
    if [ "$rc" -eq 0 ]; then pass "config-check --work-base: root-owned 0755 chain accepted"; else bad "config-check --work-base: safe chain: exit $rc"; fi
    rm -rf "$WBN" "$WBN.l"
  fi
  # Live races against config-check itself (static mode; the genuine state is broken on
  # purpose, so every run must end in exit 30; the marker must never appear; no run may hang).
  if is_root; then
    RD="$T/race1"; cp -a "$INTAKE" "$RD"; sed -i 's|^track_counts = off|track_counts = on|' "$RD/postgresql/candor-intake.conf"
    mkdir -p "$T/race1.secret"; printf 'CANDORLEAKMARKER = 1\n' > "$T/race1.secret/candor-intake.conf"; cp "$T/race1.secret/candor-intake.conf" "$T/race1.secret/pg_hba.conf"
    ( while :; do mv -T "$RD/postgresql" "$RD/pg.real" 2>/dev/null; ln -s "$T/race1.secret" "$RD/postgresql" 2>/dev/null; rm -f "$RD/postgresql"; mv -T "$RD/pg.real" "$RD/postgresql" 2>/dev/null; done ) &
    sw=$!; badrun=""
    for i in $(seq 1 25); do
      timeout -k 5 60 "$TOOLS/config-check.sh" "${CC_WB[@]}" -q --dir "$RD" --only pg > "$T/race.out" 2>&1; rc=$?
      if [ "$rc" -ne 30 ] || grep -q CANDORLEAKMARKER "$T/race.out"; then badrun="run $i exit $rc"; break; fi
    done
    kill "$sw" 2>/dev/null; wait "$sw" 2>/dev/null
    if [ -z "$badrun" ]; then pass "config-check under a parent-directory symlink swap race: 25 runs, all exit 30, nothing leaked"; else bad "config-check parent-dir swap race: $badrun"; fi
    RD="$T/race2"; cp -a "$INTAKE" "$RD"; sed 's|^SafeLogging 1$|SafeLogging 0|' "$INTAKE/torrc" > "$T/race2.torrc"
    ( while :; do rm -f "$RD/torrc.f"; mkfifo "$RD/torrc.f" && mv -f "$RD/torrc.f" "$RD/torrc"; cp "$T/race2.torrc" "$RD/torrc.n" && mv -f "$RD/torrc.n" "$RD/torrc"; done ) &
    sw=$!; badrun=""
    for i in $(seq 1 10); do
      timeout -k 5 60 "$TOOLS/config-check.sh" "${CC_WB[@]}" -q --dir "$RD" --only tor > "$T/race.out" 2>&1; rc=$?
      if [ "$rc" -ne 30 ]; then badrun="run $i exit $rc"; break; fi
    done
    kill "$sw" 2>/dev/null; wait "$sw" 2>/dev/null
    if [ -z "$badrun" ]; then pass "config-check under a FIFO swap race: 10 runs, all exit 30, none blocked"; else bad "config-check FIFO swap race: $badrun (124 = hung)"; fi
    # Deterministic end-to-end: a FIFO in place of the torrc fails at once.
    RD="$T/race3"; cp -a "$INTAKE" "$RD"; rm -f "$RD/torrc"; mkfifo "$RD/torrc"
    timeout -k 5 60 "$TOOLS/config-check.sh" "${CC_WB[@]}" -q --dir "$RD" --only tor > "$T/race.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ]; then pass "config-check: torrc replaced by a FIFO fails with exit 30 (no hang)"; else bad "config-check FIFO torrc: exit $rc"; fi
    # Unknown torrc option names are counted, never echoed (AUD-RM2-DEP-24).
    RD="$T/race4"; cp -a "$INTAKE" "$RD"; printf 'CANDORLEAKMARKERxyz 1\n' >> "$RD/torrc"
    timeout -k 5 60 "$TOOLS/config-check.sh" "${CC_WB[@]}" -q --dir "$RD" --only tor > "$T/race.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && ! grep -q CANDORLEAKMARKER "$T/race.out"; then pass "config-check: unknown torrc option rejected, its name not printed"; else bad "config-check unknown torrc option: exit $rc or name printed"; fi
  else skip "config-check race tests (need root)"; fi
else bad "candor-safe-read tests: binary missing (tools/build-safe-read.sh) or no timeout/mkfifo"; fi

# ---- AUD-RM2-DEP-21: invocation and policy integrity
cc -q --dir "$INTAKE" --only typo >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then pass "config-check rejects --only with an unknown section (exit 2)"; else bad "config-check --only typo: exit $rc, want 2"; fi
cc -q --dir "$INTAKE" --only tor,typo >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then pass "config-check rejects --only tor,typo (exit 2)"; else bad "config-check --only tor,typo: exit $rc, want 2"; fi
cc -q --dir "$INTAKE" --only host >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then pass "config-check: a selection that runs no check is an error (static --only host, exit 2)"; else bad "config-check static --only host: exit $rc, want 2"; fi
mkdir -p "$T/tools.b" "$T/tools.m"
cp -p "$TOOLS/config-check.sh" "$TOOLS/config-check.baseline" "$TOOLS/config-check.manifest" "$TOOLS/candor-safe-read" "$T/tools.b/"
cp -p "$TOOLS/config-check.sh" "$TOOLS/config-check.baseline" "$TOOLS/config-check.manifest" "$TOOLS/candor-safe-read" "$T/tools.m/"
# Baseline edited (a weakened allow-list line): the manifest digest no longer matches.
sed -i 's/^pg|track_counts|b|off$/pg|track_counts|b|on/' "$T/tools.b/config-check.baseline"
"$T/tools.b/config-check.sh" "${CC_WB[@]}" -q --dir "$INTAKE" > "$T/int.out" 2>&1; rc=$?
if [ "$rc" -eq 30 ] && grep -q 'tool.baseline_integrity' "$T/int.out"; then pass "config-check rejects an edited baseline (digest, exit 30)"; else bad "edited baseline: exit $rc"; fi
# Baseline and manifest edited together: the manifest digest pinned in the script catches it.
sed -i 's/^pg|track_counts|b|off$/pg|track_counts|b|on/' "$T/tools.m/config-check.baseline"
printf '%s  config-check.baseline\n%s  candor-safe-read\n' "$(sha256sum < "$T/tools.m/config-check.baseline" | cut -c1-64)" "$(sha256sum < "$T/tools.m/candor-safe-read" | cut -c1-64)" > "$T/tools.m/config-check.manifest"
"$T/tools.m/config-check.sh" "${CC_WB[@]}" -q --dir "$INTAKE" > "$T/int.out" 2>&1; rc=$?
if [ "$rc" -eq 30 ] && grep -q 'tool.baseline_integrity' "$T/int.out"; then pass "config-check rejects a re-signed manifest (pinned digest, exit 30)"; else bad "re-written manifest: exit $rc"; fi
# AUD-RM2-DEP-17: the private work directories are gone after all runs above.
if is_root; then
  if [ -z "$(find "$WB" -mindepth 1 -maxdepth 1 2>/dev/null)" ] && [ "$(stat -c '%u %a' "$WB" 2>/dev/null)" = "0 700" ]; then
    pass "config-check work base (this run's own, DEP-27) is root 0700 and every run cleaned up after itself"
  else bad "config-check left work directories behind or the work base is not root 0700"; fi
fi

# ---- W1-D / O-6: blob volume throughput (config-check --host section blobrate, STO-29 floor)
# The measurement needs root, a real filesystem (ext4/xfs; $T is on /var/tmp) and a few seconds.
if is_root; then
  V="$T/vol"; rm -rf "$V"; install -d -m 0700 "$V" "$V/selftest" "$V/intake" "$V/intake/blobs"
  case "$(stat -f -c %T "$V")" in
    ext2/ext3|ext4|xfs)
      # Positive: the floor is lowered to 1 MB/s so the result does not depend on this CI disk;
      # the measured rate is reported, and a second run checks the shipped 50 MB/s floor.
      if cc --host --only blobrate --blob-root "$V" --blob-mib 64 --blob-min-rate 1 > "$T/br.out" 2>&1 && grep -q 'host.blob_volume_rate.*OK' "$T/br.out"; then
        pass "config-check --host blobrate: $(sed -n 's/.*OK *\([0-9]* MB\/s\).*/\1/p' "$T/br.out" | head -n 1) over 64 MiB write+fsync (floor 1 MB/s)"
      else bad "config-check --host blobrate positive case: $(tail -n 2 "$T/br.out")"; fi
      if cc -q --host --only blobrate --blob-root "$V" --blob-mib 64 > "$T/br.out" 2>&1; then pass "config-check --host blobrate: this disk meets the shipped 50 MB/s floor"
      else skip "config-check --host blobrate: this CI disk is below the 50 MB/s floor (not a config defect): $(grep -o '[0-9]* MB/s sequential' "$T/br.out" | head -n 1)"; fi
      if [ -z "$(ls -A "$V/selftest")" ]; then pass "blobrate: test file removed"; else bad "blobrate: test file left behind"; fi
      # Negatives: each must FAIL (exit 30) with the named rule, never write outside selftest.
      brneg() { # name expect-detail args... (on a fresh copy of the volume layout)
        local name=$1 want=$2; shift 2
        if cc -q --host --only blobrate "$@" > "$T/br.out" 2>&1; then bad "blobrate accepted: $name (exit 0)"
        elif grep -q "host.blob_volume_rate.*FAIL.*$want" "$T/br.out"; then pass "blobrate rejects: $name"
        else bad "blobrate: $name: unexpected result: $(tail -n 2 "$T/br.out")"; fi
      }
      brneg "rate floor unattainable (100000 MB/s)" "below the 100000 MB/s floor" --blob-root "$V" --blob-mib 64 --blob-min-rate 100000
      chmod 0755 "$V/selftest"; brneg "selftest directory 0755" "root-owned 0700" --blob-root "$V" --blob-mib 64 --blob-min-rate 1; chmod 0700 "$V/selftest"
      chown nobody "$V/selftest"; brneg "selftest directory owned by nobody" "root-owned 0700" --blob-root "$V" --blob-mib 64 --blob-min-rate 1; chown root "$V/selftest"
      mv "$V/selftest" "$V/st.real"; ln -s "$V/st.real" "$V/selftest"; brneg "selftest is a symlink" "symlinked" --blob-root "$V" --blob-mib 64 --blob-min-rate 1; rm "$V/selftest"; mv "$V/st.real" "$V/selftest"
      mv "$V/intake/blobs" "$V/blobs.off"; brneg "blob directory missing" "missing directory" --blob-root "$V" --blob-mib 64 --blob-min-rate 1; mv "$V/blobs.off" "$V/intake/blobs"
      rm -rf "$V/selftest"; brneg "selftest directory missing" "missing directory" --blob-root "$V" --blob-mib 64 --blob-min-rate 1; install -d -m 0700 "$V/selftest"
      if [ -d /run ] && [ "$(stat -f -c %T /run)" = tmpfs ]; then
        TV=$(mktemp -d /run/candor-validate-vol.XXXXXX); chmod 0700 "$TV"; install -d -m 0700 "$TV/selftest" "$TV/intake/blobs"
        brneg "blob root on tmpfs (compressible/RAM, not the volume)" "unsupported filesystem" --blob-root "$TV" --blob-mib 64 --blob-min-rate 1
        rm -rf "$TV"
      fi
      rm -rf "$V"
      ;;
    *) skip "blobrate measurement: $T is not on ext4/xfs" ;;
  esac
  # Argument hygiene and modes (exit 2 = usage, never a green run).
  for a in "--blob-mib 32" "--blob-mib 2048" "--blob-mib 64x" "--blob-min-rate 0" "--blob-min-rate 100001" "--blob-root var/lib/candor" "--blob-root /var/lib/../candor" "--blob-root /var//candor"; do
    # shellcheck disable=SC2086 # intentional word splitting of the option pair
    if cc -q --host --only blobrate $a > "$T/br.out" 2>&1; then bad "blobrate accepted invalid option: $a"; elif [ $? -eq 2 ] || grep -q '^config-check: ' "$T/br.out"; then pass "blobrate refuses invalid option: $a (exit 2)"; else bad "blobrate: $a: unexpected exit"; fi
  done
  if cc -q --only blobrate --dir "$INTAKE" > "$T/br.out" 2>&1; then bad "blobrate ran in static mode"; else pass "blobrate is host-only (static --only blobrate: exit $?, no green run)"; fi
  if cc -q --host --root "$HR" --only blobrate > "$T/br.out" 2>&1 && grep -q 'host.blob_volume_rate.*SKIP' "$T/br.out"; then pass "blobrate: offline --root reports SKIP (not measured)"; else bad "blobrate: offline --root: $(tail -n 1 "$T/br.out")"; fi
else skip "blobrate cases (need root)"; fi

# ------------------------------------------------------------------------- 3./4. systemd-analyze
UNITS=(tor@candor-intake.service candor-intake-web.service candor-sealer.service candor-intake-store.service candor-intake-pg.service
       candor-intake-web.socket candor-sealer.socket candor-intake-store.socket candor-intake-store-relay.socket run-candor-staging.mount
       candor-intake-vacuum.service candor-intake-vacuum.timer candor-intake-maint.service candor-intake-maint.timer)
if have systemd-analyze; then
  for u in "${UNITS[@]}"; do
    out=$(SYSTEMD_LOG_LEVEL=warning systemd-analyze verify --man=no --recursive-errors=no "$INTAKE/systemd/$u" 2>&1 |
          grep -v '^$' | grep -vE "Command /usr/lib/candor/(source-web/candor-web|sealer/candor-sealer|intake-store/candor-intake-store|intake-store/candor-intake-maint) is not executable: No such file or directory" |
          grep -vE "Unknown key name 'PrivatePIDs'" || true)
    if [ -z "$out" ]; then pass "systemd-analyze verify $u"; else bad "systemd-analyze verify $u: $out"; fi
  done
  for u in candor-intake-web.service:5 candor-sealer.service:5 candor-intake-store.service:5 candor-intake-pg.service:5 tor@candor-intake.service:15 candor-intake-vacuum.service:5 candor-intake-maint.service:5; do
    name=${u%%:*}; thr=${u##*:}
    score=$(systemd-analyze security --offline=true --no-pager "$INTAKE/systemd/$name" 2>/dev/null | sed -n 's/.*Overall exposure level for .*: \([0-9.]*\) .*/\1/p')
    if systemd-analyze security --offline=true --threshold="$thr" --no-pager "$INTAKE/systemd/$name" >/dev/null 2>&1; then
      pass "systemd-analyze security $name: exposure $score (budget $((thr / 10)).$((thr % 10)))"
    else
      bad "systemd-analyze security $name: exposure $score over budget $((thr / 10)).$((thr % 10))"
    fi
  done
else skip "systemd-analyze not installed"; fi

# ------------------------------------------------------------------------- 5. nft
if have nft && is_root && users_exist; then
  if nft -c -f "$INTAKE/nftables.conf"; then pass "nft -c -f nftables.conf"; else bad "nft -c -f nftables.conf"; fi
else skip "nft -c (needs nft, root and the sysusers.d users)"; fi

# ------------------------------------------------------------------------- 6. AppArmor
if have apparmor_parser; then
  for p in "$INTAKE"/apparmor/*; do
    # AUD-RM2-DEP-12: the parser's exit status decides; any stderr other than the container's
    # cache notice is a failure too.
    apparmor_parser -Q -K -T "$p" >/dev/null 2>"$T/aa.err"; rc=$?
    if [ "$rc" -ne 0 ]; then bad "apparmor_parser $(basename "$p"): exit $rc: $(head -c 300 "$T/aa.err")"
    elif grep -v 'Cache read/write disabled' "$T/aa.err" | grep -q .; then bad "apparmor_parser $(basename "$p"): $(head -c 300 "$T/aa.err")"
    else pass "apparmor_parser $(basename "$p") (exit 0)"; fi
  done
else skip "apparmor_parser not installed"; fi

# ------------------------------------------------------------------------- 7. tor
if have tor; then
  if tor --list-modules 2>/dev/null | grep -qx 'pow: yes'; then pass "tor built with PoW (pow: yes)"; else bad "tor built without PoW"; fi
  cp "$INTAKE/torrc" "$T/torrc"; chmod 0644 "$T/torrc"
  if is_root && getent passwd _tor-candor-intake >/dev/null && have setpriv; then
    run=(setpriv --reuid=_tor-candor-intake --regid=_tor-candor-intake --clear-groups)
  else run=(); fi
  if "${run[@]}" tor --defaults-torrc /dev/null -f "$T/torrc" --verify-config >"$T/tor.out" 2>&1; then
    pass "tor --verify-config ($(tor --version | head -n 1))"
  else bad "tor --verify-config: $(tail -n 3 "$T/tor.out")"; fi
else skip "tor not installed"; fi

# ------------------------------------------------------------------------- 8. check-placement
if is_root && users_exist; then
  CP="$TOOLS/check-placement.sh"; M="$INTAKE/secret-placement.toml"
  mkroot() { # fresh synthetic host root with every required secret in place
    R="$T/root"; rm -rf "$R"
    mkdir -p "$R/etc/credstore.encrypted" "$R/var/lib/tor-instances/candor-intake/hs-source" \
             "$R/var/lib/candor/intake/blobs/ab" "$R/run/candor/staging" "$R/etc/ssh" "$R/root" "$R/etc/ssl/private"
    chmod 0700 "$R/etc/credstore.encrypted" "$R/var/lib/tor-instances/candor-intake/hs-source"
    local k="$R/var/lib/tor-instances/candor-intake/hs-source/hs_ed25519_secret_key"
    { printf '== ed25519v1-secret: type0 ==\0\0\0'; head -c 64 /dev/urandom; } > "$k"
    chown _tor-candor-intake:_tor-candor-intake "$k"; chmod 0600 "$k"
    local n
    for n in routing_key batch_signing_key relay_tls_key sealer_signing_key argon2_salt; do
      head -c 256 /dev/urandom > "$R/etc/credstore.encrypted/candor-intake.$n.cred"
      chmod 0400 "$R/etc/credstore.encrypted/candor-intake.$n.cred"
    done
    head -c 64 /dev/urandom > "$R/var/lib/candor/intake/blobs/ab/abcdefghijklmnopqrstuvwxyz"
    head -c 64 /dev/urandom > "$R/run/candor/staging/abcdefghijklmnopqrstuvwx23"
  }
  pem() { printf -- '-----BEGIN %sPRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END %sPRIVATE KEY-----\n' "$1" "$1"; }
  placement() { # name expected-exit [extra args...]
    local name=$1 want=$2; shift 2
    "$CP" -q --manifest "$M" --root "$R" "$@" > "$T/cp.out" 2>&1
    local rc=$?
    if [ "$rc" -eq "$want" ]; then pass "check-placement: $name (exit $rc)"; else bad "check-placement: $name: exit $rc, want $want: $(head -n 3 "$T/cp.out")"; fi
  }
  mkroot; placement "clean host, full scan" 0 --mode full
  mkroot; placement "clean host, light scan" 0 --mode light
  mkroot; cp "$R/var/lib/tor-instances/candor-intake/hs-source/hs_ed25519_secret_key" "$R/root/onion-backup"
          placement "onion key copy outside HiddenServiceDir (NET-043)" 30 --mode full
  mkroot; pem "" > "$R/etc/ssl/private/site.key"; placement "unlisted PEM private key" 30 --mode light
  mkroot; pem "OPENSSH " > "$R/etc/ssh/ssh_host_ed25519_key"; chmod 0600 "$R/etc/ssh/ssh_host_ed25519_key"
          placement "ssh host key without sshd flag" 30 --mode light
          placement "ssh host key with sshd flag" 0 --mode light --flags sshd
  mkroot; chmod 0640 "$R/var/lib/tor-instances/candor-intake/hs-source/hs_ed25519_secret_key"
          placement "onion key mode 0640" 30
  mkroot; chown root "$R/var/lib/tor-instances/candor-intake/hs-source/hs_ed25519_secret_key"
          placement "onion key wrong owner" 30
  mkroot; chmod 0750 "$R/var/lib/tor-instances/candor-intake/hs-source"; placement "HiddenServiceDir 0750" 30
  mkroot; rm "$R/etc/credstore.encrypted/candor-intake.routing_key.cred"; placement "routing key missing" 30
  mkroot; mv "$R/etc/credstore.encrypted/candor-intake.argon2_salt.cred" "$R/root/salt"
          ln -s /root/salt "$R/etc/credstore.encrypted/candor-intake.argon2_salt.cred"; placement "credential is a symlink" 30
  mkroot; ln "$R/etc/credstore.encrypted/candor-intake.sealer_signing_key.cred" "$R/root/hardlink"
          placement "credential hard-linked elsewhere" 30
  mkroot; printf '%s:descriptor:x25519:%s\n' "$(printf 'a%.0s' $(seq 56))" "$(printf 'A%.0s' $(seq 52))" > "$R/root/staff.auth_private"
          placement "tor client-auth private key" 30
  mkroot; printf 'AGE-SECRET-KEY-1%s\n' "$(printf 'Q%.0s' $(seq 58))" > "$R/root/id.age"; placement "age identity" 30
  mkroot; printf '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}\n' > "$R/root/k.jwk"
          placement "JWK private key" 30
  mkroot; printf -- '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' > "$R/root/k.asc"; placement "OpenPGP secret key" 30
  mkroot; : > "$R/root/bundle.p12"; placement "PKCS#12 by name" 30
  mkroot; echo plaintext > "$R/var/lib/candor/intake/blobs/notes.txt"; placement "unexpected file in blob dir" 30
  mkroot; ln -s /etc/passwd "$R/run/candor/staging/abcdefghijklmnopqrstuvwx22"; placement "symlink in staging" 30
  mkroot; mkdir "$R/run/candor/staging/sub"; placement "subdirectory in staging" 30
  # AUD-RM2-DEP-10: forbidden manifest id, symlinked parent directory, exported key format.
  mkroot; sed 's|^id = "intake.routing_key"$|id = "onion.standby_key"|' "$M" > "$T/forb.toml"
          "$CP" -q --manifest "$T/forb.toml" --root "$R" > "$T/cp.out" 2>&1; rc=$?
          if [ "$rc" -eq 30 ]; then pass "check-placement: forbidden id in manifest (exit 30)"; else bad "check-placement: forbidden id exit $rc"; fi
  mkroot; mkdir -p "$R/srv/plain"; mv "$R/var/lib/tor-instances/candor-intake" "$R/srv/plain/"
          ln -s /srv/plain/candor-intake "$R/var/lib/tor-instances/candor-intake"; placement "tor state dir moved behind a symlink" 30
  mkroot; printf 'ED25519-V3:%s==\n' "$(printf 'A%.0s' $(seq 86))" > "$R/root/onion-export.txt"; placement "ED25519-V3 exported onion key" 30
  mkroot; printf 'manifest_version = 1\nrole = "intake"\nevil = "x"\n' > "$T/bad.toml"
          "$CP" -q --manifest "$T/bad.toml" --root "$R" >/dev/null 2>&1; rc=$?
          if [ "$rc" -eq 2 ]; then pass "check-placement: malformed manifest rejected (exit 2)"; else bad "check-placement: malformed manifest exit $rc"; fi
  mkroot; sed 's|^path = "/etc/credstore.encrypted/candor-intake.routing_key.cred"|path = "/etc/../etc/x"|' "$M" > "$T/bad2.toml"
          "$CP" -q --manifest "$T/bad2.toml" --root "$R" >/dev/null 2>&1; rc=$?
          if [ "$rc" -eq 2 ]; then pass "check-placement: '..' path in manifest rejected (exit 2)"; else bad "check-placement: '..' path exit $rc"; fi
else skip "check-placement tests (need root and the sysusers.d users)"; fi

# ------------------------------------------------------------------------- 9. PostgreSQL
PGBIN=/usr/lib/postgresql/16/bin
if [ -n "${CANDOR_TEST_PG:-}" ] && is_root && users_exist && [ -x "$PGBIN/initdb" ] && getent passwd pgtest >/dev/null; then
  P="$T/pg"; mkdir -p "$P/sock" "$P/etc"
  cp "$INTAKE/postgresql/pg_ident.conf" "$P/etc/"
  # Installer step (ADR-054, DEP-25): the placeholder becomes the one tenant database name.
  sed 's/candor_intake_TENANT/candor_intake_t1/' "$INTAKE/postgresql/pg_hba.conf" > "$P/etc/pg_hba.conf"
  chown -R pgtest "$P"; chgrp candor-istore "$P/sock"; chmod 0750 "$P/sock"
  # The cluster lives inside a synthetic root (config-check --host --root resolves the data
  # directory inside the root only and refuses symlinked components, AUD-RM2-DEP-17).
  PR="$T/pgroot"; DD="$PR/var/lib/postgresql/16/candor-intake"
  mkdir -p "$PR/etc/candor/intake/postgresql" "$PR/var/lib/postgresql/16"
  chmod 0755 "$PR" "$PR/var" "$PR/var/lib" "$PR/var/lib/postgresql"; chown pgtest "$PR/var/lib/postgresql/16"
  # Second socket directory at the configured path inside the synthetic root, so config-check
  # --host --root --pg-db reaches this server the way the maintenance jobs do.
  mkdir -p "$PR/run/candor/intake-pg"; chmod 0755 "$PR/run" "$PR/run/candor"; chown pgtest:candor-istore "$PR/run/candor/intake-pg"; chmod 0750 "$PR/run/candor/intake-pg"
  sed -e "s#/var/lib/postgresql/16/candor-intake#$DD#; s#/etc/candor/intake/postgresql/#$P/etc/#; s#^unix_socket_directories = .*#unix_socket_directories = '$P/sock,$PR/run/candor/intake-pg'#; s#^unix_socket_group = .*#unix_socket_group = 'candor-istore'#" \
      "$INTAKE/postgresql/candor-intake.conf" > "$P/test.conf"
  chown pgtest "$P/test.conf"
  if su -s /bin/sh pgtest -c "$PGBIN/initdb -D '$DD' -U postgres -A reject --data-checksums" >/dev/null 2>&1; then
    # AUD-RM2-STO-11 installer step: cumulative statistics in RAM (pg_stat -> tmpfs dir; the
    # target does not exist on this test host, so nothing is written at shutdown either).
    mv "$DD/pg_stat" "$P/pg_stat.initdb" && ln -s /run/candor/intake-pg-stat "$DD/pg_stat" && chown -h pgtest "$DD/pg_stat"
    # Provisioning as the store specifies it (crate SPEC-NOTES "Database ownership"; lead
    # decision 2026-10-01): candor_intake_maint OWNS the database, owns no table, and is in no
    # role but pg_checkpoint (INHERIT TRUE, SET FALSE) - never in the schema owner.
    pgsingle() { # database, statements on stdin
      su -s /bin/sh pgtest -c "$PGBIN/postgres --single -c config_file='$P/test.conf' $1" >/dev/null 2>&1
    }
    printf '%s\n' 'CREATE ROLE candor_istore LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;' \
      'CREATE ROLE candor_intake_maint LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;' \
      'CREATE ROLE candor_intake_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;' \
      'CREATE DATABASE candor_intake_t1 OWNER candor_intake_maint;' \
      'GRANT pg_checkpoint TO candor_intake_maint WITH INHERIT TRUE, SET FALSE;' | pgsingle postgres
    printf '%s\n' 'GRANT CREATE ON SCHEMA public TO candor_istore;' | pgsingle candor_intake_t1
    pgstart() {
      su -s /bin/sh pgtest -c "$PGBIN/postgres -c config_file='$P/test.conf'" >>"$P/log" 2>&1 &
      for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$P/sock/.s.PGSQL.5432" ] && break; sleep 1; done
    }
    pgstop() { # this cluster only (AUD-RM2-DEP-12): its postmaster PID
      local pgpid
      pgpid=$(head -n 1 "$DD/postmaster.pid" 2>/dev/null)
      case "$pgpid" in ''|*[!0-9]*) bad "pg: no postmaster.pid" ;; *) kill -INT "$pgpid" 2>/dev/null; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pgpid" 2>/dev/null || break; sleep 1; done ;; esac
    }
    pgstart
    q() { su -s /bin/sh "$1" -c "psql -X -h '$P/sock' -U '$2' -d '$3' -Atc \"$4\"" 2>/dev/null; }
    got=$(q candor-istore candor_istore candor_intake_t1 "select string_agg(name||'='||setting, ',' order by name) from pg_settings where name in ('wal_level','archive_mode','max_wal_senders','track_commit_timestamp','listen_addresses','log_connections','log_statement','log_line_prefix','log_checkpoints','logging_collector','jit','max_wal_size','min_wal_size','wal_recycle','autovacuum','track_counts','track_activities','temp_file_limit')")
    want="archive_mode=off,autovacuum=off,jit=off,listen_addresses=,log_checkpoints=off,log_connections=off,log_line_prefix=%e ,log_statement=none,logging_collector=off,max_wal_senders=0,max_wal_size=256,min_wal_size=32,temp_file_limit=262144,track_activities=off,track_commit_timestamp=off,track_counts=off,wal_level=minimal,wal_recycle=off"
    if [ "$got" = "$want" ]; then pass "PostgreSQL effective settings"; else bad "PostgreSQL settings: $got"; fi
    if [ -z "$(q candor-istore candor_istore postgres 'select 1')" ]; then pass "pg: candor_istore limited to candor_intake_* databases"; else bad "pg: candor_istore reached postgres db"; fi
    if [ -z "$(q candor-istore postgres postgres 'select 1')" ]; then pass "pg: peer map refuses role switch"; else bad "pg: candor-istore became postgres"; fi
    if [ -z "$(q postgres postgres postgres "select 1")" ]; then pass "pg: superuser has no socket access (09 §10)"; else bad "pg: postgres connected"; fi
    if [ -z "$(q candor-web candor_istore candor_intake_t1 'select 1')" ]; then pass "pg: other OS users cannot reach the socket"; else bad "pg: candor-web connected"; fi
    # AUD-RM2-STO-02: with log_min_messages = panic the server writes nothing at all, even after
    # rejected connections and a deliberate error (unique violation on the expected path).
    q candor-istore candor_istore candor_intake_t1 "create table t(k int primary key); insert into t values (1); insert into t values (1)" >/dev/null
    if [ -s "$P/log" ]; then bad "pg: server emitted log output: $(head -c 200 "$P/log" | tr -c '[:print:]' '?')"; else pass "pg: no server log output at all (errors and rejected connections included)"; fi
    # config-check --host: effective settings via `postgres -C` (AUD-RM2-DEP-03(1)), on a
    # synthetic root whose data directory is this cluster's.
    cp "$INTAKE/postgresql/"* "$PR/etc/candor/intake/postgresql/"; cp "$P/etc/pg_hba.conf" "$PR/etc/candor/intake/postgresql/pg_hba.conf"; chmod 0755 "$PR/etc" "$PR/etc/candor" "$PR/etc/candor/intake" "$PR/etc/candor/intake/postgresql"; chmod 0644 "$PR/etc/candor/intake/postgresql/"*
    if cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; then pass "config-check --host pg: effective settings (postgres -C) match, stats in RAM, maintenance role is DB owner only"
    else bad "config-check --host pg on a clean cluster: $(grep ' FAIL ' "$T/pgc.out" | head -n 3 | tr -s ' ')"; fi
    if q candor-imaint candor_intake_maint candor_intake_t1 'select 1' | grep -qx 1; then bad "pg: candor-imaint connected without the socket group"; else pass "pg: maintenance login needs the socket group (SupplementaryGroups=candor-istore)"; fi
    qm() { setpriv --reuid=candor-imaint --regid=candor-imaint --groups="$(getent group candor-istore | cut -d: -f3)" -- psql -X -h "$P/sock" -U "$1" -d candor_intake_t1 -Atc 'select 1' 2>/dev/null; }
    if [ "$(qm candor_intake_maint)" = 1 ]; then pass "pg: candor-imaint (with the socket group) logs in as candor_intake_maint"; else bad "pg: maintenance login failed"; fi
    if [ -z "$(qm candor_istore)" ] && [ -z "$(qm candor_intake_migrator)" ]; then pass "pg: candor-imaint maps to candor_intake_maint only"; else bad "pg: candor-imaint became another role"; fi
    cc -q --host --root "$PR" --only pg > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.maint_role .*--pg-db' "$T/pgc.out"; then pass "config-check rejects: running server checked without --pg-db (exit 30)"; else bad "config-check without --pg-db on a running server: exit $rc"; fi
    # AUD-RM2-STO-11: pg_stat as a real directory (stats file persisted on disk) is rejected.
    mv "$DD/pg_stat" "$P/pg_stat.link"; mkdir "$DD/pg_stat"
    cc -q --host --root "$PR" --only pg > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.stats_in_ram' "$T/pgc.out"; then pass "config-check rejects: pg_stat on the data volume (exit 30)"; else bad "config-check accepted pg_stat on disk (exit $rc)"; fi
    rmdir "$DD/pg_stat"; mv "$P/pg_stat.link" "$DD/pg_stat"
    # AUD-RM2-DEP-17: a data directory reached through a symlink inside --root is refused.
    mkdir -p "$T/pgroot2/etc/candor/intake" "$T/pgroot2/var/lib/postgresql/16"; cp -a "$PR/etc/candor/intake/postgresql" "$T/pgroot2/etc/candor/intake/"
    chmod 0755 "$T/pgroot2" "$T/pgroot2/etc" "$T/pgroot2/etc/candor" "$T/pgroot2/etc/candor/intake" "$T/pgroot2/var" "$T/pgroot2/var/lib" "$T/pgroot2/var/lib/postgresql" "$T/pgroot2/var/lib/postgresql/16"
    ln -s "$DD" "$T/pgroot2/var/lib/postgresql/16/candor-intake"
    cc -q --host --root "$T/pgroot2" --only pg > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'symlinked component' "$T/pgc.out"; then pass "config-check rejects: data directory behind a symlink in --root (exit 30)"; else bad "config-check followed a symlinked data directory (exit $rc)"; fi
    printf "log_statement = 'all'\n" >> "$DD/postgresql.auto.conf"
    cc -q --host --root "$PR" --only pg > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.effective.log_statement' "$T/pgc.out"; then pass "config-check rejects: ALTER SYSTEM log_statement=all in postgresql.auto.conf (exit 30)"
    else bad "config-check accepted postgresql.auto.conf override (exit $rc)"; fi
    : > "$DD/postgresql.auto.conf"; chown pgtest "$DD/postgresql.auto.conf"
    # AUD-RM2-DEP-25: installer placeholder left in place, or pg_hba naming another database.
    HBA="$PR/etc/candor/intake/postgresql/pg_hba.conf"; cp "$HBA" "$T/hba.good"
    cp "$INTAKE/postgresql/pg_hba.conf" "$HBA"
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.hba_database' "$T/pgc.out"; then pass "config-check rejects: pg_hba placeholder left on a host (exit 30)"; else bad "config-check accepted the pg_hba placeholder on a host (exit $rc)"; fi
    sed 's/candor_intake_t1/candor_intake_t2/' "$T/hba.good" > "$HBA"
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.hba_database' "$T/pgc.out"; then pass "config-check rejects: pg_hba names another database than --pg-db (exit 30)"; else bad "config-check accepted pg_hba for another database (exit $rc)"; fi
    cp "$T/hba.good" "$HBA"
    # The owner's DoS levers (live, as the maintenance login itself): ALTER DATABASE ... SET and
    # CONNECTION LIMIT.
    setpriv --reuid=candor-imaint --regid=candor-imaint --groups="$(getent group candor-istore | cut -d: -f3)" -- psql -X -q -h "$P/sock" -U candor_intake_maint -d candor_intake_t1 -c 'ALTER DATABASE candor_intake_t1 SET statement_timeout = 0' >/dev/null 2>&1
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.maint_role.no_database_settings' "$T/pgc.out"; then pass "config-check rejects: ALTER DATABASE ... SET by the owner (exit 30)"; else bad "config-check accepted ALTER DATABASE SET (exit $rc)"; fi
    setpriv --reuid=candor-imaint --regid=candor-imaint --groups="$(getent group candor-istore | cut -d: -f3)" -- psql -X -q -h "$P/sock" -U candor_intake_maint -d candor_intake_t1 -c 'ALTER DATABASE candor_intake_t1 RESET ALL' -c 'ALTER DATABASE candor_intake_t1 CONNECTION LIMIT 5' >/dev/null 2>&1
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.maint_role.db_connlimit' "$T/pgc.out" && ! grep -q 'no_database_settings.*FAIL\|FAIL.*no_database_settings' "$T/pgc.out"; then pass "config-check rejects: database CONNECTION LIMIT set by the owner (exit 30)"; else bad "config-check accepted a database connection limit (exit $rc)"; fi
    setpriv --reuid=candor-imaint --regid=candor-imaint --groups="$(getent group candor-istore | cut -d: -f3)" -- psql -X -q -h "$P/sock" -U candor_intake_maint -d candor_intake_t1 -c 'ALTER DATABASE candor_intake_t1 CONNECTION LIMIT -1' >/dev/null 2>&1
    pgstop
    printf '%s\n' 'CREATE DATABASE candor_intake_t2;' 'ALTER ROLE candor_intake_maint CONNECTION LIMIT 3;' | pgsingle postgres
    pgstart
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.maint_role.single_database' "$T/pgc.out" && grep -q 'pg.maint_role.role_connlimit' "$T/pgc.out"; then pass "config-check rejects: second intake database in the cluster and a role connection limit (ADR-054, exit 30)"
    else bad "config-check accepted a second database / role connection limit (exit $rc)"; fi
    pgstop
    printf '%s\n' 'DROP DATABASE candor_intake_t2;' 'ALTER ROLE candor_intake_maint CONNECTION LIMIT -1;' | pgsingle postgres
    pgstart
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 0 ]; then pass "config-check --host pg passes again after the DEP-25 cases were undone"; else bad "config-check after undoing DEP-25 cases: exit $rc: $(grep ' FAIL ' "$T/pgc.out" | head -n 2 | tr -s ' ')"; fi
    # Lead decision 2026-10-01: the maintenance role must never be a member of the schema
    # owner (the old SET ROLE design). Granted on a stopped cluster, then checked live.
    pgstop
    printf '%s\n' 'GRANT candor_intake_migrator TO candor_intake_maint;' | pgsingle postgres
    pgstart
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.maint_role.memberships' "$T/pgc.out"; then pass "config-check rejects: candor_intake_maint member of the schema owner role (exit 30)"
    else bad "config-check accepted maint membership in the owner role (exit $rc)"; fi
    pgstop
    printf '%s\n' 'REVOKE candor_intake_migrator FROM candor_intake_maint;' 'ALTER DATABASE candor_intake_t1 OWNER TO candor_istore;' | pgsingle postgres
    pgstart
    cc -q --host --root "$PR" --only pg --pg-db candor_intake_t1 > "$T/pgc.out" 2>&1; rc=$?
    if [ "$rc" -eq 30 ] && grep -q 'pg.maint_role' "$T/pgc.out"; then pass "config-check rejects: tenant database not owned by the maintenance role (exit 30)"
    else bad "config-check accepted a database not owned by candor_intake_maint (exit $rc)"; fi
    pgstop
  else bad "initdb failed"; fi
else skip "PostgreSQL run (set CANDOR_TEST_PG=1; needs root, users, user pgtest, $PGBIN)"; fi

if [ "$FAIL" -ne 0 ]; then echo "validate: FAILED"; exit 1; fi
echo "validate: all executed checks passed"
