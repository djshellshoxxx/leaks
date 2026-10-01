#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# validate.sh - CI / developer validation of the Z-INTAKE deployment artefacts (deploy/intake).
#
#   1. shellcheck + bash -n on deploy/tools and deploy/tests
#   2. config-check.sh on the shipped tree (must pass) and on deliberately broken copies
#      (every mutation must fail with exit 30)
#   3. systemd-analyze verify (--man=no) on every unit; only the documented expected messages
#      (missing Candor binaries at their future install paths) are tolerated
#   4. systemd-analyze security --offline --threshold per unit (R7 SI-B-01): achieved scores
#      are printed; budgets: Candor services and PostgreSQL <= 0.5, tor <= 1.5 (17 §5.3)
#   5. nft -c -f nftables.conf          (needs root and the users from sysusers.d)
#   6. apparmor_parser -Q -K profiles   (parse/compile only, nothing loaded)
#   7. tor --verify-config on the torrc (as _tor-candor-intake when that user exists)
#   8. check-placement.sh positive and negative cases on a synthetic root (needs root + users)
#   9. PostgreSQL: start a throw-away cluster with candor-intake.conf, check effective settings
#      and peer-only access - only when CANDOR_TEST_PG is set (needs root, the users, initdb)
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
FAIL=0
pass() { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; FAIL=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }
users_exist() { local u; for u in _tor-candor-intake _tor-candor-update candor-web candor-sealer candor-istore candor-health _chrony postgres; do getent passwd "$u" >/dev/null || return 1; done; }

# ------------------------------------------------------------------------- 1. shell lint
if have shellcheck; then
  if shellcheck -x "$TOOLS"/*.sh "$HERE"/*.sh; then pass "shellcheck"; else bad "shellcheck"; fi
else skip "shellcheck not installed"; fi
for s in "$TOOLS"/*.sh "$HERE"/*.sh; do bash -n "$s" || bad "bash -n $s"; done

# ------------------------------------------------------------------------- 2. config-check
for prof in "" ce-single ce-hardened; do
  if "$TOOLS/config-check.sh" -q --dir "$INTAKE" ${prof:+--profile "$prof"} >/dev/null; then pass "config-check: shipped files ${prof:-(base)}"
  else bad "config-check: shipped files must pass ${prof:-(base)}"; fi
done

# mutate <name> <relative file> <sed-expression | +append-text>
# Each mutation runs config-check on its own copy of the tree, in parallel (bounded).
MUTN=0
JOBS=$( (nproc 2>/dev/null || echo 2) | head -n 1)
mutate() {
  local name=$1 rel=$2 expr=$3 d
  shift 3
  MUTN=$((MUTN + 1)); d="$T/mut.$MUTN"
  cp -a "$INTAKE" "$d"
  case "$expr" in
    +*) mkdir -p "$(dirname "$d/$rel")"; printf '%s\n' "${expr#+}" >> "$d/$rel" ;;
    *)  sed -i -e "$expr" "$d/$rel" ;;
  esac
  printf '%s\n' "$name" > "$d.name"
  if cmp -s "$INTAKE/$rel" "$d/$rel"; then echo nochange > "$d.rc"; return; fi
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  ( "$TOOLS/config-check.sh" -q --dir "$d" "$@" > "$d.out" 2>&1; echo $? > "$d.rc" ) &
}
mutate_results() {
  wait
  local i rc name
  for i in $(seq 1 "$MUTN"); do
    name=$(cat "$T/mut.$i.name"); rc=$(cat "$T/mut.$i.rc" 2>/dev/null || echo none)
    if [ "$rc" = nochange ]; then bad "mutation '$name' did not change its file (test bug)"
    elif [ "$rc" = 30 ]; then pass "config-check rejects: $name ($(grep -c ' FAIL ' "$T/mut.$i.out") rule(s))"
    else bad "config-check accepted broken copy: $name (exit $rc)"; fi
  done
}
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
mutate "syscall re-allow ptrace"       systemd/candor-sealer.service 's|^SystemCallFilter=seccomp$|SystemCallFilter=seccomp ptrace|'
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
mutate "staging may swap"              systemd/run-candor-staging.mount 's|,noswap,|,|'
# journald / DNS (NET-008, LOG-007, 17 §4.5/§5.5)
mutate "journald persistent"           journald/journald@candor-intake.conf 's|^Storage=volatile$|Storage=persistent|'
mutate "journald 7 days"               journald/journald@candor-intake.conf 's|^MaxRetentionSec=24h$|MaxRetentionSec=7d|'
mutate "journald forwards to syslog"   journald/candor-intake-host.conf 's|^ForwardToSyslog=no$|ForwardToSyslog=yes|'
mutate "public DNS resolver"           resolv.conf 's|^nameserver 127.0.0.1$|nameserver 9.9.9.9|'
mutate_results

# ------------------------------------------------------------------------- 3./4. systemd-analyze
UNITS=(tor@candor-intake.service candor-intake-web.service candor-sealer.service candor-intake-store.service candor-intake-pg.service
       candor-intake-web.socket candor-sealer.socket candor-intake-store.socket candor-intake-store-relay.socket run-candor-staging.mount)
if have systemd-analyze; then
  for u in "${UNITS[@]}"; do
    out=$(SYSTEMD_LOG_LEVEL=warning systemd-analyze verify --man=no --recursive-errors=no "$INTAKE/systemd/$u" 2>&1 |
          grep -v '^$' | grep -vE "Command /usr/lib/candor/(source-web/candor-web|sealer/candor-sealer|intake-store/candor-intake-store) is not executable: No such file or directory" |
          grep -vE "Unknown key name 'PrivatePIDs'" || true)
    if [ -z "$out" ]; then pass "systemd-analyze verify $u"; else bad "systemd-analyze verify $u: $out"; fi
  done
  for u in candor-intake-web.service:5 candor-sealer.service:5 candor-intake-store.service:5 candor-intake-pg.service:5 tor@candor-intake.service:15; do
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
    if apparmor_parser -Q -K -T "$p" >/dev/null 2>"$T/aa.err" || ! grep -vq 'Cache read/write disabled' "$T/aa.err"; then
      if grep -v 'Cache read/write disabled' "$T/aa.err" | grep -q .; then bad "apparmor_parser $(basename "$p"): $(cat "$T/aa.err")"; else pass "apparmor_parser $(basename "$p")"; fi
    else bad "apparmor_parser $(basename "$p"): $(cat "$T/aa.err")"; fi
  done
else skip "apparmor_parser not installed"; fi

# ------------------------------------------------------------------------- 7. tor
if have tor; then
  if tor --list-modules 2>/dev/null | grep -qx 'pow: yes'; then pass "tor built with PoW (pow: yes)"; else bad "tor built without PoW"; fi
  cp "$INTAKE/torrc" "$T/torrc"; chmod 0644 "$T/torrc"
  if is_root && getent passwd _tor-candor-intake >/dev/null && have setpriv; then
    run=(setpriv --reuid=_tor-candor-intake --regid=_candor-torctl --clear-groups)
  else run=(); fi
  if "${run[@]}" tor --defaults-torrc /dev/null -f "$T/torrc" --verify-config >"$T/tor.out" 2>&1; then
    pass "tor --verify-config ($(tor --version | head -n 1))"
  else bad "tor --verify-config: $(tail -n 3 "$T/tor.out")"; fi
else skip "tor not installed"; fi

# ------------------------------------------------------------------------- 8. check-placement
if is_root && users_exist && getent group _candor-torctl >/dev/null; then
  CP="$TOOLS/check-placement.sh"; M="$INTAKE/secret-placement.toml"
  mkroot() { # fresh synthetic host root with every required secret in place
    R="$T/root"; rm -rf "$R"
    mkdir -p "$R/etc/credstore.encrypted" "$R/var/lib/tor-instances/candor-intake/hs-source" \
             "$R/var/lib/candor/intake/blobs/ab" "$R/run/candor/staging" "$R/etc/ssh" "$R/root" "$R/etc/ssl/private"
    chmod 0700 "$R/etc/credstore.encrypted" "$R/var/lib/tor-instances/candor-intake/hs-source"
    local k="$R/var/lib/tor-instances/candor-intake/hs-source/hs_ed25519_secret_key"
    { printf '== ed25519v1-secret: type0 ==\0\0\0'; head -c 64 /dev/urandom; } > "$k"
    chown _tor-candor-intake:_candor-torctl "$k"; chmod 0600 "$k"
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
  cp "$INTAKE/postgresql/pg_hba.conf" "$INTAKE/postgresql/pg_ident.conf" "$P/etc/"
  chown -R pgtest "$P"; chgrp candor-istore "$P/sock"; chmod 0750 "$P/sock"
  sed -e "s#/var/lib/postgresql/16/candor-intake#$P/data#; s#/etc/candor/intake/postgresql/#$P/etc/#; s#/run/candor/intake-pg#$P/sock#; s#^unix_socket_group = .*#unix_socket_group = 'candor-istore'#" \
      "$INTAKE/postgresql/candor-intake.conf" > "$P/test.conf"
  chown pgtest "$P/test.conf"
  if su -s /bin/sh pgtest -c "$PGBIN/initdb -D '$P/data' -U postgres -A reject --data-checksums" >/dev/null 2>&1; then
    printf 'CREATE ROLE candor_istore LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE DATABASE candor_intake_t1 OWNER candor_istore;\n' |
      su -s /bin/sh pgtest -c "$PGBIN/postgres --single -c config_file='$P/test.conf' postgres" >/dev/null 2>&1
    su -s /bin/sh pgtest -c "$PGBIN/postgres -c config_file='$P/test.conf'" >"$P/log" 2>&1 &
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$P/sock/.s.PGSQL.5432" ] && break; sleep 1; done
    q() { su -s /bin/sh "$1" -c "psql -X -h '$P/sock' -U '$2' -d '$3' -Atc \"$4\"" 2>/dev/null; }
    got=$(q candor-istore candor_istore candor_intake_t1 "select string_agg(name||'='||setting, ',' order by name) from pg_settings where name in ('wal_level','archive_mode','max_wal_senders','track_commit_timestamp','listen_addresses','log_connections','log_statement','log_line_prefix','log_checkpoints','logging_collector','jit')")
    want="archive_mode=off,jit=off,listen_addresses=,log_checkpoints=off,log_connections=off,log_line_prefix=%e ,log_statement=none,logging_collector=off,max_wal_senders=0,track_commit_timestamp=off,wal_level=minimal"
    if [ "$got" = "$want" ]; then pass "PostgreSQL effective settings"; else bad "PostgreSQL settings: $got"; fi
    if [ -z "$(q candor-istore candor_istore postgres 'select 1')" ]; then pass "pg: candor_istore limited to candor_intake_* databases"; else bad "pg: candor_istore reached postgres db"; fi
    if [ -z "$(q candor-istore postgres postgres 'select 1')" ]; then pass "pg: peer map refuses role switch"; else bad "pg: candor-istore became postgres"; fi
    if [ -z "$(q postgres postgres postgres "select 1")" ]; then pass "pg: superuser has no socket access (09 §10)"; else bad "pg: postgres connected"; fi
    if [ -z "$(q candor-web candor_istore candor_intake_t1 'select 1')" ]; then pass "pg: other OS users cannot reach the socket"; else bad "pg: candor-web connected"; fi
    # Unix socket only: no client address can exist; assert no connection/statement/duration lines.
    if grep -qiE 'connection (received|authorized)|statement:|duration:|select 1|pg_settings' "$P/log"; then bad "pg: log contains connection or SQL records"; else pass "pg: log free of connection records and SQL text"; fi
    pkill -INT -u pgtest -f "$PGBIN/postgres" >/dev/null 2>&1; sleep 2
  else bad "initdb failed"; fi
else skip "PostgreSQL run (set CANDOR_TEST_PG=1; needs root, users, user pgtest, $PGBIN)"; fi

if [ "$FAIL" -ne 0 ]; then echo "validate: FAILED"; exit 1; fi
echo "validate: all executed checks passed"
