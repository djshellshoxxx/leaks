#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Throwaway PostgreSQL 16 cluster for candor-case-db integration tests
# (modelled on candor-intake-store/scripts/pg-test.sh).
#
#   scripts/pg-test.sh [command...]
#
# Creates (if missing) the unprivileged OS user `pgcase`, initdb's a fresh
# cluster in a private 0700 directory, listens ONLY on a Unix socket, peer
# authentication with an ident map (no host lines, no passwords), applies the
# Case DB logging/statistics profile of 09 §10 (no SQL text, no bind values,
# track_commit_timestamp = off), exports CANDOR_TEST_PG=<socket dir>, runs the
# command (default: cargo test -p candor-case-db) and always stops and deletes
# the cluster (and an OS user it created). Test-only: production provisioning
# is 18/32. Do not run on shared hosts (it creates a system account as root).
set -euo pipefail
umask 077

PGBIN="${PGBIN:-/usr/lib/postgresql/16/bin}"
PGUSER_OS="${PGUSER_OS:-pgcase}"
PORT="${CANDOR_TEST_PG_PORT:-5433}"

if [[ ! "$PGUSER_OS" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || [[ "$PGUSER_OS" == "root" ]]; then
  echo "pg-test: invalid PGUSER_OS" >&2
  exit 2
fi
if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$PORT < 1024 || 10#$PORT > 65535 )); then
  echo "pg-test: invalid CANDOR_TEST_PG_PORT" >&2
  exit 2
fi
if [[ ! -x "$PGBIN/initdb" ]]; then
  echo "pg-test: PostgreSQL binaries not found in $PGBIN" >&2
  exit 2
fi

CREATED_USER=0
if [[ "$(id -u)" -eq 0 ]]; then
  if ! id "$PGUSER_OS" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$PGUSER_OS"
    CREATED_USER=1
  elif (( $(id -u "$PGUSER_OS") == 0 || $(id -u "$PGUSER_OS") >= 1000 )); then
    echo "pg-test: refusing to run the cluster as an existing human or root account" >&2
    exit 2
  fi
  RUN=(runuser -u "$PGUSER_OS" --)
  CLIENT_OS="root"
else
  PGUSER_OS="$(id -un)"
  RUN=()
  CLIENT_OS="$PGUSER_OS"
fi

BASE="$(mktemp -d /tmp/candor-casetest.XXXXXXXX)"
DATA="$BASE/data"
SOCK="$BASE/sock"
LOG="$BASE/server.log"
cleanup() {
  "${RUN[@]}" "$PGBIN/pg_ctl" -D "$DATA" -m immediate stop >/dev/null 2>&1 || true
  rm -rf -- "$BASE"
  if [[ "$CREATED_USER" -eq 1 ]]; then
    userdel "$PGUSER_OS" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

chmod 0700 "$BASE"
mkdir -m 0700 "$SOCK"
install -m 0600 /dev/null "$LOG"
if [[ "$(id -u)" -eq 0 ]]; then chown "$PGUSER_OS" "$BASE" "$SOCK" "$LOG"; fi

"${RUN[@]}" "$PGBIN/initdb" -D "$DATA" -U "$PGUSER_OS" --auth-local=peer --auth-host=reject \
  -E UTF8 --locale=C --data-checksums --no-instructions >/dev/null

# Peer auth only, mapped OS user -> DB roles (09 §10 "Auth"). The test roles
# `candor_probe*` exist for negative tests (privileged logins are refused).
{
  echo "candor $CLIENT_OS $PGUSER_OS"
  for r in candor_case candor_admin candor_relay candor_worker candor_notify candor_kd candor_auth \
           candor_audit_w candor_audit_r candor_monitor candor_probe candor_probe2 candor_probe3; do
    echo "candor $CLIENT_OS $r"
  done
  echo "candor $PGUSER_OS $PGUSER_OS"
} > "$DATA/pg_ident.conf"
cat > "$DATA/pg_hba.conf" <<EOT
local all all peer map=candor
EOT

cat >> "$DATA/postgresql.conf" <<EOT
listen_addresses = ''
port = $PORT
unix_socket_directories = '$SOCK'
unix_socket_permissions = 0700
wal_level = replica
max_wal_senders = 0
archive_mode = off
track_commit_timestamp = off
max_wal_size = 256MB
fsync = on
full_page_writes = on
logging_collector = off
log_destination = 'stderr'
log_min_messages = panic
log_min_error_statement = panic
log_statement = 'none'
log_min_duration_statement = -1
log_parameter_max_length = 0
log_parameter_max_length_on_error = 0
log_connections = off
log_disconnections = off
log_error_verbosity = terse
log_line_prefix = '%m %e '
track_io_timing = off
track_activity_query_size = 1024
EOT

"${RUN[@]}" "$PGBIN/pg_ctl" -D "$DATA" -l "$LOG" -w -s start

export CANDOR_TEST_PG="$SOCK"
export CANDOR_TEST_PG_PORT="$PORT"
export CANDOR_TEST_PG_SUPERUSER="$PGUSER_OS"
export CANDOR_TEST_PG_LOG="$LOG"

if [[ $# -eq 0 ]]; then
  set -- cargo test -p candor-case-db
fi
"$@"
