#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Throwaway PostgreSQL 16 cluster for candor-intake-store integration tests.
#
#   scripts/pg-test.sh [command...]
#
# Creates (if missing) the unprivileged OS user `pgtest`, initdb's a fresh cluster
# in a private 0700 directory, listens ONLY on a Unix socket (listen_addresses =
# ''), authenticates ONLY by peer with an ident map (no host lines, no passwords),
# applies the intake profile settings of 09 §10 (wal_level = minimal,
# max_wal_senders = 0, archive_mode = off, track_commit_timestamp = off, no SQL
# text or bind parameters in logs), exports CANDOR_TEST_PG=<socket dir>, runs the
# command (default: cargo test -p candor-intake-store) and always stops and
# deletes the cluster afterwards. Test-only: production provisioning is 18/32.
set -euo pipefail

PGBIN="${PGBIN:-/usr/lib/postgresql/16/bin}"
PGUSER_OS="${PGUSER_OS:-pgtest}"
PORT="${CANDOR_TEST_PG_PORT:-5432}"

if [[ ! -x "$PGBIN/initdb" ]]; then
  echo "pg-test: PostgreSQL binaries not found in $PGBIN" >&2
  exit 2
fi

# initdb refuses to run as root: use a dedicated unprivileged account.
if [[ "$(id -u)" -eq 0 ]]; then
  if ! id "$PGUSER_OS" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$PGUSER_OS"
  fi
  RUN=(runuser -u "$PGUSER_OS" --)
  CLIENT_OS="root"
else
  PGUSER_OS="$(id -un)"
  RUN=()
  CLIENT_OS="$PGUSER_OS"
fi

BASE="$(mktemp -d /tmp/candor-pgtest.XXXXXXXX)"
DATA="$BASE/data"
SOCK="$BASE/sock"
cleanup() {
  "${RUN[@]}" "$PGBIN/pg_ctl" -D "$DATA" -m immediate stop >/dev/null 2>&1 || true
  rm -rf -- "$BASE"
}
trap cleanup EXIT INT TERM

chmod 0700 "$BASE"
mkdir -m 0700 "$SOCK"
if [[ "$(id -u)" -eq 0 ]]; then chown "$PGUSER_OS" "$BASE" "$SOCK"; fi

"${RUN[@]}" "$PGBIN/initdb" -D "$DATA" -U "$PGUSER_OS" --auth-local=peer --auth-host=reject \
  -E UTF8 --locale=C --data-checksums --no-instructions >/dev/null

# Peer auth only, mapped OS user -> DB roles (09 §10 "Auth"; R7 SI-E-01).
cat > "$DATA/pg_ident.conf" <<EOF
candor $CLIENT_OS $PGUSER_OS
candor $CLIENT_OS candor_istore
candor $CLIENT_OS candor_intake_backup
candor $PGUSER_OS $PGUSER_OS
EOF
cat > "$DATA/pg_hba.conf" <<EOF
local all all peer map=candor
EOF

cat >> "$DATA/postgresql.conf" <<EOF
listen_addresses = ''
port = $PORT
unix_socket_directories = '$SOCK'
unix_socket_permissions = 0700
wal_level = minimal
max_wal_senders = 0
archive_mode = off
track_commit_timestamp = off
max_wal_size = 256MB
fsync = on
full_page_writes = on
logging_collector = off
log_destination = 'stderr'
log_min_messages = warning
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
EOF

"${RUN[@]}" "$PGBIN/pg_ctl" -D "$DATA" -l /dev/null -w -s start

export CANDOR_TEST_PG="$SOCK"
export CANDOR_TEST_PG_PORT="$PORT"
export CANDOR_TEST_PG_SUPERUSER="$PGUSER_OS"

if [[ $# -eq 0 ]]; then
  set -- cargo test -p candor-intake-store
fi
"$@"
