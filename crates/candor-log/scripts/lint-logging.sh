#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# deny-free-text-logging (LOG-001, 20 §7, P-12): fails if a trust-path crate
# uses println!/eprintln!/print!/eprint!/dbg! or log::/tracing:: macros (or
# imports those crates) outside the candor-log typed API. Heuristic grep
# gate; complements clippy `disallowed-macros` (crates/candor-log/clippy.toml).
#
# Usage: lint-logging.sh [--include-tests] [WORKSPACE_ROOT]
#   default root: three levels above this script (the workspace root).
# Scans crates/*/src/**/*.rs and crates/*/build.rs (plus tests/, benches/,
# examples/ with --include-tests). All crates under crates/ are trust-path
# unless listed in the exceptions file.
#
# Exceptions: scripts/lint-logging.allow (next to this script). One entry per
# line, `<path-glob relative to root> <reason>`; '#' starts a comment. A
# matching file is skipped entirely. Every entry needs a reason and review.
#
# Exit status: 0 clean, 1 violations found, 2 usage error.
set -euo pipefail

include_tests=0
root=""
for arg in "$@"; do
  case "$arg" in
    --include-tests) include_tests=1 ;;
    -h|--help) sed -n '3,20p' "$0"; exit 0 ;;
    -*) echo "lint-logging: unknown option $arg" >&2; exit 2 ;;
    *) root="$arg" ;;
  esac
done
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$root" ]]; then
  root="$(cd "$script_dir/../../.." && pwd)"
fi
if [[ ! -d "$root/crates" ]]; then
  echo "lint-logging: no crates/ directory under $root" >&2
  exit 2
fi
allow_file="$script_dir/lint-logging.allow"

# Exception globs (path relative to root). Entries without a reason are a
# usage error so that exceptions stay justified.
allow_globs=()
if [[ -f "$allow_file" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    read -r glob reason <<<"$line" || true
    [[ -z "${glob:-}" ]] && continue
    if [[ -z "${reason:-}" ]]; then
      echo "lint-logging: exception '$glob' has no reason" >&2
      exit 2
    fi
    allow_globs+=("$glob")
  done <"$allow_file"
fi

# Banned patterns (extended regex).
patterns=(
  '(^|[^A-Za-z0-9_])(println|eprintln|print|eprint|dbg)!'
  '(^|[^A-Za-z0-9_])(log|tracing)::[A-Za-z_]+!'
  '(^|[^A-Za-z0-9_])(trace|debug|info|warn|error|event|span)!\('
  '^[[:space:]]*(pub[[:space:]]+)?use[[:space:]]+(log|tracing)(::|;|[[:space:]])'
  '^[[:space:]]*extern[[:space:]]+crate[[:space:]]+(log|tracing)\b'
)

is_allowed() {
  local rel="$1" g
  for g in "${allow_globs[@]+"${allow_globs[@]}"}"; do
    # shellcheck disable=SC2053
    if [[ "$rel" == $g ]]; then return 0; fi
  done
  return 1
}

mapfile -d '' files < <(
  find "$root/crates" -mindepth 2 \( -name target -o -name .git \) -prune -o \
    -type f -name '*.rs' -print0 |
  while IFS= read -r -d '' f; do
    rel="${f#"$root"/}"
    case "$rel" in
      crates/*/src/*|crates/*/build.rs) printf '%s\0' "$f" ;;
      crates/*/tests/*|crates/*/benches/*|crates/*/examples/*)
        if [[ $include_tests -eq 1 ]]; then printf '%s\0' "$f"; fi ;;
    esac
  done
)

violations=0
for f in "${files[@]+"${files[@]}"}"; do
  rel="${f#"$root"/}"
  if is_allowed "$rel"; then continue; fi
  for p in "${patterns[@]}"; do
    # Strip // comments before matching (doc comments may mention macros).
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      echo "lint-logging: $rel:$hit"
      violations=$((violations + 1))
    done < <(sed -E 's://.*$::' "$f" | grep -nE "$p" || true)
  done
done

# Cargo.toml: no direct dependency on log/tracing in trust-path crates.
while IFS= read -r -d '' t; do
  rel="${t#"$root"/}"
  if is_allowed "$rel"; then continue; fi
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    echo "lint-logging: $rel:$hit (logging crate dependency)"
    violations=$((violations + 1))
  done < <(grep -nE '^[[:space:]]*(log|tracing|tracing-subscriber|env_logger)[[:space:]]*(=|\.)' "$t" || true)
done < <(find "$root/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -print0)

if [[ $violations -gt 0 ]]; then
  echo "lint-logging: $violations violation(s); use the candor-log typed API (LOG-001)" >&2
  exit 1
fi
echo "lint-logging: ok (${#files[@]} files)"
