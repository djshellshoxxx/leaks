#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# safefs-lint (ST-005, SDL-030, BE-009, ADR-027): fails if any workspace crate
# other than candor-safefs uses direct filesystem path APIs, path joins or
# archive extraction. Heuristic grep gate; complements Semgrep taint rules and
# clippy `disallowed-methods` (07 §10).
#
# Usage: lint-safefs.sh [--include-tests] [WORKSPACE_ROOT]
#   default root: three levels above this script (the workspace root).
# Scans crates/*/src/**/*.rs, crates/*/build.rs and crates/*/Cargo.toml
# (plus tests/, benches/, examples/ with --include-tests).
# A single line may be exempted with a justified marker comment:
#     // safefs-lint: allow(<reason>)
# Exit status: 0 clean, 1 violations found, 2 usage error.
set -euo pipefail

include_tests=0
root=""
for arg in "$@"; do
  case "$arg" in
    --include-tests) include_tests=1 ;;
    -h|--help) sed -n '3,17p' "$0"; exit 0 ;;
    -*) echo "lint-safefs: unknown option $arg" >&2; exit 2 ;;
    *) root="$arg" ;;
  esac
done
if [[ -z "$root" ]]; then
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
fi
if [[ ! -d "$root/crates" ]]; then
  echo "lint-safefs: no crates/ directory under $root" >&2
  exit 2
fi

# Banned Rust patterns (extended regex).
rust_patterns=(
  '\bstd::fs\b'
  '\btokio::fs\b'
  '\basync_std::fs\b'
  'use std::\{[^}]*\bfs\b'
  '(^|[^A-Za-z0-9_:])fs::(File|OpenOptions|DirBuilder|write|read|read_to_string|read_dir|read_link|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename|copy|hard_link|soft_link|symlink_metadata|metadata|canonicalize|set_permissions)\b'
  '\bos::(unix|windows)::fs::symlink'
  '\bPath(Buf)?::(join|push|with_file_name|with_extension)\b'
  '[A-Za-z0-9_]*([Pp]ath|[Dd]ir|[Rr]oot|[Bb]ase|[Dd]est|[Dd]st|[Tt]arget|[Ff]older)[A-Za-z0-9_]*(\(\))?\.(join|push|set_file_name)\('
  '\b(tar|zip|cap_std|cap_fs_ext|cap_primitives)::'
  '\bextern crate (tar|zip|flate2)\b'
  '\.(unpack|unpack_in)\('
  '\bZipArchive\b'
  '\.extract\('
)
# Banned dependencies outside candor-safefs.
toml_pattern='^[[:space:]]*(tar|zip|cap-std|cap-fs-ext|cap-primitives|async-tar|async_zip)[[:space:]]*(=|\.)'
allow_marker='safefs-lint: allow\([^)]+\)'

mapfile -d '' rs_files < <(
  find "$root/crates" -mindepth 2 \
    \( -name target -o -name .git \) -prune -o \
    -type f -name '*.rs' -print0 |
  while IFS= read -r -d '' f; do
    rel="${f#"$root"/crates/}"
    crate="${rel%%/*}"
    sub="${rel#*/}"
    [[ "$crate" == "candor-safefs" ]] && continue
    case "$sub" in
      src/*|build.rs) printf '%s\0' "$f" ;;
      tests/*|benches/*|examples/*) [[ $include_tests -eq 1 ]] && printf '%s\0' "$f" ;;
    esac
  done
)
mapfile -d '' toml_files < <(
  find "$root/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -not -path '*/candor-safefs/*' -print0
)

violations=0
report() { echo "safefs-lint: $1"; violations=$((violations + 1)); }

if ((${#rs_files[@]})); then
  for pat in "${rust_patterns[@]}"; do
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      line="${hit#*:*:}"
      # Skip comment-only lines and justified exemptions.
      [[ "$line" =~ ^[[:space:]]*(//|\*|/\*) ]] && continue
      [[ "$line" =~ $allow_marker ]] && continue
      report "$hit   [pattern: $pat]"
    done < <(grep -nHE -- "$pat" "${rs_files[@]}" 2>/dev/null || true)
  done
fi
if ((${#toml_files[@]})); then
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "$hit   [banned dependency outside candor-safefs]"
  done < <(grep -nHE -- "$toml_pattern" "${toml_files[@]}" 2>/dev/null || true)
fi

if ((violations > 0)); then
  echo "safefs-lint: $violations violation(s). Use candor-safefs (ADR-027) or add a justified 'safefs-lint: allow(<reason>)' marker." >&2
  exit 1
fi
echo "safefs-lint: OK (${#rs_files[@]} Rust files, ${#toml_files[@]} manifests scanned)"
