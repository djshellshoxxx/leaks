#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# safefs-lint (ST-005, SDL-030, BE-009, ADR-027): fails if any workspace crate
# other than candor-safefs uses direct filesystem path APIs, path joins or
# archive extraction. The primary gate is clippy `disallowed-methods` /
# `disallowed-types` in the workspace clippy.toml (type-resolved, so aliases
# such as `extern crate std as s; s::fs::write` are caught); this script
# covers what clippy cannot express (AUD-RM1-SFS-01):
#   * dependencies on tar/zip/cap-* outside candor-safefs, including renamed
#     (`x = { package = "zip" }`) and table-form (`[dependencies.tar]`)
#     declarations, resolved through `cargo metadata` when a workspace
#     manifest exists;
#   * `allow(clippy::disallowed_*)` outside candor-safefs (opting out of the
#     clippy gate) and crate-local clippy.toml files (which replace the
#     workspace configuration);
#   * a grep layer for direct fs/rustix/libc/nix calls and path joins.
#
# Usage: lint-safefs.sh [--include-tests] [WORKSPACE_ROOT]
#   default root: three levels above this script (the workspace root).
# Scans crates/*/src/**/*.rs, crates/*/build.rs and crates/*/Cargo.toml
# (plus tests/, benches/, examples/ with --include-tests).
# A single line may be exempted with a justified marker comment:
#     // safefs-lint: allow(<reason>)
# Exit status: 0 clean, 1 violations found, 2 usage or tool error (fail closed).
set -euo pipefail

include_tests=0
root=""
for arg in "$@"; do
  case "$arg" in
    --include-tests) include_tests=1 ;;
    -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
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

# Banned Rust patterns (extended regex). No pattern excludes a preceding ':'
# so aliased paths (`s::fs::write`) match too.
rust_patterns=(
  '\bstd::fs\b'
  '\btokio::fs\b'
  '\basync_std::fs\b'
  'use std::\{[^}]*\bfs\b'
  '(^|[^A-Za-z0-9_])fs::(File|OpenOptions|DirBuilder|write|read|read_to_string|read_dir|read_link|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename|copy|hard_link|soft_link|symlink_metadata|metadata|canonicalize|set_permissions|exists)\b'
  '\bos::(unix|windows)::fs::symlink'
  '\bPath(Buf)?::(join|push|with_file_name|with_extension)\b'
  '[A-Za-z0-9_]*([Pp]ath|[Dd]ir|[Rr]oot|[Bb]ase|[Dd]est|[Dd]st|[Tt]arget|[Ff]older)[A-Za-z0-9_]*(\(\))?\.(join|push|set_file_name)\('
  '\b(tar|zip|cap_std|cap_fs_ext|cap_primitives)::'
  '\bextern crate (tar|zip|flate2)\b'
  '\bextern crate std as\b'
  '\buse std as\b'
  '\.(unpack|unpack_in)\('
  '\bZipArchive\b'
  '\.extract\('
  '\brustix::fs\b'
  '\blibc::(open|open64|openat|openat2|creat|rename|renameat|renameat2|unlink|unlinkat|link|linkat|symlink|symlinkat|mkdir|mkdirat|rmdir|truncate)\b'
  '\bnix::(fcntl|unistd|dir|sys::stat)::'
  'allow\([^)]*clippy::disallowed_(methods|types|macros)'
)
# Banned dependencies outside candor-safefs (regex layer).
banned_deps='tar|zip|cap-std|cap-fs-ext|cap-primitives|async-tar|async_zip'
toml_patterns=(
  "^[[:space:]]*($banned_deps)[[:space:]]*(=|\\.)"
  "^[[:space:]]*\\[(.*\\.)?(dev-|build-)?dependencies\\.($banned_deps)\\]"
  "package[[:space:]]*=[[:space:]]*\"($banned_deps)\""
)
allow_marker='safefs-lint: allow\([^)]+\)'

violations=0
report() { echo "safefs-lint: $1"; violations=$((violations + 1)); }

# grep with explicit status handling: 0 = hits, 1 = none, other = tool error.
grep_hits() {
  local rc=0 out
  out="$(grep -nHE "$@")" || rc=$?
  if ((rc > 1)); then
    echo "lint-safefs: grep failed (status $rc)" >&2
    exit 2
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
  return 0
}

rs_files=()
while IFS= read -r -d '' f; do
  rel="${f#"$root"/crates/}"
  crate="${rel%%/*}"
  sub="${rel#*/}"
  [[ "$crate" == "candor-safefs" ]] && continue
  case "$sub" in
    src/*|build.rs) rs_files+=("$f") ;;
    tests/*|benches/*|examples/*) if [[ $include_tests -eq 1 ]]; then rs_files+=("$f"); fi ;;
  esac
done < <(find "$root/crates" -mindepth 2 \( -name target -o -name .git -o -name fuzz \) -prune -o -type f -name '*.rs' -print0)

toml_files=()
while IFS= read -r -d '' f; do
  toml_files+=("$f")
done < <(find "$root/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -not -path '*/candor-safefs/*' -print0)

# Crate-local clippy.toml files replace the workspace one (and its bans).
while IFS= read -r -d '' f; do
  report "${f#"$root"/}   [crate-local clippy.toml overrides the workspace bans]"
done < <(find "$root/crates" \( -name target -o -name .git -o -name fuzz \) -prune -o -type f \( -name clippy.toml -o -name .clippy.toml \) -print0)

pattern_args=()
for pat in "${rust_patterns[@]}"; do pattern_args+=(-e "$pat"); done
# Command substitution (not process substitution) so a grep/jq failure
# aborts the script under `set -e` instead of reading as "no hits".
for f in "${rs_files[@]+"${rs_files[@]}"}"; do
  hits="$(grep_hits "${pattern_args[@]}" -- "$f")"
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    line="${hit#*:*:}"
    # Skip line comments (incl. doc comments) and justified exemptions.
    [[ "$line" =~ ^[[:space:]]*// ]] && continue
    [[ "$line" =~ $allow_marker ]] && continue
    report "$hit"
  done <<<"$hits"
done

toml_args=()
for pat in "${toml_patterns[@]}"; do toml_args+=(-e "$pat"); done
for f in "${toml_files[@]+"${toml_files[@]}"}"; do
  hits="$(grep_hits "${toml_args[@]}" -- "$f")"
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "$hit   [banned dependency outside candor-safefs]"
  done <<<"$hits"
done

# Resolved dependency graph (renames, workspace inheritance, target tables).
if [[ -f "$root/Cargo.toml" ]] && grep -q '^\[workspace\]' "$root/Cargo.toml"; then
  if ! command -v cargo >/dev/null || ! command -v jq >/dev/null; then
    echo "lint-safefs: cargo and jq are required to resolve dependencies" >&2
    exit 2
  fi
  meta="$(cd "$root" && cargo metadata --format-version 1 --no-deps --offline 2>/dev/null)" || {
    echo "lint-safefs: cargo metadata failed" >&2
    exit 2
  }
  # shellcheck disable=SC2016 # jq variables, not shell expansions
  jq_prog='.packages[] | select(.name != "candor-safefs") as $p
    | $p.dependencies[] | select(.name | test($re))
    | "\($p.name): depends on \(.name)\(if .rename then " (renamed " + .rename + ")" else "" end)"'
  hits="$(jq -r --arg re "^($banned_deps)\$" "$jq_prog" <<<"$meta")"
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "$hit   [banned dependency outside candor-safefs (cargo metadata)]"
  done <<<"$hits"
fi

if ((violations > 0)); then
  echo "safefs-lint: $violations violation(s). Use candor-safefs (ADR-027) or add a justified 'safefs-lint: allow(<reason>)' marker." >&2
  exit 1
fi
echo "safefs-lint: OK (${#rs_files[@]} Rust files, ${#toml_files[@]} manifests scanned)"
