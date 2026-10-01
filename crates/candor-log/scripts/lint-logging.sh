#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# deny-free-text-logging (LOG-001, 20 §7, P-12, P-13): fails if a trust-path
# crate writes free text outside the candor-log typed API. The primary gate is
# clippy `disallowed-macros` / `disallowed-methods` in the workspace
# clippy.toml (println!/eprintln!/print!/eprint!/dbg!, log::*/tracing::*
# macros, std::io::stdout()/stderr()); this script covers what clippy cannot
# express (AUD-RM1-LOG-09):
#   * dependencies on log/tracing/env_logger (also renamed or table-form,
#     resolved through `cargo metadata` when a workspace manifest exists);
#   * macro calls through renamed crates (`lg::log!`, `lg::warn!`), writes to
#     stdio handles, and panics carrying formatted values (P-13);
#   * crates that might be built without the workspace clippy.toml.
# Comments are stripped with a lexer that respects string, char and raw
# string literals (so `"//"` inside a string does not hide the rest of the
# line).
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
# Exit status: 0 clean, 1 violations found, 2 usage or tool error (fail closed).
set -euo pipefail

include_tests=0
root=""
for arg in "$@"; do
  case "$arg" in
    --include-tests) include_tests=1 ;;
    -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
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
command -v perl >/dev/null || { echo "lint-logging: perl is required" >&2; exit 2; }
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

# Banned patterns (extended regex), applied to comment-stripped source.
patterns=(
  '(^|[^A-Za-z0-9_])(println|eprintln|print|eprint|dbg)!'
  '(^|[^A-Za-z0-9_])(log|tracing)::[A-Za-z_]+!'
  '(^|[^A-Za-z0-9_])(log|trace|debug|info|warn|error|event|span)!\s*[([{]'
  '^[[:space:]]*(pub[[:space:]]+)?use[[:space:]]+(log|tracing)(::|;|[[:space:]])'
  '^[[:space:]]*extern[[:space:]]+crate[[:space:]]+(log|tracing)\b'
  '(^|[^A-Za-z0-9_])(stdout|stderr|stdout_locked|stderr_locked)\s*\('
  '(^|[^A-Za-z0-9_])(panic|unreachable|todo|unimplemented)!\s*\(\s*"[^"]*\{'
)
banned_deps='log|tracing|tracing-subscriber|env_logger'
toml_patterns=(
  "^[[:space:]]*($banned_deps)[[:space:]]*(=|\\.)"
  "^[[:space:]]*\\[(.*\\.)?(dev-|build-)?dependencies\\.($banned_deps)\\]"
  "package[[:space:]]*=[[:space:]]*\"($banned_deps)\""
)

# Lexer-aware comment stripper: removes // and (nested) /* */ comments and
# masks the contents of string, byte-string and raw-string literals (every
# character except quotes, braces and newlines becomes `x`, so a macro name
# inside a string never matches while format placeholders stay visible);
# line numbers are preserved.
# shellcheck disable=SC2016 # Perl source, not shell expansions
strip_comments='
  local $/; my $s = <STDIN>; my $o = ""; my $i = 0; my $n = length $s;
  while ($i < $n) {
    my $c = substr($s, $i, 1); my $d = substr($s, $i, 2);
    if ($d eq "//") { my $j = index($s, "\n", $i); $j = $n if $j < 0; $i = $j; next; }
    if ($d eq "/*") { my $depth = 1; $i += 2;
      while ($i < $n && $depth > 0) { my $e = substr($s, $i, 2);
        if ($e eq "/*") { $depth++; $i += 2; } elsif ($e eq "*/") { $depth--; $i += 2; }
        else { $o .= "\n" if substr($s, $i, 1) eq "\n"; $i++; } }
      next; }
    if (substr($s, $i) =~ /^(b?r(#*)")/) { my $h = $2; my $start = $i; $i += length $1;
      my $end = index($s, "\"" . $h, $i); $end = $n if $end < 0; $i = $end + 1 + length $h;
      (my $m = substr($s, $start, $i - $start)) =~ s/[^{}\n"]/x/g; $o .= $m; next; }
    if ($c eq "\"") { my $start = $i; $i++;
      while ($i < $n) { my $e = substr($s, $i, 1);
        if ($e eq "\\") { $i += 2; next; } $i++; last if $e eq "\""; }
      (my $m = substr($s, $start, $i - $start)) =~ s/[^{}\n"]/x/g; $o .= $m; next; }
    if ($c eq "\x27" && substr($s, $i) =~ /^(\x27(?:\\.[^\x27]*|[^\\\x27])\x27)/) {
      $o .= $1; $i += length $1; next; }
    $o .= $c; $i++;
  }
  print $o;'

is_allowed() {
  local rel="$1" g
  for g in "${allow_globs[@]+"${allow_globs[@]}"}"; do
    # shellcheck disable=SC2053
    if [[ "$rel" == $g ]]; then return 0; fi
  done
  return 1
}

files=()
while IFS= read -r -d '' f; do
  rel="${f#"$root"/}"
  case "$rel" in
    crates/*/src/*|crates/*/build.rs) files+=("$f") ;;
    crates/*/tests/*|crates/*/benches/*|crates/*/examples/*)
      if [[ $include_tests -eq 1 ]]; then files+=("$f"); fi ;;
  esac
done < <(find "$root/crates" -mindepth 2 \( -name target -o -name .git -o -name fuzz \) -prune -o -type f -name '*.rs' -print0)

violations=0
report() { echo "lint-logging: $1"; violations=$((violations + 1)); }

pattern_args=()
for p in "${patterns[@]}"; do pattern_args+=(-e "$p"); done
for f in "${files[@]+"${files[@]}"}"; do
  rel="${f#"$root"/}"
  if is_allowed "$rel"; then continue; fi
  # Command substitution so perl/grep failures abort (set -e), never pass.
  stripped="$(perl -e "$strip_comments" <"$f")"
  rc=0
  hits="$(grep -nE "${pattern_args[@]}" <<<"$stripped")" || rc=$?
  if ((rc > 1)); then echo "lint-logging: grep failed on $rel" >&2; exit 2; fi
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "$rel:$hit"
  done <<<"$hits"
done

# Cargo.toml: no dependency on log/tracing in trust-path crates.
toml_args=()
for p in "${toml_patterns[@]}"; do toml_args+=(-e "$p"); done
while IFS= read -r -d '' t; do
  rel="${t#"$root"/}"
  if is_allowed "$rel"; then continue; fi
  rc=0
  hits="$(grep -nE "${toml_args[@]}" "$t")" || rc=$?
  if ((rc > 1)); then echo "lint-logging: grep failed on $rel" >&2; exit 2; fi
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "$rel:$hit (logging crate dependency)"
  done <<<"$hits"
done < <(find "$root/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -print0)

# Resolved dependency graph (renames, target tables, workspace inheritance).
if [[ -f "$root/Cargo.toml" ]] && grep -q '^\[workspace\]' "$root/Cargo.toml"; then
  if ! command -v cargo >/dev/null || ! command -v jq >/dev/null; then
    echo "lint-logging: cargo and jq are required to resolve dependencies" >&2
    exit 2
  fi
  meta="$(cd "$root" && cargo metadata --format-version 1 --no-deps --offline 2>/dev/null)" || {
    echo "lint-logging: cargo metadata failed" >&2
    exit 2
  }
  # shellcheck disable=SC2016 # jq variables, not shell expansions
  jq_prog='.packages[] as $p | ($p.manifest_path | sub("^.*/crates/"; "crates/")) as $m
    | $p.dependencies[] | select(.name | test($re))
    | "\($m)\t\($p.name): depends on \(.name)\(if .rename then " (renamed " + .rename + ")" else "" end)"'
  hits="$(jq -r --arg re "^($banned_deps)\$" "$jq_prog" <<<"$meta")"
  while IFS=$'\t' read -r manifest hit; do
    [[ -z "${hit:-}" ]] && continue
    if is_allowed "$manifest"; then continue; fi
    report "$hit (logging crate dependency, cargo metadata)"
  done <<<"$hits"
fi

if [[ $violations -gt 0 ]]; then
  echo "lint-logging: $violations violation(s); use the candor-log typed API (LOG-001)" >&2
  exit 1
fi
echo "lint-logging: ok (${#files[@]} files)"
