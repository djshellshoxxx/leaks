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
#     stdio handles, and panics carrying formatted values (P-13), including
#     (AUD-RM1-LOG-21) `assert*!`/`debug_assert*!` messages with format
#     arguments (also spanning lines), `expect(&format!(..))`,
#     `std::panic::panic_any`/`resume_unwind` payloads and process spawning
#     (`Command::new`, e.g. `logger`), which reach stderr/journald;
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
  '(^|[^A-Za-z0-9_])(panic_any|resume_unwind)\s*\('
  '(^|[^A-Za-z0-9_])Command::new\s*\('
  '(^|[^A-Za-z0-9_])process::Command\b'
)

# Multi-line constructs (AUD-RM1-LOG-21), on the comment-stripped,
# string-masked source: an assert-family macro whose arguments contain a
# string literal with a format placeholder, and `expect(` whose argument is
# built by `format!`/`concat!` or is not a string literal. Prints
# `<line>:<what>` per hit.
# shellcheck disable=SC2016 # Perl source, not shell expansions
multi_line='
  local $/; my $s = <STDIN>;
  sub line_of { my ($p) = @_; return (substr($s, 0, $p) =~ tr/\n//) + 1; }
  while ($s =~ /(?<![A-Za-z0-9_])(?:debug_)?assert(?:_eq|_ne)?!\s*\(/g) {
    my ($start, $i, $depth) = ($-[0], pos($s), 1);
    while ($i < length($s) && $depth > 0) {
      my $c = substr($s, $i, 1); $depth++ if $c eq "("; $depth-- if $c eq ")"; $i++;
    }
    my $args = substr($s, pos($s), $i - pos($s));
    print line_of($start), ":assert message with format arguments\n" if $args =~ /"[^"]*\{/;
  }
  while ($s =~ /\.expect\(\s*(?:&\s*)?(?:(?:format|concat)!|&\s*[A-Za-z_])/g) {
    print line_of($-[0]), ":expect() with a formatted or runtime message\n";
  }'

# Files that are test-only because their module is declared under
# `#[cfg(test)] mod name;` (e.g. vector/Wycheproof suites inside src/).
# shellcheck disable=SC2016 # Perl source, not shell expansions
test_mods='
  local $/; my $s = <STDIN>; my (%t, %all);
  while ($s =~ /#\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g) {
    $t{$1}++;
  }
  while ($s =~ /(?<![A-Za-z0-9_])mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g) { $all{$1}++; }
  # Skip a module file only if every declaration of it is #[cfg(test)]
  # (a cfg(not(test)) twin would otherwise ship unscanned) and none uses
  # #[path].
  for my $m (sort keys %t) {
    print "$m\n" if $t{$m} == $all{$m} && $s !~ /#\[\s*path\s*=[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\Q$m\E\s*;/;
  }'
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
# blanks `#[cfg(test)]` items and `#![cfg(test)]` files (test-only code does
# not ship); line numbers are preserved.
# shellcheck disable=SC2016 # Perl source, not shell expansions
strip_comments='
  local $/; my $s = <STDIN>; my $o = ""; my $f = ""; my $i = 0; my $n = length $s;
  # $o: comments removed, string contents masked except quotes, braces and
  # newlines; $f: the same with braces inside strings masked too (used only
  # to find item boundaries). Both have identical lengths.
  while ($i < $n) {
    my $c = substr($s, $i, 1); my $d = substr($s, $i, 2);
    if ($d eq "//") { my $j = index($s, "\n", $i); $j = $n if $j < 0; $i = $j; next; }
    if ($d eq "/*") { my $depth = 1; $i += 2;
      while ($i < $n && $depth > 0) { my $e = substr($s, $i, 2);
        if ($e eq "/*") { $depth++; $i += 2; } elsif ($e eq "*/") { $depth--; $i += 2; }
        else { if (substr($s, $i, 1) eq "\n") { $o .= "\n"; $f .= "\n"; } $i++; } }
      next; }
    if (substr($s, $i) =~ /^(b?r(#*)")/) { my $h = $2; my $start = $i; $i += length $1;
      my $end = index($s, "\"" . $h, $i); $end = $n if $end < 0; $i = $end + 1 + length $h;
      my $lit = substr($s, $start, $i - $start);
      (my $m = $lit) =~ s/[^{}\n"]/x/g; $o .= $m; ($m = $lit) =~ s/[^\n"]/x/g; $f .= $m; next; }
    if ($c eq "\"") { my $start = $i; $i++;
      while ($i < $n) { my $e = substr($s, $i, 1);
        if ($e eq "\\") { $i += 2; next; } $i++; last if $e eq "\""; }
      my $lit = substr($s, $start, $i - $start);
      (my $m = $lit) =~ s/[^{}\n"]/x/g; $o .= $m; ($m = $lit) =~ s/[^\n"]/x/g; $f .= $m; next; }
    if ($c eq "\x27" && substr($s, $i) =~ /^(\x27(?:\\.[^\x27]*|[^\\\x27])\x27)/) {
      my $lit = $1; $o .= $lit; (my $m = $lit) =~ s/[^\n]/x/g; $f .= $m; $i += length $lit; next; }
    $o .= $c; $f .= $c; $i++;
  }
  # Test-only code never ships: blank `#![cfg(test)]` files and the item
  # following each `#[cfg(test)]` (module, fn, use, ...), keeping newlines.
  sub blank { my ($a, $b) = @_; (my $m = substr($o, $a, $b - $a)) =~ s/[^\n]/ /g; substr($o, $a, $b - $a) = $m; }
  # Only a file-level inner attribute (before any item) makes the whole
  # file test-only; one inside a nested module must not blank the file.
  if ($f =~ /\A\s*(?:#!\[[^\]]*\]\s*)*#!\[\s*cfg\s*\(\s*test\s*\)\s*\]/) { blank(0, length $o); }
  while ($f =~ /#\[\s*cfg\s*\(\s*test\s*\)\s*\]/g) {
    my $start = $-[0]; my $j = pos($f); my $m = length $f;
    while ($j < $m && substr($f, $j, 1) ne "{" && substr($f, $j, 1) ne ";") { $j++; }
    if ($j < $m && substr($f, $j, 1) eq "{") { my $depth = 0;
      while ($j < $m) { my $c = substr($f, $j, 1);
        $depth++ if $c eq "{"; if ($c eq "}") { $depth--; if ($depth == 0) { $j++; last; } } $j++; } }
    else { $j++; }
    blank($start, $j);
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

# Collect files of `#[cfg(test)] mod x;` declarations (test-only code).
test_only=()
for f in "${files[@]+"${files[@]}"}"; do
  mods="$(perl -e "$test_mods" <"$f")"
  dir="$(dirname "$f")"
  base="$(basename "$f" .rs)"
  case "$base" in
    lib|main|mod) sub="$dir" ;;
    *) sub="$dir/$base" ;;
  esac
  while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    test_only+=("$sub/$m.rs" "$sub/$m/mod.rs")
  done <<<"$mods"
done
is_test_only() {
  local f="$1" t
  for t in "${test_only[@]+"${test_only[@]}"}"; do
    [[ "$f" == "$t" ]] && return 0
  done
  return 1
}

pattern_args=()
for p in "${patterns[@]}"; do pattern_args+=(-e "$p"); done
for f in "${files[@]+"${files[@]}"}"; do
  rel="${f#"$root"/}"
  if is_allowed "$rel"; then continue; fi
  if is_test_only "$f"; then continue; fi
  # Command substitution so perl/grep failures abort (set -e), never pass.
  stripped="$(perl -e "$strip_comments" <"$f")"
  rc=0
  hits="$(grep -nE "${pattern_args[@]}" <<<"$stripped")" || rc=$?
  if ((rc > 1)); then echo "lint-logging: grep failed on $rel" >&2; exit 2; fi
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    report "$rel:$hit"
  done <<<"$hits"
  hits="$(perl -e "$multi_line" <<<"$stripped")"
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
