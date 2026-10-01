#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# CI hardening lint (28-SUPPLY-CHAIN.md §7; ST-133). Fails if any workflow or
# action file under .github/ (*.yml / *.yaml, any letter case):
#   - references an action by tag/branch instead of a full 40-hex commit SHA
#     (local "./" actions and "docker://...@sha256:" digests are allowed),
#   - lacks a "# vX.Y.Z" version comment on a pinned `uses:` line,
#   - uses the pull_request_target trigger,
#   - downloads and executes remote code: curl/wget piped into a shell or
#     interpreter, `sh <(curl ...)`, `source <(curl ...)`, `eval "$(curl ...)"`,
#     or `curl -o f ... && sh f` (AUD-RM0-INF-07).
#
# This is a lint, not a parser: it fails safe (a commented-out tag reference is
# also reported). zizmor (offline in PRs, online on schedule) is the second reader.
#
# Usage: scripts/check-actions-pinned.sh [DIR]      (default: <repo>/.github)
#        scripts/check-actions-pinned.sh --file F... (internal: check files)
# Self-test: scripts/tests/test-check-actions-pinned.sh
set -eu

check_file() {
    f=$1
    bad=0
    tmp=$(mktemp)
    # uses: lines (the while loop runs in a subshell; failures go through $tmp).
    grep -n 'uses:' "$f" | while IFS= read -r line; do
        ref=$(printf '%s\n' "$line" | sed -n 's/.*uses:[[:space:]]*["'\'']\{0,1\}\([^"'\''[:space:]#]*\).*/\1/p')
        case $ref in
            ./*) continue ;;
            docker://*@sha256:*) continue ;;
            "") continue ;;
        esac
        sha=${ref##*@}
        if [ "$sha" = "$ref" ] || ! printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
            echo "pin-check: $f:${line%%:*}: not pinned to a full commit SHA: $ref"
            echo FAIL >> "$tmp"
        elif ! printf '%s\n' "$line" | grep -Eq '#[[:space:]]*v[0-9]+(\.[0-9]+)*'; then
            echo "pin-check: $f:${line%%:*}: missing '# vX.Y.Z' version comment"
            echo FAIL >> "$tmp"
        fi
    done
    if [ -s "$tmp" ]; then bad=1; fi
    rm -f "$tmp"
    if grep -n 'pull_request_target' "$f" | grep -v '^[0-9]*:[[:space:]]*#' >/dev/null; then
        echo "pin-check: $f: pull_request_target is prohibited (28 §7)"
        bad=1
    fi
    DL='(curl|wget)'
    INTERP='(sudo[[:space:]]+)?(env[[:space:]]+[^|]*)?(ba|z|da|k|fi|c|tc)?sh|python[0-9.]*|perl|ruby|node|php|pwsh|powershell|iex'
    if grep -Eiq "$DL[^|#]*\\|[[:space:]]*($INTERP)([[:space:]]|\$|;|-)" "$f" \
        || grep -Eiq "(ba|z|da|k)?sh[[:space:]]+(-s[[:space:]]+)?<\\([[:space:]]*$DL" "$f" \
        || grep -Eiq "(source|\\.)[[:space:]]+<\\([[:space:]]*$DL" "$f" \
        || grep -Eiq "eval[[:space:]]+[\"']?\\\$[({][[:space:]]*$DL" "$f" \
        || grep -Eiq "$DL[^#]*[[:space:]](-o|-O|--output|--output-document)[[:space:]=]*[^[:space:]]+[^#]*(&&|;|\\|\\|)[[:space:]]*($INTERP|chmod[[:space:]]+\\+?[0-7]*x|\\./)" "$f"; then
        echo "pin-check: $f: remote code download-and-execute is prohibited (28 §7, INC-39)"
        bad=1
    fi
    return "$bad"
}

if [ "${1:-}" = "--file" ]; then
    shift
    rc=0
    for f in "$@"; do
        check_file "$f" || rc=1
    done
    exit "$rc"
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DIR=${1:-"$ROOT/.github"}
SELF="$ROOT/scripts/check-actions-pinned.sh"
[ -f "$SELF" ] || SELF=$0

# Null-safe enumeration: find passes file names straight to the checker.
if [ -z "$(find "$DIR" -type f \( -iname '*.yml' -o -iname '*.yaml' \) -print 2>/dev/null | head -n 1)" ]; then
    echo "pin-check: FAIL: no workflow files found under $DIR" >&2
    exit 1
fi
if find "$DIR" -type f \( -iname '*.yml' -o -iname '*.yaml' \) -exec sh "$SELF" --file {} +; then
    echo "pin-check: OK"
    exit 0
fi
exit 1
