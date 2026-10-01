#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# CI hardening lint (28-SUPPLY-CHAIN.md §7; ST-133). Fails if any workflow:
#   - references an action by tag/branch instead of a full 40-hex commit SHA
#     (local "./" actions and "docker://...@sha256:" digests are allowed),
#   - lacks a "# vX.Y.Z" version comment on a pinned `uses:` line,
#   - uses the pull_request_target trigger,
#   - pipes a download into a shell (curl|sh, wget|bash, ...).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DIR="$ROOT/.github"
fail=0
TMPF=$(mktemp)
trap 'rm -f "$TMPF"' EXIT

files=$(find "$DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | LC_ALL=C sort)
[ -n "$files" ] || { echo "pin-check: no workflow files"; exit 0; }

for f in $files; do
    rel=${f#"$ROOT"/}
    # uses: lines
    grep -n 'uses:' "$f" | while IFS= read -r line; do
        ref=$(printf '%s\n' "$line" | sed -n 's/.*uses:[[:space:]]*["'\'']\{0,1\}\([^"'\''[:space:]#]*\).*/\1/p')
        case $ref in
            ./*) continue ;;
            docker://*@sha256:*) continue ;;
            "") continue ;;
        esac
        sha=${ref##*@}
        if ! printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40}$'; then
            echo "pin-check: $rel:${line%%:*}: not pinned to a full commit SHA: $ref"
            echo FAIL >> "$TMPF"
        elif ! printf '%s\n' "$line" | grep -Eq '#[[:space:]]*v[0-9]+(\.[0-9]+)*'; then
            echo "pin-check: $rel:${line%%:*}: missing '# vX.Y.Z' version comment"
            echo FAIL >> "$TMPF"
        fi
    done
    if grep -n 'pull_request_target' "$f" | grep -v '^[0-9]*:[[:space:]]*#' >/dev/null; then
        echo "pin-check: $rel: pull_request_target is prohibited (28 §7)"
        fail=1
    fi
    if grep -En '(curl|wget)[^|#]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh' "$f" >/dev/null; then
        echo "pin-check: $rel: remote script piped to a shell is prohibited (28 §7, INC-39)"
        fail=1
    fi
done

if [ -s "$TMPF" ]; then fail=1; fi
[ "$fail" -eq 0 ] && echo "pin-check: OK"
exit "$fail"
