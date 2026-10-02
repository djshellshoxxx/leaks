#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# DCO check (36-OPEN-SOURCE-GOVERNANCE.md §4, OSG-003): every commit in
# BASE..HEAD, INCLUDING merge commits, must carry a "Signed-off-by:" trailer
# matching its author.
#
# Trust model (AUD-RM0-INF-03): nothing the PR controls is trusted.
#   * The exemption epoch is read from the BASE revision
#     (git show "$BASE:.dco-epoch"), never from the working tree or PR head.
#   * The epoch must be a full 40-hex commit SHA that exists and is an
#     ancestor of BASE; anything else fails closed.
#   * Merge commits are checked like any other commit (an "evil merge" can carry
#     content), so a merge without sign-off fails.
#   * CI runs this script as it exists at BASE (extracted with git show), so a PR
#     cannot weaken the checker it is checked by (.github/workflows/ci.yml, dco).
#
# Usage: scripts/check-dco.sh <base-rev> [<head-rev>]
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <base-rev> [<head-rev>]" >&2
    exit 2
fi
BASE_IN=$1
HEAD_IN=${2:-HEAD}

# Resolve both ends to commit SHAs once (no later re-resolution of symbolic refs).
BASE=$(git rev-parse --verify --quiet "$BASE_IN^{commit}") || {
    echo "DCO: base revision '$BASE_IN' is not a commit" >&2; exit 2; }
HEAD=$(git rev-parse --verify --quiet "$HEAD_IN^{commit}") || {
    echo "DCO: head revision '$HEAD_IN' is not a commit" >&2; exit 2; }

# Commits made before the DCO policy existed are exempt. The epoch comes from
# the BASE revision only.
EPOCH=""
if git cat-file -e "$BASE:.dco-epoch" 2>/dev/null; then
    EPOCH=$(git show "$BASE:.dco-epoch" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | head -n 1 | tr -d '[:space:]')
    if ! printf '%s\n' "$EPOCH" | grep -Eqx '[0-9a-f]{40}'; then
        echo "DCO: .dco-epoch at base is not a full 40-hex commit SHA" >&2
        exit 1
    fi
    if ! git cat-file -e "$EPOCH^{commit}" 2>/dev/null; then
        echo "DCO: .dco-epoch at base names a commit that does not exist" >&2
        exit 1
    fi
    if ! git merge-base --is-ancestor "$EPOCH" "$BASE"; then
        echo "DCO: .dco-epoch at base is not an ancestor of the base revision" >&2
        exit 1
    fi
fi

fail=0
n=0
merges=0
for c in $(git rev-list "$BASE..$HEAD"); do
    if [ -n "$EPOCH" ] && git merge-base --is-ancestor "$c" "$EPOCH"; then
        continue
    fi
    n=$((n + 1))
    parents=$(git rev-list --parents -n 1 "$c" | wc -w)
    kind=commit
    if [ "$parents" -gt 2 ]; then
        kind=merge
        merges=$((merges + 1))
    fi
    author=$(git log -1 --format='%an <%ae>' "$c")
    if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c" \
        | grep -Fqx -- "$author"; then
        echo "DCO: $kind $c lacks 'Signed-off-by: $author'" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "DCO: sign off with 'git commit -s'; merge commits need a sign-off too" >&2
    echo "DCO: (or rebase instead of merging). See CONTRIBUTING.md §1." >&2
    exit 1
fi
echo "DCO: $n commit(s) checked ($merges merge), all signed off"
