#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# DCO check (36-OPEN-SOURCE-GOVERNANCE.md §4, OSG-003): every non-merge commit
# in BASE..HEAD must carry a "Signed-off-by:" trailer matching its author.
#
# Usage: scripts/check-dco.sh <base-rev> [<head-rev>]
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <base-rev> [<head-rev>]" >&2
    exit 2
fi
BASE=$1
HEAD=${2:-HEAD}

fail=0
n=0
for c in $(git rev-list --no-merges "$BASE..$HEAD"); do
    n=$((n + 1))
    author=$(git log -1 --format='%an <%ae>' "$c")
    if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c" \
        | grep -Fqx -- "$author"; then
        echo "DCO: commit $c lacks 'Signed-off-by: $author'" >&2
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "DCO: sign off with 'git commit -s' (see CONTRIBUTING.md)" >&2
    exit 1
fi
echo "DCO: $n commit(s) checked, all signed off"
