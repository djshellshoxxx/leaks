#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-tests for scripts/check-dco.sh (AUD-RM0-INF-03; SG-21). Builds throw-away
# fixture repositories and asserts pass/fail for honest and malicious PRs.
# Usage: scripts/tests/test-check-dco.sh   (no network, no global git config)
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CHECK="$HERE/../check-dco.sh"
T=$(mktemp -d "${TMPDIR:-/tmp}/dco-test.XXXXXX")
trap 'rm -rf "$T"' EXIT

export GIT_CONFIG_NOSYSTEM=1 HOME="$T/home" GIT_AUTHOR_NAME="Ann Dev" \
    GIT_AUTHOR_EMAIL="ann@example.org" GIT_COMMITTER_NAME="Ann Dev" \
    GIT_COMMITTER_EMAIL="ann@example.org"
mkdir -p "$HOME"
SOB="Signed-off-by: Ann Dev <ann@example.org>"
pass=0
failn=0

new_repo() {
    R="$T/$1"
    git init -q -b main "$R"
    cd "$R"
    git config commit.gpgsign false
}
commit() { # commit <file> <signed:yes|no> [extra file content]
    printf '%s\n' "${3:-x$(date +%s%N)}" >> "$1"
    git add -- "$1"
    if [ "$2" = yes ]; then git commit -q -m "change $1" -m "$SOB"
    else git commit -q -m "change $1"; fi
}
expect() { # expect <pass|fail> <name> <base> <head> [script]
    want=$1 name=$2 base=$3 head=$4 script=${5:-$CHECK}
    if sh "$script" "$base" "$head" >"$T/out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ] && [ -n "${MSG:-}" ] && ! grep -Fq -- "$MSG" "$T/out"; then
        got="$got (but output lacks '$MSG')"
    fi
    MSG=""
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1)); echo "dco self-test: $name: ok"
    else
        failn=$((failn + 1)); echo "dco self-test: $name: FAILED (expected $want, got $got)"
        sed 's/^/    /' "$T/out"
    fi
}

# --- Fixture: legacy unsigned history, epoch recorded on main ---------------
new_repo r1
commit a no; commit a no
LEGACY=$(git rev-parse HEAD)
printf '# exempt\n%s\n' "$LEGACY" > .dco-epoch
git add .dco-epoch; git commit -q -m "dco epoch" -m "$SOB"
BASE=$(git rev-parse HEAD)

git checkout -q -b honest "$BASE"; commit b yes; commit b yes
expect pass "signed PR passes" "$BASE" honest

git checkout -q -b unsigned "$BASE"; commit b yes; commit b no
MSG="lacks"; expect fail "unsigned commit fails" "$BASE" unsigned

git checkout -q -b wrongname "$BASE"; printf y >> c; git add c
git commit -q -m c -m "Signed-off-by: Someone Else <else@example.org>"
expect fail "sign-off by someone other than the author fails" "$BASE" wrongname

# Malicious PR 1: unsigned commits + .dco-epoch moved to the PR head.
git checkout -q -b evil-epoch "$BASE"; commit b no; commit b no
git rev-parse HEAD > .dco-epoch; git add .dco-epoch; git commit -q -m "epoch" -m "$SOB"
MSG="lacks"; expect fail "MALICIOUS: PR rewrites .dco-epoch to its own head" "$BASE" evil-epoch

# Malicious PR 2: .dco-epoch = literal HEAD in the PR, checked out as cwd.
git checkout -q -b evil-literal "$BASE"; commit b no
printf 'HEAD\n' > .dco-epoch; git add .dco-epoch; git commit -q -m "epoch HEAD" -m "$SOB"
MSG="lacks"; expect fail "MALICIOUS: PR sets .dco-epoch to 'HEAD' (working tree ignored)" "$BASE" evil-literal

# Malicious PR 3: unsigned evil merge (content in the merge commit).
git checkout -q -b side "$BASE"; commit d yes
git checkout -q -b evil-merge "$BASE"; commit e yes
git merge -q --no-ff --no-commit side >/dev/null 2>&1; printf 'payload\n' >> e; git add e
git commit -q -m "merge side"
MSG="merge"; expect fail "MALICIOUS: unsigned merge commit fails" "$BASE" evil-merge

git checkout -q -b good-merge "$BASE"; commit e yes
git merge -q --no-ff -m "merge side" -m "$SOB" side
expect pass "signed merge commit passes" "$BASE" good-merge

# Malicious PR 4: PR replaces check-dco.sh with 'exit 0'. CI runs the BASE copy.
mkdir -p scripts
git checkout -q -b with-script "$BASE"; cp "$CHECK" scripts/check-dco.sh
git add scripts; git commit -q -m "add checker" -m "$SOB"
SBASE=$(git rev-parse HEAD)
git checkout -q -b evil-script "$SBASE"; commit b no
printf '#!/bin/sh\nexit 0\n' > scripts/check-dco.sh; git add scripts; git commit -q -m "neuter" -m "$SOB"
git show "$SBASE:scripts/check-dco.sh" > "$T/base-check.sh"
MSG="lacks"; expect fail "MALICIOUS: PR neuters checker; base copy (as CI runs it) still fails" \
    "$SBASE" evil-script "$T/base-check.sh"

# --- Fixture: bad epoch values at BASE fail closed --------------------------
new_repo r2
commit a no
printf 'HEAD\n' > .dco-epoch; git add .dco-epoch; git commit -q -m e -m "$SOB"
B=$(git rev-parse HEAD); git checkout -q -b pr; commit b yes
MSG="not a full 40-hex"; expect fail "base epoch not 40-hex fails closed" "$B" pr

new_repo r3
commit a no
printf '%s\n' 0123456789abcdef0123456789abcdef01234567 > .dco-epoch
git add .dco-epoch; git commit -q -m e -m "$SOB"
B=$(git rev-parse HEAD); git checkout -q -b pr; commit b yes
MSG="does not exist"; expect fail "base epoch naming a missing commit fails closed" "$B" pr

new_repo r4
commit a yes; B0=$(git rev-parse HEAD)
git checkout -q -b other; commit z no; OTHER=$(git rev-parse HEAD)
git checkout -q main; printf '%s\n' "$OTHER" > .dco-epoch
git add .dco-epoch; git commit -q -m e -m "$SOB"
B=$(git rev-parse HEAD); git checkout -q -b pr; commit b yes
MSG="not an ancestor"; expect fail "base epoch not an ancestor of base fails closed" "$B" pr
: "$B0"

new_repo r5
commit a yes; B=$(git rev-parse HEAD); git checkout -q -b pr; commit b no
MSG="lacks"; expect fail "no epoch at base: every commit is checked" "$B" pr
MSG="not a commit"; expect fail "invalid revision fails" "nonexistent-rev" pr

echo "dco self-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
