#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-tests for scripts/repro-check.sh (AUD-RM0-INF-04). A stub `cargo`
# (selected with CARGO=) simulates builds so each fail-open scenario runs in
# seconds: the gate must FAIL when nothing (or the wrong thing) is compared.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CHECK="$HERE/../repro-check.sh"
T=$(mktemp -d "${TMPDIR:-/tmp}/repro-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
pass=0
failn=0

# Stub cargo. STUB_MODE: none | identical | differ | wrongdir ; STUB_BINS=1 adds a bin.
cat > "$T/cargo" <<'STUB'
#!/bin/sh
set -eu
cmd=$1; shift
case $cmd in
fetch) exit 0 ;;
metadata)
    b=""
    [ "${STUB_BINS:-0}" = 1 ] && b='{"name":"candor-tool","kind":["bin"]},'
    printf '{"workspace_members":["p1"],"packages":[{"id":"p1","name":"candor-demo","manifest_path":"%s/Cargo.toml","targets":[%s{"name":"candor_demo","kind":["lib"]}]}]}\n' "$PWD" "$b" ;;
package) printf 'Cargo.toml.orig\nCargo.toml\nCargo.lock\n' ;;
build)
    target=""
    while [ $# -gt 0 ]; do [ "$1" = --target ] && target=$2; shift; done
    case ${STUB_MODE:-identical} in
    none) exit 0 ;;
    wrongdir) d="$CARGO_TARGET_DIR/release/deps" ;;
    *) d="$CARGO_TARGET_DIR/$target/release/deps" ;;
    esac
    mkdir -p "$d"
    if [ "${STUB_MODE:-}" = differ ]; then date +%s%N > "$d/libcandor_demo-abc.rlib"
    else echo same > "$d/libcandor_demo-abc.rlib"; fi
    ;;
*) echo "stub cargo: unsupported $cmd" >&2; exit 2 ;;
esac
STUB
chmod +x "$T/cargo"

run() { # run <want> <name> <expected output fragment> [VAR=val...]
    want=$1 name=$2 frag=$3; shift 3
    if env CARGO="$T/cargo" "$@" sh "$CHECK" "$T/w$((pass + failn))" >"$T/out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ] && ! grep -Fq -- "$frag" "$T/out"; then got="$got (output lacks '$frag')"; fi
    if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "repro self-test: $name: ok"
    else failn=$((failn + 1)); echo "repro self-test: $name: FAILED (expected $want, got $got)"
        sed 's/^/    /' "$T/out" | tail -5; fi
}

run pass "identical rlib + source hash passes" "OK: 2 shipped artefacts" STUB_MODE=identical
run fail "build producing nothing FAILS (no vacuous pass)" "FAIL" STUB_MODE=none
run fail "artefacts in an unexpected dir FAIL" "FAIL" STUB_MODE=wrongdir
run fail "non-deterministic artefact FAILS" "artefacts differ" STUB_MODE=differ
run pass "ambient CARGO_BUILD_TARGET is ignored" "OK" STUB_MODE=identical CARGO_BUILD_TARGET=wasm32-unknown-unknown
run fail "expected binary missing FAILS" "expected shipped artefact missing" STUB_MODE=identical STUB_BINS=1

echo "repro self-test: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
