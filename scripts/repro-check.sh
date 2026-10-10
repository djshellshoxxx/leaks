#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Local/CI reproducibility check (28-SUPPLY-CHAIN.md §8.2; 27 SG-13; 33 §5).
#
# Builds the workspace in release mode TWICE, from two separate copies of the
# source tree at different absolute paths, into two clean target directories,
# with SOURCE_DATE_EPOCH, fixed TZ/locale/umask and --remap-path-prefix, then
# compares the SHA-256 of the SHIPPED artefacts (AUD-RM0-INF-04):
#   * every workspace binary / cdylib / staticlib target (from `cargo metadata`)
#     when any exist — each one MUST be present in both builds;
#   * otherwise (library-only workspace, RM-0..RM-2) every first-party .rlib —
#     each workspace lib target MUST be present — plus a per-crate hash of the
#     `cargo package --list` source set (what a source release ships).
# Zero compared artefacts, a missing expected artefact, or any difference FAILS.
# There is no SKIP path: a gate that compares nothing must not pass.
#
# The target triple is passed explicitly (--target <host>) and CARGO_BUILD_TARGET
# and other ambient build overrides are cleared, so artefacts always land in
# target-N/<triple>/release regardless of the environment or .cargo/config.toml.
# Extra rustflags shared with the release pipeline live in
# scripts/release-rustflags (one flag per line); remap flags are appended here.
#
# This is the single-host "build twice" smoke test (SecureDrop pattern, B-SD-26).
# It does NOT replace the two-independent-builder comparison required for
# releases (Builder A / Builder B, different organisations and jurisdictions).
#
# Usage: scripts/repro-check.sh [WORKDIR]
#   WORKDIR defaults to a fresh mktemp directory and is removed on success.
# Env:   KEEP_WORKDIR=1 keeps the work directory; CARGO (default: cargo);
#        REPRO_SUMS_OUT=<file> receives the compared SHA256SUMS on success.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CARGO=${CARGO:-cargo}

log() { printf 'repro-check: %s\n' "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

found=0
for m in "$ROOT"/crates/*/Cargo.toml; do
    [ -f "$m" ] && found=1 && break
done
[ "$found" -eq 1 ] || die "no crates under crates/ — nothing to compare (gate must not pass vacuously)"
[ -f "$ROOT/Cargo.lock" ] || die "Cargo.lock missing; it must be committed (28 §5.2) for a locked build"
command -v python3 >/dev/null 2>&1 || die "python3 is required to read cargo metadata"

# Determinism inputs (28 §8.2).
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH
export TZ=UTC LC_ALL=C LANG=C
umask 022
# Ambient overrides that would move or change artefacts (INF-04).
unset RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_TARGET CARGO_BUILD_TARGET_DIR \
    CARGO_TARGET_DIR CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTFLAGS \
    CARGO_PROFILE_RELEASE_DEBUG CARGO_PROFILE_RELEASE_STRIP CARGO_PROFILE_RELEASE_LTO \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS CARGO_PROFILE_RELEASE_OPT_LEVEL || true
export CARGO_INCREMENTAL=0

CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
export CARGO_HOME
# AUD-RM2-DEP-38: with the rust-src component installed rustc records the local toolchain paths, so the
# rustup home and the sysroot are remapped like the checkout, target dir and cargo home.
RUSTUP_HOME_DIR=${RUSTUP_HOME:-$HOME/.rustup}
SYSROOT_DIR=$(rustc --print sysroot)

HOST=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$HOST" ] || die "cannot determine host target triple"

SHARED_FLAGS=""
if [ -f "$ROOT/scripts/release-rustflags" ]; then
    SHARED_FLAGS=$(grep -v '^[[:space:]]*#' "$ROOT/scripts/release-rustflags" | tr '\n' ' ')
fi

if [ $# -ge 1 ]; then
    WORK=$1
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/candor-repro.XXXXXX")
fi
# shellcheck disable=SC2317 # invoked via trap
cleanup() {
    if [ "${KEEP_WORKDIR:-0}" != 1 ] && [ "${REPRO_OK:-0}" = 1 ]; then
        rm -rf "$WORK"
    else
        log "work directory kept at $WORK"
    fi
}
trap cleanup EXIT

# Expected shipped artefacts from cargo metadata: lines "<kind> <file name>".
cargo_metadata_expect() {
    (cd "$ROOT" && "$CARGO" metadata --no-deps --format-version 1 --locked --offline) \
        | python3 -c '
import json, sys
m = json.load(sys.stdin)
ws = set(m["workspace_members"])
for p in m["packages"]:
    if p["id"] not in ws:
        continue
    for t in p["targets"]:
        k = set(t["kind"])
        n = t["name"]
        if "bin" in k:
            print("bin", n)
        if "cdylib" in k:
            print("cdylib", "lib" + n.replace("-", "_") + ".so")
        if "staticlib" in k:
            print("staticlib", "lib" + n.replace("-", "_") + ".a")
        if k & {"lib", "rlib"}:
            print("rlib", "lib" + n.replace("-", "_"))
    print("pkg", p["name"])
'
}

# Copy the tree (tracked + untracked-but-not-ignored files) to a given path.
copy_tree() {
    dest=$1
    mkdir -p "$dest"
    (cd "$ROOT" && git ls-files -z --cached --others --exclude-standard \
        | tar -cf - --null --no-recursion -T -) \
        | (cd "$dest" && tar -xf -)
}

log "fetching dependencies (--locked)"
(cd "$ROOT" && "$CARGO" fetch --locked)

EXPECT="$WORK/expected"
cargo_metadata_expect > "$EXPECT"
[ -s "$EXPECT" ] || die "cargo metadata listed no workspace targets"
if grep -Eq '^(bin|cdylib|staticlib) ' "$EXPECT"; then MODE=bins; else MODE=libs; fi
log "mode: $MODE (target $HOST)"

build() {
    n=$1
    src="$WORK/src-$n/candor"
    tgt="$WORK/target-$n"
    log "build $n: src=$src target=$tgt SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
    copy_tree "$src"
    RUSTFLAGS="$SHARED_FLAGS--remap-path-prefix=$src=/build/candor --remap-path-prefix=$tgt=/build/target --remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=$RUSTUP_HOME_DIR=/rustup --remap-path-prefix=$SYSROOT_DIR=/rustc-sysroot" \
        CARGO_TARGET_DIR="$tgt" \
        "$CARGO" build --manifest-path "$src/Cargo.toml" --target "$HOST" \
            --release --locked --offline --workspace --all-features
}

# "<sha256>  <label>" lines for the shipped artefacts of build N; dies if any
# expected artefact is missing.
hash_artefacts() {
    n=$1
    rel="$WORK/target-$n/$HOST/release"
    src="$WORK/src-$n/candor"
    [ -d "$rel" ] || die "build $n produced no $HOST/release directory"
    out="$WORK/SHA256SUMS.$n"
    : > "$out"
    if [ "$MODE" = bins ]; then
        grep -E '^(bin|cdylib|staticlib) ' "$EXPECT" | while read -r _k f; do
            [ -f "$rel/$f" ] || die "build $n: expected shipped artefact missing: $f"
            (cd "$rel" && sha256 "./$f")
        done >> "$out"
    else
        grep '^rlib ' "$EXPECT" | while read -r _k stem; do
            set -- "$rel"/deps/"$stem"-*.rlib
            [ -f "$1" ] || die "build $n: expected rlib missing: deps/$stem-*.rlib"
            [ $# -eq 1 ] || die "build $n: ambiguous rlibs for $stem ($# files)"
            (cd "$rel" && sha256 "./deps/${1##*/}")
        done >> "$out"
        # Source set of each package as `cargo package` would ship it.
        grep '^pkg ' "$EXPECT" | while read -r _k pkg; do
            list=$(cd "$src" && "$CARGO" package --list --locked --offline --allow-dirty -p "$pkg") \
                || die "cargo package --list failed for $pkg"
            dir=$(cd "$src" && "$CARGO" metadata --no-deps --format-version 1 --locked --offline \
                | python3 -c 'import json,sys,os; m=json.load(sys.stdin); print(next(os.path.dirname(p["manifest_path"]) for p in m["packages"] if p["name"]==sys.argv[1]))' "$pkg")
            mf="$WORK/srcmanifest-$n-$pkg"
            printf '%s\n' "$list" | LC_ALL=C sort | while IFS= read -r f; do
                case $f in
                    .cargo_vcs_info.json|Cargo.toml|Cargo.lock) continue ;; # generated by cargo package
                    Cargo.toml.orig) (cd "$dir" && sha256 Cargo.toml) | sed 's/ Cargo.toml$/ Cargo.toml.orig/' ;;
                    *) [ -f "$dir/$f" ] || die "source file listed by cargo package is missing: $pkg/$f"
                       (cd "$dir" && sha256 "./$f") ;;
                esac
            done > "$mf"
            [ -s "$mf" ] || die "empty source set for $pkg"
            h=$(sha256 < "$mf" | cut -d' ' -f1)
            printf '%s  source:%s\n' "$h" "$pkg"
        done >> "$out"
    fi
}

build 1
build 2
hash_artefacts 1
hash_artefacts 2

count=$(wc -l < "$WORK/SHA256SUMS.1" | tr -d ' ')
[ "$count" -gt 0 ] || die "zero artefacts compared (gate must not pass vacuously)"
expected_n=$(grep -Ec "^$( [ "$MODE" = bins ] && echo '(bin|cdylib|staticlib)' || echo '(rlib|pkg)') " "$EXPECT")
[ "$count" -eq "$expected_n" ] || die "compared $count artefacts, expected $expected_n"

if cmp -s "$WORK/SHA256SUMS.1" "$WORK/SHA256SUMS.2"; then
    log "OK: $count shipped artefacts ($MODE mode) bit-identical across two builds"
    cat "$WORK/SHA256SUMS.1"
    if [ -n "${REPRO_SUMS_OUT:-}" ]; then
        cp "$WORK/SHA256SUMS.1" "$REPRO_SUMS_OUT"
    fi
    REPRO_OK=1
    exit 0
fi

log "FAIL: artefacts differ between builds (release blocker, SG-13)"
diff "$WORK/SHA256SUMS.1" "$WORK/SHA256SUMS.2" >&2 || true
if command -v diffoscope >/dev/null 2>&1; then
    awk '{print $2}' "$WORK/SHA256SUMS.1" | grep -v '^source:' | while IFS= read -r f; do
        a="$WORK/target-1/$HOST/release/$f"
        b="$WORK/target-2/$HOST/release/$f"
        if [ -f "$a" ] && [ -f "$b" ] && ! cmp -s "$a" "$b"; then
            diffoscope --text "$WORK/diffoscope-$(echo "$f" | tr '/' '_').txt" "$a" "$b" >/dev/null 2>&1 || true
        fi
    done
    log "diffoscope reports written to $WORK"
else
    log "diffoscope not installed; install it to get a diff report"
fi
exit 1
