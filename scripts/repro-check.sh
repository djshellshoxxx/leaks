#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Local/CI reproducibility check (28-SUPPLY-CHAIN.md §8.2; 27 SG-13; 33 §5).
#
# Builds the workspace in release mode TWICE, from two separate copies of the
# source tree at different absolute paths, into two clean target directories,
# with SOURCE_DATE_EPOCH, fixed TZ/locale/umask and --remap-path-prefix, then
# compares the SHA-256 of every produced artefact (binaries, .rlib, .so, .a,
# .dylib). Any difference fails the check; diffoscope runs if installed.
#
# This is the single-host "build twice" smoke test (SecureDrop pattern, B-SD-26).
# It does NOT replace the two-independent-builder comparison required for
# releases (Builder A / Builder B, different organisations and jurisdictions).
#
# Usage: scripts/repro-check.sh [WORKDIR]
#   WORKDIR defaults to a fresh mktemp directory and is removed on success.
# Env:   KEEP_WORKDIR=1 keeps the work directory; CARGO (default: cargo).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
CARGO=${CARGO:-cargo}

log() { printf 'repro-check: %s\n' "$*" >&2; }

# Skip gracefully when the workspace has no member crates yet (RM-0 skeleton).
found=0
for m in "$ROOT"/crates/*/Cargo.toml; do
    [ -f "$m" ] && found=1 && break
done
if [ "$found" -eq 0 ]; then
    log "SKIP: no crates under crates/ — nothing to build yet"
    exit 0
fi

if [ ! -f "$ROOT/Cargo.lock" ]; then
    log "FAIL: Cargo.lock missing; it must be committed (28 §5.2) for a locked build"
    exit 1
fi

# Determinism inputs (28 §8.2).
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH
export TZ=UTC LC_ALL=C LANG=C
umask 022
unset RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_INCREMENTAL || true
export CARGO_INCREMENTAL=0

CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
export CARGO_HOME

if [ $# -ge 1 ]; then
    WORK=$1
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/candor-repro.XXXXXX")
fi
cleanup() {
    if [ "${KEEP_WORKDIR:-0}" != 1 ] && [ "${REPRO_OK:-0}" = 1 ]; then
        rm -rf "$WORK"
    else
        log "work directory kept at $WORK"
    fi
}
trap cleanup EXIT

# Copy the tree (tracked + untracked-but-not-ignored files) to a given path.
copy_tree() {
    dest=$1
    mkdir -p "$dest"
    (cd "$ROOT" && git ls-files -z --cached --others --exclude-standard \
        | tar -cf - --null --no-recursion -T -) \
        | (cd "$dest" && tar -xf -)
}

# Fetch once, with the lockfile enforced; both builds then run offline.
log "fetching dependencies (--locked)"
(cd "$ROOT" && "$CARGO" fetch --locked)

build() {
    n=$1
    src="$WORK/src-$n/candor"
    tgt="$WORK/target-$n"
    log "build $n: src=$src target=$tgt SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
    copy_tree "$src"
    RUSTFLAGS="--remap-path-prefix=$src=/build/candor --remap-path-prefix=$CARGO_HOME=/cargo" \
        CARGO_TARGET_DIR="$tgt" \
        "$CARGO" build --manifest-path "$src/Cargo.toml" \
            --release --locked --offline --workspace --all-features
}

# List artefacts as "<sha256>  <relative path>", sorted.
hash_artefacts() {
    tgt=$1/release
    [ -d "$tgt" ] || return 0
    (
        cd "$tgt"
        # Top-level and deps/ only; build-script outputs, fingerprints and
        # dep-info (*.d) are not shipped artefacts.
        find . -maxdepth 2 -type f \
            ! -path './build/*' ! -path './.fingerprint/*' ! -path './incremental/*' \
            \( -name '*.rlib' -o -name '*.so' -o -name '*.a' -o -name '*.dylib' \
               -o \( -perm -u+x ! -name '*.d' \) \) \
            | LC_ALL=C sort \
            | while IFS= read -r f; do
                if command -v sha256sum >/dev/null 2>&1; then
                    sha256sum "$f"
                else
                    shasum -a 256 "$f"
                fi
            done
    )
}

build 1
build 2

hash_artefacts "$WORK/target-1" > "$WORK/SHA256SUMS.1"
hash_artefacts "$WORK/target-2" > "$WORK/SHA256SUMS.2"

count=$(wc -l < "$WORK/SHA256SUMS.1" | tr -d ' ')
if [ "$count" -eq 0 ]; then
    log "SKIP: build produced no artefacts to compare"
    REPRO_OK=1
    exit 0
fi

if cmp -s "$WORK/SHA256SUMS.1" "$WORK/SHA256SUMS.2"; then
    log "OK: $count artefacts bit-identical across two builds"
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
    # Same-named files whose hashes differ.
    awk '{print $2}' "$WORK/SHA256SUMS.1" | while IFS= read -r f; do
        if ! cmp -s "$WORK/target-1/release/$f" "$WORK/target-2/release/$f"; then
            diffoscope --text "$WORK/diffoscope-$(echo "$f" | tr '/' '_').txt" \
                "$WORK/target-1/release/$f" "$WORK/target-2/release/$f" >/dev/null 2>&1 || true
        fi
    done
    log "diffoscope reports written to $WORK"
else
    log "diffoscope not installed; install it to get a diff report"
fi
exit 1
