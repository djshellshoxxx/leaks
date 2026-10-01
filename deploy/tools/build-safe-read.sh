#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# build-safe-read.sh - reproducible build of crates/candor-safe-read (ADR-055(3), AUD-RM2-DEP-26)
# into deploy/tools/candor-safe-read, the path config-check.sh runs it from. The binary's
# sha256 is pinned in config-check.manifest; a build with the pinned toolchain
# (rust-toolchain.toml), Cargo.lock and these flags reproduces it byte for byte.
#
# Usage: build-safe-read.sh [--print-digest]
#   Build dir: deploy/.build/safe-read (ignored by git). Needs cargo (offline, --locked).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd -P)
REPO=$(cd "$HERE/../.." && pwd -P)
TGT="$REPO/deploy/.build/safe-read"
mkdir -p "$TGT"
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
# Paths that would otherwise end up in the binary are remapped; symbols stripped; one codegen
# unit, no incremental state.
export CARGO_TARGET_DIR="$TGT" CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$REPO=/src --remap-path-prefix=$TGT=/target -C strip=symbols -C codegen-units=1"
(cd "$REPO" && cargo build --quiet --release --locked --offline -p candor-safe-read)
install -m 0755 "$TGT/release/candor-safe-read" "$HERE/candor-safe-read"
if [ "${1:-}" = --print-digest ]; then sha256sum < "$HERE/candor-safe-read" | cut -c1-64; fi
