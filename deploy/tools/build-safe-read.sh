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
RUSTUP_HOME_DIR=${RUSTUP_HOME:-$HOME/.rustup}
# The toolchain's sysroot: with the rust-src component installed, rustc rewrites the standard
# library's /rustc/<hash>/ paths to the local source tree, so the sysroot must be remapped too
# (AUD-RM2-DEP-38). Resolved through the pinned toolchain (rust-toolchain.toml).
SYSROOT=$(cd "$REPO" && rustc --print sysroot)
# With rust-src, rustc records standard-library paths as the local source tree instead of the
# upstream /rustc/<commit-hash>/ form; mapping that tree back to the upstream form makes the
# build identical with and without the component.
RUSTC_HASH=$(cd "$REPO" && rustc -vV | sed -n 's/^commit-hash: \([0-9a-f]*\).*/\1/p')
[ -n "$RUSTC_HASH" ] || { echo "build-safe-read: rustc commit hash unknown" >&2; exit 2; }
# Paths that would otherwise end up in the binary are remapped. rustc applies the LAST matching
# prefix, so the list goes from general (HOME) to specific (target dir); every directory is
# also given by its resolved real path, because rustc records paths through symlinks resolved.
# Symbols stripped; one codegen unit, no incremental state. Only validation may disable the
# remaps (BUILD_SAFE_READ_REMAP=off: the negative reproducibility case in deploy/tests/validate.sh).
export CARGO_TARGET_DIR="$TGT" CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0
remap() { # dir name -> two flags (as given and resolved)
  local real; real=$(readlink -f -- "$1" 2>/dev/null || printf '%s' "$1")
  printf -- '--remap-path-prefix=%s=%s --remap-path-prefix=%s=%s ' "$1" "$2" "$real" "$2"
}
REMAP="$(remap "$HOME" /home)$(remap "$RUSTUP_HOME_DIR" /rustup)$(remap "$CARGO_HOME_DIR" /cargo)$(remap "$SYSROOT" /rustc-sysroot)$(remap "$SYSROOT/lib/rustlib/src/rust" "/rustc/$RUSTC_HASH")$(remap "$REPO" /src)$(remap "$TGT" /target)"
if [ "${BUILD_SAFE_READ_REMAP:-on}" = off ]; then REMAP="$(remap "$REPO" /src)"; fi
export RUSTFLAGS="$REMAP -C strip=symbols -C codegen-units=1"
(cd "$REPO" && cargo build --quiet --release --locked --offline -p candor-safe-read)
install -m 0755 "$TGT/release/candor-safe-read" "$HERE/candor-safe-read"
if [ "${1:-}" = --print-digest ]; then sha256sum < "$HERE/candor-safe-read" | cut -c1-64; fi
