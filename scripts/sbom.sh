#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Generate CycloneDX JSON SBOMs for every workspace crate (28-SUPPLY-CHAIN.md §9.3;
# 27 SG-14; 33 §17). Pinned tool: cargo-cyclonedx =0.5.9
#   cargo install --locked --version =0.5.9 cargo-cyclonedx
#
# Gaps vs 28 §9.3 (tracked; release pipeline must close them before 1.0):
#   * cargo-cyclonedx 0.5.9 emits CycloneDX <= 1.5, not 1.6, and no CBOM section;
#   * no SPDX 3.0 output yet;
#   * SBOMs here are unsigned evidence; signing/attestation happens at release.
# serialNumber is a random UUID, so SBOMs are compared after normalisation
# (drop serialNumber), as 28 §9.3 allows ("content-equivalent").
#
# Usage: scripts/sbom.sh [OUTDIR]   (default: target/sbom)
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-$ROOT/target/sbom}
CARGO=${CARGO:-cargo}

found=0
for m in "$ROOT"/crates/*/Cargo.toml; do
    [ -f "$m" ] && found=1 && break
done
if [ "$found" -eq 0 ]; then
    echo "sbom: SKIP: no crates under crates/" >&2
    exit 0
fi

if ! "$CARGO" cyclonedx --version >/dev/null 2>&1; then
    echo "sbom: cargo-cyclonedx not installed (cargo install --locked --version =0.5.9 cargo-cyclonedx)" >&2
    exit 1
fi

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH

mkdir -p "$OUT"
# Remove stale outputs so only this run's SBOMs are collected.
find "$ROOT/crates" -maxdepth 2 -name '*.cdx.json' -exec rm -f {} +

"$CARGO" cyclonedx --manifest-path "$ROOT/Cargo.toml" \
    --format json --spec-version 1.5 --all-features --target all --describe crate -q

n=0
for f in "$ROOT"/crates/*/*.cdx.json; do
    [ -f "$f" ] || continue
    mv "$f" "$OUT/"
    n=$((n + 1))
done
if [ "$n" -eq 0 ]; then
    echo "sbom: FAIL: cargo-cyclonedx produced no SBOM" >&2
    exit 1
fi

(
    cd "$OUT"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum ./*.cdx.json > SHA256SUMS
    else
        shasum -a 256 ./*.cdx.json > SHA256SUMS
    fi
)
echo "sbom: $n CycloneDX SBOM(s) written to $OUT"
