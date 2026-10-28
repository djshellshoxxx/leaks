#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# cargo-vet RELEASE gate (ADR-052(8); 28-SUPPLY-CHAIN.md §5.2; AUD-RM0-INF-01).
#
# PR CI runs `cargo vet --locked` against the committed store, whose policy is
# safe-to-deploy only. This script enforces the release-only criterion: it builds
# a temporary copy of the vet store in which every locked version of every crate
# named in supply-chain/crypto-set.txt (the single source of truth) has the policy
# ["safe-to-deploy", "candor-crypto-reviewed"], then runs
# `cargo vet --locked --store-path <tmp>`. cargo-vet propagates the criterion to
# the dependencies of those crates (unless a Crypto Reviewer's audit narrows it
# with dependency-criteria). The committed store is never modified.
#
# Fails closed: before running cargo-vet it refuses a store in which
# candor-crypto-reviewed could be satisfied by anything other than a real
# per-version audit in audits.toml (exemption, [[trusted]], wildcard audit, or a
# committed policy entry that pre-empts the overlay).
#
# Expected to FAIL until real Crypto Reviewer audits exist
# (`cargo vet certify <crate> <version> candor-crypto-reviewed`); release blocker
# before RM-6. Usage: scripts/vet-release.sh   (needs cargo-vet =0.10.2)

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

for f in supply-chain/config.toml supply-chain/audits.toml supply-chain/imports.lock \
         supply-chain/crypto-set.txt Cargo.lock; do
    if [[ ! -f "$f" ]]; then
        echo "vet-release: FAIL: $f missing" >&2
        exit 1
    fi
done

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
cp -- supply-chain/config.toml supply-chain/audits.toml supply-chain/imports.lock "$tmp/"

python3 - "$tmp/config.toml" supply-chain/crypto-set.txt Cargo.lock supply-chain/audits.toml <<'PY'
import re
import sys
import tomllib

CRIT = "candor-crypto-reviewed"
NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
cfg_path, set_path, lock_path, audits_path = sys.argv[1:5]
errors = []


def crits(v):
    return v if isinstance(v, list) else [v]


names = []
with open(set_path, encoding="utf-8") as f:
    for n, line in enumerate(f, 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if not NAME.match(line):
            errors.append(f"crypto-set.txt:{n}: invalid crate name")
        elif line in names:
            errors.append(f"crypto-set.txt:{n}: duplicate {line}")
        else:
            names.append(line)
if not names:
    errors.append("crypto-set.txt: empty")

with open(lock_path, "rb") as f:
    lock = tomllib.load(f)
versions = {}
for p in lock.get("package", []):
    if p.get("source", "").startswith("registry+"):
        versions.setdefault(p["name"], set()).add(p["version"])
for name in names:
    if name not in versions:
        errors.append(f"crypto-set.txt: {name} is not a registry crate in Cargo.lock")

with open(cfg_path, "rb") as f:
    cfg = tomllib.load(f)
for crate, entries in cfg.get("exemptions", {}).items():
    for e in entries:
        if CRIT in crits(e.get("criteria")):
            errors.append(f"exemptions.{crate}@{e.get('version')} grants {CRIT}")
for key in cfg.get("policy", {}):
    if key.split(":", 1)[0] in names:
        errors.append(f"config.toml: committed [policy.{key!r}] for a crypto crate "
                      "(the release overlay owns these)")

with open(audits_path, "rb") as f:
    audits = tomllib.load(f)
for table in ("trusted", "wildcard-audits"):
    for crate, entries in audits.get(table, {}).items():
        for e in entries:
            if CRIT in crits(e.get("criteria")):
                errors.append(f"audits.toml: {table}.{crate} grants {CRIT} (real audits only)")

if errors:
    for e in errors:
        print(f"vet-release: {e}", file=sys.stderr)
    print("vet-release: FAIL (store refused before vetting)", file=sys.stderr)
    sys.exit(1)

with open(cfg_path, "a", encoding="utf-8") as f:
    for name in names:
        for v in sorted(versions[name]):
            f.write(f'\n[policy."{name}:{v}"]\ncriteria = ["safe-to-deploy", "{CRIT}"]\n')
n = sum(len(versions[x]) for x in names)
print(f"vet-release: overlay requires {CRIT} for {len(names)} crates ({n} locked versions)")
PY

# cargo-vet insists on its canonical formatting; this rewrites only the temp copy.
cargo vet fmt --store-path "$tmp"

if cargo vet --locked --store-path "$tmp"; then
    echo "vet-release: OK (every crypto-set crate has a real candor-crypto-reviewed audit)"
    exit 0
fi
echo "vet-release: FAIL: the crates listed above lack candor-crypto-reviewed audits (release blocker, ADR-052(8))" >&2
exit 1
