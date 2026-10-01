#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cargo-vet policy lint (AUD-RM0-INF-05; 28-SUPPLY-CHAIN.md §5.2).

Checks what `cargo vet` itself cannot express:
  1. No `[[exemptions.*]]` entry grants `candor-crypto-reviewed`; that criterion
     comes only from real audits by Candor Crypto Reviewers (audits.toml).
  2. Every exemption has `notes` containing `expires YYYY-MM-DD`, the date is a
     valid date, not in the past and at most 180 days ahead.
  3. Every first-party crate under crates/ has a `[policy.<crate>]` with
     `criteria = "safe-to-deploy"`, and each direct dependency in the crypto set
     requires `candor-crypto-reviewed` in `dependency-criteria`.
  4. Every `[imports.*]` has a matching, completed Security-Lead approval record
     in trusted-importers.toml (no TODO), and the URLs match.
  5. The Candor-local criterion `candor-crypto-reviewed` is defined in
     audits.toml (imported audit sets cannot grant a criterion they do not know).

Usage: scripts/check-vet-policy.py [--today YYYY-MM-DD]
"""

from __future__ import annotations

import datetime as dt
import os
import re
import sys
import tomllib

CRYPTO_CRITERION = "candor-crypto-reviewed"
# 28 §5.2 crypto set plus the primitives Candor uses directly (README "Policy").
CRYPTO_SET = {
    "chacha20poly1305", "aes-gcm", "hkdf", "hmac", "sha2", "sha3", "blake3",
    "x25519-dalek", "ed25519-dalek", "curve25519-dalek", "ml-kem", "ml-dsa",
    "x-wing", "hpke", "argon2", "aws-lc-rs", "zeroize", "subtle", "rand_core",
    "rand_chacha", "getrandom",
}
MAX_DAYS = 180
EXPIRES = re.compile(r"expires (\d{4}-\d{2}-\d{2})")


def load(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def direct_deps(manifest: dict) -> set[str]:
    deps: set[str] = set()
    for key in ("dependencies", "build-dependencies"):
        for name, spec in manifest.get(key, {}).items():
            pkg = spec.get("package", name) if isinstance(spec, dict) else name
            deps.add(pkg)
    for tgt in manifest.get("target", {}).values():
        for key in ("dependencies", "build-dependencies"):
            for name, spec in tgt.get(key, {}).items():
                pkg = spec.get("package", name) if isinstance(spec, dict) else name
                deps.add(pkg)
    return deps


def main(argv: list[str]) -> int:
    today = dt.date.today()
    if "--today" in argv:
        today = dt.date.fromisoformat(argv[argv.index("--today") + 1])
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sc = os.path.join(root, "supply-chain")
    config = load(os.path.join(sc, "config.toml"))
    audits = load(os.path.join(sc, "audits.toml"))
    importers = load(os.path.join(sc, "trusted-importers.toml"))
    errors: list[str] = []

    # 1 + 2: exemptions.
    n_ex = 0
    for crate, entries in config.get("exemptions", {}).items():
        for e in entries:
            n_ex += 1
            where = f"exemptions.{crate}@{e.get('version')}"
            crit = e.get("criteria")
            crits = crit if isinstance(crit, list) else [crit]
            if CRYPTO_CRITERION in crits:
                errors.append(f"{where}: grants {CRYPTO_CRITERION} (only real audits may)")
            m = EXPIRES.search(e.get("notes", ""))
            if not m:
                errors.append(f"{where}: notes lack 'expires YYYY-MM-DD'")
                continue
            try:
                exp = dt.date.fromisoformat(m.group(1))
            except ValueError:
                errors.append(f"{where}: invalid expiry date {m.group(1)}")
                continue
            if exp < today:
                errors.append(f"{where}: expired on {exp}")
            elif (exp - today).days > MAX_DAYS:
                errors.append(f"{where}: expiry {exp} is more than {MAX_DAYS} days ahead")

    # 3: first-party policies.
    policy = config.get("policy", {})
    crates_dir = os.path.join(root, "crates")
    n_crates = 0
    for d in sorted(os.listdir(crates_dir)):
        mpath = os.path.join(crates_dir, d, "Cargo.toml")
        if not os.path.isfile(mpath):
            continue
        n_crates += 1
        manifest = load(mpath)
        name = manifest.get("package", {}).get("name", d)
        p = policy.get(name)
        if p is None:
            errors.append(f"policy.{name}: missing (every first-party crate needs a policy)")
            continue
        crit = p.get("criteria")
        crits = crit if isinstance(crit, list) else [crit]
        if "safe-to-deploy" not in crits and CRYPTO_CRITERION not in crits:
            errors.append(f"policy.{name}: criteria must include safe-to-deploy (got {crit!r})")
        dc = p.get("dependency-criteria", {})
        for dep in sorted(direct_deps(manifest) & CRYPTO_SET):
            got = dc.get(dep, [])
            got = got if isinstance(got, list) else [got]
            if CRYPTO_CRITERION not in got:
                errors.append(
                    f"policy.{name}.dependency-criteria.{dep}: must require {CRYPTO_CRITERION}"
                )

    # 4: import approvals.
    imp = config.get("imports", {})
    rec = importers.get("importer", {})
    for org, spec in sorted(imp.items()):
        r = rec.get(org)
        if r is None:
            errors.append(f"imports.{org}: no approval record in trusted-importers.toml")
            continue
        if r.get("url") != spec.get("url"):
            errors.append(f"imports.{org}: URL differs from trusted-importers.toml")
        for k in ("approved-by", "approved", "review-due"):
            v = str(r.get(k, ""))
            if not v or "TODO" in v:
                errors.append(f"imports.{org}: approval field '{k}' not completed by the Security Lead")

    # 5: the criterion is defined locally and only granted by Candor audits.
    if CRYPTO_CRITERION not in audits.get("criteria", {}):
        errors.append(f"audits.toml: criterion {CRYPTO_CRITERION} is not defined")

    for e in errors:
        print(f"vet-policy: {e}", file=sys.stderr)
    if errors:
        print(f"vet-policy: FAIL ({len(errors)} problem(s))", file=sys.stderr)
        return 1
    print(f"vet-policy: OK ({n_ex} exemptions, {n_crates} first-party crates, {len(imp)} imports)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
