#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""cargo-vet policy lint (AUD-RM0-INF-05, AUD-RM0-INF-01; 28-SUPPLY-CHAIN.md §5.2;
ADR-052(8) staging: PR CI = safe-to-deploy, release gate = candor-crypto-reviewed).

Checks what `cargo vet` itself cannot express:
  1. No `[[exemptions.*]]` entry grants `candor-crypto-reviewed`; that criterion
     comes only from real audits by Candor Crypto Reviewers (audits.toml).
  2. Every exemption has `notes` containing `expires YYYY-MM-DD`, the date is a
     valid date, not in the past and at most 180 days ahead.
  3. PR policy (committed config.toml): every first-party crate under crates/ has
     a `[policy.<crate>]` with `criteria = "safe-to-deploy"`, and no policy entry
     (criteria or dependency-criteria, first- or third-party) mentions
     `candor-crypto-reviewed`. That criterion is applied only by the release
     gate scripts/vet-release.sh, as a temporary overlay.
  4. Every `[imports.*]` has a matching, completed Security-Lead approval record
     in trusted-importers.toml (no TODO), and the URLs match.
  5. The Candor-local criterion `candor-crypto-reviewed` is defined in
     audits.toml (imported audit sets cannot grant a criterion they do not know),
     and no `[[trusted.*]]` or `[[wildcard-audits.*]]` entry grants it (real
     per-version audits only).
  6. supply-chain/crypto-set.txt (single source of truth for the release gate)
     names every registry crate in Cargo.lock whose name is in the 28 §5.2 crypto
     list below; every entry is a valid, unique crate name present in Cargo.lock.

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
# crypto-set.txt must list every Cargo.lock crate whose name is in this set.
CRYPTO_SET = {
    "chacha20poly1305", "aes-gcm", "hkdf", "hmac", "sha2", "sha3", "blake3",
    "x25519-dalek", "ed25519-dalek", "curve25519-dalek", "ml-kem", "ml-dsa",
    "x-wing", "hpke", "argon2", "aws-lc-rs", "zeroize", "subtle", "rand_core",
    "rand_chacha", "getrandom",
}
MAX_DAYS = 180
EXPIRES = re.compile(r"expires (\d{4}-\d{2}-\d{2})")
NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def as_list(v: object) -> list:
    return v if isinstance(v, list) else [v]


def load(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


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
            if CRYPTO_CRITERION in as_list(e.get("criteria")):
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
        crits = as_list(p.get("criteria"))
        if crits != ["safe-to-deploy"]:
            errors.append(f"policy.{name}: PR criteria must be exactly safe-to-deploy (got {crits!r})")
    for key, p in sorted(policy.items()):
        if CRYPTO_CRITERION in as_list(p.get("criteria")):
            errors.append(f"policy.{key}: requires {CRYPTO_CRITERION} in the PR policy "
                          "(release gate only, ADR-052(8))")
        for dep, got in sorted(p.get("dependency-criteria", {}).items()):
            if CRYPTO_CRITERION in as_list(got):
                errors.append(f"policy.{key}.dependency-criteria.{dep}: requires "
                              f"{CRYPTO_CRITERION} in the PR policy (release gate only, ADR-052(8))")

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
    for table in ("trusted", "wildcard-audits"):
        for crate, entries in audits.get(table, {}).items():
            for e in entries:
                if CRYPTO_CRITERION in as_list(e.get("criteria")):
                    errors.append(f"audits.toml: {table}.{crate} grants {CRYPTO_CRITERION} "
                                  "(real per-version audits only)")

    # 6: crypto-set.txt covers every crypto crate in the lock graph.
    with open(os.path.join(root, "Cargo.lock"), "rb") as f:
        lock = tomllib.load(f)
    locked = {p["name"] for p in lock.get("package", [])
              if str(p.get("source", "")).startswith("registry+")}
    listed: list[str] = []
    set_path = os.path.join(sc, "crypto-set.txt")
    try:
        with open(set_path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if not NAME.match(line):
                    errors.append(f"crypto-set.txt:{n}: invalid crate name")
                elif line in listed:
                    errors.append(f"crypto-set.txt:{n}: duplicate entry {line}")
                else:
                    listed.append(line)
    except FileNotFoundError:
        errors.append("supply-chain/crypto-set.txt: missing (release-gate crypto set)")
    for name in sorted((locked & CRYPTO_SET) - set(listed)):
        errors.append(f"crypto-set.txt: crypto crate {name} is in Cargo.lock but not listed")
    for name in sorted(set(listed) - locked):
        errors.append(f"crypto-set.txt: {name} is not a registry crate in Cargo.lock (stale entry)")

    for e in errors:
        print(f"vet-policy: {e}", file=sys.stderr)
    if errors:
        print(f"vet-policy: FAIL ({len(errors)} problem(s))", file=sys.stderr)
        return 1
    print(f"vet-policy: OK ({n_ex} exemptions, {n_crates} first-party crates, {len(imp)} imports, "
          f"{len(listed)} crypto-set crates)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
