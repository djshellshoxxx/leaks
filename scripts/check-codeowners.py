#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CODEOWNERS resolution test (AUD-RM0-INF-02; 27 §11.1; 36 §6.1).

GitHub resolves a path's owners from the LAST matching CODEOWNERS pattern only;
owners of earlier matches are discarded. A general pattern placed after a
specific one therefore silently drops reviewers. This script resolves sample
paths with GitHub's semantics and asserts that each one includes the required
teams (e.g. every crypto/key path must resolve to @candor-project/crypto-reviewers).

Only the pattern subset used in this repository is supported (`*`, anchored
`/path`, directory `/dir/`, `*` within a segment). Any other syntax (`**`,
`?`, `[`, `!`, escapes, unanchored paths with `/`) makes the script FAIL rather
than guess, so the test can never pass on a mis-resolved pattern.

Usage: scripts/check-codeowners.py [CODEOWNERS] [--self-test]
"""

from __future__ import annotations

import fnmatch
import os
import sys

CRYPTO = "@candor-project/crypto-reviewers"
TRUST = "@candor-project/trust-path-maintainers"
ANON = "@candor-project/anonymity-reviewers"
SEC_LEAD = "@candor-project/security-lead"
SEC_TEAM = "@candor-project/security-team"
RELEASE = "@candor-project/release-supply-chain"

# path -> teams that MUST be among the resolved owners.
REQUIRED: dict[str, set[str]] = {
    # T0 crypto / key core (27 §11.3).
    "crates/candor-core/src/lib.rs": {CRYPTO, TRUST},
    "crates/candor-core/Cargo.toml": {CRYPTO, TRUST},
    "crates/candor-safefs/src/lib.rs": {CRYPTO, TRUST},
    "crates/candor-sealer/src/server/mod.rs": {CRYPTO, TRUST},
    "crates/candor-sealer/Cargo.toml": {CRYPTO, TRUST},
    "crates/candor-intake-store/src/lib.rs": {CRYPTO, TRUST},
    # Anonymity review (27 §11.4).
    "crates/candor-log/src/lib.rs": {TRUST, ANON},
    "crates/candor-source-ui/src/lib.rs": {TRUST, ANON},
    # Any other / future crate is at least trust-path.
    "crates/candor-future-crate/src/lib.rs": {TRUST},
    # Gate logic and policy.
    ".dco-epoch": {SEC_LEAD},
    "scripts/check-dco.sh": {SEC_LEAD, SEC_TEAM},
    "scripts/check-codeowners.py": {SEC_LEAD, SEC_TEAM},
    "scripts/repro-check.sh": {RELEASE, SEC_TEAM},
    ".github/CODEOWNERS": {SEC_LEAD},
    ".github/workflows/ci.yml": {RELEASE, SEC_TEAM},
    "supply-chain/config.toml": {RELEASE, SEC_TEAM},
    "deny.toml": {RELEASE, SEC_TEAM},
    "clippy.toml": {RELEASE, SEC_TEAM},
    "rustfmt.toml": {RELEASE},
    "deploy/intake/systemd/candor-intake-web.service": {RELEASE, SEC_TEAM},
    "CONTRIBUTING.md": {SEC_TEAM},
    "SECURITY.md": {SEC_TEAM},
    "rust-toolchain.toml": {RELEASE, SEC_TEAM},
}

UNSUPPORTED = set("?[]!\\")


class CodeownersError(Exception):
    pass


def parse(text: str) -> list[tuple[str, list[str], int]]:
    rules = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        pat, owners = parts[0], parts[1:]
        if "**" in pat or UNSUPPORTED & set(pat):
            raise CodeownersError(f"line {n}: unsupported pattern syntax: {pat}")
        if pat != "*" and not pat.startswith("/"):
            raise CodeownersError(f"line {n}: pattern must be anchored with '/': {pat}")
        if not owners:
            raise CodeownersError(f"line {n}: pattern without owners: {pat}")
        for o in owners:
            if not o.startswith("@") and "@" not in o:
                raise CodeownersError(f"line {n}: bad owner {o!r}")
        rules.append((pat, owners, n))
    return rules


def matches(pat: str, path: str) -> bool:
    if pat == "*":
        return True
    body = pat[1:]
    psegs = path.split("/")
    if body.endswith("/"):
        dsegs = body[:-1].split("/")
        if len(psegs) <= len(dsegs):
            return False
        return all(fnmatch.fnmatchcase(p, d) for p, d in zip(psegs, dsegs))
    bsegs = body.split("/")
    # "/file" matches that path or, if it is a directory, everything below it.
    if len(psegs) < len(bsegs):
        return False
    return all(fnmatch.fnmatchcase(p, b) for p, b in zip(psegs, bsegs))


def resolve(rules, path: str) -> tuple[list[str], int]:
    owners: list[str] = []
    line = 0
    for pat, o, n in rules:
        if matches(pat, path):
            owners, line = o, n
    return owners, line


def check(text: str, required: dict[str, set[str]]) -> list[str]:
    errors = []
    try:
        rules = parse(text)
    except CodeownersError as e:
        return [str(e)]
    for path, need in sorted(required.items()):
        owners, line = resolve(rules, path)
        missing = need - set(owners)
        if missing:
            errors.append(
                f"{path}: resolves to line {line} {owners}; missing {sorted(missing)}"
            )
    return errors


def self_test() -> int:
    req = {"crates/candor-core/src/lib.rs": {CRYPTO}}
    bad = f"* @m\n/crates/candor-core/ {CRYPTO}\n/crates/ {TRUST}\n"
    good = f"* @m\n/crates/ {TRUST}\n/crates/candor-core/ {CRYPTO}\n"
    cases = [
        ("specific-before-general fails (INF-02 regression)", bad, False),
        ("general-before-specific passes", good, True),
        ("unsupported ** syntax fails closed", f"* @m\n/crates/**/x {CRYPTO}\n", False),
        ("unanchored pattern fails closed", f"* @m\ncrates/ {CRYPTO}\n", False),
        ("prefix-only dir name does not match", f"* @m\n/crates/candor-cor/ {CRYPTO}\n", False),
    ]
    fail = 0
    for name, text, ok in cases:
        got = not check(text, req)
        status = "ok" if got == ok else "FAILED"
        if got != ok:
            fail = 1
        print(f"codeowners self-test: {name}: {status}")
    return fail


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = argv[1] if len(argv) > 1 else os.path.join(root, ".github", "CODEOWNERS")
    with open(path, encoding="utf-8") as f:
        errors = check(f.read(), REQUIRED)
    for e in errors:
        print(f"codeowners: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"codeowners: OK ({len(REQUIRED)} paths resolve to the required teams)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
