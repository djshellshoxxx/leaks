#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Secret scan for committed key material (AUD-RM0-INF-08; 28 §7).

Scans every tracked file (default) or every blob reachable from any ref
(--history) for private-key material: PEM/OpenSSH/OpenPGP private-key blocks,
age identities, GitHub and AWS access tokens. Matches are reported by path and
line number only — the matched text is never printed, so a real leak is not
copied into CI logs.

Known synthetic fixtures (detectors and tests that must contain the header
string) are allow-listed in scripts/secret-scan-allowlist as
"<path>\\t<sha256 of the exact line>", so an allow-list entry cannot hide a
different line (e.g. a real key) added to the same file.

Raw 32-byte HPKE/X25519 keys have no marker and cannot be found by pattern; the
deployment placement check (deploy/tools/check-placement.sh) covers key files
on hosts.

Usage: scripts/check-secrets.py [--history] [--hash-line PATH LINENO]
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys

PATTERNS = [
    ("private-key block", re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----")),
    ("age identity", re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{20,}")),
    ("GitHub token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("AWS access key id", re.compile(rb"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWLIST = os.path.join(ROOT, "scripts", "secret-scan-allowlist")


def git(*args: str) -> bytes:
    return subprocess.run(["git", "-C", ROOT, *args], check=True, capture_output=True).stdout


def load_allowlist() -> set[tuple[str, str]]:
    out = set()
    with open(ALLOWLIST, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            path, _, digest = line.partition("\t")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise SystemExit(f"secret-scan: bad allow-list entry: {line!r}")
            out.add((path, digest))
    return out


def scan_blob(label: str, path: str, data: bytes, allow, findings: list[str]) -> None:
    if b"\0" in data[:8192]:
        return  # binary
    for n, line in enumerate(data.split(b"\n"), 1):
        for name, rx in PATTERNS:
            if rx.search(line):
                digest = hashlib.sha256(line).hexdigest()
                if (path, digest) in allow:
                    continue
                findings.append(f"{label}{path}:{n}: {name}")


def main(argv: list[str]) -> int:
    if "--hash-line" in argv:
        i = argv.index("--hash-line")
        path, lineno = argv[i + 1], int(argv[i + 2])
        with open(os.path.join(ROOT, path), "rb") as f:
            line = f.read().split(b"\n")[lineno - 1]
        print(f"{path}\t{hashlib.sha256(line).hexdigest()}")
        return 0
    allow = load_allowlist()
    findings: list[str] = []
    if "--history" in argv:
        seen: set[str] = set()
        for rev in git("rev-list", "--all").split():
            for entry in git("ls-tree", "-r", "-z", rev.decode()).split(b"\0"):
                if not entry:
                    continue
                meta, _, path = entry.partition(b"\t")
                parts = meta.split()
                if len(parts) != 3 or parts[1] != b"blob" or parts[2].decode() in seen:
                    continue
                seen.add(parts[2].decode())
                data = git("cat-file", "blob", parts[2].decode())
                scan_blob(f"{rev.decode()[:12]}:", path.decode("utf-8", "replace"), data, allow, findings)
        scope = f"{len(seen)} historical blobs"
    else:
        files = [p for p in git("ls-files", "-z").split(b"\0") if p]
        for p in files:
            full = os.path.join(ROOT.encode(), p)
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            with open(full, "rb") as f:
                scan_blob("", p.decode("utf-8", "replace"), f.read(), allow, findings)
        scope = f"{len(files)} tracked files"
    for f in findings:
        print(f"secret-scan: possible secret at {f}", file=sys.stderr)
    if findings:
        print("secret-scan: FAIL — remove and rotate the secret; allow-list only synthetic fixtures", file=sys.stderr)
        return 1
    print(f"secret-scan: OK ({scope})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
