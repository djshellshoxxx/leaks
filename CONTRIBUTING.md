<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Contributing to Candor

Thank you for helping. Candor protects whistleblowers, so the bar for changes to
the code that touches sources, keys or plaintext (the **Trust Path**) is high.
The binding rules are in `specs/27-SECURE-DEVELOPMENT.md`,
`specs/28-SUPPLY-CHAIN.md` and `specs/36-OPEN-SOURCE-GOVERNANCE.md`; this file
summarises them.

**Security vulnerabilities:** do not open a public issue or PR. See
[SECURITY.md](SECURITY.md).

## 1. Developer Certificate of Origin (DCO) — required

Candor uses the [DCO v1.1](https://developercertificate.org/), not a CLA, and no
copyright assignment (36 §4, OSG-003). Your copyright stays yours; nobody can
relicense your contribution. Every commit must carry a sign-off that matches the
commit author:

```
git commit -s -m "candor-core: reject truncated envelope header"
# adds:  Signed-off-by: Your Name <you@example.org>
```

A pseudonym is acceptable if you use it consistently and can be contacted at the
address given. CI (`scripts/check-dco.sh`) rejects PRs containing unsigned commits.
To fix a branch: `git rebase --signoff <base>`. Commits that predate the DCO
policy (reachable from the commit recorded in `.dco-epoch` at the repository
root) are exempt; every later commit must be signed off.
Merge commits are checked too: sign them off (`git merge --signoff`; note that
`-s` means --strategy for merge) or, preferably, rebase
instead of merging the base branch into your PR. CI runs the checker and reads
`.dco-epoch` from the PR's **base** revision, so changes to either take effect
only after they are merged (both are owned by the Security Lead in CODEOWNERS).

## 2. Licensing of your contribution

Contributions are licensed under the licence of the directory they touch (see
[LICENSE](LICENSE)): `candor-core` and `candor-safefs` are `Apache-2.0 OR MIT`,
other code is `AGPL-3.0-or-later`, documentation is `CC-BY-SA-4.0`. Every new
source file starts with an `SPDX-License-Identifier:` header.

## 3. Review rules

Every path is classified T0 (crypto and key core), T1 (other Trust Path) or T2
(non-trust-path) in `security/classification.toml` (27 §4).

| Change | Approvals (author excluded) | Who must approve |
|---|---|---|
| T0 (crypto/key core, `candor-safefs`, update verification) | 2 | ≥ 1 Crypto Reviewer **and** ≥ 1 reviewer from a different team/organisation than the author |
| T1 (other Trust Path) | 2 | ≥ 1 Trust Path Maintainer (CODEOWNER), from ≥ 2 different employers in total; Anonymity Reviewer if 27 §11.4 triggers |
| T2 | 1 | CODEOWNER |
| Crypto, key handling, parsing, authN/authZ, logging schema, update code | as above **plus** ≥ 1 Security Team member | — |
| Lockfile / dependency change | 2 | ≥ 1 reviewer checks the cargo-vet record |
| CI, workflows, build scripts, `deny.toml`, `supply-chain/` | 2 | ≥ 1 Release/Supply-chain owner; zizmor clean |
| CODEOWNERS, classification, branch protection | 2 | Security Lead |

- Approvals are dismissed when new commits are pushed; administrators cannot bypass.
- **Two-person rule for the Trust Path:** no single person can get a Trust Path
  change merged. Trust Path commits are signed with a hardware-backed key.
- **Cooling period:** 72 h between final approval and merge for crypto and update
  code, 24 h for other Trust Path code (embargoed security fixes excepted).

### Crypto review rule (27 §11.3)

Any change under `crates/candor-core/`, to protocol constants, labels or `info`
strings, key lifecycles, RNG use, padding sizes, or any bump of a crypto crate
needs a Crypto Reviewer who signs the checklist in the PR template. **Never
implement a cryptographic primitive yourself**; use the vetted crates already in
the workspace, and only through `candor-core`.

## 4. Dependencies — none without justification

A new dependency is a new person you are asking every source to trust (28 §5.1).

1. Prefer the standard library or an existing workspace dependency.
2. If you still need one, add to the PR (and to the crate's `SPEC-NOTES.md`) a
   justification: function, alternatives considered, maintainer health, `unsafe`
   count, transitive fan-out, licence.
3. Pin it exactly (`"=x.y.z"`), `default-features = false`, minimal features.
4. The version must be ≥ 14 days old unless it fixes a vulnerability affecting us.
5. Add a cargo-vet audit (or a time-limited exemption, ≤ 180 days) in
   `supply-chain/`; `cargo deny check` and `cargo vet` must pass.
6. No git dependencies, no wildcard versions, no OpenSSL, no `build.rs` that
   touches the network.

## 5. Coding rules (summary of 27 §12)

- `unsafe` is forbidden in the workspace (`unsafe_code = "forbid"`).
- No panics on untrusted input: no `unwrap`/`expect`/`panic!`/unchecked indexing
  on attacker-controlled data; use checked arithmetic.
- Secrets are zeroized and never appear in `Debug`, `Display`, logs or errors.
- Constant-time comparison (`subtle`) for MACs, tags and secrets.
- No exact timestamps on source-linked records; no new log field without an
  anonymity classification.
- Tests for the positive, negative and hostile-input paths, mapped to spec test IDs.

## 6. Before you open a PR

```
make check     # fmt-check, clippy -D warnings, tests, cargo-deny, docs-lint
make repro     # optional locally; CI always runs the build-twice check
```

Disclose AI assistance in the PR (`AI-Assisted: yes/no`). AI-assisted code is
reviewed exactly like any other code, and you must be able to explain it. Never
give AI tools real submissions, secrets or signing material.

## 7. Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
