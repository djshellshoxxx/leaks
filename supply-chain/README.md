<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# supply-chain/ — cargo-vet store

Implements `specs/28-SUPPLY-CHAIN.md` §5.2 (cargo-vet) and gate SG-05.
Tool pin: `cargo install --locked --version =0.10.2 cargo-vet`.

| File | Purpose | Edited by |
|---|---|---|
| `config.toml` | imports, per-crate policy, `[[exemptions]]` | humans + `cargo vet` |
| `audits.toml` | Candor's own audits and the custom criterion `candor-crypto-reviewed` | humans (`cargo vet certify`) |
| `imports.lock` | pinned snapshot of the imported audit sets | `cargo vet` only |
| `trusted-importers.toml` | Security-Lead approval record for each import (28 §5.2) | Security Lead |

`cargo vet` rewrites `config.toml`, `audits.toml` and `imports.lock` in its own
format and drops comments, so policy notes live here.

## Imports

Mozilla, Google, Bytecode Alliance and Zcash audit sets (URLs in `config.toml`,
approval records in `trusted-importers.toml`). Imports are re-reviewed yearly.
An imported audit never grants `candor-crypto-reviewed`.

## Policy

- Everything shipped in T0/T1: `safe-to-deploy` (cargo-vet default for
  first-party crates). Dev-only dependencies: `safe-to-run`.
- Staging (ADR-052(8), AUD-RM0-INF-01). **PR CI** (`ci.yml` job `cargo-vet`,
  `cargo vet --locked`) uses the committed policy: `safe-to-deploy` for every
  dependency, with no `candor-crypto-reviewed` anywhere in `config.toml`.
  **Release gate** (`release-gate.yml`, tags `v*` and `workflow_dispatch`, never
  PRs) runs `scripts/vet-release.sh`: it copies the store to a temp dir, adds
  `[policy."<crate>:<version>"] criteria = ["safe-to-deploy",
  "candor-crypto-reviewed"]` for every locked version of every crate in
  `crypto-set.txt`, and runs `cargo vet --locked --store-path <tmp>`.
- `crypto-set.txt` is the single source of truth for the crypto set (28 §5.2
  list plus `blake3`, `hmac`, `curve25519-dalek`, `rand_chacha` as present in
  `Cargo.lock`). `check-vet-policy.py` fails if a Cargo.lock crate from that
  list is missing from the file or an entry is stale.
- `candor-crypto-reviewed` is NEVER granted by an exemption, `[[trusted]]` or
  wildcard audit (AUD-RM0-INF-05): only real audits recorded by a Crypto
  Reviewer with `cargo vet certify <crate> <ver> candor-crypto-reviewed` count
  (cargo-vet also requires the criterion of the crypto crates' dependencies
  unless the audit sets `dependency-criteria`). Until those audits exist the
  release gate fails; this is a release blocker before RM-6. Do not paper over
  it with exemptions. `scripts/check-vet-policy.py` (CI job cargo-vet) enforces
  the staging, the expiry notes, a policy for every crate under `crates/`, the
  crypto-set coverage and completed import approvals.
- Exemptions expire after ≤ 180 days. cargo-vet has no expiry field, so every
  exemption's `notes` must contain `expires YYYY-MM-DD`; reviewers reject
  exemptions without it.

## Initial setup and maintenance

```
cargo vet regenerate imports      # fetch/refresh imports.lock
cargo vet regenerate exemptions   # baseline exemptions for unaudited crates (RM-0 only)
cargo vet                         # must pass in CI (cargo vet --locked)
cargo vet suggest                 # review backlog
```

Status (2026-10-01): exemptions regenerated (`cargo vet regenerate
exemptions`); every exemption is `safe-to-deploy` with notes "not yet audited;
expires 2027-03-30 (28 §5.2)". `cargo vet --locked` passes; the release gate
fails until the Crypto Reviewer audits exist.
