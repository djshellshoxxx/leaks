# IMPL-RM0 — Foundations (repository, CI, supply chain, reproducible builds)

Status: Draft v1.0 · Edition applicability: both · Owner: T7 Supply Chain & Release (with Security Lead) · Standard: `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md`

## 1. Purpose and scope

| Item | Content |
|---|---|
| Milestone | RM-0 (`38` §4): repositories, protected branches, DCO, CI with pinned actions, cargo-vet/deny, SBOM, two independent reproducible builders, TUF root ceremony (test keys), threat-model baseline, SG gates wired into CI |
| Components | C-30 source repository & review · C-31 CI + reproducible builders · C-32 release signing / TUF / transparency log (**test keys only**) · C-33 package mirror (skeleton) |
| Specs implemented | 27 §3–§4, §10–§13 (roles, tiers, threat modelling, review, coding-standard enforcement, gate wiring) · 28 (SCM-001..050, RM-0 subset) · 33 (ceremony with test keys) · 36 (DCO, governance) · 38 RM-0, RM-005 · R8 §4.3–§4.4, §5.4 (RM-0 row) |
| Not in scope | Production keys (RM-7), product code (RM-1+) |

## 2. Preconditions

| # | Precondition | Evidence |
|---|---|---|
| P1 | Master threat model 02 signed off by the Security Lead (baseline version tagged) | Signed tag `tm-v1.0` |
| P2 | Forge organisation with phishing-resistant MFA enforced for every member with write access (SCM-007) | Forge org settings export |
| P3 | Every maintainer has a hardware-backed signing key listed in `security/allowed_signers` (SCM-001) | File plus signed enrolment record |
| P4 | Builder B operator identified: a different organisation, jurisdiction, admin set, hosting provider and IdP (SCM-031; 38 risk register) | Signed MoU |
| P5 | Roles staffed per 27 §3.1 (Security Lead + deputy, ≥ 2 Crypto Reviewers, ≥ 3 Trust-Path Maintainers, ≥ 2 Anonymity Reviewers) | `GOVERNANCE.md` roster |
| P6 | Independent auditor helper available. `research/R9-secure-code-audit.md` is present | R9 file |

## 3. Build sequence

Each step ends with its own verification. Steps 0.1–0.6 must be done before any product crate merges.

### 0.1 Repository governance skeleton
- **Build:** `LICENSE`/`LICENSES/` (ADR-031 split), `SECURITY.md`, `CONTRIBUTING.md` (DCO), `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `.github/CODEOWNERS` covering every T0/T1 path, `security/allowed_signers`, `.dco-epoch`.
- **Rules:** SCM-001 (signed commits, hardware keys), 36 DCO, SDL-014/015 (CODEOWNERS per tier).
- **Pitfalls:** INC-37 (xz: a single maintainer gained release control through social engineering, so no single person may hold sole merge or release power). INC-42 (account hijack, so MFA plus signed commits).
- **Verify:** `scripts/check-dco.sh` on every PR commit. Signed-commit verification against `allowed_signers` in CI (`git log --format='%G?'` must be `G` for every commit in range).

### 0.2 Branch protection as code
- **Build:** `security/branch-protection.toml` with forbidden force-push and deletion, linear history, required checks (the full list in §5), required reviews per 27 §11.1, stale-review dismissal, no admin bypass, signed commits required. A `bp-verify` job compares the forge API state to the file daily and on change.
- **Rules:** SCM-003, SCM-004 (SLSA Source L4 for T0/T1), SDL-014/015.
- **Pitfalls:** an admin override used "just once" (27 §11.1). Required checks that silently stop running after a job rename (so `bp-verify` asserts check names exist in the workflows).
- **Verify:** `bp-verify` fails on any drift. Negative test: a PR from a test account without approval cannot merge.

### 0.3 Classification and security scaffolding
- **Build:** `security/classification.toml` (every path → T0/T1/T2; unclassified files fail CI), `security/unsafe-allowlist.toml` (initially only `candor-memlock`), `security/rule-of-2.toml`, `security/proof-tcb.toml` (SL-R-004), `security/asvs-map.csv`, `security/memory-unsafe-inventory.md` (27 §9), `security/review-checklist.md`, `security/semgrep/*.yaml` (vendored rules, no registry fetch), `threat-model/features/TEMPLATE.md` (27 §10.2), `process/AUDIT-CHECKLIST.md` (from R9), `process/audits/`.
- **Rules:** 27 §4, §9, §10.2; IMP-STD-024.
- **Verify:** ST-004 classification lint over the full tree. The `tm-link` lint rejects a T0/T1 PR without a `Threat-Model:` line.

### 0.4 Toolchain, workspace and lint configuration
- **Build:** `rust-toolchain.toml` (pinned stable plus `rustfmt` and `clippy`; nightly pinned separately for Miri/fuzz). `.cargo/config.toml` with `--remap-path-prefix` for source, `$CARGO_HOME` and target (ADR-051(5)). Root `[workspace.lints]` with the full IMPL-00 §4.2 deny set (T2 crates may relax lints only through a reviewed per-crate override). Workspace `clippy.toml` with `disallowed-macros`/`-methods`/`-types` per §4.2. Profiles per SI-A-01.
- **Rules:** SI-A-01, SI-A-02, SI-A-03, SI-A-04, SI-A-08; 27 §12.
- **Pitfalls:** a crate-local `clippy.toml` **replaces** the workspace file, which drops workspace bans. Crate-local files must restate the workspace set (a CI test diffs them). Ambient `RUSTFLAGS` cause reproducibility drift.
- **Verify:** a CI grep asserts the profile keys and the lint levels. A seeded-violation fixture crate (`tools/lint-fixtures/`) must fail clippy with each banned pattern.

### 0.5 Supply-chain gates
- **Build:** `deny.toml` (advisories `unmaintained = all`, `yanked = deny`; bans on git sources, duplicate crypto crates and `openssl` outside the FIPS feature; licence allow-list per ADR-031; every `skip` carries an expiry comment, for example ADR-051(1)). `supply-chain/` cargo-vet with the custom criterion `candor-crypto-reviewed`, imports carrying a 6-month review date, and exemptions carrying an expiry. A `cooldown-check` job (crates.io `created_at` ≥ 14 days unless the PR has the `security-fix` label and a diff review). A daily scheduled `cargo audit`. `cargo geiger` baseline. Daily maintainer/owner-change detection (SCM-020).
- **Rules:** SCM-008..SCM-020, SL-R-009, SI-A-09; IMP-STD-014.
- **Pitfalls:** INC-40 (event-stream: a new maintainer added a malicious dependency, so owner-change alerts and re-review). INC-43 (typosquats, so a name allow-list in the mirror, ST-135). Leaving cargo-vet exemptions open indefinitely.
- **Verify:** ST-010 and ST-011 green. A seeded fixture (git dependency, yanked crate, 3-day-old version) is rejected. ST-135 typosquat allow-list test.

### 0.6 CI hardening
- **Build:** all actions pinned by full commit SHA of mirrored forks (SCM-022). Top-level `permissions: {}` with per-job minimal grants and `id-token: write` only in attestation jobs (SCM-023). No `pull_request_target` or privileged `workflow_run` on PR code (SCM-026). No curl-to-shell, `@latest` or unpinned downloads (SCM-024). Ephemeral runners with an egress allow-list for release jobs (SCM-027). Release jobs do not consume PR caches (SCM-029). Secret masking checked with a canary secret (SCM-028). zizmor (`--persona=auditor`) is a required check.
- **Rules:** SCM-022..SCM-029; R8 §4.3 Scorecard subset.
- **Pitfalls:** INC-44 (tj-actions: a mutable tag repointed to malicious code that dumped secrets into logs). INC-39 (Codecov: a remote script modified upstream). INC-45 (worm spreading through CI tokens).
- **Verify:** ST-133 CI configuration policy. `scripts/check-actions-pinned.sh`. Scorecard checks Dangerous-Workflow, Token-Permissions, Pinned-Dependencies, Branch-Protection, Code-Review and Signed-Releases = 10/10.

### 0.7 Reproducible builds and two independent builders
- **Build:** a hermetic two-phase build (fetch, then no-network) in a digest-pinned container: `SOURCE_DATE_EPOCH` from the tag, `CARGO_INCREMENTAL=0`, `--locked --frozen`, vendored sources, `cargo auditable build`. Builder A (forge CI) and Builder B (a separate organisation, separate mirror, non-GitHub infrastructure) both run `git verify-tag` against the pinned maintainers keyring **inside** the build and record the result in provenance (R8 §1.7). Hashes are compared and diffoscope runs automatically on any mismatch (SCM-033).
- **Rules:** SCM-016, SCM-018, SCM-030..SCM-038; ADR-022; ADR-051(5); SL-R-010.
- **Pitfalls:** INC-38 (SolarWinds: build-system implant, so independent rebuild). INC-48/INC-52 (signed or distributed artefacts replaced, so hash comparison across builders). Path and username leaks embedded through `file!()` and panic locations.
- **Verify:** ST-131 (bit-identical across A and B) and ST-132 (artefact+hash swap detection). `strings <bin> | grep -E '/home/|/root/|runner'` returns empty.

### 0.8 SBOM and provenance
- **Build:** CycloneDX 1.6 (with CBOM) and SPDX 3.0 from both builders (SCM-043). SLSA provenance via the generic generator or `attest-build-provenance` (SCM-035). `slsa-verifier` in the publishing step. Builder B signs with an identity not controlled by A (SCM-036).
- **Pitfalls:** the reusable workflows alone do not meet SLSA L3. Provenance distribution and verification must be added (R8 §4.4).
- **Verify:** `slsa-verifier verify-artifact --source-uri … --source-tag …` passes, and a tampered-provenance negative test fails. SBOM completeness check against `cargo auditable` data.

### 0.9 TUF repository and test-key ceremony
- **Build:** a TUF repository (`tough` or `rust-tuf`, chosen in a design note) with root 3-of-5 and targets 2-of-3 hybrid (Ed25519 + ML-DSA-65) **test** keys (SCM-040). A ceremony script that refuses when signer = author, or signer = builder-B operator (SL-R-010). The ceremony transcript is logged to the transparency log skeleton (C-32). The test client checks freeze, rollback and mix-and-match, and an expired timestamp older than 7 days fails closed with an operator alert (R8 §4.5).
- **Rules:** SCM-040..SCM-042, SCM-045..SCM-050; ADR-022; 33.
- **Pitfalls:** INC-58 (Storm-0558: an online signing key was stolen, so offline root and targets). INC-49 (NotPetya: an update channel used for broad compromise, so threshold signing and transparency).
- **Verify:** ST-130 update-client rejection suite (test keys). The root rotation chain N→N+1→N+2 is verified.

### 0.10 Test and gate infrastructure
- **Build:** CI jobs for `fuzz-smoke` (≥ 60 s per target per PR) and `fuzz-nightly` (≥ 1 h per target), `miri`, `kani`, `mutants` (in-diff), `semgrep`, `secret-scan` (ST-009, history delta plus artefacts), `geiger-diff`, `multi-arch-crypto` (x86_64 + aarch64 native), `anon-marker-scan` (AT-001 harness: canary generator plus sink scanner over logs, DB/WAL dumps, files and responses; required from RM-1, RM-002), `gate-evaluator` and `gate-map` (SDL-046, SDL-063), signed milestone report (RM-005).
- **Rules:** IMPL-00 §11; 29; 30; SDL-046; SDL-063.
- **Verify:** every job has a seeded-failure fixture proving it can fail (fuzz crash corpus, planted secret, planted canary in a log, surviving mutant).

### 0.11 Baseline threat model and documentation
- **Build:** 02 baseline tagged. `threat-model/features/RM0-supply-chain.md` (DFD of forge → CI → builders → TUF → mirror). Rebuild instructions (SCM-038).
- **Verify:** SG-01 baseline. Security Lead sign-off.

## 4. Component-specific threat checklist (auditor)

| # | Check | Pass condition |
|---|---|---|
| A1 | Workflow injection: `${{ github.event.* }}` in `run:`, `pull_request_target`, `workflow_run` executing PR code | None present (zizmor clean) |
| A2 | Token scope: top-level `permissions: {}`; per-job grants minimal; `id-token: write` only in attestation jobs | Matches SCM-023 |
| A3 | Pinning: every `uses:` is a 40-hex SHA of a mirrored fork. Container images pinned by digest. Tools installed `--locked` with exact versions | 0 unpinned references |
| A4 | Remote code: curl/wget piped to a shell, `npx`/`cargo install` without `--locked`/version | None |
| A5 | Secrets: none in the repo, history delta, logs or artefacts. Fork PRs run without secrets. Masking canary works | ST-009 green |
| A6 | Cache poisoning: release jobs do not restore caches written by PR jobs | SCM-029 |
| A7 | Reproducibility: no timestamps, paths, hostnames or usernames in artefacts. Remap covers source, target and CARGO_HOME | Two builders bit-identical |
| A8 | Builder independence: B shares no admin, IdP, mirror or hosting with A | Documented and verified |
| A9 | Signer separation: ceremony refuses author = signer, and builder-B = signer | Negative test passes |
| A10 | Lint config: no crate-local `clippy.toml` or `[lints]` weakens the workspace deny set | Diff test green |
| A11 | Branch protection matches the file, admins cannot bypass, required checks exist | `bp-verify` green |
| A12 | Gate jobs can fail: each has a seeded-failure fixture | All fixtures fail as expected |
| A13 | Supply-chain configs: every deny `skip`/vet exemption has an expiry and a reason | 0 unexpired-without-reason |

## 5. Test plan

| ID | Test | Tool / command |
|---|---|---|
| ST-004 | Classification + `tm-link` + route-registry lint skeleton | `python3 tools/arch_lint.py` (to build) |
| ST-007 | Rust safety lints, seeded fixtures | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| ST-008 | Semgrep rules (vendored) | `semgrep --config security/semgrep/ --error --metrics=off` |
| ST-009 | Secret scanning (history delta, artefacts, container layers) | `gitleaks detect --log-opts=<range> --redact` (pinned) |
| ST-010/011 | Advisories, bans, licences, vet | `cargo deny --locked check`; `cargo vet --locked`; `cargo audit` |
| ST-013 | RNG lint | Semgrep rule plus `disallowed-methods` |
| ST-131 | Reproducible build (A vs B) | `scripts/repro-check.sh`; diffoscope on mismatch |
| ST-132 | Artefact+hash swap detection | Swap fixture → verify fails |
| ST-133 | CI configuration policy | `zizmor --offline --persona=auditor .github`; `scripts/check-actions-pinned.sh` |
| ST-134 | Malicious install-script canary | Fixture crate with a network-touching `build.rs` → rejected |
| ST-135 | Typosquat allow-list | Mirror rejects a non-allow-listed name |
| ST-130 (test keys) | TUF client rejection suite | Rollback/freeze/mix-and-match fixtures |
| ST-167 | Spec-constant lint | `make docs-lint` |
| SG-wiring | `gate-map` fails on an unmapped ST/AT ID | Seeded unmapped ID |

## 6. OPSEC checklist

| Metadata at risk | Prevention |
|---|---|
| Builder paths, usernames and hostnames inside binaries (`file!()`, panic locations, debuginfo) | `--remap-path-prefix` (source, target, CARGO_HOME). `strip = "symbols"`. `debug = false`. A strings scan in CI |
| Build timestamps | `SOURCE_DATE_EPOCH` from the tag. No `chrono::now` in `build.rs` |
| Contributor identity and timezone in commit metadata | Contributors may use pseudonyms and a UTC commit timezone (`TZ=UTC git commit`). Documented in CONTRIBUTING |
| Internal mirror and CI hostnames in SBOM or provenance | SBOM generator configured to emit public package URLs only. Review the provenance fields |
| CI logs exposing secrets or environment | Masking canary. Release logs private (SCM-028) |
| Tool telemetry (semgrep metrics, IDE plugins, package managers) | `--metrics=off`. Network egress allow-list on runners. No analytics in the docs site |
| Test fixtures containing real-looking IPs, names or UAs | Canary-only fixtures (IMP-STD-021). Fixture scanner |

## 7. Exit criteria (RM-0 definition of done)

- [ ] 28 SCM gates for the RM-0 scope are green on the skeleton: SCM-001..011, 019, 022..030, 033, 035, 043 wired. SCM-031/036 met (independent B), with production keys deferred.
- [ ] Builders A and B produce a bit-identical skeleton artefact (38 RM-0 exit). diffoscope is empty.
- [ ] Every SG gate that has meaning at RM-0 is wired into CI with a seeded-failure fixture: SG-02, 03, 05, 07 (infrastructure), 13, 14, 15, 25.
- [ ] Scorecard subset 10/10 (R8 §4.3).
- [ ] TUF test-key ceremony completed with a logged transcript and the separation checks working.
- [ ] Every repository path is classified. `process/AUDIT-CHECKLIST.md` and `process/audits/` exist.
- [ ] Independent audit `process/audits/AUDIT-RM0.md` shows 0 open Critical/High. Mediums are dispositioned.
- [ ] Signed milestone report with gate results (RM-005).

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM0-001 | Every commit on protected branches SHALL be signed by a key in `security/allowed_signers` and carry a DCO sign-off. CI SHALL reject other commits. | INC-37; INC-42; B-SL-19 | THR-024 | C-30 | TST: signature-verify job; `check-dco.sh` |
| IMP-RM0-002 | Branch protection SHALL be declared as code and continuously compared to the forge state (`bp-verify`), with no admin bypass. | B-SL-02; INC-37 | THR-024 | C-30 | TST: `bp-verify`; SG-02 |
| IMP-RM0-003 | Every repository path SHALL be classified T0/T1/T2, and an unclassified file SHALL fail CI. | B-SL-45 | THR-024; THR-012 | C-30 | TST: ST-004 |
| IMP-RM0-004 | The workspace SHALL enforce the IMPL-00 §4.2 deny set, and no crate-local configuration SHALL weaken it. | B-SI-01; B-SI-03 | THR-012; THR-032 | C-31 | TST: lint-config diff test; seeded fixtures |
| IMP-RM0-005 | Path-prefix remapping, `SOURCE_DATE_EPOCH` and `--locked --frozen` SHALL be set from checked-in configuration only. | ADR-022; ADR-051 | THR-024; THR-016 | C-31 | TST: strings scan; ST-131 |
| IMP-RM0-006 | cargo-deny, cargo-vet (with expiring imports and exemptions), daily cargo-audit, the 14-day cooldown check and owner-change detection SHALL be required checks. | B-SI-13; B-SI-14; B-SI-15; B-SL-04; INC-40; INC-43 | THR-024 | C-30; C-31 | TST: ST-010; ST-011; ST-135; cooldown fixture |
| IMP-RM0-007 | Workflows SHALL pin actions by full SHA, default to no token permissions, avoid `pull_request_target`, and pass zizmor. | INC-44; INC-39; INC-45 | THR-024 | C-31 | TST: ST-133 |
| IMP-RM0-008 | Two independently operated builders SHALL each verify the signed tag inside the hermetic build and produce bit-identical artefacts. A mismatch SHALL trigger diffoscope and block release. | B-SL-03; B-SL-18; B-SL-19; INC-38 | THR-024; THR-025 | C-31 | TST: ST-131; ST-132 |
| IMP-RM0-009 | Every artefact SHALL have CycloneDX and SPDX SBOMs and SLSA provenance from both builders, verified with `slsa-verifier` (including a negative test). | B-SL-43; ADR-022 | THR-024 | C-31; C-32 | TST: provenance verify job |
| IMP-RM0-010 | The TUF test-key ceremony SHALL enforce signer ≠ author ≠ builder-B operator and log its transcript. | B-SL-01; INC-58 | THR-025; THR-024 | C-32 | TST: ceremony negative tests; ST-130 |
| IMP-RM0-011 | CI SHALL provide fuzz, Miri, Kani, mutation, multi-arch, Semgrep, secret-scan, geiger-diff and `anon-marker-scan` jobs, each with a seeded-failure fixture. | B-SI-09; B-SI-11; B-SL-16; INC-60 | THR-012; THR-016 | C-31 | TST: fixture runs |
| IMP-RM0-012 | Release and build runners SHALL be ephemeral with an egress allow-list, and release jobs SHALL NOT consume PR caches. | INC-39; INC-44 | THR-024 | C-31 | TST: egress canary; cache-key audit |
| IMP-RM0-013 | `process/AUDIT-CHECKLIST.md` and `threat-model/features/TEMPLATE.md` SHALL exist before RM-1 code merges. | B-SL-09; B-AU-01 | THR-024 | C-30 | INSP: file presence check |
| IMP-RM0-014 | Scorecard checks Dangerous-Workflow, Token-Permissions, Pinned-Dependencies, Branch-Protection, Code-Review and Signed-Releases SHALL score 10/10 at RM-0 exit. | B-SL-42 | THR-024 | C-30; C-31 | TST: scheduled Scorecard job |

## 9. Residual risks and open issues

- With Builder B's infrastructure not yet in place, the current "build twice on one runner" check (`reproducibility` job) proves determinism, not independence. This is an accepted interim gap until P4 is met.
- Scorecard measures configuration, not reviewer diligence.
- Hosted CI runners are third-party infrastructure (THR-024). Release builds must move to the self-managed ephemeral runners required by SCM-027.
- Open: choice of TUF library (`tough` vs `rust-tuf`; maintenance status UNVERIFIED in R8). Tamarin/ProVerif CI image pinning.

### 9.1 As-built gap list (repository state 2026-10-01 vs this standard)

| # | Area | Present | Gap → action |
|---|---|---|---|
| G1 | CI jobs | fmt, clippy, test, test-nonroot, cargo-deny, cargo-vet, docs-lint, workflow-lint (SHA pins, zizmor), dco, reproducibility (same runner, twice), sbom (CycloneDX) | Missing: signed-commit verification, `bp-verify`, cargo-audit schedule, geiger, fuzz, Miri, Kani, mutants, multi-arch, Semgrep, secret-scan, Scorecard, SPDX, SLSA provenance, Builder B, `anon-marker-scan`, gate-evaluator. Steps 0.2, 0.5, 0.7, 0.8, 0.10 |
| G2 | Workspace lints | `unsafe_code = forbid`; `unwrap_used`/`expect_used`/`panic` deny; `indexing_slicing`, `arithmetic_side_effects` **warn**; workspace `clippy.toml` bans only `dbg!` | Raise to the full §4.2 deny set. Add `print_*`, `as_conversions`, casts, `string_slice`, `todo`, `unimplemented`, `unreachable`, `mem_forget`, `disallowed-methods`. `crates/candor-log/clippy.toml` replaces the workspace file and drops the `allow-*-in-tests` settings → restate them (step 0.4) |
| G3 | `.cargo/config.toml` | Absent. Remap lives in `scripts/repro-check.sh` | Move flags to checked-in config (SI-A-01) |
| G4 | `security/` scaffolding | Absent (classification, unsafe allow-list, rule-of-2, proof-tcb, asvs-map, semgrep) | Step 0.3 |
| G5 | Audit gate artefacts | `process/AUDIT-CHECKLIST.md` and `process/audits/` absent. No audit reports exist for existing crates | Step 0.3. Retroactive audits of the RM-1 crates (see IMPL-RM1 §9.1) |
| G6 | cargo-vet | 167 exemptions, 0 own audits. The `candor-crypto-reviewed` criterion is defined but no crypto crate is audited against it | Audit the crypto set (SCM-010) before RM-1 exit. Add expiries to exemptions |
| G7 | Cooldown | PR template states 14 days, but no automated check exists | `cooldown-check` job (step 0.5) |
| G8 | Threat-model workflow | No `threat-model/features/` directory and no `tm-link` lint | Step 0.3 |
| G9 | TUF / ceremony | Not started | Step 0.9 |
| G10 | deny.toml | Present (advisories, bans, sources, licences). `sha3` skip expires 2026-12-30 (ADR-051(1)) | Add an expiry-check job for skips |
