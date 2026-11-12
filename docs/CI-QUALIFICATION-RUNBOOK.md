<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Candor CI qualification and blocker triage (2026-11-10)

**Status: developer/operator diagnostic guide, not release evidence or security approval.**
Source snapshot: repository default `claude/tender-tesla-z8tfnl` at
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`. This is **not** the
`main` branch. The required modular rules in `AGENTS.md` are proposed in
[draft PR #8](https://github.com/djshellshoxxx/leaks/pull/8), not merged.

This guide explains how to distinguish **scoped changes** from unrelated
red workspace gates. Do not report a PR as verified or release-ready just
because some checks pass.

## Exact-head evidence procedure

1. Record the **full 40-character head SHA** and base SHA of the PR being
   evaluated. Make sure GitHub Actions is inspecting that exact head or its
   corresponding PR merge ref and record which one. A CI result from another
   PR, branch, or older head does not qualify the new head.
2. Review **all** workflow jobs, including skipped and cancelled jobs, and
   the exact log locations of each failure. Keep their failing status intact.
3. For a code move or structural test extraction, compare test function names,
   negative assertions, property tests and fixture bytes before and after.
   Textual equivalence is **not** proof that the Rust compiler discovers or
   executes the moved tests. Obtain a focused test result for the changed
   package and the required workspace/security gates.
4. Record the source revision, commands, outputs, CI links, approvals and
   unresolved blockers in `docs/handoffs/CHATGPT_ZERO_CODEX_LATEST.md`
   on the owner branch. Ensure a handoff-only commit also gets a new check.
5. Do not alter rustfmt, Clippy, advisories, cargo-vet or DCO enforcement to
   make checks green. Do not take over another active PR to fix its blockers.

## Current verified CI snapshot

As inspected on **2026-11-10** (logs, not local test runs):

| Candidate | Exact head | Workflow | Observed outcome |
| --- | --- | --- | --- |
| Draft PR #13 (source-UI padding tests) | `1194085bc4ca1b58c919832aeeec40ea54d7da86` | [run 42819538406](https://github.com/djshellshoxxx/leaks/actions/runs/42819538406) | Completed: 7 pass, 6 fail, 1 skip |
| Draft PR #14 (read-only audit ledger) | `cb88d8e5d540ca0519801f59ab5001250b97463f` | [run 42819606916](https://github.com/djshellshoxxx/leaks/actions/runs/42819606916) | Completed: same job distribution |
| Draft PR #15 (documentation ledger) | `4df90c6c65d607d7af96ac6f4df507506230ece4` | [run 42819761010](https://github.com/djshellshoxxx/leaks/actions/runs/42819761010) | Completed: same job distribution |
| Draft PR #12 (continuation policy) | `47d5136360c8c773ce39b6a7dc88cec11bdda1b6` | [run 42754179538](https://github.com/djshellshoxxx/leaks/actions/runs/42754179538) | Completed: failed, including DCO |

PRs #13–#15 passed DCO, docs-lint, workflow-lint, repo-lints,
secret-scan, SBOM and reproducibility. They failed workspace fmt,
Clippy, tests, unprivileged tests, cargo-deny and cargo-vet.
The scheduled-only supply-chain job was skipped by the normal PR trigger.
**No focused source-UI runtime test was run or verified in this review.**

## Diagnosed gates and ownership

| Gate | Log-backed cause on PR #13 | Required action |
| --- | --- | --- |
| fmt | `cargo fmt --all -- --check` reports differences only in `crates/candor-worker/src/lib.rs` and `crates/candor-worker/tests/job_retention.rs`, not the extracted test files. | Existing **draft PR #11** owns the formatted worker files; do not duplicate. |
| clippy | Four `arithmetic_side_effects` errors in `candor-worker` during the workspace check. | **PR #11** has a proposed focused remediation. Its merge/review is a separate decision. |
| test and unprivileged test | `candor-auth/tests/session_invariants.rs` fails to import `Audience`, `Session`, `SessionError`, `SessionToken`, `StaffClass` from `candor_auth` (E0432). No complete workspace test run follows. | Subject-bound sessions are owned by **draft PR #7**; confirm integration and test acceptance with its owner. |
| cargo-vet | `scripts/check-vet-policy.py` reports **12 missing approval fields** across `bytecode-alliance`, `google`, `mozilla`, `zcash` imports. | **Security Lead** alone must review and fill genuine import approvals, `approved-by`, `approved`, `review-due`. Do not invent sign-off. |
| cargo-deny | Locked dependency advisories, including `tokio` and `zip`, cause the advisories subcheck to fail. Bans, licenses and sources passed in this run. | Review vulnerable-code reachability and permitted pinned dependency updates with the responsible owner; do not ignore advisories or change supply-chain policy to suppress them. |
| DCO on PR #12 | PR #12 commit lacks required Signed-off-by trailer. | Its **existing owner** must correct history through the authorized DCO procedure, without rewriting another agent's branch. |

These are *failure-attribution observations*, not a claim that PR #13 or
the default branch is secure, correct or qualified. The same red gates on
docs-only PRs support preexisting-workspace classification but are not a
substitute for package-specific test execution.

## Local reproduction commands (reference only — not executed here)

The pinned Rust toolchain is **1.94.1** (`rust-toolchain.toml`). From a
checked-out exact PR head on a suitable Unix environment:

```sh
rustc --version
cargo fmt --all -- --check
cargo test -p candor-source-ui --all-targets --locked
cargo clippy -p candor-source-ui --all-targets --all-features --locked -- -D warnings
python3 tools/traceability.py
python3 tools/constants_lint.py
bash crates/candor-safefs/scripts/lint-safefs.sh
bash crates/candor-log/scripts/lint-logging.sh
```

For whole-workspace checks, see [`Makefile`](../Makefile) and
[`ci.yml`](../.github/workflows/ci.yml). CI uses an additional
unprivileged-user workspace test with a production-like memlock limit;
`make test` is **not equivalent** to this runner job.

The project requires cargo-deny and cargo-vet gates in addition to focused
tests; passing the focused commands is necessary but insufficient for
integration or release. The separate
[`process/STATUS.md`](../process/STATUS.md) records human security-review
holds, including external crypto review and source-anonymity guarantees.

## GitHub collaboration and publication boundaries

Use the existing PRs rather than opening duplicate blocker issues.
Keep exact-head evidence in the owning PR/handoff. No automatic merge,
workflow policy change, deployment, wiki publication or release is
authorized by this guide. Wiki source is already owned by draft
[PR #9](https://github.com/djshellshoxxx/leaks/pull/9);
the **live GitHub Wiki remains unpublished**. After the PR #9 owner
accepts corrections, link this guide from the Developer Guide without
overwriting that active branch.

## Additive focused C-06 source-UI qualification (2026-11-10)

Draft [PR #13](https://github.com/djshellshoxxx/leaks/pull/13) now proposes an **additional**, narrowly scoped GitHub Actions workflow, `.github/workflows/source-ui-qualification.yml`, at commit `3e1276fca89c30103fb781d0c30ef3fe21c75e71`.

The proposed job checks out the pull-request revision using the repository's pinned action, installs the repository's pinned Rust toolchain via its existing local setup action, and executes:

```sh
cargo fmt -p candor-source-ui -- --check
cargo test -p candor-source-ui --all-targets --locked
cargo clippy -p candor-source-ui --all-targets --all-features --locked -- -D warnings
```

It uses a read-only repository token, disables checkout credential persistence, does not access secrets or production services, and is triggered by pull requests touching the source-UI crate or the focused workflow/its toolchain inputs. The existing mandatory workspace tests, supply-chain checks, DCO, and other CI gates remain **unchanged and independently required**. This additive workflow requires the normal security review appropriate to any workflow change.

At first inspection, the [focused workflow run 42849936348](https://github.com/djshellshoxxx/leaks/actions/runs/42849936348) was **in progress** and the [workspace run 42849935985](https://github.com/djshellshoxxx/leaks/actions/runs/42849935985) was **queued**. Neither constitutes passing evidence yet. The preceding PR #13 exact head `20c1361bf85bed7c89b7da7431ed9eae36b494d2` [run 42840341857](https://github.com/djshellshoxxx/leaks/actions/runs/42840341857) completed with 7 passes, 6 failures and 1 skip, matching the unresolved workspace blockers, so the structural test extraction remains unqualified.

This is **workflow-source documentation**, not a claim that the source-UI module passed, the test extraction is independently accepted, or the release/security gates were satisfied.

## Later exact-head CI reconciliation — 2026-11-10

This section supersedes the earlier **in-progress** status for the *specific* C-06 workflow but does not change its historical wording or any release criteria.

| Exact draft head | Workflow and evidence | Result |
| --- | --- | --- |
| PR #13 `84ad15de5f0deb8d2b56c262999454463d6c9854` | [Focused source-UI 42851353993](https://github.com/djshellshoxxx/leaks/actions/runs/42851353993) | **Success**, single scoped job: cargo fmt, package tests and all-target/all-feature warning-deny Clippy. |
| Same PR #13 exact head | [Mandatory workspace 42851354059](https://github.com/djshellshoxxx/leaks/actions/runs/42851354059) | **Failure**: 7 passing, 6 failing, 1 skipped. |
| Audit PR #14 head `daa08e09493cfb3f223e5a3296092a58cbb0b2e2` | [Workspace 42850455718](https://github.com/djshellshoxxx/leaks/actions/runs/42850455718) | **Failure**: 7 pass / 6 fail / 1 skip. |
| Docs PR #15 head `6abd13840968c01664ca1fa62ca53ef7ba377e7a` | [Workspace 42850726230](https://github.com/djshellshoxxx/leaks/actions/runs/42850726230) | **Failure**: 7 pass / 6 fail / 1 skip. |

The first focused run [42849936348](https://github.com/djshellshoxxx/leaks/actions/runs/42849936348), on earlier PR #13 head `3e1276fca89c30103fb781d0c30ef3fe21c75e71`, also passed; its hosted logs showed **87 successful tests, zero failures**, including the three `padding::` tests newly relocated from `render.rs`. The later exact-head focused workflow succeeded too. The Rust files and additive workflow did not change between those two commits; the later head modified only the handoff. These two scoped runs are positive executable evidence for the source-UI package, *not* independent review or whole-workspace acceptance. There were **no local Rust test executions** in the ChatGPT phase.

At the later head, the mandatory workspace's failed job names remained `fmt`, `clippy`, `test`, `test (unprivileged user)`, `cargo-deny` and `cargo-vet`. Successful jobs were DCO, docs-lint, workflow-lint, repository lints, secret scan, SBOM and reproducibility. The scheduled-only supply-chain job was skipped on this PR trigger. The same distribution on audit/docs-only PRs supports previously identified independent blockers, but is *not* evidence that those blockers are harmless or approved.

**Decision gate:** keep PR #13 draft until an independent reviewer accepts the test-only move and additive CI workflow. PR #7 remains the owned session fix, PR #11 the owned worker lint/fmt remediation; human Security Lead import sign-offs and dependency advisory triage remain mandatory. Do not merge or issue any security/release claim based on this scoped success.


## Sixth exact-head check and independent-review acceptance checklist — 2026-11-10

The latest development handoff commit `b758fff8966fefca9b20a8007c7dc5de18160db1` on draft PR #13 ran both workflows:

| Workflow | Exact-head run | Result |
| --- | --- | --- |
| Focused source-UI qualification | [42860230477](https://github.com/djshellshoxxx/leaks/actions/runs/42860230477) | **Completed success** (1/1 job). |
| Mandatory workspace CI | [42860230789](https://github.com/djshellshoxxx/leaks/actions/runs/42860230789) | **Completed failure**: 7 passed / 6 failed / 1 skipped. |

The six failing jobs remain workspace fmt, Clippy, regular and unprivileged tests, cargo-deny and cargo-vet. DCO, docs-lint, workflow-lint, repo-lints, secret-scan, SBOM and reproducibility passed. Separate draft audit PR #14 [42859914373](https://github.com/djshellshoxxx/leaks/actions/runs/42859914373) and docs PR #15 [42860343760](https://github.com/djshellshoxxx/leaks/actions/runs/42860343760) each finished with **the same 7/6/1 breakdown**. These are source-pinned job-summary observations, not a rerun of the 87 package tests or a waiver for any required gate.

Before accepting PR #13, an **independent** reviewer should confirm the three extracted test bodies/assertions are unchanged, the `render::padding` module import and test names remain discoverable, the workflow's pinned actions and read-only permissions are appropriate, and the test command exercises the actual PR head. The previous run [42849936348](https://github.com/djshellshoxxx/leaks/actions/runs/42849936348) contains the explicit hosted 87-test passing evidence; the current run establishes renewed **job-level** success. The reviewer must not infer whole-workspace, supply-chain or crypto/anonymity clearance. Keep all integration, Trust Path audit, human Security Lead and release gates in force.

No local cargo commands, live wiki updates or independent acceptance were performed while preparing this documentation.

## Seventh CI/DCO reconciliation — 2026-11-10

On draft PR #13 exact head `5b88f36e5bac28087f993b050da073e19e99ba3f`, [focused run 42870913569](https://github.com/djshellshoxxx/leaks/actions/runs/42870913569) **passed** (fmt, tests, Clippy). Its hosted logs explicitly report **87 passing tests, zero failed**, including `padding::max_content_fits_size_classes`, `padding::robots_padded`, and `padding::s02_budget_report`. This is package-only qualification, not release or security assurance.

The exact-head [workspace run 42870913553](https://github.com/djshellshoxxx/leaks/actions/runs/42870913553) **failed**: 6 successful, 7 failed, 1 skipped. The six previously known fmt, Clippy, regular/unprivileged tests, cargo-deny and cargo-vet gates remain failing, **plus a new DCO failure**. The DCO job log identifies commit `5b88f36e5bac28087f993b050da073e19e99ba3f` as carrying an incorrect trailer: `Signed-off-by: djshellshoxxx <127660907+djshellshoxxx@users.noreply.github.com>`; the checker requires the exact name `sheldon` with the same noreply address. The analogous audit [run 42870540080](https://github.com/djshellshoxxx/leaks/actions/runs/42870540080) and docs [run 42870705802](https://github.com/djshellshoxxx/leaks/actions/runs/42870705802) also finished 6/7/1 with DCO failures on their latest commits. **Do not repeat the earlier 7/6/1 breakdown for these specific heads.**

**Remediation:** coordinate with the owner of each isolated `chatgpt/zero-codex/*` branch to correct the affected commits' DCO trailers via a narrowly reviewed commit-message rebase (force-with-lease only on that owned branch), then rerun exact-head checks. A new signed-off commit alone does **not** repair historical commits checked across the PR. Do not rewrite a concurrent owner's branch or bypass the DCO script. Preserve PR diff, substantive review history and all other security gates; note that the checker name reflects the repository's expected contributor identity and must be confirmed by the contributor before attestation.

PR #13 remains draft pending independent acceptance of the test-only move and additive workflow; none of these focused tests close the external trust-path or supply-chain blockers.


## PostgreSQL-backed acceptance is not equivalent to default cargo success (2026-11-11)

The intake store's `crates/candor-intake-store/tests/pg.rs` explicitly checks
`CANDOR_TEST_PG` before provisioning test databases (`base()`, lines 30–43).
When that environment variable is absent, the PostgreSQL-specific tests
return early rather than exercise the database. Accordingly, **a passing
default `cargo test -p candor-intake-store` is not sufficient evidence**
that role grants, RLS, PostgreSQL restart/restore, deletion-list monotonicity,
or remnant-erasure tests passed against a running server.

For a dedicated test environment, the crate documents the **throwaway,
unprivileged** fixture wrapper (see
[`crates/candor-intake-store/README.md`](../crates/candor-intake-store/README.md)
and its checked-in script):

```sh
crates/candor-intake-store/scripts/pg-test.sh cargo test -p candor-intake-store --test pg
```

The wrapper creates an isolated PostgreSQL 16 Unix-socket cluster, sets
`CANDOR_TEST_PG`, runs the supplied command and tears the cluster down.
Review its script and local prerequisites before invoking it. Record the
*actual* command, resulting job logs, PostgreSQL fixture status and exact
revision; neither this guide nor ordinary workspace CI establishes that the
database-backed assertions were executed. A prior on-repository test count
without `CANDOR_TEST_PG` is **not** substitute evidence. No such database
fixture was started in the 2026-11-11 ChatGPT documentation review.

Requirement-to-test examples: R7 SI-E-02 role/grant isolation →
`pg_roles_and_grants`; R7 SI-E-03 tenant isolation →
`pg_rls_tenant_isolation`; BE-074 restore-pending / retention guards →
`pg_durability_and_guards` and the deletion-list tests in `pg.rs`.
These are **test definitions and traceability links**, not fresh test results
or an independent security certification.


## Case-zone PostgreSQL qualification (2026-11-11)

The separate `candor-case-db` PostgreSQL test suite also **returns early without executing its assertions** when `CANDOR_TEST_PG` is absent. This is explicit in `crates/candor-case-db/tests/common/mod.rs:9-22` (`base()`) and in each integration-test entry point in `crates/candor-case-db/tests/pg.rs`. A green ordinary Rust workspace test is **not** proof that the case-zone RLS, authorization role/grant, transaction, schema-drift or state-history checks ran against PostgreSQL.

The checked-in isolated PG16 harness is `crates/candor-case-db/scripts/pg-test.sh` (distinct from the intake-store script). On a suitably provisioned disposable test host, review its privileges and configuration first, then invoke:

```sh
crates/candor-case-db/scripts/pg-test.sh cargo test -p candor-case-db --test pg
```

The script uses a temporary Unix-socket-only database with peer authentication, exports `CANDOR_TEST_PG`, and cleans up after execution. When run as root it may create and later remove a system account; **do not run it on shared or production hosts**. Record the exact candidate SHA, PostgreSQL fixture startup evidence, command output, test counts and any skips before claiming case-zone acceptance. Existing relevant test definitions are `migrate_and_open_every_role`, `rls_isolation_every_table`, `rls_case_acl_hides_non_member`, `grant_matrix`, `tenant_tx_fail_closed`, and `tamper_and_drift_refused` (`crates/candor-case-db/tests/pg.rs`). Their presence is not a test result.

The source-level `display_ref` retry-path inconsistency in `crates/candor-case-db/src/repo/case.rs:236-284` requires a deterministic, **database-backed** duplicate-display-reference regression before any remediation claim. That implementation remains owned by RM-3 PR #16. No PostgreSQL fixture was executed while adding this documentation, and no audit/release gate was changed.


## Latest CI reconciliation — 2026-11-11 (checkpoint 021)

These checks were read from the **exact SHA's GitHub Actions jobs**, not inferred from a previous workflow or local test. They supersede older queued/running status notes **for the particular heads below**, but do not supersede security gates or the ownership map.

| Draft PR / exact head | Workflow | Result (latest attempt) |
| --- | --- | --- |
| #13 `32eaeeaaa0f916d8417d20203d1a7eb79ca1ab3a` | [source-UI focused #42991517529](https://github.com/djshellshoxxx/leaks/actions/runs/42991517529) | **Success**, one scoped fmt/test/Clippy job. Does not requalify the workspace or independent review. |
| #13, same exact head | [mandatory workspace #42991517547](https://github.com/djshellshoxxx/leaks/actions/runs/42991517547) | **Failure**, 6 successful, 7 failed, 1 skipped. |
| #14 `1962940a009ef514b4986149bab08088891bfc65` | [mandatory workspace #42991237530](https://github.com/djshellshoxxx/leaks/actions/runs/42991237530) | **Failure**, 6 successful, 7 failed, 1 skipped. Audit review is not security clearance. |
| #15 `4876fb89631b85eb2c1306d238b0d4b1d1af5a1a` | [mandatory workspace #42991335452](https://github.com/djshellshoxxx/leaks/actions/runs/42991335452) | **Failure**, 6 successful, 7 failed, 1 skipped. Documentation-only checks are not full CI qualification. |
| #16 `bd33ef9e530969016fefd709a1177d1d4f6c40e2` | [mandatory workspace #42941692742](https://github.com/djshellshoxxx/leaks/actions/runs/42941692742) | **Failure**, 10 successful, 3 failed (DCO, cargo-deny, cargo-vet), 1 skipped. Remains draft/unmerged. |

For #13–#15, the seven failed jobs are **DCO, workspace fmt, workspace Clippy, regular and unprivileged workspace tests, cargo-deny and cargo-vet**. Successful jobs are docs-lint, workflow-lint, repo-lints, secret-scan, SBOM and reproducibility. The scheduled-only supply-chain job is skipped on these PR triggers. DCO failures now include historical commit attestations on the ChatGPT-owned branches; a later appended commit **cannot** retroactively fix those historical trailers. Do not invent contributor sign-offs or force-rewrite unowned commits. A contributor-authorized DCO repair with fresh exact-head checks is required. PR #11 owns the unrelated worker formatting/Clippy fixes; #7 and #16 carry separate RM-3 integration; owner/Security Lead approvals remain necessary for supply-chain changes.

The source-UI focused workflow success at #13 is consistent with earlier explicitly logged **87 passing/0 failing** package tests, but this inspection verified its latest **job result**, not new test-count output. No Rust toolchain, PostgreSQL fixture, Tor socket, local browser or release gate was executed by this documentation review.

The draft Wiki Home and Sidebar on separately owned PR #9 continue to link **User Guide** and **Developer Guide**. Their content remains incomplete, and the User Guide's broad “implemented and audited” claim conflicts with open audit-FAIL gates in `process/STATUS.md`. This is already tracked with PR #9's owner; do not edit that owner's files. **The live GitHub Wiki was not published or verified.**


## Retention decision-model qualification boundary (2026-11-11)

The default-branch `candor-worker` crate exposes a *pure decision model*, not
an implemented production erasure service. At source
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`,
`crates/candor-worker/src/retention.rs` defines `RetentionCase::evaluate`:

| State supplied by caller | Expected decision |
| --- | --- |
| `legal_hold=true` or `due=false` | `Noop` |
| Due, no legal hold, proposal absent | `ProposeDisposal` |
| Due, no legal hold, proposal present, option disabled or grace not elapsed | `Noop` |
| Due, no legal hold, proposal present, auto-dispose enabled and grace elapsed | `DisposeApprovedByPolicy` |

The corresponding existing unit assertions are
`st_rm3_retention_due_case_creates_proposal_never_silent_delete`,
`st_rm3_legal_hold_always_blocks_retention_disposal`, and
`st_rm3_auto_dispose_requires_explicit_option_and_grace` in
`crates/candor-worker/tests/job_retention.rs`. These are *defined tests*,
not evidence they executed during this documentation inspection.

The Rust return value does **not** mean that the current tenant settings,
legal hold or grace deadline were looked up and authenticated, persisted,
revalidated atomically, or that data, backups or keys were erased. The separate
`candor-retention` state-machine crate has additional transitions; its
presence is not proof of integration. Any eventual RM-3 acceptance must
add independently reviewed integration/regression evidence for durable holds,
tenant policy, concurrency, bounded grace, authorized proposal/approval,
retention lifecycle, key-destruction guarantees and recoverability limits.
Never classify source-level `DisposeApprovedByPolicy` as completion of
irreversible disposal or compliance with retention policy.

To qualify the *pure worker model* on the exact branch under review:

```sh
cargo fmt -p candor-worker -- --check
cargo test -p candor-worker --all-targets --locked
cargo clippy -p candor-worker --all-targets --all-features --locked -- -D warnings
```

These commands are **reference commands; they were not executed by the
ChatGPT documentation phase**. Existing PR #11 owns worker lint/format changes;
PR #16 owns current case/retention integration, and required security/human
review is separate. Focused green tests would not satisfy failing whole-workspace
DCO, dependency, supply-chain or independent security-release gates.


## Source-UI route/method traceability (2026-11-11)

Source snapshot: default/integration branch `claude/tender-tesla-z8tfnl`,
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`. This section documents
defined contract tests and additional acceptance requirements; **no new test
run is asserted**.

| Contract | Source of truth | Existing test/evidence | Remaining qualification |
| --- | --- | --- | --- |
| Fixed, identifier-free Tier W route paths | `crates/candor-source-ui/src/routes.rs::Route::path` and `candor-intake-web/src/routes.rs::lookup` | `unknown_paths_are_not_routes` checks rejected paths and explicit landing aliases | Confirm full URL/template inventory and method-specific HTTP responses on exact integration head |
| GET versus POST-only behavior | `Route::accepts_get` and intake-web `REGISTRY` | `registry_complete_and_consistent` compares all 22 declarations and their GET flag | Exercise every POST-only path with GET/HEAD and prove no state mutation |
| Deny-by-default unknown paths and methods | `candor-intake-web/src/routes.rs` and `app.rs` | `route_registry_deny_by_default` tests 404/405 and fixed 404 response sizes on representative paths | Repeat across supported locales, signed-in and cookieless contexts; preserve anonymity-sensitive uniformity |
| CSRF-bound form methods | `candor-intake-web/src/routes.rs::rule`, `app.rs`; templates under `candor-source-ui/templates/` | Registry test checks field allow-lists; inspected forms use `method="post"` for sensitive actions | Audit all templates against the typed route registry and validate token, origin and failure behavior without weakening authorization |

The UI URL formatter `PageView::href` accepts any typed `Route`; it
constructs a path but **does not authorize GET**, perform CSRF validation or
prevent a caller from placing a POST-only path in a hyperlink. Actual method
enforcement resides in the intake-web route registry/dispatcher. The sampled
source templates inspected during read-only audit rotation 23 used POST form
actions appropriately; a comprehensive template-link inventory remains
outstanding. This is a test-coverage boundary, **not a demonstrated security
vulnerability**.

For an appropriately provisioned reviewer, focused tests to execute on the
exact proposed integration commit include:

```sh
cargo test -p candor-intake-web --locked registry_complete_and_consistent
cargo test -p candor-intake-web --locked unknown_paths_are_not_routes
cargo test -p candor-intake-web --locked route_registry_deny_by_default
cargo test -p candor-source-ui --test render --locked
```

These are reference commands only; they were **not executed in this
documentation run**. A focused source-UI job on draft PR #13 at
`860916e9411a1d3d17c541170a363e6c6099e5f8`
[passed](https://github.com/djshellshoxxx/leaks/actions/runs/43008925170),
but the same head's [mandatory workspace CI](https://github.com/djshellshoxxx/leaks/actions/runs/43008925105)
failed (DCO, fmt, Clippy, ordinary/unprivileged tests, cargo-deny and
cargo-vet). Neither result certifies the complete intake-web route matrix,
anonymity controls, security audits or release readiness.

## Source passphrase / key-derivation qualification boundary (2026-11-11)

Source-pinned to default `claude/tender-tesla-z8tfnl` at
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`.
This is a **test inventory and review checklist**, not a claim that any
cryptographic security requirement has been independently verified.

| Requirement / boundary | Implementation source | Existing defined tests | Still required |
| --- | --- | --- | --- |
| Official EFF list integrity and 10-word generation | `candor-core/src/passphrase.rs::Wordlist::eff_large`, `generate_with` | `eff_list_loads_and_hash_matches`, `generation_uniform_shape`, `stuck_rng_fails_closed` | Verify wordlist provenance externally and RNG behavior on qualified platform; do not claim entropy certification |
| Bounded passphrase input and Unicode normalization | `passphrase.rs::normalize`, `lowercase_fixed` (maximum 1,024 input bytes) | `normalization_rules`, `normalize_rejects_overlong`, `normalize_matches_reference`, `normalize_idempotent` | Review cross-platform Unicode compatibility and **existing low-severity AUD-RM1-CORE-17** before enabling localized wordlists |
| Tenant-bound deterministic source keys and fixed production KDF parameters | `passphrase.rs::source_salt`, `SourceKeys::derive_in`, `from_seed`; `kdf.rs` | `derivation_tree_small_params`, `derivation_full_params`, `argon2id_rfc9106` | Cross-implementation vectors and independent cryptographic review; distinguish reduced-parameter unit fixtures from full production Argon2id |
| Secret lifetimes and memory locking | `passphrase.rs::Argon2Arena::wipe`, `secret.rs`; caller `candor-sealer/src/server/mod.rs` | `argon2_arena_is_wiped`, `lowercase_fixed_never_reallocates` | Qualify whole-process locking, swap/coredump controls, ST-027 zeroization checks and actual sealer/deployment integration separately |

The independent core audit at `process/audits/AUDIT-RM1-candor-core.md`
ends with a historical lead **PASS** after test-only Clippy repair, but
explicitly tracks CORE-17, timing/zeroization evidence and future-suite
conditions. This verdict applies only to that audit's pinned scope and
is **not** a present-day release approval or external cryptographic audit.
Changing normalization semantics, allowed Unicode, key derivation or
wordlist eligibility would change a security-sensitive contract and
requires the relevant spec/owner approvals, cross-implementation tests
and independent review; **this guide changes none of them**.

Reference commands for a provisioned independent reviewer on the
*exact* source revision being considered:

```sh
cargo test -p candor-core --lib passphrase::tests --locked
cargo clippy -p candor-core --all-targets --all-features --locked -- -D warnings
cargo fmt -p candor-core -- --check
```

These were **not run in this documentation pass**. The prior documents
and suites were inspected statically. Preceding docs head
`605ab71d7736afb1b82335c4871e95db7d779fe7` had
[mandatory CI #43016301967](https://github.com/djshellshoxxx/leaks/actions/runs/43016301967)
complete with six successful, seven failed and one skipped job; DCO,
workspace fmt/Clippy/tests and cargo-deny/vet remain red. A new docs
commit must be independently checked. The separate draft Wiki owner
PR #9 still needs to correct stale user-facing audit claims; the live
GitHub Wiki has not been published or verified.


## Tenant-bound PostgreSQL `TenantTx` and RLS qualification (2026-11-11)

**Source:** default `claude/tender-tesla-z8tfnl` at `9097f75f6529ed3dfa259de20d2fa9c78f434bda` (not the proposed, unmerged PR #16 grant changes). This is a test/acceptance trace, **not** a database qualification, Trust Path review or release approval.

| Contract and threat boundary | Defined implementation | Existing test to run on actual PostgreSQL | Still required |
| --- | --- | --- | --- |
| Role-bound connection and effective session hardening | `crates/candor-case-db/src/db.rs::CaseDb::open`, `Role::serves`, `session_ok` | `tests/pg.rs::migrate_and_open_every_role`, `live_lint_passes` | Execute against ephemeral real database, verify restrictive grants, disabled RLS, unsafe role flags and session defaults are refused |
| Per-transaction identity and isolation | `src/tx.rs::TenantTx::begin`, parameter-bound `set_config(..., true)` for tenant/user/kind; `src/db.rs::CaseDb::begin` | `tenant_tx_fail_closed`, `rls_isolation_every_table` | Verify cross-tenant read/write rejection, rollback/commit and pooled connection reuse in a qualified live cluster |
| Deny unknown/suspended tenant; narrowly permit maintenance | `tx.rs::begin` state branch; `types.rs::PrincipalKind::serves_suspended` | `tenant_tx_fail_closed` | Test all role/state combinations and negative tokens against service authentication, not only constructed Principals |
| Bootstrap without prior visible tenant row | `repo/tenant.rs::bootstrap` first requires `Role::Admin`; crate-private `TenantTx::begin_bootstrap` skips initial tenant visibility | `tenant_tx_fail_closed` | Verify no non-admin role can bootstrap and no duplicate/cross-tenant grant is possible |
| Case membership and RLS | `src/repo/case.rs`, `db.rs` and live RLS migrations | `rls_case_acl_hides_non_member`, `rls_isolation_every_table` | Qualify the final integrated PR #16 schema/grant changes under real PostgreSQL and separately accepted access-control reviews |

**A green ordinary Cargo test result can be vacuous for this package.** `crates/candor-case-db/tests/common/mod.rs::base()` returns `None` if `CANDOR_TEST_PG` is unset; `tests/pg.rs` tests then immediately return. `tests/pg.rs` refers to the **existing** `crates/candor-case-db/scripts/pg-test.sh` (verified at default SHA `9097f75f6529ed3dfa259de20d2fa9c78f434bda`, blob `add267acf26191067fd7cb041e6c3ceeeb30d54a`). The script provisions a disposable PostgreSQL 16 cluster and exports `CANDOR_TEST_PG`. Do not claim live RLS or database-transaction evidence until that fixture/test invocation actually runs and records executed test counts, database connection, migrations and negative role/RLS assertions. Any harness/CI integration changes must coordinate with PR #16's case-db owner.

Illustrative package commands (not executed in this ChatGPT documentation pass):

```sh
cargo fmt -p candor-case-db -- --check
cargo clippy -p candor-case-db --all-targets --all-features --locked -- -D warnings
cargo test -p candor-case-db --test pg --locked  # NOT sufficient without CANDOR_TEST_PG and a live cluster
```

Record exactly which supported PostgreSQL version/socket, test database, role bootstrap, env variables, test names and results were used; use an isolated disposable cluster with **no production data**. A future harness should fail CI on missing fixtures rather than treat skip-on-unset as an execution success. Do not patch test gates just to turn workspace CI green. The distinction between a constructed `Principal` and an authenticated external identity must also be verified at the service boundary.

**Evidence/ownership:** audit rotation 25 reviewed source/tests without runtime execution and found no new reproducible vulnerability. PR #16 independently owns related RM-3 implementation and database grants; PR #9 owns source Wiki Home/User/Developer pages; neither branch is touched here. The prior docs head `6b059e40509e98692a41dc4a930dcfba33d96562` [mandatory CI 43025465980](https://github.com/djshellshoxxx/leaks/actions/runs/43025465980) completed **failure (6 successful, 7 failed, 1 skipped)**. Those DCO, fmt, Clippy, test, unprivileged-test, cargo-deny and cargo-vet failures are not waived by this documentation update. Live GitHub Wiki publication remains unverified.


## File-padding content-limit versus padded-bucket qualification (2026-11-11)

The `candor-core` file-bearing object requirements combine **two different bounds**. `specs/04-CRYPTOGRAPHY.md §13.6` and CRYPTO-014 require an exact 64-KiB-aligned geometric series for the *padded plaintext size*; `crates/candor-core/src/padding.rs` separately documents `FILE_CONTENT_MAX` as a maximum for the *unpadded input content*. A legal final padded bucket can be larger than a permitted content length. The reader's `header.rs::CoreHeader::validate` checks a legal padded bucket; this must not be confused with verifying the originating content-size policy. Intake sealer also has independently configured file and bundle limits at `crates/candor-sealer/src/server/mod.rs`.

| Requirement / boundary | Existing code and evidence | Qualification still required |
| --- | --- | --- |
| CRYPTO-014 geometric bucket vectors and alignment | `padding.rs::tests::file_bucket_series`, `file_bucket_legal` and `message_buckets` (test definitions inspected) | Execute `cargo test -p candor-core --locked` on exact approved head and retain complete logs; file-bucket vectors alone do not establish every caller's content cap. |
| Padded-length membership and exact ciphertext length | `padding.rs::is_legal_bucket`; `header.rs::CoreHeader::validate/expected_payload_len`; `object.rs::parse` | Malformed/oversized header and payload negative test evidence; do not weaken the final padded-bucket membership rule. |
| Per-object content-size ceilings and resource bounds | `padding.rs::bucket_for/pad`; `candor-sealer/src/server/mod.rs` caller caps | **Open T0 review item:** explicitly verify over-limit *content* is refused even if it fits a legal final padded bucket, including `FILE_CONTENT_MAX + 1` and per-profile boundaries. This is a source-review gap, not an assertion of a remotely reachable vulnerability. Any production core change requires independent crypto/security approval; do not change wire formats or the bucket series without an approved decision. |
| Memory-safe opening of large files | `object.rs::ParsedObject::open_bounded/open_stream`; `stream.rs` staged verified chunks | Run bounded-memory, truncation/final-chunk and failure-injection tests on a disposable host. No large-memory stress run or source-facing anonymous-intake integration result is claimed here. |

No Cargo tests, large allocations, cryptographic operations, Tor trials or protocol changes were performed in this documentation update. The separate audit rotation 26 records the source-level observation for private owner/security triage. The existing independent core audit and human approval gates remain binding; this matrix is only requirement-to-test traceability.

### Case database harness inventory clarification

The earlier random-audit rotation 25 **incorrectly described** `crates/candor-case-db/scripts/pg-test.sh` as absent. GitHub contents verification shows it **present** on default commit `9097f75f6529ed3dfa259de20d2fa9c78f434bda` (blob `add267acf26191067fd7cb041e6c3ceeeb30d54a`) and on draft PR #16. The case-zone PostgreSQL acceptance section above correctly documents the script and its disposable fixture. The actual outstanding test-evidence gap is that `CANDOR_TEST_PG` must be configured and the live tests must genuinely run; no live PostgreSQL acceptance was performed by this ChatGPT task. The audit ledger records an explicit correction rather than silently rewriting the original observation.


## Tier W source-safety tips: privacy and accessibility qualification (2026-11-11)

**Scope:** requirement-to-test traceability for the unchanged source-facing safety-tip mapping at default `claude/tender-tesla-z8tfnl` commit `9097f75f6529ed3dfa259de20d2fa9c78f434bda`; audit rotation 27 is read-only. This is **not** a new independent security or accessibility certification and makes no claim of a deployed, safe whistleblower intake service.

| Requirement / threat boundary | Source and existing regression definitions | Additional qualification / limitation |
| --- | --- | --- |
| TIP-001/002/009/011: one to three static tips per screen, no risk-track/mode-driven content | `crates/candor-source-ui/src/tips.rs::Screen::tips`, `Tip::ALL`; `tips.rs::tests::{one_to_three_tips_per_screen,every_tip_is_placed}`; `tests/tips.rs::every_screen_has_tips` | Check all 37 screen variants, locale/mode/error variants, no new analytics or server-linked risk selection |
| TIP-003/006/007: word/readability budgets, critical review classes and bounded assurance claims | `locales/en/tips.ftl`; `tests/tips.rs::{word_limits,readability,catalog_classes,honest_wording_lint}` | These checks are English-master/static heuristics; independently review translations, linguistic safety and any new claims |
| TIP-004/005/008/010: response size and no unsafe navigation, forms or higher-risk disclosure signals | `templates/{tips,tip,s02b_tips}.html`, `src/view.rs::{tip_details,tip_more_link}`; `tests/tips.rs::{budgets_all_locales,no_external_urls,no_controls_in_tips,s02b_lists_all}` | S02 intentionally omits inline detail and links locally to S02b; Leave must have no tip link. Verify shipped response sizes and actual Tor-only deployment separately |
| TIP-013 and SUI-023: labelled accessible tip region, inert localized/catalog content | `templates/tips.html`, `view.rs::tm/escape_marked`; `tests/tips.rs::region_is_labelled_landmark`; `tests/render.rs::hostile_content_is_escaped` | DOM-level tests do not replace assistive-technology checks, independent review or browser/network privacy testing |

The earlier PR #13 source-UI focused qualification [run #43049936348](https://github.com/djshellshoxxx/leaks/actions/runs/43049936348) showed package-scoped formatting, tests (**87 passed**) and Clippy passing on the then-exact head. At the **latest** PR #13 head `2090b34be9cf841e49ea8ce7b4ae1b6d9b35b2f8`, [focused run #43043525291](https://github.com/djshellshoxxx/leaks/actions/runs/43043525291) also passed; mandatory [workspace CI #43043525183](https://github.com/djshellshoxxx/leaks/actions/runs/43043525183) failed (**6 pass, 7 fail, 1 skipped**, including DCO). Do not misstate either focused result as workspace acceptance. Audit PR #14 and this docs PR #15 have their own unqualified mandatory CI and persistent historical unsigned commits; contributor-authorized DCO remediation cannot be accomplished by adding a sign-off on the latest commit alone. No Rust or browser tests were run within this documentation phase.

Draft Wiki Home and Sidebar on PR #9 link User Guide and Developer Guide, but their completeness/security-status corrections and **live Wiki publication** remain with that owner. This addendum changes only documentation; it does not modify source-ui PR #13, the Wiki owner PR #9, privacy/security policy, or any production trust path.

## Safe-path archive extraction acceptance and audit-version trace (2026-11-11)

**Pinned source:** default integration branch `claude/tender-tesla-z8tfnl`, commit `9097f75f6529ed3dfa259de20d2fa9c78f434bda`. This is a source-to-test mapping for `candor-safefs`, **not** current independent T0 clearance, a passing runtime suite, or production recipient-viewer acceptance. The earlier `process/audits/AUDIT-RM1-safefs-log.md` explicitly ends in **FAIL** (including separate `candor-log` High findings); source-level evidence of later safefs corrections cannot silently change that historical verdict.

| Contract and threat boundary | Pinned code | Existing negative/regression tests to run | Missing acceptance evidence |
| --- | --- | --- | --- |
| Archive inputs must never create paths from hostile member names (FILE-019, ADR-027) | `crates/candor-safefs/src/archive/mod.rs::check_member_path`, `Session::store_member` and `SafeRoot` | `tests/archives.rs::zip_slip_absolute_and_drive_paths_rejected`, `tar_traversal_links_devices`, `arbitrary_names_confined` | Run on exact head in isolated Scratch; test symlink/mount/owner races, fail-closed path checks and actual viewer integration |
| Count decompressed bytes and reject resource exhaustion (FILE-020, ST-081) | `archive/mod.rs::ArchiveLimits::validate`, `Session::store_member`; `tar_impl.rs::CapOut`, archive-wide `ext_headers`; `zip_impl.rs::extract_zip` | `zip_ratio_bomb_rejected_and_rolled_back`, `zip_lying_declared_size_counts_real_bytes`, `tar_limits`, `tar_extension_header_cap_is_archive_wide`, `tar_gz_ratio_bomb` | Run hostile input corpus and bounded-memory/CPU tests under configured default and hard-ceiling policies |
| ZIP structural and parser-differential hardening | `zip_impl.rs` central/local comparison, overlap and ZIP64 checks | `zip_fifield_shared_local_header_rejected`, `zip_fifield_quoted_overlap_rejected`, `zip_local_central_field_mismatch_rejected`, `zip_local_flag_and_zip64_mismatch_rejected` | Confirm exact-head tests and negative corpus, independently re-audit current code; do not infer compatibility with other ZIP readers |
| Failure must not silently strand extracted plaintext | `archive/mod.rs::Session::finish` returns `ArchiveError::RollbackIncomplete` on failed cleanup | `archive/mod.rs::tests::incomplete_rollback_is_reported`, `tests/archives.rs::zip_ratio_bomb_rejected_and_rolled_back` | Fault-injection test storage/unlink failures, ensure the real recipient viewer destroys disposable Scratch on unrecoverable cleanup |
| Detect, but do not automatically recurse into, nested archives | `archive/mod.rs::looks_like_archive`, `ExtractedMember::nested_archive`; `ExtractOptions::check` | `tests/archives.rs::nested_archives_flagged_not_recursed` | Verify human-initiated nested-viewer workflow honors `max_nesting_depth` and does not silently bypass the boundary |

Historic `AUD-RM1-SFS-05/06/09` observations concern cleanup, TAR extension-header accounting and ZIP comparison. Current source visibly includes related mitigation code and corresponding named tests, but **none of those tests was rerun by this ChatGPT documentation phase**. Require a newly source-pinned qualified security review rather than treating an old audit's open findings as implicitly closed. The independent report also tracks other unresolved safefs and candor-log items; preserve the original gates and ownership.

Reference commands on an isolated, provisioned Unix reviewer machine (not executed in this run):

```sh
cargo fmt -p candor-safefs -- --check
cargo test -p candor-safefs --all-targets --locked
cargo clippy -p candor-safefs --all-targets --all-features --locked -- -D warnings
```

The fuzz targets `fuzz_archive_zip`, `fuzz_archive_tar` and `fuzz_archive_tar_gz` and their seed directories exist in the repository, but this does not establish a present-day fuzz execution result. The application-level viewer, isolation, cleanup and Tor/privacy constraints need separate end-to-end evidence and authorized review. Source audit rotation 28 is recorded on draft PR #14; this documentation belongs only to docs draft PR #15. Wiki pages remain owned by draft PR #9, with separate User Guide / Developer Guide navigation in its source; the **live wiki has not been verified as published**.

## RM-3 draft PR #16 candidate evidence versus integration acceptance (2026-11-11)

Default branch `claude/tender-tesla-z8tfnl` is pinned at `9097f75f6529ed3dfa259de20d2fa9c78f434bda`.
[Draft PR #16](https://github.com/djshellshoxxx/leaks/pull/16) is an **unmerged** implementation candidate at
`bd33ef9e530969016fefd709a1177d1d4f6c40e2` that changes authorization, relay, staff sessions,
case DB and sealer shutdown. Do not attribute its behavior or test outcomes to the default branch.

| Candidate evidence | Verified scope / limitation | Acceptance remaining |
| --- | --- | --- |
| PR #16 / PR #17 description | **Author-reported local** 83 passing tests across RM-3 candidate crates, not rerun by this ChatGPT documentation pass | Source-pinned independent test/reviewer acceptance |
| PR #16 case DB | **Author-reported local** 8/8 PostgreSQL 16 suite passing; `crates/candor-case-db/scripts/pg-test.sh` exists on default | Independent real-DB test with `CANDOR_TEST_PG` confirmed; default Cargo may otherwise skip assertions |
| PR #16 fmt/Clippy/trust-path changes | Author-reported scoped checks; no independent security or cryptography clearance inferred | Exact-head mandatory CI, contributor-authentic DCO and required reviewer approvals |
| [PR #16 hosted CI #42941692742](https://github.com/djshellshoxxx/leaks/actions/runs/42941692742) | **Completed failure** | Triage failed jobs, preserve all red security and supply-chain gates |
| PR #13 `9b36c71c955418b474f0b4bb556388b6ffc02347` | [Focused CI #43064425213](https://github.com/djshellshoxxx/leaks/actions/runs/43064425213) passed; [mandatory #43064425540](https://github.com/djshellshoxxx/leaks/actions/runs/43064425540) failed (6 pass, 7 fail, 1 skip) | Independent review, DCO-history correction, mandatory gate clearance |

Persistent default-branch blockers include contributor-authentic DCO history, worker rustfmt/Clippy,
spec-ahead ordinary and unprivileged test compilation, pinned dependency advisories and Security Lead
cargo-vet approvals. Draft improvements are not merged qualifications. This is source/CI-traceability
documentation, not a change to `process/STATUS.md` or to any normative security policy.


## Tor-circuit rate-limit acceptance evidence (ST-079, NET-013; 2026-11-11)

This is a **requirement-to-test map**, not a completed test report. The
pinned default source is `9097f75f6529ed3dfa259de20d2fa9c78f434bda`.
Historical source-side rate-limit audit findings and their recorded follow-up
are in [AUDIT-RM2-intake-web](../process/audits/AUDIT-RM2-intake-web.md);
its historical verdict does **not** independently qualify later commits.

| Boundary / expectation | Source / existing regression | What a future acceptance run must establish |
| --- | --- | --- |
| Raw Tor circuit ID is immediately replaced with a per-process opaque HMAC token | `crates/candor-intake-web/src/proxy.rs`, `src/server.rs`, `src/ratelimit.rs::Limiter::token`; `tokens_are_keyed` | Inspect source-side logging/response surfaces and verify redaction and restart unlinkability under approved test instrumentation. |
| Per-circuit login budget is independent between circuits | `src/ratelimit.rs::login_limit_per_circuit`, `tests/http_security.rs::login_rate_limit_per_circuit` | Five accepted attempts, sixth busy/429, unaffected second circuit; preserve uniform login response timing and size constraints. |
| Request/global-session tokens refill and are atomically spent | `request_burst_and_rate`, `global_request_bucket`, `trickle_does_not_starve_refill`, `refusal_spends_nothing_globally` | Preserve correct nominal refill under frequent rejected attempts; no partial spend when a per-circuit/global check refuses. |
| Circuit map remains bounded with idle eviction | `src/limits.rs::{MAX_CIRCUITS,CIRCUIT_IDLE}`, `src/ratelimit.rs::idle_eviction` | Confirm entry cap and ten-minute idle eviction, including denied/near-capacity cases in a bounded-memory test environment. |
| Upload-specific throttle composes with request throttle and service/session concurrency | `src/app.rs::dispatch`, `src/flows.rs::upload`, `src/ratelimit.rs::Class::Upload` | Focused upload/abuse-path tests; separate test of global slots and per-session upload flag, with no assumptions about Tor production throughput. |

Reference-only commands for a qualified runner at the **exact** PR source SHA:

```sh
cargo test -p candor-intake-web --lib ratelimit::tests --locked
cargo test -p candor-intake-web --test http_security login_rate_limit_per_circuit --locked
cargo clippy -p candor-intake-web --all-targets --all-features --locked -- -D warnings
```

Do not label these commands as executed by the documentation or ChatGPT
source-audit lane. Full Tor-only intake validation, cross-circuit resource
abuse testing, source privacy/timing review, independent security audit and
whole-workspace CI remain separate acceptance gates. Any test that requires a
real Tor circuit or production-equivalent environment must identify its
environment rather than reclassifying a unit test as live network evidence.

## Record-AEAD verification trace (CRYPTO-010/011/054/057; 2026-11-11)

**Inventory only, not a cryptographic approval or an executed test report.**
Source pin: default `9097f75f6529ed3dfa259de20d2fa9c78f434bda`.
The format and AAD contracts are in `specs/04-CRYPTOGRAPHY.md` §§9.9/13.8;
implementation is `crates/candor-core/src/record.rs`. The source-preferences
caller is `crates/candor-sealer/src/server/mod.rs`. These are security-sensitive
Trust Path boundaries, so only qualified reviewers may approve changes.

| Boundary | Existing test or source evidence | Still required for acceptance |
| --- | --- | --- |
| Case row and tenant binding; stale ciphertext replay refusal | `record.rs::tests::roundtrip_and_binding` verifies tenant/case relocation and mismatched row version rejection | Verify caller obtains the authoritative case-event-chain row version, then run a genuine stale-row replay integration test |
| Record header format, supported suite and AEAD tag | `record.rs::tests::roundtrip_and_binding`; `record.rs::parse`; `src/suite.rs::Suite::from_id_supported` | Validate key selection and unsupported-suite handling in the real consumer; a parsed header alone is not authenticated |
| Distinct context domains (keystore slots and source preferences) | `record.rs::tests::other_aad_forms_are_distinct`; §9.9 AAD labels | Expand negative tests across every AAD variant and tenant, identity, slot, version and header mutation; do not change a protocol label without ADR/crypto review |
| Identifier/secret redaction | `record.rs::tests::aad_debug_is_redacted`; `src/secret.rs::tests::debug_is_redacted` | Inspect real error/log/crash sinks; no proof of system-wide non-disclosure from unit tests |
| Malformed short inputs and crypto vectors | `record.rs::tests::open_arbitrary_never_panics`; `src/aead.rs` RFC/draft vector tests | Dedicated length/property/fuzz tests, exact-head Clippy/format, independent cryptography review |

Reference-only focused qualification commands (not executed in this maintenance pass):

```sh
cargo test -p candor-core --lib record::tests --locked
cargo test -p candor-core --lib aead::tests --locked
cargo clippy -p candor-core --all-targets --all-features --locked -- -D warnings
cargo fmt -p candor-core -- --check
```

The source's previous independent candor-core audit file has a recorded
lead-disposition PASS, but that historical verdict is not a release gate for
newer integration work. Current mandatory workspace CI and required human
approvals remain separate and unresolved. Never treat a successful focused
record unit test as proof of production key lifecycle, Tor-only source intake,
case-zone authorization, backup erasure, or recipient acceptance.

## Wrap-stanza context and erasure-layer qualification (CRYPTO-011/053/057; 2026-11-11)

This is a **source-backed test inventory**, not proof of runtime qualification,
cryptographic correctness, or deployed erasure. Pinned default source:
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`.
Source: `crates/candor-core/src/stanza.rs` (blob
`a3f6c0c185b5f5f47f9bf057b70ff14f752770a1`),
`src/kem.rs`, `src/slots.rs`; contract: `specs/04-CRYPTOGRAPHY.md`
§9.10 and §13.2. Relevant implementation decisions and known spec-amendment
gaps are in `crates/candor-core/SPEC-NOTES.md`.

| Boundary / requirement | Existing source and regression inventory | Acceptance still required |
| --- | --- | --- |
| Strict stanza framing, supported suite, ciphertext bound (CRYPTO-053) | `WrapStanza::decode`, `stanza::tests::decode_rejects`, `decode_arbitrary_never_panics` | Run malformed/truncated/trailing/excessive-length cases at the exact source head; measure resource behavior with hostile inputs; ensure all consuming paths decode and validate. |
| HPKE context and object-hash binding | `HpkeWrapContext::info`, `stanza::tests::hpke_reply_roundtrip_and_binding` | Test tenant/channel/mailbox/recipient-context negatives through actual caller and reject context-inappropriate metadata before using it as identity or authorization evidence. |
| Case-key content wrapping to tenant, case, version and object | `stanza::tests::case_aead_roundtrip_and_binding`; `open_case_aead` | Verify application supplies authoritative identifiers/version and handles stale or relocated ciphertext without releasing plaintext. |
| EK as outer layer over HPKE stanza, never direct raw case key (§9.10) | `stanza::tests::casekey_ek_roundtrip_and_ek_direct_wrap`; `tests/vectors.rs::stanza_vectors` | Verify recipient/key identity, inner type and policy in real case-zone consumers; independently accept actual EKV storage, restoration and erasure semantics. |
| Privacy-safe diagnostic output | `stanza::tests::context_debug_is_redacted`, `WrapStanza::Debug` | Review downstream error/log/trace fields and telemetry under source-identifying values; crate Debug tests alone do not establish anonymity. |

Reference commands **not executed** in this documentation pass:

```sh
cargo test -p candor-core --lib stanza::tests --locked
cargo test -p candor-core --test vectors stanza_vectors --locked
cargo clippy -p candor-core --all-targets --all-features --locked -- -D warnings
cargo fmt -p candor-core -- --check
```

No producer/consumer changes, test assertions, cryptographic primitives,
normative protocol or financial/security policy are authorized by this matrix.
A focused unit/vector pass cannot replace workspace checks, Trust Path
review, case-zone authorization and recipient acceptance, full Tor-only intake
testing or independent crypto/security sign-off. Record only actually executed
test outcomes and exact-head workflow links when available.

## Authorization policy registration and test scope (RM-3; 2026-11-11)

**Source pin:** default `claude/tender-tesla-z8tfnl` at
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`. This section distinguishes
a **present Rust source file** from an actually compiled and exercised policy.
It is a documentation/traceability correction, not a change to authorization
requirements, code, security gates or approved routes.

| Intended capability | Source status on the pinned default | Existing proof / outstanding acceptance |
| --- | --- | --- |
| Basic tenancy, assignment, COI and bounded break-glass checks | `crates/candor-authz/src/lib.rs::authorize` is exported | `tests/policy.rs` has six authorization cases; focused CI and full PEP integration still require separately recorded execution |
| Explicit account-state denies, case-content role/relation obligations and wrap-recipient checks | `src/lib.rs::{authorize_case,validate_wrap_recipients}` are exported | `tests/rm3_contract.rs` has four tests; actual case-service/DB/PDP enforcement requires independently reviewed cross-service acceptance |
| Recipient/admin session idle, absolute lifetime, audience and revocation | `mod session;` and public re-exports are registered in `src/lib.rs` | `tests/session_contract.rs` has five session tests; no authentication or token-verification integration is implied |
| Canonical policy JSON, permissions matrix, declarative routes, dual-control rule parsing and `Policy::baseline` | `src/policy.rs` **exists but is not a module of `src/lib.rs`**. Its `serde`/`serde_json` dependencies are absent from `candor-authz/Cargo.toml`; its `include_bytes!("../authz/matrix.json")` asset is absent under the crate at this source pin | **Not compiled or qualified as active enforcement**. The above test files do not call this parser. Do not infer a working route registry or policy baseline from its comments or file presence |

The owned RM-3 [draft PR #16](https://github.com/djshellshoxxx/leaks/pull/16)
changes `candor-authz/src/lib.rs` and adds `pdp.rs`. Those draft
changes must be reviewed and qualified on their own exact head; they are
**not** merged into the default source and are not evidence that dormant
`policy.rs` is running. No changes to the independently owned authorization
implementation are proposed here.

Reference-only checks for the compiled public API (not executed during
documentation maintenance):

```sh
cargo test -p candor-authz --test policy --locked
cargo test -p candor-authz --test rm3_contract --locked
cargo test -p candor-authz --test session_contract --locked
cargo clippy -p candor-authz --all-targets --all-features --locked -- -D warnings
```

For any *future, approved* matrix-parser integration, obtain canonical
fixture and missing-asset provenance, dependency review, bounded malformed
JSON and route-declaration negative tests, approval/step-up/COI isolation
tests, exact-head CI and independent authorization/security review first.
Do not register inactive policy modules merely to make documentation claims
true. The user/developer Wiki pages remain under [draft PR #9](https://github.com/djshellshoxxx/leaks/pull/9):
Home and Sidebar both link separate User Guide and Developer Guide, but the
live Wiki is not verified as published. The User Guide's statements about
historical safe-file/audit-log gates need owner correction using
`process/STATUS.md`, which records FAIL outcomes.

## Sealer Unix IPC admission/timeout trace (BE-003/006, ADR-052(4); 2026-11-11)

**Source/test inventory only; no listener test was executed in this documentation
pass.** Immutable default source `claude/tender-tesla-z8tfnl` at
`9097f75f6529ed3dfa259de20d2fa9c78f434bda`. Listener:
`crates/candor-sealer/src/server/listener.rs` (blob
`904559224d4034e3b36c882c0a481b75efc801a5`). The listener is
sealer Trust Path; any behavior change requires separate owned review,
not a documentation update or this audit ledger.

| Boundary / requirement | Existing source and test inventory | Acceptance still needed |
| --- | --- | --- |
| Only Unix IPC and correct peer UID before request body | `listener.rs::serve` checks `peer_cred().uid()`; `tests/ipc.rs::wrong_peer_uid_is_disconnected_without_a_byte` | Execute on isolated Linux host with real peer credentials and verify no alternate accept path; review the deployment unit and permitted socket ownership |
| HELLO-first, canonical framing, malformed-input refusal (BE-006) | `proto::frame_len` bounds frames to 1..131,072; `listener.rs::connection` caps pre-HELLO frames at 256 and rejects bad sequencing; `tests/ipc.rs::socket_round_trip_and_bad_frames`; `tests/listener.rs::no_large_frame_before_hello` | Run protocol and negative corpus at exact head, plus dedicated fuzz tests; verify downstream handler and no sensitive error fields |
| Connection quota / best-effort BUSY | `listener.rs::serve` uses semaphore permits; `refuse_busy` attempts one *nonblocking, best-effort* response; `tests/listener.rs::connection_cap_answers_busy_and_frees_slots` | Run concurrency/rapid-churn and FD-pressure tests; BUSY delivery is not guaranteed and must not be treated as a durable receipt |
| Handshake, body, idle and write time budgets | `listener.rs::connection` uses `tokio::time::timeout`, `write_all_timed` gives a deadline; `tests/listener.rs::timeouts_close_stalled_and_idle_connections` | Run timing-interleaving and stall tests on Linux under constrained resources; verify the deployed `Limits` values and fail-closed behavior |
| Recover from transient accept errors / fd exhaustion | `listener.rs::serve` counts errors and backs off 10 ms..1 s; `tests/listener_emfile.rs::accept_survives_emfile` | Run isolated RLIMIT_NOFILE/EMFILE regression safely, verify accept recovery and service monitoring rather than inferring production resilience |
| Thread confinement, source-data handling | `server/hardening.rs::{guard,poisoned}` and `listener.rs:49–53,171–174`; `Zeroizing<Vec<u8>>` covers body buffer | Independently inspect thread/runtime hardening, error sinks, post-decode owned secrets and real deployment; buffer zeroization alone is not an anonymity proof |

Reference-only commands, **not run** during the source review or docs maintenance:

```sh
cargo test -p candor-sealer --test listener --locked
cargo test -p candor-sealer --test listener_emfile --locked
cargo test -p candor-sealer --test ipc --locked
cargo clippy -p candor-sealer --all-targets --all-features --locked -- -D warnings
cargo fmt -p candor-sealer -- --check
```

Existing focused tests are *inventory*, not passing results for this run. The
previous mandatory workspace CI remained red: DCO history, rustfmt, Clippy,
ordinary/unprivileged tests, cargo-deny and cargo-vet. The historical sealer
and IPC security-audit gates, production resource/timing characterization,
full Tor-only source-to-sealer acceptance, independent crypto/security review
and release authorization remain separate. Draft PR #16 owns sealer trust-path
work, so no adjacent production source or tests were edited. The related
read-only source inspection is recorded in audit draft PR #14, rotation 34.

## OS randomness, health checks and HPKE adapter qualification (CRYPTO-033/034, ST-028)

**Pinned evidence:** default integration source `9097f75f6529ed3dfa259de20d2fa9c78f434bda` (2026-11-11); `crates/candor-core/src/rand.rs`, `src/selftest.rs`, `src/kem.rs`, `src/slots.rs`, `src/stream.rs`, `src/secret.rs`, `SPEC-NOTES.md`, `specs/04-CRYPTOGRAPHY.md` §23.4. These references describe *implemented source and existing test definitions* on that pinned commit; they do not claim runtime acceptance or independent cryptographic review.

| Requirement / boundary | Source-level implementation | Existing test definition | Remaining evidence |
| --- | --- | --- | --- |
| CRYPTO-033 OS CSPRNG only for production entropy | `rand::fill` calls `getrandom::fill`; `RandomSource` and `TestRng` are crate-private, with `TestRng` behind `cfg(test)` | `rand::tests::os_fill_works`, `rng_failure_propagates` | Verify CI `rng-ban` source inventory/allow-list on exact head and inspect any non-Rust consumers; OS entropy and VM-resume assumptions require deployment review |
| CRYPTO-034 / ST-028 start-up health | `rand::fill` rejects an all-zero draw of at least 16 bytes; `selftest::self_test` draws two 32-byte buffers and rejects equality | `selftest::tests::self_test_passes` | Demonstrate each production C-11 consumer *invokes* and fails closed on `self_test`; supply controlled RNG failure injection and VM snapshot/resume acceptance separately |
| AUD-RM1-CORE-12 unbiased bounded sampling | `uniform_below` uses a checked 2^32 rejection threshold and 128-attempt cap; `permutation` uses Fisher–Yates | `uniform_below_in_range_and_covers`, `permutation_is_permutation`, `rng_failure_propagates`, `stuck_high_rng_fails_closed` | Focused test execution and independent negative/boundary review for `n=0` and high bounds; not a statistical entropy audit |
| HPKE X-Wing randomness consumption | `ExactBytesRng` holds a pre-drawn 64-byte buffer, refuses under/over-consumption in `check()`, zeroizes its copy at drop; `kem` checks after seal/KAT/pairwise use | `exact_bytes_rng_detects_overrun`, existing `kem` tests | Run exact-head KEM/PCT/KAT tests and fault injection; ensure every new HPKE caller retains `check()` and zeroization; independent cryptographic review required |
| Deterministic dummy-slot expansion must not be mistaken for another entropy source | `slots::dummy_slot` uses seeded ChaCha20 as a **specified deterministic expansion** from derived bytes; `rand::TestRng` is test-only | `slots::tests::chacha_expansion_matches_raw_chacha20` and dummy-slot equivalence tests | Check normative ADR/spec alignment and source privacy requirements in independent review; do not alter format or randomization policy in a documentation change |

Suggested **reference-only commands** on the exact candidate head:

```sh
cargo test -p candor-core --locked --lib rand::tests
cargo test -p candor-core --locked --lib selftest::tests::self_test_passes
cargo test -p candor-core --locked --all-targets
cargo fmt --all -- --check
cargo clippy -p candor-core --all-targets --all-features --locked -- -D warnings
```

These commands were **not executed** for this documentation maintenance. Existing historical security-audit gates, pinned dependency advisories, DCO corrections, whole-workspace CI and qualified external crypto review remain mandatory. A passing focused suite is not evidence for OS RNG quality, unique distributed randomness, resumption/reseed guarantees, start-up invocation in every service, or production security clearance.


## Sealed-object CoreHeader parsing and key-commitment checks (2026-11-12)

**Source-pinned scope:** default \`claude/tender-tesla-z8tfnl\` commit \`9097f75f6529ed3dfa259de20d2fa9c78f434bda\`. This adds **requirement-to-existing-test traceability only**, without changing the cryptographic trust path, approved wire format or source files. Audit rotation 36 reviewed \`crates/candor-core/src/header.rs\` plus callers. The section above on file-content ceilings versus padded buckets still applies.

| Requirement / trust boundary | Existing implementation and defined tests | Additional acceptance still required |
| --- | --- | --- |
| CRYPTO-018/047: exact 128-byte canonical header and fail-closed parsing | \`header.rs::CoreHeader::{decode,encode,validate}\` with \`bytes.rs::Reader\`; \`header::tests::{roundtrip,rejects_bad_fields,decode_arbitrary}\`; \`bytes::tests::reader_bounds\` | Execute exact-head property/malformed-frame tests and check decoder rejects truncation, trailing bytes, wrong magic/version/flags/reserved and wrong chunk-size field. |
| CRYPTO-003/056: supported suite and no silent negotiation | \`suite::Suite::{from_id,require_supported}\`; \`suite::tests::{ids_roundtrip_and_reject_unknown,fips_is_unsupported}\`; header negative vectors | Ensure FIPS is recognized but **rejected** in the shipped build; unsupported/unknown IDs must not fall back to STD. |
| CRYPTO-016/018: object-type semantics, bucket and recipient metadata consistency | \`header::CoreHeader::validate\` checks source/reply day stamp, slot-hash presence, member epoch restrictions, zero-channel types and \`padding::is_legal_bucket\`; \`header::tests::semantic_rules\` | Prove each supported type's negative vectors and cross-check profile/content-size admission separately; a legal padded bucket does not prove the input was within a profile limit. |
| CRYPTO-008 and §13.1: CK-bound header MAC before payload decrypt | \`header::CoreHeader::{header_mac,verify_header_mac}\`, \`object::ParsedObject::{verify,open,open_stream}\`; \`header::tests::mac_verifies_and_binds\`; \`tests/vectors.rs\` sealed-object vectors | Verify tampering with each context-bearing header field fails under the expected key; static header parsing is **not authentication** until MAC verification. Obtain independently reviewed crypto evidence. |
| CRYPTO-018 and resource limits: exact ciphertext length and bounded opening | \`header::expected_payload_len\`, \`object::parse\` and \`ParsedObject::open_bounded/open_stream\`; STREAM final-tag contract | Execute hostile-length and preallocation-limit tests; confirm all externally reachable file-opening callers enforce appropriate memory ceilings, process the final STREAM tag, and discard partial output. \`open()\` can allocate a whole file-sized plaintext and is not a substitute for bounded policy. |

Reference-only commands for an authorized build environment:

\`\`\`sh
cargo test -p candor-core --locked --lib header::tests
cargo test -p candor-core --locked --test vectors
cargo test -p candor-core --locked --all-targets
cargo fmt -p candor-core -- --check
cargo clippy -p candor-core --all-targets --all-features --locked -- -D warnings
\`\`\`

**Not executed in this documentation pass.** CI on documentation/audit heads is not a substitute for core package runtime tests. Static read-only inspection did not establish a new reproducible vulnerability, independent crypto review, Tor-safe operation, full memory-bound caller coverage or release qualification. PR #16 owns adjacent RM-3 and IPC source, and the core Trust Path remains subject to independent approval.


## istore positional IPC framing, authentication and failure-path trace (2026-11-12)

**Evidence scope:** default `claude/tender-tesla-z8tfnl`, commit `9097f75f6529ed3dfa259de20d2fa9c78f434bda`. Audit rotation 37 on [draft PR #14](https://github.com/djshellshoxxx/leaks/pull/14) read `crates/candor-intake-store/src/proto/mod.rs`, `src/{server,client,sockio}.rs` and existing `tests/{istore,staged}.rs`. The following is *traceability of source and defined regressions*, **not** executed test evidence, approval of the IPC Trust Path or a claim that draft PR #16's changes are merged.

| Requirement / IPC boundary | Existing pinned source and test definitions | Additional qualification required |
| --- | --- | --- |
| 07 §5.3 canonical versioned datagrams, maximum size and fail-closed decoding | `proto::{encode_request,decode_request,encode_response,decode_response,max_request_len,max_response_len}`; `MAX_FRAME_LEN=200000`; `Reader::{take,var16,var32,count8,finish}`; `proto::tests::{requests_round_trip_within_limits,responses_round_trip,field_limits_are_enforced,decode_total}` | Run full boundary and property tests on an exact head, including lengths near 200k, truncation, trailing bytes, wrong op/version, minimum/maximum fields and malformed count prefixes. The existing arbitrary-bytes property-test generator covers 0..512 bytes, not the full frame range. |
| SO_PEERCRED peer identity, per-role restrictions and reserved relay operations | `proto::Op::{role,is_relay}`; `server::IstoreServer::{admit,connection}` checks configured uid, per-role connection limits and reserved op refusal; `tests/istore.rs::{wrong_role_reserved_and_malformed_requests_close,unknown_uid_is_dropped_without_a_reply,connection_cap_answers_busy_and_distinct_uids_are_required}` | Execute Linux/production-identity integration, role cap under load, explicit UID separation, retry/timeout and role-op matrix on candidate deployment; a source-level UID check is not proof of systemd socket-policy configuration. |
| Record-boundary and descriptor-smuggling controls | `sockio::recv_datagram` rejects `TRUNC|CTRUNC`, ancillary messages and excessive size, dropping passed FDs; `tests/istore.rs::wrong_role_reserved_and_malformed_requests_close` and `tests/staged.rs::{staged_surplus_descriptors_closed,staged_bundle_hostile_variants_refused}` | Verify hostile ancillary/truncated datagrams, fd-pressure, socket type and resource-lifetime behavior in an isolated Linux test environment. |
| Request/response correspondence and bounded mailbox access | `client::Conn::call_inner` checks response request ID and closes on transport errors; `server::IstoreServer::connection` budgets mailbox reads; `tests/istore.rs::{idle_timeout_closes_and_client_reconnects,mailbox_read_is_budgeted_by_the_list}` | Exercise stale response, timeout/interleaving and retry under load; verify error-code uniformity and source-identifier privacy externally. |
| Staged hand-over, ambiguous failures, idempotency and deletion | `proto::Request::{CommitGroup,AccountUpsert,Delete}`, `server::IstoreServer::handle`; `tests/istore.rs::{commit_group_hand_over_and_idempotent_replay,late_commit_is_reported_by_the_retry_without_a_double_commit,deletions_append_k31_entries_and_are_idempotent}`; additional `tests/staged.rs` crash, sweep, duplicate and definite-rejection cases | Test actual persistent-store outcomes and crash/restart boundaries, with qualified independent IPC-15 and deletion safety review; avoid treating a synthetic or in-memory test as PostgreSQL-backed retention acceptance. |

Reference-only commands for an authorized and correctly configured Linux environment:

```sh
cargo test -p candor-intake-store --locked --lib proto::tests
cargo test -p candor-intake-store --locked --test istore
cargo test -p candor-intake-store --locked --test staged
cargo fmt -p candor-intake-store -- --check
cargo clippy -p candor-intake-store --all-targets --all-features --locked -- -D warnings
```

**None of these commands was run in this documentation pass.** The current default-branch implementation is distinct from draft PR #16 (RM-3/IPC ownership), which requires exact-head tests and separate independent review. Draft PR #13's [focused source-UI checks](https://github.com/djshellshoxxx/leaks/actions/runs/43131165402) passed, but its [mandatory workspace run](https://github.com/djshellshoxxx/leaks/actions/runs/43131165664) failed (six passes, seven failures, one skipped). Audit and docs exact-head mandatory runs [#43130944469](https://github.com/djshellshoxxx/leaks/actions/runs/43130944469) and [#43131066266](https://github.com/djshellshoxxx/leaks/actions/runs/43131066266) likewise failed. The DCO job explicitly identified several unsigned *historical commits on the ChatGPT handoff branch*: do not treat adding a signed later commit as retroactively fixing those. Human/contributor-authorized DCO correction, workspace rustfmt/Clippy/test fixes, supply-chain advisory remediation and Security Lead cargo-vet sign-off remain distinct mandatory gates.

## Secret-wrapper lifecycle and failure-path trace — 2026-11-12 UTC

**Source pin:** default `claude/tender-tesla-z8tfnl` at `9097f75f6529ed3dfa259de20d2fa9c78f434bda`; see audit rotation 38 on [draft PR #14](https://github.com/djshellshoxxx/leaks/pull/14). This section records source evidence and *unexecuted* verification steps, not an independent crypto assessment or an approved change.

| Requirement / boundary | Existing source and defined tests | Outstanding acceptance |
| --- | --- | --- |
| CRYPTO-057 / §23.2: sensitive key containers prevent accidental printing and wipe owned storage on drop | `candor-core/src/secret.rs` macro defines `ContentKey`, `CaseKey`, `ErasureKey`, `AeadKey`, `MacKey`, `Secret32`, `SessionKey` with `ZeroizeOnDrop`, fixed redacted `Debug`, no `Clone` or `Display`; `secret::tests::debug_is_redacted` checks `ContentKey`. | Independently check type-by-type redaction, no accidental copies or secret-bearing logs, and actual zeroization instrumentation under approved test conditions; redacted `Debug` alone does not establish absence of secret leakage. |
| Exact input lengths and explicit key-borrowing contract | `secret_key_type!` exposes checked `from_slice` and explicit `expose`; `secret::tests::from_slice_checks_length` tests 31/32/33 bytes for `ContentKey`. | Execute negative input tests on all seven wrapper types and review public callers; `from_bytes` accepts an owned array but documents that the caller must wipe its own copy. |
| CRYPTO-033 and failure-safe key creation | `secret.rs` `generate` methods and internal `ContentKey::generate_with` use `rand::fill`; `kdf.rs` zeroizes success-path temporary arrays; `rand::tests::rng_failure_propagates` checks fail-closed sampling. | Review and fault-inject partial-write/error paths before concluding that temporary key buffers are wiped on every exit; explicit wipes follow `fill(...)?` and therefore do not execute on early error. This is a source-level hardening/test gap, **not an established exploitable disclosure**. |
| Independent crypto/release gate | `candor-core/SPEC-NOTES.md`, `process/STATUS.md`, and the separate crypto audit notes | Require authorized tests and independent review; documentation and draft PR CI do not clear Trust Path or release. |

Reference-only authorized checks: `cargo test -p candor-core --locked --lib secret::tests`; `cargo test -p candor-core --locked --all-targets`; `cargo fmt -p candor-core -- --check`; `cargo clippy -p candor-core --all-targets --all-features --locked -- -D warnings`. **These commands were not run here.** No core source/tests were changed and no speculative bug report or release assurance is implied.
