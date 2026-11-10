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
