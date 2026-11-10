<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# ChatGPT documentation-maintenance ledger — 2026-11-10

## Snapshot / ownership
- Default integration branch `claude/tender-tesla-z8tfnl`: `9097f75f6529ed3dfa259de20d2fa9c78f434bda` (the repository default is not `main`).
- Wiki/README implementation already owned by **draft PR #9**, head `445ccd0ad156769416bf205e730b8699d144d15f`; modular policy docs already owned by PR #8, head `cd1cccfb24ac6247c62835ca64a3febd992143b8`; development PR #13 and audit PR #14 are independent. **Did not modify those owners' files/branches.**
- No existing `docs/handoffs/CHATGPT_DOCS_MAINTENANCE_LATEST.md` at default SHA. This file only records review evidence and actionable drift.
- Local runtime tools cannot run the Rust workspace; **no cargo, browser or wiki publication tests run** in this documentation phase.

## Wiki architecture check (PR #9 draft, not merged)
- Read `docs/wiki/Home.md`, `_Sidebar.md`, `User-Guide.md`, `Developer-Guide.md`, `Architecture-and-Design-Rationale.md`, `Codebase-Map.md` at PR #9 head.
- **Pass (static):** Home links to both **User Guide** and **Developer Guide**; Sidebar links to both and Home. All **9** wiki-name links in Home/Sidebar resolve to one of the six source filenames. Checked names only, not a GitHub Wiki deployment or external links.
- **Missing (draft):** User Guide lacks installation/access status beyond a warning, common workflows, troubleshooting, FAQs and complete limitations. Developer Guide lacks end-to-end local setup, architecture/module map link, practical debugging, release controls, full API/contracts and open work.
- **Status / assurance drift:** `docs/wiki/User-Guide.md` treats `candor-log` and safe-file handling as audited/implemented without reporting the recorded final **FAIL** gates in `process/STATUS.md` §1 and `process/audits/AUDIT-RM1-safefs-log.md`. Default-branch README also says "Each finished component passed an independent security audit" despite those failure gates. These are documentation accuracy issues, not new vulnerability findings.
- **ADR drift:** `docs/wiki/Architecture-and-Design-Rationale.md` claims 47 decisions, while `specs/DECISIONS.md` at default SHA `2ae203a9987a714134d12fbe5fca7e74186caf4e` includes ADR-001..ADR-057. Avoid duplicating unsupported guarantees.
- **Coordination:** Left a precise review request on PR #9, comment [6767849434](https://github.com/djshellshoxxx/leaks/pull/9#issuecomment-6767849434), rather than changing wiki/README files in someone else's branch.

## Requirements to verification trace
| Requirement / decision | Existing source/test evidence | Qualification |
|---|---|---|
| SUI-005 response size classes | `crates/candor-source-ui/tests/render.rs`: `max_content_fits_size_classes`, `robots_padded`, `s02_budget_report` (extracted without assertion changes by draft PR #13) | Static test inventory 37→37; runtime test and exact-head CI pending. |
| SUI-052 / I18N-005 locale rendering | `crates/candor-source-ui/tests/render.rs::every_screen_renders_for_every_locale` | Source exists; no tests run in this phase. |
| ADR-051(4) / ST-071 pre-session CSRF | `crates/candor-intake-web/src/token.rs` + embedded tests `pre_session_tokens_expire`, `origin_matrix` | Source reviewed in audit PR #14; not retested or security-cleared by this lane. |
| WEB-11 leave-page usability | `process/audits/AUDIT-RM2-intake-web.md` final gate and `token.rs` leave-token set | Known historical Low residual; needs qualified next C-06 implementation, no claim of remediation. |

## CI, limits and next actions
- Base latest observed `9097f75` scheduled CI [42817477461](https://github.com/djshellshoxxx/leaks/actions/runs/42817477461) completed with failures (fmt, clippy, test, cargo-deny, cargo-vet and supply-chain audit). This ledger does not claim clean CI.
- PR #12 CI [42754179538](https://github.com/djshellshoxxx/leaks/actions/runs/42754179538) completed with failures including DCO (unsigned commit); record until the existing owner addresses it.
- **Live GitHub wiki:** direct wiki writes are not available through the linked connector; source pages are draft under PR #9, so no live wiki publication claimed. Require authorized wiki publishing after source review and merge, then verify Home and Sidebar on the live wiki.
- **Next:** wait for PR #9 owner to correct draft status/ADR claims and complete both guide sections, then recheck all links/commands against the current default SHA; meanwhile prioritize source-backed non-overlapping operator docs, not duplicate wiki pages. Require review before asserting new privacy or deployment guarantees.
- No changes to specifications/ADRs, security policy, deployment, code, or other agent branches. No independent documentation worker was spawned; this was a sequential phase.

## Incremental maintenance pass — 2026-11-10

- **Source snapshot:** default `claude/tender-tesla-z8tfnl` remained `9097f75f6529ed3dfa259de20d2fa9c78f434bda`. PR #9 remains separately owned at `445ccd0ad156769416bf205e730b8699d144d15f`, still a draft; existing wiki Home/Sidebar User and Developer Guide navigation (9/9 static target names) was not modified. Live wiki remains unpublished.
- **New, non-overlapping documentation:** `docs/CI-QUALIFICATION-RUNBOOK.md` created in this isolated docs branch at commit `48bea2fafe08f0535d1aeff2ea87d25479df7e6f`. It documents how to qualify exact PR heads, distinguishes focused package tests from workspace tests, records the historical CI errors with traceable job URLs, identifies #7/#11 owners and human cargo-vet approval holds, and supplies commands copied/derived from `Makefile`, `.github/workflows/ci.yml` and `rust-toolchain.toml`.
- **Direct CI evidence:** PR #13 `1194085bc4ca1b58c919832aeeec40ea54d7da86` [run 42819538406](https://github.com/djshellshoxxx/leaks/actions/runs/42819538406); PR #14 `cb88d8e5d540ca0519801f59ab5001250b97463f` [run 42819606916](https://github.com/djshellshoxxx/leaks/actions/runs/42819606916); PR #15 original head `4df90c6c65d607d7af96ac6f4df507506230ece4` [run 42819761010](https://github.com/djshellshoxxx/leaks/actions/runs/42819761010). All three previous workflow runs **completed in failure** with 7 passed / 6 failed / 1 skipped jobs each. No Rust tests were run locally; focused source-UI tests are unqualified. PR #12 older DCO failure remains open.
- **Link check (source based, not live wiki):** the new runbook's internal relative references to `../Makefile`, `../.github/workflows/ci.yml`, `../process/STATUS.md` were confirmed present at base commit; all three GitHub PR links refer to previously inspected #8/#9 and CI job runs. No automated remote link crawling or markdown lint executed in this phase. Its new head CI must be checked on the next run.
- **Docs drift still owned elsewhere:** PR #9 User Guide and Developer Guide need completion of user workflows, installation caveats, troubleshooting/FAQs, architecture/API/test/release references and correction of audit-FAIL and ADR count statements. Detailed review comment remains on PR #9; do not rewrite its branch or silently publish wiki pages. Request PR #9 owner to link the new CI runbook from the Developer Guide once ready.
- **Next:** inspect exact-head CI on this docs branch, reconcile PR #9 revisions and remaining status claims, then write another independently reviewable operator/developer documentation increment. Keep security limitations and approved decisions unchanged. No separate concurrent documentation worker was available; work was a sequential phase. No merge, release or deployment.
