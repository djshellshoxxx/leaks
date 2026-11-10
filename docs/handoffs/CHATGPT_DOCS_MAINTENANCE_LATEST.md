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
