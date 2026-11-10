# ChatGPT Zero-Codex Continuation Specification

Status: proposed coordination policy. Does not itself create a timer or detect account credit balances.

## Executor and costs
Use ChatGPT direct GitHub connector and available execution tools only. No Codex, Codex CLI/cloud, paid OpenAI API, or credit-consuming agents. GitHub Actions and ChatGPT usage have independent limits and potential charges.

## Ownership
Use `chatgpt/zero-codex/` branches for implementation and `docs/handoffs/CHATGPT_ZERO_CODEX_LATEST.md` for checkpoints. This is advisory ChatGPT-only ownership, not technical enforcement. Never overwrite, rebase, close, merge or edit another agent's active branches/PRs. Before each run inspect repository default branch (not assumed to be main), AGENTS.md and nested instructions, specifications, recent commits, open PRs, source-pinned handoffs and CI. Do not treat draft work as merged.

## Sequential work queue
1. Inspect process/STATUS.md, AGENTS.md, process/MODULARIZATION-ROADMAP.md, latest security reviews, PRs and CI; select the next unblocked non-trust-path module or test.
2. Finish modular, test-first Rust implementation slices for case-zone workflow, recipient UX, recovery and operations only where accepted specs permit.
3. Improve audit-log correctness, bounded storage/retention, error handling, accessibility, docs and offline security regression tests without weakening anonymity assumptions.
4. Fix CI/rustfmt/clippy/supply-chain issues on exact heads, preserving pinned dependencies and review evidence.
5. Improve traceability, operational runbooks and security test harnesses; keep Tor-only intake, source trust isolation, cryptographic key boundaries and disposable-viewer requirements intact.
6. Keep trust-path cryptography, anonymity claims, protocol changes, independent audit and production release explicitly gated by required qualified human/security review.

## Run protocol
1. Inspect prior automation handoff and exact current PR/CI status. If the prior task or its CI is still active, do not duplicate; defer to next hourly invocation.
2. Select the highest-priority unblocked independent task and finish one slice at a time. If approval is blocked, document it and work on another safe task.
3. Follow test-driven development: reproduce a defect with a failing test, implement a minimal change, refactor and run appropriate focused and broad checks. Never invent passing tests or security reviews.
4. Preserve existing security, privacy, financial and architectural invariants. Do not weaken lint, security gates, test assertions, or fail-closed behavior.
5. Commit to isolated branch and create/update draft PR. Record exact base/head SHA, changed paths, tests, CI URLs, blockers and next steps in the handoff.
6. Continue on future scheduled runs until features are complete or as near-complete as available tools and approvals permit. Do not claim continuous execution between runs.
7. No main/default-branch merge, release, deployment, credential use, financial-policy change, production trust-path change, or security-signoff claim without required separate authorization.

## Acceptance
Complete means source, tests, docs, exact-head CI and required approvals are satisfied. Near-complete means every remaining gate has an evidence-based blocker and next action. Do not invent completion percentages.
