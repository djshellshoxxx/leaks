<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Zero-Codex log chain test modularization — 2026-11-12 UTC

## Pinned source and ownership
- Default integration source: `claude/tender-tesla-z8tfnl` at `9097f75f6529ed3dfa259de20d2fa9c78f434bda`, not `main`.
- Existing PR #13 owns source-UI test extraction; PR #16 owns RM-3 and IPC/sealer trust-path work; PR #9 owns the Wiki/root README; PR #11 owns worker lint. None were touched.
- Proposed `AGENTS.md` and `process/MODULARIZATION-ROADMAP.md` on draft PR #8 (`cd1cccfb24ac6247c62835ca64a3febd992143b8`) put `candor-log/tests/chain.rs` test-only splitting in the first low-risk wave. This work follows those rules without implying PR #8 has merged.

## Isolated implementation, rollback
- Branch: `chatgpt/zero-codex/log-chain-tamper-tests-20261112`, from unchanged source SHA above.
- First commit `551459864a015b7f9fd395cb0bb3c1924f1eb421`: add `crates/candor-log/tests/chain/tamper.rs`, containing the seven existing AUD-004 tamper tests copied byte-for-byte as one contiguous source block; only the new module header and `use super::*;` are additional.
- Second commit `04ca18a4ba1d1edb6970ce7c679fe3c3be0f9f9e`: remove that same block from `crates/candor-log/tests/chain.rs` and add private `#[path = "chain/tamper.rs"] mod tamper;` at that location.
- Qualification workflow commit `bc818f0fb0733e55f37f67ce6b453c7c68e7cd3a`: additive `.github/workflows/log-chain-qualification.yml` with read-only PR token, SHA-pinned external checkout and existing local Rust setup; package rustfmt, full log chain test target and package warning-deny Clippy.
- Old/new map: seven test functions leave `chain.rs` for its private `chain/tamper.rs`. Fixture functions and the `VkForTest` extension trait remain in the parent and are imported by its child through `use super::*;`. No runtime implementation, external API, serialized bytes, test assertion, fixture, dependency, protocol, authorization, crypto or security policy changed. Revert this PR to roll back.

## Static evidence and unqualified checks
- GitHub connector read `chain.rs` at source blob `509d07209c75fc0a09649ac61cf7af7aac395e51`. Static parser compared sorted `#[test] fn NAME` inventory before and after (parent + new module): **35 -> 35, identical names; 7 moved**. The moved source block is byte-for-byte unchanged. This does not establish compiler discovery, runtime pass or Clippy/rustfmt success.
- Focused CI is configured but **not yet reported**, and mandatory workspace CI remains independently required. Check the actual head SHA and all job steps after the draft PR is created. Do not equate older PR #13's focused source-UI success with qualification of this log suite.
- At the last confirmed prior heads, PR #13 `7d61f130e4009138eb5eb22522896b5fc494b8f0` [focused CI #43145343606](https://github.com/djshellshoxxx/leaks/actions/runs/43145343606) passed, while [workspace #43145343574](https://github.com/djshellshoxxx/leaks/actions/runs/43145343574) failed 6 passed / 7 failed / 1 skipped; audit PR #14 `ee73482c8b7dd49eafd3a03ca98d632d0914ffcd` [#43145115993](https://github.com/djshellshoxxx/leaks/actions/runs/43145115993) and docs PR #15 `ac06c184aaabd1d2863e576dbd00e67b4d47d96d` [#43145232364](https://github.com/djshellshoxxx/leaks/actions/runs/43145232364) also completed failure with those same inherited gates.
- Mandatory gate blockers: authentic historical DCO fixes, workspace rustfmt/Clippy, ordinary/unprivileged tests, locked-dependency advisories (cargo-deny), and Security Lead cargo-vet approvals. New workflow needs normal Release/Supply-chain owner review; test-only audit-log changes require appropriate independent review. No approvals or test outcomes are invented.

## Next
1. Reconcile focused `candor-log` qualification and mandatory CI on the **exact new PR head**, including rustfmt and Clippy; fix only reproducible scoped issues without weakening checks.
2. Obtain independent review of the byte-preserving extraction and new additive workflow; coordinate authentic DCO signoff/history correction with contributor/owner.
3. Do not merge, release, deploy or treat audit-log assurance as improved until all required gates are accepted. Keep Tor-only intake, privacy classifications and external cryptographic/security reviews unchanged.

**Execution:** ChatGPT direct GitHub connector only. No Codex, paid API, separate workers, local Cargo test, independent crypto sign-off, real data, merged branches or deployments.
