<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Candor repository instructions for all coding agents

These rules apply to **all future code, fixes, tests and refactors**. They supplement, and never weaken, `CONTRIBUTING.md`, the binding specifications/ADRs, the threat model, and the Trust Path review gates.

## Modular-first rule (owner requirement, 2026-10-13)

**Write every new feature and bug fix as modular, composable, maintainable code.** Candor's current implementation will **eventually be migrated to this same modular structure**, incrementally. Do not attempt a big-bang rewrite.

- Give each module a single, well-named responsibility and a narrow interface. Prefer existing domain crates/modules; add a new crate only when an independently justified dependency or trust boundary requires one.
- Keep the direction of dependencies clear. Domain types and stable contracts belong to their owner module. Never introduce circular dependencies or duplicate an existing implementation to make a branch build.
- Prefer private `mod`s, `pub(crate)`, and explicit re-exports at existing public entry points. Preserve existing public imports, API signatures, serialized formats, protocol IDs, SQL, error behaviour and privacy guarantees during extraction.
- Separate pure formatting, validation, configuration, parsing, and mapping from stateful orchestration where appropriate, **but treat security-critical parsers and validators as Trust Path code even when they appear pure**.
- Split growing files by coherent responsibility, not arbitrary line count. Tests and fixtures should follow the owning module. Avoid unrelated refactors inside a security fix.
- Define interfaces and expected behaviour before implementation; document assumptions and integration points. Follow test-driven development for behavioural changes. Refactors must have before/after equivalence tests, especially negative, hostile-input, privacy, and failure paths.
- Preserve fail-closed security, constant-time operations, zeroization, logging/metadata boundaries, error uniformity and least privilege. Never extract a helper in a way that broadens visibility or allows bypassing its policy caller.
- Avoid unnecessary dependencies, generic frameworks, speculative abstractions and over-engineering. Prefer a simple, audited Rust module to a new crate.
- Work in small, independently reviewable PRs. Coordinate with owners of active branches and security-fix PRs before touching shared paths. Record migration notes, affected consumers, tests run and rollback steps. Never force-merge a refactor whose security or integration checks have not passed.
- Maintain a module catalog / planned module map. See `process/MODULARIZATION-ROADMAP.md`; update it when work is completed or new debt is discovered.

## Safe sequencing

1. Fix open Critical/High security defects and establish passing focused regression tests.
2. Extract isolated **test-only** helpers and test groups first; ensure the test inventory and assertions are unchanged.
3. Extract data-only types and pure helpers with their existing contracts, preserving outward-facing re-exports and behaviour.
4. Split storage adapters, stateful flows and orchestration only when their trust boundaries, integration tests and rollbacks are documented.
5. Defer crypto, key lifecycle, anonymity-sensitive timing/padding, authorization and irreversible retention refactors until independent security review is available.

For each extraction, first state: old/new file map; public API impact; dependency impact; security/trust classification; behaviour-preservation tests; CI commands; and rollback instructions. A purely structural PR must not be combined with a behaviour change.
