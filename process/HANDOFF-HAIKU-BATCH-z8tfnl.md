# Haiku batch handoff (session z8tfnl)

Branch: `claude/haiku-batch-z8tfnl` at `bcf6118` (draft, unaudited checkpoint). Based on `claude/tender-tesla-z8tfnl` at `4686d63`. Not for `main`.

## Done
- `candor-source-ui/tests/render.rs` split into `tests/render/{layout,security,locale,forms,content}.rs` (commit `4d3c420`). Root file keeps the shared helpers and the `preview` path. Test names are unchanged, except the proptest, now `security::prop::arbitrary_text_is_inert`.
- `candor-log/tests/chain.rs` split into `tests/chain/{support,integrity,checkpoints,timestamps,disposal,sinks}.rs` (commit `2bfcf03`). Helpers are `pub(super)`. Test-only; no `src/` change.

## Tests run on the integration branch (this session)
- `cargo fmt -p candor-source-ui -p candor-log -- --check`: clean.
- `cargo clippy -p candor-source-ui -p candor-log --locked --all-targets -- -D warnings`: clean.
- `cargo test -p candor-source-ui -p candor-log --locked --all-targets`: candor-source-ui 87 passed, candor-log 104 passed, 0 failed. Same totals as the base commit.
- Haiku reviewers (separate agents, read-only) approved both commits. Their findings were checked: scope, Signed-off-by, function-body equivalence.

## Not done / not verified
- Not run: `make check` (cargo-deny, cargo-vet, docs-lint), other crates, browser checks.
- cargo-vet is red by design (owner sign-off needed; see `process/STATUS.md` §4).
- The `security/*` fix branches (PRs #4–#7) and the `docs/modular-first-roadmap` branch (PR #8) were not merged or re-tested here. They need owner review.

## Mock-only boundaries
- None introduced. No synthetic backends were added.

## Remaining straightforward work
- Split `candor-intake-store/tests/common/mod.rs` (needs the PostgreSQL harness).
- Split `candor-source-ui/src/model.rs` and the display-only parts of `view.rs` (see `process/MODULARIZATION-ROADMAP.md` on PR #8).
- Documentation updates for the new test layout.

## Blocked on owner decisions (not for small models)
- RM-3 core zone (authz, auth sessions, relay, retention): see `process/STATUS.md` §6.
- Source-facing S08 invisible-character notice (SUI-076): Trust Path, needs independent audit.
