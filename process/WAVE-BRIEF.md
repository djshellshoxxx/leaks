# Wave brief — shared rules for every builder and auditor after RM-2 wave 1

Read this after `process/BUILD-BRIEF.md` (which still applies in full: rules 0–9, Security and OPSEC bar,
audit gate). Where this file and BUILD-BRIEF differ, this file wins for the points below.

## 1. Environment (the session disk allowance is small, about 9 GB)
- Before any cargo command: `export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
  (this cuts target/ size by more than half; CI still builds with debug info).
- Never run `cargo build/test/clippy --workspace`. Use `-p <your crate>` (and `-p` for the crates you
  changed or depend on and must re-test). The lead runs workspace-wide checks at integration.
- Fuzz and proof-of-concept builds go only under the scratchpad
  `/tmp/claude-0/-home-user-leaks/710eb0c5-5e3b-5945-8ecd-59258f21ba8b/scratchpad/<your-name>/`
  with `CARGO_TARGET_DIR` set there. Delete them when done. If `df -h /` shows under 3 GB avail,
  run `cargo clean -p <your crate>` and delete your scratch dirs before continuing.
- Tests needing PostgreSQL: `bash crates/candor-intake-store/scripts/pg-test.sh <command>` (the
  case-zone crates get their own harness; see their SPEC-NOTES).

## 2. Shared working tree (several agents run at once)
- Edit only the files in your assignment. Other agents are editing other crates at the same time.
- Format with `cargo fmt -p <crate>` only. Never `cargo fmt --all`.
- Shared files may only be changed with append-only shell edits (`cat >> file`): `supply-chain/config.toml`
  (vet exemptions and `[policy.<crate>]` for each new first-party crate, 2027-03-30 expiry, same format as
  existing entries), `deny.toml` (build-script allow-list entries with a justification comment). Do not run
  `cargo vet fmt`. Do not edit `specs/`, `.github/`, root `Cargo.toml`, `Cargo.lock` by hand (cargo may
  rewrite the lock; that is fine). Anything else you need changed goes in your crate's `SPEC-NOTES.md`
  under "Lead requests" and the lead applies it.
- Do not commit or push. The lead integrates and commits.

## 3. Standing rules
- Token efficiency without cutting quality: grep for the spec sections you need, do not read whole specs.
- New unsafe code is forbidden everywhere except `candor-memlock` (allow-listed OS-shim crate).
- Every new first-party crate: SPDX header on every file, `[lints] workspace = true`, README.md,
  SPEC-NOTES.md (decisions, dependency justifications, "Security self-review", "Open items"),
  exact-pinned dependencies with `default-features = false`.
- No metadata anywhere (IP, UA, exact times, filenames, sizes, passphrases, bodies): logs, errors, panics,
  metrics, test fixtures. Typed `candor-log` events only. Filesystem access only through `candor-safefs`
  (or fd-only calls with a justified `// safefs-lint: allow(<reason>)` marker).
- Fail closed. Uniform responses. Strict parsers with explicit maxima. No panics on input.
- Run `bash crates/candor-safefs/scripts/lint-safefs.sh` and the logging lint (candor-log
  `tests/lint_logging.rs`) before finishing; both must be clean for your files.
- Final report: at most 200 words. State the public API, test counts, decisions that need the lead,
  and anything blocked or deferred. Never claim a check passed unless you ran it.

## 4. Audit gate (auditors)
- Auditors are separate agents who did not build the code. Follow `process/AUDIT-CHECKLIST.md` and
  `research/R9-secure-code-audit.md`. Write `process/audits/AUDIT-<step>.md` (finding IDs, severity,
  evidence with a proof of concept, fix). A step passes with zero open Critical/High and each Medium
  fixed or accepted in writing by the lead. Do not modify code except your report; PoCs go in scratch.
- Re-test every fix with the original PoC and look for variants of the same bug class.
