# Revision Brief (round 2)

You are revising part of the Candor specification set after three adversarial reviews.

## Inputs (read before editing)
1. `/home/user/leaks/specs/DECISIONS.md` — especially §7, **ADR-034..ADR-046** (binding, supersede conflicting earlier text). Also ADR-030/033.
2. `/home/user/leaks/process/REVIEW-A.md`, `REVIEW-B.md`, `REVIEW-C.md` — find EVERY finding (RVW-A-nn, RVW-B-nn, RVW-C-nn) whose AFFECTED field, scenario or proposed fix touches any of YOUR documents (grep for your document numbers, e.g. `grep -n "\b09\b\|09-DATABASE" process/REVIEW-*.md`, and read those findings in full).
3. `/home/user/leaks/process/WRITER-BRIEF.md` — format rules still apply (requirement table columns, ID prefixes, honest language).
4. Your documents in `/home/user/leaks/specs/`.

## What to do
- Edit your documents IN PLACE (use Edit for targeted changes; rewrite sections where needed). Implement the ADR-034..046 decisions and the reviewers' proposed fixes where consistent with those ADRs. If a reviewer fix conflicts with an ADR, the ADR wins; note the difference.
- Remove or correct contradictions (numbers, timers, sizes, k-thresholds, storage locations) so your documents agree with DECISIONS.md and with canonical owners: 08 for upload protocol, 24 §TEL for metrics regime, 09 for exact-timestamp tables, 04 for keys/formats, 11 for page size classes.
- Add new requirements with the NEXT free IDs in your prefixes (never renumber or reuse existing IDs; if a requirement is withdrawn, keep the row and prefix its text with "WITHDRAWN (ADR-0xx):"). Every new security requirement needs Evidence (cite `RVW-A-nn` etc. and ADR IDs are acceptable evidence) and a Verification.
- Update "Residual risks" honestly where a finding is only partially fixable.
- Remove any "Open Issues for ADR revision" items now resolved by ADR-030..046 (mark them "Resolved by ADR-0xx").
- Do not edit documents outside your assignment. If you find a needed change elsewhere, list it in your disposition file under "Cross-document requests".

## Output
Write `/home/user/leaks/process/DISP-<group>.md` containing a table:
`| Finding | Disposition | Changes (doc §, requirement IDs) | Residual risk |`
Disposition ∈ {Fixed, Partially fixed, Accepted residual (documented), Rejected (with reason), Not applicable to this group}. Include every finding that touches your documents. Then a "Cross-document requests" list.

Final message ≤200 words: files changed, count of findings by disposition, cross-document requests.
