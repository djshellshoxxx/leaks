<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Governance (summary)

The normative text is [`specs/36-OPEN-SOURCE-GOVERNANCE.md`](specs/36-OPEN-SOURCE-GOVERNANCE.md).
This page is a short summary; where they differ, the spec wins.

## Structure

- **Candor Foundation** (non-profit; jurisdiction to be chosen with legal review)
  stewards the Community Edition, owns the "Candor" trademark, hosts the
  repositories and the TUF root ceremony, and enforces the **Edition Charter**
  (`specs/24-LICENSING-BUSINESS-MODEL.md` §7), which forbids moving protections
  out of the Community Edition.
- **Vendors** build and sell Enterprise Edition modules, which are separate works
  outside the source Trust Path (ADR-020). They hold a trademark licence that is
  conditional on Charter compliance.
- **Contributors** keep their copyright (DCO, no CLA, see CONTRIBUTING.md).

| Body | Composition (key limits) | Decides |
|---|---|---|
| Board | 5–7; ≤ 2 from any one vendor; ≥ 2 civil-society/press-freedom | Budget, trademark, Charter enforcement (Charter amendments: 2/3, strengthen-only) |
| Technical Steering Committee | 5–9 maintainers; ≤ 40 % from one employer | ADRs, release policy, maintainer appointments (lazy consensus; 2/3 for Trust Path invariants) |
| Security Team | 4–8; ≥ 2 employers, ≥ 2 jurisdictions | Triage, embargo (two-person rule), advisories, CNA |
| Release Signers | 5 root (3-of-5), 3 targets (2-of-3), spread across organisations and jurisdictions | Sign releases after reproducibility verification |
| Watcher and Witness Council | 3–5, civil-society majority | External Watchers and Key Directory witnesses |
| Charter Ombudsperson | 1, independent of vendors | Charter complaints (findings published within 60 days) |

## Roles

Contributor → Reviewer (10 merged PRs, 3 months) → Maintainer (6 months as
reviewer, hardware-signed commits, FIDO2) → Trust Path Maintainer (12 months,
secure-coding review, identity verified by two TP maintainers, TSC 2/3 vote) →
Emeritus after 12 months of inactivity.

## Key rules

- Trust Path changes: ≥ 2 Trust Path Maintainers from ≥ 2 employers, plus the
  Security Team for crypto/parsing/auth/logging/update code; 72 h/24 h cooling.
- Security fixes ship to CE and EE simultaneously; one shared advisory process
  ([SECURITY.md](SECURITY.md)).
- No single organisation or jurisdiction can reach any release-signing threshold;
  reproducible builds by ≥ 2 builders in different organisations and jurisdictions.
- Bus factor: published quarterly; dead-man procedure if no release is signed for
  12 months or the Security Team is unreachable for 30 days.
- Transparency: a signed project statement every 30 days (no compelled
  modification, targeted build or compelled signing) and a per-jurisdiction
  transparency report every 6 months.
- Fork-friendly: AGPL Trust Path, reproducible builds, open formats, no CLA. Forks
  that modify the Trust Path must rebrand (trademark policy, 36 §5).
