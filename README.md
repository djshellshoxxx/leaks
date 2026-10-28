# Candor — High-Assurance Whistleblowing & Secure Case-Management Platform (Specification Set)

Candor (working name) is a specification for an anonymous reporting, source-communication and case-management platform with two editions:

- **Community Edition** — free, AGPL-3.0-or-later, self-hostable, with the **same** anonymity, cryptographic and security protections as the commercial edition.
- **Enterprise / Government Edition** — commercially supported modules (HA, fleet management, SSO bridging, compliance packs, integrations, managed hosting) that never sit in the source trust path.

This repository contains the **research and specifications** and the first part of the **Community Edition implementation** (Rust crates under `crates/`: crypto library, safe file handling, audit log, source-facing pages, intake store, sealer, intake web service, host configuration). Each finished component passed an independent security audit (`process/audits/`); the internal case zone, recipient app and operations stages are not finished. See `process/STATUS.md` for exactly what is done, what is not cleared, and what needs people.

> Candor is not "unhackable", "perfectly anonymous" or "untraceable". Every protection in these documents states what is protected, from whom, under which assumptions (`specs/40-SECURITY-ASSUMPTIONS.md`), and what residual risk remains.

## Architecture in one paragraph

Anonymous submissions arrive **only** through a Tor v3 onion service (no clearnet fallback) at an isolated intake zone that holds nothing but ciphertext. Reports are encrypted — in the source's verified client, or for the no-JavaScript web path in an isolated in-memory sealer — to **per-member, short-lived epoch keys** (hybrid post-quantum HPKE, X-Wing), after a conflict-of-interest filter removes anyone the report concerns, so excluded people never hold a key that can decrypt it. The internal case zone **pulls** sealed batches (no inbound path from the internet-facing zone), and recipients decrypt only on hardware-key-protected desktop clients; attachments are opened only in network-less disposable viewers that produce sanitized working copies while preserving hashed originals. There is no server-side master key; administrators hold no case keys; audit logs record staff actions without source-identifying metadata; deletion is cryptographic and reaches backups within a bounded window. See `specs/DECISIONS.md` for the 47 binding architecture decisions (ADR-034..047 came from the adversarial review).

## Repository layout

| Path | Contents |
|---|---|
| `research/R1..R6` | Deep research notes (SecureDrop/OnionShare; GlobaLeaks/CoverDrop/Hush Line/commercial; 74 historical incidents; Tor/I2P attack literature; cryptography/code-integrity/sanitization/supply chain; compliance/accessibility/licensing) with bibliographies |
| `specs/DECISIONS.md` | Binding ADR register, component catalog (C-nn), core threat catalog (THR-nnn), requirement format and ID prefixes |
| `specs/00..40-*.md` | The specification set (research consolidation, PRD, threat model, privacy, crypto, OPSEC, architecture, backend, API, DB, evidence pipeline, UIs, case management, auth, Tor, infrastructure, deployment, backups, logging, enterprise, government, community, licensing, compliance, accessibility, SDL, supply chain, security & anonymity testing, incident response, operations, releases, performance, retention, governance, audit plan, roadmap, traceability, assumptions) |
| `specs/COMPLETENESS-CHECKLIST.md` | Final completeness checklist mapping every required topic to specification and verification |
| `specs/REVIEW-REPORT.md` | Three adversarial reviews (nation-state red team, privacy researcher, enterprise/government architect) and how each weakness was resolved |
| `tools/constants.json`, `tools/constants_lint.py` | Canonical constants registry and cross-document consistency lint |
| `tools/review_report.py` | Generates `specs/REVIEW-REPORT.md` from reviews and dispositions |
| `tools/traceability.py` | Generates `specs/39-REQUIREMENTS-TRACEABILITY.md` and lints requirement hygiene |
| `process/` | Writer brief and raw reviewer reports |

## Suggested reading order

1. `specs/DECISIONS.md` → 2. `specs/02-THREAT-MODEL.md` → 3. `specs/03-PRIVACY-ANONYMITY.md` → 4. `specs/04-CRYPTOGRAPHY.md` → 5. `specs/06-SYSTEM-ARCHITECTURE.md` → then the documents for your team (see `specs/38-IMPLEMENTATION-ROADMAP.md` §3).

## Regenerating the traceability matrix

```bash
python3 tools/traceability.py
```

The script exits non-zero if any requirement ID is duplicated or any security requirement lacks a verification strategy.

## Status

Specification set: complete draft v1.0 (2026-09-30). Implementation: RM-0, RM-1 and most of RM-2 (intake zone) are built and audited; RM-3 (case zone) is partly started; RM-4 onwards is not started. Research limitations (blocked primary sources, items marked UNVERIFIED) are listed in `specs/00-RESEARCH.md` §1. **Not ready for real use**: external audits and a cryptography review are required before any release. Details and the hand-off list: `process/STATUS.md`.

## Preview site

A static design preview (landing page plus every source-interface screen rendered from `candor-source-ui`) lives in `docs/` for GitHub Pages. Regenerate the screens with `cargo run -p candor-source-ui --example render_all` and copy the `en_*` pages into `docs/preview/`. The preview is not a live service and accepts nothing.

## Support

Candor is developed in the open and will stay free. Donations are optional and buy no influence over security decisions. Monero (XMR):

```
85cSWLFurZj8XbKWX7Kk3u1oUtp5vLGQcLSfXEdGnTUU5P9mik6GCPk8guPfAwzHdFFUCbDKChZEphQyp6BNMQwo5oyPLUD
```
