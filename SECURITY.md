<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Security Policy

Candor is whistleblowing software. A vulnerability in it can put a source's
safety at risk. Please report problems privately, and please do not test against
instances you do not operate.

This policy implements `specs/36-OPEN-SOURCE-GOVERNANCE.md` §7–§9 and
`specs/37-SECURITY-AUDIT-PLAN.md`. It covers **both** the Community Edition (CE)
and the Enterprise Edition (EE): there is one Security Team, one disclosure
process and one set of advisories (ADR-020, Edition Charter §4).

> **Status (pre-1.0, RM-0):** contact addresses and keys below are placeholders
> marked `TODO`. Until they are published, use a GitHub private security advisory
> on this repository. Candor has not been audited yet; no production onion
> address may be published for a real organisation before roadmap milestone RM-6
> (`specs/38-IMPLEMENTATION-ROADMAP.md`).

## How to report

Use whichever channel is safest for you. Anonymous reports are welcome.

| Channel | Address | Notes |
|---|---|---|
| Onion service form (preferred for anonymity) | `TODO: http://<v3-onion>.onion/` | A Candor instance run by the Security Team. Use Tor Browser on the "Safest" setting. |
| E-mail, encrypted | `security@TODO-candor-domain` | Encrypt with the age **or** OpenPGP key below. |
| GitHub private advisory | "Report a vulnerability" on the repository's Security tab | Ties the report to your GitHub account. |

Keys (verify the fingerprints on at least two independent channels, e.g. the
project website and its onion mirror, before use):

```
age recipient:   TODO age1...
OpenPGP:         TODO fingerprint XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
```

Advisories are signed with the Security Team advisory key (Ed25519 + ML-DSA-65
dual signature, ADR-006; ≥ 2 holders in ≥ 2 jurisdictions, 36 §3.4):

```
Advisory signing key: TODO
```

Please include: affected component and version (or commit), deployment profile,
a description of the impact, and steps or a proof of concept. **Do not include
real source data or real submissions.** If the issue could identify a source, say
so in the first line.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement | ≤ 48 hours (goal: 8 hours) |
| Triage and severity | ≤ 5 business days. CVSS v4 **plus** an anonymity-impact rating A0 (none) … A3 (source identification possible) |
| Fix available | A3 or Critical: ≤ 7 days · High: ≤ 30 days · Medium: ≤ 90 days · Low: next release |
| Embargo | Default ≤ 90 days; ≤ 14 days if exploited in the wild |
| Publication | Advisory + fixed release; post-incident report within 30 days for A2/A3 issues |

Embargo decisions follow a two-person rule inside the Security Team. We will
keep you informed and agree a publication date with you.

## Scope

In scope:

- all Community Edition code in this repository;
- Enterprise Edition modules;
- project infrastructure: TUF repositories, package mirrors, the website and its
  onion mirror, the transparency-log submission tooling, CI/build/release pipeline
  (including this repository's workflows);
- documentation errors that lead operators to an unsafe configuration.

Out of scope: instances you do not operate (report those to their operator);
social engineering of project members; volumetric denial of service; findings
that require a fully compromised client device unless Candor claims to resist
that case (see `specs/02-THREAT-MODEL.md` and `specs/40-SECURITY-ASSUMPTIONS.md`).

## One advisory for CE and EE

- CE and EE fixes for shared code are released **at the same moment**.
- EE customers do **not** get earlier notice than the pre-notification list.
- The pre-notification list is criteria-based, never payment-based: distribution
  packagers, national CERTs, and Security-Team-vetted operators of registered
  high-risk deployments (CE or EE). It receives notice at most 7 days before
  publication.

Each advisory carries a CVE ID (via the GitHub Security Advisories CNA until the
Foundation becomes a CNA) and a `CANDOR-YYYY-NNN` ID; affected editions, versions
and profiles; CVSS v4 and anonymity impact; whether exploitation could identify
sources or expose content and **what operators should check**; fixed versions with
TUF target hashes and transparency-log entries; workarounds; credits. Advisories
are published as repository advisories, on the website and its onion mirror, on a
signed mailing list, as CSAF 2.0 (with VEX) and as OSV records.

## Safe harbour

We consider security research carried out in good faith and within this policy to
be authorised. We will not bring or support legal action against you for it, and
we will say so to third parties if asked. Good faith means: you test only systems
you own or are explicitly allowed to test; you do not access, keep, or disclose
other people's data (in particular, you never attempt to identify a source); you
do not degrade service for others; and you give us reasonable time to fix the
issue before disclosure. If in doubt, ask us first via the channels above.

## Credit and bounty

We offer credit in the advisory, including anonymous or pseudonymous credit. A
bounty will be funded when the Foundation's revenue allows; it will never be
conditional on a non-disclosure agreement beyond the embargo.

## Supported versions

Pre-1.0: only the latest commit on `main` is supported. From 1.0, supported
release lines and security floors are published as signed TUF metadata
(`specs/33-RELEASE-UPDATE-SECURITY.md`); a `security.txt` (RFC 9116) is served on
every official domain and on the onion information site.
