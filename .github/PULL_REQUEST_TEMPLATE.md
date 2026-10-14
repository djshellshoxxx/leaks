<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Security vulnerabilities: do NOT use a public PR. See SECURITY.md. -->

## Summary

<!-- What changes and why. Link the spec section(s) and requirement / test IDs (e.g. 04 §5, CRY-012, ST-021). -->

## Classification

- Tier(s) touched: [ ] T0 crypto/key core  [ ] T1 Trust Path  [ ] T2 non-trust-path
- [ ] Changes CI, workflows, build scripts, `deny.toml` or `supply-chain/` (Release/Supply-chain owner review)
- AI-Assisted: yes / no  <!-- OSG-028, 27 §11.5: if yes, you can explain every line -->

## Security checklist (27 §11.2)

- [ ] Every commit is signed off (`git commit -s`, DCO) and Trust Path commits are signed with a hardware-backed key
- [ ] Hostile input: every externally influenced length, count, index and name is bounded and validated before use or allocation
- [ ] No `unwrap`/`expect`/`panic!`/unchecked indexing or unchecked arithmetic on untrusted data
- [ ] No path construction from external data except through `candor-safefs`
- [ ] No new route without an authorization declaration
- [ ] No new log/metric/trace field without schema entry and anonymity classification
- [ ] No exact timestamp on a source-linked record (ADR-010)
- [ ] Errors do not echo input
- [ ] Secrets wrapped in zeroizing types; no `Debug`/`Display`/`Serialize` on secrets
- [ ] Constant-time comparison for MACs, tags and secrets
- [ ] Crypto calls only through `candor-core`; no new primitives
- [ ] Tests for positive, negative and hostile-input paths, mapped to ST/AT IDs
- [ ] Spec constants come from `tools/constants.json`; `make docs-lint` passes (SG-25)

## Dependencies (28 §5)

- [ ] No new dependency, **or** justification below (function, alternatives, maintainer health, `unsafe` count, transitive fan-out, licence) and in the crate's `SPEC-NOTES.md`
- [ ] Pinned `"=x.y.z"`, minimal features, version ≥ 14 days old (or security fast-track)
- [ ] cargo-vet audit/exemption added; `cargo deny check` and `cargo vet` pass

## Crypto review (27 §11.3) — required for T0 or crypto-crate bumps; signed by the Crypto Reviewer

- [ ] Conforms to `04-CRYPTOGRAPHY.md` suite definitions
- [ ] Domain separation: unique HKDF/HPKE `info` labels and context binding
- [ ] Key commitment where multi-recipient or key rotation is involved
- [ ] Nonce-uniqueness argument written down
- [ ] No secret-dependent branching or indexing
- [ ] Zeroization on every exit path
- [ ] KAT / Wycheproof / property tests added or updated
- [ ] Formal model updated if the message flow changed (ST-030)
- [ ] Downgrade / version negotiation cannot select weaker suites

Crypto Reviewer: @<!-- handle -->

## Anonymity review (27 §11.4)

- [ ] Not triggered, **or** Anonymity Reviewer requested (logging/metrics schema, timestamps, IDs, padding, notifications, schedules, telemetry, source UI resources, headers/cookies, error pages, backups, support bundles, statistics, COI/roster data)

## Verification

```
make check   # paste the summary
```
