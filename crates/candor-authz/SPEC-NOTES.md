<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-authz SPEC notes

## Decisions
Tenant mismatch is evaluated before every other rule. COI denies normal and emergency access. Role/action combinations are explicit; unspecified combinations deny. Break-glass requires an approved, unexpired grant and cannot cross tenants.

## Security self-review
No content or source metadata enters the policy model. Break-glass carries no free-text reason. System administrators have no case-content capability. No unsafe code, I/O or logging.

## Open items
Production C-21 token verification, full ABAC/ACL policy facts and dual-approved break-glass issuance remain integration responsibilities of the Case/Auth services.

## C-22 decision point (`pdp`; added 2026-11-11)

`pdp::authorize(principal, action, resource, context)` is the pure policy decision point of
15 §5.9. It implements the 15 §5.4 order: (1) audience and tenant → (2) explicit deny
(suspended account, blinded COI tag) → (3) role permission from the 15 §5.2 matrix → (4) relation
(case ACL; hidden case) → (6) obligations. `authorize_case` and `validate_wrap_recipients` are
now thin adapters onto `pdp`, so there is one decision procedure to review and mutate.

**Implementation decisions**
1. CASE_LEAD grants require the *lead* relation on the case, not mere membership (the matrix's
   "A" reads "member/lead"; the stricter reading is taken for lead-only powers and, for
   consistency, every CASE_LEAD row). A lead who also needs plain member access holds
   INVESTIGATOR too.
2. RECORDS_CUSTODIAN gets `case.read_content` with an ACL relation, per the §5.2 note ("only
   `case.read_content` (A, via explicit grant)"). The matrix row itself shows "—": this is a spec
   inconsistency to resolve in 15 §5.2; the note (ADR-044(5), round 2) is followed.
3. Obligations are the union over every held role that satisfies the relation, so an extra role
   never weakens what one role would require (strictest wins).
4. A principal holding any administrative role (SYS_ADMIN, USER_ADMIN, SECURITY_OFFICER) is denied
   every case action, whatever content roles it also holds (ADR-015 baseline invariant, 15 §5.7;
   role assignment should never produce such a holder, and the PDP fails closed if it does).
5. Hidden case (triage-first, ADR-037(2)), missing ACL relation and a COI match all return
   `DenyCode::NoRelation` (15 §5.4, THR-020): the Desk and the audit trail cannot tell them apart.
6. `AuthzContext.audience` defaults to `desk-api`, the only audience that reaches case routes
   (ADR-029); `admin-api` is denied before any case fact is read.
7. For `Action::Import`, `ResourceRef::member` means Triage Set membership; the route layer
   derives it (15 §5.4 step 4).
8. Key wraps (`validate_key_wraps`, 07 §5.5, BE-018): duplicate key ids, a key listed under two
   users, any excluded or stale row for a key, an unknown key, more than 256 wraps or a minimum of
   0 are refused; two keys of one user count as one recipient (ADR-044(2) counts distinct users).
9. The legacy `authorize` (single-role, assignment and break-glass model used by
   `CaseService::open_case`) is unchanged; folding break-glass into `AuthzContext` is an open item.

**Not implemented (open items):** step 5 attribute conditions (department scope, AAL3
requirement, SEALED_MATTER/LEGAL_HOLD/HOLDER_SUSPENDED flags), temporary-grant expiry (15 §5.5),
break-glass as a context fact, signed and versioned policy bundles, generation of ST-060 from
`authz/matrix.yaml` (the test transcribes the matrix independently instead), `cargo mutants`
(not available offline).

### Dependencies
- `proptest` (dev): the "deny unless an explicit grant exists; COI always wins" property and the
  wrap-validation completeness property.

### Security self-review (delta)
- No I/O, no logging, no free text: the decision carries codes only. `Principal` holds random
  ids and roles; no source data can enter the model.
- Every role × action pair is pinned by an independent transcription of 15 §5.2
  (`tests/pdp_contract.rs`), the evaluation order is pinned step by step, and a 512-case property
  test checks the invariants over random principals, resources and audiences.
- Deny by default: an empty role set, an unknown (role, action) pair, a hidden case or a missing
  relation all deny; nothing permits without a matrix row and a relation.
