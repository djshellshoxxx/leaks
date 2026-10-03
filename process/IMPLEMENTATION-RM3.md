<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# RM-3 completion plan

This plan continues the implementation from the RM-2 wave-2 / RM-3-foundations branch. The binding design sources are `specs/07-BACKEND.md`, `08-API.md`, `09-DATABASE.md`, `15-AUTHENTICATION-AUTHORIZATION.md`, `18-RETENTION-DELETION.md`, `20-LOGGING-AUDITING.md`, `30-ANONYMITY-TESTING.md`, and `38-IMPLEMENTATION-ROADMAP.md`.

## Existing dependencies retained

- `candor-intake-store`: claim/ack/reply/deletion-list relay boundary.
- `candor-log`: typed content-free events, audit hash chains, signed checkpoints, witness verification, disposal/retention tombstones and verification.
- `candor-safefs`: filesystem boundary.
- `candor-core`: cryptographic primitives and secret handling.

## Work sequence

1. **Relay core (`candor-relay`)**
   - Strict monotonically increasing request counter and replay rejection.
   - Bounded batch claiming and idempotent import acknowledgment state machine.
   - Import backpressure gate.
   - One-way transport policy model that rejects arbitrary destinations and inbound application traffic.
   - Tests first: replay, counter exhaustion, duplicate ack, backpressure, destination denial.

2. **Authorization core (`candor-authz`)**
   - Tenant-scoped principals and resources.
   - Explicit role/action policy with deny-by-default behavior.
   - Conflict-of-interest assignment and break-glass semantics without emitting source-sensitive reason data.
   - Tests first: cross-tenant/IDOR denial, COI denial, role denial, break-glass constraints.

3. **Case core (`candor-case`)**
   - Explicit DTO/command surface; no generic attribute setter.
   - Tenant context required for every operation.
   - Authorization before object lookup response disclosure.
   - Idempotent relay import keyed by header digest with bounded deduplication metadata.
   - Audit commit dependency is fail-closed.
   - Tests first: cross-tenant indistinguishability, unauthorized object probes, duplicate imports, audit failure.

4. **Erasure-key vault (`candor-ekv`)**
   - Opaque per-case key handles, no key material in Debug/Display/serialization.
   - Dual-control destruction authorization.
   - Irreversible destroyed state and idempotent destruction.
   - Tests first: single approval denied, duplicate approver denied, post-destruction retrieval denied.

5. **Notifications (`candor-notify`)**
   - Closed notification taxonomy and allow-listed destination handles.
   - Content-free payloads only; no case/source/body/filename fields.
   - Deduplication and bounded retry state.
   - Compile/runtime tests proving sensitive free text cannot enter the notification model.

6. **Retention worker (`candor-retention`)**
   - Policy-derived due set using coarse dates only.
   - Two-phase tombstone-then-delete state machine.
   - EKV destruction before content disposal completion.
   - Idempotent retries and legal-hold exclusion.

7. **Database/RLS and deployment tests**
   - Case-zone PostgreSQL migrations with forced RLS and separate least-privilege roles.
   - Static schema lint for tenant keys, RLS enable/force, prohibited source metadata and dangerous grants.
   - Integration tests for cross-tenant SQL isolation.
   - Firewall policy fixture/test proving only the relay may initiate the intake-link connection and only to the configured intake endpoint.

8. **RM-3 gate**
   - Add AT-020..AT-024 compromise-drill fixtures/tests.
   - Run per-crate tests during construction, then workspace CI, safefs lint, logging lint, docs/traceability checks, dependency policy checks and reproducibility smoke.
   - Record unresolved external/manual evidence separately; never mark it passed without evidence.

## Completion boundary

Repository implementation can satisfy code, schema, static-policy and automated-test requirements. Independent audits, multi-operator reproducible-build evidence, real usability studies, production firewall observation, public release ceremonies and bug-bounty operation require external actors/infrastructure and remain explicit release gates rather than being self-certified here.
