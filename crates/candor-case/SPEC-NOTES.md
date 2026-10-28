<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-case SPEC notes

## Decisions
Imports are tenant-scoped and idempotent by header digest. Audit commit succeeds before the in-memory case record becomes visible. Object lookup is tenant-filtered before authorization and authorization denial is collapsed to the same response as absence. The SQL foundation uses forced RLS and a fail-closed `current_setting('candor.tenant_id')` tenant function.

## Security self-review
The API exposes no generic attribute setter. Cross-tenant object probes do not reveal existence. Source-linked persistence uses day granularity only. Public table rights are revoked. No unsafe code or free-text logging.

## Open items
The current service core is transport-independent and in-memory; production PostgreSQL repository wiring, C-21 token validation, complete routers/DTOs, blob-store integration and live RLS integration tests are still required. Full compromise drills require candor-lab.
