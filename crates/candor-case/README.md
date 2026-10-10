<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-case

RM-3 Case Service core for C-10/C-12. It provides tenant-scoped relay import, header-digest idempotency, assignment, authorization-before-disclosure, and a fail-closed audit commit point. Unauthorized and nonexistent case lookups intentionally return the same `NotFound` result.

`migrations/0001_core.sql` establishes the minimal core schema with tenant-qualified keys, forced PostgreSQL RLS, least-privilege grants, day-only source-linked import metadata, and tenant-scoped import deduplication.

Run `cargo test -p candor-case` and `cargo clippy -p candor-case --all-targets -- -D warnings`.
