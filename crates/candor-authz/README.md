<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-authz

RM-3 deny-by-default authorization core for C-22. The public API evaluates tenant, role, assignment, conflict-of-interest, and bounded break-glass facts before allowing case actions. Cross-tenant access and system-administrator case-content access are always denied.

Run `cargo test -p candor-authz` and `cargo clippy -p candor-authz --all-targets -- -D warnings`.
