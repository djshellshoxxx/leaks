<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-authz

RM-3 deny-by-default authorization core for C-22. `pdp::authorize` is the policy decision point of 15 §5.9: audience and tenant, explicit deny (suspension, blinded COI tag), the 15 §5.2 role matrix, the case ACL relation, then obligations (step-up, second approver, audited access). `pdp::validate_key_wraps` enforces 07 §5.5 on case-key wraps. The older single-role `authorize` (assignment and break-glass) and `authorize_case` adapters remain for the Case Service core. Cross-tenant access and administrative-role case-content access are always denied; COI always wins.

Run `cargo test -p candor-authz` and `cargo clippy -p candor-authz --all-targets -- -D warnings`.
