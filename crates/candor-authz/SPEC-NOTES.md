<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-authz SPEC notes

## Decisions
Tenant mismatch is evaluated before every other rule. COI denies normal and emergency access. Role/action combinations are explicit; unspecified combinations deny. Break-glass requires an approved, unexpired grant and cannot cross tenants.

## Security self-review
No content or source metadata enters the policy model. Break-glass carries no free-text reason. System administrators have no case-content capability. No unsafe code, I/O or logging.

## Open items
Production C-21 token verification, full ABAC/ACL policy facts and dual-approved break-glass issuance remain integration responsibilities of the Case/Auth services.
