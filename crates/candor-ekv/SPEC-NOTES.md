<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-ekv SPEC notes

## Decisions
Key handles render as opaque values. Destruction needs two different approvers, zeroizes the key before changing state, and repeated destruction requests remain successful without restoring material.

## Security self-review
No unsafe code, filesystem access or logging. Key material is never part of handle Debug output. Arithmetic exhaustion fails closed.

## Open items
Production storage must move the vault behind its dedicated Unix-socket service, use TPM/HSM-backed VMK protection and locked memory, and avoid returning raw key material to callers that are not the case/worker trust boundary. Vault backup/exclusion and AT-026 evidence remain operations gates.
