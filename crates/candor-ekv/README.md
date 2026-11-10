<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-ekv

**Status: RM-3 in-memory implementation; not a production vault or a completed release/security gate.**

This crate provides an in-process erasure-key vault for a tenant/case pair. It generates a per-case key internally and returns an opaque `KeyHandle`; callers do not receive the raw key. `seal` and `unseal` wrap inner data with XChaCha20-Poly1305, authenticating tenant, case, key epoch and recipient key ID via associated data.

## Lifecycle and boundaries

- `create_case` rejects a duplicate tenant/case pair. A handle identifies the in-memory entry; it is **not** an authenticated access-control capability by itself. Production callers must enforce their authorization and isolation requirements.
- `approve_destroy` requires two distinct **provided** `ApproverId` values, then zeroizes the in-memory key and marks the entry destroyed. The crate itself does not authenticate the people or devices represented by those identifiers; an approved service boundary must do so.
- `mark_missing_for_restore` invalidates the previous in-memory key. `rekey_missing` generates a *new* key and resets approvals: previously sealed wraps are not restored by rekeying.
- Destruction and `Drop` invoke in-process zeroization, but this implementation does **not** establish that every physical-memory copy, serialized backup, snapshot or external key has been erased. The production vault, locked memory, VMK/HSM protection, storage/backup exclusion, restore handling and independent AT-026 evidence remain outstanding in [SPEC-NOTES.md](SPEC-NOTES.md) and the repository's [status handoff](../../process/STATUS.md).

No release or live-case use is authorized by the presence of this prototype. The source and its tests are distinct from an independently audited and integrated key-destruction workflow.

## Verification for developers

From the repository root on the pinned Rust toolchain:

```sh
cargo test -p candor-ekv --all-targets --locked
cargo clippy -p candor-ekv --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

The integration tests in `tests/aead_lifecycle.rs` cover per-case sealing, context/AAD refusal, two-approver destruction, restore/rekey non-revival and duplicate-key refusal. These commands are **instructions**, not evidence that they ran or passed for any particular commit. Whole-workspace CI, adversarial review and the owner-controlled security gates still apply.
