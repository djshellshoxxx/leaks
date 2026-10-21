# Architecture and Design Rationale

Summary from the README; the binding decisions are in `specs/DECISIONS.md` (47 ADRs, ADR-034..047 from the adversarial review).

- **Tor-only intake.** Anonymous submissions arrive only through a Tor v3 onion service, with no clearnet fallback.
- **Ciphertext-only intake zone.** The internet-facing zone holds nothing but ciphertext.
- **Per-member, short-lived epoch keys.** Reports are encrypted to per-member keys (hybrid post-quantum HPKE, X-Wing), so a member excluded by a conflict-of-interest filter never holds a key for that report.
- **Pull, not push, into the case zone.** The internal case zone pulls sealed batches; there is no inbound path from the internet-facing zone.
- **Hardware-key desktop decryption.** Recipients decrypt only on hardware-key-protected desktop clients.
- **Disposable viewers for attachments.** Attachments open only in network-less viewers that produce sanitised working copies while keeping hashed originals.
- **No server-side master key; administrators hold no case keys.**
- **Audit logs without source-identifying metadata.**
- **Cryptographic deletion** reaching backups within a bounded window.
- **Trust-path code in Rust with `unsafe` forbidden** (workspace lints), and fuzzing of parsers (`crates/candor-core/fuzz/`).

*(inferred: the crate split, e.g. `candor-core` and `candor-safefs` under Apache-2.0 OR MIT per ADR-031, is there to keep the cryptographic and file-handling primitives reusable; the Cargo.toml header states the licence split.)*
