# Codebase Map: where to find what

| I want to... | Look in |
|---|---|
| Cryptography (HPKE, envelopes, records) | `crates/candor-core/` (with fuzz targets and test vectors in `tests/vectors/`) |
| Safe file handling | `crates/candor-safefs/`, `crates/candor-safe-read/` |
| Audit log | `crates/candor-log/` |
| Intake store and sealing | `crates/candor-intake-store/`, `crates/candor-sealer/` |
| Source-facing web service | `crates/candor-intake-web/` |
| Source-facing UI | `crates/candor-source-ui/`; static preview in `docs/` |
| Case zone (authz, case model, DB) | `crates/candor-authz/`, `crates/candor-case/`, `crates/candor-case-db/` |
| Authentication | `crates/candor-auth/` |
| Epoch keys | `crates/candor-ekv/` |
| Notifications, retention, relay, worker | `crates/candor-notify/`, `crates/candor-retention/`, `crates/candor-relay/`, `crates/candor-worker/` |
| Memory locking | `crates/candor-memlock/` |
| Specifications | `specs/` (index: `specs/DECISIONS.md`) |
| Process and audits | `process/`, `process/audits/` |
| Traceability and constants tooling | `tools/` |
| Licences | `LICENSE`, `LICENSES/` |
