<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-notify

RM-3 content-free notification **model** for C-23. `Notification` stores only an opaque destination handle, a closed notification kind and a deduplication key; it has no subject, body, filename, case title or source identifier field. The in-memory `NotifyQueue` collapses duplicates among its current entries and bounds retry attempts; it is **not** a durable, production delivery queue.

## Implemented behaviors versus integration work

- `DailyT1::for_slot` emits the same fixed external template irrespective of its `pending` argument, provided the subscription is active in `DailyConstant` mode. `Off` and unsubscribed states return no message. The instance label is user-visible in that template and is bounded to 32 Unicode scalar values; it must not be populated from report/source content.
- `candor-case-db/src/repo/notify.rs` is a **separate** PostgreSQL repository API for content-free `T1` daily rows, notification targets, due-row selection, marking and purging. SQL binds the tenant from `TenantTx`; the schema uniquely keys rows by (tenant, user, due day). Its existence does **not** establish a complete authenticated, deployed or audited sender/scheduler integration.
- Actual outbound SMTP/HTTPS adapters, destination allow-list mapping, constant-time/day delivery behavior, safe failure/retry handling and independent sink/privacy verification remain open in [SPEC-NOTES.md](SPEC-NOTES.md) and [the implementation status](../../process/STATUS.md). A bounded in-memory retry counter does not prove transport delivery or log privacy. Do not treat this module as an approved production notification service.

## Developer verification

```sh
cargo test -p candor-notify --all-targets --locked
cargo clippy -p candor-notify --all-targets --locked -- -D warnings
```

These commands are **instructions, not a claim of a passing run**. Tests in [daily_constant.rs](tests/daily_constant.rs) verify pending-work independence, off/unsubscribed behavior and fixed body/label bounds; [queue.rs](tests/queue.rs) verifies the closed model, duplicate suppression and retry limit. Database integration tests live in [candor-case-db/tests/pg.rs](../candor-case-db/tests/pg.rs), but their entry point skips execution when `CANDOR_TEST_PG` is unset. A green unit-test result must not be represented as a completed PostgreSQL privilege or delivery-timing test.

Any production sender, scheduler or privacy/retention claim requires source-pinned integration evidence and the independent review gates recorded in [process/STATUS.md](../../process/STATUS.md). No specification, notification policy or security approval is modified by this README.
