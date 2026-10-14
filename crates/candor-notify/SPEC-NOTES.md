<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-notify SPEC notes

## Decisions
The notification data model is closed and content-free. Deduplication compares the complete descriptor and retry state has a fixed upper bound.

## Security self-review
The public model has no free-text/string field and therefore cannot directly carry report text, filenames, source identifiers or case titles. No unsafe code, I/O or logging.

## Open items
Production SMTP/HTTPS adapters must map opaque destinations through an allow-listed subscriber store, keep message templates constant, and undergo AT-011/AT-061 notification sink testing.
