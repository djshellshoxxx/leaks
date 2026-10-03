<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-notify

RM-3 content-free notification core for C-23. Notifications use only an opaque destination handle, a closed notification kind, and a deduplication key. There is no subject, body, filename, case title, source identifier or other free-text field. Pending duplicates collapse and retries are bounded.

Run `cargo test -p candor-notify` and `cargo clippy -p candor-notify --all-targets -- -D warnings`.
