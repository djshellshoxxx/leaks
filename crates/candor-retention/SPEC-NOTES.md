<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-retention SPEC notes

## Decisions
Legal holds remove an item from the due set. The state machine requires tombstone before key destruction and key destruction before final disposal. Repeating an already-completed transition is safe.

## Security self-review
Only coarse day values are modeled; there is no source activity timestamp or free-text field. Invalid ordering fails closed. No unsafe code, I/O or logging.

## Open items
Production worker integration must bind transitions to `candor-log` checkpointed retention/disposal tombstones, call the EKV service, execute database/blob deletion transactionally, and prove restore behavior in the RM-5 backup/restore drill.
