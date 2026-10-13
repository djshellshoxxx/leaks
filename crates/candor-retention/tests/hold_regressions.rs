// SPDX-License-Identifier: AGPL-3.0-or-later
//! An active legal hold and a future due date must block irreversible transitions.
use candor_retention::{ItemId, RetentionError, RetentionItem, RetentionState, RetentionWorker};

#[test]
fn held_case_cannot_advance_through_any_erasure_transition() {
    let mut worker = RetentionWorker::new(vec![RetentionItem::new(ItemId(17), 100, true)]);
    assert_eq!(
        worker.mark_tombstoned(ItemId(17), 101),
        Err(RetentionError::LegalHold)
    );
    assert_eq!(
        worker.mark_key_destroyed(ItemId(17)),
        Err(RetentionError::LegalHold)
    );
    assert_eq!(
        worker.mark_disposed(ItemId(17)),
        Err(RetentionError::LegalHold)
    );
    assert_eq!(worker.state(ItemId(17)), Ok(RetentionState::Pending));
}

#[test]
fn case_cannot_be_tombstoned_before_its_due_day() {
    let mut worker = RetentionWorker::new(vec![RetentionItem::new(ItemId(18), 100, false)]);
    assert_eq!(
        worker.mark_tombstoned(ItemId(18), 99),
        Err(RetentionError::NotDue)
    );
    assert_eq!(worker.state(ItemId(18)), Ok(RetentionState::Pending));
    assert_eq!(worker.mark_tombstoned(ItemId(18), 100), Ok(()));
    assert_eq!(worker.state(ItemId(18)), Ok(RetentionState::Tombstoned));
}
