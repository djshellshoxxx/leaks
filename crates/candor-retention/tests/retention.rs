// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_retention::{ItemId, RetentionError, RetentionItem, RetentionState, RetentionWorker};

#[test]
fn due_set_uses_day_granularity_and_excludes_legal_holds() {
    let worker = RetentionWorker::new(vec![
        RetentionItem::new(ItemId(1), 100, false),
        RetentionItem::new(ItemId(2), 100, true),
        RetentionItem::new(ItemId(3), 101, false),
    ]);
    assert_eq!(worker.due(100), vec![ItemId(1)]);
}

#[test]
fn disposal_requires_tombstone_then_key_destruction() {
    let mut worker = RetentionWorker::new(vec![RetentionItem::new(ItemId(1), 100, false)]);
    assert_eq!(worker.mark_disposed(ItemId(1)), Err(RetentionError::InvalidOrder));
    assert_eq!(worker.mark_tombstoned(ItemId(1)), Ok(()));
    assert_eq!(worker.mark_disposed(ItemId(1)), Err(RetentionError::InvalidOrder));
    assert_eq!(worker.mark_key_destroyed(ItemId(1)), Ok(()));
    assert_eq!(worker.mark_disposed(ItemId(1)), Ok(()));
    assert_eq!(worker.state(ItemId(1)), Ok(RetentionState::Disposed));
}

#[test]
fn transitions_are_idempotent_for_retry_safety() {
    let mut worker = RetentionWorker::new(vec![RetentionItem::new(ItemId(7), 100, false)]);
    assert_eq!(worker.mark_tombstoned(ItemId(7)), Ok(()));
    assert_eq!(worker.mark_tombstoned(ItemId(7)), Ok(()));
    assert_eq!(worker.mark_key_destroyed(ItemId(7)), Ok(()));
    assert_eq!(worker.mark_key_destroyed(ItemId(7)), Ok(()));
    assert_eq!(worker.mark_disposed(ItemId(7)), Ok(()));
    assert_eq!(worker.mark_disposed(ItemId(7)), Ok(()));
}
