// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_notify::{Destination, Notification, NotificationKind, NotifyQueue};

#[test]
fn notification_model_contains_only_closed_content_free_fields() {
    let n = Notification::new(Destination(7), NotificationKind::CaseActivity, 42);
    assert_eq!(n.destination(), Destination(7));
    assert_eq!(n.kind(), NotificationKind::CaseActivity);
    assert_eq!(n.dedup_key(), 42);
}

#[test]
fn duplicate_notifications_are_collapsed() {
    let mut q = NotifyQueue::new(3);
    let n = Notification::new(Destination(7), NotificationKind::CaseActivity, 42);
    assert_eq!(q.enqueue(n), true);
    assert_eq!(q.enqueue(n), false);
    assert_eq!(q.len(), 1);
}

#[test]
fn retry_budget_is_bounded() {
    let mut q = NotifyQueue::new(2);
    let n = Notification::new(Destination(9), NotificationKind::AccountSecurity, 88);
    assert!(q.enqueue(n));
    assert_eq!(q.record_failure(n), true);
    assert_eq!(q.record_failure(n), false);
    assert_eq!(q.len(), 0);
}
