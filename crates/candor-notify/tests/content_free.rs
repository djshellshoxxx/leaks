// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_notify::{DeliveryMode, Notification, NotificationError, Subscription};

#[test]
fn st_rm3_notification_is_constant_and_content_free() {
    let sub = Subscription::new(17, true, DeliveryMode::DailyConstant);
    let with_pending = Notification::for_daily_slot(&sub, "Candor North", true);
    let without_pending = Notification::for_daily_slot(&sub, "Candor North", false);

    assert_eq!(with_pending, without_pending);
    assert_eq!(
        with_pending,
        Ok(Some(Notification::T1 {
            recipient_ref: 17,
            instance_label: "Candor North".to_owned(),
        }))
    );
}

#[test]
fn st_rm3_off_mode_never_emits_external_notification() {
    let sub = Subscription::new(17, true, DeliveryMode::Off);
    assert_eq!(Notification::for_daily_slot(&sub, "Candor", true), Ok(None));
}

#[test]
fn st_rm3_unsubscribed_staff_are_not_sent_notifications() {
    let sub = Subscription::new(17, false, DeliveryMode::DailyConstant);
    assert_eq!(Notification::for_daily_slot(&sub, "Candor", true), Ok(None));
}

#[test]
fn st_rm3_instance_label_is_bounded_and_cannot_carry_case_context() {
    let sub = Subscription::new(17, true, DeliveryMode::DailyConstant);
    assert_eq!(
        Notification::for_daily_slot(&sub, "abcdefghijklmnopqrstuvwxyz1234567", false),
        Err(NotificationError::InstanceLabelTooLong)
    );
}

#[test]
fn st_rm3_only_t1_body_is_rendered() {
    let notification = Notification::T1 {
        recipient_ref: 17,
        instance_label: "Candor".to_owned(),
    };
    assert_eq!(
        notification.render_body(),
        "Candor: secure case-management action requires attention\nCandor"
    );
}
