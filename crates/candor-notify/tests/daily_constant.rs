// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_notify::{DailyT1, DeliveryMode, NotificationError, Subscription};

#[test]
fn st_rm3_daily_constant_is_independent_of_pending_work() {
    let subscription = Subscription::new(17, true, DeliveryMode::DailyConstant);
    let with_pending = DailyT1::for_slot(&subscription, "Candor North", true);
    let without_pending = DailyT1::for_slot(&subscription, "Candor North", false);
    assert_eq!(with_pending, without_pending);
    assert_eq!(
        with_pending,
        Ok(Some(DailyT1::new(17, "Candor North").unwrap()))
    );
}

#[test]
fn st_rm3_off_or_unsubscribed_never_emits_external_message() {
    let off = Subscription::new(17, true, DeliveryMode::Off);
    assert_eq!(DailyT1::for_slot(&off, "Candor", true), Ok(None));

    let unsubscribed = Subscription::new(17, false, DeliveryMode::DailyConstant);
    assert_eq!(DailyT1::for_slot(&unsubscribed, "Candor", true), Ok(None));
}

#[test]
fn st_rm3_t1_body_is_fixed_and_instance_label_is_bounded() {
    let notification = DailyT1::new(17, "Candor").unwrap();
    assert_eq!(
        notification.render_body(),
        "Candor: secure case-management action requires attention\nCandor"
    );
    assert_eq!(
        DailyT1::new(17, "abcdefghijklmnopqrstuvwxyz1234567"),
        Err(NotificationError::InstanceLabelTooLong)
    );
}
