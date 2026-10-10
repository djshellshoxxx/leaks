// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Destination(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotificationKind {
    CaseActivity,
    AccountSecurity,
    SystemActionRequired,
}

/// Content-free notification descriptor. There is deliberately no free-text/body field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Notification {
    destination: Destination,
    kind: NotificationKind,
    dedup_key: u128,
}

impl Notification {
    #[must_use]
    pub const fn new(destination: Destination, kind: NotificationKind, dedup_key: u128) -> Self {
        Self {
            destination,
            kind,
            dedup_key,
        }
    }

    #[must_use]
    pub const fn destination(self) -> Destination {
        self.destination
    }

    #[must_use]
    pub const fn kind(self) -> NotificationKind {
        self.kind
    }

    #[must_use]
    pub const fn dedup_key(self) -> u128 {
        self.dedup_key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Queued {
    notification: Notification,
    failures: u8,
}

#[derive(Debug)]
pub struct NotifyQueue {
    entries: Vec<Queued>,
    max_retries: u8,
}

impl NotifyQueue {
    #[must_use]
    pub const fn new(max_retries: u8) -> Self {
        Self {
            entries: Vec::new(),
            max_retries,
        }
    }

    /// Returns false when an equivalent pending notification already exists.
    pub fn enqueue(&mut self, notification: Notification) -> bool {
        if self
            .entries
            .iter()
            .any(|entry| entry.notification == notification)
        {
            return false;
        }
        self.entries.push(Queued {
            notification,
            failures: 0,
        });
        true
    }

    /// Records a failed delivery. Returns true when another retry remains.
    pub fn record_failure(&mut self, notification: Notification) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.notification == notification)
        else {
            return false;
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return false;
        };
        let next = entry.failures.saturating_add(1);
        if next >= self.max_retries {
            self.entries.remove(index);
            return false;
        }
        entry.failures = next;
        true
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Only the two notification modes permitted by ADR-038(2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryMode {
    DailyConstant,
    Off,
}

/// Content-free subscription state. It intentionally contains no channel or case relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subscription {
    recipient_ref: u64,
    subscribed: bool,
    mode: DeliveryMode,
}

impl Subscription {
    #[must_use]
    pub const fn new(recipient_ref: u64, subscribed: bool, mode: DeliveryMode) -> Self {
        Self {
            recipient_ref,
            subscribed,
            mode,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationError {
    InstanceLabelTooLong,
}

/// The sole externally rendered message template allowed by the RM-3 backend contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DailyT1 {
    recipient_ref: u64,
    instance_label: String,
}

impl DailyT1 {
    pub fn new(recipient_ref: u64, instance_label: &str) -> Result<Self, NotificationError> {
        if instance_label.chars().count() > 32 {
            return Err(NotificationError::InstanceLabelTooLong);
        }
        Ok(Self {
            recipient_ref,
            instance_label: instance_label.to_owned(),
        })
    }

    /// Constructs the fixed daily message. `pending` is deliberately ignored so externally
    /// observable delivery is independent of case or intake activity.
    pub fn for_slot(
        subscription: &Subscription,
        instance_label: &str,
        _pending: bool,
    ) -> Result<Option<Self>, NotificationError> {
        if !subscription.subscribed || subscription.mode == DeliveryMode::Off {
            return Ok(None);
        }
        Self::new(subscription.recipient_ref, instance_label).map(Some)
    }

    #[must_use]
    pub fn render_body(&self) -> String {
        format!(
            "Candor: secure case-management action requires attention\n{}",
            self.instance_label
        )
    }

    #[must_use]
    pub const fn recipient_ref(&self) -> u64 {
        self.recipient_ref
    }
}
