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
        Self { destination, kind, dedup_key }
    }
    #[must_use]
    pub const fn destination(self) -> Destination { self.destination }
    #[must_use]
    pub const fn kind(self) -> NotificationKind { self.kind }
    #[must_use]
    pub const fn dedup_key(self) -> u128 { self.dedup_key }
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
        Self { entries: Vec::new(), max_retries }
    }

    /// Returns false when an equivalent pending notification already exists.
    pub fn enqueue(&mut self, notification: Notification) -> bool {
        if self.entries.iter().any(|entry| entry.notification == notification) {
            return false;
        }
        self.entries.push(Queued { notification, failures: 0 });
        true
    }

    /// Records a failed delivery. Returns true when another retry remains.
    pub fn record_failure(&mut self, notification: Notification) -> bool {
        let Some(index) = self.entries.iter().position(|entry| entry.notification == notification) else {
            return false;
        };
        let next = self.entries[index].failures.saturating_add(1);
        if next >= self.max_retries {
            self.entries.remove(index);
            return false;
        }
        self.entries[index].failures = next;
        true
    }

    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}
