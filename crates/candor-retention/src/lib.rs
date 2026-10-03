// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ItemId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionState {
    Pending,
    Tombstoned,
    KeyDestroyed,
    Disposed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionError {
    NotFound,
    InvalidOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionItem {
    id: ItemId,
    due_day: u32,
    legal_hold: bool,
    state: RetentionState,
}

impl RetentionItem {
    #[must_use]
    pub const fn new(id: ItemId, due_day: u32, legal_hold: bool) -> Self {
        Self { id, due_day, legal_hold, state: RetentionState::Pending }
    }
}

#[derive(Debug)]
pub struct RetentionWorker {
    items: Vec<RetentionItem>,
}

impl RetentionWorker {
    #[must_use]
    pub const fn new(items: Vec<RetentionItem>) -> Self { Self { items } }

    #[must_use]
    pub fn due(&self, today: u32) -> Vec<ItemId> {
        self.items
            .iter()
            .filter(|item| !item.legal_hold && item.due_day <= today && item.state != RetentionState::Disposed)
            .map(|item| item.id)
            .collect()
    }

    pub fn state(&self, id: ItemId) -> Result<RetentionState, RetentionError> {
        self.items.iter().find(|item| item.id == id).map(|item| item.state).ok_or(RetentionError::NotFound)
    }

    pub fn mark_tombstoned(&mut self, id: ItemId) -> Result<(), RetentionError> {
        let item = self.item_mut(id)?;
        match item.state {
            RetentionState::Pending => item.state = RetentionState::Tombstoned,
            RetentionState::Tombstoned | RetentionState::KeyDestroyed | RetentionState::Disposed => {}
        }
        Ok(())
    }

    pub fn mark_key_destroyed(&mut self, id: ItemId) -> Result<(), RetentionError> {
        let item = self.item_mut(id)?;
        match item.state {
            RetentionState::Tombstoned => item.state = RetentionState::KeyDestroyed,
            RetentionState::KeyDestroyed | RetentionState::Disposed => {}
            RetentionState::Pending => return Err(RetentionError::InvalidOrder),
        }
        Ok(())
    }

    pub fn mark_disposed(&mut self, id: ItemId) -> Result<(), RetentionError> {
        let item = self.item_mut(id)?;
        match item.state {
            RetentionState::KeyDestroyed => item.state = RetentionState::Disposed,
            RetentionState::Disposed => {}
            RetentionState::Pending | RetentionState::Tombstoned => return Err(RetentionError::InvalidOrder),
        }
        Ok(())
    }

    fn item_mut(&mut self, id: ItemId) -> Result<&mut RetentionItem, RetentionError> {
        self.items.iter_mut().find(|item| item.id == id).ok_or(RetentionError::NotFound)
    }
}
