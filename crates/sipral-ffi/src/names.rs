// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Handles for the things inside one stack.
//!
//! Accounts and calls are named by the layer below with identifiers whose
//! insides it keeps to itself, so they cannot be handed to C as they are. What
//! crosses instead is a handle of the same shape as every other handle here —
//! an index and a generation, zero never live, a freed one stale — minted per
//! stack rather than per process, because an account only means anything
//! inside the user agent that holds it.
//!
//! Nothing locks. The stack's own lock is already held by whoever is looking,
//! which is the arrangement [`crate::stack`] describes.

use crate::handle::{FIRST_GENERATION, SipralHandle, join, split};
use crate::status::SipralStatus;

struct Named<T> {
    generation: u32,
    value: Option<T>,
}

/// The things of one kind that one stack has handed out handles to.
pub(crate) struct Names<T> {
    slots: Vec<Named<T>>,
    free: Vec<u32>,
}

impl<T: Copy + PartialEq> Names<T> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Name something the layer below made.
    pub(crate) fn insert(&mut self, value: T) -> Result<SipralHandle, SipralStatus> {
        if let Some(index) = self.free.pop() {
            let Some(slot) = self.slots.get_mut(index as usize) else {
                return Err(SipralStatus::Exhausted);
            };
            let generation = slot.generation;
            slot.value = Some(value);
            return Ok(join(index, generation));
        }
        let Ok(index) = u32::try_from(self.slots.len()) else {
            return Err(SipralStatus::Exhausted);
        };
        if index == u32::MAX {
            return Err(SipralStatus::Exhausted);
        }
        self.slots.push(Named {
            generation: FIRST_GENERATION,
            value: Some(value),
        });
        Ok(join(index, FIRST_GENERATION))
    }

    /// What the handle names, if it still names anything.
    pub(crate) fn get(&self, handle: SipralHandle) -> Result<T, SipralStatus> {
        let (index, generation) = split(handle)?;
        let Some(slot) = self.slots.get(index as usize) else {
            return Err(SipralStatus::InvalidHandle);
        };
        if slot.generation != generation {
            return Err(SipralStatus::StaleHandle);
        }
        slot.value.ok_or(SipralStatus::StaleHandle)
    }

    /// Retire a handle, so that using it again says so.
    pub(crate) fn remove(&mut self, handle: SipralHandle) -> Result<T, SipralStatus> {
        let (index, generation) = split(handle)?;
        let Some(slot) = self.slots.get_mut(index as usize) else {
            return Err(SipralStatus::InvalidHandle);
        };
        if slot.generation != generation {
            return Err(SipralStatus::StaleHandle);
        }
        let value = slot.value.take().ok_or(SipralStatus::StaleHandle)?;
        // a generation that wrapped would make an old handle look live again,
        // so a slot that has run out of them is never offered back
        if let Some(next) = slot.generation.checked_add(1) {
            slot.generation = next;
            self.free.push(index);
        }
        Ok(value)
    }

    /// The handle for something the layer below named by itself.
    ///
    /// An incoming call, or a branch of a fork, appears in an event rather than
    /// as the result of a call, and the application still has to be given
    /// something to answer it with.
    pub(crate) fn name_of(&mut self, value: T) -> Result<SipralHandle, SipralStatus> {
        let found = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.value == Some(value));
        if let Some((index, slot)) = found {
            let Ok(index) = u32::try_from(index) else {
                return Err(SipralStatus::Exhausted);
            };
            return Ok(join(index, slot.generation));
        }
        self.insert(value)
    }

    /// Retire whatever handle names `value`, if one does.
    ///
    /// A call that has ended is gone from the layer below, and a handle that
    /// still answered for it would name a call the user agent has forgotten.
    pub(crate) fn forget(&mut self, value: T) {
        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.value == Some(value))
        else {
            return;
        };
        slot.value = None;
        let Ok(index) = u32::try_from(index) else {
            return;
        };
        if let Some(next) = slot.generation.checked_add(1) {
            slot.generation = next;
            self.free.push(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Names;
    use crate::handle::{SIPRAL_HANDLE_NONE, join};
    use crate::status::SipralStatus;

    fn names() -> Names<u32> {
        Names::new()
    }

    #[test]
    fn a_handle_names_what_was_put_in() {
        let mut names = names();
        let handle = names.insert(7).expect("room for one");
        assert_ne!(handle, SIPRAL_HANDLE_NONE);
        assert_eq!(names.get(handle), Ok(7));
    }

    #[test]
    fn zero_names_nothing() {
        let mut names = names();
        names.insert(7).expect("room for one");
        assert_eq!(
            names.get(SIPRAL_HANDLE_NONE),
            Err(SipralStatus::InvalidHandle)
        );
    }

    #[test]
    fn an_index_that_was_never_handed_out_is_not_a_handle() {
        let mut names = names();
        names.insert(7).expect("room for one");
        assert_eq!(names.get(join(9, 1)), Err(SipralStatus::InvalidHandle));
    }

    #[test]
    fn a_retired_handle_is_stale_and_stays_stale() {
        let mut names = names();
        let handle = names.insert(7).expect("room for one");
        assert_eq!(names.remove(handle), Ok(7));
        assert_eq!(names.get(handle), Err(SipralStatus::StaleHandle));
        assert_eq!(names.remove(handle), Err(SipralStatus::StaleHandle));
    }

    #[test]
    fn a_reused_slot_answers_to_a_different_handle() {
        let mut names = names();
        let first = names.insert(1).expect("room");
        names.remove(first).expect("retired");
        let second = names.insert(2).expect("the slot comes back");
        assert_ne!(first, second);
        assert_eq!(names.get(first), Err(SipralStatus::StaleHandle));
        assert_eq!(names.get(second), Ok(2));
    }

    #[test]
    fn asking_for_the_name_of_something_twice_gives_the_same_handle() {
        let mut names = names();
        let first = names.name_of(5).expect("room");
        let again = names.name_of(5).expect("already named");
        assert_eq!(first, again);
        let other = names.name_of(6).expect("room");
        assert_ne!(first, other);
    }

    #[test]
    fn what_the_layer_below_forgets_goes_stale_here_too() {
        let mut names = names();
        let handle = names.name_of(5).expect("room");
        names.forget(5);
        assert_eq!(names.get(handle), Err(SipralStatus::StaleHandle));
        // and the same value coming back later is a new handle, not the old one
        let again = names.name_of(5).expect("room");
        assert_ne!(handle, again);
        assert_eq!(names.get(again), Ok(5));
    }

    #[test]
    fn forgetting_something_that_was_never_named_changes_nothing() {
        let mut names = names();
        let handle = names.insert(1).expect("room");
        names.forget(99);
        assert_eq!(names.get(handle), Ok(1));
    }

    #[test]
    fn one_slot_does_not_answer_for_another() {
        let mut names = names();
        let first = names.insert(1).expect("room");
        let second = names.insert(2).expect("room");
        assert_eq!(names.get(first), Ok(1));
        assert_eq!(names.get(second), Ok(2));
        names.remove(first).expect("retired");
        assert_eq!(names.get(second), Ok(2));
    }
}
