// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Handles, and why a use after free stops here.
//!
//! A handle is not an address. An address that has been freed is an address
//! the allocator hands out again, so a stale pointer arriving from C either
//! names somebody else's object or is dereferenced into whatever is there now,
//! and neither can be told apart from a live one. A handle here is an index
//! into a table together with the generation of the slot it names, and the
//! generation moves every time the slot is freed: a handle that names a slot
//! whose generation has moved on is stale, and stale is an error code.
//!
//! Nothing in a handle is ever dereferenced, so a value invented by the caller
//! is a wrong answer rather than a crash.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::abi::{alias, constants};
use crate::status::SipralStatus;

alias! {
    /// An opaque reference to something this library owns.
    ///
    /// It is a number, not a pointer: nothing is to be read from it, and
    /// nothing but this library can make one. Zero is never a live handle,
    /// which is what a caller can zero a variable to.
    pub type SipralHandle = u64;
}

constants! {
    /// The value no live handle ever takes.
    pub const SIPRAL_HANDLE_NONE: SipralHandle = 0;
}

/// The generation a slot starts at. Zero is kept out of use so that a handle
/// of zero, and any handle whose top half a caller left empty, is refused
/// before a slot is ever looked at.
pub(crate) const FIRST_GENERATION: u32 = 1;

const INDEX_MASK: u64 = 0xFFFF_FFFF;

/// One thing the library owns, and how many times its slot has been reused.
struct Slot<T> {
    generation: u32,
    value: Option<Arc<T>>,
}

struct Inner<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

/// The objects of one kind that this library has handed out handles to.
pub(crate) struct HandleTable<T> {
    inner: Mutex<Inner<T>>,
}

impl<T> HandleTable<T> {
    pub(crate) const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                slots: Vec::new(),
                free: Vec::new(),
            }),
        }
    }

    /// Take ownership of `value` and name it.
    pub(crate) fn insert(&self, value: T) -> Result<SipralHandle, SipralStatus> {
        let value = Arc::new(value);
        let mut inner = self.lock();
        if let Some(index) = inner.free.pop() {
            let Some(slot) = inner.slots.get_mut(index as usize) else {
                return Err(SipralStatus::Exhausted);
            };
            let generation = slot.generation;
            slot.value = Some(value);
            return Ok(join(index, generation));
        }
        let Ok(index) = u32::try_from(inner.slots.len()) else {
            return Err(SipralStatus::Exhausted);
        };
        // u32::MAX is what a handle that cannot be decoded turns into, so no
        // real slot is allowed to sit there
        if index == u32::MAX {
            return Err(SipralStatus::Exhausted);
        }
        inner.slots.push(Slot {
            generation: FIRST_GENERATION,
            value: Some(value),
        });
        Ok(join(index, FIRST_GENERATION))
    }

    /// What the handle names, if it still names anything.
    ///
    /// The caller gets a share of the object rather than a borrow of the
    /// table, so a call that runs for a while — a poll that dispatches into
    /// the caller's own callback — does not hold the table shut behind it, and
    /// a free that arrives during that call takes effect at the end of it.
    pub(crate) fn get(&self, handle: SipralHandle) -> Result<Arc<T>, SipralStatus> {
        let (index, generation) = split(handle)?;
        let inner = self.lock();
        let Some(slot) = inner.slots.get(index as usize) else {
            return Err(SipralStatus::InvalidHandle);
        };
        if slot.generation != generation {
            return Err(SipralStatus::StaleHandle);
        }
        match slot.value.as_ref() {
            Some(value) => Ok(Arc::clone(value)),
            None => Err(SipralStatus::StaleHandle),
        }
    }

    /// Retire the handle and give back what it named.
    ///
    /// The object itself goes when the last share of it does, which may be
    /// after this returns.
    pub(crate) fn remove(&self, handle: SipralHandle) -> Result<Arc<T>, SipralStatus> {
        let (index, generation) = split(handle)?;
        let mut inner = self.lock();
        let (value, reusable) = {
            let Some(slot) = inner.slots.get_mut(index as usize) else {
                return Err(SipralStatus::InvalidHandle);
            };
            if slot.generation != generation {
                return Err(SipralStatus::StaleHandle);
            }
            let Some(value) = slot.value.take() else {
                return Err(SipralStatus::StaleHandle);
            };
            match slot.generation.checked_add(1) {
                Some(next) => {
                    slot.generation = next;
                    (value, true)
                }
                // the generation has run out, and one that wrapped would make
                // an old handle look live again; the slot is spent
                None => (value, false),
            }
        };
        if reusable {
            inner.free.push(index);
        }
        Ok(value)
    }

    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        // poisoning means a panic was caught while this was held, and what is
        // held here is two vectors that are whole between statements
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub(crate) fn join(index: u32, generation: u32) -> SipralHandle {
    (u64::from(generation) << 32) | u64::from(index)
}

pub(crate) fn split(handle: SipralHandle) -> Result<(u32, u32), SipralStatus> {
    // both halves are thirty-two bits wide by construction, so neither
    // conversion can fail; u32::MAX stands in for the impossible, and no slot
    // is ever put there
    let index = u32::try_from(handle & INDEX_MASK).unwrap_or(u32::MAX);
    let generation = u32::try_from(handle >> 32).unwrap_or(u32::MAX);
    if generation < FIRST_GENERATION {
        return Err(SipralStatus::InvalidHandle);
    }
    Ok((index, generation))
}

#[cfg(test)]
impl<T> HandleTable<T> {
    /// The generation a slot is on, for the tests that have to reach one.
    fn generation_of(&self, index: u32) -> Option<u32> {
        self.lock()
            .slots
            .get(index as usize)
            .map(|slot| slot.generation)
    }

    /// Move a slot to a chosen generation. Only a test needs this: it is how
    /// the last generation a slot can have is reached without freeing it four
    /// billion times.
    fn force_generation(&self, index: u32, generation: u32) {
        let mut inner = self.lock();
        if let Some(slot) = inner.slots.get_mut(index as usize) {
            slot.generation = generation;
        }
    }

    fn slot_count(&self) -> usize {
        self.lock().slots.len()
    }

    fn free_count(&self) -> usize {
        self.lock().free.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{FIRST_GENERATION, HandleTable, SIPRAL_HANDLE_NONE, join};
    use crate::status::SipralStatus;
    use std::sync::Arc;

    fn table() -> HandleTable<u32> {
        HandleTable::new()
    }

    #[test]
    fn a_handle_names_what_was_put_in() {
        let table = table();
        let handle = table.insert(41).expect("room for one");
        assert_eq!(*table.get(handle).expect("still there"), 41);
    }

    #[test]
    fn no_handle_is_ever_zero() {
        let table = table();
        let handle = table.insert(1).expect("room for one");
        assert_ne!(handle, SIPRAL_HANDLE_NONE);
    }

    #[test]
    fn zero_is_not_a_handle_from_this_library() {
        let table = table();
        table.insert(1).expect("room for one");
        assert_eq!(
            table.get(SIPRAL_HANDLE_NONE).err(),
            Some(SipralStatus::InvalidHandle)
        );
        assert_eq!(
            table.remove(SIPRAL_HANDLE_NONE).err(),
            Some(SipralStatus::InvalidHandle)
        );
    }

    #[test]
    fn a_handle_with_no_generation_is_refused_before_a_slot_is_looked_at() {
        let table = table();
        table.insert(1).expect("room for one");
        assert_eq!(table.get(0).err(), Some(SipralStatus::InvalidHandle));
    }

    #[test]
    fn an_index_that_was_never_allocated_is_not_a_handle() {
        let table = table();
        table.insert(1).expect("room for one");
        let invented = join(7, FIRST_GENERATION);
        assert_eq!(table.get(invented).err(), Some(SipralStatus::InvalidHandle));
    }

    #[test]
    fn using_a_handle_after_it_was_freed_is_an_error_and_not_a_read() {
        let table = table();
        let handle = table.insert(5).expect("room for one");
        table.remove(handle).expect("the first free works");
        assert_eq!(table.get(handle).err(), Some(SipralStatus::StaleHandle));
    }

    #[test]
    fn a_second_free_is_an_error_code() {
        let table = table();
        let handle = table.insert(5).expect("room for one");
        table.remove(handle).expect("the first free works");
        assert_eq!(table.remove(handle).err(), Some(SipralStatus::StaleHandle));
        assert_eq!(table.remove(handle).err(), Some(SipralStatus::StaleHandle));
    }

    #[test]
    fn a_reused_slot_answers_to_a_different_handle() {
        let table = table();
        let first = table.insert(1).expect("room for one");
        table.remove(first).expect("freed");
        let second = table.insert(2).expect("the slot comes back");
        assert_eq!(table.slot_count(), 1, "the slot was reused, not added to");
        assert_ne!(first, second);
        assert_eq!(table.get(first).err(), Some(SipralStatus::StaleHandle));
        assert_eq!(*table.get(second).expect("live"), 2);
    }

    #[test]
    fn a_handle_from_one_slot_does_not_open_another() {
        let table = table();
        let first = table.insert(1).expect("room");
        let second = table.insert(2).expect("room");
        assert_ne!(first, second);
        assert_eq!(*table.get(first).expect("live"), 1);
        assert_eq!(*table.get(second).expect("live"), 2);
    }

    #[test]
    fn a_generation_that_cannot_move_retires_the_slot() {
        let table = table();
        let handle = table.insert(1).expect("room");
        table.force_generation(0, u32::MAX);
        let last = join(0, u32::MAX);
        table.remove(last).expect("the last generation still frees");
        assert_eq!(table.free_count(), 0, "a spent slot is not offered again");
        let next = table.insert(2).expect("room");
        assert_eq!(table.slot_count(), 2);
        assert_eq!(table.get(last).err(), Some(SipralStatus::StaleHandle));
        assert_eq!(table.get(handle).err(), Some(SipralStatus::StaleHandle));
        assert_eq!(*table.get(next).expect("live"), 2);
    }

    #[test]
    fn the_generation_moves_on_every_free() {
        let table = table();
        for round in 0..5_u32 {
            let handle = table.insert(round).expect("room");
            assert_eq!(table.generation_of(0), Some(FIRST_GENERATION + round));
            table.remove(handle).expect("freed");
        }
        assert_eq!(table.generation_of(0), Some(FIRST_GENERATION + 5));
    }

    #[test]
    fn what_is_taken_out_survives_a_reader_that_is_still_holding_it() {
        let table = table();
        let handle = table.insert(9).expect("room");
        let held = table.get(handle).expect("live");
        let removed = table.remove(handle).expect("freed");
        assert_eq!(Arc::strong_count(&held), 2);
        assert_eq!(*held, 9);
        drop(removed);
        assert_eq!(*held, 9);
    }

    #[test]
    fn two_threads_can_hold_handles_from_the_same_table() {
        static TABLE: HandleTable<u32> = HandleTable::new();
        let first = TABLE.insert(1).expect("room");
        let worker = std::thread::spawn(|| {
            let second = TABLE.insert(2).expect("room");
            assert_eq!(*TABLE.get(second).expect("live"), 2);
            second
        })
        .join()
        .expect("the thread finished");
        assert_ne!(first, worker);
        assert_eq!(*TABLE.get(first).expect("live"), 1);
        TABLE.remove(first).expect("freed");
        TABLE.remove(worker).expect("freed");
    }
}
