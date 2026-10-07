// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Handles for the things inside one stack.
//!
//! The layer below's identifiers are opaque, so C gets ordinary handles (slot,
//! generation, stack tag) minted per stack. The stack tag must be checked here:
//! every stack's tables start at the same slot. No locking; the caller holds
//! the stack's lock ([`crate::stack`]).

use crate::handle::{Kind, Mint, Refused, SipralHandle, StackTag, next_generation};
use crate::status::SipralStatus;

struct Named<T> {
    generation: u32,
    value: Option<T>,
}

/// The things of one kind that one stack has handed out handles to.
pub(crate) struct Names<T> {
    mint: Mint,
    slots: Vec<Named<T>>,
    free: Vec<u32>,
}

impl<T: Copy + PartialEq> Names<T> {
    /// An empty table for the stack holding `stack`, naming things of `kind`.
    pub(crate) fn new(stack: &StackTag, kind: Kind) -> Self {
        Self {
            mint: stack.mint(kind),
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
            let handle = self.mint.join(index, slot.generation)?;
            slot.value = Some(value);
            return Ok(handle);
        }
        let Ok(index) = u32::try_from(self.slots.len()) else {
            return Err(SipralStatus::Exhausted);
        };
        let generation = self.mint.first();
        let handle = self.mint.join(index, generation)?;
        self.slots.push(Named {
            generation,
            value: Some(value),
        });
        Ok(handle)
    }

    /// What the handle names, if it still names anything.
    pub(crate) fn get(&self, handle: SipralHandle) -> Result<T, Refused> {
        let parts = self.mint.split(handle)?;
        let Some(slot) = self.slots.get(parts.index as usize) else {
            return Err(Refused::NotOurs);
        };
        if slot.generation != parts.generation {
            return Err(Refused::Gone);
        }
        slot.value.ok_or(Refused::Gone)
    }

    /// Retire a handle, so that using it again says so.
    pub(crate) fn remove(&mut self, handle: SipralHandle) -> Result<T, Refused> {
        let parts = self.mint.split(handle)?;
        let Some(slot) = self.slots.get_mut(parts.index as usize) else {
            return Err(Refused::NotOurs);
        };
        if slot.generation != parts.generation {
            return Err(Refused::Gone);
        }
        let value = slot.value.take().ok_or(Refused::Gone)?;
        // a generation that wrapped would make an old handle look live again,
        // so a slot that has run out of them is never offered back
        if let Some(next) = next_generation(slot.generation) {
            slot.generation = next;
            self.free.push(parts.index);
        }
        Ok(value)
    }

    /// The handle for something that arrived in an event (an incoming call,
    /// a fork branch), minting one if needed.
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
            return self.mint.join(index, slot.generation);
        }
        self.insert(value)
    }

    /// Retire whatever handle names `value`, e.g. a call the agent forgot.
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
        if let Some(next) = next_generation(slot.generation) {
            slot.generation = next;
            self.free.push(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Names;
    use crate::handle::{
        FIRST_GENERATION, GENERATION_LIMIT, Kind, Refused, SIPRAL_HANDLE_NONE, StackTag, StackTags,
        split,
    };

    /// One kind for all; kinds are tested in `crate::handle`.
    const KIND: Kind = Kind::Call;

    fn names(stack: &StackTag) -> Names<u32> {
        Names::new(stack, KIND)
    }

    #[test]
    fn a_handle_names_what_was_put_in() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let handle = names.insert(7).expect("room for one");
        assert_ne!(handle, SIPRAL_HANDLE_NONE);
        assert_eq!(names.get(handle), Ok(7));
    }

    #[test]
    fn zero_names_nothing() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        names.insert(7).expect("room for one");
        assert_eq!(names.get(SIPRAL_HANDLE_NONE), Err(Refused::NotOurs));
    }

    #[test]
    fn an_index_that_was_never_handed_out_is_not_a_handle() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        names.insert(7).expect("room for one");
        let invented = stack.mint(KIND).join(9, FIRST_GENERATION).expect("fits");
        assert_eq!(names.get(invented), Err(Refused::NotOurs));
    }

    #[test]
    fn a_retired_handle_is_stale_and_stays_stale() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let handle = names.insert(7).expect("room for one");
        assert_eq!(names.remove(handle), Ok(7));
        assert_eq!(names.get(handle), Err(Refused::Gone));
        assert_eq!(names.remove(handle), Err(Refused::Gone));
    }

    #[test]
    fn a_reused_slot_answers_to_a_different_handle() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let first = names.insert(1).expect("room");
        names.remove(first).expect("retired");
        let second = names.insert(2).expect("the slot comes back");
        assert_ne!(first, second);
        assert_eq!(names.get(first), Err(Refused::Gone));
        assert_eq!(names.get(second), Ok(2));
    }

    #[test]
    fn asking_for_the_name_of_something_twice_gives_the_same_handle() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let first = names.name_of(5).expect("room");
        let again = names.name_of(5).expect("already named");
        assert_eq!(first, again);
        let other = names.name_of(6).expect("room");
        assert_ne!(first, other);
    }

    #[test]
    fn what_the_layer_below_forgets_goes_stale_here_too() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let handle = names.name_of(5).expect("room");
        names.forget(5);
        assert_eq!(names.get(handle), Err(Refused::Gone));
        // and the same value coming back later is a new handle, not the old one
        let again = names.name_of(5).expect("room");
        assert_ne!(handle, again);
        assert_eq!(names.get(again), Ok(5));
    }

    #[test]
    fn forgetting_something_that_was_never_named_changes_nothing() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let handle = names.insert(1).expect("room");
        names.forget(99);
        assert_eq!(names.get(handle), Ok(1));
    }

    #[test]
    fn one_slot_does_not_answer_for_another() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        let first = names.insert(1).expect("room");
        let second = names.insert(2).expect("room");
        assert_eq!(names.get(first), Ok(1));
        assert_eq!(names.get(second), Ok(2));
        names.remove(first).expect("retired");
        assert_eq!(names.get(second), Ok(2));
    }

    #[test]
    fn every_handle_a_stack_mints_carries_its_tag() {
        static TAGS: StackTags = StackTags::new();
        let _before = TAGS.lease().expect("a tag");
        let stack = TAGS.lease().expect("a second tag");
        let mut names = names(&stack);
        let inserted = names.insert(1).expect("room");
        let looked_up = names.name_of(2).expect("room");
        for handle in [inserted, looked_up] {
            assert_eq!(split(handle).map(|parts| parts.tag), Ok(stack.tag()));
        }
    }

    #[test]
    fn a_handle_from_another_live_stack_at_the_same_slot_is_that_stacks() {
        static TAGS: StackTags = StackTags::new();
        let one = TAGS.lease().expect("a tag");
        let other = TAGS.lease().expect("a second tag");
        let mut ones = names(&one);
        let mut others = names(&other);
        let foreign = ones.insert(1).expect("room");
        let own = others.insert(2).expect("room");
        assert_eq!(
            split(foreign).map(|parts| (parts.index, parts.generation)),
            split(own).map(|parts| (parts.index, parts.generation)),
            "both stacks started at the same slot"
        );
        assert_eq!(others.get(foreign), Err(Refused::OtherStack));
        assert_eq!(others.remove(foreign), Err(Refused::OtherStack));
        assert_eq!(
            others.get(own),
            Ok(2),
            "and the slot it matched is untouched"
        );
    }

    #[test]
    fn a_handle_kept_from_a_destroyed_stack_names_nothing_on_the_stack_that_took_its_tag() {
        static TAGS: StackTags = StackTags::new();
        let gone = TAGS.lease().expect("a tag");
        let mut accounts = names(&gone);
        let mut calls = names(&gone);
        let account = accounts.insert(1).expect("room");
        let call = calls.insert(1).expect("room");
        let reused = calls.insert(2).expect("room");
        calls.remove(reused).expect("retired");
        let last = calls.insert(3).expect("the slot comes back");
        let tag = gone.tag();
        drop((accounts, calls, gone));

        let taken = TAGS.lease().expect("the tag came back");
        assert_eq!(taken.tag(), tag, "the same tag, or this proves nothing");
        let mut accounts = names(&taken);
        let mut calls = names(&taken);
        let own_account = accounts.insert(10).expect("room");
        let own_call = calls.insert(10).expect("room");
        let own_second = calls.insert(20).expect("room");
        for (kept, table) in [(account, &accounts), (call, &calls), (last, &calls)] {
            assert_eq!(table.get(kept), Err(Refused::OtherStack));
        }
        for own in [own_account, own_call, own_second] {
            assert!(
                ![account, call, reused, last].contains(&own),
                "a handle the new stack minted is one the old one already handed out"
            );
        }
        assert_eq!(accounts.get(own_account), Ok(10));
        assert_eq!(calls.get(own_call), Ok(10));
    }

    /// A slot at its last generation is retired, not freed, by both `remove`
    /// and `forget`; otherwise the next insert would be refused as full.
    #[test]
    fn a_slot_whose_generation_cannot_move_on_is_retired_and_not_offered_again() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("a tag");
        let mut names = names(&stack);
        names.insert(1).expect("room");
        names.insert(2).expect("room");
        let last = GENERATION_LIMIT - 1;
        for slot in &mut names.slots {
            slot.generation = last;
        }
        let spent = stack.mint(KIND).join(0, last).expect("the last one fits");
        assert_eq!(names.remove(spent), Ok(1));
        names.forget(2);
        assert!(
            names.free.is_empty(),
            "a slot with no generation left was offered again"
        );
        let next = names
            .insert(3)
            .expect("a fresh slot, not a refusal for want of room");
        assert_eq!(split(next).map(|parts| parts.index), Ok(2));
        assert_eq!(names.get(spent), Err(Refused::Gone));
    }
}
