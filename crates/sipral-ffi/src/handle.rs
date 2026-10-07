// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Handles, and why a use after free stops here.
//!
//! A freed address is reused by the allocator, so a stale pointer cannot be
//! told from a live one. A handle is a table index plus the generation of its
//! slot; the generation moves on every free, so a stale handle is an error
//! code. Nothing in a handle is dereferenced: an invented value is a wrong
//! answer, not a crash.
//!
//! # Layout of the 64 bits
//!
//! Bits 0-23 slot, 24-31 stack tag, 32-35 kind, 36-63 generation. Zero is
//! never a generation, so zero is never a handle, nor is a handle truncated to
//! 32 bits.
//!
//! Every stack numbers its tables from slot zero, so the tag refuses a handle
//! used on a stack that did not mint it. Within one stack, the first stack,
//! account and call are all tag 0, slot 0, generation 1; the kind refuses a
//! handle of the wrong table (otherwise `sipral_call_hangup(stack, stack, now)`
//! would hit slot zero and answer OK).
//!
//! 28 generation bits last about 310 days at ten calls a second through one
//! slot. A slot that runs out is retired, not wrapped (`next_generation`), so
//! the limit never costs correctness. 24 slot bits allow 16 million live
//! objects per stack; 8 tag bits allow 256 live stacks.
//!
//! # Tag reuse
//!
//! A stack takes the lowest free tag and gives it back when its last share is
//! gone, not when destroyed: a stack destroyed from its own callback is still
//! being polled and may still mint.
//!
//! A returned tag remembers the highest generation its stack minted, and the
//! next holder starts above it, so old handles are refused like any other
//! stack's. A tag with no generations left is never offered again. The 257th
//! live stack is refused with `SIPRAL_STATUS_EXHAUSTED`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::abi::{alias, constants};
use crate::status::SipralStatus;

alias! {
    /// An opaque reference to something this library owns.
    ///
    /// A number, not a pointer: nothing is read from it, and only this
    /// library makes one. Zero is never a live handle.
    ///
    /// An account or call handle is valid only on the stack that minted it;
    /// on any other stack it is `SIPRAL_STATUS_INVALID_HANDLE`.
    pub type SipralHandle = u64;
}

constants! {
    /// The value no live handle ever takes.
    pub const SIPRAL_HANDLE_NONE: SipralHandle = 0;
}

/// The generation a slot starts at on a fresh tag. Zero is never used, so a
/// zero handle or one with an empty top half is refused early.
pub(crate) const FIRST_GENERATION: u32 = 1;

/// How many stacks can be alive at once (one per tag value).
pub(crate) const STACK_TAGS: usize = 256;

const INDEX_BITS: u32 = 24;
const TAG_SHIFT: u32 = INDEX_BITS;
const KIND_SHIFT: u32 = TAG_SHIFT + 8;
const KIND_BITS: u32 = 4;
const GENERATION_SHIFT: u32 = KIND_SHIFT + KIND_BITS;
const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;
const TAG_MASK: u64 = 0xFF;
const KIND_MASK: u64 = (1 << KIND_BITS) - 1;

/// One past the last slot a handle has room to name.
pub(crate) const INDEX_LIMIT: u32 = 1 << INDEX_BITS;

/// One past the last generation a handle can hold; more would spill into
/// the [`Kind`] bits, so `join` refuses it.
pub(crate) const GENERATION_LIMIT: u32 = 1 << (32 - KIND_BITS);

/// What sort of thing a handle names.
///
/// Carried in the handle because every table starts at the same first slot,
/// and a handle of the wrong table must be refused before a slot is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `sipral_stack_create`'s handle.
    Stack,
    /// `sipral_account_add`'s.
    Account,
    /// `sipral_call_place`'s and every other call handle.
    Call,
    /// `sipral_call_media`'s.
    Media,
    /// `sipral_account_subscribe`'s.
    Subscription,
    /// `sipral_account_announce`'s.
    Announcement,
    /// The dialog a `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` names, answered by
    /// `sipral_stack_resolved`. The only kind the library mints unasked.
    Dialog,
    /// `sipral_account_message`'s.
    Message,
    /// `sipral_local_conference_create`'s.
    Conference,
}

impl Kind {
    const fn bits(self) -> u8 {
        match self {
            Self::Stack => 0,
            Self::Account => 1,
            Self::Call => 2,
            Self::Media => 3,
            Self::Subscription => 4,
            Self::Announcement => 5,
            Self::Dialog => 6,
            Self::Message => 7,
            Self::Conference => 8,
        }
    }

    /// The kind these four bits name, or none for an unused pattern.
    const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Stack),
            1 => Some(Self::Account),
            2 => Some(Self::Call),
            3 => Some(Self::Media),
            4 => Some(Self::Subscription),
            5 => Some(Self::Announcement),
            6 => Some(Self::Dialog),
            7 => Some(Self::Message),
            8 => Some(Self::Conference),
            _ => None,
        }
    }

    /// The noun used in the error text for a wrong-kind handle.
    pub(crate) const fn noun(self) -> &'static str {
        match self {
            Self::Stack => "a stack",
            Self::Account => "an account",
            Self::Call => "a call",
            Self::Media => "a call's media",
            Self::Subscription => "a subscription",
            Self::Announcement => "an announced call",
            Self::Dialog => "a dialog waiting to be resolved",
            Self::Message => "a message send",
            Self::Conference => "a local conference",
        }
    }
}

/// Why a handle names nothing where it was used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Not minted here: zero, no generation, or a slot never handed out.
    NotOurs,
    /// Minted by another stack, alive or destroyed before this one took
    /// the tag.
    OtherStack,
    /// A handle of this [`Kind`] where another was expected.
    WrongKind(Kind),
    /// Minted here, and what it named is gone.
    Gone,
}

impl Refused {
    /// The code C switches on.
    pub(crate) const fn status(self) -> SipralStatus {
        match self {
            Self::NotOurs | Self::OtherStack | Self::WrongKind(_) => SipralStatus::InvalidHandle,
            Self::Gone => SipralStatus::StaleHandle,
        }
    }
}

/// A handle taken apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Parts {
    pub(crate) tag: u8,
    pub(crate) index: u32,
    pub(crate) generation: u32,
    pub(crate) kind: Kind,
}

/// The next generation, or none if the slot has used them all.
///
/// The slot is then retired: wrapping to zero would make zero live, and
/// wrapping to one would revive the slot's first handle.
pub(crate) const fn next_generation(generation: u32) -> Option<u32> {
    match generation.checked_add(1) {
        Some(next) if next < GENERATION_LIMIT => Some(next),
        _ => None,
    }
}

/// Build a handle, refusing a slot or generation that would spill into the
/// field above. Every handle is made here.
pub(crate) fn join(
    tag: u8,
    index: u32,
    generation: u32,
    kind: Kind,
) -> Result<SipralHandle, SipralStatus> {
    if index >= INDEX_LIMIT || generation >= GENERATION_LIMIT {
        return Err(SipralStatus::Exhausted);
    }
    Ok((u64::from(generation) << GENERATION_SHIFT)
        | (u64::from(kind.bits()) << KIND_SHIFT)
        | (u64::from(tag) << TAG_SHIFT)
        | u64::from(index))
}

/// Take a handle apart, refusing one with no generation or an unknown kind.
pub(crate) fn split(handle: SipralHandle) -> Result<Parts, Refused> {
    // fields are masked first, so these cannot fail; if they did, the value
    // is treated as not ours
    let (Ok(generation), Ok(kind_bits), Ok(tag), Ok(index)) = (
        u32::try_from(handle >> GENERATION_SHIFT),
        u8::try_from((handle >> KIND_SHIFT) & KIND_MASK),
        u8::try_from((handle >> TAG_SHIFT) & TAG_MASK),
        u32::try_from(handle & INDEX_MASK),
    ) else {
        return Err(Refused::NotOurs);
    };
    if generation < FIRST_GENERATION {
        return Err(Refused::NotOurs);
    }
    let Some(kind) = Kind::from_bits(kind_bits) else {
        return Err(Refused::NotOurs);
    };
    Ok(Parts {
        tag,
        index,
        generation,
        kind,
    })
}

/// What one table of one stack mints with: its [`Kind`] and a share of the
/// stack's tag lease.
///
/// The tag returns to [`StackTags`] only when the last share goes, so a mint
/// that outlives its [`StackTag`] keeps the tag from another stack while it
/// can still mint. All tables of a stack share the lease's high mark.
pub(crate) struct Mint {
    kind: Kind,
    lease: Arc<Lease>,
}

impl Mint {
    /// The generation a new slot starts at.
    pub(crate) fn first(&self) -> u32 {
        self.lease.first
    }

    /// A handle for a slot of this stack's, remembered as minted.
    pub(crate) fn join(&self, index: u32, generation: u32) -> Result<SipralHandle, SipralStatus> {
        let handle = join(self.lease.tag, index, generation, self.kind)?;
        // tables are behind the stack's lock, so this is never raced; the
        // atomic only lets tables and tag share it
        self.lease.highest.fetch_max(generation, Ordering::Relaxed);
        Ok(handle)
    }

    /// Take a handle apart, refusing one this table or stack cannot have
    /// minted.
    ///
    /// Kind first. Another tag, or this tag below `first`, is another stack's
    /// handle (a live one, or the tag's previous holder).
    pub(crate) fn split(&self, handle: SipralHandle) -> Result<Parts, Refused> {
        let parts = split(handle)?;
        if parts.kind != self.kind {
            return Err(Refused::WrongKind(parts.kind));
        }
        if parts.tag != self.lease.tag || parts.generation < self.lease.first {
            return Err(Refused::OtherStack);
        }
        Ok(parts)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// Nobody has it, and the next stack to take it starts here.
    Free {
        first: u32,
    },
    Leased,
    /// Generations used up; reusing it could match a stale handle.
    Spent,
}

/// The tags a process hands to its stacks.
pub(crate) struct StackTags {
    held: Mutex<[Held; STACK_TAGS]>,
}

impl StackTags {
    pub(crate) const fn new() -> Self {
        Self {
            held: Mutex::new(
                [Held::Free {
                    first: FIRST_GENERATION,
                }; STACK_TAGS],
            ),
        }
    }

    /// Take the lowest free tag, or say there is none.
    pub(crate) fn lease(&'static self) -> Result<StackTag, SipralStatus> {
        let mut held = self.lock();
        let found = held.iter_mut().enumerate().find_map(|(index, state)| {
            let Held::Free { first } = *state else {
                return None;
            };
            let tag = u8::try_from(index).ok()?;
            *state = Held::Leased;
            Some((tag, first))
        });
        let Some((tag, first)) = found else {
            return Err(SipralStatus::Exhausted);
        };
        Ok(StackTag {
            lease: Arc::new(Lease {
                tags: self,
                tag,
                first,
                highest: AtomicU32::new(first.saturating_sub(1)),
            }),
        })
    }

    fn give_back(&self, tag: u8, next: Option<u32>) {
        if let Some(state) = self.lock().get_mut(usize::from(tag)) {
            *state = next.map_or(Held::Spent, |first| Held::Free { first });
        }
    }

    fn lock(&self) -> MutexGuard<'_, [Held; STACK_TAGS]> {
        // a caught panic poisons it; the array is whole between statements
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One stack's hold on its tag: the tag, the first generation, and the
/// highest generation minted. Shared by the [`StackTag`] and every [`Mint`];
/// the tag is given back when the last goes.
struct Lease {
    tags: &'static StackTags,
    tag: u8,
    first: u32,
    highest: AtomicU32,
}

impl Drop for Lease {
    /// Give the tag back, carrying past everything this stack minted.
    fn drop(&mut self) {
        let next = next_generation(self.highest.load(Ordering::Relaxed));
        self.tags.give_back(self.tag, next);
    }
}

/// One stack's tag, held for as long as the stack is.
pub(crate) struct StackTag {
    lease: Arc<Lease>,
}

impl StackTag {
    /// The byte every handle this stack mints carries.
    pub(crate) fn tag(&self) -> u8 {
        self.lease.tag
    }

    /// A mint for one [`Kind`] of thing this stack names.
    ///
    /// It holds a share of the lease, so the tag stays reserved while it lives.
    pub(crate) fn mint(&self, kind: Kind) -> Mint {
        Mint {
            kind,
            lease: Arc::clone(&self.lease),
        }
    }
}

/// One thing the library owns, and how many times its slot has been reused.
struct Slot<T> {
    generation: u32,
    tag: u8,
    value: Option<Arc<T>>,
}

impl<T> Slot<T> {
    /// Whether a handle taken apart names this slot as it is now.
    fn answers(&self, parts: Parts) -> Result<(), Refused> {
        if self.generation != parts.generation {
            return Err(Refused::Gone);
        }
        // a generation is minted once with one tag, so a mismatch was never ours
        if self.tag != parts.tag {
            return Err(Refused::NotOurs);
        }
        Ok(())
    }
}

struct Inner<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

/// The objects of one kind handed out, across every stack.
///
/// Generations never restart, so a reused tag cannot revive an old handle.
/// The tag is kept per slot to catch an altered handle. The [`Kind`] belongs
/// to the table and is checked before any slot is read.
pub(crate) struct HandleTable<T> {
    kind: Kind,
    inner: Mutex<Inner<T>>,
}

impl<T> HandleTable<T> {
    pub(crate) const fn new(kind: Kind) -> Self {
        Self {
            kind,
            inner: Mutex::new(Inner {
                slots: Vec::new(),
                free: Vec::new(),
            }),
        }
    }

    /// Take ownership of `value` and name it, as belonging to the stack
    /// tagged `tag`.
    pub(crate) fn insert(&self, tag: u8, value: T) -> Result<SipralHandle, SipralStatus> {
        let value = Arc::new(value);
        let mut inner = self.lock();
        if let Some(index) = inner.free.pop() {
            let Some(slot) = inner.slots.get_mut(index as usize) else {
                return Err(SipralStatus::Exhausted);
            };
            let handle = join(tag, index, slot.generation, self.kind)?;
            slot.tag = tag;
            slot.value = Some(value);
            return Ok(handle);
        }
        let Ok(index) = u32::try_from(inner.slots.len()) else {
            return Err(SipralStatus::Exhausted);
        };
        let handle = join(tag, index, FIRST_GENERATION, self.kind)?;
        inner.slots.push(Slot {
            generation: FIRST_GENERATION,
            tag,
            value: Some(value),
        });
        Ok(handle)
    }

    /// What the handle names, if it still names anything.
    ///
    ///
    /// Returns a share, not a borrow, so a long call (a poll running the
    /// caller's callback) does not hold the table locked; a free during it
    /// takes effect when it ends.
    pub(crate) fn get(&self, handle: SipralHandle) -> Result<Arc<T>, Refused> {
        let parts = split(handle)?;
        if parts.kind != self.kind {
            return Err(Refused::WrongKind(parts.kind));
        }
        let inner = self.lock();
        let Some(slot) = inner.slots.get(parts.index as usize) else {
            return Err(Refused::NotOurs);
        };
        slot.answers(parts)?;
        match slot.value.as_ref() {
            Some(value) => Ok(Arc::clone(value)),
            None => Err(Refused::Gone),
        }
    }

    /// Retire the handle and give back what it named.
    ///
    /// The object is dropped with its last share, maybe after this returns.
    pub(crate) fn remove(&self, handle: SipralHandle) -> Result<Arc<T>, Refused> {
        let parts = split(handle)?;
        if parts.kind != self.kind {
            return Err(Refused::WrongKind(parts.kind));
        }
        let mut inner = self.lock();
        let (value, reusable) = {
            let Some(slot) = inner.slots.get_mut(parts.index as usize) else {
                return Err(Refused::NotOurs);
            };
            slot.answers(parts)?;
            let Some(value) = slot.value.take() else {
                return Err(Refused::Gone);
            };
            match next_generation(slot.generation) {
                Some(next) => {
                    slot.generation = next;
                    (value, true)
                }
                // out of generations: retire the slot rather than wrap
                None => (value, false),
            }
        };
        if reusable {
            inner.free.push(parts.index);
        }
        Ok(value)
    }

    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        // a caught panic poisons it; the vectors are whole between statements
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
impl<T> HandleTable<T> {
    /// A slot's generation, for tests.
    fn generation_of(&self, index: u32) -> Option<u32> {
        self.lock()
            .slots
            .get(index as usize)
            .map(|slot| slot.generation)
    }

    /// Set a slot's generation, to reach the last one without that many frees.
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
impl StackTag {
    /// Record `generation` as minted without minting it.
    pub(crate) fn force_highest(&self, generation: u32) {
        self.lease.highest.store(generation, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FIRST_GENERATION, GENERATION_LIMIT, HandleTable, INDEX_LIMIT, Kind, Parts, Refused,
        SIPRAL_HANDLE_NONE, STACK_TAGS, StackTags, join, split,
    };
    use crate::status::SipralStatus;
    use std::sync::Arc;

    /// The kind generic tests mint.
    const KIND: Kind = Kind::Call;

    fn table() -> HandleTable<u32> {
        HandleTable::new(KIND)
    }

    #[test]
    fn a_handle_names_what_was_put_in() {
        let table = table();
        let handle = table.insert(0, 41).expect("room for one");
        assert_eq!(*table.get(handle).expect("still there"), 41);
    }

    #[test]
    fn no_handle_is_ever_zero() {
        let table = table();
        let handle = table.insert(0, 1).expect("room for one");
        assert_ne!(handle, SIPRAL_HANDLE_NONE);
    }

    #[test]
    fn zero_is_not_a_handle_from_this_library() {
        let table = table();
        table.insert(0, 1).expect("room for one");
        assert_eq!(table.get(SIPRAL_HANDLE_NONE).err(), Some(Refused::NotOurs));
        assert_eq!(
            table.remove(SIPRAL_HANDLE_NONE).err(),
            Some(Refused::NotOurs)
        );
    }

    #[test]
    fn a_handle_with_no_generation_is_refused_before_a_slot_is_looked_at() {
        let table = table();
        table.insert(0, 1).expect("room for one");
        assert_eq!(table.get(0).err(), Some(Refused::NotOurs));
    }

    #[test]
    fn a_handle_that_lost_its_top_half_is_refused_whatever_the_bottom_half_says() {
        let table = table();
        // the first slot would survive truncation under a low-half generation
        // layout; the second has a non-zero low half
        let first = table.insert(0, 1).expect("room");
        let elsewhere = table.insert(3, 2).expect("room");
        for handle in [first, elsewhere] {
            assert_eq!(
                table.get(handle & 0xFFFF_FFFF).err(),
                Some(Refused::NotOurs),
                "{handle:#018x} cut to 32 bits was taken"
            );
        }
    }

    #[test]
    fn the_four_parts_come_back_out_as_they_went_in() {
        let widest = join(u8::MAX, INDEX_LIMIT - 1, GENERATION_LIMIT - 1, Kind::Media)
            .expect("every part fits");
        assert_eq!(
            split(widest),
            Ok(Parts {
                tag: u8::MAX,
                index: INDEX_LIMIT - 1,
                generation: GENERATION_LIMIT - 1,
                kind: Kind::Media,
            })
        );
        let plain = join(1, 2, 3, Kind::Account).expect("every part fits");
        assert_eq!(
            split(plain),
            Ok(Parts {
                tag: 1,
                index: 2,
                generation: 3,
                kind: Kind::Account,
            })
        );
    }

    #[test]
    fn every_kind_round_trips_through_a_handle() {
        for kind in [Kind::Stack, Kind::Account, Kind::Call, Kind::Media] {
            let handle = join(0, 0, FIRST_GENERATION, kind).expect("fits");
            assert_eq!(split(handle).map(|parts| parts.kind), Ok(kind));
        }
    }

    #[test]
    fn a_slot_past_what_a_handle_can_name_is_refused_rather_than_spilled_into_the_tag() {
        assert_eq!(
            join(0, INDEX_LIMIT, FIRST_GENERATION, KIND),
            Err(SipralStatus::Exhausted)
        );
    }

    #[test]
    fn a_generation_past_what_a_handle_can_name_is_refused_rather_than_spilled_into_the_kind() {
        assert_eq!(
            join(0, 0, GENERATION_LIMIT, KIND),
            Err(SipralStatus::Exhausted),
            "this generation's bottom bit is the kind's own bit zero"
        );
        let widest = join(0, 0, GENERATION_LIMIT - 1, Kind::Stack).expect("the last one fits");
        assert_eq!(
            split(widest).map(|parts| parts.kind),
            Ok(Kind::Stack),
            "one below the limit does not touch the kind above it"
        );
    }

    #[test]
    fn an_index_that_was_never_allocated_is_not_a_handle() {
        let table = table();
        table.insert(0, 1).expect("room for one");
        let invented = join(0, 7, FIRST_GENERATION, KIND).expect("fits");
        assert_eq!(table.get(invented).err(), Some(Refused::NotOurs));
    }

    #[test]
    fn a_handle_whose_tag_was_altered_is_not_taken() {
        let table = table();
        let handle = table.insert(4, 1).expect("room for one");
        let parts = split(handle).expect("a handle");
        let altered = join(5, parts.index, parts.generation, parts.kind).expect("fits");
        assert_eq!(table.get(altered).err(), Some(Refused::NotOurs));
        assert_eq!(table.remove(altered).err(), Some(Refused::NotOurs));
        assert_eq!(*table.get(handle).expect("untouched"), 1);
    }

    #[test]
    fn a_handle_of_another_kind_is_refused_before_a_slot_is_looked_at() {
        // both tables mint tag 0, slot 0, generation 1: the collision the
        // kind bits exist to end
        let stacks: HandleTable<u32> = HandleTable::new(Kind::Stack);
        let calls: HandleTable<u32> = HandleTable::new(Kind::Call);
        let stack_handle = stacks.insert(0, 100).expect("room");
        let call_handle = calls.insert(0, 200).expect("room");
        let stack_parts = split(stack_handle).expect("a handle");
        let call_parts = split(call_handle).expect("a handle");
        assert_eq!(
            (stack_parts.tag, stack_parts.index, stack_parts.generation),
            (call_parts.tag, call_parts.index, call_parts.generation),
            "both tables started at the same slot, or this proves nothing"
        );
        assert_ne!(
            stack_handle, call_handle,
            "the kind is what tells them apart now that everything else matches"
        );

        assert_eq!(
            calls.get(stack_handle).err(),
            Some(Refused::WrongKind(Kind::Stack)),
            "a stack handle names no call, whatever slot it shares"
        );
        assert_eq!(
            stacks.get(call_handle).err(),
            Some(Refused::WrongKind(Kind::Call))
        );
        assert_eq!(*stacks.get(stack_handle).expect("its own kind"), 100);
        assert_eq!(*calls.get(call_handle).expect("its own kind"), 200);
    }

    #[test]
    fn using_a_handle_after_it_was_freed_is_an_error_and_not_a_read() {
        let table = table();
        let handle = table.insert(0, 5).expect("room for one");
        table.remove(handle).expect("the first free works");
        assert_eq!(table.get(handle).err(), Some(Refused::Gone));
    }

    #[test]
    fn a_second_free_is_an_error_code() {
        let table = table();
        let handle = table.insert(0, 5).expect("room for one");
        table.remove(handle).expect("the first free works");
        assert_eq!(table.remove(handle).err(), Some(Refused::Gone));
        assert_eq!(table.remove(handle).err(), Some(Refused::Gone));
    }

    #[test]
    fn a_reused_slot_answers_to_a_different_handle() {
        let table = table();
        let first = table.insert(0, 1).expect("room for one");
        table.remove(first).expect("freed");
        let second = table.insert(0, 2).expect("the slot comes back");
        assert_eq!(table.slot_count(), 1, "the slot was reused, not added to");
        assert_ne!(first, second);
        assert_eq!(table.get(first).err(), Some(Refused::Gone));
        assert_eq!(*table.get(second).expect("live"), 2);
    }

    #[test]
    fn a_slot_reused_under_another_tag_leaves_the_old_handle_stale() {
        let table = table();
        let first = table.insert(1, 1).expect("room for one");
        table.remove(first).expect("freed");
        let second = table.insert(2, 2).expect("the slot comes back");
        assert_eq!(table.get(first).err(), Some(Refused::Gone));
        assert_eq!(*table.get(second).expect("live"), 2);
    }

    #[test]
    fn a_handle_from_one_slot_does_not_open_another() {
        let table = table();
        let first = table.insert(0, 1).expect("room");
        let second = table.insert(0, 2).expect("room");
        assert_ne!(first, second);
        assert_eq!(*table.get(first).expect("live"), 1);
        assert_eq!(*table.get(second).expect("live"), 2);
    }

    #[test]
    fn a_generation_that_cannot_move_retires_the_slot() {
        let table = table();
        let handle = table.insert(0, 1).expect("room");
        table.force_generation(0, GENERATION_LIMIT - 1);
        let last = join(0, 0, GENERATION_LIMIT - 1, KIND).expect("fits");
        table.remove(last).expect("the last generation still frees");
        assert_eq!(table.free_count(), 0, "a spent slot is not offered again");
        let next = table.insert(0, 2).expect("room");
        assert_eq!(table.slot_count(), 2);
        assert_eq!(table.get(last).err(), Some(Refused::Gone));
        assert_eq!(table.get(handle).err(), Some(Refused::Gone));
        assert_eq!(*table.get(next).expect("live"), 2);
    }

    #[test]
    fn the_generation_moves_on_every_free() {
        let table = table();
        for round in 0..5_u32 {
            let handle = table.insert(0, round).expect("room");
            assert_eq!(table.generation_of(0), Some(FIRST_GENERATION + round));
            table.remove(handle).expect("freed");
        }
        assert_eq!(table.generation_of(0), Some(FIRST_GENERATION + 5));
    }

    #[test]
    fn what_is_taken_out_survives_a_reader_that_is_still_holding_it() {
        let table = table();
        let handle = table.insert(0, 9).expect("room");
        let held = table.get(handle).expect("live");
        let removed = table.remove(handle).expect("freed");
        assert_eq!(Arc::strong_count(&held), 2);
        assert_eq!(*held, 9);
        drop(removed);
        assert_eq!(*held, 9);
    }

    #[test]
    fn two_threads_can_hold_handles_from_the_same_table() {
        static TABLE: HandleTable<u32> = HandleTable::new(KIND);
        let first = TABLE.insert(0, 1).expect("room");
        let worker = std::thread::spawn(|| {
            let second = TABLE.insert(0, 2).expect("room");
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

    #[test]
    fn a_stack_takes_the_lowest_free_tag_and_starts_at_the_first_generation() {
        static TAGS: StackTags = StackTags::new();
        let first = TAGS.lease().expect("room");
        let second = TAGS.lease().expect("room");
        assert_eq!((first.tag(), second.tag()), (0, 1));
        assert_eq!(first.mint(KIND).first(), FIRST_GENERATION);
        drop(first);
        let again = TAGS.lease().expect("room");
        assert_eq!(again.tag(), 0, "the tag given back is the lowest free");
    }

    #[test]
    fn the_stack_after_the_last_tag_is_refused_until_one_is_given_back() {
        static TAGS: StackTags = StackTags::new();
        let mut held: Vec<_> = (0..STACK_TAGS)
            .map(|_| TAGS.lease().expect("room for every tag"))
            .collect();
        assert_eq!(held.last().map(super::StackTag::tag), Some(u8::MAX));
        assert_eq!(TAGS.lease().err(), Some(SipralStatus::Exhausted));
        let returned = held.swap_remove(100);
        drop(returned);
        let taken = TAGS.lease().expect("one came back");
        assert_eq!(taken.tag(), 100);
        assert_eq!(TAGS.lease().err(), Some(SipralStatus::Exhausted));
    }

    #[test]
    fn a_tag_given_back_starts_its_next_stack_past_everything_the_last_one_minted() {
        static TAGS: StackTags = StackTags::new();
        let before = TAGS.lease().expect("room");
        let mint = before.mint(KIND);
        let early = mint.join(0, FIRST_GENERATION).expect("fits");
        let late = mint.join(3, 41).expect("fits");
        drop((mint, before));

        let after = TAGS.lease().expect("room");
        assert_eq!(after.tag(), 0, "the same tag");
        assert_eq!(after.mint(KIND).first(), 42);
        for kept in [early, late] {
            assert_eq!(after.mint(KIND).split(kept), Err(Refused::OtherStack));
        }
    }

    #[test]
    fn a_tag_whose_stack_minted_nothing_comes_back_where_it_was() {
        static TAGS: StackTags = StackTags::new();
        let idle = TAGS.lease().expect("room");
        drop(idle);
        let next = TAGS.lease().expect("room");
        assert_eq!(next.mint(KIND).first(), FIRST_GENERATION);
    }

    #[test]
    fn a_tag_whose_generations_are_used_up_is_never_offered_again() {
        static TAGS: StackTags = StackTags::new();
        let worn = TAGS.lease().expect("room");
        worn.force_highest(GENERATION_LIMIT - 1);
        drop(worn);
        let next = TAGS.lease().expect("room");
        assert_eq!(next.tag(), 1, "tag 0 is spent");
        drop(next);
        assert_eq!(TAGS.lease().map(|tag| tag.tag()), Ok(1));
    }

    #[test]
    fn a_handle_minted_for_one_stack_is_another_stacks_to_every_other_mint() {
        static TAGS: StackTags = StackTags::new();
        let one = TAGS.lease().expect("room");
        let other = TAGS.lease().expect("room");
        let handle = one.mint(KIND).join(0, FIRST_GENERATION).expect("fits");
        assert_eq!(
            other.mint(KIND).split(handle),
            Err(Refused::OtherStack),
            "the same slot and generation, on another tag"
        );
        assert!(one.mint(KIND).split(handle).is_ok());
    }

    #[test]
    fn a_mint_refuses_a_handle_of_another_kind_before_it_asks_whose_stack_minted_it() {
        static TAGS: StackTags = StackTags::new();
        let stack = TAGS.lease().expect("room");
        let accounts = stack.mint(Kind::Account);
        let calls = stack.mint(Kind::Call);
        let account = accounts.join(0, FIRST_GENERATION).expect("fits");
        assert_eq!(
            calls.split(account),
            Err(Refused::WrongKind(Kind::Account)),
            "the same tag and the same slot, and still not a call"
        );
        assert!(accounts.split(account).is_ok());
    }

    #[test]
    fn a_refusal_is_the_status_its_kind_of_failure_has_always_been() {
        assert_eq!(Refused::NotOurs.status(), SipralStatus::InvalidHandle);
        assert_eq!(Refused::OtherStack.status(), SipralStatus::InvalidHandle);
        assert_eq!(
            Refused::WrongKind(Kind::Stack).status(),
            SipralStatus::InvalidHandle
        );
        assert_eq!(Refused::Gone.status(), SipralStatus::StaleHandle);
    }

    /// A mint that outlives its stack keeps the tag from the next stack.
    #[test]
    fn a_tag_is_not_given_to_another_stack_while_a_mint_of_it_is_alive() {
        static TAGS: StackTags = StackTags::new();
        let gone = TAGS.lease().expect("room");
        let kept = gone.mint(KIND);
        drop(gone);
        let taken = TAGS.lease().expect("room");
        let late = kept.join(0, kept.first()).expect("fits");
        assert_eq!(
            taken.mint(KIND).split(late),
            Err(Refused::OtherStack),
            "a handle minted after its stack was gone answers to the stack that took the tag"
        );
        drop(kept);
        drop(taken);
        let again = TAGS.lease().expect("room");
        assert_eq!(
            again.tag(),
            0,
            "the tag comes back once the last mint is gone"
        );
    }
}
