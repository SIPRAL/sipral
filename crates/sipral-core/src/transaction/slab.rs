// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Storage that hands out handles which cannot come back to the wrong thing.
//!
//! A transaction dies on a timer, its slot is reused by the next one, and the
//! caller is still holding the old handle — a retransmission arrived late, a
//! UI thread got round to it, an FFI caller kept an integer. Indexing by
//! position alone would answer with whoever moved in.
//!
//! So every slot carries a generation that advances when it is vacated, and a
//! handle carries the generation it was issued under. A stale handle finds
//! nothing.

use super::handle::Raw;

/// A generational arena.
#[derive(Debug)]
pub(crate) struct Slab<T> {
    entries: Vec<Entry<T>>,
    free: Vec<u32>,
    live: usize,
}

#[derive(Debug)]
struct Entry<T> {
    generation: u32,
    value: Option<T>,
}

impl<T> Slab<T> {
    /// An empty arena.
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }

    /// Put a value in and get the handle to it.
    ///
    /// Reuses a vacated slot when there is one, so a long-lived endpoint does
    /// not grow a slot per transaction it has ever had.
    pub(crate) fn insert(&mut self, value: T) -> Raw {
        self.live += 1;
        if let Some(slot) = self.free.pop()
            && let Some(entry) = self.entries.get_mut(slot as usize)
        {
            entry.value = Some(value);
            return Raw {
                slot,
                generation: entry.generation,
            };
        }
        let slot = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        self.entries.push(Entry {
            generation: 0,
            value: Some(value),
        });
        Raw {
            slot,
            generation: 0,
        }
    }

    /// The value, if this handle is still the one that slot answers to.
    pub(crate) fn get(&self, raw: Raw) -> Option<&T> {
        let entry = self.entries.get(raw.slot as usize)?;
        if entry.generation != raw.generation {
            return None;
        }
        entry.value.as_ref()
    }

    /// The value, mutably.
    pub(crate) fn get_mut(&mut self, raw: Raw) -> Option<&mut T> {
        let entry = self.entries.get_mut(raw.slot as usize)?;
        if entry.generation != raw.generation {
            return None;
        }
        entry.value.as_mut()
    }

    /// Take the value out and retire the handle.
    ///
    /// The generation advances, so every copy of the handle stops matching —
    /// including the one that is about to arrive from somewhere slow. A slot
    /// whose generation has run out is dropped rather than reused, since
    /// wrapping would make an ancient handle valid again.
    pub(crate) fn remove(&mut self, raw: Raw) -> Option<T> {
        let entry = self.entries.get_mut(raw.slot as usize)?;
        if entry.generation != raw.generation {
            return None;
        }
        let value = entry.value.take()?;
        self.live -= 1;
        match entry.generation.checked_add(1) {
            Some(next) => {
                entry.generation = next;
                self.free.push(raw.slot);
            }
            None => entry.generation = u32::MAX,
        }
        Some(value)
    }

    /// How many values are in.
    pub(crate) const fn len(&self) -> usize {
        self.live
    }

    /// Every live value with its handle, in slot order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (Raw, &T)> {
        self.entries.iter().enumerate().filter_map(|(slot, entry)| {
            let value = entry.value.as_ref()?;
            let slot = u32::try_from(slot).ok()?;
            Some((
                Raw {
                    slot,
                    generation: entry.generation,
                },
                value,
            ))
        })
    }

    /// Put a slot one generation short of running out, so the branch that
    /// retires it for good can be reached without four billion inserts.
    #[cfg(test)]
    fn exhaust(&mut self, raw: Raw) -> Raw {
        let Some(entry) = self.entries.get_mut(raw.slot as usize) else {
            return raw;
        };
        entry.generation = u32::MAX;
        Raw {
            slot: raw.slot,
            generation: u32::MAX,
        }
    }
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Slab;

    #[test]
    fn a_handle_finds_what_it_was_given() {
        let mut slab = Slab::new();
        let a = slab.insert("a");
        let b = slab.insert("b");
        assert_eq!(slab.get(a), Some(&"a"));
        assert_eq!(slab.get(b), Some(&"b"));
        assert_eq!(slab.len(), 2);
    }

    #[test]
    fn a_retired_handle_does_not_find_the_slot_it_used_to_have() {
        // the whole reason this type exists: a transaction dies, its slot is
        // reused, and a late retransmission arrives holding the old handle
        let mut slab = Slab::new();
        let first = slab.insert("first");
        assert_eq!(slab.remove(first), Some("first"));
        assert_eq!(slab.get(first), None);

        let second = slab.insert("second");
        assert_eq!(first.slot, second.slot, "the slot was meant to be reused");
        assert_ne!(first, second);
        assert_eq!(slab.get(first), None);
        assert_eq!(slab.get(second), Some(&"second"));
        assert_eq!(slab.remove(first), None);
        assert_eq!(slab.len(), 1);
    }

    #[test]
    fn removing_twice_takes_the_value_once() {
        let mut slab = Slab::new();
        let handle = slab.insert(7);
        assert_eq!(slab.remove(handle), Some(7));
        assert_eq!(slab.remove(handle), None);
        assert_eq!(slab.len(), 0);
    }

    #[test]
    fn a_slot_that_has_run_out_of_generations_is_dropped_rather_than_reused() {
        // wrapping would make an ancient handle valid again, which is the one
        // thing the generation exists to prevent
        let mut slab = Slab::new();
        let handle = slab.insert("x");
        let last = slab.exhaust(handle);
        assert_eq!(slab.remove(last), Some("x"));

        let next = slab.insert("y");
        assert_ne!(next.slot, last.slot, "the worn-out slot came back");
        assert_eq!(slab.get(last), None);
        assert_eq!(slab.get(next), Some(&"y"));
    }

    #[test]
    fn a_handle_from_another_slab_finds_nothing_here() {
        let mut one = Slab::new();
        let mut two: Slab<&str> = Slab::new();
        let handle = one.insert("only in one");
        assert_eq!(two.get(handle), None);
        assert_eq!(two.remove(handle), None);
    }

    #[test]
    fn iteration_sees_the_live_ones_only() {
        let mut slab = Slab::new();
        let a = slab.insert(1);
        let b = slab.insert(2);
        let c = slab.insert(3);
        slab.remove(b);
        let mut seen: Vec<i32> = slab.iter().map(|(_, v)| *v).collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![1, 3]);
        assert_eq!(slab.get(a), Some(&1));
        assert_eq!(slab.get(c), Some(&3));
    }
}
