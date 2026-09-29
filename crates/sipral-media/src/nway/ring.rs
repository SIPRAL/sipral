// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A queue of samples that never grows.

/// First in, first out, with its storage allocated once.
///
/// Pushing past the capacity drops the oldest samples rather than growing,
/// which is what bounds the delay a queue can build up: a writer that runs
/// ahead of its reader loses audio instead of adding latency.
pub(crate) struct Ring {
    storage: Vec<i16>,
    /// Where the oldest sample is.
    head: usize,
    /// How many samples are queued.
    len: usize,
}

impl Ring {
    /// An empty queue that holds up to `capacity` samples.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            storage: vec![0; capacity],
            head: 0,
            len: 0,
        }
    }

    /// Samples queued.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Drops up to `count` of the oldest samples, returning how many went.
    pub(crate) fn discard(&mut self, count: usize) -> usize {
        let dropped = count.min(self.len);
        let capacity = self.storage.len();
        if capacity > 0 {
            self.head = (self.head + dropped) % capacity;
        }
        self.len -= dropped;
        dropped
    }

    /// Queues `samples`, dropping the oldest to make room, and returns how
    /// many samples were dropped, counting any of `samples` itself that could
    /// never have fitted.
    pub(crate) fn push(&mut self, samples: &[i16]) -> usize {
        let capacity = self.storage.len();
        let skipped = samples.len().saturating_sub(capacity);
        let kept = samples.get(skipped..).unwrap_or_default();
        let overflow = (self.len + kept.len()).saturating_sub(capacity);
        let dropped = skipped + self.discard(overflow);
        if kept.is_empty() {
            return dropped;
        }
        let tail = (self.head + self.len) % capacity;
        let Some((front, back)) = kept.split_at_checked(kept.len().min(capacity - tail)) else {
            return dropped;
        };
        if let Some(slot) = self.storage.get_mut(tail..tail + front.len()) {
            slot.copy_from_slice(front);
        }
        if let Some(slot) = self.storage.get_mut(..back.len()) {
            slot.copy_from_slice(back);
        }
        self.len += kept.len();
        dropped
    }

    /// Moves up to `output.len()` of the oldest samples into `output`,
    /// returning how many were moved.
    pub(crate) fn pop(&mut self, output: &mut [i16]) -> usize {
        let count = output.len().min(self.len);
        let first = count.min(self.storage.len() - self.head);
        let Some((front, rest)) = output.split_at_mut_checked(first) else {
            return 0;
        };
        if let (Some(source), Some(back)) = (
            self.storage.get(self.head..self.head + first),
            rest.get_mut(..count - first),
        ) {
            front.copy_from_slice(source);
            if let Some(wrapped) = self.storage.get(..back.len()) {
                back.copy_from_slice(wrapped);
            }
        }
        self.discard(count)
    }
}

#[cfg(test)]
mod tests {
    use super::Ring;

    #[test]
    fn samples_come_out_in_the_order_they_went_in_across_the_wrap() {
        let mut ring = Ring::new(5);
        assert_eq!(ring.push(&[1, 2, 3]), 0);
        let mut out = [0; 2];
        assert_eq!(ring.pop(&mut out), 2);
        assert_eq!(out, [1, 2]);
        assert_eq!(ring.push(&[4, 5, 6, 7]), 0);
        let mut all = [0; 8];
        assert_eq!(ring.pop(&mut all), 5);
        assert_eq!(all[..5], [3, 4, 5, 6, 7]);
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn a_full_queue_drops_its_oldest_samples() {
        let mut ring = Ring::new(4);
        ring.push(&[1, 2, 3]);
        assert_eq!(ring.push(&[4, 5, 6]), 2);
        let mut out = [0; 4];
        ring.pop(&mut out);
        assert_eq!(out, [3, 4, 5, 6]);
        // more than the whole capacity at once keeps only the newest
        assert_eq!(ring.push(&[7, 8, 9, 10, 11, 12]), 2);
        ring.pop(&mut out);
        assert_eq!(out, [9, 10, 11, 12]);
    }

    #[test]
    fn discarding_forgets_the_oldest_samples() {
        let mut ring = Ring::new(4);
        ring.push(&[1, 2, 3]);
        assert_eq!(ring.discard(2), 2);
        assert_eq!(ring.discard(5), 1);
        assert_eq!(ring.len(), 0);
        ring.push(&[4, 5, 6]);
        ring.discard(1);
        let mut out = [0; 3];
        assert_eq!(ring.pop(&mut out), 2);
        assert_eq!(out[..2], [5, 6]);
    }
}
