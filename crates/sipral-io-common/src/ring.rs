// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The one place a realtime thread and an ordinary one meet.
//!
//! The device callback cannot allocate, lock, log or block, so it meets the
//! rest of the process here: memory allocated once, two indices, no waiting.
//! Whoever is late loses samples, and the loss is counted. One producer, one
//! consumer.
//!
//! Samples are relaxed atomics rather than an `UnsafeCell`, so the racy head
//! is defined behaviour; acquire/release on the indices orders them.

use core::sync::atomic::{AtomicI16, AtomicUsize, Ordering};

const MIN_CAPACITY: usize = 2;

/// About 87 s at 48 kHz; also keeps `next_power_of_two` from overflowing.
const MAX_CAPACITY: usize = 1 << 22;

/// A single-producer, single-consumer buffer of samples, sized once.
///
/// Neither side waits; whoever is late loses samples.
pub struct Ring {
    cells: Box<[AtomicI16]>,
    /// Power-of-two length minus one, so indices wrap continuously past
    /// `usize::MAX`.
    mask: usize,
    write: AtomicUsize,
    read: AtomicUsize,
}

impl Ring {
    /// A ring holding at least `samples`, rounded up to a power of two.
    #[must_use]
    pub fn new(samples: usize) -> Self {
        Self::starting_at(samples, 0)
    }

    /// Tests start the indices near the wrap.
    fn starting_at(samples: usize, index: usize) -> Self {
        let capacity = samples
            .clamp(MIN_CAPACITY, MAX_CAPACITY)
            .next_power_of_two();
        let mut cells = Vec::with_capacity(capacity);
        cells.resize_with(capacity, || AtomicI16::new(0));
        Self {
            cells: cells.into_boxed_slice(),
            mask: capacity - 1,
            write: AtomicUsize::new(index),
            read: AtomicUsize::new(index),
        }
    }

    /// The requested size rounded up to a power of two.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cells.len()
    }

    /// Room for more, as the producer sees it. Acquire pairs with the
    /// consumer's release, so freed cells are really done with.
    pub fn free(&self) -> usize {
        let write = self.write.load(Ordering::Relaxed);
        let read = self.read.load(Ordering::Acquire);
        self.cells.len() - write.wrapping_sub(read)
    }

    /// Samples waiting, as the consumer sees it. Acquire makes the
    /// producer's relaxed sample stores visible.
    pub fn filled(&self) -> usize {
        let read = self.read.load(Ordering::Relaxed);
        let write = self.write.load(Ordering::Acquire);
        write.wrapping_sub(read)
    }

    /// Put in as much as fits, and say how much that was. Producer side only.
    pub fn write(&self, samples: &[i16]) -> usize {
        // only this side moves `write`
        let index = self.write.load(Ordering::Relaxed);
        let taken = self.free().min(samples.len());
        if let Some(head) = samples.get(..taken) {
            self.store_at(index, head);
        }
        self.write
            .store(index.wrapping_add(taken), Ordering::Release);
        taken
    }

    /// Put in a whole frame or none of it.
    ///
    /// The consumer can only free room, so a frame that fits stays fitting.
    pub fn write_frame(&self, frame: &[i16]) -> bool {
        self.free() >= frame.len() && self.write(frame) == frame.len()
    }

    /// Take as much as there is, and say how much that was. Consumer side only.
    pub fn read(&self, out: &mut [i16]) -> usize {
        let index = self.read.load(Ordering::Relaxed);
        let taken = self.filled().min(out.len());
        if let Some(head) = out.get_mut(..taken) {
            self.load_at(index, head);
        }
        self.read
            .store(index.wrapping_add(taken), Ordering::Release);
        taken
    }

    /// Take a whole frame or leave it.
    pub fn read_frame(&self, frame: &mut [i16]) -> bool {
        self.filled() >= frame.len() && self.read(frame) == frame.len()
    }

    fn store_at(&self, index: usize, samples: &[i16]) {
        let start = index & self.mask;
        let (head, tail) = samples.split_at(samples.len().min(self.cells.len() - start));
        if let Some(cells) = self.cells.get(start..start + head.len()) {
            for (cell, sample) in cells.iter().zip(head) {
                cell.store(*sample, Ordering::Relaxed);
            }
        }
        if let Some(cells) = self.cells.get(..tail.len()) {
            for (cell, sample) in cells.iter().zip(tail) {
                cell.store(*sample, Ordering::Relaxed);
            }
        }
    }

    fn load_at(&self, index: usize, out: &mut [i16]) {
        let start = index & self.mask;
        let (head, tail) = out.split_at_mut(out.len().min(self.cells.len() - start));
        if let Some(cells) = self.cells.get(start..start + head.len()) {
            for (slot, cell) in head.iter_mut().zip(cells) {
                *slot = cell.load(Ordering::Relaxed);
            }
        }
        if let Some(cells) = self.cells.get(..tail.len()) {
            for (slot, cell) in tail.iter_mut().zip(cells) {
                *slot = cell.load(Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CAPACITY, Ring};
    use std::sync::Arc;
    use std::thread;

    fn value(index: usize) -> i16 {
        // a prime, so the pattern repeats late
        i16::try_from(index % 30_011).unwrap_or(0)
    }

    #[test]
    fn capacity_rounds_up_and_is_clamped() {
        assert_eq!(Ring::new(0).free(), 2);
        assert_eq!(Ring::new(1).free(), 2);
        assert_eq!(Ring::new(5).free(), 8);
        assert_eq!(Ring::new(160).free(), 256);
        assert_eq!(Ring::new(1024).free(), 1024);
        assert_eq!(Ring::new(usize::MAX).free(), MAX_CAPACITY);
        assert_eq!(Ring::new(160).capacity(), 256);
        assert_eq!(Ring::new(usize::MAX).capacity(), MAX_CAPACITY);
    }

    #[test]
    fn an_empty_ring_gives_nothing() {
        let ring = Ring::new(8);
        let mut out = [7i16; 4];
        assert_eq!(ring.filled(), 0);
        assert_eq!(ring.free(), 8);
        assert_eq!(ring.read(&mut out), 0);
        assert_eq!(out, [7i16; 4]);
        assert!(!ring.read_frame(&mut out));
    }

    #[test]
    fn a_full_ring_takes_no_more() {
        let ring = Ring::new(4);
        assert_eq!(ring.write(&[1, 2, 3, 4]), 4);
        assert_eq!(ring.free(), 0);
        assert_eq!(ring.filled(), 4);
        assert_eq!(ring.write(&[5]), 0);
        assert!(!ring.write_frame(&[5, 6]));

        let mut out = [0i16; 4];
        assert_eq!(ring.read(&mut out), 4);
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn a_partial_write_takes_what_fits() {
        let ring = Ring::new(4);
        assert_eq!(ring.write(&[1, 2, 3]), 3);
        assert_eq!(ring.write(&[4, 5, 6]), 1);
        let mut out = [0i16; 8];
        assert_eq!(ring.read(&mut out), 4);
        assert_eq!(out, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn a_frame_goes_in_whole_or_not_at_all() {
        let ring = Ring::new(4);
        assert!(ring.write_frame(&[1, 2, 3]));
        assert!(!ring.write_frame(&[4, 5]));
        // the refused frame left nothing behind
        assert_eq!(ring.filled(), 3);
        let mut frame = [0i16; 3];
        assert!(ring.read_frame(&mut frame));
        assert_eq!(frame, [1, 2, 3]);
        assert!(!ring.read_frame(&mut frame));
    }

    #[test]
    fn writing_and_reading_past_the_end_wraps() {
        let ring = Ring::new(4);
        let mut out = [0i16; 3];
        for round in 0..1_000usize {
            let base = round * 3;
            let samples = [value(base), value(base + 1), value(base + 2)];
            assert_eq!(ring.write(&samples), 3);
            assert_eq!(ring.read(&mut out), 3);
            assert_eq!(out, samples);
        }
    }

    #[test]
    fn the_indices_stay_right_when_they_go_round() {
        // three samples short of the wrap, in a ring of four
        let ring = Ring::starting_at(4, usize::MAX - 3);
        let mut out = [0i16; 2];
        for round in 0..16usize {
            let samples = [value(round * 2), value(round * 2 + 1)];
            assert_eq!(ring.write(&samples), 2);
            assert_eq!(ring.read(&mut out), 2);
            assert_eq!(out, samples);
        }
        assert_eq!(ring.filled(), 0);
        assert_eq!(ring.free(), 4);
    }

    #[test]
    fn a_producer_and_a_consumer_lose_nothing_and_reorder_nothing() {
        const TOTAL: usize = 200_000;
        let ring = Arc::new(Ring::new(64));
        let producer = {
            let ring = Arc::clone(&ring);
            thread::spawn(move || {
                let mut batch = [0i16; 7];
                let mut sent = 0;
                while sent < TOTAL {
                    let size = batch.len().min(TOTAL - sent);
                    for (offset, slot) in batch.iter_mut().take(size).enumerate() {
                        *slot = value(sent + offset);
                    }
                    let mut done = 0;
                    while done < size {
                        done += ring.write(&batch[done..size]);
                    }
                    sent += size;
                }
            })
        };

        let mut got: Vec<i16> = Vec::with_capacity(TOTAL);
        let mut out = [0i16; 5];
        while got.len() < TOTAL {
            let taken = ring.read(&mut out);
            got.extend_from_slice(&out[..taken]);
        }
        producer.join().unwrap();

        assert_eq!(got.len(), TOTAL);
        for (index, sample) in got.iter().enumerate() {
            assert_eq!(*sample, value(index), "sample {index} came back wrong");
        }
        assert_eq!(ring.filled(), 0);
    }

    #[test]
    fn a_consumer_that_stops_reading_costs_the_producer_frames() {
        let ring = Ring::new(8);
        let frame = [1i16, 2, 3, 4];
        assert!(ring.write_frame(&frame));
        assert!(ring.write_frame(&frame));
        assert!(!ring.write_frame(&frame));
        assert_eq!(ring.filled(), 8);
    }
}
