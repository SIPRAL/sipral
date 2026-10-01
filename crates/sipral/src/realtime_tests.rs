// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What recording a call costs the thread that carries its audio in
//! allocations: none, once the recorder's buffers have grown to a frame. The
//! recorder is fed from inside the engine's pump, which runs as audio, and a
//! thread the scheduler runs ahead of everything else is not one to wait
//! inside the allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Result, Seek, SeekFrom, Write};

use crate::record::{Recorder, RecordingOptions};

thread_local! {
    /// Allocations made by this thread since it started. Per thread, because
    /// the other tests run beside this one and allocate as they please.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// The system's allocator, counting what each thread asks of it.
struct Counting;

fn counted() {
    // `try_with`, because a thread being torn down still frees
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
}

// SAFETY: every method hands the call to `System` unchanged and only bumps a
// thread-local counter besides, which neither allocates nor unwinds.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        counted();
        // SAFETY: the caller's contract for `alloc` is `System`'s.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        counted();
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: `block` came from this allocator, which is `System`'s.
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        counted();
        // SAFETY: as for `dealloc`, with the size the caller vouches for.
        unsafe { System.realloc(block, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

/// A file that keeps nothing: what is measured is the recorder, not a sink
/// that grows a buffer of its own.
struct Discard(u64);

impl Write for Discard {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0 = self.0.saturating_add(u64::try_from(buf.len()).unwrap_or(0));
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Seek for Discard {
    fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        if let SeekFrom::Start(at) = to {
            self.0 = at;
        }
        Ok(self.0)
    }
}

/// Both directions of a call recorded, a frame of each in turn and the
/// microphone's twice in a row now and then — a direction that stopped for a
/// frame, whose frame waits for its opposite number — and on hold: past the
/// first few frames, not one allocation.
#[test]
fn recording_a_call_allocates_nothing_per_frame() {
    // well inside the first checkpoint, five seconds in, whose header the
    // file format builds afresh
    const FRAMES: usize = 100;
    let mut recorder =
        Recorder::start(Box::new(Discard(0)), &RecordingOptions::default(), 8_000, 1)
            .expect("the recording starts");
    let microphone: Vec<i16> = (0..160_i16).map(|n| (n % 40 - 20) * 300).collect();
    let earpiece: Vec<i16> = (0..160_i16).map(|n| (n % 16 - 8) * 500).collect();
    let frame = |recorder: &mut Recorder, round: usize| {
        recorder.captured(&microphone).expect("this end");
        if round.is_multiple_of(5) {
            recorder.captured(&microphone).expect("this end again");
        }
        if round.is_multiple_of(7) {
            recorder.captured_on_hold(160).expect("on hold");
        }
        recorder.played(&earpiece).expect("the far end");
    };
    for round in 0..10 {
        frame(&mut recorder, round);
    }
    let before = allocations();
    for round in 0..FRAMES {
        frame(&mut recorder, round);
    }
    let made = allocations() - before;
    assert_eq!(made, 0, "{made} allocations over {FRAMES} frames");
    recorder.finish().expect("the file is finished");
}
