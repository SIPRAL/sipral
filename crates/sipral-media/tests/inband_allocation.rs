// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The in-band module's promise that each detector and generator allocates
//! when it is built and never again, held to by counting what the thread
//! running them asks the allocator for. It needs a global allocator of its
//! own, which is why it is a test binary of its own.

// a counting allocator is unsafe code by nature: it forwards to `System`,
// and the test that uses it has no reason to avoid the harness's panics
#![allow(unsafe_code, clippy::unwrap_used, clippy::indexing_slicing)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use sipral_media::inband::SampleRate;
use sipral_media::inband::amd::AnsweringMachineDetector;
use sipral_media::inband::beep::BeepDetector;
use sipral_media::inband::dtmf::{Digit, DtmfDetector};
use sipral_media::inband::generate::{DtmfGenerator, ToneGenerator};
use sipral_media::inband::progress::{ProgressDetector, Region};

thread_local! {
    /// Allocations this thread has asked for since the count was cleared.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// The system's own allocator, counting each request on the thread that
/// makes it.
struct Counting;

fn count() {
    // `try_with`, because a thread being torn down may still free memory
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
}

// SAFETY: every method hands the call to `System` unchanged, with the layout
// and pointer it was given, and only bumps a thread-local counter, which
// needs no allocation of its own.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller's contract for `alloc` is `System`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: `block` came from this allocator, which is `System`'s.
        unsafe { System.dealloc(block, layout) };
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: as for `dealloc`, with the new size the caller vouches for.
        unsafe { System.realloc(block, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// How many allocations `run` makes on this thread.
fn allocations(run: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|n| n.set(0));
    run();
    ALLOCATIONS.with(Cell::get)
}

#[test]
fn nothing_in_band_allocates_once_built() {
    for rate in [SampleRate::Hz8000, SampleRate::Hz16000] {
        for region in Region::ALL {
            // every tone of the region, for twelve seconds each: enough for
            // every cadence to match, and for the history to fill and roll
            let mut pcm = vec![0_i16; rate.samples(12_000) * region.tones().len()];
            let mut digits = vec![0_i16; rate.samples(160) * Digit::ALL.len()];
            let mut progress = ProgressDetector::new(rate, region.tones());
            let mut dtmf = DtmfDetector::new(rate);
            let mut beep = BeepDetector::new(rate);
            let mut amd = AnsweringMachineDetector::new(rate);
            let mut generators: Vec<ToneGenerator> = region
                .tones()
                .iter()
                .map(|spec| ToneGenerator::new(rate, spec, -13.0))
                .collect();
            let mut digit = DtmfGenerator::new(rate);
            let mut heard = 0;
            let made = allocations(|| {
                for (generator, out) in generators
                    .iter_mut()
                    .zip(pcm.chunks_mut(rate.samples(12_000)))
                {
                    generator.fill(out);
                }
                for (&key, out) in Digit::ALL.iter().zip(digits.chunks_mut(rate.samples(160))) {
                    digit.start(key);
                    digit.fill(out);
                }
                for chunk in pcm.chunks(rate.samples(20)).chain(digits.chunks(160)) {
                    progress.process(chunk, |_| heard += 1);
                    dtmf.process(chunk, |_| heard += 1);
                    beep.process(chunk, |_| heard += 1);
                    let _ = amd.process(chunk);
                }
                dtmf.finish(|_| heard += 1);
            });
            assert!(heard > 0, "{rate:?} {region:?}: the audio was heard");
            assert_eq!(made, 0, "{rate:?} {region:?}: allocations while running");
        }
    }
}
