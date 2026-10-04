// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What carrying a call's microphone to the far end costs the audio
//! engine's pump in allocations: none, once the packet it keeps has grown to
//! a packet's size. The pump runs as audio, and a thread the scheduler runs
//! ahead of everything else is not one to wait inside the allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::Instant;

use sipral_audio::{CallAudio, Outgoing};

use crate::call::tests::media_call_tuned;
use crate::stack::tests::Observed;

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

/// A call's session, as the engine's pump carries it, encodes a frame and
/// hands its packet over without allocating once it is running.
#[test]
fn carrying_a_calls_microphone_allocates_nothing() {
    let mut observed = Observed::default();
    let (stack, _) = media_call_tuned(&mut observed, |_| {});
    let share = crate::stack::with_stack(stack, |state| {
        let call = state.engine.active().next();
        Ok(call.and_then(|call| state.engine.share(call)))
    })
    .expect("the stack")
    .expect("the call has media");
    let mut audio: Box<dyn CallAudio> = Box::new(share);
    let frame: Vec<i16> = (0..160_i16).map(|n| (n % 40 - 20) * 300).collect();
    let mut octets = 0_usize;
    let mut send = |_, packet: &Outgoing| octets += packet.payload.len();
    for _ in 0..20 {
        audio
            .capture_each(1, &frame, Instant::now(), &mut send)
            .expect("the call is up");
    }
    let before = allocations();
    for _ in 0..200 {
        audio
            .capture_each(1, &frame, Instant::now(), &mut send)
            .expect("the call is up");
    }
    let made = allocations() - before;
    assert!(octets > 0, "no packet came out");
    assert_eq!(made, 0, "{made} allocations in 200 frames");
}
