// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a tick of the pump costs in allocations: none, once it has run long
//! enough for its buffers to reach their size. The pump runs as audio
//! (`Backend::pump_scheduling`), and a thread the scheduler runs ahead of
//! everything else is not one to wait inside the allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sipral_io_common::level::{Channel, Controls, window_samples};

use crate::backend::{CaptureStream, Format, PlaybackStream, StreamCommon};
use crate::call::{CallAudio, CallGone, CallId, Outgoing, Transport};
use crate::device::Role;
use crate::pump::{CallChannels, Command, Pump, Report, Stream};

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

const DEVICE_HZ: u32 = 48_000;

/// A microphone that has one frame ready every tick.
struct Microphone {
    channel: Arc<Channel>,
    ready: bool,
}

impl StreamCommon for Microphone {
    fn format(&self) -> Format {
        Format::twenty_ms(DEVICE_HZ)
    }

    fn identity(&self) -> &'static str {
        "microphone"
    }

    fn lost(&mut self) -> bool {
        false
    }

    fn controls(&self) -> Controls {
        Controls::new(&self.channel)
    }

    fn latency(&self) -> Duration {
        Duration::ZERO
    }
}

impl CaptureStream for Microphone {
    fn read(&mut self, frame: &mut [i16]) -> bool {
        // a frame, then nothing until the next tick asks again
        self.ready = !self.ready;
        if self.ready {
            frame.fill(1_000);
            self.channel.apply(frame, frame.len());
        }
        self.ready
    }

    fn system_echo_cancellation(&self) -> bool {
        false
    }
}

/// A loudspeaker that plays what it is given at once.
struct Speaker {
    channel: Arc<Channel>,
}

impl StreamCommon for Speaker {
    fn format(&self) -> Format {
        Format::twenty_ms(DEVICE_HZ)
    }

    fn identity(&self) -> &'static str {
        "speaker"
    }

    fn lost(&mut self) -> bool {
        false
    }

    fn controls(&self) -> Controls {
        Controls::new(&self.channel)
    }

    fn latency(&self) -> Duration {
        Duration::ZERO
    }
}

impl PlaybackStream for Speaker {
    fn write(&mut self, frame: &[i16]) -> bool {
        let mut played = [0_i16; 960];
        let length = frame.len().min(played.len());
        played[..length].copy_from_slice(&frame[..length]);
        self.channel.apply(&mut played, length);
        true
    }

    fn queued(&self) -> usize {
        0
    }
}

/// A call at 16 kHz that sends a packet of its own for every frame and plays
/// a constant: what a session does, with nothing of its own allocated.
struct Call {
    packet: Outgoing,
}

impl CallAudio for Call {
    fn sample_rate(&self) -> Result<u32, CallGone> {
        Ok(16_000)
    }

    fn frame_samples(&self) -> Result<usize, CallGone> {
        Ok(320)
    }

    fn capture(&mut self, _frame: &[i16], _now: Instant) -> Result<Option<Outgoing>, CallGone> {
        Ok(None)
    }

    fn capture_each(
        &mut self,
        own: CallId,
        frame: &[i16],
        _now: Instant,
        send: &mut dyn FnMut(CallId, &Outgoing),
    ) -> Result<(), CallGone> {
        self.packet.payload.clear();
        self.packet.payload.extend(
            frame
                .iter()
                .take(80)
                .flat_map(|sample| sample.to_be_bytes()),
        );
        send(own, &self.packet);
        Ok(())
    }

    fn playback(&mut self, out: &mut [i16]) -> Result<(), CallGone> {
        out.fill(2_000);
        Ok(())
    }
}

/// A tick of the pump carrying a call between a microphone and a
/// loudspeaker, each at another rate than the call's, allocates nothing once
/// its buffers have grown to their size.
#[test]
fn a_tick_allocates_nothing() {
    let sent = Arc::new(AtomicUsize::new(0));
    let counted_sent = Arc::clone(&sent);
    let (sender, receiver) = mpsc::channel();
    let mut pump = Pump::new(
        receiver,
        Arc::new(Report::default()),
        Box::new(move |_, packet: &Outgoing| {
            counted_sent.fetch_add(packet.payload.len(), Ordering::Relaxed);
        }),
        Arc::new(Instant::now),
        DEVICE_HZ,
        None,
    );
    let window = window_samples(DEVICE_HZ);
    sender
        .send(Command::Replace(
            Role::Microphone,
            Some(Stream::Capture(Box::new(Microphone {
                channel: Arc::new(Channel::new(window)),
                ready: false,
            }))),
        ))
        .unwrap();
    sender
        .send(Command::Replace(
            Role::Speaker,
            Some(Stream::Playback(Box::new(Speaker {
                channel: Arc::new(Channel::new(window)),
            }))),
        ))
        .unwrap();
    sender
        .send(Command::Attach(
            1,
            Box::new(Call {
                packet: Outgoing {
                    destination: "203.0.113.5:41000".parse().unwrap(),
                    payload: Vec::with_capacity(1_500),
                    transport: Transport::Udp,
                },
            }),
            CallChannels::new(DEVICE_HZ),
        ))
        .unwrap();
    for _ in 0..50 {
        pump.tick();
    }
    let before = allocations();
    let sent_before = sent.load(Ordering::Relaxed);
    for _ in 0..500 {
        pump.tick();
    }
    let made = allocations() - before;
    assert!(
        sent.load(Ordering::Relaxed) > sent_before,
        "no packet went out: the capture path did not run"
    );
    assert_eq!(made, 0, "{made} allocations in 500 ticks");
}
