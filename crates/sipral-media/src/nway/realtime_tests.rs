// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a tick costs: allocations, counted, and time, measured.
//!
//! The benchmark is ignored by default, because a timing is only worth
//! reading from an optimised build on a quiet machine:
//!
//! ```text
//! cargo test -p sipral-media --release --lib nway::realtime_tests -- --ignored --nocapture
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::{Duration, Instant};

use super::{Mixer, MixerConfig, ParticipantConfig, ParticipantId, Rate};
use crate::mix::Gain;

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

/// One tick of a tone, at a participant's rate.
fn tick_of_tone(rate: Rate, hz: f64) -> Vec<i16> {
    let step = core::f64::consts::TAU * hz / f64::from(rate.hz());
    (0..rate.tick_samples())
        .map(|n| {
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let sample = (6_000.0 * (step * n as f64).sin()).round() as i16;
            sample
        })
        .collect()
}

const RATES: [Rate; 4] = [Rate::Hz8000, Rate::Hz16000, Rate::Hz32000, Rate::Hz48000];

/// A participant in the benchmark: who, the tick it sends, and room for the
/// tick it hears.
type Seat = (ParticipantId, Vec<i16>, Vec<i16>);

/// A conference of `count` participants at every rate in turn, each with a
/// tick of its tone ready to push and room to pull a tick into.
fn conference(count: usize) -> (Mixer, Vec<Seat>) {
    let mut mixer = Mixer::new(MixerConfig {
        max_participants: count,
    })
    .unwrap();
    let legs = (0..count)
        .map(|n| {
            let rate = RATES[n % RATES.len()];
            let id = mixer.join(ParticipantConfig::new(rate)).unwrap();
            let hz = 300.0 + 97.0 * f64::from(u32::try_from(n).unwrap());
            (id, tick_of_tone(rate, hz), vec![0; rate.tick_samples()])
        })
        .collect();
    (mixer, legs)
}

#[test]
fn nothing_allocates_once_everybody_has_joined() {
    let mut mixer = Mixer::new(MixerConfig {
        max_participants: 12,
    })
    .unwrap();
    let mut legs = Vec::new();
    for n in 0..12_u8 {
        let rate = RATES[usize::from(n) % RATES.len()];
        // frames of a tick, of half a tick and of three ticks
        let frame = match n % 3 {
            0 => rate.tick_samples(),
            1 => rate.tick_samples() / 2,
            _ => 3 * rate.tick_samples(),
        };
        let config = ParticipantConfig::new(rate).with_frame(frame);
        let id = mixer.join(config).unwrap();
        let tone = tick_of_tone(rate, 400.0 + 90.0 * f64::from(n));
        let frames: Vec<i16> = tone.iter().cycle().take(frame).copied().collect();
        legs.push((id, frame, frames, vec![0_i16; frame]));
    }
    mixer.start_recording(Rate::Hz16000).unwrap();
    let mut recorded = vec![0_i16; Rate::Hz16000.tick_samples()];
    let mut listed = 0;

    let before = allocations();
    for tick in 0..60_usize {
        for (index, (id, frame, frames, heard)) in legs.iter_mut().enumerate() {
            let tick_samples = RATES[index % RATES.len()].tick_samples();
            let per_tick = (tick_samples / *frame).max(1);
            let every = (*frame / tick_samples).max(1);
            if tick % every == 0 {
                for _ in 0..per_tick {
                    mixer.push(*id, frames).unwrap();
                }
            }
            if tick % every == every - 1 {
                for _ in 0..per_tick {
                    mixer.pull(*id, heard).unwrap();
                }
            }
        }
        let (id, ..) = legs[tick % legs.len()];
        mixer.set_gain_in(id, Gain::ratio(3, 4)).unwrap();
        mixer.set_gain_out(id, Gain::ratio(5, 4)).unwrap();
        mixer.set_mute_in(id, tick % 7 == 0).unwrap();
        mixer.set_mute_out(id, tick % 5 == 0).unwrap();
        mixer.set_listen_only(id, tick % 11 == 0).unwrap();
        mixer.mix();
        mixer.read_recording(&mut recorded);
        listed += mixer.talkers().len();
        let _ = (mixer.is_talking(id), mixer.talk_level(id), mixer.stats(id));
    }
    let during = allocations() - before;

    assert!(listed > 0, "nobody was ever talking");
    assert_eq!(during, 0, "{during} allocations in 60 ticks");
}

#[test]
fn the_allocation_counter_sees_an_allocation() {
    let before = allocations();
    let boxed = std::hint::black_box(Box::new(7_u64));
    assert_eq!(*boxed, 7);
    assert_eq!(allocations() - before, 1);
}

/// Mean and worst time of a tick: pushing a tick for everybody, mixing, and
/// pulling a tick for everybody.
fn time_ticks(count: usize, ticks: u32) -> (Duration, Duration) {
    let (mut mixer, mut legs) = conference(count);
    let mut tick = |mixer: &mut Mixer| {
        for (id, tone, _) in &legs {
            mixer.push(*id, tone).unwrap();
        }
        mixer.mix();
        for (id, _, heard) in &mut legs {
            mixer.pull(*id, heard).unwrap();
        }
    };
    for _ in 0..50 {
        tick(&mut mixer);
    }
    let mut worst = Duration::ZERO;
    let started = Instant::now();
    for _ in 0..ticks {
        let one = Instant::now();
        tick(&mut mixer);
        worst = worst.max(one.elapsed());
    }
    (started.elapsed() / ticks, worst)
}

#[test]
#[ignore = "a timing: run it on an optimised build, with --ignored --nocapture"]
fn benchmark_a_tick_for_3_10_and_50_participants() {
    let budget = Duration::from_millis(u64::from(super::TICK_MS));
    for count in [3, 10, 50] {
        let (mean, worst) = time_ticks(count, 1_000);
        let share = mean.as_secs_f64() / budget.as_secs_f64() * 100.0;
        println!(
            "{count:>3} participants: {:>8.1} us per 20 ms tick on average ({share:.2}% of it), worst {:>8.1} us",
            mean.as_secs_f64() * 1e6,
            worst.as_secs_f64() * 1e6,
        );
        assert!(mean < budget, "{count} participants do not fit a tick");
    }
}
