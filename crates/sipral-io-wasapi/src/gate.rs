// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Knowing when the audio thread is no longer in our memory.
//!
//! Teardown has to answer one question: is the audio thread still touching the
//! rings, the counters and the handles? The obvious answer is to join the
//! thread, and the obvious answer is wrong — `join` waits for ever, and the way
//! this goes wrong in the field is a driver call that does not return, which
//! would hang whichever thread happened to drop the stream.
//!
//! So the property is built instead. Each pass over the shared memory asks to
//! come in; if it is let in, its presence is counted until it leaves, on the
//! unwind path as well as the ordinary one. Teardown shuts the door, wakes the
//! thread, then waits for the count to reach zero with a deadline. If it never
//! does, nothing is joined and no handle the thread could still be waiting on
//! is closed: a thread that outlives its owner is a bug report, a handle closed
//! under a thread still blocked on it is a crash in the middle of somebody's
//! call — and handle values are recycled, so it would be a crash somewhere
//! else entirely.
//!
//! This is `sipral-io-coreaudio`'s gate, with one difference worth naming. There
//! the callback belongs to the framework and the memory behind it is reached
//! through a raw pointer, so a failed drain means leaking the buffers. Here the
//! thread is ours and holds its own reference to the shared state, so the
//! memory stays alive on its own; what a failed drain costs is the thread, its
//! interfaces and its handles, and the right to say the shutdown was clean.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// How long a waiter sleeps between looks. Long enough not to spin, short
/// enough that an ordinary teardown is over before anyone notices.
const LOOK_AGAIN_AFTER: Duration = Duration::from_millis(1);

/// How long teardown waits for whoever is inside to come out.
///
/// A pass over a buffer is a few milliseconds of work, so any number above a
/// handful means something is wedged rather than slow. Two seconds is generous
/// enough that reaching it is a real fault, and short enough that the thread
/// taking the stream down is not hung by one for ever.
pub(crate) const TEARDOWN_WAIT_MILLIS: u64 = 2_000;

/// The same, as the type the wait takes.
pub(crate) const TEARDOWN_WAIT: Duration = Duration::from_millis(TEARDOWN_WAIT_MILLIS);

/// A door that can be shut, and a count of who is through it.
pub(crate) struct Gate {
    open: AtomicBool,
    inside: AtomicUsize,
}

impl Gate {
    /// A gate that is open and empty.
    pub(crate) const fn new() -> Self {
        Self {
            open: AtomicBool::new(true),
            inside: AtomicUsize::new(0),
        }
    }

    /// Ask to come in. `None` means teardown has started and the caller must
    /// touch nothing that teardown can take away.
    ///
    /// Counting first and reading the door second is deliberate, and so is
    /// sequential consistency on all four accesses here and in [`Gate::close`]
    /// and [`Gate::drained`]. This is the store-buffer shape: one side writes A
    /// then reads B, the other writes B then reads A, and under acquire and
    /// release alone both are allowed to read the stale value and both would
    /// then believe they are alone. A total order over these four is what makes
    /// at least one of them see the other, which is the entire argument that
    /// nothing is taken away underneath the audio thread.
    pub(crate) fn enter(&self) -> Option<Pass<'_>> {
        self.inside.fetch_add(1, Ordering::SeqCst);
        if self.open.load(Ordering::SeqCst) {
            Some(Pass { gate: self })
        } else {
            self.inside.fetch_sub(1, Ordering::SeqCst);
            None
        }
    }

    /// Let nobody else in. Whoever is already inside stays counted.
    pub(crate) fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
    }

    /// Wait for everyone inside to leave, and say whether they did.
    ///
    /// `false` is the answer that matters: the caller must then leave the
    /// thread and its handles alone rather than tidy them up.
    pub(crate) fn drained(&self, within: Duration) -> bool {
        // The first look comes before the clock is read, and not by accident.
        // An empty gate is the ordinary case and should not pay for a
        // timestamp, and putting anything at all between the door being shut
        // and the count being read widens the only window in which both sides
        // could miss each other.
        if self.inside.load(Ordering::SeqCst) == 0 {
            return true;
        }

        let start = Instant::now();
        loop {
            if self.inside.load(Ordering::SeqCst) == 0 {
                return true;
            }
            if start.elapsed() >= within {
                return false;
            }
            thread::sleep(LOOK_AGAIN_AFTER);
        }
    }
}

/// Proof that the audio thread is inside, and the thing that says when it is
/// not.
///
/// It is a guard rather than a pair of calls because each pass catches panics:
/// an unwind runs this destructor, where a bare decrement at the end of the
/// function would be skipped and teardown would wait out its whole deadline and
/// then give up for nothing.
pub(crate) struct Pass<'a> {
    gate: &'a Gate,
}

impl Drop for Pass<'_> {
    fn drop(&mut self) {
        self.gate.inside.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::{Gate, Pass};
    use core::hint;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    const AT_ONCE: Duration = Duration::from_millis(0);
    const A_MOMENT: Duration = Duration::from_millis(500);

    #[test]
    fn an_open_gate_lets_callers_in() {
        let gate = Gate::new();
        let first = gate.enter().expect("open");
        let second = gate.enter().expect("open");
        assert!(!gate.drained(AT_ONCE));
        drop(first);
        assert!(!gate.drained(AT_ONCE));
        drop(second);
        assert!(gate.drained(AT_ONCE));
    }

    #[test]
    fn a_shut_gate_lets_nobody_in_and_is_already_empty() {
        let gate = Gate::new();
        gate.close();
        assert!(gate.enter().is_none());
        assert!(gate.drained(AT_ONCE));
    }

    #[test]
    fn shutting_the_gate_does_not_evict_whoever_is_inside() {
        let gate = Gate::new();
        let inside = gate.enter().expect("open");
        gate.close();
        // this is the case teardown exists for: the door is shut and someone
        // is still in the room
        assert!(!gate.drained(AT_ONCE));
        assert!(gate.enter().is_none());
        drop(inside);
        assert!(gate.drained(AT_ONCE));
    }

    #[test]
    fn a_pass_that_is_dropped_by_an_unwind_still_counts_out() {
        let gate = Gate::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _inside: Pass<'_> = gate.enter().expect("open");
            panic!("as a pass over a buffer might");
        }));
        assert!(outcome.is_err());
        assert!(gate.drained(AT_ONCE));
    }

    #[test]
    fn the_ordinary_case_spends_none_of_the_teardown_budget() {
        assert_eq!(
            super::TEARDOWN_WAIT,
            Duration::from_millis(super::TEARDOWN_WAIT_MILLIS)
        );

        let gate = Gate::new();
        gate.close();
        let start = std::time::Instant::now();
        assert!(gate.drained(super::TEARDOWN_WAIT));
        // an empty gate returns on the first look rather than sleeping its way
        // to the deadline, which is what keeps dropping a stream instant
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn a_waiter_gives_up_rather_than_wait_for_ever() {
        let gate = Gate::new();
        let _inside = gate.enter().expect("open");
        gate.close();
        assert!(!gate.drained(Duration::from_millis(20)));
    }

    #[test]
    fn a_waiter_returns_as_soon_as_the_last_one_leaves() {
        let gate = Arc::new(Gate::new());
        let arrived = Arc::new(AtomicBool::new(false));
        let leaving = {
            let gate = Arc::clone(&gate);
            let arrived = Arc::clone(&arrived);
            thread::spawn(move || {
                let inside = gate.enter().expect("open");
                arrived.store(true, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(30));
                drop(inside);
            })
        };
        while !arrived.load(Ordering::SeqCst) {
            thread::yield_now();
        }

        gate.close();
        assert!(gate.drained(A_MOMENT));
        leaving.join().unwrap();
    }

    #[test]
    fn an_audio_thread_and_a_teardown_thread_never_both_believe_they_are_alone() {
        // The one thing the ordering has to buy: it must never happen that a
        // caller was let in and is still inside while a drain was told the room
        // was empty. That pair, and nothing weaker, is what says the handles
        // the audio thread is waiting on are not closed underneath it.
        //
        // Two details make the assertion mean what it says. The caller holds
        // its pass until the drain has looked, so "was let in" and "was inside
        // when the drain looked" are the same statement. And both values are
        // read before the join, because joining a thread carries its own
        // happens-before: an assertion made after it would hold whatever
        // ordering these atomics used, and would prove nothing about them.
        //
        // The count is what the same test in `sipral-io-coreaudio` established
        // it needed there, where relaxed orderings failed it within the first
        // twenty thousand rounds on every run. The two gates are the same code,
        // so the number carries over rather than being rediscovered.
        const ROUNDS: usize = 20_000;

        for round in 0..ROUNDS {
            let gate = Arc::new(Gate::new());
            let got_in = Arc::new(AtomicBool::new(false));
            let looked = Arc::new(AtomicBool::new(false));
            let ready = Arc::new(AtomicUsize::new(0));

            let caller = {
                let gate = Arc::clone(&gate);
                let got_in = Arc::clone(&got_in);
                let looked = Arc::clone(&looked);
                let ready = Arc::clone(&ready);
                thread::spawn(move || {
                    // meet the other thread, so the two operations that have to
                    // race actually race
                    ready.fetch_add(1, Ordering::SeqCst);
                    while ready.load(Ordering::SeqCst) < 2 {
                        hint::spin_loop();
                    }

                    if let Some(pass) = gate.enter() {
                        got_in.store(true, Ordering::SeqCst);
                        while !looked.load(Ordering::SeqCst) {
                            hint::spin_loop();
                        }
                        drop(pass);
                    }
                })
            };

            ready.fetch_add(1, Ordering::SeqCst);
            while ready.load(Ordering::SeqCst) < 2 {
                hint::spin_loop();
            }

            gate.close();
            let empty_at_once = gate.drained(AT_ONCE);
            let was_let_in = got_in.load(Ordering::SeqCst);
            looked.store(true, Ordering::SeqCst);
            caller.join().unwrap();

            assert!(
                !(was_let_in && empty_at_once),
                "a caller was inside while the drain was told the room was empty (round {round})"
            );
        }
    }
}
