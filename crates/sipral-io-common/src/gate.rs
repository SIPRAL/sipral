// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Knowing when a framework callback is no longer inside our memory.
//!
//! Both places this crate hands a pointer to a framework have the same
//! problem at the end: the callback holds a borrow nothing in Rust can see,
//! and the memory behind it has to stay alive until the last one is out. The
//! usual answer is to trust that some teardown call is synchronous. That is a
//! promise read out of a document, and it is not what the compiler checks.
//!
//! So the property is built instead of assumed. A callback asks to come in; if
//! it is let in, its presence is counted until it leaves, on the unwind path
//! as well as the ordinary one. Teardown shuts the door, then waits for the
//! count to reach zero. If it never does, nothing is freed: a leaked buffer is
//! a bug report, and a freed one that a realtime thread is still reading is a
//! crash on someone's machine during a call.
//!
//! What is left unproved, and cannot be proved here: reaching the gate at all
//! means dereferencing the context pointer, so a callback that already holds
//! that pointer and has not yet reached [`Gate::enter`] is invisible to this,
//! and the only thing ruling that one out is `AudioOutputUnitStop` being
//! synchronous when it is not called from the I/O thread. This narrows the
//! undocumented assumption to that one call rather than removing it.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// How long a waiter sleeps between looks. Long enough not to spin, short
/// enough that an ordinary teardown is over before anyone notices.
const LOOK_AGAIN_AFTER: Duration = Duration::from_millis(1);

/// How long teardown waits for whoever is inside to come out.
///
/// A callback is a few milliseconds of work, so any number above a handful
/// means something is wedged rather than slow. Two seconds is generous enough
/// that reaching it is a real fault, and short enough that the thread taking
/// the stream down is not hung by one for ever.
pub const TEARDOWN_WAIT_MILLIS: u64 = 2_000;

/// The same, as the type the wait takes.
pub const TEARDOWN_WAIT: Duration = Duration::from_millis(TEARDOWN_WAIT_MILLIS);

/// A door that can be shut, and a count of who is through it.
pub struct Gate {
    open: AtomicBool,
    inside: AtomicUsize,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    /// A gate that is open and empty.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            open: AtomicBool::new(true),
            inside: AtomicUsize::new(0),
        }
    }

    /// Ask to come in. `None` means teardown has started and the caller must
    /// touch nothing that teardown can free.
    ///
    /// Counting first and reading the door second is deliberate, and so is
    /// sequential consistency on all four accesses here and in [`Gate::close`]
    /// and [`Gate::drained`]. This is the store-buffer shape: one side writes
    /// A then reads B, the other writes B then reads A, and under acquire and
    /// release alone both are allowed to read the stale value and both would
    /// then believe they are alone. A total order over these four is what
    /// makes at least one of them see the other, which is the entire argument
    /// that nothing is freed underneath a callback.
    pub fn enter(&self) -> Option<Pass<'_>> {
        self.inside.fetch_add(1, Ordering::SeqCst);
        if self.open.load(Ordering::SeqCst) {
            Some(Pass { gate: self })
        } else {
            self.inside.fetch_sub(1, Ordering::SeqCst);
            None
        }
    }

    /// Let nobody else in. Whoever is already inside stays counted.
    pub fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
    }

    /// Wait for everyone inside to leave, and say whether they did.
    ///
    /// `false` is the answer that matters: the caller must then leak whatever
    /// the callbacks can reach rather than free it.
    pub fn drained(&self, within: Duration) -> bool {
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

/// Proof that a callback is inside, and the thing that says when it is not.
///
/// It is a guard rather than a pair of calls because the callback bodies catch
/// panics: an unwind runs this destructor, where a bare decrement at the end of
/// the function would be skipped and teardown would wait out its whole deadline
/// and then leak for nothing.
pub struct Pass<'a> {
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
            panic!("as a callback body might");
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
    fn a_callback_thread_and_a_teardown_thread_never_both_believe_they_are_alone() {
        // The one thing the ordering has to buy: it must never happen that a
        // caller was let in and is still inside while a drain was told the
        // room was empty. That pair, and nothing weaker, is what says the
        // memory behind a callback is not freed underneath it.
        //
        // Two details make the assertion mean what it says. The caller holds
        // its pass until the drain has looked, so "was let in" and "was inside
        // when the drain looked" are the same statement. And both values are
        // read before the join, because joining a thread carries its own
        // happens-before: an assertion made after it would hold whatever
        // ordering these atomics used, and would prove nothing about them.
        //
        // It was checked against its own subject. With the four orderings in
        // `enter`, `close` and `drained` changed to relaxed, this failed on
        // every one of six runs on an Apple Silicon machine, first at rounds
        // 4584, 4708, 5055, 6491, 14535 and 18661 — so the count below is
        // roughly three times what it takes. With them sequentially consistent
        // it passed eight runs out of eight.
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
                    // meet the other thread, so the two operations that have
                    // to race actually race
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
