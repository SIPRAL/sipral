// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Knowing when a framework callback is no longer inside our memory.
//!
//! A framework callback holds a borrow Rust cannot see. Rather than trust
//! that a teardown call is synchronous, each callback is counted in and out
//! (unwinds included); teardown closes the gate and waits for zero. If the
//! count never drains, nothing is freed: a leak beats a use-after-free on a
//! realtime thread.
//!
//! Not covered: a callback that holds the context pointer but has not yet
//! reached [`Gate::enter`]. That case still relies on `AudioOutputUnitStop`
//! being synchronous off the I/O thread.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const LOOK_AGAIN_AFTER: Duration = Duration::from_millis(1);

/// How long teardown waits for callbacks to leave. A callback takes a few
/// milliseconds, so reaching this means something is wedged.
pub const TEARDOWN_WAIT_MILLIS: u64 = 2_000;

/// [`TEARDOWN_WAIT_MILLIS`] as a [`Duration`].
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
    /// Count first, then read the door, all `SeqCst` (here, in
    /// [`Gate::close`] and [`Gate::drained`]). This is the store-buffer
    /// pattern: with acquire/release alone both sides may read stale values
    /// and each believe it is alone.
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
    /// On `false` the caller must leak what callbacks can reach.
    pub fn drained(&self, within: Duration) -> bool {
        // look before reading the clock: nothing between close and this load
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

/// A callback's presence inside the gate, released on drop.
///
/// A guard, so a caught panic still counts the callback out.
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
        // The caller holds its pass until the drain has looked, and both values
        // are read before the join (a join adds its own happens-before).
        // With relaxed orderings this failed on six of six runs on Apple
        // Silicon, by round 18661 at the latest.
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
                    // rendezvous so the two really race
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
