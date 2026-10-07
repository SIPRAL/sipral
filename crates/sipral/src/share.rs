// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One call's media, reachable from more than one thread.
//!
//! Each session sits behind its own lock. The engine holds the only strong reference; a
//! [`SessionShare`] is a weak one for an audio thread, valid while the engine still has the
//! session.
//!
//! # A lock that waits
//!
//! Work under the lock is bounded (a frame encoded or decoded, a packet opened, a timer checked, a
//! renegotiation applied, a recording write), and the only foreign code is an attached
//! [`Processor`](crate::Processor). So a thread that finds the session busy waits instead of being
//! refused: render and capture are two threads, and a refused frame is an audible glitch.
//!
//! The one case that cannot wait is the same thread re-entering, typically a processor reaching
//! into its own call; it gets [`SessionUnavailable::Reentered`] before the lock is touched.
//!
//! # When the call ends
//!
//! The engine removes the session from its table and marks it ended under the lock, before closing
//! the recording and reporting the call's cost. Any later share, including one already waiting for
//! the lock, gets [`SessionUnavailable::Ended`], and the session is freed when the last thread
//! inside leaves.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use sipral_ua::CallHandle;

use crate::MediaEvent;
use crate::session::MediaSession;

/// A session, and whether its call still has it.
#[derive(Debug)]
pub(crate) struct Slot {
    pub(crate) session: MediaSession,
    pub(crate) ended: bool,
}

/// The engine's own reference to one session: the strong one.
pub(crate) type Held = Arc<Mutex<Slot>>;

/// Put a session that has just been opened behind its lock.
pub(crate) fn hold(session: MediaSession) -> Held {
    Arc::new(Mutex::new(Slot {
        session,
        ended: false,
    }))
}

/// Calls whose sessions have an event waiting, in the order each first had one.
///
/// A session adds its call when an event enters an empty queue, under its own lock, from whatever
/// thread is running its audio. The engine takes the next media event from the head of this list,
/// so a poll costs only the sessions with something to say.
///
/// This lock is taken only with a session lock already held or with none, never the reverse, so the
/// two cannot deadlock.
#[derive(Debug, Default)]
pub(crate) struct Ready {
    calls: Mutex<VecDeque<CallHandle>>,
}

impl Ready {
    fn calls(&self) -> MutexGuard<'_, VecDeque<CallHandle>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The call at the head of the list, taken off it.
    pub(crate) fn take(&self) -> Option<CallHandle> {
        self.calls().pop_front()
    }

    /// Put a call back at the head: it has more events, which come before any other call's.
    pub(crate) fn put_back(&self, call: CallHandle) {
        self.calls().push_front(call);
    }

    fn raise(&self, call: CallHandle) {
        self.calls().push_back(call);
    }
}

/// A session's events and how it notifies the engine.
///
/// FIFO. The engine's list is told once per run of events: `raised` stays set until the engine
/// takes the last one, so a hundred digits in one frame put the call on the list once.
#[derive(Debug, Default)]
pub(crate) struct Outbox {
    queue: VecDeque<MediaEvent>,
    to: Option<(CallHandle, Arc<Ready>)>,
    raised: bool,
}

impl Outbox {
    /// Queue an event, adding the call to the engine's list if it is not there.
    pub(crate) fn push_back(&mut self, event: MediaEvent) {
        self.queue.push_back(event);
        if let Some((call, ready)) = &self.to
            && !self.raised
        {
            self.raised = true;
            ready.raise(*call);
        }
    }

    /// The oldest event, taken.
    pub(crate) fn pop_front(&mut self) -> Option<MediaEvent> {
        self.queue.pop_front()
    }

    /// Set where to raise this session from now on, and raise it at once if events were queued
    /// before the engine took it in.
    pub(crate) fn report_to(&mut self, call: CallHandle, ready: Arc<Ready>) {
        self.raised = !self.queue.is_empty();
        if self.raised {
            ready.raise(call);
        }
        self.to = Some((call, ready));
    }

    /// The engine took the call off its list: the next event, and whether the call must go back on
    /// for another.
    pub(crate) fn take_for_engine(&mut self) -> (Option<MediaEvent>, bool) {
        let event = self.queue.pop_front();
        let more = !self.queue.is_empty();
        self.raised = more;
        (event, more)
    }
}

/// Take a session's lock, waiting if needed.
///
/// A poisoned lock is still taken: refusing the call's audio forever after a caught panic is worse
/// than continuing.
pub(crate) fn lock(held: &Held) -> MutexGuard<'_, Slot> {
    held.lock().unwrap_or_else(PoisonError::into_inner)
}

thread_local! {
    /// The sessions this thread is inside, by address, innermost last.
    static INSIDE: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// This thread's mark on one session, for as long as it is inside it.
#[derive(Debug)]
struct Inside {
    key: usize,
}

impl Inside {
    /// Mark the session, or say that this thread had already marked it.
    fn enter(held: &Held) -> Option<Self> {
        // a live session's address; `held` keeps it alive while the mark exists, so no other
        // session can reuse it
        let key = Arc::as_ptr(held).addr();
        INSIDE.with_borrow_mut(|inside| {
            if inside.contains(&key) {
                return None;
            }
            inside.push(key);
            Some(Self { key })
        })
    }
}

impl Drop for Inside {
    fn drop(&mut self) {
        INSIDE.with_borrow_mut(|inside| {
            if let Some(at) = inside.iter().rposition(|key| *key == self.key) {
                inside.swap_remove(at);
            }
        });
    }
}

/// One call's media, locked by this thread until the guard is dropped. What
/// [`MediaEngine::session`](crate::MediaEngine::session) returns, for code that already has the
/// engine.
#[derive(Debug)]
pub struct SessionGuard<'a> {
    // declared first so the lock is released before the "inside" mark
    slot: MutexGuard<'a, Slot>,
    _inside: Inside,
}

impl<'a> SessionGuard<'a> {
    /// Lock `held` once it is free, unless its call ended or this thread already holds it.
    pub(crate) fn of(held: &'a Held) -> Option<Self> {
        let inside = Inside::enter(held)?;
        let slot = lock(held);
        (!slot.ended).then_some(Self {
            slot,
            _inside: inside,
        })
    }
}

impl Deref for SessionGuard<'_> {
    type Target = MediaSession;

    fn deref(&self) -> &MediaSession {
        &self.slot.session
    }
}

impl DerefMut for SessionGuard<'_> {
    fn deref_mut(&mut self) -> &mut MediaSession {
        &mut self.slot.session
    }
}

/// Why a [`SessionShare`] did not reach its session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionUnavailable {
    /// The call's media has ended, or the engine that held it is gone.
    Ended,
    /// This thread is already inside this session further down its stack, most likely a processor
    /// reaching into its own call.
    Reentered,
}

/// Access to one call's media from a thread that does not have the engine.
///
/// From [`MediaEngine::share`](crate::MediaEngine::share). It keeps nothing alive: the session
/// belongs to the engine and is freed when the call ends, shares or not.
#[derive(Clone, Debug)]
pub struct SessionShare {
    slot: Weak<Mutex<Slot>>,
}

impl SessionShare {
    /// A share of `held`.
    pub(crate) fn of(held: &Held) -> Self {
        Self {
            slot: Arc::downgrade(held),
        }
    }

    /// Run `f` on the session once it is free.
    ///
    /// # Errors
    ///
    /// [`SessionUnavailable::Ended`] once the call's media ended or the engine is gone;
    /// [`SessionUnavailable::Reentered`] if this thread is already inside this session.
    pub fn with<R>(
        &self,
        act: impl FnOnce(&mut MediaSession) -> R,
    ) -> Result<R, SessionUnavailable> {
        let held = self.slot.upgrade().ok_or(SessionUnavailable::Ended)?;
        let _inside = Inside::enter(&held).ok_or(SessionUnavailable::Reentered)?;
        let mut slot = lock(&held);
        if slot.ended {
            return Err(SessionUnavailable::Ended);
        }
        Ok(act(&mut slot.session))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use sipral_core::sdp::{Direction, MediaPlan, NegotiatedCodec, RtcpPlan, RtpMap};

    use super::{SessionShare, SessionUnavailable, hold, lock};
    use crate::clock::WallClock;
    use crate::session::{MediaConfig, MediaSession, Start, StreamIdentity};

    /// An unnegotiated session: enough to lock, not to carry a call.
    fn a_session() -> MediaSession {
        let now = Instant::now();
        let plan = MediaPlan {
            local: "192.0.2.1:40000".parse().expect("an address"),
            remote: "192.0.2.2:40002".parse().expect("an address"),
            codec: NegotiatedCodec::new(RtpMap {
                payload: 0,
                encoding: "PCMU".to_owned(),
                clock_rate: 8_000,
                parameters: None,
            }),
            direction: Direction::SendRecv,
            dtmf: None,
            dtmf_in: None,
            codec_in: 0,
            rtcp: RtcpPlan::Off,
            keying: None,
            voip_metrics_xr: false,
        };
        let identity = StreamIdentity {
            ssrc: 1,
            sequence: 0,
            timestamp: 0,
            seed: 1,
        };
        MediaSession::open(
            &plan,
            20,
            &MediaConfig::default(),
            Vec::new(),
            Start {
                identity,
                clock: WallClock::from_unix(now, 1_700_000_000, 0),
                #[cfg(feature = "dtls")]
                handshake: None,
                #[cfg(feature = "ice")]
                ice: None,
                annex_b: false,
                now,
            },
        )
        .expect("PCMU is always in this build's catalogue")
    }

    /// The race `MediaEngine::release` guards against: it marks the slot ended before dropping its
    /// reference, so a share arriving in between (while this test's clone keeps the session alive)
    /// sees the call is over. If every strong reference were dropped first, `Ended` would come from
    /// the failed upgrade and the test would pass without the flag being read.
    #[test]
    fn a_share_is_refused_once_ended_is_marked_even_while_another_reference_keeps_the_session_alive()
     {
        let held = hold(a_session());
        let share = SessionShare::of(&held);
        // the point in `MediaEngine::release` where the slot is marked ended but the engine's
        // `Held` still exists; `held` plays that reference
        lock(&held).ended = true;

        let mut touched = false;
        let outcome = share.with(|_session| touched = true);

        assert_eq!(outcome, Err(SessionUnavailable::Ended));
        assert!(
            !touched,
            "the session was acted on after its call had ended"
        );
        drop(held);
    }
}
