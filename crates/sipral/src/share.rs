// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One call's media, reachable from more than one thread.
//!
//! The engine used to own every session outright, so the only way to a frame
//! of a call's audio went through the engine — and whoever held the engine to
//! run signalling held every call's audio with it. Each session now sits
//! behind a lock of its own. The engine keeps the one strong reference to it;
//! a [`SessionShare`] is a weak one, handed out for a thread that carries
//! audio, and it reaches the session only while the engine still has it.
//!
//! # A lock that waits
//!
//! Everything done under it is bounded: a frame decoded or encoded, a packet
//! opened, a timer looked at, a re-negotiation applied, a recording's write.
//! None of it waits for anything else, and the only code it runs that is not
//! this tree's is a [`Processor`](crate::Processor) the application attached.
//! So a thread that finds the session taken waits for that work to finish
//! rather than being refused: the render thread and the capture thread of one
//! call are two threads, and refusing either of them a frame is a glitch
//! somebody hears.
//!
//! The one arrival a wait cannot survive is the same thread coming back — a
//! processor reaching into the call it is running inside. That is answered
//! with [`SessionUnavailable::Reentered`] before the lock is touched, rather
//! than with a thread that waits for itself.
//!
//! # When the call ends
//!
//! The engine takes its reference out of its table and marks the session
//! ended while it holds the lock, before it closes the recording and says what
//! the call cost. A share that arrives afterwards — including one that was
//! already waiting for the lock while that happened — answers
//! [`SessionUnavailable::Ended`], and the session itself is freed as soon as
//! the last thread that was inside it lets go.

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

/// The calls whose sessions have an event waiting, in the order each first
/// had one.
///
/// A session raises its own call here the moment an event goes into its
/// queue with nothing already waiting there, and does it under its own lock,
/// from whichever thread was carrying its audio at the time. So the engine
/// finds the next media event by taking the first call off this list rather
/// than by locking every session in turn to ask: a poll costs the sessions
/// that have something to say, not the sessions there are.
///
/// Its lock is only ever taken with a session's lock already held or with no
/// lock held at all, never the other way round, so the two cannot wait for
/// each other.
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

    /// Put a call back at the head: it has more to say, and what it says
    /// next comes before any other call's.
    pub(crate) fn put_back(&self, call: CallHandle) {
        self.calls().push_front(call);
    }

    fn raise(&self, call: CallHandle) {
        self.calls().push_back(call);
    }
}

/// A session's events, and how it tells the engine it has one.
///
/// What goes in comes out in the same order. The list the engine reads is
/// told once per run of events rather than once per event: `raised` stays set
/// from the first event of a run until the engine has taken the last, so a
/// session that raises a hundred digits in one frame is on the list once.
#[derive(Debug, Default)]
pub(crate) struct Outbox {
    queue: VecDeque<MediaEvent>,
    to: Option<(CallHandle, Arc<Ready>)>,
    raised: bool,
}

impl Outbox {
    /// Queue an event, and put the call on the engine's list if it is not
    /// already there.
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

    /// Say where to raise this session from now on, and raise it at once
    /// when events are already waiting: they were queued before the engine
    /// took the session in.
    pub(crate) fn report_to(&mut self, call: CallHandle, ready: Arc<Ready>) {
        self.raised = !self.queue.is_empty();
        if self.raised {
            ready.raise(call);
        }
        self.to = Some((call, ready));
    }

    /// The engine took the call off its list: the next event, and whether
    /// the call has to go back on it for the one after.
    pub(crate) fn take_for_engine(&mut self) -> (Option<MediaEvent>, bool) {
        let event = self.queue.pop_front();
        let more = !self.queue.is_empty();
        self.raised = more;
        (event, more)
    }
}

/// Take a session's lock, waiting for whoever has it.
///
/// A poisoned lock is taken all the same. It means a panic was caught while
/// the session was held, and refusing the call's audio for ever afterwards is
/// a worse answer than carrying on from where the panic left it.
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
        // the address of a session that is alive; `held` keeps it alive for
        // as long as the mark exists, so no other session can be given it
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

/// One call's media, held by this thread until the guard is dropped.
///
/// What [`MediaEngine::session`](crate::MediaEngine::session) hands out: the
/// engine's own reach into a session, for code that already has the engine.
#[derive(Debug)]
pub struct SessionGuard<'a> {
    // declared first so that it is dropped first: the lock goes before the
    // mark saying this thread is inside
    slot: MutexGuard<'a, Slot>,
    _inside: Inside,
}

impl<'a> SessionGuard<'a> {
    /// Hold `held`, once whoever has it is done — unless its call has ended,
    /// or this thread already holds it and would be waiting for itself.
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
    /// This thread is already inside this session, further down its own
    /// stack: a processor, most likely, reaching into the call it is running
    /// inside.
    Reentered,
}

/// A way to one call's media from a thread that does not have the engine.
///
/// [`MediaEngine::share`](crate::MediaEngine::share) hands one out. It holds
/// nothing up: the session is the engine's, ends when the call does, and is
/// freed then whether or not a share of it still exists.
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

    /// Do something with the session, once whoever has it is done.
    ///
    /// # Errors
    /// [`SessionUnavailable::Ended`] once the call's media has ended or the
    /// engine is gone, and [`SessionUnavailable::Reentered`] when this thread
    /// is already inside this session.
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

    /// A session nobody negotiated: enough to put behind a lock, not enough
    /// to carry a real call.
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

    /// The race `MediaEngine::release` guards against: it marks a slot ended
    /// before it lets its own reference go, precisely so that a share which
    /// reaches the lock in between — while something else (here, this test's
    /// own clone) still keeps the session itself alive — finds out the call
    /// is over instead of acting on a stream mid-teardown. Dropping every
    /// strong reference before a share arrives would answer `Ended` for an
    /// unrelated reason (nothing left to upgrade to) and this test would pass
    /// even if the `ended` flag were never read.
    #[test]
    fn a_share_is_refused_once_ended_is_marked_even_while_another_reference_keeps_the_session_alive()
     {
        let held = hold(a_session());
        let share = SessionShare::of(&held);
        // stands in for the moment inside `MediaEngine::release` where the
        // slot is marked ended but the engine has not yet dropped its own
        // `Held`; `held` here plays that still-alive reference.
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
