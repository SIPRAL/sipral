// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call, one agent on the other end of a socket — `docs/07-headless.md`'s
//! Concurrency section: a state that says whether the call is ringing, up,
//! held or gone, and the two bounded queues that carry PCM between the wire
//! and the agent.
//!
//! Nothing here touches a socket or the wire codec. A caller decodes a frame
//! with [`crate::codec::Decoder`] first and hands the payload to
//! [`Session::push_capture`], and takes what [`Session::pop_playback`] gives
//! back to [`crate::codec::encode_audio`] itself. This module only owns the
//! queueing, the state, and the arithmetic of dropping instead of
//! backlogging.

use core::fmt;
use std::collections::VecDeque;

use crate::audio::AudioConfig;
use crate::control::{ErrorCode, ErrorMessage, OtherErrorCode};
use crate::latency::LatencyBudget;

/// Where a session is in its lifecycle.
///
/// Distinct from [`crate::control::CallStateKind`], which is what gets
/// written to the wire when the call moves: that enum has no `Held` because
/// the document only names three wire states, while a session held locally
/// is a real state this crate has to track even though nobody on the socket
/// has been told about it yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Placed or arrived, not yet answered.
    Ringing,
    /// Up: audio is expected to be flowing.
    Active,
    /// Answered, then parked. Nothing here plays music on hold — that is a
    /// local media decision, not one this crate makes for anyone.
    Held,
    /// Over. A session in this state accepts no more transitions and no
    /// more audio.
    Ended,
}

/// One kind of queue a frame can be dropped from, named only for the error
/// message and code it produces.
#[derive(Clone, Copy)]
enum QueueKind {
    Capture,
    Playback,
}

impl QueueKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Playback => "playback",
        }
    }
}

/// `code` as [`ErrorCode::Other`], falling back to [`ErrorCode::Internal`]
/// on the unreachable case that it collides with one of the six reserved
/// strings — every caller here builds `code` from a literal or a queue
/// name, never from anything a peer sent, so the fallback is defensive
/// rather than expected to fire.
fn other_error_code(code: impl Into<String>) -> ErrorCode {
    OtherErrorCode::new(code.into()).map_or(ErrorCode::Internal, ErrorCode::Other)
}

/// A bounded run of PCM frames, oldest first.
///
/// Bounded rather than growable on purpose: the document rules out queuing
/// forever for a stalled agent, so a frame that arrives once the queue is
/// already full is dropped instead of the queue growing to hold it.
#[derive(Debug)]
struct FrameQueue {
    frames: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl FrameQueue {
    fn new(capacity: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            capacity,
        }
    }

    /// `true` if `frame` was queued, `false` if the queue was already at
    /// capacity and `frame` was dropped instead. A capacity of zero drops
    /// every frame offered to it, which is a legal, if useless, session.
    fn push(&mut self, frame: Vec<u8>) -> bool {
        if self.frames.len() >= self.capacity {
            return false;
        }
        self.frames.push_back(frame);
        true
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        self.frames.pop_front()
    }

    fn len(&self) -> usize {
        self.frames.len()
    }

    /// Empty the queue immediately and say how many frames that discarded.
    fn clear(&mut self) -> usize {
        let discarded = self.frames.len();
        self.frames.clear();
        discarded
    }
}

/// One call, with the agent's queues and where the call stands.
#[derive(Debug)]
pub struct Session {
    call_id: String,
    audio: AudioConfig,
    state: SessionState,
    capture: FrameQueue,
    playback: FrameQueue,
    latency: LatencyBudget,
}

impl Session {
    /// A new session for `call_id`, ringing, with `capture_capacity` and
    /// `playback_capacity` frames of headroom in their respective
    /// directions.
    #[must_use]
    pub fn new(
        call_id: String,
        audio: AudioConfig,
        capture_capacity: usize,
        playback_capacity: usize,
    ) -> Self {
        Self {
            call_id,
            audio,
            state: SessionState::Ringing,
            capture: FrameQueue::new(capture_capacity),
            playback: FrameQueue::new(playback_capacity),
            latency: LatencyBudget::new(audio),
        }
    }

    /// The call this session is for.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The session's audio configuration, agreed once at open.
    #[must_use]
    pub const fn audio(&self) -> AudioConfig {
        self.audio
    }

    /// Where the session is in its lifecycle.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Ringing: placed or arrived, not yet answered.
    #[must_use]
    pub const fn is_ringing(&self) -> bool {
        matches!(self.state, SessionState::Ringing)
    }

    /// Up: audio is expected to be flowing.
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Held.
    #[must_use]
    pub const fn is_held(&self) -> bool {
        matches!(self.state, SessionState::Held)
    }

    /// Gone: no more transitions, no more audio.
    #[must_use]
    pub const fn is_gone(&self) -> bool {
        matches!(self.state, SessionState::Ended)
    }

    /// Ringing to active.
    ///
    /// # Errors
    /// [`SessionError::IllegalTransition`] from any state but `Ringing`.
    pub fn answer(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Ringing, SessionState::Active)
    }

    /// Active to held.
    ///
    /// # Errors
    /// [`SessionError::IllegalTransition`] from any state but `Active`.
    pub fn hold(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Active, SessionState::Held)
    }

    /// Held back to active.
    ///
    /// # Errors
    /// [`SessionError::IllegalTransition`] from any state but `Held`.
    pub fn resume(&mut self) -> Result<(), SessionError> {
        self.require(SessionState::Held, SessionState::Active)
    }

    /// End the call, from ringing, active or held.
    ///
    /// # Errors
    /// [`SessionError::IllegalTransition`] if the call has already ended.
    pub fn hangup(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, SessionState::Ended) {
            return Err(SessionError::IllegalTransition {
                from: self.state,
                to: SessionState::Ended,
            });
        }
        self.state = SessionState::Ended;
        Ok(())
    }

    fn require(&mut self, from: SessionState, to: SessionState) -> Result<(), SessionError> {
        if self.state == from {
            self.state = to;
            Ok(())
        } else {
            Err(SessionError::IllegalTransition {
                from: self.state,
                to,
            })
        }
    }

    /// The latency budget the document describes, read or updated as
    /// upstream conditions change.
    #[must_use]
    pub const fn latency(&self) -> &LatencyBudget {
        &self.latency
    }

    /// Mutable access to the same budget, for whatever is watching the
    /// jitter buffer and the codec to report into.
    pub fn latency_mut(&mut self) -> &mut LatencyBudget {
        &mut self.latency
    }

    /// Frames waiting to be delivered to the agent.
    #[must_use]
    pub fn capture_depth(&self) -> usize {
        self.capture.len()
    }

    /// Frames waiting to be sent as RTP.
    #[must_use]
    pub fn playback_depth(&self) -> usize {
        self.playback.len()
    }

    /// Queue one frame of the caller's audio for the agent to read.
    ///
    /// # Errors
    /// An [`ErrorMessage`] ready for the error channel, and `frame` is gone
    /// either way rather than held for a retry: [`ErrorCode::InvalidAudioFrame`]
    /// if it is not exactly one frame at the session's rate and duration, or
    /// a queue-full drop if the agent is not reading fast enough to keep up
    /// — a queue that waited for it would be exactly the unbounded backlog
    /// the document rules out.
    pub fn push_capture(&mut self, frame: Vec<u8>) -> Result<(), ErrorMessage> {
        self.push(QueueKind::Capture, frame)
    }

    /// Queue one frame of the agent's audio for playback toward the caller.
    ///
    /// # Errors
    /// See [`Session::push_capture`]; the same three outcomes apply in this
    /// direction.
    pub fn push_playback(&mut self, frame: Vec<u8>) -> Result<(), ErrorMessage> {
        self.push(QueueKind::Playback, frame)
    }

    fn push(&mut self, kind: QueueKind, frame: Vec<u8>) -> Result<(), ErrorMessage> {
        if let Err(error) = self.audio.validate_frame(&frame) {
            return Err(self.drop_message(ErrorCode::InvalidAudioFrame, error.to_string()));
        }
        let name = kind.as_str();
        if matches!(self.state, SessionState::Ended) {
            return Err(self.drop_message(
                other_error_code("call_ended"),
                format!("{name} frame dropped: call already ended"),
            ));
        }
        let queued = match kind {
            QueueKind::Capture => self.capture.push(frame),
            QueueKind::Playback => self.playback.push(frame),
        };
        if queued {
            Ok(())
        } else {
            Err(self.drop_message(
                other_error_code(format!("{name}_queue_full")),
                format!("{name} queue full, frame dropped"),
            ))
        }
    }

    fn drop_message(&self, code: ErrorCode, message: String) -> ErrorMessage {
        ErrorMessage {
            call_id: Some(self.call_id.clone()),
            code,
            message,
        }
    }

    /// The next frame of the caller's audio, for the agent to read.
    pub fn pop_capture(&mut self) -> Option<Vec<u8>> {
        self.capture.pop()
    }

    /// The next frame of the agent's audio, for the wire.
    pub fn pop_playback(&mut self) -> Option<Vec<u8>> {
        self.playback.pop()
    }

    /// Discard everything queued for playback immediately, per the
    /// document's barge-in message — without waiting for what is already
    /// buffered to drain. Returns how many frames were discarded.
    ///
    /// The residual time to silence on the wire after this call is bounded
    /// by [`LatencyBudget::playback_latency_ms`] alone, never by how many
    /// frames happened to be queued a moment before: that is the entire
    /// point of discarding instead of draining.
    pub fn barge_in(&mut self) -> usize {
        self.playback.clear()
    }
}

/// A transition the state machine has no edge for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// No edge in the state machine goes from `from` to `to`.
    IllegalTransition {
        /// Where the session was.
        from: SessionState,
        /// Where the caller tried to move it.
        to: SessionState,
    },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(f, "cannot move from {from:?} to {to:?}")
            }
        }
    }
}

impl core::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::{Session, SessionError, SessionState};
    use crate::audio::{AudioConfig, SampleRate};
    use crate::control::{ErrorCode, OtherErrorCode};

    fn config() -> AudioConfig {
        AudioConfig::new(SampleRate::Hz8000) // 20 ms frames, 320 bytes each
    }

    fn frame() -> Vec<u8> {
        vec![0_u8; usize::from(config().frame_bytes().expect("fits"))]
    }

    fn session(capture_capacity: usize, playback_capacity: usize) -> Session {
        Session::new(
            "call-1".to_owned(),
            config(),
            capture_capacity,
            playback_capacity,
        )
    }

    #[test]
    fn a_new_session_starts_ringing() {
        let session = session(4, 4);
        assert!(session.is_ringing());
        assert_eq!(session.state(), SessionState::Ringing);
    }

    #[test]
    fn answer_moves_ringing_to_active() {
        let mut session = session(4, 4);
        session.answer().expect("ringing to active");
        assert!(session.is_up());
    }

    #[test]
    fn answer_from_anywhere_but_ringing_is_illegal() {
        let mut session = session(4, 4);
        session.answer().expect("ringing to active");
        assert_eq!(
            session.answer(),
            Err(SessionError::IllegalTransition {
                from: SessionState::Active,
                to: SessionState::Active,
            })
        );
    }

    #[test]
    fn hold_and_resume_round_trip_through_active() {
        let mut session = session(4, 4);
        session.answer().expect("ringing to active");
        session.hold().expect("active to held");
        assert!(session.is_held());
        session.resume().expect("held to active");
        assert!(session.is_up());
    }

    #[test]
    fn hold_before_answering_is_illegal() {
        let mut session = session(4, 4);
        assert_eq!(
            session.hold(),
            Err(SessionError::IllegalTransition {
                from: SessionState::Ringing,
                to: SessionState::Held,
            })
        );
    }

    #[test]
    fn hangup_ends_the_call_while_ringing() {
        let mut session = session(4, 4);
        session.hangup().expect("ringing to ended");
        assert!(session.is_gone());
    }

    #[test]
    fn hangup_ends_the_call_while_active() {
        let mut session = session(4, 4);
        session.answer().expect("ringing to active");
        session.hangup().expect("active to ended");
        assert!(session.is_gone());
    }

    #[test]
    fn hangup_ends_the_call_while_held() {
        let mut session = session(4, 4);
        session.answer().expect("ringing to active");
        session.hold().expect("active to held");
        session.hangup().expect("held to ended");
        assert!(session.is_gone());
    }

    #[test]
    fn hanging_up_twice_is_illegal() {
        let mut session = session(4, 4);
        session.hangup().expect("ringing to ended");
        assert_eq!(
            session.hangup(),
            Err(SessionError::IllegalTransition {
                from: SessionState::Ended,
                to: SessionState::Ended,
            })
        );
    }

    #[test]
    fn capture_and_playback_frames_come_back_in_the_order_they_were_pushed() {
        let mut session = session(4, 4);
        let frames: Vec<Vec<u8>> = (0..3_u8)
            .map(|n| {
                let mut f = frame();
                if let Some(first) = f.first_mut() {
                    *first = n;
                }
                f
            })
            .collect();
        for f in &frames {
            session.push_capture(f.clone()).expect("within capacity");
            session.push_playback(f.clone()).expect("within capacity");
        }
        for f in &frames {
            assert_eq!(session.pop_capture().as_ref(), Some(f));
            assert_eq!(session.pop_playback().as_ref(), Some(f));
        }
        assert_eq!(session.pop_capture(), None);
        assert_eq!(session.pop_playback(), None);
    }

    #[test]
    fn a_capture_frame_of_the_wrong_size_is_refused_and_reported() {
        let mut session = session(4, 4);
        let error = session.push_capture(vec![0_u8; 3]).expect_err("wrong size");
        assert_eq!(error.code, ErrorCode::InvalidAudioFrame);
        assert_eq!(error.call_id.as_deref(), Some("call-1"));
    }

    #[test]
    fn pushing_past_capacity_drops_the_new_frame_and_reports_the_queue_full() {
        let mut session = session(2, 2);
        session.push_capture(frame()).expect("first fits");
        session.push_capture(frame()).expect("second fits");
        let error = session.push_capture(frame()).expect_err("queue is full");
        assert_eq!(
            error.code,
            ErrorCode::Other(
                OtherErrorCode::new("capture_queue_full".to_owned()).expect("not a reserved code")
            )
        );
        assert_eq!(session.capture_depth(), 2);
    }

    #[test]
    fn a_zero_capacity_queue_drops_every_frame_from_the_first() {
        let mut session = session(0, 0);
        let error = session.push_playback(frame()).expect_err("no headroom");
        assert_eq!(
            error.code,
            ErrorCode::Other(
                OtherErrorCode::new("playback_queue_full".to_owned()).expect("not a reserved code")
            )
        );
        assert_eq!(session.playback_depth(), 0);
    }

    #[test]
    fn frames_pushed_after_hangup_are_dropped_and_reported_as_ended() {
        let mut session = session(4, 4);
        session.hangup().expect("ringing to ended");
        let error = session.push_capture(frame()).expect_err("call is over");
        assert_eq!(
            error.code,
            ErrorCode::Other(
                OtherErrorCode::new("call_ended".to_owned()).expect("not a reserved code")
            )
        );
        assert_eq!(session.capture_depth(), 0);
    }

    #[test]
    fn a_stalled_agent_does_not_lose_frames_pushed_before_it_stalled() {
        // dropping only ever applies to the frame that could not fit; what
        // was already queued stays exactly as it was
        let mut session = session(2, 2);
        session.push_capture(frame()).expect("first fits");
        assert!(session.push_capture(frame()).is_ok());
        assert!(session.push_capture(frame()).is_err());
        assert_eq!(session.capture_depth(), 2);
        assert!(session.pop_capture().is_some());
        assert!(session.pop_capture().is_some());
        assert_eq!(session.pop_capture(), None);
    }

    #[test]
    fn barge_in_on_an_empty_queue_discards_nothing() {
        let mut session = session(4, 4);
        assert_eq!(session.barge_in(), 0);
    }

    #[test]
    fn barge_in_never_touches_the_capture_queue() {
        let mut session = session(4, 4);
        session.answer().expect("ringing to active");
        session.push_capture(frame()).expect("within capacity");
        session.push_playback(frame()).expect("within capacity");
        session.barge_in();
        assert_eq!(session.capture_depth(), 1);
        assert_eq!(session.playback_depth(), 0);
    }

    #[test]
    fn barge_in_clears_playback_instantly_and_stays_under_the_budget() {
        let mut session = session(64, 64);
        session.answer().expect("ringing to active");

        // fifty frames at 20 ms each is a full second of queued speech: were
        // this drained rather than discarded, it alone would blow the
        // hundred-millisecond target by an order of magnitude
        for _ in 0..50 {
            session.push_playback(frame()).expect("within capacity");
        }
        let queued_frames = u32::try_from(session.playback_depth()).expect("fits in a test");
        let queued_ms = queued_frames * session.audio().frame_duration_ms();
        assert!(
            queued_ms >= 100,
            "the setup should exceed the budget on its own, or the test proves nothing"
        );

        session.latency_mut().set_encode_frames(1);

        let discarded = session.barge_in();

        assert_eq!(discarded, 50);
        assert_eq!(session.playback_depth(), 0);

        // this is the number the document actually measures: time from the
        // request to silence on the wire, in accounted frames rather than
        // wall clock. Not playback_latency_ms() alone -- that only counts
        // the encode-and-one-frame term already past the queue, and holds
        // regardless of what barge_in() did -- but that term plus whatever
        // is still queued, drained at the frame duration. Skip the
        // barge_in() call above and playback_depth() stays at fifty, this
        // sum lands at a full second, and the assertion below catches it.
        let still_queued_ms = u32::try_from(session.playback_depth())
            .expect("fits in a test")
            .saturating_mul(session.audio().frame_duration_ms());
        let residual_ms = still_queued_ms.saturating_add(session.latency().playback_latency_ms());
        assert!(
            residual_ms < 100,
            "residual latency after barge-in: {residual_ms} ms"
        );
    }
}
