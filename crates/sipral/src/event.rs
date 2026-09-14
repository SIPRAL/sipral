// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One stream of news, about a call rather than about a layer.
//!
//! An application driving this crate has two sources of events — what the user
//! agent says about signalling and what the pipeline says about audio — and
//! two drains is one too many: the second one is the one somebody forgets, and
//! what gets forgotten is always the media, because a call that rings and
//! answers looks like it is working.
//!
//! So there is one drain, and a media event names the call it is about. What
//! the user agent said travels through untouched — this crate has no policy
//! about registration or transfer and does not pretend to — with one
//! exception: a digit that arrived by SIP INFO is [`sipral_ua::UaEvent`]'s
//! own, but it is not forwarded as [`Event::Signalling`]. RFC 4733's digit
//! already has an event of its own here, and a second one for the other way
//! a digit crosses the wire would be the split every application then has to
//! undo. So it is folded into the same [`MediaEvent::DigitReceived`] instead,
//! told apart by [`DigitSource`].

use std::time::Duration;

use sipral_core::sdp::Direction;
use sipral_ua::{CallHandle, UaEvent};

use crate::codec::Codec;
use crate::error::MediaError;
use crate::stats::StreamStatistics;

/// Something the application has to know.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// What the user agent said, unchanged.
    Signalling(UaEvent),
    /// What the media of one call is doing.
    Media {
        /// Which call.
        call: CallHandle,
        /// What happened to it.
        event: MediaEvent,
    },
}

/// Which of the two ways this stack accepts a digit carried the one
/// [`MediaEvent::DigitReceived`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigitSource {
    /// RFC 4733: a named telephone event in the RTP stream.
    Rtp,
    /// RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
    /// or `application/dtmf` — see `docs/04-ua.md` for the two conventions.
    Info,
}

/// What one call's audio is doing.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum MediaEvent {
    /// Audio is running: the negotiation settled, an RTP session is open, and
    /// [`MediaEngine::session`](crate::MediaEngine::session) will hand it
    /// over.
    Started {
        /// What was agreed. A4's reporting half: this is the answer to "what
        /// is this call actually using".
        codec: Codec,
        /// Which way it may flow, as seen from here.
        direction: Direction,
    },
    /// The session changed under a live call: a hold, a resume, a peer that
    /// moved its media address, or a re-negotiation onto another codec.
    Changed {
        /// What is agreed now.
        codec: Codec,
        /// Which way it may flow now. `SendOnly` or `Inactive` is what a hold
        /// looks like from here.
        direction: Direction,
    },
    /// Nothing has arrived for longer than the configured threshold, while
    /// signalling is perfectly happy.
    ///
    /// This is B5, and it is here because every application otherwise builds
    /// the same watchdog and every one of them discovers the need the same
    /// way: from a complaint about a call where both people went quiet and
    /// neither hung up.
    Stalled {
        /// How long the stream has been silent.
        silent_for: Duration,
    },
    /// Packets are arriving again.
    Resumed {
        /// How long the gap turned out to be.
        silent_for: Duration,
    },
    /// The call is over and this is what its media cost.
    ///
    /// The last word on the stream: the handle is released when this is
    /// emitted, so anything an end-of-call record needs is in here rather than
    /// behind a lookup that would now fail.
    Ended(StreamStatistics),
    /// The far end pressed a key, or sent some other named telephone event
    /// (RFC 4733).
    ///
    /// One per keypress, not one per packet: RFC 4733 sends a digit as a run
    /// of updates and then repeats the closing packet three times (§2.5.1.4),
    /// and reporting each of them would turn one key into five. The event is
    /// identified by the RTP timestamp it carries (§2.2.1), which is what
    /// makes collapsing them possible at all.
    DigitReceived {
        /// The key, where the event names one. Event codes at and above 16
        /// are real events that no keypad has a key for. Always `Some` when
        /// `source` is [`DigitSource::Info`]: an INFO never names anything
        /// but a keypad character.
        digit: Option<char>,
        /// The event code itself (§3.2), or the one that character names
        /// when `source` is [`DigitSource::Info`] rather than an event RFC
        /// 4733 actually carried.
        event: u8,
        /// How long the far end held it. `None` when nothing said: RFC
        /// 4733 always carries a duration, but `application/dtmf`'s INFO
        /// never does, and that is not the same fact as `Duration=0` on the
        /// other form, which is `Some(Duration::ZERO)` — a peer that held a
        /// key for no time at all still said so (8.3.11-ter).
        held: Option<Duration>,
        /// Which of the two ways this stack accepts a digit reported this
        /// one.
        source: DigitSource,
    },
    /// Media could not be started or could not be kept: an answer naming a
    /// codec this build has no decoder for, a description that could not be
    /// read.
    ///
    /// The call itself is untouched. Whether to hang it up is a decision with
    /// a person on the other end of it, so it is the application's.
    Failed(MediaError),
    /// A recording stopped on its own, part-way through.
    ///
    /// The disk filled, the file was removed underneath, the volume went away.
    /// B3's rule holds here too: it is an event, never an abort, and the call
    /// carries on without it.
    RecordingStopped {
        /// Why the sink refused.
        reason: MediaError,
        /// How much audio reached the file before it did.
        written: Duration,
    },
}
