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

#[cfg(any(feature = "dtls", feature = "ice"))]
use std::net::SocketAddr;

use sipral_core::sdp::Direction;
#[cfg(feature = "dtls")]
use sipral_rtp::srtp::Suite;
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
    ///
    /// A G.729 far end in a pause it announced with an Annex B SID frame
    /// sends no audio on purpose, for as long as its background stays the
    /// same; while its RTCP reports keep arriving that pause is not a stall.
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
    /// The account this call belongs to asked for an RFC 6035 voice
    /// quality report and the attempt to publish it has now been made,
    /// once, on call end.
    ///
    /// Emitted only when there was a collector to publish to at all
    /// (`Account::quality_report_uri` — see `sipral_ua`); a call whose
    /// account named none raises nothing here, since nothing was ever
    /// attempted for the application to hear about. Whether it is worth
    /// telling anyone `ok` is `false` is the application's call: this
    /// crate never retries either way.
    QualityReportSent {
        /// Whether the PUBLISH left this end. Not whether a collector
        /// accepted it — this stack does not wait for that answer.
        ok: bool,
    },
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
    /// The handshake that keys this call finished, and audio can move.
    ///
    /// Only DTLS-SRTP produces this, and it is the moment the call becomes
    /// what it agreed to be: between
    /// [`MediaEvent::Started`](MediaEvent::Started) and this one, the stream
    /// exists, has an address and a codec, and carries nothing in either
    /// direction. An application that draws a padlock draws it here, and
    /// [`MediaSession::is_encrypted`](crate::MediaSession::is_encrypted)
    /// answers the same question at any other moment.
    ///
    /// A call keyed by SDES never emits it, because such a call is keyed
    /// before its session is opened at all.
    #[cfg(feature = "dtls")]
    Secured {
        /// The transform the handshake agreed on, which RFC 5764 §4.1.2 has
        /// it choose rather than the signalling.
        suite: Suite,
        /// Where the far end's handshake records came from, which is the
        /// address its media will be believed from too. `None` only for a
        /// handshake in which this end sent every record and the far end
        /// answered from nowhere, which no completed handshake can be.
        peer: Option<SocketAddr>,
    },
    /// ICE chose the path this call's media will take (RFC 8445 §8.1.1).
    ///
    /// The moment the checks stop and the audio starts, and the answer to
    /// "why is this call going to an address the signalling never named" —
    /// which, for a call behind a NAT, is the ordinary outcome rather than a
    /// fault. It arrives again if a nomination of higher priority replaces
    /// the pair part-way through the call; each one names the pair in force
    /// from that moment.
    ///
    /// A call not using ICE never emits it, and that is most calls: the
    /// policy is off by default, and a peer that described no ICE leaves the
    /// stream on the address its signalling named.
    #[cfg(feature = "ice")]
    PathChosen {
        /// This end of the pair: the socket the media goes out of.
        local: SocketAddr,
        /// The far end of it, which is where the media goes.
        remote: SocketAddr,
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
    /// The call this one was joined to has ended, taking the pair down with
    /// it.
    ///
    /// [`MediaEngine::join`](crate::MediaEngine::join) paired the two calls
    /// and neither one ever called
    /// [`MediaEngine::leave`](crate::MediaEngine::leave) — the partner's own
    /// call simply ended first, the same way any call does, and this is the
    /// half of that this call has to be told: the pairing does not outlive
    /// either side of it. This call's own session is untouched and carries
    /// on exactly as an unjoined call always has, on whatever
    /// [`MediaSession::playback`](crate::MediaSession::playback) and
    /// [`MediaSession::capture`](crate::MediaSession::capture) it is next
    /// given directly.
    Unjoined,
}
