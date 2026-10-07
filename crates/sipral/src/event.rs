// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One stream of events, organised by call rather than by layer.
//!
//! Two drains (signalling and media) would invite applications to forget one, and it is always
//! media, because a call that rings and answers looks fine. So there is one drain, and media events
//! name their call. User agent events pass through untouched, with one exception: a digit received
//! by SIP INFO is not forwarded as [`Event::Signalling`] but folded into the same
//! [`MediaEvent::DigitReceived`] RFC 4733 digits use, told apart by [`DigitSource`].

use std::time::Duration;

#[cfg(any(feature = "dtls", feature = "ice"))]
use std::net::SocketAddr;

use sipral_core::sdp::Direction;
#[cfg(feature = "dtls")]
use sipral_rtp::srtp::Suite;
use sipral_ua::{CallHandle, UaEvent};

use crate::codec::Codec;
use crate::error::MediaError;
use crate::inband::CallProgress;
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

/// Which of the three digit transports carried a [`MediaEvent::DigitReceived`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigitSource {
    /// RFC 4733: a named telephone event in the RTP stream.
    Rtp,
    /// SIP INFO (RFC 6086) with `application/dtmf-relay` or `application/dtmf`; see
    /// `docs/04-ua.md`.
    Info,
    /// The tones themselves, detected in the far-end audio (ITU-T Q.23), as
    /// [`DtmfDetection`](crate::DtmfDetection) configures.
    InBand,
}

/// What one call's audio is doing.
// `Ended` carries the full statistics by value (`StreamStatistics` is `Copy`); raised once per
// call, so boxing would gain nothing and lose `Copy`
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum MediaEvent {
    /// Audio is running: the negotiation settled, an RTP session is open, and
    /// [`MediaEngine::session`](crate::MediaEngine::session) will return it.
    Started {
        /// What was agreed (A4: what this call is actually using).
        codec: Codec,
        /// Which way it may flow, as seen from here.
        direction: Direction,
    },
    /// The session changed during the call: hold, resume, a peer that moved its media address, or a
    /// new codec.
    Changed {
        /// What is agreed now.
        codec: Codec,
        /// The direction now. `SendOnly` or `Inactive` is how a hold looks from here.
        direction: Direction,
    },
    /// No audio has arrived for longer than the configured threshold, although signalling is fine
    /// (B5).
    ///
    /// A G.729 far end in an announced Annex B pause sends no audio on purpose; while its RTCP
    /// reports keep arriving, that is not a stall.
    Stalled {
        /// How long the stream has been silent.
        silent_for: Duration,
    },
    /// Packets are arriving again.
    Resumed {
        /// How long the gap turned out to be.
        silent_for: Duration,
    },
    /// The call is over, with its media totals.
    ///
    /// The last event for the stream: the handle is released now, so everything an end-of-call
    /// record needs is included.
    Ended(StreamStatistics),
    /// The account asked for an RFC 6035 voice quality report and one publish attempt was made at
    /// call end.
    ///
    /// Only raised if the account named a collector (`Account::quality_report_uri` in `sipral_ua`).
    /// Never retried.
    QualityReportSent {
        /// Whether the PUBLISH was sent. Not whether a collector accepted it; this stack does not
        /// wait for that.
        ok: bool,
    },
    /// The far end pressed a key or sent another RFC 4733 named event.
    ///
    /// One event per keypress: RFC 4733 sends a run of updates and repeats the end packet three
    /// times (§2.5.1.4), all identified by the same RTP timestamp (§2.2.1), so they are collapsed.
    DigitReceived {
        /// The key, where the event names one; codes 16 and above have no key. Always `Some` for
        /// [`DigitSource::Info`] and [`DigitSource::InBand`].
        digit: Option<char>,
        /// The event code (§3.2), or for [`DigitSource::Info`] and [`DigitSource::InBand`] the code
        /// the character maps to.
        event: u8,
        /// How long the key was held. `None` when not stated: RFC 4733 and in-band digits always
        /// have a duration, `application/dtmf` INFO never does. `Duration=0` from the other INFO
        /// form is `Some(Duration::ZERO)` (8.3.11-ter).
        held: Option<Duration>,
        /// Which of the ways this stack accepts a digit reported this one.
        source: DigitSource,
    },
    /// What the far end's network played, or who answered: listened for on
    /// a call given a [`ProgressDetection`](crate::ProgressDetection).
    Progress(CallProgress),
    /// The DTLS handshake keying this call finished, and audio can flow.
    ///
    /// Between [`MediaEvent::Started`](MediaEvent::Started) and this event the stream exists but
    /// carries nothing either way. Show a padlock here;
    /// [`MediaSession::is_encrypted`](crate::MediaSession::is_encrypted) answers at any other time.
    /// SDES calls never raise it, since they are keyed before the session opens.
    #[cfg(feature = "dtls")]
    Secured {
        /// The transform the handshake agreed; with DTLS the handshake chooses it, not the
        /// signalling (RFC 5764 §4.1.2).
        suite: Suite,
        /// Where the far end's handshake records came from, which is also where its media is
        /// accepted from. `None` cannot happen for a completed handshake.
        peer: Option<SocketAddr>,
    },
    /// ICE chose the path this call's media takes (RFC 8445 §8.1.1).
    ///
    /// Explains why media goes to an address the signalling never named, which is normal behind a
    /// NAT. Raised again if a higher-priority nomination replaces the pair; each names the pair in
    /// force from then. Calls without ICE never raise it.
    #[cfg(feature = "ice")]
    PathChosen {
        /// This end of the pair: the socket the media goes out of.
        local: SocketAddr,
        /// The far end of it, which is where the media goes.
        remote: SocketAddr,
    },
    /// Media could not start or continue: an undecodable codec in the answer, an unreadable
    /// description.
    ///
    /// The call is left up; hanging up is the application's decision.
    Failed(MediaError),
    /// A recording stopped on its own: disk full, file removed, volume gone. An event, never an
    /// abort (B3); the call continues.
    RecordingStopped {
        /// Why the sink refused.
        reason: MediaError,
        /// How much audio reached the file before it did.
        written: Duration,
    },
    /// The call this one was joined to ended, ending the pair.
    ///
    /// The pairing from [`MediaEngine::join`](crate::MediaEngine::join) does not outlive either
    /// call. This call's session is untouched and continues with whatever
    /// [`MediaSession::playback`](crate::MediaSession::playback) and
    /// [`MediaSession::capture`](crate::MediaSession::capture) it is given directly.
    Unjoined,
    /// The far end typed on the real-time text stream (RFC 4103), in order.
    ///
    /// Raised as blocks arrive and are reordered, so one event may hold one keystroke or a burst.
    /// An unrecoverable lost block is marked and the text continues.
    TextReceived {
        /// The text: characters as typed, BACKSPACE (U+0008) for an erasure, LINE SEPARATOR
        /// (U+2028) for a new line, BELL (U+0007) for an alert, and REPLACEMENT CHARACTER (U+FFFD)
        /// where text was lost (RFC 4103 §5.3).
        text: String,
        /// Lost blocks: the number of REPLACEMENT CHARACTERs in `text` (RFC 4103 §5.3).
        missing: u32,
    },
}
