// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Pairing `sipral-headless`'s sans-I/O socket protocol with a live call's
//! media.
//!
//! `docs/07-headless.md`'s own "Real media" section is the design this
//! module is, and the reasoning for why it lives here rather than in
//! `sipral-headless` itself. In short: that crate stays a leaf that names no
//! Sipral crate, exactly as before, and this facade — already the one place
//! signalling and media are allowed to meet — is where a third sans-I/O
//! layer gets to meet both, behind its own `headless` Cargo feature.
//!
//! Everything below moves `i16` PCM and a handful of plain values across the
//! seam. Nothing here holds a `MediaSession` across a call it did not
//! receive as an argument, and nothing here opens a socket — an application
//! still owns the transport, on both sides of this module, exactly as
//! `docs/01-architecture.md`'s "who owns the sockets" section says it does
//! everywhere else in this tree.

use std::time::{Duration, Instant};

use sipral_headless::{
    AudioConfig, CallStateKind, DtmfDigit, DtmfReceived, Session as ProtocolSession, read_samples,
    write_samples,
};
use sipral_media::resample::{RateError, Resampler};
use sipral_media::vad::{Activity, Vad};
use sipral_ua::{CallHandle, UaEvent};

use crate::{Datagram, Digit, MediaError, MediaSession};

/// Why [`HeadlessSession::open`] or [`HeadlessSession::set_codec_rate`] could
/// not pair the socket's own rate with the codec's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeadlessMediaError {
    /// The two rates cannot be bridged — see
    /// [`sipral_media::resample::RateError`]'s own three reasons: a rate of
    /// zero, a reduction deeper than the resampler will filter, or a ratio
    /// whose filter bank would be too large.
    Rate(RateError),
    /// The socket's own frame duration and rate describe a frame with no
    /// samples in it, which no frame arithmetic here can make progress on.
    /// Every rate and the default duration `docs/07-headless.md` names
    /// cannot produce this; it is reachable only from a
    /// [`sipral_headless::AudioConfig`] built with an unusual frame
    /// duration of its own.
    EmptyFrame,
}

impl core::fmt::Display for HeadlessMediaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rate(error) => write!(f, "{error}"),
            Self::EmptyFrame => {
                f.write_str("the socket's frame duration and rate carry no samples")
            }
        }
    }
}

impl core::error::Error for HeadlessMediaError {}

impl From<RateError> for HeadlessMediaError {
    fn from(error: RateError) -> Self {
        Self::Rate(error)
    }
}

/// One call's `sipral-headless` session, paired with what sitting it against
/// a live [`MediaSession`] needs and that crate has no way to supply on its
/// own: a resampling filter each way, and a voice-activity detector run over
/// the caller's decoded audio.
///
/// Has no socket of its own either way. [`HeadlessSession::hear`] and
/// [`HeadlessSession::speak`] are the whole of its surface with `media`, and
/// an application drives them identically whether the frames on the other
/// side of this session came off a real socket or were never framed at all
/// — see `docs/07-headless.md#real-media` for both shapes.
#[derive(Debug)]
pub struct HeadlessSession {
    protocol: ProtocolSession,
    /// Samples in one of this session's own frames — cached at
    /// [`HeadlessSession::open`] rather than asked of `protocol.audio()`
    /// every call, and never zero: that case is refused up front instead.
    session_frame_samples: usize,
    /// Codec rate to the socket's own rate, for [`HeadlessSession::hear`].
    to_headless: Resampler,
    /// The socket's own rate to the codec's, for [`HeadlessSession::speak`].
    to_codec: Resampler,
    /// Resampled audio waiting to fill this session's own next frame.
    inbound: Vec<i16>,
    /// Resampled audio waiting to fill the codec's next frame.
    outbound: Vec<i16>,
    voice: Vad,
    speaking: bool,
}

impl HeadlessSession {
    /// Opens a session for `call_id`, on the socket's own `audio`, matched to
    /// `codec_rate` — [`MediaSession::sample_rate`]'s own answer for the call
    /// this pairs with, read from the live negotiation rather than picked
    /// ahead of it.
    ///
    /// # Errors
    /// [`HeadlessMediaError`] when the two rates cannot be bridged, or when
    /// `audio` describes a frame with no samples in it.
    pub fn open(
        call_id: String,
        audio: AudioConfig,
        codec_rate: u32,
        capture_capacity: usize,
        playback_capacity: usize,
    ) -> Result<Self, HeadlessMediaError> {
        let headless_rate = audio.sample_rate().hz();
        let session_frame_samples =
            usize::try_from(audio.frame_samples().unwrap_or(0)).unwrap_or(0);
        if session_frame_samples == 0 {
            return Err(HeadlessMediaError::EmptyFrame);
        }
        Ok(Self {
            protocol: ProtocolSession::new(call_id, audio, capture_capacity, playback_capacity),
            session_frame_samples,
            to_headless: Resampler::new(codec_rate, headless_rate)?,
            to_codec: Resampler::new(headless_rate, codec_rate)?,
            inbound: Vec::new(),
            outbound: Vec::new(),
            voice: Vad::new(codec_rate),
            speaking: false,
        })
    }

    /// This call's socket protocol state and queues, exactly as
    /// `sipral-headless` defines them: session lifecycle, latency budget, and
    /// the two frame queues' own depth and drop counters.
    #[must_use]
    pub const fn protocol(&self) -> &ProtocolSession {
        &self.protocol
    }

    /// Mutable access to the same state, for answering, holding or ending the
    /// call and for reading the frames [`HeadlessSession::speak`] has not
    /// consumed yet.
    pub const fn protocol_mut(&mut self) -> &mut ProtocolSession {
        &mut self.protocol
    }

    /// Rebuilds the resampling filters and this call's voice-activity
    /// detector for a call that re-negotiated onto a different codec
    /// mid-call (`sipral::MediaEvent::Changed`'s own `codec`). The socket
    /// session's own state and queues are untouched — only the filters
    /// between them and the codec move.
    ///
    /// # Errors
    /// See [`HeadlessSession::open`].
    pub fn set_codec_rate(&mut self, codec_rate: u32) -> Result<(), HeadlessMediaError> {
        let headless_rate = self.protocol.audio().sample_rate().hz();
        self.to_headless = Resampler::new(codec_rate, headless_rate)?;
        self.to_codec = Resampler::new(headless_rate, codec_rate)?;
        self.inbound.clear();
        self.outbound.clear();
        self.voice = Vad::new(codec_rate);
        Ok(())
    }

    /// One [`MediaSession::playback`]-sized frame of the caller's decoded
    /// audio in — read again rather than reached into, since `sipral-media`
    /// and `sipral-headless` still do not know about each other. Run past
    /// this call's voice-activity detector, resampled to the socket's own
    /// rate and queued as whole frames onto
    /// [`sipral_headless::Session::push_capture`] — the oldest queued frame
    /// evicted first if the agent has not kept up, per that crate's own drop
    /// policy.
    ///
    /// `Some(speaking)` the frame this call's voice activity changed, ready
    /// to become a [`sipral_headless::VoiceActivity`] control message;
    /// `None` on every frame that agrees with what the last one reported.
    pub fn hear(&mut self, decoded: &[i16]) -> Option<bool> {
        let now_speaking = matches!(self.voice.process(decoded), Activity::Speech);
        let changed = (now_speaking != self.speaking).then_some(now_speaking);
        self.speaking = now_speaking;

        accumulate(&mut self.to_headless, decoded, &mut self.inbound);

        let frame = self.session_frame_samples;
        let mut offset = 0;
        while self.inbound.len().saturating_sub(offset) >= frame {
            let mut bytes = Vec::with_capacity(frame * 2);
            write_samples(
                self.inbound.get(offset..offset + frame).unwrap_or(&[]),
                &mut bytes,
            );
            // an invalid frame size cannot reach `push_capture` from here —
            // `bytes` is exactly `frame` samples by construction — and the
            // only other refusal, the call having ended, is one this
            // session's own audio has nowhere useful to go for either way
            let _ = self.protocol.push_capture(bytes);
            offset += frame;
        }
        self.inbound.drain(..offset);

        changed
    }

    /// Fills `room` with the agent's own outgoing audio, resampled to
    /// whatever rate `room`'s own samples are at (the codec's) and drawn from
    /// [`sipral_headless::Session::pop_playback`] as needed.
    ///
    /// Always fills the whole of `room`, the way [`MediaSession::playback`]
    /// always fills the whole of its own buffer: with real audio once the
    /// queue has given up a whole frame's worth, with silence, sample for
    /// sample, on every frame it has not — which is what lets this sit
    /// directly in a paced caller's own "always give me a frame" seam, such
    /// as `crates/sipral/examples/common/media_socket.rs`'s own
    /// `MediaSocket::turn`'s `source` closure. Nothing queued is lost on a
    /// silent frame: what had not reached a whole frame yet is kept for the
    /// next call to finish.
    ///
    /// `true` once real audio filled the whole of `room`; `false` on a frame
    /// of silence — ordinary while the queue has not caught up yet, and
    /// otherwise a stalled agent's own signal that nothing is coming.
    pub fn fill_outbound(&mut self, room: &mut [i16]) -> bool {
        while self.outbound.len() < room.len() {
            let Some(bytes) = self.protocol.pop_playback() else {
                break;
            };
            let samples: Vec<i16> = read_samples(&bytes).collect();
            accumulate(&mut self.to_codec, &samples, &mut self.outbound);
        }
        if self.outbound.len() < room.len() {
            room.fill(0);
            return false;
        }
        let taken: Vec<i16> = self.outbound.drain(..room.len()).collect();
        room.copy_from_slice(&taken);
        true
    }

    /// [`HeadlessSession::fill_outbound`], sent straight on as one of
    /// `media`'s own frames — [`MediaSession::capture`]'s own contract,
    /// `Ok(None)` when nothing was due to go out yet, which is ordinary while
    /// a whole frame has not accumulated. The pair a caller driving `media`
    /// by hand uses instead of `fill_outbound` and `media.capture` apart —
    /// see `docs/07-headless.md#real-media`'s own description of that shape.
    ///
    /// # Errors
    /// Whatever [`MediaSession::capture`] itself refuses. Resampling here
    /// cannot fail once this session is open: [`HeadlessSession::open`] and
    /// [`HeadlessSession::set_codec_rate`] already proved the two rates make
    /// a filter.
    pub fn speak<'m>(
        &mut self,
        media: &'m mut MediaSession,
        now: Instant,
    ) -> Result<Option<Datagram<'m>>, MediaError> {
        let frame = media.frame_samples();
        let mut room = vec![0_i16; frame];
        if !self.fill_outbound(&mut room) {
            return Ok(None);
        }
        media.capture(&room, now)
    }
}

/// Resamples `input` through `resampler` and appends whatever it produced to
/// `scratch`.
fn accumulate(resampler: &mut Resampler, input: &[i16], scratch: &mut Vec<i16>) {
    let needed = resampler.output_capacity(input.len());
    let start = scratch.len();
    scratch.resize(start + needed, 0);
    let produced = match scratch
        .get_mut(start..)
        .map(|room| resampler.process(input, room))
    {
        Some(Ok(produced)) => produced,
        // `scratch` was just grown to `output_capacity`'s own answer for
        // this input, so neither branch here is reachable from a caller's
        // mistake; nothing is corrupted either way — the audio simply does
        // not advance on this call, and the next one still catches up
        Some(Err(_)) | None => 0,
    };
    scratch.truncate(start + produced);
}

/// Which call a `sipral_ua::UaEvent` is about, and the socket's own
/// [`CallStateKind`] for what it says, or `None` for every event that is not
/// one of the three transitions the protocol names on the wire —
/// session-local `Held` has no wire counterpart, per
/// [`sipral_headless::SessionState`]'s own documentation, and every other
/// `UaEvent` is not about a call's own lifecycle at all.
///
/// The call comes back with the state because an agent's stack hears about
/// every call on it, not only the one a session carries: a second INVITE
/// refused while the first is up ends too, and its `CallEnded` is not the
/// first call's. Compare the handle before putting a
/// [`CallState`](sipral_headless::CallState) on the wire under a session's
/// `call_id`.
#[must_use]
pub fn call_state_of(event: &UaEvent) -> Option<(CallHandle, CallStateKind)> {
    match event {
        UaEvent::IncomingCall { call, .. } => Some((*call, CallStateKind::Ringing)),
        UaEvent::CallConfirmed { call, .. } => Some((*call, CallStateKind::Answered)),
        UaEvent::CallEnded { call, reason, .. } => Some((
            *call,
            CallStateKind::Ended {
                reason: Some(reason.to_string()),
            },
        )),
        _ => None,
    }
}

/// A digit `sipral::MediaEvent::DigitReceived` reported, as the socket's own
/// [`DtmfReceived`] — `None` for an RFC 4733 event code outside the sixteen
/// keys [`DtmfDigit`] names, which no keypad has a key for and the socket
/// protocol therefore has no way to carry.
#[must_use]
pub fn dtmf_received_of(
    call_id: String,
    digit: Option<char>,
    held: Option<Duration>,
) -> Option<DtmfReceived> {
    let digit = DtmfDigit::new(digit?)?;
    let duration_ms = held.map(|held| u32::try_from(held.as_millis()).unwrap_or(u32::MAX));
    Some(DtmfReceived {
        call_id,
        digit,
        duration_ms,
    })
}

/// Sends the socket's own `DtmfSend` digit out on `media`, for `duration`.
///
/// # Errors
/// Whatever [`MediaSession::send_dtmf`] itself refuses: no telephone-event
/// payload type in this call's negotiation, or a length outside what RFC
/// 4733 sends.
pub fn send_digit(
    media: &mut MediaSession,
    digit: DtmfDigit,
    duration: Duration,
) -> Result<(), MediaError> {
    let Some(key) = Digit::from_char(digit.get()) else {
        // unreachable: `sipral_headless::DtmfDigit` and `sipral::Digit` both
        // parse exactly RFC 4733's sixteen-event alphabet, so every
        // character `DtmfDigit::get` returns is one `Digit::from_char`
        // accepts. Written as a real refusal rather than unwrapped, on this
        // crate's own no-panic discipline.
        return Err(MediaError::UnknownDigit { key: digit.get() });
    };
    media.send_dtmf(key, duration)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sipral_headless::{AudioConfig, DtmfDigit, SampleRate};

    use super::{HeadlessMediaError, HeadlessSession, dtmf_received_of};

    fn audio() -> AudioConfig {
        AudioConfig::new(SampleRate::Hz8000)
    }

    #[test]
    fn opening_at_matching_rates_builds_passthrough_filters() {
        let session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        assert_eq!(session.session_frame_samples, 160);
    }

    #[test]
    fn opening_at_a_codec_rate_the_resampler_refuses_is_an_error() {
        // ten to one is past what `sipral_media::resample` will filter
        let error = HeadlessSession::open("call-1".to_owned(), audio(), 80_000, 4, 4)
            .expect_err("decimation too deep");
        assert!(matches!(error, HeadlessMediaError::Rate(_)));
    }

    #[test]
    fn hearing_silence_reports_no_voice_activity_change_but_still_queues_the_frame() {
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        let silence = vec![0_i16; 160];
        // a fresh detector starts on `Silence`'s own side of the change, so
        // the very first silent frame reports no change either — but the
        // frame is still the caller's audio and still reaches the agent, a
        // pause is not the same fact as nothing having arrived
        assert_eq!(session.hear(&silence), None);
        assert_eq!(session.protocol().capture_depth(), 1);
    }

    #[test]
    fn a_loud_frame_reports_speech_started_and_queues_it_for_the_agent() {
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        let tone: Vec<i16> = (0..160)
            .map(|n| if n % 2 == 0 { 20_000 } else { -20_000 })
            .collect();
        assert_eq!(session.hear(&tone), Some(true));
        assert_eq!(session.hear(&tone), None, "still speaking, no change");
        assert_eq!(session.protocol().capture_depth(), 2);
    }

    #[test]
    fn hearing_at_a_different_codec_rate_resamples_to_whole_session_frames() {
        // 48 kHz codec audio into an 8 kHz session, six to one and well
        // inside the resampler's eightfold limit: six codec frames of 960
        // samples each (120 ms) resample down to about six session frames of
        // 160 — within one, for the half-kernel of history the filter holds
        // back at the start of the stream
        let mut session = HeadlessSession::open("call-1".to_owned(), audio(), 48_000, 20, 20)
            .expect("six to one bridges fine");
        for _ in 0..6 {
            session.hear(&[0_i16; 960]);
        }
        assert!(
            (5..=6).contains(&session.protocol().capture_depth()),
            "capture depth: {}",
            session.protocol().capture_depth()
        );
        assert_eq!(session.protocol().capture_dropped(), 0);
    }

    // `call_state_of` reads `sipral_ua::UaEvent` — every variant carries a
    // `CallHandle` or an `AccountId`, both minted only by a running
    // `UserAgent`, so there is no way to build one to test against from
    // outside that crate. It is exercised end to end, with a real call's own
    // events, by `crates/sipral/tests/headless_bridge.rs`.

    #[test]
    fn dtmf_received_of_maps_a_recognised_key() {
        let received = dtmf_received_of(
            "call-1".to_owned(),
            Some('5'),
            Some(Duration::from_millis(120)),
        )
        .expect("a keypad digit");
        assert_eq!(received.call_id, "call-1");
        assert_eq!(received.digit, DtmfDigit::new('5').expect("valid digit"));
        assert_eq!(received.duration_ms, Some(120));
    }

    #[test]
    fn dtmf_received_of_answers_nothing_for_an_event_code_no_keypad_has() {
        assert_eq!(dtmf_received_of("call-1".to_owned(), None, None), None);
    }

    #[test]
    fn set_codec_rate_rebuilds_the_filters_without_touching_the_protocol_state() {
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        session.protocol_mut().answer().expect("ringing to active");
        session
            .set_codec_rate(16_000)
            .expect("sixteen kilohertz bridges fine");
        assert!(session.protocol().is_up());
    }

    // `HeadlessSession::speak` needs a live `MediaSession`, which is built
    // only by a negotiated call (`MediaSession::open` is `pub(crate)`); it is
    // exercised end to end by `crates/sipral/tests/headless_bridge.rs`.
}
