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
    /// [`sipral_headless::Session::barge_ins`] as of the last time
    /// `outbound` was filled: a different number now means what `outbound`
    /// holds is the tail of speech the agent abandoned.
    barge_ins: u64,
    /// Run over the caller's audio at the socket's own rate, which is fixed
    /// for the session, rather than at the codec's, which a re-negotiation
    /// can move: a detector rebuilt mid-call starts with no hangover and no
    /// noise floor, and reads the next quiet frame of a word as its end.
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
            barge_ins: 0,
            voice: Vad::new(headless_rate),
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

    /// Rebuilds the resampling filters for a call that re-negotiated onto a
    /// codec at a different rate mid-call (`sipral::MediaEvent::Changed`'s
    /// own `codec`). Safe to call on every `Changed`: a hold, a resume or a
    /// moved address arrives as one too, with the rate the call already had,
    /// and that changes nothing here — not the filters' history, not a
    /// sample already resampled.
    ///
    /// On a real change only what is at the codec's rate goes: the two
    /// filters, and whatever of the agent's audio was already resampled to
    /// the old rate and waiting for the next frame. The caller's audio
    /// already at the socket's own rate stays, and so do the socket
    /// session's state and queues and the voice-activity detector, which
    /// reads the socket's rate and so never has a reason to start over.
    ///
    /// # Errors
    /// See [`HeadlessSession::open`]; nothing is changed when the new rate
    /// is refused.
    pub fn set_codec_rate(&mut self, codec_rate: u32) -> Result<(), HeadlessMediaError> {
        if codec_rate == self.to_headless.input_rate() {
            return Ok(());
        }
        let headless_rate = self.protocol.audio().sample_rate().hz();
        let to_headless = Resampler::new(codec_rate, headless_rate)?;
        let to_codec = Resampler::new(headless_rate, codec_rate)?;
        self.to_headless = to_headless;
        self.to_codec = to_codec;
        self.outbound.clear();
        Ok(())
    }

    /// One [`MediaSession::playback`]-sized frame of the caller's decoded
    /// audio in — read again rather than reached into, since `sipral-media`
    /// and `sipral-headless` still do not know about each other. Resampled
    /// to the socket's own rate, run past this call's voice-activity
    /// detector there, and queued as whole frames onto
    /// [`sipral_headless::Session::push_capture`] — the oldest queued frame
    /// evicted first if the agent has not kept up, per that crate's own drop
    /// policy.
    ///
    /// `Some(speaking)` the frame this call's voice activity changed, ready
    /// to become a [`sipral_headless::VoiceActivity`] control message;
    /// `None` on every frame that agrees with what the last one reported,
    /// and on one too short to judge — fewer than two samples at the
    /// socket's rate, which says nothing about speech either way.
    pub fn hear(&mut self, decoded: &[i16]) -> Option<bool> {
        let fresh = self.inbound.len();
        accumulate(&mut self.to_headless, decoded, &mut self.inbound);

        let heard = self.inbound.get(fresh..).unwrap_or_default();
        let changed = if heard.len() < 2 {
            None
        } else {
            let now_speaking = matches!(self.voice.process(heard), Activity::Speech);
            let changed = (now_speaking != self.speaking).then_some(now_speaking);
            self.speaking = now_speaking;
            changed
        };

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
    /// next call to finish — unless the agent barged in since
    /// ([`sipral_headless::Session::barge_in`]), in which case what was kept
    /// is the tail of the speech it abandoned and goes with the queue,
    /// rather than playing ahead of whatever it says next.
    ///
    /// `true` once real audio filled the whole of `room`; `false` on a frame
    /// of silence — ordinary while the queue has not caught up yet, and
    /// otherwise a stalled agent's own signal that nothing is coming.
    pub fn fill_outbound(&mut self, room: &mut [i16]) -> bool {
        let barge_ins = self.protocol.barge_ins();
        if barge_ins != self.barge_ins {
            self.barge_ins = barge_ins;
            self.outbound.clear();
            self.to_codec.reset();
        }
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
    /// `media`'s own frames, once per media tick whether the agent had
    /// anything to say or not: a frame of silence is still a frame to
    /// [`MediaSession::capture`], which is where the RTP clock moves on
    /// (RFC 3550 §5.1), where a digit queued by [`send_digit`] goes out, and
    /// where silence suppression — the session's to configure, not this
    /// type's — decides whether the frame is sent at all. Skipping the call
    /// on an agent's silence would do all three wrong: the timestamp would
    /// stop while the call went on, a digit sent by an agent that is not
    /// talking would never leave, and a listening agent's far end would hear
    /// no RTP at all and could take the call for dead.
    ///
    /// [`MediaSession::capture`]'s own contract otherwise: `Ok(None)` for a
    /// frame deliberately not sent. The pair a caller driving `media` by hand
    /// uses instead of `fill_outbound` and `media.capture` apart — see
    /// `docs/07-headless.md#real-media`'s own description of that shape.
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
        self.fill_outbound(&mut room);
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
    use std::time::{Duration, Instant};

    use sipral_core::sdp::{Direction, MediaPlan, NegotiatedCodec, RtcpPlan, RtpMap};
    use sipral_headless::{AudioConfig, DtmfDigit, SampleRate, write_samples};

    use super::{HeadlessMediaError, HeadlessSession, dtmf_received_of, send_digit};
    use crate::MediaSession;
    use crate::clock::WallClock;
    use crate::session::{MediaConfig, Start, StreamIdentity};

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

    /// A PCMU stream with telephone-events on 101, opened the way the engine
    /// opens one but with no user agent: enough for `speak` to put real
    /// datagrams out of, which is all the tests below read.
    fn media() -> MediaSession {
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
            dtmf: Some(101),
            rtcp: RtcpPlan::Off,
            keying: None,
            voip_metrics_xr: false,
        };
        MediaSession::open(
            &plan,
            20,
            &MediaConfig::default(),
            Vec::new(),
            Start {
                identity: StreamIdentity {
                    ssrc: 1,
                    sequence: 0,
                    timestamp: 0,
                    seed: 1,
                },
                clock: WallClock::from_unix(now, 1_700_000_000, 0),
                #[cfg(feature = "dtls")]
                handshake: None,
                #[cfg(feature = "ice")]
                ice: None,
                now,
            },
        )
        .expect("PCMU is always in this build's catalogue")
    }

    fn payload_type(datagram: &[u8]) -> u8 {
        datagram[1] & 0x7F
    }

    fn timestamp(datagram: &[u8]) -> u32 {
        u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]])
    }

    fn tone(len: usize, amplitude: i16) -> Vec<i16> {
        (0..len)
            .map(|n| if n % 2 == 0 { amplitude } else { -amplitude })
            .collect()
    }

    fn frame_of(samples: &[i16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_samples(samples, &mut bytes);
        bytes
    }

    #[test]
    fn a_digit_the_agent_sends_goes_out_while_the_agent_itself_is_silent() {
        // an IVR is navigated by an agent that is not talking: the digit is
        // the whole of what it has to say, and nothing is on its playback
        // queue while it says it
        let mut media = media();
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        send_digit(
            &mut media,
            DtmfDigit::new('5').expect("a key"),
            Duration::from_millis(100),
        )
        .expect("telephone-events were negotiated");
        let sent = session
            .speak(&mut media, Instant::now())
            .expect("a frame")
            .map(|datagram| payload_type(datagram.payload));
        assert_eq!(sent, Some(101), "the digit's first packet");
    }

    #[test]
    fn the_rtp_clock_keeps_running_while_the_agent_is_silent() {
        // RFC 3550 §5.1: the timestamp measures time, not packets. Three
        // ticks of an agent with nothing to say, then one frame of speech:
        // that frame is sixty milliseconds after the stream began, 480
        // ticks at 8 kHz, not the first frame of the stream
        let mut media = media();
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        let now = Instant::now();
        for _ in 0..3 {
            let _ = session.speak(&mut media, now).expect("no error");
        }
        session
            .protocol_mut()
            .push_playback(frame_of(&tone(160, 8_000)))
            .expect("one frame");
        let stamp = session
            .speak(&mut media, now)
            .expect("no error")
            .map(|datagram| timestamp(datagram.payload));
        assert_eq!(stamp, Some(480));
    }

    #[test]
    fn a_barge_in_leaves_nothing_of_the_interrupted_audio_to_play() {
        // thirty-millisecond socket frames against a twenty-millisecond
        // codec frame: every frame the agent sent leaves ten milliseconds
        // already resampled and waiting, which is exactly what a barge-in
        // has to throw away along with the queue
        let socket = AudioConfig::with_frame_duration_ms(SampleRate::Hz8000, 30).expect("fits");
        let mut session =
            HeadlessSession::open("call-1".to_owned(), socket, 8_000, 4, 4).expect("same rate");
        session
            .protocol_mut()
            .push_playback(frame_of(&[1_000; 240]))
            .expect("one frame");
        let mut room = [0_i16; 160];
        assert!(session.fill_outbound(&mut room));

        session.protocol_mut().barge_in();
        session
            .protocol_mut()
            .push_playback(frame_of(&[-1_000; 240]))
            .expect("one frame");
        assert!(session.fill_outbound(&mut room));
        assert!(
            room.iter().all(|&sample| sample == -1_000),
            "interrupted audio played after the barge-in: {:?}",
            room.iter().filter(|&&sample| sample == 1_000).count()
        );
    }

    #[test]
    fn a_renegotiation_onto_the_same_rate_does_not_end_speech_early() {
        // a hold, a resume or a moved address is `MediaEvent::Changed` with
        // the codec it already had; the caller who was talking a frame ago
        // is still inside the detector's hangover, and one quiet frame is a
        // closure in a word, not the end of it
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        assert_eq!(session.hear(&[0; 160]), None);
        assert_eq!(session.hear(&tone(160, 20_000)), Some(true));
        session.set_codec_rate(8_000).expect("same rate");
        assert_eq!(session.hear(&[0; 160]), None);
    }

    #[test]
    fn a_codec_change_mid_word_does_not_end_speech_early() {
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        assert_eq!(session.hear(&[0; 160]), None);
        assert_eq!(session.hear(&tone(160, 20_000)), Some(true));
        session.set_codec_rate(16_000).expect("two to one");
        assert_eq!(session.hear(&[0; 320]), None);
    }

    #[test]
    fn a_codec_change_keeps_the_callers_audio_already_at_the_socket_rate() {
        // 160 samples already resampled to the socket's own 8 kHz wait for
        // the rest of a thirty-millisecond frame; the codec moving to 16 kHz
        // changes nothing about them
        let socket = AudioConfig::with_frame_duration_ms(SampleRate::Hz8000, 30).expect("fits");
        let mut session =
            HeadlessSession::open("call-1".to_owned(), socket, 8_000, 4, 4).expect("same rate");
        let _ = session.hear(&[0; 160]);
        assert_eq!(session.protocol().capture_depth(), 0);
        session.set_codec_rate(16_000).expect("two to one");
        let _ = session.hear(&[0; 320]);
        assert_eq!(session.protocol().capture_depth(), 1);
    }

    /// `len` samples of a 440 Hz sine at `rate`, starting `start` samples
    /// into it, at half of full scale.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn sine(rate: u32, start: usize, len: usize) -> Vec<i16> {
        (start..start + len)
            .map(|n| {
                let phase = 2.0 * std::f64::consts::PI * 440.0 * n as f64 / f64::from(rate);
                (phase.sin() * 16_000.0).round() as i16
            })
            .collect()
    }

    /// That `samples` at `rate` are still [`sine`]'s 440 Hz, past a quarter
    /// of them left for the filter's own start: 880 zero crossings a second,
    /// within three.
    fn assert_in_tune(samples: &[i16], rate: u32, case: &str) {
        let settled = samples.get(samples.len() / 4..).unwrap();
        let got = settled
            .windows(2)
            .filter(|pair| (pair[0] < 0) != (pair[1] < 0))
            .count();
        let want = 880 * settled.len() / usize::try_from(rate).unwrap();
        assert!(
            got.abs_diff(want) <= 3,
            "{case}: {got} zero crossings for {want}"
        );
    }

    /// Every sample the caller's side has produced at the socket's rate:
    /// whole frames on the capture queue plus what waits to become one.
    fn heard_so_far(session: &HeadlessSession) -> usize {
        session.protocol().capture_depth() * session.session_frame_samples + session.inbound.len()
    }

    fn rate(hz: u32) -> SampleRate {
        SampleRate::try_from(hz).expect("one of the four")
    }

    /// Socket and codec frame durations in milliseconds: equal, and each
    /// way around a pair where neither divides the other's sample count.
    const DURATIONS: [(u32, u32); 4] = [(20, 20), (30, 20), (20, 30), (10, 30)];
    const RATES: [u32; 4] = [8_000, 16_000, 24_000, 48_000];

    #[test]
    fn every_rate_pair_hears_the_caller_in_real_time_and_at_the_right_pitch() {
        for socket_hz in RATES {
            for codec_hz in RATES {
                for (socket_ms, codec_ms) in DURATIONS {
                    let socket =
                        AudioConfig::with_frame_duration_ms(rate(socket_hz), socket_ms).unwrap();
                    let mut session =
                        HeadlessSession::open("c".to_owned(), socket, codec_hz, 1_000, 1_000)
                            .unwrap();
                    let codec_frame = usize::try_from(codec_hz * codec_ms / 1_000).unwrap();
                    let frames = usize::try_from(300 / codec_ms).unwrap();
                    let case = format!("{socket_hz}/{socket_ms} ms <- {codec_hz}/{codec_ms} ms");
                    for n in 0..frames {
                        session.hear(&sine(codec_hz, n * codec_frame, codec_frame));
                    }
                    let first = heard_so_far(&session);
                    for n in frames..2 * frames {
                        session.hear(&sine(codec_hz, n * codec_frame, codec_frame));
                    }
                    // the second run carries exactly its own length in time,
                    // to the sample: no drift, whatever the frame sizes
                    let expected = frames * codec_frame * usize::try_from(socket_hz).unwrap()
                        / usize::try_from(codec_hz).unwrap();
                    let second = heard_so_far(&session) - first;
                    assert!(
                        second.abs_diff(expected) <= 1,
                        "{case}: {second} samples for {expected}"
                    );
                    assert_eq!(session.protocol().capture_dropped(), 0, "{case}");

                    let mut delivered = Vec::new();
                    while let Some(bytes) = session.protocol_mut().pop_capture() {
                        delivered.extend(sipral_headless::read_samples(&bytes));
                    }
                    assert_in_tune(&delivered, socket_hz, &case);
                }
            }
        }
    }

    #[test]
    fn every_rate_pair_speaks_the_agent_in_real_time_and_at_the_right_pitch() {
        for socket_hz in RATES {
            for codec_hz in RATES {
                for (socket_ms, codec_ms) in DURATIONS {
                    let socket =
                        AudioConfig::with_frame_duration_ms(rate(socket_hz), socket_ms).unwrap();
                    let mut session =
                        HeadlessSession::open("c".to_owned(), socket, codec_hz, 1_000, 1_000)
                            .unwrap();
                    let socket_frame = usize::try_from(socket_hz * socket_ms / 1_000).unwrap();
                    let codec_frame = usize::try_from(codec_hz * codec_ms / 1_000).unwrap();
                    let case = format!("{socket_hz}/{socket_ms} ms -> {codec_hz}/{codec_ms} ms");
                    let pushed = usize::try_from(600 / socket_ms).unwrap();
                    for n in 0..pushed {
                        session
                            .protocol_mut()
                            .push_playback(frame_of(&sine(
                                socket_hz,
                                n * socket_frame,
                                socket_frame,
                            )))
                            .unwrap();
                    }
                    let mut sent = Vec::new();
                    let mut room = vec![0_i16; codec_frame];
                    while session.fill_outbound(&mut room) {
                        sent.extend_from_slice(&room);
                    }
                    // every sample pushed came out, less what the filter
                    // still holds — at most a kernel's worth of input, at
                    // the codec's rate once it comes out — and the part of
                    // one frame left over
                    let (socket_rate, codec_rate) = (
                        usize::try_from(socket_hz).unwrap(),
                        usize::try_from(codec_hz).unwrap(),
                    );
                    let expected = pushed * socket_frame * codec_rate / socket_rate;
                    let produced = sent.len() + session.outbound.len();
                    let slack = session.to_codec.taps() * codec_rate / socket_rate + 1;
                    assert!(
                        produced <= expected + 1 && expected - produced <= slack,
                        "{case}: {produced} samples for {expected}"
                    );
                    assert_in_tune(&sent, codec_hz, &case);
                }
            }
        }
    }

    #[test]
    fn a_codec_rate_change_mid_call_keeps_the_caller_in_real_time_and_in_tune() {
        // G.711 at 8 kHz re-negotiated onto Opus at 48 kHz, into a 16 kHz
        // socket, and back
        let mut session = HeadlessSession::open(
            "c".to_owned(),
            AudioConfig::new(rate(16_000)),
            8_000,
            1_000,
            1_000,
        )
        .unwrap();
        let mut at = 0;
        for codec_hz in [8_000_u32, 48_000, 8_000] {
            session.set_codec_rate(codec_hz).unwrap();
            let frame = usize::try_from(codec_hz / 50).unwrap();
            let start = heard_so_far(&session);
            for _ in 0..25 {
                session.hear(&sine(codec_hz, at * frame, frame));
                at += 1;
            }
            let middle = heard_so_far(&session);
            for _ in 0..25 {
                session.hear(&sine(codec_hz, at * frame, frame));
                at += 1;
            }
            // half a second at 16 kHz once the new filter is running, to the
            // sample, and the first half within the filter's own start
            assert!(
                (heard_so_far(&session) - middle).abs_diff(8_000) <= 1,
                "{codec_hz}: {}",
                heard_so_far(&session) - middle
            );
            assert!(
                (middle - start).abs_diff(8_000) <= 200,
                "{codec_hz}: {}",
                middle - start
            );
        }
        let mut delivered = Vec::new();
        while let Some(bytes) = session.protocol_mut().pop_capture() {
            delivered.extend(sipral_headless::read_samples(&bytes));
        }
        for (codec_hz, third) in [8_000, 48_000, 8_000]
            .into_iter()
            .zip(delivered.chunks(delivered.len() / 3))
        {
            assert_in_tune(third, 16_000, &format!("while the codec ran at {codec_hz}"));
        }
    }

    #[test]
    fn hearing_nothing_reports_no_change_in_voice_activity() {
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        assert_eq!(session.hear(&[0; 160]), None);
        assert_eq!(session.hear(&[]), None);
    }
}
