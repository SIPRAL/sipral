// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Pairs `sipral-headless`'s sans-I/O socket protocol with a live call's media.
//!
//! The design is the "Real media" section of `docs/07-headless.md`. `sipral-headless` stays a leaf
//! that names no Sipral crate; this facade, where signalling and media already meet, joins it
//! behind the `headless` feature.
//!
//! Only `i16` PCM and plain values cross here. No `MediaSession` is held beyond the call that
//! passed it, and no socket is opened: the application owns the transport on both sides
//! (`docs/01-architecture.md`).

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
    /// The rates cannot be bridged; see [`sipral_media::resample::RateError`]: a zero rate, too
    /// deep a reduction, or too large a filter bank.
    Rate(RateError),
    /// The socket's frame duration and rate give a frame of zero samples. Unreachable through
    /// `sipral-headless` (it refuses zero durations); kept so this type never divides by zero.
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

/// One call's `sipral-headless` session plus what pairing it with a live [`MediaSession`] needs: a
/// resampler each way and a voice activity detector on the caller's decoded audio.
///
/// No socket either way. [`HeadlessSession::hear`] and [`HeadlessSession::speak`] are its whole
/// interface to `media`, whether or not real socket frames are involved
/// (`docs/07-headless.md#real-media`).
#[derive(Debug)]
pub struct HeadlessSession {
    protocol: ProtocolSession,
    /// Samples per session frame, cached at [`HeadlessSession::open`]; never zero, since that is
    /// refused there.
    session_frame_samples: usize,
    /// Codec rate to the socket's own rate, for [`HeadlessSession::hear`].
    to_headless: Resampler,
    /// The socket's own rate to the codec's, for [`HeadlessSession::speak`].
    to_codec: Resampler,
    /// Resampled audio waiting to fill this session's own next frame.
    inbound: Vec<i16>,
    /// Resampled audio waiting to fill the codec's next frame.
    outbound: Vec<i16>,
    /// [`sipral_headless::Session::barge_ins`] when `outbound` was last filled. A different value
    /// means `outbound` holds the tail of abandoned speech.
    barge_ins: u64,
    /// Runs at the socket's rate, which is fixed, not the codec's, which a renegotiation can
    /// change: a rebuilt detector loses its hangover and noise floor and would end a word at its
    /// next quiet frame.
    voice: Vad,
    speaking: bool,
}

impl HeadlessSession {
    /// Open a session for `call_id` on the socket's `audio`, matched to `codec_rate` (the call's
    /// [`MediaSession::sample_rate`] from the live negotiation).
    ///
    /// # Errors
    ///
    /// [`HeadlessMediaError`] when the rates cannot be bridged or `audio` gives a zero-sample
    /// frame.
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

    /// This call's socket protocol state and queues as `sipral-headless` defines them: lifecycle,
    /// latency budget, queue depths and drop counters.
    #[must_use]
    pub const fn protocol(&self) -> &ProtocolSession {
        &self.protocol
    }

    /// Mutable access to the same, to answer, hold or end the call and read frames
    /// [`HeadlessSession::speak`] has not consumed.
    pub const fn protocol_mut(&mut self) -> &mut ProtocolSession {
        &mut self.protocol
    }

    /// Rebuild the resamplers after the call renegotiated to a codec at another rate
    /// (`sipral::MediaEvent::Changed`'s `codec`). Safe on every `Changed`: hold, resume or a moved
    /// address keep the rate and change nothing here.
    ///
    /// On a real change only codec-rate state is dropped: both filters and agent audio already
    /// resampled to the old rate. Caller audio at the socket rate, the protocol state and queues,
    /// and the detector (which runs at the socket rate) are kept.
    ///
    /// # Errors
    ///
    /// As [`HeadlessSession::open`]; nothing changes when the rate is refused.
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

    /// Feed one [`MediaSession::playback`]-sized frame of the caller's decoded audio: resampled to
    /// the socket rate, run through the voice detector, and queued as whole frames with
    /// [`sipral_headless::Session::push_capture`] (oldest dropped first if the agent lags, per that
    /// crate's policy).
    ///
    /// `Some(speaking)` when voice activity changed, ready to become a
    /// [`sipral_headless::VoiceActivity`] message; `None` when unchanged, or for a frame under two
    /// samples at the socket rate.
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
            // frame size is right by construction; the only other refusal is an ended call, where
            // the audio has nowhere to go anyway
            let _ = self.protocol.push_capture(bytes);
            offset += frame;
        }
        self.inbound.drain(..offset);

        changed
    }

    /// Fill `room` with the agent's outgoing audio, resampled to `room`'s rate (the codec's),
    /// pulling from [`sipral_headless::Session::pop_playback`] as needed.
    ///
    /// Always fills all of `room`, like [`MediaSession::playback`]: real audio once the queue has a
    /// whole frame, silence otherwise, so it fits a paced "always give me a frame" loop such as
    /// `MediaSocket::turn` in `crates/sipral/examples/common/media_socket.rs`. A partial frame is
    /// kept for the next call, unless the agent barged in ([`sipral_headless::Session::barge_in`]);
    /// then it is the tail of abandoned speech and is dropped with the queue.
    ///
    /// `true` when real audio filled `room`; `false` for silence, normal while the queue catches
    /// up, otherwise a stalled agent.
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

    /// [`HeadlessSession::fill_outbound`] sent as one of `media`'s frames, every media tick even
    /// when the agent is silent. A silent frame still goes to [`MediaSession::capture`], which
    /// advances the RTP clock (RFC 3550 §5.1), sends digits queued by [`send_digit`], and applies
    /// the session's silence suppression. Skipping silent ticks would freeze the timestamp, strand
    /// digits from a silent agent, and make the far end think the call died.
    ///
    /// Otherwise as [`MediaSession::capture`]: `Ok(None)` for a frame deliberately not sent. For
    /// driving `media` by hand, use `fill_outbound` and `media.capture` separately
    /// (`docs/07-headless.md#real-media`).
    ///
    /// # Errors
    ///
    /// Whatever [`MediaSession::capture`] refuses. Resampling cannot fail here; `open` and
    /// `set_codec_rate` already validated the rates.
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

/// Resample `input` and append the result to `scratch`.
fn accumulate(resampler: &mut Resampler, input: &[i16], scratch: &mut Vec<i16>) {
    let needed = resampler.output_capacity(input.len());
    let start = scratch.len();
    scratch.resize(start + needed, 0);
    let produced = match scratch
        .get_mut(start..)
        .map(|room| resampler.process(input, room))
    {
        Some(Ok(produced)) => produced,
        // unreachable, since `scratch` was sized by `output_capacity`; if it happened the audio
        // would just not advance this time
        Some(Err(_)) | None => 0,
    };
    scratch.truncate(start + produced);
}

/// Which call a `sipral_ua::UaEvent` concerns and the matching [`CallStateKind`], or `None` for
/// events that are not one of the three wire transitions. Session-local `Held` has no wire form
/// ([`sipral_headless::SessionState`]); other events are not about call lifecycle.
///
/// The call handle is returned because the stack reports every call, not just the session's: a
/// refused second INVITE also ends. Compare the handle before sending a
/// [`CallState`](sipral_headless::CallState) under a session's `call_id`.
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

/// A `sipral::MediaEvent::DigitReceived` digit as the socket's [`DtmfReceived`], or `None` for an
/// RFC 4733 event outside the sixteen keys of [`DtmfDigit`], which the protocol cannot carry.
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

/// Send the socket's `DtmfSend` digit on `media` for `duration`.
///
/// # Errors
///
/// Whatever [`MediaSession::send_dtmf`] refuses, such as a length outside what RFC 4733 sends.
pub fn send_digit(
    media: &mut MediaSession,
    digit: DtmfDigit,
    duration: Duration,
) -> Result<(), MediaError> {
    let Some(key) = Digit::from_char(digit.get()) else {
        // unreachable: both types parse the same sixteen RFC 4733 keys; returned as an error rather
        // than unwrapped, to avoid panics
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
        // ten to one exceeds what the resampler filters
        let error = HeadlessSession::open("call-1".to_owned(), audio(), 80_000, 4, 4)
            .expect_err("decimation too deep");
        assert!(matches!(error, HeadlessMediaError::Rate(_)));
    }

    #[test]
    fn hearing_silence_reports_no_voice_activity_change_but_still_queues_the_frame() {
        let mut session =
            HeadlessSession::open("call-1".to_owned(), audio(), 8_000, 4, 4).expect("same rate");
        let silence = vec![0_i16; 160];
        // a fresh detector starts on silence, so no change is reported, but the frame still reaches
        // the agent
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
        // 48 kHz codec into 8 kHz session (6:1, within the 8:1 limit): six 960-sample codec frames
        // give about six 160-sample session frames, give or take the filter's initial delay
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

    // `call_state_of` needs `UaEvent`s, whose handles only a running `UserAgent` makes;
    // `crates/sipral/tests/headless_bridge.rs` tests it end to end.

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

    /// A PCMU stream with telephone events on 101, opened without a user agent: enough for `speak`
    /// to emit real datagrams.
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
            dtmf_in: Some(101),
            codec_in: 0,
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
                annex_b: false,
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
        // an agent navigating an IVR sends digits while saying nothing
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
        // RFC 3550 §5.1: the timestamp measures time. Three silent ticks then speech: that frame is
        // 60 ms in, 480 ticks at 8 kHz
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
        // 30 ms socket frames against 20 ms codec frames leave 10 ms resampled and waiting, which a
        // barge-in must discard
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
        // hold, resume or a moved address is a `Changed` with the same codec; the caller is still
        // within the detector's hangover, so one quiet frame does not end the word
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
        // 160 samples already at the socket's 8 kHz wait for the rest of a 30 ms frame; a codec
        // change to 16 kHz leaves them alone
        let socket = AudioConfig::with_frame_duration_ms(SampleRate::Hz8000, 30).expect("fits");
        let mut session =
            HeadlessSession::open("call-1".to_owned(), socket, 8_000, 4, 4).expect("same rate");
        let _ = session.hear(&[0; 160]);
        assert_eq!(session.protocol().capture_depth(), 0);
        session.set_codec_rate(16_000).expect("two to one");
        let _ = session.hear(&[0; 320]);
        assert_eq!(session.protocol().capture_depth(), 1);
    }

    /// `len` samples of a half-scale 440 Hz sine at `rate`, from sample `start`.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn sine(rate: u32, start: usize, len: usize) -> Vec<i16> {
        (start..start + len)
            .map(|n| {
                let phase = 2.0 * std::f64::consts::PI * 440.0 * n as f64 / f64::from(rate);
                (phase.sin() * 16_000.0).round() as i16
            })
            .collect()
    }

    /// Check `samples` at `rate` is still 440 Hz (880 zero crossings per second, within three),
    /// skipping the first quarter for the filter start.
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

    /// Samples the caller side has produced at the socket rate: whole queued frames plus the
    /// partial one.
    fn heard_so_far(session: &HeadlessSession) -> usize {
        session.protocol().capture_depth() * session.session_frame_samples + session.inbound.len()
    }

    fn rate(hz: u32) -> SampleRate {
        SampleRate::try_from(hz).expect("one of the four")
    }

    /// Socket and codec frame durations in ms: equal, and pairs where neither sample count divides
    /// the other, both ways round.
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
                    // the second run carries exactly its length in time, no drift
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
                    // everything pushed came out, minus at most a kernel's worth still in the
                    // filter and one partial frame
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
        // G.711 at 8 kHz renegotiated to Opus at 48 kHz, into a 16 kHz socket, and back
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
            // half a second at 16 kHz exactly once the new filter runs; the first half within the
            // filter's start-up
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
