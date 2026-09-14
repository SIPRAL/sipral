// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The media half of a flow: a socket, an RTP session, and a tone.
//!
//! Signalling that agrees on a codec proves the two ends can talk about a
//! call. It does not prove anybody can hear it, and until this module existed
//! the harness negotiated media and then sent nothing — so a call to an echo
//! test passed on the strength of its 200 OK.
//!
//! What happens here is deliberately the smallest thing that answers the
//! question: send audio, and measure what arrives.
//!
//! Be exact about what that proves, because it is less than it looks. The lab
//! does not echo — an echo was tried and does not survive the loopback bridge
//! FreeSWITCH needs in order to be transferable — so what comes back is the
//! far end's own cadenced tone. So `audible` says the media path is alive in
//! the direction that matters: ports negotiated, codec agreed and decoding,
//! packets arriving and being played. It does **not** say a round trip
//! happened. A test that needs that needs a peer that echoes.
//!
//! What this end sends is cadenced too, and for a different reason: a client
//! that never stops speaking is not a client, and the buffer at the far end is
//! entitled to the pauses a real one would give it.

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use sipral_core::sdp::{MediaPlan, RtcpPlan};
use sipral_media::{g711::Law, g722};
use sipral_rtp::{
    Activity, BufferConfig, PayloadTypes, Pull, Quality, Received, RtpSession, StreamConfig,
};

/// A packet is twenty milliseconds of audio, whatever the codec.
const PTIME_MS: u32 = 20;

/// Timestamp ticks one packet covers. Eight thousand a second for every codec
/// here, G.722 included: RFC 3551 §4.5.2 fixes its RTP clock at 8000 although
/// it samples at 16000, so this is not the sample count and must not be
/// written as if it were.
const FRAME_TICKS: u32 = 160;

/// The largest frame any of them produces, in samples: G.722's, which hears
/// twice as fast as it counts.
const MAX_SAMPLES: usize = 320;

/// The largest frame in octets, which is the same number for all of them.
const MAX_OCTETS: usize = 160;

/// Roughly 440 Hz, whatever the rate: the period is in samples, so it has to
/// come from the rate rather than being a constant.
const TONE_HZ: u32 = 444;

/// How loud it is: a quarter of full scale.
const AMPLITUDE: i16 = 8000;

/// How often a frame goes out.
const PACE: Duration = Duration::from_millis(20);

/// How long the tone sounds, and how long it then stops for.
///
/// A continuous tone is not a conversation, and the difference is not
/// cosmetic. A de-jitter buffer that has grown to cover an interruption gives
/// the growth back only in a pause — dropping a frame during speech is
/// audible and dropping one in silence is not — so a signal that never stops
/// speaking can never let it recover, and every measurement taken over an
/// impaired link is then taken against a buffer stuck where the worst moment
/// left it. Measured on the lab before this existed: twenty seconds of tone
/// through an eight-second outage ended at 420 ms of delay where a clean run
/// of the same length sat at 20 ms, and none of that was the buffer's fault.
const SPURT: Duration = Duration::from_millis(1_200);
/// The pause after it. Long enough to contain several shrink steps, which are
/// deliberately one frame at a time.
const PAUSE: Duration = Duration::from_millis(600);

/// Mean absolute sample value above which a frame counts as sound rather than
/// silence. G.711 silence sits within a handful of units of zero; a tone at a
/// quarter of full scale is thousands. Anything in between is neither, and the
/// gap is wide enough that the threshold does not need to be argued about.
const AUDIBLE: i32 = 500;

/// Whether the tone is sounding at this point in the call.
fn in_spurt(elapsed: Duration) -> bool {
    let cycle = SPURT.saturating_add(PAUSE).as_millis().max(1);
    elapsed.as_millis() % cycle < SPURT.as_millis()
}

/// What this end sends. Roughly 440 Hz, square rather than sine.
///
/// Square because it needs no floating point and lands exactly on values
/// G.711 represents, so nothing about the signal can be blamed for what comes
/// back. Its harmonics alias, and for the question being asked that does not
/// matter.
fn tone(samples: &mut [i16], phase: &mut u32, rate: u32) {
    let period = (rate / TONE_HZ).max(2);
    for slot in samples.iter_mut() {
        *slot = if *phase % period < period / 2 {
            AMPLITUDE
        } else {
            -AMPLITUDE
        };
        *phase = phase.wrapping_add(1);
    }
}

/// What the two ends settled on, and everything that follows from it.
///
/// A single `Law` field used to be enough, and it hid the trap: G.711's sample
/// rate, its octet count and its timestamp ticks are all 160 for a
/// twenty-millisecond frame, so one constant served all three. G.722's are
/// 320, 160 and 160. Anything written against the old shape encodes half a
/// frame and calls it a packet.
enum Codec {
    /// G.711, either law: one octet a sample, eight kilohertz.
    Companded(Law),
    /// G.722: one octet per two samples, sixteen kilohertz in and out.
    Wideband(Box<(g722::Encoder, g722::Decoder)>),
}

impl Codec {
    /// What the negotiation's payload type means, falling back to mu-law —
    /// which is what an unknown type would have been decoded as anyway, and is
    /// at least visible in the flow's report.
    fn for_payload(payload_type: u8) -> Self {
        if payload_type == g722::PAYLOAD_TYPE {
            return Self::Wideband(Box::new((g722::Encoder::new(), g722::Decoder::default())));
        }
        Self::Companded(Law::from_payload_type(payload_type).unwrap_or(Law::Mu))
    }

    /// The rate the codec hears at, which is not the RTP clock rate.
    const fn sample_rate(&self) -> u32 {
        match self {
            Self::Companded(_) => 8_000,
            Self::Wideband(_) => g722::SAMPLE_RATE,
        }
    }

    /// Samples in one packet.
    const fn frame_samples(&self) -> usize {
        match self {
            Self::Companded(_) => 160,
            Self::Wideband(_) => g722::frame_samples(PTIME_MS),
        }
    }

    fn encode_into(&mut self, samples: &[i16], octets: &mut [u8]) -> usize {
        match self {
            Self::Companded(law) => law.encode_into(samples, octets),
            Self::Wideband(pair) => pair.0.encode_into(samples, octets),
        }
    }

    fn decode_into(&mut self, octets: &[u8], samples: &mut [i16]) -> usize {
        match self {
            Self::Companded(law) => law.decode_into(octets, samples),
            Self::Wideband(pair) => pair.1.decode_into(octets, samples),
        }
    }
}

/// What the far end sent back.
#[derive(Debug, Default)]
pub(crate) struct Heard {
    /// Packets we put on the wire.
    pub(crate) sent: u32,
    /// Datagrams the session accepted.
    pub(crate) received: u32,
    /// Frames the buffer handed back with sound in them.
    pub(crate) audible: u32,
    /// Datagrams it refused, and why the first one was refused.
    pub(crate) refused: u32,
}

/// One media stream, driven by the same tick as the signalling.
pub(crate) struct Media {
    socket: UdpSocket,
    session: Option<RtpSession>,
    /// Where the negotiation said RTCP goes, which is where the goodbye goes.
    rtcp: RtcpPlan,
    /// Whether the goodbye has gone out, after which this end sends nothing.
    said_goodbye: bool,
    codec: Codec,
    started: Instant,
    next: Instant,
    phase: u32,
    samples: [i16; MAX_SAMPLES],
    payload: [u8; MAX_OCTETS],
    packet: [u8; 1500],
    decoded: [i16; MAX_SAMPLES],
    /// What the last frame played sounded like, which is what the buffer is
    /// told about the next one.
    playing: Activity,
    heard: Heard,
}

impl Media {
    /// Bind a socket for RTP and report the port, so the offer can name it.
    ///
    /// # Errors
    /// When the socket cannot be bound or put in non-blocking mode.
    pub(crate) fn bind(now: Instant) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|error| format!("cannot bind an RTP socket: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| format!("cannot make the RTP socket non-blocking: {error}"))?;
        Ok(Self {
            socket,
            session: None,
            rtcp: RtcpPlan::Off,
            said_goodbye: false,
            codec: Codec::Companded(Law::Mu),
            started: now,
            next: now,
            phase: 0,
            samples: [0; MAX_SAMPLES],
            payload: [0; MAX_OCTETS],
            packet: [0; 1500],
            decoded: [0; MAX_SAMPLES],
            playing: Activity::Speech,
            heard: Heard::default(),
        })
    }

    /// The port the offer has to advertise.
    ///
    /// # Errors
    /// When the socket cannot say what it was bound to.
    pub(crate) fn port(&self) -> Result<u16, String> {
        self.socket
            .local_addr()
            .map(|address| address.port())
            .map_err(|error| format!("the RTP socket has no address: {error}"))
    }

    /// Start sending, now that the answer has said where and in what.
    ///
    /// The codec comes from the negotiated payload type rather than from what
    /// we would have preferred: the first real PBX this met allows A-law only.
    pub(crate) fn start(&mut self, plan: &MediaPlan, ssrc: u32, now: Instant) {
        let payload_type = plan.codec.payload();
        self.codec = Codec::for_payload(payload_type);
        self.session = Some(RtpSession::new(
            &StreamConfig {
                ssrc,
                payload_type,
                // whatever we agreed, plus the other law: a peer that answers
                // with one and sends the other is a real thing, and dropping
                // its audio would look like silence rather than like a fault
                accepted: PayloadTypes::none()
                    .with(0)
                    .with(8)
                    .with(g722::PAYLOAD_TYPE),
                // the RTP clock, which the negotiation carries and which is
                // 8000 for all three of these
                clock_rate: plan.codec.clock_rate(),
                sequence: 0,
                timestamp: 0,
                remote: plan.remote,
                silence_suppression: false,
                playout: BufferConfig::new(FRAME_TICKS),
                cname: format!("sipral-interop@{}", plan.local.ip()),
                rtcp_bandwidth: 1000.0,
            },
            1.0,
        ));
        self.rtcp = plan.rtcp;
        self.said_goodbye = false;
        self.next = now;
    }

    /// Send what is due and take in what arrived.
    pub(crate) fn turn(&mut self, now: Instant) {
        if self.said_goodbye {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let elapsed = now.saturating_duration_since(self.started);

        while now >= self.next {
            let frame = self.codec.frame_samples().min(MAX_SAMPLES);
            let rate = self.codec.sample_rate();
            let samples = self.samples.get_mut(..frame).unwrap_or_default();
            if in_spurt(elapsed) {
                tone(samples, &mut self.phase, rate);
            } else {
                samples.fill(0);
            }
            let written = self.codec.encode_into(
                self.samples.get(..frame).unwrap_or_default(),
                &mut self.payload,
            );
            if let Ok(length) = session.send(
                self.payload.get(..written).unwrap_or_default(),
                FRAME_TICKS,
                &mut self.packet,
            ) && let Some(datagram) = self.packet.get(..length)
                && self.socket.send_to(datagram, session.destination()).is_ok()
            {
                self.heard.sent = self.heard.sent.saturating_add(1);
            }
            self.next += PACE;
        }

        let mut inbox = [0_u8; 2048];
        loop {
            match self.socket.recv_from(&mut inbox) {
                Ok((length, from)) => {
                    let datagram = inbox.get_mut(..length).unwrap_or_default();
                    match session.receive(datagram, from, elapsed) {
                        Received::Queued => {
                            self.heard.received = self.heard.received.saturating_add(1);
                        }
                        Received::Dropped(_) => {
                            self.heard.refused = self.heard.refused.saturating_add(1);
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // What the buffer is told is what the last frame sounded like, which
        // is what a client knows: it has just decoded one. Saying "speech"
        // unconditionally is the same as telling the buffer it may never
        // shorten, and it will believe it.
        while let Pull::Packet(frame) = session.pull(self.playing) {
            let count = self.codec.decode_into(frame.payload, &mut self.decoded);
            let played = self.decoded.get(..count).unwrap_or_default();
            let loud = loudness(played) >= AUDIBLE;
            self.playing = if loud {
                Activity::Speech
            } else {
                Activity::Silence
            };
            if loud {
                self.heard.audible = self.heard.audible.saturating_add(1);
            }
        }
    }

    /// Say goodbye on this end's own RTP session (RFC 3550 §6.3.7), the
    /// moment signalling reports the call over.
    ///
    /// The harness runs its media on a raw `RtpSession` rather than through
    /// `sipral::MediaEngine`, so there is no `poll_farewell` to drain here —
    /// this is that same obligation met at the layer the harness actually
    /// runs on, and it is why the lab now sees a BYE on this socket rather
    /// than a session that simply stops.
    ///
    /// A fixed unit interval rather than a fresh draw: RFC 3550 §6.2's
    /// randomisation spreads many participants' reports across an interval so
    /// they do not all land at once, and two peers sending one BYE each have
    /// nothing to spread.
    ///
    /// Sent where the negotiation put RTCP rather than where the audio goes:
    /// the same port only when both ends asked for `a=rtcp-mux` (RFC 5761),
    /// otherwise the port of its own the plan names, and not at all when the
    /// far end said it runs no RTCP.
    ///
    /// Once, and the last thing this stream sends: a source that has said
    /// goodbye and then goes on sending audio is back in the session it just
    /// left, so [`Media::turn`] sends nothing afterwards.
    pub(crate) fn hang_up(&mut self, now: Instant) {
        if self.said_goodbye {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.said_goodbye = true;
        let destination = match self.rtcp {
            RtcpPlan::Muxed => session.destination(),
            RtcpPlan::SeparatePort { remote, .. } => remote,
            RtcpPlan::Off => return,
        };
        let elapsed = now.saturating_duration_since(self.started);
        if let Ok(length) = session.send_bye(&mut self.packet, elapsed, b"", 1.0)
            && let Some(datagram) = self.packet.get(..length)
        {
            let _ = self.socket.send_to(datagram, destination);
        }
    }

    /// What came back.
    pub(crate) const fn heard(&self) -> &Heard {
        &self.heard
    }

    /// What the de-jitter buffer made of it. Empty before a call is up.
    pub(crate) fn quality(&self) -> Option<Quality> {
        self.session.as_ref().map(RtpSession::quality)
    }
}

/// Mean absolute sample value.
fn loudness(samples: &[i16]) -> i32 {
    if samples.is_empty() {
        return 0;
    }
    let total: i64 = samples
        .iter()
        .map(|value| i64::from(value.saturating_abs()))
        .sum();
    let count = i64::try_from(samples.len()).unwrap_or(1).max(1);
    i32::try_from(total / count).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{Codec, FRAME_TICKS, MAX_OCTETS, MAX_SAMPLES, PTIME_MS, TONE_HZ, tone};
    use sipral_media::{g711::Law, g722};

    /// The trap this module used to walk into: for G.711 the samples in a
    /// frame, the octets in a frame and the timestamp ticks in a frame are all
    /// the same number, so one constant served all three. For G.722 they are
    /// 320, 160 and 160.
    #[test]
    fn a_frame_is_three_different_numbers_for_g722_and_one_for_g711() {
        let narrow = Codec::for_payload(0);
        assert_eq!(narrow.frame_samples(), 160);
        assert_eq!(narrow.sample_rate(), 8_000);

        let wide = Codec::for_payload(g722::PAYLOAD_TYPE);
        assert_eq!(wide.frame_samples(), 320);
        assert_eq!(wide.sample_rate(), 16_000);
        assert_eq!(g722::frame_octets(PTIME_MS), 160);
        assert_eq!(g722::frame_ticks(PTIME_MS), FRAME_TICKS);

        // and the buffers are sized for the larger of them
        assert!(wide.frame_samples() <= MAX_SAMPLES);
        assert_eq!(g722::frame_octets(PTIME_MS), MAX_OCTETS);
    }

    #[test]
    fn the_payload_type_picks_the_codec_the_negotiation_named() {
        assert!(matches!(Codec::for_payload(0), Codec::Companded(Law::Mu)));
        assert!(matches!(Codec::for_payload(8), Codec::Companded(Law::A)));
        assert!(matches!(Codec::for_payload(9), Codec::Wideband(_)));
        // an unknown type still produces something that can be reported
        assert!(matches!(Codec::for_payload(97), Codec::Companded(Law::Mu)));
    }

    /// A frame that goes out and comes straight back has to be the same length
    /// and the same sound, whichever codec carried it.
    #[test]
    fn a_frame_survives_each_codec_at_its_own_rate() {
        for payload_type in [0_u8, 8, 9] {
            let mut codec = Codec::for_payload(payload_type);
            let frame = codec.frame_samples();
            let rate = codec.sample_rate();
            let mut phase = 0_u32;
            let mut samples = [0_i16; MAX_SAMPLES];
            let mut octets = [0_u8; MAX_OCTETS];
            let mut back = [0_i16; MAX_SAMPLES];

            // run several frames: G.722 needs its filter and its step size to
            // settle before the first one means anything
            let mut written = 0;
            let mut decoded = 0;
            for _ in 0..20 {
                tone(&mut samples[..frame], &mut phase, rate);
                written = codec.encode_into(&samples[..frame], &mut octets);
                decoded = codec.decode_into(&octets[..written], &mut back);
            }
            assert_eq!(written, 160, "payload type {payload_type} octets");
            assert_eq!(decoded, frame, "payload type {payload_type} samples");
            assert!(
                super::loudness(&back[..decoded]) > super::AUDIBLE,
                "payload type {payload_type} came back inaudible"
            );
        }
    }

    /// A stream started against a far end on this machine, its RTP and its
    /// RTCP on sockets of their own. The RTCP one is named by `a=rtcp`, so
    /// nothing this stream sends can reach a port the test did not bind.
    fn started(
        now: std::time::Instant,
        ssrc: u32,
    ) -> (super::Media, std::net::UdpSocket, std::net::UdpSocket) {
        let mut media = super::Media::bind(now).expect("a media socket");
        let audio = std::net::UdpSocket::bind("127.0.0.1:0").expect("the far end's RTP socket");
        let control = std::net::UdpSocket::bind("127.0.0.1:0").expect("the far end's RTCP socket");
        let port_of = |socket: &std::net::UdpSocket| socket.local_addr().expect("bound").port();
        let ours = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
            media.port().expect("a port")
        );
        let theirs = format!(
            "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp:{} IN IP4 127.0.0.1\r\n",
            port_of(&audio),
            port_of(&control)
        );
        let theirs = sipral_core::sdp::parse(theirs.as_bytes()).expect("their answer");
        let plan = sipral_core::sdp::parse(ours.as_bytes())
            .expect("our offer")
            .media_plan(&theirs, 0)
            .expect("a plan")
            .expect("a stream");
        media.start(&plan, ssrc, now);
        (media, audio, control)
    }

    /// Once the goodbye is out this end has left the session (RFC 3550
    /// §6.3.7), and audio sent after it would bring back a source the far end
    /// has just been told is gone.
    #[test]
    fn nothing_goes_out_after_the_goodbye() {
        let now = std::time::Instant::now();
        let (mut media, audio, _control) = started(now, 0x4259_4521);
        media.hang_up(now);
        media.turn(now + std::time::Duration::from_millis(100));

        audio
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .expect("a timeout");
        let mut inbox = [0_u8; 1500];
        assert!(
            audio.recv_from(&mut inbox).is_err(),
            "no audio followed the goodbye"
        );
    }

    /// A call's goodbye goes where the negotiation said its RTCP goes. Neither
    /// description here asks for `a=rtcp-mux`, so that is a port of its own,
    /// the one the answer's `a=rtcp` names, and not the port the audio goes
    /// to: without the mux attribute on both sides, RTP and RTCP must not
    /// share a port (RFC 5761 §5.1.1).
    #[test]
    fn the_goodbye_goes_to_the_rtcp_port_the_answer_named() {
        let now = std::time::Instant::now();
        let ssrc = 0x4259_4521_u32;
        let (mut media, audio, control) = started(now, ssrc);
        media.hang_up(now);

        control
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("a timeout");
        let mut inbox = [0_u8; 1500];
        let (length, _) = control
            .recv_from(&mut inbox)
            .expect("the goodbye reached the RTCP port");
        let compound =
            sipral_rtp::CompoundPacket::parse(&inbox[..length]).expect("a compound RTCP packet");
        assert!(
            compound.packets().any(|packet| matches!(
                packet,
                sipral_rtp::RtcpPacket::Goodbye(bye) if bye.sources().eq([ssrc])
            )),
            "a BYE naming this end's SSRC"
        );
        audio.set_nonblocking(true).expect("non-blocking");
        assert!(
            audio.recv_from(&mut inbox).is_err(),
            "and nothing of it reached the audio port"
        );
    }

    /// The tone has to stay at the same pitch when the rate doubles, or the
    /// wideband flow is measuring a different signal from the narrowband one.
    #[test]
    fn the_tone_keeps_its_pitch_across_the_rates() {
        for rate in [8_000_u32, 16_000] {
            let mut phase = 0_u32;
            let mut samples = vec![0_i16; usize::try_from(rate).unwrap_or(8_000)];
            tone(&mut samples, &mut phase, rate);
            let crossings = samples
                .windows(2)
                .filter(|pair| pair[0].signum() != pair[1].signum())
                .count();
            // two crossings a period, over one second
            let hertz = crossings / 2;
            assert!(
                hertz.abs_diff(TONE_HZ as usize) < 10,
                "at {rate} Hz the tone came out at {hertz} Hz"
            );
        }
    }
}
