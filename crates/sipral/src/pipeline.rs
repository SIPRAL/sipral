// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One codec, driven for one call.
//!
//! `sipral-media` holds an encoder and a decoder for every codec this build
//! contains, and has no opinion about which of them a call is using because
//! it never sees a negotiation. This is where the negotiation's answer
//! becomes a pair of state machines: an encoder fed frames of PCM and a
//! decoder fed payloads, both at the rate the codec hears at rather than the
//! rate the wire counts in.
//!
//! Concealment belongs here for the same reason. What fills a lost frame is
//! the codec's business, so it is settled once, where the pair is built,
//! rather than at every lost packet: G.711 and G.722 get
//! [`plc::Concealer`], which extends the pitch period of the last audio that
//! arrived; G.729 carries the concealment its own Recommendation defines
//! (§4.4), which repeats the last filter and decays the excitation inside the
//! decoder's own state, so the frame after a loss decodes from where the
//! concealment left it; and Opus, in a build that has it, carries its own —
//! it can reconstruct the lost frame from the redundancy in the next packet,
//! which is better than anything that works on the decoded waveform.
//!
//! # G.729's silence
//!
//! A G.729 payload can end in an Annex B SID frame, the far end's way of
//! saying it has gone quiet and will send nothing more until something
//! changes. This end signals `annexb=no` and should never see one, but a
//! receiver that plays a SID as garbage or as a gap is the one that sounds
//! broken, so it is read for what can be read of it without the rest of
//! Annex B: a pause begins, at a level. The level is that of the far end's
//! own last decoded frame, the nearest measure of its background this end
//! has, and each later SID of the same pause moves it by the change in
//! energy it states (B.4.2.1's decibels). What plays is the facade's own
//! RFC 3389 generator at that level, the same noise a CN payload would
//! have started — flat, where Annex B's comfort noise would be shaped by
//! the SID's spectrum, which is the part not decoded.

use sipral_media::comfort_noise::ComfortNoise;
use sipral_media::g711::Law;
#[cfg(feature = "opus")]
use sipral_media::opus;
#[cfg(feature = "opus")]
use sipral_media::opus::{FrameDuration, SampleRate};
use sipral_media::plc::Concealer;
use sipral_media::{g722, g729};

use crate::codec::Codec;
use crate::error::MediaError;

/// The encoder and decoder a call is running, and the concealment that goes
/// with them.
pub(crate) struct Coder {
    codec: Codec,
    kind: Kind,
    frame_samples: usize,
}

/// What is behind the pair, which is a different thing for each codec and not
/// a trait: a handful of codecs is not enough to earn dynamic dispatch, and
/// the differences between them — a stateless companding table, a filter bank
/// with memory, a C library with a pointer — do not share a shape worth
/// naming.
enum Kind {
    /// G.711, either law. Stateless in both directions, so the only state is
    /// the concealer's history.
    Companded(Law, Concealer),
    /// G.722. Its filter bank and step sizes carry across frames, so encoder
    /// and decoder are as stateful as the audio is.
    ///
    /// The concealer is the same one, run on sixteen-kilohertz audio, and its
    /// two bounds are stated in samples rather than in time: the pitch search
    /// therefore covers 100 to 800 Hz here instead of 50 to 400, and the gap
    /// it will extend across is thirty milliseconds instead of sixty. Both are
    /// still an extension of the voice that was there, and both are better
    /// than the silence the alternative writes. A rate on
    /// [`Concealer::new`](sipral_media::plc::Concealer::new) would make them
    /// right rather than acceptable.
    Wideband(Box<(g722::Encoder, g722::Decoder)>, Concealer),
    /// G.729, which conceals for itself (§4.4) and keeps what it knows of
    /// the far end's pauses.
    Celp(Box<(g729::Encoder, g729::Decoder)>, Pause),
    /// Opus, which conceals for itself. Only where the `opus` feature is on;
    /// without it there is no codec here that libopus decodes.
    #[cfg(feature = "opus")]
    Opus(Box<(opus::Encoder, opus::Decoder)>),
}

/// What one payload came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// This many samples of the far end's audio.
    Audio(usize),
    /// This many samples of audio, and then a G.729 SID frame: the far end
    /// has gone quiet, and this is the noise to fill the pause with, from
    /// the rest of this frame on.
    Silenced(usize, ComfortNoise),
    /// Nothing a decoder can read: a G.729 payload whose length is no
    /// arrangement of frames. What it displaced is concealed.
    Unreadable,
}

/// What a G.729 call knows about the far end's pauses: see the module
/// documentation.
#[derive(Debug, Default)]
struct Pause {
    /// The mean square of the last frame decoded from speech.
    power: u64,
    /// The first SID frame's energy in decibels and the noise amplitude the
    /// pause started at, until speech ends the pause.
    anchor: Option<(i8, i16)>,
}

/// One two-decibel step of amplitude, `10^(2/20)`, and its inverse, in Q14.
/// Every level of B.4.2.1's quantizer is an even number of decibels, so a
/// change between two of them is a whole number of these steps.
const TWO_DB_UP: u32 = 20_626;
const TWO_DB_DOWN: u32 = 13_014;

impl Pause {
    /// A frame of speech was decoded: remember how loud it was, and end any
    /// pause.
    fn spoke(&mut self, frame: &[i16]) {
        let count = u64::try_from(frame.len()).unwrap_or(1).max(1);
        let total: u64 = frame
            .iter()
            .map(|&sample| u64::from(sample.unsigned_abs()).pow(2))
            .sum();
        self.power = total / count;
        self.anchor = None;
    }

    /// A SID frame arrived: the noise to play.
    ///
    /// The first of a pause sets the amplitude from the last speech, with
    /// the peak of uniform noise of the same power — `√3` times its root
    /// mean square, since that is the noise the generator makes. Every later
    /// one moves it from there by the difference between its energy and the
    /// first one's.
    fn silenced(&mut self, sid: g729::Sid) -> ComfortNoise {
        let level = sid.energy_db();
        let (anchor, amplitude) = *self.anchor.get_or_insert_with(|| {
            let peak = self.power.saturating_mul(3).isqrt();
            (level, i16::try_from(peak).unwrap_or(i16::MAX))
        });
        let amplitude = scaled(amplitude, level.saturating_sub(anchor));
        ComfortNoise::from_amplitude(amplitude)
    }
}

/// `amplitude` moved by `decibels`, an even number, two at a time.
fn scaled(amplitude: i16, decibels: i8) -> i16 {
    let step = if decibels < 0 { TWO_DB_DOWN } else { TWO_DB_UP };
    let mut value = u32::from(amplitude.unsigned_abs());
    for _ in 0..decibels.unsigned_abs() / 2 {
        value = (value * step + (1 << 13)) >> 14;
        value = value.min(u32::from(i16::MAX.unsigned_abs()));
    }
    i16::try_from(value).unwrap_or(i16::MAX)
}

// Opus is the only codec here that refuses anything, so with the feature off
// these four return a `Result` that is always `Ok`. The signature is the same
// in both builds on purpose: a caller written against one of them compiles
// against the other, and this crate has one shape of error path and not two.
#[cfg_attr(not(feature = "opus"), allow(clippy::unnecessary_wraps))]
impl Coder {
    /// The pair for a codec, cutting frames of `frame_ms` milliseconds.
    ///
    /// Opus is asked for in-band forward error correction and told what loss
    /// to expect. Both are §7.1 of RFC 7587 and both are free where the peer
    /// does not use them: the flag says this end will *decode* redundancy, and
    /// the expected loss is what makes libopus put redundancy in what it
    /// sends. Five percent is a rate at which a call is already audibly
    /// suffering, so it is the point at which the extra bits are worth
    /// spending rather than a guess about this particular network.
    ///
    /// # Errors
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well, or the documentation of a build without it points at
    // nothing and promises an error that build cannot produce
    #[cfg_attr(
        feature = "opus",
        doc = "[`MediaError::Codec`] when Opus refuses the rate or the frame \
               length, which for the frame length can only happen for a peer \
               that negotiated a `ptime` Opus has no frame for."
    )]
    #[cfg_attr(
        not(feature = "opus"),
        doc = "None. Opus is the only codec here that refuses anything and \
               this build does not have it, so the answer is always `Ok` — \
               see the note above the `impl`."
    )]
    pub(crate) fn new(codec: Codec, frame_ms: u32) -> Result<Self, MediaError> {
        let kind = match codec {
            Codec::Pcmu => Kind::Companded(Law::Mu, Concealer::new()),
            Codec::Pcma => Kind::Companded(Law::A, Concealer::new()),
            Codec::G722 => Kind::Wideband(
                Box::new((g722::Encoder::new(), g722::Decoder::default())),
                Concealer::new(),
            ),
            Codec::G729 => Kind::Celp(
                Box::new((g729::Encoder::new(), g729::Decoder::new())),
                Pause::default(),
            ),
            #[cfg(feature = "opus")]
            Codec::Opus => {
                let rate = SampleRate::from_hertz(codec.sample_rate())?;
                let frame = FrameDuration::from_micros(frame_ms.saturating_mul(1_000))?;
                let mut encoder = opus::Encoder::new(rate, frame)?;
                encoder.set_inband_fec(true)?;
                encoder.set_expected_loss(5)?;
                Kind::Opus(Box::new((encoder, opus::Decoder::new(rate, frame)?)))
            }
        };
        Ok(Self {
            codec,
            kind,
            frame_samples: codec.frame_samples(frame_ms),
        })
    }

    /// Which codec this is.
    pub(crate) const fn codec(&self) -> Codec {
        self.codec
    }

    /// Samples in one frame, at the rate the codec hears.
    pub(crate) const fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    /// Turn one frame of PCM into a payload, and say how long it is.
    ///
    /// # Errors
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well, or the documentation of a build without it points at
    // nothing and promises an error that build cannot produce
    #[cfg_attr(
        feature = "opus",
        doc = "[`MediaError::Codec`] when Opus refuses the frame."
    )]
    #[cfg_attr(
        not(feature = "opus"),
        doc = "None. Nothing in this build refuses a frame it can cut, so \
               the answer is always `Ok`."
    )]
    pub(crate) fn encode(&mut self, samples: &[i16], out: &mut [u8]) -> Result<usize, MediaError> {
        match &mut self.kind {
            Kind::Companded(law, _) => Ok(law.encode_into(samples, out)),
            Kind::Wideband(pair, _) => Ok(pair.0.encode_into(samples, out)),
            Kind::Celp(pair, _) => Ok(pair.0.encode_into(samples, out)),
            #[cfg(feature = "opus")]
            Kind::Opus(pair) => Ok(pair.0.encode(samples, out)?),
        }
    }

    /// Turn one payload into PCM, and say what it held: audio, audio and then
    /// the start of a pause, or nothing readable.
    ///
    /// # Errors
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well, or the documentation of a build without it points at
    // nothing and promises an error that build cannot produce
    #[cfg_attr(
        feature = "opus",
        doc = "[`MediaError::Codec`] when Opus refuses the packet, which for \
               a payload off the wire means a corrupt one."
    )]
    #[cfg_attr(
        not(feature = "opus"),
        doc = "None. The codecs in this build decode whatever octets arrive, \
               so the answer is always `Ok`."
    )]
    pub(crate) fn decode(
        &mut self,
        payload: &[u8],
        out: &mut [i16],
    ) -> Result<Decoded, MediaError> {
        match &mut self.kind {
            Kind::Companded(law, concealer) => {
                let count = law.decode_into(payload, out);
                concealer.received(out.get_mut(..count).unwrap_or_default());
                Ok(Decoded::Audio(count))
            }
            Kind::Wideband(pair, concealer) => {
                let count = pair.1.decode_into(payload, out);
                concealer.received(out.get_mut(..count).unwrap_or_default());
                Ok(Decoded::Audio(count))
            }
            Kind::Celp(pair, pause) => {
                let Some(parsed) = g729::Payload::parse(payload)
                    .filter(|parsed| parsed.frame_count() > 0 || parsed.sid().is_some())
                else {
                    return Ok(Decoded::Unreadable);
                };
                let count = pair.1.decode_into(parsed.speech(), out);
                if let Some(last) = out.get(count.saturating_sub(g729::FRAME_SAMPLES)..count)
                    && !last.is_empty()
                {
                    pause.spoke(last);
                }
                Ok(match parsed.sid() {
                    Some(sid) => Decoded::Silenced(count, pause.silenced(sid)),
                    None => Decoded::Audio(count),
                })
            }
            #[cfg(feature = "opus")]
            Kind::Opus(pair) => Ok(Decoded::Audio(pair.1.decode(payload, out)?)),
        }
    }

    /// Fill a frame the far end sent and this end did not get.
    ///
    /// # Errors
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well, or the documentation of a build without it points at
    // nothing and promises an error that build cannot produce
    #[cfg_attr(
        feature = "opus",
        doc = "[`MediaError::Codec`] when Opus refuses, which it does only \
               for an output slice too short for one frame."
    )]
    #[cfg_attr(
        not(feature = "opus"),
        doc = "None. The concealer in this build fills whatever it is given, \
               so the answer is always `Ok`."
    )]
    pub(crate) fn conceal(&mut self, out: &mut [i16]) -> Result<usize, MediaError> {
        let frame = self.frame_samples.min(out.len());
        match &mut self.kind {
            Kind::Companded(_, concealer) | Kind::Wideband(_, concealer) => {
                concealer.conceal(out.get_mut(..frame).unwrap_or_default());
                Ok(frame)
            }
            // a frame length is a whole number of G.729 frames, which the
            // catalogue checks where it is set; only an `out` shorter than
            // one leaves a remainder, and that is written silent
            Kind::Celp(pair, _) => {
                let mut chunks = out
                    .get_mut(..frame)
                    .unwrap_or_default()
                    .chunks_exact_mut(g729::FRAME_SAMPLES);
                for chunk in &mut chunks {
                    chunk.copy_from_slice(&pair.1.conceal());
                }
                chunks.into_remainder().fill(0);
                Ok(frame)
            }
            #[cfg(feature = "opus")]
            Kind::Opus(pair) => Ok(pair.1.conceal(out)?),
        }
    }
}

impl core::fmt::Debug for Coder {
    /// Written out rather than derived: `opus::Encoder` and `plc::Concealer`
    /// both write their own, and neither has anything a `Coder` would want to
    /// print twice.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Coder")
            .field("codec", &self.codec)
            .field("frame_samples", &self.frame_samples)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Coder, Decoded, scaled};
    use crate::codec::{Codec, DEFAULT_FRAME_MS};

    /// A tone the codecs can all carry, at a quarter of full scale so that
    /// nothing is clipping and the comparison is about the codec.
    fn tone(samples: &mut [i16], rate: u32, phase: &mut u32) {
        let period = (rate / 444).max(2);
        for slot in samples.iter_mut() {
            *slot = if *phase % period < period / 2 {
                8_000
            } else {
                -8_000
            };
            *phase = phase.wrapping_add(1);
        }
    }

    fn loudness(samples: &[i16]) -> i64 {
        if samples.is_empty() {
            return 0;
        }
        let total: i64 = samples.iter().map(|s| i64::from(s.saturating_abs())).sum();
        total / i64::try_from(samples.len()).unwrap_or(1).max(1)
    }

    /// Every codec has to carry a frame there and back at its own rate, and
    /// the number of samples that comes back has to be the number that went
    /// in. This is the test that catches a frame length taken from the wrong
    /// one of the three numbers.
    #[test]
    fn every_codec_carries_a_frame_at_its_own_rate() {
        for codec in Codec::ALL {
            let mut coder = Coder::new(codec, DEFAULT_FRAME_MS).unwrap();
            let frame = codec.frame_samples(DEFAULT_FRAME_MS);
            assert_eq!(coder.frame_samples(), frame);

            let mut samples = vec![0_i16; frame];
            let mut payload = vec![0_u8; codec.max_payload(DEFAULT_FRAME_MS)];
            let mut back = vec![0_i16; frame];
            let mut phase = 0_u32;

            // several frames: G.722's filters and Opus's encoder both need a
            // moment before what comes out means anything
            let mut written = 0;
            let mut decoded = Decoded::Unreadable;
            for _ in 0..25 {
                tone(&mut samples, codec.sample_rate(), &mut phase);
                written = coder.encode(&samples, &mut payload).unwrap();
                decoded = coder.decode(&payload[..written], &mut back).unwrap();
            }
            assert!(written > 0, "{codec} produced an empty payload");
            assert_eq!(
                decoded,
                Decoded::Audio(frame),
                "{codec} gave back the wrong frame length"
            );
            assert!(
                loudness(&back) > 500,
                "{codec} came back inaudible at {}",
                loudness(&back)
            );
        }
    }

    /// A concealed frame is a whole frame of audio, whichever concealment ran.
    /// A short one is a click in the earpiece and a gap in the recording.
    #[test]
    fn concealment_fills_a_whole_frame_for_every_codec() {
        for codec in Codec::ALL {
            let mut coder = Coder::new(codec, DEFAULT_FRAME_MS).unwrap();
            let frame = codec.frame_samples(DEFAULT_FRAME_MS);
            let mut samples = vec![0_i16; frame];
            let mut payload = vec![0_u8; codec.max_payload(DEFAULT_FRAME_MS)];
            let mut back = vec![0_i16; frame];
            let mut phase = 0_u32;

            for _ in 0..25 {
                tone(&mut samples, codec.sample_rate(), &mut phase);
                let written = coder.encode(&samples, &mut payload).unwrap();
                coder.decode(&payload[..written], &mut back).unwrap();
            }

            let mut concealed = vec![0_i16; frame];
            assert_eq!(coder.conceal(&mut concealed).unwrap(), frame, "{codec}");
            assert!(
                loudness(&concealed) > 100,
                "{codec} concealed a voiced frame with near-silence"
            );
        }
    }

    /// Opus is the codec that has an opinion about frame length, and it says
    /// so when the pair is built rather than at the first packet of a call.
    #[cfg(feature = "opus")]
    #[test]
    fn opus_refuses_a_frame_length_it_has_no_frame_for() {
        let refused = Coder::new(Codec::Opus, 30).expect_err("Opus has no 30 ms frame");
        assert!(
            refused.is_codec(),
            "the refusal is the codec's own, and everything above reads that \
             rather than a `cfg` of its own"
        );
        assert!(Coder::new(Codec::Pcmu, 30).is_ok());
    }

    /// And without it, nothing here refuses one. G.729's whole tens are the
    /// catalogue's to enforce where the length is set, and thirty
    /// milliseconds is three of its frames.
    #[cfg(not(feature = "opus"))]
    #[test]
    fn without_opus_every_codec_takes_thirty_milliseconds() {
        for codec in Codec::ALL {
            assert!(Coder::new(codec, 30).is_ok(), "{codec}");
        }
    }

    /// A G.729 coder that has decoded a second of the tone, and the last
    /// payload it sent.
    fn g729_talking() -> (Coder, Vec<u8>) {
        let mut coder = Coder::new(Codec::G729, DEFAULT_FRAME_MS).unwrap();
        let mut samples = [0_i16; 160];
        let mut payload = [0_u8; 20];
        let mut back = [0_i16; 160];
        let mut phase = 0_u32;
        for _ in 0..50 {
            tone(&mut samples, 8_000, &mut phase);
            let written = coder.encode(&samples, &mut payload).unwrap();
            coder.decode(&payload[..written], &mut back).unwrap();
        }
        (coder, payload.to_vec())
    }

    /// A SID frame at the end of a payload decodes the speech before it and
    /// starts a pause at about the level that speech had; one alone starts
    /// it with nothing decoded.
    #[test]
    fn a_g729_sid_frame_starts_a_pause_at_the_level_of_the_speech_before_it() {
        let (mut coder, payload) = g729_talking();
        let mut back = [0_i16; 160];
        let mut one_and_sid: Vec<u8> = payload[..10].to_vec();
        one_and_sid.extend_from_slice(&[0x00, 0x14]); // energy index 10
        let Ok(Decoded::Silenced(80, noise)) = coder.decode(&one_and_sid, &mut back) else {
            panic!("one frame and a SID is audio, then a pause");
        };
        // the tone at a quarter of full scale sits about 12 dB below it, and
        // uniform noise of the same power peaks √3 higher
        assert!(
            (5..=16).contains(&noise.level()),
            "{} dB below full scale",
            noise.level()
        );

        // and a SID alone, 6 dB louder than the first, raises it by as much
        let Ok(Decoded::Silenced(0, louder)) = coder.decode(&[0x00, 0x1a], &mut back) else {
            panic!("a SID alone is a pause with no audio before it");
        };
        let raised = i16::from(noise.level()) - i16::from(louder.level());
        assert!((5..=7).contains(&raised), "raised by {raised} dB");
    }

    /// Speech after a pause ends it: the next pause is measured afresh from
    /// the speech, not moved from the last one.
    #[test]
    fn g729_speech_ends_a_pause() {
        let (mut coder, payload) = g729_talking();
        let mut back = [0_i16; 160];
        let Ok(Decoded::Silenced(0, first)) = coder.decode(&[0x00, 0x14], &mut back) else {
            panic!("a SID alone is a pause");
        };
        assert_eq!(coder.decode(&payload, &mut back), Ok(Decoded::Audio(160)));
        let Ok(Decoded::Silenced(0, second)) = coder.decode(&[0x00, 0x3e], &mut back) else {
            panic!("a SID alone is a pause");
        };
        let apart = i16::from(first.level()) - i16::from(second.level());
        assert!(apart.abs() <= 3, "{apart} dB apart");
    }

    /// A length that is no arrangement of frames, and a payload with nothing
    /// in it, are not decoded as a guess.
    #[test]
    fn a_g729_payload_of_no_known_shape_is_unreadable() {
        let (mut coder, _) = g729_talking();
        let mut back = [0_i16; 160];
        for length in [0, 1, 3, 11, 13, 21] {
            assert_eq!(
                coder.decode(&vec![0x55; length], &mut back),
                Ok(Decoded::Unreadable),
                "{length} octets"
            );
        }
    }

    /// Two decibels at a time, both ways, and never past full scale.
    #[test]
    fn a_level_moves_by_the_decibels_it_is_given() {
        let up = i32::from(scaled(1_000, 20));
        assert!((9_900..=10_100).contains(&up), "{up}");
        let down = i32::from(scaled(10_000, -20));
        assert!((990..=1_010).contains(&down), "{down}");
        assert_eq!(scaled(20_000, 60), i16::MAX);
        assert_eq!(scaled(1_234, 0), 1_234);
    }
}
