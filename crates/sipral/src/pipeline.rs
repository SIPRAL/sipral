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
//! saying it has gone quiet and will send nothing more until the background
//! changes. The decoder turns it into Annex B's comfort noise — shaped by
//! the SID's spectrum, at its level — and goes on making that noise for
//! every frame that does not arrive while the pause lasts
//! ([`Coder::pause`]), because in a pause a frame that does not arrive is
//! one the far end did not send (B.4.5).
//!
//! With Annex B negotiated both ways, the encoder runs Annex B's DTX too
//! ([`Coder::set_annex_b`]): each ten-millisecond frame is speech, a SID
//! frame or nothing, and a payload is cut from them the way RFC 3551
//! §4.5.6 allows — speech frames and at most one SID frame after them. A
//! frame length of several G.729 frames can hold a transition that no one
//! payload can carry; [`Coder::encode`] says what it did with each case.

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
    /// G.729, which conceals for itself (§4.4) and makes its own comfort
    /// noise (Annex B).
    Celp(Box<(g729::Encoder, g729::Decoder)>),
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
    /// This many samples of comfort noise: a G.729 payload that held nothing
    /// but an Annex B SID frame.
    Noise(usize),
    /// Nothing a decoder can read: a G.729 payload whose length is no
    /// arrangement of frames. What it displaced is concealed.
    Unreadable,
}

/// What one frame of the microphone came to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sent {
    /// The payload's length in octets: zero for a frame with nothing to send.
    pub(crate) octets: usize,
    /// Samples at the start of the frame that are not in the payload, so the
    /// payload's timestamp is this much later than the frame's. Only G.729
    /// with Annex B has any: a pause that ends inside the frame.
    pub(crate) skipped: usize,
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
            Codec::G729 => Kind::Celp(Box::new((g729::Encoder::new(), g729::Decoder::new()))),
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

    /// Run G.729's encoder with Annex B's DTX, or without it: what the
    /// negotiation settled, both ends having allowed Annex B. A change
    /// starts the encoder afresh, since its state is the DTX's too; every
    /// other codec has no Annex B, and nothing changes for it.
    pub(crate) fn set_annex_b(&mut self, on: bool) {
        if let Kind::Celp(pair) = &mut self.kind
            && pair.0.dtx() != on
        {
            pair.0 = if on {
                g729::Encoder::with_dtx()
            } else {
                g729::Encoder::new()
            };
        }
    }

    /// Whether the encoder runs Annex B's DTX.
    pub(crate) fn annex_b(&self) -> bool {
        matches!(&self.kind, Kind::Celp(pair) if pair.0.dtx())
    }

    /// Turn one frame of PCM into a payload, and say how long it is.
    ///
    /// For G.729 with Annex B, each ten-millisecond frame is speech, a SID
    /// frame or nothing, and the payload is what RFC 3551 §4.5.6 lets one
    /// carry: speech frames and, after them, at most one SID frame. Frames
    /// with nothing to send before the first one that has something are
    /// left out and counted in [`Sent::skipped`]. A SID frame followed by
    /// speech in the same frame — a pause of ten milliseconds — is left out
    /// the same way, since the payload cannot carry a SID before speech and
    /// the speech is what matters; and after a SID frame nothing more goes
    /// in: a pause frame is only time, and speech after it, in a frame of
    /// thirty milliseconds or more, is not sent.
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
    pub(crate) fn encode(&mut self, samples: &[i16], out: &mut [u8]) -> Result<Sent, MediaError> {
        let whole = |octets| Sent { octets, skipped: 0 };
        match &mut self.kind {
            Kind::Companded(law, _) => Ok(whole(law.encode_into(samples, out))),
            Kind::Wideband(pair, _) => Ok(whole(pair.0.encode_into(samples, out))),
            Kind::Celp(pair) if pair.0.dtx() => Ok(discontinuous(&mut pair.0, samples, out)),
            Kind::Celp(pair) => Ok(whole(pair.0.encode_into(samples, out))),
            #[cfg(feature = "opus")]
            Kind::Opus(pair) => Ok(whole(pair.0.encode(samples, out)?)),
        }
    }

    /// Turn one payload into PCM, and say what it held: audio, comfort noise
    /// alone, or nothing readable.
    ///
    /// A G.729 payload fills the whole of `out`: its frames and its SID
    /// frame decoded, and the rest — a payload that carried less than a
    /// frame's worth — as the pause going on if it ended in one, and
    /// concealed as speech if it did not.
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
            Kind::Celp(pair) => {
                let Some(parsed) = g729::Payload::parse(payload)
                    .filter(|parsed| parsed.frame_count() > 0 || parsed.sid().is_some())
                else {
                    return Ok(Decoded::Unreadable);
                };
                let count = pair.1.decode_into(payload, out);
                let rest = out.get_mut(count..).unwrap_or_default();
                let mut chunks = rest.chunks_exact_mut(g729::FRAME_SAMPLES);
                for chunk in &mut chunks {
                    chunk.copy_from_slice(&pair.1.conceal());
                }
                chunks.into_remainder().fill(0);
                Ok(if parsed.frame_count() == 0 {
                    Decoded::Noise(out.len())
                } else {
                    Decoded::Audio(out.len())
                })
            }
            #[cfg(feature = "opus")]
            Kind::Opus(pair) => Ok(Decoded::Audio(pair.1.decode(payload, out)?)),
        }
    }

    /// Whether the far end is in a pause it announced: a G.729 stream whose
    /// last frame was an Annex B SID frame, or the pause one began. `false`
    /// for every other codec, which announces nothing.
    pub(crate) fn far_end_paused(&self) -> bool {
        matches!(&self.kind, Kind::Celp(pair) if pair.1.in_pause())
    }

    /// Fill a frame the far end did not send, when it did not send it
    /// because it is in a pause: G.729's comfort noise, carried on from the
    /// last SID frame (B.4.4). `None` for every other case — another codec,
    /// or G.729 whose far end was last heard speaking — and nothing is
    /// written.
    pub(crate) fn pause(&mut self, out: &mut [i16]) -> Option<usize> {
        let Kind::Celp(pair) = &mut self.kind else {
            return None;
        };
        if !pair.1.in_pause() {
            return None;
        }
        let frame = self.frame_samples.min(out.len());
        let mut chunks = out
            .get_mut(..frame)
            .unwrap_or_default()
            .chunks_exact_mut(g729::FRAME_SAMPLES);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&pair.1.untransmitted());
        }
        chunks.into_remainder().fill(0);
        Some(frame)
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
            // one leaves a remainder, and that is written silent. In a pause
            // the decoder's concealment is the pause going on (B.4.5)
            Kind::Celp(pair) => {
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

/// One frame of G.729 with Annex B's DTX, cut into a payload as
/// [`Coder::encode`] describes.
fn discontinuous(encoder: &mut g729::Encoder, samples: &[i16], out: &mut [u8]) -> Sent {
    let frames = samples.chunks_exact(g729::FRAME_SAMPLES).map(|chunk| {
        let mut frame = [0_i16; g729::FRAME_SAMPLES];
        frame.copy_from_slice(chunk);
        encoder.encode(&frame)
    });
    cut(frames, out)
}

/// The payload a run of G.729 frames with Annex B makes, written into `out`.
fn cut(frames: impl Iterator<Item = g729::Encoded>, out: &mut [u8]) -> Sent {
    let mut sent = Sent::default();
    let mut speech = 0_usize;
    // a SID frame is in the payload, or a pause came after its speech:
    // nothing more may go in
    let mut closed = false;
    for encoded in frames {
        match encoded {
            g729::Encoded::Nothing => {
                if sent.octets == 0 {
                    sent.skipped += g729::FRAME_SAMPLES;
                } else {
                    closed = true;
                }
            }
            g729::Encoded::Speech(octets) => {
                if closed && speech == 0 {
                    // a SID alone, and speech after it: the SID's frame goes
                    // the way of a frame with nothing to send
                    sent.skipped += g729::FRAME_SAMPLES;
                    sent.octets = 0;
                    closed = false;
                }
                if !closed && append(out, &mut sent.octets, &octets) {
                    speech += 1;
                }
            }
            g729::Encoded::Sid(sid) => {
                if !closed {
                    closed = append(out, &mut sent.octets, sid.as_octets());
                }
            }
        }
    }
    sent
}

/// Put `octets` in `out` after the `written` already there, if they fit.
fn append(out: &mut [u8], written: &mut usize, octets: &[u8]) -> bool {
    let end = *written + octets.len();
    match out.get_mut(*written..end) {
        Some(slot) => {
            slot.copy_from_slice(octets);
            *written = end;
            true
        }
        None => false,
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
    use super::{Coder, Decoded, Sent, cut};
    use crate::codec::{Codec, DEFAULT_FRAME_MS};
    use sipral_media::g729::{Encoded, Sid};

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
                written = coder.encode(&samples, &mut payload).unwrap().octets;
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
                let written = coder.encode(&samples, &mut payload).unwrap().octets;
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
            let written = coder.encode(&samples, &mut payload).unwrap().octets;
            coder.decode(&payload[..written], &mut back).unwrap();
        }
        (coder, payload.to_vec())
    }

    /// A SID frame at the end of a payload decodes the speech before it and
    /// the pause after it, all of the frame written; the frames that then do
    /// not arrive are the pause going on, at the SID's level; and a SID
    /// alone is a frame of noise.
    #[test]
    fn a_g729_sid_frame_is_comfort_noise_and_the_pause_goes_on() {
        let (mut coder, payload) = g729_talking();
        let mut back = [0_i16; 160];
        assert_eq!(coder.pause(&mut back), None, "nothing to carry on yet");
        let mut one_and_sid: Vec<u8> = payload[..10].to_vec();
        one_and_sid.extend_from_slice(&[0x00, 0x14]); // energy index 10, 26 dB
        assert_eq!(
            coder.decode(&one_and_sid, &mut back),
            Ok(Decoded::Audio(160))
        );
        let talking = loudness(&back[..80]);

        let mut quiet = [0_i16; 160];
        for _ in 0..20 {
            assert_eq!(coder.pause(&mut quiet), Some(160));
        }
        assert!(loudness(&quiet) > 0, "noise, not silence");
        assert!(
            loudness(&quiet) * 10 < talking,
            "{} against the speech's {talking}",
            loudness(&quiet)
        );

        // a louder SID alone: noise, and louder
        assert_eq!(
            coder.decode(&[0x00, 0x3e], &mut back), // index 31, 66 dB
            Ok(Decoded::Noise(160))
        );
        let mut louder = [0_i16; 160];
        for _ in 0..20 {
            coder.pause(&mut louder);
        }
        assert!(loudness(&louder) > 10 * loudness(&quiet));
    }

    /// Speech after a pause ends it: a frame that then does not arrive is
    /// concealed as speech, not carried on as noise.
    #[test]
    fn g729_speech_ends_a_pause() {
        let (mut coder, payload) = g729_talking();
        let mut back = [0_i16; 160];
        assert_eq!(
            coder.decode(&[0x00, 0x14], &mut back),
            Ok(Decoded::Noise(160))
        );
        assert_eq!(coder.pause(&mut back), Some(160));
        assert_eq!(coder.decode(&payload, &mut back), Ok(Decoded::Audio(160)));
        assert_eq!(coder.pause(&mut back), None);
    }

    /// With Annex B, a tone goes out as speech, a pause as a SID frame and
    /// then nothing, and the tone again as speech; and a coder that decodes
    /// what went out plays the pause as noise.
    #[test]
    fn g729_with_annex_b_sends_a_pause_as_a_sid_and_then_nothing() {
        let mut coder = Coder::new(Codec::G729, DEFAULT_FRAME_MS).unwrap();
        assert!(!coder.annex_b());
        coder.set_annex_b(true);
        assert!(coder.annex_b());
        let mut far = Coder::new(Codec::G729, DEFAULT_FRAME_MS).unwrap();
        let mut samples = [0_i16; 160];
        let mut payload = [0_u8; 22];
        let mut back = [0_i16; 160];
        let mut phase = 0_u32;
        let mut sent = Vec::new();
        for frame in 0..150 {
            if (50..100).contains(&frame) {
                samples.fill(0);
            } else {
                tone(&mut samples, 8_000, &mut phase);
            }
            let out = coder.encode(&samples, &mut payload).unwrap();
            if out.octets == 0 {
                far.pause(&mut back);
            } else {
                far.decode(&payload[..out.octets], &mut back).unwrap();
            }
            sent.push(out);
        }
        assert!(sent[..50].iter().all(|s| *s
            == Sent {
                octets: 20,
                skipped: 0
            }));
        let pause = &sent[55..100];
        assert!(
            pause.iter().filter(|s| s.octets == 0).count() > 30,
            "{pause:?}"
        );
        assert!(pause.iter().all(|s| s.octets == 0 || s.octets == 2));
        assert!(sent[110..].iter().all(|s| s.octets == 20));
        assert!(loudness(&back) > 500, "the tone decoded again");
    }

    /// The payloads a run of frames with Annex B makes, one case at a time:
    /// what RFC 3551 §4.5.6 lets one payload carry, and what is left out.
    #[test]
    fn a_payload_is_speech_and_then_at_most_one_sid() {
        let speech = Encoded::Speech([7; 10]);
        let sid = Encoded::Sid(Sid::from_octets([0x12, 0x34]));
        let nothing = Encoded::Nothing;
        let mut out = [0_u8; 40];
        let mut run = |frames: &[Encoded]| {
            let sent = cut(frames.iter().copied(), &mut out);
            (sent.octets, sent.skipped)
        };
        assert_eq!(run(&[speech, speech]), (20, 0));
        assert_eq!(run(&[speech, sid]), (12, 0));
        assert_eq!(run(&[sid, nothing]), (2, 0));
        assert_eq!(run(&[nothing, nothing]), (0, 160));
        assert_eq!(run(&[nothing, sid]), (2, 80));
        assert_eq!(run(&[nothing, speech]), (10, 80));
        // a ten-millisecond pause: the SID gives way to the speech after it
        assert_eq!(run(&[sid, speech]), (10, 80));
        assert_eq!(run(&[nothing, sid, speech]), (10, 160));
        // after speech and a SID nothing more fits, speech included
        assert_eq!(run(&[speech, sid, speech]), (12, 0));
        assert_eq!(run(&[speech, sid, nothing]), (12, 0));
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
}
