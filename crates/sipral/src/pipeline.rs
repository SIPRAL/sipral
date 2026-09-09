// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One codec, driven for one call.
//!
//! `sipral-media` holds four encoders and four decoders and has no opinion
//! about which of them a call is using, because it never sees a negotiation.
//! This is where the negotiation's answer becomes a pair of state machines: an
//! encoder fed frames of PCM and a decoder fed payloads, both at the rate the
//! codec hears at rather than the rate the wire counts in.
//!
//! Concealment belongs here for the same reason. Opus carries its own — it can
//! reconstruct a lost frame from the redundancy in the next one, which is
//! better than anything that works on the decoded waveform — and the three
//! written codecs get [`plc::Concealer`], which extends the pitch period of
//! the last audio that arrived. Which of the two runs is decided by what the
//! call negotiated and by nothing else, so the decision is made once, here,
//! rather than at every lost packet.

use sipral_media::g711::Law;
use sipral_media::opus::{FrameDuration, SampleRate};
use sipral_media::plc::Concealer;
use sipral_media::{g722, opus};

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
/// a trait: four codecs is not enough to earn dynamic dispatch, and the
/// differences between them — a stateless companding table, a filter bank with
/// memory, a C library with a pointer — do not share a shape worth naming.
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
    /// Opus, which conceals for itself.
    Opus(Box<(opus::Encoder, opus::Decoder)>),
}

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
    /// [`MediaError::Codec`] when Opus refuses the rate or the frame length,
    /// which for the frame length can only happen for a peer that negotiated
    /// a `ptime` Opus has no frame for.
    pub(crate) fn new(codec: Codec, frame_ms: u32) -> Result<Self, MediaError> {
        let kind = match codec {
            Codec::Pcmu => Kind::Companded(Law::Mu, Concealer::new()),
            Codec::Pcma => Kind::Companded(Law::A, Concealer::new()),
            Codec::G722 => Kind::Wideband(
                Box::new((g722::Encoder::new(), g722::Decoder::default())),
                Concealer::new(),
            ),
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
    /// [`MediaError::Codec`] when Opus refuses the frame.
    pub(crate) fn encode(&mut self, samples: &[i16], out: &mut [u8]) -> Result<usize, MediaError> {
        match &mut self.kind {
            Kind::Companded(law, _) => Ok(law.encode_into(samples, out)),
            Kind::Wideband(pair, _) => Ok(pair.0.encode_into(samples, out)),
            Kind::Opus(pair) => Ok(pair.0.encode(samples, out)?),
        }
    }

    /// Turn one payload into PCM, and say how many samples it held.
    ///
    /// # Errors
    /// [`MediaError::Codec`] when Opus refuses the packet, which for a payload
    /// off the wire means a corrupt one.
    pub(crate) fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, MediaError> {
        match &mut self.kind {
            Kind::Companded(law, concealer) => {
                let count = law.decode_into(payload, out);
                concealer.received(out.get_mut(..count).unwrap_or_default());
                Ok(count)
            }
            Kind::Wideband(pair, concealer) => {
                let count = pair.1.decode_into(payload, out);
                concealer.received(out.get_mut(..count).unwrap_or_default());
                Ok(count)
            }
            Kind::Opus(pair) => Ok(pair.1.decode(payload, out)?),
        }
    }

    /// Fill a frame the far end sent and this end did not get.
    ///
    /// # Errors
    /// [`MediaError::Codec`] when Opus refuses, which it does only for an
    /// output slice too short for one frame.
    pub(crate) fn conceal(&mut self, out: &mut [i16]) -> Result<usize, MediaError> {
        let frame = self.frame_samples.min(out.len());
        match &mut self.kind {
            Kind::Companded(_, concealer) | Kind::Wideband(_, concealer) => {
                concealer.conceal(out.get_mut(..frame).unwrap_or_default());
                Ok(frame)
            }
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
    use super::Coder;
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
            let mut decoded = 0;
            for _ in 0..25 {
                tone(&mut samples, codec.sample_rate(), &mut phase);
                written = coder.encode(&samples, &mut payload).unwrap();
                decoded = coder.decode(&payload[..written], &mut back).unwrap();
            }
            assert!(written > 0, "{codec} produced an empty payload");
            assert_eq!(decoded, frame, "{codec} gave back the wrong frame length");
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
    #[test]
    fn opus_refuses_a_frame_length_it_has_no_frame_for() {
        assert!(Coder::new(Codec::Opus, 30).is_err());
        assert!(Coder::new(Codec::Pcmu, 30).is_ok());
    }
}
