// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! G.711 companding, which RFC 3551 §4.5.14 carries as PCMU and PCMA.
//!
//! Both laws fold a 16-bit linear sample into one octet the same way: a sign
//! bit, a three-bit chord and a four-bit step inside that chord. The step
//! grows with the chord, which is the whole trick — quiet passages are
//! quantised finely and loud ones coarsely, and eight bits end up sounding
//! like fourteen. Where it starts to grow differs: mu-law doubles it at every
//! chord, and A-law gives its first two chords the same step and doubles from
//! there. The laws also differ in where the chords start and in what is done
//! to the octet before it goes on the wire.
//!
//! RFC 3551 §4.5.14 adds one rule of its own: "The sign bit of each G.711
//! octet SHALL correspond to the most significant bit of the octet in the RTP
//! packet", which is what both encoders here produce.

pub mod a_law;
pub mod mu_law;

/// The clock rate the static payload types are registered at, in hertz
/// (RFC 3551 §6), and the rate written after the encoding name on an
/// `a=rtpmap` line for them.
///
/// Not a property of the law. Table 1 of §4.5 gives the sampling rate for both
/// as "var.", and §6's own example of a dynamic binding is "payload type 96
/// indicates PCMU encoding, 8,000 Hz sampling rate, 2 channels" — so an
/// encoding bound dynamically may say something else, and a caller that reads
/// an `a=rtpmap` should believe it rather than this.
pub const CLOCK_RATE: u32 = 8_000;

/// One, which is how the static payload types are registered (RFC 3551 §6).
/// As with the clock rate, a dynamic binding may say otherwise.
pub const CHANNELS: u8 = 1;

/// The packetisation interval RFC 3551 §4.5 gives as the default for both
/// laws, in milliseconds. A caller may send another and say so with `a=ptime`;
/// this is what the far end assumes when nothing does.
pub const DEFAULT_PTIME_MS: u32 = 20;

/// How many samples a frame of `millis` milliseconds holds at [`CLOCK_RATE`].
///
/// Twenty milliseconds is 160 samples, which is the number every G.711 caller
/// ends up writing down somewhere; this is where it comes from.
#[must_use]
pub const fn frame_samples(millis: u32) -> usize {
    (CLOCK_RATE as usize).saturating_mul(millis as usize) / 1000
}

/// How many octets that same frame occupies on the wire.
///
/// The same number, because both laws spend exactly one octet per sample. It
/// is a separate function because the two are different quantities that happen
/// to be equal here, and a caller sizing a packet buffer should say which it
/// means.
#[must_use]
pub const fn frame_octets(millis: u32) -> usize {
    frame_samples(millis)
}

/// Which of the two laws a stream carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Law {
    /// mu-law, `PCMU`, payload type 0. North America and Japan.
    Mu,
    /// A-law, `PCMA`, payload type 8. Everywhere else, and what most European
    /// carriers put first in an offer.
    A,
}

impl Law {
    /// The static payload type RFC 3551 §6 assigns to this law.
    #[must_use]
    pub const fn payload_type(self) -> u8 {
        match self {
            Self::Mu => 0,
            Self::A => 8,
        }
    }

    /// The law a static payload type names, if it names one of these two.
    #[must_use]
    pub const fn from_payload_type(payload_type: u8) -> Option<Self> {
        match payload_type {
            0 => Some(Self::Mu),
            8 => Some(Self::A),
            _ => None,
        }
    }

    /// The encoding name an `a=rtpmap` line carries for it.
    #[must_use]
    pub const fn encoding_name(self) -> &'static str {
        match self {
            Self::Mu => "PCMU",
            Self::A => "PCMA",
        }
    }

    /// One linear sample as one octet.
    #[must_use]
    pub fn encode(self, sample: i16) -> u8 {
        match self {
            Self::Mu => mu_law::encode(sample),
            Self::A => a_law::encode(sample),
        }
    }

    /// One octet back to one linear sample.
    #[must_use]
    pub fn decode(self, octet: u8) -> i16 {
        match self {
            Self::Mu => mu_law::decode(octet),
            Self::A => a_law::decode(octet),
        }
    }

    /// Encode a frame of samples into `octets`, one octet per sample.
    ///
    /// Converts the shorter of the two lengths and returns how many, so a
    /// caller that sized both from [`frame_samples`] and [`frame_octets`] gets
    /// the whole frame and one that did not gets a number it can check.
    pub fn encode_into(self, samples: &[i16], octets: &mut [u8]) -> usize {
        let converted = samples.len().min(octets.len());
        for (sample, octet) in samples.iter().zip(octets.iter_mut()) {
            *octet = self.encode(*sample);
        }
        converted
    }

    /// Decode a frame of octets into `samples`, one sample per octet.
    ///
    /// Converts the shorter of the two lengths and returns how many.
    pub fn decode_into(self, octets: &[u8], samples: &mut [i16]) -> usize {
        let converted = octets.len().min(samples.len());
        for (octet, sample) in octets.iter().zip(samples.iter_mut()) {
            *sample = self.decode(*octet);
        }
        converted
    }
}

/// Which chord a magnitude falls in.
///
/// Chord `n` runs from 2^(n+7) up to 2^(n+8)-1, so this is the position of the
/// top set bit less seven, with everything quieter than 256 in chord 0 and
/// everything louder than 16383 in chord 7. Both laws chop the range the same
/// way. mu-law biases its magnitude first, which forces bit 7 on and so leaves
/// nothing below chord 0.
fn chord_of(magnitude: u16) -> u8 {
    let mut chord = 7;
    while chord > 0 && magnitude < (0x0080 << chord) {
        chord -= 1;
    }
    chord
}

/// The four bits of the step, read off the magnitude at the shift the chord
/// asks for.
fn step_of(magnitude: u16, shift: u8) -> u8 {
    ((magnitude >> shift) & 0x0F) as u8
}

#[cfg(test)]
mod tests {
    use super::{
        CHANNELS, CLOCK_RATE, DEFAULT_PTIME_MS, Law, a_law, frame_octets, frame_samples, mu_law,
    };

    /// How far a round trip through a law is allowed to move a sample: half the
    /// step of the chord it falls in, plus whatever the law refused to carry
    /// because the sample was past its overload point.
    ///
    /// Worked out here from the segmentation rather than from the code under
    /// test, and counting the chords upwards where `chord_of` counts down.
    fn tolerance(law: Law, sample: i16) -> i32 {
        let magnitude = i32::from(sample).abs();
        // what the law agreed to carry, and the value it reads the chord off:
        // mu-law clips at 32635 and chords the biased magnitude, A-law clips at
        // 32767 and chords the magnitude itself
        let (carried, chorded) = match law {
            Law::Mu => (magnitude.min(32_635), magnitude.min(32_635) + 0x84),
            Law::A => (magnitude.min(32_767), magnitude.min(32_767)),
        };
        let mut chord = 0;
        while chord < 7 && chorded >= 256 << chord {
            chord += 1;
        }
        // A-law's first two chords share a step of 16, so the first one is not
        // half of what the doubling would say
        let half_step = if law == Law::A && chord == 0 {
            8
        } else {
            1 << (chord + 2)
        };
        half_step + (magnitude - carried)
    }

    #[test]
    fn the_static_payload_types_are_the_ones_rfc_3551_fixed() {
        assert_eq!(Law::Mu.payload_type(), 0);
        assert_eq!(Law::A.payload_type(), 8);
        assert_eq!(Law::Mu.encoding_name(), "PCMU");
        assert_eq!(Law::A.encoding_name(), "PCMA");
        assert_eq!(CLOCK_RATE, 8_000);
        assert_eq!(CHANNELS, 1);
        for law in [Law::Mu, Law::A] {
            assert_eq!(Law::from_payload_type(law.payload_type()), Some(law));
        }
        // 9 is G722 and 18 is G729, neither of which is this crate's business
        assert_eq!(Law::from_payload_type(9), None);
        assert_eq!(Law::from_payload_type(18), None);
    }

    #[test]
    fn a_twenty_millisecond_frame_is_a_hundred_and_sixty_samples_and_as_many_octets() {
        assert_eq!(DEFAULT_PTIME_MS, 20);
        assert_eq!(frame_samples(DEFAULT_PTIME_MS), 160);
        assert_eq!(frame_octets(DEFAULT_PTIME_MS), 160);
        // the intervals a carrier actually asks for with a=ptime
        assert_eq!(frame_samples(10), 80);
        assert_eq!(frame_samples(30), 240);
        assert_eq!(frame_samples(60), 480);
        assert_eq!(frame_samples(0), 0);
    }

    #[test]
    fn the_dispatching_methods_agree_with_the_laws() {
        for sample in i16::MIN..=i16::MAX {
            assert_eq!(Law::Mu.encode(sample), mu_law::encode(sample));
            assert_eq!(Law::A.encode(sample), a_law::encode(sample));
        }
        for octet in 0..=u8::MAX {
            assert_eq!(Law::Mu.decode(octet), mu_law::decode(octet));
            assert_eq!(Law::A.decode(octet), a_law::decode(octet));
        }
    }

    #[test]
    fn a_frame_survives_the_slice_helpers_within_the_quantisation_error() {
        // a sawtooth that wraps through both polarities, so one frame touches
        // every chord instead of only the quiet ones
        let samples: Vec<i16> = (0..160).map(|n: i16| n.wrapping_mul(401)).collect();
        for law in [Law::Mu, Law::A] {
            let mut octets = vec![0_u8; frame_octets(DEFAULT_PTIME_MS)];
            assert_eq!(law.encode_into(&samples, &mut octets), 160);

            let mut back = vec![0_i16; frame_samples(DEFAULT_PTIME_MS)];
            assert_eq!(law.decode_into(&octets, &mut back), 160);

            for (sample, round) in samples.iter().zip(back.iter()) {
                let error = (i32::from(*round) - i32::from(*sample)).abs();
                assert!(
                    error <= tolerance(law, *sample),
                    "{law:?}: {sample} came back as {round}"
                );
            }
        }
    }

    #[test]
    fn the_slice_helpers_stop_at_the_shorter_of_the_two() {
        let samples = [1_000_i16; 8];
        let mut octets = [0_u8; 3];
        assert_eq!(Law::Mu.encode_into(&samples, &mut octets), 3);
        assert!(octets.iter().all(|o| *o == Law::Mu.encode(1_000)));

        let mut roomy = [0_u8; 16];
        assert_eq!(Law::A.encode_into(&samples, &mut roomy), 8);
        assert_eq!(roomy[8], 0);

        let mut back = [0_i16; 2];
        assert_eq!(Law::A.decode_into(&roomy, &mut back), 2);
        assert_eq!(Law::A.encode_into(&[], &mut roomy), 0);
        assert_eq!(Law::A.decode_into(&[], &mut back), 0);
    }

    #[test]
    fn no_sample_comes_back_further_off_than_half_a_step() {
        for law in [Law::Mu, Law::A] {
            for sample in i16::MIN..=i16::MAX {
                let round = law.decode(law.encode(sample));
                let error = (i32::from(round) - i32::from(sample)).abs();
                assert!(
                    error <= tolerance(law, sample),
                    "{law:?}: {sample} came back as {round}, off by {error}"
                );
            }
        }
    }

    #[test]
    fn the_round_trip_never_runs_backwards() {
        // a companding law is monotone: a louder sample never decodes quieter,
        // and the sign bit is not allowed to fold the curve back on itself
        for law in [Law::Mu, Law::A] {
            let mut previous = law.decode(law.encode(i16::MIN));
            for sample in i16::MIN..=i16::MAX {
                let round = law.decode(law.encode(sample));
                assert!(
                    round >= previous,
                    "{law:?}: {sample} decoded to {round}, below the sample before it"
                );
                previous = round;
            }
        }
    }
}
