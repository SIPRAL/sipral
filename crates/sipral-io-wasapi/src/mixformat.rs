// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Asking an endpoint for a format, and reading the answer.
//!
//! Two functions, and the second one is where the honesty is. Windows in
//! shared mode does not run the endpoint at the format a client asks for — it
//! runs the audio engine's mix format and lets the engine do the rest — so the
//! question "will you take mono sixteen-bit at eight kilohertz" nearly always
//! comes back as "no, here is what I do run". This turns that answer into
//! something the caller can act on rather than something the crate pretends
//! did not happen.

use crate::abi::{
    SPEAKER_FRONT_CENTER, SUBTYPE_IEEE_FLOAT, SUBTYPE_PCM, WAVE_FORMAT_EXTENSIBLE,
    WAVE_FORMAT_IEEE_FLOAT, WAVE_FORMAT_PCM, WaveFormat, WaveFormatExtensible,
};
use crate::format::{DeviceFormat, SampleFormat};
use crate::status::Error;

/// The lowest rate this crate believes an endpoint about.
const MIN_RATE_HZ: u32 = 8_000;

/// The highest.
const MAX_RATE_HZ: u32 = 384_000;

/// The most channels an endpoint may claim before this crate stops believing
/// it. Sixteen-channel virtual cables exist and are ordinary; a device
/// claiming hundreds has answered a question it did not understand.
const MAX_CHANNELS: u16 = 64;

/// Read a `WAVEFORMATEX` the engine handed over.
///
/// The tag decides how to read the rest, and `WAVE_FORMAT_EXTENSIBLE` says to
/// look at the subtype instead — which is the case that matters, because the
/// mix format of a machine with more than two channels always takes that form.
/// A format that is neither integer nor float PCM is refused here rather than
/// read as whichever of the two it resembles.
///
/// # Errors
/// [`Error::SampleFormat`] when the samples are a width or a kind this crate
/// does not convert, and when the endpoint describes itself in a way no
/// endpoint could be.
pub(crate) fn describe(format: &WaveFormatExtensible) -> Result<DeviceFormat, Error> {
    // copied out one at a time: the structure is byte-packed, so there is no
    // reference to be taken to a field of it
    let tag = format.format.format_tag;
    let channels = format.format.channels;
    let sample_rate_hz = format.format.samples_per_sec;
    let bits = format.format.bits_per_sample;
    let extended = tag == WAVE_FORMAT_EXTENSIBLE
        && format.format.cb_size >= WaveFormatExtensible::EXTENSION_BYTES;

    let floating = if extended {
        let sub = format.sub_format;
        if sub == SUBTYPE_IEEE_FLOAT {
            true
        } else if sub == SUBTYPE_PCM {
            false
        } else {
            return Err(Error::SampleFormat {
                bits,
                floating: false,
            });
        }
    } else if tag == WAVE_FORMAT_IEEE_FLOAT {
        true
    } else if tag == WAVE_FORMAT_PCM {
        false
    } else {
        return Err(Error::SampleFormat {
            bits,
            floating: false,
        });
    };

    // valid bits of zero means "all of them", which is what a driver writes
    // when it has nothing to say; a driver claiming more valid bits than it
    // has container for is contradicting itself and is believed only as far
    // as the container
    let valid_bits = if extended && format.valid_bits_per_sample != 0 {
        format.valid_bits_per_sample.min(bits)
    } else {
        bits
    };

    let sample = match (floating, bits) {
        (true, 32) => SampleFormat::F32,
        (false, 16) => SampleFormat::I16,
        (false, 32) => SampleFormat::I32 { valid_bits },
        _ => return Err(Error::SampleFormat { bits, floating }),
    };

    if channels == 0
        || channels > MAX_CHANNELS
        || !(MIN_RATE_HZ..=MAX_RATE_HZ).contains(&sample_rate_hz)
    {
        return Err(Error::SampleFormat { bits, floating });
    }

    Ok(DeviceFormat {
        sample_rate_hz,
        channels,
        sample,
    })
}

/// The format to ask an endpoint for: one channel of signed sixteen-bit at the
/// rate the caller wants.
///
/// Spelled as a plain `WAVEFORMATEX` — `cbSize` is zero and the extension is
/// left blank. Mono sixteen-bit is exactly the case the extensible form was
/// not invented for, it is the spelling every driver has seen, and asking with
/// the long form would be asking the same question in a dialect fewer of them
/// answer.
pub(crate) fn request(sample_rate_hz: u32) -> WaveFormatExtensible {
    let block_align = 2;
    WaveFormatExtensible {
        format: WaveFormat {
            format_tag: WAVE_FORMAT_PCM,
            channels: 1,
            samples_per_sec: sample_rate_hz,
            avg_bytes_per_sec: sample_rate_hz.saturating_mul(u32::from(block_align)),
            block_align,
            bits_per_sample: 16,
            cb_size: 0,
        },
        valid_bits_per_sample: 0,
        channel_mask: SPEAKER_FRONT_CENTER,
        sub_format: SUBTYPE_PCM,
    }
}

#[cfg(test)]
mod tests {
    use super::{describe, request};
    use crate::abi::{
        Guid, SPEAKER_FRONT_CENTER, SUBTYPE_IEEE_FLOAT, SUBTYPE_PCM, WAVE_FORMAT_EXTENSIBLE,
        WAVE_FORMAT_IEEE_FLOAT, WAVE_FORMAT_PCM, WaveFormat, WaveFormatExtensible,
    };
    use crate::format::{DeviceFormat, SampleFormat, StreamFormat};
    use crate::status::Error;

    /// A `WAVEFORMATEXTENSIBLE` the way the engine writes one: the tag is
    /// extensible, `cbSize` is twenty-two, and the subtype carries the truth.
    fn extensible(
        rate: u32,
        channels: u16,
        bits: u16,
        valid: u16,
        float: bool,
    ) -> WaveFormatExtensible {
        let block_align = channels * bits / 8;
        WaveFormatExtensible {
            format: WaveFormat {
                format_tag: WAVE_FORMAT_EXTENSIBLE,
                channels,
                samples_per_sec: rate,
                avg_bytes_per_sec: rate * u32::from(block_align),
                block_align,
                bits_per_sample: bits,
                cb_size: WaveFormatExtensible::EXTENSION_BYTES,
            },
            valid_bits_per_sample: valid,
            channel_mask: 0x3,
            sub_format: if float {
                SUBTYPE_IEEE_FLOAT
            } else {
                SUBTYPE_PCM
            },
        }
    }

    #[test]
    fn the_request_is_the_short_spelling_of_mono_sixteen_bit() {
        let wanted = request(8_000);
        let tag = wanted.format.format_tag;
        let channels = wanted.format.channels;
        let rate = wanted.format.samples_per_sec;
        let average = wanted.format.avg_bytes_per_sec;
        let align = wanted.format.block_align;
        let bits = wanted.format.bits_per_sample;
        let extension = wanted.format.cb_size;
        let mask = wanted.channel_mask;
        assert_eq!(tag, WAVE_FORMAT_PCM);
        assert_eq!(channels, 1);
        assert_eq!(rate, 8_000);
        assert_eq!(align, 2);
        assert_eq!(bits, 16);
        assert_eq!(average, 16_000);
        assert_eq!(extension, 0);
        assert_eq!(mask, SPEAKER_FRONT_CENTER);

        // and it reads back as what it says it is
        assert_eq!(
            describe(&wanted),
            Ok(DeviceFormat {
                sample_rate_hz: 8_000,
                channels: 1,
                sample: SampleFormat::I16,
            })
        );
        assert!(describe(&wanted).unwrap().is(StreamFormat::narrowband()));
    }

    #[test]
    fn the_ordinary_windows_mix_format_reads_as_float() {
        // what nearly every machine answers with: 48 kHz, stereo, float
        let mixed = extensible(48_000, 2, 32, 32, true);
        let format = describe(&mixed).unwrap();
        assert_eq!(
            format,
            DeviceFormat {
                sample_rate_hz: 48_000,
                channels: 2,
                sample: SampleFormat::F32,
            }
        );
        assert_eq!(format.block_align(), 8);
        assert!(!format.is(StreamFormat::narrowband()));
        assert_eq!(format.to_string(), "48000 Hz, 2 channels, 32-bit float");
    }

    #[test]
    fn a_sixteen_channel_cable_is_a_device_like_any_other() {
        let cable = extensible(48_000, 16, 32, 32, true);
        let format = describe(&cable).unwrap();
        assert_eq!(format.channels, 16);
        assert_eq!(format.block_align(), 64);
    }

    #[test]
    fn the_short_spelling_is_read_by_its_tag() {
        let mut plain = extensible(44_100, 2, 16, 0, false);
        plain.format.format_tag = WAVE_FORMAT_PCM;
        plain.format.cb_size = 0;
        // the subtype still says PCM, but with cbSize at zero it is not there
        // to be read, and the tag is what decides
        assert_eq!(describe(&plain).unwrap().sample, SampleFormat::I16);

        let mut floated = extensible(44_100, 1, 32, 0, false);
        floated.format.format_tag = WAVE_FORMAT_IEEE_FLOAT;
        floated.format.cb_size = 0;
        assert_eq!(describe(&floated).unwrap().sample, SampleFormat::F32);
    }

    #[test]
    fn an_extensible_header_that_lies_about_its_size_is_not_read_past() {
        // the tag says extensible but cbSize does not cover the subtype, so
        // there is nothing there to read: the tag alone is not a format this
        // crate knows, and it is refused rather than read out of whatever
        // happens to follow
        let mut truncated = extensible(48_000, 2, 32, 32, true);
        truncated.format.cb_size = 0;
        assert!(matches!(
            describe(&truncated),
            Err(Error::SampleFormat { bits: 32, .. })
        ));
    }

    #[test]
    fn twenty_four_in_thirty_two_keeps_both_numbers() {
        let studio = extensible(96_000, 2, 32, 24, false);
        assert_eq!(
            describe(&studio).unwrap().sample,
            SampleFormat::I32 { valid_bits: 24 }
        );
        let vague = extensible(96_000, 2, 32, 0, false);
        assert_eq!(
            describe(&vague).unwrap().sample,
            SampleFormat::I32 { valid_bits: 32 }
        );
        let confused = extensible(96_000, 2, 32, 64, false);
        assert_eq!(
            describe(&confused).unwrap().sample,
            SampleFormat::I32 { valid_bits: 32 }
        );
    }

    #[test]
    fn widths_this_crate_does_not_convert_are_refused_rather_than_guessed_at() {
        assert_eq!(
            describe(&extensible(48_000, 2, 24, 24, false)),
            Err(Error::SampleFormat {
                bits: 24,
                floating: false
            })
        );
        assert_eq!(
            describe(&extensible(48_000, 2, 64, 64, true)),
            Err(Error::SampleFormat {
                bits: 64,
                floating: true
            })
        );
        assert_eq!(
            describe(&extensible(48_000, 2, 8, 8, false)),
            Err(Error::SampleFormat {
                bits: 8,
                floating: false
            })
        );
    }

    #[test]
    fn an_endpoint_that_makes_no_sense_is_refused() {
        assert!(describe(&extensible(48_000, 0, 16, 16, false)).is_err());
        assert!(describe(&extensible(48_000, 200, 16, 16, false)).is_err());
        assert!(describe(&extensible(1_000, 2, 16, 16, false)).is_err());
        assert!(describe(&extensible(768_000, 2, 16, 16, false)).is_err());
    }

    #[test]
    fn a_subtype_nobody_recognises_is_refused() {
        let mut odd = extensible(48_000, 2, 32, 32, true);
        odd.sub_format = Guid::new(0x1234_5678, 0, 0, [0; 8]);
        assert!(describe(&odd).is_err());
    }
}
