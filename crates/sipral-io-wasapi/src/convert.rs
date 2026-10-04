// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Between the endpoint's frames and this crate's mono sixteen-bit ones.
//!
//! Two conversions happen here and no third one. Sample type, because the
//! Windows audio engine mixes in float and the codecs above take integers;
//! and channel count, because a call has one channel and an endpoint has as
//! many as it likes. The rate is left exactly as it is — see `format.rs` for
//! why that is a boundary rather than an omission.
//!
//! Everything in this file runs on the audio thread, so it allocates nothing,
//! branches on the format once per buffer rather than once per sample, and
//! has no path that can panic: a slice that is the wrong length is read as
//! silence rather than as a reason to unwind.

use crate::format::{DeviceFormat, SampleFormat};

/// What one full-scale sample is worth as a float.
///
/// Two to the fifteenth in both directions, rather than the 32767 that is
/// sometimes used one way: with the same number on both sides, sixteen-bit
/// through float and back is the same sixteen bits, which is a property worth
/// having when the loopback test is the thing proving the driver works.
const FULL_SCALE: f32 = 32_768.0;

/// One sample of one channel, read out of the endpoint's buffer.
///
/// A lane too short to hold the sample reads as silence. That cannot happen —
/// the caller walks the buffer in exact chunks — but it is the answer that
/// keeps this function total.
fn read(lane: &[u8], sample: SampleFormat) -> i16 {
    match sample {
        SampleFormat::I16 => lane
            .first_chunk::<2>()
            .map_or(0, |octets| i16::from_le_bytes(*octets)),
        // The valid bits sit at the top of the container — that is what
        // "left-justified" in the WAVEFORMATEXTENSIBLE documentation means —
        // so the top sixteen are the sixteen wanted whether the endpoint
        // fills twenty-four of them or all thirty-two.
        SampleFormat::I32 { .. } => lane.first_chunk::<4>().map_or(0, |octets| {
            i16::try_from(i32::from_le_bytes(*octets) >> 16).unwrap_or(0)
        }),
        SampleFormat::F32 => lane
            .first_chunk::<4>()
            .map_or(0, |octets| from_float(f32::from_le_bytes(*octets))),
    }
}

/// One sample of one channel, written into the endpoint's buffer.
fn write(lane: &mut [u8], sample: SampleFormat, value: i16) {
    match sample {
        SampleFormat::I16 => {
            if let Some(octets) = lane.first_chunk_mut::<2>() {
                *octets = value.to_le_bytes();
            }
        }
        SampleFormat::I32 { .. } => {
            if let Some(octets) = lane.first_chunk_mut::<4>() {
                *octets = (i32::from(value) << 16).to_le_bytes();
            }
        }
        SampleFormat::F32 => {
            if let Some(octets) = lane.first_chunk_mut::<4>() {
                *octets = (f32::from(value) / FULL_SCALE).to_le_bytes();
            }
        }
    }
}

/// A float sample as sixteen bits, clipped rather than wrapped.
///
/// `to_int_unchecked` rather than `as`: the three tests above it are the
/// safety argument, and stating it once here is better than an unbounded cast
/// whose saturation nobody reads. A buffer that arrives full of NaN — a device
/// that has gone wrong, or one that has not started — becomes silence, which
/// is the only value that cannot make it worse.
pub(crate) fn from_float(value: f32) -> i16 {
    if value.is_nan() {
        return 0;
    }
    let scaled = (value * FULL_SCALE).round();
    if scaled >= f32::from(i16::MAX) {
        return i16::MAX;
    }
    if scaled <= f32::from(i16::MIN) {
        return i16::MIN;
    }
    // SAFETY: not a NaN, and strictly between the two ends of i16 by the tests
    // above — which catch the infinities too — so the truncation the intrinsic
    // performs is in range.
    unsafe { scaled.to_int_unchecked::<i16>() }
}

/// Fold one buffer of the endpoint's interleaved frames into mono.
///
/// Returns how many frames were written, which is the shorter of what the
/// buffer holds and what `out` has room for.
///
/// Channels are averaged rather than picked from. Taking the first would
/// silently throw away the microphone of a headset that puts it on the second,
/// and a mean is what a person means by "the microphone" on a device with more
/// than one.
pub(crate) fn fold(bytes: &[u8], format: DeviceFormat, out: &mut [i16]) -> usize {
    let block = format.block_align();
    let width = format.sample.bytes();
    if block == 0 || width == 0 {
        return 0;
    }
    let channels = i32::from(format.channels).max(1);
    let mut frames = 0;
    for (frame, slot) in bytes.chunks_exact(block).zip(out.iter_mut()) {
        let mut sum: i32 = 0;
        for lane in frame.chunks_exact(width) {
            sum += i32::from(read(lane, format.sample));
        }
        *slot = i16::try_from(sum / channels).unwrap_or(0);
        frames += 1;
    }
    frames
}

/// Spread mono samples across every channel the endpoint carries.
///
/// Returns how many frames were written. Whatever is left of `bytes` is the
/// caller's to silence.
///
/// Every channel gets the same sample. A call is one voice and it should come
/// out of whichever speaker the person is listening to, which on a device
/// whose channel layout nobody here knows means all of them.
pub(crate) fn spread(mono: &[i16], format: DeviceFormat, bytes: &mut [u8]) -> usize {
    let block = format.block_align();
    let width = format.sample.bytes();
    if block == 0 || width == 0 {
        return 0;
    }
    let mut frames = 0;
    for (sample, frame) in mono.iter().zip(bytes.chunks_exact_mut(block)) {
        for lane in frame.chunks_exact_mut(width) {
            write(lane, format.sample, *sample);
        }
        frames += 1;
    }
    frames
}

/// Silence, in every format here: zero is zero as an integer and as an IEEE
/// float, so one memset covers all three.
pub(crate) fn silence(bytes: &mut [u8]) {
    bytes.fill(0);
}

#[cfg(test)]
mod tests {
    use super::{FULL_SCALE, fold, from_float, silence, spread};
    use crate::format::{DeviceFormat, SampleFormat};

    fn format(channels: u16, sample: SampleFormat) -> DeviceFormat {
        DeviceFormat {
            sample_rate_hz: 48_000,
            channels,
            sample,
        }
    }

    #[test]
    fn sixteen_bit_mono_is_a_copy_in_both_directions() {
        let shape = format(1, SampleFormat::I16);
        let wanted = [-32_768i16, -1, 0, 1, 32_767];
        let mut bytes = vec![0u8; wanted.len() * 2];
        assert_eq!(spread(&wanted, shape, &mut bytes), 5);

        let mut back = [0i16; 5];
        assert_eq!(fold(&bytes, shape, &mut back), 5);
        assert_eq!(back, wanted);
    }

    #[test]
    fn float_round_trips_exactly_because_the_scale_is_the_same_both_ways() {
        let shape = format(1, SampleFormat::F32);
        let wanted: Vec<i16> = (-32_768..32_767).step_by(37).collect();
        let mut bytes = vec![0u8; wanted.len() * 4];
        assert_eq!(spread(&wanted, shape, &mut bytes), wanted.len());

        let mut back = vec![0i16; wanted.len()];
        assert_eq!(fold(&bytes, shape, &mut back), wanted.len());
        assert_eq!(back, wanted);
    }

    #[test]
    fn a_full_scale_float_is_the_loudest_sample_and_not_the_quietest() {
        // the one that wraps if the conversion is a bare cast
        assert_eq!(from_float(1.0), i16::MAX);
        assert_eq!(from_float(-1.0), i16::MIN);
        assert_eq!(from_float(2.5), i16::MAX);
        assert_eq!(from_float(-9.0), i16::MIN);
        assert_eq!(from_float(f32::INFINITY), i16::MAX);
        assert_eq!(from_float(f32::NEG_INFINITY), i16::MIN);
        assert_eq!(from_float(f32::NAN), 0);
        assert_eq!(from_float(0.0), 0);
        assert_eq!(from_float(0.5), 16_384);
        assert!((f32::from(16_384i16) / FULL_SCALE - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn twenty_four_in_thirty_two_keeps_the_top_sixteen() {
        let shape = format(1, SampleFormat::I32 { valid_bits: 24 });
        let wanted = [-32_768i16, -256, 0, 4_096, 32_767];
        let mut bytes = vec![0u8; wanted.len() * 4];
        assert_eq!(spread(&wanted, shape, &mut bytes), 5);
        let mut back = [0i16; 5];
        assert_eq!(fold(&bytes, shape, &mut back), 5);
        assert_eq!(back, wanted);

        // and the low bits a real device fills are dropped rather than read
        let quarter = 0x1234_5678i32.to_le_bytes();
        let mut one = [0i16; 1];
        assert_eq!(fold(&quarter, shape, &mut one), 1);
        assert_eq!(one, [0x1234]);
    }

    #[test]
    fn every_channel_gets_the_same_sample_and_the_mean_gives_it_back() {
        for channels in [1u16, 2, 6, 16] {
            let shape = format(channels, SampleFormat::F32);
            let wanted = [1_000i16, -2_000, 3_000];
            let mut bytes = vec![0u8; wanted.len() * shape.block_align()];
            assert_eq!(spread(&wanted, shape, &mut bytes), 3);
            let mut back = [0i16; 3];
            assert_eq!(fold(&bytes, shape, &mut back), 3);
            assert_eq!(back, wanted, "at {channels} channels");
        }
    }

    #[test]
    fn a_microphone_on_the_second_channel_is_not_thrown_away() {
        // the case that a "take the first channel" fold gets wrong: a stereo
        // endpoint with silence on the left and a voice on the right
        let shape = format(2, SampleFormat::I16);
        let mut bytes = Vec::new();
        for sample in [1_000i16, 2_000, 3_000] {
            bytes.extend_from_slice(&0i16.to_le_bytes());
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        let mut back = [0i16; 3];
        assert_eq!(fold(&bytes, shape, &mut back), 3);
        assert_eq!(back, [500, 1_000, 1_500]);
    }

    #[test]
    fn a_short_buffer_stops_at_what_it_holds() {
        let shape = format(2, SampleFormat::F32);
        // two and a half frames of room, so two frames come out
        let bytes = vec![0u8; 20];
        let mut back = [7i16; 8];
        assert_eq!(fold(&bytes, shape, &mut back), 2);
        assert_eq!(back, [0, 0, 7, 7, 7, 7, 7, 7]);

        let mono = [1i16; 8];
        let mut out = vec![0xffu8; 20];
        assert_eq!(spread(&mono, shape, &mut out), 2);
        // the odd half frame at the end is left exactly as it was, for the
        // caller to silence
        assert_eq!(&out[16..], &[0xffu8; 4]);
    }

    #[test]
    fn an_empty_buffer_moves_nothing_rather_than_falling_over() {
        let shape = format(2, SampleFormat::I16);
        let mut back = [0i16; 4];
        assert_eq!(fold(&[], shape, &mut back), 0);
        assert_eq!(spread(&[1, 2], shape, &mut []), 0);
        assert_eq!(fold(&[0, 0, 0, 0], shape, &mut []), 0);
    }

    #[test]
    fn a_device_claiming_no_channels_at_all_is_not_divided_by() {
        let shape = format(0, SampleFormat::I16);
        let mut back = [0i16; 4];
        assert_eq!(fold(&[0, 0, 0, 0], shape, &mut back), 0);
        assert_eq!(spread(&[1, 2], shape, &mut [0, 0, 0, 0]), 0);
    }

    #[test]
    fn silence_is_zero_in_every_format() {
        let mut bytes = [0xffu8; 16];
        silence(&mut bytes);
        assert_eq!(bytes, [0u8; 16]);
        for sample in [
            SampleFormat::I16,
            SampleFormat::I32 { valid_bits: 24 },
            SampleFormat::F32,
        ] {
            let shape = format(2, sample);
            let mut back = [1i16; 2];
            // two frames, because that is all `back` has room for
            assert_eq!(fold(&bytes, shape, &mut back), 2);
            assert_eq!(back, [0, 0]);
        }
    }
}
