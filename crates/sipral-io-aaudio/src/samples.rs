// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Between a stream's buffer and a call's mono frames.
//!
//! A stream is asked for one channel of sixteen-bit samples, and AAudio says
//! after opening what it actually runs: a device that only takes two
//! channels, or a path that only carries floats, answers with those. So the
//! callback converts on the way past — both ways, every combination — and
//! does it here, over plain slices, where a test can reach it. Nothing here
//! allocates: it runs on the thread AAudio will not wait for.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

/// One float sample, `[-1.0, 1.0)`, as a sixteen-bit one.
fn from_float(sample: f32) -> i16 {
    let scaled = (sample * 32_768.0).clamp(-32_768.0, 32_767.0);
    // in range by the clamp, and the fraction is meant to go
    #[allow(clippy::cast_possible_truncation)]
    let whole = scaled as i16;
    whole
}

/// One sixteen-bit sample as a float.
fn to_float(sample: i16) -> f32 {
    f32::from(sample) / 32_768.0
}

/// Mix `channels` interleaved sixteen-bit samples down into `out`, as many
/// whole frames as both have room for, and say how many that was.
pub(crate) fn mono_from_i16(interleaved: &[i16], channels: usize, out: &mut [i16]) -> usize {
    let channels = channels.max(1);
    let mut done = 0;
    for (frame, sample) in interleaved.chunks_exact(channels).zip(out.iter_mut()) {
        let sum: i32 = frame.iter().map(|&one| i32::from(one)).sum();
        let divisor = i32::try_from(channels).unwrap_or(1);
        *sample = i16::try_from(sum / divisor).unwrap_or(0);
        done += 1;
    }
    done
}

/// The same from floats.
pub(crate) fn mono_from_f32(interleaved: &[f32], channels: usize, out: &mut [i16]) -> usize {
    let channels = channels.max(1);
    let mut done = 0;
    for (frame, sample) in interleaved.chunks_exact(channels).zip(out.iter_mut()) {
        let sum: f32 = frame.iter().sum();
        // at most a handful of channels
        #[allow(clippy::cast_precision_loss)]
        let mean = sum / channels as f32;
        *sample = from_float(mean);
        done += 1;
    }
    done
}

/// Spread mono `samples` into `channels` interleaved sixteen-bit ones, as
/// many whole frames as both have room for, and say how many that was.
pub(crate) fn i16_from_mono(samples: &[i16], channels: usize, interleaved: &mut [i16]) -> usize {
    let channels = channels.max(1);
    let mut done = 0;
    for (frame, &sample) in interleaved.chunks_exact_mut(channels).zip(samples) {
        frame.fill(sample);
        done += 1;
    }
    done
}

/// The same into floats.
pub(crate) fn f32_from_mono(samples: &[i16], channels: usize, interleaved: &mut [f32]) -> usize {
    let channels = channels.max(1);
    let mut done = 0;
    for (frame, &sample) in interleaved.chunks_exact_mut(channels).zip(samples) {
        frame.fill(to_float(sample));
        done += 1;
    }
    done
}

#[cfg(test)]
mod tests {
    use super::{f32_from_mono, i16_from_mono, mono_from_f32, mono_from_i16};

    #[test]
    fn two_channels_are_averaged_down_and_one_is_spread_back_over_both() {
        let mut mono = [0i16; 4];
        assert_eq!(
            mono_from_i16(&[100, 300, -32_768, -32_768, 32_767, 32_767], 2, &mut mono),
            3
        );
        assert_eq!(mono, [200, -32_768, 32_767, 0]);

        let mut stereo = [0i16; 6];
        assert_eq!(i16_from_mono(&[5, -7, 9, 11], 2, &mut stereo), 3);
        assert_eq!(stereo, [5, 5, -7, -7, 9, 9]);
    }

    #[test]
    fn one_channel_passes_through_and_a_zero_count_is_taken_as_one() {
        let mut mono = [0i16; 3];
        assert_eq!(mono_from_i16(&[1, 2, 3], 1, &mut mono), 3);
        assert_eq!(mono, [1, 2, 3]);
        assert_eq!(mono_from_i16(&[4, 5, 6], 0, &mut mono), 3);
        assert_eq!(mono, [4, 5, 6]);
    }

    #[test]
    // every value compared is a power of two, exact in a float
    #[allow(clippy::float_cmp)]
    fn floats_are_scaled_to_the_sixteen_bit_range_and_clipped_at_its_ends() {
        let mut mono = [0i16; 4];
        assert_eq!(mono_from_f32(&[0.5, -0.5, 2.0, -2.0], 1, &mut mono), 4);
        assert_eq!(mono, [16_384, -16_384, 32_767, -32_768]);
        let mut mono = [0i16; 1];
        assert_eq!(mono_from_f32(&[0.25, 0.75], 2, &mut mono), 1);
        assert_eq!(mono, [16_384]);

        let mut stereo = [0f32; 4];
        assert_eq!(f32_from_mono(&[16_384, -32_768], 2, &mut stereo), 2);
        assert_eq!(stereo, [0.5, 0.5, -1.0, -1.0]);
    }
}
