// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `sipral_media_set_app_rate` from the C side: the frames a call hands out
//! and takes at the rate the application chose, a tone that crosses a call
//! that way both directions and comes out as the tone it was, and every
//! refusal.

use std::f64::consts::TAU;
use std::ptr;

use sipral::Capabilities;

use crate::audio::SipralAudioActivation;
use crate::audio::tests::{a_desk, device_call};
use crate::call::sipral_call_join;
use crate::call::tests::{PEER_MEDIA, media_call, media_call_offering, media_call_pair};
use crate::error::last_error_text;
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::tests::{Buffers, OPUS_ANSWER, media_info, media_of};
use crate::media::{
    SipralPlayback, sipral_call_media, sipral_media_capture, sipral_media_mix,
    sipral_media_playback, sipral_media_receive, sipral_media_set_app_rate,
};
use crate::stack::sipral_stack_destroy;
use crate::stack::tests::Observed;
use crate::status::SipralStatus;

/// The tone sent, and how loud: a quarter of full scale, well clear of
/// clipping in either codec.
const TONE_HZ: f64 = 1_000.0;
const AMPLITUDE: f64 = 8_000.0;

/// What the tone may come back as: within one percent of its frequency and
/// one and a half decibels of its level, which is wider than G.711's
/// quantisation or Opus at its default bitrate moves a steady tone and
/// narrower than any resampling mistake — a wrong ratio moves the pitch by a
/// third or more, and a filter in the wrong place takes the level with it.
const FREQUENCY_TOLERANCE: f64 = 0.01;
const LEVEL_TOLERANCE_DB: f64 = 1.5;

/// Frames pumped before the measurement starts, for the jitter buffer and
/// the two filters to fill, and frames measured: 400 ms, 400 cycles.
const SETTLING_FRAMES: usize = 30;
const MEASURED_FRAMES: usize = 20;

fn set_rate(media: SipralHandle, hz: u32) -> SipralStatus {
    unsafe { sipral_media_set_app_rate(media, hz) }
}

/// One frame of the tone at `rate`, carrying on from `phase`.
fn tone_frame(samples: usize, rate: u32, phase: &mut f64) -> Vec<i16> {
    let step = TAU * TONE_HZ / f64::from(rate);
    (0..samples)
        .map(|_| {
            let value = AMPLITUDE * phase.sin();
            *phase = (*phase + step) % TAU;
            // a quarter of full scale, so the cast never saturates
            #[expect(
                clippy::cast_possible_truncation,
                reason = "within i16 by construction"
            )]
            let sample = value.round() as i16;
            sample
        })
        .collect()
}

/// Play one frame of `media` at whatever rate it hands out, refusing a
/// buffer one sample short first so the length is the library's own.
fn playback(media: SipralHandle) -> (Vec<i16>, SipralPlayback) {
    let frame = media_info(media).frame_samples;
    let mut short = vec![0_i16; frame - 1];
    let mut written = 0_usize;
    assert_eq!(
        unsafe {
            sipral_media_playback(
                media,
                short.as_mut_ptr(),
                short.len(),
                &raw mut written,
                ptr::null_mut(),
            )
        },
        SipralStatus::BufferTooSmall
    );
    assert_eq!(written, frame, "the length asked for is not the info's");
    let mut samples = vec![i16::MIN; frame];
    let mut source = u32::MAX;
    let status = unsafe {
        sipral_media_playback(
            media,
            samples.as_mut_ptr(),
            samples.len(),
            &raw mut written,
            (&raw mut source).cast(),
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(written, frame);
    let source = match source {
        1 => SipralPlayback::Packet,
        2 => SipralPlayback::Concealed,
        3 => SipralPlayback::ComfortNoise,
        4 => SipralPlayback::Silence,
        _ => SipralPlayback::Unknown,
    };
    (samples, source)
}

/// Send `samples` from `from` and hand the packet to `to` as its far end's.
fn carry(from: SipralHandle, to: SipralHandle, samples: &[i16], now_ms: u64) {
    let mut buffers = Buffers::new();
    let mut packet = buffers.packet();
    let status = unsafe {
        sipral_media_capture(
            from,
            now_ms,
            samples.as_ptr(),
            samples.len(),
            &raw mut packet,
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let (mut datagram, _) = buffers.taken(&packet);
    assert!(!datagram.is_empty(), "a frame of tone was not sent");
    let status = unsafe {
        sipral_media_receive(
            to,
            datagram.as_mut_ptr(),
            datagram.len(),
            PEER_MEDIA.as_ptr().cast(),
            PEER_MEDIA.len(),
            now_ms,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
}

/// The frequency of `heard`, from its upward zero crossings, and its level
/// against the tone's own, in decibels.
fn measure(heard: &[i16], rate: u32) -> (f64, f64) {
    let upward = heard
        .windows(2)
        .filter(|pair| pair[0] < 0 && pair[1] >= 0)
        .count();
    #[expect(clippy::cast_precision_loss, reason = "a few thousand samples")]
    let seconds = heard.len() as f64 / f64::from(rate);
    #[expect(clippy::cast_precision_loss, reason = "a few hundred crossings")]
    let frequency = upward as f64 / seconds;
    let energy: f64 = heard.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
    #[expect(clippy::cast_precision_loss, reason = "a few thousand samples")]
    let rms = (energy / heard.len() as f64).sqrt();
    let level = 20.0 * (rms / (AMPLITUDE / 2.0_f64.sqrt())).log10();
    (frequency, level)
}

/// A tone sent at `rate` from one call and played at `rate` by another,
/// both on `codec_rate` underneath: the frames are the length the rate
/// makes of 20 ms, and the tone comes out as the tone it was.
fn the_tone_crosses(sender: SipralHandle, receiver: SipralHandle, rate: u32, codec_rate: u32) {
    for media in [sender, receiver] {
        let before = media_info(media);
        assert_eq!(
            before.sample_rate, codec_rate,
            "the call starts at the codec's"
        );
        assert_eq!(
            set_rate(media, rate),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let after = media_info(media);
        assert_eq!(after.sample_rate, rate);
        assert_eq!(after.frame_ms, 20, "the frame keeps the call's duration");
        assert_eq!(after.frame_samples, usize::try_from(rate / 50).unwrap());
        assert_eq!(
            after.clock_rate, before.clock_rate,
            "the wire is not touched"
        );
    }
    let frame = media_info(sender).frame_samples;

    // a frame of the codec's length is the wrong length now
    let mut buffers = Buffers::new();
    let mut packet = buffers.packet();
    let codec_frame = vec![0_i16; usize::try_from(codec_rate / 50).unwrap()];
    assert_eq!(
        unsafe {
            sipral_media_capture(
                sender,
                0,
                codec_frame.as_ptr(),
                codec_frame.len(),
                &raw mut packet,
            )
        },
        SipralStatus::InvalidArgument
    );

    let mut phase = 0.0;
    let mut heard = Vec::new();
    for index in 0..SETTLING_FRAMES + MEASURED_FRAMES {
        let now_ms = 2_000 + 20 * u64::try_from(index).unwrap();
        carry(
            sender,
            receiver,
            &tone_frame(frame, rate, &mut phase),
            now_ms,
        );
        let (played, source) = playback(receiver);
        if index >= SETTLING_FRAMES {
            assert_eq!(source, SipralPlayback::Packet, "frame {index}");
            heard.extend_from_slice(&played);
        }
    }
    let (frequency, level) = measure(&heard, rate);
    assert!(
        (frequency - TONE_HZ).abs() <= TONE_HZ * FREQUENCY_TOLERANCE,
        "{TONE_HZ} Hz came back at {frequency} Hz"
    );
    assert!(
        level.abs() <= LEVEL_TOLERANCE_DB,
        "the tone came back {level:.2} dB off its level"
    );
}

#[test]
fn a_call_on_g711_hands_out_and_takes_24_khz_frames_and_a_tone_crosses_it() {
    let mut observed_sender = Observed::default();
    let mut observed_receiver = Observed::default();
    let (stack_sender, call_sender) = media_call(&mut observed_sender);
    let (stack_receiver, call_receiver) = media_call(&mut observed_receiver);
    let sender = media_of(stack_sender, call_sender);
    let receiver = media_of(stack_receiver, call_receiver);
    the_tone_crosses(sender, receiver, 24_000, 8_000);
    assert_eq!(
        unsafe { sipral_stack_destroy(stack_sender) },
        SipralStatus::Ok
    );
    assert_eq!(
        unsafe { sipral_stack_destroy(stack_receiver) },
        SipralStatus::Ok
    );
}

#[test]
fn a_call_on_opus_hands_out_and_takes_16_khz_frames_and_a_tone_crosses_it() {
    if !Capabilities::of_this_build().opus {
        return;
    }
    let mut observed_sender = Observed::default();
    let mut observed_receiver = Observed::default();
    let (stack_sender, call_sender) =
        media_call_offering(&mut observed_sender, "opus", OPUS_ANSWER);
    let (stack_receiver, call_receiver) =
        media_call_offering(&mut observed_receiver, "opus", OPUS_ANSWER);
    let sender = media_of(stack_sender, call_sender);
    let receiver = media_of(stack_receiver, call_receiver);
    the_tone_crosses(sender, receiver, 16_000, 48_000);
    assert_eq!(
        unsafe { sipral_stack_destroy(stack_sender) },
        SipralStatus::Ok
    );
    assert_eq!(
        unsafe { sipral_stack_destroy(stack_receiver) },
        SipralStatus::Ok
    );
}

#[test]
fn a_rate_that_is_not_one_of_the_four_is_refused_and_changes_nothing() {
    let mut observed = Observed::default();
    let (stack, call) = media_call(&mut observed);
    let media = media_of(stack, call);
    assert_eq!(set_rate(media, 16_000), SipralStatus::Ok);
    for refused in [1, 11_025, 12_000, 22_050, 32_000, 44_100, 96_000, u32::MAX] {
        assert_eq!(
            set_rate(media, refused),
            SipralStatus::InvalidArgument,
            "{refused} Hz"
        );
        assert!(
            last_error_text().contains(&refused.to_string()),
            "the refusal does not name {refused}: {}",
            last_error_text()
        );
        let info = media_info(media);
        assert_eq!(info.sample_rate, 16_000, "a refusal moved the rate");
        assert_eq!(info.frame_samples, 320);
    }
    // the same rate again is a choice already made, and zero is the codec's
    assert_eq!(set_rate(media, 16_000), SipralStatus::Ok);
    assert_eq!(set_rate(media, 0), SipralStatus::Ok);
    let info = media_info(media);
    assert_eq!((info.sample_rate, info.frame_samples), (8_000, 160));
    assert_eq!(
        set_rate(SIPRAL_HANDLE_NONE, 16_000),
        SipralStatus::InvalidHandle,
        "{}",
        last_error_text()
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// Every one of the four is taken on a narrowband call, and each is the
/// call's 20 ms counted at that rate.
#[test]
fn each_of_the_four_rates_is_twenty_milliseconds_at_that_rate() {
    let mut observed = Observed::default();
    let (stack, call) = media_call(&mut observed);
    let media = media_of(stack, call);
    for (hz, samples) in [(8_000, 160), (16_000, 320), (24_000, 480), (48_000, 960)] {
        assert_eq!(
            set_rate(media, hz),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let info = media_info(media);
        assert_eq!((info.sample_rate, info.frame_samples), (hz, samples));
        let (played, _) = playback(media);
        assert_eq!(played.len(), samples);
    }
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// A pair is mixed at its codec's rate, so a call with a rate of its own is
/// refused there until it is set back.
#[test]
fn a_pair_is_not_mixed_while_one_call_has_a_rate_of_its_own() {
    let mut observed = Observed::default();
    let (stack, call_a, call_b) = media_call_pair(&mut observed);
    let mut media_a = SIPRAL_HANDLE_NONE;
    let mut media_b = SIPRAL_HANDLE_NONE;
    assert_eq!(
        unsafe { sipral_call_media(stack, call_a, &raw mut media_a) },
        SipralStatus::Ok
    );
    assert_eq!(
        unsafe { sipral_call_media(stack, call_b, &raw mut media_b) },
        SipralStatus::Ok
    );
    assert_eq!(
        unsafe { sipral_call_join(stack, call_a, call_b) },
        SipralStatus::Ok
    );
    let mix = || {
        let samples = [0_i16; 160];
        let mut local = [0_i16; 160];
        let mut buffers_a = Buffers::new();
        let mut buffers_b = Buffers::new();
        let mut packet_a = buffers_a.packet();
        let mut packet_b = buffers_b.packet();
        unsafe {
            sipral_media_mix(
                media_a,
                media_b,
                0,
                samples.as_ptr(),
                samples.len(),
                local.as_mut_ptr(),
                local.len(),
                &raw mut packet_a,
                &raw mut packet_b,
            )
        }
    };
    assert_eq!(set_rate(media_b, 24_000), SipralStatus::Ok);
    assert_eq!(mix(), SipralStatus::WrongState);
    assert!(
        last_error_text().contains("local conference"),
        "{}",
        last_error_text()
    );
    assert_eq!(set_rate(media_b, 0), SipralStatus::Ok);
    assert_eq!(mix(), SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// In device mode the engine takes the frames, at the devices' rate.
#[test]
fn a_stack_in_device_mode_takes_no_rate_from_the_application() {
    let mut observed = Observed::default();
    let fake = a_desk();
    let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
    let media = media_of(stack, call);
    assert_eq!(set_rate(media, 16_000), SipralStatus::WrongState);
    assert!(
        last_error_text().contains("device mode"),
        "{}",
        last_error_text()
    );
    assert_eq!(media_info(media).sample_rate, 8_000);
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}
