// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The long runs: a minute of speech-like audio and of noise through every
//! detector, counting what each finds that is not there, and the CPU cost
//! of one channel.

use super::SampleRate;
use super::dtmf::{DtmfDetector, DtmfEvent};
use super::progress::{ProgressDetector, ProgressEvent, Region};
use super::signals::{Rng, pink, speech, to_pcm, white};

const RATES: [SampleRate; 2] = [SampleRate::Hz8000, SampleRate::Hz16000];

/// Sixty seconds of speech-like audio at `rate`: twenty seconds each at a
/// quiet, an ordinary and a loud talker's level.
fn a_minute_of_speech(rate: SampleRate, seed: u64) -> Vec<i16> {
    let mut rng = Rng::new(seed);
    let mut signal = Vec::new();
    for level in [-24.0, -16.0, -8.0] {
        signal.extend(speech(&mut rng, rate.hz(), 20.0, level));
    }
    to_pcm(&signal)
}

fn digits_in(rate: SampleRate, pcm: &[i16]) -> Vec<DtmfEvent> {
    let mut detector = DtmfDetector::new(rate);
    let mut events = Vec::new();
    for chunk in pcm.chunks(160) {
        detector.process(chunk, |e| events.push(e));
    }
    detector.finish(|e| events.push(e));
    events
}

#[test]
fn a_minute_of_speech_dials_nothing() {
    for rate in RATES {
        for seed in [11, 12] {
            let events = digits_in(rate, &a_minute_of_speech(rate, seed));
            assert!(
                events.is_empty(),
                "{rate:?} seed {seed}: {} false digits: {events:?}",
                events.len()
            );
        }
    }
}

#[test]
fn a_minute_of_white_or_pink_noise_dials_nothing() {
    let mut rng = Rng::new(0xB0B);
    for rate in RATES {
        let len = usize::try_from(rate.hz()).unwrap() * 20;
        let mut signal = Vec::new();
        for level in [-30.0, -15.0, -3.0] {
            signal.extend(white(&mut rng, level, len));
        }
        let events = digits_in(rate, &to_pcm(&signal));
        assert!(events.is_empty(), "{rate:?} white: {events:?}");
        let mut signal = Vec::new();
        for level in [-30.0, -15.0, -3.0] {
            signal.extend(pink(&mut rng, level, len));
        }
        let events = digits_in(rate, &to_pcm(&signal));
        assert!(events.is_empty(), "{rate:?} pink: {events:?}");
    }
}

fn progress_in(rate: SampleRate, region: Region, pcm: &[i16]) -> Vec<ProgressEvent> {
    let mut detector = ProgressDetector::new(rate, region.tones());
    let mut events = Vec::new();
    for chunk in pcm.chunks(160) {
        detector.process(chunk, |e| events.push(e));
    }
    events
}

#[test]
fn a_minute_of_speech_is_no_call_progress_tone_anywhere() {
    for rate in RATES {
        let pcm = a_minute_of_speech(rate, 21);
        for region in Region::ALL {
            let events = progress_in(rate, region, &pcm);
            assert!(events.is_empty(), "{rate:?} {region:?}: {events:?}");
        }
    }
}

#[test]
fn a_minute_of_noise_is_no_call_progress_tone_anywhere() {
    let mut rng = Rng::new(0xC0DE);
    for rate in RATES {
        let len = usize::try_from(rate.hz()).unwrap() * 30;
        let mut signal = white(&mut rng, -20.0, len);
        signal.extend(pink(&mut rng, -20.0, len));
        let pcm = to_pcm(&signal);
        for region in Region::ALL {
            let events = progress_in(rate, region, &pcm);
            assert!(events.is_empty(), "{rate:?} {region:?}: {events:?}");
        }
    }
}
