// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The long runs: a minute of speech-like audio and of noise through every
//! detector, counting what each finds that is not there, and the CPU cost
//! of one channel.

use super::SampleRate;
use super::amd::{AnsweringMachineDetector, Verdict};
use super::beep::{Beep, BeepDetector};
use super::dtmf::{DtmfDetector, DtmfEvent};
use super::progress::{ProgressDetector, ProgressEvent, Region};
use super::signals::{Rng, mix, pink, span, speech, syllable, to_pcm, white};

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

fn beeps_in(rate: SampleRate, pcm: &[i16]) -> Vec<Beep> {
    let mut detector = BeepDetector::new(rate);
    let mut beeps = Vec::new();
    for chunk in pcm.chunks(160) {
        detector.process(chunk, |b| beeps.push(b));
    }
    beeps
}

#[test]
fn a_minute_of_speech_or_noise_is_no_beep() {
    let mut rng = Rng::new(0xBEE9);
    for rate in RATES {
        for seed in [31, 32] {
            let beeps = beeps_in(rate, &a_minute_of_speech(rate, seed));
            assert!(beeps.is_empty(), "{rate:?} seed {seed}: {beeps:?}");
        }
        let len = usize::try_from(rate.hz()).unwrap() * 30;
        let mut signal = white(&mut rng, -15.0, len);
        signal.extend(pink(&mut rng, -15.0, len));
        let beeps = beeps_in(rate, &to_pcm(&signal));
        assert!(beeps.is_empty(), "{rate:?} noise: {beeps:?}");
    }
}

/// Who answers: `words` syllables of a person's greeting, or a machine's
/// recorded one, after a random wait, over the line's noise.
fn answered(rng: &mut Rng, rate: SampleRate, machine: bool) -> Vec<i16> {
    let hz = rate.hz();
    let mut signal = vec![0.0; span(hz, rng.range(200.0, 1_500.0))];
    if machine {
        // a recorded greeting runs on: syllables, with pauses between
        // phrases that stay under the silence a person leaves
        let end = signal.len() + span(hz, rng.range(2_500.0, 6_000.0));
        let level = rng.range(-24.0, -12.0);
        while signal.len() < end {
            let (ms, jitter) = (rng.range(90.0, 380.0), rng.range(-4.0, 4.0));
            signal.extend(syllable(rng, hz, ms, level + jitter));
            let pause = if rng.uniform() < 0.2 {
                rng.range(250.0, 450.0)
            } else {
                rng.range(30.0, 200.0)
            };
            signal.extend(vec![0.0; span(hz, pause)]);
        }
    } else {
        let words = 1 + rng.next_u64() % 2;
        for _ in 0..words {
            let (ms, level) = (rng.range(200.0, 550.0), rng.range(-24.0, -12.0));
            signal.extend(syllable(rng, hz, ms, level));
            signal.extend(vec![0.0; span(hz, rng.range(80.0, 250.0))]);
        }
    }
    signal.extend(vec![0.0; span(hz, 3_000.0)]);
    let noise = white(rng, -55.0, signal.len());
    mix(&mut signal, &noise);
    to_pcm(&signal)
}

#[test]
fn people_and_machines_answering_are_told_apart() {
    let mut rng = Rng::new(0xA11CE);
    for rate in RATES {
        for machine in [false, true] {
            for attempt in 0..25 {
                let pcm = answered(&mut rng, rate, machine);
                let mut detector = AnsweringMachineDetector::new(rate);
                let result = detector.process(&pcm).unwrap();
                let expected = if machine {
                    Verdict::Machine
                } else {
                    Verdict::Human
                };
                assert_eq!(
                    result.verdict, expected,
                    "{rate:?} attempt {attempt}: {result:?}"
                );
            }
        }
    }
}
