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
use super::signals::{
    Rng, digit_vowels, glottal_speech, mix, music, pink, span, speech, sweeps, syllable, to_pcm,
    white,
};

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

/// One part of the talk-off corpus: a name, and `seconds` of it at `rate`
/// from `seed`.
type Part = (&'static str, fn(&mut Rng, u32, f64) -> Vec<f64>);

/// What a digit receiver hears that is not a digit, in kinds chosen to
/// catch it out: talkers of every pitch, vowels built to sit on a row and a
/// column, music, two sweeps crossing the band, and noise.
const TALK_OFF: [Part; 7] = [
    ("glottal speech", |rng, rate, s| {
        let mut out = Vec::new();
        for level in [-26.0, -18.0, -10.0] {
            out.extend(glottal_speech(rng, rate, s / 3.0, level));
        }
        out
    }),
    ("harmonic speech", |rng, rate, s| {
        let mut out = Vec::new();
        for level in [-24.0, -16.0, -8.0] {
            out.extend(speech(rng, rate, s / 3.0, level));
        }
        out
    }),
    ("vowels on digit pairs", |rng, rate, s| {
        digit_vowels(rng, rate, s, -16.0)
    }),
    ("music", |rng, rate, s| music(rng, rate, s, -14.0)),
    ("two sweeps", |rng, rate, s| sweeps(rng, rate, s, -14.0)),
    ("white noise", |rng, rate, s| {
        white(rng, -18.0, span(rate, s * 1_000.0))
    }),
    ("pink noise", |rng, rate, s| {
        pink(rng, -18.0, span(rate, s * 1_000.0))
    }),
];

/// Digits a detector at `rate` starts over `seconds` of `part` of the
/// corpus, generated from `seed`.
fn talk_off(rate: SampleRate, part: &Part, seconds: f64, seed: u64) -> usize {
    let mut rng = Rng::new(seed);
    let pcm = to_pcm(&(part.1)(&mut rng, rate.hz(), seconds));
    digits_in(rate, &pcm)
        .iter()
        .filter(|e| matches!(e, DtmfEvent::Start { .. }))
        .count()
}

#[test]
fn talkers_of_every_pitch_and_music_dial_nothing() {
    for rate in RATES {
        for part in TALK_OFF
            .iter()
            .filter(|p| ["glottal speech", "music"].contains(&p.0))
        {
            let starts = talk_off(rate, part, 30.0, 0x5EED);
            assert_eq!(starts, 0, "{rate:?} {}", part.0);
        }
    }
}

/// The false-digit rate over the whole corpus, a quarter of an hour of
/// each part at each rate, per hour of audio. Run with
/// `cargo test -p sipral-media --release -- --ignored --nocapture talk_off_rate`.
///
/// Speech, music and noise dial nothing. What does dial is what is built
/// to: vowels whose formants and harmonics sit on a row and a column are
/// two steady tones, and so is a pair of sweeps slow enough to stay inside
/// both bands for a digit's length.
#[test]
#[ignore = "a measurement over three and a half hours of audio"]
fn talk_off_rate() {
    let seconds = 900.0;
    for rate in RATES {
        let mut total = 0;
        for part in &TALK_OFF {
            let starts = talk_off(rate, part, seconds, 0x7A1C);
            println!("{rate:?} {:>22}: {starts} in {seconds} s", part.0);
            total += starts;
        }
        let hours = seconds * 7.0 / 3_600.0;
        println!(
            "{rate:?}: {total} false digits in {hours:.2} h, {:.1} an hour",
            f64::from(u32::try_from(total).unwrap()) / hours
        );
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

/// Samples per second of CPU time `run` gets through, over `pcm` handed
/// over in 20 ms frames, as the median of five passes.
fn throughput(rate: SampleRate, pcm: &[i16], mut run: impl FnMut(&[i16])) -> f64 {
    let frame = rate.samples(20);
    let mut passes: Vec<f64> = (0..5)
        .map(|_| {
            let began = std::time::Instant::now();
            for chunk in pcm.chunks(frame) {
                run(chunk);
            }
            let seconds = began.elapsed().as_secs_f64();
            f64::from(u32::try_from(pcm.len()).unwrap()) / seconds
        })
        .collect();
    passes.sort_by(f64::total_cmp);
    passes[2]
}

/// What one channel of each detector costs on this machine: samples
/// processed per second of one core's time, and the same as a multiple of
/// real time, which is how many channels one core could carry. Run with
/// `cargo test -p sipral-media --release -- --ignored --nocapture cpu`.
#[test]
#[ignore = "a measurement, not a check: run it on the machine being sized"]
fn cpu_per_channel() {
    for rate in RATES {
        let hz = f64::from(rate.hz());
        let pcm = a_minute_of_speech(rate, 41);
        let mut dtmf = DtmfDetector::new(rate);
        let mut progress = ProgressDetector::new(rate, Region::Europe.tones());
        let mut beep = BeepDetector::new(rate);
        let mut amd = AnsweringMachineDetector::new(rate);
        let rows = [
            ("dtmf", throughput(rate, &pcm, |c| dtmf.process(c, |_| {}))),
            (
                "progress + sit",
                throughput(rate, &pcm, |c| progress.process(c, |_| {})),
            ),
            ("beep", throughput(rate, &pcm, |c| beep.process(c, |_| {}))),
            (
                "amd",
                throughput(rate, &pcm, |c| {
                    if amd.process(c).is_some() {
                        amd.reset();
                    }
                }),
            ),
            (
                "all four",
                throughput(rate, &pcm, |c| {
                    dtmf.process(c, |_| {});
                    progress.process(c, |_| {});
                    beep.process(c, |_| {});
                    if amd.process(c).is_some() {
                        amd.reset();
                    }
                }),
            ),
        ];
        for (name, samples_per_second) in rows {
            println!(
                "{rate:?} {name:>15}: {samples_per_second:>14.0} samples/s, {:>8.0}x real time",
                samples_per_second / hz
            );
        }
    }
}
