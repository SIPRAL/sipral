// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The conference as a whole, driven with synthetic tones.

use super::limiter::CEILING;
use super::{
    MAX_FRAME_TICKS, MAX_PARTICIPANTS, MixError, Mixer, MixerConfig, ParticipantConfig,
    ParticipantId, Rate,
};
use crate::mix::Gain;

/// One side of a conference leg: what it sends and what it has heard.
struct Leg {
    id: ParticipantId,
    rate: Rate,
    frame: usize,
    /// Hertz and peak amplitude of the tone it sends; `None` sends nothing.
    tone: Option<(f64, f64)>,
    /// Samples sent so far, so a tone stays continuous across frames.
    sent: usize,
    heard: Vec<i16>,
}

impl Leg {
    fn join(mixer: &mut Mixer, rate: Rate, tone: Option<(f64, f64)>) -> Self {
        Self::join_framed(mixer, ParticipantConfig::new(rate), tone)
    }

    fn join_framed(mixer: &mut Mixer, config: ParticipantConfig, tone: Option<(f64, f64)>) -> Self {
        Self {
            id: mixer.join(config).unwrap(),
            rate: config.rate,
            frame: config.frame_samples,
            tone,
            sent: 0,
            heard: Vec::new(),
        }
    }

    fn tick(&self) -> usize {
        self.rate.tick_samples()
    }

    /// The next `len` samples of the leg's tone.
    fn next(&mut self, len: usize) -> Vec<i16> {
        let samples = match self.tone {
            Some((hz, amplitude)) => tone(hz, amplitude, self.rate, self.sent, len),
            None => vec![0; len],
        };
        self.sent += len;
        samples
    }

    /// Pushes one frame, or as many as fit in a tick.
    fn send_tick(&mut self, mixer: &mut Mixer) {
        if self.tone.is_none() {
            return;
        }
        let frames = (self.tick() / self.frame).max(1);
        for _ in 0..frames {
            let frame = self.next(self.frame);
            mixer.push(self.id, &frame).unwrap();
        }
    }

    /// Pulls everything there is to hear.
    fn listen(&mut self, mixer: &mut Mixer) {
        let mut buffer = vec![0; mixer.available(self.id).unwrap()];
        let got = mixer.pull(self.id, &mut buffer).unwrap();
        self.heard.extend_from_slice(&buffer[..got]);
    }

    /// The last `ticks` ticks of what the leg heard.
    fn last(&self, ticks: usize) -> &[i16] {
        &self.heard[self.heard.len() - ticks * self.tick()..]
    }
}

/// Every leg sends a tick, the mixer mixes, every leg listens, `ticks` times.
fn run(mixer: &mut Mixer, legs: &mut [Leg], ticks: usize) {
    for _ in 0..ticks {
        for leg in legs.iter_mut() {
            leg.send_tick(mixer);
        }
        mixer.mix();
        for leg in legs.iter_mut() {
            leg.listen(mixer);
        }
    }
}

fn tone(hz: f64, amplitude: f64, rate: Rate, start: usize, len: usize) -> Vec<i16> {
    let step = core::f64::consts::TAU * hz / f64::from(rate.hz());
    (start..start + len)
        .map(|n| {
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let sample = (amplitude * (step * n as f64).sin()).round() as i16;
            sample
        })
        .collect()
}

/// The amplitude of the component of `samples` at `hz`, by the Goertzel
/// recurrence. Exact for a tone with a whole number of cycles in the window.
fn goertzel(samples: &[i16], hz: f64, rate: Rate) -> f64 {
    let omega = core::f64::consts::TAU * hz / f64::from(rate.hz());
    let coefficient = 2.0 * omega.cos();
    let (mut previous, mut before) = (0.0_f64, 0.0_f64);
    for sample in samples {
        let current = f64::from(*sample) + coefficient * previous - before;
        before = previous;
        previous = current;
    }
    let power = previous * previous + before * before - coefficient * previous * before;
    #[allow(clippy::cast_precision_loss)]
    let len = samples.len() as f64;
    2.0 * power.max(0.0).sqrt() / len
}

fn mixer(places: usize) -> Mixer {
    Mixer::new(MixerConfig {
        max_participants: places,
    })
    .unwrap()
}

fn assert_near(measured: f64, expected: f64, tolerance: f64, what: &str) {
    assert!(
        (measured - expected).abs() <= expected * tolerance,
        "{what}: {measured:.1} where {expected:.1} was expected"
    );
}

const RATES: [Rate; 4] = [Rate::Hz8000, Rate::Hz16000, Rate::Hz32000, Rate::Hz48000];

#[test]
fn each_participant_hears_everyone_but_itself() {
    let tones = [400.0, 700.0, 1_100.0, 1_700.0];
    for rates in [[Rate::Hz48000; 4], RATES] {
        let mut mixer = mixer(4);
        let mut legs: Vec<Leg> = rates
            .iter()
            .zip(tones)
            .map(|(rate, hz)| Leg::join(&mut mixer, *rate, Some((hz, 3_000.0))))
            .collect();
        run(&mut mixer, &mut legs, 15);
        for leg in &legs {
            let heard = leg.last(10);
            let own = leg.tone.unwrap().0;
            for hz in tones {
                let level = goertzel(heard, hz, leg.rate);
                if (hz - own).abs() < 1.0 {
                    assert!(level < 3.0, "{} hears itself at {level:.1}", leg.id);
                } else {
                    assert_near(level, 3_000.0, 0.02, &format!("{} at {hz} Hz", leg.id));
                }
            }
        }
    }
}

#[test]
fn resampled_tones_keep_their_frequency() {
    let mut mixer = mixer(5);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz8000, Some((1_000.0, 6_000.0))),
        Leg::join(&mut mixer, Rate::Hz16000, Some((6_000.0, 6_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, None),
        Leg::join(&mut mixer, Rate::Hz32000, None),
        Leg::join(&mut mixer, Rate::Hz48000, None),
    ];
    run(&mut mixer, &mut legs, 20);

    for leg in &legs[2..] {
        let heard = leg.last(10);
        // the strongest component near the tone is the tone, to the hertz
        let strongest = (900..=1_100)
            .max_by(|a, b| {
                goertzel(heard, f64::from(*a), leg.rate).total_cmp(&goertzel(
                    heard,
                    f64::from(*b),
                    leg.rate,
                ))
            })
            .unwrap();
        assert_eq!(strongest, 1_000, "at {} Hz", leg.rate.hz());
        assert_near(
            goertzel(heard, 1_000.0, leg.rate),
            6_000.0,
            0.02,
            &format!("1 kHz at {} Hz", leg.rate.hz()),
        );
    }
    // 6 kHz from 16 kHz comes through where the rate carries it
    for leg in &legs[3..] {
        assert_near(
            goertzel(leg.last(10), 6_000.0, leg.rate),
            6_000.0,
            0.03,
            &format!("6 kHz at {} Hz", leg.rate.hz()),
        );
    }
    // and at 8 kHz it is filtered out, not folded down to 2 kHz
    let narrow = legs[2].last(10);
    assert!(
        goertzel(narrow, 2_000.0, Rate::Hz8000) < 30.0,
        "6 kHz folded"
    );
    assert!(
        goertzel(narrow, 6_000.0, Rate::Hz8000) < 30.0,
        "6 kHz passed"
    );
}

#[test]
fn gains_scale_what_is_sent_and_what_is_heard() {
    let mut mixer = mixer(3);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz48000, Some((500.0, 8_000.0))),
        Leg::join(&mut mixer, Rate::Hz16000, Some((900.0, 8_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, None),
    ];
    let (a, b, c) = (legs[0].id, legs[1].id, legs[2].id);
    mixer.set_gain_in(a, Gain::ratio(1, 2)).unwrap();
    mixer.set_gain_out(c, Gain::ratio(1, 4)).unwrap();
    mixer.set_gain_out(a, Gain::ratio(3, 2)).unwrap();
    run(&mut mixer, &mut legs, 15);

    let level = |leg: &Leg, hz: f64| goertzel(leg.last(10), hz, leg.rate);
    assert_near(level(&legs[1], 500.0), 4_000.0, 0.02, "b hears a halved");
    assert_near(
        level(&legs[2], 500.0),
        1_000.0,
        0.02,
        "c hears a halved, quartered",
    );
    assert_near(level(&legs[2], 900.0), 2_000.0, 0.02, "c hears b quartered");
    assert_near(level(&legs[0], 900.0), 12_000.0, 0.02, "a hears b lifted");
    assert_eq!(mixer.controls(b).unwrap().gain_in, Gain::UNITY);
    assert_eq!(mixer.controls(a).unwrap().gain_in, Gain::ratio(1, 2));
}

#[test]
fn mutes_silence_one_direction_each() {
    let mut mixer = mixer(3);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz16000, Some((500.0, 5_000.0))),
        Leg::join(&mut mixer, Rate::Hz48000, Some((900.0, 5_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, Some((1_300.0, 5_000.0))),
    ];
    let (a, b) = (legs[0].id, legs[1].id);
    mixer.set_mute_in(a, true).unwrap();
    mixer.set_mute_out(b, true).unwrap();
    run(&mut mixer, &mut legs, 15);

    let level = |leg: &Leg, hz: f64| goertzel(leg.last(10), hz, leg.rate);
    // nobody hears a, but a hears everybody
    assert!(level(&legs[2], 500.0) < 1.0, "c hears muted a");
    assert_near(level(&legs[0], 900.0), 5_000.0, 0.02, "muted a hears b");
    // b hears silence, a tick of it every tick, and everybody hears b
    assert_eq!(legs[1].heard.len(), 15 * Rate::Hz48000.tick_samples());
    assert!(legs[1].heard.iter().all(|sample| *sample == 0), "b hears");
    assert_near(level(&legs[2], 900.0), 5_000.0, 0.02, "c hears b");

    // and both come back
    mixer.set_mute_in(a, false).unwrap();
    mixer.set_mute_out(b, false).unwrap();
    run(&mut mixer, &mut legs, 15);
    assert_near(level(&legs[2], 500.0), 5_000.0, 0.02, "c hears a again");
    assert_near(level(&legs[1], 500.0), 5_000.0, 0.02, "b hears a again");
}

#[test]
fn a_muted_participant_does_not_play_back_what_it_said_while_muted() {
    let mut mixer = mixer(2);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz8000, Some((500.0, 5_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, None),
    ];
    let a = legs[0].id;
    run(&mut mixer, &mut legs, 5);
    mixer.set_mute_in(a, true).unwrap();
    run(&mut mixer, &mut legs, 5);
    // unmuted, with no new audio: neither what was pushed while muted nor
    // what the filter held from before the mute comes out
    legs[0].tone = None;
    mixer.set_mute_in(a, false).unwrap();
    run(&mut mixer, &mut legs, 2);
    // the first muted tick still carries the tail of the listener's filter
    assert!(legs[1].last(6).iter().all(|sample| *sample == 0));
}

#[test]
fn a_participant_muted_out_hears_nothing_of_before_when_unmuted() {
    let mut mixer = mixer(3);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz8000, Some((500.0, 30_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, Some((900.0, 30_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, None),
    ];
    let c = legs[2].id;
    run(&mut mixer, &mut legs, 5);
    mixer.set_mute_out(c, true).unwrap();
    legs[0].tone = Some((500.0, 4_000.0));
    legs[1].tone = None;
    run(&mut mixer, &mut legs, 2);
    // unmuted, c hears a at a's level at once: nothing of the loud tones the
    // filter and the limiter were holding before the mute
    mixer.set_mute_out(c, false).unwrap();
    run(&mut mixer, &mut legs, 1);
    let first = legs[2].last(1);
    assert!(first[..32].iter().all(|s| *s == 0), "the filter kept b");
    let peak = first.iter().map(|s| i32::from(*s).abs()).max().unwrap();
    assert!((3_900..=4_100).contains(&peak), "a at {peak}");
}

#[test]
fn a_listen_only_participant_is_heard_by_nobody_and_hears_everybody() {
    let mut mixer = mixer(5);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz16000, Some((500.0, 5_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, Some((900.0, 5_000.0))),
        Leg::join(&mut mixer, Rate::Hz48000, Some((1_300.0, 5_000.0))),
    ];
    let (listener, muted) = (legs[0].id, legs[1].id);
    // what it had queued before is dropped by the next tick
    legs[0].send_tick(&mut mixer);
    mixer.set_listen_only(listener, true).unwrap();
    assert!(mixer.controls(listener).unwrap().listen_only);
    run(&mut mixer, &mut legs, 15);

    let level = |leg: &Leg, hz: f64| goertzel(leg.last(10), hz, leg.rate);
    let everything = goertzel(&legs[2].heard, 500.0, Rate::Hz48000);
    assert!(everything < 50.0, "c heard the listener at {everything:.1}");
    assert!(level(&legs[1], 500.0) < 1.0, "b hears the listener");
    assert_near(level(&legs[0], 900.0), 5_000.0, 0.02, "listener hears b");
    assert_near(level(&legs[0], 1_300.0), 5_000.0, 0.02, "listener hears c");

    // silence from a listener is expected; from a muted speaker it is not
    mixer.set_mute_in(muted, true).unwrap();
    legs[0].tone = None;
    legs[1].tone = None;
    run(&mut mixer, &mut legs, 3);
    assert_eq!(mixer.stats(listener).unwrap().underruns, 0);
    assert_eq!(mixer.stats(muted).unwrap().underruns, 3);

    // what a listener pushed was never queued, so letting it speak again
    // does not play it back
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz8000, None),
        Leg::join(&mut mixer, Rate::Hz8000, None),
    ];
    mixer.set_listen_only(legs[0].id, true).unwrap();
    let spoken = tone(500.0, 5_000.0, Rate::Hz8000, 0, 320);
    mixer.push(legs[0].id, &spoken).unwrap();
    run(&mut mixer, &mut legs, 1);
    mixer.set_listen_only(legs[0].id, false).unwrap();
    run(&mut mixer, &mut legs, 2);
    assert!(legs[1].heard.iter().all(|sample| *sample == 0));
}

#[test]
fn eight_loud_participants_are_limited_without_touching_the_rail() {
    let mut mixer = mixer(8);
    let mut legs: Vec<Leg> = (0..8_u8)
        .map(|n| {
            let hz = 300.0 + 170.0 * f64::from(n);
            let rate = RATES[usize::from(n) % 4];
            Leg::join(&mut mixer, rate, Some((hz, 30_000.0)))
        })
        .collect();
    run(&mut mixer, &mut legs, 25);

    for leg in &legs {
        let rail = leg
            .heard
            .iter()
            .filter(|sample| **sample == i16::MAX || **sample <= i16::MIN + 1)
            .count();
        assert_eq!(
            rail,
            0,
            "{} at {} Hz reached the rail",
            leg.id,
            leg.rate.hz()
        );
        // after the first tick the peaks sit at the ceiling: a few beat
        // faster than the attack and are left to the soft clipper, which
        // keeps them well clear of the rail
        let settled = leg.last(20);
        let peak = settled.iter().map(|s| i32::from(*s).abs()).max().unwrap();
        let over = settled
            .iter()
            .filter(|sample| i32::from(**sample).abs() > CEILING)
            .count();
        assert!(peak <= 30_000, "{} peaks at {peak}", leg.id);
        assert!(
            over * 10 < settled.len(),
            "{} over the ceiling {over} times",
            leg.id
        );
        assert!(peak >= CEILING * 9 / 10, "{} crushed to {peak}", leg.id);
    }

    // seven stop; the last one is heard at its own level once the release
    // has run out, 400 ms later
    for leg in &mut legs[1..] {
        leg.tone = None;
    }
    legs[0].tone = Some((1_000.0, 8_000.0));
    run(&mut mixer, &mut legs, 5);
    let recovering = goertzel(legs[1].last(5), 1_000.0, legs[1].rate);
    assert!(recovering < 7_000.0, "recovered at once: {recovering:.1}");
    run(&mut mixer, &mut legs, 20);
    for leg in &legs[1..] {
        assert_near(
            goertzel(leg.last(10), 1_000.0, leg.rate),
            8_000.0,
            0.02,
            &format!("{} after the release", leg.id),
        );
    }
}

#[test]
fn participants_join_and_leave_between_two_pushes_of_a_tick() {
    let mut mixer = mixer(3);
    let halves = ParticipantConfig::new(Rate::Hz8000).with_frame(80);
    let mut a = Leg::join_framed(&mut mixer, halves, Some((500.0, 4_000.0)));
    let mut b = Leg::join_framed(&mut mixer, halves, Some((900.0, 4_000.0)));
    let half = |leg: &mut Leg, mixer: &mut Mixer| {
        let frame = leg.next(80);
        mixer.push(leg.id, &frame)
    };

    for _ in 0..10 {
        half(&mut a, &mut mixer).unwrap();
        half(&mut b, &mut mixer).unwrap();
        half(&mut a, &mut mixer).unwrap();
        half(&mut b, &mut mixer).unwrap();
        mixer.mix();
        a.listen(&mut mixer);
        b.listen(&mut mixer);
    }

    // c joins between a's two halves, and takes part in that very tick
    half(&mut a, &mut mixer).unwrap();
    let mut c = Leg::join(&mut mixer, Rate::Hz16000, Some((1_300.0, 4_000.0)));
    half(&mut a, &mut mixer).unwrap();
    half(&mut b, &mut mixer).unwrap();
    half(&mut b, &mut mixer).unwrap();
    c.send_tick(&mut mixer);
    mixer.mix();
    for leg in [&mut a, &mut b, &mut c] {
        leg.listen(&mut mixer);
    }
    assert_eq!(c.heard.len(), Rate::Hz16000.tick_samples());
    let first = goertzel(a.last(1), 1_300.0, a.rate);
    // less than all of it: c's filter starts from silence, and a's filters
    // put 6 ms of that silence in front of c's first sample
    assert!(first > 2_400.0, "a heard c's first tick at {first:.1}");

    for _ in 0..10 {
        half(&mut a, &mut mixer).unwrap();
        half(&mut b, &mut mixer).unwrap();
        half(&mut a, &mut mixer).unwrap();
        half(&mut b, &mut mixer).unwrap();
        c.send_tick(&mut mixer);
        mixer.mix();
        for leg in [&mut a, &mut b, &mut c] {
            leg.listen(&mut mixer);
        }
    }
    assert_near(
        goertzel(c.last(10), 500.0, c.rate),
        4_000.0,
        0.02,
        "c hears a",
    );
    assert_near(
        goertzel(c.last(10), 900.0, c.rate),
        4_000.0,
        0.02,
        "c hears b",
    );
    assert_near(
        goertzel(a.last(10), 1_300.0, a.rate),
        4_000.0,
        0.02,
        "a hears c",
    );

    // b leaves after its first half; the half it left behind is never heard
    half(&mut a, &mut mixer).unwrap();
    half(&mut b, &mut mixer).unwrap();
    mixer.leave(b.id).unwrap();
    half(&mut a, &mut mixer).unwrap();
    assert_eq!(
        half(&mut b, &mut mixer),
        Err(MixError::UnknownParticipant(b.id))
    );
    for _ in 0..11 {
        c.send_tick(&mut mixer);
        mixer.mix();
        a.listen(&mut mixer);
        c.listen(&mut mixer);
        half(&mut a, &mut mixer).unwrap();
        half(&mut a, &mut mixer).unwrap();
    }
    // the tick b left in still carries the tail of the filter; after that
    // there is nothing of b at all
    assert!(goertzel(a.last(10), 900.0, a.rate) < 1.0, "a hears b");
    assert!(goertzel(c.last(10), 900.0, c.rate) < 1.0, "c hears b");
    assert_near(
        goertzel(c.last(10), 500.0, c.rate),
        4_000.0,
        0.02,
        "c hears a",
    );
    // and a heard a tick every tick throughout, with no gap and no repeat
    assert_eq!(a.heard.len(), 32 * a.tick());
    assert_eq!(mixer.len(), 2);

    // b's place is given to d, and b's id is still nobody
    let d = mixer.join(ParticipantConfig::new(Rate::Hz32000)).unwrap();
    assert_eq!(d.index(), b.id.index());
    assert_ne!(d, b.id);
    assert_eq!(mixer.leave(b.id), Err(MixError::UnknownParticipant(b.id)));
    assert_eq!(mixer.stats(b.id), Err(MixError::UnknownParticipant(b.id)));
    assert_eq!(mixer.len(), 3);
}

#[test]
fn a_frame_either_divides_a_tick_or_is_whole_ticks() {
    let mut mixer = mixer(8);
    for (rate, frame) in [
        (Rate::Hz8000, 80),
        (Rate::Hz8000, 40),
        (Rate::Hz16000, 640),
        (Rate::Hz48000, 2_880),
        (Rate::Hz32000, 640),
    ] {
        let config = ParticipantConfig::new(rate).with_frame(frame);
        assert!(mixer.join(config).is_ok(), "{frame} at {}", rate.hz());
    }
    for (rate, frame) in [
        (Rate::Hz8000, 0),
        (Rate::Hz8000, 240),
        (Rate::Hz8000, 150),
        (Rate::Hz48000, 960 * (MAX_FRAME_TICKS + 1)),
    ] {
        let config = ParticipantConfig::new(rate).with_frame(frame);
        assert_eq!(
            mixer.join(config),
            Err(MixError::FrameSize {
                rate,
                frame_samples: frame
            })
        );
    }
}

#[test]
fn a_conference_has_the_places_it_was_given() {
    for requested in [0, MAX_PARTICIPANTS + 1] {
        let config = MixerConfig {
            max_participants: requested,
        };
        assert_eq!(
            Mixer::new(config).err(),
            Some(MixError::Capacity { requested })
        );
    }
    let mut mixer = mixer(2);
    let config = ParticipantConfig::new(Rate::Hz8000);
    mixer.join(config).unwrap();
    mixer.join(config).unwrap();
    assert_eq!(mixer.join(config), Err(MixError::Full { capacity: 2 }));
}

#[test]
fn a_participant_with_long_frames_pushes_and_pulls_every_few_ticks() {
    let mut mixer = mixer(2);
    let long = ParticipantConfig::new(Rate::Hz16000).with_frame(3 * 320);
    let mut a = Leg::join_framed(&mut mixer, long, Some((700.0, 5_000.0)));
    let mut b = Leg::join(&mut mixer, Rate::Hz8000, Some((1_100.0, 5_000.0)));
    for tick in 0..30 {
        if tick % 3 == 0 {
            let frame = a.next(a.frame);
            mixer.push(a.id, &frame).unwrap();
        }
        b.send_tick(&mut mixer);
        mixer.mix();
        b.listen(&mut mixer);
        if tick % 3 == 2 {
            assert_eq!(mixer.available(a.id).unwrap(), a.frame);
            a.listen(&mut mixer);
        }
    }
    assert_near(
        goertzel(b.last(15), 700.0, b.rate),
        5_000.0,
        0.02,
        "b hears a",
    );
    assert_near(
        goertzel(a.last(15), 1_100.0, a.rate),
        5_000.0,
        0.02,
        "a hears b",
    );
    let stats = mixer.stats(a.id).unwrap();
    assert_eq!((stats.underruns, stats.input_dropped), (0, 0));
}

#[test]
fn a_participant_that_runs_ahead_loses_its_oldest_audio_not_its_latency() {
    let mut mixer = mixer(2);
    let a = mixer.join(ParticipantConfig::new(Rate::Hz8000)).unwrap();
    let b = mixer.join(ParticipantConfig::new(Rate::Hz48000)).unwrap();
    // five ticks of a ramp at once: only the last two ticks can be queued
    let ramp: Vec<i16> = (0..800).map(|n| i16::try_from(n).unwrap()).collect();
    mixer.push(a, &ramp).unwrap();
    assert_eq!(mixer.stats(a).unwrap().input_dropped, 480);
    // nobody pulls b for five ticks: b keeps the newest two
    for _ in 0..5 {
        mixer.mix();
    }
    assert_eq!(mixer.available(b).unwrap(), 2 * 960);
    assert_eq!(mixer.stats(b).unwrap().output_dropped, 3 * 960);
    // a ran dry after its two ticks; b never pushed, so it never ran dry
    assert_eq!(mixer.stats(a).unwrap().underruns, 3);
    assert_eq!(mixer.stats(b).unwrap().underruns, 0);
}

#[test]
fn audio_pushed_before_a_tick_is_heard_right_after_it() {
    // at 48 kHz there is no filter: an impulse comes out in the tick it went
    // in, at the sample it went in at
    let mut mixer = mixer(4);
    let a = mixer.join(ParticipantConfig::new(Rate::Hz48000)).unwrap();
    let b = mixer.join(ParticipantConfig::new(Rate::Hz48000)).unwrap();
    let c = mixer.join(ParticipantConfig::new(Rate::Hz8000)).unwrap();
    let d = mixer.join(ParticipantConfig::new(Rate::Hz8000)).unwrap();
    let mut impulse = vec![0_i16; 960];
    impulse[300] = 10_000;
    mixer.push(a, &impulse).unwrap();
    mixer.mix();
    let mut heard = vec![0_i16; 960];
    assert_eq!(mixer.pull(b, &mut heard).unwrap(), 960);
    assert_eq!(heard, impulse);

    // at 8 kHz both filters are in the way, and they delay by 4 ms each
    let mut drain = vec![0_i16; 160];
    mixer.pull(d, &mut drain).unwrap();
    let mut impulse = vec![0_i16; 160];
    impulse[20] = 10_000;
    mixer.push(c, &impulse).unwrap();
    let mut heard = Vec::new();
    for _ in 0..2 {
        mixer.mix();
        let mut tick = vec![0_i16; 160];
        mixer.pull(d, &mut tick).unwrap();
        heard.extend_from_slice(&tick);
    }
    let peak = (0..heard.len())
        .max_by_key(|n| i32::from(heard[*n]).abs())
        .unwrap();
    assert_eq!(peak, 20 + 64, "the impulse came out at {peak}");
}

#[test]
fn talkers_are_listed_loudest_first_with_hysteresis() {
    let mut mixer = mixer(5);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz8000, Some((500.0, 2_000.0))),
        Leg::join(&mut mixer, Rate::Hz16000, Some((700.0, 8_000.0))),
        Leg::join(&mut mixer, Rate::Hz48000, Some((900.0, 4_000.0))),
        Leg::join(&mut mixer, Rate::Hz32000, None),
    ];
    let (a, b, c, d) = (legs[0].id, legs[1].id, legs[2].id, legs[3].id);

    // one tick of speech is not enough, two are
    run(&mut mixer, &mut legs, 1);
    assert!(mixer.talkers().is_empty());
    run(&mut mixer, &mut legs, 1);
    assert_eq!(mixer.talkers(), [b, c, a]);
    assert!(!mixer.is_talking(d).unwrap());

    // b falls silent: it keeps its place in the list through the pause, but
    // sinks as its level decays, and is gone once the pause is long enough
    legs[1].tone = None;
    run(&mut mixer, &mut legs, 10);
    assert_eq!(mixer.talkers(), [c, a, b]);
    run(&mut mixer, &mut legs, 9);
    assert_eq!(mixer.talkers(), [c, a, b]);
    run(&mut mixer, &mut legs, 1);
    assert_eq!(mixer.talkers(), [c, a]);
    assert!(mixer.talk_level(c).unwrap() > mixer.talk_level(a).unwrap());

    // a muted talker is not listed, but can be told it is talking; a
    // listen-only one is neither
    mixer.set_mute_in(c, true).unwrap();
    mixer.set_listen_only(a, true).unwrap();
    run(&mut mixer, &mut legs, 1);
    assert!(mixer.talkers().is_empty());
    assert!(mixer.is_talking(c).unwrap());
    assert!(!mixer.is_talking(a).unwrap());

    // and one that leaves is off the list before the next tick
    mixer.set_mute_in(c, false).unwrap();
    run(&mut mixer, &mut legs, 1);
    assert_eq!(mixer.talkers(), [c]);
    mixer.leave(c).unwrap();
    assert!(mixer.talkers().is_empty());
}

#[test]
fn talkers_at_the_same_level_are_listed_by_who_started_first() {
    let mut mixer = mixer(2);
    let late = mixer.join(ParticipantConfig::new(Rate::Hz8000)).unwrap();
    let early = mixer.join(ParticipantConfig::new(Rate::Hz8000)).unwrap();
    // a constant has the same energy in every tick, so both levels converge
    // on the same value by the same steps
    let level = vec![1_000_i16; 160];
    for tick in 0..100 {
        mixer.push(early, &level).unwrap();
        if tick >= 5 {
            mixer.push(late, &level).unwrap();
        }
        mixer.mix();
    }
    assert_eq!(
        mixer.talk_level(early).unwrap(),
        mixer.talk_level(late).unwrap()
    );
    assert_eq!(mixer.talkers(), [early, late]);
}

#[test]
fn talking_is_measured_after_the_input_gain() {
    let mut mixer = mixer(2);
    let mut legs = vec![
        Leg::join(&mut mixer, Rate::Hz8000, Some((500.0, 1_000.0))),
        Leg::join(&mut mixer, Rate::Hz8000, None),
    ];
    let a = legs[0].id;
    mixer.set_gain_in(a, Gain::ratio(1, 4)).unwrap();
    run(&mut mixer, &mut legs, 5);
    // an RMS of 707 before the gain, 177 after it: under the start level
    assert!(mixer.talkers().is_empty());
    mixer.set_gain_in(a, Gain::UNITY).unwrap();
    run(&mut mixer, &mut legs, 2);
    assert_eq!(mixer.talkers(), [a]);
}
