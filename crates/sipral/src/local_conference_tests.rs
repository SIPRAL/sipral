// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A local conference of three real calls, each on its own codec and rate,
//! and this end: four stacks with no network under any of them, as in
//! `crate::tests`.
//!
//! Every member sends a tone of its own pitch, and what each one hears is
//! measured at every pitch: a member has to hear every other member's and
//! not its own.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_media::formats::wav::HEADER_LEN;

use crate::CallHandle;
use crate::codec::CodecCatalog;
use crate::error::MediaError;
use crate::local_conference::{
    ConferenceChange, ConferenceDirection, Departure, Gain, LocalConference, LocalConferenceConfig,
    Member,
};
use crate::record::RecordingOptions;
use crate::record::tests::Buffer;
use crate::tests::{
    Stack, callee_media, callee_sip, caller_media, caller_sip, carol_media, carol_sip, connect_two,
    settle_two,
};

const TICK: Duration = Duration::from_millis(20);

/// The rate this end takes part at.
const LOCAL_RATE: u32 = 16_000;

/// The pitches: bob, carol, dave, and this end.
const BOB_HZ: f64 = 500.0;
const CAROL_HZ: f64 = 900.0;
const DAVE_HZ: f64 = 1_300.0;
const LOCAL_HZ: f64 = 1_700.0;

fn dave_sip() -> SocketAddr {
    "192.0.2.4:5060".parse().expect("an address")
}

fn dave_media() -> SocketAddr {
    "192.0.2.4:40006".parse().expect("an address")
}

/// The codec dave's call settles on: Opus at 48 kHz where the build has it,
/// L16 at 16 kHz where it does not — either way a rate neither bob's nor
/// carol's call is at.
#[cfg(feature = "opus")]
const DAVE_CODEC: &str = "opus";
#[cfg(not(feature = "opus"))]
const DAVE_CODEC: &str = "L16/16000";

/// A sine at `hz`, carried on from `phase` samples in.
fn sine(len: usize, rate: u32, hz: f64, phase: &mut usize) -> Vec<i16> {
    let step = core::f64::consts::TAU * hz / f64::from(rate);
    (0..len)
        .map(|_| {
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let sample = (5_000.0 * (step * *phase as f64).sin()).round() as i16;
            *phase += 1;
            sample
        })
        .collect()
}

/// The amplitude of the component at `hz`, by Goertzel.
fn level_at(samples: &[i16], rate: u32, hz: f64) -> f64 {
    let coefficient = 2.0 * (core::f64::consts::TAU * hz / f64::from(rate)).cos();
    let (mut before, mut last) = (0.0_f64, 0.0_f64);
    for sample in samples {
        let next = f64::from(*sample) + coefficient * last - before;
        before = last;
        last = next;
    }
    let power = before.mul_add(before, last * last) - coefficient * before * last;
    #[allow(clippy::cast_precision_loss)]
    let length = samples.len().max(1) as f64;
    2.0 * power.max(0.0).sqrt() / length
}

/// One far end: its stack, its call, its codec's rate and what it heard.
struct FarEnd {
    stack: Stack,
    call: CallHandle,
    /// This end's call to it.
    near: CallHandle,
    media: SocketAddr,
    hz: f64,
    phase: usize,
    sending: bool,
    heard: Vec<i16>,
}

impl FarEnd {
    fn rate(&mut self) -> u32 {
        self.stack
            .engine
            .session(self.call)
            .map_or(8_000, |session| session.sample_rate())
    }
}

/// This end, three far ends on three codecs, and the conference.
struct Quartet {
    me: Stack,
    ends: Vec<FarEnd>,
    conference: LocalConference,
    local_phase: usize,
    local_heard: Vec<i16>,
    now: Instant,
}

impl Quartet {
    fn new(config: LocalConferenceConfig) -> Self {
        Self::with_bob_on(&["PCMU"], config)
    }

    /// The same, bob's own stack offering `bob_codecs`: his call still
    /// settles on PCMU, which this end offers first.
    fn with_bob_on(bob_codecs: &[&str], config: LocalConferenceConfig) -> Self {
        let now = Instant::now();
        let mine = CodecCatalog::with_order(&["PCMU", "G722", DAVE_CODEC]).expect("an order");
        let mut me = Stack::new(61, caller_sip(), caller_media(), mine, now);
        let mut ends = Vec::new();
        for (seed, sip, media, codecs, hz, user) in [
            (62, callee_sip(), callee_media(), bob_codecs, BOB_HZ, "bob"),
            (
                63,
                carol_sip(),
                carol_media(),
                &["G722"][..],
                CAROL_HZ,
                "carol",
            ),
            (
                64,
                dave_sip(),
                dave_media(),
                &[DAVE_CODEC][..],
                DAVE_HZ,
                "dave",
            ),
        ] {
            let catalog = CodecCatalog::with_order(codecs).expect("an order");
            let mut stack = Stack::new(seed, sip, media, catalog, now);
            let (near, call) = connect_two(&mut me, &mut stack, user, now);
            ends.push(FarEnd {
                stack,
                call,
                near,
                media,
                hz,
                phase: 0,
                sending: true,
                heard: Vec::new(),
            });
        }
        let conference = me.engine.local_conference(config).expect("a conference");
        Self {
            me,
            ends,
            conference,
            local_phase: 0,
            local_heard: Vec::new(),
            now,
        }
    }

    /// With all three calls added.
    fn joined(config: LocalConferenceConfig) -> Self {
        Self::new(config).all_added()
    }

    fn all_added(mut self) -> Self {
        let quartet = &mut self;
        for index in 0..quartet.ends.len() {
            let near = quartet.ends[index].near;
            let share = quartet.me.engine.share(near).expect("the call has media");
            quartet.conference.add(near, share).expect("the call joins");
        }
        self
    }

    fn end(&self, index: usize) -> &FarEnd {
        &self.ends[index]
    }

    /// One tick: every far end sends a frame of its tone, the conference
    /// mixes, and every far end plays what it was sent.
    fn tick(&mut self, local_tone: bool) {
        for end in &mut self.ends {
            if end.stack.engine.session(end.call).is_none() {
                continue;
            }
            let rate = end.rate();
            let frame = end
                .stack
                .engine
                .session(end.call)
                .expect("media")
                .frame_samples();
            let tone = if end.sending {
                sine(frame, rate, end.hz, &mut end.phase)
            } else {
                vec![0; frame]
            };
            let sent = end
                .stack
                .engine
                .session(end.call)
                .expect("media")
                .capture(&tone, self.now)
                .expect("the frame encodes")
                .map(|datagram| datagram.payload.to_vec());
            if let Some(mut payload) = sent
                && let Some(mut session) = self.me.engine.session(end.near)
            {
                session.receive(&mut payload, end.media, self.now);
            }
        }

        let frame = self.conference.local_frame();
        let mic = if local_tone && self.conference.local_rate().is_some() {
            sine(frame, LOCAL_RATE, LOCAL_HZ, &mut self.local_phase)
        } else {
            vec![0; frame]
        };
        self.conference.tick(&mic, self.now).expect("the tick");
        let mut speaker = vec![0_i16; frame];
        self.conference.speaker(&mut speaker);
        self.local_heard.extend_from_slice(&speaker);

        while let Some(packet) = self.conference.poll_transmit() {
            let Some(end) = self.ends.iter_mut().find(|end| end.near == packet.call) else {
                panic!("a packet for a call nobody placed");
            };
            let mut payload = packet.payload;
            if let Some(mut session) = end.stack.engine.session(end.call) {
                session.receive(&mut payload, caller_media(), self.now);
            }
        }
        for end in &mut self.ends {
            if let Some(mut session) = end.stack.engine.session(end.call) {
                let mut played = vec![0_i16; session.frame_samples()];
                session.playback(&mut played);
                end.heard.extend_from_slice(&played);
            }
        }
        self.now += TICK;
    }

    fn run(&mut self, ticks: usize, local_tone: bool) {
        for _ in 0..ticks {
            self.tick(local_tone);
        }
    }

    /// Forget what everybody heard so far.
    fn forget(&mut self) {
        for end in &mut self.ends {
            end.heard.clear();
        }
        self.local_heard.clear();
    }

    /// What far end `index` heard at every pitch: bob's, carol's, dave's
    /// and this end's.
    fn heard_by(&mut self, index: usize) -> [f64; 4] {
        let rate = self.ends[index].rate();
        let heard = &self.ends[index].heard;
        [BOB_HZ, CAROL_HZ, DAVE_HZ, LOCAL_HZ].map(|hz| level_at(heard, rate, hz))
    }

    fn heard_here(&self) -> [f64; 4] {
        [BOB_HZ, CAROL_HZ, DAVE_HZ, LOCAL_HZ].map(|hz| level_at(&self.local_heard, LOCAL_RATE, hz))
    }

    fn changes(&mut self) -> Vec<ConferenceChange> {
        std::iter::from_fn(|| self.conference.poll_change()).collect()
    }
}

/// Heard: well above the noise a codec and a resampler leave.
const HEARD: f64 = 800.0;
/// Not heard: under what a codec's own distortion puts at another pitch.
const SILENT: f64 = 150.0;

fn assert_hears(who: &str, levels: [f64; 4], expected: [bool; 4]) {
    let names = ["bob", "carol", "dave", "this end"];
    for ((level, heard), name) in levels.iter().zip(expected).zip(names) {
        if heard {
            assert!(*level > HEARD, "{who} did not hear {name}: {levels:?}");
        } else {
            assert!(*level < SILENT, "{who} heard {name}: {levels:?}");
        }
    }
}

fn three_calls_and_this_end() -> Quartet {
    Quartet::joined(LocalConferenceConfig {
        max_members: 4,
        local: Some(LOCAL_RATE),
    })
}

/// The point of the whole conference: bob on G.711 at 8 kHz, carol on G.722
/// at 16 kHz, dave on a third codec at a third rate and this end at 16 kHz,
/// each sending a pitch of its own, and each hearing the other three and not
/// itself.
#[test]
fn every_member_hears_every_other_member_and_not_itself() {
    let mut quartet = three_calls_and_this_end();
    let rates: Vec<u32> = (0..3).map(|index| quartet.ends[index].rate()).collect();
    assert_eq!(rates[0], 8_000);
    assert_eq!(rates[1], 16_000);
    assert!(
        rates[2] != 8_000 && rates[2] != 16_000 || DAVE_CODEC != "opus",
        "dave's call is not on a third rate: {rates:?}"
    );
    quartet.run(20, true);
    quartet.forget();
    quartet.run(25, true);

    assert_hears("bob", quartet.heard_by(0), [false, true, true, true]);
    assert_hears("carol", quartet.heard_by(1), [true, false, true, true]);
    assert_hears("dave", quartet.heard_by(2), [true, true, false, true]);
    assert_hears("this end", quartet.heard_here(), [true, true, true, false]);
}

/// A call that hangs up leaves on the next tick, says so, and the others go
/// on hearing each other.
#[test]
fn a_member_that_hangs_up_leaves_and_the_others_keep_talking() {
    let mut quartet = three_calls_and_this_end();
    quartet.run(20, false);
    let dave = quartet.end(2).near;
    let dave_call = quartet.end(2).call;
    let now = quartet.now;
    {
        let Quartet { me, ends, .. } = &mut quartet;
        let far = &mut ends[2].stack;
        far.agent.hangup(dave_call, now).expect("the BYE");
        far.drain(now, false);
        settle_two(far, me, false, now);
    }
    quartet.run(20, false);
    quartet.forget();
    quartet.run(25, false);

    assert!(!quartet.conference.contains(dave));
    assert!(
        quartet.changes().contains(&ConferenceChange::Left {
            member: Member::Call(dave),
            why: Departure::Ended,
        }),
        "dave's leaving was never reported"
    );
    assert_hears("bob", quartet.heard_by(0), [false, true, false, false]);
    assert_hears("carol", quartet.heard_by(1), [true, false, false, false]);
    assert_hears("this end", quartet.heard_here(), [true, true, false, false]);
}

/// A call taken out is gone from the mix at once, and its own session is
/// the application's again.
#[test]
fn a_member_removed_is_heard_no_more_and_hears_nothing_more() {
    let mut quartet = three_calls_and_this_end();
    quartet.run(20, false);
    let bob = quartet.end(0).near;
    quartet.conference.remove(bob).expect("bob is a member");
    assert_eq!(
        quartet.conference.remove(bob),
        Err(MediaError::NotInConference)
    );
    quartet.run(10, false);
    quartet.forget();
    quartet.run(25, false);

    assert_hears("carol", quartet.heard_by(1), [false, false, true, false]);
    assert_hears("dave", quartet.heard_by(2), [false, true, false, false]);
    // nobody sends bob anything now: this end drives his call no longer
    assert_hears("bob", quartet.heard_by(0), [false, false, false, false]);
}

/// This end holding one member leaves the other two talking to each other,
/// and to this end.
#[test]
fn a_member_on_hold_leaves_the_others_talking() {
    let mut quartet = three_calls_and_this_end();
    quartet.run(20, true);
    let dave = quartet.end(2).near;
    let now = quartet.now;
    {
        let Quartet { me, ends, .. } = &mut quartet;
        me.agent.hold(dave, now).expect("the hold");
        me.drain(now, false);
        settle_two(me, &mut ends[2].stack, false, now);
    }
    assert!(
        !quartet
            .me
            .engine
            .session(dave)
            .expect("dave's call keeps its media")
            .is_receiving(),
        "the hold never reached dave's session"
    );
    quartet.run(20, true);
    quartet.forget();
    quartet.run(25, true);

    assert!(
        quartet.conference.contains(dave),
        "a held member was dropped"
    );
    assert_hears("bob", quartet.heard_by(0), [false, true, false, true]);
    assert_hears("carol", quartet.heard_by(1), [true, false, false, true]);
    assert_hears("this end", quartet.heard_here(), [true, true, false, false]);
}

/// A member muted on the way in is heard by nobody; one muted on the way
/// out hears nothing and is still heard.
#[test]
fn a_mute_silences_one_member_one_way() {
    let mut quartet = three_calls_and_this_end();
    let bob = Member::Call(quartet.end(0).near);
    let carol = Member::Call(quartet.end(1).near);
    quartet
        .conference
        .set_muted(bob, ConferenceDirection::Input, true)
        .expect("bob is a member");
    quartet
        .conference
        .set_muted(carol, ConferenceDirection::Output, true)
        .expect("carol is a member");
    assert_eq!(
        quartet.conference.muted(bob, ConferenceDirection::Input),
        Ok(true)
    );
    quartet.run(20, true);
    quartet.forget();
    quartet.run(25, true);

    assert_hears("carol", quartet.heard_by(1), [false, false, false, false]);
    assert_hears("dave", quartet.heard_by(2), [false, true, false, true]);
    assert_hears("this end", quartet.heard_here(), [false, true, true, false]);
    assert!(
        !quartet.conference.talkers().contains(&bob),
        "a member muted on the way in was listed as talking"
    );
}

/// A gain on one member's input changes how loud everybody else hears it,
/// and nobody else.
#[test]
fn a_gain_scales_one_member_for_everybody_else() {
    let mut quartet = three_calls_and_this_end();
    quartet.run(20, true);
    quartet.forget();
    quartet.run(25, true);
    let before = quartet.heard_here();

    let dave = Member::Call(quartet.end(2).near);
    quartet
        .conference
        .set_gain(dave, ConferenceDirection::Input, Gain::ratio(1, 4))
        .expect("dave is a member");
    assert_eq!(
        quartet.conference.gain(dave, ConferenceDirection::Input),
        Ok(Gain::ratio(1, 4))
    );
    quartet.run(10, true);
    quartet.forget();
    quartet.run(25, true);
    let after = quartet.heard_here();

    let ratio = after[2] / before[2];
    assert!(
        (0.15..0.35).contains(&ratio),
        "dave at a quarter came through at {ratio} of before: {before:?} then {after:?}"
    );
    let bob = after[0] / before[0];
    assert!((0.85..1.15).contains(&bob), "bob moved with dave: {bob}");
}

/// Who is talking is reported as it changes, loudest first, and a silent
/// member is not listed.
#[test]
fn the_talkers_are_reported_as_they_change() {
    let mut quartet = three_calls_and_this_end();
    quartet.ends[1].sending = false;
    quartet.ends[2].sending = false;
    quartet.run(20, false);
    let bob = Member::Call(quartet.end(0).near);
    assert_eq!(quartet.conference.talkers(), &[bob]);
    assert!(quartet.conference.is_talking(bob).expect("a member"));
    assert!(quartet.changes().contains(&ConferenceChange::Talkers));

    quartet.ends[2].sending = true;
    quartet.run(20, false);
    let dave = Member::Call(quartet.end(2).near);
    let talking = quartet.conference.talkers().to_vec();
    assert_eq!(talking.len(), 2, "{talking:?}");
    assert!(
        talking.contains(&bob) && talking.contains(&dave),
        "{talking:?}"
    );
    assert!(quartet.changes().contains(&ConferenceChange::Talkers));
}

/// The refusals: a conference that is full, a call added twice, a member
/// that is not there, and a rate the conference cannot mix.
#[test]
fn a_full_conference_and_a_second_add_are_refused() {
    let mut quartet = Quartet::new(LocalConferenceConfig {
        max_members: 3,
        local: Some(LOCAL_RATE),
    });
    let calls: Vec<CallHandle> = quartet.ends.iter().map(|end| end.near).collect();
    for call in &calls[..2] {
        let share = quartet.me.engine.share(*call).expect("media");
        quartet.conference.add(*call, share).expect("room for it");
    }
    let share = quartet.me.engine.share(calls[0]).expect("media");
    assert_eq!(
        quartet.conference.add(calls[0], share),
        Err(MediaError::InConference)
    );
    let share = quartet.me.engine.share(calls[2]).expect("media");
    assert_eq!(
        quartet.conference.add(calls[2], share),
        Err(MediaError::ConferenceFull { capacity: 3 })
    );
    assert_eq!(quartet.conference.len(), 3);
    assert_eq!(
        quartet
            .conference
            .set_muted(Member::Call(calls[2]), ConferenceDirection::Input, true),
        Err(MediaError::NotInConference)
    );
    assert_eq!(
        LocalConference::new(
            LocalConferenceConfig {
                max_members: 4,
                local: Some(44_100),
            },
            1
        )
        .unwrap_err(),
        MediaError::ConferenceIncompatible {
            hertz: 44_100,
            frame_samples: 0
        }
    );
    assert!(matches!(
        LocalConference::new(
            LocalConferenceConfig {
                max_members: 0,
                local: None,
            },
            1
        ),
        Err(MediaError::ConferenceFull { .. })
    ));
    assert_eq!(
        quartet.conference.tick(&[0; 100], quartet.now),
        Err(MediaError::LocalFrame {
            expected: 320,
            given: 100
        })
    );
}

/// A conference this end does not take part in still bridges its calls,
/// and hands this end silence.
#[test]
fn a_conference_without_this_end_bridges_its_calls() {
    let mut quartet = Quartet::joined(LocalConferenceConfig {
        max_members: 3,
        local: None,
    });
    assert_eq!(quartet.conference.members().count(), 3);
    quartet.run(20, true);
    quartet.forget();
    quartet.run(25, true);

    assert_hears("bob", quartet.heard_by(0), [false, true, true, false]);
    assert_hears("carol", quartet.heard_by(1), [true, false, true, false]);
    assert_hears(
        "this end",
        quartet.heard_here(),
        [false, false, false, false],
    );
}

/// The recording is the whole conference: every member at its own pitch,
/// in one channel, at this end's rate.
#[test]
fn the_recording_keeps_the_whole_mix() {
    let mut quartet = three_calls_and_this_end();
    quartet.run(20, true);
    let file = Buffer::new();
    quartet
        .conference
        .start_recording(Box::new(file.clone()), &RecordingOptions::default())
        .expect("the recording starts");
    assert_eq!(
        quartet
            .conference
            .start_recording(Box::new(Buffer::new()), &RecordingOptions::default()),
        Err(MediaError::AlreadyRecording)
    );
    quartet.run(25, true);
    assert!(quartet.conference.is_recording());
    quartet
        .conference
        .stop_recording()
        .expect("the file is finished");

    let wav = file.contents();
    assert_eq!(
        crate::record::tests::field(&wav, crate::record::tests::CHANNELS_AT, 2),
        1
    );
    assert_eq!(
        crate::record::tests::field(&wav, crate::record::tests::RATE_AT, 4),
        LOCAL_RATE
    );
    let samples: Vec<i16> = wav[HEADER_LEN..]
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert_eq!(samples.len(), 25 * 320);
    for (hz, who) in [
        (BOB_HZ, "bob"),
        (CAROL_HZ, "carol"),
        (DAVE_HZ, "dave"),
        (LOCAL_HZ, "this end"),
    ] {
        let level = level_at(&samples[5 * 320..], LOCAL_RATE, hz);
        assert!(level > HEARD, "{who} is not in the recording: {level}");
    }
    let stereo = RecordingOptions {
        layout: crate::RecordingLayout::Stereo,
        ..RecordingOptions::default()
    };
    assert_eq!(
        quartet
            .conference
            .start_recording(Box::new(Buffer::new()), &stereo),
        Err(MediaError::ConferenceStereo)
    );
}

/// A member whose call moves to a codec at another rate mid-conference is
/// seated again at the new rate, with the controls it had, and goes on
/// hearing and being heard.
#[test]
fn a_member_whose_codec_moves_is_seated_again_at_the_new_rate() {
    let mut quartet = Quartet::with_bob_on(
        &["PCMU", "G722"],
        LocalConferenceConfig {
            max_members: 4,
            local: Some(LOCAL_RATE),
        },
    )
    .all_added();
    let bob = quartet.end(0).near;
    assert_eq!(quartet.ends[0].rate(), 8_000);
    quartet
        .conference
        .set_gain(
            Member::Call(bob),
            ConferenceDirection::Output,
            Gain::ratio(1, 2),
        )
        .expect("bob is a member");
    quartet.run(20, true);
    let now = quartet.now;
    {
        let Quartet { me, ends, .. } = &mut quartet;
        me.engine
            .change_codecs(&mut me.agent, bob, &["G722"], now)
            .expect("the re-offer goes");
        me.drain(now, false);
        settle_two(me, &mut ends[0].stack, false, now);
    }
    assert_eq!(quartet.ends[0].rate(), 16_000, "bob's call did not move");
    quartet.run(20, true);
    quartet.forget();
    quartet.run(25, true);

    assert!(
        quartet.conference.contains(bob),
        "a member that moved was dropped"
    );
    assert_eq!(
        quartet
            .conference
            .gain(Member::Call(bob), ConferenceDirection::Output),
        Ok(Gain::ratio(1, 2)),
        "the controls did not follow the member to its new seat"
    );
    assert_hears("bob", quartet.heard_by(0), [false, true, true, true]);
    assert_hears("carol", quartet.heard_by(1), [true, false, true, true]);
    assert_hears("this end", quartet.heard_here(), [true, true, true, false]);
}
