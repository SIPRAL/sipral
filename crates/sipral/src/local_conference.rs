// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A local conference of any number of calls, with or without this end.
//!
//! [`MediaEngine::join`](crate::MediaEngine::join) pairs two calls that
//! already agree on a rate and a frame. This is the general case:
//! `sipral_media::nway`'s mixer behind calls that each keep their own codec,
//! their own rate and their own frame, so a G.711 call, a G.722 call and an
//! Opus call can be in one conference. Every member hears everybody but
//! itself; nobody's own voice comes back to it.
//!
//! # Who is in it
//!
//! Calls, added with [`LocalConference::add`] and taken out with
//! [`LocalConference::remove`], each reached through its [`SessionShare`] —
//! the conference holds no engine and takes no engine lock, so the thread
//! that runs it is the one that carries audio, as for a single call. And,
//! when [`LocalConferenceConfig::local`] names a rate, this end: the
//! microphone frame handed to [`LocalConference::tick`] is what this end
//! says, and [`LocalConference::speaker`] is what it hears.
//!
//! A call in a conference is driven by it and by nothing else: its
//! [`MediaSession::playback`](crate::MediaSession::playback) and
//! [`MediaSession::capture`](crate::MediaSession::capture) are called from
//! the tick, and a thread calling them on the same call as well would take
//! every other frame out from under the conference. A call joined into a
//! pair with [`MediaEngine::join`](crate::MediaEngine::join) is the same
//! mistake; `sipral-ffi` refuses both, and a Rust application keeps to it.
//!
//! # The tick
//!
//! [`LocalConference::tick`] is twenty milliseconds of conference: every
//! member's decoded audio taken off its session, one mix formed, and every
//! member's share of it encoded and queued for
//! [`LocalConference::poll_transmit`]. A call whose frame is 10 ms is read
//! twice a tick; one whose frame is 40 or 60 ms every second or third tick,
//! and one at 30 ms every tick and a half, so that each call keeps its own
//! packetisation. A frame of more than three ticks is refused.
//!
//! # Hold, and calls that end
//!
//! Nothing about hold is special here, and that is the point: a member this
//! end holds has nothing sent to it (its session answers `None` for a frame
//! it may not send) and a member that holds this end sends nothing, so it
//! is mixed as silence. Everybody else goes on hearing everybody else. A
//! member whose call ends leaves the conference on the next tick, and its
//! departure is reported like any other.
//!
//! # What changes are reported
//!
//! [`LocalConference::poll_change`] hands out, in order, who joined, who
//! left and why, when the list of who is talking changed
//! ([`LocalConference::talkers`], loudest first, with the hysteresis
//! `sipral_media::nway::talker` describes), and a recording that stopped by
//! itself.
//!
//! # Recording
//!
//! [`LocalConference::start_recording`] writes the whole mix — everybody
//! the conference hears, at each member's own level — through the recorder
//! a call's recording uses, in any of its formats, as one channel.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use sipral_media::nway::{MixError, Mixer, MixerConfig, ParticipantConfig, ParticipantId, Rate};
use sipral_ua::CallHandle;

pub use sipral_media::mix::Gain;

use crate::error::MediaError;
use crate::record::{Recorder, RecordingLayout, RecordingOptions, RecordingSink};
use crate::share::{SessionShare, SessionUnavailable};

/// The most members a conference can be made for, this end included.
pub const MAX_CONFERENCE_MEMBERS: usize = sipral_media::nway::MAX_PARTICIPANTS;

/// How many changes wait for [`LocalConference::poll_change`] before the
/// oldest are dropped.
const CHANGES_KEPT: usize = 256;

/// How many packets wait for [`LocalConference::poll_transmit`] before the
/// oldest are dropped.
const PACKETS_KEPT: usize = 1_024;

/// How a conference is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalConferenceConfig {
    /// The most members it holds at once, this end included: from one to
    /// [`MAX_CONFERENCE_MEMBERS`].
    pub max_members: usize,
    /// The rate this end's own microphone and speaker frames are at, in
    /// hertz — 8, 16, 32 or 48 kHz — or `None` for a conference this end
    /// does not take part in, which only bridges its calls.
    pub local: Option<u32>,
}

impl Default for LocalConferenceConfig {
    /// Sixteen members, this end among them at 16 kHz.
    fn default() -> Self {
        Self {
            max_members: 16,
            local: Some(16_000),
        }
    }
}

/// One member of a conference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Member {
    /// This end: the microphone and the speaker.
    Local,
    /// A call.
    Call(CallHandle),
}

/// Which way a member's audio goes, for a mute or a gain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConferenceDirection {
    /// What the member says: muted, nobody hears it.
    Input,
    /// What the member hears: muted, it hears silence.
    Output,
}

/// Why a member left.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Departure {
    /// [`LocalConference::remove`] took it out.
    Removed,
    /// Its call's media ended.
    Ended,
    /// Its call moved to a codec whose rate or frame the conference cannot
    /// mix.
    Incompatible,
}

/// Something about a conference that changed, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConferenceChange {
    /// A member joined.
    Joined(Member),
    /// A member left.
    Left {
        /// Who.
        member: Member,
        /// Why.
        why: Departure,
    },
    /// The list of who is talking changed:
    /// [`LocalConference::talkers`] has the new one.
    Talkers,
    /// A recording stopped by itself: its sink refused what was written.
    /// The file holds the audio up to its last checkpoint.
    RecordingStopped(MediaError),
}

/// A packet a member's call owes its far end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConferencePacket {
    /// The call it belongs to, whose media socket sends it.
    pub call: CallHandle,
    /// Where it goes.
    pub destination: SocketAddr,
    /// The octets.
    pub payload: Vec<u8>,
    /// How it leaves, as [`Datagram::transport`](crate::Datagram::transport)
    /// says.
    #[cfg(feature = "ice")]
    pub transport: crate::TurnTransport,
}

/// A call in the conference.
struct Seat {
    call: CallHandle,
    share: SessionShare,
    id: ParticipantId,
    /// The session's rate and frame when it was last looked at.
    rate: u32,
    frame: usize,
    /// Samples at the call's rate the conference owes the mixer from this
    /// call and has not read yet: a tick adds one, each frame read takes
    /// one frame.
    due: usize,
    /// One frame, reused.
    buffer: Vec<i16>,
}

/// A local conference: see the [module documentation](self).
pub struct LocalConference {
    mixer: Mixer,
    /// How many members it was made for, this end included.
    places: usize,
    seats: Vec<Seat>,
    local: Option<(ParticipantId, Rate)>,
    talkers: Vec<Member>,
    changes: VecDeque<ConferenceChange>,
    changes_dropped: u64,
    packets: VecDeque<ConferencePacket>,
    packets_dropped: u64,
    recorder: Option<Recorder>,
    /// The rate the mix is recorded at before the recorder converts it to
    /// the file's: this end's own, or 16 kHz.
    tap_rate: Rate,
    tap: Vec<i16>,
    /// Where Ogg stream serial numbers come from.
    serials: u64,
}

impl core::fmt::Debug for LocalConference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalConference")
            .field("members", &self.len())
            .field("capacity", &self.capacity())
            .field("talkers", &self.talkers)
            .field("recording", &self.recorder.is_some())
            .finish_non_exhaustive()
    }
}

impl LocalConference {
    /// An empty conference, with this end in it when `config.local` says so.
    /// `seed` is where the serial numbers of its Ogg recordings are drawn
    /// from; [`MediaEngine::local_conference`](crate::MediaEngine::local_conference)
    /// draws it from the engine's own randomness.
    ///
    /// # Errors
    /// [`MediaError::ConferenceIncompatible`] for a local rate that is not
    /// 8, 16, 32 or 48 kHz, and [`MediaError::ConferenceFull`] for a
    /// `max_members` of zero or past [`MAX_CONFERENCE_MEMBERS`].
    pub fn new(config: LocalConferenceConfig, seed: u64) -> Result<Self, MediaError> {
        let mut mixer = Mixer::new(MixerConfig {
            max_participants: config.max_members,
        })
        .map_err(|_| MediaError::ConferenceFull {
            capacity: config.max_members,
        })?;
        let local = match config.local {
            None => None,
            Some(hertz) => {
                let rate = Rate::from_hz(hertz).ok_or(MediaError::ConferenceIncompatible {
                    hertz,
                    frame_samples: 0,
                })?;
                let id = mixer
                    .join(ParticipantConfig::new(rate))
                    .map_err(|error| refused(error, hertz, rate.tick_samples()))?;
                Some((id, rate))
            }
        };
        let tap_rate = local.map_or(Rate::Hz16000, |(_, rate)| rate);
        let mut conference = Self {
            mixer,
            places: config.max_members,
            seats: Vec::new(),
            local,
            talkers: Vec::new(),
            changes: VecDeque::new(),
            changes_dropped: 0,
            packets: VecDeque::new(),
            packets_dropped: 0,
            recorder: None,
            tap_rate,
            tap: vec![0; tap_rate.tick_samples()],
            serials: seed,
        };
        if conference.local.is_some() {
            conference.note(ConferenceChange::Joined(Member::Local));
        }
        Ok(conference)
    }

    /// How many members it holds at most, this end included.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.places
    }

    fn free_places(&self) -> usize {
        self.places.saturating_sub(self.mixer.len())
    }

    /// How many members it has, this end included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mixer.len()
    }

    /// Whether it has no members at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mixer.is_empty()
    }

    /// Whether this end takes part, and at what rate its frames are.
    #[must_use]
    pub fn local_rate(&self) -> Option<u32> {
        self.local.map(|(_, rate)| rate.hz())
    }

    /// Samples in one tick of this end's own audio: what [`Self::tick`]'s
    /// microphone frame and [`Self::speaker`]'s frame are. Twenty
    /// milliseconds at the local rate, or at 16 kHz when this end does not
    /// take part.
    #[must_use]
    pub fn local_frame(&self) -> usize {
        self.tap_rate.tick_samples()
    }

    /// Every member, this end first when it takes part, then the calls in
    /// the order they joined.
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.local
            .map(|_| Member::Local)
            .into_iter()
            .chain(self.seats.iter().map(|seat| Member::Call(seat.call)))
    }

    /// Whether a call is a member.
    #[must_use]
    pub fn contains(&self, call: CallHandle) -> bool {
        self.seats.iter().any(|seat| seat.call == call)
    }

    /// Who was talking in the last tick, loudest first. A muted member is
    /// never listed.
    #[must_use]
    pub fn talkers(&self) -> &[Member] {
        &self.talkers
    }

    /// Add a call. It takes part from the next tick.
    ///
    /// # Errors
    /// [`MediaError::InConference`] for a call already in this conference,
    /// [`MediaError::ConferenceFull`] when every place is taken,
    /// [`MediaError::NoSuchCall`] for a call whose media has ended, and
    /// [`MediaError::ConferenceIncompatible`] for a call whose codec hears at
    /// a rate other than 8, 16, 32 or 48 kHz or cuts frames longer than
    /// three ticks.
    pub fn add(&mut self, call: CallHandle, share: SessionShare) -> Result<(), MediaError> {
        if self.contains(call) {
            return Err(MediaError::InConference);
        }
        if self.free_places() == 0 {
            return Err(MediaError::ConferenceFull {
                capacity: self.places,
            });
        }
        let (rate, frame) = share
            .with(|session| (session.sample_rate(), session.frame_samples()))
            .map_err(|_| MediaError::NoSuchCall)?;
        let id = self.seat(rate, frame)?;
        self.seats.push(Seat {
            call,
            share,
            id,
            rate,
            frame,
            due: 0,
            buffer: vec![0; frame],
        });
        self.note(ConferenceChange::Joined(Member::Call(call)));
        Ok(())
    }

    /// A place in the mixer for a call at `hertz` with frames of `frame`.
    fn seat(&mut self, hertz: u32, frame: usize) -> Result<ParticipantId, MediaError> {
        let incompatible = || MediaError::ConferenceIncompatible {
            hertz,
            frame_samples: frame,
        };
        let rate = Rate::from_hz(hertz).ok_or_else(incompatible)?;
        let tick = rate.tick_samples();
        if frame == 0 {
            return Err(incompatible());
        }
        // a frame that neither divides a tick nor is whole ticks — 30 ms —
        // is read as it comes and queued as whole ticks; the mixer only
        // needs to know how much to hold
        let held = if tick.is_multiple_of(frame) {
            frame
        } else {
            frame.div_ceil(tick) * tick
        };
        self.mixer
            .join(ParticipantConfig::new(rate).with_frame(held))
            .map_err(|error| refused(error, hertz, frame))
    }

    /// Take a call out. It is gone from the next tick, and its session is
    /// left exactly as the conference last drove it.
    ///
    /// # Errors
    /// [`MediaError::NotInConference`] for a call that is not a member.
    pub fn remove(&mut self, call: CallHandle) -> Result<(), MediaError> {
        self.depart(call, Departure::Removed)
            .ok_or(MediaError::NotInConference)
    }

    fn depart(&mut self, call: CallHandle, why: Departure) -> Option<()> {
        let at = self.seats.iter().position(|seat| seat.call == call)?;
        let seat = self.seats.remove(at);
        let _ = self.mixer.leave(seat.id);
        self.talkers.retain(|member| *member != Member::Call(call));
        self.note(ConferenceChange::Left {
            member: Member::Call(call),
            why,
        });
        Some(())
    }

    /// Mute or unmute one way of a member, from the next tick.
    ///
    /// # Errors
    /// [`MediaError::NotInConference`] for a member that is not in it.
    pub fn set_muted(
        &mut self,
        member: Member,
        direction: ConferenceDirection,
        muted: bool,
    ) -> Result<(), MediaError> {
        let id = self.id_of(member)?;
        let done = match direction {
            ConferenceDirection::Input => self.mixer.set_mute_in(id, muted),
            ConferenceDirection::Output => self.mixer.set_mute_out(id, muted),
        };
        done.map_err(|_| MediaError::NotInConference)
    }

    /// Whether one way of a member is muted.
    ///
    /// # Errors
    /// [`MediaError::NotInConference`] for a member that is not in it.
    pub fn muted(&self, member: Member, direction: ConferenceDirection) -> Result<bool, MediaError> {
        let controls = self
            .mixer
            .controls(self.id_of(member)?)
            .map_err(|_| MediaError::NotInConference)?;
        Ok(match direction {
            ConferenceDirection::Input => controls.mute_in,
            ConferenceDirection::Output => controls.mute_out,
        })
    }

    /// Set the level of one way of a member, from the next tick: of what it
    /// says for everybody else, or of what it hears.
    ///
    /// # Errors
    /// [`MediaError::NotInConference`] for a member that is not in it.
    pub fn set_gain(
        &mut self,
        member: Member,
        direction: ConferenceDirection,
        gain: Gain,
    ) -> Result<(), MediaError> {
        let id = self.id_of(member)?;
        let done = match direction {
            ConferenceDirection::Input => self.mixer.set_gain_in(id, gain),
            ConferenceDirection::Output => self.mixer.set_gain_out(id, gain),
        };
        done.map_err(|_| MediaError::NotInConference)
    }

    /// The level of one way of a member.
    ///
    /// # Errors
    /// [`MediaError::NotInConference`] for a member that is not in it.
    pub fn gain(&self, member: Member, direction: ConferenceDirection) -> Result<Gain, MediaError> {
        let controls = self
            .mixer
            .controls(self.id_of(member)?)
            .map_err(|_| MediaError::NotInConference)?;
        Ok(match direction {
            ConferenceDirection::Input => controls.gain_in,
            ConferenceDirection::Output => controls.gain_out,
        })
    }

    /// Whether a member was talking in the last tick, muted or not: what a
    /// client needs to say "you are muted" to somebody talking into a mute.
    ///
    /// # Errors
    /// [`MediaError::NotInConference`] for a member that is not in it.
    pub fn is_talking(&self, member: Member) -> Result<bool, MediaError> {
        self.mixer
            .is_talking(self.id_of(member)?)
            .map_err(|_| MediaError::NotInConference)
    }

    fn id_of(&self, member: Member) -> Result<ParticipantId, MediaError> {
        match member {
            Member::Local => self.local.map(|(id, _)| id),
            Member::Call(call) => self
                .seats
                .iter()
                .find(|seat| seat.call == call)
                .map(|seat| seat.id),
        }
        .ok_or(MediaError::NotInConference)
    }

    /// Twenty milliseconds of conference.
    ///
    /// `mic` is this end's own frame, [`Self::local_frame`] samples at the
    /// local rate; a conference this end does not take part in reads none of
    /// it. Every member's audio is read, mixed and encoded; the packets wait
    /// for [`Self::poll_transmit`] and this end's share for
    /// [`Self::speaker`].
    ///
    /// # Errors
    /// [`MediaError::LocalFrame`] for a microphone frame of any other
    /// length, when this end takes part. Nothing was mixed.
    pub fn tick(&mut self, mic: &[i16], now: Instant) -> Result<(), MediaError> {
        if let Some((id, rate)) = self.local {
            if mic.len() != rate.tick_samples() {
                return Err(MediaError::LocalFrame {
                    expected: rate.tick_samples(),
                    given: mic.len(),
                });
            }
            let _ = self.mixer.push(id, mic);
        }
        self.read_calls();
        self.mixer.mix();
        self.send_calls(now);
        self.record();
        self.follow_talkers();
        Ok(())
    }

    /// What this end hears, into `out`, and how many samples that was: one
    /// tick after every [`Self::tick`], at the local rate. Whatever `out`
    /// has room for past what was mixed is silence. A conference this end
    /// does not take part in fills it with silence.
    pub fn speaker(&mut self, out: &mut [i16]) -> usize {
        let taken = match self.local {
            Some((id, _)) => self.mixer.pull(id, out).unwrap_or(0),
            None => 0,
        };
        if let Some(rest) = out.get_mut(taken..) {
            rest.fill(0);
        }
        taken
    }

    /// The oldest packet a member's call owes its far end, if any.
    pub fn poll_transmit(&mut self) -> Option<ConferencePacket> {
        self.packets.pop_front()
    }

    /// Packets dropped because nobody polled for them in time.
    #[must_use]
    pub const fn packets_dropped(&self) -> u64 {
        self.packets_dropped
    }

    /// The oldest change not yet handed out.
    pub fn poll_change(&mut self) -> Option<ConferenceChange> {
        self.changes.pop_front()
    }

    /// Changes dropped because nobody polled for them in time.
    #[must_use]
    pub const fn changes_dropped(&self) -> u64 {
        self.changes_dropped
    }

    /// Start writing the whole mix to `sink`.
    ///
    /// # Errors
    /// [`MediaError::AlreadyRecording`] when one is running,
    /// [`MediaError::ConferenceStereo`] for a stereo layout — a conference is
    /// one mix, recorded as one channel — and whatever
    /// [`MediaSession::start_recording_with`](crate::MediaSession::start_recording_with)
    /// refuses about the options or the sink.
    pub fn start_recording(
        &mut self,
        sink: Box<dyn RecordingSink>,
        options: &RecordingOptions,
    ) -> Result<(), MediaError> {
        if self.recorder.is_some() {
            return Err(MediaError::AlreadyRecording);
        }
        if options.layout == RecordingLayout::Stereo {
            return Err(MediaError::ConferenceStereo);
        }
        let serial = self.next_serial();
        let recorder = Recorder::start(sink, options, self.tap_rate.hz(), serial)?;
        self.mixer
            .start_recording(self.tap_rate)
            .map_err(|_| MediaError::RecordingRate {
                hertz: self.tap_rate.hz(),
            })?;
        self.recorder = Some(recorder);
        Ok(())
    }

    /// Stop the recording and finish the file.
    ///
    /// # Errors
    /// [`MediaError::NotRecording`], and [`MediaError::Recording`] when the
    /// file could not be finished.
    pub fn stop_recording(&mut self) -> Result<(), MediaError> {
        let recorder = self.recorder.take().ok_or(MediaError::NotRecording)?;
        self.mixer.stop_recording();
        recorder.finish()
    }

    /// Whether a recording is running.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// How much has been recorded, while a recording runs.
    #[must_use]
    pub fn recorded(&self) -> Option<std::time::Duration> {
        self.recorder.as_ref().map(Recorder::recorded)
    }

    fn next_serial(&mut self) -> u32 {
        // SplitMix64, as a session draws its own
        self.serials = self.serials.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.serials;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        u32::try_from(z >> 32).unwrap_or(0)
    }

    /// Each call's audio for this tick, off its session and into the mixer.
    fn read_calls(&mut self) {
        let mut gone = Vec::new();
        let mut moved = Vec::new();
        let mixer = &mut self.mixer;
        for seat in &mut self.seats {
            let Seat {
                call,
                share,
                id,
                rate,
                frame,
                due,
                buffer,
            } = seat;
            *due += Rate::from_hz(*rate).map_or(0, Rate::tick_samples);
            let read = share.with(|session| {
                let format = (session.sample_rate(), session.frame_samples());
                if format != (*rate, *frame) {
                    return Some(format);
                }
                while *due >= *frame {
                    session.playback(buffer);
                    let _ = mixer.push(*id, buffer);
                    *due -= *frame;
                }
                None
            });
            match read {
                Ok(None) | Err(SessionUnavailable::Reentered) => {}
                Ok(Some(format)) => moved.push((*call, format)),
                Err(_) => gone.push(*call),
            }
        }
        for call in gone {
            self.depart(call, Departure::Ended);
        }
        for (call, format) in moved {
            self.reseat(call, format);
        }
    }

    /// A call whose codec moved under it: a new place in the mixer at the
    /// new rate and frame, with the same controls, or out of the
    /// conference when there is none.
    fn reseat(&mut self, call: CallHandle, (hertz, frame): (u32, usize)) {
        let Some(at) = self.seats.iter().position(|seat| seat.call == call) else {
            return;
        };
        let Some(old) = self.seats.get(at).map(|seat| seat.id) else {
            return;
        };
        let controls = self.mixer.controls(old).ok();
        let _ = self.mixer.leave(old);
        let Ok(id) = self.seat(hertz, frame) else {
            let seat = self.seats.remove(at);
            self.talkers
                .retain(|member| *member != Member::Call(seat.call));
            self.note(ConferenceChange::Left {
                member: Member::Call(call),
                why: Departure::Incompatible,
            });
            return;
        };
        if let Some(controls) = controls {
            let _ = self.mixer.set_gain_in(id, controls.gain_in);
            let _ = self.mixer.set_gain_out(id, controls.gain_out);
            let _ = self.mixer.set_mute_in(id, controls.mute_in);
            let _ = self.mixer.set_mute_out(id, controls.mute_out);
        }
        if let Some(seat) = self.seats.get_mut(at) {
            seat.id = id;
            seat.rate = hertz;
            seat.frame = frame;
            seat.due = 0;
            seat.buffer = vec![0; frame];
        }
    }

    /// What each call is owed, off the mixer and onto its session.
    fn send_calls(&mut self, now: Instant) {
        let mut gone = Vec::new();
        for seat in &mut self.seats {
            let Seat {
                share,
                buffer,
                frame,
                id,
                call,
                ..
            } = seat;
            let mixer = &mut self.mixer;
            let packets = &mut self.packets;
            let dropped = &mut self.packets_dropped;
            let sent = share.with(|session| {
                while mixer.available(*id).unwrap_or(0) >= *frame {
                    let _ = mixer.pull(*id, buffer);
                    let Ok(Some(datagram)) = session.capture(buffer, now) else {
                        continue;
                    };
                    if packets.len() >= PACKETS_KEPT {
                        packets.pop_front();
                        *dropped = dropped.saturating_add(1);
                    }
                    packets.push_back(ConferencePacket {
                        call: *call,
                        destination: datagram.destination,
                        payload: datagram.payload.to_vec(),
                        #[cfg(feature = "ice")]
                        transport: datagram.transport,
                    });
                }
            });
            if matches!(sent, Err(SessionUnavailable::Ended)) {
                gone.push(*call);
            }
        }
        for call in gone {
            self.depart(call, Departure::Ended);
        }
    }

    /// The tick's whole mix, into the recording.
    fn record(&mut self) {
        let Some(recorder) = self.recorder.as_mut() else {
            return;
        };
        let taken = self.mixer.read_recording(&mut self.tap);
        let Some(mix) = self.tap.get(..taken) else {
            return;
        };
        if let Err(error) = recorder.mix(mix) {
            self.recorder = None;
            self.mixer.stop_recording();
            self.note(ConferenceChange::RecordingStopped(error));
        }
    }

    /// The talkers as the mixer ranked them, and a change when they moved.
    fn follow_talkers(&mut self) {
        let local = self.local.map(|(id, _)| id);
        let now: Vec<Member> = self
            .mixer
            .talkers()
            .iter()
            .filter_map(|id| {
                if Some(*id) == local {
                    return Some(Member::Local);
                }
                self.seats
                    .iter()
                    .find(|seat| seat.id == *id)
                    .map(|seat| Member::Call(seat.call))
            })
            .collect();
        if now != self.talkers {
            self.talkers = now;
            self.note(ConferenceChange::Talkers);
        }
    }

    fn note(&mut self, change: ConferenceChange) {
        if self.changes.len() >= CHANGES_KEPT {
            self.changes.pop_front();
            self.changes_dropped = self.changes_dropped.saturating_add(1);
        }
        self.changes.push_back(change);
    }
}

/// Why the mixer would not seat somebody, in the facade's terms.
fn refused(error: MixError, hertz: u32, frame_samples: usize) -> MediaError {
    match error {
        MixError::Full { capacity } => MediaError::ConferenceFull { capacity },
        _ => MediaError::ConferenceIncompatible {
            hertz,
            frame_samples,
        },
    }
}
