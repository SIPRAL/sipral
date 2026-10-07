// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A local conference of any number of calls, with or without this end:
//! [`LocalConference`] says what it does and how it is driven.

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

/// A call's own audio controls (gain, mute, meter), kept by its application whether or not it is in
/// a conference; [`LocalConference::filter`] puts them in the member's path.
///
/// Both methods run on the conference's tick thread, once per member frame at its own rate. They
/// are real-time: take no lock that thread could wait on.
pub trait MemberFilter: Send {
    /// A frame the member said, at `hertz`, before mixing. What remains is what everyone else hears
    /// of that call.
    fn said(&mut self, frame: &mut [i16], hertz: u32);
    /// A frame of the mix owed to the member, at `hertz`, before encoding. What remains is what its
    /// far end hears.
    fn heard(&mut self, frame: &mut [i16], hertz: u32);
}

/// A call in the conference.
struct Seat {
    call: CallHandle,
    share: SessionShare,
    id: ParticipantId,
    /// The session's rate and frame when it was last looked at.
    rate: u32,
    frame: usize,
    /// Samples at the call's rate owed to the mixer and not read yet: each tick adds one tick's
    /// worth, each frame read removes a frame.
    due: usize,
    /// One frame, reused.
    buffer: Vec<i16>,
    /// The call's own controls, when its application put them in its path.
    filter: Option<Box<dyn MemberFilter>>,
}

/// A local conference of any number of calls, with or without this end.
///
/// [`MediaEngine::join`](crate::MediaEngine::join) pairs two calls with the same rate and frame.
/// This is the general case: the `sipral_media::nway` mixer behind calls that each keep their
/// codec, rate and frame, so G.711, G.722 and Opus calls can share a conference. Each member hears
/// everyone but itself.
///
/// # Members
///
/// Calls are added with [`LocalConference::add`] and removed with [`LocalConference::remove`], each
/// through its [`SessionShare`]; the conference holds no engine lock, so it runs on the audio
/// thread. When [`LocalConferenceConfig::local`] names a rate, this end is a member too: the
/// microphone frame passed to [`LocalConference::tick`] is what it says, and
/// [`LocalConference::speaker`] is what it hears.
///
/// A call in a conference must be driven only by it: the tick calls its
/// [`MediaSession::playback`](crate::MediaSession::playback) and
/// [`MediaSession::capture`](crate::MediaSession::capture), and another caller would steal every
/// other frame. The same applies to a call paired with
/// [`MediaEngine::join`](crate::MediaEngine::join). `sipral-ffi` refuses both; Rust applications
/// must not do it.
///
/// # The tick
///
/// [`LocalConference::tick`] is 20 ms: each member's decoded audio is read, mixed once, and each
/// member's share encoded and queued for [`LocalConference::poll_transmit`]. Each call keeps its
/// packetisation: a 10 ms call is read twice per tick, 40 or 60 ms calls every second or third
/// tick, 30 ms every tick and a half. Frames longer than three ticks are refused.
///
/// # Hold and ending calls
///
/// Hold needs nothing special: a held member is sent nothing (its session refuses the frame), and a
/// member holding this end sends nothing and mixes as silence. A member whose call ends leaves on
/// the next tick, reported like any departure.
///
/// # Reported changes
///
/// [`LocalConference::poll_change`] returns, in order, joins, departures with reason, changes in
/// [`LocalConference::talkers`] (loudest first, with `sipral_media::nway::talker` hysteresis), and
/// recordings that stopped by themselves.
///
/// # Recording
///
/// [`LocalConference::start_recording`] writes the whole mix, at each member's level, as one
/// channel, using the call recorder and any of its formats.
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
    /// The rate the mix is recorded at before conversion to the file rate: this end's, or 16 kHz.
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
    /// An empty conference, including this end if `config.local` says so. `seed` seeds the Ogg
    /// recording serial numbers;
    /// [`MediaEngine::local_conference`](crate::MediaEngine::local_conference) draws it from the
    /// engine.
    ///
    /// # Errors
    ///
    /// [`MediaError::ConferenceIncompatible`] for a local rate other than 8, 16, 32 or 48 kHz;
    /// [`MediaError::ConferenceFull`] for `max_members` of zero or above
    /// [`MAX_CONFERENCE_MEMBERS`].
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

    /// Samples per tick of this end's audio, the size of [`Self::tick`]'s microphone frame and
    /// [`Self::speaker`]'s output: 20 ms at the local rate, or at 16 kHz without this end.
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

    /// Add a call; it takes part from the next tick.
    ///
    /// # Errors
    ///
    /// [`MediaError::InConference`] if already a member, [`MediaError::ConferenceFull`],
    /// [`MediaError::NoSuchCall`] if its media has ended, [`MediaError::ConferenceIncompatible`]
    /// for a rate other than 8, 16, 32 or 48 kHz or frames longer than three ticks.
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
            filter: None,
        });
        self.note(ConferenceChange::Joined(Member::Call(call)));
        Ok(())
    }

    /// Put a call's own controls in its path from the next tick until it leaves: frames it says go
    /// through [`MemberFilter::said`] before mixing, frames it is owed through
    /// [`MemberFilter::heard`] before encoding, on top of the conference's own controls. Replaces
    /// and drops any previous filter.
    ///
    /// # Errors
    ///
    /// [`MediaError::NotInConference`] for a non-member.
    pub fn filter(
        &mut self,
        call: CallHandle,
        filter: Box<dyn MemberFilter>,
    ) -> Result<(), MediaError> {
        let seat = self
            .seats
            .iter_mut()
            .find(|seat| seat.call == call)
            .ok_or(MediaError::NotInConference)?;
        seat.filter = Some(filter);
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
        // a 30 ms frame neither divides a tick nor is whole ticks: read as it comes, queued as
        // whole ticks
        let held = if tick.is_multiple_of(frame) {
            frame
        } else {
            frame.div_ceil(tick) * tick
        };
        self.mixer
            .join(ParticipantConfig::new(rate).with_frame(held))
            .map_err(|error| refused(error, hertz, frame))
    }

    /// Remove a call from the next tick; its session is left as the conference last drove it.
    ///
    /// # Errors
    ///
    /// [`MediaError::NotInConference`] for a non-member.
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
    pub fn muted(
        &self,
        member: Member,
        direction: ConferenceDirection,
    ) -> Result<bool, MediaError> {
        let controls = self
            .mixer
            .controls(self.id_of(member)?)
            .map_err(|_| MediaError::NotInConference)?;
        Ok(match direction {
            ConferenceDirection::Input => controls.mute_in,
            ConferenceDirection::Output => controls.mute_out,
        })
    }

    /// Set the level of one direction of a member from the next tick: what it says to others, or
    /// what it hears.
    ///
    /// # Errors
    ///
    /// [`MediaError::NotInConference`] for a non-member.
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

    /// Whether a member talked in the last tick, muted or not, so a client can warn someone talking
    /// into a mute.
    ///
    /// # Errors
    ///
    /// [`MediaError::NotInConference`] for a non-member.
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

    /// Run 20 ms of conference.
    ///
    /// `mic` is this end's frame of [`Self::local_frame`] samples at the local rate, ignored when
    /// this end is not a member. Every member is read, mixed and encoded; packets wait for
    /// [`Self::poll_transmit`] and this end's share for [`Self::speaker`].
    ///
    /// # Errors
    ///
    /// [`MediaError::LocalFrame`] for a microphone frame of the wrong length when this end is a
    /// member; nothing is mixed then.
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

    /// Write what this end hears into `out` and return the sample count: one tick at the local rate
    /// after each [`Self::tick`]. Extra room is filled with silence, as is everything when this end
    /// is not a member.
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
    ///
    /// [`MediaError::AlreadyRecording`], [`MediaError::ConferenceStereo`] for a stereo layout (the
    /// mix is one channel), and whatever
    /// [`MediaSession::start_recording_with`](crate::MediaSession::start_recording_with) refuses
    /// about the options or sink.
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
                filter,
            } = seat;
            *due += Rate::from_hz(*rate).map_or(0, Rate::tick_samples);
            let read = share.with(|session| {
                let format = (session.sample_rate(), session.frame_samples());
                if format != (*rate, *frame) {
                    return Some(format);
                }
                while *due >= *frame {
                    session.playback(buffer);
                    if let Some(filter) = filter.as_mut() {
                        filter.said(buffer, *rate);
                    }
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

    /// A member's codec changed: reseat it at the new rate and frame with the same controls, or
    /// remove it if that is not possible.
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
                rate,
                id,
                call,
                filter,
                ..
            } = seat;
            let mixer = &mut self.mixer;
            let packets = &mut self.packets;
            let dropped = &mut self.packets_dropped;
            let sent = share.with(|session| {
                while mixer.available(*id).unwrap_or(0) >= *frame {
                    let _ = mixer.pull(*id, buffer);
                    if let Some(filter) = filter.as_mut() {
                        filter.heard(buffer, *rate);
                    }
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
