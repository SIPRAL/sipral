// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A local conference across the boundary: any number of this stack's
//! calls, each on its own codec and rate, mixed so that every member hears
//! everybody but itself — this end too, when it takes part (ABI 0.32).
//!
//! `sipral_call_join` pairs two calls that agree on a rate. This is the
//! general case, and the one a softphone's "merge calls" button wants.
//!
//! **Who drives it depends on the stack's mode.** In device mode the audio
//! engine does: the conference is carried like one more call, the
//! microphone is this end's voice in it and the loudspeaker plays this
//! end's share, and every packet the members owe their far ends reaches
//! `audio_transmit_callback` with the member's own call handle. In
//! application mode the application does, once every twenty milliseconds:
//! [`sipral_local_conference_tick`] takes this end's microphone frame and
//! gives back its loudspeaker frame, and
//! [`sipral_local_conference_poll_transmit`] hands out the packets, each
//! with the call whose socket sends it.
//!
//! **A member is driven by the conference and by nothing else.** Its
//! `sipral_media_playback` and `sipral_media_capture` belong to the
//! conference while it is in it; in device mode the audio engine lets go of
//! it on the way in and takes it up again on the way out. A call joined with
//! `sipral_call_join`, or already in another conference, is refused with
//! `SIPRAL_STATUS_CONFERENCE_REFUSED`, as is any call when the conference is
//! full and a call whose codec it cannot mix.
//!
//! **This end is a member too.** Where a member is named — a mute, a gain,
//! the talkers, an event — this end is named by the conference's own
//! handle, and every call by its call handle.
//!
//! What changes — who joined, who left and why, who is talking, a recording
//! that stopped by itself — arrives as
//! `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` from the stack's poll.

use std::ffi::c_char;
use std::fs::File;
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use sipral::{
    CallHandle, ConferenceChange, ConferenceDirection, ConferencePacket, Departure, Gain,
    LocalConference, LocalConferenceConfig, MediaError, Member,
};
use sipral_audio::{CallAudio, CallGone, CallId, Outgoing};

use crate::abi::{codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::{HandleTable, Kind, SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::{SipralMediaPacket, SipralToggle, media_failed, prepare, put};
use crate::record::{SipralRecordingOptions, options_of};
use crate::stack::{StackState, handle_failed, instant_at, with_stack};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, declared_size, read_versioned, write_versioned};

codes! {
    /// What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` says happened.
    /// Names for `sipral_local_conference_event_t::change`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralLocalConferenceChange: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// `member` joined: a call added, or this end when the conference was
        /// made with it.
        Joined = 1,
        /// `member` left, for the reason `departure` gives.
        Left = 2,
        /// Who is talking changed: `talkers` and `loudest` say who now, and
        /// `sipral_local_conference_talker_at` lists them, loudest first.
        Talkers = 3,
        /// The conference's recording stopped by itself: the file would not
        /// take what was written. It holds the audio up to its last
        /// checkpoint.
        RecordingStopped = 4,
    }
}

codes! {
    /// Why a member left. Names for
    /// `sipral_local_conference_event_t::departure`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDeparture: u32 {
        /// Nobody left.
        None = 0,
        /// `sipral_local_conference_remove` took it out.
        Removed = 1,
        /// Its call's media ended.
        Ended = 2,
        /// Its call moved to a codec whose rate or frame the conference
        /// cannot mix.
        Incompatible = 3,
    }
}

record! {
    /// How `sipral_local_conference_create` makes a conference. Zero in
    /// every member but `size` is a conference of sixteen with this end in
    /// it at 16 kHz.
    ///
    /// Set `size` to `sizeof(sipral_local_conference_config_t)` before the
    /// call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralLocalConferenceConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// The most members it holds at once, this end included, or zero
        /// for sixteen. At most 1024.
        pub max_members: u32,
        /// A `SipralToggle`: whether this end takes part. On unless it is
        /// `SIPRAL_TOGGLE_OFF`; a conference without this end only bridges
        /// its calls.
        pub local: u32,
        /// The rate of this end's frames in application mode, in hertz —
        /// 8000, 16000, 32000 or 48000 — or zero for 16000. A tick's frame is
        /// twenty milliseconds of it. In device mode the audio engine
        /// converts the devices to it.
        pub sample_rate: u32,
    }
}

// Safety: the trait's contract. Integers only, and all-zero is a valid value
// of each: it is the ordinary conference.
unsafe impl Versioned for SipralLocalConferenceConfig {
    const NAME: &'static str = "sipral_local_conference_config";
    const MIN_SIZE: usize = crate::versioned::min_size::LOCAL_CONFERENCE_CONFIG;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// A conference as it stands: `sipral_local_conference_info`.
    ///
    /// Set `size` to `sizeof(sipral_local_conference_info_t)` before the
    /// call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralLocalConferenceInfo {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Members, this end included.
        pub members: u32,
        /// The most it holds.
        pub capacity: u32,
        /// Members talking in the last tick.
        pub talkers: u32,
        /// 1 when this end takes part.
        pub local: u32,
        /// The rate of this end's frames, in hertz.
        pub sample_rate: u32,
        /// Samples in one of this end's frames: twenty milliseconds.
        pub frame_samples: u32,
        /// 1 while the conference is being recorded.
        pub recording: u32,
        /// How much has been recorded, while it is.
        pub recorded_ms: u64,
        /// Packets dropped because nobody polled for them in time.
        pub packets_dropped: u64,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralLocalConferenceInfo {
    const NAME: &'static str = "sipral_local_conference_info";
    const MIN_SIZE: usize = crate::versioned::min_size::LOCAL_CONFERENCE_INFO;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One member of a conference: `sipral_local_conference_member_at`.
    ///
    /// Set `size` to `sizeof(sipral_local_conference_member_t)` before the
    /// call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralLocalConferenceMember {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The call, or the conference's own handle for this end.
        pub member: SipralHandle,
        /// 1 when it was talking in the last tick, muted or not.
        pub talking: u32,
        /// 1 when nobody hears it.
        pub muted_input: u32,
        /// 1 when it hears nothing.
        pub muted_output: u32,
        /// The level of what it says, in the steps `sipral_audio_set_gain`
        /// takes: 256 is unity.
        pub gain_input: u32,
        /// The level of what it hears, in the same steps.
        pub gain_output: u32,
    }
}

// Safety: integers and a handle, and zero is a valid value of each.
unsafe impl Versioned for SipralLocalConferenceMember {
    const NAME: &'static str = "sipral_local_conference_member";
    const MIN_SIZE: usize = crate::versioned::min_size::LOCAL_CONFERENCE_MEMBER;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` carries.
    #[derive(Clone, Copy)]
    pub struct SipralLocalConferenceEvent {
        /// The conference.
        pub conference: SipralHandle,
        /// A [`SipralLocalConferenceChange`].
        pub change: u32,
        /// A [`SipralDeparture`], for `SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT`.
        pub departure: u32,
        /// Who joined or left: a call, or the conference's own handle for
        /// this end. `SIPRAL_HANDLE_NONE` for the other changes.
        pub member: SipralHandle,
        /// Members now, this end included.
        pub members: u32,
        /// Members talking now.
        pub talkers: u32,
        /// The loudest of them, or `SIPRAL_HANDLE_NONE`.
        pub loudest: SipralHandle,
    }
}

/// The steps a gain crosses in: 256 is unity, as for the audio engine.
const GAIN_UNITY: u32 = 256;

/// The most a step count means: four times.
const GAIN_MOST: u32 = 4 * GAIN_UNITY;

/// One conference, and the names its members go by across the boundary.
pub(crate) struct Conference {
    pub(crate) inner: LocalConference,
    /// This conference's own handle, which is this end's name as a member.
    handle: SipralHandle,
    /// Every call ever added, with its handle, so that a packet or a
    /// departure is named after the call even once the stack has forgotten
    /// it.
    names: Vec<(CallHandle, SipralHandle)>,
}

impl Conference {
    fn name_of(&self, member: Member) -> SipralHandle {
        match member {
            Member::Local => self.handle,
            Member::Call(call) => self
                .names
                .iter()
                .find(|(named, _)| *named == call)
                .map_or(SIPRAL_HANDLE_NONE, |(_, handle)| *handle),
        }
    }

    fn member_named(&self, handle: SipralHandle) -> Result<Member, Fail> {
        if handle == self.handle {
            return Ok(Member::Local);
        }
        self.names
            .iter()
            .find(|(call, named)| *named == handle && self.inner.contains(*call))
            .map(|(call, _)| Member::Call(*call))
            .ok_or_else(|| {
                fail(
                    SipralStatus::WrongState,
                    "that member is not in this conference",
                )
            })
    }
}

/// A conference, shared between its handle, its stack and the audio engine.
pub(crate) type Shared = Arc<Mutex<Conference>>;

/// Lock one; poisoning means a panic was caught while it was held, and a
/// conference is whole between statements.
pub(crate) fn lock(shared: &Shared) -> MutexGuard<'_, Conference> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a conference handle names.
struct Entry {
    stack: SipralHandle,
    shared: Shared,
    /// What `now_ms` of zero means on the stack that made it.
    origin: Instant,
    /// Whether the audio engine drives it.
    device: bool,
}

static CONFERENCES: HandleTable<Entry> = HandleTable::new(Kind::Conference);

/// Do something with a conference, refused to a thread that is inside one
/// of its ticks — a processor on one of its calls — which would wait for
/// itself.
fn with_conference<R>(
    conference: SipralHandle,
    act: impl FnOnce(&mut Conference, &Entry) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry = CONFERENCES.get(conference).map_err(handle_failed)?;
    if crate::media::inside_media_of(conference) {
        return Err(fail(
            SipralStatus::Busy,
            "this thread is inside a tick of this conference, further down its own call stack",
        ));
    }
    let mut held = lock(&entry.shared);
    act(&mut held, &entry)
}

/// The conference's own view of a refusal, as a status.
fn conference_failed(error: &MediaError) -> Fail {
    match error {
        MediaError::ConferenceFull { .. }
        | MediaError::ConferenceIncompatible { .. }
        | MediaError::InConference => fail(SipralStatus::ConferenceRefused, error.to_string()),
        MediaError::NotInConference => fail(SipralStatus::WrongState, error.to_string()),
        MediaError::LocalFrame { .. } | MediaError::ConferenceStereo => {
            fail(SipralStatus::InvalidArgument, error.to_string())
        }
        other => media_failed(other),
    }
}

/// Whether `call` is a member of any conference of this stack.
pub(crate) fn in_a_conference(state: &StackState, call: CallHandle) -> bool {
    state
        .conferences
        .iter()
        .any(|(_, shared)| lock(shared).inner.contains(call))
}

/// The audio engine's view of a conference: one more call, whose frame is
/// this end's twenty milliseconds and whose packets are its members'.
struct Carried {
    shared: Shared,
    /// The conference's handle, which the pump's thread is marked with for
    /// the length of a tick, as an application's is.
    handle: SipralHandle,
    rate: u32,
    frame: usize,
}

impl CallAudio for Carried {
    fn sample_rate(&self) -> Result<u32, CallGone> {
        Ok(self.rate)
    }

    fn frame_samples(&self) -> Result<usize, CallGone> {
        Ok(self.frame)
    }

    fn capture(&mut self, frame: &[i16], now: Instant) -> Result<Option<Outgoing>, CallGone> {
        // the pump hands over a frame of this end's own length; the packets
        // wait in the conference for `capture_each`
        let _inside = crate::media::Inside::enter(self.handle);
        let _ = lock(&self.shared).inner.tick(frame, now);
        Ok(None)
    }

    fn capture_each(
        &mut self,
        _own: CallId,
        frame: &[i16],
        now: Instant,
        send: &mut dyn FnMut(CallId, Outgoing),
    ) -> Result<(), CallGone> {
        let _inside = crate::media::Inside::enter(self.handle);
        let mut held = lock(&self.shared);
        let _ = held.inner.tick(frame, now);
        while let Some(packet) = held.inner.poll_transmit() {
            let call = held.name_of(Member::Call(packet.call));
            send(call, outgoing(packet));
        }
        Ok(())
    }

    fn playback(&mut self, out: &mut [i16]) -> Result<(), CallGone> {
        lock(&self.shared).inner.speaker(out);
        Ok(())
    }
}

fn outgoing(packet: ConferencePacket) -> Outgoing {
    let transport = transport_of(&packet);
    Outgoing {
        destination: packet.destination,
        payload: packet.payload,
        transport,
    }
}

#[cfg(feature = "ice")]
const fn transport_of(packet: &ConferencePacket) -> sipral_audio::Transport {
    match packet.transport {
        sipral::TurnTransport::Udp => sipral_audio::Transport::Udp,
        sipral::TurnTransport::Tcp => sipral_audio::Transport::Tcp,
        sipral::TurnTransport::Tls => sipral_audio::Transport::Tls,
    }
}

#[cfg(not(feature = "ice"))]
const fn transport_of(_: &ConferencePacket) -> sipral_audio::Transport {
    sipral_audio::Transport::Udp
}

#[cfg(feature = "ice")]
const fn protocol_of(packet: &ConferencePacket) -> u32 {
    crate::nat::protocol_of(packet.transport)
}

#[cfg(not(feature = "ice"))]
const fn protocol_of(_: &ConferencePacket) -> u32 {
    crate::stack::SipralTransport::Udp as u32
}

/// A direction as C names it: `SipralAudioDirection`'s input and output.
fn direction_of(direction: u32) -> Result<ConferenceDirection, Fail> {
    match direction {
        1 => Ok(ConferenceDirection::Input),
        2 => Ok(ConferenceDirection::Output),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("direction is {other}; it is 1 for input or 2 for output"),
        )),
    }
}

fn steps_of(gain: Gain) -> u32 {
    let q15 = u32::try_from(gain.to_q15()).unwrap_or(0);
    (q15 * GAIN_UNITY + (1 << 14)) >> 15
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

entry! {
    /// Make a local conference on this stack, empty but for this end when
    /// `config` says it takes part, and write its handle to
    /// `out_conference`.
    ///
    /// In device mode the audio engine starts carrying it at once, opening
    /// the devices under automatic activation as a call's media does.
    ///
    /// `SIPRAL_STATUS_CONFERENCE_REFUSED` for a rate that is not 8, 16, 32
    /// or 48 kHz and for more than 1024 members.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_local_conference_config_t` whose
    /// `size` member says how long it is, and `out_conference` at one
    /// `sipral_handle_t`.
    fn sipral_local_conference_create(
        stack: SipralHandle,
        config: *const SipralLocalConferenceConfig,
        out_conference: *mut SipralHandle,
    ) {
        let config = unsafe { read_versioned(config) }?;
        if out_conference.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_conference is null"));
        }
        let wanted = LocalConferenceConfig {
            max_members: if config.max_members == 0 {
                LocalConferenceConfig::default().max_members
            } else {
                usize::try_from(config.max_members).unwrap_or(usize::MAX)
            },
            local: (config.local != SipralToggle::Off as u32).then_some(
                if config.sample_rate == 0 { 16_000 } else { config.sample_rate },
            ),
        };
        let handle = with_stack(stack, |state| {
            let inner = state
                .engine
                .local_conference(wanted)
                .map_err(|error| conference_failed(&error))?;
            let (rate, frame) = (
                inner.local_rate().unwrap_or(16_000),
                inner.local_frame(),
            );
            let shared = Arc::new(Mutex::new(Conference {
                inner,
                handle: SIPRAL_HANDLE_NONE,
                names: Vec::new(),
            }));
            let device = state.audio.is_some();
            let handle = CONFERENCES
                .insert(
                    state.tag.tag(),
                    Entry {
                        stack,
                        shared: Arc::clone(&shared),
                        origin: state.origin(),
                        device,
                    },
                )
                .map_err(|status| fail(status, "no room for another conference"))?;
            lock(&shared).handle = handle;
            state.conferences.push((handle, Arc::clone(&shared)));
            if let Some(audio) = state.audio.clone() {
                let attached = audio
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .attach(
                        handle,
                        Box::new(Carried {
                            shared,
                            handle,
                            rate,
                            frame,
                        }),
                    );
                if attached.is_err() {
                    state.conferences.retain(|(held, _)| *held != handle);
                    let _ = CONFERENCES.remove(handle);
                    return Err(fail(
                        SipralStatus::DeviceUnusable,
                        "the audio engine could not open its devices for the conference",
                    ));
                }
            }
            Ok(handle)
        })?;
        unsafe { out_conference.write(handle) };
        Ok(())
    }
}

entry! {
    /// End a conference. Every call still in it goes back to carrying its
    /// own audio — in device mode, the audio engine takes each up again —
    /// a recording running is finished, and the handle is stale.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_local_conference_destroy(conference: SipralHandle) {
        let entry = CONFERENCES.get(conference).map_err(handle_failed)?;
        if crate::media::inside_media_of(conference) {
            return Err(fail(
                SipralStatus::Busy,
                "this thread is inside a tick of this conference",
            ));
        }
        let back = with_stack(entry.stack, |state| {
            state.conferences.retain(|(held, _)| *held != conference);
            if let Some(audio) = state.audio.clone() {
                let mut engine = audio.lock().unwrap_or_else(PoisonError::into_inner);
                engine.detach(conference);
                let held = lock(&entry.shared);
                for (call, handle) in &held.names {
                    if held.inner.contains(*call)
                        && let Some(share) = state.engine.share(*call)
                    {
                        let _ = engine.attach(*handle, Box::new(share));
                    }
                }
            }
            Ok(())
        });
        // a stack destroyed first has nothing left to hand the calls back
        // to, and the conference still goes
        if let Err(refused) = back
            && refused.status != SipralStatus::InvalidHandle
            && refused.status != SipralStatus::StaleHandle
        {
            return Err(refused);
        }
        let _ = CONFERENCES.remove(conference);
        let mut held = lock(&entry.shared);
        if held.inner.is_recording() {
            let _ = held.inner.stop_recording();
        }
        Ok(())
    }
}

entry! {
    /// Add a call. It takes part from the next tick, at its own codec's rate,
    /// and its far end hears everybody in the conference but itself.
    ///
    /// The call needs media running, as for `sipral_call_media`.
    /// `SIPRAL_STATUS_CONFERENCE_REFUSED` when the conference is full, for a
    /// call already in this one or another or joined with
    /// `sipral_call_join`, and for a codec the conference cannot mix — a
    /// rate other than 8, 16, 32 or 48 kHz, or frames past 60 ms.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_local_conference_add(conference: SipralHandle, call: SipralHandle) {
        let entry = CONFERENCES.get(conference).map_err(handle_failed)?;
        with_stack(entry.stack, |state| {
            let named = state.calls.get(call).map_err(handle_failed)?;
            if state.engine.joined_with(named).is_some() || in_a_conference(state, named) {
                return Err(conference_failed(&MediaError::InConference));
            }
            let share = state.engine.share(named).ok_or_else(crate::media::no_media)?;
            {
                let mut held = lock(&entry.shared);
                held.inner
                    .add(named, share)
                    .map_err(|error| conference_failed(&error))?;
                if !held.names.iter().any(|(known, _)| *known == named) {
                    held.names.push((named, call));
                }
            }
            if let Some(audio) = state.audio.clone() {
                audio
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .detach(call);
            }
            Ok(())
        })
    }
}

entry! {
    /// Take a call out. From the next tick nobody in the conference hears it
    /// and it hears nobody; its media is the application's again — in device
    /// mode, the audio engine carries it as it carries any call.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call that is not in it.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_local_conference_remove(conference: SipralHandle, call: SipralHandle) {
        let entry = CONFERENCES.get(conference).map_err(handle_failed)?;
        with_stack(entry.stack, |state| {
            let named = state.calls.get(call).map_err(handle_failed)?;
            lock(&entry.shared)
                .inner
                .remove(named)
                .map_err(|error| conference_failed(&error))?;
            if let (Some(audio), Some(share)) = (state.audio.clone(), state.engine.share(named)) {
                let _ = audio
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .attach(call, Box::new(share));
            }
            Ok(())
        })
    }
}

entry! {
    /// Mute or unmute one way of a member, from the next tick: its input,
    /// which everybody else stops hearing, or its output, which it stops
    /// hearing. `direction` is `SIPRAL_AUDIO_DIRECTION_INPUT` or
    /// `SIPRAL_AUDIO_DIRECTION_OUTPUT`; `member` is a call in the conference,
    /// or the conference's own handle for this end.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a member that is not in it.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_local_conference_set_muted(
        conference: SipralHandle,
        member: SipralHandle,
        direction: u32,
        muted: u32,
    ) {
        let direction = direction_of(direction)?;
        with_conference(conference, |held, _| {
            let member = held.member_named(member)?;
            held.inner
                .set_muted(member, direction, muted != 0)
                .map_err(|error| conference_failed(&error))
        })
    }
}

entry! {
    /// Set the level of one way of a member, from the next tick, in the
    /// steps `sipral_audio_set_gain` takes: 256 is unity and 1024, four
    /// times, the most. Its input's level is what everybody else hears of
    /// it; its output's is what it hears.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_local_conference_set_gain(
        conference: SipralHandle,
        member: SipralHandle,
        direction: u32,
        gain: u32,
    ) {
        let direction = direction_of(direction)?;
        let steps = i32::try_from(gain.min(GAIN_MOST)).unwrap_or(0);
        let unity = i32::try_from(GAIN_UNITY).unwrap_or(1);
        with_conference(conference, |held, _| {
            let member = held.member_named(member)?;
            held.inner
                .set_gain(member, direction, Gain::ratio(steps, unity))
                .map_err(|error| conference_failed(&error))
        })
    }
}

entry! {
    /// How the conference stands.
    ///
    /// # Safety
    ///
    /// `out_info` must point at a `sipral_local_conference_info_t` whose
    /// `size` member says how long it is.
    fn sipral_local_conference_info(
        conference: SipralHandle,
        out_info: *mut SipralLocalConferenceInfo,
    ) {
        unsafe { declared_size(out_info.cast_const()) }?;
        let info = with_conference(conference, |held, _| {
            let inner = &held.inner;
            Ok(SipralLocalConferenceInfo {
                size: size_of::<SipralLocalConferenceInfo>(),
                members: count(inner.len()),
                capacity: count(inner.capacity()),
                talkers: count(inner.talkers().len()),
                local: u32::from(inner.local_rate().is_some()),
                sample_rate: inner.local_rate().unwrap_or(16_000),
                frame_samples: count(inner.local_frame()),
                recording: u32::from(inner.is_recording()),
                recorded_ms: inner
                    .recorded()
                    .map_or(0, |span| u64::try_from(span.as_millis()).unwrap_or(u64::MAX)),
                packets_dropped: inner.packets_dropped(),
            })
        })?;
        unsafe { write_versioned(out_info, info) }
    }
}

entry! {
    /// One member, by index: this end first when it takes part, then the
    /// calls in the order they joined. The index is stable until the next
    /// member joins or leaves.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
    ///
    /// # Safety
    ///
    /// `out_member` must point at a `sipral_local_conference_member_t` whose
    /// `size` member says how long it is.
    fn sipral_local_conference_member_at(
        conference: SipralHandle,
        index: usize,
        out_member: *mut SipralLocalConferenceMember,
    ) {
        unsafe { declared_size(out_member.cast_const()) }?;
        let out = with_conference(conference, |held, _| {
            let member = held.inner.members().nth(index).ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("index is {index} and there are {} members", held.inner.len()),
                )
            })?;
            let inner = &held.inner;
            let read = |error: MediaError| conference_failed(&error);
            Ok(SipralLocalConferenceMember {
                size: size_of::<SipralLocalConferenceMember>(),
                member: held.name_of(member),
                talking: u32::from(inner.is_talking(member).map_err(read)?),
                muted_input: u32::from(
                    inner.muted(member, ConferenceDirection::Input).map_err(read)?,
                ),
                muted_output: u32::from(
                    inner.muted(member, ConferenceDirection::Output).map_err(read)?,
                ),
                gain_input: steps_of(inner.gain(member, ConferenceDirection::Input).map_err(read)?),
                gain_output: steps_of(
                    inner.gain(member, ConferenceDirection::Output).map_err(read)?,
                ),
            })
        })?;
        unsafe { write_versioned(out_member, out) }
    }
}

entry! {
    /// Who was talking in the last tick, by rank: index zero is the
    /// loudest. A muted member is never listed.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last talker,
    /// which `sipral_local_conference_info_t::talkers` counts.
    ///
    /// # Safety
    ///
    /// `out_member` must point at one `sipral_handle_t`.
    fn sipral_local_conference_talker_at(
        conference: SipralHandle,
        index: usize,
        out_member: *mut SipralHandle,
    ) {
        if out_member.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_member is null"));
        }
        let named = with_conference(conference, |held, _| {
            let talker = held.inner.talkers().get(index).copied().ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "index is {index} and {} members are talking",
                        held.inner.talkers().len()
                    ),
                )
            })?;
            Ok(held.name_of(talker))
        })?;
        unsafe { out_member.write(named) };
        Ok(())
    }
}

entry! {
    /// Twenty milliseconds of conference, in application mode: `mic` is this
    /// end's frame, `sipral_local_conference_info_t::frame_samples` long,
    /// and `speaker` is filled with what this end hears, the same length,
    /// written to `out_written`. A conference without this end reads no
    /// microphone — `mic` may be null — and fills `speaker` with silence.
    ///
    /// Call it once every twenty milliseconds, from the thread that carries
    /// the audio, and then drain `sipral_local_conference_poll_transmit`.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` in device mode, where the audio engine
    /// ticks it; `SIPRAL_STATUS_INVALID_ARGUMENT` for a frame of any other
    /// length, and `SIPRAL_STATUS_BUFFER_TOO_SMALL` for a speaker buffer
    /// shorter than a frame, with the length needed in `out_written`.
    ///
    /// # Safety
    ///
    /// `mic` must be readable for `mic_count` `int16_t`, `speaker` writable
    /// for `capacity` `int16_t`, and `out_written` must point at one
    /// `size_t` or be null.
    fn sipral_local_conference_tick(
        conference: SipralHandle,
        now_ms: u64,
        mic: *const i16,
        mic_count: usize,
        speaker: *mut i16,
        capacity: usize,
        out_written: *mut usize,
    ) {
        if mic.is_null() && mic_count != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "mic is null"));
        }
        if speaker.is_null() && capacity != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "speaker is null"));
        }
        let entry = CONFERENCES.get(conference).map_err(handle_failed)?;
        if entry.device {
            return Err(fail(
                SipralStatus::WrongState,
                "the audio engine ticks a conference on a stack in device mode",
            ));
        }
        let now = instant_at(entry.origin, now_ms)?;
        let _inside = crate::media::Inside::enter(entry.stack);
        with_conference(conference, |held, _| {
            let frame = held.inner.local_frame();
            if !out_written.is_null() {
                unsafe { out_written.write(frame) };
            }
            if capacity < frame {
                return Err(fail(
                    SipralStatus::BufferTooSmall,
                    format!("a frame is {frame} samples and there is room for {capacity}"),
                ));
            }
            let taken = if held.inner.local_rate().is_some() {
                unsafe { slice::from_raw_parts(mic, mic_count) }
            } else {
                &[]
            };
            let _in_tick = crate::media::Inside::enter(conference);
            held.inner
                .tick(taken, now)
                .map_err(|error| conference_failed(&error))?;
            // the capacity reaches the frame, so the buffer is not null
            let out = unsafe { slice::from_raw_parts_mut(speaker, frame) };
            held.inner.speaker(out);
            Ok(())
        })
    }
}

entry! {
    /// The oldest packet a member's call owes its far end, in application
    /// mode: `out_call` names the call, whose media socket sends it, and
    /// `out_packet` is filled as `sipral_media_capture` fills one. A `len`
    /// of zero, with `SIPRAL_HANDLE_NONE` in `out_call`, means nothing is
    /// waiting. Drain it after every tick.
    ///
    /// # Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `out_packet` at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    fn sipral_local_conference_poll_transmit(
        conference: SipralHandle,
        out_call: *mut SipralHandle,
        out_packet: *mut SipralMediaPacket,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let mut out = unsafe { read_versioned(out_packet) }?;
        prepare(&mut out)?;
        let call = with_conference(conference, |held, _| {
            let Some(packet) = held.inner.poll_transmit() else {
                return Ok(SIPRAL_HANDLE_NONE);
            };
            let call = held.name_of(Member::Call(packet.call));
            let protocol = protocol_of(&packet);
            unsafe { put(&mut out, packet.destination, &packet.payload, protocol) }?;
            Ok(call)
        })?;
        unsafe { out_call.write(call) };
        unsafe { write_versioned(out_packet, out) }
    }
}

entry! {
    /// Record the whole conference to `path`: everybody it hears, each at
    /// its own level, in one channel, written as `options` say — WAV or Ogg
    /// Opus, at the conference's rate unless another is named.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when it is already being recorded,
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a stereo layout, for options no
    /// file can be written with and for a path the file system refuses, and
    /// `SIPRAL_STATUS_RECORDING_FAILED` when the file would not take its
    /// header.
    ///
    /// # Safety
    ///
    /// `path` must be readable for `path_len` bytes, and `options` must point
    /// at a `sipral_recording_options_t` whose `size` member says how long
    /// it is.
    fn sipral_local_conference_record_start(
        conference: SipralHandle,
        path: *const c_char,
        path_len: usize,
        options: *const SipralRecordingOptions,
    ) {
        let path = unsafe { required_text(path, path_len, "path") }?;
        let options = options_of(&unsafe { read_versioned(options) }?)?;
        options.rate_for(8_000).map_err(|error| media_failed(&error))?;
        if options.layout == sipral::RecordingLayout::Stereo {
            return Err(conference_failed(&MediaError::ConferenceStereo));
        }
        with_conference(conference, |held, _| {
            if held.inner.is_recording() {
                return Err(fail(
                    SipralStatus::WrongState,
                    "this conference is already being recorded",
                ));
            }
            let file = File::create(path).map_err(|error| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("path is {path:?}, which cannot be written: {error}"),
                )
            })?;
            held.inner
                .start_recording(Box::new(file), &options)
                .map_err(|error| conference_failed(&error))
        })
    }
}

entry! {
    /// Stop recording the conference, and finish the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_local_conference_record_stop(conference: SipralHandle) {
        with_conference(conference, |held, _| {
            held.inner
                .stop_recording()
                .map_err(|error| conference_failed(&error))
        })
    }
}

/// Every change the stack's conferences have to report, as events.
pub(crate) fn drain(state: &StackState, stack: SipralHandle) -> Vec<crate::event::SipralEvent> {
    let mut raised = Vec::new();
    for (handle, shared) in &state.conferences {
        let mut held = lock(shared);
        while let Some(change) = held.inner.poll_change() {
            let (kind, departure, member) = match change {
                ConferenceChange::Joined(member) => (
                    SipralLocalConferenceChange::Joined,
                    SipralDeparture::None,
                    held.name_of(member),
                ),
                ConferenceChange::Left { member, why } => (
                    SipralLocalConferenceChange::Left,
                    match why {
                        Departure::Removed => SipralDeparture::Removed,
                        Departure::Ended => SipralDeparture::Ended,
                        Departure::Incompatible => SipralDeparture::Incompatible,
                    },
                    held.name_of(member),
                ),
                ConferenceChange::Talkers => (
                    SipralLocalConferenceChange::Talkers,
                    SipralDeparture::None,
                    SIPRAL_HANDLE_NONE,
                ),
                ConferenceChange::RecordingStopped(_) => (
                    SipralLocalConferenceChange::RecordingStopped,
                    SipralDeparture::None,
                    SIPRAL_HANDLE_NONE,
                ),
            };
            let talkers = held.inner.talkers();
            let loudest = talkers
                .first()
                .map_or(SIPRAL_HANDLE_NONE, |first| held.name_of(*first));
            raised.push(crate::event::local_conference_changed(
                stack,
                SipralLocalConferenceEvent {
                    conference: *handle,
                    change: kind as u32,
                    departure: departure as u32,
                    member,
                    members: count(held.inner.len()),
                    talkers: count(talkers.len()),
                    loudest,
                },
            ));
        }
    }
    raised
}

#[cfg(test)]
mod tests {
    use super::{
        SipralDeparture, SipralLocalConferenceChange, SipralLocalConferenceConfig,
        SipralLocalConferenceEvent, SipralLocalConferenceInfo, SipralLocalConferenceMember,
        sipral_local_conference_add, sipral_local_conference_create,
        sipral_local_conference_destroy, sipral_local_conference_info,
        sipral_local_conference_member_at, sipral_local_conference_poll_transmit,
        sipral_local_conference_record_start, sipral_local_conference_record_stop,
        sipral_local_conference_remove, sipral_local_conference_set_gain,
        sipral_local_conference_set_muted, sipral_local_conference_talker_at,
        sipral_local_conference_tick,
    };
    use crate::audio::tests::{Packets, a_desk, transmit};
    use crate::audio::{FAKE_PLATFORM, SipralAudio, SipralAudioActivation};
    use crate::call::tests::{
        ANSWER, PEER_MEDIA, SECOND_PEER_MEDIA, hangup, media_call_pair, media_line,
        second_media_call, up,
    };
    use crate::call::{sipral_call_join, sipral_call_leave};
    use crate::error::last_error_text;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::tests::{Buffers, arrive, media_of, release};
    use crate::record::SipralRecordingOptions;
    use crate::stack::tests::{Observed, poll};
    use crate::stack::with_stack;
    use crate::status::SipralStatus;
    use sipral_audio::fake::FakeControl;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Samples in one G.711 frame, which is what both calls here are on.
    const FRAME: usize = 160;

    fn config(max_members: u32, sample_rate: u32) -> SipralLocalConferenceConfig {
        SipralLocalConferenceConfig {
            size: size_of::<SipralLocalConferenceConfig>(),
            max_members,
            local: 0,
            sample_rate,
        }
    }

    fn create(stack: SipralHandle, config: &SipralLocalConferenceConfig) -> SipralHandle {
        let mut conference = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_local_conference_create(stack, config, &raw mut conference) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(conference, SIPRAL_HANDLE_NONE);
        conference
    }

    fn add(conference: SipralHandle, call: SipralHandle) -> SipralStatus {
        unsafe { sipral_local_conference_add(conference, call) }
    }

    fn info_zeroed() -> SipralLocalConferenceInfo {
        SipralLocalConferenceInfo {
            size: size_of::<SipralLocalConferenceInfo>(),
            members: u32::MAX,
            capacity: u32::MAX,
            talkers: u32::MAX,
            local: u32::MAX,
            sample_rate: u32::MAX,
            frame_samples: u32::MAX,
            recording: u32::MAX,
            recorded_ms: u64::MAX,
            packets_dropped: u64::MAX,
        }
    }

    fn info(conference: SipralHandle) -> SipralLocalConferenceInfo {
        let mut out = info_zeroed();
        let status = unsafe { sipral_local_conference_info(conference, &raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    fn member_at(conference: SipralHandle, index: usize) -> SipralLocalConferenceMember {
        let mut out = SipralLocalConferenceMember {
            size: size_of::<SipralLocalConferenceMember>(),
            member: u64::MAX,
            talking: u32::MAX,
            muted_input: u32::MAX,
            muted_output: u32::MAX,
            gain_input: u32::MAX,
            gain_output: u32::MAX,
        };
        let status = unsafe { sipral_local_conference_member_at(conference, index, &raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    /// One mu-law RTP packet of a 500 Hz square wave: eight samples at the
    /// top of the scale and eight at the bottom.
    fn loud(sequence: u16) -> Vec<u8> {
        let mut out = vec![0x80, 0x00];
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        out.extend_from_slice(&0x5EED_0001_u32.to_be_bytes());
        out.extend((0..FRAME).map(|n| if (n / 8) % 2 == 0 { 0x80 } else { 0x00 }));
        out
    }

    /// The share of a mu-law payload that is loud: its segment in the top
    /// three of eight.
    fn loud_share(payload: &[u8]) -> f64 {
        let audio = payload.get(12..).unwrap_or_default();
        let loud = audio
            .iter()
            .filter(|byte| ((!**byte) & 0x70) >> 4 >= 5)
            .count();
        #[allow(clippy::cast_precision_loss)]
        let share = loud as f64 / audio.len().max(1) as f64;
        share
    }

    /// What one tick gave: this end's frame, and the packets by call.
    struct Ticked {
        speaker: Vec<i16>,
        packets: Vec<(SipralHandle, Vec<u8>)>,
    }

    fn tick(conference: SipralHandle, now_ms: u64, mic: &[i16], speaker: usize) -> Ticked {
        let mut heard = vec![0_i16; speaker];
        let mut written = 0_usize;
        let status = unsafe {
            sipral_local_conference_tick(
                conference,
                now_ms,
                mic.as_ptr(),
                mic.len(),
                heard.as_mut_ptr(),
                heard.len(),
                &raw mut written,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(written, speaker);
        let mut packets = Vec::new();
        loop {
            let mut buffers = Buffers::new();
            let mut packet = buffers.packet();
            let mut call = u64::MAX;
            let status = unsafe {
                sipral_local_conference_poll_transmit(conference, &raw mut call, &raw mut packet)
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len == 0 {
                assert_eq!(call, SIPRAL_HANDLE_NONE);
                break;
            }
            let (payload, _) = buffers.taken(&packet);
            packets.push((call, payload));
        }
        Ticked {
            speaker: heard,
            packets,
        }
    }

    fn loudness(samples: &[i16]) -> i64 {
        let total: i64 = samples.iter().map(|s| i64::from(s.saturating_abs())).sum();
        total / i64::try_from(samples.len().max(1)).unwrap_or(1)
    }

    /// What the second half of a run gave: this end's loudness, how loud
    /// the packets to call a's and call b's far ends were, and how many
    /// went to each.
    struct Heard {
        speaker: i64,
        to_a: f64,
        to_b: f64,
        packets_a: usize,
        packets_b: usize,
    }

    /// Ticks with call a's far end sending its square wave. Every packet
    /// has to name call a or call b.
    fn run(
        conference: SipralHandle,
        (call_a, media_a, call_b): (SipralHandle, SipralHandle, SipralHandle),
        from_ms: u64,
        ticks: u16,
        first_sequence: u16,
    ) -> Heard {
        let frame = usize::try_from(info(conference).frame_samples).unwrap_or(0);
        let silent = vec![0_i16; frame];
        let (mut speaker, mut to_a, mut to_b) = (0, 0.0, 0.0);
        let (mut counted, mut packets_a, mut packets_b) = (0_u32, 0, 0);
        for n in 0..ticks {
            let now = from_ms + u64::from(n) * 20;
            let mut datagram = loud(first_sequence + n);
            arrive(media_a, &mut datagram, PEER_MEDIA, now);
            let ticked = tick(conference, now, &silent, frame);
            if n >= ticks / 2 {
                counted += 1;
                speaker += loudness(&ticked.speaker);
                for (call, payload) in &ticked.packets {
                    let share = loud_share(payload);
                    if *call == call_a {
                        to_a += share;
                        packets_a += 1;
                    } else {
                        assert_eq!(*call, call_b, "a packet named neither call");
                        to_b += share;
                        packets_b += 1;
                    }
                }
            }
        }
        let counted = counted.max(1);
        Heard {
            speaker: speaker / i64::from(counted),
            to_a: to_a / f64::from(counted),
            to_b: to_b / f64::from(counted),
            packets_a,
            packets_b,
        }
    }

    fn events_of(
        observed: &Observed,
        change: SipralLocalConferenceChange,
    ) -> Vec<SipralLocalConferenceEvent> {
        observed
            .local_conferences
            .iter()
            .filter(|event| event.change == change as u32)
            .copied()
            .collect()
    }

    /// Two calls on one stack, both in a conference of three at 8 kHz with
    /// this end: the stack, the two calls, call a's media handle and the
    /// conference.
    fn two_calls_in_one(
        observed: &mut Observed,
    ) -> (SipralHandle, SipralHandle, SipralHandle, SipralHandle, SipralHandle) {
        let (stack, call_a, call_b) = media_call_pair(observed);
        let media_a = media_of(stack, call_a);
        let conference = create(stack, &config(3, 8_000));
        assert_eq!(add(conference, call_a), SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(add(conference, call_b), SipralStatus::Ok, "{}", last_error_text());
        (stack, call_a, call_b, media_a, conference)
    }

    /// Application mode: two calls and this end, each hearing the others and
    /// not itself, and who is talking reported.
    #[test]
    fn two_calls_and_this_end_hear_each_other_over_the_abi() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b, media_a, conference) = two_calls_in_one(&mut observed);
        assert_eq!(
            add(conference, call_a),
            SipralStatus::ConferenceRefused,
            "a call added twice"
        );
        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_b) },
            SipralStatus::WrongState,
            "a member joined into a pair as well"
        );
        let standing = info(conference);
        assert_eq!((standing.members, standing.capacity), (3, 3));
        assert_eq!(
            (standing.local, standing.sample_rate, standing.frame_samples),
            (1, 8_000, 160)
        );
        assert_eq!(member_at(conference, 0).member, conference, "this end first");
        assert_eq!(member_at(conference, 1).member, call_a);
        assert_eq!(member_at(conference, 2).member, call_b);
        assert_eq!(member_at(conference, 1).gain_input, 256);

        let heard = run(conference, (call_a, media_a, call_b), 3_000, 40, 1);
        assert!(heard.speaker > 2_000, "this end did not hear call a: {}", heard.speaker);
        assert!(heard.to_b > 0.5, "call b's far end did not hear call a: {}", heard.to_b);
        assert!(heard.to_a < 0.05, "call a's far end heard itself: {}", heard.to_a);
        assert!(heard.packets_b >= 19, "call b was sent {} packets in 20 ticks", heard.packets_b);
        assert!(heard.packets_a >= 19, "call a was sent {} packets in 20 ticks", heard.packets_a);

        poll(stack, 3_800);
        let mut talker = u64::MAX;
        assert_eq!(
            unsafe { sipral_local_conference_talker_at(conference, 0, &raw mut talker) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(talker, call_a);
        assert_eq!(
            unsafe { sipral_local_conference_talker_at(conference, 1, &raw mut talker) },
            SipralStatus::InvalidArgument
        );
        let joined: Vec<SipralHandle> = events_of(&observed, SipralLocalConferenceChange::Joined)
            .iter()
            .map(|event| event.member)
            .collect();
        assert_eq!(joined, [conference, call_a, call_b]);
        let talking = events_of(&observed, SipralLocalConferenceChange::Talkers);
        assert!(
            talking
                .iter()
                .any(|event| event.loudest == call_a && event.talkers == 1),
            "call a talking was never reported"
        );

        release(media_a);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A mute and a gain taken, a member removed and a member whose call
    /// ended, each reported, and the conference destroyed.
    #[test]
    fn members_are_muted_levelled_removed_and_let_go_over_the_abi() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b, media_a, conference) = two_calls_in_one(&mut observed);
        let _ = run(conference, (call_a, media_a, call_b), 3_000, 40, 1);

        // call a muted on the way in: nobody hears it
        assert_eq!(
            unsafe { sipral_local_conference_set_muted(conference, call_a, 1, 1) },
            SipralStatus::Ok
        );
        assert_eq!(member_at(conference, 1).muted_input, 1);
        let heard = run(conference, (call_a, media_a, call_b), 3_800, 20, 41);
        assert!(heard.to_b < 0.05, "call b heard a muted call a: {}", heard.to_b);
        assert!(heard.speaker < 200, "this end heard a muted call a: {}", heard.speaker);
        assert_eq!(
            unsafe { sipral_local_conference_set_muted(conference, call_a, 1, 0) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_local_conference_set_gain(conference, call_a, 1, 128) },
            SipralStatus::Ok
        );
        assert_eq!(member_at(conference, 1).gain_input, 128);
        assert_eq!(
            unsafe { sipral_local_conference_set_gain(conference, call_a, 3, 128) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_local_conference_set_muted(conference, 12_345, 1, 1) },
            SipralStatus::WrongState,
            "a member that is not in it"
        );

        // call a taken out: a Left event, and a pair is refused until call b
        // is out too
        assert_eq!(
            unsafe { sipral_local_conference_remove(conference, call_a) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_local_conference_remove(conference, call_a) },
            SipralStatus::WrongState
        );
        poll(stack, 4_300);
        let left = events_of(&observed, SipralLocalConferenceChange::Left);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].member, call_a);
        assert_eq!(left[0].departure, SipralDeparture::Removed as u32);
        assert_eq!(left[0].members, 2);
        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_b) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_local_conference_remove(conference, call_b) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_b) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_call_leave(stack, call_a) }, SipralStatus::Ok);

        // call b back in, and its call ending takes it out by itself
        assert_eq!(add(conference, call_b), SipralStatus::Ok, "{}", last_error_text());
        hangup(stack, call_b, 4_400);
        let _ = tick(conference, 4_420, &[0; FRAME], FRAME);
        poll(stack, 4_440);
        let left = events_of(&observed, SipralLocalConferenceChange::Left);
        assert_eq!(left.last().map(|event| event.member), Some(call_b));
        assert_eq!(
            left.last().map(|event| event.departure),
            Some(SipralDeparture::Ended as u32)
        );
        assert_eq!(info(conference).members, 1);

        assert_eq!(
            unsafe { sipral_local_conference_destroy(conference) },
            SipralStatus::Ok
        );
        let mut after = info_zeroed();
        assert_eq!(
            unsafe { sipral_local_conference_info(conference, &raw mut after) },
            SipralStatus::StaleHandle
        );
        release(media_a);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A conference with no place left refuses the next call with status 23,
    /// as does a call already in another conference and a rate the
    /// conference cannot mix; a conference without this end reads no
    /// microphone and plays silence.
    #[test]
    fn a_full_conference_refuses_the_next_call() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b) = media_call_pair(&mut observed);
        let conference = create(stack, &config(2, 0));
        assert_eq!(info(conference).sample_rate, 16_000, "zero is 16 kHz");
        assert_eq!(add(conference, call_a), SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(add(conference, call_b), SipralStatus::ConferenceRefused);
        assert!(
            last_error_text().contains("no place left"),
            "{}",
            last_error_text()
        );

        let mut refused = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe {
                sipral_local_conference_create(stack, &config(4, 44_100), &raw mut refused)
            },
            SipralStatus::ConferenceRefused
        );
        let without_this_end = SipralLocalConferenceConfig {
            local: 2,
            ..config(4, 0)
        };
        let bridge = create(stack, &without_this_end);
        assert_eq!(info(bridge).local, 0);
        assert_eq!(info(bridge).members, 0);
        assert_eq!(
            add(bridge, call_a),
            SipralStatus::ConferenceRefused,
            "a call in another conference"
        );
        assert_eq!(add(bridge, call_b), SipralStatus::Ok, "{}", last_error_text());
        let ticked = tick(bridge, 3_000, &[], 320);
        assert!(ticked.speaker.iter().all(|sample| *sample == 0));
        for handle in [conference, bridge] {
            assert_eq!(
                unsafe { sipral_local_conference_destroy(handle) },
                SipralStatus::Ok
            );
        }
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The recording is a file of the whole mix, finished when it stops.
    #[test]
    fn the_conference_is_recorded_to_a_file() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b) = media_call_pair(&mut observed);
        let media_a = media_of(stack, call_a);
        let conference = create(stack, &config(3, 8_000));
        assert_eq!(add(conference, call_a), SipralStatus::Ok);
        assert_eq!(add(conference, call_b), SipralStatus::Ok);
        let path = std::env::temp_dir().join(format!(
            "sipral-conference-{}-{}.wav",
            std::process::id(),
            conference
        ));
        let text = path.to_string_lossy().into_owned();
        let options = SipralRecordingOptions {
            size: size_of::<SipralRecordingOptions>(),
            format: 0,
            layout: 0,
            sample_rate: 0,
            bitrate: 0,
            checkpoint_ms: 0,
        };
        let stereo = SipralRecordingOptions { layout: 1, ..options };
        assert_eq!(
            unsafe {
                sipral_local_conference_record_start(
                    conference,
                    text.as_ptr().cast(),
                    text.len(),
                    &raw const stereo,
                )
            },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe {
                sipral_local_conference_record_start(
                    conference,
                    text.as_ptr().cast(),
                    text.len(),
                    &raw const options,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = run(conference, (call_a, media_a, call_b), 3_000, 25, 1);
        let standing = info(conference);
        assert_eq!(standing.recording, 1);
        assert!(standing.recorded_ms >= 480, "{}", standing.recorded_ms);
        assert_eq!(
            unsafe { sipral_local_conference_record_stop(conference) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_local_conference_record_stop(conference) },
            SipralStatus::WrongState
        );
        let wav = std::fs::read(&path).expect("the file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(&wav[..4], b"RIFF");
        let data: Vec<i16> = wav[wav.len() - 25 * 160 * 2..]
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert!(
            loudness(&data[20 * 160..]) > 2_000,
            "call a is not in the file"
        );
        release(media_a);
        assert_eq!(
            unsafe { sipral_local_conference_destroy(conference) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// Two calls on a stack in device mode over a fake platform, and the
    /// platform.
    fn device_pair(
        observed: &mut Observed,
    ) -> (SipralHandle, SipralHandle, SipralHandle, Packets, FakeControl) {
        let fake = a_desk();
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = Some(fake.clone()));
        let packets: Packets = Arc::new(Mutex::new(Vec::new()));
        let leaked: &'static Packets = Box::leak(Box::new(Arc::clone(&packets)));
        let (stack, account) = media_line(observed, |config| {
            config.audio = SipralAudio::Device as u32;
            config.audio_activation = SipralAudioActivation::Automatic as u32;
            config.audio_transmit_callback = Some(transmit);
            config.audio_transmit_user_data = ptr::from_ref(leaked).cast_mut().cast::<c_void>();
            config.audio_probe_ms = 500;
        });
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = None);
        let (_, call_a) = up(observed, stack, account, ANSWER);
        let call_b = second_media_call(observed, stack, account);
        (stack, call_a, call_b, packets, fake)
    }

    fn attached(stack: SipralHandle) -> Vec<SipralHandle> {
        with_stack(stack, |state| {
            Ok(state
                .audio
                .as_ref()
                .map(|audio| audio.lock().unwrap().attached().to_vec())
                .unwrap_or_default())
        })
        .expect("the stack")
    }

    /// In device mode the audio engine carries the conference in place of
    /// its members, every packet reaches the transmit callback under its
    /// own call's handle, and a member taken out — or the conference
    /// destroyed — is carried by the engine again.
    #[test]
    fn in_device_mode_the_engine_carries_the_conference_in_place_of_its_members() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b, packets, fake) = device_pair(&mut observed);
        let before = attached(stack);
        assert!(
            before.contains(&call_a) && before.contains(&call_b),
            "{before:?}"
        );
        let conference = create(stack, &config(3, 16_000));
        assert_eq!(add(conference, call_a), SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(add(conference, call_b), SipralStatus::Ok, "{}", last_error_text());
        let carried = attached(stack);
        assert_eq!(carried, [conference], "{carried:?}");
        let mut speaker = [0_i16; 320];
        let mic = [0_i16; 320];
        let mut written = 0;
        assert_eq!(
            unsafe {
                sipral_local_conference_tick(
                    conference,
                    3_000,
                    mic.as_ptr(),
                    mic.len(),
                    speaker.as_mut_ptr(),
                    speaker.len(),
                    &raw mut written,
                )
            },
            SipralStatus::WrongState,
            "the engine ticks it"
        );

        packets.lock().unwrap().clear();
        let started = Instant::now();
        loop {
            let sent = packets.lock().unwrap().clone();
            let to_a = sent
                .iter()
                .any(|(call, destination, _)| *call == call_a && destination == PEER_MEDIA);
            let to_b = sent.iter().any(|(call, destination, _)| {
                *call == call_b && destination == SECOND_PEER_MEDIA
            });
            if to_a && to_b {
                assert!(
                    sent.iter().all(|(call, _, _)| *call != conference),
                    "a packet was named after the conference"
                );
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the engine sent no packet for both members: {sent:?}"
            );
            fake.speak_into("builtin-mic", &[1_000; 960]);
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(
            unsafe { sipral_local_conference_remove(conference, call_a) },
            SipralStatus::Ok
        );
        let carried = attached(stack);
        assert!(
            carried.contains(&call_a) && carried.contains(&conference),
            "{carried:?}"
        );
        assert_eq!(
            unsafe { sipral_local_conference_destroy(conference) },
            SipralStatus::Ok
        );
        let carried = attached(stack);
        assert!(
            carried.contains(&call_a) && carried.contains(&call_b) && !carried.contains(&conference),
            "{carried:?}"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }
}
