// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A local conference: any number of this stack's calls, each on its own
//! codec and rate, mixed so every member hears everybody but itself, this
//! end included when it takes part (ABI 0.32). `sipral_call_join` is the
//! two-call, same-rate case.
//!
//! **Device mode:** the audio engine carries the conference like one more
//! call (microphone in, loudspeaker out), and member packets reach
//! `audio_transmit_callback` under each member's call handle. **Application
//! mode:** every 20 ms the application calls [`sipral_local_conference_tick`]
//! and drains [`sipral_local_conference_poll_transmit`].
//!
//! **Members are driven only by the conference.** Their
//! `sipral_media_playback` and `sipral_media_capture` belong to it while
//! inside. A call joined with `sipral_call_join` or in another conference, a
//! full conference, or an unmixable codec is
//! `SIPRAL_STATUS_CONFERENCE_REFUSED`.
//!
//! This end is named by the conference's own handle wherever a member is
//! named. Changes arrive as `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.

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

use crate::abi::{Number, codes, record};
use crate::audio::SipralAudioDirection;
use crate::error::{Fail, entry, fail};
use crate::handle::{HandleTable, Kind, SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::{SipralMediaPacket, SipralToggle, media_failed, prepare, put};
use crate::record::{SipralRecordingOptions, options_of};
use crate::stack::{StackState, handle_failed, instant_at, with_stack};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, declared_size, read_versioned, write_versioned};

codes! {
    /// What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` reports
    /// (`sipral_local_conference_event_t::change`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralLocalConferenceChange: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// `member` joined (a call, or this end at creation).
        Joined = 1,
        /// `member` left, for the reason `departure` gives.
        Left = 2,
        /// The talkers changed: see `talkers`, `loudest` and
        /// `sipral_local_conference_talker_at`.
        Talkers = 3,
        /// The recording stopped because the file refused a write; it holds
        /// audio up to its last checkpoint.
        RecordingStopped = 4,
    }
}

codes! {
    /// Why a member left (`sipral_local_conference_event_t::departure`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDeparture: u32 {
        /// Nobody left.
        None = 0,
        /// `sipral_local_conference_remove` took it out.
        Removed = 1,
        /// Its call's media ended.
        Ended = 2,
        /// Its call moved to a codec the conference cannot mix.
        Incompatible = 3,
    }
}

record! {
    /// How `sipral_local_conference_create` makes a conference. All zero but
    /// `size`: sixteen members, this end in, 16 kHz.
    ///
    /// Set `size` to `sizeof(sipral_local_conference_config_t)` first.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralLocalConferenceConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Most members at once, this end included; zero for 16, at most 1024.
        pub max_members: u32,
        /// A `SipralToggle`: whether this end takes part. On unless
        /// `SIPRAL_TOGGLE_OFF`; without it the conference only bridges calls.
        pub local: Number<SipralToggle>,
        /// This end's frame rate in application mode, in Hz: 8000, 16000,
        /// 32000 or 48000, zero for 16000. A tick is 20 ms of it. In device
        /// mode the engine converts the devices to it.
        pub sample_rate: u32,
        /// Zero. Pads the struct to its alignment so an appended member starts
        /// past the declared length. Never read.
        pub reserved: u32,
    }
}

// Safety: integers only; all-zero is the ordinary conference.
unsafe impl Versioned for SipralLocalConferenceConfig {
    const NAME: &'static str = "sipral_local_conference_config";
    const PIN: crate::versioned::Pin =
        crate::versioned::pin!(SipralLocalConferenceConfig, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// A conference as it stands: `sipral_local_conference_info`.
    ///
    /// Set `size` to `sizeof(sipral_local_conference_info_t)` first.
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
        /// Recorded so far, while recording.
        pub recorded_ms: u64,
        /// Packets dropped because nobody polled for them in time.
        pub packets_dropped: u64,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralLocalConferenceInfo {
    const NAME: &'static str = "sipral_local_conference_info";
    const PIN: crate::versioned::Pin =
        crate::versioned::pin!(SipralLocalConferenceInfo, packets_dropped);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One member of a conference: `sipral_local_conference_member_at`.
    ///
    /// Set `size` to `sizeof(sipral_local_conference_member_t)` first.
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
        /// Level of what it says, in `sipral_audio_set_gain` steps (256 = unity).
        pub gain_input: u32,
        /// The level of what it hears, in the same steps.
        pub gain_output: u32,
        /// Zero. Pads the struct to its alignment so an appended member starts
        /// past the declared length. Written as zero, never read.
        pub reserved: u32,
    }
}

// Safety: integers and a handle; zero is valid for each.
unsafe impl Versioned for SipralLocalConferenceMember {
    const NAME: &'static str = "sipral_local_conference_member";
    const PIN: crate::versioned::Pin =
        crate::versioned::pin!(SipralLocalConferenceMember, reserved);

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
        pub change: Number<SipralLocalConferenceChange>,
        /// A [`SipralDeparture`], for `SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT`.
        pub departure: Number<SipralDeparture>,
        /// Who joined or left (a call, or the conference handle for this end);
        /// `SIPRAL_HANDLE_NONE` otherwise.
        pub member: SipralHandle,
        /// Members now, this end included.
        pub members: u32,
        /// Members talking now.
        pub talkers: u32,
        /// The loudest of them, or `SIPRAL_HANDLE_NONE`.
        pub loudest: SipralHandle,
    }
}

/// Gain steps: 256 is unity, as in the audio engine.
const GAIN_UNITY: u32 = 256;

/// Largest gain in steps: four times.
const GAIN_MOST: u32 = 4 * GAIN_UNITY;

/// One conference, and the names its members go by across the boundary.
pub(crate) struct Conference {
    pub(crate) inner: LocalConference,
    /// This conference's own handle, which is this end's name as a member.
    handle: SipralHandle,
    /// Every call ever added, so packets and departures can still be named
    /// after the stack forgets the call.
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

/// Lock one; poisoning is ignored since a conference is whole between
/// statements.
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

/// Act on a conference, refused to a thread inside one of its ticks (a
/// processor on a member call), which would wait for itself.
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

/// The engine's view of a conference: one more call, whose frame is this
/// end's 20 ms and whose packets are its members'.
struct Carried {
    shared: Shared,
    /// The conference's handle, marking the pump's thread during a tick.
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
        // the pump gives a frame of this end's length; packets wait for
        // `capture_each`
        let _inside = crate::media::Inside::enter(self.handle);
        let _ = lock(&self.shared).inner.tick(frame, now);
        Ok(None)
    }

    fn capture_each(
        &mut self,
        _own: CallId,
        frame: &[i16],
        now: Instant,
        send: &mut dyn FnMut(CallId, &Outgoing),
    ) -> Result<(), CallGone> {
        let _inside = crate::media::Inside::enter(self.handle);
        let mut held = lock(&self.shared);
        let _ = held.inner.tick(frame, now);
        while let Some(packet) = held.inner.poll_transmit() {
            let call = held.name_of(Member::Call(packet.call));
            send(call, &outgoing(packet));
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
    /// Make a local conference on this stack, holding only this end if it
    /// takes part, and write its handle to `out_conference`.
    ///
    /// In device mode the engine carries it at once, opening the devices
    /// under automatic activation.
    ///
    /// `SIPRAL_STATUS_CONFERENCE_REFUSED` for a rate other than 8, 16, 32 or
    /// 48 kHz, or more than 1024 members.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_local_conference_config_t` whose
    /// `size` says how long it is, and `out_conference` at one `sipral_handle_t`.
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
    /// End a conference. Its calls carry their own audio again (in device
    /// mode the engine takes them back), a running recording is finished, and
    /// the handle is stale.
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
                // controls made by the first attach go with it
                engine.forget_call(conference);
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
                // the conference goes even if the stack is already destroyed
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
    /// Add a call, from the next tick, at its codec's rate; its far end hears
    /// everybody but itself.
    ///
    /// The call needs running media. `SIPRAL_STATUS_CONFERENCE_REFUSED` when
    /// full, for a call already in a conference or joined with
    /// `sipral_call_join`, or for an unmixable codec (rate not 8, 16, 32 or
    /// 48 kHz, or frames over 60 ms).
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
                let mut engine = audio.lock().unwrap_or_else(PoisonError::into_inner);
                engine.detach(call);
                // the call's gain, mute and meter move with it into the conference
                if let Some(controls) = engine.call_controls(call) {
                    let _ = lock(&entry.shared).inner.filter(named, Box::new(controls));
                }
            }
            Ok(())
        })
    }
}

entry! {
    /// Take a call out, from the next tick. Its media is the application's
    /// again (in device mode, the engine's).
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
    /// Mute or unmute one direction of a member from the next tick: input
    /// (others stop hearing it) or output (it stops hearing).
    /// `direction` is `SIPRAL_AUDIO_DIRECTION_INPUT` or `_OUTPUT`; `member` is a
    /// call in the conference, or the conference handle for this end.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a member that is not in it.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_local_conference_set_muted(
        conference: SipralHandle,
        member: SipralHandle,
        direction: Number<SipralAudioDirection>,
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
    /// Set one direction's level for a member, from the next tick, in
    /// `sipral_audio_set_gain` steps: 256 unity, 1024 at most. Input is what
    /// others hear of it; output is what it hears.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_local_conference_set_gain(
        conference: SipralHandle,
        member: SipralHandle,
        direction: Number<SipralAudioDirection>,
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
    /// `size` says how long it is.
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
    /// One member by index: this end first if it takes part, then calls in
    /// join order. Stable until the next join or leave.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
    ///
    /// # Safety
    ///
    /// `out_member` must point at a `sipral_local_conference_member_t` whose
    /// `size` says how long it is.
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
                reserved: 0,
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
    /// Who talked in the last tick, loudest at index zero. Muted members are
    /// never listed.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` past the last talker (count in
    /// `sipral_local_conference_info_t::talkers`).
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
    /// 20 ms of conference in application mode. `mic` is this end's frame,
    /// `sipral_local_conference_info_t::frame_samples` long; `speaker` gets
    /// what this end hears, same length, written to `out_written`. Without
    /// this end, `mic` may be null and `speaker` gets silence.
    ///
    /// Call every 20 ms from the audio thread, then drain
    /// `sipral_local_conference_poll_transmit`.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` in device mode;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a wrong frame length;
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` for a short speaker buffer, with the
    /// length needed in `out_written`.
    ///
    /// # Safety
    ///
    /// `mic` readable for `mic_count` `int16_t`, `speaker` writable for
    /// `capacity` `int16_t`, `out_written` one `size_t` or null.
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
    /// mode. `out_call` names the call whose socket sends it; `packet` is
    /// filled as by `sipral_media_capture`. `len` zero with
    /// `SIPRAL_HANDLE_NONE` means nothing waits. Drain after every tick.
    ///
    /// # Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `packet` at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    fn sipral_local_conference_poll_transmit(
        conference: SipralHandle,
        out_call: *mut SipralHandle,
        packet: *mut SipralMediaPacket,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let mut out = unsafe { read_versioned(packet) }?;
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
        unsafe { write_versioned(packet, out) }
    }
}

entry! {
    /// Record the whole conference mix to `path`, one channel, as `options`
    /// say (WAV or Ogg Opus, at the conference rate unless another is named).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` if already recording;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for stereo, unusable options or a
    /// refused path; `SIPRAL_STATUS_RECORDING_FAILED` if the header write fails.
    ///
    /// # Safety
    ///
    /// `path` readable for `path_len` bytes; `options` a
    /// `sipral_recording_options_t` whose `size` says how long it is.
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
    use crate::audio::tests::{Packets, a_desk, landed, transmit};
    use crate::audio::{
        FAKE_PLATFORM, SipralAudio, SipralAudioActivation, SipralAudioDirection,
        SipralAudioTransmit, sipral_audio_call_level, sipral_audio_call_set_muted,
    };
    use crate::call::tests::{
        ANSWER, PEER_MEDIA, SECOND_PEER_MEDIA, hangup, media_call_pair, media_line,
        second_media_call, up,
    };
    use crate::call::{sipral_call_join, sipral_call_leave};
    use crate::error::last_error_text;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::SipralProcessorFrame;
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
            reserved: 0,
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
            reserved: 0,
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

    /// One mu-law RTP packet of a 500 Hz square wave (8 high, 8 low samples).
    fn loud(sequence: u16) -> Vec<u8> {
        let mut out = vec![0x80, 0x00];
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        out.extend_from_slice(&0x5EED_0001_u32.to_be_bytes());
        out.extend((0..FRAME).map(|n| if (n / 8) % 2 == 0 { 0x80 } else { 0x00 }));
        out
    }

    /// The share of a mu-law payload in the top three of eight segments.
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

    /// The second half of a run: this end's loudness, the loudness of packets
    /// to a's and b's far ends, and how many went to each.
    struct Heard {
        speaker: i64,
        to_a: f64,
        to_b: f64,
        packets_a: usize,
        packets_b: usize,
    }

    /// Ticks with a's far end sending its square wave; every packet names a or b.
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

    /// Two calls in an 8 kHz conference of three with this end: stack, calls,
    /// a's media handle, conference.
    fn two_calls_in_one(
        observed: &mut Observed,
    ) -> (
        SipralHandle,
        SipralHandle,
        SipralHandle,
        SipralHandle,
        SipralHandle,
    ) {
        let (stack, call_a, call_b) = media_call_pair(observed);
        let media_a = media_of(stack, call_a);
        let conference = create(stack, &config(3, 8_000));
        assert_eq!(
            add(conference, call_a),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            add(conference, call_b),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        (stack, call_a, call_b, media_a, conference)
    }

    /// Application mode: everyone hears the others and not itself; talkers
    /// are reported.
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
        assert_eq!(
            member_at(conference, 0).member,
            conference,
            "this end first"
        );
        assert_eq!(member_at(conference, 1).member, call_a);
        assert_eq!(member_at(conference, 2).member, call_b);
        assert_eq!(member_at(conference, 1).gain_input, 256);

        let heard = run(conference, (call_a, media_a, call_b), 3_000, 40, 1);
        assert!(
            heard.speaker > 2_000,
            "this end did not hear call a: {}",
            heard.speaker
        );
        assert!(
            heard.to_b > 0.5,
            "call b's far end did not hear call a: {}",
            heard.to_b
        );
        assert!(
            heard.to_a < 0.05,
            "call a's far end heard itself: {}",
            heard.to_a
        );
        assert!(
            heard.packets_b >= 19,
            "call b was sent {} packets in 20 ticks",
            heard.packets_b
        );
        assert!(
            heard.packets_a >= 19,
            "call a was sent {} packets in 20 ticks",
            heard.packets_a
        );

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

    /// Mute, gain, removal and an ended call are reported; then destroy.
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
        assert!(
            heard.to_b < 0.05,
            "call b heard a muted call a: {}",
            heard.to_b
        );
        assert!(
            heard.speaker < 200,
            "this end heard a muted call a: {}",
            heard.speaker
        );
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

        // call a out: a Left event; a pair is refused until b is out too
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
        assert_eq!(
            unsafe { sipral_call_leave(stack, call_a) },
            SipralStatus::Ok
        );

        // call b back in, and its call ending takes it out by itself
        assert_eq!(
            add(conference, call_b),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
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

    /// Refused with status 23 when full, for a call in another conference, or
    /// for an unmixable rate. Without this end: no microphone, silent speaker.
    #[test]
    fn a_full_conference_refuses_the_next_call() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b) = media_call_pair(&mut observed);
        let conference = create(stack, &config(2, 0));
        assert_eq!(info(conference).sample_rate, 16_000, "zero is 16 kHz");
        assert_eq!(
            add(conference, call_a),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(add(conference, call_b), SipralStatus::ConferenceRefused);
        assert!(
            last_error_text().contains("no place left"),
            "{}",
            last_error_text()
        );

        let mut refused = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_local_conference_create(stack, &config(4, 44_100), &raw mut refused) },
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
        assert_eq!(
            add(bridge, call_b),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
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
            reserved: 0,
            size: size_of::<SipralRecordingOptions>(),
            format: 0,
            layout: 0,
            sample_rate: 0,
            bitrate: 0,
            checkpoint_ms: 0,
        };
        let stereo = SipralRecordingOptions {
            layout: 1,
            ..options
        };
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
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes(*pair))
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

    /// What a member's processor saw re-entering conference and stack in a tick.
    struct Reentered {
        conference: SipralHandle,
        stack: SipralHandle,
        said: Mutex<Vec<(SipralStatus, SipralStatus)>>,
    }

    unsafe extern "C" fn call_back_in(_frame: *const SipralProcessorFrame, user_data: *mut c_void) {
        let reentered = unsafe { &*user_data.cast::<Reentered>() };
        let mut info = info_zeroed();
        let conference =
            unsafe { sipral_local_conference_info(reentered.conference, &raw mut info) };
        let stack = unsafe { crate::stack::sipral_stack_poll(reentered.stack, 0, ptr::null_mut()) };
        reentered.said.lock().unwrap().push((conference, stack));
    }

    /// A processor inside a tick re-entering the conference or the stack is
    /// told BUSY rather than deadlocking.
    #[test]
    fn a_processor_inside_a_tick_is_told_busy_rather_than_waiting_for_itself() {
        let mut observed = Observed::default();
        let (stack, _, _, media_a, conference) = two_calls_in_one(&mut observed);
        let reentered: &'static Reentered = Box::leak(Box::new(Reentered {
            conference,
            stack,
            said: Mutex::new(Vec::new()),
        }));
        assert_eq!(
            unsafe {
                crate::media::sipral_media_attach_processor(
                    media_a,
                    Some(call_back_in),
                    ptr::from_ref(reentered).cast_mut().cast::<c_void>(),
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for n in 0..3 {
                let _ = tick(conference, 3_000 + n * 20, &[0; FRAME], FRAME);
            }
            let _ = done.send(());
        });
        assert!(
            finished.recv_timeout(Duration::from_secs(5)).is_ok(),
            "a tick whose processor called back in never finished"
        );
        let said = reentered.said.lock().unwrap().clone();
        assert!(!said.is_empty(), "the processor never ran inside a tick");
        assert!(
            said.iter()
                .all(|seen| *seen == (SipralStatus::Busy, SipralStatus::Busy)),
            "{said:?}"
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

    /// Two calls in device mode over a fake platform, and the platform.
    fn device_pair(
        observed: &mut Observed,
    ) -> (
        SipralHandle,
        SipralHandle,
        SipralHandle,
        Packets,
        FakeControl,
    ) {
        let packets: Packets = Arc::new(Mutex::new(Vec::new()));
        let leaked: &'static Packets = Box::leak(Box::new(Arc::clone(&packets)));
        let (stack, call_a, call_b, fake) = device_pair_through(
            observed,
            transmit,
            ptr::from_ref(leaked).cast_mut().cast::<c_void>(),
        );
        (stack, call_a, call_b, packets, fake)
    }

    /// The same, every packet handed to `callback` with `user_data`.
    fn device_pair_through(
        observed: &mut Observed,
        callback: unsafe extern "C" fn(*const SipralAudioTransmit, *mut c_void),
        user_data: *mut c_void,
    ) -> (SipralHandle, SipralHandle, SipralHandle, FakeControl) {
        let fake = a_desk();
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = Some(fake.clone()));
        let (stack, account) = media_line(observed, |config| {
            config.audio = SipralAudio::Device as u32;
            config.audio_activation = SipralAudioActivation::Automatic as u32;
            config.audio_transmit_callback = Some(callback);
            config.audio_transmit_user_data = user_data;
            config.audio_probe_ms = 500;
        });
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = None);
        let (_, call_a) = up(observed, stack, account, ANSWER);
        let call_b = second_media_call(observed, stack, account);
        // devices open in the background and only a poll attaches them;
        // nothing below polls, so they must be attached now
        landed(stack, 2_500);
        (stack, call_a, call_b, fake)
    }

    /// Every packet the engine sent, whole, by the call it was sent for.
    type Payloads = Arc<Mutex<Vec<(SipralHandle, Vec<u8>)>>>;

    unsafe extern "C" fn keep_payloads(event: *const SipralAudioTransmit, user_data: *mut c_void) {
        let transmit = unsafe { &*event };
        let payload =
            unsafe { std::slice::from_raw_parts(transmit.payload, transmit.payload_len) }.to_vec();
        let kept = unsafe { &*user_data.cast::<Payloads>() };
        kept.lock().unwrap().push((transmit.call, payload));
    }

    /// One call's meter in one direction, through the C entry point.
    fn call_level(stack: SipralHandle, call: SipralHandle, direction: u32) -> u32 {
        let mut peak = u32::MAX;
        assert_eq!(
            unsafe { sipral_audio_call_level(stack, call, direction, &raw mut peak) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        peak
    }

    /// Device mode: a call's controls move into the conference. With a's
    /// input muted its far end hears silence, b's hears this end, and b's
    /// meter reads what its far end is sent.
    #[test]
    fn in_device_mode_a_calls_own_controls_act_inside_a_conference() {
        let mut observed = Observed::default();
        let payloads: Payloads = Arc::default();
        let leaked: &'static Payloads = Box::leak(Box::new(Arc::clone(&payloads)));
        let (stack, call_a, call_b, fake) = device_pair_through(
            &mut observed,
            keep_payloads,
            ptr::from_ref(leaked).cast_mut().cast::<c_void>(),
        );
        let input = SipralAudioDirection::Input as u32;
        assert_eq!(
            unsafe { sipral_audio_call_set_muted(stack, call_a, input, 1) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let conference = create(stack, &config(3, 16_000));
        assert_eq!(add(conference, call_a), SipralStatus::Ok);
        assert_eq!(add(conference, call_b), SipralStatus::Ok);

        // 500 Hz square wave near full scale, at the fake mic's 48 kHz
        let square: Vec<i16> = (0..960)
            .map(|n| if (n / 48) % 2 == 0 { 12_000 } else { -12_000 })
            .collect();
        let started = Instant::now();
        let mut cleared = false;
        let (to_a, to_b) = loop {
            fake.speak_into("builtin-mic", &square);
            std::thread::sleep(Duration::from_millis(10));
            if !cleared && started.elapsed() > Duration::from_millis(400) {
                payloads.lock().unwrap().clear();
                cleared = true;
            }
            let sent = payloads.lock().unwrap().clone();
            let shares = |call: SipralHandle| -> Vec<f64> {
                sent.iter()
                    .filter(|(named, _)| *named == call)
                    .map(|(_, payload)| loud_share(payload))
                    .collect()
            };
            let (to_a, to_b) = (shares(call_a), shares(call_b));
            if cleared && to_a.len() >= 25 && to_b.len() >= 25 {
                break (to_a, to_b);
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the engine sent too few packets: {} to a, {} to b",
                to_a.len(),
                to_b.len()
            );
        };
        #[allow(clippy::cast_precision_loss)]
        let mean = |shares: &[f64]| shares.iter().sum::<f64>() / shares.len().max(1) as f64;
        assert!(
            mean(&to_a) < 0.01,
            "call a's far end heard this end through its own mute: {to_a:?}"
        );
        assert!(
            mean(&to_b) > 0.3,
            "call b's far end did not hear this end: {to_b:?}"
        );
        assert_eq!(call_level(stack, call_a, input), 0);
        let up = call_level(stack, call_b, input);
        assert!(up > 4_000, "call b's meter read {up} inside the conference");

        assert_eq!(
            unsafe { sipral_local_conference_destroy(conference) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
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

    /// Whether the engine holds a call's own controls under `handle`.
    fn has_controls(stack: SipralHandle, handle: SipralHandle) -> bool {
        with_stack(stack, |state| {
            Ok(state.audio.as_ref().is_some_and(|audio| {
                audio
                    .lock()
                    .unwrap()
                    .call_gain(handle, sipral_audio::Direction::Output)
                    .is_some()
            }))
        })
        .expect("the stack")
    }

    /// Device mode: the engine carries the conference instead of its members,
    /// packets reach the callback under each call's handle, and removed
    /// members (or all, on destroy) are carried by the engine again.
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
        assert_eq!(
            add(conference, call_a),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            add(conference, call_b),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
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
            let to_b = sent
                .iter()
                .any(|(call, destination, _)| *call == call_b && destination == SECOND_PEER_MEDIA);
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
        assert!(has_controls(stack, conference));
        assert_eq!(
            unsafe { sipral_local_conference_destroy(conference) },
            SipralStatus::Ok
        );
        let carried = attached(stack);
        assert!(
            carried.contains(&call_a)
                && carried.contains(&call_b)
                && !carried.contains(&conference),
            "{carried:?}"
        );
        assert!(
            !has_controls(stack, conference),
            "a destroyed conference leaves no controls behind in the engine"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }
}
