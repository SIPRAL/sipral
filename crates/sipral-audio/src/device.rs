// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the engine calls a device, and what it says when the devices move.

use core::fmt;
use core::num::NonZeroU32;

/// The engine's own name for one device.
///
/// Handed out when a device is first seen and kept for as long as the engine
/// lives, whatever the platform does to its own identifiers in between: a
/// refresh finds the same identity and keeps the same handle, and a device
/// that is unplugged keeps its handle too, marked absent, so that a stream
/// running on it and a selection saved against it still name something. The
/// number is never reused. Zero is not a handle, and is what "the system's own
/// choice" is written as across the C boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceHandle(NonZeroU32);

impl DeviceHandle {
    /// The handle with this number, or `None` for zero.
    #[must_use]
    pub const fn new(number: u32) -> Option<Self> {
        match NonZeroU32::new(number) {
            Some(number) => Some(Self(number)),
            None => None,
        }
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for DeviceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "device {}", self.0)
    }
}

/// Which way audio flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// From the microphone.
    Input,
    /// To a loudspeaker or an earpiece.
    Output,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Input => "input",
            Self::Output => "output",
        })
    }
}

/// What a device is used for. A softphone has three jobs for its devices,
/// and the third is the one every SDK forgets: the ring goes to the room,
/// the call to the headset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The call's microphone.
    Microphone,
    /// The call's loudspeaker or earpiece.
    Speaker,
    /// Where an incoming call is announced, which is not necessarily where
    /// it is then answered.
    Ringer,
}

impl Role {
    /// Every role, in the order the engine opens them.
    pub const ALL: [Self; 3] = [Self::Microphone, Self::Speaker, Self::Ringer];

    /// Which way a device in this role carries audio.
    #[must_use]
    pub const fn direction(self) -> Direction {
        match self {
            Self::Microphone => Direction::Input,
            Self::Speaker | Self::Ringer => Direction::Output,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Microphone => "microphone",
            Self::Speaker => "speaker",
            Self::Ringer => "ringer",
        })
    }
}

/// One device the engine knows about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The engine's name for it, stable across refreshes.
    pub handle: DeviceHandle,
    /// The platform's identity for it: the one worth writing into a
    /// configuration file, since it survives a replug and a reboot.
    pub identity: String,
    /// What it is called, for a list a person chooses from.
    pub name: String,
    /// How many channels it captures. Zero for a device that is not a
    /// microphone, and for one whose microphone has nothing behind it.
    pub input_channels: u32,
    /// How many channels it plays. Zero likewise.
    pub output_channels: u32,
    /// Whether the system currently routes recording to it.
    pub default_input: bool,
    /// Whether the system currently routes playback to it.
    pub default_output: bool,
    /// Whether the last refresh still found it. A device that has gone keeps
    /// its handle and its row, so that whatever named it can still say so.
    pub present: bool,
}

impl DeviceInfo {
    /// Whether it has anything to offer a role.
    #[must_use]
    pub const fn serves(&self, role: Role) -> bool {
        match role.direction() {
            Direction::Input => self.input_channels > 0,
            Direction::Output => self.output_channels > 0,
        }
    }
}

/// Which device a role is on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Selection {
    /// Whatever the system routes that direction to, followed when it moves.
    #[default]
    System,
    /// That device and no other, until the application says otherwise. When
    /// it goes the engine falls back to the system's route and says so.
    Device(DeviceHandle),
}

/// Why a device could not be chosen for a role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectError {
    /// The handle names nothing this engine has ever listed. Refused before
    /// any platform call is made.
    NoSuchDevice,
    /// The device exists and has no channels in this role's direction: a
    /// loudspeaker asked to be a microphone.
    NoChannels,
    /// The device was unplugged since it was listed. Refused rather than
    /// opened and lost a moment later; a refresh says what is there now.
    Absent,
    /// This platform cannot put this role on a device of its own: on macOS
    /// the voice-processing unit takes one device for the call.
    NotSupported,
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::NoSuchDevice => "no device has that handle",
            Self::NoChannels => "the device has no channels in that direction",
            Self::Absent => "the device is not plugged in",
            Self::NotSupported => "this platform cannot put that role on a device of its own",
        })
    }
}

impl std::error::Error for SelectError {}

/// Who made a change: the point of telling the two apart is that the
/// application acts on one and merely notes the other, and an application
/// that re-applies its own selection on hearing the engine announce it is a
/// loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The operating system, or a person at a socket: a headset arrived or
    /// left, the default moved.
    System,
    /// The engine, doing what the application asked or what the loss of a
    /// device made it do.
    Engine,
}

/// What changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// The set of devices is not what it was; the list has been refreshed.
    ListChanged,
    /// The system's default for one direction moved.
    DefaultChanged(Direction),
    /// A role is on a device because the application chose it.
    Selected(Role),
    /// The device a role was running on went away. The engine reopens the
    /// role on its fallback and reports that separately.
    Lost(Role),
    /// A role is running on a device again: after a loss, after the
    /// default moved under a role that follows it, or after a selection.
    Reopened(Role),
    /// A role could not be opened on anything; the audio for that direction
    /// is silence until a device arrives.
    Unavailable(Role),
}

/// Something the engine has to say about its devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioEvent {
    /// What happened.
    pub change: Change,
    /// Who did it.
    pub origin: Origin,
    /// The device it happened to, when there is one: the one a role landed
    /// on, or the one that went.
    pub device: Option<DeviceHandle>,
}

#[cfg(test)]
mod tests {
    use super::{DeviceHandle, DeviceInfo, Direction, Role};

    #[test]
    fn zero_is_not_a_handle() {
        assert!(DeviceHandle::new(0).is_none());
        assert_eq!(DeviceHandle::new(7).map(DeviceHandle::get), Some(7));
    }

    #[test]
    fn a_role_has_a_direction_and_a_device_serves_it_by_channel_count() {
        assert_eq!(Role::Microphone.direction(), Direction::Input);
        assert_eq!(Role::Ringer.direction(), Direction::Output);
        let speaker = DeviceInfo {
            handle: DeviceHandle::new(1).unwrap(),
            identity: "x".into(),
            name: "x".into(),
            input_channels: 0,
            output_channels: 2,
            default_input: false,
            default_output: true,
            present: true,
        };
        assert!(speaker.serves(Role::Speaker));
        assert!(speaker.serves(Role::Ringer));
        assert!(!speaker.serves(Role::Microphone));
    }
}
