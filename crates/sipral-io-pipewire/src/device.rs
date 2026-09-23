// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Devices, and the fact that they come and go.
//!
//! A headset unplugged in the middle of a call is not an error, it is
//! Tuesday. Nothing above this crate should have to know that PipeWire
//! exists to cope with it, so a route change arrives as an event the caller
//! polls and answers by asking for the list again.
//!
//! A PipeWire node is one direction, the same as a WASAPI endpoint and unlike
//! a CoreAudio device: `PW_KEY_MEDIA_CLASS` is `"Audio/Sink"` or
//! `"Audio/Source"` and never both. The registry hands out a numeric global
//! id for a node the moment it appears, and reuses that number after the node
//! is gone — [`registry::devices`](crate::devices) never exposes it. What
//! identifies a node across a replug is its `node.name`, a stable string a
//! session manager assigns once (`alsa_output.pci-0000_00_1f.3.analog-stereo`
//! for a physical card, `bluez_output.AA_BB_CC_DD_EE_FF.1` for a headset), and
//! that is what [`DeviceId`] wraps.

use core::fmt;

/// A node's stable name: `node.name`, assigned once by the session manager
/// and the same across a replug and a reboot for the same physical route.
///
/// Not the registry's numeric global id, which is reused the moment a node
/// goes away and means nothing once it has.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Wrap a `node.name` the registry gave out.
    #[must_use]
    pub fn new(node_name: impl Into<String>) -> Self {
        Self(node_name.into())
    }

    /// The name underneath, as PipeWire's own tools (`pw-cli`, `wpctl`) print
    /// it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which way audio is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// From the microphone into the stack. `PW_KEY_MEDIA_CLASS = "Audio/Source"`.
    Input,
    /// From the stack out to the speaker. `PW_KEY_MEDIA_CLASS = "Audio/Sink"`.
    Output,
}

impl Direction {
    /// The `media.class` value a node of this direction carries.
    #[cfg(any(target_os = "linux", test))]
    #[must_use]
    pub(crate) const fn media_class(self) -> &'static str {
        match self {
            Self::Input => "Audio/Source",
            Self::Output => "Audio/Sink",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Input => "input",
            Self::Output => "output",
        })
    }
}

/// A node the graph has, at the moment it was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// Its stable `node.name`.
    pub id: DeviceId,
    /// What a person would call it: `node.description` when the node set
    /// one, `node.name` otherwise.
    pub name: String,
    /// Which way it carries audio.
    pub direction: Direction,
    /// Whether this is the session's default route for its direction, per
    /// the `default.audio.sink` / `default.audio.source` key on the metadata
    /// object named `"default"`.
    pub is_default: bool,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} \"{}\", {}", self.id, self.name, self.direction)?;
        if self.is_default {
            f.write_str(", default")?;
        }
        Ok(())
    }
}

/// Something changed about the graph's audio nodes.
///
/// Every one of these means the same thing to the caller: ask again. They are
/// notifications, not a record — several changes in a row coalesce into one,
/// because acting on the second would give the same answer as acting on the
/// fifth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DeviceEvent {
    /// A node appeared or went away.
    ListChanged,
    /// The session's default node for a direction is now a different one.
    /// On a desktop this is what a headset being plugged in looks like.
    DefaultChanged(Direction),
}

impl fmt::Display for DeviceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ListChanged => f.write_str("the device list changed"),
            Self::DefaultChanged(direction) => write!(f, "the default {direction} device changed"),
        }
    }
}

/// Which node a stream should open, and what to do when it is not there.
///
/// The difference between the last two is the whole of what a saved
/// selection needs. [`DeviceChoice::Device`] names a node by the `node.name`
/// it is carrying, which is right for "the one the person just clicked" and
/// fails outright once it is unplugged. [`DeviceChoice::Preferred`] names it
/// the same way and falls back to the session's route when the machine does
/// not have it, which is what a preference read out of a configuration file
/// at start-up means.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DeviceChoice {
    /// Whatever the session is routing to at the moment the stream opens.
    #[default]
    System,
    /// This node, and no other.
    Device(DeviceId),
    /// This node if the machine has it, and the session's route otherwise.
    Preferred(DeviceId),
}

impl fmt::Display for DeviceChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::System => f.write_str("the session route"),
            Self::Device(ref id) => write!(f, "{id}"),
            Self::Preferred(ref id) => write!(f, "{id}, or the session route"),
        }
    }
}

/// Something a stream noticed about the node underneath it.
///
/// Not an [`Error`](crate::Error): a headset being unplugged during a call is
/// not a fault in anything, and the caller's answer to it is a decision
/// rather than a retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StreamEvent {
    /// The node the stream was running on is gone — unplugged, switched off,
    /// or removed by the session manager.
    ///
    /// The stream stops rather than pretending: `PW_STREAM_FLAG_DONT_RECONNECT`
    /// keeps PipeWire from silently rerouting it, so nothing more arrives
    /// from a capture stream once what it had already read is drained, and a
    /// playback stream's ring fills up and takes no more. What puts a node
    /// back under it is `CaptureStream::recover` or `PlaybackStream::recover`,
    /// and what that lands on is the
    /// stream's own [`DeviceChoice`] resolved again.
    DeviceLost,
}

impl fmt::Display for StreamEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DeviceLost => f.write_str("the device the stream was on is gone"),
        }
    }
}

/// The changes seen but not yet handed over.
///
/// A set of bits rather than a queue: the events are idempotent, the
/// listener runs on PipeWire's own thread loop, and a queue that a slow
/// caller stops draining would either grow without bound or lose the newest
/// change, which is the one that matters. Bits lose nothing and cost one
/// word.
#[cfg(any(target_os = "linux", test))]
pub(crate) struct Pending(core::sync::atomic::AtomicU32);

#[cfg(any(target_os = "linux", test))]
impl Pending {
    const LIST: u32 = 1;
    const DEFAULT_INPUT: u32 = 2;
    const DEFAULT_OUTPUT: u32 = 4;

    pub(crate) const fn new() -> Self {
        Self(core::sync::atomic::AtomicU32::new(0))
    }

    /// Record a change. Called from PipeWire's thread loop.
    pub(crate) fn note(&self, event: DeviceEvent) {
        let bit = match event {
            DeviceEvent::ListChanged => Self::LIST,
            DeviceEvent::DefaultChanged(Direction::Input) => Self::DEFAULT_INPUT,
            DeviceEvent::DefaultChanged(Direction::Output) => Self::DEFAULT_OUTPUT,
        };
        // Release: whatever the listener did before this is visible to the
        // caller that acquires the bit.
        self.0.fetch_or(bit, core::sync::atomic::Ordering::Release);
    }

    /// Take one change, if there is one.
    ///
    /// The compare-exchange rather than a plain `fetch_and` is the whole
    /// point: a change noted between reading the word and clearing the bit
    /// would be erased by an unconditional clear, and that is the report of
    /// the unplugging nobody hears.
    pub(crate) fn take(&self) -> Option<DeviceEvent> {
        use core::sync::atomic::Ordering;

        let mut seen = self.0.load(Ordering::Acquire);
        loop {
            // lowest bit still set, so the oldest kind reported comes out first
            let bit = seen & seen.wrapping_neg();
            let event = match bit {
                Self::LIST => DeviceEvent::ListChanged,
                Self::DEFAULT_INPUT => DeviceEvent::DefaultChanged(Direction::Input),
                Self::DEFAULT_OUTPUT => DeviceEvent::DefaultChanged(Direction::Output),
                _ => return None,
            };
            match self.0.compare_exchange_weak(
                seen,
                seen & !bit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(event),
                Err(current) => seen = current,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Pending, StreamEvent};

    fn device() -> Device {
        Device {
            id: DeviceId::new("alsa_output.pci-0000_00_1f.3.analog-stereo"),
            name: "Built-in Audio Analog Stereo".to_string(),
            direction: Direction::Output,
            is_default: true,
        }
    }

    #[test]
    fn a_device_reads_as_a_sentence() {
        let speaker = device();
        assert_eq!(
            speaker.to_string(),
            "alsa_output.pci-0000_00_1f.3.analog-stereo \"Built-in Audio Analog Stereo\", output, default"
        );
        let not_default = Device {
            is_default: false,
            ..device()
        };
        assert!(!not_default.to_string().ends_with("default"));
    }

    #[test]
    fn a_direction_names_its_media_class() {
        assert_eq!(Direction::Input.media_class(), "Audio/Source");
        assert_eq!(Direction::Output.media_class(), "Audio/Sink");
        assert_eq!(Direction::Input.to_string(), "input");
        assert_eq!(Direction::Output.to_string(), "output");
    }

    #[test]
    fn events_read_as_sentences() {
        assert_eq!(
            DeviceEvent::ListChanged.to_string(),
            "the device list changed"
        );
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Input).to_string(),
            "the default input device changed"
        );
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Output).to_string(),
            "the default output device changed"
        );
    }

    #[test]
    fn a_choice_says_what_it_would_open() {
        assert_eq!(DeviceChoice::default(), DeviceChoice::System);
        assert_eq!(DeviceChoice::System.to_string(), "the session route");
        let id = device().id;
        assert_eq!(DeviceChoice::Device(id.clone()).to_string(), id.to_string());
        assert_eq!(
            DeviceChoice::Preferred(id.clone()).to_string(),
            format!("{id}, or the session route")
        );
    }

    #[test]
    fn a_lost_device_reads_as_a_sentence() {
        assert_eq!(
            StreamEvent::DeviceLost.to_string(),
            "the device the stream was on is gone"
        );
    }

    #[test]
    fn nothing_pending_hands_back_nothing() {
        let pending = Pending::new();
        assert_eq!(pending.take(), None);
    }

    #[test]
    fn every_kind_comes_back_once() {
        let pending = Pending::new();
        pending.note(DeviceEvent::ListChanged);
        pending.note(DeviceEvent::DefaultChanged(Direction::Input));
        pending.note(DeviceEvent::DefaultChanged(Direction::Output));

        assert_eq!(pending.take(), Some(DeviceEvent::ListChanged));
        assert_eq!(
            pending.take(),
            Some(DeviceEvent::DefaultChanged(Direction::Input))
        );
        assert_eq!(
            pending.take(),
            Some(DeviceEvent::DefaultChanged(Direction::Output))
        );
        assert_eq!(pending.take(), None);
    }

    #[test]
    fn the_same_change_twice_is_still_one_change() {
        let pending = Pending::new();
        pending.note(DeviceEvent::ListChanged);
        pending.note(DeviceEvent::ListChanged);
        assert_eq!(pending.take(), Some(DeviceEvent::ListChanged));
        assert_eq!(pending.take(), None);
    }

    #[test]
    fn a_listener_thread_and_a_polling_caller_agree() {
        use std::sync::Arc;
        use std::thread;

        let pending = Arc::new(Pending::new());
        let listener = {
            let pending = Arc::clone(&pending);
            thread::spawn(move || {
                for _ in 0..10_000 {
                    pending.note(DeviceEvent::ListChanged);
                }
            })
        };

        let mut seen = 0;
        for _ in 0..10_000 {
            if pending.take().is_some() {
                seen += 1;
            }
        }
        listener.join().unwrap();

        // coalescing means fewer come out than went in, and nothing is lost:
        // either a change was handed over or one is still waiting
        assert!(seen <= 10_000);
        let waiting = pending.take();
        assert!(seen > 0 || waiting == Some(DeviceEvent::ListChanged));
        assert_eq!(pending.take(), None);
    }
}
