// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Devices, and the fact that they come and go.
//!
//! A headset unplugged in the middle of a call is not an error, it is Tuesday.
//! Nothing above this crate should have to know that CoreAudio exists to cope
//! with it, so a route change arrives as an event the caller polls and answers
//! by asking for the list again.

use core::fmt;

/// One device, as the audio hardware layer numbers it.
///
/// The number is assigned when the device appears and is reused after it goes,
/// so it identifies a device only for as long as that device is there. What
/// survives a replug is [`Device::uid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Wrap an identifier the hardware layer gave out.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// The number underneath.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "device {}", self.0)
    }
}

/// Which way audio is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// From the microphone into the stack.
    Input,
    /// From the stack out to the speaker.
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

/// A device the machine has, at the moment it was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// What to name it in a configuration, until it is unplugged.
    pub id: DeviceId,
    /// What a person would call it. Empty when the device declines to say,
    /// which some virtual devices do.
    pub name: String,
    /// The identifier that survives a replug and a reboot, when the device has
    /// one. Worth storing if a preference has to outlive the session.
    pub uid: Option<String>,
    /// Channels it can capture. Zero means it is not an input at all.
    pub input_channels: u32,
    /// Channels it can play. Zero means it is not an output at all.
    pub output_channels: u32,
}

impl Device {
    /// Whether it can be captured from.
    #[must_use]
    pub const fn is_input(&self) -> bool {
        self.input_channels > 0
    }

    /// Whether it can be played to.
    #[must_use]
    pub const fn is_output(&self) -> bool {
        self.output_channels > 0
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} \"{}\", {} in, {} out",
            self.id, self.name, self.input_channels, self.output_channels
        )
    }
}

/// Something changed about the machine's audio hardware.
///
/// Every one of these means the same thing to the caller: ask again. They are
/// notifications, not a record — several changes in a row coalesce into one,
/// because acting on the second would give the same answer as acting on the
/// fifth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DeviceEvent {
    /// A device appeared or went away.
    ListChanged,
    /// The system's default device for a direction is now a different one.
    /// On a Mac this is what a headset being plugged in looks like.
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

/// The changes seen but not yet handed over.
///
/// A set of bits rather than a queue: the events are idempotent, the listener
/// runs on a thread owned by the framework, and a queue that a slow caller
/// stops draining would either grow without bound or lose the newest change,
/// which is the one that matters. Bits lose nothing and cost one word.
#[cfg(any(target_os = "macos", test))]
pub(crate) struct Pending(core::sync::atomic::AtomicU32);

#[cfg(any(target_os = "macos", test))]
impl Pending {
    const LIST: u32 = 1;
    const DEFAULT_INPUT: u32 = 2;
    const DEFAULT_OUTPUT: u32 = 4;

    pub(crate) const fn new() -> Self {
        Self(core::sync::atomic::AtomicU32::new(0))
    }

    /// Record a change. Called from the framework's listener thread.
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
    /// The compare-exchange rather than a plain `fetch_and` is the whole point:
    /// a change noted between reading the word and clearing the bit would be
    /// erased by an unconditional clear, and that is the report of the
    /// unplugging nobody hears.
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
    use super::{Device, DeviceEvent, DeviceId, Direction, Pending};

    fn device() -> Device {
        Device {
            id: DeviceId::new(51),
            name: "Studio Display Speakers".to_string(),
            uid: Some("AppleUSBAudioEngine:Apple Inc.:1".to_string()),
            input_channels: 0,
            output_channels: 2,
        }
    }

    #[test]
    fn a_device_says_which_way_it_goes() {
        let speaker = device();
        assert!(!speaker.is_input());
        assert!(speaker.is_output());
        assert_eq!(
            speaker.to_string(),
            "device 51 \"Studio Display Speakers\", 0 in, 2 out"
        );
    }

    #[test]
    fn an_identifier_is_the_number_it_was_given() {
        assert_eq!(DeviceId::new(51).get(), 51);
        assert_eq!(DeviceId::new(51).to_string(), "device 51");
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
