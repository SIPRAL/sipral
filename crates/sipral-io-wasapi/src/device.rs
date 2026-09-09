// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Endpoints, and the fact that they come and go.
//!
//! A headset unplugged in the middle of a call is not an error, it is Tuesday.
//! Nothing above this crate should have to know that WASAPI exists to cope with
//! it, so a change arrives as an event the caller polls and answers by asking
//! for the list again.

use core::fmt;

/// One endpoint, as Windows names it.
///
/// A string rather than a number, because that is what an endpoint identifier
/// is: something like `{0.0.1.00000000}.{a5b3...}`, stable across a replug and
/// across a reboot, and meant to be written into a configuration file. Nothing
/// in it is worth parsing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Wrap an identifier Windows gave out, or one read back from a
    /// configuration file.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The string underneath.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether it names nothing. An endpoint that will not say what it is
    /// called is still an endpoint; one with no identifier is not.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    /// From the microphone into the stack. `eCapture`, to Windows.
    Input,
    /// From the stack out to the speaker. `eRender`.
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

/// An endpoint the machine has, at the moment it was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// What to name it in a configuration. It outlives the session.
    pub id: DeviceId,
    /// What a person would call it — `PKEY_Device_FriendlyName`, which is the
    /// string the sound control panel shows. Empty when the endpoint declines
    /// to say, which some virtual devices do.
    pub name: String,
    /// Which way it carries audio. Windows endpoints are one direction each:
    /// a headset with a microphone is two of them.
    pub direction: Direction,
    /// Whether it is the machine's default for calls in that direction —
    /// `eCommunications`, not `eConsole`, because that is the one a person
    /// chooses for a softphone.
    pub is_default: bool,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} \"{}\"{}",
            self.direction,
            self.name,
            if self.is_default { ", default" } else { "" }
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
    /// An endpoint appeared, went away, or was enabled or disabled. On Windows
    /// these are four separate notifications and one answer.
    ListChanged,
    /// The system's default endpoint for a direction is now a different one.
    /// This is what plugging in a headset looks like.
    DefaultChanged(Direction),
}

impl fmt::Display for DeviceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ListChanged => f.write_str("the endpoint list changed"),
            Self::DefaultChanged(direction) => {
                write!(f, "the default {direction} endpoint changed")
            }
        }
    }
}

/// Which endpoint a stream should open, and what to do when it is not there.
///
/// The difference between the last two is the whole of what a saved selection
/// needs. [`DeviceChoice::Device`] opens that endpoint or nothing;
/// [`DeviceChoice::Preferred`] opens it if the machine has it and falls back
/// to the system's route for calls when it does not, which is what a
/// preference read out of a configuration file at start-up means.
///
/// Both carry the same string, because on Windows the identity a stream is
/// opened by is already the one that survives a replug and a reboot. What
/// differs is only what happens when the machine has no such endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DeviceChoice {
    /// Whatever Windows is routing calls to at the moment the stream opens.
    #[default]
    System,
    /// This endpoint, and no other.
    Device(DeviceId),
    /// This endpoint if the machine has it, and the system's route otherwise.
    Preferred(DeviceId),
}

impl fmt::Display for DeviceChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::System => f.write_str("the system route"),
            Self::Device(ref id) => write!(f, "{id}"),
            Self::Preferred(ref id) => write!(f, "{id}, or the system route"),
        }
    }
}

/// Something a stream noticed about the endpoint underneath it.
///
/// Not an [`Error`](crate::Error): a headset being unplugged during a call is
/// not a fault in anything, and the caller's answer to it is a decision rather
/// than a retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StreamEvent {
    /// The endpoint the stream was running on is gone — unplugged, disabled,
    /// or reconfigured from the sound control panel, all of which Windows
    /// reports the same way and none of which it lets a client carry on
    /// through.
    ///
    /// The stream stops rather than pretending: nothing more arrives from the
    /// microphone once what it had already captured has been read out, and the
    /// speaker ring fills up and takes no more. What puts an endpoint back
    /// under it is `CaptureStream::recover` or `PlaybackStream::recover`, and
    /// what that lands on is the stream's own [`DeviceChoice`] resolved again.
    DeviceLost,
}

impl fmt::Display for StreamEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DeviceLost => f.write_str("the endpoint the stream was on is gone"),
        }
    }
}

/// The changes seen but not yet handed over.
///
/// A set of bits rather than a queue: the events are idempotent, the
/// notifications arrive on a thread Windows owns, and a queue that a slow
/// caller stops draining would either grow without bound or lose the newest
/// change, which is the one that matters. Bits lose nothing and cost one word.
#[cfg(any(target_os = "windows", test))]
pub(crate) struct Pending(core::sync::atomic::AtomicU32);

#[cfg(any(target_os = "windows", test))]
impl Pending {
    const LIST: u32 = 1;
    const DEFAULT_INPUT: u32 = 2;
    const DEFAULT_OUTPUT: u32 = 4;

    pub(crate) const fn new() -> Self {
        Self(core::sync::atomic::AtomicU32::new(0))
    }

    /// Record a change. Called from the thread Windows delivers notifications
    /// on.
    pub(crate) fn note(&self, event: DeviceEvent) {
        let bit = match event {
            DeviceEvent::ListChanged => Self::LIST,
            DeviceEvent::DefaultChanged(Direction::Input) => Self::DEFAULT_INPUT,
            DeviceEvent::DefaultChanged(Direction::Output) => Self::DEFAULT_OUTPUT,
        };
        // Release: whatever the notification did before this is visible to the
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
    use super::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Pending, StreamEvent};

    fn cable() -> Device {
        Device {
            id: DeviceId::new("{0.0.0.00000000}.{c4d2f0a1-0000-0000-0000-000000000001}"),
            name: "CABLE In 16 Ch".to_string(),
            direction: Direction::Output,
            is_default: false,
        }
    }

    #[test]
    fn an_endpoint_says_which_way_it_goes() {
        let device = cable();
        assert_eq!(device.to_string(), "output \"CABLE In 16 Ch\"");
        let chosen = Device {
            is_default: true,
            ..device
        };
        assert_eq!(chosen.to_string(), "output \"CABLE In 16 Ch\", default");
    }

    #[test]
    fn an_identifier_is_the_string_it_was_given() {
        let id = DeviceId::new("{0.0.1.00000000}.{abc}");
        assert_eq!(id.as_str(), "{0.0.1.00000000}.{abc}");
        assert_eq!(id.to_string(), "{0.0.1.00000000}.{abc}");
        assert!(!id.is_empty());
        assert!(DeviceId::new(String::new()).is_empty());
    }

    #[test]
    fn events_read_as_sentences() {
        assert_eq!(
            DeviceEvent::ListChanged.to_string(),
            "the endpoint list changed"
        );
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Input).to_string(),
            "the default input endpoint changed"
        );
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Output).to_string(),
            "the default output endpoint changed"
        );
    }

    #[test]
    fn a_choice_says_what_it_would_open() {
        assert_eq!(DeviceChoice::default(), DeviceChoice::System);
        assert_eq!(DeviceChoice::System.to_string(), "the system route");
        let id = cable().id;
        assert_eq!(DeviceChoice::Device(id.clone()).to_string(), id.to_string());
        assert_eq!(
            DeviceChoice::Preferred(id.clone()).to_string(),
            format!("{id}, or the system route")
        );
        // the same endpoint, and two different answers to it being unplugged
        assert_ne!(
            DeviceChoice::Device(id.clone()),
            DeviceChoice::Preferred(id)
        );
    }

    #[test]
    fn a_lost_endpoint_reads_as_a_sentence() {
        assert_eq!(
            StreamEvent::DeviceLost.to_string(),
            "the endpoint the stream was on is gone"
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
        // Windows reports an unplug as a state change and often a removal too,
        // and the caller has the same one thing to do about both
        pending.note(DeviceEvent::ListChanged);
        pending.note(DeviceEvent::ListChanged);
        assert_eq!(pending.take(), Some(DeviceEvent::ListChanged));
        assert_eq!(pending.take(), None);
    }

    #[test]
    fn a_notification_thread_and_a_polling_caller_agree() {
        use std::sync::Arc;
        use std::thread;

        let pending = Arc::new(Pending::new());
        let notifier = {
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
        notifier.join().unwrap();

        // coalescing means fewer come out than went in, and nothing is lost:
        // either a change was handed over or one is still waiting
        assert!(seen <= 10_000);
        let waiting = pending.take();
        assert!(seen > 0 || waiting == Some(DeviceEvent::ListChanged));
        assert_eq!(pending.take(), None);
    }
}
