// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where a call's audio can go on a phone, and moving it there.
//!
//! AAudio opens streams and lists nothing: the devices a call can use are
//! `AudioManager`'s, a Java API, and so is routing a call between them. This
//! module is everything about that which is not Java — which platform
//! entries make one device, what each is called, which one the call is on,
//! how a choice is carried out on each API level, and what changed since the
//! last look — written against [`Platform`], so that all of it runs on a
//! machine with no phone attached. The one implementation that talks to a
//! phone is the JNI shim's bridge (`crate::bridge`, Android only).
//!
//! # Routing
//!
//! A voice-communication stream does not choose its output: the platform
//! puts it on the *communication device*, which is the earpiece until
//! something says otherwise. From API level 31 that something is
//! `AudioManager.setCommunicationDevice`, given one of
//! `getAvailableCommunicationDevices`. Before it, the same four outcomes were
//! reached with two switches: `setSpeakerphoneOn` for the loudspeaker, and
//! `startBluetoothSco` with `setBluetoothScoOn` for a Bluetooth headset;
//! with both off the platform picks a wired headset when one is plugged in
//! and the earpiece when none is. Both are carried out here, by API level
//! ([`COMMUNICATION_DEVICE_API`]).
//!
//! A microphone is chosen differently: an input stream names its device
//! (`AAudioStreamBuilder_setDeviceId`), and one that names none follows the
//! communication device — a Bluetooth headset's microphone comes with its
//! earpiece.
//!
//! # Changes
//!
//! The platform announces device changes to a Java callback, which a native
//! library cannot register without a class of its own. So [`Routes`] looks
//! instead: at most every [`POLL_INTERVAL`], the list and the communication
//! device are read again and compared with the last look. A route this crate
//! changed itself is taken in without being announced for [`SETTLE`]
//! afterwards — the platform applies it asynchronously, and a change the
//! engine made must not come back to it as one the system made.

use core::fmt;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The API level `AudioManager.setCommunicationDevice` arrived in.
pub const COMMUNICATION_DEVICE_API: u32 = 31;

/// How often the platform's list is read again for changes.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long after this crate moved the route a change of the default output
/// is taken as its own doing rather than announced.
pub const SETTLE: Duration = Duration::from_millis(1500);

/// One entry of `AudioManager.getDevices(GET_DEVICES_ALL)`, as the platform
/// reports it. A headset is two entries, one source and one sink, with the
/// same type and address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformDevice {
    /// `AudioDeviceInfo.getId`: what a stream is opened on and a route set
    /// to. Valid while the device is connected; a device plugged in again
    /// gets a new one.
    pub id: i32,
    /// `AudioDeviceInfo.getType`, one of its `TYPE_*` constants.
    pub type_code: i32,
    /// Whether it captures.
    pub source: bool,
    /// Whether it plays.
    pub sink: bool,
    /// The most channels it offers, or zero when it lists none — which
    /// `AudioDeviceInfo.getChannelCounts` documents as "any".
    pub channels: u32,
    /// `AudioDeviceInfo.getAddress`: a Bluetooth device's hardware address,
    /// a USB device's card and device, a built-in microphone's position;
    /// empty for most built-in devices.
    pub address: String,
    /// `AudioDeviceInfo.getProductName`.
    pub product: String,
}

/// What kind of device an entry is, for the types a call can use.
///
/// The discriminants are `AudioDeviceInfo`'s own `TYPE_*` values. Every
/// other type — a telephony uplink, a remote submix, an FM tuner, an HDMI
/// sink, the Bluetooth media (A2DP) profile, which carries no microphone and
/// is not where the platform routes a call — is left out of the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// `TYPE_BUILTIN_EARPIECE`.
    Earpiece = 1,
    /// `TYPE_BUILTIN_SPEAKER`.
    Speaker = 2,
    /// `TYPE_WIRED_HEADSET`: headphones with a microphone.
    WiredHeadset = 3,
    /// `TYPE_WIRED_HEADPHONES`: without one.
    WiredHeadphones = 4,
    /// `TYPE_BLUETOOTH_SCO`: a Bluetooth headset on the profile calls use.
    BluetoothHeadset = 7,
    /// `TYPE_USB_DEVICE`.
    UsbDevice = 11,
    /// `TYPE_BUILTIN_MIC`.
    Microphone = 15,
    /// `TYPE_USB_HEADSET`.
    UsbHeadset = 22,
    /// `TYPE_HEARING_AID`.
    HearingAid = 23,
    /// `TYPE_BLE_HEADSET`.
    BleHeadset = 26,
    /// `TYPE_BLE_SPEAKER`.
    BleSpeaker = 27,
}

impl Kind {
    /// The kind of an `AudioDeviceInfo` type, or `None` for one a call does
    /// not use.
    #[must_use]
    pub const fn of(type_code: i32) -> Option<Self> {
        Some(match type_code {
            1 => Self::Earpiece,
            2 => Self::Speaker,
            3 => Self::WiredHeadset,
            4 => Self::WiredHeadphones,
            7 => Self::BluetoothHeadset,
            11 => Self::UsbDevice,
            15 => Self::Microphone,
            22 => Self::UsbHeadset,
            23 => Self::HearingAid,
            26 => Self::BleHeadset,
            27 => Self::BleSpeaker,
            _ => return None,
        })
    }

    /// The word an identity is built from: stable, lower case, no spaces.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Earpiece => "earpiece",
            Self::Speaker => "speaker",
            Self::WiredHeadset => "wired-headset",
            Self::WiredHeadphones => "wired-headphones",
            Self::BluetoothHeadset => "bluetooth-sco",
            Self::UsbDevice => "usb-device",
            Self::Microphone => "microphone",
            Self::UsbHeadset => "usb-headset",
            Self::HearingAid => "hearing-aid",
            Self::BleHeadset => "ble-headset",
            Self::BleSpeaker => "ble-speaker",
        }
    }

    /// What a person calls it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Earpiece => "Earpiece",
            Self::Speaker => "Speaker",
            Self::WiredHeadset => "Wired headset",
            Self::WiredHeadphones => "Wired headphones",
            Self::BluetoothHeadset => "Bluetooth headset",
            Self::UsbDevice => "USB audio",
            Self::Microphone => "Microphone",
            Self::UsbHeadset => "USB headset",
            Self::HearingAid => "Hearing aid",
            Self::BleHeadset => "Bluetooth LE headset",
            Self::BleSpeaker => "Bluetooth LE speaker",
        }
    }

    /// Whether it is part of the phone, and so named by its kind rather
    /// than by a product name that is the phone's own.
    const fn built_in(self) -> bool {
        matches!(self, Self::Earpiece | Self::Speaker | Self::Microphone)
    }

    /// Whether, before API level 31, the platform routes a call to it on
    /// its own once it is connected and neither switch is on.
    const fn plugged(self) -> bool {
        matches!(
            self,
            Self::WiredHeadset | Self::WiredHeadphones | Self::UsbHeadset | Self::UsbDevice
        )
    }
}

/// One device as this crate lists it: a source and a sink of the same kind
/// and address, merged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// Stable across a reconnection, unlike the platform's id:
    /// `android:<kind>` for a device the phone has one of, and
    /// `android:<kind>:<address>` for one that has an address.
    pub identity: String,
    /// What it is called.
    pub name: String,
    /// What kind it is.
    pub kind: Kind,
    /// Channels it captures; zero for a device that is no microphone.
    pub input_channels: u32,
    /// Channels it plays; zero for a device that is no speaker.
    pub output_channels: u32,
    /// The platform's id for its microphone half.
    pub source: Option<i32>,
    /// The platform's id for its speaker half.
    pub sink: Option<i32>,
    /// Whether a call's microphone is on it when nothing is chosen.
    pub default_input: bool,
    /// Whether a call's audio is on it when nothing is chosen.
    pub default_output: bool,
}

/// The platform's list, merged into devices, in the order the platform
/// first named each.
#[must_use]
pub fn catalog(entries: &[PlatformDevice]) -> Vec<Device> {
    let mut devices: Vec<Device> = Vec::new();
    for entry in entries {
        let Some(kind) = Kind::of(entry.type_code) else {
            continue;
        };
        let identity = if entry.address.is_empty() {
            format!("android:{}", kind.slug())
        } else {
            format!("android:{}:{}", kind.slug(), entry.address)
        };
        let channels = entry.channels.max(1);
        let at = if let Some(at) = devices.iter().position(|known| known.identity == identity) {
            at
        } else {
            devices.push(Device {
                name: name_of(kind, entry),
                identity,
                kind,
                input_channels: 0,
                output_channels: 0,
                source: None,
                sink: None,
                default_input: false,
                default_output: false,
            });
            devices.len() - 1
        };
        let Some(device) = devices.get_mut(at) else {
            continue;
        };
        if entry.source && device.source.is_none() {
            device.source = Some(entry.id);
            device.input_channels = channels;
        }
        if entry.sink && device.sink.is_none() {
            device.sink = Some(entry.id);
            device.output_channels = channels;
        }
    }
    devices
}

fn name_of(kind: Kind, entry: &PlatformDevice) -> String {
    let product = entry.product.trim();
    if kind.built_in() || product.is_empty() {
        if kind == Kind::Microphone && !entry.address.is_empty() {
            format!("{} ({})", kind.label(), entry.address)
        } else {
            kind.label().to_owned()
        }
    } else {
        product.to_owned()
    }
}

/// What a phone's audio routing is made of: `AudioManager`, reached from
/// Rust through the JNI shim, or a fake in a test.
pub trait Platform: Send {
    /// The API level the process runs on.
    fn sdk(&self) -> u32;
    /// `AudioManager.getDevices(GET_DEVICES_ALL)`, or `None` when there is
    /// nothing to ask: no application context was handed over, or the call
    /// failed.
    fn devices(&mut self) -> Option<Vec<PlatformDevice>>;
    /// `AudioManager.getCommunicationDevice`'s id, from API level 31.
    fn communication_device(&mut self) -> Option<i32>;
    /// `AudioManager.setCommunicationDevice` on the sink with `id`, and
    /// whether the platform took it.
    fn set_communication_device(&mut self, id: i32) -> bool;
    /// `AudioManager.clearCommunicationDevice`.
    fn clear_communication_device(&mut self);
    /// `AudioManager.isSpeakerphoneOn`.
    fn speakerphone(&mut self) -> bool;
    /// `AudioManager.setSpeakerphoneOn`.
    fn set_speakerphone(&mut self, on: bool);
    /// `AudioManager.isBluetoothScoOn`.
    fn bluetooth_sco(&mut self) -> bool;
    /// `startBluetoothSco` and `setBluetoothScoOn(true)`, or
    /// `setBluetoothScoOn(false)` and `stopBluetoothSco`.
    fn set_bluetooth_sco(&mut self, on: bool);
}

/// What changed since the last look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A device arrived or left.
    ListChanged,
    /// The device a call's audio goes to when nothing is chosen moved.
    DefaultOutputChanged,
    /// The same for the microphone.
    DefaultInputChanged,
}

/// Why a route could not be set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteError {
    /// Nothing with that identity is connected.
    Absent(String),
    /// It is connected, and plays nothing.
    NotAnOutput(String),
    /// The platform refused to route calls to it.
    Refused(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Absent(ref identity) => write!(f, "{identity} is not connected"),
            Self::NotAnOutput(ref name) => write!(f, "{name} plays nothing"),
            Self::Refused(ref name) => {
                write!(f, "the platform does not route calls to {name}")
            }
        }
    }
}

impl std::error::Error for RouteError {}

/// What the last look saw, to compare the next one with.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Look {
    present: Vec<(String, bool, bool)>,
    output: Option<String>,
    input: Option<String>,
}

impl Look {
    fn of(devices: &[Device]) -> Self {
        let mut present: Vec<(String, bool, bool)> = devices
            .iter()
            .map(|device| {
                (
                    device.identity.clone(),
                    device.input_channels > 0,
                    device.output_channels > 0,
                )
            })
            .collect();
        present.sort();
        let default = |pick: fn(&Device) -> bool| {
            devices
                .iter()
                .find(|device| pick(device))
                .map(|device| device.identity.clone())
        };
        Self {
            present,
            output: default(|device| device.default_output),
            input: default(|device| device.default_input),
        }
    }
}

/// A phone's devices, the route of its calls, and what changed.
pub struct Routes<P> {
    platform: P,
    last: Option<Look>,
    looked_at: Option<Instant>,
    pending: VecDeque<Notice>,
    routed: bool,
    settle_until: Option<Instant>,
}

impl<P: Platform> Routes<P> {
    /// Over `platform`, with nothing looked at yet: the first look is the
    /// baseline the second is compared with.
    pub const fn new(platform: P) -> Self {
        Self {
            platform,
            last: None,
            looked_at: None,
            pending: VecDeque::new(),
            routed: false,
            settle_until: None,
        }
    }

    /// Every device a call can use, as the platform has them now, with the
    /// defaults marked. Empty when there is nothing to ask.
    pub fn devices(&mut self) -> Vec<Device> {
        let Some(entries) = self.platform.devices() else {
            return Vec::new();
        };
        let mut devices = catalog(&entries);
        let output = self.default_output(&devices);
        if let Some(device) = output.and_then(|at| devices.get_mut(at)) {
            device.default_output = true;
        }
        let input = output
            .filter(|&at| {
                devices
                    .get(at)
                    .is_some_and(|device| device.source.is_some())
            })
            .or_else(|| {
                devices
                    .iter()
                    .position(|device| device.kind == Kind::Microphone)
            })
            .or_else(|| devices.iter().position(|device| device.source.is_some()));
        if let Some(device) = input.and_then(|at| devices.get_mut(at)) {
            device.default_input = true;
        }
        devices
    }

    /// Where a call's audio goes when nothing is chosen: the communication
    /// device from API level 31, and before it what the two switches and a
    /// plugged-in headset make of it.
    fn default_output(&mut self, devices: &[Device]) -> Option<usize> {
        let sinks = |kind: Kind| {
            devices
                .iter()
                .position(|device| device.kind == kind && device.sink.is_some())
        };
        if self.platform.sdk() >= COMMUNICATION_DEVICE_API
            && let Some(id) = self.platform.communication_device()
            && let Some(at) = devices.iter().position(|device| device.sink == Some(id))
        {
            return Some(at);
        }
        if self.platform.bluetooth_sco()
            && let Some(at) = sinks(Kind::BluetoothHeadset)
        {
            return Some(at);
        }
        if self.platform.speakerphone()
            && let Some(at) = sinks(Kind::Speaker)
        {
            return Some(at);
        }
        devices
            .iter()
            .position(|device| device.kind.plugged() && device.sink.is_some())
            .or_else(|| sinks(Kind::Earpiece))
            .or_else(|| devices.iter().position(|device| device.sink.is_some()))
    }

    /// The platform's id for the microphone half of `identity`.
    pub fn source_of(&mut self, identity: &str) -> Option<i32> {
        self.devices()
            .into_iter()
            .find(|device| device.identity == identity)
            .and_then(|device| device.source)
    }

    /// The platform's id for the speaker half of `identity`.
    pub fn sink_of(&mut self, identity: &str) -> Option<i32> {
        self.devices()
            .into_iter()
            .find(|device| device.identity == identity)
            .and_then(|device| device.sink)
    }

    /// The identity of the device the platform calls `id`, which is where
    /// a stream reports it landed.
    pub fn identity_of(&mut self, id: i32) -> Option<String> {
        self.devices()
            .into_iter()
            .find(|device| device.source == Some(id) || device.sink == Some(id))
            .map(|device| device.identity)
    }

    /// The identity of the device a call's audio goes to now.
    pub fn default_output_identity(&mut self) -> Option<String> {
        self.devices()
            .into_iter()
            .find(|device| device.default_output)
            .map(|device| device.identity)
    }

    /// The identity of the device a call's microphone is on now.
    pub fn default_input_identity(&mut self) -> Option<String> {
        self.devices()
            .into_iter()
            .find(|device| device.default_input)
            .map(|device| device.identity)
    }

    /// Put every call's audio on `identity`.
    ///
    /// # Errors
    /// [`RouteError::Absent`] when it is not connected,
    /// [`RouteError::NotAnOutput`] when it plays nothing, and
    /// [`RouteError::Refused`] when the platform would not take it.
    pub fn route_to(&mut self, identity: &str, now: Instant) -> Result<(), RouteError> {
        let device = self
            .devices()
            .into_iter()
            .find(|device| device.identity == identity)
            .ok_or_else(|| RouteError::Absent(identity.to_owned()))?;
        let sink = device
            .sink
            .ok_or_else(|| RouteError::NotAnOutput(device.name.clone()))?;
        if self.platform.sdk() >= COMMUNICATION_DEVICE_API {
            if !self.platform.set_communication_device(sink) {
                return Err(RouteError::Refused(device.name));
            }
        } else {
            let (speaker, sco) = match device.kind {
                Kind::Speaker => (true, false),
                Kind::BluetoothHeadset => (false, true),
                _ => (false, false),
            };
            // off before on: the platform takes the speaker and a
            // Bluetooth headset as exclusive, and asked for both at once
            // keeps whichever it was told last
            if !sco {
                self.platform.set_bluetooth_sco(false);
            }
            if !speaker {
                self.platform.set_speakerphone(false);
            }
            if speaker {
                self.platform.set_speakerphone(true);
            }
            if sco {
                self.platform.set_bluetooth_sco(true);
            }
        }
        self.routed = true;
        self.settle_until = Some(now + SETTLE);
        Ok(())
    }

    /// Give the route back to the platform, if this crate took it.
    pub fn release(&mut self, now: Instant) {
        if !self.routed {
            return;
        }
        if self.platform.sdk() >= COMMUNICATION_DEVICE_API {
            self.platform.clear_communication_device();
        } else {
            self.platform.set_bluetooth_sco(false);
            self.platform.set_speakerphone(false);
        }
        self.routed = false;
        self.settle_until = Some(now + SETTLE);
    }

    /// Whether this crate holds the route.
    pub const fn routed(&self) -> bool {
        self.routed
    }

    /// What changed since the last look, one at a time. Looks again only
    /// once [`POLL_INTERVAL`] has passed since the last time it did.
    pub fn poll_notice(&mut self, now: Instant) -> Option<Notice> {
        if let Some(notice) = self.pending.pop_front() {
            return Some(notice);
        }
        if self
            .looked_at
            .is_some_and(|then| now.saturating_duration_since(then) < POLL_INTERVAL)
        {
            return None;
        }
        self.looked_at = Some(now);
        let devices = self.devices();
        let look = Look::of(&devices);
        let settling = self.settle_until.is_some_and(|until| now < until);
        if let Some(last) = self.last.as_ref() {
            if look.present != last.present {
                self.pending.push_back(Notice::ListChanged);
            }
            if look.output != last.output && !settling {
                self.pending.push_back(Notice::DefaultOutputChanged);
            }
            if look.input != last.input && !settling {
                self.pending.push_back(Notice::DefaultInputChanged);
            }
        }
        self.last = Some(look);
        self.pending.pop_front()
    }

    /// The platform underneath.
    pub fn platform(&mut self) -> &mut P {
        &mut self.platform
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMUNICATION_DEVICE_API, Kind, Notice, POLL_INTERVAL, Platform, PlatformDevice,
        RouteError, Routes, SETTLE, catalog,
    };
    use std::time::{Duration, Instant};

    fn entry(id: i32, type_code: i32, source: bool, sink: bool, address: &str) -> PlatformDevice {
        PlatformDevice {
            id,
            type_code,
            source,
            sink,
            channels: 0,
            address: address.to_owned(),
            product: "Pixel 9".to_owned(),
        }
    }

    /// A phone's built-in devices, as `getDevices` lists them.
    fn phone() -> Vec<PlatformDevice> {
        vec![
            entry(1, 1, false, true, ""),
            entry(2, 2, false, true, ""),
            entry(3, 15, true, false, "bottom"),
            entry(4, 15, true, false, "back"),
            entry(5, 18, true, true, ""),
            entry(6, 25, true, true, "0"),
        ]
    }

    /// A Bluetooth headset: its call profile twice, and its media profile.
    fn headset() -> Vec<PlatformDevice> {
        vec![
            PlatformDevice {
                product: "Buds".to_owned(),
                ..entry(20, 7, false, true, "AA:BB:CC:DD:EE:FF")
            },
            PlatformDevice {
                product: "Buds".to_owned(),
                ..entry(21, 7, true, false, "AA:BB:CC:DD:EE:FF")
            },
            PlatformDevice {
                product: "Buds".to_owned(),
                ..entry(22, 8, false, true, "AA:BB:CC:DD:EE:FF")
            },
        ]
    }

    #[derive(Default)]
    struct Fake {
        sdk: u32,
        entries: Option<Vec<PlatformDevice>>,
        communication: Option<i32>,
        refuse: bool,
        speaker: bool,
        sco: bool,
        calls: Vec<String>,
    }

    impl Platform for Fake {
        fn sdk(&self) -> u32 {
            self.sdk
        }
        fn devices(&mut self) -> Option<Vec<PlatformDevice>> {
            self.entries.clone()
        }
        fn communication_device(&mut self) -> Option<i32> {
            self.communication
        }
        fn set_communication_device(&mut self, id: i32) -> bool {
            self.calls.push(format!("set {id}"));
            if self.refuse {
                return false;
            }
            self.communication = Some(id);
            true
        }
        fn clear_communication_device(&mut self) {
            self.calls.push("clear".to_owned());
            self.communication = None;
        }
        fn speakerphone(&mut self) -> bool {
            self.speaker
        }
        fn set_speakerphone(&mut self, on: bool) {
            self.calls.push(format!("speaker {on}"));
            self.speaker = on;
        }
        fn bluetooth_sco(&mut self) -> bool {
            self.sco
        }
        fn set_bluetooth_sco(&mut self, on: bool) {
            self.calls.push(format!("sco {on}"));
            self.sco = on;
        }
    }

    fn over(sdk: u32, entries: Vec<PlatformDevice>) -> Routes<Fake> {
        Routes::new(Fake {
            sdk,
            entries: Some(entries),
            ..Fake::default()
        })
    }

    fn identities(routes: &mut Routes<Fake>) -> Vec<String> {
        routes
            .devices()
            .into_iter()
            .map(|device| device.identity)
            .collect()
    }

    #[test]
    fn a_headsets_two_halves_are_one_device_and_what_a_call_cannot_use_is_left_out() {
        let mut all = phone();
        all.extend(headset());
        let devices = catalog(&all);
        let listed: Vec<(&str, &str, u32, u32)> = devices
            .iter()
            .map(|device| {
                (
                    device.identity.as_str(),
                    device.name.as_str(),
                    device.input_channels,
                    device.output_channels,
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                ("android:earpiece", "Earpiece", 0, 1),
                ("android:speaker", "Speaker", 0, 1),
                ("android:microphone:bottom", "Microphone (bottom)", 1, 0),
                ("android:microphone:back", "Microphone (back)", 1, 0),
                ("android:bluetooth-sco:AA:BB:CC:DD:EE:FF", "Buds", 1, 1),
            ]
        );
        let buds = devices.last().unwrap();
        assert_eq!((buds.source, buds.sink), (Some(21), Some(20)));
        assert_eq!(buds.kind, Kind::BluetoothHeadset);
    }

    #[test]
    fn a_channel_count_the_platform_leaves_open_is_one_and_a_listed_one_is_kept() {
        let devices = catalog(&[PlatformDevice {
            channels: 2,
            ..entry(9, 22, true, true, "card=1;device=0")
        }]);
        assert_eq!(devices.first().unwrap().input_channels, 2);
        assert_eq!(devices.first().unwrap().output_channels, 2);
        assert_eq!(devices.first().unwrap().name, "Pixel 9");
    }

    #[test]
    fn from_api_31_the_default_is_the_communication_device_and_its_microphone_comes_with_it() {
        let mut all = phone();
        all.extend(headset());
        let mut routes = over(COMMUNICATION_DEVICE_API, all);
        routes.platform().communication = Some(1);
        assert_eq!(
            routes.default_output_identity().as_deref(),
            Some("android:earpiece")
        );
        assert_eq!(
            routes.default_input_identity().as_deref(),
            Some("android:microphone:bottom")
        );
        routes.platform().communication = Some(20);
        assert_eq!(
            routes.default_output_identity().as_deref(),
            Some("android:bluetooth-sco:AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            routes.default_input_identity().as_deref(),
            Some("android:bluetooth-sco:AA:BB:CC:DD:EE:FF")
        );
    }

    #[test]
    fn before_api_31_the_default_is_what_the_switches_and_a_plugged_headset_make_of_it() {
        let mut all = phone();
        all.extend(headset());
        let mut routes = over(28, all);
        assert_eq!(
            routes.default_output_identity().as_deref(),
            Some("android:earpiece")
        );
        routes.platform().speaker = true;
        assert_eq!(
            routes.default_output_identity().as_deref(),
            Some("android:speaker")
        );
        routes.platform().sco = true;
        assert_eq!(
            routes.default_output_identity().as_deref(),
            Some("android:bluetooth-sco:AA:BB:CC:DD:EE:FF")
        );
        let mut wired = over(28, {
            let mut all = phone();
            all.push(entry(30, 3, false, true, ""));
            all.push(entry(31, 3, true, false, ""));
            all
        });
        assert_eq!(
            wired.default_output_identity().as_deref(),
            Some("android:wired-headset")
        );
        assert_eq!(
            wired.default_input_identity().as_deref(),
            Some("android:wired-headset")
        );
    }

    #[test]
    fn from_api_31_a_route_is_the_communication_device_and_a_refusal_is_said() {
        let mut all = phone();
        all.extend(headset());
        let mut routes = over(COMMUNICATION_DEVICE_API, all);
        let now = Instant::now();
        routes.route_to("android:speaker", now).unwrap();
        assert_eq!(routes.platform().calls, ["set 2"]);
        assert!(routes.routed());
        routes.release(now);
        assert_eq!(routes.platform().calls, ["set 2", "clear"]);
        assert!(!routes.routed());
        routes.release(now);
        assert_eq!(routes.platform().calls.len(), 2, "released once, not twice");

        routes.platform().refuse = true;
        assert_eq!(
            routes.route_to("android:bluetooth-sco:AA:BB:CC:DD:EE:FF", now),
            Err(RouteError::Refused("Buds".to_owned()))
        );
        assert!(!routes.routed());
        assert_eq!(
            routes.route_to("android:microphone:back", now),
            Err(RouteError::NotAnOutput("Microphone (back)".to_owned()))
        );
        assert_eq!(
            routes.route_to("android:wired-headset", now),
            Err(RouteError::Absent("android:wired-headset".to_owned()))
        );
    }

    #[test]
    fn before_api_31_a_route_is_the_two_switches_and_releasing_turns_both_off() {
        let mut all = phone();
        all.extend(headset());
        let mut routes = over(30, all);
        let now = Instant::now();
        routes
            .route_to("android:bluetooth-sco:AA:BB:CC:DD:EE:FF", now)
            .unwrap();
        assert_eq!(routes.platform().calls, ["speaker false", "sco true"]);
        routes.route_to("android:speaker", now).unwrap();
        assert!(routes.platform().speaker && !routes.platform().sco);
        routes.route_to("android:earpiece", now).unwrap();
        assert!(!routes.platform().speaker && !routes.platform().sco);
        assert_eq!(
            routes.default_output_identity().as_deref(),
            Some("android:earpiece")
        );
        routes.platform().calls.clear();
        routes.release(now);
        assert_eq!(routes.platform().calls, ["sco false", "speaker false"]);
    }

    #[test]
    fn nothing_to_ask_is_an_empty_list_and_no_notice() {
        let mut routes = Routes::new(Fake {
            sdk: 34,
            ..Fake::default()
        });
        assert!(routes.devices().is_empty());
        let start = Instant::now();
        assert_eq!(routes.poll_notice(start), None);
        assert_eq!(routes.poll_notice(start + POLL_INTERVAL), None);
        assert_eq!(
            routes.route_to("android:speaker", start),
            Err(RouteError::Absent("android:speaker".to_owned()))
        );
    }

    #[test]
    fn a_headset_arriving_is_a_list_change_and_the_system_moving_the_call_to_it_a_default_change() {
        let mut routes = over(34, phone());
        routes.platform().communication = Some(1);
        let start = Instant::now();
        assert_eq!(
            routes.poll_notice(start),
            None,
            "the first look is the baseline"
        );

        let mut all = phone();
        all.extend(headset());
        routes.platform().entries = Some(all);
        assert_eq!(
            routes.poll_notice(start + Duration::from_millis(100)),
            None,
            "not looked at again before the interval"
        );
        let later = start + POLL_INTERVAL;
        assert_eq!(routes.poll_notice(later), Some(Notice::ListChanged));
        assert_eq!(routes.poll_notice(later), None);

        routes.platform().communication = Some(20);
        let later = later + POLL_INTERVAL;
        assert_eq!(
            routes.poll_notice(later),
            Some(Notice::DefaultOutputChanged)
        );
        assert_eq!(routes.poll_notice(later), Some(Notice::DefaultInputChanged));
        assert_eq!(routes.poll_notice(later), None);
        assert!(
            identities(&mut routes).contains(&"android:bluetooth-sco:AA:BB:CC:DD:EE:FF".to_owned())
        );

        routes.platform().entries = Some(phone());
        routes.platform().communication = Some(1);
        let later = later + POLL_INTERVAL;
        assert_eq!(routes.poll_notice(later), Some(Notice::ListChanged));
        assert_eq!(
            routes.poll_notice(later),
            Some(Notice::DefaultOutputChanged)
        );
    }

    #[test]
    fn a_route_this_crate_set_is_not_announced_back_and_a_later_one_is() {
        let mut routes = over(34, phone());
        routes.platform().communication = Some(1);
        let start = Instant::now();
        assert_eq!(routes.poll_notice(start), None);

        routes.route_to("android:speaker", start).unwrap();
        let later = start + POLL_INTERVAL;
        assert_eq!(routes.poll_notice(later), None, "the engine's own move");

        routes.platform().communication = Some(1);
        let later = start + SETTLE + POLL_INTERVAL;
        assert_eq!(
            routes.poll_notice(later),
            Some(Notice::DefaultOutputChanged),
            "the system moving it back, once the route has settled"
        );
    }
}
