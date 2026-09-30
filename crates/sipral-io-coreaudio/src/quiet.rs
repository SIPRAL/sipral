// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Where a test that opens this machine's real devices plays and records.
//!
//! A virtual loopback device when the machine has one — `BlackHole 2ch`, which
//! plays nowhere and hands back what it was given — so that a gate run on a
//! laptop never sounds through its loudspeaker or listens to its room. A
//! machine without one is tested on the system's route, as it always was.
//! Tests only: nothing an application opens goes through here.

use crate::device::{Device, DeviceChoice};
#[cfg(target_os = "macos")]
use crate::status::Error;

/// The name the virtual device carries, exactly.
pub(crate) const QUIET_DEVICE: &str = "BlackHole 2ch";

/// The quiet device among `devices`: the one named [`QUIET_DEVICE`], able to
/// both play and record, and carrying the identity a choice is saved by.
pub(crate) fn quiet_among(devices: &[Device]) -> Option<&Device> {
    devices.iter().find(|device| {
        device.name == QUIET_DEVICE
            && device.is_input()
            && device.is_output()
            && device.uid.is_some()
    })
}

/// What a test opens both halves of a stream on: the quiet device when
/// `devices` has it, and the system's route otherwise.
pub(crate) fn route_among(devices: &[Device]) -> DeviceChoice {
    quiet_among(devices)
        .and_then(|device| device.uid.clone())
        .map_or(DeviceChoice::System, DeviceChoice::Preferred)
}

/// [`route_among`] this machine's devices, and the quiet device itself when
/// that is where it leads.
///
/// # Errors
/// Whatever listing the devices answers.
#[cfg(target_os = "macos")]
pub(crate) fn route() -> Result<(DeviceChoice, Option<Device>), Error> {
    let devices = crate::hal::devices()?;
    Ok((route_among(&devices), quiet_among(&devices).cloned()))
}

#[cfg(test)]
mod tests {
    use super::{QUIET_DEVICE, quiet_among, route_among};
    use crate::device::{Device, DeviceChoice, DeviceId};

    fn device(id: u32, name: &str, uid: Option<&str>, inputs: u32, outputs: u32) -> Device {
        Device {
            id: DeviceId::new(id),
            name: name.to_owned(),
            uid: uid.map(str::to_owned),
            input_channels: inputs,
            output_channels: outputs,
        }
    }

    fn laptop() -> Vec<Device> {
        vec![
            device(
                1,
                "MacBook Air Microphone",
                Some("BuiltInMicrophoneDevice"),
                1,
                0,
            ),
            device(
                2,
                "MacBook Air Speakers",
                Some("BuiltInSpeakerDevice"),
                0,
                2,
            ),
        ]
    }

    #[test]
    fn the_quiet_device_is_chosen_when_the_machine_has_it() {
        let mut devices = laptop();
        devices.push(device(3, QUIET_DEVICE, Some("BlackHole2ch_UID"), 2, 2));
        assert_eq!(
            quiet_among(&devices).map(|device| device.id),
            Some(DeviceId::new(3))
        );
        assert_eq!(
            route_among(&devices),
            DeviceChoice::Preferred("BlackHole2ch_UID".to_owned())
        );
    }

    #[test]
    fn without_it_the_system_route_is_what_it_always_was() {
        assert_eq!(quiet_among(&laptop()), None);
        assert_eq!(route_among(&laptop()), DeviceChoice::System);
        assert_eq!(route_among(&[]), DeviceChoice::System);
    }

    #[test]
    fn only_the_whole_device_by_its_exact_name_will_do() {
        for lookalike in [
            device(4, "BlackHole 16ch", Some("BlackHole16ch_UID"), 16, 16),
            device(5, "blackhole 2ch", Some("x"), 2, 2),
            device(6, QUIET_DEVICE, None, 2, 2),
            device(7, QUIET_DEVICE, Some("a"), 0, 2),
            device(8, QUIET_DEVICE, Some("b"), 2, 0),
        ] {
            let mut devices = laptop();
            devices.push(lookalike.clone());
            assert_eq!(route_among(&devices), DeviceChoice::System, "{lookalike:?}");
        }
    }
}
