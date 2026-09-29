// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! `AudioManager`, reached through the Kotlin binding's JNI shim.
//!
//! Listing a phone's devices and routing a call between them are Java calls
//! on an `AudioManager`, which needs the application's `Context` to get and
//! a `JavaVM` to make. Both are the Kotlin binding's: its shim,
//! `libsipral_jni.so`, is the library a JVM loads, and
//! `SipralAndroidAudio.attach(context)` hands it the context. So the shim
//! makes the calls and this module only finds them: the shim exports one
//! function, `sipral_jni_audio_bridge`, returning a table of plain C
//! functions over the context it holds. The table is found in the library
//! already loaded (`RTLD_NOLOAD`), never by loading one — an application
//! that drives the C ABI from its own JNI has no such library, and gets an
//! empty list and the platform's own route, which is what a phone does
//! anyway.
//!
//! The table's layout is shared with
//! `bindings/kotlin/sipral/src/main/jni/audio_routes.c` and nothing else;
//! it is not part of `sipral.h`. Its first member is its own size, so a
//! shim older or newer than this library is read only as far as both know.

use core::ffi::c_char;
use core::mem::{offset_of, size_of};

use crate::api;
use crate::route::{Platform, PlatformDevice};

/// `sipral_jni_audio_device_t`: one `AudioDeviceInfo`, copied out.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawDevice {
    id: i32,
    type_code: i32,
    source: i32,
    sink: i32,
    channels: i32,
    address: [c_char; 64],
    product: [c_char; 128],
}

impl RawDevice {
    const EMPTY: Self = Self {
        id: 0,
        type_code: 0,
        source: 0,
        sink: 0,
        channels: 0,
        address: [0; 64],
        product: [0; 128],
    };
}

/// `sipral_jni_audio_bridge_t`. Every function answers a negative number
/// for "could not ask": no context attached, or the call threw.
#[repr(C)]
struct Table {
    size: u32,
    devices: unsafe extern "C" fn(out: *mut RawDevice, capacity: i32) -> i32,
    communication_device: unsafe extern "C" fn() -> i32,
    set_communication_device: unsafe extern "C" fn(id: i32) -> i32,
    clear_communication_device: unsafe extern "C" fn() -> i32,
    speakerphone: unsafe extern "C" fn(set: i32) -> i32,
    bluetooth_sco: unsafe extern "C" fn(set: i32) -> i32,
}

/// The most devices one look copies out. A phone has a handful; a hub full
/// of USB interfaces a few dozen.
const CAPACITY: usize = 64;

/// "Only ask": the argument that leaves a switch as it is.
const QUERY: i32 = -1;

fn text(raw: &[c_char]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// [`Platform`] over the JNI shim's table.
pub struct JniPlatform {
    table: Option<&'static Table>,
    sdk: u32,
}

impl JniPlatform {
    /// Find the shim's table in the process, if the Kotlin binding loaded
    /// it. Found or not, the platform answers: without it, with nothing.
    #[must_use]
    pub fn find() -> Self {
        Self {
            table: table(),
            sdk: api::sdk(),
        }
    }

    /// Whether the shim was found.
    #[must_use]
    pub fn connected(&self) -> bool {
        self.table.is_some()
    }
}

fn table() -> Option<&'static Table> {
    let library = api::open_library(c"libsipral_jni.so", api::RTLD_NOW | api::RTLD_NOLOAD)?;
    // SAFETY: the shim's function of this signature, never unloaded while
    // the process runs: a JVM does not unload a JNI library its classes use.
    let get: unsafe extern "C" fn() -> *const Table =
        unsafe { api::function(library, c"sipral_jni_audio_bridge") }?;
    // SAFETY: as above; the answer is a static table or null.
    let table = unsafe { get() };
    if table.is_null() {
        return None;
    }
    // SAFETY: a static table whose first member is its size.
    let size = unsafe { (*table).size } as usize;
    // every member this library calls, or none of them
    if size < offset_of!(Table, bluetooth_sco) + size_of::<usize>() {
        return None;
    }
    // SAFETY: as above, and long enough.
    Some(unsafe { &*table })
}

impl Platform for JniPlatform {
    fn sdk(&self) -> u32 {
        self.sdk
    }

    fn devices(&mut self) -> Option<Vec<PlatformDevice>> {
        let table = self.table?;
        let mut raw = vec![RawDevice::EMPTY; CAPACITY];
        let capacity = i32::try_from(raw.len()).unwrap_or(0);
        // SAFETY: a buffer of `capacity` entries the shim writes at most
        // that many of.
        let count = unsafe { (table.devices)(raw.as_mut_ptr(), capacity) };
        let count = usize::try_from(count).ok()?.min(raw.len());
        raw.truncate(count);
        Some(
            raw.iter()
                .map(|device| PlatformDevice {
                    id: device.id,
                    type_code: device.type_code,
                    source: device.source != 0,
                    sink: device.sink != 0,
                    channels: u32::try_from(device.channels).unwrap_or(0),
                    address: text(&device.address),
                    product: text(&device.product),
                })
                .collect(),
        )
    }

    fn communication_device(&mut self) -> Option<i32> {
        let table = self.table?;
        // SAFETY: a function of the shim's table.
        let id = unsafe { (table.communication_device)() };
        (id > 0).then_some(id)
    }

    fn set_communication_device(&mut self, id: i32) -> bool {
        // SAFETY: a function of the shim's table.
        self.table
            .is_some_and(|table| unsafe { (table.set_communication_device)(id) } == 1)
    }

    fn clear_communication_device(&mut self) {
        if let Some(table) = self.table {
            // SAFETY: a function of the shim's table.
            unsafe { (table.clear_communication_device)() };
        }
    }

    fn speakerphone(&mut self) -> bool {
        // SAFETY: a function of the shim's table.
        self.table
            .is_some_and(|table| unsafe { (table.speakerphone)(QUERY) } == 1)
    }

    fn set_speakerphone(&mut self, on: bool) {
        if let Some(table) = self.table {
            // SAFETY: a function of the shim's table.
            unsafe { (table.speakerphone)(i32::from(on)) };
        }
    }

    fn bluetooth_sco(&mut self) -> bool {
        // SAFETY: a function of the shim's table.
        self.table
            .is_some_and(|table| unsafe { (table.bluetooth_sco)(QUERY) } == 1)
    }

    fn set_bluetooth_sco(&mut self, on: bool) {
        if let Some(table) = self.table {
            // SAFETY: a function of the shim's table.
            unsafe { (table.bluetooth_sco)(i32::from(on)) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::JniPlatform;
    use crate::route::{Platform, Routes};

    /// A process no JVM loaded has no shim: nothing to ask, an empty list,
    /// and the platform's own route.
    #[test]
    fn without_the_kotlin_shim_there_is_nothing_to_ask() {
        let mut platform = JniPlatform::find();
        assert!(!platform.connected());
        assert!(platform.devices().is_none());
        assert!(!platform.set_communication_device(1));
        assert!(platform.sdk() > 0, "the API level is read");
        let mut routes = Routes::new(platform);
        assert!(routes.devices().is_empty());
    }
}
