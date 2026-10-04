// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The framework entry points, declared by hand.
//!
//! Nothing generates this file and nothing needs to: the calls are a dozen,
//! their signatures are published, and a binding generator would drag in a
//! dependency for the privilege. Each declaration carries the C prototype it
//! was written from, so a reader can check it against the header rather than
//! against the person who typed it.
//!
//! The Rust names are ours; `link_name` carries the symbol.

use core::ffi::c_void;

use crate::abi::{BufferList, ComponentDescription, TimeStamp};
use crate::status::{Error, OsStatus};

#[cfg(target_os = "macos")]
use crate::abi::hardware::PropertyAddress;
#[cfg(target_os = "macos")]
use core::ffi::c_char;

/// `OSStatus`: zero, or a reason.
pub(crate) type Status = i32;

/// `struct OpaqueAudioComponent`, which only the framework looks inside.
#[repr(C)]
pub(crate) struct ComponentRecord {
    _opaque: [u8; 0],
}

/// `AudioComponent`.
pub(crate) type Component = *mut ComponentRecord;

/// `struct ComponentInstanceRecord`.
#[repr(C)]
pub(crate) struct InstanceRecord {
    _opaque: [u8; 0],
}

/// `AudioComponentInstance`, and for an output unit also `AudioUnit`.
pub(crate) type Unit = *mut InstanceRecord;

/// `AURenderCallback`: `OSStatus (*)(void *inRefCon,
/// AudioUnitRenderActionFlags *ioActionFlags,
/// const AudioTimeStamp *inTimeStamp, UInt32 inBusNumber,
/// UInt32 inNumberFrames, AudioBufferList *ioData)`.
pub(crate) type RenderProc = unsafe extern "C" fn(
    *mut c_void,
    *mut u32,
    *const TimeStamp,
    u32,
    u32,
    *mut BufferList,
) -> Status;

/// `AURenderCallbackStruct`: the function and the pointer it is handed back.
#[repr(C)]
pub(crate) struct RenderCallback {
    pub(crate) procedure: RenderProc,
    pub(crate) context: *mut c_void,
}

/// `AudioObjectPropertyListenerProc`: `OSStatus (*)(AudioObjectID inObjectID,
/// UInt32 inNumberAddresses, const AudioObjectPropertyAddress *inAddresses,
/// void *inClientData)`.
#[cfg(target_os = "macos")]
pub(crate) type PropertyListenerProc =
    unsafe extern "C" fn(u32, u32, *const PropertyAddress, *mut c_void) -> Status;

/// `CFStringRef`, borrowed or owned depending on which call produced it.
#[cfg(target_os = "macos")]
pub(crate) type StringRef = *const c_void;

#[link(name = "AudioToolbox", kind = "framework")]
unsafe extern "C" {
    /// `AudioComponent AudioComponentFindNext(AudioComponent inComponent,
    /// const AudioComponentDescription *inDesc)`. Null in, first match out;
    /// null out means there is no such component.
    #[link_name = "AudioComponentFindNext"]
    pub(crate) fn find_component(
        after: Component,
        wanted: *const ComponentDescription,
    ) -> Component;

    /// `OSStatus AudioComponentInstanceNew(AudioComponent inComponent,
    /// AudioComponentInstance *outInstance)`.
    #[link_name = "AudioComponentInstanceNew"]
    pub(crate) fn open_component(component: Component, instance: *mut Unit) -> Status;

    /// `OSStatus AudioComponentInstanceDispose(AudioComponentInstance
    /// inInstance)`.
    ///
    /// Apple documents nothing about callbacks that are running when this is
    /// called, so nothing here rests on it. What makes teardown safe is the
    /// gate in `gate.rs` and the order `Stream::teardown` does things in.
    #[link_name = "AudioComponentInstanceDispose"]
    pub(crate) fn dispose_component(instance: Unit) -> Status;

    /// `OSStatus AudioUnitInitialize(AudioUnit inUnit)`.
    #[link_name = "AudioUnitInitialize"]
    pub(crate) fn initialize_unit(unit: Unit) -> Status;

    /// `OSStatus AudioUnitUninitialize(AudioUnit inUnit)`.
    #[link_name = "AudioUnitUninitialize"]
    pub(crate) fn uninitialize_unit(unit: Unit) -> Status;

    /// `OSStatus AudioUnitSetProperty(AudioUnit inUnit,
    /// AudioUnitPropertyID inID, AudioUnitScope inScope,
    /// AudioUnitElement inElement, const void *inData, UInt32 inDataSize)`.
    #[link_name = "AudioUnitSetProperty"]
    pub(crate) fn set_unit_property(
        unit: Unit,
        property: u32,
        scope: u32,
        element: u32,
        data: *const c_void,
        size: u32,
    ) -> Status;

    /// `OSStatus AudioUnitGetProperty(AudioUnit inUnit,
    /// AudioUnitPropertyID inID, AudioUnitScope inScope,
    /// AudioUnitElement inElement, void *outData, UInt32 *ioDataSize)`.
    #[link_name = "AudioUnitGetProperty"]
    pub(crate) fn get_unit_property(
        unit: Unit,
        property: u32,
        scope: u32,
        element: u32,
        data: *mut c_void,
        size: *mut u32,
    ) -> Status;

    /// `OSStatus AudioUnitRender(AudioUnit inUnit,
    /// AudioUnitRenderActionFlags *ioActionFlags,
    /// const AudioTimeStamp *inTimeStamp, UInt32 inOutputBusNumber,
    /// UInt32 inNumberFrames, AudioBufferList *ioData)`. Called from the
    /// input callback and nowhere else.
    #[link_name = "AudioUnitRender"]
    pub(crate) fn render_unit(
        unit: Unit,
        flags: *mut u32,
        time: *const TimeStamp,
        bus: u32,
        frames: u32,
        buffers: *mut BufferList,
    ) -> Status;

    /// `OSStatus AudioOutputUnitStart(AudioUnit ci)`.
    #[link_name = "AudioOutputUnitStart"]
    pub(crate) fn start_unit(unit: Unit) -> Status;

    /// `OSStatus AudioOutputUnitStop(AudioUnit ci)`.
    ///
    /// This is the one call in the teardown sequence with a stated guarantee:
    /// called from anywhere but the I/O thread it is synchronous, so no
    /// callback begins after it returns. It says nothing about the one that
    /// was already running, which is what the gate is for.
    #[link_name = "AudioOutputUnitStop"]
    pub(crate) fn stop_unit(unit: Unit) -> Status;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreAudio", kind = "framework")]
unsafe extern "C" {
    /// `OSStatus AudioObjectGetPropertyDataSize(AudioObjectID inObjectID,
    /// const AudioObjectPropertyAddress *inAddress,
    /// UInt32 inQualifierDataSize, const void *inQualifierData,
    /// UInt32 *outDataSize)`.
    #[link_name = "AudioObjectGetPropertyDataSize"]
    pub(crate) fn object_property_size(
        object: u32,
        address: *const PropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: *mut u32,
    ) -> Status;

    /// `OSStatus AudioObjectGetPropertyData(AudioObjectID inObjectID,
    /// const AudioObjectPropertyAddress *inAddress,
    /// UInt32 inQualifierDataSize, const void *inQualifierData,
    /// UInt32 *ioDataSize, void *outData)`.
    #[link_name = "AudioObjectGetPropertyData"]
    pub(crate) fn object_property_data(
        object: u32,
        address: *const PropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: *mut u32,
        data: *mut c_void,
    ) -> Status;

    /// `OSStatus AudioObjectAddPropertyListener(AudioObjectID inObjectID,
    /// const AudioObjectPropertyAddress *inAddress,
    /// AudioObjectPropertyListenerProc inListener, void *inClientData)`.
    #[link_name = "AudioObjectAddPropertyListener"]
    pub(crate) fn add_property_listener(
        object: u32,
        address: *const PropertyAddress,
        listener: PropertyListenerProc,
        context: *mut c_void,
    ) -> Status;

    /// `OSStatus AudioObjectRemovePropertyListener(AudioObjectID inObjectID,
    /// const AudioObjectPropertyAddress *inAddress,
    /// AudioObjectPropertyListenerProc inListener, void *inClientData)`. The
    /// listener will not be called after this returns.
    #[link_name = "AudioObjectRemovePropertyListener"]
    pub(crate) fn remove_property_listener(
        object: u32,
        address: *const PropertyAddress,
        listener: PropertyListenerProc,
        context: *mut c_void,
    ) -> Status;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// `Boolean CFStringGetCString(CFStringRef theString, char *buffer,
    /// CFIndex bufferSize, CFStringEncoding encoding)`.
    #[link_name = "CFStringGetCString"]
    pub(crate) fn string_to_bytes(
        string: StringRef,
        buffer: *mut c_char,
        size: isize,
        encoding: u32,
    ) -> u8;

    /// `CFIndex CFStringGetLength(CFStringRef theString)`, in UTF-16 units.
    #[link_name = "CFStringGetLength"]
    pub(crate) fn string_length(string: StringRef) -> isize;

    /// `CFIndex CFStringGetMaximumSizeForEncoding(CFIndex length,
    /// CFStringEncoding encoding)`, which is what to size the buffer by.
    #[link_name = "CFStringGetMaximumSizeForEncoding"]
    pub(crate) fn string_max_bytes(length: isize, encoding: u32) -> isize;

    /// `void CFRelease(CFTypeRef cf)`. The property calls hand back a string
    /// this side owns, so every one of them ends here.
    #[link_name = "CFRelease"]
    pub(crate) fn release(object: *const c_void);

    /// `CFStringRef CFStringCreateWithBytes(CFAllocatorRef alloc, const UInt8
    /// *bytes, CFIndex numBytes, CFStringEncoding encoding, Boolean
    /// isExternalRepresentation)`, which the caller then owns.
    #[link_name = "CFStringCreateWithBytes"]
    pub(crate) fn string_from_bytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> StringRef;

    /// `const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void
    /// *key)`: borrowed from the dictionary, not owned.
    #[link_name = "CFDictionaryGetValue"]
    pub(crate) fn dictionary_value(dictionary: *const c_void, key: *const c_void) -> *const c_void;

    /// `CFTypeID CFGetTypeID(CFTypeRef cf)`.
    #[link_name = "CFGetTypeID"]
    pub(crate) fn type_of(object: *const c_void) -> usize;

    /// `CFTypeID CFNumberGetTypeID(void)`.
    #[link_name = "CFNumberGetTypeID"]
    pub(crate) fn number_type() -> usize;

    /// `CFTypeID CFBooleanGetTypeID(void)`.
    #[link_name = "CFBooleanGetTypeID"]
    pub(crate) fn boolean_type() -> usize;

    /// `Boolean CFNumberGetValue(CFNumberRef number, CFNumberType theType,
    /// void *valuePtr)`.
    #[link_name = "CFNumberGetValue"]
    pub(crate) fn number_value(number: *const c_void, kind: isize, value: *mut c_void) -> u8;

    /// `Boolean CFBooleanGetValue(CFBooleanRef boolean)`.
    #[link_name = "CFBooleanGetValue"]
    pub(crate) fn boolean_value(boolean: *const c_void) -> u8;
}

/// Turn what a call returned into a result that names the call.
pub(crate) fn check(call: &'static str, status: Status) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Call {
            call,
            status: OsStatus::new(status),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::check;
    use crate::status::{Error, OsStatus};

    #[test]
    fn zero_is_not_a_failure() {
        assert_eq!(check("AudioUnitInitialize", 0), Ok(()));
    }

    #[test]
    fn anything_else_keeps_the_call_and_the_status() {
        assert_eq!(
            check("AudioOutputUnitStart", -10863),
            Err(Error::Call {
                call: "AudioOutputUnitStart",
                status: OsStatus::new(-10863),
            })
        );
    }
}
