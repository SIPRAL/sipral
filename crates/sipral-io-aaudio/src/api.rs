// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `libaaudio.so`, looked up rather than linked.
//!
//! The Android packages are built for API level 21, and the NDK carries no
//! `libaaudio.so` to link against below 26: a library that linked it would
//! not load on the phones below that at all, where the application still
//! wants the rest of this one. So the functions are found with `dlsym` the
//! first time they are wanted, every one of them or none, and kept for the
//! life of the process. Declared from the NDK's `aaudio/AAudio.h`; the
//! constants are its values.

use core::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;

/// `aaudio_result_t` and every other enumeration in the header.
pub(crate) type Code = i32;

/// `AAUDIO_OK`.
pub(crate) const OK: Code = 0;
/// `AAUDIO_UNSPECIFIED`.
pub(crate) const UNSPECIFIED: i32 = 0;
/// `AAUDIO_STREAM_STATE_DISCONNECTED`.
pub(crate) const STATE_DISCONNECTED: Code = 13;
/// `AAUDIO_DIRECTION_OUTPUT`, `AAUDIO_DIRECTION_INPUT`.
pub(crate) const DIRECTION_OUTPUT: i32 = 0;
pub(crate) const DIRECTION_INPUT: i32 = 1;
/// `AAUDIO_FORMAT_PCM_I16`, `AAUDIO_FORMAT_PCM_FLOAT`.
pub(crate) const FORMAT_I16: i32 = 1;
pub(crate) const FORMAT_FLOAT: i32 = 2;
/// `AAUDIO_SHARING_MODE_SHARED`.
pub(crate) const SHARING_SHARED: i32 = 1;
/// `AAUDIO_PERFORMANCE_MODE_NONE`, `AAUDIO_PERFORMANCE_MODE_LOW_LATENCY`.
pub(crate) const PERFORMANCE_NONE: i32 = 10;
pub(crate) const PERFORMANCE_LOW_LATENCY: i32 = 12;
/// `AAUDIO_USAGE_VOICE_COMMUNICATION`, `AAUDIO_USAGE_NOTIFICATION_RINGTONE`.
pub(crate) const USAGE_VOICE_COMMUNICATION: i32 = 2;
pub(crate) const USAGE_NOTIFICATION_RINGTONE: i32 = 6;
/// `AAUDIO_CONTENT_TYPE_SPEECH`, `AAUDIO_CONTENT_TYPE_SONIFICATION`.
pub(crate) const CONTENT_SPEECH: i32 = 1;
pub(crate) const CONTENT_SONIFICATION: i32 = 4;
/// `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION`.
pub(crate) const PRESET_VOICE_COMMUNICATION: i32 = 7;
/// `AAUDIO_INPUT_PRESET_VOICE_RECOGNITION`: speech, tuned for a recogniser,
/// with no echo canceller and no gain control in its path, on every device
/// (where `UNPROCESSED` is optional).
pub(crate) const PRESET_VOICE_RECOGNITION: i32 = 6;
/// `AAUDIO_CALLBACK_RESULT_CONTINUE`, `AAUDIO_CALLBACK_RESULT_STOP`.
pub(crate) const CALLBACK_CONTINUE: i32 = 0;
pub(crate) const CALLBACK_STOP: i32 = 1;

/// `AAudioStreamBuilder`, never looked inside.
#[repr(C)]
pub(crate) struct Builder {
    _opaque: [u8; 0],
}

/// `AAudioStream`, never looked inside.
#[repr(C)]
pub(crate) struct RawStream {
    _opaque: [u8; 0],
}

/// `AAudioStream_dataCallback`.
pub(crate) type DataCallback = unsafe extern "C" fn(
    stream: *mut RawStream,
    user_data: *mut c_void,
    audio_data: *mut c_void,
    num_frames: i32,
) -> i32;

/// `AAudioStream_errorCallback`.
pub(crate) type ErrorCallback =
    unsafe extern "C" fn(stream: *mut RawStream, user_data: *mut c_void, error: Code);

type SetInt = unsafe extern "C" fn(*mut Builder, i32);
type GetInt = unsafe extern "C" fn(*mut RawStream) -> i32;
type Control = unsafe extern "C" fn(*mut RawStream) -> Code;

/// Every function this crate calls.
pub(crate) struct Api {
    pub(crate) create_builder: unsafe extern "C" fn(*mut *mut Builder) -> Code,
    pub(crate) delete_builder: unsafe extern "C" fn(*mut Builder) -> Code,
    pub(crate) set_device_id: SetInt,
    pub(crate) set_direction: SetInt,
    pub(crate) set_sample_rate: SetInt,
    pub(crate) set_channel_count: SetInt,
    pub(crate) set_format: SetInt,
    pub(crate) set_sharing_mode: SetInt,
    pub(crate) set_performance_mode: SetInt,
    pub(crate) set_usage: SetInt,
    pub(crate) set_content_type: SetInt,
    pub(crate) set_input_preset: SetInt,
    pub(crate) set_data_callback: unsafe extern "C" fn(*mut Builder, DataCallback, *mut c_void),
    pub(crate) set_error_callback: unsafe extern "C" fn(*mut Builder, ErrorCallback, *mut c_void),
    pub(crate) open_stream: unsafe extern "C" fn(*mut Builder, *mut *mut RawStream) -> Code,
    pub(crate) request_start: Control,
    pub(crate) request_stop: Control,
    pub(crate) close: Control,
    pub(crate) state: GetInt,
    pub(crate) sample_rate: GetInt,
    pub(crate) channel_count: GetInt,
    pub(crate) format: GetInt,
    pub(crate) device_id: GetInt,
    pub(crate) frames_per_burst: GetInt,
    pub(crate) buffer_size: GetInt,
    pub(crate) set_buffer_size: unsafe extern "C" fn(*mut RawStream, i32) -> Code,
    pub(crate) result_text: unsafe extern "C" fn(Code) -> *const c_char,
}

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

#[link(name = "c")]
unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
}

/// `RTLD_NOW` from bionic's `dlfcn.h`, which is 0 on 32-bit ABIs.
#[cfg(target_pointer_width = "64")]
pub(crate) const RTLD_NOW: c_int = 2;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) const RTLD_NOW: c_int = 0;
/// `RTLD_NOLOAD`: find a library already loaded, never load one.
pub(crate) const RTLD_NOLOAD: c_int = 4;

/// Open a library by name with `flags`, or say it is not there.
pub(crate) fn open_library(name: &core::ffi::CStr, flags: c_int) -> Option<*mut c_void> {
    // SAFETY: a NUL-terminated name; dlopen reads it and nothing else.
    let handle = unsafe { dlopen(name.as_ptr(), flags) };
    (!handle.is_null()).then_some(handle)
}

/// One symbol out of a library `open_library` found.
pub(crate) fn symbol(handle: *mut c_void, name: &core::ffi::CStr) -> Option<*mut c_void> {
    // SAFETY: a handle dlopen returned, never closed, and a NUL-terminated
    // name.
    let found = unsafe { dlsym(handle, name.as_ptr()) };
    (!found.is_null()).then_some(found)
}

/// One function out of a library `open_library` found, as the pointer
/// type `T`.
///
/// # Safety
///
/// `T` must be the function pointer type the symbol has.
pub(crate) unsafe fn function<T: Copy>(handle: *mut c_void, name: &core::ffi::CStr) -> Option<T> {
    if core::mem::size_of::<T>() != core::mem::size_of::<*mut c_void>() {
        return None;
    }
    let found = symbol(handle, name)?;
    // SAFETY: the caller's promise that `T` is the symbol's own type, and
    // the size checked above.
    Some(unsafe { core::mem::transmute_copy::<*mut c_void, T>(&found) })
}

/// `ro.build.version.sdk`, the API level, or zero if it cannot be read.
pub(crate) fn sdk() -> u32 {
    static SDK: OnceLock<u32> = OnceLock::new();
    *SDK.get_or_init(|| {
        // PROP_VALUE_MAX from sys/system_properties.h
        let mut value = [0 as c_char; 92];
        // SAFETY: a NUL-terminated name and a buffer of PROP_VALUE_MAX,
        // which is the most the call writes.
        let len =
            unsafe { __system_property_get(c"ro.build.version.sdk".as_ptr(), value.as_mut_ptr()) };
        let len = usize::try_from(len).unwrap_or(0).min(value.len());
        let text: Vec<u8> = value
            .iter()
            .take(len)
            .map(|&byte| byte.to_ne_bytes()[0])
            .collect();
        core::str::from_utf8(&text)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    })
}

impl Api {
    /// The functions, looked up once; `None` for ever if any is missing.
    pub(crate) fn get() -> Option<&'static Self> {
        static API: OnceLock<Option<Api>> = OnceLock::new();
        API.get_or_init(Self::load).as_ref()
    }

    fn load() -> Option<Self> {
        let library = open_library(c"libaaudio.so", RTLD_NOW)?;
        // SAFETY (for every `function` below): each name is the function
        // the header declares with the signature of the member it fills.
        macro_rules! find {
            ($name:literal) => {
                unsafe { function(library, $name) }?
            };
        }
        Some(Self {
            create_builder: find!(c"AAudio_createStreamBuilder"),
            delete_builder: find!(c"AAudioStreamBuilder_delete"),
            set_device_id: find!(c"AAudioStreamBuilder_setDeviceId"),
            set_direction: find!(c"AAudioStreamBuilder_setDirection"),
            set_sample_rate: find!(c"AAudioStreamBuilder_setSampleRate"),
            set_channel_count: find!(c"AAudioStreamBuilder_setChannelCount"),
            set_format: find!(c"AAudioStreamBuilder_setFormat"),
            set_sharing_mode: find!(c"AAudioStreamBuilder_setSharingMode"),
            set_performance_mode: find!(c"AAudioStreamBuilder_setPerformanceMode"),
            set_usage: find!(c"AAudioStreamBuilder_setUsage"),
            set_content_type: find!(c"AAudioStreamBuilder_setContentType"),
            set_input_preset: find!(c"AAudioStreamBuilder_setInputPreset"),
            set_data_callback: find!(c"AAudioStreamBuilder_setDataCallback"),
            set_error_callback: find!(c"AAudioStreamBuilder_setErrorCallback"),
            open_stream: find!(c"AAudioStreamBuilder_openStream"),
            request_start: find!(c"AAudioStream_requestStart"),
            request_stop: find!(c"AAudioStream_requestStop"),
            close: find!(c"AAudioStream_close"),
            state: find!(c"AAudioStream_getState"),
            sample_rate: find!(c"AAudioStream_getSampleRate"),
            channel_count: find!(c"AAudioStream_getChannelCount"),
            format: find!(c"AAudioStream_getFormat"),
            device_id: find!(c"AAudioStream_getDeviceId"),
            frames_per_burst: find!(c"AAudioStream_getFramesPerBurst"),
            buffer_size: find!(c"AAudioStream_getBufferSizeInFrames"),
            set_buffer_size: find!(c"AAudioStream_setBufferSizeInFrames"),
            result_text: find!(c"AAudio_convertResultToText"),
        })
    }

    /// What AAudio calls `code`.
    pub(crate) fn describe(&self, code: Code) -> String {
        // SAFETY: the function returns a static string for every code, or
        // null, which is checked.
        let text = unsafe { (self.result_text)(code) };
        if text.is_null() {
            return format!("AAudio error {code}");
        }
        // SAFETY: a NUL-terminated static string the library owns.
        unsafe { core::ffi::CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    }
}
