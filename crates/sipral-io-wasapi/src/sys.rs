// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The Windows entry points, declared by hand.
//!
//! Nothing generates this file and nothing needs to: the calls are a dozen,
//! their prototypes are published, and a binding generator would drag in a
//! dependency for the privilege. Each declaration carries the C prototype it
//! was written from, so a reader can check it against the header rather than
//! against the person who typed it.
//!
//! `extern "system"` throughout, which is what `WINAPI` and `STDMETHODCALLTYPE`
//! expand to: the same as C on x86-64 and `stdcall` on 32-bit x86, where
//! getting it wrong would corrupt the stack on every call rather than fail to
//! link.
//!
//! The Rust names are ours; the symbol is the one Windows exports.

use core::ffi::c_void;

use crate::abi::{Guid, Handle, Hr, PropVariant, Unknown};
use crate::status::{Error, HResult};

/// `BOOL`: zero is false and anything else is true, which is not the same
/// thing as one.
pub(crate) type Bool = i32;

#[link(name = "ole32")]
unsafe extern "system" {
    /// `HRESULT CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit)`. Returns
    /// `S_FALSE` when the thread was already initialised to the same
    /// apartment, which still counts and still has to be balanced.
    #[link_name = "CoInitializeEx"]
    pub(crate) fn co_initialize(reserved: *mut c_void, options: u32) -> Hr;

    /// `void CoUninitialize(void)`. Balances exactly one successful
    /// `CoInitializeEx` on the same thread.
    #[link_name = "CoUninitialize"]
    pub(crate) fn co_uninitialize();

    /// `HRESULT CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    /// DWORD dwClsContext, REFIID riid, LPVOID *ppv)`.
    #[link_name = "CoCreateInstance"]
    pub(crate) fn co_create_instance(
        class: *const Guid,
        outer: *mut Unknown,
        context: u32,
        interface: *const Guid,
        out: *mut *mut c_void,
    ) -> Hr;

    /// `void CoTaskMemFree(LPVOID pv)`. Frees what `GetId` and `GetMixFormat`
    /// hand over, which the caller owns from the moment they return.
    #[link_name = "CoTaskMemFree"]
    pub(crate) fn co_task_mem_free(memory: *mut c_void);

    /// `HRESULT PropVariantClear(PROPVARIANT *pvar)`. A property store fills
    /// one in and this is what empties it again; for a string it is the free.
    #[link_name = "PropVariantClear"]
    pub(crate) fn prop_variant_clear(variant: *mut PropVariant) -> Hr;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    /// `HANDLE CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes,
    /// BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName)`. Null out means
    /// it failed.
    #[link_name = "CreateEventW"]
    pub(crate) fn create_event(
        attributes: *mut c_void,
        manual_reset: Bool,
        initial_state: Bool,
        name: *const u16,
    ) -> Handle;

    /// `BOOL SetEvent(HANDLE hEvent)`.
    #[link_name = "SetEvent"]
    pub(crate) fn set_event(event: Handle) -> Bool;

    /// `BOOL CloseHandle(HANDLE hObject)`. Called only once the audio thread
    /// has been shown to be out; a handle closed under a thread waiting on it
    /// is worse than one that is never closed, because handle values come
    /// round again.
    #[link_name = "CloseHandle"]
    pub(crate) fn close_handle(object: Handle) -> Bool;

    /// `DWORD WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles,
    /// BOOL bWaitAll, DWORD dwMilliseconds)`. Returns `WAIT_OBJECT_0` plus the
    /// index of whichever was signalled first.
    #[link_name = "WaitForMultipleObjects"]
    pub(crate) fn wait_for_multiple_objects(
        count: u32,
        handles: *const Handle,
        wait_all: Bool,
        milliseconds: u32,
    ) -> u32;
}

#[link(name = "avrt")]
unsafe extern "system" {
    /// `HANDLE AvSetMmThreadCharacteristicsW(LPCWSTR TaskName,
    /// LPDWORD TaskIndex)`.
    ///
    /// Without this the audio thread is an ordinary one and the scheduler will
    /// take the processor away from it in the middle of a buffer. `TaskIndex`
    /// is in and out: zero going in, a number coming back that has to be kept
    /// only if the same thread registers again.
    ///
    /// Null out means it failed, which is not fatal — the stream runs, it just
    /// runs at a priority that will be interrupted — so it is recorded rather
    /// than returned.
    #[link_name = "AvSetMmThreadCharacteristicsW"]
    pub(crate) fn set_thread_characteristics(task: *const u16, index: *mut u32) -> Handle;

    /// `BOOL AvRevertMmThreadCharacteristics(HANDLE AvrtHandle)`.
    #[link_name = "AvRevertMmThreadCharacteristics"]
    pub(crate) fn revert_thread_characteristics(handle: Handle) -> Bool;
}

/// The task name to register the audio thread under.
///
/// `"Pro Audio"` rather than `"Audio"`: the two differ in the priority the
/// Multimedia Class Scheduler gives them, and the one that exists for
/// glitch-free playback is the one a call wants. The name is a wide string
/// with its terminator, spelled out here because there is no runtime cost to
/// having it already in that shape.
pub(crate) const PRO_AUDIO: [u16; 10] = [
    b'P' as u16,
    b'r' as u16,
    b'o' as u16,
    b' ' as u16,
    b'A' as u16,
    b'u' as u16,
    b'd' as u16,
    b'i' as u16,
    b'o' as u16,
    0,
];

/// Turn what a call returned into a result that names the call.
pub(crate) fn check(call: &'static str, status: Hr) -> Result<(), Error> {
    if HResult::new(status).is_ok() {
        Ok(())
    } else {
        Err(Error::Call {
            call,
            status: HResult::new(status),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PRO_AUDIO, check};
    use crate::status::{Error, HResult};

    #[test]
    fn success_and_s_false_are_both_not_failures() {
        assert_eq!(check("IAudioClient::Initialize", 0), Ok(()));
        // S_FALSE is what IsFormatSupported says when it has a closest match,
        // and treating it as an error is the classic way to refuse every
        // device on the machine
        assert_eq!(check("IAudioClient::IsFormatSupported", 1), Ok(()));
    }

    #[test]
    fn anything_with_the_top_bit_keeps_the_call_and_the_code() {
        assert_eq!(
            check("IAudioClient::Start", 0x8889_0004_u32.cast_signed()),
            Err(Error::Call {
                call: "IAudioClient::Start",
                status: HResult::new(0x8889_0004_u32.cast_signed()),
            })
        );
    }

    #[test]
    fn the_scheduling_class_is_a_terminated_wide_string() {
        let text: String = PRO_AUDIO
            .iter()
            .take_while(|unit| **unit != 0)
            .filter_map(|unit| char::from_u32(u32::from(*unit)))
            .collect();
        assert_eq!(text, "Pro Audio");
        assert_eq!(PRO_AUDIO.last(), Some(&0));
    }
}
