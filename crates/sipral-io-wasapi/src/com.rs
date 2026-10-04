// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Owning the things Windows hands over.
//!
//! Four kinds of resource cross into this crate and every one of them has to
//! go back: an interface pointer carries a reference count, an event carries a
//! handle, the multimedia scheduler hands back a registration, and
//! `CoInitializeEx` has to be balanced on the thread that called it. Each gets
//! a type here whose destructor is the return path, so that the error paths in
//! the rest of the crate are `?` and not a ladder of cleanup.
//!
//! The one place this deliberately does not apply is teardown of a running
//! stream, where a destructor is exactly the wrong tool: see `gate.rs`.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::abi::{COINIT_MULTITHREADED, Handle, Object, Unknown};
use crate::status::{Error, HResult, RPC_E_CHANGED_MODE};
use crate::sys;

/// A wide string can be longer than any name a device has; this is where
/// reading one stops believing the terminator is coming.
const MAX_WIDE_UNITS: usize = 32_768;

/// An interface pointer, and the reference it carries.
pub(crate) struct Com<V: 'static> {
    object: NonNull<Object<V>>,
}

impl<V: 'static> Com<V> {
    /// Take over a reference a call handed back. `None` for null, which is
    /// what a failed call leaves behind.
    ///
    /// # Safety
    /// `pointer` is either null or a live interface of this kind, and its
    /// reference count belongs to the caller — every `Activate`, `GetService`,
    /// `QueryInterface` and `Item` in this crate returns one already counted.
    pub(crate) unsafe fn from_raw(pointer: *mut Object<V>) -> Option<Self> {
        NonNull::new(pointer).map(|object| Self { object })
    }

    /// The pointer, for a call that takes it.
    pub(crate) fn as_ptr(&self) -> *mut Object<V> {
        self.object.as_ptr()
    }

    /// The table of methods.
    pub(crate) fn vtable(&self) -> &V {
        // SAFETY: a live COM object's first word is a pointer to its vtable,
        // and the table is static data that outlives the object.
        unsafe { &*(*self.object.as_ptr()).vtable }
    }
}

impl<V: 'static> Drop for Com<V> {
    fn drop(&mut self) {
        let unknown = self.object.as_ptr().cast::<Unknown>();
        // SAFETY: every vtable declared in `abi` begins with the three
        // IUnknown slots — asserted there — so reading `Release` through a
        // cast to IUnknown is the same cast the C headers make, and the
        // reference being given back is the one `from_raw` took over.
        unsafe {
            let release = (*(*unknown).vtable).release;
            release(unknown);
        }
    }
}

/// A thread's COM initialisation.
///
/// Not `Send`, and that is the point rather than an oversight:
/// `CoUninitialize` balances the thread that called `CoInitializeEx`, so a
/// guard that could be dropped somewhere else would be a bug with no symptom
/// until an unrelated part of the program stopped working.
pub(crate) struct Apartment {
    /// Whether this guard is the one that has to undo it. A thread that was
    /// already in an apartment is somebody else's to take down.
    ours: bool,
    not_send: PhantomData<*const ()>,
}

impl Apartment {
    /// Join the multi-threaded apartment, or note that this thread is already
    /// somewhere else and leave it there.
    ///
    /// A thread that a host application has already put in a single-threaded
    /// apartment answers `RPC_E_CHANGED_MODE`. That is not a failure: every
    /// object this crate makes is created and released on the thread that made
    /// it, so an apartment either way works — what would not work is
    /// uninitialising an apartment that was not ours.
    ///
    /// # Errors
    /// [`Error::Call`] when COM itself will not start.
    pub(crate) fn enter() -> Result<Self, Error> {
        // SAFETY: no reserved argument, and the flags are a documented value.
        let status = unsafe { sys::co_initialize(ptr::null_mut(), COINIT_MULTITHREADED) };
        if status == RPC_E_CHANGED_MODE {
            return Ok(Self {
                ours: false,
                not_send: PhantomData,
            });
        }
        sys::check("CoInitializeEx", status)?;
        Ok(Self {
            ours: true,
            not_send: PhantomData,
        })
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.ours {
            // SAFETY: balances exactly one successful CoInitializeEx, on the
            // thread that made it, which is what `not_send` guarantees.
            unsafe { sys::co_uninitialize() };
        }
    }
}

/// An event handle.
///
/// Auto-reset and initially unsignalled, which is what both uses want: the
/// audio engine signals one when a buffer wants attention, and teardown
/// signals the other once.
pub(crate) struct Event(Handle);

impl Event {
    /// Make one.
    ///
    /// # Errors
    /// [`Error::Call`] carrying nothing but the fact that it failed —
    /// `CreateEventW` reports through `GetLastError`, which is a `DWORD` and
    /// not an `HRESULT`, and inventing a code for it would be worse than
    /// saying plainly that the call returned null.
    pub(crate) fn new() -> Result<Self, Error> {
        // SAFETY: no security attributes, no name; the two flags are booleans.
        let handle = unsafe { sys::create_event(ptr::null_mut(), 0, 0, ptr::null()) };
        if handle.is_null() {
            return Err(Error::Call {
                call: "CreateEventW",
                status: HResult::new(crate::status::E_POINTER),
            });
        }
        Ok(Self(handle))
    }

    /// The handle, for a call that takes it.
    pub(crate) fn handle(&self) -> Handle {
        self.0
    }

    /// Wake whoever is waiting.
    pub(crate) fn signal(&self) {
        // SAFETY: the handle is live for as long as this value is, and the
        // return says only whether it was, which is not in doubt.
        unsafe { sys::set_event(self.0) };
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: closed once, and only when nothing can still be waiting on
        // it — which for the stream's events is what the gate establishes.
        unsafe { sys::close_handle(self.0) };
    }
}

// SAFETY: a handle is a process-wide number, not a thread-local one, and
// `SetEvent` and `WaitForMultipleObjects` are documented to be called from any
// thread.
unsafe impl Send for Event {}
// SAFETY: as above; nothing here mutates through `&self` but the kernel object,
// which does its own synchronising.
unsafe impl Sync for Event {}

/// The audio thread's registration with the multimedia class scheduler.
///
/// Without one, the thread is scheduled like any other and Windows will take
/// the processor away in the middle of a buffer. With one, it runs in the Pro
/// Audio class and does not.
pub(crate) struct Priority(Handle);

impl Priority {
    /// Register the calling thread as Pro Audio, or say that it could not be.
    ///
    /// `None` is survivable: the stream runs, it is just interruptible, and
    /// that is a fact worth reporting rather than a reason to refuse the call.
    /// It happens when the audio service is not running, and in some session
    /// zero contexts.
    pub(crate) fn pro_audio() -> Option<Self> {
        let mut index: u32 = 0;
        // SAFETY: the task name is a terminated wide string with static
        // storage, and `index` is a live in-out parameter.
        let handle =
            unsafe { sys::set_thread_characteristics(sys::PRO_AUDIO.as_ptr(), &raw mut index) };
        if handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }
}

impl Drop for Priority {
    fn drop(&mut self) {
        // SAFETY: the registration this took out, given back once, on the
        // thread that took it.
        unsafe { sys::revert_thread_characteristics(self.0) };
    }
}

/// Memory a COM call allocated, which the caller owns from the moment it
/// returns.
///
/// `GetId` and `GetMixFormat` both hand one of these back, and both are easy
/// to leak on the error path of the thing that reads them.
pub(crate) struct TaskMemory<T>(*mut T);

impl<T> TaskMemory<T> {
    /// Take over what a call allocated. `None` for null.
    ///
    /// # Safety
    /// `pointer` is null or was allocated by the COM task allocator and is not
    /// owned by anyone else.
    pub(crate) unsafe fn from_raw(pointer: *mut T) -> Option<Self> {
        if pointer.is_null() {
            None
        } else {
            Some(Self(pointer))
        }
    }

    /// What it points at.
    pub(crate) fn as_ptr(&self) -> *const T {
        self.0
    }
}

impl<T> Drop for TaskMemory<T> {
    fn drop(&mut self) {
        // SAFETY: freed once, with the allocator that made it.
        unsafe { sys::co_task_mem_free(self.0.cast::<c_void>()) };
    }
}

/// A Rust string as Windows wants it: UTF-16 with a terminator.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    units.push(0);
    units
}

/// A wide string Windows handed over, as a Rust one.
///
/// Lone surrogates become the replacement character rather than an error: this
/// is a device name on its way to a log line, and a name that cannot be
/// spelled is still better than no device.
///
/// # Safety
/// `pointer` is null, or a terminated wide string that stays valid for the
/// length of the call.
pub(crate) unsafe fn text_from(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut units = Vec::new();
    for step in 0..MAX_WIDE_UNITS {
        // SAFETY: every unit up to the terminator is inside the string the
        // caller promised, and the loop stops at the first zero.
        let unit = unsafe { ptr::read_unaligned(pointer.add(step)) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::{text_from, wide};

    #[test]
    fn a_string_goes_out_with_its_terminator() {
        let units = wide("CABLE Output");
        assert_eq!(units.len(), 13);
        assert_eq!(units.last(), Some(&0));
        // SAFETY: a terminated wide string this test owns.
        assert_eq!(unsafe { text_from(units.as_ptr()) }, "CABLE Output");
    }

    #[test]
    fn an_empty_string_is_one_terminator_and_comes_back_empty() {
        let units = wide("");
        assert_eq!(units, [0]);
        // SAFETY: as above.
        assert_eq!(unsafe { text_from(units.as_ptr()) }, "");
        // SAFETY: null is the case this is documented to answer for.
        assert_eq!(unsafe { text_from(core::ptr::null()) }, "");
    }

    #[test]
    fn a_name_outside_the_basic_plane_survives_the_round_trip() {
        // an endpoint named by whoever wrote its driver, which is nobody's
        // guarantee of being ASCII
        let units = wide("Røde NT-USB 🎙");
        // SAFETY: a terminated wide string this test owns.
        assert_eq!(unsafe { text_from(units.as_ptr()) }, "Røde NT-USB 🎙");
    }
}
