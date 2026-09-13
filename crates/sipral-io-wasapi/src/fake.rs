// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! COM objects written here, for a test to hand to the code that expects
//! Windows to have written them.
//!
//! Everything that talks to Windows in this crate takes an interface pointer
//! and calls through its table. So the way to put that code in front of a
//! headset that is unplugged, or a client that refuses to start, on a machine
//! that has neither, is an object whose table is the test's. Each one here has
//! the shape Windows hands over — a pointer to a table whose first three slots
//! are `IUnknown` — followed by a script the test fills in and reads back.
//!
//! The memory belongs to the [`Fake`], not to the reference count. `Release`
//! counts down and frees nothing; dropping the `Fake` is the free. A release
//! too many therefore shows up as a count below the test's own reference,
//! which an assertion can read, instead of as a use after free, which it
//! cannot.

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::abi::{Guid, Object, Unknown, UnknownVtable};
use crate::com::Com;
use crate::status::E_NOINTERFACE;

/// `E_NOTIMPL`, from `winerror.h`: what a slot no test drives answers.
pub(crate) const NOT_IMPLEMENTED: i32 = 0x8000_4001_u32.cast_signed();

/// What a caller's interface pointer points at.
#[repr(C)]
struct Body<V: 'static, S> {
    /// First, as in every COM object: it is what a caller reads the table
    /// from.
    vtable: *const V,
    refs: AtomicU32,
    script: S,
}

/// One object, owned by the test that made it.
pub(crate) struct Fake<V: 'static, S> {
    body: NonNull<Body<V, S>>,
}

impl<V: 'static, S> Fake<V, S> {
    /// An object calling through `vtable`, holding the test's one reference.
    pub(crate) fn new(vtable: &'static V, script: S) -> Self {
        let body = Box::new(Body {
            vtable,
            refs: AtomicU32::new(1),
            script,
        });
        Self {
            body: NonNull::from(Box::leak(body)),
        }
    }

    fn body(&self) -> &Body<V, S> {
        // SAFETY: the box this came from is freed only by this value's drop.
        unsafe { self.body.as_ref() }
    }

    /// What the test wrote, and what the table's functions wrote back.
    pub(crate) fn script(&self) -> &S {
        &self.body().script
    }

    /// References held, the test's own included.
    pub(crate) fn refs(&self) -> u32 {
        self.body().refs.load(Ordering::SeqCst)
    }

    /// The object's address, which is what an interface pointer to it is.
    pub(crate) fn as_ptr(&self) -> *mut Object<V> {
        self.body.as_ptr().cast::<Object<V>>()
    }

    /// A counted pointer for an out-parameter, the way a call that hands an
    /// interface over counts it.
    pub(crate) fn hand_out(&self) -> *mut Object<V> {
        self.body().refs.fetch_add(1, Ordering::SeqCst);
        self.as_ptr()
    }

    /// A counted reference for the code under test to hold and give back.
    pub(crate) fn com(&self) -> Com<V> {
        // SAFETY: a live object whose first word is its table, carrying the
        // reference `hand_out` just counted for the `Com` to give back.
        unsafe { Com::from_raw(self.hand_out()) }.expect("an object this fake owns is not null")
    }
}

impl<V: 'static, S> Drop for Fake<V, S> {
    fn drop(&mut self) {
        // SAFETY: the pointer came out of `Box::leak` in `new` and nothing
        // else frees it; a reference still held past this point is the test's
        // own bug, and the count it can read before dropping is there to
        // catch it.
        drop(unsafe { Box::from_raw(self.body.as_ptr()) });
    }
}

/// The script behind a pointer one of these objects was called through.
///
/// # Safety
/// `this` is null, or the address of a [`Fake`] made with this `V` and `S`
/// that is still alive.
pub(crate) unsafe fn script<'a, V: 'static, S>(this: *mut Object<V>) -> Option<&'a S> {
    // SAFETY: the caller's promise.
    unsafe { this.cast::<Body<V, S>>().as_ref() }.map(|body| &body.script)
}

/// The three `IUnknown` slots for a table of `V` over a script of `S`.
pub(crate) const fn unknown<V: 'static, S>() -> UnknownVtable {
    UnknownVtable {
        query_interface: refuse,
        add_ref: add_ref::<V, S>,
        release: release::<V, S>,
    }
}

/// `IUnknown::QueryInterface`, answering no identifier at all: nothing a test
/// drives asks one of these objects for another interface.
unsafe extern "system" fn refuse(
    _this: *mut Unknown,
    _wanted: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    // SAFETY: null, or the caller's live out-parameter.
    if let Some(out) = unsafe { out.as_mut() } {
        *out = ptr::null_mut();
    }
    E_NOINTERFACE
}

/// `IUnknown::AddRef`.
unsafe extern "system" fn add_ref<V: 'static, S>(this: *mut Unknown) -> u32 {
    // SAFETY: the pointer this module handed out, which is a live body.
    let Some(body) = (unsafe { this.cast::<Body<V, S>>().as_ref() }) else {
        return 0;
    };
    body.refs.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

/// `IUnknown::Release`, which counts and does not free.
unsafe extern "system" fn release<V: 'static, S>(this: *mut Unknown) -> u32 {
    // SAFETY: as above.
    let Some(body) = (unsafe { this.cast::<Body<V, S>>().as_ref() }) else {
        return 0;
    };
    body.refs.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1)
}
