// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The library entry points, declared by hand, and the small amount of glue
//! that calling some of them needs.
//!
//! Nothing generates this file and nothing needs to: the calls this crate
//! makes are a few dozen, their signatures are published in
//! `pipewire/*.h`, and a binding generator would drag in `bindgen` and
//! `libclang` for the privilege — `docs/05-media.md` and
//! `sipral-io-coreaudio`/`sipral-io-wasapi` make the same choice for their
//! own frameworks. Every declaration carries the C prototype it was written
//! from, so a reader can check it against the header rather than against the
//! person who typed it.
//!
//! Three of `libpipewire`'s own objects — `pw_core`, `pw_registry`,
//! `pw_metadata` — are not called through ordinary exported symbols at all.
//! Their methods (`pw_core_sync`, `pw_registry_bind`, and so on) are
//! `static inline` wrappers in the header around `spa_interface_call`, a
//! vtable dispatch through the object's own `struct spa_interface` — the
//! same shape as the `IUnknown` vtable `sipral-io-wasapi::com` reads, except
//! SPA's is a plain C struct of function pointers rather than a COM
//! interface. What is declared here is that dispatch, done by hand for the
//! six methods this crate actually calls, checked against the method-table
//! layouts in `abi.rs`.

use core::ffi::{c_char, c_void};
use core::ptr;

use crate::abi::{
    PwCoreEvents, PwCoreMethods, PwMetadataEvents, PwMetadataMethods, PwRegistryEvents,
    PwRegistryMethods, SpaDict, SpaHook, SpaInterface,
};
use crate::status::{Errno, Error};

/// `struct pw_thread_loop`, opaque on this side.
#[repr(C)]
pub(crate) struct PwThreadLoop {
    _opaque: [u8; 0],
}

/// `struct pw_loop`, opaque on this side.
#[repr(C)]
pub(crate) struct PwLoop {
    _opaque: [u8; 0],
}

/// `struct pw_context`, opaque on this side.
#[repr(C)]
pub(crate) struct PwContext {
    _opaque: [u8; 0],
}

/// `struct pw_core`, opaque on this side except for the `spa_interface`
/// header every method call reads.
#[repr(C)]
pub(crate) struct PwCore {
    _opaque: [u8; 0],
}

/// `struct pw_registry`, the same shape as [`PwCore`].
#[repr(C)]
pub(crate) struct PwRegistry {
    _opaque: [u8; 0],
}

/// `struct pw_metadata`, the same shape as [`PwCore`]. What `pw_registry_bind`
/// hands back for the `"default"` metadata global is also a `struct
/// pw_proxy*`, which is why [`proxy_destroy`] takes the same pointer cast.
#[repr(C)]
pub(crate) struct PwMetadata {
    _opaque: [u8; 0],
}

/// `struct pw_properties`, opaque on this side.
#[repr(C)]
pub(crate) struct PwProperties {
    _opaque: [u8; 0],
}

/// `struct pw_stream`, opaque on this side.
#[repr(C)]
pub(crate) struct PwStream {
    _opaque: [u8; 0],
}

#[link(name = "pipewire-0.3")]
unsafe extern "C" {
    /// `void pw_init(int *argc, char **argv[])`. `NULL, NULL` reads the
    /// environment and nothing else — no command line to pass on.
    #[link_name = "pw_init"]
    pub(crate) fn init(argc: *mut i32, argv: *mut *mut *mut c_char);

    /// `struct pw_thread_loop *pw_thread_loop_new(const char *name, const
    /// struct spa_dict *props)`.
    #[link_name = "pw_thread_loop_new"]
    pub(crate) fn thread_loop_new(name: *const c_char, props: *const SpaDict) -> *mut PwThreadLoop;

    /// `void pw_thread_loop_destroy(struct pw_thread_loop *loop)`. Stops the
    /// thread first if it is still running, per the header's own contract.
    #[link_name = "pw_thread_loop_destroy"]
    pub(crate) fn thread_loop_destroy(loop_: *mut PwThreadLoop);

    /// `struct pw_loop *pw_thread_loop_get_loop(struct pw_thread_loop *loop)`.
    #[link_name = "pw_thread_loop_get_loop"]
    pub(crate) fn thread_loop_get_loop(loop_: *mut PwThreadLoop) -> *mut PwLoop;

    /// `int pw_thread_loop_start(struct pw_thread_loop *loop)`.
    #[link_name = "pw_thread_loop_start"]
    pub(crate) fn thread_loop_start(loop_: *mut PwThreadLoop) -> i32;

    /// `void pw_thread_loop_stop(struct pw_thread_loop *loop)`. Must be
    /// called without the loop's own lock held — the header is explicit.
    #[link_name = "pw_thread_loop_stop"]
    pub(crate) fn thread_loop_stop(loop_: *mut PwThreadLoop);

    /// `void pw_thread_loop_lock(struct pw_thread_loop *loop)`.
    #[link_name = "pw_thread_loop_lock"]
    pub(crate) fn thread_loop_lock(loop_: *mut PwThreadLoop);

    /// `void pw_thread_loop_unlock(struct pw_thread_loop *loop)`.
    #[link_name = "pw_thread_loop_unlock"]
    pub(crate) fn thread_loop_unlock(loop_: *mut PwThreadLoop);

    /// `void pw_thread_loop_signal(struct pw_thread_loop *loop, bool
    /// wait_for_accept)`.
    #[link_name = "pw_thread_loop_signal"]
    pub(crate) fn thread_loop_signal(loop_: *mut PwThreadLoop, wait_for_accept: bool);

    /// `int pw_thread_loop_timed_wait(struct pw_thread_loop *loop, int
    /// wait_max_sec)`. Releases the loop's lock and waits, for a signal or
    /// for `wait_max_sec` seconds, whichever is first; the caller must hold
    /// the lock when calling this and holds it again on return. A wait
    /// without the deadline would hang whoever opened a connection to a
    /// daemon that never answers.
    #[link_name = "pw_thread_loop_timed_wait"]
    pub(crate) fn thread_loop_timed_wait(loop_: *mut PwThreadLoop, wait_max_sec: i32) -> i32;

    /// `struct pw_context *pw_context_new(struct pw_loop *main_loop, struct
    /// pw_properties *props, size_t user_data_size)`. Takes ownership of
    /// `props` "even if the function returns NULL"; `props` may be null.
    #[link_name = "pw_context_new"]
    pub(crate) fn context_new(
        main_loop: *mut PwLoop,
        props: *mut PwProperties,
        user_data_size: usize,
    ) -> *mut PwContext;

    /// `void pw_context_destroy(struct pw_context *context)`.
    #[link_name = "pw_context_destroy"]
    pub(crate) fn context_destroy(context: *mut PwContext);

    /// `struct pw_core *pw_context_connect(struct pw_context *context, struct
    /// pw_properties *properties, size_t user_data_size)`. `properties` is
    /// optional, and a set passed here is owned by the call.
    #[link_name = "pw_context_connect"]
    pub(crate) fn context_connect(
        context: *mut PwContext,
        properties: *mut PwProperties,
        user_data_size: usize,
    ) -> *mut PwCore;

    /// `int pw_core_disconnect(struct pw_core *core)`.
    #[link_name = "pw_core_disconnect"]
    pub(crate) fn core_disconnect(core: *mut PwCore) -> i32;

    /// `struct pw_properties *pw_properties_new_string(const char *args)`.
    /// `""` is an empty property set to build up with `properties_set`.
    #[link_name = "pw_properties_new_string"]
    pub(crate) fn properties_new_string(args: *const c_char) -> *mut PwProperties;

    /// `int pw_properties_set(struct pw_properties *properties, const char
    /// *key, const char *value)`.
    #[link_name = "pw_properties_set"]
    pub(crate) fn properties_set(
        properties: *mut PwProperties,
        key: *const c_char,
        value: *const c_char,
    ) -> i32;

    /// `struct pw_stream *pw_stream_new_simple(struct pw_loop *loop, const
    /// char *name, struct pw_properties *props, const struct
    /// pw_stream_events *events, void *data)`.
    ///
    /// Makes its own context and its own connection on `loop`, and destroys
    /// both with the stream. Takes ownership of `props` ("ownership is
    /// taken", `pipewire/stream.h`). `events` is registered as a listener,
    /// so it is kept as a pointer for the stream's whole life and has to be
    /// a `static` — see [`crate::abi::SpaHook`].
    #[link_name = "pw_stream_new_simple"]
    pub(crate) fn stream_new_simple(
        loop_: *mut PwLoop,
        name: *const c_char,
        props: *mut PwProperties,
        events: *const crate::abi::PwStreamEvents,
        data: *mut c_void,
    ) -> *mut PwStream;

    /// `void pw_stream_destroy(struct pw_stream *stream)`.
    #[link_name = "pw_stream_destroy"]
    pub(crate) fn stream_destroy(stream: *mut PwStream);

    /// `int pw_stream_connect(struct pw_stream *stream, enum pw_direction
    /// direction, uint32_t target_id, enum pw_stream_flags flags, const
    /// struct spa_pod **params, uint32_t n_params)`.
    #[link_name = "pw_stream_connect"]
    pub(crate) fn stream_connect(
        stream: *mut PwStream,
        direction: u32,
        target_id: u32,
        flags: u32,
        params: *const *const crate::abi::SpaPod,
        n_params: u32,
    ) -> i32;

    /// `int pw_stream_set_active(struct pw_stream *stream, bool active)`.
    #[link_name = "pw_stream_set_active"]
    pub(crate) fn stream_set_active(stream: *mut PwStream, active: bool) -> i32;

    /// `int pw_stream_get_time_n(struct pw_stream *stream, struct pw_time
    /// *time, size_t size)`. RT safe.
    #[link_name = "pw_stream_get_time_n"]
    pub(crate) fn stream_get_time_n(
        stream: *mut PwStream,
        time: *mut crate::abi::PwTime,
        size: usize,
    ) -> i32;

    /// `struct pw_buffer *pw_stream_dequeue_buffer(struct pw_stream
    /// *stream)`. RT safe.
    #[link_name = "pw_stream_dequeue_buffer"]
    pub(crate) fn stream_dequeue_buffer(stream: *mut PwStream) -> *mut crate::abi::PwBuffer;

    /// `int pw_stream_queue_buffer(struct pw_stream *stream, struct
    /// pw_buffer *buffer)`. RT safe.
    #[link_name = "pw_stream_queue_buffer"]
    pub(crate) fn stream_queue_buffer(
        stream: *mut PwStream,
        buffer: *mut crate::abi::PwBuffer,
    ) -> i32;

    /// `void pw_proxy_destroy(struct pw_proxy *proxy)`. `pw_registry_bind`'s
    /// return value is a `struct pw_proxy *` under whatever interface type it
    /// was bound as, so this takes the same pointer, cast.
    #[link_name = "pw_proxy_destroy"]
    pub(crate) fn proxy_destroy(proxy: *mut c_void);
}

/// Turn a `libpipewire` or SPA return value into a result that names the
/// call. Zero and positive are success across this whole API.
pub(crate) fn check(call: &'static str, code: i32) -> Result<(), Error> {
    match Errno::from_return(code) {
        None => Ok(()),
        Some(errno) => Err(Error::Call { call, errno }),
    }
}

/// Read a method out of an object's `struct spa_interface` head and call it,
/// the way `spa_interface_call` in `spa/utils/hook.h` does: `object` is cast
/// to `struct spa_interface*`, its `cb.funcs` is the method table, and
/// `cb.data` — not `object` itself — is what every method's first argument
/// actually is. A null table or a null slot answers `None` rather than
/// dereferencing, mirroring `SPA_CALLBACK_CHECK`, which every one of these
/// header wrappers guards its own call with.
///
/// # Safety
/// `object` must be a live `pw_core`, `pw_registry` or `pw_metadata` pointer,
/// whose `struct spa_interface` head has a `cb.funcs` pointing to a table of
/// type `Table` — true of every one of `libpipewire`'s own objects, which is
/// what this crate ever calls this with.
unsafe fn interface_call<Table>(object: *mut c_void) -> (*const Table, *mut c_void) {
    // SAFETY: the caller's contract is exactly this cast being valid.
    let iface = unsafe { &*object.cast::<SpaInterface>() };
    (iface.cb_funcs.cast::<Table>(), iface.cb_data)
}

/// `pw_core_add_listener`.
///
/// # Safety
/// `core` is a live `pw_core*`; `listener` outlives the registration this
/// starts and is never moved while it lasts; `events` outlives it too.
pub(crate) unsafe fn core_add_listener(
    core: *mut PwCore,
    listener: *mut SpaHook,
    events: *const PwCoreEvents,
    data: *mut c_void,
) -> i32 {
    // SAFETY: `core` is a live `pw_core*` per this function's contract.
    let (methods, cb_data) = unsafe { interface_call::<PwCoreMethods>(core.cast()) };
    if methods.is_null() {
        return -libc_enotsup();
    }
    // SAFETY: `methods` was just read from a live core's own interface, and
    // `add_listener` is either null (checked) or the function `libpipewire`
    // installed there.
    match unsafe { (*methods).add_listener } {
        // SAFETY: same interface contract; the arguments are this call's own.
        Some(add_listener) => unsafe { add_listener(cb_data, listener, events, data) },
        None => -libc_enotsup(),
    }
}

/// `pw_core_sync`. RT safe on `libpipewire`'s side, but never called from
/// this crate's own realtime callback.
///
/// # Safety
/// `core` is a live `pw_core*`.
pub(crate) unsafe fn core_sync(core: *mut PwCore, id: u32, seq: i32) -> i32 {
    // SAFETY: forwarded from this function's own contract.
    let (methods, cb_data) = unsafe { interface_call::<PwCoreMethods>(core.cast()) };
    if methods.is_null() {
        return -libc_enotsup();
    }
    // SAFETY: see `core_add_listener`.
    match unsafe { (*methods).sync } {
        Some(sync) => unsafe { sync(cb_data, id, seq) },
        None => -libc_enotsup(),
    }
}

/// `pw_core_get_registry(core, PW_VERSION_REGISTRY, 0)`.
///
/// # Safety
/// `core` is a live `pw_core*`.
pub(crate) unsafe fn core_get_registry(core: *mut PwCore, version: u32) -> *mut PwRegistry {
    // SAFETY: forwarded from this function's own contract.
    let (methods, cb_data) = unsafe { interface_call::<PwCoreMethods>(core.cast()) };
    if methods.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: see `core_add_listener`.
    match unsafe { (*methods).get_registry } {
        Some(get_registry) => unsafe { get_registry(cb_data, version, 0).cast() },
        None => ptr::null_mut(),
    }
}

/// `pw_registry_add_listener`.
///
/// # Safety
/// `registry` is a live `pw_registry*`; `listener` and `events` outlive the
/// registration, and `listener` is never moved while it lasts.
pub(crate) unsafe fn registry_add_listener(
    registry: *mut PwRegistry,
    listener: *mut SpaHook,
    events: *const PwRegistryEvents,
    data: *mut c_void,
) -> i32 {
    // SAFETY: forwarded from this function's own contract.
    let (methods, cb_data) = unsafe { interface_call::<PwRegistryMethods>(registry.cast()) };
    if methods.is_null() {
        return -libc_enotsup();
    }
    // SAFETY: see `core_add_listener`.
    match unsafe { (*methods).add_listener } {
        Some(add_listener) => unsafe { add_listener(cb_data, listener, events, data) },
        None => -libc_enotsup(),
    }
}

/// `pw_registry_bind`.
///
/// # Safety
/// `registry` is a live `pw_registry*`; `interface_type` is a NUL-terminated
/// C string naming a type PipeWire actually implements for global `id`.
pub(crate) unsafe fn registry_bind(
    registry: *mut PwRegistry,
    id: u32,
    interface_type: *const c_char,
    version: u32,
) -> *mut c_void {
    // SAFETY: forwarded from this function's own contract.
    let (methods, cb_data) = unsafe { interface_call::<PwRegistryMethods>(registry.cast()) };
    if methods.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: see `core_add_listener`.
    match unsafe { (*methods).bind } {
        Some(bind) => unsafe { bind(cb_data, id, interface_type, version, 0) },
        None => ptr::null_mut(),
    }
}

/// `pw_metadata_add_listener`.
///
/// # Safety
/// `metadata` is a live `pw_metadata*`; `listener` and `events` outlive the
/// registration, and `listener` is never moved while it lasts.
pub(crate) unsafe fn metadata_add_listener(
    metadata: *mut PwMetadata,
    listener: *mut SpaHook,
    events: *const PwMetadataEvents,
    data: *mut c_void,
) -> i32 {
    // SAFETY: forwarded from this function's own contract.
    let (methods, cb_data) = unsafe { interface_call::<PwMetadataMethods>(metadata.cast()) };
    if methods.is_null() {
        return -libc_enotsup();
    }
    // SAFETY: see `core_add_listener`.
    match unsafe { (*methods).add_listener } {
        Some(add_listener) => unsafe { add_listener(cb_data, listener, events, data) },
        None => -libc_enotsup(),
    }
}

/// `spa_hook_remove`, which `spa/utils/hook.h` defines inline: take a hook
/// out of whichever listener list it is linked into, then call the
/// `removed` callback the list's owner may have put in it.
///
/// Then the hook is zeroed, which the header's own version does not do: a
/// zeroed hook reads as never linked, so removing it twice — `close` after a
/// failed `open`, or a metadata binding released on its way out — does
/// nothing the second time rather than unlinking a neighbour.
///
/// # Safety
/// `hook` is either all zero or linked by a `*_add_listener` call into the
/// list of an object that is still alive, and this is called with that
/// object's thread loop locked or on that loop's own thread.
pub(crate) unsafe fn hook_remove(hook: &mut SpaHook) {
    let (next, prev) = (hook.link.next, hook.link.prev);
    // `spa_list_is_initialized`: a hook never linked has a null `prev`
    if !prev.is_null() && !next.is_null() {
        // SAFETY: a linked hook's neighbours are live list nodes of an
        // object that is still alive, per this function's contract; this is
        // `spa_list_remove`.
        unsafe {
            (*prev).next = next;
            (*next).prev = prev;
        }
    }
    if let Some(removed) = hook.removed {
        // SAFETY: installed by the list's owner for exactly this call.
        unsafe { removed(ptr::from_mut(hook)) };
    }
    *hook = SpaHook::new();
}

/// `-ENOTSUP`'s magnitude, the answer `SPA_CALLBACK_CHECK`'s callers fall
/// back to in the header when a table or a slot is missing. Linux's is `95`
/// on every target this crate builds for; naming it here rather than
/// linking `<errno.h>` avoids a C compile step for one constant.
const fn libc_enotsup() -> i32 {
    95
}

#[cfg(test)]
mod tests {
    use super::check;
    use crate::status::{Errno, Error};

    #[test]
    fn zero_and_positive_are_not_failures() {
        assert_eq!(check("pw_stream_connect", 0), Ok(()));
        assert_eq!(check("pw_core_sync", 3), Ok(()));
    }

    #[test]
    fn a_negative_return_keeps_the_call_and_the_errno() {
        assert_eq!(
            check("pw_stream_connect", -2),
            Err(Error::Call {
                call: "pw_stream_connect",
                errno: Errno::from_return(-2).expect("negative"),
            })
        );
    }
}
