// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
//! Enumeration and hotplug: watching the graph's registry for nodes that are
//! sinks or sources, and the metadata object for which one is the session's
//! default.
//!
//! Unlike CoreAudio's `AudioObjectGetPropertyData`, PipeWire has no
//! synchronous "give me the current list" call — the registry hands over
//! nodes as `global` events on the connection's own thread loop, as they
//! exist at the moment a client asks for one, and `pipewire/core.h` says how
//! to find the end of that burst: `pw_core_sync` right after
//! `pw_core_get_registry`, and wait for the core's `done` event carrying the
//! sequence number the sync returned. So a one-shot [`devices`] still starts
//! a thread loop, waits for that burst, reads the snapshot, and tears the
//! loop down — the same steps [`DeviceMonitor`] takes, except it keeps the
//! loop running afterward for hotplug.
//!
//! The default route is not a property of a node at all: it is the
//! `"default.audio.sink"` / `"default.audio.source"` key on the metadata
//! object named `"default"`, a convention every PipeWire session manager and
//! `pipewire-pulse` follow, holding a small JSON object — `{"name":
//! "<node.name>"}` — as its value. This crate binds that one metadata global
//! reactively, the moment the registry's own `global` event reports it,
//! rather than assuming its id. Binding it happens *during* the first burst,
//! so its own first `property` events arrive after the first `done`: start-up
//! syncs a second time, and the second `done` is the one after which the
//! defaults are known.
//!
//! Three listeners are registered here — on the core, on the registry, and
//! on the metadata object — and each one's `*_events` table is a `static`.
//! `crate::abi::SpaHook` says why that is not a style choice: the hook keeps
//! a pointer to the table, and an earlier version of this file built the
//! tables on the stack and crashed inside `libpipewire-module-metadata` the
//! first time the metadata object had something to say.

use core::ffi::{CStr, c_char, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::Instant;

use crate::abi::{self, PwCoreEvents, PwMetadataEvents, PwRegistryEvents, SpaDict, SpaHook};
use crate::device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Pending};
use crate::status::Error;
use crate::sys::{self, PwContext, PwCore, PwMetadata, PwProperties, PwRegistry, PwThreadLoop};

/// How long a one-shot enumeration or a monitor's start-up waits for the
/// registry's initial burst before giving up. PipeWire delivers it in one
/// graph cycle on every machine this was tested against; a number in whole
/// seconds is for a daemon that is not answering at all.
const SYNC_TIMEOUT: Duration = Duration::from_secs(5);

/// How many round trips start-up makes before reading anything: one for the
/// registry's burst, and one for the first `property` events of the
/// metadata object that burst made this crate bind.
const SYNC_ROUNDS: usize = 2;

/// The core's listener. `static` because the hook keeps a pointer to it.
static CORE_EVENTS: PwCoreEvents = PwCoreEvents {
    version: abi::PW_VERSION_CORE_EVENTS,
    info: None,
    done: Some(on_done),
    ping: None,
    error: Some(on_error),
    remove_id: None,
    bound_id: None,
    add_mem: None,
    remove_mem: None,
    bound_props: None,
};

/// The registry's listener, `static` for the same reason.
static REGISTRY_EVENTS: PwRegistryEvents = PwRegistryEvents {
    version: abi::PW_VERSION_REGISTRY_EVENTS,
    global: Some(on_global),
    global_remove: Some(on_global_remove),
};

/// The `"default"` metadata object's listener, `static` for the same reason
/// — and the one whose absence was the crash.
static METADATA_EVENTS: PwMetadataEvents = PwMetadataEvents {
    version: abi::PW_VERSION_METADATA_EVENTS,
    property: Some(on_metadata_property),
};

/// `pw_init` may only be called once per process — repeat calls are not
/// documented as safe, and nothing this crate does needs `pw_deinit` to run
/// before the process exits.
static PW_INIT: Once = Once::new();

pub(crate) fn ensure_init() {
    PW_INIT.call_once(|| {
        // SAFETY: `NULL, NULL` reads the environment and nothing else, and
        // `Once` is what makes this run exactly once across every caller.
        unsafe { sys::init(ptr::null_mut(), ptr::null_mut()) };
    });
}

/// A `pw_properties` built from key/value pairs, starting empty.
///
/// `pub(crate)` because `stream.rs` builds a stream's own properties this
/// way. Whoever it is handed to owns it: `pw_stream_new_simple`, the one
/// call this crate hands a set of properties to, says "ownership is taken"
/// in `pipewire/stream.h`, so nothing here frees one.
pub(crate) fn new_properties(pairs: &[(&CStr, &CStr)]) -> Result<*mut PwProperties, Error> {
    // SAFETY: `c""` is a valid NUL-terminated empty string.
    let props = unsafe { sys::properties_new_string(c"".as_ptr()) };
    if props.is_null() {
        return Err(Error::Refused {
            call: "pw_properties_new_string",
        });
    }
    for (key, value) in pairs {
        // SAFETY: `props` was just checked non-null, and both strings are
        // NUL-terminated for the length of this call, which copies them.
        unsafe { sys::properties_set(props, key.as_ptr(), value.as_ptr()) };
    }
    Ok(props)
}

/// What this crate remembers about one node between `global` events.
struct NodeRecord {
    /// `node.name`: stable across a replug, what [`DeviceId`] wraps.
    name: String,
    /// `node.description`, or `node.name` again when the node gave none.
    description: String,
    direction: Direction,
}

/// The metadata object bound for `"default"`, and the listener on it.
struct MetadataBinding {
    /// The registry's id for it, so that its `global_remove` is recognised.
    global: u32,
    ptr: *mut PwMetadata,
    /// Boxed so its address is stable for as long as it is linked into the
    /// metadata proxy's listener list. Unlinked with `sys::hook_remove`
    /// before the proxy is destroyed and before this is dropped.
    hook: Box<SpaHook>,
}

impl MetadataBinding {
    /// Take the listener off the proxy and destroy the proxy.
    ///
    /// # Safety
    /// Called on the thread loop's own thread or under its lock, with `ptr`
    /// a proxy this crate bound and has not destroyed.
    unsafe fn release(mut self) {
        // SAFETY: per this function's own contract; the hook is either
        // linked into this proxy's list or all zero.
        unsafe {
            sys::hook_remove(&mut self.hook);
            sys::proxy_destroy(self.ptr.cast());
        }
    }
}

/// The state a registry (and, once bound, a metadata) listener writes into,
/// shared with whichever thread reads a snapshot.
struct State {
    /// The loop the listeners run on, which `on_done` and `on_error` signal
    /// to wake whoever is waiting in [`Connection::sync`].
    thread_loop: *mut PwThreadLoop,
    /// Set once `pw_core_get_registry` has answered, before the registry's
    /// listener is added, so that `on_global` never sees it null.
    registry: AtomicPtr<PwRegistry>,
    /// The sequence number the round trip being waited for will come back
    /// with: what `pw_core_sync` returned, which is not the number it was
    /// given.
    awaited: AtomicI32,
    /// Whether the `done` for [`Self::awaited`] has arrived.
    synced: AtomicBool,
    /// Whether the core reported an error on itself — the daemon went away,
    /// or refused this client.
    failed: AtomicBool,
    nodes: Mutex<HashMap<u32, NodeRecord>>,
    default_sink: Mutex<Option<String>>,
    default_source: Mutex<Option<String>>,
    metadata: Mutex<Option<MetadataBinding>>,
    pending: Pending,
}

// SAFETY: every field is an atomic, a `Mutex`, or a pointer to a PipeWire
// object this crate only dereferences on the thread loop's own thread (the
// callbacks below, which `pipewire/thread-loop.h` says run with the loop's
// lock held) or with that lock taken explicitly (`Connection`) — never two at once.
// `thread_loop` itself is only used for `pw_thread_loop_signal`, which is
// what the header gives a callback to wake a waiter with.
unsafe impl Send for State {}
unsafe impl Sync for State {}

impl State {
    fn snapshot(&self) -> Vec<Device> {
        let default_sink = self
            .default_sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let default_source = self
            .default_source
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let nodes = self.nodes.lock().unwrap_or_else(PoisonError::into_inner);
        nodes
            .values()
            .map(|record| {
                let default_name = match record.direction {
                    Direction::Output => default_sink.as_deref(),
                    Direction::Input => default_source.as_deref(),
                };
                Device {
                    id: DeviceId::new(record.name.clone()),
                    name: record.description.clone(),
                    direction: record.direction,
                    is_default: default_name == Some(record.name.as_str()),
                }
            })
            .collect()
    }

    fn default_id(&self, direction: Direction) -> Option<DeviceId> {
        let name = match direction {
            Direction::Output => self
                .default_sink
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            Direction::Input => self
                .default_source
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }?;
        Some(DeviceId::new(name))
    }
}

/// Pull a string field out of a small, flat JSON object —
/// `{"name":"alsa_output...", ...}` — without a general JSON parser.
///
/// The value this is used for is the one object the `"default"` metadata
/// keeps per key, written by the session manager: one level deep, string
/// values. A `node.name` PipeWire generated from a card or a Bluetooth
/// address never needs escaping, but one a person gave a virtual device can
/// hold a quote or a backslash, so the two escapes JSON has for those are
/// read rather than taken as the end of the value; the rest of JSON's escapes
/// are for text no node name contains, and a value that uses one is
/// answered with `None` rather than guessed at.
fn json_string_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let after_key = json.find(&needle)? + needle.len();
    let rest = json.get(after_key..)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut value = String::new();
    let mut characters = rest.chars();
    loop {
        match characters.next()? {
            '"' => return Some(value),
            '\\' => match characters.next()? {
                escaped @ ('"' | '\\' | '/') => value.push(escaped),
                _ => return None,
            },
            other => value.push(other),
        }
    }
}

/// The state a listener was registered with.
///
/// # Safety
/// `data` is the `data` pointer one of this module's `*_add_listener` calls
/// was given: an `Arc<State>`'s pointee, which [`Connection`] keeps alive until the
/// listener is unlinked and the thread loop has stopped.
unsafe fn state<'a>(data: *mut c_void) -> &'a State {
    // SAFETY: per this function's own contract.
    unsafe { &*data.cast::<State>() }
}

/// `pw_core_events.done`: the round trip [`Connection::sync`] started has come
/// back.
unsafe extern "C" fn on_done(data: *mut c_void, id: u32, seq: i32) {
    // SAFETY: registered with a `State`, per `state`'s contract.
    let state = unsafe { state(data) };
    if id != abi::PW_ID_CORE || seq != state.awaited.load(Ordering::SeqCst) {
        return;
    }
    state.synced.store(true, Ordering::SeqCst);
    // SAFETY: the loop is running — this is its own thread calling — and
    // signalling from inside one of its callbacks is what the header gives
    // a callback to wake a waiter with.
    unsafe { sys::thread_loop_signal(state.thread_loop, false) };
}

/// `pw_core_events.error`: an error on the core object itself means the
/// connection is not coming back — the daemon went away, or refused this
/// client — so whoever waits for a round trip stops waiting.
unsafe extern "C" fn on_error(
    data: *mut c_void,
    id: u32,
    _seq: i32,
    _res: i32,
    _message: *const c_char,
) {
    if id != abi::PW_ID_CORE {
        return;
    }
    // SAFETY: registered with a `State`, per `state`'s contract.
    let state = unsafe { state(data) };
    state.failed.store(true, Ordering::SeqCst);
    // SAFETY: as in `on_done`.
    unsafe { sys::thread_loop_signal(state.thread_loop, false) };
}

/// `pw_registry_events.global`.
unsafe extern "C" fn on_global(
    data: *mut c_void,
    id: u32,
    _permissions: u32,
    interface_type: *const c_char,
    _version: u32,
    props: *const SpaDict,
) {
    if interface_type.is_null() || props.is_null() {
        return;
    }
    // SAFETY: registered with a `State`, per `state`'s contract.
    // `interface_type` and `props` are valid for the length of this call,
    // which is all a registry event promises about them.
    let (state, type_str, props) =
        unsafe { (state(data), CStr::from_ptr(interface_type), &*props) };

    if type_str == abi::PW_TYPE_INTERFACE_NODE {
        // SAFETY: `props` is valid for the length of this call.
        let Some(class) = (unsafe { props.get(abi::PW_KEY_MEDIA_CLASS) }) else {
            return;
        };
        let direction = if class == Direction::Output.media_class() {
            Direction::Output
        } else if class == Direction::Input.media_class() {
            Direction::Input
        } else {
            return;
        };
        // SAFETY: same contract.
        let Some(name) = (unsafe { props.get(abi::PW_KEY_NODE_NAME) }) else {
            return;
        };
        // SAFETY: same contract.
        let description =
            unsafe { props.get(abi::PW_KEY_NODE_DESCRIPTION) }.unwrap_or_else(|| name.clone());

        state
            .nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                NodeRecord {
                    name,
                    description,
                    direction,
                },
            );
        state.pending.note(DeviceEvent::ListChanged);
    } else if type_str == abi::PW_TYPE_INTERFACE_METADATA {
        // SAFETY: same contract.
        let is_default =
            unsafe { props.get(abi::PW_KEY_METADATA_NAME) }.as_deref() == Some("default");
        if is_default {
            bind_default_metadata(state, id, data);
        }
    }
}

/// Bind the `"default"` metadata global and listen to it, unless one is
/// bound already.
fn bind_default_metadata(state: &State, id: u32, data: *mut c_void) {
    let mut slot = state
        .metadata
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if slot.is_some() {
        return;
    }
    let registry = state.registry.load(Ordering::SeqCst);
    // SAFETY: set before the registry's listener was added, and the registry
    // proxy lives until `Connection::close` disconnects the core, after removing
    // this listener; this runs on the loop's own thread.
    let bound = unsafe {
        sys::registry_bind(
            registry,
            id,
            abi::PW_TYPE_INTERFACE_METADATA.as_ptr(),
            abi::PW_VERSION_METADATA,
        )
    };
    if bound.is_null() {
        return;
    }
    let mut binding = MetadataBinding {
        global: id,
        ptr: bound.cast::<PwMetadata>(),
        hook: Box::new(SpaHook::new()),
    };
    // SAFETY: the proxy was just bound; the hook is boxed and is moved, box
    // and all, into `state.metadata` below, so the address PipeWire links
    // stays put until `MetadataBinding::release` unlinks it; the table is a
    // `static`; `data` is the same `State` the registry listener was given.
    let added = unsafe {
        sys::metadata_add_listener(
            binding.ptr,
            &raw mut *binding.hook,
            &raw const METADATA_EVENTS,
            data,
        )
    };
    if added < 0 {
        // SAFETY: on this loop's thread; the proxy was bound here and has not
        // been destroyed, and its hook is either linked or still all zero.
        unsafe { binding.release() };
        return;
    }
    *slot = Some(binding);
}

/// `pw_registry_events.global_remove`.
unsafe extern "C" fn on_global_remove(data: *mut c_void, id: u32) {
    // SAFETY: registered with a `State`, per `state`'s contract.
    let state = unsafe { state(data) };
    let removed = state
        .nodes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id)
        .is_some();
    if removed {
        state.pending.note(DeviceEvent::ListChanged);
        return;
    }
    let mut slot = state
        .metadata
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if slot.as_ref().is_some_and(|binding| binding.global == id)
        && let Some(binding) = slot.take()
    {
        // The session manager restarting takes its metadata object with it.
        // The proxy for it is dead weight from here, and its listener has to
        // come off before the proxy goes; when the manager comes back, its
        // new `"default"` global is bound afresh by `on_global`.
        //
        // SAFETY: on the loop's own thread; this proxy was bound by
        // `bind_default_metadata` and not yet destroyed.
        unsafe { binding.release() };
    }
}

/// `pw_metadata_events.property`.
///
/// Only subject `PW_ID_CORE` is the session's own. The `"default"` object
/// also keeps keys under other nodes' ids — `target.object`, where a stream
/// was moved to — and PipeWire 1.4 clears those, with a null key, when the
/// node goes. Read as the session's, every moved stream that ended would
/// have wiped both defaults.
unsafe extern "C" fn on_metadata_property(
    data: *mut c_void,
    subject: u32,
    key: *const c_char,
    _value_type: *const c_char,
    value: *const c_char,
) -> i32 {
    if subject != abi::PW_ID_CORE {
        return 0;
    }
    // SAFETY: registered with a `State`, per `state`'s contract.
    let state = unsafe { state(data) };
    if key.is_null() {
        // `pipewire/extensions/metadata.h`: a null key means every property
        // of the subject was removed, the two this crate reads among them
        set_default(state, Direction::Output, None);
        set_default(state, Direction::Input, None);
        return 0;
    }
    // SAFETY: `key` is non-null and NUL-terminated for the length of this
    // call, which is all a metadata event promises about it.
    let direction = match unsafe { CStr::from_ptr(key) }.to_bytes() {
        b"default.audio.sink" => Direction::Output,
        b"default.audio.source" => Direction::Input,
        _ => return 0,
    };
    let name = if value.is_null() {
        // the key was cleared
        None
    } else {
        // SAFETY: a non-null value is a NUL-terminated string for the length
        // of this call.
        let json = unsafe { CStr::from_ptr(value) }.to_string_lossy();
        json_string_field(&json, "name")
    };
    set_default(state, direction, name);
    0
}

/// Record the default node for a direction, and note it when it changed.
fn set_default(state: &State, direction: Direction, name: Option<String>) {
    let slot = match direction {
        Direction::Output => &state.default_sink,
        Direction::Input => &state.default_source,
    };
    let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if *slot != name {
        *slot = name;
        drop(slot);
        state.pending.note(DeviceEvent::DefaultChanged(direction));
    }
}

/// Everything a connection owns, torn down together by [`Connection::close`] — which
/// is also what cleans up after an [`Connection::open`] that got part of the way.
struct Connection {
    thread_loop: *mut PwThreadLoop,
    context: *mut PwContext,
    /// Null until connected.
    core: *mut PwCore,
    /// Null until asked for.
    registry: *mut PwRegistry,
    /// Linked into the core's listener list once connected, and unlinked by
    /// `close` before the core is disconnected. Boxed: it must not move
    /// while linked, and a `Connection` does.
    core_hook: Box<SpaHook>,
    /// The same, for the registry.
    registry_hook: Box<SpaHook>,
    state: Arc<State>,
    /// Whether the loop's thread was started, and so has to be stopped.
    running: bool,
    closed: bool,
}

// SAFETY: every pointer here is to a PipeWire object touched only under the
// thread loop's lock, taken by `open` and `close` — the header's rule for
// using a thread loop's objects from another thread — and `state` is already
// `Send + Sync`. `DeviceMonitor`'s readers go through `state` alone.
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

impl Connection {
    /// Connect, listen to the core and the registry, and wait until the
    /// graph's nodes and its default routes are known.
    fn open() -> Result<Self, Error> {
        ensure_init();

        // SAFETY: a NUL-terminated name, and no properties.
        let thread_loop =
            unsafe { sys::thread_loop_new(c"sipral-io-pipewire".as_ptr(), ptr::null()) };
        if thread_loop.is_null() {
            return Err(Error::Refused {
                call: "pw_thread_loop_new",
            });
        }
        // SAFETY: `thread_loop` was just checked non-null. The loop it wraps
        // lives as long as it does, which is longer than the context below:
        // `close` destroys the context first.
        let pw_loop = unsafe { sys::thread_loop_get_loop(thread_loop) };
        // SAFETY: `pw_loop` is live. No properties: `pipewire/context.h` says
        // ownership of a set passed here is taken even on failure, and there
        // is nothing this crate needs to set on a context.
        let context = unsafe { sys::context_new(pw_loop, ptr::null_mut(), 0) };
        if context.is_null() {
            // SAFETY: nothing else references `thread_loop`, which was never
            // started.
            unsafe { sys::thread_loop_destroy(thread_loop) };
            return Err(Error::Refused {
                call: "pw_context_new",
            });
        }

        let mut this = Self {
            thread_loop,
            context,
            core: ptr::null_mut(),
            registry: ptr::null_mut(),
            core_hook: Box::new(SpaHook::new()),
            registry_hook: Box::new(SpaHook::new()),
            state: Arc::new(State {
                thread_loop,
                registry: AtomicPtr::new(ptr::null_mut()),
                awaited: AtomicI32::new(0),
                synced: AtomicBool::new(false),
                failed: AtomicBool::new(false),
                nodes: Mutex::new(HashMap::new()),
                default_sink: Mutex::new(None),
                default_source: Mutex::new(None),
                metadata: Mutex::new(None),
                pending: Pending::new(),
            }),
            running: false,
            closed: false,
        };

        // SAFETY: `thread_loop` is live and not yet started.
        sys::check("pw_thread_loop_start", unsafe {
            sys::thread_loop_start(thread_loop)
        })?;
        this.running = true;

        // SAFETY: the loop is running, and everything below touches objects
        // it owns, so it is done under its lock; `connect` and `sync` wait
        // with `pw_thread_loop_timed_wait`, which releases it while waiting.
        unsafe { sys::thread_loop_lock(thread_loop) };
        let connected = this.connect();
        // SAFETY: balances the lock above, on every path.
        unsafe { sys::thread_loop_unlock(thread_loop) };
        // an error drops `this`, and `close` undoes whatever part was done
        connected.map(|()| this)
    }

    /// The part of `open` done under the loop's lock.
    fn connect(&mut self) -> Result<(), Error> {
        // SAFETY: `context` is live and the lock is held. No properties, as
        // for `pw_context_new`.
        self.core = unsafe { sys::context_connect(self.context, ptr::null_mut(), 0) };
        if self.core.is_null() {
            return Err(Error::Refused {
                call: "pw_context_connect",
            });
        }
        let data = ptr::from_ref(self.state.as_ref())
            .cast_mut()
            .cast::<c_void>();
        // SAFETY: `core` is live; the hook is boxed, all zero, and stays
        // where it is until `close` unlinks it; the table is a `static`;
        // `data` is the `State` this `Connection` keeps alive past the unlinking.
        sys::check("pw_core_add_listener", unsafe {
            sys::core_add_listener(
                self.core,
                &raw mut *self.core_hook,
                &raw const CORE_EVENTS,
                data,
            )
        })?;
        // SAFETY: `core` is live.
        self.registry = unsafe { sys::core_get_registry(self.core, abi::PW_VERSION_REGISTRY) };
        if self.registry.is_null() {
            return Err(Error::Refused {
                call: "pw_core_get_registry",
            });
        }
        self.state.registry.store(self.registry, Ordering::SeqCst);
        // SAFETY: as for the core's listener above.
        sys::check("pw_registry_add_listener", unsafe {
            sys::registry_add_listener(
                self.registry,
                &raw mut *self.registry_hook,
                &raw const REGISTRY_EVENTS,
                data,
            )
        })?;
        for _ in 0..SYNC_ROUNDS {
            self.sync()?;
        }
        Ok(())
    }

    /// One round trip to the daemon: everything it had to say before this
    /// has been said, and every listener has heard it, when this returns.
    ///
    /// Called with the loop's lock held. `pw_core_sync` returns the number
    /// the `done` will carry — not the one it is given — and that is written
    /// down before the lock is released to wait, so the `done` cannot arrive
    /// before anyone knows what to look for.
    fn sync(&mut self) -> Result<(), Error> {
        self.state.synced.store(false, Ordering::SeqCst);
        // SAFETY: `core` is live and the lock is held.
        let seq = unsafe { sys::core_sync(self.core, abi::PW_ID_CORE, 0) };
        sys::check("pw_core_sync", seq)?;
        self.state.awaited.store(seq, Ordering::SeqCst);
        let started = Instant::now();
        while !self.state.synced.load(Ordering::SeqCst) {
            if self.state.failed.load(Ordering::SeqCst) {
                return Err(Error::Refused {
                    call: "pw_core_sync (the connection failed)",
                });
            }
            if started.elapsed() >= SYNC_TIMEOUT {
                return Err(Error::Refused {
                    call: "pw_core_sync (no answer)",
                });
            }
            // SAFETY: the lock is held, which the wait releases while it
            // waits and takes back before returning. A second at most, so a
            // daemon that never answers is noticed by the check above.
            unsafe { sys::thread_loop_timed_wait(self.thread_loop, 1) };
        }
        Ok(())
    }

    /// Undo whatever `open` got done, in the order that leaves PipeWire
    /// nothing of ours to call.
    ///
    /// Listeners come off first, under the lock — the metadata object's,
    /// the registry's and the core's — so that nothing can be emitted into a
    /// hook this is about to free; then the core is disconnected, which
    /// destroys the registry proxy with it; then the loop's thread is
    /// stopped, outside the lock as `pipewire/thread-loop.h` requires, and
    /// joined, so no callback is still running; and only then are the
    /// context, the loop, and — when `self` drops — the hooks and the state
    /// freed.
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if self.running {
            // SAFETY: the loop is running; the lock is what every touch of
            // its objects is made under.
            unsafe { sys::thread_loop_lock(self.thread_loop) };
            let binding = self
                .state
                .metadata
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(binding) = binding {
                // SAFETY: under the lock; bound by this connection and not
                // yet destroyed.
                unsafe { binding.release() };
            }
            // SAFETY: under the lock. A hook that was never linked is all
            // zero, which `hook_remove` leaves alone.
            unsafe {
                sys::hook_remove(&mut self.registry_hook);
                sys::hook_remove(&mut self.core_hook);
            }
            if !self.core.is_null() {
                // SAFETY: under the lock; `core` is live. What it returns
                // says nothing a caller dropping a connection could act on.
                unsafe { sys::core_disconnect(self.core) };
            }
            // SAFETY: balances the lock above.
            unsafe { sys::thread_loop_unlock(self.thread_loop) };
            // SAFETY: without the lock held, as the header requires; this
            // joins the loop's thread.
            unsafe { sys::thread_loop_stop(self.thread_loop) };
        }
        // SAFETY: the loop's thread is not running, so nothing else touches
        // either; the context goes first, since it runs on the loop.
        unsafe {
            sys::context_destroy(self.context);
            sys::thread_loop_destroy(self.thread_loop);
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}

/// Watches the graph's nodes and remembers what changed.
///
/// A headset arriving or leaving is not an error and does not interrupt a
/// stream running on another node; it is a fact the caller may want to act
/// on, so it waits here until asked for. Dropping the monitor stops the
/// watching.
pub struct DeviceMonitor(Connection);

impl DeviceMonitor {
    /// Connect to PipeWire and start watching the node list and the default
    /// route.
    ///
    /// # Errors
    /// [`Error::Refused`] when any step of connecting fails, or
    /// [`Error::Call`] when a `libpipewire` call the connection depends on
    /// refuses.
    pub fn new() -> Result<Self, Error> {
        Connection::open().map(Self)
    }

    /// Every node the graph has, as of the last change this monitor saw.
    #[must_use]
    pub fn devices(&self) -> Vec<Device> {
        self.0.state.snapshot()
    }

    /// The session's default node for a direction, if it has named one.
    #[must_use]
    pub fn default_device(&self, direction: Direction) -> Option<DeviceId> {
        self.0.state.default_id(direction)
    }

    /// Take one change, or `None` when nothing has happened since the last
    /// time. Several changes of the same kind arrive as one.
    #[must_use]
    pub fn poll(&self) -> Option<DeviceEvent> {
        self.0.state.pending.take()
    }

    /// Stop watching. Dropping the monitor does the same.
    pub fn close(mut self) {
        self.0.close();
    }
}

/// Every node the graph has right now: connect, wait for the registry's
/// initial burst, read it, and disconnect.
///
/// # Errors
/// The same as [`DeviceMonitor::new`].
pub fn devices() -> Result<Vec<Device>, Error> {
    let monitor = DeviceMonitor::new()?;
    let devices = monitor.devices();
    monitor.close();
    Ok(devices)
}

/// The session's default node for a direction, right now.
///
/// # Errors
/// The same as [`DeviceMonitor::new`].
pub fn default_device(direction: Direction) -> Result<Option<DeviceId>, Error> {
    let monitor = DeviceMonitor::new()?;
    let id = monitor.default_device(direction);
    monitor.close();
    Ok(id)
}

/// Resolve a [`DeviceChoice`] against the graph as it is now: the node a
/// stream should name as its `target.object`, or `None` when the choice
/// falls back to a session that has named no default.
///
/// Every choice is looked up, the session's route included —
/// [`DeviceChoice::resolve`] says why a stream is never left for the session
/// manager to follow. A named node is looked up among this direction's
/// rather than handed over as it is, because the session manager's answer
/// to a `target.object` it cannot find is to link the stream to the default
/// instead — right for a preference and wrong for a named device, which is
/// "that node and nothing else".
///
/// # Errors
/// [`Error::NoDevice`] for a named device the graph does not have in this
/// direction, and whatever connecting to look it up says.
pub(crate) fn resolve(
    choice: &DeviceChoice,
    direction: Direction,
) -> Result<Option<DeviceId>, Error> {
    choice.resolve(direction, &devices()?)
}

#[cfg(test)]
mod tests {
    use super::{State, json_string_field, on_metadata_property};
    use crate::abi::PW_ID_CORE;
    use crate::device::{DeviceEvent, DeviceId, Direction, Pending};
    use core::ffi::{CStr, c_void};
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A listener's state with no connection behind it: the metadata
    /// listener signals no loop, so this is all it touches.
    fn detached() -> State {
        State {
            thread_loop: ptr::null_mut(),
            registry: AtomicPtr::new(ptr::null_mut()),
            awaited: AtomicI32::new(0),
            synced: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            nodes: Mutex::new(HashMap::new()),
            default_sink: Mutex::new(None),
            default_source: Mutex::new(None),
            metadata: Mutex::new(None),
            pending: Pending::new(),
        }
    }

    /// One `property` event, the way the metadata proxy delivers it.
    fn property(state: &State, subject: u32, key: Option<&CStr>, value: Option<&CStr>) {
        let data = ptr::from_ref(state).cast_mut().cast::<c_void>();
        let key = key.map_or(ptr::null(), CStr::as_ptr);
        let value = value.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: `data` is a live `State`, and the strings are
        // NUL-terminated for the length of the call.
        unsafe { on_metadata_property(data, subject, key, ptr::null(), value) };
    }

    #[test]
    fn only_the_sessions_own_subject_names_the_defaults() {
        let state = detached();
        property(
            &state,
            PW_ID_CORE,
            Some(c"default.audio.source"),
            Some(c"{\"name\":\"sipral-mic\"}"),
        );
        assert_eq!(
            state.default_id(Direction::Input),
            Some(DeviceId::new("sipral-mic"))
        );
        assert_eq!(
            state.pending.take(),
            Some(DeviceEvent::DefaultChanged(Direction::Input))
        );

        // a stream that was moved, and has gone: its own keys cleared
        property(&state, 57, None, None);
        // and a key of the same name on some other node is that node's
        property(
            &state,
            57,
            Some(c"default.audio.source"),
            Some(c"{\"name\":\"elsewhere\"}"),
        );
        assert_eq!(
            state.default_id(Direction::Input),
            Some(DeviceId::new("sipral-mic"))
        );
        assert_eq!(state.pending.take(), None);

        // the session's own keys cleared is the default gone
        property(&state, PW_ID_CORE, None, None);
        assert_eq!(state.default_id(Direction::Input), None);
        assert_eq!(
            state.pending.take(),
            Some(DeviceEvent::DefaultChanged(Direction::Input))
        );
    }

    #[test]
    fn a_plain_default_nodes_value_gives_up_its_name() {
        let json = r#"{"name":"alsa_output.pci-0000_00_1f.3.analog-stereo"}"#;
        assert_eq!(
            json_string_field(json, "name").as_deref(),
            Some("alsa_output.pci-0000_00_1f.3.analog-stereo")
        );
    }

    #[test]
    fn extra_whitespace_and_fields_do_not_confuse_it() {
        let json = r#"{ "name" : "bluez_output.AA_BB_CC.1" , "other": 1 }"#;
        assert_eq!(
            json_string_field(json, "name").as_deref(),
            Some("bluez_output.AA_BB_CC.1")
        );
    }

    #[test]
    fn a_missing_field_or_malformed_json_gives_nothing() {
        assert_eq!(json_string_field(r#"{"other":"x"}"#, "name"), None);
        assert_eq!(json_string_field("not json at all", "name"), None);
        assert_eq!(json_string_field(r#"{"name":}"#, "name"), None);
        // a value that never ends is not a value
        assert_eq!(json_string_field(r#"{"name":"alsa_output"#, "name"), None);
    }

    /// A virtual device a person named can carry a quote; the value runs to
    /// the quote that is not escaped, not to the first one.
    #[test]
    fn an_escaped_quote_is_part_of_the_name() {
        assert_eq!(
            json_string_field(r#"{"name":"my \"desk\" mic\\2"}"#, "name").as_deref(),
            Some(r#"my "desk" mic\2"#)
        );
        // an escape no node name needs — a backslash, a `u` and four hex
        // digits — is refused rather than guessed at
        let unicode = format!(r#"{{"name":"a{}u0041"}}"#, '\\');
        assert_eq!(json_string_field(&unicode, "name"), None);
    }
}
