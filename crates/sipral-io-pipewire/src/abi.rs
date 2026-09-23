// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The structures and constants PipeWire and SPA read, declared from their
//! public headers (`spa/pod/pod.h`, `spa/utils/hook.h`, `spa/utils/dict.h`,
//! `spa/buffer/buffer.h`, `spa/param/param.h`, `spa/param/format.h`,
//! `spa/param/audio/raw.h`, `pipewire/stream.h`, `pipewire/core.h`,
//! `pipewire/extensions/metadata.h`) rather than generated from them: SPA's
//! own helpers for reading and building these — `spa_pod_builder`,
//! `spa_format_audio_raw_build`, `spa_interface_call` — are `static inline`
//! in the header and compile into whichever binary includes them, so there is
//! no `libspa.so` symbol to link even if this crate wanted one. What is
//! declared here is the layout those inline functions read and write, worked
//! out from the header source rather than borrowed from it.
//!
//! Every field keeps the width the header gives it and the order the header
//! gives it in. The names are ours.

use core::ffi::{c_char, c_void};

/// A pod's eight-byte header: `struct spa_pod { uint32_t size; uint32_t type; }`.
/// `size` is the body's length, never including this header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SpaPod {
    pub(crate) size: u32,
    pub(crate) type_: u32,
}

/// `SPA_TYPE_Id`: `enum spa_type` in `spa/utils/type.h`, an identifier drawn
/// from a closed set — a format, a media type, a channel position.
pub(crate) const SPA_TYPE_ID: u32 = 3;
/// `SPA_TYPE_Int`.
pub(crate) const SPA_TYPE_INT: u32 = 4;
/// `SPA_TYPE_Array`.
pub(crate) const SPA_TYPE_ARRAY: u32 = 13;
/// `SPA_TYPE_Object`.
pub(crate) const SPA_TYPE_OBJECT: u32 = 15;

/// `SPA_TYPE_OBJECT_Format`: `0x40000 + 3`, the object type a format
/// parameter is built as.
pub(crate) const SPA_TYPE_OBJECT_FORMAT: u32 = 0x4_0003;

/// `SPA_PARAM_EnumFormat`: `enum spa_param_type` in `spa/param/param.h`. The
/// id a format object is passed to `pw_stream_connect` under.
pub(crate) const SPA_PARAM_ENUM_FORMAT: u32 = 3;

/// `SPA_FORMAT_mediaType`: `enum spa_format` in `spa/param/format.h`.
pub(crate) const SPA_FORMAT_MEDIA_TYPE: u32 = 1;
/// `SPA_FORMAT_mediaSubtype`.
pub(crate) const SPA_FORMAT_MEDIA_SUBTYPE: u32 = 2;
/// `SPA_FORMAT_START_Audio + 1`: `SPA_FORMAT_AUDIO_format`.
pub(crate) const SPA_FORMAT_AUDIO_FORMAT: u32 = 0x1_0001;
/// `SPA_FORMAT_START_Audio + 3`: `SPA_FORMAT_AUDIO_rate`.
pub(crate) const SPA_FORMAT_AUDIO_RATE: u32 = 0x1_0003;
/// `SPA_FORMAT_START_Audio + 4`: `SPA_FORMAT_AUDIO_channels`.
pub(crate) const SPA_FORMAT_AUDIO_CHANNELS: u32 = 0x1_0004;
/// `SPA_FORMAT_START_Audio + 5`: `SPA_FORMAT_AUDIO_position`.
pub(crate) const SPA_FORMAT_AUDIO_POSITION: u32 = 0x1_0005;

/// `SPA_MEDIA_TYPE_audio`: `enum spa_media_type` in `spa/param/format.h`.
pub(crate) const SPA_MEDIA_TYPE_AUDIO: u32 = 1;
/// `SPA_MEDIA_SUBTYPE_raw`: `enum spa_media_subtype`.
pub(crate) const SPA_MEDIA_SUBTYPE_RAW: u32 = 1;

/// `SPA_AUDIO_FORMAT_S16_LE`: `enum spa_audio_format` in
/// `spa/param/audio/raw.h`, `SPA_AUDIO_FORMAT_START_Interleaved + 3`. This
/// crate's boundary is signed sixteen-bit, and every target Sipral builds
/// `sipral-io-pipewire` for is little-endian, so the plain (native-endian)
/// `SPA_AUDIO_FORMAT_S16` alias and this one are the same value.
pub(crate) const SPA_AUDIO_FORMAT_S16: u32 = 259;

/// `SPA_AUDIO_CHANNEL_MONO`: `enum spa_audio_channel`, after `UNKNOWN` and
/// `NA`. The one position a mono stream's one channel has — see
/// [`FormatPod::new`].
pub(crate) const SPA_AUDIO_CHANNEL_MONO: u32 = 2;

/// `SPA_DIRECTION_INPUT` / `PW_DIRECTION_INPUT`: a stream that consumes data
/// — capture, reading from a `Audio/Source` node.
pub(crate) const PW_DIRECTION_INPUT: u32 = 0;
/// `SPA_DIRECTION_OUTPUT` / `PW_DIRECTION_OUTPUT`: a stream that produces
/// data — playback, writing to an `Audio/Sink` node.
pub(crate) const PW_DIRECTION_OUTPUT: u32 = 1;

/// `PW_ID_ANY`: let PipeWire (or the `PW_KEY_TARGET_OBJECT` property) choose
/// the node, rather than naming one by its numeric global id.
pub(crate) const PW_ID_ANY: u32 = 0xffff_ffff;
/// `PW_ID_CORE`: the core object's own id after connecting, which is what
/// `pw_core_sync` is called with.
pub(crate) const PW_ID_CORE: u32 = 0;

/// `PW_STREAM_FLAG_AUTOCONNECT`: let the session manager link the stream,
/// to `target.object` when the properties name one and to the session's
/// default node when they do not.
pub(crate) const PW_STREAM_FLAG_AUTOCONNECT: u32 = 1 << 0;
/// `PW_STREAM_FLAG_INACTIVE`: connect and negotiate, but do not process until
/// `pw_stream_set_active` says so, so that opening a stream and starting it
/// are two different calls, the same as `sipral-io-coreaudio` and
/// `sipral-io-wasapi`. `stream.rs`'s own `start` is what leaves this state.
pub(crate) const PW_STREAM_FLAG_INACTIVE: u32 = 1 << 1;
/// `PW_STREAM_FLAG_MAP_BUFFERS`: map every buffer's memory into this process,
/// so that `spa_data.data` is a pointer the process callback can read and
/// write rather than a file descriptor it would have to map itself.
pub(crate) const PW_STREAM_FLAG_MAP_BUFFERS: u32 = 1 << 2;
/// `PW_STREAM_FLAG_RT_PROCESS`: call `process` from the realtime data thread
/// rather than from the thread loop — which is the only way a period is
/// never late behind whatever else that loop is doing, and why the callback
/// touches nothing but the ring, a few atomics and the calls `stream.h`
/// marks RT safe.
pub(crate) const PW_STREAM_FLAG_RT_PROCESS: u32 = 1 << 4;
/// `PW_STREAM_FLAG_DONT_RECONNECT`: a lost node is reported as
/// [`crate::StreamEvent::DeviceLost`] rather than silently rerouted, which is
/// what lets this crate's own recovery own the decision. `pipewire/keys.h`
/// says what the session manager does instead for the property this flag
/// sets, `node.dont-reconnect`: "if the target is removed, the node is
/// destroyed" — which reaches the stream as a state change it did not ask for.
pub(crate) const PW_STREAM_FLAG_DONT_RECONNECT: u32 = 1 << 7;

/// `enum pw_stream_state`: `PW_STREAM_STATE_ERROR`.
pub(crate) const PW_STREAM_STATE_ERROR: i32 = -1;
/// `PW_STREAM_STATE_UNCONNECTED`.
pub(crate) const PW_STREAM_STATE_UNCONNECTED: i32 = 0;
/// `PW_STREAM_STATE_PAUSED`: connected and negotiated, and not processing.
pub(crate) const PW_STREAM_STATE_PAUSED: i32 = 2;
/// `PW_STREAM_STATE_STREAMING`.
pub(crate) const PW_STREAM_STATE_STREAMING: i32 = 3;

/// `SPA_PARAM_Format`: the id `param_changed` carries for the format the
/// adapter settled on, as opposed to the `SPA_PARAM_EnumFormat` this crate
/// offers when connecting.
pub(crate) const SPA_PARAM_FORMAT: u32 = 4;

/// `PW_VERSION_STREAM_EVENTS`.
pub(crate) const PW_VERSION_STREAM_EVENTS: u32 = 2;
/// `PW_VERSION_CORE_EVENTS`.
pub(crate) const PW_VERSION_CORE_EVENTS: u32 = 1;
/// `PW_VERSION_REGISTRY_EVENTS`.
pub(crate) const PW_VERSION_REGISTRY_EVENTS: u32 = 0;
/// `PW_VERSION_METADATA_EVENTS`.
pub(crate) const PW_VERSION_METADATA_EVENTS: u32 = 0;
/// `PW_VERSION_REGISTRY`, the interface version `pw_core_get_registry` is
/// asked for.
pub(crate) const PW_VERSION_REGISTRY: u32 = 3;
/// `PW_VERSION_METADATA`, the interface version `pw_registry_bind` is asked
/// for when binding the `"default"` metadata object.
pub(crate) const PW_VERSION_METADATA: u32 = 3;

/// `PW_TYPE_INTERFACE_Metadata`: `"PipeWire:Interface:Metadata"`, the
/// `type` a registry `global` event carries for the metadata object, and
/// what `pw_registry_bind` is told to bind to.
pub(crate) const PW_TYPE_INTERFACE_METADATA: &core::ffi::CStr = c"PipeWire:Interface:Metadata";
/// `PW_TYPE_INTERFACE_Node`: `"PipeWire:Interface:Node"`, the `type` a
/// registry `global` event carries for a sink or source.
pub(crate) const PW_TYPE_INTERFACE_NODE: &core::ffi::CStr = c"PipeWire:Interface:Node";

/// `PW_KEY_METADATA_NAME`: `"metadata.name"`. The metadata object this crate
/// wants is the one whose value for this key is `"default"` — the session's
/// own record of which node is the default sink and source.
pub(crate) const PW_KEY_METADATA_NAME: &core::ffi::CStr = c"metadata.name";
/// `PW_KEY_MEDIA_CLASS`: `"media.class"`, `"Audio/Sink"` or `"Audio/Source"`
/// on the nodes this crate lists.
pub(crate) const PW_KEY_MEDIA_CLASS: &core::ffi::CStr = c"media.class";
/// `PW_KEY_NODE_NAME`: `"node.name"`, what [`crate::DeviceId`] wraps.
pub(crate) const PW_KEY_NODE_NAME: &core::ffi::CStr = c"node.name";
/// `PW_KEY_NODE_DESCRIPTION`: `"node.description"`, what a person reads.
pub(crate) const PW_KEY_NODE_DESCRIPTION: &core::ffi::CStr = c"node.description";
/// `PW_KEY_MEDIA_TYPE`: `"media.type"`.
pub(crate) const PW_KEY_MEDIA_TYPE: &core::ffi::CStr = c"media.type";
/// `PW_KEY_MEDIA_CATEGORY`: `"media.category"`, `"Capture"` or `"Playback"`.
pub(crate) const PW_KEY_MEDIA_CATEGORY: &core::ffi::CStr = c"media.category";
/// `PW_KEY_MEDIA_ROLE`: `"media.role"`.
pub(crate) const PW_KEY_MEDIA_ROLE: &core::ffi::CStr = c"media.role";
/// `PW_KEY_TARGET_OBJECT`: `"target.object"`, the `node.name` (or serial) of
/// the node a stream with [`PW_STREAM_FLAG_AUTOCONNECT`] is linked to.
pub(crate) const PW_KEY_TARGET_OBJECT: &core::ffi::CStr = c"target.object";
/// `PW_KEY_NODE_LATENCY`: `"node.latency"`, the quantum a stream asks the
/// graph for, as a fraction of a second: `160/8000` for a narrowband frame.
pub(crate) const PW_KEY_NODE_LATENCY: &core::ffi::CStr = c"node.latency";
/// `"node.dont-fallback"`: not one of `pipewire/keys.h`'s own, but the
/// property the session manager reads to decide whether a stream whose
/// `target.object` is missing may be linked to the default node instead.
///
/// Set on every stream that names a target. Without it, the session manager
/// this was tested against (WirePlumber 0.5) did not take a stream down when
/// the node it named went away, `node.dont-reconnect` notwithstanding, and
/// the loss was never reported; with it, the stream is taken down and says
/// so, and where it goes next is the application's decision, made by
/// recovering.
pub(crate) const KEY_NODE_DONT_FALLBACK: &core::ffi::CStr = c"node.dont-fallback";

/// `struct spa_dict_item { const char *key; const char *value; }`.
#[repr(C)]
pub(crate) struct SpaDictItem {
    pub(crate) key: *const c_char,
    pub(crate) value: *const c_char,
}

/// `struct spa_dict { uint32_t flags; uint32_t n_items; const struct
/// spa_dict_item *items; }`: the property set a registry `global` event, a
/// core event or a stream's own properties carry.
#[repr(C)]
pub(crate) struct SpaDict {
    pub(crate) flags: u32,
    pub(crate) n_items: u32,
    pub(crate) items: *const SpaDictItem,
}

impl SpaDict {
    /// Read one value by key, the way `spa_dict_lookup` does: a linear scan,
    /// because the registry hands over a handful of properties per global and
    /// this runs once per hotplug event rather than per audio frame.
    ///
    /// # Safety
    /// `self` must be a dict PipeWire just handed to an event callback:
    /// `items` valid for `n_items` reads, and every key and value in it
    /// either null or a NUL-terminated C string, for as long as the callback
    /// runs. The value need not be valid UTF-8 — it is read with
    /// [`CStr::to_string_lossy`](core::ffi::CStr::to_string_lossy).
    pub(crate) unsafe fn get(&self, key: &core::ffi::CStr) -> Option<String> {
        if self.items.is_null() {
            return None;
        }
        for index in 0..self.n_items {
            // SAFETY: `items` is valid for `n_items` reads per this
            // function's own contract.
            let item = unsafe { &*self.items.add(index as usize) };
            if item.key.is_null() || item.value.is_null() {
                continue;
            }
            // SAFETY: same contract — a NUL-terminated string from this call.
            let item_key = unsafe { core::ffi::CStr::from_ptr(item.key) };
            if item_key == key {
                // SAFETY: same contract.
                let value = unsafe { core::ffi::CStr::from_ptr(item.value) };
                return Some(value.to_string_lossy().into_owned());
            }
        }
        None
    }
}

/// `struct spa_list { struct spa_list *next; struct spa_list *prev; }`, the
/// intrusive list a hook is linked into.
#[repr(C)]
pub(crate) struct SpaList {
    pub(crate) next: *mut SpaList,
    pub(crate) prev: *mut SpaList,
}

/// `struct spa_hook`: `struct spa_list link; struct spa_callbacks cb; void
/// (*removed)(struct spa_hook *); void *priv;` — six pointer-sized words.
///
/// What a listener is while it is registered, and the reason every `*_events`
/// table this crate hands over is a `static`. `spa_hook_list_append` in
/// `spa/utils/hook.h` zeroes the hook, stores `funcs` and `data` in `cb` *as
/// pointers*, and links `link` into the object's list: PipeWire copies
/// nothing out of the table, it calls through `cb.funcs` every time an event
/// is emitted. A table on the stack of the function that registered it is a
/// dangling pointer from the moment that function returns, and the first
/// event after that jumps wherever the stack now says. A hook outlives its
/// registration only by being unlinked first ([`crate::sys::hook_remove`]),
/// and it must never move while it is linked, which is why every owner keeps
/// it boxed.
#[repr(C)]
pub(crate) struct SpaHook {
    pub(crate) link: SpaList,
    _cb_funcs: *const c_void,
    _cb_data: *mut c_void,
    pub(crate) removed: Option<unsafe extern "C" fn(hook: *mut SpaHook)>,
    _priv: *mut c_void,
}

impl SpaHook {
    /// An unlinked hook, all zero: what `spa_zero` makes of one before the
    /// first `*_add_listener` call.
    pub(crate) const fn new() -> Self {
        Self {
            link: SpaList {
                next: core::ptr::null_mut(),
                prev: core::ptr::null_mut(),
            },
            _cb_funcs: core::ptr::null(),
            _cb_data: core::ptr::null_mut(),
            removed: None,
            _priv: core::ptr::null_mut(),
        }
    }
}

/// The head of `struct spa_interface { const char *type; uint32_t version;
/// struct spa_callbacks cb; }`, which `struct pw_core`, `struct pw_registry`
/// and `struct pw_metadata` all begin with. `pw_core_methods`,
/// `pw_registry_methods` and `pw_metadata_methods` are what `cb.funcs` points
/// to, and `cb.data` is the opaque object `spa_interface_call` in
/// `spa/utils/hook.h` passes as every method's first argument — not
/// necessarily the interface pointer itself.
#[repr(C)]
pub(crate) struct SpaInterface {
    pub(crate) type_: *const c_char,
    pub(crate) version: u32,
    pub(crate) cb_funcs: *const c_void,
    pub(crate) cb_data: *mut c_void,
}

/// `struct pw_core_methods`: `add_listener`, `hello`, `sync`, `pong`,
/// `error`, `get_registry`, `create_object`, `destroy`, in that order after
/// `version`. Only the three this crate calls are given a name; the rest are
/// read as opaque words so the table's layout stays right regardless.
#[repr(C)]
pub(crate) struct PwCoreMethods {
    pub(crate) version: u32,
    pub(crate) add_listener: Option<
        unsafe extern "C" fn(
            object: *mut c_void,
            listener: *mut SpaHook,
            events: *const PwCoreEvents,
            data: *mut c_void,
        ) -> i32,
    >,
    _hello: *const c_void,
    pub(crate) sync: Option<unsafe extern "C" fn(object: *mut c_void, id: u32, seq: i32) -> i32>,
    _pong: *const c_void,
    _error: *const c_void,
    pub(crate) get_registry: Option<
        unsafe extern "C" fn(
            object: *mut c_void,
            version: u32,
            user_data_size: usize,
        ) -> *mut c_void,
    >,
    _create_object: *const c_void,
    _destroy: *const c_void,
}

/// A slot in an events table this crate leaves empty.
///
/// Typed as a function pointer rather than as a raw pointer so that a table
/// of them is `Sync` and can be the `static` a registered listener needs —
/// see [`SpaHook`]. `Option` of a function pointer is one pointer wide, with
/// `None` the null PipeWire checks for before it calls a slot.
pub(crate) type Unused = Option<unsafe extern "C" fn()>;

/// `struct pw_core_events`: `version`, `info`, `done`, `ping`, `error`,
/// `remove_id`, `bound_id`, `add_mem`, `remove_mem`, `bound_props`.
///
/// The unused fields are `pub(crate)` rather than private: `registry.rs`
/// builds this table as a literal, and a struct literal has to set every
/// field from the module that owns it.
#[repr(C)]
pub(crate) struct PwCoreEvents {
    pub(crate) version: u32,
    pub(crate) info: Unused,
    pub(crate) done: Option<unsafe extern "C" fn(data: *mut c_void, id: u32, seq: i32)>,
    pub(crate) ping: Unused,
    pub(crate) error: Option<
        unsafe extern "C" fn(
            data: *mut c_void,
            id: u32,
            seq: i32,
            res: i32,
            message: *const c_char,
        ),
    >,
    pub(crate) remove_id: Unused,
    pub(crate) bound_id: Unused,
    pub(crate) add_mem: Unused,
    pub(crate) remove_mem: Unused,
    pub(crate) bound_props: Unused,
}

/// `struct pw_registry_methods`: `add_listener`, `bind`, `destroy`.
#[repr(C)]
pub(crate) struct PwRegistryMethods {
    pub(crate) version: u32,
    pub(crate) add_listener: Option<
        unsafe extern "C" fn(
            object: *mut c_void,
            listener: *mut SpaHook,
            events: *const PwRegistryEvents,
            data: *mut c_void,
        ) -> i32,
    >,
    pub(crate) bind: Option<
        unsafe extern "C" fn(
            object: *mut c_void,
            id: u32,
            interface_type: *const c_char,
            version: u32,
            user_data_size: usize,
        ) -> *mut c_void,
    >,
    _destroy: *const c_void,
}

/// `struct pw_registry_events`: `version`, `global`, `global_remove`.
#[repr(C)]
pub(crate) struct PwRegistryEvents {
    pub(crate) version: u32,
    pub(crate) global: Option<
        unsafe extern "C" fn(
            data: *mut c_void,
            id: u32,
            permissions: u32,
            interface_type: *const c_char,
            version: u32,
            props: *const SpaDict,
        ),
    >,
    pub(crate) global_remove: Option<unsafe extern "C" fn(data: *mut c_void, id: u32)>,
}

/// `struct pw_metadata_methods`: `add_listener`, `set_property`, `clear`.
#[repr(C)]
pub(crate) struct PwMetadataMethods {
    pub(crate) version: u32,
    pub(crate) add_listener: Option<
        unsafe extern "C" fn(
            object: *mut c_void,
            listener: *mut SpaHook,
            events: *const PwMetadataEvents,
            data: *mut c_void,
        ) -> i32,
    >,
    _set_property: *const c_void,
    _clear: *const c_void,
}

/// `struct pw_metadata_events`: `version`, `property`.
#[repr(C)]
pub(crate) struct PwMetadataEvents {
    pub(crate) version: u32,
    pub(crate) property: Option<
        unsafe extern "C" fn(
            data: *mut c_void,
            subject: u32,
            key: *const c_char,
            value_type: *const c_char,
            value: *const c_char,
        ) -> i32,
    >,
}

/// `struct pw_stream_events`: `version`, `destroy`, `state_changed`,
/// `control_info`, `io_changed`, `param_changed`, `add_buffer`,
/// `remove_buffer`, `process`, `drained`, `command`, `trigger_done`.
///
/// The unused fields are `pub(crate)` rather than private, as
/// [`PwCoreEvents`]'s: `stream.rs` builds this table as a literal too.
#[repr(C)]
pub(crate) struct PwStreamEvents {
    pub(crate) version: u32,
    pub(crate) destroy: Unused,
    pub(crate) state_changed:
        Option<unsafe extern "C" fn(data: *mut c_void, old: i32, state: i32, error: *const c_char)>,
    pub(crate) control_info: Unused,
    pub(crate) io_changed: Unused,
    pub(crate) param_changed:
        Option<unsafe extern "C" fn(data: *mut c_void, id: u32, param: *const SpaPod)>,
    pub(crate) add_buffer: Unused,
    pub(crate) remove_buffer: Unused,
    pub(crate) process: Option<unsafe extern "C" fn(data: *mut c_void)>,
    pub(crate) drained: Unused,
    pub(crate) command: Unused,
    pub(crate) trigger_done: Unused,
}

/// `struct spa_chunk`: `offset`, `size`, `stride`, `flags`.
#[repr(C)]
pub(crate) struct SpaChunk {
    pub(crate) offset: u32,
    pub(crate) size: u32,
    pub(crate) stride: i32,
    pub(crate) flags: i32,
}

/// `struct spa_data`: `type`, `flags`, `fd`, `mapoffset`, `maxsize`, `data`,
/// `chunk`.
#[repr(C)]
pub(crate) struct SpaData {
    pub(crate) type_: u32,
    pub(crate) flags: u32,
    pub(crate) fd: i64,
    pub(crate) mapoffset: u32,
    pub(crate) maxsize: u32,
    pub(crate) data: *mut c_void,
    pub(crate) chunk: *mut SpaChunk,
}

/// `struct spa_buffer`: `n_metas`, `n_datas`, `metas`, `datas`. This crate
/// only ever reads `datas[0]`: every stream it opens is mono, one
/// `spa_data` per buffer.
#[repr(C)]
pub(crate) struct SpaBuffer {
    pub(crate) n_metas: u32,
    pub(crate) n_datas: u32,
    pub(crate) metas: *mut c_void,
    pub(crate) datas: *mut SpaData,
}

/// `struct pw_buffer`: `buffer`, `user_data`, `size`, `requested`, `time`.
#[repr(C)]
pub(crate) struct PwBuffer {
    pub(crate) buffer: *mut SpaBuffer,
    pub(crate) user_data: *mut c_void,
    pub(crate) size: u64,
    pub(crate) requested: u64,
    pub(crate) time: u64,
}

/// `struct spa_fraction`: `num`, `denom`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SpaFraction {
    pub(crate) num: u32,
    pub(crate) denom: u32,
}

/// `struct pw_time`, as `pipewire/stream.h` documents it at length: `now`,
/// `rate`, `ticks`, `delay`, `queued`, `buffered`, `queued_buffers`,
/// `avail_buffers`, `size`. `crate::latency` reads `rate`, `delay`,
/// `queued` and `buffered` out of this.
#[repr(C)]
#[derive(Default)]
pub(crate) struct PwTime {
    pub(crate) now: i64,
    pub(crate) rate: SpaFraction,
    pub(crate) ticks: u64,
    pub(crate) delay: i64,
    pub(crate) queued: u64,
    pub(crate) buffered: u64,
    pub(crate) queued_buffers: u32,
    pub(crate) avail_buffers: u32,
    pub(crate) size: u64,
}

/// One property of a `SPA_TYPE_OBJECT_Format`: `struct spa_pod_prop { key;
/// flags; struct spa_pod value; }` followed by the value's own body — here
/// always a plain `Id` or `Int`, sixteen bytes with the builder's own
/// round-up-to-eight padding included as `_padding`, so `Prop32` is the
/// prop's whole twenty-four bytes with nothing left implicit.
#[repr(C)]
#[derive(Clone, Copy)]
struct Prop32 {
    key: u32,
    flags: u32,
    value_pod: SpaPod,
    value: u32,
    _padding: i32,
}

impl Prop32 {
    const fn id(key: u32, value: u32) -> Self {
        Self {
            key,
            flags: 0,
            value_pod: SpaPod {
                size: 4,
                type_: SPA_TYPE_ID,
            },
            value,
            _padding: 0,
        }
    }

    const fn int(key: u32, value: u32) -> Self {
        Self {
            key,
            flags: 0,
            value_pod: SpaPod {
                size: 4,
                type_: SPA_TYPE_INT,
            },
            value,
            _padding: 0,
        }
    }
}

/// `SPA_FORMAT_AUDIO_position` for one channel: `spa_pod_prop { key; flags;
/// struct spa_pod value /* Array */; }` followed by the array's own `child`
/// header (`struct spa_pod_array_body`) and its one raw `Id` value, with the
/// round-up-to-eight padding SPA puts after every pod body kept as an
/// explicit field.
///
/// The position is `SPA_AUDIO_CHANNEL_MONO` rather than left unknown: a
/// channel that says it is the mono one is what the adapter's channel mixer
/// spreads across every channel of a stereo sink and folds every channel of
/// a stereo source into, which is exactly what a call wants from a headset.
#[repr(C)]
#[derive(Clone, Copy)]
struct PropPositionMono {
    key: u32,
    flags: u32,
    value_pod: SpaPod,
    child: SpaPod,
    value: u32,
    _padding: u32,
}

impl PropPositionMono {
    const fn new() -> Self {
        Self {
            key: SPA_FORMAT_AUDIO_POSITION,
            flags: 0,
            value_pod: SpaPod {
                size: 12,
                type_: SPA_TYPE_ARRAY,
            },
            child: SpaPod {
                size: 4,
                type_: SPA_TYPE_ID,
            },
            value: SPA_AUDIO_CHANNEL_MONO,
            _padding: 0,
        }
    }
}

/// A `SPA_TYPE_OBJECT_Format` pod describing one fixed format — mono, signed
/// sixteen-bit, at a stated rate — built by hand in the shape
/// `spa_format_audio_raw_build` (`spa/param/audio/raw-utils.h`) gives one,
/// since that function and the `spa_pod_builder` it calls are `static
/// inline` and this crate links no such symbol.
///
/// This is not a range or a choice: every value is a plain `Id` or `Int`,
/// so PipeWire reads it as one fixed format to negotiate rather than a set
/// to pick from, exactly the shape `pw_stream_connect`'s own tutorial
/// examples pass for `SPA_PARAM_EnumFormat` when they already know what they
/// want.
#[repr(C)]
pub(crate) struct FormatPod {
    pod: SpaPod,
    body_type: u32,
    body_id: u32,
    media_type: Prop32,
    media_subtype: Prop32,
    format: Prop32,
    rate: Prop32,
    channels: Prop32,
    position: PropPositionMono,
}

impl FormatPod {
    /// Build the pod for `pw_stream_connect`'s `params`: mono, `S16`, at
    /// `sample_rate_hz`.
    pub(crate) const fn new(sample_rate_hz: u32) -> Self {
        let media_type = Prop32::id(SPA_FORMAT_MEDIA_TYPE, SPA_MEDIA_TYPE_AUDIO);
        let media_subtype = Prop32::id(SPA_FORMAT_MEDIA_SUBTYPE, SPA_MEDIA_SUBTYPE_RAW);
        let format = Prop32::id(SPA_FORMAT_AUDIO_FORMAT, SPA_AUDIO_FORMAT_S16);
        let rate = Prop32::int(SPA_FORMAT_AUDIO_RATE, sample_rate_hz);
        let channels = Prop32::int(SPA_FORMAT_AUDIO_CHANNELS, 1);
        let position = PropPositionMono::new();

        // The body size the pod header carries: everything after the header
        // itself. Each Prop32 occupies 24 bytes on the wire (8 prop header +
        // 16 padded value) and the position property 32; both match this
        // struct's own field sizes exactly, which `tests::the_layout_matches_the_wire_shape`
        // below checks rather than assumes.
        let body_size = 8 + 24 * 5 + 32;

        Self {
            pod: SpaPod {
                size: body_size,
                type_: SPA_TYPE_OBJECT,
            },
            body_type: SPA_TYPE_OBJECT_FORMAT,
            body_id: SPA_PARAM_ENUM_FORMAT,
            media_type,
            media_subtype,
            format,
            rate,
            channels,
            position,
        }
    }

    /// The pod's address, for the single-element `params` array
    /// `pw_stream_connect` takes.
    pub(crate) const fn as_ptr(&self) -> *const SpaPod {
        core::ptr::from_ref(&self.pod)
    }
}

/// What a `SPA_TYPE_OBJECT_Format` object says, of the three things this
/// crate asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AudioFormat {
    /// `SPA_FORMAT_AUDIO_format`, an `enum spa_audio_format`.
    pub(crate) format: u32,
    /// `SPA_FORMAT_AUDIO_rate`.
    pub(crate) rate: u32,
    /// `SPA_FORMAT_AUDIO_channels`.
    pub(crate) channels: u32,
}

/// Read the format, the rate and the channel count out of a format object's
/// bytes — the pod header and everything its `size` says follows it.
///
/// The walk is `spa/pod/iter.h`'s, done over a slice rather than over
/// pointers: after the object's eight-byte header and its `type`/`id` body
/// header come `spa_pod_prop`s one after another, each a key, flags, a value
/// pod's own header and that value's body padded up to eight bytes. A value
/// that is not a plain `Id` or `Int` — a `Choice` would be, in a format that
/// was offered rather than settled — is not a value, and a format missing
/// any of the three answers `None` rather than a guess.
pub(crate) fn read_audio_format(bytes: &[u8]) -> Option<AudioFormat> {
    let word = |at: usize| -> Option<u32> {
        let four = bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_ne_bytes(four.try_into().ok()?))
    };
    let size = usize::try_from(word(0)?).ok()?;
    if word(4)? != SPA_TYPE_OBJECT || word(8)? != SPA_TYPE_OBJECT_FORMAT {
        return None;
    }
    let end = size.checked_add(8)?;
    if end > bytes.len() {
        return None;
    }
    let (mut format, mut rate, mut channels) = (None, None, None);
    // past the pod header and the object body's `type` and `id`
    let mut at = 16_usize;
    while at.checked_add(16)? <= end {
        let key = word(at)?;
        let value_size = usize::try_from(word(at + 8)?).ok()?;
        let value_type = word(at + 12)?;
        let body = at + 16;
        if value_size >= 4 && (value_type == SPA_TYPE_ID || value_type == SPA_TYPE_INT) {
            let value = word(body)?;
            match key {
                SPA_FORMAT_AUDIO_FORMAT => format = Some(value),
                SPA_FORMAT_AUDIO_RATE => rate = Some(value),
                SPA_FORMAT_AUDIO_CHANNELS => channels = Some(value),
                _ => {}
            }
        }
        at = body.checked_add(value_size.checked_next_multiple_of(8)?)?;
    }
    Some(AudioFormat {
        format: format?,
        rate: rate?,
        channels: channels?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AudioFormat, FormatPod, PropPositionMono, PwBuffer, PwCoreEvents, PwMetadataEvents,
        PwRegistryEvents, PwStreamEvents, PwTime, SPA_AUDIO_FORMAT_S16, SpaBuffer, SpaData,
        SpaHook, SpaInterface, read_audio_format,
    };
    use core::mem::{offset_of, size_of};

    /// The bytes of a format pod, the way `param_changed` hands one over.
    fn bytes_of(pod: &FormatPod) -> &[u8] {
        // SAFETY: `FormatPod` is `repr(C)` and made of `u32`s only, so every
        // byte of it is initialised and it has no padding to read.
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(pod).cast::<u8>(),
                size_of::<FormatPod>(),
            )
        }
    }

    /// Every size and offset here was read off the headers for LP64 Linux,
    /// the only target this crate talks to PipeWire on. A slip in any of
    /// them is a wrong offset into memory PipeWire owns, and it is found here
    /// rather than as a crash.
    #[test]
    fn the_hand_written_structs_are_the_size_the_headers_say() {
        // spa_list (two pointers), spa_callbacks (two), removed, priv
        assert_eq!(size_of::<SpaHook>(), 48);
        // a pointer, a u32 padded to eight, then spa_callbacks at 16
        assert_eq!(size_of::<SpaInterface>(), 32);
        assert_eq!(offset_of!(SpaInterface, cb_funcs), 16);
        assert_eq!(size_of::<PropPositionMono>(), 32);
        // version padded to eight, then one pointer per event
        assert_eq!(size_of::<PwCoreEvents>(), 8 + 9 * 8);
        assert_eq!(size_of::<PwRegistryEvents>(), 8 + 2 * 8);
        assert_eq!(size_of::<PwMetadataEvents>(), 8 + 8);
        assert_eq!(size_of::<PwStreamEvents>(), 8 + 11 * 8);
        assert_eq!(offset_of!(PwStreamEvents, process), 8 + 7 * 8);
        // type, flags, fd (i64), mapoffset, maxsize, data, chunk
        assert_eq!(size_of::<SpaData>(), 40);
        assert_eq!(offset_of!(SpaData, data), 24);
        assert_eq!(size_of::<SpaBuffer>(), 24);
        assert_eq!(size_of::<PwBuffer>(), 40);
        // now, rate, ticks, delay, queued, buffered, two u32 counts, size
        assert_eq!(size_of::<PwTime>(), 64);
        assert_eq!(offset_of!(PwTime, delay), 24);
        assert_eq!(offset_of!(PwTime, size), 56);
    }

    /// The tables a listener is registered with have to be `static`, which
    /// they can only be if they are `Sync`: the property the typed empty
    /// slots are there for.
    #[test]
    fn an_events_table_can_be_a_static() {
        fn shareable<T: Sync>() {}
        shareable::<PwCoreEvents>();
        shareable::<PwRegistryEvents>();
        shareable::<PwMetadataEvents>();
        shareable::<PwStreamEvents>();
    }

    #[test]
    fn a_format_pod_reads_back_as_what_it_was_built_with() {
        let pod = FormatPod::new(16_000);
        assert_eq!(
            read_audio_format(bytes_of(&pod)),
            Some(AudioFormat {
                format: SPA_AUDIO_FORMAT_S16,
                rate: 16_000,
                channels: 1,
            })
        );
    }

    #[test]
    fn a_short_or_foreign_pod_reads_as_nothing() {
        let pod = FormatPod::new(8_000);
        let bytes = bytes_of(&pod);
        assert_eq!(read_audio_format(&bytes[..bytes.len() - 8]), None);
        assert_eq!(read_audio_format(&[]), None);
        let mut other = bytes.to_vec();
        // the object's own type, one word into its body
        other[8..12].copy_from_slice(&0x4_0002_u32.to_ne_bytes());
        assert_eq!(read_audio_format(&other), None);
    }

    #[test]
    fn a_format_pod_is_the_size_its_own_header_claims() {
        let pod = FormatPod::new(8_000);
        // the pod's declared body size, plus the eight-byte header, has to be
        // this struct's own in-memory size: anything else means a field was
        // added to one and not the other, and the bytes `pw_stream_connect`
        // reads past the end of what was actually initialised
        assert_eq!(
            pod.pod.size as usize + core::mem::size_of::<super::SpaPod>(),
            core::mem::size_of::<FormatPod>()
        );
        assert_eq!(core::mem::size_of::<FormatPod>(), 168);
        // every pod in the object, including the object itself, is a
        // multiple of eight bytes: SPA's own alignment rule
        assert_eq!(core::mem::size_of::<FormatPod>() % 8, 0);
    }

    #[test]
    fn a_format_pod_names_the_rate_it_was_built_with() {
        let pod = FormatPod::new(48_000);
        assert_eq!(pod.rate.value, 48_000);
        assert_eq!(pod.channels.value, 1);
        assert_eq!(pod.format.value, super::SPA_AUDIO_FORMAT_S16);
    }
}
