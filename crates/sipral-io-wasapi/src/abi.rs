// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The structures, identifiers and vtables Windows reads, declared from
//! Microsoft's published headers.
//!
//! These are plain data, so they are compiled everywhere; only the calls that
//! take them need a library to link against. That is deliberate. A struct with
//! a field in the wrong place produces audio that is noise rather than a
//! diagnostic, and a vtable with a slot missing is a call into a different
//! function of the same object — neither is a compile error, and the tests at
//! the bottom of this file are cheap enough to run on every target the
//! workspace builds for.
//!
//! Where each declaration came from is written above it. The C names are in
//! the comments so a reader can find the header; the Rust names are ours.
//!
//! Two shapes repeat and are worth stating once:
//!
//! * Everything from `mmreg.h` is byte-packed — the header is wrapped in
//!   `#pragma pack(1)` — so `WAVEFORMATEX` is eighteen octets rather than the
//!   twenty a natural layout would give it. Getting that wrong shifts every
//!   field after the sample rate.
//! * Every COM vtable begins with the three `IUnknown` slots in that order, so
//!   each one here embeds [`UnknownVtable`] as its first field. That is what
//!   makes releasing an interface through a cast to `IUnknown` correct rather
//!   than lucky, and it is what the C headers do too.

use core::ffi::c_void;
use core::fmt;

/// `HRESULT`.
pub(crate) type Hr = i32;

/// `HANDLE`.
pub(crate) type Handle = *mut c_void;

/// `GUID`, from `guiddef.h`: a `DWORD`, two `WORD`s and eight bytes, which is
/// why the canonical text form has the first three groups byte-swapped on a
/// little-endian machine and the last two not.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Guid {
    pub(crate) data1: u32,
    pub(crate) data2: u16,
    pub(crate) data3: u16,
    pub(crate) data4: [u8; 8],
}

impl Guid {
    /// The four fields as a header writes them.
    pub(crate) const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}",
            self.data1, self.data2, self.data3
        )?;
        // the last eight octets read left to right, with the group break after
        // the second: 8-4-4-4-12, and only the first three fields are numbers
        for (index, octet) in self.data4.iter().enumerate() {
            if index == 0 || index == 2 {
                f.write_str("-")?;
            }
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

/// A COM object as C sees it: a pointer to a vtable, and whatever the
/// implementation keeps after it.
#[repr(C)]
pub(crate) struct Object<V: 'static> {
    pub(crate) vtable: *const V,
}

/// An interface this crate asks for by name.
pub(crate) trait Interface {
    /// The `IID` the header declares for it.
    const IID: Guid;
}

/// `IUnknownVtbl`, from `unknwn.h`. `IID_IUnknown` is
/// `00000000-0000-0000-c000-000000000046`, which nothing here asks for by
/// name — but every object answers it, and the notification client below has
/// to.
#[repr(C)]
pub(crate) struct UnknownVtable {
    pub(crate) query_interface:
        unsafe extern "system" fn(*mut Unknown, *const Guid, *mut *mut c_void) -> Hr,
    pub(crate) add_ref: unsafe extern "system" fn(*mut Unknown) -> u32,
    pub(crate) release: unsafe extern "system" fn(*mut Unknown) -> u32,
}

/// `IUnknown`.
pub(crate) type Unknown = Object<UnknownVtable>;

impl Interface for UnknownVtable {
    const IID: Guid = Guid::new(0, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
}

/// `IMMDeviceEnumeratorVtbl`, from `mmdeviceapi.h`: three `IUnknown` slots
/// then `EnumAudioEndpoints`, `GetDefaultAudioEndpoint`, `GetDevice`,
/// `RegisterEndpointNotificationCallback`,
/// `UnregisterEndpointNotificationCallback`. Eight slots.
#[repr(C)]
pub(crate) struct DeviceEnumeratorVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) enum_audio_endpoints: unsafe extern "system" fn(
        *mut DeviceEnumerator,
        u32,
        u32,
        *mut *mut DeviceCollection,
    ) -> Hr,
    pub(crate) get_default_audio_endpoint:
        unsafe extern "system" fn(*mut DeviceEnumerator, u32, u32, *mut *mut MmDevice) -> Hr,
    pub(crate) get_device:
        unsafe extern "system" fn(*mut DeviceEnumerator, *const u16, *mut *mut MmDevice) -> Hr,
    pub(crate) register_endpoint_notification_callback:
        unsafe extern "system" fn(*mut DeviceEnumerator, *mut NotificationClient) -> Hr,
    pub(crate) unregister_endpoint_notification_callback:
        unsafe extern "system" fn(*mut DeviceEnumerator, *mut NotificationClient) -> Hr,
}

/// `IMMDeviceEnumerator`.
pub(crate) type DeviceEnumerator = Object<DeviceEnumeratorVtable>;

impl Interface for DeviceEnumeratorVtable {
    /// `A95664D2-9614-4F35-A746-DE8DB63617E6`, from the `MIDL_INTERFACE`
    /// attribute on `IMMDeviceEnumerator`.
    const IID: Guid = Guid::new(
        0xa956_64d2,
        0x9614,
        0x4f35,
        [0xa7, 0x46, 0xde, 0x8d, 0xb6, 0x36, 0x17, 0xe6],
    );
}

/// `IMMDeviceCollectionVtbl`, from `mmdeviceapi.h`: `GetCount` then `Item`.
/// Five slots.
#[repr(C)]
pub(crate) struct DeviceCollectionVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) get_count: unsafe extern "system" fn(*mut DeviceCollection, *mut u32) -> Hr,
    pub(crate) item:
        unsafe extern "system" fn(*mut DeviceCollection, u32, *mut *mut MmDevice) -> Hr,
}

/// `IMMDeviceCollection`.
pub(crate) type DeviceCollection = Object<DeviceCollectionVtable>;

impl Interface for DeviceCollectionVtable {
    /// `0BD7A1BE-7A1A-44DB-8397-CC5392387B5E`.
    const IID: Guid = Guid::new(
        0x0bd7_a1be,
        0x7a1a,
        0x44db,
        [0x83, 0x97, 0xcc, 0x53, 0x92, 0x38, 0x7b, 0x5e],
    );
}

/// `IMMDeviceVtbl`, from `mmdeviceapi.h`: `Activate`, `OpenPropertyStore`,
/// `GetId`, `GetState`. Seven slots.
#[repr(C)]
pub(crate) struct MmDeviceVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) activate: unsafe extern "system" fn(
        *mut MmDevice,
        *const Guid,
        u32,
        *mut PropVariant,
        *mut *mut c_void,
    ) -> Hr,
    pub(crate) open_property_store:
        unsafe extern "system" fn(*mut MmDevice, u32, *mut *mut PropertyStore) -> Hr,
    pub(crate) get_id: unsafe extern "system" fn(*mut MmDevice, *mut *mut u16) -> Hr,
    pub(crate) get_state: unsafe extern "system" fn(*mut MmDevice, *mut u32) -> Hr,
}

/// `IMMDevice`.
pub(crate) type MmDevice = Object<MmDeviceVtable>;

impl Interface for MmDeviceVtable {
    /// `D666063F-1587-4E43-81F1-B948E807363F`.
    const IID: Guid = Guid::new(
        0xd666_063f,
        0x1587,
        0x4e43,
        [0x81, 0xf1, 0xb9, 0x48, 0xe8, 0x07, 0x36, 0x3f],
    );
}

/// `IPropertyStoreVtbl`, from `propsys.h`: `GetCount`, `GetAt`, `GetValue`,
/// `SetValue`, `Commit`. Eight slots, of which this crate calls one.
#[repr(C)]
pub(crate) struct PropertyStoreVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) get_count: unsafe extern "system" fn(*mut PropertyStore, *mut u32) -> Hr,
    pub(crate) get_at: unsafe extern "system" fn(*mut PropertyStore, u32, *mut PropertyKey) -> Hr,
    pub(crate) get_value:
        unsafe extern "system" fn(*mut PropertyStore, *const PropertyKey, *mut PropVariant) -> Hr,
    pub(crate) set_value:
        unsafe extern "system" fn(*mut PropertyStore, *const PropertyKey, *const PropVariant) -> Hr,
    pub(crate) commit: unsafe extern "system" fn(*mut PropertyStore) -> Hr,
}

/// `IPropertyStore`.
pub(crate) type PropertyStore = Object<PropertyStoreVtable>;

impl Interface for PropertyStoreVtable {
    /// `886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99`.
    const IID: Guid = Guid::new(
        0x886d_8eeb,
        0x8cf2,
        0x4446,
        [0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99],
    );
}

/// `IAudioClientVtbl`, from `Audioclient.h`: `Initialize`, `GetBufferSize`,
/// `GetStreamLatency`, `GetCurrentPadding`, `IsFormatSupported`,
/// `GetMixFormat`, `GetDevicePeriod`, `Start`, `Stop`, `Reset`,
/// `SetEventHandle`, `GetService`. Fifteen slots, and the order is the whole
/// of the interface — `Start` and `Stop` are adjacent and take the same
/// arguments, so a slot out of place there is a stream that never runs and
/// never says why.
#[repr(C)]
pub(crate) struct AudioClientVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) initialize: unsafe extern "system" fn(
        *mut AudioClient,
        u32,
        u32,
        i64,
        i64,
        *const WaveFormat,
        *const Guid,
    ) -> Hr,
    pub(crate) get_buffer_size: unsafe extern "system" fn(*mut AudioClient, *mut u32) -> Hr,
    pub(crate) get_stream_latency: unsafe extern "system" fn(*mut AudioClient, *mut i64) -> Hr,
    pub(crate) get_current_padding: unsafe extern "system" fn(*mut AudioClient, *mut u32) -> Hr,
    pub(crate) is_format_supported: unsafe extern "system" fn(
        *mut AudioClient,
        u32,
        *const WaveFormat,
        *mut *mut WaveFormat,
    ) -> Hr,
    pub(crate) get_mix_format:
        unsafe extern "system" fn(*mut AudioClient, *mut *mut WaveFormat) -> Hr,
    pub(crate) get_device_period:
        unsafe extern "system" fn(*mut AudioClient, *mut i64, *mut i64) -> Hr,
    pub(crate) start: unsafe extern "system" fn(*mut AudioClient) -> Hr,
    pub(crate) stop: unsafe extern "system" fn(*mut AudioClient) -> Hr,
    pub(crate) reset: unsafe extern "system" fn(*mut AudioClient) -> Hr,
    pub(crate) set_event_handle: unsafe extern "system" fn(*mut AudioClient, Handle) -> Hr,
    pub(crate) get_service:
        unsafe extern "system" fn(*mut AudioClient, *const Guid, *mut *mut c_void) -> Hr,
}

/// `IAudioClient`.
pub(crate) type AudioClient = Object<AudioClientVtable>;

impl Interface for AudioClientVtable {
    /// `1CB9AD4C-DBFA-4C32-B178-C2F568A703B2`.
    const IID: Guid = Guid::new(
        0x1cb9_ad4c,
        0xdbfa,
        0x4c32,
        [0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2],
    );
}

/// `IAudioClient2Vtbl`, from `Audioclient.h`. `IAudioClient2` derives from
/// `IAudioClient`, so its table is that whole table and then
/// `IsOffloadCapable`, `SetClientProperties`, `GetBufferSizeLimits`. Eighteen
/// slots, of which this crate calls the middle one of the three.
///
/// It embeds [`AudioClientVtable`] entire for the same reason every table here
/// embeds [`UnknownVtable`]: that is what the C header does, and it is what
/// makes the derived interface usable as the base one — the same object
/// answers to both, so the client this crate initialises and the client it
/// sets properties on are one client and not two.
#[repr(C)]
pub(crate) struct AudioClient2Vtable {
    pub(crate) client: AudioClientVtable,
    pub(crate) is_offload_capable:
        unsafe extern "system" fn(*mut AudioClient2, i32, *mut i32) -> Hr,
    pub(crate) set_client_properties:
        unsafe extern "system" fn(*mut AudioClient2, *const AudioClientProperties) -> Hr,
    pub(crate) get_buffer_size_limits: unsafe extern "system" fn(
        *mut AudioClient2,
        *const WaveFormat,
        i32,
        *mut i64,
        *mut i64,
    ) -> Hr,
}

/// `IAudioClient2`.
pub(crate) type AudioClient2 = Object<AudioClient2Vtable>;

impl Interface for AudioClient2Vtable {
    /// `726778CD-F60A-4EDA-82DE-E47610CD78AA`.
    const IID: Guid = Guid::new(
        0x7267_78cd,
        0xf60a,
        0x4eda,
        [0x82, 0xde, 0xe4, 0x76, 0x10, 0xcd, 0x78, 0xaa],
    );
}

/// `AudioClientProperties`, from `Audioclient.h`: a size, a flag, a category
/// and a set of options. Four four-octet fields and no padding.
///
/// `cbSize` is how Windows tells which version of the structure it has been
/// handed: the Windows 8 one ended after the category and was twelve octets,
/// and the options field arrived with 8.1. Sixteen is therefore not a
/// formality, it is the statement that the fourth field is there to be read.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AudioClientProperties {
    pub(crate) size: u32,
    /// `bIsOffload`, a `BOOL`. Offload is hardware-accelerated playback of
    /// long media, it has to be asked about with `IsOffloadCapable` first, and
    /// a call is neither long nor media.
    pub(crate) is_offload: i32,
    /// `eCategory`, an `AUDIO_STREAM_CATEGORY`.
    pub(crate) category: i32,
    /// `Options`, an `AUDCLNT_STREAMOPTIONS` bitmask.
    pub(crate) options: i32,
}

impl AudioClientProperties {
    /// What `cbSize` carries: the octets of the structure itself.
    pub(crate) const BYTES: u32 = 16;

    /// A call. The category Windows applies its communications processing to,
    /// no offload, and nothing bypassed.
    ///
    /// `AUDCLNT_STREAMOPTIONS_RAW` is the option that matters here and it is
    /// the one deliberately not set: raw takes the stream past the endpoint's
    /// processing objects, which is exactly where the echo canceller lives.
    pub(crate) const COMMUNICATIONS: Self = Self {
        size: Self::BYTES,
        is_offload: 0,
        category: AUDIO_CATEGORY_COMMUNICATIONS,
        options: STREAMOPTIONS_NONE,
    };

    /// A call past the endpoint's processing: the same category, so routing
    /// and ducking still treat it as a call, with
    /// `AUDCLNT_STREAMOPTIONS_RAW`, which takes the echo canceller and the
    /// rest out of its path. For an application that turned the platform's
    /// echo cancellation off.
    pub(crate) const COMMUNICATIONS_RAW: Self = Self {
        size: Self::BYTES,
        is_offload: 0,
        category: AUDIO_CATEGORY_COMMUNICATIONS,
        options: STREAMOPTIONS_RAW,
    };
}

/// `AudioCategory_Communications`, from the `AUDIO_STREAM_CATEGORY`
/// enumeration in `audiosessiontypes.h`.
///
/// The fourth entry, counting `AudioCategory_Other` as the zeroth. It is what
/// Windows reads to decide that a stream is a call: which endpoint it follows
/// when the user has chosen a separate one for communications, whether other
/// applications are ducked under it, and whether the endpoint's own voice
/// processing runs on it.
pub(crate) const AUDIO_CATEGORY_COMMUNICATIONS: i32 = 3;

/// `AUDCLNT_STREAMOPTIONS_NONE`, from `audiosessiontypes.h`: the default
/// treatment, which is the one wanted.
pub(crate) const STREAMOPTIONS_NONE: i32 = 0;

/// `AUDCLNT_STREAMOPTIONS_RAW`, from `audiosessiontypes.h`: the stream
/// bypasses the endpoint's signal processing.
pub(crate) const STREAMOPTIONS_RAW: i32 = 1;

/// `IAudioRenderClientVtbl`, from `Audioclient.h`: `GetBuffer`,
/// `ReleaseBuffer`. Five slots.
#[repr(C)]
pub(crate) struct AudioRenderClientVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) get_buffer:
        unsafe extern "system" fn(*mut AudioRenderClient, u32, *mut *mut u8) -> Hr,
    pub(crate) release_buffer: unsafe extern "system" fn(*mut AudioRenderClient, u32, u32) -> Hr,
}

/// `IAudioRenderClient`.
pub(crate) type AudioRenderClient = Object<AudioRenderClientVtable>;

impl Interface for AudioRenderClientVtable {
    /// `F294ACFC-3146-4483-A7BF-ADDCA7C260E2`.
    const IID: Guid = Guid::new(
        0xf294_acfc,
        0x3146,
        0x4483,
        [0xa7, 0xbf, 0xad, 0xdc, 0xa7, 0xc2, 0x60, 0xe2],
    );
}

/// `IAudioCaptureClientVtbl`, from `Audioclient.h`: `GetBuffer`,
/// `ReleaseBuffer`, `GetNextPacketSize`. Six slots.
///
/// Its `GetBuffer` takes five out-parameters where the render client's takes
/// one in and one out, which is the pair most likely to be transcribed into
/// each other's shape.
#[repr(C)]
pub(crate) struct AudioCaptureClientVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) get_buffer: unsafe extern "system" fn(
        *mut AudioCaptureClient,
        *mut *mut u8,
        *mut u32,
        *mut u32,
        *mut u64,
        *mut u64,
    ) -> Hr,
    pub(crate) release_buffer: unsafe extern "system" fn(*mut AudioCaptureClient, u32) -> Hr,
    pub(crate) get_next_packet_size:
        unsafe extern "system" fn(*mut AudioCaptureClient, *mut u32) -> Hr,
}

/// `IAudioCaptureClient`.
pub(crate) type AudioCaptureClient = Object<AudioCaptureClientVtable>;

impl Interface for AudioCaptureClientVtable {
    /// `C8ADBD64-E71E-48A0-A4DE-185C395CD317`.
    const IID: Guid = Guid::new(
        0xc8ad_bd64,
        0xe71e,
        0x48a0,
        [0xa4, 0xde, 0x18, 0x5c, 0x39, 0x5c, 0xd3, 0x17],
    );
}

/// `IMMNotificationClientVtbl`, from `mmdeviceapi.h`: `OnDeviceStateChanged`,
/// `OnDeviceAdded`, `OnDeviceRemoved`, `OnDefaultDeviceChanged`,
/// `OnPropertyValueChanged`. Eight slots.
///
/// This is the one interface here that Windows calls rather than answers, so
/// this crate fills the table in. `OnPropertyValueChanged` takes its
/// `PROPERTYKEY` by value: twenty octets, which the calling convention passes
/// by hidden pointer on x86-64 and inline on x86, and which the compiler gets
/// right from the declaration because it is the same declaration the header
/// makes.
#[repr(C)]
pub(crate) struct NotificationClientVtable {
    pub(crate) unknown: UnknownVtable,
    pub(crate) on_device_state_changed:
        unsafe extern "system" fn(*mut NotificationClient, *const u16, u32) -> Hr,
    pub(crate) on_device_added:
        unsafe extern "system" fn(*mut NotificationClient, *const u16) -> Hr,
    pub(crate) on_device_removed:
        unsafe extern "system" fn(*mut NotificationClient, *const u16) -> Hr,
    pub(crate) on_default_device_changed:
        unsafe extern "system" fn(*mut NotificationClient, u32, u32, *const u16) -> Hr,
    pub(crate) on_property_value_changed:
        unsafe extern "system" fn(*mut NotificationClient, *const u16, PropertyKey) -> Hr,
}

/// `IMMNotificationClient`.
pub(crate) type NotificationClient = Object<NotificationClientVtable>;

impl Interface for NotificationClientVtable {
    /// `7991EEC9-7E89-4D85-8390-6C703CEC60C0`.
    const IID: Guid = Guid::new(
        0x7991_eec9,
        0x7e89,
        0x4d85,
        [0x83, 0x90, 0x6c, 0x70, 0x3c, 0xec, 0x60, 0xc0],
    );
}

/// `CLSID_MMDeviceEnumerator`, `BCDE0395-E52F-467C-8E3D-C4579291692E`: the
/// class to ask `CoCreateInstance` for. It is the only object in this crate
/// that is created rather than handed over.
pub(crate) const CLSID_DEVICE_ENUMERATOR: Guid = Guid::new(
    0xbcde_0395,
    0xe52f,
    0x467c,
    [0x8e, 0x3d, 0xc4, 0x57, 0x92, 0x91, 0x69, 0x2e],
);

/// `PKEY_Device_FriendlyName`, from `functiondiscoverykeys_devpkey.h`: the
/// property that holds what a person would call the endpoint.
pub(crate) const PKEY_DEVICE_FRIENDLY_NAME: PropertyKey = PropertyKey {
    formatter: Guid::new(
        0xa45c_254e,
        0xdf1c,
        0x4efd,
        [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
    ),
    property: 14,
};

/// `KSDATAFORMAT_SUBTYPE_PCM`, from `ksmedia.h`. The first four octets are the
/// `WAVE_FORMAT_` tag the subtype stands in for, which is why it and the float
/// one below differ by one bit.
pub(crate) const SUBTYPE_PCM: Guid = Guid::new(
    0x0000_0001,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);

/// `KSDATAFORMAT_SUBTYPE_IEEE_FLOAT`, from `ksmedia.h`.
pub(crate) const SUBTYPE_IEEE_FLOAT: Guid = Guid::new(
    0x0000_0003,
    0x0000,
    0x0010,
    [0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71],
);

/// `PROPERTYKEY`, from `wtypes.h`: a GUID naming a set and a number naming one
/// property in it. Twenty octets, four-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct PropertyKey {
    pub(crate) formatter: Guid,
    pub(crate) property: u32,
}

/// `PROPVARIANT`, from `propidl.h`, as much of it as reading one string
/// needs: a type tag, three reserved words, and a union whose largest member
/// is a count and a pointer.
///
/// The union is not spelled out because nothing here writes one and only the
/// `VT_LPWSTR` arm is read. What matters is the size — twenty-four octets on a
/// sixty-four-bit target — because the caller allocates it and
/// `IPropertyStore::GetValue` writes into it.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PropVariant {
    pub(crate) kind: u16,
    pub(crate) reserved1: u16,
    pub(crate) reserved2: u16,
    pub(crate) reserved3: u16,
    /// `pwszVal` when [`PropVariant::kind`] is [`VT_LPWSTR`], and something
    /// else otherwise, which is why it is never read without that check.
    pub(crate) text: *mut u16,
    /// The rest of the widest union member. Never read; it is here so the
    /// structure is the size Windows writes.
    pub(crate) tail: usize,
}

impl PropVariant {
    /// An empty one, which is what `GetValue` expects to be handed.
    pub(crate) const EMPTY: Self = Self {
        kind: VT_EMPTY,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
        text: core::ptr::null_mut(),
        tail: 0,
    };
}

/// `VT_EMPTY`, from the `VARENUM` enumeration in `wtypes.h`.
pub(crate) const VT_EMPTY: u16 = 0;

/// `VT_LPWSTR`, from the same enumeration: a null-terminated wide string the
/// property store owns until `PropVariantClear`.
pub(crate) const VT_LPWSTR: u16 = 31;

/// `WAVEFORMATEX`, from `mmreg.h`. Eighteen octets, byte-packed.
///
/// `cb_size` counts what follows this structure and nothing else, so an
/// eighteen-octet header with `cb_size` of twenty-two is a
/// [`WaveFormatExtensible`] and one with zero is not.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct WaveFormat {
    pub(crate) format_tag: u16,
    pub(crate) channels: u16,
    pub(crate) samples_per_sec: u32,
    pub(crate) avg_bytes_per_sec: u32,
    pub(crate) block_align: u16,
    pub(crate) bits_per_sample: u16,
    pub(crate) cb_size: u16,
}

/// `WAVEFORMATEXTENSIBLE`, from `mmreg.h`. Forty octets, byte-packed: the
/// eighteen above, then the bits that are really in each sample, the channel
/// mask, and the subtype GUID that says what the samples mean.
///
/// Anything with more than two channels or more than sixteen bits has to be
/// described this way, which on Windows means the audio engine's own mix
/// format nearly always is.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct WaveFormatExtensible {
    pub(crate) format: WaveFormat,
    /// `Samples.wValidBitsPerSample`, the first arm of a union whose other
    /// arms this crate never sets.
    pub(crate) valid_bits_per_sample: u16,
    pub(crate) channel_mask: u32,
    pub(crate) sub_format: Guid,
}

impl WaveFormatExtensible {
    /// Octets the extension adds, which is what `cbSize` carries for it.
    pub(crate) const EXTENSION_BYTES: u16 = 22;

    /// All zeroes, to be filled in or written into.
    pub(crate) const EMPTY: Self = Self {
        format: WaveFormat {
            format_tag: 0,
            channels: 0,
            samples_per_sec: 0,
            avg_bytes_per_sec: 0,
            block_align: 0,
            bits_per_sample: 0,
            cb_size: 0,
        },
        valid_bits_per_sample: 0,
        channel_mask: 0,
        sub_format: Guid::new(0, 0, 0, [0; 8]),
    };
}

/// `WAVE_FORMAT_PCM`, from `mmreg.h`.
pub(crate) const WAVE_FORMAT_PCM: u16 = 0x0001;

/// `WAVE_FORMAT_IEEE_FLOAT`, from `mmreg.h`.
pub(crate) const WAVE_FORMAT_IEEE_FLOAT: u16 = 0x0003;

/// `WAVE_FORMAT_EXTENSIBLE`, from `mmreg.h`.
pub(crate) const WAVE_FORMAT_EXTENSIBLE: u16 = 0xfffe;

/// `SPEAKER_FRONT_CENTER`, from `ksmedia.h`: where one channel goes.
pub(crate) const SPEAKER_FRONT_CENTER: u32 = 0x4;

/// `eRender`, from the `EDataFlow` enumeration in `mmdeviceapi.h`.
pub(crate) const DATA_FLOW_RENDER: u32 = 0;

/// `eCapture`, from the same enumeration.
pub(crate) const DATA_FLOW_CAPTURE: u32 = 1;

/// `eCommunications`, from the `ERole` enumeration in `mmdeviceapi.h`.
///
/// Not `eConsole`. Windows lets a person choose a different endpoint for calls
/// than for music, and a SIP stack is the reason that setting exists; asking
/// for the console default would ignore a choice the user has already made.
pub(crate) const ROLE_COMMUNICATIONS: u32 = 2;

/// `DEVICE_STATE_ACTIVE`, from `mmdeviceapi.h`: plugged in, enabled, and
/// present. The other three states describe endpoints that exist in the
/// registry and cannot carry audio.
pub(crate) const DEVICE_STATE_ACTIVE: u32 = 0x0000_0001;

/// `AUDCLNT_SHAREMODE_SHARED`, from `audiosessiontypes.h`.
///
/// Exclusive mode is the other arm of that enumeration and this crate does not
/// use it: it takes the endpoint away from every other application on the
/// machine, which for a softphone means the user stops hearing their
/// notifications, and it buys latency that a network with a jitter buffer in
/// front of it will not notice.
pub(crate) const SHARE_MODE_SHARED: u32 = 0;

/// `AUDCLNT_STREAMFLAGS_EVENTCALLBACK`, from `audiosessiontypes.h`: Windows
/// signals an event when a buffer wants attention, rather than the client
/// waking on a timer and guessing.
pub(crate) const STREAMFLAGS_EVENTCALLBACK: u32 = 0x0004_0000;

/// `AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY`, from `Audioclient.h`: the packet
/// that follows a gap the engine could not fill.
pub(crate) const BUFFERFLAGS_DATA_DISCONTINUITY: u32 = 0x1;

/// `AUDCLNT_BUFFERFLAGS_SILENT`, from `Audioclient.h`. On capture it means the
/// buffer's contents are undefined and should be read as zeroes; on release it
/// tells the engine to ignore what was written and play silence.
pub(crate) const BUFFERFLAGS_SILENT: u32 = 0x2;

/// `CLSCTX_ALL`, from `wtypesbase.h`: the four server kinds ORed together.
pub(crate) const CLSCTX_ALL: u32 = 0x17;

/// `COINIT_MULTITHREADED`, from `objbase.h`.
pub(crate) const COINIT_MULTITHREADED: u32 = 0x0;

/// `STGM_READ`, from `objbase.h`: how the property store is opened.
pub(crate) const STGM_READ: u32 = 0;

/// `WAIT_OBJECT_0`, from `winbase.h`. A wait on several objects returns this
/// plus the index of the one that was signalled.
pub(crate) const WAIT_OBJECT_0: u32 = 0;

/// `WAIT_TIMEOUT`, from `winerror.h`.
pub(crate) const WAIT_TIMEOUT: u32 = 258;

/// One hundred-nanosecond unit, which is what `REFERENCE_TIME` counts.
pub(crate) const REFERENCE_TIMES_PER_SECOND: i64 = 10_000_000;

#[cfg(test)]
mod tests {
    use super::{
        AudioCaptureClientVtable, AudioClient2Vtable, AudioClientProperties, AudioClientVtable,
        AudioRenderClientVtable, CLSID_DEVICE_ENUMERATOR, DeviceCollectionVtable,
        DeviceEnumeratorVtable, Guid, Interface, MmDeviceVtable, NotificationClientVtable,
        PKEY_DEVICE_FRIENDLY_NAME, PropVariant, PropertyKey, PropertyStoreVtable,
        SUBTYPE_IEEE_FLOAT, SUBTYPE_PCM, UnknownVtable, WaveFormat, WaveFormatExtensible,
    };
    use core::mem::{align_of, offset_of, size_of};

    /// Which slot a member sits in, counted from the top of the table the way
    /// a header counts them.
    fn slot(offset: usize) -> usize {
        offset / size_of::<*const ()>()
    }

    /// How many slots a table has.
    fn slots<V>() -> usize {
        size_of::<V>() / size_of::<*const ()>()
    }

    // Every member of every table is asserted into its place below, and that
    // is the point of this file. A vtable is an array of function pointers
    // whatever it is called; a member left out or written in the wrong order
    // is not a type error, it is a call into a different method of the same
    // object, at run time, with the arguments of the one that was meant. The
    // audio client is where it would hurt most — `Start` and `Stop` are
    // adjacent and take the same arguments — so a stream that never runs and
    // never complains is the shape the mistake takes.
    //
    // What these prove is narrower than it looks: the offsets follow from the
    // field order in this file, so they catch a later edit, not a
    // transcription that was wrong to begin with. Only the headers catch that,
    // and the headers are what each declaration names.

    #[test]
    fn the_unknown_table_is_the_three_slots_everything_starts_with() {
        assert_eq!(slots::<UnknownVtable>(), 3);
        assert_eq!(slot(offset_of!(UnknownVtable, query_interface)), 0);
        assert_eq!(slot(offset_of!(UnknownVtable, add_ref)), 1);
        assert_eq!(slot(offset_of!(UnknownVtable, release)), 2);

        // and every other table begins with it, which is what makes releasing
        // any interface through a cast to IUnknown correct rather than lucky
        assert_eq!(offset_of!(DeviceEnumeratorVtable, unknown), 0);
        assert_eq!(offset_of!(DeviceCollectionVtable, unknown), 0);
        assert_eq!(offset_of!(MmDeviceVtable, unknown), 0);
        assert_eq!(offset_of!(PropertyStoreVtable, unknown), 0);
        assert_eq!(offset_of!(AudioClientVtable, unknown), 0);
        // through two derivations for this one, which is what makes releasing
        // an IAudioClient2 through a cast to IUnknown right
        assert_eq!(offset_of!(AudioClient2Vtable, client.unknown), 0);
        assert_eq!(offset_of!(AudioRenderClientVtable, unknown), 0);
        assert_eq!(offset_of!(AudioCaptureClientVtable, unknown), 0);
        assert_eq!(offset_of!(NotificationClientVtable, unknown), 0);
    }

    #[test]
    fn the_device_enumerator_table_is_five_members_after_unknown() {
        assert_eq!(slots::<DeviceEnumeratorVtable>(), 8);
        assert_eq!(
            slot(offset_of!(DeviceEnumeratorVtable, enum_audio_endpoints)),
            3
        );
        assert_eq!(
            slot(offset_of!(
                DeviceEnumeratorVtable,
                get_default_audio_endpoint
            )),
            4
        );
        assert_eq!(slot(offset_of!(DeviceEnumeratorVtable, get_device)), 5);
        assert_eq!(
            slot(offset_of!(
                DeviceEnumeratorVtable,
                register_endpoint_notification_callback
            )),
            6
        );
        assert_eq!(
            slot(offset_of!(
                DeviceEnumeratorVtable,
                unregister_endpoint_notification_callback
            )),
            7
        );
    }

    #[test]
    fn the_device_and_collection_tables_are_where_the_header_puts_them() {
        assert_eq!(slots::<DeviceCollectionVtable>(), 5);
        assert_eq!(slot(offset_of!(DeviceCollectionVtable, get_count)), 3);
        assert_eq!(slot(offset_of!(DeviceCollectionVtable, item)), 4);

        assert_eq!(slots::<MmDeviceVtable>(), 7);
        assert_eq!(slot(offset_of!(MmDeviceVtable, activate)), 3);
        assert_eq!(slot(offset_of!(MmDeviceVtable, open_property_store)), 4);
        assert_eq!(slot(offset_of!(MmDeviceVtable, get_id)), 5);
        assert_eq!(slot(offset_of!(MmDeviceVtable, get_state)), 6);
    }

    #[test]
    fn the_property_store_table_has_five_members_of_which_one_is_used() {
        assert_eq!(slots::<PropertyStoreVtable>(), 8);
        assert_eq!(slot(offset_of!(PropertyStoreVtable, get_count)), 3);
        assert_eq!(slot(offset_of!(PropertyStoreVtable, get_at)), 4);
        // the one this crate calls, and the reason the four around it are
        // declared at all: it has to be in slot five
        assert_eq!(slot(offset_of!(PropertyStoreVtable, get_value)), 5);
        assert_eq!(slot(offset_of!(PropertyStoreVtable, set_value)), 6);
        assert_eq!(slot(offset_of!(PropertyStoreVtable, commit)), 7);
    }

    #[test]
    fn the_audio_client_table_is_twelve_members_after_unknown() {
        assert_eq!(slots::<AudioClientVtable>(), 15);
        assert_eq!(slot(offset_of!(AudioClientVtable, initialize)), 3);
        assert_eq!(slot(offset_of!(AudioClientVtable, get_buffer_size)), 4);
        assert_eq!(slot(offset_of!(AudioClientVtable, get_stream_latency)), 5);
        assert_eq!(slot(offset_of!(AudioClientVtable, get_current_padding)), 6);
        assert_eq!(slot(offset_of!(AudioClientVtable, is_format_supported)), 7);
        assert_eq!(slot(offset_of!(AudioClientVtable, get_mix_format)), 8);
        assert_eq!(slot(offset_of!(AudioClientVtable, get_device_period)), 9);
        assert_eq!(slot(offset_of!(AudioClientVtable, start)), 10);
        assert_eq!(slot(offset_of!(AudioClientVtable, stop)), 11);
        assert_eq!(slot(offset_of!(AudioClientVtable, reset)), 12);
        assert_eq!(slot(offset_of!(AudioClientVtable, set_event_handle)), 13);
        assert_eq!(slot(offset_of!(AudioClientVtable, get_service)), 14);
    }

    #[test]
    fn the_audio_client_two_table_is_the_first_one_with_three_more_on_the_end() {
        assert_eq!(slots::<AudioClient2Vtable>(), 18);
        // the base interface's whole table, in place and in order: an
        // `IAudioClient2` handed to any of the calls above has to be the same
        // object at the same offsets, because it is
        assert_eq!(offset_of!(AudioClient2Vtable, client), 0);
        assert_eq!(slots::<AudioClientVtable>(), 15);
        assert_eq!(slot(offset_of!(AudioClient2Vtable, is_offload_capable)), 15);
        // the one this crate calls, and the reason the two around it are
        // declared at all: it has to be in slot sixteen
        assert_eq!(
            slot(offset_of!(AudioClient2Vtable, set_client_properties)),
            16
        );
        assert_eq!(
            slot(offset_of!(AudioClient2Vtable, get_buffer_size_limits)),
            17
        );
    }

    #[test]
    fn the_client_properties_are_four_words_that_say_their_own_size() {
        assert_eq!(size_of::<AudioClientProperties>(), 16);
        assert_eq!(align_of::<AudioClientProperties>(), 4);
        assert_eq!(offset_of!(AudioClientProperties, size), 0);
        assert_eq!(offset_of!(AudioClientProperties, is_offload), 4);
        assert_eq!(offset_of!(AudioClientProperties, category), 8);
        assert_eq!(offset_of!(AudioClientProperties, options), 12);
        assert_eq!(
            usize::try_from(AudioClientProperties::BYTES).unwrap(),
            size_of::<AudioClientProperties>(),
            "cbSize is what Windows reads to know the options field is there"
        );

        // what a call asks to be treated as, spelled out: the communications
        // category, no offload, and nothing bypassed
        let asked = AudioClientProperties::COMMUNICATIONS;
        assert_eq!(asked.size, 16);
        assert_eq!(asked.is_offload, 0);
        assert_eq!(asked.category, super::AUDIO_CATEGORY_COMMUNICATIONS);
        assert_eq!(asked.options, super::STREAMOPTIONS_NONE);
        assert_ne!(
            asked.options, 1,
            "AUDCLNT_STREAMOPTIONS_RAW takes the stream past the processing"
        );

        // and a call with the echo canceller turned off: the same category,
        // past the processing
        let raw = AudioClientProperties::COMMUNICATIONS_RAW;
        assert_eq!(raw.size, 16);
        assert_eq!(raw.category, super::AUDIO_CATEGORY_COMMUNICATIONS);
        assert_eq!(raw.options, super::STREAMOPTIONS_RAW);
        assert_eq!(raw.options, 1);
    }

    #[test]
    fn the_two_buffer_tables_are_not_each_other() {
        assert_eq!(slots::<AudioRenderClientVtable>(), 5);
        assert_eq!(slot(offset_of!(AudioRenderClientVtable, get_buffer)), 3);
        assert_eq!(slot(offset_of!(AudioRenderClientVtable, release_buffer)), 4);

        assert_eq!(slots::<AudioCaptureClientVtable>(), 6);
        assert_eq!(slot(offset_of!(AudioCaptureClientVtable, get_buffer)), 3);
        assert_eq!(
            slot(offset_of!(AudioCaptureClientVtable, release_buffer)),
            4
        );
        assert_eq!(
            slot(offset_of!(AudioCaptureClientVtable, get_next_packet_size)),
            5
        );
    }

    #[test]
    fn the_notification_table_is_the_one_this_crate_fills_in() {
        assert_eq!(slots::<NotificationClientVtable>(), 8);
        assert_eq!(
            slot(offset_of!(
                NotificationClientVtable,
                on_device_state_changed
            )),
            3
        );
        assert_eq!(
            slot(offset_of!(NotificationClientVtable, on_device_added)),
            4
        );
        assert_eq!(
            slot(offset_of!(NotificationClientVtable, on_device_removed)),
            5
        );
        assert_eq!(
            slot(offset_of!(
                NotificationClientVtable,
                on_default_device_changed
            )),
            6
        );
        assert_eq!(
            slot(offset_of!(
                NotificationClientVtable,
                on_property_value_changed
            )),
            7
        );
    }

    #[test]
    fn the_constants_are_the_numbers_their_headers_define() {
        use super::{
            AUDIO_CATEGORY_COMMUNICATIONS, BUFFERFLAGS_DATA_DISCONTINUITY, BUFFERFLAGS_SILENT,
            CLSCTX_ALL, COINIT_MULTITHREADED, DATA_FLOW_CAPTURE, DATA_FLOW_RENDER,
            DEVICE_STATE_ACTIVE, REFERENCE_TIMES_PER_SECOND, ROLE_COMMUNICATIONS,
            SHARE_MODE_SHARED, SPEAKER_FRONT_CENTER, STGM_READ, STREAMFLAGS_EVENTCALLBACK,
            STREAMOPTIONS_NONE, VT_EMPTY, VT_LPWSTR, WAIT_OBJECT_0, WAIT_TIMEOUT,
            WAVE_FORMAT_EXTENSIBLE, WAVE_FORMAT_IEEE_FLOAT, WAVE_FORMAT_PCM,
        };

        assert_eq!(DATA_FLOW_RENDER, 0);
        assert_eq!(DATA_FLOW_CAPTURE, 1);
        assert_eq!(ROLE_COMMUNICATIONS, 2);
        // the fourth AUDIO_STREAM_CATEGORY, and not to be confused with the
        // third ERole above: two enumerations, two meanings of the same word
        assert_eq!(AUDIO_CATEGORY_COMMUNICATIONS, 3);
        assert_eq!(STREAMOPTIONS_NONE, 0);
        assert_eq!(DEVICE_STATE_ACTIVE, 0x0000_0001);
        assert_eq!(SHARE_MODE_SHARED, 0);
        assert_eq!(STREAMFLAGS_EVENTCALLBACK, 0x0004_0000);
        assert_eq!(BUFFERFLAGS_DATA_DISCONTINUITY, 0x1);
        assert_eq!(BUFFERFLAGS_SILENT, 0x2);
        assert_eq!(WAVE_FORMAT_PCM, 1);
        assert_eq!(WAVE_FORMAT_IEEE_FLOAT, 3);
        assert_eq!(WAVE_FORMAT_EXTENSIBLE, 0xfffe);
        assert_eq!(SPEAKER_FRONT_CENTER, 0x4);
        assert_eq!(CLSCTX_ALL, 0x17);
        assert_eq!(COINIT_MULTITHREADED, 0);
        assert_eq!(STGM_READ, 0);
        assert_eq!(WAIT_OBJECT_0, 0);
        assert_eq!(WAIT_TIMEOUT, 258);
        assert_eq!(VT_EMPTY, 0);
        assert_eq!(VT_LPWSTR, 31);
        // REFERENCE_TIME counts hundreds of nanoseconds, so a second is ten
        // million of them and a ten-millisecond period is a hundred thousand
        assert_eq!(REFERENCE_TIMES_PER_SECOND, 10_000_000);
        assert_eq!(REFERENCE_TIMES_PER_SECOND / 100, 100_000);
    }

    #[test]
    fn a_wave_format_is_eighteen_octets_because_the_header_is_byte_packed() {
        assert_eq!(size_of::<WaveFormat>(), 18);
        assert_eq!(align_of::<WaveFormat>(), 1);
        assert_eq!(offset_of!(WaveFormat, format_tag), 0);
        assert_eq!(offset_of!(WaveFormat, channels), 2);
        assert_eq!(offset_of!(WaveFormat, samples_per_sec), 4);
        assert_eq!(offset_of!(WaveFormat, avg_bytes_per_sec), 8);
        assert_eq!(offset_of!(WaveFormat, block_align), 12);
        assert_eq!(offset_of!(WaveFormat, bits_per_sample), 14);
        assert_eq!(offset_of!(WaveFormat, cb_size), 16);
    }

    #[test]
    fn the_extensible_form_is_forty_and_says_so_in_its_own_field() {
        assert_eq!(size_of::<WaveFormatExtensible>(), 40);
        assert_eq!(align_of::<WaveFormatExtensible>(), 1);
        assert_eq!(offset_of!(WaveFormatExtensible, format), 0);
        assert_eq!(offset_of!(WaveFormatExtensible, valid_bits_per_sample), 18);
        assert_eq!(offset_of!(WaveFormatExtensible, channel_mask), 20);
        assert_eq!(offset_of!(WaveFormatExtensible, sub_format), 24);
        // cbSize counts everything after the eighteen-octet header
        assert_eq!(
            usize::from(WaveFormatExtensible::EXTENSION_BYTES),
            size_of::<WaveFormatExtensible>() - size_of::<WaveFormat>()
        );

        // and a blank one is blank all the way through, which is what a
        // short-form header read into it has to leave behind
        let blank = WaveFormatExtensible::EMPTY;
        let tag = blank.format.format_tag;
        let extension = blank.format.cb_size;
        let subtype = blank.sub_format;
        assert_eq!(tag, 0);
        assert_eq!(extension, 0);
        assert_eq!(subtype, Guid::new(0, 0, 0, [0; 8]));
    }

    #[test]
    fn a_property_key_is_a_guid_and_a_number() {
        assert_eq!(size_of::<Guid>(), 16);
        assert_eq!(align_of::<Guid>(), 4);
        assert_eq!(size_of::<PropertyKey>(), 20);
        assert_eq!(offset_of!(PropertyKey, property), 16);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_propvariant_is_twenty_four_octets() {
        assert_eq!(size_of::<PropVariant>(), 24);
        assert_eq!(align_of::<PropVariant>(), 8);
        assert_eq!(offset_of!(PropVariant, kind), 0);
        assert_eq!(offset_of!(PropVariant, text), 8);
        assert_eq!(PropVariant::EMPTY.kind, super::VT_EMPTY);
        assert!(PropVariant::EMPTY.text.is_null());
    }

    /// The identifiers, read back as the text the headers write them in. A
    /// transposed pair of digits is the one mistake in this file that has no
    /// symptom at all until a call returns `E_NOINTERFACE`.
    #[test]
    fn the_identifiers_read_back_as_the_headers_spell_them() {
        assert_eq!(
            CLSID_DEVICE_ENUMERATOR.to_string(),
            "bcde0395-e52f-467c-8e3d-c4579291692e"
        );
        assert_eq!(
            DeviceEnumeratorVtable::IID.to_string(),
            "a95664d2-9614-4f35-a746-de8db63617e6"
        );
        assert_eq!(
            DeviceCollectionVtable::IID.to_string(),
            "0bd7a1be-7a1a-44db-8397-cc5392387b5e"
        );
        assert_eq!(
            MmDeviceVtable::IID.to_string(),
            "d666063f-1587-4e43-81f1-b948e807363f"
        );
        assert_eq!(
            PropertyStoreVtable::IID.to_string(),
            "886d8eeb-8cf2-4446-8d02-cdba1dbdcf99"
        );
        assert_eq!(
            AudioClientVtable::IID.to_string(),
            "1cb9ad4c-dbfa-4c32-b178-c2f568a703b2"
        );
        assert_eq!(
            AudioClient2Vtable::IID.to_string(),
            "726778cd-f60a-4eda-82de-e47610cd78aa"
        );
        assert_ne!(
            AudioClient2Vtable::IID,
            AudioClientVtable::IID,
            "the derived interface has its own identifier and has to be asked for by it"
        );
        assert_eq!(
            AudioRenderClientVtable::IID.to_string(),
            "f294acfc-3146-4483-a7bf-addca7c260e2"
        );
        assert_eq!(
            AudioCaptureClientVtable::IID.to_string(),
            "c8adbd64-e71e-48a0-a4de-185c395cd317"
        );
        assert_eq!(
            NotificationClientVtable::IID.to_string(),
            "7991eec9-7e89-4d85-8390-6c703cec60c0"
        );
        assert_eq!(
            UnknownVtable::IID.to_string(),
            "00000000-0000-0000-c000-000000000046"
        );
        assert_eq!(
            SUBTYPE_PCM.to_string(),
            "00000001-0000-0010-8000-00aa00389b71"
        );
        assert_eq!(
            SUBTYPE_IEEE_FLOAT.to_string(),
            "00000003-0000-0010-8000-00aa00389b71"
        );
        assert_eq!(
            PKEY_DEVICE_FRIENDLY_NAME.formatter.to_string(),
            "a45c254e-df1c-4efd-8020-67d146a850e0"
        );
        assert_eq!(PKEY_DEVICE_FRIENDLY_NAME.property, 14);
    }

    #[test]
    fn the_two_subtypes_differ_only_in_the_tag_they_stand_for() {
        assert_eq!(SUBTYPE_PCM.data1, u32::from(super::WAVE_FORMAT_PCM));
        assert_eq!(
            SUBTYPE_IEEE_FLOAT.data1,
            u32::from(super::WAVE_FORMAT_IEEE_FLOAT)
        );
        assert_eq!(SUBTYPE_PCM.data4, SUBTYPE_IEEE_FLOAT.data4);
    }
}
