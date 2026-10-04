// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Asking the machine what audio endpoints it has, and being told when that
//! changes.
//!
//! Windows counts an endpoint per direction: a headset with a microphone is
//! two of them, with two identifiers and two names, and a stream opens one.
//! That is the shape this file reports, rather than a device with a channel
//! count on each side, because it is the shape the operating system has and
//! flattening it would lose the case where the two halves are separately
//! chosen — which is exactly what a virtual cable is for.
//!
//! Everything here belongs to the thread that called it. COM says so: an
//! apartment is per thread, so an object created on one has to be released on
//! the same one. [`DeviceMonitor`] is therefore not `Send`, which is a
//! constraint rather than an omission.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::panic::{self, AssertUnwindSafe};

use crate::abi::{
    CLSCTX_ALL, CLSID_DEVICE_ENUMERATOR, DATA_FLOW_CAPTURE, DATA_FLOW_RENDER, DEVICE_STATE_ACTIVE,
    DeviceCollectionVtable, DeviceEnumerator, DeviceEnumeratorVtable, Guid, Interface, MmDevice,
    MmDeviceVtable, NotificationClient, NotificationClientVtable, PKEY_DEVICE_FRIENDLY_NAME,
    PropVariant, PropertyKey, PropertyStoreVtable, ROLE_COMMUNICATIONS, STGM_READ, Unknown,
    UnknownVtable, VT_LPWSTR,
};
use crate::com::{Apartment, Com, TaskMemory, text_from, wide};
use crate::device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Pending};
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
use crate::status::{E_NOINTERFACE, E_NOTFOUND, E_POINTER, Error, HResult};
use crate::sys;

/// Which way Windows counts a direction.
pub(crate) const fn data_flow(direction: Direction) -> u32 {
    match direction {
        Direction::Input => DATA_FLOW_CAPTURE,
        Direction::Output => DATA_FLOW_RENDER,
    }
}

/// The one object in this crate that is created rather than handed over.
pub(crate) fn enumerator() -> Result<Com<DeviceEnumeratorVtable>, Error> {
    // bound to locals so that what is pointed at outlives the call, which a
    // constant used in place would not
    let class = CLSID_DEVICE_ENUMERATOR;
    let interface = DeviceEnumeratorVtable::IID;
    let mut raw: *mut c_void = ptr::null_mut();
    // SAFETY: two static identifiers, no aggregation, and a live
    // out-parameter of the type the identifier names.
    let status = unsafe {
        sys::co_create_instance(
            &raw const class,
            ptr::null_mut(),
            CLSCTX_ALL,
            &raw const interface,
            &raw mut raw,
        )
    };
    sys::check("CoCreateInstance (MMDeviceEnumerator)", status)?;
    // SAFETY: the call succeeded, so the pointer is a live enumerator whose
    // reference this takes over.
    unsafe { Com::from_raw(raw.cast::<DeviceEnumerator>()) }.ok_or(Error::Call {
        call: "CoCreateInstance (MMDeviceEnumerator)",
        status: HResult::new(E_POINTER),
    })
}

/// The endpoint a choice names, opened.
///
/// A preference the machine does not have is not an error, and neither is one
/// it has and cannot play through. That is the whole point of one: the headset
/// is in a bag, the call still has to happen.
pub(crate) fn open_choice(
    enumerator: &Com<DeviceEnumeratorVtable>,
    choice: &DeviceChoice,
    direction: Direction,
) -> Result<Com<MmDeviceVtable>, Error> {
    match *choice {
        DeviceChoice::System => open(enumerator, None, direction),
        DeviceChoice::Device(ref id) => open(enumerator, Some(id), direction),
        DeviceChoice::Preferred(ref id) => match open(enumerator, Some(id), direction) {
            // Windows keeps an unplugged, disabled or absent endpoint in its
            // registry, and `GetDevice` finds one of those as readily as a
            // live one; it is `Activate` that refuses, after this has already
            // answered. Without asking, a preference would fall back only for
            // an endpoint the machine has never seen — which is not the one a
            // saved selection names.
            Ok(saved) => {
                if carries_audio(&saved)? {
                    Ok(saved)
                } else {
                    drop(saved);
                    open(enumerator, None, direction)
                }
            }
            Err(Error::NoDevice) => open(enumerator, None, direction),
            // A GetDevice that failed for any other reason is not a missing
            // endpoint, it is a broken one, and falling back would hide it.
            other => other,
        },
    }
}

/// Whether an endpoint can carry audio now: plugged in, enabled and present.
///
/// The same test `EnumAudioEndpoints` applies with the mask [`devices`] asks
/// for, so an endpoint this accepts is one the list would have offered.
///
/// # Errors
/// [`Error::Call`] when the endpoint will not say. That is a broken endpoint
/// rather than a missing one, and a preference does not fall back past it for
/// the same reason it does not fall back past a `GetDevice` that failed.
fn carries_audio(device: &Com<MmDeviceVtable>) -> Result<bool, Error> {
    let mut state: u32 = 0;
    // SAFETY: a live endpoint and a live out-parameter.
    let status = unsafe { (device.vtable().get_state)(device.as_ptr(), &raw mut state) };
    sys::check("IMMDevice::GetState", status)?;
    Ok(state & DEVICE_STATE_ACTIVE != 0)
}

/// The endpoint a stream should open: the one named, or the machine's default
/// for calls in that direction.
pub(crate) fn open(
    enumerator: &Com<DeviceEnumeratorVtable>,
    wanted: Option<&DeviceId>,
    direction: Direction,
) -> Result<Com<MmDeviceVtable>, Error> {
    let mut raw: *mut MmDevice = ptr::null_mut();
    let (call, status) = if let Some(id) = wanted {
        let name = wide(id.as_str());
        // SAFETY: a terminated wide string that outlives the call, and a live
        // out-parameter.
        let status = unsafe {
            (enumerator.vtable().get_device)(enumerator.as_ptr(), name.as_ptr(), &raw mut raw)
        };
        ("IMMDeviceEnumerator::GetDevice", status)
    } else {
        // SAFETY: two documented enumeration values and a live out-parameter.
        let status = unsafe {
            (enumerator.vtable().get_default_audio_endpoint)(
                enumerator.as_ptr(),
                data_flow(direction),
                ROLE_COMMUNICATIONS,
                &raw mut raw,
            )
        };
        ("IMMDeviceEnumerator::GetDefaultAudioEndpoint", status)
    };
    if HResult::new(status).code() == E_NOTFOUND {
        return Err(Error::NoDevice);
    }
    sys::check(call, status)?;
    // SAFETY: the call succeeded, so the pointer is a live endpoint whose
    // reference this takes over.
    unsafe { Com::from_raw(raw) }.ok_or(Error::NoDevice)
}

/// Everything worth saying about an endpoint that is already open.
///
/// Infallible, because a stream that has an endpoint open has an endpoint
/// whatever its property store thinks: a name that cannot be read is an empty
/// name, and a default that cannot be established is `false`.
pub(crate) fn describe(
    enumerator: &Com<DeviceEnumeratorVtable>,
    device: &Com<MmDeviceVtable>,
    direction: Direction,
) -> Device {
    let id = identify(device).unwrap_or_else(|_| DeviceId::new(String::new()));
    let is_default = default_id(enumerator, direction)
        .ok()
        .flatten()
        .is_some_and(|chosen| chosen == id);
    Device {
        id,
        name: name_of(device),
        direction,
        is_default,
    }
}

/// Every endpoint the machine has, at this instant.
///
/// Only the ones that are plugged in and enabled — `DEVICE_STATE_ACTIVE`. The
/// other three states describe endpoints that exist in the registry and cannot
/// carry audio, and listing them would offer the caller a choice that fails
/// when it is taken.
///
/// The answer is a snapshot and it goes stale, which is what [`DeviceMonitor`]
/// is for.
///
/// # Errors
/// [`Error::Call`] when COM or the enumerator refuses.
pub fn devices() -> Result<Vec<Device>, Error> {
    let _apartment = Apartment::enter()?;
    let enumerator = enumerator()?;
    let mut found = Vec::new();
    for direction in [Direction::Input, Direction::Output] {
        let chosen = default_id(&enumerator, direction)?;
        for device in list(&enumerator, direction)? {
            let id = identify(&device)?;
            found.push(Device {
                name: name_of(&device),
                is_default: chosen.as_ref() == Some(&id),
                id,
                direction,
            });
        }
    }
    Ok(found)
}

/// What the machine is routing calls to in a direction right now, or `None`
/// when it has nothing to route them to.
///
/// # Errors
/// [`Error::Call`] when COM or the enumerator refuses.
pub fn default_device(direction: Direction) -> Result<Option<DeviceId>, Error> {
    let _apartment = Apartment::enter()?;
    let enumerator = enumerator()?;
    default_id(&enumerator, direction)
}

fn default_id(
    enumerator: &Com<DeviceEnumeratorVtable>,
    direction: Direction,
) -> Result<Option<DeviceId>, Error> {
    match open(enumerator, None, direction) {
        Ok(device) => identify(&device).map(Some),
        Err(Error::NoDevice) => Ok(None),
        Err(error) => Err(error),
    }
}

fn list(
    enumerator: &Com<DeviceEnumeratorVtable>,
    direction: Direction,
) -> Result<Vec<Com<MmDeviceVtable>>, Error> {
    let mut raw = ptr::null_mut();
    // SAFETY: documented enumeration values and a live out-parameter.
    let status = unsafe {
        (enumerator.vtable().enum_audio_endpoints)(
            enumerator.as_ptr(),
            data_flow(direction),
            DEVICE_STATE_ACTIVE,
            &raw mut raw,
        )
    };
    sys::check("IMMDeviceEnumerator::EnumAudioEndpoints", status)?;
    // SAFETY: the call succeeded, so this is a live collection.
    let Some(collection) = (unsafe { Com::<DeviceCollectionVtable>::from_raw(raw) }) else {
        return Ok(Vec::new());
    };

    let mut count: u32 = 0;
    // SAFETY: a live out-parameter.
    let status = unsafe { (collection.vtable().get_count)(collection.as_ptr(), &raw mut count) };
    sys::check("IMMDeviceCollection::GetCount", status)?;

    let mut devices = Vec::new();
    for index in 0..count {
        let mut item: *mut MmDevice = ptr::null_mut();
        // SAFETY: the index is below the count the collection just gave, and
        // the out-parameter is live.
        let status =
            unsafe { (collection.vtable().item)(collection.as_ptr(), index, &raw mut item) };
        // An endpoint that goes away between the count and the fetch is an
        // ordinary Tuesday, not a reason to fail the whole enumeration.
        if !HResult::new(status).is_ok() {
            continue;
        }
        // SAFETY: the call succeeded, so this is a live endpoint.
        if let Some(device) = unsafe { Com::from_raw(item) } {
            devices.push(device);
        }
    }
    Ok(devices)
}

/// The endpoint's identifier, which is the thing worth writing down.
fn identify(device: &Com<MmDeviceVtable>) -> Result<DeviceId, Error> {
    let mut raw: *mut u16 = ptr::null_mut();
    // SAFETY: a live out-parameter; what comes back is task memory this side
    // owns.
    let status = unsafe { (device.vtable().get_id)(device.as_ptr(), &raw mut raw) };
    sys::check("IMMDevice::GetId", status)?;
    // SAFETY: the call succeeded, so this is task memory holding a terminated
    // wide string.
    let Some(owned) = (unsafe { TaskMemory::from_raw(raw) }) else {
        return Ok(DeviceId::new(String::new()));
    };
    // SAFETY: the string stays valid until `owned` is dropped below.
    Ok(DeviceId::new(unsafe { text_from(owned.as_ptr()) }))
}

/// What a person would call it, or nothing when the endpoint will not say.
///
/// A name is a label on a list. An endpoint that has none is still an
/// endpoint, so this answers with an empty string rather than a failure.
fn name_of(device: &Com<MmDeviceVtable>) -> String {
    let mut raw = ptr::null_mut();
    // SAFETY: a documented access mode and a live out-parameter.
    let status =
        unsafe { (device.vtable().open_property_store)(device.as_ptr(), STGM_READ, &raw mut raw) };
    if !HResult::new(status).is_ok() {
        return String::new();
    }
    // SAFETY: the call succeeded, so this is a live property store.
    let Some(store) = (unsafe { Com::<PropertyStoreVtable>::from_raw(raw) }) else {
        return String::new();
    };

    let key: PropertyKey = PKEY_DEVICE_FRIENDLY_NAME;
    let mut value = PropVariant::EMPTY;
    // SAFETY: a live key and a live, empty variant for the store to fill in.
    let status =
        unsafe { (store.vtable().get_value)(store.as_ptr(), &raw const key, &raw mut value) };
    if !HResult::new(status).is_ok() {
        return String::new();
    }
    let name = if value.kind == VT_LPWSTR {
        // SAFETY: the tag says the union holds a terminated wide string, and
        // the store owns it until the clear below.
        unsafe { text_from(value.text) }
    } else {
        String::new()
    };
    // SAFETY: the variant was filled in by the call above and is cleared once.
    unsafe { sys::prop_variant_clear(&raw mut value) };
    name
}

/// What the notification client is holding on behalf of the monitor.
#[repr(C)]
struct Notify {
    /// First, and it has to be: this is the object Windows calls through.
    vtable: *const NotificationClientVtable,
    refs: AtomicU32,
    gate: Gate,
    pending: Pending,
}

/// The table Windows calls into. Static, because there is one implementation
/// however many monitors exist.
static NOTIFY_VTABLE: NotificationClientVtable = NotificationClientVtable {
    unknown: UnknownVtable {
        query_interface: notify_query_interface,
        add_ref: notify_add_ref,
        release: notify_release,
    },
    on_device_state_changed: notify_state_changed,
    on_device_added: notify_added,
    on_device_removed: notify_removed,
    on_default_device_changed: notify_default_changed,
    on_property_value_changed: notify_property_changed,
};

/// `IUnknown::QueryInterface`. Two identifiers are answered and everything
/// else is refused, which is the whole of what an object with one interface
/// has to do.
unsafe extern "system" fn notify_query_interface(
    this: *mut Unknown,
    wanted: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: checked for null; the caller owns a live pointer otherwise.
    unsafe { *out = ptr::null_mut() };
    // SAFETY: as above.
    let Some(wanted) = (unsafe { wanted.as_ref() }) else {
        return E_POINTER;
    };
    if *wanted != UnknownVtable::IID && *wanted != NotificationClientVtable::IID {
        return E_NOINTERFACE;
    }
    // SAFETY: `this` is the pointer Windows was given, which is a `Notify`.
    unsafe { notify_add_ref(this) };
    // SAFETY: checked for null above.
    unsafe { *out = this.cast::<c_void>() };
    0
}

/// `IUnknown::AddRef`.
unsafe extern "system" fn notify_add_ref(this: *mut Unknown) -> u32 {
    // SAFETY: `this` is a live `Notify`, which is what was registered.
    let Some(notify) = (unsafe { this.cast::<Notify>().as_ref() }) else {
        return 0;
    };
    notify.refs.fetch_add(1, Ordering::Relaxed) + 1
}

/// `IUnknown::Release`. The last one frees the object, and only the last one.
unsafe extern "system" fn notify_release(this: *mut Unknown) -> u32 {
    let raw = this.cast::<Notify>();
    // SAFETY: a live `Notify`.
    let Some(notify) = (unsafe { raw.as_ref() }) else {
        return 0;
    };
    // Release on the decrement, so that everything every other thread did to
    // this object happens before the acquire below; acquire on the last one,
    // so the drop sees all of it. The standard reference-count pair.
    let left = notify.refs.fetch_sub(1, Ordering::Release) - 1;
    if left == 0 {
        core::sync::atomic::fence(Ordering::Acquire);
        // SAFETY: the count reached zero, so this is the only reference left
        // and the box it came from can be taken back.
        drop(unsafe { Box::from_raw(raw) });
    }
    left
}

/// Note a change on the monitor's pending set, if the monitor is still there
/// to have one.
///
/// The gate is what says it is. A panic is caught because an unwind across the
/// boundary Windows called through would be undefined, and there is nothing
/// here that could raise one — which is why nothing counts them.
///
/// # Safety
/// `this` is null, or the notification client Windows was handed.
unsafe fn noted(this: *mut NotificationClient, event: DeviceEvent) -> i32 {
    // SAFETY: `this` is the pointer Windows was given, which is a `Notify`.
    let Some(notify) = (unsafe { this.cast::<Notify>().as_ref() }) else {
        return 0;
    };
    let Some(_inside) = notify.gate.enter() else {
        return 0;
    };
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| notify.pending.note(event)));
    drop(outcome);
    0
}

unsafe extern "system" fn notify_state_changed(
    this: *mut NotificationClient,
    _id: *const u16,
    _state: u32,
) -> i32 {
    // enabled, disabled, unplugged: all of them mean the list is not what it
    // was, and the caller answers all of them by asking again
    // SAFETY: the pointer Windows was given.
    unsafe { noted(this, DeviceEvent::ListChanged) }
}

unsafe extern "system" fn notify_added(this: *mut NotificationClient, _id: *const u16) -> i32 {
    // SAFETY: the pointer Windows was given.
    unsafe { noted(this, DeviceEvent::ListChanged) }
}

unsafe extern "system" fn notify_removed(this: *mut NotificationClient, _id: *const u16) -> i32 {
    // SAFETY: the pointer Windows was given.
    unsafe { noted(this, DeviceEvent::ListChanged) }
}

unsafe extern "system" fn notify_default_changed(
    this: *mut NotificationClient,
    flow: u32,
    role: u32,
    _id: *const u16,
) -> i32 {
    // Windows reports each role separately and this crate only ever asks for
    // the communications one, so reporting the others would be telling the
    // caller about a change that cannot affect anything it opens.
    if role != ROLE_COMMUNICATIONS {
        return 0;
    }
    let direction = if flow == DATA_FLOW_CAPTURE {
        Direction::Input
    } else {
        Direction::Output
    };
    // SAFETY: the pointer Windows was given.
    unsafe { noted(this, DeviceEvent::DefaultChanged(direction)) }
}

unsafe extern "system" fn notify_property_changed(
    _this: *mut NotificationClient,
    _id: *const u16,
    _key: PropertyKey,
) -> i32 {
    // A property changed on some endpoint: its name, its icon, its format.
    // None of it changes what a caller would do, and answering S_OK is what
    // an implementation that does not care is supposed to do.
    0
}

/// Watches the machine's audio endpoints and remembers what changed.
///
/// A headset arriving or leaving is not an error and does not interrupt a
/// stream running on another endpoint; it is a fact the caller may want to act
/// on, so it waits here until asked for. Dropping the monitor stops the
/// watching.
///
/// Belongs to the thread that made it, because its COM apartment does.
pub struct DeviceMonitor {
    /// Dropped last, after the enumerator and the notification client, because
    /// it is what makes both of them legal.
    enumerator: Option<Com<DeviceEnumeratorVtable>>,
    apartment: Option<Apartment>,
    /// This side's reference to the notification client, or null once it has
    /// been given back — or once teardown decided it never would be.
    notify: *mut Notify,
    registered: bool,
    not_send: PhantomData<*const ()>,
}

impl DeviceMonitor {
    /// Start watching.
    ///
    /// # Errors
    /// [`Error::Call`] from COM, the enumerator, or the registration. A
    /// registration that fails leaves nothing behind.
    pub fn new() -> Result<Self, Error> {
        let apartment = Apartment::enter()?;
        let enumerator = enumerator()?;
        let notify = Box::into_raw(Box::new(Notify {
            vtable: &raw const NOTIFY_VTABLE,
            // one reference: this side's. Registering adds Windows's.
            refs: AtomicU32::new(1),
            gate: Gate::new(),
            pending: Pending::new(),
        }));

        // SAFETY: a live notification client whose first word is the table
        // above, which is what the interface pointer means.
        let status = unsafe {
            (enumerator.vtable().register_endpoint_notification_callback)(
                enumerator.as_ptr(),
                notify.cast::<NotificationClient>(),
            )
        };
        if let Err(error) = sys::check(
            "IMMDeviceEnumerator::RegisterEndpointNotificationCallback",
            status,
        ) {
            // SAFETY: nothing else holds a reference, so this is the last one
            // and it frees the box.
            unsafe { notify_release(notify.cast::<Unknown>()) };
            return Err(error);
        }

        Ok(Self {
            enumerator: Some(enumerator),
            apartment: Some(apartment),
            notify,
            registered: true,
            not_send: PhantomData,
        })
    }

    /// Take one change, or `None` when nothing has happened since the last
    /// time. Several changes of the same kind arrive as one.
    #[must_use]
    pub fn poll(&self) -> Option<DeviceEvent> {
        // SAFETY: this side holds a reference for as long as the pointer is
        // not null, so the object is alive.
        unsafe { self.notify.as_ref() }.and_then(|notify| notify.pending.take())
    }

    /// Stop watching, and say what Windows made of it.
    ///
    /// Dropping a monitor does the same and has nowhere to report to.
    ///
    /// # Errors
    /// [`Error::Draining`] when a notification could not be shown to have
    /// finished, in which case the client object is deliberately never freed;
    /// otherwise [`Error::Call`] from the unregistration.
    pub fn close(mut self) -> Result<(), Error> {
        self.teardown()
    }

    fn teardown(&mut self) -> Result<(), Error> {
        self.shut_down(TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS)
    }

    /// The same with the wait spelled out, so a test can ask for a deadline it
    /// is willing to sit through.
    ///
    /// The order is the argument: shut the gate first, so a notification that
    /// has not started reading turns itself around; unregister next, which is
    /// what stops further ones arriving; then wait for anything already inside
    /// to come out, which is the only thing that says so about one that was
    /// already running.
    fn shut_down(&mut self, within: Duration, millis: u64) -> Result<(), Error> {
        if self.notify.is_null() {
            return Ok(());
        }
        let notify = self.notify;
        // SAFETY: this side still holds a reference, so the object is alive.
        let watch = unsafe { &*notify };
        watch.gate.close();

        let mut unregistered = 0;
        if let Some(enumerator) = self.enumerator.as_ref().filter(|_| self.registered) {
            // SAFETY: unregistering exactly the client that was registered,
            // with the same pointer.
            unregistered = unsafe {
                (enumerator
                    .vtable()
                    .unregister_endpoint_notification_callback)(
                    enumerator.as_ptr(),
                    notify.cast::<NotificationClient>(),
                )
            };
        }
        self.registered = false;

        if !watch.gate.drained(within) {
            // The reference is dropped without being given back, so the object
            // outlives us. A notification thread reading a freed one is a
            // crash on somebody's machine during a call; an object that is
            // never freed is a number in a memory graph.
            self.notify = ptr::null_mut();
            return Err(Error::Draining {
                waited_millis: millis,
            });
        }

        self.notify = ptr::null_mut();
        // SAFETY: nothing is inside the gate and Windows has given its
        // reference back, so this is the last one.
        unsafe { notify_release(notify.cast::<Unknown>()) };
        sys::check(
            "IMMDeviceEnumerator::UnregisterEndpointNotificationCallback",
            unregistered,
        )
    }
}

impl Drop for DeviceMonitor {
    fn drop(&mut self) {
        // nothing to report a status to from here; the record a teardown that
        // could not finish leaves behind is the object it did not free
        let _ = self.teardown();
        // the enumerator goes back before the apartment it was made in, which
        // is the one ordering COM cares about here
        drop(self.enumerator.take());
        drop(self.apartment.take());
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceMonitor, default_device, devices, open_choice};
    use crate::abi::{
        DEVICE_STATE_ACTIVE, DeviceCollection, DeviceEnumerator, DeviceEnumeratorVtable, Guid,
        MmDevice, MmDeviceVtable, NotificationClient, PropVariant, PropertyStore,
    };
    use crate::device::{DeviceChoice, DeviceId, Direction};
    use crate::fake::{self, Fake, NOT_IMPLEMENTED};
    use crate::status::{E_POINTER, Error, HResult};
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::time::Duration;

    /// `DEVICE_STATE_DISABLED`, from `mmdeviceapi.h`.
    const DEVICE_STATE_DISABLED: u32 = 0x0000_0002;
    /// `DEVICE_STATE_NOTPRESENT`, from `mmdeviceapi.h`.
    const DEVICE_STATE_NOTPRESENT: u32 = 0x0000_0004;
    /// `DEVICE_STATE_UNPLUGGED`, from `mmdeviceapi.h`.
    const DEVICE_STATE_UNPLUGGED: u32 = 0x0000_0008;

    /// What one endpoint says about itself.
    struct Endpoint {
        state: u32,
        /// What `GetState` returns, whatever the state.
        answers: i32,
        asked: AtomicU32,
    }

    static ENDPOINT: MmDeviceVtable = MmDeviceVtable {
        unknown: fake::unknown::<MmDeviceVtable, Endpoint>(),
        activate: endpoint_activate,
        open_property_store: endpoint_property_store,
        get_id: endpoint_id,
        get_state: endpoint_state,
    };

    unsafe extern "system" fn endpoint_activate(
        _this: *mut MmDevice,
        _interface: *const Guid,
        _context: u32,
        _parameters: *mut PropVariant,
        _out: *mut *mut c_void,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn endpoint_property_store(
        _this: *mut MmDevice,
        _access: u32,
        _out: *mut *mut PropertyStore,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn endpoint_id(_this: *mut MmDevice, _out: *mut *mut u16) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn endpoint_state(this: *mut MmDevice, out: *mut u32) -> i32 {
        // SAFETY: `this` is the address of a live `Fake` over this table.
        let Some(endpoint) = (unsafe { fake::script::<MmDeviceVtable, Endpoint>(this) }) else {
            return E_POINTER;
        };
        endpoint.asked.fetch_add(1, Ordering::SeqCst);
        // SAFETY: null, or the caller's live out-parameter.
        let Some(out) = (unsafe { out.as_mut() }) else {
            return E_POINTER;
        };
        *out = endpoint.state;
        endpoint.answers
    }

    /// The machine's endpoints in one direction: the one a selection saved,
    /// which the registry still has, and the one calls are routed to.
    struct Machine {
        saved: Fake<MmDeviceVtable, Endpoint>,
        route: Fake<MmDeviceVtable, Endpoint>,
        routes_asked: AtomicU32,
    }

    static MACHINE: DeviceEnumeratorVtable = DeviceEnumeratorVtable {
        unknown: fake::unknown::<DeviceEnumeratorVtable, Machine>(),
        enum_audio_endpoints: machine_enumerate,
        get_default_audio_endpoint: machine_route,
        get_device: machine_device,
        register_endpoint_notification_callback: machine_register,
        unregister_endpoint_notification_callback: machine_register,
    };

    unsafe extern "system" fn machine_enumerate(
        _this: *mut DeviceEnumerator,
        _flow: u32,
        _mask: u32,
        _out: *mut *mut DeviceCollection,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn machine_register(
        _this: *mut DeviceEnumerator,
        _client: *mut NotificationClient,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn machine_route(
        this: *mut DeviceEnumerator,
        _flow: u32,
        _role: u32,
        out: *mut *mut MmDevice,
    ) -> i32 {
        // SAFETY: `this` is the address of a live `Fake` over this table.
        let Some(machine) = (unsafe { fake::script::<DeviceEnumeratorVtable, Machine>(this) })
        else {
            return E_POINTER;
        };
        machine.routes_asked.fetch_add(1, Ordering::SeqCst);
        // SAFETY: null, or the caller's live out-parameter.
        let Some(out) = (unsafe { out.as_mut() }) else {
            return E_POINTER;
        };
        *out = machine.route.hand_out();
        0
    }

    unsafe extern "system" fn machine_device(
        this: *mut DeviceEnumerator,
        _id: *const u16,
        out: *mut *mut MmDevice,
    ) -> i32 {
        // SAFETY: `this` is the address of a live `Fake` over this table.
        let Some(machine) = (unsafe { fake::script::<DeviceEnumeratorVtable, Machine>(this) })
        else {
            return E_POINTER;
        };
        // SAFETY: null, or the caller's live out-parameter.
        let Some(out) = (unsafe { out.as_mut() }) else {
            return E_POINTER;
        };
        *out = machine.saved.hand_out();
        0
    }

    fn endpoint(state: u32, answers: i32) -> Fake<MmDeviceVtable, Endpoint> {
        Fake::new(
            &ENDPOINT,
            Endpoint {
                state,
                answers,
                asked: AtomicU32::new(0),
            },
        )
    }

    fn machine(saved: Fake<MmDeviceVtable, Endpoint>) -> Fake<DeviceEnumeratorVtable, Machine> {
        Fake::new(
            &MACHINE,
            Machine {
                saved,
                route: endpoint(DEVICE_STATE_ACTIVE, 0),
                routes_asked: AtomicU32::new(0),
            },
        )
    }

    fn headset() -> DeviceChoice {
        DeviceChoice::Preferred(DeviceId::new("{0.0.1.00000000}.{headset}"))
    }

    #[test]
    fn a_preference_the_machine_has_but_cannot_play_through_opens_the_route() {
        for state in [
            DEVICE_STATE_DISABLED,
            DEVICE_STATE_NOTPRESENT,
            DEVICE_STATE_UNPLUGGED,
        ] {
            let machine = machine(endpoint(state, 0));
            let enumerator = machine.com();
            let script = machine.script();
            let saved = &script.saved;

            let opened = open_choice(&enumerator, &headset(), Direction::Input)
                .unwrap_or_else(|error| panic!("state {state:#x}: {error}"));

            assert_eq!(
                opened.as_ptr(),
                script.route.as_ptr(),
                "state {state:#x}: the saved endpoint was opened although it cannot carry audio"
            );
            assert_eq!(saved.script().asked.load(Ordering::SeqCst), 1);
            assert_eq!(
                saved.refs(),
                1,
                "state {state:#x}: the endpoint passed over was not given back"
            );
            drop(opened);
            drop(enumerator);
            assert_eq!(script.route.refs(), 1);
            assert_eq!(machine.refs(), 1);
        }
    }

    #[test]
    fn a_preference_that_can_play_is_the_one_opened() {
        let machine = machine(endpoint(DEVICE_STATE_ACTIVE, 0));
        let enumerator = machine.com();
        let script = machine.script();
        let saved = &script.saved;

        let opened = open_choice(&enumerator, &headset(), Direction::Output).expect("the headset");

        assert_eq!(opened.as_ptr(), saved.as_ptr());
        assert_eq!(saved.script().asked.load(Ordering::SeqCst), 1);
        assert_eq!(
            script.routes_asked.load(Ordering::SeqCst),
            0,
            "a live preference does not look at the route at all"
        );
        drop(opened);
        assert_eq!(saved.refs(), 1);
    }

    #[test]
    fn a_preference_that_will_not_say_its_state_is_not_hidden_behind_the_route() {
        let machine = machine(endpoint(DEVICE_STATE_UNPLUGGED, E_POINTER));
        let enumerator = machine.com();
        let script = machine.script();

        let outcome = open_choice(&enumerator, &headset(), Direction::Input);

        assert_eq!(
            outcome.err(),
            Some(Error::Call {
                call: "IMMDevice::GetState",
                status: HResult::new(E_POINTER),
            })
        );
        assert_eq!(script.routes_asked.load(Ordering::SeqCst), 0);
        assert_eq!(
            script.saved.refs(),
            1,
            "the endpoint was not given back on the way out of a refusal"
        );
    }

    #[test]
    fn enumeration_either_answers_or_says_why() {
        match devices() {
            Ok(list) => {
                for device in &list {
                    // an endpoint with no identifier could not be opened
                    // again, and enumerating one would be offering a choice
                    // that cannot be taken
                    assert!(!device.id.is_empty(), "{device} has no identifier");
                }
            }
            Err(error) => {
                // a machine with no audio service running is a legitimate
                // answer; a code without the name of the call on it is not
                let text = error.to_string();
                assert!(
                    text.contains("IMMDevice") || text.contains("CoCreateInstance"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn a_default_endpoint_is_one_of_the_endpoints() {
        let Ok(list) = devices() else {
            return;
        };
        for direction in [Direction::Input, Direction::Output] {
            if let Ok(Some(id)) = default_device(direction) {
                assert!(
                    list.iter()
                        .any(|device| device.direction == direction && device.id == id),
                    "the default {direction} endpoint is not in the list"
                );
                // and the list says so about exactly that one
                assert!(
                    list.iter()
                        .any(|device| device.direction == direction && device.is_default)
                );
            }
        }
    }

    #[test]
    fn a_monitor_starts_with_nothing_to_report() {
        let Ok(monitor) = DeviceMonitor::new() else {
            return;
        };
        assert_eq!(monitor.poll(), None);
    }

    #[test]
    fn closing_a_monitor_leaves_the_destructor_nothing_to_do() {
        let Ok(mut monitor) = DeviceMonitor::new() else {
            return;
        };
        assert_eq!(monitor.teardown(), Ok(()));
        assert!(monitor.notify.is_null(), "the reference was given back");
        assert!(!monitor.registered);
        // what the destructor does after `close` consumed the monitor: it must
        // not unregister twice, and it must not release twice
        assert_eq!(monitor.teardown(), Ok(()));
        assert_eq!(monitor.poll(), None);
    }

    #[test]
    fn a_monitor_that_cannot_drain_never_frees_the_client() {
        let Ok(mut monitor) = DeviceMonitor::new() else {
            return;
        };
        // stand in for a notification that is inside and does not come out
        // SAFETY: the monitor holds a reference, so the object is alive.
        let watch = unsafe { &*monitor.notify };
        let inside = watch.gate.enter().expect("the gate is open");

        let outcome = monitor.shut_down(Duration::from_millis(20), 20);

        assert_eq!(outcome, Err(Error::Draining { waited_millis: 20 }));
        // the pointer is gone without the reference having been given back,
        // which is the deliberate leak: a notification thread reading a freed
        // object is a crash in the middle of somebody's call
        assert!(monitor.notify.is_null());
        // the unregistration still happened, which is what stops another
        // notification arriving
        assert!(!monitor.registered);
        drop(inside);
    }

    #[test]
    #[ignore = "reports what this particular machine has"]
    fn what_this_machine_has() {
        let list = devices().unwrap();
        for device in &list {
            println!("{device}  {}", device.id);
        }
        println!("default input:  {:?}", default_device(Direction::Input));
        println!("default output: {:?}", default_device(Direction::Output));
        assert!(!list.is_empty(), "a Windows machine with no audio at all");
    }
}
