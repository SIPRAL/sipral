// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Asking the machine what audio hardware it has, and being told when that
//! changes.
//!
//! macOS only. iOS answers the same questions through `AVAudioSession`, which
//! is Objective-C and is the application's to configure — its category and its
//! interruption policy depend on what the application is, not on what this
//! crate does with the samples. The voice-processing unit behaves correctly
//! once the session is set, which is why the stream side needs none of this.

use core::ffi::{c_char, c_void};
use core::time::Duration;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;

use crate::abi::hardware::{
    ENCODING_UTF8, PROPERTY_DEFAULT_INPUT, PROPERTY_DEFAULT_OUTPUT, PROPERTY_DEVICE_IS_ALIVE,
    PROPERTY_DEVICES, PROPERTY_NAME, PROPERTY_STREAM_CONFIGURATION, PROPERTY_UID, PropertyAddress,
    SCOPE_GLOBAL, SCOPE_INPUT, SCOPE_OUTPUT, SYSTEM_OBJECT,
};
use crate::abi::{BAD_PROPERTY_SIZE, Buffer, BufferList};
use crate::device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Pending};
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
use crate::status::{Error, OsStatus};
use crate::sys;

/// Where the buffers begin inside an `AudioBufferList`: after the count and
/// the padding the pointer alignment forces. A list the framework allocated is
/// longer than the declared structure, so it is walked by offset.
const BUFFERS_AT: usize = core::mem::offset_of!(BufferList, buffers);

/// Every device the machine has, at this instant.
///
/// The answer is a snapshot and it goes stale — that is what
/// [`DeviceMonitor`] is for, and why a device is named by
/// [`DeviceId`] rather than by an index into this list.
///
/// # Errors
/// [`Error::Call`] when the hardware layer refuses to answer, which on a
/// healthy machine it does not.
pub fn devices() -> Result<Vec<Device>, Error> {
    let address = PropertyAddress::new(PROPERTY_DEVICES, SCOPE_GLOBAL);
    let bytes = property_size(SYSTEM_OBJECT, &address)?;
    // rounded up, never down: the size handed over below is what the layer is
    // allowed to write, so the allocation has to cover it even if the property
    // is somehow not a whole number of identifiers
    let mut ids: Vec<u32> = vec![0; bytes.div_ceil(size_of::<u32>())];
    let mut size = u32::try_from(bytes).unwrap_or(0);
    // SAFETY: the buffer holds at least `size` octets, which is the most the
    // call will write.
    let status = unsafe {
        sys::object_property_data(
            SYSTEM_OBJECT,
            &raw const address,
            0,
            ptr::null(),
            &raw mut size,
            ids.as_mut_ptr().cast::<c_void>(),
        )
    };
    sys::check("AudioObjectGetPropertyData (Devices)", status)?;

    // what came back, not what was asked for: the list can shrink between the
    // two calls, which on a Mac means a device was unplugged just then
    let found = usize::try_from(size).unwrap_or(0) / size_of::<u32>();
    let Some(ids) = ids.get(..found.min(ids.len())) else {
        return Ok(Vec::new());
    };
    Ok(ids.iter().copied().map(describe).collect())
}

/// What the system is routing a direction to right now, or `None` when it is
/// routing nothing that way — a Mac whose microphone the user has turned off,
/// or one with no speaker attached.
///
/// # Errors
/// [`Error::Call`] when the hardware layer refuses to answer.
pub fn default_device(direction: Direction) -> Result<Option<DeviceId>, Error> {
    let selector = match direction {
        Direction::Input => PROPERTY_DEFAULT_INPUT,
        Direction::Output => PROPERTY_DEFAULT_OUTPUT,
    };
    let address = PropertyAddress::new(selector, SCOPE_GLOBAL);
    let id: u32 = property_value(
        SYSTEM_OBJECT,
        &address,
        "AudioObjectGetPropertyData (DefaultDevice)",
    )?;
    // kAudioObjectUnknown, which is what the layer says for "nothing"
    Ok((id != 0).then(|| DeviceId::new(id)))
}

/// The device carrying a saved identity, if the machine has it right now.
///
/// The identity to save is [`Device::uid`], not [`Device::id`]: the number is
/// handed back out to whatever is plugged in next, and a preference stored as
/// one would eventually name somebody else's headset.
///
/// # Errors
/// [`Error::Call`] when the hardware layer refuses to enumerate.
pub fn device_with_uid(uid: &str) -> Result<Option<Device>, Error> {
    Ok(devices()?
        .into_iter()
        .find(|device| device.uid.as_deref() == Some(uid)))
}

/// Whether the hardware layer still has this device.
///
/// A device object outlives the hardware behind it for a moment, which is what
/// makes the question answerable at all: an object that has gone entirely
/// refuses to answer, and that is the same answer.
#[must_use]
pub fn is_alive(device: DeviceId) -> bool {
    let address = PropertyAddress::new(PROPERTY_DEVICE_IS_ALIVE, SCOPE_GLOBAL);
    property_value::<u32>(
        device.get(),
        &address,
        "AudioObjectGetPropertyData (DeviceIsAlive)",
    )
    .is_ok_and(|alive| alive != 0)
}

/// The device a choice names, or `None` for the system route.
///
/// A preference the machine does not have is not an error. That is the whole
/// point of one: the headset is in a bag, the call still has to happen.
pub(crate) fn choose(choice: &DeviceChoice) -> Result<Option<DeviceId>, Error> {
    match *choice {
        DeviceChoice::System => Ok(None),
        DeviceChoice::Device(id) => Ok(Some(id)),
        DeviceChoice::Preferred(ref uid) => Ok(device_with_uid(uid)?.map(|device| device.id)),
    }
}

/// What the listener is handed a pointer to: the changes it records, behind
/// the gate that says when it is no longer looking at them.
struct Watch {
    gate: Gate,
    pending: Pending,
}

/// Watches the machine's audio hardware and remembers what changed.
///
/// A headset arriving or leaving is not an error and does not interrupt a
/// stream that is running on another device; it is a fact the caller may want
/// to act on, so it waits here until asked for. Dropping the monitor stops the
/// watching.
pub struct DeviceMonitor {
    watch: Arc<Watch>,
    /// The listeners that are installed right now, which is the state rather
    /// than a flag describing it. Teardown empties it as it removes them, so
    /// a second teardown — the one the destructor runs after
    /// [`DeviceMonitor::close`] — has nothing to remove and cannot ask the
    /// framework to remove anything twice.
    installed: Vec<PropertyAddress>,
    /// Set when removal could not be shown to have taken effect. Nothing is
    /// then freed.
    leak: bool,
}

impl DeviceMonitor {
    /// Start watching the device list and both default devices.
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioObjectAddPropertyListener`. Any listener
    /// already installed when one fails is removed again, so a failed monitor
    /// leaves nothing behind.
    pub fn new() -> Result<Self, Error> {
        let watch = Arc::new(Watch {
            gate: Gate::new(),
            pending: Pending::new(),
        });
        let context = Arc::as_ptr(&watch).cast::<c_void>().cast_mut();
        let wanted = [
            PropertyAddress::new(PROPERTY_DEVICES, SCOPE_GLOBAL),
            PropertyAddress::new(PROPERTY_DEFAULT_INPUT, SCOPE_GLOBAL),
            PropertyAddress::new(PROPERTY_DEFAULT_OUTPUT, SCOPE_GLOBAL),
        ];
        let mut monitor = Self {
            watch,
            installed: Vec::with_capacity(wanted.len()),
            leak: false,
        };

        for address in wanted {
            // SAFETY: the address is a live local and the context points into
            // the `Arc` the monitor above is holding.
            let status = unsafe {
                sys::add_property_listener(SYSTEM_OBJECT, ptr::from_ref(&address), changed, context)
            };
            if let Err(error) = sys::check("AudioObjectAddPropertyListener", status) {
                // the ones already installed come out through the same
                // sequence as any other teardown, rather than a second one
                // written out here
                let _ = monitor.teardown();
                return Err(error);
            }
            monitor.installed.push(address);
        }

        Ok(monitor)
    }

    /// Take one change, or `None` when nothing has happened since the last
    /// time. Several changes of the same kind arrive as one.
    #[must_use]
    pub fn poll(&self) -> Option<DeviceEvent> {
        self.watch.pending.take()
    }

    /// Stop watching, and say what the framework made of it.
    ///
    /// Dropping a monitor does the same and has nowhere to report to.
    ///
    /// # Errors
    /// [`Error::Draining`] when a listener could not be shown to have left,
    /// in which case what it was reading is never freed; otherwise
    /// [`Error::Call`] from the first `AudioObjectRemovePropertyListener` to
    /// complain, all three having been attempted.
    pub fn close(mut self) -> Result<(), Error> {
        self.teardown()
    }

    /// Same argument as the stream's, one step shorter because there is no
    /// separate call that stops new listeners arriving: shutting the gate is
    /// what turns a listener already on its way around, removal is what stops
    /// further ones, and the drain is what says the ones in flight are out.
    fn teardown(&mut self) -> Result<(), Error> {
        self.shut_down(TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS)
    }

    /// The same with the wait spelled out, so a test can ask for a deadline it
    /// is willing to sit through.
    fn shut_down(&mut self, within: Duration, millis: u64) -> Result<(), Error> {
        if self.installed.is_empty() {
            // nothing is installed, so there is nothing to remove and nothing
            // to wait for: this is the destructor arriving after `close`
            return Ok(());
        }
        let context = Arc::as_ptr(&self.watch).cast::<c_void>().cast_mut();
        self.watch.gate.close();

        let mut first = 0;
        for address in self.installed.drain(..) {
            // SAFETY: removing exactly the listeners installed in `new`, with
            // the same address, function and context.
            let status = unsafe {
                sys::remove_property_listener(
                    SYSTEM_OBJECT,
                    ptr::from_ref(&address),
                    changed,
                    context,
                )
            };
            if first == 0 {
                first = status;
            }
        }

        if !self.watch.gate.drained(within) {
            self.leak = true;
            return Err(Error::Draining {
                waited_millis: millis,
            });
        }
        sys::check("AudioObjectRemovePropertyListener", first)
    }
}

impl Drop for DeviceMonitor {
    fn drop(&mut self) {
        let _ = self.teardown();
        if self.leak {
            // a listener may still be inside; what it reads outlives us rather
            // than disappearing under it
            core::mem::forget(Arc::clone(&self.watch));
        }
    }
}

/// What the hardware layer calls when something it was asked about moved.
///
/// It arrives on a thread the framework owns, not a realtime one, but a panic
/// crossing back into C would still be undefined, so it is caught here and
/// there is nothing left that could raise one.
unsafe extern "C" fn changed(
    _object: u32,
    count: u32,
    addresses: *const PropertyAddress,
    context: *mut c_void,
) -> sys::Status {
    // SAFETY: the context is the pointer given to the framework in `new`, and
    // teardown does not free what is behind it until the gate below is empty.
    let Some(watch) = (unsafe { context.cast::<Watch>().as_ref() }) else {
        return 0;
    };
    // the monitor is going away and its pending set may be about to go with it
    let Some(_inside) = watch.gate.enter() else {
        return 0;
    };
    let pending = &watch.pending;
    if addresses.is_null() {
        return 0;
    }
    // SAFETY: the framework passes `count` addresses at that pointer.
    let changes =
        unsafe { core::slice::from_raw_parts(addresses, usize::try_from(count).unwrap_or(0)) };

    let noted = panic::catch_unwind(AssertUnwindSafe(|| {
        for change in changes {
            match change.selector {
                PROPERTY_DEVICES => pending.note(DeviceEvent::ListChanged),
                PROPERTY_DEFAULT_INPUT => {
                    pending.note(DeviceEvent::DefaultChanged(Direction::Input));
                }
                PROPERTY_DEFAULT_OUTPUT => {
                    pending.note(DeviceEvent::DefaultChanged(Direction::Output));
                }
                _ => {}
            }
        }
    }));
    // there is no counter on a monitor and nowhere to report to; what matters
    // is that the unwind stopped here
    drop(noted);
    0
}

fn describe(id: u32) -> Device {
    Device {
        id: DeviceId::new(id),
        // a device that will not say what it is called is still a device
        name: text(id, PROPERTY_NAME).unwrap_or_default(),
        uid: text(id, PROPERTY_UID).ok().filter(|uid| !uid.is_empty()),
        input_channels: channels(id, SCOPE_INPUT),
        output_channels: channels(id, SCOPE_OUTPUT),
    }
}

/// How many channels a device has on one side. Zero for a side it does not
/// have, which is how an input-only device is told from an output-only one.
fn channels(object: u32, scope: u32) -> u32 {
    let address = PropertyAddress::new(PROPERTY_STREAM_CONFIGURATION, scope);
    let Ok(words) = property_words(object, &address) else {
        return 0;
    };
    let bytes = words.len() * size_of::<u64>();
    if bytes < size_of::<u32>() {
        return 0;
    }
    // held as words, so the storage is eight-aligned and every offset the
    // list uses lands where the framework put it
    let base = words.as_ptr();
    // SAFETY: the allocation is `bytes` long, so the count at its head is
    // there, and eight-aligned storage is aligned for a `u32`.
    let count = usize::try_from(unsafe { ptr::read(base.cast::<u32>()) }).unwrap_or(0);

    let mut total: u32 = 0;
    for index in 0..count {
        let Some(offset) = index
            .checked_mul(size_of::<Buffer>())
            .and_then(|at| at.checked_add(BUFFERS_AT))
        else {
            break;
        };
        if offset.saturating_add(size_of::<Buffer>()) > bytes {
            // the count says more buffers than the layer actually wrote
            break;
        }
        // SAFETY: the offset and the whole buffer are inside the allocation,
        // which is aligned for `Buffer` because it is aligned for a pointer.
        let buffer = unsafe { ptr::read(base.byte_add(offset).cast::<Buffer>()) };
        total = total.saturating_add(buffer.channels);
    }
    total
}

/// A string property, converted out of Core Foundation and released.
fn text(object: u32, selector: u32) -> Result<String, Error> {
    let address = PropertyAddress::new(selector, SCOPE_GLOBAL);
    let handle: sys::StringRef =
        property_value(object, &address, "AudioObjectGetPropertyData (name)")?;
    if handle.is_null() {
        return Ok(String::new());
    }
    // SAFETY: a live string this side now owns, as the property calls hand it
    // over.
    let text = unsafe { to_utf8(handle) };
    // SAFETY: released exactly once, and nothing refers to it afterwards.
    unsafe { sys::release(handle) };
    Ok(text)
}

/// # Safety
/// `handle` is a live `CFStringRef`.
unsafe fn to_utf8(handle: sys::StringRef) -> String {
    // SAFETY: the caller's live string.
    let length = unsafe { sys::string_length(handle) };
    // SAFETY: as above; the call only reads the length it is given.
    let maximum = unsafe { sys::string_max_bytes(length, ENCODING_UTF8) };
    // room for the terminator the conversion writes
    let capacity = usize::try_from(maximum).unwrap_or(0).saturating_add(1);
    let mut bytes = vec![0u8; capacity];
    // SAFETY: the buffer is `capacity` octets and the length says so.
    let converted = unsafe {
        sys::string_to_bytes(
            handle,
            bytes.as_mut_ptr().cast::<c_char>(),
            isize::try_from(capacity).unwrap_or(0),
            ENCODING_UTF8,
        )
    };
    if converted == 0 {
        return String::new();
    }
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(0);
    bytes.truncate(end);
    String::from_utf8(bytes).unwrap_or_default()
}

/// The octets a property will take, which is how much to allocate for it.
fn property_size(object: u32, address: &PropertyAddress) -> Result<usize, Error> {
    let mut size: u32 = 0;
    // SAFETY: the address is a live local and `size` a live out-parameter.
    let status = unsafe {
        sys::object_property_size(
            object,
            ptr::from_ref(address),
            0,
            ptr::null(),
            &raw mut size,
        )
    };
    sys::check("AudioObjectGetPropertyDataSize", status)?;
    Ok(usize::try_from(size).unwrap_or(0))
}

/// A property of a size known in advance.
fn property_value<T: Copy>(
    object: u32,
    address: &PropertyAddress,
    call: &'static str,
) -> Result<T, Error> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let mut size = u32::try_from(size_of::<T>()).unwrap_or(0);
    // SAFETY: the buffer is exactly `size_of::<T>()` octets and aligned for T.
    let status = unsafe {
        sys::object_property_data(
            object,
            ptr::from_ref(address),
            0,
            ptr::null(),
            &raw mut size,
            value.as_mut_ptr().cast::<c_void>(),
        )
    };
    sys::check(call, status)?;
    if usize::try_from(size).unwrap_or(0) != size_of::<T>() {
        return Err(Error::Call {
            call,
            status: OsStatus::new(BAD_PROPERTY_SIZE),
        });
    }
    // SAFETY: the call reported writing exactly the size of T.
    Ok(unsafe { value.assume_init() })
}

/// A property whose size is only known once it has been asked for, held in
/// eight-aligned storage because what comes back is usually a structure.
fn property_words(object: u32, address: &PropertyAddress) -> Result<Vec<u64>, Error> {
    let bytes = property_size(object, address)?;
    let mut storage: Vec<u64> = vec![0; bytes.div_ceil(size_of::<u64>()).max(1)];
    let mut size = u32::try_from(bytes).unwrap_or(0);
    // SAFETY: the storage holds at least `bytes` octets.
    let status = unsafe {
        sys::object_property_data(
            object,
            ptr::from_ref(address),
            0,
            ptr::null(),
            &raw mut size,
            storage.as_mut_ptr().cast::<c_void>(),
        )
    };
    sys::check("AudioObjectGetPropertyData", status)?;
    Ok(storage)
}

#[cfg(test)]
mod tests {
    use super::{DeviceMonitor, choose, default_device, device_with_uid, devices, is_alive};
    use crate::device::{DeviceChoice, DeviceId, Direction};
    use crate::status::Error;
    use core::time::Duration;
    use std::sync::Arc;

    #[test]
    fn a_saved_identity_finds_the_device_it_was_saved_from() {
        let Ok(list) = devices() else {
            return;
        };
        let Some(saved) = list.iter().find_map(|device| device.uid.clone()) else {
            return;
        };
        let found = device_with_uid(&saved).expect("the enumeration answered a moment ago");
        assert_eq!(found.and_then(|device| device.uid), Some(saved));
        assert_eq!(
            device_with_uid("no device on any machine carries this").expect("as above"),
            None
        );
    }

    #[test]
    fn what_is_enumerated_is_alive_and_what_was_never_there_is_not() {
        let Ok(list) = devices() else {
            return;
        };
        for device in &list {
            assert!(is_alive(device.id), "{device} is in the list but not alive");
        }
        // kAudioObjectUnknown, and a number no machine has handed out
        assert!(!is_alive(DeviceId::new(0)));
        assert!(!is_alive(DeviceId::new(u32::MAX)));
    }

    #[test]
    fn a_preference_nothing_carries_falls_back_rather_than_failing() {
        assert_eq!(choose(&DeviceChoice::System), Ok(None));
        assert_eq!(
            choose(&DeviceChoice::Device(DeviceId::new(7))),
            Ok(Some(DeviceId::new(7)))
        );
        if devices().is_ok() {
            assert_eq!(
                choose(&DeviceChoice::Preferred("a headset in a bag".to_string())),
                Ok(None)
            );
        }
    }

    #[test]
    fn enumeration_either_answers_or_says_why() {
        match devices() {
            Ok(list) => {
                for device in &list {
                    // zero is what the layer calls "no object", so nothing it
                    // enumerated can carry it
                    assert_ne!(device.id.get(), 0);
                    assert!(device.uid.as_ref().is_none_or(|uid| !uid.is_empty()));
                }
            }
            Err(error) => {
                // a machine with no audio at all is a legitimate answer; a
                // status without the name of the call on it is not
                assert!(error.to_string().contains("AudioObject"));
            }
        }
    }

    #[test]
    fn a_default_device_is_one_of_the_devices() {
        let Ok(list) = devices() else {
            return;
        };
        for direction in [Direction::Input, Direction::Output] {
            if let Ok(Some(id)) = default_device(direction) {
                assert!(
                    list.iter().any(|device| device.id == id),
                    "the default {direction} device is not in the device list"
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
    fn each_listener_is_removed_once_however_many_times_teardown_is_asked() {
        let Ok(mut monitor) = DeviceMonitor::new() else {
            return;
        };
        assert_eq!(monitor.installed.len(), 3);

        assert_eq!(monitor.teardown(), Ok(()));
        // the removal loop walks `installed`, so an empty one is the proof
        // that a second pass asks the framework for nothing. Removing a
        // listener that is not there returns zero on this platform, so a
        // status could never have shown this.
        assert!(monitor.installed.is_empty());
        assert!(!monitor.leak);

        // what the destructor does after `close` consumed the monitor
        assert_eq!(monitor.teardown(), Ok(()));
        assert!(monitor.installed.is_empty());
    }

    #[test]
    fn closing_a_monitor_leaves_the_destructor_nothing_to_do() {
        let Ok(monitor) = DeviceMonitor::new() else {
            return;
        };
        // `close` consumes it, so the destructor runs on the way out of this
        // line: the double removal, if it were still there, would happen here
        assert_eq!(monitor.close(), Ok(()));
    }

    #[test]
    fn a_monitor_that_cannot_drain_leaks_rather_than_frees() {
        let Ok(mut monitor) = DeviceMonitor::new() else {
            return;
        };
        // stand in for a listener that is inside and does not come out
        let held = Arc::clone(&monitor.watch);
        let inside = held.gate.enter().expect("the gate is open");

        let outcome = monitor.shut_down(Duration::from_millis(20), 20);

        assert_eq!(outcome, Err(Error::Draining { waited_millis: 20 }));
        assert!(monitor.leak);
        // the listeners still came out, which is what stops another one
        // arriving; what did not happen is the free
        assert!(monitor.installed.is_empty());
        drop(inside);
    }

    #[test]
    #[ignore = "reports what this particular machine has"]
    fn what_this_machine_has() {
        let list = devices().unwrap();
        assert!(!list.is_empty(), "a Mac with no audio devices at all");
        for device in &list {
            println!("{device}");
        }
        println!("default input: {:?}", default_device(Direction::Input));
        println!("default output: {:?}", default_device(Direction::Output));
    }
}
