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
    AGGREGATE_PRIVATE_KEY, ENCODING_UTF8, NUMBER_SINT32, PROPERTY_AGGREGATE_COMPOSITION,
    PROPERTY_BUFFER_FRAME_SIZE, PROPERTY_DEFAULT_INPUT, PROPERTY_DEFAULT_OUTPUT,
    PROPERTY_DEVICE_IS_ALIVE, PROPERTY_DEVICES, PROPERTY_LATENCY, PROPERTY_NAME,
    PROPERTY_NOMINAL_SAMPLE_RATE, PROPERTY_REFERENCE_STREAM_ENABLED, PROPERTY_SAFETY_OFFSET,
    PROPERTY_STREAM_CONFIGURATION, PROPERTY_STREAM_LATENCY, PROPERTY_STREAMS,
    PROPERTY_TRANSPORT_TYPE, PROPERTY_UID, PropertyAddress, SCOPE_GLOBAL, SCOPE_INPUT,
    SCOPE_OUTPUT, SYSTEM_OBJECT, TRANSPORT_AGGREGATE,
};
use crate::abi::{BAD_PROPERTY_SIZE, BUFFERS_AT, Buffer};
use crate::device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Pending};
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
use crate::latency::{Latency, RenderDelay};
use crate::status::{Error, OsStatus};
use crate::sys;

/// Every device the machine has, at this instant.
///
/// The answer is a snapshot and it goes stale — that is what
/// [`DeviceMonitor`] is for, and why a device is named by
/// [`DeviceId`] rather than by an index into this list.
///
/// It is the machine's devices as a person would pick from them, whether or
/// not a voice-processing unit is open in this process. Such a unit makes a
/// private aggregate device, visible to this process alone, which is left
/// out; and it has the output devices hand what they play back in as an
/// extra input stream, the reference its echo canceller listens for, which
/// is not counted among a device's inputs — the loudspeaker does not become
/// a microphone because a call is up.
///
/// # Errors
/// [`Error::Call`] when the hardware layer refuses to answer, which on a
/// healthy machine it does not.
pub fn devices() -> Result<Vec<Device>, Error> {
    let address = PropertyAddress::new(PROPERTY_DEVICES, SCOPE_GLOBAL);
    let bytes = property_size(SYSTEM_OBJECT, &address)?;
    let mut ids = identifiers(bytes);
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
    Ok(ids.iter().copied().map(facts).filter_map(listed).collect())
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

/// What a device says one direction of it costs, part by part.
///
/// Never fails, and that is deliberate. Every part is separately optional in
/// the hardware layer — a virtual device implements the properties its author
/// thought of — so a refusal here would mean a caller with three quarters of a
/// delay was handed nothing at all. What the device did not answer for comes
/// back as [`None`] and [`Latency::is_complete`] says so.
///
/// The stream half is asked of the first stream on that side, which is the one
/// carrying channel one, and this crate is mono. A device with several streams
/// a side answers for each of them separately; the first is the one these
/// samples travel on, so it is the one that counts.
#[must_use]
pub fn latency(device: DeviceId, direction: Direction) -> Latency {
    let object = device.get();
    let scope = match direction {
        Direction::Input => SCOPE_INPUT,
        Direction::Output => SCOPE_OUTPUT,
    };
    Latency {
        device_frames: frames(object, PROPERTY_LATENCY, scope),
        stream_frames: first_stream(object, scope)
            .and_then(|stream| frames(stream, PROPERTY_STREAM_LATENCY, SCOPE_GLOBAL)),
        safety_offset_frames: frames(object, PROPERTY_SAFETY_OFFSET, scope),
        // the IO buffer is the device's rather than one direction's, so it is
        // asked for globally and counted once on each side of the loop
        buffer_frames: frames(object, PROPERTY_BUFFER_FRAME_SIZE, SCOPE_GLOBAL),
        sample_rate_hz: nominal_rate(object),
    }
}

/// The whole loop: out of `playback` and back in through `capture`.
///
/// Two devices rather than one, because on a Mac they usually are: the
/// built-in microphone and the built-in speakers are two device objects, and
/// so are the built-in microphone and a pair of headphones, each with its own
/// rate and buffer size. A duplex device, such as a USB headset, is passed
/// twice. [`Stream::render_delay`] is this, for the two objects the unit
/// reports it is on.
///
/// [`Stream::render_delay`]: crate::Stream::render_delay
#[must_use]
pub fn render_delay(playback: DeviceId, capture: DeviceId) -> RenderDelay {
    RenderDelay {
        playback: latency(playback, Direction::Output),
        capture: latency(capture, Direction::Input),
    }
}

/// A count of frames a device or a stream keeps, or nothing where it does not
/// keep that one.
fn frames(object: u32, selector: u32, scope: u32) -> Option<u32> {
    let address = PropertyAddress::new(selector, scope);
    property_value::<u32>(object, &address, "AudioObjectGetPropertyData (frames)").ok()
}

/// The rate the device says it is running at, in whole hertz.
///
/// The property is a `Float64` because the hardware layer describes rates as
/// ranges, not because a device runs at half a hertz.
fn nominal_rate(device: u32) -> Option<u32> {
    let address = PropertyAddress::new(PROPERTY_NOMINAL_SAMPLE_RATE, SCOPE_GLOBAL);
    let hertz: f64 = property_value(
        device,
        &address,
        "AudioObjectGetPropertyData (NominalSampleRate)",
    )
    .ok()?;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the cast saturates and turns anything that is not a number into zero, and zero is refused on the line after it"
    )]
    let rounded = hertz.round() as u32;
    (rounded > 0).then_some(rounded)
}

/// The first stream on one side of a device.
fn first_stream(device: u32, scope: u32) -> Option<u32> {
    let address = PropertyAddress::new(PROPERTY_STREAMS, scope);
    let bytes = property_size(device, &address).ok()?;
    if bytes < size_of::<u32>() {
        // a device with nothing on this side, which is most of them
        return None;
    }
    let mut ids = identifiers(bytes);
    let mut size = u32::try_from(bytes).unwrap_or(0);
    // SAFETY: the buffer holds at least `size` octets, which is the most the
    // call will write.
    let status = unsafe {
        sys::object_property_data(
            device,
            ptr::from_ref(&address),
            0,
            ptr::null(),
            &raw mut size,
            ids.as_mut_ptr().cast::<c_void>(),
        )
    };
    if status != 0 || usize::try_from(size).unwrap_or(0) < size_of::<u32>() {
        return None;
    }
    ids.first().copied()
}

/// Room for a property that is a list of object identifiers `bytes` long.
///
/// Rounded up, never down: the size handed to the call alongside this buffer
/// is what the layer is allowed to write, so the allocation has to cover it
/// even when a driver reports a size that is not a whole number of
/// identifiers. What such a size means is not this function's to guess; the
/// callers read only the whole identifiers that came back.
fn identifiers(bytes: usize) -> Vec<u32> {
    vec![0; bytes.div_ceil(size_of::<u32>())]
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

/// What the hardware layer says about one device, before anything is made
/// of it: what [`listed`] decides from, so that the decision can be tested on
/// a listing no machine has to produce.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Facts {
    id: u32,
    name: String,
    uid: Option<String>,
    /// An aggregate device only this process can see.
    private_aggregate: bool,
    /// Whether the device is handing what it plays back in as an input
    /// stream of its own, the reference an echo canceller listens for.
    reference: bool,
    /// Channels per input stream, in the order the device lists them.
    input: Vec<u32>,
    /// The same for output.
    output: Vec<u32>,
}

/// Ask the hardware layer about `id`.
fn facts(id: u32) -> Facts {
    let transport = property_value::<u32>(
        id,
        &PropertyAddress::new(PROPERTY_TRANSPORT_TYPE, SCOPE_GLOBAL),
        "AudioObjectGetPropertyData (TransportType)",
    );
    let reference = property_value::<u32>(
        id,
        &PropertyAddress::new(PROPERTY_REFERENCE_STREAM_ENABLED, SCOPE_OUTPUT),
        "AudioObjectGetPropertyData (ReferenceStreamEnabled)",
    );
    Facts {
        id,
        // a device that will not say what it is called is still a device
        name: text(id, PROPERTY_NAME).unwrap_or_default(),
        uid: text(id, PROPERTY_UID).ok().filter(|uid| !uid.is_empty()),
        private_aggregate: transport == Ok(TRANSPORT_AGGREGATE) && is_private(id),
        reference: reference.is_ok_and(|enabled| enabled != 0),
        input: buffers(id, SCOPE_INPUT),
        output: buffers(id, SCOPE_OUTPUT),
    }
}

/// The device a person picks from, or `None` for one that is not theirs to
/// pick: the private aggregate a voice-processing unit makes. A device whose
/// reference stream is on counts its inputs without it — the stream is
/// appended after the device's own, and is the last one listed — so a
/// loudspeaker shows no microphone and a duplex device shows the one it has.
fn listed(facts: Facts) -> Option<Device> {
    if facts.private_aggregate {
        return None;
    }
    let inputs = match facts.input.split_last() {
        Some((_, own)) if facts.reference => own,
        _ => facts.input.as_slice(),
    };
    let total = |channels: &[u32]| {
        channels
            .iter()
            .fold(0_u32, |sum, count| sum.saturating_add(*count))
    };
    Some(Device {
        id: DeviceId::new(facts.id),
        name: facts.name,
        uid: facts.uid,
        input_channels: total(inputs),
        output_channels: total(&facts.output),
    })
}

/// Whether an aggregate device says it is private: its composition's
/// [`AGGREGATE_PRIVATE_KEY`] entry, a number or a boolean, non-zero. An
/// aggregate that will not say is a person's, and listed.
fn is_private(id: u32) -> bool {
    let address = PropertyAddress::new(PROPERTY_AGGREGATE_COMPOSITION, SCOPE_GLOBAL);
    let Ok(composition) = property_value::<sys::StringRef>(
        id,
        &address,
        "AudioObjectGetPropertyData (AggregateComposition)",
    ) else {
        return false;
    };
    if composition.is_null() {
        return false;
    }
    let length = isize::try_from(AGGREGATE_PRIVATE_KEY.len()).unwrap_or(0);
    // SAFETY: the bytes are a live constant of that length; a null
    // allocator is the default one.
    let key = unsafe {
        sys::string_from_bytes(
            ptr::null(),
            AGGREGATE_PRIVATE_KEY.as_ptr(),
            length,
            ENCODING_UTF8,
            0,
        )
    };
    let private = !key.is_null() && {
        // SAFETY: both are live Core Foundation objects; what comes back is
        // borrowed from the dictionary, which is released only below.
        let value = unsafe { sys::dictionary_value(composition, key) };
        // SAFETY: as above.
        unsafe { flag(value) }
    };
    if !key.is_null() {
        // SAFETY: created above and released once.
        unsafe { sys::release(key) };
    }
    // SAFETY: the property handed it over, and it is released once.
    unsafe { sys::release(composition) };
    private
}

/// A Core Foundation number or boolean read as a flag; anything else, or
/// nothing, is `false`.
///
/// # Safety
/// `value` is null or a live Core Foundation object.
unsafe fn flag(value: *const c_void) -> bool {
    if value.is_null() {
        return false;
    }
    // SAFETY: the caller's live object.
    let kind = unsafe { sys::type_of(value) };
    // SAFETY: no arguments, nothing read.
    if kind == unsafe { sys::boolean_type() } {
        // SAFETY: a live boolean, as its type says.
        return unsafe { sys::boolean_value(value) } != 0;
    }
    // SAFETY: as above.
    if kind == unsafe { sys::number_type() } {
        let mut number: i32 = 0;
        // SAFETY: a live number, and the out-parameter is the type asked for.
        let read =
            unsafe { sys::number_value(value, NUMBER_SINT32, (&raw mut number).cast::<c_void>()) };
        return read != 0 && number != 0;
    }
    false
}

/// How many channels each stream on one side of a device has, in the order
/// the device lists them. Empty for a side it does not have, which is how an
/// input-only device is told from an output-only one.
fn buffers(object: u32, scope: u32) -> Vec<u32> {
    let address = PropertyAddress::new(PROPERTY_STREAM_CONFIGURATION, scope);
    let Ok(words) = property_words(object, &address) else {
        return Vec::new();
    };
    let bytes = words.len() * size_of::<u64>();
    if bytes < size_of::<u32>() {
        return Vec::new();
    }
    // held as words, so the storage is eight-aligned and every offset the
    // list uses lands where the framework put it
    let base = words.as_ptr();
    // SAFETY: the allocation is `bytes` long, so the count at its head is
    // there, and eight-aligned storage is aligned for a `u32`.
    let count = usize::try_from(unsafe { ptr::read(base.cast::<u32>()) }).unwrap_or(0);

    let mut channels = Vec::new();
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
        channels.push(buffer.channels);
    }
    channels
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
    use super::{
        DeviceMonitor, choose, default_device, device_with_uid, devices, identifiers, is_alive,
        latency, render_delay,
    };
    use crate::device::{DeviceChoice, DeviceId, Direction};
    use crate::latency::Latency;
    use crate::status::Error;
    use core::time::Duration;
    use std::sync::Arc;

    /// What the facade refuses to look back by, spelled out here because a
    /// device crate does not depend on the facade. A delay above this is not a
    /// long echo path, it is a number that came out wrong.
    const REFUSED_ABOVE: Duration = Duration::from_millis(500);

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
    fn the_delay_of_the_machines_own_devices_is_one_a_call_could_look_back_by() {
        let (Ok(Some(speaker)), Ok(Some(microphone))) = (
            default_device(Direction::Output),
            default_device(Direction::Input),
        ) else {
            // no audio hardware, or a Mac whose microphone the user has turned
            // off: nothing to ask, and nothing wrong
            return;
        };
        let delay = render_delay(speaker, microphone);
        println!("{delay}");

        // Every part is a `u32` of frames, so below zero cannot arise; what
        // can is a device answering something absurd, and the facade would
        // refuse to hold that much history rather than believe it.
        assert!(
            delay.total() < REFUSED_ABOVE,
            "a delay of {:?} is not a room, it is a wrong answer",
            delay.total()
        );
        for (side, leg) in [("playback", delay.playback), ("capture", delay.capture)] {
            if let Some(rate) = leg.sample_rate_hz {
                assert!(rate >= 8_000, "{side} claims to run at {rate} Hz");
                assert!(
                    leg.duration() * 2 < Duration::from_secs(1),
                    "{side} alone is {:?}",
                    leg.duration()
                );
            } else {
                assert_eq!(
                    leg.duration(),
                    Duration::ZERO,
                    "{side} gave a time without a rate to measure it in"
                );
            }
        }
    }

    #[test]
    fn a_device_the_machine_does_not_have_answers_nothing_rather_than_zero() {
        // no machine has handed this number out, so every property read
        // refuses; what must not happen is a refusal arriving as a delay
        let nothing = latency(DeviceId::new(u32::MAX), Direction::Output);
        assert_eq!(nothing, Latency::default());
        assert!(!nothing.is_complete());
        assert_eq!(nothing.frames(), 0);
        assert_eq!(nothing.duration(), Duration::ZERO);
        assert_eq!(
            render_delay(DeviceId::new(u32::MAX), DeviceId::new(u32::MAX)).total(),
            Duration::ZERO
        );
    }

    #[test]
    fn every_device_the_machine_has_answers_for_the_side_it_carries() {
        let Ok(list) = devices() else {
            return;
        };
        for device in &list {
            for direction in [Direction::Input, Direction::Output] {
                let leg = latency(device.id, direction);
                let carries = match direction {
                    Direction::Input => device.is_input(),
                    Direction::Output => device.is_output(),
                };
                if carries {
                    // A device with channels on this side has a stream on it,
                    // and the buffer size and the rate belong to the device
                    // rather than to a direction, so those three are answered
                    // by anything the hardware layer enumerated.
                    assert!(
                        leg.stream_frames.is_some(),
                        "{device} has {direction} channels and no {direction} stream"
                    );
                    assert!(leg.buffer_frames.is_some(), "{device} has no IO buffer");
                    assert!(leg.sample_rate_hz.is_some(), "{device} runs at no rate");
                }
                println!("{device} {direction}: {leg}");
            }
        }
    }

    #[test]
    fn a_ragged_property_size_is_given_room_for_all_of_it() {
        // A driver may report any size at all, and whatever it reports is
        // what the layer is then allowed to write into the room made for it.
        for bytes in 0..=64 {
            let room = identifiers(bytes).len() * size_of::<u32>();
            assert!(room >= bytes, "{bytes} octets were given {room}");
            assert!(
                room < bytes + size_of::<u32>(),
                "{bytes} octets were given {room}, a whole identifier more than needed"
            );
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

    /// A machine as the hardware layer described it on a laptop with a
    /// voice-processing unit running: the speaker on a virtual loopback
    /// device, the microphone the built-in one. Each output device hands its
    /// output back in as one more input stream, and the unit's own private
    /// aggregate sits in the list beside them.
    fn during_a_call() -> Vec<super::Facts> {
        let device = |id, name: &str, reference, input: &[u32], output: &[u32]| super::Facts {
            id,
            name: name.to_owned(),
            uid: Some(format!("uid-{id}")),
            private_aggregate: false,
            reference,
            input: input.to_vec(),
            output: output.to_vec(),
        };
        vec![
            device(81, "BlackHole 2ch", true, &[2, 2], &[2]),
            device(123, "MacBook Air Microphone", false, &[3], &[]),
            device(116, "MacBook Air Speakers", true, &[6], &[2]),
            device(159, "a headset's output half", true, &[2], &[2]),
            device(164, "a headset's input half", false, &[2], &[]),
            device(300, "an aggregate a person made", false, &[2], &[2]),
            super::Facts {
                private_aggregate: true,
                ..device(216, "VPAUAggregateAudioDevice-0x1", false, &[3, 2, 2], &[2])
            },
        ]
    }

    #[test]
    fn a_call_in_progress_neither_adds_a_device_nor_turns_a_speaker_into_a_microphone() {
        let listed: Vec<_> = during_a_call()
            .into_iter()
            .filter_map(super::listed)
            .map(|device| (device.name, device.input_channels, device.output_channels))
            .collect();
        assert_eq!(
            listed,
            [
                ("BlackHole 2ch".to_owned(), 2, 2),
                ("MacBook Air Microphone".to_owned(), 3, 0),
                ("MacBook Air Speakers".to_owned(), 0, 2),
                ("a headset's output half".to_owned(), 0, 2),
                ("a headset's input half".to_owned(), 2, 0),
                ("an aggregate a person made".to_owned(), 2, 2),
            ]
        );
    }

    #[test]
    fn without_a_reference_stream_every_input_is_the_devices_own() {
        let facts = super::Facts {
            id: 7,
            name: "a duplex headset".to_owned(),
            input: vec![1, 1],
            output: vec![2],
            ..super::Facts::default()
        };
        let device = super::listed(facts).expect("listed");
        assert_eq!((device.input_channels, device.output_channels), (2, 2));
    }

    /// The same on this machine: with a voice unit running on the quiet
    /// route, the list has no device it did not have before, no device
    /// that had no input before has one now, and every output is what it
    /// was. A microphone the unit switches into its own mode may report
    /// more channels while it is in it; that is the device's own answer.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "opens the real devices"]
    fn a_running_voice_unit_leaves_the_device_list_as_it_was() {
        use crate::{Stream, StreamConfig, StreamFormat};
        use std::collections::HashMap;

        let before: HashMap<_, _> = devices()
            .expect("the list")
            .into_iter()
            .map(|device| (device.id, device))
            .collect();
        let (route, _) = crate::quiet::route().expect("the device list");
        let format = StreamFormat::with_frame_millis(48_000, 20).expect("a twenty ms frame");
        let mut stream = Stream::open(StreamConfig {
            device: route,
            ..StreamConfig::new(format)
        })
        .expect("open");
        stream.start().expect("start");
        std::thread::sleep(Duration::from_millis(300));
        let during = devices().expect("the list");
        stream.close().expect("close");

        for device in &during {
            println!(
                "{device} in {} out {}",
                device.input_channels, device.output_channels
            );
            let was = before
                .get(&device.id)
                .unwrap_or_else(|| panic!("{device} was not there before the call"));
            assert_eq!(device.output_channels, was.output_channels, "{device}");
            assert_eq!(device.is_input(), was.is_input(), "{device}");
        }
        assert_eq!(during.len(), before.len());
    }
}
