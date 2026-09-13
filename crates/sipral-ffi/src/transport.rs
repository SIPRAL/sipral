// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Signalling across the boundary: the bytes out, the bytes in, and the news
//! about the socket they travel on.
//!
//! Until this module existed the C ABI could describe a call, negotiate its
//! audio, record it and report what it cost — and it could not place one. The
//! stack wrote its REGISTER into a queue that `sipral_stack_poll` emptied into
//! nothing, and there was no way to hand back what arrived. Media I/O was ahead
//! of signalling I/O: the ABI could carry a call's audio and not its INVITE.
//!
//! No socket here either, for the same reason as everywhere else in this tree.
//! The application takes what the stack wants written
//! ([`sipral_stack_poll_transmit`]) and writes it; it reads a datagram and hands
//! it over ([`sipral_stack_receive_datagram`]) or a run of bytes off a
//! connection ([`sipral_stack_receive_stream`]); and it says when a transport
//! died ([`sipral_stack_transport_failed`]), when a connection closed
//! ([`sipral_stack_stream_closed`]) and when one is open again
//! ([`sipral_stack_transport_bind`]).
//!
//! # Placing a call, in the order it happens
//!
//! ```c
//! sipral_stack_create(&config, &stack);          /* bind_address names this end */
//! sipral_account_add(stack, &line, &account);
//! sipral_account_register(stack, account, now_ms());
//! for (;;) {
//!     sipral_stack_poll(stack, now_ms(), NULL);  /* events, and the timers */
//!     sipral_transmit_t out = { .size = sizeof out, .data = buf, .capacity = sizeof buf,
//!                               .destination = to, .destination_capacity = sizeof to };
//!     while (sipral_stack_poll_transmit(stack, &out) == SIPRAL_STATUS_OK && out.len)
//!         sendto(fd, buf, out.len, 0, sockaddr_of(to), socklen_of(to));
//!     ssize_t n = recvfrom(fd, in, sizeof in, 0, (struct sockaddr *) &from, &len);
//!     if (n > 0) sipral_stack_receive_datagram(stack, SIPRAL_TRANSPORT_MAIN, in, (size_t) n,
//!                                              print(&from), strlen(print(&from)), NULL, 0,
//!                                              now_ms());
//! }
//! ```
//!
//! `sipral_call_place` is the same shape one line further on, and the audio of
//! that call rides the four calls in [`crate::media`] on a socket of its own.
//! Nothing else has to be arranged: poll, drain, read, repeat.
//!
//! The order in that loop is the whole contract. A poll produces the messages
//! that go out — a retransmission, a refresh, a response the stack wrote for
//! itself — and handing bytes in produces them too, so both are followed by
//! draining. What is produced waits until it is taken: nothing here throws away
//! a message the stack has committed to, and a poll that happens in between
//! leaves the queue where it was.
//!
//! # One transport, named
//!
//! A stack is bound to exactly one transport, at creation, and its number is
//! [`SIPRAL_TRANSPORT_MAIN`]. Every call here names it anyway, and every other
//! number is `SIPRAL_STATUS_INVALID_ARGUMENT`.
//!
//! That is a decision rather than an omission. A second transport is not an I/O
//! question: an account carries the transport its REGISTER goes out on and a
//! call carries the one its INVITE does, so a stack with two of them has to be
//! told which account uses which — a member of `sipral_account_config_t`, and
//! one that belongs with the §18.1.1 promotion onto a stream that spends event
//! number 18. Until then the honest surface is one transport whose number is
//! written down, because widening it later means more numbers becoming valid
//! and not a second set of functions taking an argument the first set lacks.
//!
//! # A datagram, a stream, and a WebSocket
//!
//! A datagram carries exactly one message and says where it came from. Stream
//! bytes are a fragment of a framing the layer below reassembles on
//! `Content-Length` (§18.3), arrive in whatever sizes the reads happened to come
//! in, and carry no addresses at all: a connection has one far end and it was
//! named when the transport was bound.
//!
//! A WebSocket frame goes in as a datagram. RFC 7118 §4.2 puts exactly one SIP
//! message in each frame, so the framing is already done by the time the bytes
//! reach here and there is nothing for the reassembler to do.
//!
//! # When a transport dies
//!
//! Both [`sipral_stack_transport_failed`] and [`sipral_stack_stream_closed`]
//! retire the transport: every transaction waiting on it fails at once, the
//! calls and registrations behind them are reported on the next poll, and
//! nothing can be sent until [`sipral_stack_transport_bind`] brings a transport
//! back. That is why neither is the thing to call for one refused `sendto`. A
//! single ICMP unreachable is one destination saying no; a transport failure is
//! the socket saying it is over.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::ptr;
use std::slice;

use sipral_core::endpoint::{Input, ReceiveError, Transmit, TransportErrorKind, TransportId};

use crate::abi::{codes, constants, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{SIPRAL_ADDRESS_BYTES, address};
use crate::stack::{SipralTransport, StackState, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, read_versioned, write_versioned};

constants! {
    /// The transport a stack is created with, and the only one this build
    /// binds.
    ///
    /// Named rather than assumed, so that the day a stack has two of them is a
    /// day more numbers become valid and not a day this ABI grows a second way
    /// to hand bytes over.
    pub const SIPRAL_TRANSPORT_MAIN: u32 = 0;

    /// The largest message that crosses in either direction.
    ///
    /// The bound the layer below parses to, which is what stops a hostile peer
    /// from making the parser do unbounded work. A caller's read buffer wants
    /// to be this big on a stream, where one read can hold the end of one
    /// message and the start of another, and 1500 bytes or so on a datagram
    /// socket, where anything larger was fragmented on the way.
    pub const SIPRAL_MESSAGE_BYTES: usize = 65_535;
}

codes! {
    /// Why a transport could not deliver. Names for
    /// [`sipral_stack_transport_failed`]'s `error`.
    ///
    /// Coarse on purpose, and it is the layer below that is coarse: a client
    /// transaction informs its user and terminates on every one of these (§17), and
    /// the detail belongs in the caller's log, where the real message still is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTransportError: u32 {
        /// Anything the caller could not classify. Zero, because a caller that
        /// knows only that the write failed is telling the truth by saying nothing.
        Other = 0,
        /// Nothing is listening at the far end.
        ConnectionRefused = 1,
        /// An established connection was reset.
        ConnectionReset = 2,
        /// No route, or an ICMP unreachable.
        Unreachable = 3,
        /// The connection attempt or the write timed out.
        TimedOut = 4,
        /// The connection was closed and cannot be written to again.
        Closed = 5,
    }
}

record! {
    /// One message on its way out, written into the caller's own buffers.
    ///
    /// The caller fills in `size`, the three pointers and the three capacities; the
    /// library fills in everything else. A `len` of zero means the stack had nothing
    /// to send, which is how the draining loop ends.
    ///
    /// The two address buffers are checked before a message is taken, so the address
    /// side is never the reason one is held. The payload buffer is not: a message
    /// too long for it is kept and offered again, because a message the stack has
    /// already committed to is not one this ABI may drop.
    #[derive(Clone, Copy)]
    pub struct SipralTransmit {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Which transport to write to. [`SIPRAL_TRANSPORT_MAIN`], for now always.
        pub transport: u32,
        /// What that transport speaks, as a `SipralTransport`.
        ///
        /// Carried because it is the message's and not the socket's: §18.1.1 lets a
        /// request that outgrew a datagram go out on a stream instead, and the
        /// transport it ends up on is the one this says. Zero for a protocol this
        /// ABI has no number for.
        pub protocol: u32,
        /// Where to write the message. Nothing is written unless the whole of it
        /// fits.
        pub data: *mut u8,
        /// How much room `data` has.
        pub capacity: usize,
        /// How much was written — or, when the call answered
        /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much room the message needs.
        pub len: usize,
        /// Where to write the destination, as `host:port` with a trailing NUL. Null
        /// with a capacity of zero for a caller whose socket is connected and
        /// already knows.
        pub destination: *mut c_char,
        /// How much room `destination` has. At least [`SIPRAL_ADDRESS_BYTES`] when
        /// it is not null.
        pub destination_capacity: usize,
        /// How many bytes of it were written, the NUL not counted.
        pub destination_len: usize,
        /// Where to write the address to send *from*, in the same shape.
        ///
        /// RFC 3581 §4: "The response MUST be sent from the same address and port
        /// that the corresponding request was received on", which a caller listening
        /// on a wildcard address cannot work out for itself. Empty — a `source_len`
        /// of zero — means the transport's own address, which is the answer for
        /// every request this stack originates.
        pub source: *mut c_char,
        /// How much room `source` has. At least [`SIPRAL_ADDRESS_BYTES`] when it is
        /// not null.
        pub source_capacity: usize,
        /// How many bytes of it were written, the NUL not counted.
        pub source_len: usize,
    }
}

// Safety: plain data with no invariant between the members. The three pointers
// are the caller's own buffers, as in every other struct here, and all-zero is a
// caller that brought none — which is refused by reading it, not by being
// undefined.
unsafe impl Versioned for SipralTransmit {
    const NAME: &'static str = "sipral_transmit";
    const MIN_SIZE: usize = crate::versioned::min_size::TRANSMIT;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

entry! {
    /// Take the next message the stack wants written.
    ///
    /// One at a time, like every other poll here: a caller loops until the
    /// message comes back with a `len` of zero. Call it after every
    /// `sipral_stack_poll` and after every call that hands bytes in, since both
    /// are moments the stack writes at.
    ///
    /// A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
    /// the length it needs in `len`, and it is *kept*: the next call with room
    /// for it hands over that same message, before anything queued behind it. So
    /// a caller that brought no buffer at all — a null `data` with a capacity of
    /// zero — learns what to bring without losing the message it asked about.
    ///
    /// # Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says
    /// how long it is and whose buffers are writable for the capacities beside
    /// them.
    fn sipral_stack_poll_transmit(stack: SipralHandle, transmit: *mut SipralTransmit) {
        let mut out = unsafe { read_versioned(transmit) }?;
        prepare(&mut out)?;
        with_stack(stack, |state| {
            let Some(pending) = state.held.take().or_else(|| state.agent.poll_transmit()) else {
                return Ok(());
            };
            if pending.payload.len() > out.capacity {
                // the length is written back even though the message was not,
                // which is how the caller learns what to come back with
                out.len = pending.payload.len();
                state.held = Some(pending);
                return Ok(());
            }
            let put = unsafe { put(&mut out, &pending) };
            if put.is_err() {
                // it has been taken out of the queue by now, and a message that
                // failed on its way into a buffer is not one to lose
                state.held = Some(pending);
            }
            put
        })?;
        let short = out.len > out.capacity;
        unsafe { write_versioned(transmit, out) }?;
        if short {
            return Err(fail(
                SipralStatus::BufferTooSmall,
                format!(
                    "the message is {} bytes and there is room for {}; it is still here, and the \
                     next call with room for it takes it",
                    out.len, out.capacity
                ),
            ));
        }
        Ok(())
    }
}

/// Check the caller brought address buffers big enough for anything this can
/// write, and empty the members it is about to fill in.
///
/// The lengths are cleared for the same reason the buffers are checked: they are
/// the library's to write, and whatever the caller left in them must never read
/// as a message that was produced.
fn prepare(transmit: &mut SipralTransmit) -> Result<(), Fail> {
    transmit.transport = 0;
    transmit.protocol = 0;
    transmit.len = 0;
    transmit.destination_len = 0;
    transmit.source_len = 0;
    if transmit.data.is_null() && transmit.capacity != 0 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "data is null and says it has room for {}",
                transmit.capacity
            ),
        ));
    }
    for (pointer, capacity, name) in [
        (
            transmit.destination.cast_const(),
            transmit.destination_capacity,
            "destination",
        ),
        (
            transmit.source.cast_const(),
            transmit.source_capacity,
            "source",
        ),
    ] {
        if !pointer.is_null() && capacity < SIPRAL_ADDRESS_BYTES {
            return Err(fail(
                SipralStatus::BufferTooSmall,
                format!(
                    "an address buffer is at least {SIPRAL_ADDRESS_BYTES} bytes and {name} has \
                     room for {capacity}"
                ),
            ));
        }
    }
    Ok(())
}

/// Put one message in the caller's buffers.
///
/// # Safety
///
/// The buffers in `transmit` must be writable for the capacities beside them,
/// which [`prepare`] has already been asked about, and the payload must fit.
unsafe fn put(transmit: &mut SipralTransmit, pending: &Transmit) -> Result<(), Fail> {
    if !pending.payload.is_empty() {
        unsafe {
            ptr::copy_nonoverlapping(
                pending.payload.as_ptr(),
                transmit.data,
                pending.payload.len(),
            );
        }
    }
    transmit.len = pending.payload.len();
    transmit.transport = pending.transport.0;
    transmit.protocol = SipralTransport::named(pending.protocol);
    transmit.destination_len = unsafe {
        write_address(
            transmit.destination,
            Some(pending.destination),
            "the destination",
        )
    }?;
    transmit.source_len =
        unsafe { write_address(transmit.source, pending.source, "the source address") }?;
    Ok(())
}

/// Write one address, or an empty string for the one there is nothing to say
/// about. `None` for a buffer the caller did not bring.
///
/// # Safety
///
/// `buffer`, when it is not null, must be writable for [`SIPRAL_ADDRESS_BYTES`].
unsafe fn write_address(
    buffer: *mut c_char,
    address: Option<SocketAddr>,
    name: &'static str,
) -> Result<usize, Fail> {
    if buffer.is_null() {
        return Ok(0);
    }
    let written = address
        .map(|address| address.to_string())
        .unwrap_or_default();
    if written.len() >= SIPRAL_ADDRESS_BYTES {
        // an address longer than the room this ABI promises cannot happen: the
        // longest a socket address prints as is a bracketed IPv6 and a port
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!("{name} prints as {} bytes", written.len()),
        ));
    }
    unsafe {
        ptr::copy_nonoverlapping(written.as_ptr().cast::<c_char>(), buffer, written.len());
        buffer.add(written.len()).write(0);
    }
    Ok(written.len())
}

entry! {
    /// Hand over one datagram, whole, and say where it came from.
    ///
    /// `from` is the far end, as `host:port`. `to` is the address the datagram
    /// arrived on, which RFC 3581 §4 makes the address the response has to go
    /// out from; null with a length of zero means the address this stack was
    /// created with, which is the answer for a socket bound to one address.
    ///
    /// A WebSocket frame comes in here too: RFC 7118 §4.2 puts one SIP message
    /// in each, so it arrives whole the way a datagram does.
    ///
    /// Bytes that are not a message are `SIPRAL_STATUS_INVALID_ARGUMENT` with
    /// the parse error in the last error. That is an ordinary morning on a
    /// public SIP port and costs exactly this one packet: log it and carry on.
    ///
    /// # Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and `to`
    /// for `to_len`.
    fn sipral_stack_receive_datagram(
        stack: SipralHandle,
        transport: u32,
        data: *const u8,
        len: usize,
        from: *const c_char,
        from_len: usize,
        to: *const c_char,
        to_len: usize,
        now_ms: u64,
    ) {
        let datagram = unsafe { arrived(data, len, "a datagram") }?;
        let remote = unsafe { address(from, from_len, "from") }?;
        let arrived_on = unsafe { optional_address(to, to_len, "to") }?;
        with_stack_at(stack, now_ms, |state, now| {
            let transport = named(state, transport)?;
            let local = arrived_on.unwrap_or(state.local);
            state
                .agent
                .receive(
                    Input::Datagram {
                        transport,
                        remote,
                        local,
                        data: datagram,
                    },
                    now,
                )
                .map_err(|error| received_badly(&error))
        })
    }
}

entry! {
    /// Hand over bytes off a connection, in whatever sizes the reads came in.
    ///
    /// Not a message: a fragment of a framing the layer below reassembles on
    /// `Content-Length` (§18.3), and one call may hold several messages, half of
    /// one, or none at all. No addresses travel with it, because a connection
    /// has one far end and it was named when the transport was bound.
    ///
    /// Framing that cannot be read is fatal to the connection, and unlike a
    /// datagram it cannot be resynchronised: the transport is already retired by
    /// the time this answers `SIPRAL_STATUS_INVALID_ARGUMENT`, and the socket
    /// should be closed. A read of zero bytes is the far end closing, which is
    /// [`sipral_stack_stream_closed`] and not this.
    ///
    /// # Safety
    ///
    /// `data` must be readable for `len` bytes.
    fn sipral_stack_receive_stream(
        stack: SipralHandle,
        transport: u32,
        data: *const u8,
        len: usize,
        now_ms: u64,
    ) {
        let read = unsafe { arrived(data, len, "a read") }?;
        with_stack_at(stack, now_ms, |state, now| {
            let transport = named(state, transport)?;
            state
                .agent
                .receive(Input::StreamData { transport, data: read }, now)
                .map_err(|error| received_badly(&error))
        })
    }
}

entry! {
    /// Say that a transport is open and may be written to.
    ///
    /// The one way back from [`sipral_stack_transport_failed`], and the way a
    /// stream stack names its far end: a connection that has just been made
    /// knows its peer, and a stack created before the connect did not. It is
    /// also how a socket re-opened on another address after the network moved
    /// tells this stack what to put in its `Via` from now on — every message
    /// after this one carries `local`, and the ones already in flight carry what
    /// they were written with.
    ///
    /// `local` is the address the far end reaches this one at, as `host:port`.
    /// `remote` is the far end of a connection, and is refused on a datagram
    /// transport, which has many.
    ///
    /// The protocol is not an argument: a stack retransmits or does not
    /// according to what it was created speaking, and a transport that changed
    /// that underneath the timers would be a stack configured out of RFC 3261
    /// §17 halfway through a call.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes and `remote` for
    /// `remote_len`.
    fn sipral_stack_transport_bind(
        stack: SipralHandle,
        transport: u32,
        local: *const c_char,
        local_len: usize,
        remote: *const c_char,
        remote_len: usize,
        now_ms: u64,
    ) {
        let advertised = unsafe { address(local, local_len, "local") }?;
        let connected = unsafe { optional_address(remote, remote_len, "remote") }?;
        with_stack_at(stack, now_ms, |state, now| {
            let transport = named(state, transport)?;
            let protocol = state.speaks.protocol();
            if connected.is_some() && !protocol.is_stream() {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "remote names one far end and this stack speaks {}, which has many",
                        protocol.as_str()
                    ),
                ));
            }
            state
                .agent
                .receive(
                    Input::TransportBound {
                        transport,
                        protocol,
                        local: advertised,
                        remote: connected,
                    },
                    now,
                )
                .map_err(|error| received_badly(&error))?;
            state.local = advertised;
            Ok(())
        })
    }
}

entry! {
    /// Say that a transport failed, and that whatever was written to it did not
    /// arrive.
    ///
    /// The transport is retired: every transaction waiting on it fails now, and
    /// the calls and registrations behind them are reported on the next
    /// `sipral_stack_poll` — nothing is delivered from inside this call, here as
    /// everywhere else. Nothing can be sent until
    /// [`sipral_stack_transport_bind`] brings one back.
    ///
    /// So this is not the call for one `sendto` that was refused. An ICMP
    /// unreachable is one destination saying no, and a stack that retired its
    /// socket over it would drop the calls that were fine. This is for the
    /// socket that is over.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_transport_failed(
        stack: SipralHandle,
        transport: u32,
        error: u32,
        now_ms: u64,
    ) {
        let error = failure(error)?;
        with_stack_at(stack, now_ms, |state, now| {
            let transport = named(state, transport)?;
            state
                .agent
                .receive(Input::TransportFailed { transport, error }, now)
                .map_err(|error| received_badly(&error))
        })
    }
}

entry! {
    /// Say that a connection closed: the far end went away, or a read returned
    /// zero.
    ///
    /// The same retirement as [`sipral_stack_transport_failed`], and a separate
    /// call because it is a separate thing to have happened. An orderly close is
    /// not an error the caller has to invent a kind for, and a stack that made it
    /// one would have the two indistinguishable in a log for ever after.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_stream_closed(stack: SipralHandle, transport: u32, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let transport = named(state, transport)?;
            state
                .agent
                .receive(Input::StreamClosed { transport }, now)
                .map_err(|error| received_badly(&error))
        })
    }
}

/// An address a caller may leave out, as one.
///
/// # Safety
///
/// `pointer`, when it is not null, must be readable for `len` bytes.
unsafe fn optional_address(
    pointer: *const c_char,
    len: usize,
    name: &'static str,
) -> Result<Option<SocketAddr>, Fail> {
    if pointer.is_null() && len == 0 {
        return Ok(None);
    }
    Ok(Some(unsafe { address(pointer, len, name) }?))
}

/// The transport a number names, or why it names none.
fn named(state: &StackState, transport: u32) -> Result<TransportId, Fail> {
    if transport == state.transport.0 {
        return Ok(state.transport);
    }
    Err(fail(
        SipralStatus::InvalidArgument,
        format!(
            "transport {transport} is not one this stack has; it was created with {}, which is \
             SIPRAL_TRANSPORT_MAIN and the only one a stack of this build binds",
            state.transport.0
        ),
    ))
}

/// Bytes a caller handed in, as a slice, or why they are not one.
///
/// # Safety
///
/// `data`, when it is not null, must be readable for `len` bytes.
unsafe fn arrived<'a>(data: *const u8, len: usize, what: &'static str) -> Result<&'a [u8], Fail> {
    if data.is_null() {
        return Err(fail(SipralStatus::InvalidArgument, "data is null"));
    }
    if len == 0 || len > SIPRAL_MESSAGE_BYTES {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("data says it is {len} bytes, and {what} is 1 to {SIPRAL_MESSAGE_BYTES}"),
        ));
    }
    Ok(unsafe { slice::from_raw_parts(data, len) })
}

/// What kind of failure a number names.
fn failure(error: u32) -> Result<TransportErrorKind, Fail> {
    match error {
        0 => Ok(TransportErrorKind::Other),
        1 => Ok(TransportErrorKind::ConnectionRefused),
        2 => Ok(TransportErrorKind::ConnectionReset),
        3 => Ok(TransportErrorKind::Unreachable),
        4 => Ok(TransportErrorKind::TimedOut),
        5 => Ok(TransportErrorKind::Closed),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{other} is not a transport error this library names"),
        )),
    }
}

/// Why the layer below would not take what arrived.
///
/// The transport being unknown is the one that is not about the argument: this
/// crate checked the number before it went down, so the transport was there and
/// has since been retired, and what is wrong is the moment rather than the call.
fn received_badly(error: &ReceiveError) -> Fail {
    let status = match *error {
        ReceiveError::UnknownTransport => SipralStatus::WrongState,
        _ => SipralStatus::InvalidArgument,
    };
    let explanation = match *error {
        ReceiveError::UnknownTransport => {
            "this stack's transport has been retired, and nothing arrives on it until \
             sipral_stack_transport_bind brings one back"
                .to_owned()
        }
        _ => error.to_string(),
    };
    fail(status, explanation)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        SIPRAL_MESSAGE_BYTES, SIPRAL_TRANSPORT_MAIN, SipralTransmit, SipralTransportError,
        sipral_stack_poll_transmit, sipral_stack_receive_datagram, sipral_stack_receive_stream,
        sipral_stack_stream_closed, sipral_stack_transport_bind, sipral_stack_transport_failed,
    };
    use crate::account::{SipralAccountConfig, sipral_account_add, sipral_account_register};
    use crate::error::last_error_text;
    use crate::event::{SipralEventKind, SipralRegistrationState};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::SIPRAL_ADDRESS_BYTES;
    use crate::stack::tests::{BIND, Observed, config, create, poll, record, stack};
    use crate::stack::{SipralTransport, sipral_stack_destroy};
    use crate::status::SipralStatus;
    use sipral_core::msg::{HeaderName, Limits, ParseMode, ParseScratch, parse};
    use std::ffi::{CStr, c_char};
    use std::ptr;

    const REGISTRAR: &str = "203.0.113.9:5060";
    const AOR: &str = "sip:alice@example.com";

    /// What a PBX challenges a REGISTER with: its own, as a UAS (§22.2).
    const CHALLENGE: &str = "WWW-Authenticate: Digest realm=\"example.com\", \
                             nonce=\"abc123\", qop=\"auth\"\r\n";

    /// The buffers a caller brings, sized as the ABI asks.
    struct Buffers {
        message: Vec<u8>,
        destination: [c_char; SIPRAL_ADDRESS_BYTES],
        source: [c_char; SIPRAL_ADDRESS_BYTES],
    }

    impl Buffers {
        fn new() -> Self {
            Self::of(SIPRAL_MESSAGE_BYTES)
        }

        fn of(room: usize) -> Self {
            Self {
                message: vec![0; room],
                destination: [0; SIPRAL_ADDRESS_BYTES],
                source: [0; SIPRAL_ADDRESS_BYTES],
            }
        }

        fn transmit(&mut self) -> SipralTransmit {
            SipralTransmit {
                size: size_of::<SipralTransmit>(),
                transport: u32::MAX,
                protocol: u32::MAX,
                data: self.message.as_mut_ptr(),
                capacity: self.message.len(),
                len: usize::MAX,
                destination: self.destination.as_mut_ptr(),
                destination_capacity: self.destination.len(),
                destination_len: usize::MAX,
                source: self.source.as_mut_ptr(),
                source_capacity: self.source.len(),
                source_len: usize::MAX,
            }
        }

        /// What was written, where it was going, and where from.
        fn taken(&self, transmit: &SipralTransmit) -> (Vec<u8>, String, String) {
            (
                self.message
                    .get(..transmit.len)
                    .unwrap_or_default()
                    .to_vec(),
                written(&self.destination),
                written(&self.source),
            )
        }
    }

    fn written(buffer: &[c_char]) -> String {
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    /// One message out, through the ABI and nothing else.
    fn take_one(stack: SipralHandle) -> (Vec<u8>, String, String) {
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(transmit.len, 0, "the stack had nothing to send");
        assert_eq!(transmit.transport, SIPRAL_TRANSPORT_MAIN);
        buffers.taken(&transmit)
    }

    /// Everything the stack wants written, in order, through the C ABI.
    pub(crate) fn drain(stack: SipralHandle) -> Vec<Vec<u8>> {
        let mut buffers = Buffers::new();
        let mut all = Vec::new();
        loop {
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return all;
            }
            all.push(buffers.taken(&transmit).0);
        }
    }

    fn feed(stack: SipralHandle, from: &str, message: &[u8], now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_receive_datagram(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                message.as_ptr(),
                message.len(),
                from.as_ptr().cast::<c_char>(),
                from.len(),
                ptr::null(),
                0,
                now_ms,
            )
        }
    }

    fn header(message: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let parsed = parse(message, &mut scratch, ParseMode::Lenient).expect("a message");
        parsed.header(name).unwrap_or_default().to_vec()
    }

    /// A response to `request`, copied through the way a registrar's is.
    fn reply(request: &[u8], status: u16, reason: &str, extra: &str) -> Vec<u8> {
        let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
        for (name, value) in [
            ("Via", header(request, HeaderName::Via)),
            ("From", header(request, HeaderName::From)),
            ("To", header(request, HeaderName::To)),
            ("Call-ID", header(request, HeaderName::CallId)),
            ("CSeq", header(request, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(extra.as_bytes());
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    fn account_config() -> SipralAccountConfig {
        let text = |value: &'static str| (value.as_ptr().cast::<c_char>(), value.len());
        let (aor, aor_len) = text(AOR);
        let (registrar, registrar_len) = text("sip:example.com");
        let (contact, contact_len) = text("sip:alice@192.0.2.10:5060");
        let (registrar_address, registrar_address_len) = text(REGISTRAR);
        let (auth_user, auth_user_len) = text("alice");
        let (auth_password, auth_password_len) = text("open sesame");
        SipralAccountConfig {
            size: size_of::<SipralAccountConfig>(),
            aor,
            aor_len,
            registrar,
            registrar_len,
            contact,
            contact_len,
            registrar_address,
            registrar_address_len,
            display_name: ptr::null(),
            display_name_len: 0,
            auth_user,
            auth_user_len,
            auth_password,
            auth_password_len,
            instance_id: ptr::null(),
            instance_id_len: 0,
            expires_seconds: 0,
        }
    }

    fn line(stack: SipralHandle) -> SipralHandle {
        let config = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(stack, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    /// A stack speaking something other than UDP, which is the only way to
    /// reach the stream half of this surface.
    fn speaking(observed: &mut Observed, protocol: SipralTransport) -> SipralHandle {
        let mut config = config(record, observed);
        config.transport = protocol as u32;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        handle
    }

    /// A whole registration, from the account being added to the binding being
    /// reported, driven through the C ABI and nothing else: no test reaches
    /// past it into the stack it is testing.
    #[test]
    fn a_registration_goes_out_and_comes_back_through_the_abi_alone() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = line(handle);

        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_000);

        let (first, to, from) = take_one(handle);
        assert!(first.starts_with(b"REGISTER "), "{:?}", start_of(&first));
        assert_eq!(to, REGISTRAR, "it goes to the registrar's address");
        assert_eq!(
            from, "",
            "a request this end originates has no source to name"
        );
        assert!(
            header(&first, HeaderName::Authorization).is_empty(),
            "nothing is answered before it is asked"
        );

        assert_eq!(
            feed(
                handle,
                REGISTRAR,
                &reply(&first, 401, "Unauthorized", CHALLENGE),
                1_100
            ),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_100);

        let (retry, _, _) = take_one(handle);
        assert!(retry.starts_with(b"REGISTER "));
        let credentials =
            String::from_utf8_lossy(&header(&retry, HeaderName::Authorization)).into_owned();
        assert!(credentials.contains("username=\"alice\""), "{credentials}");
        assert!(credentials.contains("nonce=\"abc123\""), "{credentials}");
        assert!(
            !credentials.contains("open sesame"),
            "the password does not travel: {credentials}"
        );

        let granted = reply(
            &retry,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.10:5060>;expires=3600\r\n",
        );
        assert_eq!(feed(handle, REGISTRAR, &granted, 1_200), SipralStatus::Ok);
        let result = poll(handle, 1_200);
        assert!(result.events_delivered >= 1);
        assert!(
            observed
                .kinds()
                .contains(&SipralEventKind::RegistrationChanged),
            "the binding was never reported: {:?}",
            observed.kinds()
        );
        assert_eq!(
            crate::account::tests::state_of(handle, account),
            SipralRegistrationState::Registered as u32,
            "the registrar granted the binding and the stack does not know it"
        );
        assert!(
            drain(handle).is_empty(),
            "nothing else was waiting to go out"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Every 2xx a callback was handed on a registration that went live,
    /// copied out while the callback was still running.
    #[derive(Default)]
    struct Granted {
        messages: Vec<Vec<u8>>,
    }

    unsafe extern "C" fn keep_granted(
        event: *const crate::event::SipralEvent,
        user_data: *mut std::ffi::c_void,
    ) {
        let granted = unsafe { &mut *user_data.cast::<Granted>() };
        let event = unsafe { &*event };
        if event.kind != SipralEventKind::RegistrationChanged || event.message.is_null() {
            return;
        }
        let state = unsafe { event.payload.registration.state };
        if state == SipralRegistrationState::Registered as u32 {
            let bytes = unsafe { std::slice::from_raw_parts(event.message, event.message_len) };
            granted.messages.push(bytes.to_vec());
        }
    }

    /// The 200 OK to a REGISTER reaches the callback whole, the way a refusal
    /// always has. A Service-Route, the GRUUs and P-Associated-URI are read out
    /// of `message`, and no binding needs a member of its own for any of them.
    #[test]
    fn the_200_ok_to_a_register_reaches_the_callback_whole() {
        let mut observed = Observed::default();
        let mut granted = Granted::default();
        let mut settings = config(keep_granted, &mut observed);
        settings.event_user_data = ptr::from_mut(&mut granted).cast::<std::ffi::c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_000);
        let (request, _, _) = take_one(handle);

        let ok = reply(
            &request,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.10:5060>;expires=3600\r\n\
             Service-Route: <sip:edge.example.com;lr>\r\n\
             P-Associated-URI: <sip:alice.smith@example.com>\r\n",
        );
        assert_eq!(
            feed(handle, REGISTRAR, &ok, 1_100),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_100);
        assert_eq!(
            granted.messages,
            vec![ok],
            "the registered event carries the 200 it was granted by, byte for byte"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    fn start_of(message: &[u8]) -> String {
        String::from_utf8_lossy(
            message
                .split(|byte| *byte == b'\r')
                .next()
                .unwrap_or_default(),
        )
        .into_owned()
    }

    /// A stack with a REGISTER waiting to be taken.
    fn pending(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        (handle, account)
    }

    #[test]
    fn a_stack_with_nothing_to_say_answers_a_length_of_zero() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) },
            SipralStatus::Ok
        );
        assert_eq!(transmit.len, 0);
        assert_eq!(transmit.transport, 0, "nothing was named either");
        assert_eq!(transmit.destination_len, 0);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What poll used to do to the queue, and no longer does. The bytes a poll
    /// produces are still there afterwards, or the loop in this module's
    /// documentation would lose a message on every pass.
    #[test]
    fn polling_does_not_throw_away_what_the_stack_wanted_written() {
        let mut observed = Observed::default();
        let (handle, _) = pending(&mut observed);
        let result = poll(handle, 1_000);
        assert_eq!(result.transmits_discarded, 0);
        let result = poll(handle, 1_001);
        assert_eq!(result.transmits_discarded, 0);
        let out = drain(handle);
        assert_eq!(out.len(), 1, "the REGISTER survived two polls");
        assert!(
            out.first()
                .is_some_and(|first| first.starts_with(b"REGISTER "))
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The whole of the buffer-too-small promise: the length needed comes back,
    /// nothing is written, and the message is still there afterwards.
    #[test]
    fn a_message_too_long_for_the_buffer_is_kept_rather_than_dropped() {
        let mut observed = Observed::default();
        let (handle, _) = pending(&mut observed);

        let mut small = Buffers::of(8);
        let mut transmit = small.transmit();
        let status = unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        let needed = transmit.len;
        assert!(needed > 8, "the length it needs came back: {needed}");
        assert!(
            small.message.iter().all(|byte| *byte == 0),
            "a message that did not fit was written anyway"
        );
        assert_eq!(
            transmit.destination_len, 0,
            "and nothing else was filled in"
        );
        let message = last_error_text();
        assert!(
            message.contains(&needed.to_string()) && message.contains('8'),
            "the message names neither figure: {message}"
        );

        let (taken, _, _) = take_one(handle);
        assert_eq!(taken.len(), needed, "the same message came back whole");
        assert!(taken.starts_with(b"REGISTER "));
        assert!(drain(handle).is_empty(), "and only once");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The ask-for-the-length-then-ask-for-the-bytes sequence, which is how a
    /// caller that sizes its buffer at run time starts.
    #[test]
    fn a_caller_with_no_buffer_at_all_is_told_what_to_bring() {
        let mut observed = Observed::default();
        let (handle, _) = pending(&mut observed);
        let mut transmit = SipralTransmit {
            size: size_of::<SipralTransmit>(),
            transport: u32::MAX,
            protocol: u32::MAX,
            data: ptr::null_mut(),
            capacity: 0,
            len: usize::MAX,
            destination: ptr::null_mut(),
            destination_capacity: 0,
            destination_len: usize::MAX,
            source: ptr::null_mut(),
            source_capacity: 0,
            source_len: usize::MAX,
        };
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) },
            SipralStatus::BufferTooSmall
        );
        assert!(transmit.len > 0);
        let (taken, _, _) = take_one(handle);
        assert_eq!(taken.len(), transmit.len);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_buffer_that_is_null_while_claiming_room_is_a_bad_argument() {
        let mut observed = Observed::default();
        let (handle, _) = pending(&mut observed);
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        transmit.data = ptr::null_mut();
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) },
            SipralStatus::InvalidArgument
        );
        assert!(!drain(handle).is_empty(), "and the message is untouched");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_address_buffer_too_small_is_refused_before_a_message_is_taken() {
        let mut observed = Observed::default();
        let (handle, _) = pending(&mut observed);
        let mut buffers = Buffers::new();
        for shrink in [
            (|transmit: &mut SipralTransmit| transmit.destination_capacity = 4) as fn(&mut _),
            |transmit: &mut SipralTransmit| transmit.source_capacity = 4,
        ] {
            let mut transmit = buffers.transmit();
            shrink(&mut transmit);
            assert_eq!(
                unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) },
                SipralStatus::BufferTooSmall
            );
            assert_eq!(
                transmit.len,
                usize::MAX,
                "the struct was not written to, so nothing was taken"
            );
        }
        assert_eq!(drain(handle).len(), 1, "the message waited through both");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_transmit_struct_that_is_null_or_the_wrong_size_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(handle, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        transmit.size = size_of::<SipralTransmit>() - 1;
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) },
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The request every PBX sends its registered contacts on a timer, and the
    /// one this stack answers by itself — so it is the one that produces a
    /// response with nobody's help.
    fn options(branch: &str) -> String {
        format!(
            "OPTIONS {AOR} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-{branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:pbx@example.com>;tag=pbx\r\n\
             To: <{AOR}>\r\n\
             Call-ID: {branch}@example.com\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        )
    }

    /// RFC 3581 §4: a response goes out from the address its request arrived on,
    /// and a caller on a wildcard socket cannot work that out for itself.
    #[test]
    fn a_response_says_which_address_to_send_it_from() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let options = options("options-1");
        assert_eq!(
            feed(handle, REGISTRAR, options.as_bytes(), 1_000),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let (answer, to, from) = take_one(handle);
        assert!(
            answer.starts_with(b"SIP/2.0 200 "),
            "{:?}",
            start_of(&answer)
        );
        assert_eq!(to, REGISTRAR);
        assert_eq!(from, BIND, "the address it arrived on");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The other half of the same field: a caller listening on several
    /// interfaces says which one a datagram landed on, and the answer goes back
    /// from there rather than from the address the stack was created with.
    #[test]
    fn the_address_a_datagram_arrived_on_is_the_one_the_answer_leaves_from() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let second = "198.51.100.7:5060";
        let options = options("options-2");
        let status = unsafe {
            sipral_stack_receive_datagram(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                options.as_ptr(),
                options.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                second.as_ptr().cast::<c_char>(),
                second.len(),
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (_, _, from) = take_one(handle);
        assert_eq!(from, second);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn bytes_that_are_not_a_message_cost_one_packet_and_nothing_else() {
        let mut observed = Observed::default();
        let (handle, _) = pending(&mut observed);
        assert_eq!(
            feed(handle, REGISTRAR, b"not a SIP message at all", 1_000),
            SipralStatus::InvalidArgument
        );
        assert!(!last_error_text().is_empty(), "it says what was wrong");
        let (first, _, _) = take_one(handle);
        let granted = reply(
            &first,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.10:5060>;expires=60\r\n",
        );
        assert_eq!(
            feed(handle, REGISTRAR, &granted, 1_100),
            SipralStatus::Ok,
            "the stack carried on: {}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    fn hand_in(handle: SipralHandle, data: *const u8, len: usize) -> SipralStatus {
        unsafe {
            sipral_stack_receive_datagram(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                data,
                len,
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                ptr::null(),
                0,
                1_000,
            )
        }
    }

    #[test]
    fn a_datagram_that_is_null_or_a_nonsense_length_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let one = [0_u8; 1];
        for (data, len) in [(ptr::null(), 4), (ptr::null(), 0)] {
            assert_eq!(hand_in(handle, data, len), SipralStatus::InvalidArgument);
            assert!(last_error_text().contains("null"), "{}", last_error_text());
        }
        // the length is answered from the length alone, before a byte behind
        // the pointer is read: the second of these describes 64 KiB of a buffer
        // that is one byte long, and reading it to find out would be the bug
        for len in [0, SIPRAL_MESSAGE_BYTES + 1] {
            assert_eq!(
                hand_in(handle, one.as_ptr(), len),
                SipralStatus::InvalidArgument
            );
            let message = last_error_text();
            assert!(
                message.contains(&format!("{len} bytes")) && message.contains("1 to 65535"),
                "the length was not what was refused: {message}"
            );
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_datagram_from_nowhere_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let message = b"SIP/2.0 200 OK\r\n\r\n";
        for (from, from_len) in [
            (ptr::null(), 0),
            ("example.com".as_ptr().cast::<c_char>(), 11),
        ] {
            let status = unsafe {
                sipral_stack_receive_datagram(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    message.as_ptr(),
                    message.len(),
                    from,
                    from_len,
                    ptr::null(),
                    0,
                    1_000,
                )
            };
            assert_eq!(status, SipralStatus::InvalidArgument);
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_transport_this_stack_does_not_have_is_refused_and_says_which_it_does() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let message = b"SIP/2.0 200 OK\r\n\r\n";
        let status = unsafe {
            sipral_stack_receive_datagram(
                handle,
                7,
                message.as_ptr(),
                message.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                ptr::null(),
                0,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains('7'), "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_stack_stream_closed(handle, 7, 1_000) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_stack_transport_failed(handle, 7, 0, 1_000) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A transport that failed takes the transactions on it with it, which is
    /// §17's "inform the TU and terminate" arriving where an application can
    /// see it: the registration is reported failed rather than waiting out
    /// 64·T1 for a reply that cannot come.
    #[test]
    fn a_transport_that_failed_fails_what_was_waiting_on_it() {
        let mut observed = Observed::default();
        let (handle, account) = pending(&mut observed);
        drain(handle);
        assert_eq!(
            unsafe {
                sipral_stack_transport_failed(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    SipralTransportError::Unreachable as u32,
                    1_100,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_100);
        assert!(
            observed
                .kinds()
                .contains(&SipralEventKind::RegistrationChanged),
            "nothing was reported: {:?}",
            observed.kinds()
        );
        assert_ne!(
            crate::account::tests::state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
        assert_eq!(
            feed(handle, REGISTRAR, b"SIP/2.0 200 OK\r\n\r\n", 1_200),
            SipralStatus::WrongState,
            "the transport is retired and nothing arrives on it"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_error_kind_this_library_does_not_name_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_transport_failed(handle, SIPRAL_TRANSPORT_MAIN, 6, 1_000) },
            SipralStatus::InvalidArgument
        );
        for error in [
            SipralTransportError::Other,
            SipralTransportError::ConnectionRefused,
            SipralTransportError::ConnectionReset,
            SipralTransportError::Unreachable,
            SipralTransportError::TimedOut,
            SipralTransportError::Closed,
        ] {
            let mut observed = Observed::default();
            let handle = stack(&mut observed);
            assert_eq!(
                unsafe {
                    sipral_stack_transport_failed(
                        handle,
                        SIPRAL_TRANSPORT_MAIN,
                        error as u32,
                        1_000,
                    )
                },
                SipralStatus::Ok,
                "{error:?}"
            );
            assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The way back: a socket re-opened after the network moved says so, and
    /// every message from then on carries the address it was bound to.
    #[test]
    fn a_transport_bound_again_is_one_the_stack_can_send_on() {
        let mut observed = Observed::default();
        let (handle, account) = pending(&mut observed);
        drain(handle);
        assert_eq!(
            unsafe { sipral_stack_transport_failed(handle, SIPRAL_TRANSPORT_MAIN, 0, 1_100) },
            SipralStatus::Ok
        );
        poll(handle, 1_100);

        let moved = "198.51.100.7:5062";
        assert_eq!(
            unsafe {
                sipral_stack_transport_bind(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    moved.as_ptr().cast::<c_char>(),
                    moved.len(),
                    ptr::null(),
                    0,
                    1_200,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_300) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let (again, to, _) = take_one(handle);
        assert!(again.starts_with(b"REGISTER "));
        assert_eq!(to, REGISTRAR);
        let via = String::from_utf8_lossy(&header(&again, HeaderName::Via)).into_owned();
        assert!(
            via.contains(moved),
            "the Via still names the old socket: {via}"
        );

        // and the address a datagram is taken to have arrived on moved with it,
        // for the caller that names none
        assert_eq!(
            feed(handle, REGISTRAR, options("options-3").as_bytes(), 1_400),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let (answer, _, from) = take_one(handle);
        assert!(answer.starts_with(b"SIP/2.0 200 "));
        assert_eq!(from, moved);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_far_end_named_on_a_transport_that_has_many_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("UDP"), "{}", last_error_text());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_address_that_is_not_one_does_not_bind_a_transport() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let nonsense = "example.com";
        for (local, local_len) in [(ptr::null(), 0), (nonsense.as_ptr().cast::<c_char>(), 11)] {
            assert_eq!(
                unsafe {
                    sipral_stack_transport_bind(
                        handle,
                        SIPRAL_TRANSPORT_MAIN,
                        local,
                        local_len,
                        ptr::null(),
                        0,
                        1_000,
                    )
                },
                SipralStatus::InvalidArgument
            );
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    // -- the stream half -----------------------------------------------------

    /// §18.3: a byte stream is framed on `Content-Length`, so a message split
    /// across two reads is one message and neither half is one.
    #[test]
    fn a_message_split_across_two_reads_is_one_message() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tcp);
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        let (first, _, _) = take_one(handle);
        let granted = reply(
            &first,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.10:5060>;expires=3600\r\n",
        );
        let (head, tail) = granted.split_at(granted.len() / 2);
        for half in [head, tail] {
            let status = unsafe {
                sipral_stack_receive_stream(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    half.as_ptr(),
                    half.len(),
                    1_100,
                )
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        }
        poll(handle, 1_100);
        assert_eq!(
            crate::account::tests::state_of(handle, account),
            SipralRegistrationState::Registered as u32,
            "the two halves never became a message"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn stream_bytes_on_a_datagram_transport_are_refused_and_the_other_way_round() {
        let mut observed = Observed::default();
        let datagram = stack(&mut observed);
        let bytes = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            unsafe {
                sipral_stack_receive_stream(
                    datagram,
                    SIPRAL_TRANSPORT_MAIN,
                    bytes.as_ptr(),
                    bytes.len(),
                    1_000,
                )
            },
            SipralStatus::InvalidArgument
        );

        let mut other = Observed::default();
        let stream = speaking(&mut other, SipralTransport::Tcp);
        assert_eq!(
            feed(stream, REGISTRAR, bytes, 1_000),
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(datagram) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(stream) }, SipralStatus::Ok);
    }

    /// A WebSocket carries one message per frame (RFC 7118 §4.2), so it is fed
    /// in whole, the way a datagram is, and the framer never sees it.
    #[test]
    fn a_websocket_frame_goes_in_as_a_datagram() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Ws);
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        let (first, _, _) = take_one(handle);
        let granted = reply(
            &first,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.10:5060>;expires=3600\r\n",
        );
        assert_eq!(feed(handle, REGISTRAR, &granted, 1_100), SipralStatus::Ok);
        poll(handle, 1_100);
        assert_eq!(
            crate::account::tests::state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_connection_that_closed_retires_the_transport_it_was() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tcp);
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        drain(handle);
        assert_eq!(
            unsafe { sipral_stack_stream_closed(handle, SIPRAL_TRANSPORT_MAIN, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_100);
        assert!(
            observed
                .kinds()
                .contains(&SipralEventKind::RegistrationChanged)
        );
        let bytes = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            unsafe {
                sipral_stack_receive_stream(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    bytes.as_ptr(),
                    bytes.len(),
                    1_200,
                )
            },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A connection re-made after it dropped names its far end, which is what a
    /// response to an inbound request over that connection goes back to.
    #[test]
    fn a_reconnected_stream_names_the_far_end_it_reached() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tcp);
        assert_eq!(
            unsafe { sipral_stack_stream_closed(handle, SIPRAL_TRANSPORT_MAIN, 1_000) },
            SipralStatus::Ok
        );
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                1_100,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_200) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let (out, to, _) = take_one(handle);
        assert!(out.starts_with(b"REGISTER "));
        assert_eq!(to, REGISTRAR);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The number is written out rather than derived, so that a limit which
    /// moved in the layer below disagrees with a constant this ABI published.
    #[test]
    fn the_largest_message_is_the_one_the_parser_will_read() {
        assert_eq!(
            SIPRAL_MESSAGE_BYTES,
            Limits::DEFAULT.max_message_bytes as usize
        );
        assert_eq!(SIPRAL_TRANSPORT_MAIN, 0);
    }

    #[test]
    fn every_entry_point_here_answers_a_handle_that_names_nothing() {
        let message = b"SIP/2.0 200 OK\r\n\r\n";
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        let gone = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(gone, &raw mut transmit) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            feed(gone, REGISTRAR, message, 0),
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe {
                sipral_stack_receive_stream(
                    gone,
                    SIPRAL_TRANSPORT_MAIN,
                    message.as_ptr(),
                    message.len(),
                    0,
                )
            },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe { sipral_stack_stream_closed(gone, SIPRAL_TRANSPORT_MAIN, 0) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe { sipral_stack_transport_failed(gone, SIPRAL_TRANSPORT_MAIN, 0, 0) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe {
                sipral_stack_transport_bind(
                    gone,
                    SIPRAL_TRANSPORT_MAIN,
                    BIND.as_ptr().cast::<c_char>(),
                    BIND.len(),
                    ptr::null(),
                    0,
                    0,
                )
            },
            SipralStatus::InvalidHandle
        );
    }
}
