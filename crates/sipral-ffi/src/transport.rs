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
//! # A table of transports, and the main one named
//!
//! A stack is bound to one transport at creation, [`SIPRAL_TRANSPORT_MAIN`],
//! and every call here still names it by default — a caller that never binds
//! a second one sees exactly the surface this crate always had. What changed
//! (task 8.4.10) is that [`sipral_stack_transport_bind`] may now bind more:
//! `transport` on `sipral_account_config_t` and `sipral_call_config_t` says
//! which one an account's REGISTER, or a call's INVITE, goes out on, and zero
//! keeps meaning [`SIPRAL_TRANSPORT_MAIN`] there too, so a caller that fills
//! neither in gets exactly what it always got.
//!
//! A stack's transports are a table rather than a single id from the moment
//! it is created, and the table only grows: [`SIPRAL_TRANSPORT_MAIN`] is in it
//! first, and [`sipral_stack_transport_bind`] adds an entry the first time a
//! number is bound and confirms it every time after. Numbers beyond the main
//! one are the caller's own to choose — the layer below already documents a
//! transport as "named by the caller" and never interprets what the number
//! means — so `out_transport_id` on a bind hands back exactly the number that
//! was asked for, which is a caller's one place to read the id it is about to
//! put in an account or a call config, and reads the same after a rebind as
//! before it.
//!
//! An account whose transport is later unbound is not retired with it: a
//! failed or closed transport stops carrying traffic, the same as it always
//! has, and starts again the moment [`sipral_stack_transport_bind`] brings it
//! back — nothing about the account changes underneath it. A call with its
//! own `transport` left at zero is the account's to route exactly as it
//! always was: `destination` unset means the INVITE goes where the account
//! registers, over the account's own transport, and `transport` is read only
//! together with an explicit `destination`, since there is nothing else to
//! combine it with.
//!
//! This is also where §18.1.1's promotion lands: a request too large for a
//! datagram now arrives as [`crate::event::SipralEventKind::TransportWanted`]
//! (event 18, previously reserved), naming where it was going and over what
//! protocol, and the call that asked for it is refused with
//! `SIPRAL_STATUS_NOT_SENT`. The application answers it with
//! [`sipral_stack_transport_bind`] the same way it answers a network change
//! that took a transport with it, and asks again — places the call, registers
//! — once the bind succeeds: the request then leaves on that stream, and
//! there is no separate "it went" event, the same as for a request that fit
//! the first time.
//!
//! The answer to a challenge is where a request most often crosses the line,
//! and there nobody asks again: the stack holds the retry itself and sends it
//! the moment the bind succeeds. An application that cannot open the stream
//! — the far end refused the connection, it timed out, or it opens none at
//! all — says so with [`sipral_stack_transport_failed`] or
//! [`sipral_stack_transport_failed_with`] naming the number it would have bound,
//! and everything waiting stops waiting at once: a call's INVITE is tried
//! once more over the datagram with one SDES suite per media stream, when
//! that fits, and what still does not fit ends — a call with
//! `SIPRAL_CALL_END_REASON_UNREACHABLE`, `cause_sip` 513 and a `cause_text`
//! naming the size and the limit; a registration failed as unreachable with
//! a 513. An application that says nothing gets the same ten seconds after
//! the event (`sipral_ua::STREAM_WAIT`).
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
    /// The transport a stack is created with.
    ///
    /// Never retired: [`sipral_stack_transport_failed`] and
    /// [`sipral_stack_stream_closed`] can still stop it carrying traffic, and
    /// [`sipral_stack_transport_bind`] is still what brings it back, exactly
    /// as when this was the only number a stack had. Zero on
    /// `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
    /// means this one, so a caller that never binds a second transport fills
    /// neither in and gets exactly what it always got.
    pub const SIPRAL_TRANSPORT_MAIN: u32 = 0;

    /// The largest message that crosses in either direction.
    ///
    /// The bound the layer below parses to, which is what stops a hostile peer
    /// from making the parser do unbounded work. A caller's read buffer wants
    /// to be this big on a stream, where one read can hold the end of one
    /// message and the start of another, and 1500 bytes or so on a datagram
    /// socket, where anything larger was fragmented on the way.
    pub const SIPRAL_MESSAGE_BYTES: usize = 65_535;

    /// The longest `sipral_transport_failure_t::detail` this library takes.
    ///
    /// A platform's sentence about a refused certificate is a line, not a
    /// document; one longer than this is refused rather than cut, since a
    /// sentence cut short can say something else.
    pub const SIPRAL_TRANSPORT_DETAIL_BYTES: usize = 1_024;
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

codes! {
    /// Why a TLS connection was refused, as the platform's TLS library said
    /// it. Names for `sipral_transport_failure_t::tls` and
    /// `sipral_transport_failed_event_t::tls`.
    ///
    /// Sipral links no TLS library (`docs/22-tls.md`), so these are the
    /// application's words, mapped from its own library's error: the stack
    /// only carries them to whoever reads the event, so that a user can be
    /// told which of the four it was rather than "the connection closed".
    /// A connection that was never answered is not one of them: that is
    /// `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED` with this left at none.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTlsFailure: u32 {
        /// Not a TLS failure, or one the application could not classify.
        None = 0,
        /// No trusted authority stands behind the server's certificate: a
        /// self-signed one, a private authority not handed over, or an
        /// authority other than the one pinned.
        Untrusted = 1,
        /// The certificate is trusted and names another server.
        NameMismatch = 2,
        /// The certificate has expired, or is not valid yet.
        Expired = 3,
        /// The handshake itself failed: no protocol version or cipher in
        /// common, an alert from the server, or a server that does not speak
        /// TLS on that port.
        HandshakeRefused = 4,
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
        /// Which transport to write to: [`SIPRAL_TRANSPORT_MAIN`] for a stack
        /// that never bound another, or the number
        /// [`sipral_stack_transport_bind`] gave whichever account or call
        /// this message belongs to.
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
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralTransmit, source_len);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// A transport that failed, and why, for
    /// [`sipral_stack_transport_failed_with`].
    ///
    /// The caller fills in all of it. `detail` is the platform's own sentence
    /// — OpenSSL's, `SslStream`'s, `SSLSocket`'s, Network.framework's — and
    /// is optional; it travels to the event unread and unparsed, so a user's
    /// report can quote it.
    #[derive(Clone, Copy)]
    pub struct SipralTransportFailure {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Which transport: [`SIPRAL_TRANSPORT_MAIN`], or a number
        /// [`sipral_stack_transport_bind`] added.
        pub transport: u32,
        /// A [`SipralTransportError`].
        pub error: u32,
        /// A [`SipralTlsFailure`]; `SIPRAL_TLS_FAILURE_NONE` for anything
        /// that was not TLS refusing, and only that on a transport that does
        /// not speak TLS.
        pub tls: u32,
        /// The platform's own words for it, not NUL-terminated. Null with a
        /// length of zero for none.
        pub detail: *const c_char,
        /// How many bytes of it; at most [`SIPRAL_TRANSPORT_DETAIL_BYTES`].
        pub detail_len: usize,
    }
}

// Safety: plain data with no invariant between the members; the one pointer
// is the caller's and is read for as long as the call runs and no longer.
unsafe impl Versioned for SipralTransportFailure {
    const NAME: &'static str = "sipral_transport_failure";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralTransportFailure, detail_len);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// The payload of `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: a transport this
    /// stack signals on stopped carrying traffic.
    ///
    /// The text is the library's, valid for as long as the callback runs.
    #[derive(Clone, Copy)]
    pub struct SipralTransportFailedEvent {
        /// Which transport: [`SIPRAL_TRANSPORT_MAIN`], or a number
        /// [`sipral_stack_transport_bind`] added.
        pub transport: u32,
        /// What it spoke, as a `SipralTransport`.
        pub protocol: u32,
        /// A [`SipralTransportError`]: what the application said went wrong,
        /// `SIPRAL_TRANSPORT_ERROR_CLOSED` for a connection that closed.
        pub error: u32,
        /// A [`SipralTlsFailure`]: why TLS refused, when that is what it was.
        pub tls: u32,
        /// The platform's own sentence, as the application handed it over.
        /// Null with a length of zero when it gave none.
        pub detail: *const c_char,
        /// How many bytes of it.
        pub detail_len: usize,
    }
}

/// One transport lost, waiting for the next poll to say so.
///
/// Queued by the entry point that retired it and raised by the poll, before
/// anything the layers below have to say about the transactions that failed
/// with it: the cause comes before its effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lost {
    pub(crate) transport: u32,
    pub(crate) protocol: u32,
    pub(crate) error: SipralTransportError,
    pub(crate) tls: SipralTlsFailure,
    pub(crate) detail: String,
}

impl Lost {
    /// The event, and the text it points into.
    pub(crate) fn raised(self, stack: SipralHandle) -> (crate::event::SipralEvent, String) {
        let payload = SipralTransportFailedEvent {
            transport: self.transport,
            protocol: self.protocol,
            error: self.error as u32,
            tls: self.tls as u32,
            detail: if self.detail.is_empty() {
                ptr::null()
            } else {
                self.detail.as_ptr().cast::<c_char>()
            },
            detail_len: self.detail.len(),
        };
        (crate::event::transport_failed(stack, payload), self.detail)
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
            // a STUN request for a signalling socket leaves by the transport
            // that socket is, which is what makes the answer describe it
            let Some(pending) = state
                .held
                .take()
                .or_else(|| crate::nat::Nat::poll_signalling(state))
                .or_else(|| state.agent.poll_transmit())
            else {
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
            } else {
                state.log.sip_message(
                    sipral::Travel::Sent,
                    pending.destination,
                    &pending.payload,
                    state.last_instant(),
                );
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
pub(crate) fn prepare(transmit: &mut SipralTransmit) -> Result<(), Fail> {
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
pub(crate) unsafe fn write_address(
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
    /// out from; a length of zero, whatever the pointer, means the address
    /// this stack was created with, which is the answer for a socket bound to
    /// one address.
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
            // the STUN server's answer about this socket, when the stack asks
            // one: the server's own address and a transaction this stack
            // started, or it goes on to the parser like anything else
            let socket = crate::nat::Nat::socket_of(state, transport, local);
            if crate::nat::Nat::intercept(state, socket, remote, datagram, now) {
                return Ok(());
            }
            state
                .log
                .sip_message(sipral::Travel::Received, remote, datagram, now);
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
            state.log.line(sipral::LogLevel::Trace, "sip", now, || {
                format!(
                    "{} bytes read on transport {}, whole messages once framed",
                    read.len(),
                    transport.0
                )
            });
            let received = state
                .agent
                .receive(Input::StreamData { transport, data: read }, now);
            if let Err(ReceiveError::Malformed(ref broken)) = received {
                // the framing is lost with it and the endpoint has already
                // forgotten the transport: a loss like any other, said the
                // same way
                state.lost.push(Lost {
                    transport: transport.0,
                    protocol: protocol_number(state, transport.0),
                    error: SipralTransportError::Other,
                    tls: SipralTlsFailure::None,
                    detail: format!("the stream carried something no message starts with: {broken}"),
                });
            }
            received.map_err(|error| received_badly(&error))
        })
    }
}

entry! {
    /// Say that a transport is open and may be written to — the main one
    /// again, or a further one this stack has not had before.
    ///
    /// The one way back from [`sipral_stack_transport_failed`], the way a
    /// stream stack names its far end, and the way a further transport enters
    /// the table at all. `transport` is [`SIPRAL_TRANSPORT_MAIN`] to (re)bind
    /// the main one, or any other number: one this stack already has rebinds
    /// it, and one it does not opens it — the number is the caller's own
    /// choice, the same as `sipral_account_config_t::transport` and
    /// `sipral_call_config_t::transport` read it. `out_transport_id` may be
    /// null; when it is not, it receives that same number, which is where a
    /// caller answering
    /// [`SipralEventKind::TransportWanted`](crate::event::SipralEventKind::TransportWanted)
    /// reads back the id it just gave one of those two configs.
    ///
    /// `protocol` is a [`crate::stack::SipralTransport`].
    /// Rebinding an existing transport takes zero to mean "whatever it
    /// already speaks" and anything else has to agree with that or this is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` — a stack retransmits or does not
    /// according to what a transport was opened speaking, and changing that
    /// underneath the timers would be a transport configured out of RFC 3261
    /// §17 halfway through a call. Opening a new one needs a protocol to
    /// speak, so zero there is the same refusal for the opposite reason:
    /// nothing to fall back on.
    ///
    /// `local` is the address the far end reaches this one at, as `host:port`.
    /// `remote` is the far end of a connection, and is refused on a datagram
    /// transport, which has many; a length of zero, whatever the pointer,
    /// leaves it out.
    ///
    /// This is also how a request
    /// [`SipralEventKind::TransportWanted`](crate::event::SipralEventKind::TransportWanted)
    /// named gets to leave: the call that asked for it was refused with
    /// `SIPRAL_STATUS_NOT_SENT` and nothing went on the wire, and once this
    /// returns `SIPRAL_STATUS_OK` for the protocol and destination the event
    /// gave, asking again — placing the call, registering — sends it on the
    /// stream just bound. There is no further event about that one request.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes, `remote` for
    /// `remote_len`, and `out_transport_id`, when it is not null, must point
    /// at one `uint32_t`.
    fn sipral_stack_transport_bind(
        stack: SipralHandle,
        transport: u32,
        protocol: u32,
        local: *const c_char,
        local_len: usize,
        remote: *const c_char,
        remote_len: usize,
        now_ms: u64,
        out_transport_id: *mut u32,
    ) {
        let advertised = unsafe { address(local, local_len, "local") }?;
        let connected = unsafe { optional_address(remote, remote_len, "remote") }?;
        with_stack_at(stack, now_ms, |state, now| {
            let known = state.transports.protocol_of(transport);
            let resolved = match (known, protocol) {
                (Some(speaks), 0) => speaks,
                (Some(speaks), asked) => {
                    let asked = crate::stack::transport_of(asked)?.protocol();
                    if asked != speaks {
                        return Err(fail(
                            SipralStatus::InvalidArgument,
                            format!(
                                "transport {transport} already speaks {speaks}, and this call \
                                 named {asked}; a transport does not change protocol underneath \
                                 the timers it was opened with"
                            ),
                        ));
                    }
                    asked
                }
                (None, 0) => {
                    return Err(fail(
                        SipralStatus::InvalidArgument,
                        format!(
                            "transport {transport} is not one this stack has yet, and opening \
                             one needs a protocol to speak"
                        ),
                    ));
                }
                (None, asked) => crate::stack::transport_of(asked)?.protocol(),
            };
            if connected.is_some() && !resolved.is_stream() {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("remote names one far end and {resolved} has many"),
                ));
            }
            let id = TransportId(transport);
            state
                .agent
                .receive(
                    Input::TransportBound {
                        transport: id,
                        protocol: resolved,
                        local: advertised,
                        remote: connected,
                    },
                    now,
                )
                .map_err(|error| received_badly(&error))?;
            state.transports.record(transport, resolved);
            if transport == SIPRAL_TRANSPORT_MAIN {
                state.local = advertised;
            }
            // a datagram transport is kept mapped from the address it is
            // bound at now, and not from the one it had before
            crate::nat::Nat::bound(state, id, resolved, advertised, now);
            if !out_transport_id.is_null() {
                unsafe { out_transport_id.write(transport) };
            }
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
    /// It is also the answer to a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` the
    /// application could not honour: a failure told of a transport that is
    /// not up — the number it would have bound the stream at, never bound or
    /// retired — while the stack waits for that stream is a connection that
    /// could not be opened, and every request waiting for it stops waiting
    /// now (RFC 3261 §18.1.1: trimmed into a datagram when it then fits,
    /// ended with a 513 naming the limit otherwise). A number never bound is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` while nothing is waiting.
    ///
    /// The next poll raises `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` for it, ahead
    /// of what the failure did to the registrations and calls on it.
    /// [`sipral_stack_transport_failed_with`] is the same call with the TLS
    /// library's reason carried along.
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
        let error = error_named(error)?;
        with_stack_at(stack, now_ms, |state, now| {
            lose(
                state,
                transport,
                error,
                SipralTlsFailure::None,
                String::new(),
                now,
            )
        })
    }
}

entry! {
    /// Say that a transport failed, and why, in the words of the TLS library
    /// that refused it.
    ///
    /// Everything [`sipral_stack_transport_failed`] does — the transport is
    /// retired, the transactions on it fail, nothing is sent on it until
    /// [`sipral_stack_transport_bind`] brings it back — and the reason is
    /// carried to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: `failure->tls` for a
    /// machine to switch on, `failure->detail` for a person to read. A
    /// connection that never got as far as a handshake is told here too, so
    /// that the application hears about it in the one place it hears about
    /// every other loss; retiring a transport that carried nothing yet costs
    /// nothing, and the bind that follows the reconnect undoes it. A
    /// transport already down is not retired twice, and the failure is still
    /// raised: that is how each attempt to connect again that fails is told.
    /// A stream a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for and that
    /// could not be opened is told here as well, as
    /// [`sipral_stack_transport_failed`] says.
    ///
    /// A TLS reason on a transport that does not speak TLS or WSS is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, and so is a detail longer than
    /// [`SIPRAL_TRANSPORT_DETAIL_BYTES`] or not UTF-8; nothing is retired.
    ///
    /// # Safety
    ///
    /// `failure` must point at a `sipral_transport_failure_t` whose `size`
    /// member says how long it is, and its `detail` must be readable for
    /// `detail_len` bytes.
    fn sipral_stack_transport_failed_with(
        stack: SipralHandle,
        failure: *const SipralTransportFailure,
        now_ms: u64,
    ) {
        let failure = unsafe { read_versioned(failure) }?;
        let error = error_named(failure.error)?;
        let tls = tls_named(failure.tls)?;
        let detail = unsafe { detail_of(failure.detail, failure.detail_len) }?;
        with_stack_at(stack, now_ms, |state, now| {
            if tls != SipralTlsFailure::None {
                let speaks = state.transports.protocol_of(failure.transport);
                if speaks.is_some_and(|protocol| !protocol.is_secure()) {
                    return Err(fail(
                        SipralStatus::InvalidArgument,
                        format!(
                            "transport {} speaks {}, and a TLS reason is for one that speaks \
                             TLS",
                            failure.transport,
                            speaks.map_or_else(String::new, |protocol| protocol.to_string())
                        ),
                    ));
                }
            }
            lose(state, failure.transport, error, tls, detail, now)
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
    /// one would have the two indistinguishable in a log for ever after. The
    /// event the next poll raises says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_stream_closed(stack: SipralHandle, transport: u32, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = named(state, transport)?;
            state
                .agent
                .receive(Input::StreamClosed { transport: id }, now)
                .map_err(|error| received_badly(&error))?;
            state.lost.push(Lost {
                transport,
                protocol: protocol_number(state, transport),
                error: SipralTransportError::Closed,
                tls: SipralTlsFailure::None,
                detail: String::new(),
            });
            Ok(())
        })
    }
}

/// Retire a transport, and queue the event that says so.
///
/// A failure told of a transport that is not up — one never bound, or one
/// already retired — is a connection that could not be opened. While the
/// stack is waiting for the stream a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`
/// asked for, that is the answer to it, and everything waiting stops
/// waiting now (`sipral_ua::UserAgent::stream_unavailable`). A number never
/// bound is refused when nothing is waiting, as it always was.
fn lose(
    state: &mut StackState,
    transport: u32,
    error: SipralTransportError,
    tls: SipralTlsFailure,
    detail: String,
    now: std::time::Instant,
) -> Result<(), Fail> {
    let waiting = state.agent.wants_a_stream();
    let Some(id) = state.transports.resolve(transport) else {
        if !waiting {
            return named(state, transport).map(|_| ());
        }
        state.agent.stream_unavailable(now);
        state.lost.push(Lost {
            transport,
            protocol: 0,
            error,
            tls,
            detail,
        });
        return Ok(());
    };
    let was_up = state.agent.endpoint().bound_transport(id).is_some();
    // a transport already down is not retired twice, and the failure is
    // still raised: an attempt to connect again that failed
    state
        .agent
        .receive(
            Input::TransportFailed {
                transport: id,
                error: kind_of(error),
            },
            now,
        )
        .map_err(|error| received_badly(&error))?;
    if waiting && !was_up {
        state.agent.stream_unavailable(now);
    }
    state.lost.push(Lost {
        transport,
        protocol: protocol_number(state, transport),
        error,
        tls,
        detail,
    });
    Ok(())
}

/// What a transport in the table speaks, as a `SipralTransport`.
fn protocol_number(state: &StackState, transport: u32) -> u32 {
    state
        .transports
        .protocol_of(transport)
        .map_or(0, SipralTransport::named)
}

/// The platform's sentence, as text this library keeps.
///
/// # Safety
///
/// `detail`, when it is not null, must be readable for `len` bytes.
unsafe fn detail_of(detail: *const c_char, len: usize) -> Result<String, Fail> {
    if len > SIPRAL_TRANSPORT_DETAIL_BYTES {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "detail is {len} bytes, and a transport failure's is at most \
                 {SIPRAL_TRANSPORT_DETAIL_BYTES}"
            ),
        ));
    }
    Ok(unsafe { crate::text::text(detail, len, "detail") }?
        .unwrap_or_default()
        .to_owned())
}

/// An address a caller may leave out, as one.
///
/// Left out is a length of zero, with the pointer null or not: what every
/// other optional piece of text in this ABI means by it, and the only way a
/// binding that hands every string over as a buffer — an empty one included
/// — has of saying "none".
///
/// # Safety
///
/// `pointer`, when it is not null, must be readable for `len` bytes.
pub(crate) unsafe fn optional_address(
    pointer: *const c_char,
    len: usize,
    name: &'static str,
) -> Result<Option<SocketAddr>, Fail> {
    if len == 0 {
        return Ok(None);
    }
    Ok(Some(unsafe { address(pointer, len, name) }?))
}

/// The transport a number names, or why it names none.
///
/// [`crate::lifecycle`] has the same check, as `transport_named`; it is not
/// `pub(crate)` here for that, and the reason not to share it is written
/// there.
pub(crate) fn named(state: &StackState, transport: u32) -> Result<TransportId, Fail> {
    state.transports.resolve(transport).ok_or_else(|| {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "transport {transport} is not one this stack has; sipral_stack_transport_bind \
                 is what adds one, and 0 is SIPRAL_TRANSPORT_MAIN, which every stack has from \
                 its creation"
            ),
        )
    })
}

/// Bytes a caller handed in, as a slice, or why they are not one.
///
/// # Safety
///
/// `data`, when it is not null, must be readable for `len` bytes.
pub(crate) unsafe fn arrived<'a>(
    data: *const u8,
    len: usize,
    what: &'static str,
) -> Result<&'a [u8], Fail> {
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
fn error_named(error: u32) -> Result<SipralTransportError, Fail> {
    match error {
        0 => Ok(SipralTransportError::Other),
        1 => Ok(SipralTransportError::ConnectionRefused),
        2 => Ok(SipralTransportError::ConnectionReset),
        3 => Ok(SipralTransportError::Unreachable),
        4 => Ok(SipralTransportError::TimedOut),
        5 => Ok(SipralTransportError::Closed),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{other} is not a transport error this library names"),
        )),
    }
}

/// What the layer below calls a failure.
const fn kind_of(error: SipralTransportError) -> TransportErrorKind {
    match error {
        SipralTransportError::Other => TransportErrorKind::Other,
        SipralTransportError::ConnectionRefused => TransportErrorKind::ConnectionRefused,
        SipralTransportError::ConnectionReset => TransportErrorKind::ConnectionReset,
        SipralTransportError::Unreachable => TransportErrorKind::Unreachable,
        SipralTransportError::TimedOut => TransportErrorKind::TimedOut,
        SipralTransportError::Closed => TransportErrorKind::Closed,
    }
}

/// What TLS failure a number names.
fn tls_named(tls: u32) -> Result<SipralTlsFailure, Fail> {
    match tls {
        0 => Ok(SipralTlsFailure::None),
        1 => Ok(SipralTlsFailure::Untrusted),
        2 => Ok(SipralTlsFailure::NameMismatch),
        3 => Ok(SipralTlsFailure::Expired),
        4 => Ok(SipralTlsFailure::HandshakeRefused),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{other} is not a TLS failure this library names"),
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
        SIPRAL_MESSAGE_BYTES, SIPRAL_TRANSPORT_DETAIL_BYTES, SIPRAL_TRANSPORT_MAIN,
        SipralTlsFailure, SipralTransmit, SipralTransportError, SipralTransportFailure,
        sipral_stack_poll_transmit, sipral_stack_receive_datagram, sipral_stack_receive_stream,
        sipral_stack_stream_closed, sipral_stack_transport_bind, sipral_stack_transport_failed,
        sipral_stack_transport_failed_with,
    };
    use crate::account::{SipralAccountConfig, sipral_account_add, sipral_account_register};
    use crate::error::last_error_text;
    use crate::event::{SipralEventKind, SipralRegistrationState};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::header::SipralHeader;
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

    /// The same, keeping where each one was going: what a test that is about
    /// an address rather than a message needs.
    pub(crate) fn drain_addressed(stack: SipralHandle) -> Vec<(Vec<u8>, String)> {
        let mut buffers = Buffers::new();
        let mut all = Vec::new();
        loop {
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return all;
            }
            let (message, destination, _) = buffers.taken(&transmit);
            all.push((message, destination));
        }
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
            headers: ptr::null(),
            headers_len: 0,
            transport: 0,
            push_provider: ptr::null(),
            push_provider_len: 0,
            push_prid: ptr::null(),
            push_prid_len: 0,
            push_param: ptr::null(),
            push_param_len: 0,
            push_wakes_itself: 0,
            quality_report_uri: ptr::null(),
            quality_report_uri_len: 0,
            session_timer: 0,
            session_interval_seconds: 0,
            privacy: 0,
            trusted_peers: ptr::null(),
            trusted_peers_len: 0,
            srtp: 0,
            srtp_suites: ptr::null(),
            srtp_suites_len: 0,
            stir_verification: 0,
            stir_key: ptr::null(),
            stir_key_len: 0,
            stir_certificate_url: ptr::null(),
            stir_certificate_url_len: 0,
            stir_orig: ptr::null(),
            stir_orig_len: 0,
            stir_origid: ptr::null(),
            stir_origid_len: 0,
            stir_attestation: 0,
            recording_in_clear: 0,
        }
    }

    fn line(stack: SipralHandle) -> SipralHandle {
        let config = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(stack, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    /// An account like [`line`]'s, but its own `aor`, pointed at `transport`
    /// and answering at `registrar` instead of the shared [`REGISTRAR`], so
    /// that two of these on one stack never share an identity or a wire.
    fn line_on(
        stack: SipralHandle,
        transport: u32,
        aor: &'static str,
        registrar: &'static str,
    ) -> SipralHandle {
        let text = |value: &'static str| (value.as_ptr().cast::<c_char>(), value.len());
        let (aor, aor_len) = text(aor);
        let (registrar_address, registrar_address_len) = text(registrar);
        let config = SipralAccountConfig {
            aor,
            aor_len,
            registrar_address,
            registrar_address_len,
            transport,
            ..account_config()
        };
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

    /// `to` left out as an empty buffer rather than a null pointer is left
    /// out all the same, as every other optional text in this ABI is: a
    /// binding that hands every string over as a buffer has no null to pass,
    /// and was refused for passing the one thing it could.
    #[test]
    fn an_empty_arrival_address_is_no_address_whatever_its_pointer() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let options = options("options-3");
        let nothing = [0_u8; 1];
        let status = unsafe {
            sipral_stack_receive_datagram(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                options.as_ptr(),
                options.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                nothing.as_ptr().cast::<c_char>(),
                0,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (_, _, from) = take_one(handle);
        assert_eq!(from, BIND, "the address the stack was created with");
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

    /// A request the parser refuses still gets an answer out of the ABI, the
    /// way it would out of the core, and the status the caller gets back says
    /// what was refused.
    #[test]
    fn a_request_past_a_parser_bound_is_answered_and_the_status_says_why() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let long = options("options-long").replace(
            "Max-Forwards: 70\r\n",
            &format!("Max-Forwards: 70\r\nSubject: {}\r\n", "s".repeat(20_000)),
        );
        assert_eq!(
            feed(handle, REGISTRAR, long.as_bytes(), 1_000),
            SipralStatus::InvalidArgument
        );
        assert!(last_error_text().contains("16384"), "{}", last_error_text());
        let (answer, to, _) = take_one(handle);
        assert!(
            answer.starts_with(b"SIP/2.0 400 Subject Too Long (limit 16384 bytes)\r\n"),
            "{}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(to, REGISTRAR);
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
                    0,
                    moved.as_ptr().cast::<c_char>(),
                    moved.len(),
                    ptr::null(),
                    0,
                    1_200,
                    ptr::null_mut(),
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
                0,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                1_000,
                ptr::null_mut(),
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
                        0,
                        local,
                        local_len,
                        ptr::null(),
                        0,
                        1_000,
                        ptr::null_mut(),
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

    /// The size is checked before the handle is even looked up: a stack that
    /// was never created and a transmit struct too short to be any version of
    /// this one both fail, and the size is the one this answers with.
    #[test]
    fn a_transmit_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        transmit.size =
            <crate::transport::SipralTransmit as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_stack_poll_transmit(SIPRAL_HANDLE_NONE, &raw mut transmit) },
            SipralStatus::UnsupportedVersion
        );
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
                0,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                1_100,
                ptr::null_mut(),
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
                    0,
                    BIND.as_ptr().cast::<c_char>(),
                    BIND.len(),
                    ptr::null(),
                    0,
                    0,
                    ptr::null_mut(),
                )
            },
            SipralStatus::InvalidHandle
        );
    }

    // -- 8.4.10: a table of transports ---------------------------------------

    fn header_of(name: &'static str, value: &str) -> SipralHeader {
        let (name_ptr, name_len) = (name.as_ptr().cast::<c_char>(), name.len());
        SipralHeader {
            name: name_ptr,
            name_len,
            value: value.as_ptr().cast::<c_char>(),
            value_len: value.len(),
        }
    }

    /// A transport this stack has never bound is refused, and opening one
    /// needs a protocol — the two ways `sipral_stack_transport_bind` can fail
    /// before it ever touches the layer below.
    #[test]
    fn a_new_transport_needs_a_protocol_and_an_existing_one_keeps_the_one_it_has() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);

        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                9,
                0,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                ptr::null(),
                0,
                1_000,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("protocol"),
            "{}",
            last_error_text()
        );

        // main already speaks UDP; asking it to speak TLS instead is refused
        // rather than quietly changing the transport underneath its timers
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                SipralTransport::Tls as u32,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                ptr::null(),
                0,
                1_000,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("UDP") && last_error_text().contains("TLS"),
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The acceptance test the task names: two accounts, two transports, one
    /// stack, and each account's own traffic leaves on the transport it was
    /// given — not on the other account's, and not on the stack's main one,
    /// which neither of them uses at all.
    #[test]
    fn two_accounts_on_two_transports_each_leave_on_their_own() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let first = "203.0.113.9:5061";
        let second = "203.0.113.10:5061";

        for (id, remote) in [(1_u32, first), (2_u32, second)] {
            let mut bound = u32::MAX;
            let status = unsafe {
                sipral_stack_transport_bind(
                    handle,
                    id,
                    SipralTransport::Tls as u32,
                    BIND.as_ptr().cast::<c_char>(),
                    BIND.len(),
                    remote.as_ptr().cast::<c_char>(),
                    remote.len(),
                    1_000,
                    &raw mut bound,
                )
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            assert_eq!(
                bound, id,
                "the id handed back is the one that was asked for"
            );
        }

        let alice = line_on(handle, 1, "sip:alice@example.com", first);
        let bob = line_on(handle, 2, "sip:bob@example.com", second);
        assert_eq!(
            unsafe { sipral_account_register(handle, alice, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_account_register(handle, bob, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_100);

        let mut on_one = 0;
        let mut on_two = 0;
        loop {
            let mut buffers = Buffers::new();
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                break;
            }
            let (bytes, _, _) = buffers.taken(&transmit);
            assert!(bytes.starts_with(b"REGISTER "), "{:?}", start_of(&bytes));
            match transmit.transport {
                1 => on_one += 1,
                2 => on_two += 1,
                other => panic!("a message left on transport {other}, which neither account is on"),
            }
        }
        assert_eq!(
            on_one, 1,
            "alice's REGISTER did not leave on her own transport"
        );
        assert_eq!(
            on_two, 1,
            "bob's REGISTER did not leave on his own transport"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What a [`SipralEventKind::TransportWanted`] carried, copied out while
    /// the callback was still running: the pointers in an event are the
    /// library's and are valid for exactly that long.
    #[derive(Default)]
    struct Wanted {
        seen: Vec<(u32, String, usize, u32)>,
    }

    unsafe extern "C" fn keep_wanted(
        event: *const crate::event::SipralEvent,
        user_data: *mut std::ffi::c_void,
    ) {
        let wanted = unsafe { &mut *user_data.cast::<Wanted>() };
        let event = unsafe { &*event };
        if event.kind != SipralEventKind::TransportWanted {
            return;
        }
        let payload = unsafe { event.payload.transport_wanted };
        let destination = if payload.destination.is_null() {
            String::new()
        } else {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    payload.destination.cast::<u8>(),
                    payload.destination_len,
                )
            };
            String::from_utf8_lossy(bytes).into_owned()
        };
        wanted.seen.push((
            payload.protocol,
            destination,
            payload.request_bytes,
            payload.limit_bytes,
        ));
    }

    /// B1, driven from C alone and end to end: a REGISTER too large for the
    /// datagram it would have gone out on raises
    /// `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` naming where it was going and
    /// over what protocol, nothing is put on the wire for it, the
    /// application binds exactly that, and the very same call succeeds and
    /// leaves on the transport it just bound.
    #[test]
    fn a_request_too_large_for_a_datagram_is_promoted_once_a_stream_is_bound() {
        let mut observed = Observed::default();
        let mut wanted = Wanted::default();
        let mut settings = config(keep_wanted, &mut observed);
        settings.event_user_data = ptr::from_mut(&mut wanted).cast::<std::ffi::c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let padding = "x".repeat(1_400);
        let fields = [header_of("X-Padding", &padding)];
        let account_settings = SipralAccountConfig {
            headers: fields.as_ptr(),
            headers_len: fields.len(),
            ..account_config()
        };
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_account_add(handle, ptr::from_ref(&account_settings), &raw mut account)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::NotSent,
            "a REGISTER this large does not fit a datagram and nothing was open to move it to: \
             {}",
            last_error_text()
        );
        poll(handle, 1_000);
        assert!(
            drain(handle).is_empty(),
            "nothing this large was ever put on the wire"
        );

        let (protocol, destination, request_bytes, limit_bytes) = wanted
            .seen
            .first()
            .cloned()
            .expect("SIPRAL_EVENT_KIND_TRANSPORT_WANTED was never raised");
        assert_eq!(protocol, SipralTransport::Tcp as u32);
        assert_eq!(destination, REGISTRAR);
        assert!(
            request_bytes > usize::try_from(limit_bytes).unwrap_or(0),
            "{request_bytes} against a limit of {limit_bytes}"
        );

        let mut bound = u32::MAX;
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                7,
                protocol,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                destination.as_ptr().cast::<c_char>(),
                destination.len(),
                1_100,
                &raw mut bound,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(bound, 7);

        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_200) },
            SipralStatus::Ok,
            "the same call succeeds now that the stream it asked for exists: {}",
            last_error_text()
        );
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        let status = unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(transmit.len, 0, "the stack had nothing to send");
        assert_eq!(transmit.transport, 7, "it left on the transport just bound");
        let (out, to, _) = buffers.taken(&transmit);
        assert!(out.starts_with(b"REGISTER "), "{:?}", start_of(&out));
        assert_eq!(to, REGISTRAR);
        assert!(
            String::from_utf8_lossy(&out).contains("X-Padding"),
            "the same oversized request went out, not a smaller one"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What a TLS library refused, as the application hands it over.
    fn refused(transport: u32, tls: SipralTlsFailure, detail: &str) -> SipralTransportFailure {
        SipralTransportFailure {
            size: size_of::<SipralTransportFailure>(),
            transport,
            error: SipralTransportError::ConnectionReset as u32,
            tls: tls as u32,
            detail: detail.as_ptr().cast::<c_char>(),
            detail_len: detail.len(),
        }
    }

    fn rebind(handle: SipralHandle, now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_transport_bind(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                0,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                now_ms,
                ptr::null_mut(),
            )
        }
    }

    /// The TLS library's reason reaches the event whole, and the event comes
    /// before the registration that failed with the connection.
    #[test]
    fn a_tls_refusal_is_raised_with_its_reason_before_what_it_did() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tls);
        assert_eq!(
            rebind(handle, 900),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        poll(handle, 1_000);
        drain(handle);
        let seen = observed.events.len();

        let said = "certificate verify failed: certificate has expired";
        let failure = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::Expired, said);
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const failure, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(
            observed.transports_lost.is_empty(),
            "nothing is said inside the call"
        );
        poll(handle, 1_100);
        assert_eq!(
            observed.transports_lost,
            [(
                SIPRAL_TRANSPORT_MAIN,
                SipralTransport::Tls as u32,
                SipralTransportError::ConnectionReset as u32,
                SipralTlsFailure::Expired as u32,
                said.to_owned(),
            )]
        );
        let after: Vec<SipralEventKind> = observed.kinds()[seen..].to_vec();
        assert_eq!(
            after.first(),
            Some(&SipralEventKind::TransportFailed),
            "{after:?}"
        );
        assert!(
            after.contains(&SipralEventKind::RegistrationChanged),
            "the registration on it failed with it: {after:?}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A request asked for while the transport is down is refused as that,
    /// not as a request that could not be built, and goes once it is back.
    #[test]
    fn a_request_on_a_transport_that_is_down_is_refused_until_it_is_bound_again() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tls);
        assert_eq!(rebind(handle, 900), SipralStatus::Ok);
        let account = line(handle);
        let failure = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::Untrusted, "");
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const failure, 1_000) },
            SipralStatus::Ok
        );
        poll(handle, 1_000);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_100) },
            SipralStatus::TransportDown,
            "{}",
            last_error_text()
        );
        assert!(drain(handle).is_empty(), "nothing went out");
        assert_eq!(
            observed.transports_lost.first().map(|lost| lost.4.clone()),
            Some(String::new()),
            "no detail was given and none is invented"
        );

        assert_eq!(rebind(handle, 1_200), SipralStatus::Ok);
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

    /// The two older calls raise the same event, with no TLS reason, and an
    /// orderly close says closed.
    #[test]
    fn a_failure_and_a_close_told_the_old_way_are_raised_too() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tcp);
        assert_eq!(
            unsafe {
                sipral_stack_transport_failed(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    SipralTransportError::ConnectionRefused as u32,
                    1_000,
                )
            },
            SipralStatus::Ok
        );
        poll(handle, 1_000);
        assert_eq!(rebind(handle, 1_100), SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_stream_closed(handle, SIPRAL_TRANSPORT_MAIN, 1_200) },
            SipralStatus::Ok
        );
        poll(handle, 1_200);
        let tcp = SipralTransport::Tcp as u32;
        let refused_code = SipralTransportError::ConnectionRefused as u32;
        let closed_code = SipralTransportError::Closed as u32;
        assert_eq!(
            observed.transports_lost,
            [
                (0, tcp, refused_code, 0, String::new()),
                (0, tcp, closed_code, 0, String::new()),
            ]
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Every attempt to connect again that fails is raised, the transport
    /// down since the first, whichever of the two calls tells it.
    #[test]
    fn each_attempt_to_connect_again_that_fails_is_raised() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tls);
        let untrusted = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::Untrusted, "first");
        let expired = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::Expired, "second");
        for (failure, at) in [(&untrusted, 1_000), (&expired, 2_000)] {
            assert_eq!(
                unsafe { sipral_stack_transport_failed_with(handle, failure, at) },
                SipralStatus::Ok,
                "{}",
                last_error_text()
            );
            poll(handle, at);
        }
        let reasons: Vec<(u32, String)> = observed
            .transports_lost
            .iter()
            .map(|lost| (lost.3, lost.4.clone()))
            .collect();
        assert_eq!(
            reasons,
            [
                (SipralTlsFailure::Untrusted as u32, "first".to_owned()),
                (SipralTlsFailure::Expired as u32, "second".to_owned()),
            ]
        );
        assert_eq!(
            unsafe { sipral_stack_transport_failed(handle, SIPRAL_TRANSPORT_MAIN, 0, 3_000) },
            SipralStatus::Ok
        );
        poll(handle, 3_000);
        assert_eq!(observed.transports_lost.len(), 3);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A stream that loses its framing is a transport lost like any other,
    /// and said the same way.
    #[test]
    fn a_stream_that_carried_garbage_is_raised_as_lost() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tls);
        let garbage = b"\x16\x03\x01 this is a TLS record read as SIP\r\n\r\n";
        let status = unsafe {
            sipral_stack_receive_stream(
                handle,
                SIPRAL_TRANSPORT_MAIN,
                garbage.as_ptr(),
                garbage.len(),
                1_000,
            )
        };
        assert_ne!(status, SipralStatus::Ok);
        poll(handle, 1_000);
        assert_eq!(
            observed.transports_lost.len(),
            1,
            "{:?}",
            observed.transports_lost
        );
        let (transport, protocol, error, tls, detail) = observed.transports_lost[0].clone();
        assert_eq!(transport, SIPRAL_TRANSPORT_MAIN);
        assert_eq!(protocol, SipralTransport::Tls as u32);
        assert_eq!(error, SipralTransportError::Other as u32);
        assert_eq!(tls, SipralTlsFailure::None as u32);
        assert!(detail.contains("no message starts with"), "{detail}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A TLS reason is refused on a transport that has no TLS in it, and so
    /// is a detail too long, a reason with no name and a transport this
    /// stack does not have; none of them retires anything.
    #[test]
    fn a_failure_that_cannot_be_what_it_says_retires_nothing() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tcp);
        let mismatched = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::NameMismatch, "");
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const mismatched, 1_000) },
            SipralStatus::InvalidArgument
        );
        assert!(last_error_text().contains("TLS"), "{}", last_error_text());

        let long = "x".repeat(SIPRAL_TRANSPORT_DETAIL_BYTES + 1);
        let too_long = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::None, &long);
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const too_long, 1_000) },
            SipralStatus::InvalidArgument
        );
        let mut unknown = refused(SIPRAL_TRANSPORT_MAIN, SipralTlsFailure::None, "");
        unknown.tls = 9;
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const unknown, 1_000) },
            SipralStatus::InvalidArgument
        );
        let elsewhere = refused(7, SipralTlsFailure::None, "");
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const elsewhere, 1_000) },
            SipralStatus::InvalidArgument
        );
        poll(handle, 1_000);
        assert!(observed.transports_lost.is_empty());
        let account = line(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_100) },
            SipralStatus::Ok,
            "the transport is still up: {}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What a call challenged past RFC 3261 §18.1.1's line said, copied out
    /// while the callback ran: the stream asked for, and how the call ended.
    #[derive(Default)]
    struct Outgrown {
        wanted: Vec<(u32, String, usize, u32)>,
        ended: Vec<(u32, u32, u32, String)>,
        lost: Vec<(u32, u32)>,
    }

    unsafe extern "C" fn keep_outgrown(
        event: *const crate::event::SipralEvent,
        user_data: *mut std::ffi::c_void,
    ) {
        let seen = unsafe { &mut *user_data.cast::<Outgrown>() };
        let event = unsafe { &*event };
        let text = |pointer: *const u8, len: usize| {
            if pointer.is_null() {
                String::new()
            } else {
                String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(pointer, len) })
                    .into_owned()
            }
        };
        match event.kind {
            SipralEventKind::TransportWanted => {
                let payload = unsafe { event.payload.transport_wanted };
                seen.wanted.push((
                    payload.protocol,
                    text(payload.destination.cast::<u8>(), payload.destination_len),
                    payload.request_bytes,
                    payload.limit_bytes,
                ));
            }
            SipralEventKind::CallEnded => {
                let payload = unsafe { event.payload.call };
                seen.ended.push((
                    payload.end_reason,
                    payload.status_code,
                    payload.cause_sip,
                    text(payload.cause_text, payload.cause_text_len),
                ));
            }
            SipralEventKind::TransportFailed => {
                let payload = unsafe { event.payload.transport_failed };
                seen.lost.push((payload.transport, payload.error));
            }
            _ => {}
        }
    }

    /// A stack whose call a PBX has just challenged with a nonce long enough
    /// that the answer outgrows a datagram, driven through the C ABI alone.
    fn challenged_past_the_line(seen: &mut Outgrown) -> SipralHandle {
        let mut observed = Observed::default();
        let mut settings = config(keep_outgrown, &mut observed);
        settings.event_user_data = ptr::from_mut(seen).cast::<std::ffi::c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = line(handle);
        let (status, _) =
            crate::call::tests::place(handle, account, &crate::call::tests::call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (invite, to, _) = take_one(handle);
        assert!(invite.starts_with(b"INVITE "), "{}", start_of(&invite));
        assert_eq!(to, REGISTRAR);
        let nonce = "n".repeat(1_200);
        let to_tagged = format!(
            "{};tag=pbx",
            String::from_utf8_lossy(&header(&invite, HeaderName::To))
        );
        let challenge = reply(
            &invite,
            401,
            "Unauthorized",
            &format!(
                "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"{nonce}\", \
                 qop=\"auth\"\r\n"
            ),
        );
        // the To of a UAS's refusal carries its tag
        let challenge = String::from_utf8_lossy(&challenge).replacen(
            &format!(
                "To: {}",
                String::from_utf8_lossy(&header(&invite, HeaderName::To))
            ),
            &format!("To: {to_tagged}"),
            1,
        );
        assert_eq!(
            feed(handle, REGISTRAR, challenge.as_bytes(), 1_010),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_010);
        let out = drain(handle);
        assert!(
            out.iter().all(|message| message.starts_with(b"ACK ")),
            "only the ACK to the refusal went: {:?}",
            out.iter()
                .map(|message| start_of(message))
                .collect::<Vec<_>>()
        );
        handle
    }

    /// RFC 3261 §18.1.1 on the answer to a challenge, as a C application sees
    /// it: `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` with both sizes, and once the
    /// application binds the stream, the retry on it with a `Via` that says so,
    /// without the call being placed again.
    #[test]
    fn a_challenged_call_whose_answer_outgrew_the_datagram_goes_on_the_stream_bound_for_it() {
        let mut seen = Outgrown::default();
        let handle = challenged_past_the_line(&mut seen);
        let (protocol, destination, request_bytes, limit_bytes) = seen
            .wanted
            .first()
            .cloned()
            .expect("SIPRAL_EVENT_KIND_TRANSPORT_WANTED was raised");
        assert_eq!(protocol, SipralTransport::Tcp as u32);
        assert_eq!(destination, REGISTRAR);
        assert_eq!(limit_bytes, 1_300);
        assert!(request_bytes > 1_300, "{request_bytes}");
        assert!(seen.ended.is_empty(), "the call is still being placed");

        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                2,
                protocol,
                "192.0.2.10:49152".as_ptr().cast::<c_char>(),
                "192.0.2.10:49152".len(),
                destination.as_ptr().cast::<c_char>(),
                destination.len(),
                1_050,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        poll(handle, 1_050);
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        let status = unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(transmit.transport, 2, "the retry went on the stream");
        assert_eq!(transmit.protocol, SipralTransport::Tcp as u32);
        let (retry, to, _) = buffers.taken(&transmit);
        assert!(retry.starts_with(b"INVITE "), "{}", start_of(&retry));
        assert_eq!(to, REGISTRAR);
        assert!(
            retry.len() > 1_300,
            "the whole request, over the line: {}",
            retry.len()
        );
        assert!(
            header(&retry, HeaderName::Via).starts_with(b"SIP/2.0/TCP 192.0.2.10:49152;"),
            "{}",
            String::from_utf8_lossy(&header(&retry, HeaderName::Via))
        );
        assert!(!header(&retry, HeaderName::Authorization).is_empty());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// And when the application cannot open that stream, it says so on the
    /// number it would have bound, and the call ends on that poll with the
    /// limit named rather than hanging.
    #[test]
    fn a_stream_that_could_not_be_opened_ends_the_call_waiting_for_it_with_the_limit_named() {
        let mut seen = Outgrown::default();
        let handle = challenged_past_the_line(&mut seen);
        let request_bytes = seen.wanted.first().map(|wanted| wanted.2).expect("wanted");
        assert_eq!(
            unsafe {
                sipral_stack_transport_failed(
                    handle,
                    2,
                    SipralTransportError::ConnectionRefused as u32,
                    1_060,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_060);
        assert_eq!(
            seen.lost,
            vec![(2, SipralTransportError::ConnectionRefused as u32)],
            "the refused connection is told like any other"
        );
        assert_eq!(seen.ended.len(), 1, "the call ended on this poll");
        let (reason, status, cause, text) = seen.ended[0].clone();
        assert_eq!(
            reason,
            crate::event::SipralCallEndReason::Unreachable as u32
        );
        assert_eq!(status, 513);
        assert_eq!(cause, 513);
        assert!(text.contains(&format!("{request_bytes} bytes")), "{text}");
        assert!(text.contains("1300-byte"), "{text}");
        assert!(drain(handle).is_empty(), "nothing went");
        // nothing waits any more, so a number never bound is refused again
        assert_eq!(
            unsafe { sipral_stack_transport_failed(handle, 2, 0, 1_070) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Polls to `to_ms`, takes everything the stack wants written, and says
    /// whether a keep-alive ping was among it on `transport`.
    fn pinged_on(handle: SipralHandle, transport: u32, to_ms: u64) -> bool {
        poll(handle, to_ms);
        let mut pinged = false;
        let mut buffers = Buffers::new();
        loop {
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return pinged;
            }
            let (payload, _, _) = buffers.taken(&transmit);
            pinged |= transmit.transport == transport && payload == b"\r\n\r\n";
        }
    }

    /// RFC 5626 §4.4.1 on a stream a C application opened: once the far end
    /// has answered a ping and then leaves one unanswered for ten seconds, the
    /// stack retires the transport, and the application that holds the
    /// socket hears it as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` rather than
    /// not at all.
    #[test]
    fn a_stream_the_stack_calls_dead_is_told_as_a_transport_failed() {
        let mut seen = Outgrown::default();
        let handle = challenged_past_the_line(&mut seen);
        let (protocol, destination, _, _) = seen.wanted.first().cloned().expect("wanted");
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                2,
                protocol,
                "192.0.2.10:49152".as_ptr().cast::<c_char>(),
                "192.0.2.10:49152".len(),
                destination.as_ptr().cast::<c_char>(),
                destination.len(),
                1_050,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        drain(handle);

        // the first ping is due twenty to twenty-five seconds in, and answered
        assert!(pinged_on(handle, 2, 1_050 + 25_000), "the first ping");
        let pong = b"\r\n";
        assert_eq!(
            unsafe {
                sipral_stack_receive_stream(handle, 2, pong.as_ptr(), pong.len(), 1_050 + 25_040)
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(seen.lost.is_empty(), "{:?}", seen.lost);
        // the second is not, and ten seconds after it the flow is dead
        assert!(pinged_on(handle, 2, 1_050 + 50_000), "the second ping");
        poll(handle, 1_050 + 60_000);
        assert_eq!(
            seen.lost,
            vec![(2, SipralTransportError::TimedOut as u32)],
            "the application is told which transport the stack let go"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A C application that never answers the event is not left with a call
    /// that hangs: the wait runs out on the stack's own clock.
    #[test]
    fn a_stream_nobody_opens_ends_the_call_when_the_wait_runs_out() {
        let mut seen = Outgrown::default();
        let handle = challenged_past_the_line(&mut seen);
        let wait = u64::try_from(sipral_ua::STREAM_WAIT.as_millis()).expect("milliseconds");
        poll(handle, 1_010 + wait - 1);
        assert!(seen.ended.is_empty(), "not yet");
        poll(handle, 1_010 + wait);
        assert_eq!(seen.ended.len(), 1);
        assert_eq!(seen.ended[0].1, 513);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
