// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Signalling across the boundary: bytes out, bytes in, and news about the socket.
//!
//! There is no socket here. The application writes what [`sipral_stack_poll_transmit`] hands
//! out, hands in datagrams ([`sipral_stack_receive_datagram`]) and stream reads
//! ([`sipral_stack_receive_stream`]), and reports a dead transport
//! ([`sipral_stack_transport_failed`]), a closed connection ([`sipral_stack_stream_closed`])
//! and a reopened one ([`sipral_stack_transport_bind`]).
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
//! A call's audio uses the four calls in [`crate::media`] on its own socket.
//!
//! The loop order is the contract: both polling and handing bytes in produce messages, so
//! both are followed by draining. A produced message waits until taken; nothing committed
//! is dropped, and a poll in between leaves the queue alone.
//!
//! # A table of transports, and the main one named
//!
//! A stack starts with [`SIPRAL_TRANSPORT_MAIN`]. [`sipral_stack_transport_bind`] adds more
//! under numbers the caller chooses; `transport` on `sipral_account_config_t` and
//! `sipral_call_config_t` selects one, zero meaning main. A call's `transport` is read only
//! with an explicit `destination`. The table only grows: a failed or closed transport stops
//! carrying traffic and resumes when bound again, without touching its accounts.
//!
//! A request too large for a datagram (RFC 3261 §18.1.1) raises
//! [`crate::event::SipralEventKind::TransportWanted`] and the call that asked is refused with
//! `SIPRAL_STATUS_NOT_SENT`. The application binds the stream and asks again; no separate
//! "sent" event follows. An oversized challenge answer is retried by the stack itself once
//! the bind succeeds. If the stream cannot be opened, [`sipral_stack_transport_failed`] or
//! [`sipral_stack_transport_failed_with`] on the intended number ends the wait: an INVITE is
//! retried over the datagram with one SDES suite per stream if that fits, otherwise the call
//! ends with `SIPRAL_CALL_END_REASON_UNREACHABLE` and `cause_sip` 513 (a registration fails
//! the same way). Silence gets the same after ten seconds (`sipral_ua::STREAM_WAIT`).
//!
//! # A datagram, a stream, and a WebSocket
//!
//! A datagram carries one message and its source. Stream bytes are fragments, framed below
//! on `Content-Length` (§18.3), with no addresses: the far end was named at bind time.
//!
//! A WebSocket bound as `SIPRAL_TRANSPORT_WS` or `SIPRAL_TRANSPORT_WSS` *with* `remote` is
//! run by the stack (RFC 6455, RFC 7118): [`sipral_stack_poll_transmit`] first hands out the
//! handshake, reads go to [`sipral_stack_receive_stream`], and output is frames. Any
//! WebSocket failure retires the transport with `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`; close
//! the connection. Bound *without* `remote`, the application runs the WebSocket and hands
//! each frame in as a datagram (one message per frame, RFC 7118 §4.2). The handshake asks
//! for `/ws` with the far end as `Host`; the ABI cannot change either yet.
//!
//! # When a transport dies
//!
//! [`sipral_stack_transport_failed`] and [`sipral_stack_stream_closed`] retire the transport:
//! its transactions fail at once, effects are reported on the next poll, and nothing is sent
//! until [`sipral_stack_transport_bind`]. Do not call them for one refused `sendto`: an ICMP
//! unreachable is one destination, not the socket.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::ptr;
use std::slice;

use sipral_core::endpoint::{Input, ReceiveError, Transmit, TransportErrorKind, TransportId};

use crate::abi::{Number, codes, constants, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{SIPRAL_ADDRESS_BYTES, address};
use crate::stack::{SipralTransport, StackState, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, read_versioned, write_versioned};

constants! {
    /// The transport a stack is created with.
    ///
    /// Never removed from the table; failure stops it, [`sipral_stack_transport_bind`] restores
    /// it. Zero in `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
    /// means this one.
    pub const SIPRAL_TRANSPORT_MAIN: u32 = 0;

    /// The largest message that crosses in either direction.
    ///
    /// Bounds the parser's work against a hostile peer. Size stream read buffers to this; about
    /// 1500 bytes suffices on a datagram socket.
    pub const SIPRAL_MESSAGE_BYTES: usize = 65_535;

    /// The longest `sipral_transport_failure_t::detail` accepted. Longer is refused, not cut.
    pub const SIPRAL_TRANSPORT_DETAIL_BYTES: usize = 1_024;
}

codes! {
    /// Why a transport could not deliver. Names for [`sipral_stack_transport_failed`]'s `error`.
    ///
    /// Coarse on purpose: a client transaction terminates on every one of these (§17); the
    /// detail belongs in the caller's log.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTransportError: u32 {
        /// Anything the caller could not classify.
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
    /// Why a TLS connection was refused, as the platform's TLS library said it. Names for
    /// `sipral_transport_failure_t::tls` and `sipral_transport_failed_event_t::tls`.
    ///
    /// Sipral links no TLS library (`docs/22-tls.md`); the stack only carries the application's
    /// classification. A connection never answered is `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED`
    /// with this left at none.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTlsFailure: u32 {
        /// Not a TLS failure, or one the application could not classify.
        None = 0,
        /// No trusted authority: self-signed, an unprovided private CA, or not the pinned one.
        Untrusted = 1,
        /// The certificate is trusted and names another server.
        NameMismatch = 2,
        /// The certificate has expired, or is not valid yet.
        Expired = 3,
        /// The handshake failed: no common version or cipher, a server alert, or no TLS there.
        HandshakeRefused = 4,
    }
}

record! {
    /// One message on its way out, written into the caller's own buffers.
    ///
    /// The caller fills `size`, the three pointers and the three capacities; the library fills
    /// the rest. A `len` of zero means nothing to send, which ends the draining loop. Address
    /// buffers are checked before a message is taken. A payload buffer too small leaves the
    /// message queued and offered again: a committed message is never dropped.
    #[derive(Clone, Copy)]
    pub struct SipralTransmit {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Which transport to write to: [`SIPRAL_TRANSPORT_MAIN`], or a number
        /// [`sipral_stack_transport_bind`] bound for the owning account or call.
        pub transport: u32,
        /// What that transport speaks, as a `SipralTransport`. Per message, since §18.1.1
        /// can move a request onto a stream. Zero for a protocol with no ABI number.
        pub protocol: Number<SipralTransport>,
        /// Where to write the message. Nothing is written unless all of it fits.
        pub data: *mut u8,
        /// How much room `data` has.
        pub capacity: usize,
        /// How much was written, or after `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much is needed.
        pub len: usize,
        /// Where to write the destination, `host:port` with a trailing NUL. Null with capacity zero
        /// for a connected socket.
        pub destination: *mut c_char,
        /// Room in `destination`: at least [`SIPRAL_ADDRESS_BYTES`] when not null.
        pub destination_capacity: usize,
        /// How many bytes of it were written, the NUL not counted.
        pub destination_len: usize,
        /// Where to write the address to send *from*, in the same shape. RFC 3581 §4: a response
        /// leaves from the address its request arrived on, which a wildcard listener cannot tell.
        /// `source_len` zero means the transport's own address.
        pub source: *mut c_char,
        /// Room in `source`: at least [`SIPRAL_ADDRESS_BYTES`] when not null.
        pub source_capacity: usize,
        /// How many bytes of it were written, the NUL not counted.
        pub source_len: usize,
    }
}

// Safety: plain data with no invariant between members. The pointers are caller buffers;
// all-zero is refused when read, not undefined.
unsafe impl Versioned for SipralTransmit {
    const NAME: &'static str = "sipral_transmit";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralTransmit, source_len);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// A failed transport and why, for [`sipral_stack_transport_failed_with`]. All caller-filled;
    /// `detail` is the platform's own optional sentence, passed through unparsed.
    #[derive(Clone, Copy)]
    pub struct SipralTransportFailure {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Which transport: [`SIPRAL_TRANSPORT_MAIN`] or a bound number.
        pub transport: u32,
        /// A [`SipralTransportError`].
        pub error: Number<SipralTransportError>,
        /// A [`SipralTlsFailure`]; `SIPRAL_TLS_FAILURE_NONE` unless TLS refused.
        pub tls: Number<SipralTlsFailure>,
        /// The platform's words, not NUL-terminated. Null with length zero for none.
        pub detail: *const c_char,
        /// How many bytes of it; at most [`SIPRAL_TRANSPORT_DETAIL_BYTES`].
        pub detail_len: usize,
    }
}

// Safety: plain data; the one pointer is the caller's and is read only during the call.
unsafe impl Versioned for SipralTransportFailure {
    const NAME: &'static str = "sipral_transport_failure";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralTransportFailure, detail_len);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: a signalling transport stopped carrying traffic.
    /// The text is the library's, valid during the callback.
    #[derive(Clone, Copy)]
    pub struct SipralTransportFailedEvent {
        /// Which transport: [`SIPRAL_TRANSPORT_MAIN`] or a bound number.
        pub transport: u32,
        /// What it spoke, as a `SipralTransport`.
        pub protocol: Number<SipralTransport>,
        /// A [`SipralTransportError`]; `SIPRAL_TRANSPORT_ERROR_CLOSED` for a closed connection.
        pub error: Number<SipralTransportError>,
        /// A [`SipralTlsFailure`], when TLS refused.
        pub tls: Number<SipralTlsFailure>,
        /// The platform's sentence as handed over. Null with length zero for none.
        pub detail: *const c_char,
        /// How many bytes of it.
        pub detail_len: usize,
    }
}

/// A lost transport, raised on the next poll before the transaction failures it caused.
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
    /// Loop until `len` is zero, after every `sipral_stack_poll` and every call that hands bytes
    /// in. A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the needed
    /// length in `len` and is kept for the next call, ahead of the queue; a null `data` with
    /// capacity zero thus asks for the length.
    ///
    /// # Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is and
    /// whose buffers are writable for the capacities beside them.
    fn sipral_stack_poll_transmit(stack: SipralHandle, transmit: *mut SipralTransmit) {
        let mut out = unsafe { read_versioned(transmit) }?;
        prepare(&mut out)?;
        with_stack(stack, |state| {
            // a STUN request leaves by its socket's own transport, so the answer describes it
            let Some(pending) = state
                .held
                .take()
                .or_else(|| crate::nat::Nat::poll_signalling(state))
                .or_else(|| state.agent.poll_transmit())
            else {
                return Ok(());
            };
            if pending.payload.len() > out.capacity {
                out.len = pending.payload.len();
                state.held = Some(pending);
                return Ok(());
            }
            let put = unsafe { put(&mut out, &pending) };
            if put.is_err() {
                // already out of the queue; keep it rather than lose it
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

/// Check the address buffers are big enough and clear the library-written members, so stale
/// caller values never read as a produced message.
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
/// The buffers must be writable for their capacities, already checked by [`prepare`], and the
/// payload must fit.
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

/// Write one address, or an empty string. `None` for a buffer the caller did not bring.
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
        // unreachable: a bracketed IPv6 and port fit the promised room
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
    /// Hand over one datagram, whole, with its source.
    ///
    /// `from` is the far end as `host:port`. `to` is the receiving address, which the response
    /// leaves from (RFC 3581 §4); length zero means the stack's creation address. Frames from a
    /// WebSocket the application runs come here too (RFC 7118 §4.2).
    ///
    /// Non-SIP bytes are `SIPRAL_STATUS_INVALID_ARGUMENT` with the parse error as last error;
    /// only that packet is lost.
    ///
    /// # Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
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
            // a STUN answer from the server to this stack's own transaction is taken here; anything
            // else goes to the parser
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
    /// Hand over bytes read off a connection, in whatever sizes the reads came in.
    ///
    /// A fragment of the `Content-Length` framing (§18.3): may hold several messages or none. A
    /// stack-run WebSocket's handshake and frames come here too. Unreadable framing cannot be
    /// resynchronised: the transport is retired before `SIPRAL_STATUS_INVALID_ARGUMENT` returns;
    /// close the socket. A zero-byte read is [`sipral_stack_stream_closed`], not this.
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
            // the trace takes whole messages from the framing, only when tracing
            let tracing = state.log.enabled(sipral::LogLevel::Trace);
            state.agent.endpoint().tap_streams(tracing);
            let received = state
                .agent
                .receive(Input::StreamData { transport, data: read }, now);
            for framed in state.agent.endpoint().take_stream_messages() {
                let travel = sipral::Travel::Received;
                match framed.remote {
                    Some(remote) => state.log.sip_message(travel, remote, &framed.bytes, now),
                    None => state
                        .log
                        .sip_message_on_a_connection(travel, &framed.bytes, now),
                }
            }
            if let Err(ReceiveError::Malformed(ref broken)) = received {
                // the framing is lost and the endpoint dropped the transport: report it as a loss
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
    /// Say that a transport is open: the main one again, or a new one.
    ///
    /// The way back after [`sipral_stack_transport_failed`] and the way new transports enter the
    /// table. `transport` is [`SIPRAL_TRANSPORT_MAIN`] or any caller-chosen number; a known one
    /// is rebound, an unknown one opened. `out_transport_id`, if not null, receives the same
    /// number.
    ///
    /// `protocol` is a [`crate::stack::SipralTransport`]. On rebind, zero keeps the current
    /// protocol and anything different is `SIPRAL_STATUS_INVALID_ARGUMENT`: switching it under
    /// running RFC 3261 §17 timers is not allowed. Opening a new transport requires a protocol.
    ///
    /// `local` is the address the far end reaches, `host:port`. `remote` names a connection's far
    /// end, is refused on a datagram transport, and length zero omits it. On WS/WSS, `remote`
    /// makes the stack run the WebSocket: the handshake comes out of
    /// [`sipral_stack_poll_transmit`] and reads go to [`sipral_stack_receive_stream`].
    ///
    /// After a
    /// [`SipralEventKind::TransportWanted`](crate::event::SipralEventKind::TransportWanted),
    /// binding what it named and asking again sends the request on the new stream.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes, `remote` for `remote_len`, and
    /// `out_transport_id`, when it is not null, must point at one `uint32_t`.
    fn sipral_stack_transport_bind(
        stack: SipralHandle,
        transport: u32,
        protocol: Number<SipralTransport>,
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
            // a WebSocket's far end is named too: the stack opens the WebSocket to it
            if connected.is_some() && !resolved.is_reliable() {
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
            crate::nat::Nat::bound(state, id, resolved, advertised, now);
            if !out_transport_id.is_null() {
                unsafe { out_transport_id.write(transport) };
            }
            Ok(())
        })
    }
}

entry! {
    /// Say that a transport failed and what was written to it did not arrive.
    ///
    /// The transport is retired: its transactions fail now, effects are reported on the next
    /// `sipral_stack_poll`, and nothing is sent until [`sipral_stack_transport_bind`]. Not for one
    /// refused `sendto`: retiring the socket over an ICMP unreachable drops healthy calls.
    ///
    /// Also answers a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` the application could not honour:
    /// on the number it would have bound, waiting requests stop waiting (RFC 3261 §18.1.1:
    /// trimmed into a datagram if it fits, else ended with 513). A never-bound number is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` when nothing waits.
    ///
    /// The next poll raises `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` before the effects.
    /// [`sipral_stack_transport_failed_with`] adds the TLS reason.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_transport_failed(
        stack: SipralHandle,
        transport: u32,
        error: Number<SipralTransportError>,
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
    /// Say that a transport failed, with the TLS library's reason.
    ///
    /// Does what [`sipral_stack_transport_failed`] does, and carries `failure->tls` and
    /// `failure->detail` to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`. A connection that failed before
    /// any handshake belongs here too. A transport already down is not retired again but the
    /// event is still raised, so each failed reconnect is reported.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, retiring nothing, for a TLS reason on a non-TLS/WSS
    /// transport, or a detail over [`SIPRAL_TRANSPORT_DETAIL_BYTES`] or not UTF-8.
    ///
    /// # Safety
    ///
    /// `failure` must point at a `sipral_transport_failure_t` whose `size` member says how long
    /// it is, and its `detail` must be readable for `detail_len` bytes.
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
    /// Say that a connection closed: the far end left, or a read returned zero.
    ///
    /// Retires like [`sipral_stack_transport_failed`], but kept separate so an orderly close is
    /// distinguishable in logs. The event says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
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

/// Retire a transport and queue its event.
///
/// A failure on a transport that is not up is a connection that could not be opened. It
/// answers a pending `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`
/// (`sipral_ua::UserAgent::stream_unavailable`), or is raised while an account waits for its
/// own connection. Otherwise a never-bound number is refused.
fn lose(
    state: &mut StackState,
    transport: u32,
    error: SipralTransportError,
    tls: SipralTlsFailure,
    detail: String,
    now: std::time::Instant,
) -> Result<(), Fail> {
    let streaming = state.agent.wants_a_stream();
    let waiting = streaming || state.agent.wants_a_flow();
    let Some(id) = state.transports.resolve(transport) else {
        if !waiting {
            return named(state, transport).map(|_| ());
        }
        if streaming {
            state.agent.stream_unavailable(now);
        }
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
    // already down: raise again, retire once
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
    if streaming && !was_up {
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

/// The platform's sentence, copied.
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
/// Length zero means omitted, whatever the pointer: bindings that pass every string as a
/// buffer have no null.
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

/// The transport a number names, or why it names none. Duplicated in [`crate::lifecycle`] on
/// purpose; the reason is written there.
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

/// The reverse of `kind_of`; unknown kinds are `Other`.
pub(crate) const fn error_of(kind: TransportErrorKind) -> SipralTransportError {
    match kind {
        TransportErrorKind::ConnectionRefused => SipralTransportError::ConnectionRefused,
        TransportErrorKind::ConnectionReset => SipralTransportError::ConnectionReset,
        TransportErrorKind::Unreachable => SipralTransportError::Unreachable,
        TransportErrorKind::TimedOut => SipralTransportError::TimedOut,
        TransportErrorKind::Closed => SipralTransportError::Closed,
        _ => SipralTransportError::Other,
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

/// Why the layer below refused what arrived. An unknown transport here was retired after
/// this crate checked it, so the moment is wrong, not the argument.
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

    /// A PBX's REGISTER challenge, as a UAS (§22.2).
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

    /// The same, keeping each message's destination.
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
            keepalive_ms: 0,
            server_uri: ptr::null(),
            server_uri_len: 0,
            tls_pin_sha256: ptr::null(),
            tls_pin_sha256_len: 0,
            server_naptr: 0,
            reserved: 0,
            stream_protocol: 0,
            reserved_35: 0,
            realms: ptr::null(),
            realms_len: 0,
        }
    }

    fn line(stack: SipralHandle) -> SipralHandle {
        let config = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(stack, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    /// An account with its own `aor`, on `transport`, registering at `registrar`.
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

    /// A stack speaking something other than UDP, to reach the stream path.
    fn speaking(observed: &mut Observed, protocol: SipralTransport) -> SipralHandle {
        let mut config = config(record, observed);
        config.transport = protocol as u32;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        handle
    }

    /// A whole registration driven through the C ABI alone.
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

    /// Every 2xx handed to a callback on a live registration, copied out during it.
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

    /// The 200 to a REGISTER reaches the callback whole; Service-Route, GRUUs and
    /// P-Associated-URI are read from `message`.
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

    /// A poll does not drain the queue, or the module doc's loop would lose messages.
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

    /// Buffer too small: length returned, nothing written, message kept.
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

    /// Ask for the length, then the bytes.
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

    /// The OPTIONS ping a PBX sends; the stack answers it by itself.
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

    /// RFC 3581 §4: a response leaves from the address its request arrived on.
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

    /// A multi-homed caller names the arrival address; the answer leaves from it.
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

    /// `to` given as an empty buffer counts as omitted, like a null.
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

    /// A request the parser refuses still gets an answer, and the status says why.
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
        // the length is checked before the pointer is read: the second case claims 64 KiB of a
        // one-byte buffer
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

    /// A failed transport fails its transactions (§17), so the registration fails now rather
    /// than after 64·T1.
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

    /// A rebound socket's address is used in every later message.
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

    /// An account on its own TLS connection beside the UDP transport: adding it asks for the
    /// connection, registering waits, and the REGISTER leaves on the bound number. An unknown
    /// protocol is refused.
    #[test]
    fn an_account_on_a_connection_of_its_own_asks_for_it_and_registers_over_it() {
        let mut observed = Observed::default();
        let mut wanted = Wanted::default();
        let mut settings = config(keep_wanted, &mut observed);
        settings.event_user_data = ptr::from_mut(&mut wanted).cast::<std::ffi::c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let on_tls = SipralAccountConfig {
            stream_protocol: SipralTransport::Tls as u32,
            ..account_config()
        };
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&on_tls), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_000);
        assert!(drain(handle).is_empty(), "nothing over the stack's UDP");
        assert_eq!(
            wanted.seen,
            [(SipralTransport::Tls as u32, REGISTRAR.to_owned(), 0, 0)]
        );

        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                9,
                SipralTransport::Tls as u32,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                1_100,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        poll(handle, 1_100);
        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        let status = unsafe { sipral_stack_poll_transmit(handle, &raw mut transmit) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (message, destination, _) = buffers.taken(&transmit);
        assert!(
            message.starts_with(b"REGISTER "),
            "{}",
            String::from_utf8_lossy(&message)
        );
        assert_eq!(
            transmit.transport, 9,
            "on the connection, not the main transport"
        );
        assert_eq!(transmit.protocol, SipralTransport::Tls as u32);
        assert_eq!(destination, REGISTRAR);

        let unknown = SipralAccountConfig {
            stream_protocol: 9,
            ..account_config()
        };
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&unknown), &raw mut account) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("stream_protocol"),
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// An account's TLS connection that cannot be opened is raised with the TLS reason; nothing
    /// goes over UDP meanwhile.
    #[test]
    fn an_account_connection_that_could_not_be_opened_is_raised_with_its_reason() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let on_tls = SipralAccountConfig {
            stream_protocol: SipralTransport::Tls as u32,
            ..account_config()
        };
        let mut account = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_account_add(handle, ptr::from_ref(&on_tls), &raw mut account) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        poll(handle, 1_000);

        let said = "certificate verify failed: self-signed certificate";
        let failure = refused(9, SipralTlsFailure::Untrusted, said);
        assert_eq!(
            unsafe { sipral_stack_transport_failed_with(handle, &raw const failure, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_100);
        assert_eq!(
            observed
                .transports_lost
                .iter()
                .map(|lost| (lost.0, lost.3, lost.4.clone()))
                .collect::<Vec<_>>(),
            [(9, SipralTlsFailure::Untrusted as u32, said.to_owned())]
        );
        assert!(drain(handle).is_empty(), "nothing over the stack's UDP");
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

    fn stream_in(handle: SipralHandle, transport: u32, bytes: &[u8], now_ms: u64) {
        let status = unsafe {
            sipral_stack_receive_stream(handle, transport, bytes.as_ptr(), bytes.len(), now_ms)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    /// WS with `remote`: handshake out, answer in as stream bytes, then messages in masked frames.
    #[test]
    fn a_websocket_bound_with_its_far_end_is_opened_and_framed_by_the_stack() {
        const WS: u32 = 5;
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let status = unsafe {
            sipral_stack_transport_bind(
                handle,
                WS,
                SipralTransport::Ws as u32,
                BIND.as_ptr().cast::<c_char>(),
                BIND.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                1_000,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let out = drain(handle);
        assert_eq!(out.len(), 1);
        let handshake = String::from_utf8(out[0].clone()).unwrap();
        assert!(handshake.starts_with("GET /ws HTTP/1.1\r\n"), "{handshake}");
        assert!(handshake.contains("Sec-WebSocket-Protocol: sip\r\n"));
        let key = handshake
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap();
        let answer = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: sip\r\n\r\n",
            sipral_ua::websocket::accept_for(key)
        );
        stream_in(handle, WS, answer.as_bytes(), 1_010);
        assert!(drain(handle).is_empty(), "nothing was waiting");

        let request = options("ws-1").replace("SIP/2.0/UDP", "SIP/2.0/WS");
        let mut frame = vec![0x81, 126];
        frame.extend_from_slice(&u16::try_from(request.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(request.as_bytes());
        let (head, tail) = frame.split_at(9);
        stream_in(handle, WS, head, 1_020);
        stream_in(handle, WS, tail, 1_020);
        let out = drain(handle);
        assert_eq!(out.len(), 1);
        let framed = &out[0];
        assert_eq!(framed[0], 0x81, "one final text frame");
        assert_eq!(framed[1] & 0x80, 0x80, "masked");
        let at = if framed[1] & 0x7F == 126 { 4 } else { 2 };
        let mask = &framed[at..at + 4];
        let answer: Vec<u8> = framed[at + 4..]
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, key)| byte ^ key)
            .collect();
        assert!(
            answer.starts_with(b"SIP/2.0 200 "),
            "{:?}",
            start_of(&answer)
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// §18.3: a message split across two reads is one message.
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

    /// The size is checked before the handle: both a missing stack and a short struct fail on
    /// size.
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

    /// A WebSocket frame holds one message (RFC 7118 §4.2), fed in whole like a datagram.
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

    /// A reconnected stream names its far end, where responses go.
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

    /// Written out, not derived, so a changed limit below disagrees with the published constant.
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

    fn header_of(name: &'static str, value: &str) -> SipralHeader {
        let (name_ptr, name_len) = (name.as_ptr().cast::<c_char>(), name.len());
        SipralHeader {
            name: name_ptr,
            name_len,
            value: value.as_ptr().cast::<c_char>(),
            value_len: value.len(),
        }
    }

    /// Two refusals before the layer below: an unknown transport, and opening without a
    /// protocol.
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

        // switching main from UDP to TLS under its timers is refused
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

    /// Two accounts on two transports in one stack: each account's traffic leaves on its own,
    /// never on the other or on main.
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

    /// What a [`SipralEventKind::TransportWanted`] carried, copied out during the callback.
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

    /// B1 end to end from C: an oversized REGISTER raises `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`,
    /// sends nothing, and after the bind the same call leaves on the new transport.
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

    /// The TLS reason reaches the event whole, before the failed registration.
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

    /// A request while the transport is down is refused as such, and goes once it is back.
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

    /// The two older calls raise the same event without a TLS reason; a close says closed.
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

    /// Every failed reconnect is raised, through either call.
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

    /// A stream that loses its framing is reported as a lost transport.
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

    /// Refused, retiring nothing: TLS reason on non-TLS, overlong detail, unnamed reason,
    /// unknown transport.
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

    /// A call challenged past RFC 3261 §18.1.1's limit: the stream asked for and the call's end.
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

    /// A call challenged with a nonce long enough to outgrow a datagram, via the C ABI.
    fn challenged_past_the_line(seen: &mut Outgrown) -> SipralHandle {
        let (handle, out) = challenged(seen, |_| {});
        assert!(
            out.iter().all(|message| message.starts_with(b"ACK ")),
            "only the ACK to the refusal went: {:?}",
            out.iter()
                .map(|message| start_of(message))
                .collect::<Vec<_>>()
        );
        handle
    }

    /// The same on a stack `tune` configured, with what went out after the challenge.
    fn challenged(
        seen: &mut Outgrown,
        tune: impl FnOnce(&mut crate::stack::SipralStackConfig),
    ) -> (SipralHandle, Vec<Vec<u8>>) {
        let mut observed = Observed::default();
        let mut settings = config(keep_outgrown, &mut observed);
        settings.event_user_data = ptr::from_mut(seen).cast::<std::ffi::c_void>();
        tune(&mut settings);
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
        (handle, drain(handle))
    }

    /// A UDP-only PBX with `datagram_without_stream_bytes`: once the stream is refused, the
    /// retry goes over the datagram and the diagnostic record notes the overrun.
    #[test]
    fn a_retry_goes_over_udp_once_no_stream_is_coming_when_the_stack_allows_it() {
        let mut seen = Outgrown::default();
        let (handle, out) = challenged(&mut seen, |config| {
            config.datagram_without_stream_bytes = 4_000;
        });
        assert!(
            out.iter().all(|message| message.starts_with(b"ACK ")),
            "§18.1.1 first"
        );
        assert!(!seen.wanted.is_empty(), "a stream was asked for");
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
        let (retry, to, _) = take_one(handle);
        assert!(retry.starts_with(b"INVITE "), "{}", start_of(&retry));
        assert_eq!(to, REGISTRAR);
        assert!(retry.len() > 1_300, "the whole retry: {}", retry.len());
        assert!(header(&retry, HeaderName::Via).starts_with(b"SIP/2.0/UDP "));
        assert!(!header(&retry, HeaderName::Authorization).is_empty());
        assert!(seen.ended.is_empty(), "the call goes on");

        let mut needed = 0_usize;
        let _ = unsafe {
            crate::diagnostics::sipral_stack_diagnostics_json(
                handle,
                ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        let mut json = vec![0_u8; needed];
        let status = unsafe {
            crate::diagnostics::sipral_stack_diagnostics_json(
                handle,
                json.as_mut_ptr().cast::<c_char>(),
                json.len(),
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let json = String::from_utf8_lossy(&json);
        assert!(json.contains("transport.kept.datagram"), "{json}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A known larger path MTU moves RFC 3261 §18.1.1's limit: the retry fits at once.
    #[test]
    fn a_known_path_mtu_keeps_a_retry_that_fits_it_on_udp() {
        let mut seen = Outgrown::default();
        let (handle, out) = challenged(&mut seen, |config| config.path_mtu = 9_000);
        assert!(seen.wanted.is_empty(), "no stream was asked for");
        let retry = out
            .iter()
            .find(|message| message.starts_with(b"INVITE "))
            .expect("the retry went");
        assert!(retry.len() > 1_300, "{}", retry.len());
        assert!(header(retry, HeaderName::Via).starts_with(b"SIP/2.0/UDP "));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Split and coalesced reads are each traced whole, with their far end.
    #[test]
    fn a_stream_is_traced_a_whole_message_at_a_time() {
        let mut observed = Observed::default();
        let handle = speaking(&mut observed, SipralTransport::Tcp);
        assert_eq!(
            rebind(handle, 900),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let account = line(handle);
        let heard = crate::log::tests::Heard::default();
        crate::log::tests::listen(handle, crate::log::SipralLogLevel::Trace, &heard);
        let on = crate::media::SipralToggle::On as u32;
        assert_eq!(
            unsafe { crate::log::sipral_stack_diagnostic_trace(handle, on) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        let (first, _, _) = take_one(handle);
        let challenge = reply(&first, 401, "Unauthorized", CHALLENGE);
        let granted = reply(
            &first,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.10:5060>;expires=3600\r\n",
        );
        let mut both = challenge.clone();
        both.extend_from_slice(&granted);
        let cut = challenge.len() + 20;
        heard.lines.lock().unwrap().clear();
        for read in [&both[..cut], &both[cut..]] {
            let status = unsafe {
                sipral_stack_receive_stream(
                    handle,
                    SIPRAL_TRANSPORT_MAIN,
                    read.as_ptr(),
                    read.len(),
                    1_100,
                )
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        }
        let received: Vec<String> = heard
            .lines
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, target, message, _)| target == "sip" && message.starts_with("received"))
            .map(|(_, _, message, _)| message.clone())
            .collect();
        assert_eq!(received.len(), 2, "{received:#?}");
        let whole = |message: &[u8]| {
            format!(
                "received from {REGISTRAR}, {} bytes:\n{}",
                message.len(),
                String::from_utf8_lossy(message)
            )
        };
        assert_eq!(received[0], whole(&challenge));
        assert_eq!(received[1], whole(&granted));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// RFC 3261 §18.1.1 on a challenge answer from C: `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` with
    /// both sizes, then the retry on the bound stream without placing the call again.
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

    /// If the stream cannot be opened, the call ends on that poll with the limit named.
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
        assert_eq!(
            unsafe { sipral_stack_transport_failed(handle, 2, 0, 1_070) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// Polls to `to_ms`, drains, and says whether a keep-alive ping went on `transport`.
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

    /// RFC 5626 §4.4.1 on an application-opened stream: a ping unanswered for ten seconds
    /// retires the transport with `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`.
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
        assert!(pinged_on(handle, 2, 1_050 + 50_000), "the second ping");
        poll(handle, 1_050 + 60_000);
        assert_eq!(
            seen.lost,
            vec![(2, SipralTransportError::TimedOut as u32)],
            "the application is told which transport the stack let go"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// An application that never answers the event gets a timeout, not a hung call.
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

    /// Declined challenges copied out during the callback: account, reason, server, realms.
    #[derive(Default)]
    struct Declined {
        seen: Vec<(SipralHandle, u32, String, String)>,
    }

    unsafe extern "C" fn keep_declined(
        event: *const crate::event::SipralEvent,
        user_data: *mut std::ffi::c_void,
    ) {
        let declined = unsafe { &mut *user_data.cast::<Declined>() };
        let event = unsafe { &*event };
        if event.kind != SipralEventKind::ChallengeDeclined {
            return;
        }
        let payload = unsafe { event.payload.challenge };
        let text = |pointer: *const c_char, len: usize| {
            String::from_utf8_lossy(unsafe {
                std::slice::from_raw_parts(pointer.cast::<u8>(), len)
            })
            .into_owned()
        };
        declined.seen.push((
            event.account,
            payload.refusal,
            text(payload.server, payload.server_len),
            text(payload.realms, payload.realms_len),
        ));
    }

    /// A call's INVITE refused 407 under `realm` by the account's server, and what followed.
    fn challenged_under(
        handle: SipralHandle,
        account: SipralHandle,
        realm: &str,
        now_ms: u64,
    ) -> Vec<Vec<u8>> {
        let (status, _) =
            crate::call::tests::place(handle, account, &crate::call::tests::call_config(), now_ms);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (invite, to, _) = take_one(handle);
        assert_eq!(to, REGISTRAR);
        let to = String::from_utf8_lossy(&header(&invite, HeaderName::To)).into_owned();
        let challenge = String::from_utf8_lossy(&reply(
            &invite,
            407,
            "Proxy Authentication Required",
            &format!("Proxy-Authenticate: Digest realm=\"{realm}\", nonce=\"{realm}-n\", qop=\"auth\"\r\n"),
        ))
        .replacen(&format!("To: {to}"), &format!("To: {to};tag=sbc"), 1);
        assert_eq!(
            feed(handle, REGISTRAR, challenge.as_bytes(), now_ms + 10),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, now_ms + 10);
        let call_id = header(&invite, HeaderName::CallId);
        drain(handle)
            .into_iter()
            .filter(|message| header(message, HeaderName::CallId) == call_id)
            .collect()
    }

    /// `realms` limits which challenges the password answers; another realm raises
    /// `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED` with account, server and realm.
    #[test]
    fn the_realms_an_account_names_are_answered_and_any_other_is_reported_declined() {
        let mut declined = Declined::default();
        let mut observed = Observed::default();
        let mut settings = config(keep_declined, &mut observed);
        settings.event_user_data = ptr::from_mut(&mut declined).cast::<std::ffi::c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let realms = "registrar.example\nsbc.example";
        let mut account_config = account_config();
        account_config.realms = realms.as_ptr().cast::<c_char>();
        account_config.realms_len = realms.len();
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&account_config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let out = challenged_under(handle, account, "registrar.example", 500);
        assert!(out.iter().any(|message| message.starts_with(b"INVITE ")
            && !header(message, HeaderName::ProxyAuthorization).is_empty()));
        let out = challenged_under(handle, account, "sbc.example", 1_000);
        assert!(
            out.iter().any(|message| message.starts_with(b"INVITE ")
                && !header(message, HeaderName::ProxyAuthorization).is_empty()),
            "the SBC's realm is the account's, and its challenge is answered"
        );
        assert!(declined.seen.is_empty(), "{:?}", declined.seen);

        let out = challenged_under(handle, account, "callee.example", 2_000);
        assert!(
            !out.iter().any(|message| message.starts_with(b"INVITE ")),
            "a realm the account does not name gets no answer"
        );
        assert_eq!(declined.seen.len(), 1, "{:?}", declined.seen);
        let (whose, refusal, server, realms) = &declined.seen[0];
        assert_eq!(*whose, account);
        assert_eq!(
            *refusal,
            crate::event::SipralChallengeRefusal::NotTheAccountsRealm as u32
        );
        assert_eq!(server, REGISTRAR);
        assert!(
            realms.split('\n').any(|realm| realm == "callee.example"),
            "{realms}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// An empty realm list is an error, and so is a control byte other than line feed.
    #[test]
    fn realms_that_name_no_realm_are_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let realms = "\n\n";
        let mut account_config = account_config();
        account_config.realms = realms.as_ptr().cast::<c_char>();
        account_config.realms_len = realms.len();
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&account_config), &raw mut account) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("names no realm"),
            "{}",
            last_error_text()
        );
        let realms = "sbc.example\n\tregistrar.example";
        account_config.realms = realms.as_ptr().cast::<c_char>();
        account_config.realms_len = realms.len();
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&account_config), &raw mut account) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("control byte"),
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `SIPRAL_EVENT_KIND_TOKEN_REQUIRED` copied out during the callback.
    #[derive(Default)]
    struct TokenWanted {
        seen: Vec<(SipralHandle, u32, u32, String, String, String, String)>,
    }

    unsafe extern "C" fn keep_token_wanted(
        event: *const crate::event::SipralEvent,
        user_data: *mut std::ffi::c_void,
    ) {
        let wanted = unsafe { &mut *user_data.cast::<TokenWanted>() };
        let event = unsafe { &*event };
        if event.kind != SipralEventKind::TokenRequired {
            return;
        }
        let payload = unsafe { event.payload.token };
        let text = |pointer: *const c_char, len: usize| {
            String::from_utf8_lossy(unsafe {
                std::slice::from_raw_parts(pointer.cast::<u8>(), len)
            })
            .into_owned()
        };
        wanted.seen.push((
            event.account,
            payload.error,
            payload.proxy,
            text(payload.server, payload.server_len),
            text(payload.realm, payload.realm_len),
            text(payload.scope, payload.scope_len),
            text(payload.authz_server, payload.authz_server_len),
        ));
    }

    fn bearer(error: &str) -> String {
        format!(
            "WWW-Authenticate: Bearer realm=\"example.com\", scope=\"sip\", \
             authz_server=\"https://as.example.com\"{error}\r\n"
        )
    }

    fn set_token(handle: SipralHandle, account: SipralHandle, token: &str) -> SipralStatus {
        unsafe {
            crate::account::sipral_account_set_access_token(
                handle,
                account,
                token.as_ptr().cast::<c_char>(),
                token.len(),
            )
        }
    }

    /// RFC 8898 via C: a `Bearer` challenge raises `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, the token
    /// from `sipral_account_set_access_token` answers it, and an `invalid_token` one is not
    /// resent.
    #[test]
    fn a_bearer_challenge_asks_for_a_token_and_the_token_answers_it() {
        let mut wanted = TokenWanted::default();
        let mut observed = Observed::default();
        let mut settings = config(keep_token_wanted, &mut observed);
        settings.event_user_data = ptr::from_mut(&mut wanted).cast::<std::ffi::c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account_config = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&account_config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok
        );
        let (register, _, _) = take_one(handle);
        let refused = reply(&register, 401, "Unauthorized", &bearer(""));
        assert_eq!(feed(handle, REGISTRAR, &refused, 1_010), SipralStatus::Ok);
        poll(handle, 1_010);
        assert!(
            drain(handle).is_empty(),
            "a password does not answer Bearer"
        );
        assert_eq!(wanted.seen.len(), 1);
        let (whose, error, proxy, server, realm, scope, authz_server) = &wanted.seen[0];
        assert_eq!(*whose, account);
        assert_eq!(*error, crate::event::SipralTokenError::None as u32);
        assert_eq!(*proxy, crate::media::SipralToggle::Off as u32);
        assert_eq!(server, REGISTRAR);
        assert_eq!(realm, "example.com");
        assert_eq!(scope, "sip");
        assert_eq!(authz_server, "https://as.example.com");

        assert_eq!(
            set_token(handle, account, "not a token"),
            SipralStatus::InvalidArgument
        );
        assert!(
            !last_error_text().contains("not a token"),
            "the refusal does not repeat the token"
        );
        assert_eq!(set_token(handle, account, "first.token"), SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 2_000) },
            SipralStatus::Ok
        );
        let (register, _, _) = take_one(handle);
        assert_eq!(
            header(&register, HeaderName::Authorization),
            b"Bearer first.token"
        );

        let expired = reply(
            &register,
            401,
            "Unauthorized",
            &bearer(", error=\"invalid_token\""),
        );
        assert_eq!(feed(handle, REGISTRAR, &expired, 2_010), SipralStatus::Ok);
        poll(handle, 2_010);
        assert!(
            drain(handle).is_empty(),
            "the refused token is not sent again"
        );
        assert_eq!(wanted.seen.len(), 2);
        assert_eq!(
            wanted.seen[1].1,
            crate::event::SipralTokenError::InvalidToken as u32
        );

        assert_eq!(set_token(handle, account, "second.token"), SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 3_000) },
            SipralStatus::Ok
        );
        let (register, _, _) = take_one(handle);
        assert_eq!(
            header(&register, HeaderName::Authorization),
            b"Bearer second.token"
        );
        // a length of zero takes the token away
        assert_eq!(
            unsafe {
                crate::account::sipral_account_set_access_token(handle, account, ptr::null(), 0)
            },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
