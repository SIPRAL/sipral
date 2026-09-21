# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Stack``: one SIP endpoint, headless and in-process.

This is the object an application actually reaches for. It owns the UDP
socket signalling travels on, a background thread that drains
`sipral_stack_poll` and the transport queues around it, and the
`asyncio.Queue` events land on -- the layer `_sipral_cffi.py` (the raw
`ffi`/`lib` pair, printed by `tools/abi-gen` from `crates/sipral-ffi`) is
written against directly, the way `SipralAbi.swift` is the base the Swift
package is written by hand against (`docs/08-ffi.md`, "Swift").
"""

from __future__ import annotations

import asyncio
import os
import selectors
import socket
import threading
import time

from . import events as _events
from ._sipral_cffi import ffi, lib
from .account import Account
from .call import Call
from .errors import call as _retry
from .errors import check

__all__ = ["Stack"]

#: `sipral_transmit_t` and `sipral_media_packet_t` both bound a single
#: datagram at this many bytes (`SIPRAL_MEDIA_PACKET_BYTES`); a signalling
#: message can be larger, so the transmit buffer below is a comfortable
#: multiple of it rather than that same bound.
_TRANSMIT_BYTES = 1 << 16
_ADDRESS_BYTES = 128


def _toggle(value: bool | None) -> int:
    """A Python `True`/`False`/`None` as a `sipral_toggle_t`."""
    if value is None:
        return lib.SIPRAL_TOGGLE_DEFAULT
    return lib.SIPRAL_TOGGLE_ON if value else lib.SIPRAL_TOGGLE_OFF


def format_address(host: str, port: int) -> str:
    """``host:port``, the text shape every address crosses this ABI as."""
    return f"{host}:{port}"


def parse_address(text: str) -> tuple[str, int]:
    """The inverse of :func:`format_address`."""
    host, _, port = text.rpartition(":")
    return host, int(port)


class Stack:
    """One `sipral_stack_create` handle, its socket and its poll thread.

    Built and torn down like the handle it wraps: :meth:`close` (also
    reached through ``with Stack(...) as stack:``) calls
    `sipral_stack_destroy` exactly once, and a stack a caller lets go of
    without closing still does at garbage collection -- the deterministic
    path is the one to prefer, since a stack still bound to a socket is a
    port nothing else can use until Python's collector gets around to it.
    """

    def __init__(
        self,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        user_agent: str | None = None,
        codecs: str | None = None,
        frame_ms: int = 0,
        offer_dtmf: bool | None = None,
        srtp: int = 0,
    ) -> None:
        self._loop = loop
        self.events: asyncio.Queue[_events.Event] = asyncio.Queue()
        self._calls: dict[int, Call] = {}
        self._lock = threading.Lock()

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((bind_host, bind_port))
        self._socket.setblocking(False)
        self.bind_address = format_address(*self._socket.getsockname())

        self._origin = time.monotonic()

        # Kept alive on the instance: cffi frees a callback's trampoline
        # once nothing in Python still references it, and C would be
        # calling into freed memory on the very next event if this were a
        # local instead.
        self._callback = ffi.callback("void(const sipral_event_t *, void *)")(
            self._on_event
        )

        # Everything else here is read once, inside `sipral_stack_create`,
        # and never touched again (`docs/08-ffi.md` calls a struct like
        # this one "versioned" precisely because the library copies what
        # it needs out of it before answering) -- so a local `char[]`/
        # `uint8_t[]` that outlives the call and nothing longer is enough;
        # nothing here has to be kept on `self`.
        bind_address = ffi.new("char[]", self.bind_address.encode("utf-8"))
        user_agent_buf = ffi.new("char[]", user_agent.encode("utf-8")) if user_agent else None
        codecs_buf = ffi.new("char[]", codecs.encode("utf-8")) if codecs else None
        entropy = ffi.new("uint8_t[]", os.urandom(32))
        media_seed = ffi.new("uint8_t[]", os.urandom(32))

        config = ffi.new("sipral_stack_config_t *")
        config.size = ffi.sizeof("sipral_stack_config_t")
        config.event_callback = self._callback
        config.event_user_data = ffi.NULL
        config.transport = lib.SIPRAL_TRANSPORT_UDP
        config.bind_address = bind_address
        config.bind_address_len = len(self.bind_address)
        config.user_agent = user_agent_buf or ffi.NULL
        config.user_agent_len = len(user_agent.encode("utf-8")) if user_agent else 0
        config.entropy = entropy
        config.entropy_len = 32
        config.codecs = codecs_buf or ffi.NULL
        config.codecs_len = len(codecs.encode("utf-8")) if codecs else 0
        config.frame_ms = frame_ms
        config.offer_dtmf = _toggle(offer_dtmf)
        config.media_clock_unix_seconds = int(time.time())
        config.media_seed = media_seed
        config.media_seed_len = 32
        config.srtp = srtp

        out_stack = ffi.new("sipral_handle_t *")
        check(lib.sipral_stack_create(config, out_stack), "sipral_stack_create")
        self.handle = int(out_stack[0])

        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ)
        self._transmit = ffi.new("sipral_transmit_t *")
        self._transmit_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._transmit_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._transmit_source = ffi.new(f"char[{_ADDRESS_BYTES}]")

        self._closed = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="sipral-stack", daemon=True
        )
        self._thread.start()

    def __enter__(self) -> "Stack":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        # A safety net, not the intended path: see the class docstring.
        try:
            self.close()
        except Exception:  # noqa: BLE001 -- never raise out of __del__
            pass

    def now_ms(self) -> int:
        """Elapsed milliseconds since this stack was created.

        `sipral_stack_create` fixed its own origin at that same moment
        (`crates/sipral-ffi/src/stack.rs`), so a reading taken from here
        a few milliseconds later is exactly the figure every entry point
        below expects `now_ms` to be.
        """
        return int((time.monotonic() - self._origin) * 1000)

    # -- accounts and calls --------------------------------------------

    def add_account(
        self,
        aor: str,
        *,
        registrar_address: str,
        registrar: str | None = None,
        contact: str | None = None,
        display_name: str | None = None,
        auth_user: str | None = None,
        auth_password: str | None = None,
        expires_seconds: int = 0,
    ) -> Account:
        """`sipral_account_add`. See :class:`sipral.account.Account`.

        ``registrar`` left out makes an account that never registers --
        `docs/08-ffi.md`'s "An account with no registrar never registers"
        -- with ``registrar_address`` as the outbound proxy every request
        it places still goes to; two stacks on loopback that want to call
        each other directly, with no registrar between them at all, each
        add one account this way, pointed at the other's own
        :attr:`bind_address`.
        """
        return Account.add(
            self,
            aor,
            registrar_address=registrar_address,
            registrar=registrar,
            contact=contact,
            display_name=display_name,
            auth_user=auth_user,
            auth_password=auth_password,
            expires_seconds=expires_seconds,
        )

    def place_call(
        self,
        account: Account,
        target: str,
        *,
        media_host: str = "127.0.0.1",
        media_port: int = 0,
        destination: str | None = None,
        srtp: int = 0,
    ) -> Call:
        """`sipral_call_place`, with this stack running the call's audio.

        A media socket is opened here, before the INVITE goes out, and its
        `host:port` is what `media_address` in `sipral_call_config_t`
        offers: the stack writes the offer from its own codec order and
        reads the answer, and :class:`sipral.media.Media` starts once
        `SIPRAL_EVENT_KIND_MEDIA_STARTED` says the session is up
        (`docs/08-ffi.md`, "A call is described one way or the other").
        """
        media_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        media_socket.bind((media_host, media_port))
        media_socket.setblocking(False)
        media_address = format_address(*media_socket.getsockname())

        target_buf = ffi.new("char[]", target.encode("utf-8"))
        media_address_buf = ffi.new("char[]", media_address.encode("utf-8"))
        destination_buf = (
            ffi.new("char[]", destination.encode("utf-8")) if destination else None
        )

        config = ffi.new("sipral_call_config_t *")
        config.size = ffi.sizeof("sipral_call_config_t")
        config.target = target_buf
        config.target_len = len(target.encode("utf-8"))
        config.media_address = media_address_buf
        config.media_address_len = len(media_address.encode("utf-8"))
        config.srtp = srtp
        if destination_buf is not None:
            config.destination = destination_buf
            config.destination_len = len(destination.encode("utf-8"))

        out_call = ffi.new("sipral_handle_t *")
        _retry(
            lambda: lib.sipral_call_place(
                self.handle, account.handle, config, out_call, self.now_ms()
            ),
            "sipral_call_place",
        )
        call = Call(self, int(out_call[0]), media_socket, media_address)
        with self._lock:
            self._calls[call.handle] = call
        return call

    def answer_call(
        self,
        event: _events.Event,
        *,
        media_host: str = "127.0.0.1",
        media_port: int = 0,
    ) -> Call:
        """Open a media socket for an incoming call and answer it there.

        ``event`` is the `SIPRAL_EVENT_KIND_INCOMING_CALL` a listener read
        off :attr:`events`: an incoming call has no :class:`Call` of its
        own until the application decides what to do with it, which is
        exactly what this builds -- `sipral_call_answer_media` under it,
        the other half of :meth:`place_call`. Call :meth:`Call.reject`
        instead when the application does not want it; that needs no
        socket, so it takes the call handle straight off ``event.call``.
        """
        media_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        media_socket.bind((media_host, media_port))
        media_socket.setblocking(False)
        media_address = format_address(*media_socket.getsockname())

        call = Call(self, event.call, media_socket, media_address)
        self.register_call(call)
        call.answer()
        return call

    def reject_call(self, event: _events.Event, code: int = 486) -> None:
        """`sipral_call_reject` for an incoming call nothing has answered,
        so no :class:`Call` -- and no media socket -- was ever needed."""
        _retry(
            lambda: lib.sipral_call_reject(self.handle, event.call, code, self.now_ms()),
            "sipral_call_reject",
        )

    def call_for(self, handle: int) -> Call | None:
        """The :class:`sipral.call.Call` already made for a call handle."""
        with self._lock:
            return self._calls.get(handle)

    def register_call(self, call: Call) -> None:
        """Track a call this ``Stack`` did not place itself.

        Used for a call `SIPRAL_EVENT_KIND_INCOMING_CALL` reports: the
        application answers it and only then does a :class:`Call` exist
        to dispatch that event's own delivery to, since the constructor
        is what would have to send it.
        """
        with self._lock:
            self._calls[call.handle] = call

    def forget_call(self, handle: int) -> None:
        with self._lock:
            self._calls.pop(handle, None)

    # -- the poll thread --------------------------------------------------

    def _on_event(self, raw, _user_data: object) -> None:
        """The C callback. Runs on the poll thread, with nothing held."""
        event = _events.decode(raw[0])
        if event.kind == lib.SIPRAL_EVENT_KIND_RESOLVE_NEEDED:
            self._resolve(event)
        self._deliver(event)

    def _resolve(self, event: _events.Event) -> None:
        """Answer `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` with the host as given.

        This package wires no DNS resolver of its own -- `docs/08-ffi.md`
        leaves RFC 3263 lookup to the caller on purpose, and a headless
        binding with no asyncio-friendly resolver to reach for by default
        treats the host it was handed as a literal address instead, which
        is exactly right for the numeric `host:port` targets
        :meth:`place_call` and two loopback stacks calling each other
        direct are built around. An application that talks to a real
        registrar behind a name would answer `SIPRAL_EVENT_KIND_RESOLVE_NEEDED`
        itself instead, with its own lookup, through `sipral_stack_resolved`
        (`sipral._sipral_cffi.lib`) directly.
        """
        host = event.fields.get("host")
        if not host:
            return
        port = event.fields.get("port") or 5060
        protocol = event.fields.get("protocol") or lib.SIPRAL_TRANSPORT_UDP
        address = f"{host}:{port}".encode("utf-8")
        lib.sipral_stack_resolved(
            self.handle, event.fields["dialog"], address, len(address), protocol
        )

    def _deliver(self, event: _events.Event) -> None:
        # The call's own side effects (minting `Call.media`, marking it
        # ended) happen before `event` reaches any queue, for the same
        # reason `Call.deliver` orders its own steps that way: a consumer
        # of `self.events` may look up `self.call_for(event.call)` and
        # read its state, and that state has to already be current.
        call = self.call_for(event.call) if event.call else None
        if call is not None:
            call.deliver(event)

        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.events.put_nowait, event)
        else:
            self.events.put_nowait(event)

    def _drain_transmit(self) -> None:
        """`sipral_stack_poll_transmit`, until nothing is left to send.

        `SIPRAL_STATUS_BUSY` here means another thread -- an application
        thread answering or placing a call while this one is between two
        polls -- holds this stack's lock right now, not that anything is
        wrong (`docs/08-ffi.md`, "Signalling on one stack is one thread at
        a time"). This is the poll thread: nothing here may raise on it,
        because a `SipralError` that reached the top would end the thread
        for good and this stack would never poll again. Whatever is still
        queued is drained on the next pass instead.
        """
        transmit = self._transmit
        while True:
            transmit.size = ffi.sizeof("sipral_transmit_t")
            transmit.data = self._transmit_data
            transmit.capacity = _TRANSMIT_BYTES
            transmit.destination = self._transmit_destination
            transmit.destination_capacity = _ADDRESS_BYTES
            transmit.source = ffi.NULL
            transmit.source_capacity = 0
            status = lib.sipral_stack_poll_transmit(self.handle, transmit)
            if status != lib.SIPRAL_STATUS_OK:
                return
            if transmit.len == 0:
                return
            payload = bytes(ffi.buffer(transmit.data, transmit.len))
            destination = ffi.string(transmit.destination, transmit.destination_len)
            host, port = parse_address(destination.decode("utf-8"))
            self._socket.sendto(payload, (host, port))

    def _drain_farewells(self) -> None:
        """`sipral_stack_poll_farewell`: the RTCP BYE a call that just
        ended still owes, sent through that call's own media socket and
        to the last address media was actually heard from
        (`docs/08-ffi.md`, "A call that ends owes the far end an RTCP
        BYE"). A call whose :class:`sipral.call.Call` was already closed,
        or that never heard from the far end at all, is skipped: there is
        nothing left here that could still reach it.
        """
        out_call = ffi.new("sipral_handle_t *")
        packet = ffi.new("sipral_media_packet_t *")
        data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        while True:
            packet.size = ffi.sizeof("sipral_media_packet_t")
            packet.data = data
            packet.capacity = _TRANSMIT_BYTES
            packet.destination = ffi.NULL
            packet.destination_capacity = 0
            status = lib.sipral_stack_poll_farewell(self.handle, out_call, packet)
            if status != lib.SIPRAL_STATUS_OK:
                return
            if packet.len == 0:
                return
            call = self.call_for(int(out_call[0]))
            if call is None or call.media is None or call.media.remote_address is None:
                continue
            call.media.send_to(bytes(ffi.buffer(packet.data, packet.len)), call.media.remote_address)

    def _run(self) -> None:
        result = ffi.new("sipral_poll_result_t *")
        while not self._closed.is_set():
            timeout = 0.05
            events = self._selector.select(timeout)
            for _key, _mask in events:
                try:
                    data, from_address = self._socket.recvfrom(_TRANSMIT_BYTES)
                except (BlockingIOError, OSError):
                    continue
                from_text = format_address(*from_address).encode("utf-8")
                lib.sipral_stack_receive_datagram(
                    self.handle,
                    lib.SIPRAL_TRANSPORT_MAIN,
                    data,
                    len(data),
                    from_text,
                    len(from_text),
                    ffi.NULL,
                    0,
                    self.now_ms(),
                )
            result.size = ffi.sizeof("sipral_poll_result_t")
            status = lib.sipral_stack_poll(self.handle, self.now_ms(), result)
            if status != lib.SIPRAL_STATUS_OK:
                continue
            self._drain_transmit()
            self._drain_farewells()

    def close(self) -> None:
        """`sipral_stack_destroy`, and everything this wrapper opened.

        Whatever calls are still open are hung up first, while the poll
        thread can still send what that queues: `Call.close` only calls
        `sipral_call_hangup`, which enqueues the BYE; `_drain_transmit` is
        what actually writes it to the socket, and that only happens from
        inside this thread's own loop. Closing the calls after stopping
        the thread instead would queue a BYE that nothing ever sends -- a
        clean call reaching for the door on its way out and finding it
        already locked.
        """
        if self._closed.is_set():
            return
        with self._lock:
            calls = list(self._calls.values())
        for call in calls:
            call.close()
        if calls:
            # One more round of polling for the hangups just queued to go
            # out and, on loopback, for their answers to come back and be
            # read -- 200ms is comfortably more than a direct call over a
            # local network needs and still bounded.
            time.sleep(0.2)
        self._closed.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)
        lib.sipral_stack_destroy(self.handle)
        self._selector.close()
        self._socket.close()
