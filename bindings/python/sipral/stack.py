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
        ice: int = 0,
        nat: int = 0,
        stun_server: str | None = None,
        turn_server: str | None = None,
        turn_username: str | None = None,
        turn_password: str | None = None,
        g729_annex_b: bool | None = None,
        referrals: bool | None = None,
        registrar_keepalive: bool | None = None,
        registrar_keepalive_ms: int = 0,
    ) -> None:
        """See the class docstring for the socket and thread this owns.

        ``ice`` and ``nat`` are :class:`sipral.enums.Ice` /
        :class:`sipral.enums.Nat` values, or ``0`` for this build's own
        default (`SIPRAL_ICE_OFF`, `SIPRAL_NAT_OFF` -- exactly today's
        behaviour). ``Ice.LITE`` is for a server reachable at the address
        it advertises and nowhere else: it answers a full ICE peer's checks
        and never sends its own (`docs/06-nat.md`, "ICE-lite").

        ``referrals=True`` hands a REFER outside any dialog -- click-to-dial
        from a switchboard -- to the application as
        `SIPRAL_EVENT_KIND_REFERRAL`, to take with :meth:`accept_referral`
        or refuse with :meth:`reject_referral`. Off by default, when every
        one is refused 403: a peer that can make a phone dial is a
        toll-fraud vector, so each one is the application's decision.

        ``registrar_keepalive`` keeps the registrar's flow open behind a
        NAT: every account ``stun_server`` showed to be behind one sends its
        registrar a double CRLF every ``registrar_keepalive_ms`` (``0`` for
        25 seconds, 1 000 to 120 000), so that a NAT filtering by address
        and port still lets the registrar's INVITE in minutes after the
        REGISTER. On by default; ``False`` turns it off, and an interval
        with it off is refused. Nothing is sent while the stack is
        suspended.

        ``nat=Nat.STUN`` needs ``stun_server`` as ``host:port``;
        ``turn_server`` rides on it and needs ``turn_username`` and
        ``turn_password`` with it (`docs/06-nat.md`, `docs/08-ffi.md`
        "Behind a NAT"). The TURN credentials are copied into the library
        and kept out of every log, event and error this package raises --
        neither is in `repr(stack)` (there is none) or anywhere else this
        module writes text.
        """
        self._loop = loop
        self.events: asyncio.Queue[_events.Event] = asyncio.Queue()
        self._calls: dict[int, Call] = {}
        self._lock = threading.Lock()
        self._nat = nat
        self._turn = turn_server is not None

        #: Media sockets currently named with `sipral_stack_nat_map`, keyed
        #: by their own `host:port` text -- from that call until either
        #: `SIPRAL_EVENT_KIND_MEDIA_STARTED` hands the socket to
        #: :class:`sipral.media.Media` or the call gives up on it. Written
        #: from the calling thread (:meth:`_map_media_socket`,
        #: :meth:`_release_stun_socket`) and read from the poll thread
        #: (:meth:`_run`, :meth:`_drain_stun`); :attr:`_nat_lock` covers
        #: this and the two dicts below.
        self._nat_lock = threading.Lock()
        self._stun_sockets: dict[str, socket.socket] = {}
        #: Per socket, one `threading.Event` for `SIPRAL_EVENT_KIND_NAT_MAPPING`
        #: and one for `SIPRAL_EVENT_KIND_NAT_RELAY` -- a stack built with
        #: `turn_server` waits out both before a call may be placed or
        #: answered on the socket (`sipral_call_place`'s own
        #: `SIPRAL_STATUS_WRONG_STATE` for one that has not), a stack
        #: without it only the first.
        self._nat_waiters: dict[str, dict[str, threading.Event]] = {}

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
        stun_server_buf = (
            ffi.new("char[]", stun_server.encode("utf-8")) if stun_server else None
        )
        turn_server_buf = (
            ffi.new("char[]", turn_server.encode("utf-8")) if turn_server else None
        )
        turn_username_buf = (
            ffi.new("char[]", turn_username.encode("utf-8")) if turn_username else None
        )
        turn_password_buf = (
            ffi.new("char[]", turn_password.encode("utf-8")) if turn_password else None
        )

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
        config.ice = ice
        config.nat = nat
        if stun_server_buf is not None:
            config.stun_server = stun_server_buf
            config.stun_server_len = len(stun_server.encode("utf-8"))
        config.g729_annex_b = _toggle(g729_annex_b)
        if turn_server_buf is not None:
            config.turn_server = turn_server_buf
            config.turn_server_len = len(turn_server.encode("utf-8"))
        if turn_username_buf is not None:
            config.turn_username = turn_username_buf
            config.turn_username_len = len(turn_username.encode("utf-8"))
        if turn_password_buf is not None:
            config.turn_password = turn_password_buf
            config.turn_password_len = len(turn_password.encode("utf-8"))
        config.referrals = _toggle(referrals)
        config.registrar_keepalive = _toggle(registrar_keepalive)
        config.registrar_keepalive_ms = registrar_keepalive_ms

        out_stack = ffi.new("sipral_handle_t *")
        check(lib.sipral_stack_create(config, out_stack), "sipral_stack_create")
        self.handle = int(out_stack[0])

        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ, data="main")
        self._transmit = ffi.new("sipral_transmit_t *")
        self._transmit_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._transmit_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._transmit_source = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._stun_transmit = ffi.new("sipral_transmit_t *")
        self._stun_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._stun_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._stun_source = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._farewell = ffi.new("sipral_media_packet_t *")
        self._farewell_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._farewell_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")

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
        ice: int = 0,
    ) -> Call:
        """`sipral_call_place`, with this stack running the call's audio.

        A media socket is opened here, before the INVITE goes out, and its
        `host:port` is what `media_address` in `sipral_call_config_t`
        offers: the stack writes the offer from its own codec order and
        reads the answer, and :class:`sipral.media.Media` starts once
        `SIPRAL_EVENT_KIND_MEDIA_STARTED` says the session is up
        (`docs/08-ffi.md`, "A call is described one way or the other").

        ``ice`` is a :class:`sipral.enums.Ice` value, or ``0`` for the
        stack's own default. On a stack built with ``nat=Nat.STUN``, the
        socket is named with `sipral_stack_nat_map` first and this call
        blocks the calling thread -- never the poll thread -- until its
        `SIPRAL_EVENT_KIND_NAT_MAPPING` arrives, exactly as
        `sipral_stack_nat_map`'s own doc comment requires: placing a call
        on the socket any sooner is `SIPRAL_STATUS_WRONG_STATE`.
        """
        media_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        media_socket.bind((media_host, media_port))
        media_socket.setblocking(False)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)

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
        config.ice = ice
        if destination_buf is not None:
            config.destination = destination_buf
            config.destination_len = len(destination.encode("utf-8"))

        out_call = ffi.new("sipral_handle_t *")
        try:
            _retry(
                lambda: lib.sipral_call_place(
                    self.handle, account.handle, config, out_call, self.now_ms()
                ),
                "sipral_call_place",
            )
        except Exception:
            self._forget_media_socket(media_address)
            media_socket.close()
            raise
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

        On a stack built with ``nat=Nat.STUN`` this blocks the calling
        thread until the socket's `SIPRAL_EVENT_KIND_NAT_MAPPING` arrives,
        the same wait :meth:`place_call` makes.
        """
        media_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        media_socket.bind((media_host, media_port))
        media_socket.setblocking(False)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)

        call = Call(self, event.call, media_socket, media_address)
        self.register_call(call)
        try:
            call.answer()
        except Exception:
            self.forget_call(call.handle)
            self._forget_media_socket(media_address)
            media_socket.close()
            raise
        return call

    def reject_call(self, event: _events.Event, code: int = 486) -> None:
        """`sipral_call_reject` for an incoming call nothing has answered,
        so no :class:`Call` -- and no media socket -- was ever needed."""
        _retry(
            lambda: lib.sipral_call_reject(self.handle, event.call, code, self.now_ms()),
            "sipral_call_reject",
        )

    def accept_referral(
        self,
        event: _events.Event,
        *,
        media_host: str = "127.0.0.1",
        media_port: int = 0,
        srtp: int = 0,
        ice: int = 0,
    ) -> Call:
        """Take a REFER outside any dialog and place the call it asks for.

        ``event`` is the `SIPRAL_EVENT_KIND_REFERRAL` a listener read off
        :attr:`events`, with ``event.fields["status_code"]`` zero. This is
        `sipral_call_accept_transfer` on the referral's handle: the stack
        answers 202, reports on the call to whoever asked, and places it
        from the account the event names -- to ``event.fields["target"]``,
        which is the REFER's and never the caller's. A media socket is
        opened for it here, the way :meth:`place_call` opens one, and the
        :class:`Call` returned is that placed call. Taking one is a decision
        with a bill attached -- whoever sent it can make this line dial
        anything -- so it is never made on the application's behalf.
        """
        media_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        media_socket.bind((media_host, media_port))
        media_socket.setblocking(False)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)

        media_address_buf = ffi.new("char[]", media_address.encode("utf-8"))
        config = ffi.new("sipral_call_config_t *")
        config.size = ffi.sizeof("sipral_call_config_t")
        config.media_address = media_address_buf
        config.media_address_len = len(media_address.encode("utf-8"))
        config.srtp = srtp
        config.ice = ice

        out_placed = ffi.new("sipral_handle_t *")
        try:
            _retry(
                lambda: lib.sipral_call_accept_transfer(
                    self.handle, event.call, config, out_placed, self.now_ms()
                ),
                "sipral_call_accept_transfer",
            )
        except Exception:
            self._forget_media_socket(media_address)
            media_socket.close()
            raise
        call = Call(self, int(out_placed[0]), media_socket, media_address)
        with self._lock:
            self._calls[call.handle] = call
        return call

    def reject_referral(self, event: _events.Event, code: int = 603) -> None:
        """Refuse a REFER outside any dialog with ``code``, 300 to 699:
        `sipral_call_reject_transfer` on the referral's handle."""
        _retry(
            lambda: lib.sipral_call_reject_transfer(
                self.handle, event.call, code, self.now_ms()
            ),
            "sipral_call_reject_transfer",
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
        """The C callback. Runs on the poll thread, with nothing held.

        `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` is delivered and not answered
        here. A dialog keeps the flow its INVITE went out on -- the
        registrar or outbound proxy the account names, the only path that
        survives a NAT -- and the event only says that the far end's
        `Contact` names some other address. This package has no resolver to
        answer it with, and answering with that `Contact` as a literal
        address moves the rest of the call onto it: behind a registrar
        reached through a port mapping or a NAT, the BYE then goes to an
        address nothing answers on. An application with a real lookup
        answers the event itself, through `sipral_stack_resolved`
        (`sipral._sipral_cffi.lib`).
        """
        self._deliver(_events.decode(raw[0]))

    def _deliver(self, event: _events.Event) -> None:
        # The call's own side effects (minting `Call.media`, marking it
        # ended) happen before `event` reaches any queue, for the same
        # reason `Call.deliver` orders its own steps that way: a consumer
        # of `self.events` may look up `self.call_for(event.call)` and
        # read its state, and that state has to already be current.
        if event.kind in (lib.SIPRAL_EVENT_KIND_NAT_MAPPING, lib.SIPRAL_EVENT_KIND_NAT_RELAY):
            local = event.fields.get("local")
            if local:
                with self._nat_lock:
                    waiters = self._nat_waiters.get(local)
                if waiters is not None:
                    key = "mapping" if event.kind == lib.SIPRAL_EVENT_KIND_NAT_MAPPING else "relay"
                    waiters[key].set()

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
        """`sipral_stack_poll_farewell`: what a call that just ended still
        owes -- its RTCP BYE, and with a TURN server the Refresh that gives
        its relay back -- sent through that call's own media socket to the
        address the stack names. Under ICE that is the path ICE chose or
        the TURN server, not necessarily the last address media came from,
        which is only the fallback for a packet that names none. A call
        whose :class:`sipral.call.Call` was already closed, or that named
        no destination and never heard from the far end at all, is
        skipped: there is nothing left here that could still reach it.
        """
        out_call = ffi.new("sipral_handle_t *")
        packet = self._farewell
        while True:
            packet.size = ffi.sizeof("sipral_media_packet_t")
            packet.data = self._farewell_data
            packet.capacity = _TRANSMIT_BYTES
            packet.destination = self._farewell_destination
            packet.destination_capacity = _ADDRESS_BYTES
            status = lib.sipral_stack_poll_farewell(self.handle, out_call, packet)
            if status != lib.SIPRAL_STATUS_OK:
                return
            if packet.len == 0:
                return
            call = self.call_for(int(out_call[0]))
            if call is None:
                continue
            if packet.destination_len > 0:
                address = ffi.string(packet.destination, packet.destination_len).decode("utf-8")
            elif call.media is not None:
                address = call.media.remote_address
            else:
                address = None
            if call.media is None or address is None:
                continue
            call.media.send_to(bytes(ffi.buffer(packet.data, packet.len)), address)

    # -- STUN/TURN on a media socket, before it has a call's media handle -

    def _map_media_socket(self, sock: socket.socket, address: str, *, timeout: float = 7.0) -> None:
        """`sipral_stack_nat_map`, and the wait its own doc comment
        requires before a call may be described on ``sock``.

        A no-op when this stack was not built with `nat=Nat.STUN`: exactly
        today's behaviour for every other stack. Otherwise ``sock`` is
        registered with the poll thread's own selector under the
        ``("stun", address)`` tag -- :meth:`_run` then hands what arrives
        on it to `sipral_stack_receive_stun` instead of treating it as
        ordinary media, and :meth:`_drain_stun` sends what
        `sipral_stack_poll_stun` hands out for it -- and this call blocks
        the *calling* thread, never the poll thread, until
        `SIPRAL_EVENT_KIND_NAT_MAPPING` names this socket. `docs/06-nat.md`
        and `docs/08-ffi.md` ("Behind a NAT") put that within five and a
        half seconds whatever the server does; ``timeout`` leaves
        comfortable room over that before raising `TimeoutError`, which
        should not happen unless the poll thread itself has stopped.
        """
        if self._nat != lib.SIPRAL_NAT_STUN:
            return
        waiters = {"mapping": threading.Event(), "relay": threading.Event()}
        with self._nat_lock:
            self._stun_sockets[address] = sock
            self._nat_waiters[address] = waiters
        self._selector.register(sock, selectors.EVENT_READ, data=("stun", address))
        address_bytes = address.encode("utf-8")
        local_buf = ffi.new("char[]", address_bytes)
        try:
            _retry(
                lambda: lib.sipral_stack_nat_map(
                    self.handle, local_buf, len(address_bytes), self.now_ms()
                ),
                "sipral_stack_nat_map",
            )
        except Exception:
            self._release_stun_socket(address)
            raise
        if not waiters["mapping"].wait(timeout):
            self._release_stun_socket(address)
            raise TimeoutError(f"no NAT mapping answer for {address} within {timeout}s")
        # `turn_server` rides the same socket: `sipral_call_place` and
        # `sipral_call_answer_media` both refuse a socket named here until
        # its `SIPRAL_EVENT_KIND_NAT_RELAY` has arrived too, allocated or
        # not (`docs/08-ffi.md`, "Behind a NAT").
        if self._turn and not waiters["relay"].wait(timeout):
            self._release_stun_socket(address)
            raise TimeoutError(f"no TURN allocation answer for {address} within {timeout}s")

    def _release_stun_socket(self, address: str) -> None:
        """Stop treating ``address`` as a pre-media-handle STUN/TURN
        socket: called once `SIPRAL_EVENT_KIND_MEDIA_STARTED` hands it to
        :class:`sipral.media.Media` (which reads it from then on) or once
        a call gives up on it before that ever happens."""
        with self._nat_lock:
            sock = self._stun_sockets.pop(address, None)
            self._nat_waiters.pop(address, None)
        if sock is not None:
            try:
                self._selector.unregister(sock)
            except (KeyError, ValueError, OSError):
                pass

    def _forget_media_socket(self, address: str) -> None:
        """`sipral_stack_nat_unmap` for a media socket named with
        `sipral_stack_nat_map` that will carry no call after all --
        `sipral_call_place` or `sipral_call_answer_media` refused it, or
        :meth:`close` is tearing the stack down with it still named. A
        no-op for a socket this stack never mapped (no `nat=Nat.STUN`,
        or the socket already reached `SIPRAL_EVENT_KIND_MEDIA_STARTED`
        and belongs to `Media` now).
        """
        with self._nat_lock:
            mapped = address in self._stun_sockets
        if not mapped:
            return
        address_bytes = address.encode("utf-8")
        local_buf = ffi.new("char[]", address_bytes)
        try:
            _retry(
                lambda: lib.sipral_stack_nat_unmap(
                    self.handle, local_buf, len(address_bytes), self.now_ms()
                ),
                "sipral_stack_nat_unmap",
            )
        except Exception:  # noqa: BLE001 -- best effort on the way out
            pass
        else:
            # A relayed socket owes the server a Refresh with a lifetime
            # of zero, waiting in `sipral_stack_poll_stun` now
            # (`docs/08-ffi.md`, "sipral_stack_nat_unmap"); one drain
            # sends it from the socket while it is still registered and
            # still open.
            self._drain_stun()
        self._release_stun_socket(address)

    def _drain_stun(self) -> None:
        """`sipral_stack_poll_stun`, until nothing is left to send.

        `transmit.source` names which media socket to send from --
        exactly the point of this queue being separate from
        `_drain_transmit`'s: a STUN request for one socket sent from
        another would teach the server the wrong socket's mapping,
        silently (`docs/08-ffi.md`, "Three entry points rather than a
        second use of the two signalling ones").
        """
        transmit = self._stun_transmit
        while True:
            transmit.size = ffi.sizeof("sipral_transmit_t")
            transmit.data = self._stun_data
            transmit.capacity = _TRANSMIT_BYTES
            transmit.destination = self._stun_destination
            transmit.destination_capacity = _ADDRESS_BYTES
            transmit.source = self._stun_source
            transmit.source_capacity = _ADDRESS_BYTES
            status = lib.sipral_stack_poll_stun(self.handle, transmit)
            if status != lib.SIPRAL_STATUS_OK or transmit.len == 0:
                return
            payload = bytes(ffi.buffer(transmit.data, transmit.len))
            destination = ffi.string(transmit.destination, transmit.destination_len).decode("utf-8")
            source_text = ffi.string(transmit.source, transmit.source_len).decode("utf-8")
            with self._nat_lock:
                sock = self._stun_sockets.get(source_text)
            if sock is None:
                continue
            host, port = parse_address(destination)
            try:
                sock.sendto(payload, (host, port))
            except OSError:
                pass

    def _run(self) -> None:
        result = ffi.new("sipral_poll_result_t *")
        while not self._closed.is_set():
            timeout = 0.05
            events = self._selector.select(timeout)
            for key, _mask in events:
                if key.data == "main":
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
                else:
                    # A media socket `_map_media_socket` named, still
                    # waiting for `SIPRAL_EVENT_KIND_NAT_MAPPING` or a
                    # call, or already described but with no media handle
                    # yet: everything arriving on it still goes to
                    # `sipral_stack_receive_stun` (`docs/08-ffi.md`,
                    # "Behind a NAT" -- "Until the call's media handle
                    # exists, everything arriving on its socket still
                    # goes to sipral_stack_receive_stun").
                    _tag, address = key.data
                    sock = key.fileobj
                    try:
                        data, from_address = sock.recvfrom(_TRANSMIT_BYTES)
                    except (BlockingIOError, OSError):
                        continue
                    from_text = format_address(*from_address).encode("utf-8")
                    to_text = address.encode("utf-8")
                    lib.sipral_stack_receive_stun(
                        self.handle,
                        data,
                        len(data),
                        from_text,
                        len(from_text),
                        to_text,
                        len(to_text),
                        self.now_ms(),
                    )
            result.size = ffi.sizeof("sipral_poll_result_t")
            status = lib.sipral_stack_poll(self.handle, self.now_ms(), result)
            if status != lib.SIPRAL_STATUS_OK:
                continue
            self._drain_transmit()
            self._drain_stun()
            self._drain_farewells()

    def close(self) -> None:
        """`sipral_stack_destroy`, and everything this wrapper opened.

        Whatever calls are still open are hung up first, while the poll
        thread can still send what that queues, and while each call is
        still tracked and its media socket still open: `sipral_call_hangup`
        only enqueues the BYE and, once it is answered, the RTCP BYE
        `sipral_stack_poll_farewell` owes the far end
        (`docs/08-ffi.md`, "A call that ends owes the far end an RTCP
        BYE") -- `_drain_transmit` and `_drain_farewells` are what
        actually write those, and that only happens from inside this
        thread's own loop, through `Stack.call_for` and the call's own
        `Media`. Calling `Call.close` on each call before that poll has
        had a chance to run would forget the call and close its media
        socket first, and a farewell drained afterwards would find
        nothing left to send it through -- a clean call reaching for the
        door on its way out and finding it already locked. So hanging up
        happens first, `Call.close` -- which releases the media handle
        and forgets the call -- only after the poll thread has had this
        round to drain both queues.
        """
        if self._closed.is_set():
            return
        with self._lock:
            calls = list(self._calls.values())
        for call in calls:
            if not call.ended:
                try:
                    call.hangup()
                except Exception:  # noqa: BLE001 -- best effort on the way out
                    pass
        if calls:
            # One more round of polling for the hangups just queued to go
            # out and, on loopback, for their answers to come back and be
            # read, and for the farewell each one then owes to be drained
            # and sent while the call is still tracked and its media
            # socket still open -- 200ms is comfortably more than a direct
            # call over a local network needs and still bounded.
            time.sleep(0.2)
        for call in calls:
            call.close()
        # Every media socket still named with `sipral_stack_nat_map` and
        # never reached by a call's own media handle -- `sipral_stack_destroy`
        # sends nothing, and a relay left allocated stays on the server
        # until its lifetime runs out (`docs/08-ffi.md`,
        # "sipral_stack_nat_unmap"). `Call.close` above already did this
        # for every socket a call still owned; this catches one mapped
        # and then abandoned before any call was ever placed on it.
        with self._nat_lock:
            leftover = list(self._stun_sockets)
        for address in leftover:
            self._forget_media_socket(address)
        self._closed.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)
        lib.sipral_stack_destroy(self.handle)
        self._selector.close()
        self._socket.close()
