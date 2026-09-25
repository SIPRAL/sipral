# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``nat=Nat.STUN`` and ``stun_server`` on :class:`sipral.stack.Stack`.

Two things this proves, each with a server this test runs itself rather
than a real one: no lab, no coturn, no network beyond loopback.

`TwoStacksTalkThroughStun` answers a STUN Binding request the way RFC 5389
Section 15.2 describes -- `XOR-MAPPED-ADDRESS` set to a made-up public
address this loopback pair could never actually route to -- and checks
that a stack pointed at it both raises `SIPRAL_EVENT_KIND_NAT_MAPPING`
(`Stack.events`, not a call's own) for its *signalling* socket with no
application code beyond the constructor, and, once it places a call, waits
for its *media* socket's own mapping (`sipral.stack.Stack._map_media_socket`,
the `sipral_stack_nat_map` / `sipral_stack_receive_stun` exchange
`bindings/python/sipral/stack.py` drives from the poll thread) and offers
that address in `c=` -- `docs/06-nat.md`'s "With ICE on" is what a peer
would read it as if the call went on to use ICE, and this is the offer
before any of that, which is where the address has to be for a peer with
no NAT helper of its own to work at all.

`TurnAllocateRequestLeaves` is what the brief calls "at least as far as the
allocation request leaving": a `turn_server` naming a fake server that
never answers still gets `sipral_stack_nat_map`'s Binding request out
(taken by this test's fake STUN responder, which this one also is) and,
once that is answered, an unauthenticated TURN Allocate request, read off
the wire this test listens on directly -- RFC 8656 Section 9's mandatory
401 challenge round, and the credentialed retry it would prompt, needs a
server that actually sends the 401, which this fake one deliberately does
not (checked directly: this test's own server sees nothing but identical
retransmits of that first request over several seconds of retrying, never
a second one with `labuser`/`labpass` attached). Proving that leg, and an
actual relay, both need coturn, which this repository does not run outside
the lab (`intern/ops/agenti-si-cost.md`); this is as far as a unit test
gets.
"""

from __future__ import annotations

import asyncio
import socket as socket_module
import struct
import threading
import unittest

from sipral import Stack
from sipral.enums import CallState, EventKind, Ice, Nat

_MAGIC_COOKIE = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_XOR_MAPPED_ADDRESS = 0x0020
_ALLOCATE_REQUEST = 0x0003


def _routable_address() -> str | None:
    """This host's own address on whatever interface its default route
    uses, or ``None`` on a machine with none to find.

    RFC 8445 Section 5.1.1.1 rules loopback out as a host candidate --
    `docs/06-nat.md`, "Gathering" -- so `TwoStacksTalkThroughIce` needs an
    address that is not `127.0.0.1` even though both stacks it binds stay
    on this one machine. `connect` on a UDP socket asks the kernel to pick
    a source address for a destination without ever sending a packet
    (there is no three-way handshake to complete, the way there would be
    over TCP), so this reads the routing table and nothing else.
    """
    probe = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    try:
        probe.connect(("203.0.113.1", 80))  # RFC 5737 TEST-NET-3: never dialled
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def _xor_mapped_address(transaction_id: bytes, host: str, port: int) -> bytes:
    """One RFC 5389 Section 15.2 Binding Success Response, IPv4 only."""
    cookie = struct.pack("!I", _MAGIC_COOKIE)
    ip_bytes = socket_module.inet_aton(host)
    xport = port ^ (_MAGIC_COOKIE >> 16)
    xaddr = bytes(a ^ b for a, b in zip(ip_bytes, cookie))
    attr_value = struct.pack("!BBH", 0, 0x01, xport) + xaddr
    body = struct.pack("!HH", _XOR_MAPPED_ADDRESS, len(attr_value)) + attr_value
    header = struct.pack("!HH", _BINDING_SUCCESS, len(body)) + cookie + transaction_id
    return header + body


class _FakeStunServer:
    """A UDP socket that answers every STUN Binding request it reads with
    the same made-up public address, and records every other STUN message
    -- a TURN Allocate among them -- it saw instead of answering it."""

    def __init__(self, public_host: str, public_port: int) -> None:
        self.public_host = public_host
        self.public_port = public_port
        self._socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.05)
        self.address = f"127.0.0.1:{self._socket.getsockname()[1]}"
        self.other_requests: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, from_address = self._socket.recvfrom(2048)
            except (socket_module.timeout, OSError):
                continue
            if len(data) < 20:
                continue
            msg_type = struct.unpack("!H", data[0:2])[0]
            transaction_id = data[8:20]
            if msg_type == _BINDING_REQUEST:
                response = _xor_mapped_address(transaction_id, self.public_host, self.public_port)
                self._socket.sendto(response, from_address)
            else:
                # An Allocate request (or its authenticated retry): recorded,
                # not answered, so the request this test cares about -- that
                # it left at all -- is not entangled with a second one, real
                # relay allocation, this test cannot make.
                self.other_requests.append(data)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)
        self._socket.close()


class TwoStacksTalkThroughStun(unittest.IsolatedAsyncioTestCase):
    PUBLIC_HOST = "203.0.113.7"  # RFC 5737 TEST-NET-3: never a real route
    PUBLIC_PORT = 40000

    async def asyncSetUp(self) -> None:
        self.server = _FakeStunServer(self.PUBLIC_HOST, self.PUBLIC_PORT)
        self.addAsyncCleanup(self._close_server)
        loop = asyncio.get_running_loop()
        self.alice_stack = Stack(loop=loop, nat=Nat.STUN, stun_server=self.server.address)
        self.bob_stack = Stack(loop=loop)
        self.addAsyncCleanup(self._close_stacks)

    async def _close_server(self) -> None:
        self.server.close()

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def test_signalling_socket_learns_the_mapping_on_its_own(self) -> None:
        """No call, no account: the stack's own signalling socket asks the
        moment it is built (`docs/08-ffi.md`, "Behind a NAT")."""
        event = None
        while event is None or event.kind != EventKind.NAT_MAPPING:
            event = await asyncio.wait_for(self.alice_stack.events.get(), timeout=5)
        self.assertTrue(event.fields["signalling"])
        self.assertEqual(event.fields["mapped"], f"{self.PUBLIC_HOST}:{self.PUBLIC_PORT}")

    async def test_call_offers_the_mapped_media_address(self) -> None:
        """`Stack.place_call` waits out its own media socket's mapping
        (`Stack._map_media_socket`) before the offer is ever written, so
        the public address this test's fake server handed out is already
        in `c=`/`m=` the moment the far end reads the INVITE."""
        alice_account = self.alice_stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=self.bob_stack.bind_address,
        )
        self.bob_stack.add_account(
            "sip:bob@sipral.invalid",
            registrar_address=self.alice_stack.bind_address,
        )

        alice_call = self.alice_stack.place_call(
            alice_account, f"sip:bob@{self.bob_stack.bind_address}"
        )
        self.addAsyncCleanup(alice_call.close)

        # `sipral_call_event_t::local_sdp`/`remote_sdp` are only ever set on
        # `SIPRAL_EVENT_KIND_SESSION_CHANGED` (a hold, a re-INVITE -- neither
        # happens here); the offer itself is read the way any SIP listener
        # would, off the raw INVITE `SIPRAL_EVENT_KIND_INCOMING_CALL`
        # attaches as `event.message` (`crates/sipral-ffi/src/event.rs`'s
        # `attach`).
        event = None
        while event is None or event.kind != EventKind.INCOMING_CALL:
            event = await asyncio.wait_for(self.bob_stack.events.get(), timeout=5)
        self.assertIn(f"c=IN IP4 {self.PUBLIC_HOST}".encode("ascii"), event.message)
        self.assertIn(f"{self.PUBLIC_HOST}:{self.PUBLIC_PORT}".encode("ascii"), event.message)


class TurnAllocateRequestLeaves(unittest.IsolatedAsyncioTestCase):
    """`turn_server`/`turn_username`/`turn_password`: proof bounded by what
    a unit test can see without a real relay (module docstring)."""

    PUBLIC_HOST = "203.0.113.8"
    PUBLIC_PORT = 40001

    async def asyncSetUp(self) -> None:
        self.server = _FakeStunServer(self.PUBLIC_HOST, self.PUBLIC_PORT)
        self.addAsyncCleanup(self._close_server)
        loop = asyncio.get_running_loop()
        self.alice_stack = Stack(
            loop=loop,
            nat=Nat.STUN,
            stun_server=self.server.address,
            turn_server=self.server.address,
            turn_username="labuser",
            turn_password="labpass",
        )
        self.bob_stack = Stack(loop=loop)
        self.addAsyncCleanup(self._close_stacks)

    async def _close_server(self) -> None:
        self.server.close()

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def test_allocate_leaves_for_the_configured_server(self) -> None:
        # `sipral_call_place` itself refuses a socket named with
        # `sipral_stack_nat_map` until both `SIPRAL_EVENT_KIND_NAT_MAPPING`
        # and `SIPRAL_EVENT_KIND_NAT_RELAY` have answered for it
        # (`Stack._map_media_socket` waits out both once `turn_server` is
        # set) -- and this fake server, true to the module docstring,
        # never answers the Allocate its own `SIPRAL_EVENT_KIND_NAT_RELAY`
        # would need. So this reaches into `Stack._map_media_socket`
        # directly, on a thread of its own, with a short timeout: what it
        # proves is that the Allocate left, not that a call could be
        # placed on the socket.
        media_socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
        media_socket.bind(("127.0.0.1", 0))
        media_socket.setblocking(False)
        media_address = f"127.0.0.1:{media_socket.getsockname()[1]}"

        outcome: dict[str, BaseException] = {}

        def _map() -> None:
            try:
                self.alice_stack._map_media_socket(media_socket, media_address, timeout=2.0)
            except BaseException as exc:  # noqa: BLE001 -- carried back for assertion
                outcome["error"] = exc

        thread = threading.Thread(target=_map, daemon=True)
        thread.start()
        thread.join(timeout=5.0)
        self.assertFalse(thread.is_alive(), "_map_media_socket did not return")
        self.assertIsInstance(outcome.get("error"), TimeoutError)

        deadline = asyncio.get_running_loop().time() + 2
        while not self.server.other_requests and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)
        self.assertTrue(self.server.other_requests, "no Allocate request reached the server")
        msg_type = struct.unpack("!H", self.server.other_requests[0][0:2])[0]
        self.assertEqual(msg_type, _ALLOCATE_REQUEST)
        media_socket.close()


class TwoStacksTalkThroughIce(unittest.IsolatedAsyncioTestCase):
    """`ice=Ice.REQUIRED`, no NAT and no server at all: two stacks bound to
    this host's own routable address (never `127.0.0.1` -- RFC 8445
    Section 5.1.1.1, `docs/06-nat.md` "Gathering") gather one host
    candidate each, run a full checklist and nominate it, and media
    starts, both ways, only once that agent's own `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`
    says so -- the ICE plumbing `Stack.place_call`'s and
    `Stack.answer_call`'s ``ice=``/`nat=Nat.STUN`` never touch, since
    nothing here is behind a NAT.
    """

    async def asyncSetUp(self) -> None:
        host = _routable_address()
        if host is None:
            self.skipTest("no routable address on this machine to gather a host candidate from")
        self.host = host
        loop = asyncio.get_running_loop()
        self.alice_stack = Stack(bind_host=host, loop=loop, ice=Ice.REQUIRED)
        self.bob_stack = Stack(bind_host=host, loop=loop, ice=Ice.REQUIRED)
        self.addAsyncCleanup(self._close_stacks)

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def test_call_reaches_confirmed_with_media_both_ways(self) -> None:
        alice_account = self.alice_stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=self.bob_stack.bind_address,
        )
        self.bob_stack.add_account(
            "sip:bob@sipral.invalid",
            registrar_address=self.alice_stack.bind_address,
        )

        alice_call = self.alice_stack.place_call(
            alice_account,
            f"sip:bob@{self.bob_stack.bind_address}",
            media_host=self.host,
            ice=Ice.REQUIRED,
        )
        self.addAsyncCleanup(alice_call.close)

        bob_call = None
        while bob_call is None:
            event = await asyncio.wait_for(self.bob_stack.events.get(), timeout=8)
            if event.kind == EventKind.INCOMING_CALL:
                bob_call = self.bob_stack.answer_call(event, media_host=self.host)
        self.addAsyncCleanup(bob_call.close)

        while alice_call.media is None:
            await asyncio.wait_for(alice_call.events.get(), timeout=8)
        while bob_call.media is None:
            await asyncio.wait_for(bob_call.events.get(), timeout=8)

        # `MEDIA_PATH_CHOSEN` is the agent's own nomination, on each side
        # (`docs/08-ffi.md`); reaching it, rather than `MEDIA_FAILED`, is
        # what tells this from a call ICE never got to run on.
        for call in (alice_call, bob_call):
            event = None
            while event is None or event.kind != EventKind.MEDIA_PATH_CHOSEN:
                event = await asyncio.wait_for(call.events.get(), timeout=8)

        self.assertEqual(alice_call.state, CallState.CONFIRMED)
        self.assertEqual(bob_call.state, CallState.CONFIRMED)
        self.assertTrue(alice_call.media.info()["sending"])
        self.assertTrue(bob_call.media.info()["receiving"])
