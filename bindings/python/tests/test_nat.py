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
a second one with `labuser`/`labpass` attached). Proving that leg needs a
server that actually answers -- `_FakeStunServer(credential=...)` below,
the same shape `bindings/swift/Tests/SipralTests/NatTests.swift` and
`bindings/kotlin/.../NatCheck.kt`'s own fake servers are -- which
`TurnAllocationIsGivenBackWhenTheCallEnds` uses for a real, if fake, relay.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_module
import socket as socket_module
import struct
import threading
import unittest

from sipral import Stack
from sipral.enums import (
    CallState,
    CandidateKind,
    EventKind,
    Ice,
    Nat,
    NatRelay,
    PathKind,
    PathOutcome,
)

_MAGIC_COOKIE = 0x2112A442
_COOKIE = struct.pack("!I", _MAGIC_COOKIE)
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_XOR_MAPPED_ADDRESS = 0x0020
_XOR_RELAYED_ADDRESS = 0x0016
_ERROR_CODE = 0x0009
_REALM = 0x0014
_NONCE = 0x0015
_USERNAME = 0x0006
_MESSAGE_INTEGRITY = 0x0008
_LIFETIME = 0x000D
_ALLOCATE_REQUEST = 0x0003
_ALLOCATE_SUCCESS = 0x0103
_ALLOCATE_ERROR = 0x0113
_REFRESH_REQUEST = 0x0004


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


def _xor_address(transaction_id: bytes, host: str, port: int) -> bytes:
    """One RFC 8489 Section 14.2 `XOR-MAPPED-ADDRESS`/`XOR-RELAYED-ADDRESS`
    value, IPv4 only -- the transaction id is what `XOR-RELAYED-ADDRESS`
    (RFC 8656 Section 14.5) XORs the address octets with too, same as
    `XOR-MAPPED-ADDRESS` does; the two share this one encoding."""
    ip_bytes = socket_module.inet_aton(host)
    xport = port ^ (_MAGIC_COOKIE >> 16)
    xaddr = bytes(a ^ b for a, b in zip(ip_bytes, _COOKIE))
    return struct.pack("!BBH", 0, 0x01, xport) + xaddr


def _xor_mapped_address(transaction_id: bytes, host: str, port: int) -> bytes:
    """One RFC 5389 Section 15.2 Binding Success Response, IPv4 only."""
    attr_value = _xor_address(transaction_id, host, port)
    body = struct.pack("!HH", _XOR_MAPPED_ADDRESS, len(attr_value)) + attr_value
    header = struct.pack("!HH", _BINDING_SUCCESS, len(body)) + _COOKIE + transaction_id
    return header + body


def _parse_attributes(data: bytes) -> dict[int, bytes]:
    attributes: dict[int, bytes] = {}
    offset = 20
    while offset + 4 <= len(data):
        attribute, length = struct.unpack("!HH", data[offset : offset + 4])
        if offset + 4 + length > len(data):
            break
        attributes[attribute] = data[offset + 4 : offset + 4 + length]
        offset += 4 + (length + 3) // 4 * 4
    return attributes


def _message(msg_type: int, transaction_id: bytes, attributes: list[tuple[int, bytes]]) -> bytes:
    body = b""
    for attribute, value in attributes:
        padding = b"\x00" * ((4 - len(value) % 4) % 4)
        body += struct.pack("!HH", attribute, len(value)) + value + padding
    return struct.pack("!HH", msg_type, len(body)) + _COOKIE + transaction_id + body


def _long_term_key(username: str, realm: str, password: str) -> bytes:
    """RFC 8489 Section 9.2.2: MD5 of `username:realm:password`."""
    return hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).digest()


def _hmac(data: bytes, key: bytes) -> bytes:
    return hmac_module.new(key, data, hashlib.sha1).digest()


def _integrity_holds(message: bytes, key: bytes) -> bool:
    """RFC 8489 Section 14.5: the HMAC covers the message up to the
    attribute, with the header's length counting up to the attribute's
    end."""
    offset = 20
    while offset + 4 <= len(message):
        attribute, length = struct.unpack("!HH", message[offset : offset + 4])
        if attribute == _MESSAGE_INTEGRITY and length == 20 and offset + 24 <= len(message):
            counted = offset + 24 - 20
            covered = bytearray(message[:offset])
            covered[2:4] = struct.pack("!H", counted)
            return _hmac(bytes(covered), key) == message[offset + 4 : offset + 24]
        offset += 4 + (length + 3) // 4 * 4
    return False


def _signed(msg_type: int, transaction_id: bytes, attributes: list[tuple[int, bytes]], key: bytes) -> bytes:
    unsigned = bytearray(_message(msg_type, transaction_id, attributes))
    counted = len(unsigned) - 20 + 24
    unsigned[2:4] = struct.pack("!H", counted)
    return bytes(unsigned) + struct.pack("!HH", _MESSAGE_INTEGRITY, 20) + _hmac(bytes(unsigned), key)


class _FakeStunServer:
    """A UDP socket that answers every STUN Binding request it reads with
    the same made-up public address.

    Without ``credential``, every other message -- a TURN Allocate among
    them -- is recorded in :attr:`other_requests` and never answered, the
    way :class:`TurnAllocateRequestLeaves` needs it. With one, it is a real,
    if fake, TURN server too: an unauthenticated Allocate (RFC 8656 Section
    7) gets the mandatory 401 with a REALM and a NONCE, a signed one is
    checked against the long-term key and answered with a relay on
    ``relay_host``, and a Refresh -- among them the one with a lifetime of
    zero that gives an allocation back -- is recorded in
    :attr:`requests` the same way every request is, signed or not, answered
    or not (`bindings/swift/Tests/SipralTests/NatTests.swift`'s
    `FakeStunServer` and `bindings/kotlin/.../NatCheck.kt`'s own).
    """

    REALM = "sipral.test"
    NONCE = "0123456789abcdef"
    RELAY_HOST = "198.51.100.9"

    def __init__(
        self,
        public_host: str,
        public_port: int,
        credential: tuple[str, str] | None = None,
    ) -> None:
        self.public_host = public_host
        self.public_port = public_port
        self._credential = credential
        self._socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.05)
        self.address = f"127.0.0.1:{self._socket.getsockname()[1]}"
        self.other_requests: list[bytes] = []
        self.requests: list[tuple[int, dict[int, bytes]]] = []
        self.signed_allocate_verified: bool | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, from_address = self._socket.recvfrom(2048)
            except (socket_module.timeout, OSError):
                continue
            if len(data) < 20 or data[4:8] != _COOKIE:
                continue
            msg_type = struct.unpack("!H", data[0:2])[0]
            transaction_id = data[8:20]
            attributes = _parse_attributes(data)
            method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2)
            self.requests.append((method, attributes))
            if msg_type == _BINDING_REQUEST:
                response = _xor_mapped_address(transaction_id, self.public_host, self.public_port)
                self._socket.sendto(response, from_address)
                continue
            if method == _ALLOCATE_REQUEST and self._credential is not None:
                answer = self._answer_allocate(data, transaction_id, attributes, from_address)
                if answer is not None:
                    self._socket.sendto(answer, from_address)
                continue
            # Without a credential, an Allocate (or its authenticated retry);
            # a Refresh (with or without a lifetime of zero) with one; and
            # anything else: recorded above already, answered to nobody -- a
            # farewell neither waits for nor retries on one.
            self.other_requests.append(data)

    def _answer_allocate(
        self, data: bytes, transaction_id: bytes, attributes: dict[int, bytes], from_address: tuple[str, int]
    ) -> bytes | None:
        if self._credential is None:
            return None
        username, password = self._credential
        given = attributes.get(_USERNAME)
        if given is None:
            return _message(
                _ALLOCATE_ERROR,
                transaction_id,
                [
                    (_ERROR_CODE, struct.pack("!HBB", 0, 4, 1) + b"Unauthorized"),
                    (_REALM, self.REALM.encode("utf-8")),
                    (_NONCE, self.NONCE.encode("utf-8")),
                ],
            )
        key = _long_term_key(username, self.REALM, password)
        verified = given.decode("utf-8", "replace") == username and _integrity_holds(data, key)
        self.signed_allocate_verified = verified
        if not verified:
            return _message(
                _ALLOCATE_ERROR, transaction_id, [(_ERROR_CODE, struct.pack("!HBB", 0, 4, 1) + b"Unauthorized")]
            )
        _, port = from_address
        relayed = _xor_address(transaction_id, self.RELAY_HOST, _moved(port, 20000))
        mapped = _xor_address(transaction_id, self.public_host, _moved(port, 10000))
        return _signed(
            _ALLOCATE_SUCCESS,
            transaction_id,
            [
                (_XOR_RELAYED_ADDRESS, relayed),
                (_XOR_MAPPED_ADDRESS, mapped),
                (_LIFETIME, struct.pack("!I", 600)),
            ],
            key,
        )

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)
        self._socket.close()


def _moved(port: int, distance: int) -> int:
    """A port well away from ``port`` -- never the port itself, so an
    address naming the socket's own port cannot pass for the mapped or
    relayed one."""
    return port - distance if port > 40000 else port + distance


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


class RegistrarFlowKeptOpenBehindTheNat(unittest.IsolatedAsyncioTestCase):
    """`registrar_keepalive`/`registrar_keepalive_ms`: an account the STUN
    answer showed behind a NAT sends its registrar a double CRLF, alone in a
    datagram, so that a NAT filtering by address and port keeps letting the
    registrar's INVITE in (`docs/06-nat.md`, "Refresh"); none goes with it
    off."""

    PUBLIC_HOST = "203.0.113.7"
    PUBLIC_PORT = 40000

    async def _pings(self, keepalive: bool) -> list[bytes]:
        server = _FakeStunServer(self.PUBLIC_HOST, self.PUBLIC_PORT)
        registrar = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
        registrar.bind(("127.0.0.1", 0))
        registrar.settimeout(0.1)
        loop = asyncio.get_running_loop()
        stack = Stack(
            loop=loop,
            nat=Nat.STUN,
            stun_server=server.address,
            registrar_keepalive=keepalive,
            registrar_keepalive_ms=1000 if keepalive else 0,
        )
        try:
            event = None
            while event is None or event.kind != EventKind.NAT_MAPPING:
                event = await asyncio.wait_for(stack.events.get(), timeout=5)
            account = stack.add_account(
                "sip:alice@sipral.invalid",
                registrar_address="127.0.0.1:%d" % registrar.getsockname()[1],
                registrar="sip:sipral.invalid",
            )
            account.register()
            pings: list[bytes] = []
            deadline = loop.time() + 4
            while loop.time() < deadline:
                try:
                    data = await loop.run_in_executor(None, registrar.recv, 2048)
                except (socket_module.timeout, OSError):
                    continue
                if data == b"\r\n\r\n":
                    pings.append(data)
            return pings
        finally:
            stack.close()
            registrar.close()
            server.close()

    async def test_the_registrar_hears_a_keepalive_every_interval(self) -> None:
        self.assertGreaterEqual(len(await self._pings(True)), 2)

    async def test_none_goes_with_it_off(self) -> None:
        self.assertEqual(await self._pings(False), [])


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


class TurnAllocationIsGivenBackWhenTheCallEnds(unittest.IsolatedAsyncioTestCase):
    """Task 8.5.5, ``intern/rapoarte/2026-09-25-nat-layers.json``
    (``natmobile.review.findings[1]``): ``Stack._drain_farewells`` must
    send what ``sipral_stack_poll_farewell`` hands out to the destination
    it names -- the TURN server, for the Refresh with a lifetime of zero
    that gives a relay back (``crates/sipral/src/relay.rs``, "gives it
    back when the call ends") -- and only fall back to the last address
    media was heard from when it names none.

    ``crates/sipral/src/relay.rs`` also says: "A call whose peer does no
    ICE never uses it, and gives it back the same way" -- so this needs
    nothing more than a call that reaches ``bob``, an ordinary stack with
    no NAT handling of its own, and is then closed. Were the destination
    ignored in favour of the far end's own address, as it once was, this
    fake TURN server would never see the Refresh at all -- and if
    ``call.media.remote_address`` was still ``None`` at that point, the
    farewell used to be dropped outright rather than sent anywhere.
    """

    PUBLIC_HOST = "203.0.113.9"
    PUBLIC_PORT = 40002

    async def asyncSetUp(self) -> None:
        host = _routable_address()
        if host is None:
            self.skipTest("no routable address on this machine for ICE to gather a host candidate from")
        self.host = host
        self.password = "turn-secret-42"
        self.server = _FakeStunServer(
            self.PUBLIC_HOST, self.PUBLIC_PORT, credential=("alice-turn", self.password)
        )
        self.addAsyncCleanup(self._close_server)
        loop = asyncio.get_running_loop()
        # `codecs="PCMU"` keeps the offer's `m=`/`a=rtpmap` short: with three
        # ICE candidates (host, server-reflexive, relayed) added on top of
        # every codec this build has by default, the INVITE clears RFC
        # 3261 Section 18.1.1's 1300-byte line and this loopback pair has no
        # stream transport open to fall back to.
        self.alice_stack = Stack(
            bind_host=host,
            loop=loop,
            nat=Nat.STUN,
            ice=Ice.OFFERED,
            codecs="PCMU",
            stun_server=self.server.address,
            turn_server=self.server.address,
            turn_username="alice-turn",
            turn_password=self.password,
        )
        self.bob_stack = Stack(bind_host=host, loop=loop, codecs="PCMU")
        self.addAsyncCleanup(self._close_stacks)

    async def _close_server(self) -> None:
        self.server.close()

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def test_refresh_reaches_the_turn_server_not_the_peer(self) -> None:
        alice_account = self.alice_stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=self.bob_stack.bind_address,
        )
        self.bob_stack.add_account(
            "sip:bob@sipral.invalid",
            registrar_address=self.alice_stack.bind_address,
        )

        alice_call = self.alice_stack.place_call(
            alice_account, f"sip:bob@{self.bob_stack.bind_address}", media_host=self.host
        )

        relay = None
        while relay is None:
            event = await asyncio.wait_for(self.alice_stack.events.get(), timeout=8)
            if event.kind == EventKind.NAT_RELAY:
                relay = event
        self.assertEqual(
            relay.fields["outcome"], NatRelay.ALLOCATED, f"relay failed: {relay.fields}"
        )

        bob_call = None
        while bob_call is None:
            event = await asyncio.wait_for(self.bob_stack.events.get(), timeout=8)
            if event.kind == EventKind.INCOMING_CALL:
                bob_call = self.bob_stack.answer_call(event, media_host=self.host)
        self.addAsyncCleanup(bob_call.close)

        # The session has to actually open -- and the relay actually become
        # the call's -- before there is anything for a farewell to give
        # back; a call hung up before its media ever starts leaves the
        # relay to `Stack._forget_media_socket` instead
        # (`bindings/python/sipral/call.py`'s `Call.close`).
        while alice_call.media is None:
            await asyncio.wait_for(alice_call.events.get(), timeout=8)

        # `Stack.close`, not `Call.close`: hanging up and forgetting the
        # call right here would race the poll thread's own drain of the
        # farewell it leaves behind (`Stack.close`'s own doc comment).
        # `Stack.close` hangs up, gives the poll thread a round to drain
        # both queues while the call is still tracked, and only then
        # forgets it.
        self.alice_stack.close()

        deadline = asyncio.get_running_loop().time() + 5
        refresh = None
        while refresh is None and asyncio.get_running_loop().time() < deadline:
            for method, attributes in self.server.requests:
                if method == _REFRESH_REQUEST:
                    refresh = (method, attributes)
                    break
            if refresh is None:
                await asyncio.sleep(0.05)
        self.assertIsNotNone(
            refresh,
            "the TURN server never saw the Refresh that gives the relay back -- "
            f"the farewell went somewhere other than {self.server.address}",
        )
        lifetime = refresh[1].get(_LIFETIME)
        self.assertEqual(lifetime, struct.pack("!I", 0), "the Refresh does not ask for a lifetime of zero")


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
        alice_call, bob_call = await self._connect()
        self.assertEqual(alice_call.state, CallState.CONFIRMED)
        self.assertEqual(bob_call.state, CallState.CONFIRMED)
        self.assertTrue(alice_call.media.info()["sending"])
        self.assertTrue(bob_call.media.info()["receiving"])

    async def test_the_call_says_which_paths_it_tried_and_restarts_its_ice(self) -> None:
        """D5's path half and a restart this end starts, through the
        idiomatic layer: the agent names the one pair that carries the call,
        and `restart_ice()` checks again under new credentials until a
        second path is chosen."""
        alice_call, _ = await self._connect()
        paths = alice_call.media.path_candidates()
        chosen = [
            path
            for path in paths
            if path["kind"] == PathKind.PAIR and path["outcome"] == PathOutcome.SELECTED
        ]
        self.assertEqual(len(chosen), 1, paths)
        self.assertEqual(chosen[0]["local_kind"], CandidateKind.HOST, paths)
        self.assertGreater(chosen[0]["priority"], 0)
        self.assertTrue(chosen[0]["remote"], paths)

        alice_call.restart_ice()
        event = None
        while event is None or event.kind != EventKind.MEDIA_PATH_CHOSEN:
            event = await asyncio.wait_for(alice_call.events.get(), timeout=10)

    async def _connect(self):
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
        return alice_call, bob_call
