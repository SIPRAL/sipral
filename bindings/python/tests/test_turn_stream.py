# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``turn_transport``: a TURN server reached over TCP, or over TLS, from a
network that lets no UDP through to it (RFC 8656 Section 3.1).

The server here is this test's own, on loopback, and it listens on a TCP
port alone: nothing about the relay can reach it as a datagram. It frames
what arrives the way RFC 8656 Section 12.5 and RFC 8489 Section 6.2.2
describe -- a STUN message is twenty octets and its length, a channel
message four and its length padded to whole words -- answers an
unauthenticated Allocate with the 401 of the long-term mechanism and a
signed one with a relay, and records every request with the connection it
came on. The STUN Binding request that maps the media socket still goes
over UDP, to the fake server `test_nat.py` already has: the mapping is the
socket's own, and a stream's would describe another binding.

`TurnOverTcp` proves the connection is opened when the stack asks, carries
the Allocate and its answer, carries the Refresh with a lifetime of zero
when the stack closes -- on the connection the allocation was made on,
since the server knows it by that connection -- and is closed after.
`TurnOverTls` proves the handshake checks the server's certificate: a
context that trusts the test's own self-signed certificate reaches the
server and gets a relay, and the platform's default trust, which does not
know that certificate, gets none -- and the call goes ahead without one.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket as socket_module
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest

from sipral import Stack
from sipral.enums import AudioMode, EventKind, Ice, Nat, NatRelay, Transport

from tests.test_nat import (
    _ALLOCATE_ERROR,
    _ALLOCATE_REQUEST,
    _ALLOCATE_SUCCESS,
    _COOKIE,
    _ERROR_CODE,
    _LIFETIME,
    _NONCE,
    _REALM,
    _REFRESH_REQUEST,
    _USERNAME,
    _XOR_MAPPED_ADDRESS,
    _XOR_RELAYED_ADDRESS,
    _FakeStunServer,
    _integrity_holds,
    _long_term_key,
    _message,
    _parse_attributes,
    _routable_address,
    _signed,
    _xor_address,
)

_SERVER_NAME = "turn.sipral.test"


def _method(msg_type: int) -> int:
    return (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2)


class _FakeTurnOverStream:
    """A TURN server on a TCP port, over TLS when given a certificate.

    :attr:`requests` holds ``(connection, method, attributes)`` for every
    STUN request, in order, ``connection`` counting the connections from
    one; :attr:`closed` the connections the client closed.
    """

    REALM = "sipral.test"
    NONCE = "fedcba9876543210"
    RELAY_HOST = "198.51.100.19"

    def __init__(self, credential: tuple[str, str], certificate: tuple[str, str] | None = None) -> None:
        self._credential = credential
        self._context = None
        if certificate is not None:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.load_cert_chain(*certificate)
        self._listener = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen()
        self._listener.settimeout(0.05)
        self.address = f"127.0.0.1:{self._listener.getsockname()[1]}"
        self.requests: list[tuple[int, int, dict[int, bytes]]] = []
        self.closed: list[int] = []
        self.connections = 0
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        accepting = threading.Thread(target=self._accept, daemon=True)
        accepting.start()
        self._threads.append(accepting)

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (socket_module.timeout, OSError):
                continue
            self.connections += 1
            serving = threading.Thread(target=self._serve, args=(conn, self.connections), daemon=True)
            serving.start()
            self._threads.append(serving)

    def _serve(self, conn: socket_module.socket, number: int) -> None:
        conn.settimeout(0.05)
        peer = conn.getpeername()
        if self._context is not None:
            conn.settimeout(5.0)
            try:
                conn = self._context.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                conn.close()
                self.closed.append(number)
                return
            conn.settimeout(0.05)
        held = b""
        while not self._stop.is_set():
            try:
                data = conn.recv(4096)
            except (socket_module.timeout, ssl.SSLWantReadError):
                continue
            except (OSError, ssl.SSLError):
                data = b""
            if not data:
                self.closed.append(number)
                conn.close()
                return
            held += data
            while True:
                frame, held = self._frame(held)
                if frame is None:
                    break
                answer = self._answer(number, frame, peer)
                if answer is not None:
                    conn.sendall(answer)
        conn.close()

    @staticmethod
    def _frame(held: bytes) -> tuple[bytes | None, bytes]:
        if len(held) < 4:
            return None, held
        if held[0] < 4:
            if len(held) < 20:
                return None, held
            length = 20 + struct.unpack("!H", held[2:4])[0]
            if len(held) < length:
                return None, held
            return held[:length], held[length:]
        length = 4 + struct.unpack("!H", held[2:4])[0]
        padded = (length + 3) // 4 * 4
        if len(held) < padded:
            return None, held
        return held[:length], held[padded:]

    def _answer(self, number: int, frame: bytes, peer: tuple[str, int]) -> bytes | None:
        if frame[0] >= 4 or frame[4:8] != _COOKIE:
            return None
        msg_type = struct.unpack("!H", frame[0:2])[0]
        if msg_type & 0x0110 != 0x0000:
            # an indication -- the keepalive -- or anything but a request
            return None
        method = _method(msg_type)
        transaction_id = frame[8:20]
        attributes = _parse_attributes(frame)
        self.requests.append((number, method, attributes))
        username, password = self._credential
        if _USERNAME not in attributes:
            return _message(
                _ALLOCATE_ERROR if method == _ALLOCATE_REQUEST else (0x0110 | msg_type),
                transaction_id,
                [
                    (_ERROR_CODE, struct.pack("!HBB", 0, 4, 1) + b"Unauthorized"),
                    (_REALM, self.REALM.encode("utf-8")),
                    (_NONCE, self.NONCE.encode("utf-8")),
                ],
            )
        key = _long_term_key(username, self.REALM, password)
        if not _integrity_holds(frame, key):
            return None
        success = msg_type | 0x0100
        if method == _ALLOCATE_REQUEST:
            relayed = _xor_address(transaction_id, self.RELAY_HOST, 50000 + number)
            mapped = _xor_address(transaction_id, peer[0], peer[1])
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
        if method == _REFRESH_REQUEST:
            lifetime = attributes.get(_LIFETIME, struct.pack("!I", 600))
            return _signed(success, transaction_id, [(_LIFETIME, lifetime)], key)
        return _signed(success, transaction_id, [], key)

    def refreshes(self) -> list[tuple[int, bytes | None]]:
        """Every signed Refresh, with its connection and its lifetime."""
        return [
            (number, attributes.get(_LIFETIME))
            for number, method, attributes in self.requests
            if method == _REFRESH_REQUEST and _USERNAME in attributes
        ]

    def allocations(self) -> list[int]:
        """The connection of every signed Allocate."""
        return [
            number
            for number, method, attributes in self.requests
            if method == _ALLOCATE_REQUEST and _USERNAME in attributes
        ]

    def close(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._listener.close()


class _TwoStacks(unittest.IsolatedAsyncioTestCase):
    """Alice behind a TURN server reached over ``TRANSPORT``, Bob with no
    NAT handling at all; both on a routable address so that ICE has a host
    candidate to gather."""

    TRANSPORT = Transport.TCP
    PUBLIC = ("203.0.113.21", 40021)

    def certificate(self) -> tuple[str, str] | None:
        return None

    def client_context(self) -> ssl.SSLContext | None:
        return None

    async def asyncSetUp(self) -> None:
        host = _routable_address()
        if host is None:
            self.skipTest("no routable address on this machine for ICE to gather a host candidate from")
        self.host = host
        # before any server exists: a TLS case skips here on a machine with
        # no openssl, and a cleanup already registered would then close a
        # server that was never made
        certificate = self.certificate()
        self.stun = _FakeStunServer(*self.PUBLIC, host=host)
        self.turn = _FakeTurnOverStream(("alice-turn", "turn-secret-7"), certificate)
        self.addAsyncCleanup(self._close_servers)
        loop = asyncio.get_running_loop()
        self.alice_stack = Stack(
            bind_host=host,
            loop=loop, audio=AudioMode.APPLICATION,
            nat=Nat.STUN,
            ice=Ice.OFFERED,
            codecs="PCMU",
            stun_server=self.stun.address,
            turn_server=self.turn.address,
            turn_username="alice-turn",
            turn_password="turn-secret-7",
            turn_transport=self.TRANSPORT,
            turn_server_name=_SERVER_NAME,
            turn_tls_context=self.client_context(),
        )
        self.bob_stack = Stack(bind_host=host, loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.addAsyncCleanup(self._close_stacks)

    async def _close_servers(self) -> None:
        self.stun.close()
        self.turn.close()

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def place(self):
        """Alice calls Bob, and Bob answers: Alice's call, and what her
        socket's `SIPRAL_EVENT_KIND_NAT_RELAY` said."""
        alice_account = self.alice_stack.add_account(
            "sip:alice@sipral.invalid", registrar_address=self.bob_stack.bind_address
        )
        self.bob_stack.add_account("sip:bob@sipral.invalid", registrar_address=self.alice_stack.bind_address)
        call = await asyncio.to_thread(
            self.alice_stack.place_call,
            alice_account,
            f"sip:bob@{self.bob_stack.bind_address}",
            media_host=self.host,
        )
        relay = None
        while relay is None:
            event = await asyncio.wait_for(self.alice_stack.events.get(), timeout=10)
            if event.kind == EventKind.NAT_RELAY:
                relay = event
        bob_call = None
        while bob_call is None:
            event = await asyncio.wait_for(self.bob_stack.events.get(), timeout=10)
            if event.kind == EventKind.INCOMING_CALL:
                bob_call = self.bob_stack.answer_call(event, media_host=self.host)
        self.addAsyncCleanup(bob_call.close)
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=10)
        return call, relay

    async def until(self, what, seconds: float = 5.0) -> None:
        deadline = asyncio.get_running_loop().time() + seconds
        while not what() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)


class TurnOverTcp(_TwoStacks):
    async def test_the_relay_is_made_and_given_back_on_its_connection(self) -> None:
        call, relay = await self.place()
        self.assertEqual(relay.fields["outcome"], NatRelay.ALLOCATED, relay.fields)
        # the connection's own mapping says nothing about the socket
        self.assertFalse(relay.fields["mapped"], relay.fields)
        self.assertEqual(self.turn.allocations(), [1], "one Allocate, on the one connection")
        self.assertFalse(
            any(struct.unpack("!H", request[0:2])[0] == _ALLOCATE_REQUEST for request in self.stun.other_requests),
            "an Allocate went as a datagram",
        )

        # the call is closed and forgotten while the stack runs on: its relay
        # still goes back on the connection, which then has nothing left
        call.close()
        await self.until(lambda: any(lifetime == struct.pack("!I", 0) for _, lifetime in self.turn.refreshes()))
        given_back = [number for number, lifetime in self.turn.refreshes() if lifetime == struct.pack("!I", 0)]
        self.assertEqual(given_back, [1], "given back on the connection it was made on")
        await self.until(lambda: 1 in self.turn.closed)
        self.assertIn(1, self.turn.closed, "the connection was closed once nothing was left for it")


def _self_signed(directory: str) -> tuple[str, str] | None:
    """A certificate and key for :data:`_SERVER_NAME`, made with the
    `openssl` command, or `None` where there is none."""
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    certificate = os.path.join(directory, "turn.pem")
    key = os.path.join(directory, "turn.key")
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN={_SERVER_NAME}",
            "-addext",
            f"subjectAltName=DNS:{_SERVER_NAME}",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-keyout",
            key,
            "-out",
            certificate,
        ],
        check=True,
        capture_output=True,
    )
    return certificate, key


class _OverTls(_TwoStacks):
    TRANSPORT = Transport.TLS
    PUBLIC = ("203.0.113.22", 40022)

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.mkdtemp()
        cls._certificate = _self_signed(cls._directory)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._directory, ignore_errors=True)

    def certificate(self) -> tuple[str, str] | None:
        if self._certificate is None:
            self.skipTest("no openssl command to make the server's certificate with")
        return self._certificate


class TurnOverTls(_OverTls):
    def client_context(self) -> ssl.SSLContext | None:
        return ssl.create_default_context(cafile=self._certificate[0])

    async def test_a_server_the_context_vouches_for_gives_a_relay(self) -> None:
        started = asyncio.get_running_loop().time()
        _call, relay = await self.place()
        # TLS 1.3 sends its session tickets after the handshake, and a
        # read that waited on them for more would hold the poll thread --
        # every timer, every datagram, every event of the stack -- for as
        # long as the socket's timeout
        self.assertLess(asyncio.get_running_loop().time() - started, 3.0, "the poll thread stalled on the connection")
        self.assertEqual(relay.fields["outcome"], NatRelay.ALLOCATED, relay.fields)
        self.assertEqual(self.turn.allocations(), [1])
        self.alice_stack.close()
        await self.until(lambda: any(lifetime == struct.pack("!I", 0) for _, lifetime in self.turn.refreshes()))
        self.assertIn((1, struct.pack("!I", 0)), self.turn.refreshes())


class TurnOverTlsUntrusted(_OverTls):
    PUBLIC = ("203.0.113.23", 40023)

    async def test_a_certificate_nobody_vouches_for_is_no_relay_and_the_call_goes_on(self) -> None:
        call, relay = await self.place()
        self.assertEqual(relay.fields["outcome"], NatRelay.FAILED, relay.fields)
        self.assertIn("connection", relay.fields["reason"])
        self.assertEqual(self.turn.allocations(), [], "nothing reached the server past the handshake")
        self.assertIsNotNone(call.media, "the call went ahead without a relay")


if __name__ == "__main__":
    unittest.main()
