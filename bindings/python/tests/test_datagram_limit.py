# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""RFC 3261 Section 18.1.1 through the Python layer: a call whose answer to
a challenge is too large for a datagram.

A fake PBX challenges with a nonce long enough to push the authenticated
INVITE (two SDES suites) past 1300 bytes, optionally with a TCP listener
answering 486.

With TCP the stack opens a connection itself and the call continues over it
with a TCP `Via`; without, or with ``stream_fallback=False``, the call ends
at once as unreachable with a 513 naming size and limit.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import unittest

from sipral import SipralError, Stack
from sipral._sipral_cffi import lib
from sipral.events import Event
from sipral.enums import AudioMode, CallEndReason, EventKind, Status, TransportError

#: Long enough that even a one-suite retry exceeds the limit.
_NONCE_BYTES = 700


#: Compact header names (RFC 3261 Section 7.3.3): an oversized request is
#: compacted before it is measured.
_COMPACT = {"via": "v", "from": "f", "to": "t", "call-id": "i", "content-length": "l"}


def _header(name: str, message: str) -> str | None:
    names = {name.lower(), _COMPACT.get(name.lower(), name.lower())}
    for line in message.split("\r\n"):
        field, colon, value = line.partition(":")
        if colon and field.strip().lower() in names:
            return value.strip()
    return None


def _response(request: str, status: str, extra: str = "") -> bytes:
    lines = [f"SIP/2.0 {status}"]
    for name in ("Via", "From", "To", "Call-ID", "CSeq"):
        value = _header(name, request)
        if name == "To" and value is not None and ";tag=" not in value:
            value = f"{value};tag=pbx"
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n" + extra + "Content-Length: 0\r\n\r\n").encode("utf-8")


class _Pbx:
    """Challenges INVITEs over UDP; with ``tcp``, also listens on TCP.
    :attr:`over_tcp` holds requests received on connections."""

    def __init__(self, *, tcp: bool, apart: bool = False) -> None:
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.05)
        port = self._udp.getsockname()[1]
        self.address = f"127.0.0.1:{port}"
        self._listener: socket.socket | None = None
        if tcp:
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # ``apart``: TCP on its own port, like 5060/5160.
            self._listener.bind(("127.0.0.1", 0 if apart else port))
            self._listener.listen()
            self._listener.settimeout(0.05)
        #: Where TCP is taken, ``None`` without it.
        self.tcp_address = (
            f"127.0.0.1:{self._listener.getsockname()[1]}" if self._listener is not None else None
        )
        self.over_tcp: list[str] = []
        #: Sizes of authenticated INVITEs received over UDP.
        self.answered_over_udp: list[tuple[str, int]] = []
        self.connections = 0
        #: How many of those connections the stack closed.
        self.closed_by_the_stack = 0
        self._stop = threading.Event()
        threading.Thread(target=self._serve_udp, daemon=True).start()
        if self._listener is not None:
            threading.Thread(target=self._accept, daemon=True).start()

    def _serve_udp(self) -> None:
        nonce = "n" * _NONCE_BYTES
        while not self._stop.is_set():
            try:
                data, peer = self._udp.recvfrom(65536)
            except (socket.timeout, OSError):
                continue
            message = data.decode("utf-8", "replace")
            if message.startswith("INVITE ") and _header("Authorization", message) is None:
                challenge = f'WWW-Authenticate: Digest realm="asterisk", nonce="{nonce}", qop="auth"\r\n'
                self._udp.sendto(_response(message, "401 Unauthorized", challenge), peer)
            elif message.startswith("INVITE "):
                self.answered_over_udp.append((message, len(data)))
                self._udp.sendto(_response(message, "486 Busy Here"), peer)

    def _accept(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            threading.Thread(target=self._serve_tcp, args=(conn,), daemon=True).start()

    def _serve_tcp(self, conn: socket.socket) -> None:
        conn.settimeout(0.05)
        held = b""
        while not self._stop.is_set():
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                data = b""
            if not data:
                self.closed_by_the_stack += 1
                conn.close()
                return
            held += data
            while b"\r\n\r\n" in held:
                head, _, rest = held.partition(b"\r\n\r\n")
                text = head.decode("utf-8", "replace") + "\r\n"
                length = int(_header("Content-Length", text) or 0)
                if len(rest) < length:
                    break
                held = rest[length:]
                self.over_tcp.append(text)
                if text.startswith("INVITE "):
                    conn.sendall(_response(text, "486 Busy Here"))
        conn.close()

    def close(self) -> None:
        self._stop.set()
        self._udp.close()
        if self._listener is not None:
            self._listener.close()


class ACallWhoseAnswerOutgrewTheDatagram(unittest.IsolatedAsyncioTestCase):
    def pbx(self, *, tcp: bool, apart: bool = False) -> _Pbx:
        pbx = _Pbx(tcp=tcp, apart=apart)
        self.addCleanup(pbx.close)
        return pbx

    def stack(self, **options) -> Stack:
        stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION, **options)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    def call(self, stack: Stack, pbx: _Pbx) -> None:
        account = stack.add_account(
            "sip:alice@example.com",
            registrar_address=pbx.address,
            auth_user="alice",
            auth_password="open sesame",
            srtp=lib.SIPRAL_SRTP_OFFERED,
            srtp_suites=["AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80"],
        )
        stack.place_call(account, "sip:bob@example.com")

    async def events_until_the_end(self, stack: Stack, seconds: float = 5.0):
        seen = []
        deadline = asyncio.get_running_loop().time() + seconds
        while True:
            left = deadline - asyncio.get_running_loop().time()
            event = await asyncio.wait_for(stack.events.get(), timeout=max(left, 0.01))
            seen.append(event)
            if event.kind == EventKind.CALL_ENDED:
                return seen

    async def test_a_pbx_listening_on_tcp_gets_the_answer_over_a_connection_the_stack_opened(self) -> None:
        pbx = self.pbx(tcp=True)
        stack = self.stack()
        self.call(stack, pbx)
        seen = await self.events_until_the_end(stack)

        wanted = [event.fields for event in seen if event.kind == EventKind.TRANSPORT_WANTED]
        self.assertEqual(len(wanted), 1, seen)
        self.assertEqual(wanted[0]["destination"], pbx.address)
        self.assertGreater(wanted[0]["request_bytes"], 1300)
        self.assertEqual(wanted[0]["limit_bytes"], 1300)

        ended = seen[-1].fields
        self.assertEqual(ended["status_code"], 486, "the PBX's own answer, over the connection")
        self.assertEqual(ended["end_reason"], CallEndReason.REFUSED)
        self.assertEqual(pbx.connections, 1)
        invites = [message for message in pbx.over_tcp if message.startswith("INVITE ")]
        self.assertEqual(len(invites), 1, pbx.over_tcp)
        self.assertIsNotNone(_header("Authorization", invites[0]))
        self.assertTrue((_header("Via", invites[0]) or "").startswith("SIP/2.0/TCP "), invites[0])
        # The 486 is ACKed on the connection (RFC 3261 Section 17.1.1.3).
        deadline = time.monotonic() + 2.0
        while not any(m.startswith("ACK ") for m in pbx.over_tcp) and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        self.assertTrue(any(m.startswith("ACK ") for m in pbx.over_tcp), pbx.over_tcp)

    async def test_a_pbx_on_udp_alone_ends_the_call_at_once_with_the_limit_named(self) -> None:
        pbx = self.pbx(tcp=False)
        stack = self.stack()
        started = time.monotonic()
        self.call(stack, pbx)
        seen = await self.events_until_the_end(stack, seconds=4.0)
        self.assertLess(time.monotonic() - started, 4.0, "ended by the refusal, not by the wait")

        lost = [event.fields for event in seen if event.kind == EventKind.TRANSPORT_FAILED]
        self.assertTrue(lost, seen)
        self.assertEqual(lost[0]["error"], TransportError.CONNECTION_REFUSED)
        self.assertTrue(lost[0]["detail"].startswith(f"TCP to {pbx.address} refused"), lost[0]["detail"])
        ended = seen[-1]
        self.assertEqual(ended.fields["end_reason"], CallEndReason.UNREACHABLE)
        self.assertEqual(ended.fields["status_code"], 513)
        cause = ended.cause
        self.assertIsNotNone(cause)
        self.assertEqual(cause.sip, 513)
        self.assertIn("1300-byte", cause.text)
        self.assertIn("18.1.1", cause.text)

    async def test_a_pbx_taking_tcp_on_another_port_is_reached_at_the_stream_server(self) -> None:
        pbx = self.pbx(tcp=True, apart=True)
        stack = self.stack(stream_server=pbx.tcp_address)
        self.call(stack, pbx)
        seen = await self.events_until_the_end(stack)
        self.assertEqual(seen[-1].fields["status_code"], 486, "answered over the connection")
        self.assertEqual(pbx.connections, 1)
        invites = [message for message in pbx.over_tcp if message.startswith("INVITE ")]
        self.assertEqual(len(invites), 1, pbx.over_tcp)
        self.assertIsNotNone(_header("Authorization", invites[0]))

    async def test_a_pbx_on_udp_alone_takes_the_request_over_udp_up_to_the_stacks_limit(self) -> None:
        # Deliberate deviation from Section 18.1.1: large UDP allowed.
        pbx = self.pbx(tcp=False)
        stack = self.stack(datagram_without_stream_bytes=4000, path_mtu=1500)
        self.call(stack, pbx)
        seen = await self.events_until_the_end(stack, seconds=4.0)
        self.assertEqual(seen[-1].fields["status_code"], 486, "the PBX's own answer, over UDP")
        [(invite, size)] = pbx.answered_over_udp
        self.assertIsNotNone(_header("Authorization", invite))
        self.assertGreater(size, 1300)
        diagnostics = stack.diagnostics_json()
        self.assertIn("transport.kept.datagram", diagnostics)
        self.assertIn("transport.compacted.size", diagnostics)

    def test_a_limit_past_one_datagram_and_a_path_under_the_ipv4_floor_are_refused(self) -> None:
        with self.assertRaises(SipralError) as past:
            Stack(audio=AudioMode.APPLICATION, datagram_without_stream_bytes=65508)
        self.assertEqual(past.exception.status, Status.INVALID_ARGUMENT)
        with self.assertRaises(SipralError) as under:
            Stack(audio=AudioMode.APPLICATION, path_mtu=575)
        self.assertEqual(under.exception.status, Status.INVALID_ARGUMENT)

    async def test_a_stack_told_to_open_no_stream_ends_the_call_without_trying(self) -> None:
        pbx = self.pbx(tcp=True)
        stack = self.stack(stream_fallback=False)
        self.call(stack, pbx)
        seen = await self.events_until_the_end(stack, seconds=4.0)
        self.assertEqual(seen[-1].fields["status_code"], 513)
        self.assertEqual(pbx.connections, 0, "nothing was opened")
        lost = [event.fields for event in seen if event.kind == EventKind.TRANSPORT_FAILED]
        self.assertEqual(lost[0]["detail"], f"TCP to {pbx.address} not tried: stream_fallback is off")

    async def test_a_connection_the_stack_let_go_of_is_closed_here_too(self) -> None:
        # RFC 5626 Section 4.4.1: a retired stream must be closed here, or it
        # would stand in for the next connection the stack asks for.
        pbx = self.pbx(tcp=True)
        stack = self.stack()
        self.call(stack, pbx)
        await self.events_until_the_end(stack)
        self.assertEqual(pbx.connections, 1)
        self.assertEqual(pbx.closed_by_the_stack, 0, "the connection outlives the call")
        (transport,) = list(stack._sip_streams)
        stack._deliver(
            Event(
                kind=lib.SIPRAL_EVENT_KIND_TRANSPORT_FAILED,
                kind_name="transport failed",
                stack=0,
                account=0,
                call=0,
                message=None,
                fields={
                    "transport": transport,
                    "protocol": lib.SIPRAL_TRANSPORT_TCP,
                    "error": TransportError.TIMED_OUT,
                    "tls": 0,
                    "detail": "",
                },
            )
        )
        deadline = time.monotonic() + 3.0
        while pbx.closed_by_the_stack == 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        self.assertEqual(pbx.closed_by_the_stack, 1, "the connection was let go of")
        self.assertEqual(list(stack._sip_streams), [])


if __name__ == "__main__":
    unittest.main()
