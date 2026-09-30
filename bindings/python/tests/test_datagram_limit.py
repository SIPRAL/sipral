# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""RFC 3261 Section 18.1.1 through the Python layer: a call whose answer to
a challenge is too large for a datagram.

The PBX here is this test's own, on loopback: a UDP socket that answers every
INVITE without credentials with a 401 whose nonce is long enough that the
`Authorization` answering it takes the INVITE past 1300 bytes, and -- when
asked for -- a TCP listener on the same port that frames what arrives on
`Content-Length` and answers the INVITE that carries credentials with a 486.
The account offers both SDES suites, the stronger first, which is the offer
that crossed the line against a real PBX.

What is proved: with a TCP listener there, the stack opens a connection by
itself, the INVITE with credentials goes on it with a `Via` that names TCP,
and the call carries on over it to the PBX's answer and the ACK; with none,
or with ``stream_fallback=False``, the call ends at once as unreachable with
a 513 whose text names the size and the limit, never hanging.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import unittest

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.events import Event
from sipral.enums import AudioMode, CallEndReason, EventKind, TransportError

#: How long the nonce is: enough that the retry is over the line even with
#: one suite fewer, so no trimmed offer fits a datagram either.
_NONCE_BYTES = 700


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
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
    """A PBX that challenges INVITEs over UDP, with a TCP listener on the same
    port when ``tcp``. :attr:`over_tcp` holds every request that arrived on a
    connection, in order."""

    def __init__(self, *, tcp: bool, apart: bool = False) -> None:
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.05)
        port = self._udp.getsockname()[1]
        self.address = f"127.0.0.1:{port}"
        self._listener: socket.socket | None = None
        if tcp:
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # ``apart``: TCP on a port of its own, as a PBX that takes UDP on
            # 5060 and TCP on 5160 has it
            self._listener.bind(("127.0.0.1", 0 if apart else port))
            self._listener.listen()
            self._listener.settimeout(0.05)
        #: Where TCP is taken, ``None`` without it.
        self.tcp_address = (
            f"127.0.0.1:{self._listener.getsockname()[1]}" if self._listener is not None else None
        )
        self.over_tcp: list[str] = []
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
        # the dialog carries on over the connection: the 486 is acknowledged
        # on it (RFC 3261 Section 17.1.1.3)
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

    async def test_a_stack_told_to_open_no_stream_ends_the_call_without_trying(self) -> None:
        pbx = self.pbx(tcp=True)
        stack = self.stack(stream_fallback=False)
        self.call(stack, pbx)
        seen = await self.events_until_the_end(stack, seconds=4.0)
        self.assertEqual(seen[-1].fields["status_code"], 513)
        self.assertEqual(pbx.connections, 0, "nothing was opened")

    async def test_a_connection_the_stack_let_go_of_is_closed_here_too(self) -> None:
        # RFC 5626 Section 4.4.1: the stack retires a stream that stopped
        # answering keep-alives and says so with a TRANSPORT_FAILED; the socket
        # is this layer's, and one kept open would stand in for the new
        # connection the stack asks for next time
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
