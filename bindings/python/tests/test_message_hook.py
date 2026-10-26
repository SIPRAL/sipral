# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The message hook through the Python layer: a header added to every
request on its way out, one taken off a response on its way in, and a
message stopped.

A fake PBX on UDP answers every INVITE 486 with an ``X-Carrier-Route``
header and writes down what it received.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import unittest

from sipral import Stack
from sipral.enums import AudioMode, EventKind


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        field, colon, value = line.partition(":")
        if colon and field.strip().lower() == name.lower():
            return value.strip()
    return None


def _with_header(message: bytes, line: str) -> bytes:
    head, _, body = message.partition(b"\r\n\r\n")
    return head + b"\r\n" + line.encode("utf-8") + b"\r\n\r\n" + body


def _without_header(message: bytes, name: str) -> bytes:
    head, _, body = message.partition(b"\r\n\r\n")
    kept = [
        line
        for line in head.split(b"\r\n")
        if line.partition(b":")[0].strip().lower() != name.lower().encode("utf-8")
    ]
    return b"\r\n".join(kept) + b"\r\n\r\n" + body


class _Pbx:
    def __init__(self) -> None:
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.05)
        self.address = f"127.0.0.1:{self._udp.getsockname()[1]}"
        self.received: list[str] = []
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._udp.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            text = data.decode("utf-8", "replace")
            self.received.append(text)
            if not text.startswith("INVITE "):
                continue
            lines = ["SIP/2.0 486 Busy Here"]
            for name in ("Via", "From", "To", "Call-ID", "CSeq"):
                value = _header(name, text)
                if name == "To" and value is not None and ";tag=" not in value:
                    value = f"{value};tag=pbx"
                lines.append(f"{name}: {value}")
            lines.append("X-Carrier-Route: trunk-7")
            answer = "\r\n".join(lines) + "\r\nContent-Length: 0\r\n\r\n"
            self._udp.sendto(answer.encode("utf-8"), peer)

    def close(self) -> None:
        self._stop.set()
        self._udp.close()


class AMessageHook(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.pbx = _Pbx()
        self.addCleanup(self.pbx.close)

    async def stack(self) -> Stack:
        stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def ended(self, stack: Stack):
        while True:
            event = await asyncio.wait_for(stack.events.get(), timeout=5.0)
            if event.kind == EventKind.CALL_ENDED:
                return event

    async def test_a_header_goes_out_on_every_request_and_one_is_taken_off_what_comes_in(self) -> None:
        stack = await self.stack()
        seen: list[tuple[bool, bytes, str]] = []

        def hook(outgoing: bool, message: bytes, remote: str):
            seen.append((outgoing, message, remote))
            if outgoing and not message.startswith(b"SIP/2.0 "):
                return _with_header(message, "X-Tenant: blue")
            if not outgoing:
                return _without_header(message, "X-Carrier-Route")
            return None

        stack.set_message_hook(hook)
        account = stack.add_account("sip:alice@example.com", registrar_address=self.pbx.address)
        stack.place_call(account, "sip:bob@example.com")
        ended = await self.ended(stack)
        self.assertEqual(ended.fields["status_code"], 486)

        invites = [m for m in self.pbx.received if m.startswith("INVITE ")]
        self.assertEqual(len(invites), 1, self.pbx.received)
        self.assertEqual(_header("X-Tenant", invites[0]), "blue")
        arrived = [message for outgoing, message, _ in seen if not outgoing]
        self.assertTrue(any(b"X-Carrier-Route: trunk-7" in message for message in arrived))
        self.assertTrue(all(remote == self.pbx.address for _, _, remote in seen), seen)

    async def test_a_dropped_invite_never_reaches_the_pbx_and_removing_the_hook_lets_the_next_out(self) -> None:
        stack = await self.stack()
        stack.set_message_hook(
            lambda outgoing, message, _remote: False
            if outgoing and message.startswith(b"INVITE ")
            else None
        )
        account = stack.add_account("sip:alice@example.com", registrar_address=self.pbx.address)
        stack.place_call(account, "sip:bob@example.com")
        await asyncio.sleep(0.6)
        self.assertFalse([m for m in self.pbx.received if m.startswith("INVITE ")])

        stack.set_message_hook(None)
        stack.place_call(account, "sip:carol@example.com")
        ended = await self.ended(stack)
        while ended.fields["status_code"] != 486:
            ended = await self.ended(stack)
        self.assertTrue([m for m in self.pbx.received if m.startswith("INVITE sip:carol")])

    async def test_a_hook_that_raises_keeps_the_message(self) -> None:
        stack = await self.stack()

        def broken(_outgoing: bool, _message: bytes, _remote: str):
            raise RuntimeError("a mistake in the application's hook")

        stack.set_message_hook(broken)
        account = stack.add_account("sip:alice@example.com", registrar_address=self.pbx.address)
        stack.place_call(account, "sip:bob@example.com")
        ended = await self.ended(stack)
        self.assertEqual(ended.fields["status_code"], 486)


if __name__ == "__main__":
    unittest.main()
