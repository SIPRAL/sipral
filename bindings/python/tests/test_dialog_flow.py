# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A server reached at one address whose answer names another in its
`Contact` -- the lab's Asterisk, published on a mapped port and naming the
port it listens on inside its container, or any registrar behind a NAT.
The dialog's requests have to stay on the path the INVITE took: the ACK did
all along, and the BYE has to follow it rather than go to an address
nothing answers on.
"""

from __future__ import annotations

import asyncio
import re
import socket
import unittest

from sipral import Stack
from sipral.enums import AudioMode, EventKind


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.startswith(f"{name}:"):
            return line
    return None


class ADialogsRequestsStayOnThePathTheInviteTook(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.setblocking(False)
        self.named = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.named.bind(("127.0.0.1", 0))
        self.named.setblocking(False)
        self.audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.audio.bind(("127.0.0.1", 0))
        self.audio.setblocking(False)
        self.addAsyncCleanup(self._close_sockets)

        self.stack = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self.stack.close)

    async def _close_sockets(self) -> None:
        self.server.close()
        self.named.close()
        self.audio.close()

    async def _recv_until(self, sock: socket.socket, method: str, seconds: float) -> list[str]:
        loop = asyncio.get_running_loop()
        seen: list[str] = []
        deadline = loop.time() + seconds
        while loop.time() < deadline:
            try:
                data, _addr = sock.recvfrom(65536)
            except BlockingIOError:
                await asyncio.sleep(0.01)
                continue
            text = data.decode("utf-8", "replace")
            seen.append(text)
            if text.startswith(f"{method} "):
                return seen
        return seen

    async def test_every_request_of_the_dialog_takes_the_path_the_invite_took(self) -> None:
        server_address = "%s:%d" % self.server.getsockname()
        named_address = "%s:%d" % self.named.getsockname()
        audio_port = self.audio.getsockname()[1]

        account = self.stack.add_account("sip:alice@sipral.invalid", registrar_address=server_address)
        call = self.stack.place_call(account, f"sip:bob@{server_address}")
        self.addAsyncCleanup(call.close)

        arrived = await self._recv_until(self.server, "INVITE", 5)
        invite = next((m for m in arrived if m.startswith("INVITE ")), None)
        self.assertIsNotNone(invite, "no INVITE reached the server")

        sdp = (
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            f"m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
        copied = [h for h in (_header(n, invite) for n in ("Via", "From", "Call-ID", "CSeq")) if h]
        to_header = _header("To", invite) or "To: <sip:bob@sipral.invalid>"
        answer = "\r\n".join(
            [
                "SIP/2.0 200 OK",
                *copied,
                f"{to_header};tag=far",
                f"Contact: <sip:bob@{named_address}>",
                "Content-Type: application/sdp",
                f"Content-Length: {len(sdp.encode('utf-8'))}",
                "",
                sdp,
            ]
        )
        # `Via` on the INVITE names the port the INVITE itself came from.
        via = _header("Via", invite) or ""
        via_port = int(re.search(r"127\.0\.0\.1:(\d+)", via).group(1))
        self.server.sendto(answer.encode("utf-8"), ("127.0.0.1", via_port))

        confirmed = None
        try:
            async with asyncio.timeout(5):
                while True:
                    event = await call.events.get()
                    if event.kind == EventKind.CALL_CONFIRMED:
                        confirmed = event
                        break
        except TimeoutError:
            pass
        self.assertIsNotNone(confirmed, "the 200 OK did not confirm the call")
        call.hangup()

        at_server = await self._recv_until(self.server, "BYE", 5)
        at_named = await self._recv_until(self.named, "BYE", 0.5)
        self.assertTrue(any(m.startswith("ACK ") for m in at_server), "the ACK did not reach the server")
        self.assertTrue(any(m.startswith("BYE ") for m in at_server), "the BYE did not reach the server")
        self.assertFalse(
            any(m.startswith("BYE ") for m in at_named),
            "the BYE went to the address the Contact names instead of the path the INVITE took",
        )
