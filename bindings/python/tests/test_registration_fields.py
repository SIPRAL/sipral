# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""An account's RFC 5626 instance id and its own header fields, through the
Python layer, on every REGISTER it sends.

A push proxy (RFC 8599) refuses a REGISTER whose `Contact` has no
``+sip.instance``. A fake registrar on loopback challenges the first
REGISTER, grants the answer for a few seconds so the refresh comes soon,
grants the refresh, and writes down every REGISTER, the de-registration
included.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import unittest

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode, EventKind

_URN = "urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6"


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n")[1:]:
        field, colon, value = line.partition(":")
        if colon and field.strip().lower() == name.lower():
            return value.strip()
    return None


class _Registrar:
    def __init__(self) -> None:
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.settimeout(0.05)
        self.address = f"127.0.0.1:{self._udp.getsockname()[1]}"
        self.registers: list[str] = []
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._udp.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            text = data.decode("utf-8", "replace")
            if not text.startswith("REGISTER "):
                continue
            self.registers.append(text)
            lines = []
            for name in ("Via", "From", "To", "Call-ID", "CSeq"):
                value = _header(name, text)
                if name == "To" and value is not None and ";tag=" not in value:
                    value = f"{value};tag=registrar"
                lines.append(f"{name}: {value}")
            if _header("Authorization", text) is None and len(self.registers) == 1:
                status = "401 Unauthorized"
                lines.append('WWW-Authenticate: Digest realm="example.com", nonce="n1", qop="auth"')
            else:
                status = "200 OK"
                expires = "0" if _header("Expires", text) == "0" else "4"
                lines.append(f"Contact: {_header('Contact', text)};expires={expires}")
            answer = f"SIP/2.0 {status}\r\n" + "\r\n".join(lines) + "\r\nContent-Length: 0\r\n\r\n"
            self._udp.sendto(answer.encode("utf-8"), peer)

    def close(self) -> None:
        self._stop.set()
        self._udp.close()


class AnAccountsInstanceAndFields(unittest.IsolatedAsyncioTestCase):
    async def test_ride_on_the_first_register_the_answer_to_a_challenge_the_refresh_and_the_goodbye(self) -> None:
        registrar = _Registrar()
        self.addCleanup(registrar.close)
        stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        account = stack.add_account(
            "sip:alice@example.com",
            registrar="sip:example.com",
            registrar_address=registrar.address,
            auth_user="alice",
            auth_password="open sesame",
            instance_id=_URN,
            headers=[("X-Push-Key", "k-17")],
        )
        account.register()

        async def until(count: int, seconds: float) -> None:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + seconds
            while len(registrar.registers) < count and loop.time() < deadline:
                try:
                    await asyncio.wait_for(stack.events.get(), timeout=0.2)
                except TimeoutError:
                    pass

        await until(3, 10.0)  # the first, the answer to the challenge, the refresh
        self.assertGreaterEqual(len(registrar.registers), 3, registrar.registers)
        account.unregister()
        await until(4, 5.0)
        self.assertGreaterEqual(len(registrar.registers), 4, registrar.registers)

        first, answered, refresh, goodbye = registrar.registers[:4]
        self.assertIsNone(_header("Authorization", first))
        self.assertIsNotNone(_header("Authorization", answered))
        self.assertEqual(_header("Expires", goodbye), "0")
        for which, request in (
            ("the first", first),
            ("the answer to the challenge", answered),
            ("the refresh", refresh),
            ("the de-registration", goodbye),
        ):
            with self.subTest(which):
                self.assertEqual(_header("X-Push-Key", request), "k-17")
                self.assertIn(f'+sip.instance="<{_URN}>"', _header("Contact", request) or "")

    def test_a_field_the_stack_writes_itself_is_refused(self) -> None:
        stack = Stack(audio=AudioMode.APPLICATION)
        self.addCleanup(stack.close)
        with self.assertRaises(Exception) as refused:
            stack.add_account(
                "sip:alice@example.com",
                registrar="sip:example.com",
                registrar_address="127.0.0.1:5060",
                headers=[("Expires", "60")],
            )
        self.assertEqual(getattr(refused.exception, "status", None), lib.SIPRAL_STATUS_INVALID_ARGUMENT)


if __name__ == "__main__":
    unittest.main()
