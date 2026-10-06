# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Ringing, header fields and transfer through this package's ``Call``.

Stacks on 127.0.0.1 with no registrar, as in ``test_call``: a call placed
with header fields of its own, rung with a 180 and then answered, ended by
a BYE that carries a field the other side reads off ``CALL_ENDED``; a REFER
refused, which the transferor hears as ``TRANSFER_DONE``; and a REFER taken
with a call the transferee placed itself, whose answer reaches the
transferor as the transfer's success.
"""

from __future__ import annotations

import asyncio
import unittest

from sipral import Stack
from sipral.enums import AudioMode, CallState, EventKind


def _header(message: bytes | None, name: str) -> str | None:
    for line in (message or b"").decode("utf-8", "replace").split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return None


class CallControl(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.bob = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.stacks = [self.alice, self.bob]
        self.addAsyncCleanup(self._close)
        self.alice_line = self.alice.add_account(
            "sip:alice@sipral.invalid", registrar_address=self.bob.bind_address
        )
        self.bob_line = self.bob.add_account(
            "sip:bob@sipral.invalid", registrar_address=self.alice.bind_address
        )

    async def _close(self) -> None:
        for stack in self.stacks:
            stack.close()

    async def _next(self, queue, kind, status=None):
        async with asyncio.timeout(5):
            while True:
                event = await queue.get()
                if event.kind == kind and status in (None, event.fields.get("status_code")):
                    return event

    async def _up(self, **place):
        alice_call = self.alice.place_call(
            self.alice_line, f"sip:bob@{self.bob.bind_address}", **place
        )
        incoming = await self._next(self.bob.events, EventKind.INCOMING_CALL)
        bob_call = self.bob.answer_call(incoming)
        await self._next(alice_call.events, EventKind.CALL_CONFIRMED)
        return alice_call, bob_call, incoming

    async def test_ringing_then_answered_with_header_fields_both_ways(self) -> None:
        alice_call = self.alice.place_call(
            self.alice_line,
            f"sip:bob@{self.bob.bind_address}",
            headers=[("X-Context", "order-17")],
        )
        incoming = await self._next(self.bob.events, EventKind.INCOMING_CALL)
        self.assertEqual(_header(incoming.message, "X-Context"), "order-17")

        bob_call = self.bob.ring_call(incoming)
        await self._next(alice_call.events, EventKind.CALL_PROGRESS, 180)
        self.assertIs(self.bob.answer_call(incoming), bob_call)
        await self._next(alice_call.events, EventKind.CALL_CONFIRMED)
        await self._next(bob_call.events, EventKind.CALL_CONFIRMED)
        self.assertEqual(bob_call.state, CallState.CONFIRMED)

        bob_call.set_headers({"X-Sipral-Outcome": "resolved"})
        bob_call.hangup()
        ended = await self._next(alice_call.events, EventKind.CALL_ENDED)
        self.assertTrue(ended.message.startswith(b"BYE "), ended.message)
        self.assertEqual(_header(ended.message, "X-Sipral-Outcome"), "resolved")

    async def test_ringing_with_media_opens_the_session_before_the_answer(self) -> None:
        alice_call = self.alice.place_call(self.alice_line, f"sip:bob@{self.bob.bind_address}")
        incoming = await self._next(self.bob.events, EventKind.INCOMING_CALL)
        bob_call = self.bob.ring_call(incoming, media=True, codecs="PCMA")
        await self._next(bob_call.events, EventKind.MEDIA_STARTED)
        self.assertIsNotNone(bob_call.media)
        self.bob.answer_call(incoming)
        await self._next(alice_call.events, EventKind.CALL_CONFIRMED)

    async def test_a_refused_refer_is_heard_as_transfer_done(self) -> None:
        alice_call, bob_call, _ = await self._up()
        alice_call.transfer("sip:carol@sipral.invalid")
        asked = await self._next(bob_call.events, EventKind.TRANSFER_REQUESTED)
        self.bob.reject_referral(asked, 603)
        done = await self._next(alice_call.events, EventKind.TRANSFER_DONE)
        self.assertEqual(done.fields.get("status_code"), 603)
        self.assertEqual(alice_call.state, CallState.CONFIRMED)

    async def test_a_refer_taken_with_a_call_of_the_applications_own(self) -> None:
        carol = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
        self.stacks.append(carol)
        carol.add_account("sip:carol@sipral.invalid", registrar_address=self.bob.bind_address)
        alice_call, bob_call, _ = await self._up()

        alice_call.transfer(f"sip:carol@{carol.bind_address}")
        asked = await self._next(bob_call.events, EventKind.TRANSFER_REQUESTED)
        placed = self.bob.place_call(
            self.bob_line, f"sip:carol@{carol.bind_address}", destination=carol.bind_address
        )
        self.bob.accept_transfer_placed(asked, placed)
        await self._next(alice_call.events, EventKind.TRANSFER_PROGRESS)

        incoming = await self._next(carol.events, EventKind.INCOMING_CALL)
        carol.answer_call(incoming)
        done = await self._next(alice_call.events, EventKind.TRANSFER_DONE)
        self.assertEqual(done.fields.get("status_code"), 200)
        await self._next(alice_call.events, EventKind.CALL_ENDED)


if __name__ == "__main__":
    unittest.main()
