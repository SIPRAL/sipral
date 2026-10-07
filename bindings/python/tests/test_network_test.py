# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The network test before a call, between two stacks on loopback: the
account's server asked with an OPTIONS, and an echo call measured and hung
up."""

from __future__ import annotations

import asyncio
import unittest

from sipral import Stack
from sipral.enums import AudioMode, EventKind, NetworkProbe, NetworkVerdict, ServerReach


class ANetworkTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.bob = Stack(loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.addAsyncCleanup(self._close)
        self.account = self.alice.add_account(
            "sip:alice@sipral.invalid", registrar_address=self.bob.bind_address
        )
        self.bob.add_account("sip:bob@sipral.invalid", registrar_address=self.alice.bind_address)
        self.calls = []

    async def _close(self) -> None:
        for call in self.calls:
            call.close()
        self.alice.close()
        self.bob.close()

    async def _tested(self, test: int, timeout: float = 10):
        async with asyncio.timeout(timeout):
            while True:
                event = await self.alice.events.get()
                if event.kind == EventKind.NETWORK_TEST and event.fields["test"] == test:
                    return event

    async def test_the_accounts_server_answers_its_options(self) -> None:
        test = self.alice.network_test(self.account)
        event = await self._tested(test)
        self.assertEqual(event.account, self.account.handle)
        self.assertEqual(event.fields["server"], ServerReach.ANSWERED)
        self.assertEqual(event.fields["server_status"], 200)
        self.assertEqual(event.fields["stun"], NetworkProbe.NOT_TESTED, "no STUN server")
        self.assertEqual(event.fields["verdict"], NetworkVerdict.GOOD)

    async def test_an_echo_call_is_measured_and_hung_up(self) -> None:
        call = self.alice.place_call(self.account, f"sip:bob@{self.bob.bind_address}")
        self.calls.append(call)
        echoed = asyncio.create_task(self._echo())
        self.addCleanup(echoed.cancel)
        test = self.alice.network_test(echo_call=call, echo_ms=1500)
        while call.media is None:
            await asyncio.wait_for(call.events.get(), 5)
        silence = bytes(2 * call.media.frame_samples)
        sending = asyncio.create_task(self._speak(call, silence))
        self.addCleanup(sending.cancel)
        event = await self._tested(test)
        self.assertEqual(event.call, call.handle)
        self.assertEqual(event.fields["echo"], NetworkProbe.SUCCEEDED)
        self.assertLess(event.fields["loss_percent"], 1.0)
        self.assertGreater(event.fields["r_factor"], 80)
        self.assertGreaterEqual(event.fields["mos"], 4.0)
        self.assertEqual(event.fields["echo_verdict"], NetworkVerdict.GOOD)
        async with asyncio.timeout(5):
            while not call.ended:
                await asyncio.sleep(0.02)

    async def _echo(self) -> None:
        while True:
            event = await self.bob.events.get()
            if event.kind == EventKind.INCOMING_CALL:
                call = self.bob.answer_call(event)
                self.calls.append(call)
                break
        while call.media is None and not call.ended:
            await asyncio.sleep(0.01)
        while not call.ended:
            call.media.send_audio(await call.media.frames.get())

    async def _speak(self, call, frame: bytes) -> None:
        while not call.ended:
            call.media.send_audio(frame)
            await asyncio.sleep(call.media.frame_samples / call.media.sample_rate)


if __name__ == "__main__":
    unittest.main()
