# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The one-command demo with no key: a call to it hears its own voice back
through the local echo agent."""

from __future__ import annotations

import asyncio
import unittest

from sipral import Stack
from sipral.enums import AudioMode
from sipral_agents import wait_for_media
from sipral_agents.demo import run

from .harness import LOUD, rms, tone


class DemoTest(unittest.IsolatedAsyncioTestCase):
    async def test_a_call_hears_the_echo_agent(self) -> None:
        loop = asyncio.get_running_loop()
        started: asyncio.Future = loop.create_future()
        demo = asyncio.create_task(run("127.0.0.1", 0, {}, started))
        caller = Stack(loop=loop, audio=AudioMode.APPLICATION)
        try:
            address = await asyncio.wait_for(started, 5)
            account = caller.add_account("sip:caller@sipral.invalid", registrar_address=address)
            call = caller.place_call(account, f"sip:agent@{address}")
            self.assertTrue(await wait_for_media(call, 5), "the call never got media")
            await asyncio.sleep(0.5)
            call.media.send_audio(tone(call.media.sample_rate, 1.0))
            loud = 0
            deadline = loop.time() + 2.0
            while (left := deadline - loop.time()) > 0:
                try:
                    frame = await asyncio.wait_for(call.media.frames.get(), left)
                except TimeoutError:
                    break
                loud += rms(frame) > LOUD
            self.assertGreaterEqual(loud, 25, "less than half the tone came back")
            call.hangup()
            call.close()
        finally:
            demo.cancel()
            await asyncio.gather(demo, return_exceptions=True)
            caller.close()


if __name__ == "__main__":
    unittest.main()
