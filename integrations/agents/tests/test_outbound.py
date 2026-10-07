# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Calls the agent places: a far end on loopback answers and plays a
synthesised person, a machine's greeting, or a greeting and its beep, and
the agent connects -- or does not -- as the policy says. A stand-in for
OpenAI Realtime on a local WebSocket; no key, no cost."""

from __future__ import annotations

import asyncio
import contextlib
import io
import math
import struct
import time
import unittest

from sipral import Stack
from sipral.enums import AudioMode, EventKind

from sipral_agents import MachinePolicy, dial
from sipral_agents.__main__ import main
from sipral_agents.openai_realtime import OpenAIRealtime
from sipral_agents.runner import ConfigError, parse_config

from .test_openai_realtime import FakeRealtime


def voiced(seconds: float, rate: int, words: bool = True) -> bytes:
    """Speech as the detector hears it: a 180 Hz fundamental whose level a
    700 Hz component moves, in words of 200 ms with 100 ms between them."""
    out = bytearray()
    for n in range(int(rate * seconds)):
        at = n / rate
        speaking = not words or (n % int(rate * 0.3)) < int(rate * 0.2)
        value = 0.0
        if speaking:
            value = 6000.0 * math.sin(2 * math.pi * 180 * at) * (1 + 0.5 * math.sin(2 * math.pi * 700 * at))
        out += struct.pack("<h", int(round(value)))
    return bytes(out)


def silence(seconds: float, rate: int) -> bytes:
    return bytes(2 * int(rate * seconds))


def beep(seconds: float, rate: int, hz: int = 1000) -> bytes:
    return b"".join(
        struct.pack("<h", int(8000 * math.sin(2 * math.pi * hz * n / rate)))
        for n in range(int(rate * seconds))
    )


class AnOutboundCall(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.service = FakeRealtime()
        self.url = await self.service.start()
        self.agent = Stack(loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.callee = Stack(loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.line = self.agent.add_account(
            "sip:agent@sipral.invalid", registrar_address=self.callee.bind_address
        )
        self.callee.add_account("sip:callee@sipral.invalid", registrar_address=self.agent.bind_address)
        self.answered: list = []
        self.connected_at: list[float] = []
        self.beeped_at: list[float] = []
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        for call in self.answered:
            call.close()
        self.agent.close()
        self.callee.close()
        await self.service.stop()

    def provider(self, _call) -> OpenAIRealtime:
        self.connected_at.append(time.monotonic())
        return OpenAIRealtime(model="gpt-realtime", api_key="test-key", url=self.url)

    async def far_end(self, script: list[tuple[str, float]], hang_up_after: float) -> None:
        """Answer the one call and play ``script``, then hang up."""
        while True:
            event = await self.callee.events.get()
            if event.kind == EventKind.INCOMING_CALL:
                call = self.callee.answer_call(event)
                break
        self.answered.append(call)
        while call.media is None and not call.ended:
            await asyncio.sleep(0.01)
        rate = call.media.sample_rate
        for what, seconds in script:
            if what == "beep":
                self.beeped_at.append(time.monotonic() + seconds)
            pcm = {"words": voiced, "silence": silence, "beep": beep}[what](seconds, rate)
            call.media.send_audio(pcm)
            await asyncio.sleep(seconds)
        await asyncio.sleep(hang_up_after)
        if not call.ended:
            call.hangup()

    async def run_dial(self, policy: MachinePolicy, script, hang_up_after: float) -> str:
        far = asyncio.create_task(self.far_end(script, hang_up_after))
        try:
            return await asyncio.wait_for(
                dial(
                    self.agent,
                    self.line,
                    f"sip:callee@{self.callee.bind_address}",
                    self.provider,
                    policy=policy,
                    ring_timeout=10,
                ),
                30,
            )
        finally:
            far.cancel()
            await asyncio.gather(far, return_exceptions=True)

    async def test_a_person_who_says_hello_and_waits_gets_the_agent(self) -> None:
        outcome = await self.run_dial(
            MachinePolicy(), [("words", 0.6), ("silence", 2.0)], hang_up_after=1.0
        )
        self.assertEqual(outcome, "human")
        self.assertEqual(len(self.connected_at), 1, "the agent joined")
        self.assertEqual(len(self.service.connections), 1)

    async def test_a_machine_is_hung_up_on_without_the_agent_by_default(self) -> None:
        outcome = await self.run_dial(
            MachinePolicy(), [("words", 4.0), ("silence", 1.0)], hang_up_after=5.0
        )
        self.assertEqual(outcome, "machine")
        self.assertEqual(self.connected_at, [], "no agent session for a machine")
        self.assertEqual(self.service.connections, [])
        async with asyncio.timeout(5):
            while not self.answered[0].ended:
                await asyncio.sleep(0.02)

    async def test_the_agent_leaves_its_message_after_the_beep(self) -> None:
        outcome = await self.run_dial(
            MachinePolicy(on_machine="message", beep_wait_s=10),
            [("words", 3.0), ("silence", 0.3), ("beep", 0.5), ("silence", 1.0)],
            hang_up_after=1.0,
        )
        self.assertEqual(outcome, "message")
        self.assertEqual(len(self.connected_at), 1)
        self.assertGreater(
            self.connected_at[0],
            self.beeped_at[0],
            "the agent waited for the machine to start recording",
        )

    async def test_the_agent_can_talk_to_the_machine_instead(self) -> None:
        outcome = await self.run_dial(
            MachinePolicy(on_machine="agent"), [("words", 4.0)], hang_up_after=1.0
        )
        self.assertEqual(outcome, "machine_agent")
        self.assertEqual(len(self.connected_at), 1)


class ThePolicyInTheConfiguration(unittest.TestCase):
    BASE = {
        "agents": {"sales": {"service": "openai-realtime", "model": "m", "api_key_env": "K"}},
    }

    def account(self, machine) -> dict:
        raw = dict(self.BASE)
        entry = {"aor": "sip:a@x.invalid", "agent": "sales", "registrar_address": "127.0.0.1:5060"}
        if machine is not None:
            entry["machine"] = machine
        raw["accounts"] = [entry]
        return raw

    def test_an_account_without_one_hangs_up_on_machines(self) -> None:
        settings = parse_config(self.account(None), {"K": "k"})
        self.assertEqual(settings.accounts[0].machine, MachinePolicy())

    def test_the_table_is_read_with_the_detectors_limits(self) -> None:
        settings = parse_config(
            self.account({"on_machine": "message", "beep_wait_s": 15, "max_greeting_ms": 2000}),
            {"K": "k"},
        )
        policy = settings.accounts[0].machine
        self.assertEqual(policy.on_machine, "message")
        self.assertEqual(policy.beep_wait_s, 15.0)
        self.assertEqual(policy.detector, {"max_greeting_ms": 2000})

    def test_dial_needs_the_account_it_calls_from(self) -> None:
        with self.assertRaises(SystemExit) as stopped, contextlib.redirect_stderr(io.StringIO()):
            main(["bridge.toml", "--dial", "sip:1001@pbx.invalid"])
        self.assertEqual(stopped.exception.code, 2)

    def test_mistakes_are_named(self) -> None:
        for machine, said in (
            ({"on_machine": "voicemail"}, "on_machine"),
            ({"max_greting_ms": 1}, "max_greting_ms"),
            ({"beep_wait_s": 0}, "beep_wait_s"),
            ("hangup", "must be a table"),
        ):
            with self.subTest(machine=machine):
                with self.assertRaises(ConfigError) as raised:
                    parse_config(self.account(machine), {"K": "k"})
                self.assertIn(said, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
