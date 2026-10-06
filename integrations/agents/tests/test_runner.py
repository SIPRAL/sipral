# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The ready-to-run bridge: its configuration file read and checked, and a
bridge started from one routing each account's calls to its own agent --
a stand-in for OpenAI Realtime over WebSocket, and a SIP agent that echoes
-- all on loopback."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from sipral import Stack
from sipral.enums import AudioMode, EventKind

from sipral_agents.__main__ import main
from sipral_agents.runner import Bridge, ConfigError, load_config, parse_config

from .harness import LOUD, rms, tone
from .test_openai_realtime import FakeRealtime

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "bridge.toml")
EXAMPLE_ENV = {
    "SALES_SIP_PASSWORD": "s1",
    "SUPPORT_SIP_PASSWORD": "s2",
    "OPENAI_API_KEY": "k",
}


def write(text: str) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    with handle:
        handle.write(text)
    return handle.name


class TheConfigurationFile(unittest.TestCase):
    def test_the_example_reads_with_its_secrets_from_the_environment(self) -> None:
        settings = load_config(EXAMPLE, EXAMPLE_ENV)
        self.assertEqual([a.aor for a in settings.accounts], [
            "sip:sales@pbx.example.com", "sip:support@pbx.example.com"])
        self.assertEqual(settings.accounts[0].auth_password, "s1")
        self.assertEqual(settings.accounts[1].agent, "support")
        sales = settings.agents["sales"]
        self.assertEqual(sales.service, "openai-realtime")
        self.assertEqual(sales.provider().api_key, "k")
        support = settings.agents["support"]
        self.assertEqual(support.service, "sip")
        self.assertEqual(support.options["max_seconds"], 900)

    def test_a_missing_environment_variable_is_named(self) -> None:
        env = dict(EXAMPLE_ENV)
        del env["OPENAI_API_KEY"]
        with self.assertRaisesRegex(ConfigError, "OPENAI_API_KEY"):
            load_config(EXAMPLE, env)

    def test_a_secret_written_in_the_file_is_refused(self) -> None:
        raw = {
            "accounts": [{"aor": "sip:a@x", "registrar_address": "127.0.0.1:5060", "agent": "a"}],
            "agents": {"a": {"service": "openai-realtime", "model": "m", "api_key": "sk-1"}},
        }
        with self.assertRaisesRegex(ConfigError, "api_key_env"):
            parse_config(raw, {})
        raw["agents"]["a"] = {"service": "sip", "uri": "sip:b@x"}
        raw["accounts"][0]["auth_password"] = "p"
        with self.assertRaisesRegex(ConfigError, "auth_password_env"):
            parse_config(raw, {})

    def test_mistakes_are_named(self) -> None:
        account = {"aor": "sip:a@x", "registrar_address": "127.0.0.1:5060", "agent": "a"}
        cases = [
            ({"agents": {"a": {"service": "sip", "uri": "sip:b@x"}}}, "accounts"),
            ({"accounts": [account], "agents": {}}, r"\[agents.a\]"),
            ({"accounts": [account], "agents": {"a": {"service": "nope"}}}, "service is one of"),
            ({"accounts": [account], "agents": {"a": {"service": "sip"}}}, "uri"),
            ({"accounts": [account], "agents": {"a": {"service": "deepgram", "api_key_env": "K"}}}, "agent"),
            ({"accounts": [account], "agents": {"a": {"service": "vapi", "api_key_env": "K"}}}, "assistant"),
            ({"accounts": [account, account], "agents": {"a": {"service": "sip", "uri": "sip:b@x"}}}, "twice"),
            (
                {
                    "accounts": [account],
                    "agents": {
                        "a": {"service": "sip", "uri": "sips:b@one.example"},
                        "b": {"service": "sip", "uri": "sip:c@two.example;transport=tls"},
                    },
                },
                "one bridge each",
            ),
        ]
        for raw, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigError, message):
                    parse_config(raw, {"K": "k"})

    def test_check_prints_the_routes(self) -> None:
        out = io.StringIO()
        with mock.patch.dict(os.environ, EXAMPLE_ENV), contextlib.redirect_stdout(out):
            self.assertEqual(main([EXAMPLE, "--check", "--quiet"]), 0)
        self.assertIn("sip:sales@pbx.example.com -> sales (openai-realtime)", out.getvalue())
        self.assertIn("sip:support@pbx.example.com -> support (sip:support-agent@", out.getvalue())

    def test_a_bad_file_exits_2_with_the_reason(self) -> None:
        path = write("[[accounts]]\naor = 1\n")
        self.addCleanup(os.unlink, path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main([path, "--check", "--quiet"]), 2)
        self.assertIn("sipral-agents:", err.getvalue())


async def echo_agent(stack: Stack, answered: asyncio.Queue) -> None:
    """A SIP voice agent: answers every call and sends back what it hears."""
    echoes: set[asyncio.Task] = set()

    async def echo(call) -> None:
        while call.media is None and not call.ended:
            await asyncio.sleep(0.01)
        while not call.ended:
            frame = await call.media.frames.get()
            call.media.send_audio(frame)

    try:
        while True:
            event = await stack.events.get()
            if event.kind == EventKind.INCOMING_CALL:
                call = stack.answer_call(event)
                answered.put_nowait(call)
                task = asyncio.create_task(echo(call))
                echoes.add(task)
    finally:
        for task in echoes:
            task.cancel()


class ABridgeFromItsConfiguration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.service = FakeRealtime()
        ws_url = await self.service.start()
        self.caller = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.vendor = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.vendor.add_account("sip:support-agent@sipral.invalid", registrar_address=self.caller.bind_address)
        self.answered: asyncio.Queue = asyncio.Queue()
        self.vendor_task = asyncio.create_task(echo_agent(self.vendor, self.answered))
        caller = self.caller.bind_address
        path = write(
            f"""
[sip]
bind_host = "127.0.0.1"

[[accounts]]
aor = "sip:sales@sipral.invalid"
registrar_address = "{caller}"
agent = "sales"

[[accounts]]
aor = "sip:support@sipral.invalid"
registrar_address = "{caller}"
agent = "support"

[agents.sales]
service = "openai-realtime"
model = "gpt-realtime"
api_key_env = "SIPRAL_TEST_OPENAI_KEY"
url = "{ws_url}"

[agents.support]
service = "sip"
uri = "sip:support-agent@{self.vendor.bind_address}"
"""
        )
        self.addCleanup(os.unlink, path)
        settings = load_config(path, {"SIPRAL_TEST_OPENAI_KEY": "test-key"})
        self.bridge = Bridge(settings)
        self.stack = await self.bridge.start()
        self.serving = asyncio.create_task(self.bridge.serve())
        self.caller_account = self.caller.add_account(
            "sip:caller@sipral.invalid", registrar_address=self.stack.bind_address
        )
        self.calls = []
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        self.serving.cancel()
        self.vendor_task.cancel()
        await asyncio.gather(self.serving, self.vendor_task, return_exceptions=True)
        for call in self.calls:
            call.close()
        self.caller.close()
        self.vendor.close()
        await self.service.stop()

    async def dial(self, user: str):
        call = self.caller.place_call(self.caller_account, f"sip:{user}@{self.stack.bind_address}")
        self.calls.append(call)
        async with asyncio.timeout(5):
            while call.media is None:
                await asyncio.sleep(0.01)
        return call

    async def hears_itself(self, call) -> int:
        """Send a second of tone and count the loud frames that come back."""
        while not call.media.frames.empty():
            call.media.frames.get_nowait()
        call.media.send_audio(tone(call.media.sample_rate, 1.0))
        loud = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.6
        while (left := deadline - loop.time()) > 0:
            try:
                frame = await asyncio.wait_for(call.media.frames.get(), left)
            except TimeoutError:
                break
            if rms(frame) > LOUD:
                loud += 1
        return loud

    async def test_each_account_reaches_its_own_agent(self) -> None:
        sales = await self.dial("sales")
        update = await self.service.next(lambda b: b.get("type") == "session.update")
        self.assertEqual(update["session"]["audio"]["input"]["format"]["rate"], 24000)
        self.assertEqual(self.service.requests[0][1].get("authorization"), "Bearer test-key")
        self.assertGreaterEqual(await self.hears_itself(sales), 25)
        self.assertTrue(self.answered.empty(), "the SIP agent got a call meant for OpenAI")

        support = await self.dial("support")
        bridged = await asyncio.wait_for(self.answered.get(), 5)
        async with asyncio.timeout(5):
            while bridged.media is None:
                await asyncio.sleep(0.01)
        # past the ringback, the caller hears its own tone through the agent
        await asyncio.sleep(0.5)
        self.assertGreaterEqual(await self.hears_itself(support), 25)
        self.assertEqual(len(self.service.connections), 1, "the SIP call reached the WebSocket agent")

        support.hangup()
        async with asyncio.timeout(5):
            while not bridged.ended:
                await asyncio.sleep(0.02)
        sales.hangup()
        self.assertEqual(await asyncio.wait_for(self.service.closed.get(), 5), 1000)


if __name__ == "__main__":
    unittest.main()
