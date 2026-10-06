# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A Sipral call joined to a stand-in for Deepgram Voice Agent that speaks
the WebSocket protocol as Deepgram documents it."""

from __future__ import annotations

import asyncio
import json
import unittest

from websockets.asyncio.server import ServerConnection

from sipral_agents import AgentEventKind, DeepgramAgent

from .harness import AgentCallTest, FakeService

CHUNK = 24000 * 2 // 10  # 100 ms at 24 kHz

AGENT = {
    "listen": {"provider": {"type": "deepgram", "model": "listen-test"}},
    "think": {"provider": {"type": "open_ai", "model": "think-test"}},
    "speak": {"provider": {"type": "deepgram", "model": "speak-test"}},
}


class FakeDeepgram(FakeService):
    binary_audio = True

    def __init__(self, refuse: bool = False) -> None:
        super().__init__()
        self.refuse = refuse

    async def on_message(self, ws: ServerConnection, body: dict) -> None:
        if body.get("type") == "Settings":
            await ws.send(json.dumps({"type": "Welcome", "request_id": "req_1"}))
            if self.refuse:
                await ws.send(
                    json.dumps({"type": "Error", "description": "unknown think model", "code": "INVALID_SETTINGS"})
                )
                return
            await ws.send(json.dumps({"type": "SettingsApplied"}))
        elif "pcm" in body and self.echo:
            await self.send_audio(ws, body["pcm"])

    async def send_audio(self, ws: ServerConnection, pcm: bytes) -> None:
        for at in range(0, len(pcm), CHUNK):
            await ws.send(pcm[at : at + CHUNK])

    async def send_agent_audio(self, pcm: bytes) -> None:
        await self.current.send(json.dumps({"type": "AgentStartedSpeaking", "total_latency": 0.5}))
        await self.send_audio(self.current, pcm)

    async def user_started(self) -> None:
        await self.current.send(json.dumps({"type": "UserStartedSpeaking"}))


class DeepgramOnACall(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeDeepgram()

    def provider(self, url: str) -> DeepgramAgent:
        return DeepgramAgent(api_key="test-key", agent=AGENT, settings={"tags": ["test"]}, url=url)

    async def test_the_settings_apply_and_the_caller_hears_the_agent(self) -> None:
        call, _agent = await self.dial()
        path, headers = self.service.requests[0]
        self.assertEqual(path, "/ws")
        self.assertEqual(headers.get("authorization"), "Token test-key")
        settings = self.service.log[0]
        self.assertEqual(settings["type"], "Settings")
        self.assertEqual(settings["audio"]["input"], {"encoding": "linear16", "sample_rate": 24000})
        self.assertEqual(
            settings["audio"]["output"], {"encoding": "linear16", "sample_rate": 24000, "container": "none"}
        )
        self.assertEqual(settings["agent"], AGENT)
        self.assertEqual(settings["tags"], ["test"])

        await self.assert_echo(call)
        frame = await self.service.next(lambda b: "pcm" in b)
        self.assertEqual(len(frame["pcm"]), 960)

    async def test_the_caller_speaking_cuts_the_agent(self) -> None:
        call, agent = await self.dial()
        interrupted = await self.assert_barge_in(call, agent, self.service.user_started)
        self.assertGreater(interrupted.data["heard_ms"], 100)

    async def test_conversation_text_and_turn_end_become_events(self) -> None:
        _call, agent = await self.dial()
        await self.service.current.send(json.dumps({"type": "ConversationText", "role": "user", "content": "hi"}))
        await self.service.current.send(
            json.dumps({"type": "ConversationText", "role": "assistant", "content": "hello"})
        )
        await self.service.current.send(json.dumps({"type": "AgentAudioDone"}))
        first = await self.event(agent, AgentEventKind.TRANSCRIPT)
        second = await self.event(agent, AgentEventKind.TRANSCRIPT)
        self.assertEqual((first.data["role"], first.data["text"]), ("user", "hi"))
        self.assertEqual((second.data["role"], second.data["text"]), ("agent", "hello"))
        await self.event(agent, AgentEventKind.TURN_COMPLETE)

    async def test_the_caller_hanging_up_closes_the_websocket_normally(self) -> None:
        call, agent = await self.dial()
        call.hangup()
        self.assertEqual(await asyncio.wait_for(self.service.closed.get(), 5), 1000)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "call_ended")


class DeepgramRefusing(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeDeepgram(refuse=True)

    def provider(self, url: str) -> DeepgramAgent:
        return DeepgramAgent(api_key="test-key", agent=AGENT, url=url)

    async def test_settings_the_service_rejects_end_the_call_without_retries(self) -> None:
        call = self.caller.place_call(self.caller_account, f"sip:agent@{self.agent.bind_address}")
        self.calls.append(call)
        agent = await asyncio.wait_for(self.agent_calls.get(), 5)
        error = await self.event(agent, AgentEventKind.ERROR)
        self.assertIn("INVALID_SETTINGS", error.data["message"])
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "refused")
        await self.wait_ended(call)
        self.assertEqual(len(self.service.connections), 1)


if __name__ == "__main__":
    unittest.main()
