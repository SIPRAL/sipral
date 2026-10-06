# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A Sipral call joined to a stand-in for Gemini Live that speaks the
WebSocket protocol as Google documents it."""

from __future__ import annotations

import asyncio
import base64
import json
import unittest

from websockets.asyncio.server import ServerConnection

from sipral_agents import AgentEventKind, GeminiLive

from .harness import AgentCallTest, FakeService

CHUNK = 24000 * 2 // 10  # 100 ms at 24 kHz


class FakeLive(FakeService):
    def __init__(self) -> None:
        super().__init__()
        self.handles = 0

    async def on_message(self, ws: ServerConnection, body: dict) -> None:
        if "setup" in body:
            # Google's service sends its JSON in binary frames
            await ws.send(json.dumps({"setupComplete": {}}).encode())
            self.handles += 1
            await ws.send(
                json.dumps(
                    {"sessionResumptionUpdate": {"newHandle": f"handle-{self.handles}", "resumable": True}}
                ).encode()
            )
        elif "realtimeInput" in body and self.echo:
            await self.send_audio(ws, base64.b64decode(body["realtimeInput"]["audio"]["data"]))

    async def send_audio(self, ws: ServerConnection, pcm: bytes) -> None:
        for at in range(0, len(pcm), CHUNK):
            part = {"inlineData": {"mimeType": "audio/pcm;rate=24000", "data": base64.b64encode(pcm[at : at + CHUNK]).decode()}}
            await ws.send(json.dumps({"serverContent": {"modelTurn": {"parts": [part]}}}).encode())

    async def send_agent_audio(self, pcm: bytes) -> None:
        await self.send_audio(self.current, pcm)

    async def interrupt(self) -> None:
        await self.current.send(json.dumps({"serverContent": {"interrupted": True}}).encode())


class GeminiLiveOnACall(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeLive()

    def provider(self, url: str) -> GeminiLive:
        return GeminiLive(model="gemini-live-test", api_key="test-key", instructions="Be brief.", voice="Puck", url=url)

    async def test_the_session_is_set_up_and_the_caller_hears_the_agent(self) -> None:
        call, _agent = await self.dial()
        path, _headers = self.service.requests[0]
        self.assertEqual(path, "/ws?key=test-key")
        setup = self.service.log[0]["setup"]
        self.assertEqual(setup["model"], "models/gemini-live-test")
        self.assertEqual(setup["generationConfig"]["responseModalities"], ["AUDIO"])
        self.assertEqual(
            setup["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"], "Puck"
        )
        self.assertEqual(setup["systemInstruction"], {"parts": [{"text": "Be brief."}]})
        self.assertEqual(setup["sessionResumption"], {})

        await self.assert_echo(call)
        sent = await self.service.next(lambda b: "realtimeInput" in b)
        audio = sent["realtimeInput"]["audio"]
        self.assertEqual(audio["mimeType"], "audio/pcm;rate=24000")
        self.assertEqual(len(base64.b64decode(audio["data"])), 960)

    async def test_an_interruption_from_the_service_silences_the_agent(self) -> None:
        call, agent = await self.dial()
        interrupted = await self.assert_barge_in(call, agent, self.service.interrupt)
        self.assertGreater(interrupted.data["heard_ms"], 100)

    async def test_go_away_moves_the_session_to_a_new_connection_resumed(self) -> None:
        call, agent = await self.dial()
        await self.service.current.send(json.dumps({"goAway": {"timeLeft": "5s"}}).encode())
        connected = await self.event(agent, AgentEventKind.CONNECTED)
        self.assertTrue(connected.data["resumed"])
        setups = [body["setup"] for body in self.service.log if "setup" in body]
        self.assertEqual(setups[-1]["sessionResumption"], {"handle": "handle-1"})
        await self.assert_echo(call)

    async def test_a_dropped_connection_is_retried_and_resumed(self) -> None:
        call, agent = await self.dial()
        self.service.drop()
        await self.event(agent, AgentEventKind.RECONNECTING)
        connected = await self.event(agent, AgentEventKind.CONNECTED)
        self.assertTrue(connected.data["resumed"])
        await self.assert_echo(call)

    async def test_the_caller_hanging_up_closes_the_websocket_normally(self) -> None:
        call, agent = await self.dial()
        call.hangup()
        self.assertEqual(await asyncio.wait_for(self.service.closed.get(), 5), 1000)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "call_ended")

    async def test_the_service_closing_hangs_up_the_call(self) -> None:
        call, agent = await self.dial()
        await self.service.current.close()
        await self.wait_ended(call)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "agent_closed")


if __name__ == "__main__":
    unittest.main()
