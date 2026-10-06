# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A Sipral call joined to a stand-in for OpenAI Realtime that speaks the
WebSocket protocol as OpenAI documents it."""

from __future__ import annotations

import asyncio
import base64
import json
import unittest

from websockets.asyncio.server import ServerConnection

from sipral_agents import AgentEventKind, OpenAIRealtime

from .harness import AgentCallTest, FakeService

CHUNK = 24000 * 2 // 10  # 100 ms at 24 kHz


class FakeRealtime(FakeService):
    def __init__(self) -> None:
        super().__init__()
        self.items = 0

    async def on_message(self, ws: ServerConnection, body: dict) -> None:
        kind = body.get("type")
        if kind == "session.update":
            await ws.send(json.dumps({"type": "session.updated", "session": body["session"]}))
        elif kind == "input_audio_buffer.append" and self.echo:
            await self.send_audio(ws, base64.b64decode(body["audio"]), "item_echo")

    async def send_audio(self, ws: ServerConnection, pcm: bytes, item: str) -> None:
        for at in range(0, len(pcm), CHUNK):
            await ws.send(
                json.dumps(
                    {
                        "type": "response.output_audio.delta",
                        "response_id": "resp_1",
                        "item_id": item,
                        "output_index": 0,
                        "content_index": 0,
                        "delta": base64.b64encode(pcm[at : at + CHUNK]).decode(),
                    }
                )
            )

    async def send_agent_audio(self, pcm: bytes) -> None:
        self.items += 1
        await self.send_audio(self.current, pcm, f"item_{self.items}")

    async def speech_started(self) -> None:
        await self.current.send(
            json.dumps(
                {"type": "input_audio_buffer.speech_started", "audio_start_ms": 1000, "item_id": "item_user"}
            )
        )


class OpenAIRealtimeOnACall(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeRealtime()

    def provider(self, url: str) -> OpenAIRealtime:
        return OpenAIRealtime(
            model="gpt-realtime", api_key="test-key", instructions="Be brief.", voice="marin", url=url
        )

    async def test_the_session_is_set_up_and_the_caller_hears_the_agent(self) -> None:
        call, _agent = await self.dial()
        path, headers = self.service.requests[0]
        self.assertEqual(path, "/ws?model=gpt-realtime")
        self.assertEqual(headers.get("authorization"), "Bearer test-key")
        update = self.service.log[0]
        self.assertEqual(update["type"], "session.update")
        session = update["session"]
        self.assertEqual(session["type"], "realtime")
        self.assertEqual(session["instructions"], "Be brief.")
        audio = session["audio"]
        self.assertEqual(audio["input"]["format"], {"type": "audio/pcm", "rate": 24000})
        self.assertEqual(audio["output"]["format"], {"type": "audio/pcm", "rate": 24000})
        self.assertEqual(audio["output"]["voice"], "marin")
        self.assertTrue(audio["input"]["turn_detection"]["interrupt_response"])

        await self.assert_echo(call)
        append = await self.service.next(lambda b: b["type"] == "input_audio_buffer.append")
        # one 20 ms frame at 24 kHz, whatever the call's codec runs at
        self.assertEqual(len(base64.b64decode(append["audio"])), 960)

    async def test_the_caller_speaking_cuts_the_agent_and_truncates_its_turn(self) -> None:
        call, agent = await self.dial()
        interrupted = await self.assert_barge_in(call, agent, self.service.speech_started)
        truncate = await self.service.next(lambda b: b["type"] == "conversation.item.truncate")
        self.assertEqual(truncate["item_id"], "item_1")
        self.assertEqual(truncate["content_index"], 0)
        self.assertEqual(truncate["audio_end_ms"], interrupted.data["heard_ms"])
        # the agent played some of its 3 s, not all
        self.assertGreater(truncate["audio_end_ms"], 100)
        self.assertLess(truncate["audio_end_ms"], 2500)

    async def test_the_caller_hanging_up_closes_the_websocket_normally(self) -> None:
        call, agent = await self.dial()
        call.hangup()
        code = await asyncio.wait_for(self.service.closed.get(), 5)
        self.assertEqual(code, 1000)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "call_ended")

    async def test_the_service_closing_hangs_up_the_call(self) -> None:
        call, agent = await self.dial()
        await self.service.current.close()
        await self.wait_ended(call)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "agent_closed")

    async def test_a_dropped_connection_is_opened_again_as_a_new_session(self) -> None:
        call, agent = await self.dial()
        self.service.drop()
        reconnecting = await self.event(agent, AgentEventKind.RECONNECTING)
        self.assertEqual(reconnecting.data["attempt"], 1)
        connected = await self.event(agent, AgentEventKind.CONNECTED)
        self.assertFalse(connected.data["resumed"])
        self.assertEqual(len(self.service.connections), 2)
        await self.assert_echo(call)


if __name__ == "__main__":
    unittest.main()
