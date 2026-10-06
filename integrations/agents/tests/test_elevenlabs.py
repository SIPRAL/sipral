# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A Sipral call joined to a stand-in for an ElevenLabs agent that speaks
the conversation WebSocket as ElevenLabs documents it."""

from __future__ import annotations

import asyncio
import base64
import json
import unittest

from websockets.asyncio.server import ServerConnection

from sipral_agents import AgentEventKind, ElevenLabsAgent

from .harness import AgentCallTest, FakeService

CHUNK = 16000 * 2 // 10  # 100 ms at 16 kHz


class FakeElevenLabs(FakeService):
    def __init__(self, formats: str = "pcm_16000") -> None:
        super().__init__()
        self.formats = formats
        self.event_id = 0

    async def on_message(self, ws: ServerConnection, body: dict) -> None:
        if body.get("type") == "conversation_initiation_client_data":
            # a ping before the conversation starts, which the client must answer
            await ws.send(json.dumps({"type": "ping", "ping_event": {"event_id": 7, "ping_ms": 20}}))
            await ws.send(
                json.dumps(
                    {
                        "type": "conversation_initiation_metadata",
                        "conversation_initiation_metadata_event": {
                            "conversation_id": "conv_1",
                            "agent_output_audio_format": self.formats,
                            "user_input_audio_format": self.formats,
                        },
                    }
                )
            )
        elif "user_audio_chunk" in body and self.echo:
            await self.send_audio(ws, base64.b64decode(body["user_audio_chunk"]))

    async def send_audio(self, ws: ServerConnection, pcm: bytes) -> None:
        for at in range(0, len(pcm), CHUNK):
            self.event_id += 1
            await ws.send(
                json.dumps(
                    {
                        "type": "audio",
                        "audio_event": {
                            "audio_base_64": base64.b64encode(pcm[at : at + CHUNK]).decode(),
                            "event_id": self.event_id,
                        },
                    }
                )
            )

    async def send_agent_audio(self, pcm: bytes) -> None:
        await self.send_audio(self.current, pcm)

    async def interrupt(self) -> None:
        cut = self.event_id
        await self.current.send(
            json.dumps({"type": "interruption", "interruption_event": {"event_id": cut}})
        )
        # audio generated before the cut and delivered after it: stale
        await self.current.send(
            json.dumps(
                {
                    "type": "audio",
                    "audio_event": {
                        "audio_base_64": base64.b64encode(b"\x40\x1f" * 1600).decode(),
                        "event_id": cut,
                    },
                }
            )
        )


class ElevenLabsOnACall(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeElevenLabs()

    def provider(self, url: str) -> ElevenLabsAgent:
        return ElevenLabsAgent(
            agent_id="agent_test",
            api_key="test-key",
            overrides={"agent": {"first_message": "Hello."}},
            dynamic_variables={"caller": "100"},
            url=url,
        )

    async def test_the_conversation_starts_and_the_caller_hears_the_agent(self) -> None:
        call, _agent = await self.dial()
        path, headers = self.service.requests[0]
        self.assertEqual(path, "/ws?agent_id=agent_test")
        self.assertEqual(headers.get("xi-api-key"), "test-key")
        start = self.service.log[0]
        self.assertEqual(start["type"], "conversation_initiation_client_data")
        self.assertEqual(start["conversation_config_override"], {"agent": {"first_message": "Hello."}})
        self.assertEqual(start["dynamic_variables"], {"caller": "100"})
        self.assertEqual(self.service.log[1], {"type": "pong", "event_id": 7})

        await self.assert_echo(call)
        chunk = await self.service.next(lambda b: "user_audio_chunk" in b)
        # one 20 ms frame at 16 kHz
        self.assertEqual(len(base64.b64decode(chunk["user_audio_chunk"])), 640)

    async def test_a_ping_during_the_call_is_answered(self) -> None:
        await self.dial()
        await self.service.current.send(
            json.dumps({"type": "ping", "ping_event": {"event_id": 42, "ping_ms": 10}})
        )
        pong = await self.service.next(lambda b: b.get("type") == "pong" and b["event_id"] == 42)
        self.assertEqual(pong, {"type": "pong", "event_id": 42})

    async def test_an_interruption_silences_the_agent_and_drops_stale_audio(self) -> None:
        call, agent = await self.dial()
        interrupted = await self.assert_barge_in(call, agent, self.service.interrupt)
        self.assertGreater(interrupted.data["heard_ms"], 100)

    async def test_transcripts_become_events(self) -> None:
        _call, agent = await self.dial()
        await self.service.current.send(
            json.dumps(
                {"type": "user_transcript", "user_transcription_event": {"user_transcript": "hi", "event_id": 1}}
            )
        )
        await self.service.current.send(
            json.dumps(
                {"type": "agent_response", "agent_response_event": {"agent_response": "hello", "event_id": 2}}
            )
        )
        first = await self.event(agent, AgentEventKind.TRANSCRIPT)
        second = await self.event(agent, AgentEventKind.TRANSCRIPT)
        self.assertEqual((first.data["role"], first.data["text"]), ("user", "hi"))
        self.assertEqual((second.data["role"], second.data["text"]), ("agent", "hello"))

    async def test_the_caller_hanging_up_closes_the_websocket_normally(self) -> None:
        call, agent = await self.dial()
        call.hangup()
        self.assertEqual(await asyncio.wait_for(self.service.closed.get(), 5), 1000)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "call_ended")


class ElevenLabsWithOtherFormats(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeElevenLabs(formats="ulaw_8000")

    def provider(self, url: str) -> ElevenLabsAgent:
        return ElevenLabsAgent(agent_id="agent_test", url=url)

    async def test_a_session_in_another_format_is_refused_without_retries(self) -> None:
        call = self.caller.place_call(self.caller_account, f"sip:agent@{self.agent.bind_address}")
        self.calls.append(call)
        agent = await asyncio.wait_for(self.agent_calls.get(), 5)
        error = await self.event(agent, AgentEventKind.ERROR)
        self.assertIn("ulaw_8000", error.data["message"])
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "refused")
        await self.wait_ended(call)
        self.assertEqual(len(self.service.connections), 1)


if __name__ == "__main__":
    unittest.main()
