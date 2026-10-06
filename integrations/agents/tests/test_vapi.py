# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A Sipral call joined to a stand-in for Vapi's WebSocket transport: the
call created over HTTP, then the audio over the WebSocket the answer
names, as Vapi documents both."""

from __future__ import annotations

import asyncio
import json
import socketserver
import threading
import unittest
from http.server import BaseHTTPRequestHandler

from websockets.asyncio.server import ServerConnection

from sipral_agents import AgentEventKind, VapiAgent

from .harness import AgentCallTest, FakeService

CHUNK = 16000 * 2 // 10  # 100 ms at 16 kHz


class FakeVapi(FakeService):
    """The WebSocket side, and an HTTP server for ``POST /call``."""

    binary_audio = True

    def __init__(self, status: int = 201) -> None:
        super().__init__()
        self.status = status
        self.created: list[tuple[dict, dict]] = []

    async def start(self) -> str:
        ws_url = await super().start()
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                service.created.append((self.path, dict(self.headers), body))
                if service.status >= 300:
                    answer = {"message": "assistantId does not exist"}
                else:
                    answer = {
                        "id": "call_1",
                        "transport": {"provider": "vapi.websocket", "websocketCallUrl": ws_url},
                    }
                data = json.dumps(answer).encode()
                self.send_response(service.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args) -> None:
                pass

        # a plain TCP server: HTTPServer looks its own name up, which can
        # take seconds on a machine with no reverse DNS
        self.http = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.http.daemon_threads = True
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.http.server_address[1]}"

    async def stop(self) -> None:
        self.http.shutdown()
        self.http.server_close()
        await super().stop()

    async def on_message(self, ws: ServerConnection, body: dict) -> None:
        if "pcm" in body and self.echo:
            await self.send_audio(ws, body["pcm"])

    async def send_audio(self, ws: ServerConnection, pcm: bytes) -> None:
        for at in range(0, len(pcm), CHUNK):
            await ws.send(pcm[at : at + CHUNK])

    async def send_agent_audio(self, pcm: bytes) -> None:
        await self.send_audio(self.current, pcm)

    async def user_interrupted(self) -> None:
        await self.current.send(json.dumps({"type": "user-interrupted", "turnId": "turn-1"}))


class VapiOnACall(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeVapi()

    def provider(self, url: str) -> VapiAgent:
        return VapiAgent(
            api_key="test-key", assistant_id="asst_test", call={"customer": {"number": "+100"}}, api_url=url
        )

    async def test_the_call_is_created_and_the_caller_hears_the_agent(self) -> None:
        call, _agent = await self.dial()
        path, headers, body = self.service.created[0]
        self.assertEqual(path, "/call")
        self.assertEqual(headers.get("Authorization"), "Bearer test-key")
        self.assertEqual(body["assistantId"], "asst_test")
        self.assertEqual(
            body["transport"],
            {
                "provider": "vapi.websocket",
                "audioFormat": {"format": "pcm_s16le", "container": "raw", "sampleRate": 16000},
            },
        )
        self.assertEqual(body["customer"], {"number": "+100"})

        await self.assert_echo(call)
        frame = await self.service.next(lambda b: "pcm" in b)
        self.assertEqual(len(frame["pcm"]), 640)

    async def test_the_caller_interrupting_silences_the_agent(self) -> None:
        call, agent = await self.dial()
        interrupted = await self.assert_barge_in(call, agent, self.service.user_interrupted)
        self.assertGreater(interrupted.data["heard_ms"], 100)

    async def test_control_messages_become_events(self) -> None:
        _call, agent = await self.dial()
        await self.service.current.send(
            json.dumps({"type": "transcript", "role": "user", "transcriptType": "partial", "transcript": "h"})
        )
        await self.service.current.send(
            json.dumps(
                {"message": {"type": "transcript", "role": "user", "transcriptType": "final", "transcript": "hi"}}
            )
        )
        await self.service.current.send(
            json.dumps({"type": "speech-update", "role": "assistant", "status": "stopped"})
        )
        transcript = await self.event(agent, AgentEventKind.TRANSCRIPT)
        self.assertEqual((transcript.data["role"], transcript.data["text"]), ("user", "hi"))
        await self.event(agent, AgentEventKind.TURN_COMPLETE)

    async def test_the_caller_hanging_up_sends_hangup_and_closes_normally(self) -> None:
        call, agent = await self.dial()
        call.hangup()
        self.assertEqual(await asyncio.wait_for(self.service.closed.get(), 5), 1000)
        self.assertIn({"type": "hangup"}, self.service.log)
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "call_ended")

    async def test_a_dropped_connection_goes_back_to_the_same_call(self) -> None:
        call, agent = await self.dial()
        self.service.drop()
        await self.event(agent, AgentEventKind.RECONNECTING)
        connected = await self.event(agent, AgentEventKind.CONNECTED)
        self.assertTrue(connected.data["resumed"])
        self.assertEqual(len(self.service.created), 1)
        await self.assert_echo(call)


class VapiRefusing(AgentCallTest):
    def setUp(self) -> None:
        self.service = FakeVapi(status=400)

    def provider(self, url: str) -> VapiAgent:
        return VapiAgent(api_key="test-key", assistant_id="asst_missing", api_url=url)

    async def test_a_call_vapi_will_not_create_ends_without_retries(self) -> None:
        call = self.caller.place_call(self.caller_account, f"sip:agent@{self.agent.bind_address}")
        self.calls.append(call)
        agent = await asyncio.wait_for(self.agent_calls.get(), 5)
        error = await self.event(agent, AgentEventKind.ERROR)
        self.assertIn("400", error.data["message"])
        ended = await self.event(agent, AgentEventKind.ENDED)
        self.assertEqual(ended.data["reason"], "refused")
        await self.wait_ended(call)
        self.assertEqual(len(self.service.created), 1)


if __name__ == "__main__":
    unittest.main()
