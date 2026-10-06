# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Two Sipral stacks on 127.0.0.1 and a stand-in service on a local
WebSocket: one stack serves calls through ``sipral_agents.serve``, the other
places them and listens. No network beyond loopback, no key, no cost."""

from __future__ import annotations

import abc
import asyncio
import json
import math
import time
import unittest

from websockets.asyncio.server import ServerConnection
from websockets.exceptions import ConnectionClosedError
from websockets.asyncio.server import serve as ws_serve

from sipral import Stack
from sipral.enums import AudioMode
from sipral_agents import AgentCall, AgentEvent, AgentEventKind, Backoff, serve, wait_for_media

TONE_HZ = 1000
LOUD = 1000


def tone(sample_rate: int, seconds: float, amplitude: int = 8000) -> bytes:
    count = int(sample_rate * seconds)
    return b"".join(
        int(amplitude * math.sin(2 * math.pi * TONE_HZ * n / sample_rate)).to_bytes(
            2, "little", signed=True
        )
        for n in range(count)
    )


def rms(pcm: bytes) -> float:
    values = [int.from_bytes(pcm[at : at + 2], "little", signed=True) for at in range(0, len(pcm), 2)]
    return math.sqrt(sum(v * v for v in values) / max(len(values), 1))


class FakeService(abc.ABC):
    """A local WebSocket server; a subclass speaks one vendor's protocol.

    Every connection is kept in :attr:`connections`, every message it got
    in :attr:`received` as parsed JSON, and the request's path and headers
    in :attr:`requests`. ``echo`` sends the caller's audio straight back as
    the agent's. A binary frame of a service whose audio travels as raw PCM
    (``binary_audio``) is kept as ``{"pcm": bytes}``.
    """

    binary_audio = False

    def __init__(self) -> None:
        self.connections: list[ServerConnection] = []
        self.received: asyncio.Queue[dict] = asyncio.Queue()
        self.log: list[dict] = []
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.closed: asyncio.Queue[int | None] = asyncio.Queue()
        self.ready = asyncio.Event()
        self.echo = True
        self.server = None

    async def start(self) -> str:
        self.server = await ws_serve(self._handler, "127.0.0.1", 0, max_size=None)
        port = self.server.sockets[0].getsockname()[1]
        return f"ws://127.0.0.1:{port}/ws"

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    @property
    def current(self) -> ServerConnection:
        return self.connections[-1]

    async def _handler(self, ws: ServerConnection) -> None:
        self.connections.append(ws)
        self.requests.append((ws.request.path, dict(ws.request.headers)))
        try:
            async for message in ws:
                if self.binary_audio and isinstance(message, bytes):
                    body = {"pcm": message}
                else:
                    body = json.loads(message)
                self.log.append(body)
                await self.on_message(ws, body)
                self.received.put_nowait(body)
        except ConnectionClosedError:
            # drop() cuts connections on purpose
            pass
        finally:
            self.closed.put_nowait(ws.close_code)

    @abc.abstractmethod
    async def on_message(self, ws: ServerConnection, body: dict) -> None:
        """Answer one message from the client."""

    @abc.abstractmethod
    async def send_agent_audio(self, pcm: bytes) -> None:
        """Speak ``pcm`` (24 kHz) as the agent's new turn."""

    async def next(self, predicate, timeout: float = 5.0) -> dict:
        async with asyncio.timeout(timeout):
            while True:
                body = await self.received.get()
                if predicate(body):
                    return body

    def drop(self) -> None:
        """Cut the current connection with no closing handshake."""
        self.current.transport.abort()


class AgentCallTest(unittest.IsolatedAsyncioTestCase):
    """Builds the stacks and serves calls with ``self.provider(url)``, which
    a subclass defines next to the ``service`` it sets up."""

    service: FakeService

    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.url = await self.service.start()
        self.agent = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.caller = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close)
        agent_account = self.agent.add_account(
            "sip:agent@sipral.invalid", registrar_address=self.caller.bind_address
        )
        self.caller_account = self.caller.add_account(
            "sip:caller@sipral.invalid", registrar_address=self.agent.bind_address
        )
        self.agent_calls: asyncio.Queue[AgentCall] = asyncio.Queue()
        self.serving = asyncio.create_task(
            serve(
                agent_account,
                lambda _call: self.provider(self.url),
                backoff=Backoff(first=0.1, longest=0.4, attempts=5),
                on_agent_call=self.agent_calls.put_nowait,
            )
        )
        self.calls = []

    async def _close(self) -> None:
        self.serving.cancel()
        await asyncio.gather(self.serving, return_exceptions=True)
        for call in self.calls:
            call.close()
        self.caller.close()
        self.agent.close()
        await self.service.stop()

    async def dial(self):
        call = self.caller.place_call(self.caller_account, f"sip:agent@{self.agent.bind_address}")
        self.calls.append(call)
        self.assertTrue(await wait_for_media(call, 5), "the call never got media")
        agent = await asyncio.wait_for(self.agent_calls.get(), 5)
        await self.event(agent, AgentEventKind.CONNECTED)
        return call, agent

    async def event(self, agent: AgentCall, kind: AgentEventKind, timeout: float = 5.0) -> AgentEvent:
        async with asyncio.timeout(timeout):
            while True:
                event = await agent.events.get()
                if event.kind == kind:
                    return event

    async def listen(self, call, seconds: float, heard=None):
        """Every frame the caller hears for ``seconds``, with when it came."""
        heard = [] if heard is None else heard
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            try:
                frame = await asyncio.wait_for(call.media.frames.get(), left)
            except TimeoutError:
                break
            heard.append((time.monotonic(), frame))
        return heard

    async def wait_ended(self, call, timeout: float = 5.0) -> None:
        async with asyncio.timeout(timeout):
            while not call.ended:
                await asyncio.sleep(0.02)

    async def assert_echo(self, call) -> None:
        """A tone the caller sends comes back through the service."""
        call.media.send_audio(tone(call.media.sample_rate, 1.0))
        heard = await self.listen(call, 1.6)
        loud = [pcm for _, pcm in heard if rms(pcm) > LOUD]
        self.assertGreaterEqual(len(loud), 25, "less than half the tone came back")

    async def assert_barge_in(self, call, agent: AgentCall, cut) -> AgentEvent:
        """Three seconds of the agent's tone, cut by ``cut()`` once the caller
        hears it: the caller stops hearing it soon after."""
        heard: list = []
        listening = asyncio.create_task(self.listen(call, 30, heard))
        self.addCleanup(listening.cancel)
        self.service.echo = False
        await self.service.send_agent_audio(tone(24000, 3.0))
        async with asyncio.timeout(5):
            while not any(rms(pcm) > LOUD for _, pcm in heard):
                await asyncio.sleep(0.005)
        await asyncio.sleep(0.3)
        cut_at = time.monotonic()
        await cut()
        interrupted = await self.event(agent, AgentEventKind.INTERRUPTED)
        await asyncio.sleep(1.0)
        late = [at for at, pcm in heard if at > cut_at + 0.4 and rms(pcm) > LOUD]
        self.assertEqual(late, [], "the agent's audio went on after the barge-in")
        quiet = [pcm for at, pcm in heard if at > cut_at + 0.4]
        self.assertGreater(len(quiet), 20, "the call stopped carrying audio altogether")
        return interrupted
