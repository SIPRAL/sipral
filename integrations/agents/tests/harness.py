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
# how long anything may take on a machine loaded by everything else on it
PATIENCE = 30


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


async def echoed(call, again: bool = False) -> bool:
    """Whether a second of tone the caller sends comes back, half of its
    frames at least.

    Counted in the frames the caller hears rather than in seconds: a loaded
    machine delays them, it does not make the call carry fewer. An agent
    drops what the caller said before its session counted as connected, and
    a test that only sees the call cannot tell when that was: ``again``
    sends the tone again once two seconds of frames brought too little of
    it back, and each one is counted on its own. A test that waited for the
    agent's ``CONNECTED`` leaves it off, since from then on nothing the
    caller says may be lost.
    """
    rate = call.media.sample_rate
    frames = rate // call.media.frame_samples
    while not call.media.frames.empty():
        call.media.frames.get_nowait()
    try:
        async with asyncio.timeout(PATIENCE):
            while True:
                call.media.send_audio(tone(rate, 1.0))
                loud = 0
                heard = 0
                while not again or heard < 2 * frames:
                    loud += rms(await call.media.frames.get()) > LOUD
                    heard += 1
                    if loud >= frames // 2:
                        return True
                    # a queue that is never empty never suspends the task,
                    # and the timeout can only cancel one that does
                    await asyncio.sleep(0)
    except TimeoutError:
        return False


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
        self.assertTrue(await wait_for_media(call, PATIENCE), "the call never got media")
        agent = await asyncio.wait_for(self.agent_calls.get(), PATIENCE)
        await self.event(agent, AgentEventKind.CONNECTED)
        return call, agent

    async def event(
        self, agent: AgentCall, kind: AgentEventKind, timeout: float = PATIENCE
    ) -> AgentEvent:
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

    async def hear(self, call, loud: int = 0, quiet: int = 0, frames: int = 0) -> list[bytes]:
        """What the caller hears until ``loud`` loud frames in all, ``quiet``
        silent frames in a row and ``frames`` frames in all came.

        Counted in frames rather than in seconds: a loaded machine delays
        them, it does not make the call carry fewer.
        """
        heard: list[bytes] = []
        louds = silence = 0
        async with asyncio.timeout(PATIENCE):
            while louds < loud or silence < quiet or len(heard) < frames:
                pcm = await call.media.frames.get()
                heard.append(pcm)
                if rms(pcm) > LOUD:
                    louds += 1
                    silence = 0
                else:
                    silence += 1
                # a queue that is never empty never suspends the task, and
                # the timeout can only cancel one that does
                await asyncio.sleep(0)
        return heard

    @staticmethod
    def drain(call) -> None:
        """What the caller heard before the test speaks is not its answer."""
        while not call.media.frames.empty():
            call.media.frames.get_nowait()

    async def assert_echo(self, call) -> None:
        """A tone the caller sends comes back through the service: half of
        its frames at least."""
        self.assertTrue(await echoed(call), "less than half the tone came back")

    async def assert_barge_in(self, call, agent: AgentCall, cut) -> AgentEvent:
        """Three seconds of the agent's tone, cut by ``cut()`` once the caller
        hears it.

        Timed from the moment the agent's side drops what it queued -- the
        ``INTERRUPTED`` event -- not from when the test cut it: the service's
        message reaches it late on a loaded machine, and the caller's jitter
        buffer grows. What the agent's side promises is exact: no tone is
        handed to the call's media after that moment, and what the media held
        then is at most ``send_ahead_ms``. The caller then hears the tone stop
        short of its three seconds, and silence after it.
        """
        media = agent.call.media
        frame_seconds = media.frame_samples / media.sample_rate
        sent: list[tuple[float, bool]] = []
        send_audio = media.send_audio

        def recording_send(pcm: bytes) -> None:
            sent.append((time.monotonic(), rms(pcm) > LOUD))
            send_audio(pcm)

        media.send_audio = recording_send
        silenced_at: list[float] = []
        silence = agent._silence

        def timed_silence():
            silenced_at.append(time.monotonic())
            return silence()

        agent._silence = timed_silence
        self.service.echo = False
        self.drain(call)
        await self.service.send_agent_audio(tone(24000, 3.0))
        heard = await self.hear(call, loud=1)
        await asyncio.sleep(0.3)
        await cut()
        interrupted = await self.event(agent, AgentEventKind.INTERRUPTED)
        cut_at = silenced_at[0]

        late = [at for at, loud in sent if loud and at >= cut_at]
        self.assertEqual(late, [], "tone went to the call after the interruption reached the agent")
        toned = [at for at, loud in sent if loud]
        held = len(toned) * frame_seconds - (cut_at - toned[0])
        self.assertLessEqual(
            held,
            agent._ahead + 0.005,
            f"the call's media held {held * 1000:.0f} ms of tone when interrupted",
        )

        heard += await self.hear(call, quiet=25)
        tail = await self.hear(call, frames=25)
        self.assertTrue(all(rms(pcm) < LOUD for pcm in tail), "the tone came back")
        tone_heard = sum(rms(pcm) > LOUD for pcm in heard) * frame_seconds
        self.assertLess(tone_heard, 3.0, "the interruption did not cut the tone")
        return interrupted
