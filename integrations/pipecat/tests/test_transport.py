# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Two stacks on 127.0.0.1: one serves calls through a Pipecat pipeline that
echoes what it hears, the other places the call and listens.

No network beyond loopback and no service: the pipeline is the transport's
two halves around an echo, which is all it takes to prove that audio, an
interruption, DTMF and the end of the call cross both ways.
"""

from __future__ import annotations

import asyncio
import math
import sys
import time
import unittest

from loguru import logger
from pipecat.audio.dtmf.types import KeypadEntry
from pipecat.frames.frames import (
    EndFrame,
    Frame,
    InputAudioRawFrame,
    InputDTMFFrame,
    InterruptionWorkerFrame,
    OutputAudioRawFrame,
    OutputDTMFUrgentFrame,
)
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.worker import PipelineParams, PipelineWorker
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor

from sipral import Stack
from sipral.enums import AudioMode
from sipral_pipecat import SipralTransport, serve, wait_for_media

logger.remove()
logger.add(sys.stderr, level="WARNING")

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


def samples(pcm: bytes) -> list[int]:
    return [int.from_bytes(pcm[at : at + 2], "little", signed=True) for at in range(0, len(pcm), 2)]


def rms(pcm: bytes) -> float:
    values = samples(pcm)
    return math.sqrt(sum(v * v for v in values) / max(len(values), 1))


def tone_share(pcm: bytes, sample_rate: int) -> float:
    """How much of the frame's energy sits at TONE_HZ (Goertzel)."""
    values = samples(pcm)
    coefficient = 2 * math.cos(2 * math.pi * TONE_HZ / sample_rate)
    previous = before = 0.0
    for value in values:
        previous, before = value + coefficient * previous - before, previous
    power = previous * previous + before * before - coefficient * previous * before
    energy = sum(v * v for v in values) * len(values) / 2
    return power / energy if energy else 0.0


class Echo(FrameProcessor):
    """Says back what the caller says, and keeps the digits it pressed."""

    def __init__(self) -> None:
        super().__init__()
        self.echoing = True
        self.digits: asyncio.Queue[KeypadEntry] = asyncio.Queue()

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        await super().process_frame(frame, direction)
        if isinstance(frame, InputAudioRawFrame):
            if self.echoing:
                await self.push_frame(
                    OutputAudioRawFrame(
                        audio=frame.audio,
                        sample_rate=frame.sample_rate,
                        num_channels=frame.num_channels,
                    )
                )
            return
        if isinstance(frame, InputDTMFFrame):
            self.digits.put_nowait(frame.button)
        await self.push_frame(frame, direction)


class Served:
    """What the factory built for one call."""

    def __init__(self, transport: SipralTransport) -> None:
        self.transport = transport
        self.echo = Echo()
        self.started = asyncio.Event()
        self.finished = asyncio.Event()
        self.worker = PipelineWorker(
            Pipeline([transport.input(), self.echo, transport.output()]),
            params=PipelineParams(
                audio_in_sample_rate=transport.sample_rate,
                audio_out_sample_rate=transport.sample_rate,
            ),
            idle_timeout_secs=None,
        )

        @self.worker.event_handler("on_pipeline_started")
        async def on_started(_worker, _frame):
            self.started.set()

        @self.worker.event_handler("on_pipeline_finished")
        async def on_finished(_worker, _frame):
            self.finished.set()


class APipecatPipelineOnACall(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.agent = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.caller = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close)
        agent_account = self.agent.add_account(
            "sip:agent@sipral.invalid", registrar_address=self.caller.bind_address
        )
        self.caller_account = self.caller.add_account(
            "sip:caller@sipral.invalid", registrar_address=self.agent.bind_address
        )
        self.served: asyncio.Queue[Served] = asyncio.Queue()

        def factory(transport: SipralTransport) -> PipelineWorker:
            served = Served(transport)
            self.served.put_nowait(served)
            return served.worker

        self.serving = asyncio.create_task(serve(agent_account, factory))
        self.calls = []

    async def _close(self) -> None:
        self.serving.cancel()
        await asyncio.gather(self.serving, return_exceptions=True)
        for call in self.calls:
            call.close()
        self.caller.close()
        self.agent.close()

    async def _dial(self):
        call = self.caller.place_call(self.caller_account, f"sip:agent@{self.agent.bind_address}")
        self.calls.append(call)
        self.assertTrue(await wait_for_media(call, 5), "the call never got media")
        served = await asyncio.wait_for(self.served.get(), 5)
        await asyncio.wait_for(served.started.wait(), 10)
        return call, served

    async def _listen(
        self, call, seconds: float, heard: list[tuple[float, bytes]] | None = None
    ) -> list[tuple[float, bytes]]:
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

    async def test_a_tone_the_caller_sends_comes_back(self) -> None:
        call, served = await self._dial()
        rate = call.media.sample_rate
        self.assertEqual(served.transport.sample_rate, served.transport.call.media.sample_rate)

        call.media.send_audio(tone(rate, 1.0))
        heard = await self._listen(call, 1.6)

        echoed = [pcm for _, pcm in heard if rms(pcm) > LOUD]
        self.assertGreaterEqual(len(echoed), 25, "less than half the tone came back")
        shares = sorted(tone_share(pcm, rate) for pcm in echoed)
        self.assertGreater(shares[len(shares) // 2], 0.8, "what came back is not the tone")

    async def test_an_interruption_silences_queued_audio_within_100_ms(self) -> None:
        """Three seconds of tone are queued, and interrupted once the caller
        hears it.

        What the caller hears is late by the path from the agent's media --
        the codec, the caller's jitter buffer, which grows on a loaded
        machine -- so a tone sent straight on that media measures it before
        and after, and the longer of the two is taken off; past that, the
        agent stops within 100 ms.
        """
        call, served = await self._dial()
        served.echo.echoing = False
        media = served.transport.call.media
        rate = served.transport.sample_rate
        heard: list[tuple[float, bytes]] = []
        listening = asyncio.create_task(self._listen(call, 30, heard))
        self.addCleanup(listening.cancel)

        async def loud_after(since: float) -> float:
            async with asyncio.timeout(5):
                while True:
                    for at, pcm in heard:
                        if at > since and rms(pcm) > LOUD:
                            return at
                    await asyncio.sleep(0.005)

        async def path() -> float:
            sent = time.monotonic()
            media.send_audio(tone(media.sample_rate, 0.2))
            heard_at = await loud_after(sent)
            await asyncio.sleep(0.4)
            return heard_at - sent

        before = await path()

        queued = time.monotonic()
        await served.worker.queue_frame(
            OutputAudioRawFrame(audio=tone(rate, 3.0), sample_rate=rate, num_channels=1)
        )
        await loud_after(queued)
        await asyncio.sleep(0.3)
        interrupted = time.monotonic()
        await served.worker.queue_frame(InterruptionWorkerFrame())
        await asyncio.sleep(1.0)
        stopped = time.monotonic()
        latency = max(before, await path())

        loud = [at for at, pcm in heard if queued < at < stopped and rms(pcm) > LOUD]
        after = loud[-1] - interrupted - latency
        self.assertLess(
            after,
            0.1,
            f"the agent sent tone for {after * 1000:.0f} ms after the interruption "
            f"(path {latency * 1000:.0f} ms)",
        )
        quiet = [pcm for at, pcm in heard if interrupted + latency + 0.1 < at < stopped]
        self.assertGreater(len(quiet), 30, "the call stopped carrying audio altogether")
        self.assertTrue(all(rms(pcm) < LOUD for pcm in quiet), "the tone came back")

    async def test_dtmf_crosses_as_pipecat_frames_both_ways(self) -> None:
        call, served = await self._dial()

        call.send_dtmf("5")
        button = await asyncio.wait_for(served.echo.digits.get(), 5)
        self.assertEqual(button, KeypadEntry.FIVE)

        await served.worker.queue_frame(OutputDTMFUrgentFrame(button=KeypadEntry.POUND))
        digit = await asyncio.wait_for(call.dtmf.get(), 5)
        self.assertEqual(digit, "#")

    async def test_the_caller_hanging_up_ends_the_pipeline(self) -> None:
        call, served = await self._dial()

        call.hangup()
        await asyncio.wait_for(served.finished.wait(), 5)
        self.assertTrue(served.transport.call.ended)

    async def test_ending_the_pipeline_hangs_up_the_call(self) -> None:
        call, served = await self._dial()

        await served.worker.queue_frame(EndFrame())
        async with asyncio.timeout(5):
            while not call.ended:
                await asyncio.sleep(0.02)
        await asyncio.wait_for(served.finished.wait(), 5)
        self.assertTrue(served.transport.call.ended)


if __name__ == "__main__":
    unittest.main()
