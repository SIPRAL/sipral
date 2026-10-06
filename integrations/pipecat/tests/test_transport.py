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
    InterruptionFrame,
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
        self.assertTrue(await wait_for_media(call, PATIENCE), "the call never got media")
        served = await asyncio.wait_for(self.served.get(), PATIENCE)
        await asyncio.wait_for(served.started.wait(), PATIENCE)
        return call, served

    async def _hear(
        self, call, loud: int = 0, whole: int = 0, quiet: int = 0, frames: int = 0
    ) -> list[bytes]:
        """What the caller hears until ``loud`` loud frames in all, ``whole``
        frames of nothing but the tone, ``quiet`` silent frames in a row and
        ``frames`` frames in all came.

        Counted in frames rather than in seconds: a loaded machine delays
        them, it does not make the call carry fewer.
        """
        heard: list[bytes] = []
        louds = wholes = silence = 0
        async with asyncio.timeout(PATIENCE):
            while louds < loud or wholes < whole or silence < quiet or len(heard) < frames:
                pcm = await call.media.frames.get()
                heard.append(pcm)
                if rms(pcm) > LOUD:
                    louds += 1
                    if whole and tone_share(pcm, call.media.sample_rate) > 0.8:
                        wholes += 1
                    silence = 0
                else:
                    silence += 1
                # a queue that is never empty never suspends the task, and
                # the timeout can only cancel one that does
                await asyncio.sleep(0)
        return heard

    @staticmethod
    def _drain(call) -> None:
        """What the caller heard before the test speaks is not its answer."""
        while not call.media.frames.empty():
            call.media.frames.get_nowait()

    async def test_a_tone_the_caller_sends_comes_back(self) -> None:
        call, served = await self._dial()
        rate = call.media.sample_rate
        self.assertEqual(served.transport.sample_rate, served.transport.call.media.sample_rate)
        frames = int(1.0 * rate / call.media.frame_samples)

        self._drain(call)
        call.media.send_audio(tone(rate, 2.0))
        # On a loaded machine the agent's event loop wakes late now and then,
        # and the frame sent then carries a gap: frames of nothing but the
        # tone are what is counted, as many as the median of half a second
        # of loud ones vouched for.
        try:
            await self._hear(call, whole=frames // 4 + 1)
        except TimeoutError:
            self.fail("what came back is not the tone")

    async def test_an_interruption_silences_queued_audio_within_100_ms(self) -> None:
        """Three seconds of tone are queued, and interrupted once the caller
        hears it.

        Timed from the moment the output transport sees the interruption,
        not from when the test queued it: the pipeline carrying it there
        runs late on a loaded machine, and so does the caller's jitter
        buffer. What the transport promises is exact: no tone is handed to
        the call's media after that moment, and what the media held then is
        at most ``send_ahead_ms`` (40 ms) -- well under 100 ms. The caller
        then hears the tone stop short of its three seconds, and silence
        after it.
        """
        call, served = await self._dial()
        served.echo.echoing = False
        output = served.transport.output()
        media = served.transport.call.media
        rate = served.transport.sample_rate
        frame_seconds = media.frame_samples / rate
        ahead = output._params.send_ahead_ms / 1000.0

        sent: list[tuple[float, bool]] = []
        send_audio = media.send_audio

        def recording_send(pcm):
            sent.append((time.monotonic(), rms(pcm) > LOUD))
            send_audio(pcm)

        media.send_audio = recording_send
        seen = asyncio.Event()
        seen_at: list[float] = []
        process_frame = output.process_frame

        async def watching_process_frame(frame, direction):
            if isinstance(frame, InterruptionFrame) and not seen_at:
                seen_at.append(time.monotonic())
                seen.set()
            await process_frame(frame, direction)

        output.process_frame = watching_process_frame

        await served.worker.queue_frame(
            OutputAudioRawFrame(audio=tone(rate, 3.0), sample_rate=rate, num_channels=1)
        )
        self._drain(call)
        heard = await self._hear(call, loud=1)
        await asyncio.sleep(0.3)
        await served.worker.queue_frame(InterruptionWorkerFrame())
        await asyncio.wait_for(seen.wait(), PATIENCE)
        interrupted = seen_at[0]

        late = [at for at, loud in sent if loud and at >= interrupted]
        self.assertEqual(late, [], "tone went to the call after the interruption reached it")
        toned = [at for at, loud in sent if loud]
        held = len(toned) * frame_seconds - (interrupted - toned[0])
        self.assertLessEqual(
            held,
            ahead + 0.005,
            f"the call's media held {held * 1000:.0f} ms of tone when interrupted",
        )
        self.assertLess(ahead, 0.1)

        heard += await self._hear(call, quiet=25)
        tail = await self._hear(call, frames=25)
        self.assertTrue(all(rms(pcm) < LOUD for pcm in tail), "the tone came back")
        tone_heard = sum(rms(pcm) > LOUD for pcm in heard) * frame_seconds
        self.assertLess(tone_heard, 3.0, "the interruption did not cut the tone")

    async def test_dtmf_crosses_as_pipecat_frames_both_ways(self) -> None:
        call, served = await self._dial()

        call.send_dtmf("5")
        button = await asyncio.wait_for(served.echo.digits.get(), PATIENCE)
        self.assertEqual(button, KeypadEntry.FIVE)

        await served.worker.queue_frame(OutputDTMFUrgentFrame(button=KeypadEntry.POUND))
        digit = await asyncio.wait_for(call.dtmf.get(), PATIENCE)
        self.assertEqual(digit, "#")

    async def test_the_caller_hanging_up_ends_the_pipeline(self) -> None:
        call, served = await self._dial()

        call.hangup()
        await asyncio.wait_for(served.finished.wait(), PATIENCE)
        self.assertTrue(served.transport.call.ended)

    async def test_ending_the_pipeline_hangs_up_the_call(self) -> None:
        call, served = await self._dial()

        await served.worker.queue_frame(EndFrame())
        async with asyncio.timeout(PATIENCE):
            while not call.ended:
                await asyncio.sleep(0.02)
        await asyncio.wait_for(served.finished.wait(), PATIENCE)
        self.assertTrue(served.transport.call.ended)


if __name__ == "__main__":
    unittest.main()
