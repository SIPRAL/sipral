# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``SipralTransport``: one Sipral call as a Pipecat transport.

The call's media hands decoded 16-bit mono PCM at the codec's own rate and
takes it back at that rate, so both halves declare the call's rate and leave
any resampling to Pipecat: the input stamps it on every frame, the output
transport resamples whatever the services produce to it before
:meth:`SipralOutputTransport.write_audio_frame` sees it.
"""

from __future__ import annotations

import asyncio
import time

from pipecat.audio.dtmf.types import KeypadEntry
from pipecat.frames.frames import (
    CancelFrame,
    CancelWorkerFrame,
    EndFrame,
    Frame,
    InputAudioRawFrame,
    InputDTMFFrame,
    InterruptionFrame,
    OutputAudioRawFrame,
    OutputDTMFFrame,
    OutputDTMFUrgentFrame,
    StartFrame,
)
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor
from pipecat.transports.base_input import BaseInputTransport
from pipecat.transports.base_output import BaseOutputTransport
from pipecat.transports.base_transport import BaseTransport, TransportParams

from sipral import Call, SipralError
from sipral.enums import EventKind

__all__ = [
    "SipralInputTransport",
    "SipralOutputTransport",
    "SipralTransport",
    "SipralTransportParams",
    "wait_for_media",
]


class SipralTransportParams(TransportParams):
    """`TransportParams` with audio on both ways, and what a call adds.

    ``audio_in_sample_rate`` and ``audio_out_sample_rate`` are always the
    call's own; whatever is set here is replaced. ``send_ahead_ms`` is the
    most audio the call's media holds queued, at least one frame: what an
    interruption cannot take back, and what absorbs a late wake-up of the
    event loop. ``dtmf_duration_ms`` is how long each digit Pipecat sends
    lasts.
    """

    audio_in_enabled: bool = True
    audio_out_enabled: bool = True
    # A phone's jitter buffer holds far less than a browser's.
    audio_out_end_silence_secs: int = 1
    send_ahead_ms: int = 40
    dtmf_duration_ms: int = 100


async def wait_for_media(call: Call, timeout: float | None = None) -> bool:
    """Wait until ``call.media`` exists; `False` when the call ended first
    or ``timeout`` passed.

    Polled rather than read off ``call.events``: those belong to the
    transport, which reports each one as ``on_call_event``.
    """

    async def started() -> None:
        while call.media is None and not call.ended:
            await asyncio.sleep(0.01)

    try:
        await asyncio.wait_for(started(), timeout)
    except TimeoutError:
        return False
    return call.media is not None and not call.ended


class SipralInputTransport(BaseInputTransport):
    """The caller's audio, keypad digits and the call's end, into a pipeline."""

    _params: SipralTransportParams

    def __init__(self, transport: "SipralTransport", params: SipralTransportParams, **kwargs):
        super().__init__(params, **kwargs)
        self._transport = transport
        self._tasks: list[asyncio.Task] = []

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        if isinstance(frame, StartFrame):
            # What arrived while the pipeline was being built is stale by now.
            # Dropped here, before the StartFrame goes on: Pipecat passes it
            # downstream before calling start(), so the pipeline counts as
            # started first, and audio the caller sends from then on is kept.
            frames = self._transport.call.media.frames
            while not frames.empty():
                frames.get_nowait()
        await super().process_frame(frame, direction)

    async def start(self, frame: StartFrame):
        await super().start(frame)
        if not self._tasks:
            self._tasks = [
                self.create_task(self._receive_audio()),
                self.create_task(self._receive_digits()),
                self.create_task(self._watch_call()),
            ]
        await self.set_transport_ready(frame)

    async def stop(self, frame: EndFrame):
        await super().stop(frame)
        await self._stop_tasks()

    async def cancel(self, frame: CancelFrame):
        await super().cancel(frame)
        await self._stop_tasks()

    async def _stop_tasks(self) -> None:
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            if task is not asyncio.current_task():
                await self.cancel_task(task)

    async def _receive_audio(self) -> None:
        media = self._transport.call.media
        while True:
            pcm = await media.frames.get()
            await self.push_audio_frame(
                InputAudioRawFrame(audio=pcm, sample_rate=media.sample_rate, num_channels=1)
            )

    async def _receive_digits(self) -> None:
        call = self._transport.call
        while True:
            digit = await call.dtmf.get()
            try:
                button = KeypadEntry(digit)
            except ValueError:
                # A to D have no key in Pipecat
                continue
            await self.push_frame(InputDTMFFrame(button=button))

    async def _watch_call(self) -> None:
        call = self._transport.call
        while True:
            event = await call.events.get()
            await self._transport._report("on_call_event", event)
            if event.kind == EventKind.CALL_ENDED:
                break
        await self._transport._report("on_call_ended", call)
        # nobody is left to hear what is still queued
        await self.push_frame(CancelWorkerFrame(reason="call ended"), FrameDirection.UPSTREAM)


class SipralOutputTransport(BaseOutputTransport):
    """A pipeline's audio and digits, onto the call.

    Audio goes to ``media.send_audio`` one codec frame at a time, at the
    pace the media plays it, so the media never holds more than
    ``send_ahead_ms`` of it and an interruption silences the call that
    soon. Whatever is shorter than a frame waits for the next write.
    """

    _params: SipralTransportParams

    def __init__(self, transport: "SipralTransport", params: SipralTransportParams, **kwargs):
        super().__init__(params, **kwargs)
        self._transport = transport
        media = transport.call.media
        self._frame_bytes = media.frame_samples * 2
        self._frame_seconds = media.frame_samples / media.sample_rate
        self._ahead = max(params.send_ahead_ms / 1000.0, self._frame_seconds)
        self._remainder = b""
        # when the media will have played everything handed to it
        self._due = 0.0
        self._interruptions = 0
        self._interrupting = False

    async def start(self, frame: StartFrame):
        await super().start(frame)
        await self.set_transport_ready(frame)

    async def stop(self, frame: EndFrame):
        await super().stop(frame)
        await self._flush()
        await self._transport.hang_up()

    async def cancel(self, frame: CancelFrame):
        await super().cancel(frame)
        await self._transport.hang_up()

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        if not isinstance(frame, InterruptionFrame):
            await super().process_frame(frame, direction)
            return
        self._remainder = b""
        self._interruptions += 1
        # Pipecat drops the audio it still holds only once the frame has
        # gone on; until then its audio task can hand over more, which is
        # not to reach the call.
        self._interrupting = True
        try:
            await super().process_frame(frame, direction)
        finally:
            self._interrupting = False

    async def write_audio_frame(self, frame: OutputAudioRawFrame) -> bool:
        if self._transport.call.ended:
            return False
        if self._interrupting and frame.interruptible:
            return True
        data = self._remainder + frame.audio
        self._remainder = b""
        interruptions = self._interruptions
        sent = 0
        while len(data) - sent >= self._frame_bytes:
            await self._wait_for_room()
            if frame.interruptible and (
                self._interrupting or self._interruptions != interruptions
            ):
                return True
            self._send(data[sent : sent + self._frame_bytes])
            sent += self._frame_bytes
        self._remainder = data[sent:]
        return True

    def _supports_native_dtmf(self) -> bool:
        return True

    async def _write_dtmf_native(self, frame: OutputDTMFFrame | OutputDTMFUrgentFrame):
        digits = "".join(button.value for button in frame.buttons or [])
        if not digits or self._transport.call.ended:
            return
        try:
            self._transport.call.send_dtmf(digits, duration_ms=self._params.dtmf_duration_ms)
        except SipralError as refused:
            await self.push_error(f"the call refused DTMF {digits!r}: {refused}")

    async def _wait_for_room(self) -> None:
        delay = self._due + self._frame_seconds - self._ahead - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)

    def _send(self, pcm: bytes) -> None:
        try:
            self._transport.call.media.send_audio(pcm)
        except (RuntimeError, SipralError):
            return
        self._due = max(self._due, time.monotonic()) + self._frame_seconds

    async def _flush(self) -> None:
        """The last words, padded to a frame, played before the hangup."""
        if self._remainder and not self._transport.call.ended:
            self._send(self._remainder + bytes(self._frame_bytes - len(self._remainder)))
        self._remainder = b""
        delay = self._due - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)


class SipralTransport(BaseTransport):
    """One Sipral call whose media has started, as a Pipecat transport.

    ``input()`` turns the caller's audio into `InputAudioRawFrame` at the
    call's rate and each keypad digit into `InputDTMFFrame`; ``output()``
    plays `OutputAudioRawFrame` on the call and sends `OutputDTMFFrame` and
    `OutputDTMFUrgentFrame` as the call's own DTMF. The call ending cancels
    the pipeline; the pipeline ending, or being cancelled, hangs up.

    The transport reads ``call.events``, ``call.dtmf`` and
    ``media.frames``; nothing else should. Each event is reported as
    ``on_call_event(transport, event)`` and the end as
    ``on_call_ended(transport, call)``. Closing the call stays with
    whoever placed or answered it.
    """

    def __init__(
        self,
        call: Call,
        params: SipralTransportParams | None = None,
        *,
        name: str | None = None,
        input_name: str | None = None,
        output_name: str | None = None,
    ):
        media = call.media
        if media is None:
            raise ValueError("the call has no media yet: await wait_for_media(call) first")
        if media.pumped:
            raise ValueError(
                "the call's audio is the library's own (device mode): create the stack "
                "with audio=AudioMode.APPLICATION"
            )
        super().__init__(name=name, input_name=input_name, output_name=output_name)
        self.call = call
        self._params = (params or SipralTransportParams()).model_copy(
            update={
                "audio_in_sample_rate": media.sample_rate,
                "audio_out_sample_rate": media.sample_rate,
                "audio_in_channels": 1,
                "audio_out_channels": 1,
            }
        )
        self._input: SipralInputTransport | None = None
        self._output: SipralOutputTransport | None = None
        self._hung_up = False
        self._register_event_handler("on_call_event")
        self._register_event_handler("on_call_ended")

    @property
    def sample_rate(self) -> int:
        """The call's audio rate, in Hz, both ways."""
        return self.call.media.sample_rate

    def input(self) -> FrameProcessor:
        if self._input is None:
            self._input = SipralInputTransport(self, self._params, name=self._input_name)
        return self._input

    def output(self) -> FrameProcessor:
        if self._output is None:
            self._output = SipralOutputTransport(self, self._params, name=self._output_name)
        return self._output

    async def hang_up(self) -> None:
        """Hang up the call, once, unless it already ended."""
        if self._hung_up or self.call.ended:
            return
        self._hung_up = True
        try:
            self.call.hangup()
        except SipralError:
            pass

    async def _report(self, event_name: str, *args) -> None:
        await self._call_event_handler(event_name, *args)
