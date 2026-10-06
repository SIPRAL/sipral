# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""What every connector shares: one Sipral call joined to one voice-agent
service over a WebSocket.

A service is described by a :class:`Provider`: where to connect, how to
open a session, how a frame of the caller's audio becomes a message and how
a message becomes :class:`Signal` values. Everything else lives here, once:

- **Rate.** The call's frames are switched to the provider's rate with
  ``Media.set_app_rate``, so the library's own resampler converts between
  the codec and the service both ways and no audio is resampled in Python.
- **Pacing and barge-in.** The service's audio is played a codec frame at a
  time in real time, with never more than ``send_ahead_ms`` queued in the
  call's media; when the service says the caller started speaking, or that
  it cut its own turn short, whatever is still queued is dropped at once
  and the provider is told how much of its turn was heard.
- **Events.** Each step is an :class:`AgentEvent` on ``AgentCall.events``.
- **Reconnection.** A connection that drops while the call is up is opened
  again with exponential backoff (:class:`Backoff`); one the service
  announces it will close is replaced at once, resuming the session where
  the provider can.
- **Ending.** The call ending closes the WebSocket with a normal closure;
  the service closing its side normally hangs up the call.
"""

from __future__ import annotations

import abc
import asyncio
import enum
import random
import time
from dataclasses import dataclass, field
from typing import Any

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, ConnectionClosedOK, InvalidHandshake

from sipral import Call, SipralError
from sipral.enums import EventKind

__all__ = [
    "AgentCall",
    "AgentEvent",
    "AgentEventKind",
    "Audio",
    "Backoff",
    "GoAway",
    "Interrupted",
    "Provider",
    "ProviderError",
    "Signal",
    "SpeechStarted",
    "Transcript",
    "TurnComplete",
]


# -- what a provider reads off the wire -------------------------------------


@dataclass(frozen=True)
class Audio:
    """The agent's audio: 16-bit little-endian mono PCM at the provider's
    rate. ``item`` names the turn it belongs to, where the service does."""

    pcm: bytes
    item: str | None = None


@dataclass(frozen=True)
class SpeechStarted:
    """The service heard the caller start speaking: a barge-in."""


@dataclass(frozen=True)
class Interrupted:
    """The service cut its own turn short; what is queued is stale."""


@dataclass(frozen=True)
class TurnComplete:
    """The service finished a turn."""


@dataclass(frozen=True)
class Transcript:
    """Text of what was said: ``role`` is ``"user"`` or ``"agent"``."""

    role: str
    text: str


@dataclass(frozen=True)
class ProviderError:
    """The service reported an error. A ``fatal`` one ends the session."""

    message: str
    fatal: bool = False


@dataclass(frozen=True)
class GoAway:
    """The service will close this connection soon; open another now."""


Signal = Audio | SpeechStarted | Interrupted | TurnComplete | Transcript | ProviderError | GoAway


class Provider(abc.ABC):
    """One voice-agent service's WebSocket protocol.

    A subclass sets :attr:`name` and :attr:`sample_rate` -- the PCM rate
    the service takes and returns, which must be one of 8000, 16000, 24000
    or 48000, the rates a call's media converts to -- and implements
    :meth:`url`, :meth:`open`, :meth:`audio_message` and :meth:`parse`.
    """

    name = "provider"
    sample_rate = 24000

    @abc.abstractmethod
    def url(self) -> str:
        """The WebSocket address to connect to."""

    def headers(self) -> dict[str, str]:
        """HTTP headers for the opening handshake."""
        return {}

    @abc.abstractmethod
    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        """Configure a freshly opened connection and return once the service
        accepts the session. ``resuming`` is true for every connection after
        the first; the return value says whether the service kept the
        session's state across it."""

    @abc.abstractmethod
    def audio_message(self, pcm: bytes) -> str | bytes:
        """One frame of the caller's audio, as a message for the service."""

    @abc.abstractmethod
    def parse(self, message: str | bytes) -> list[Signal]:
        """What one message from the service means."""

    def barge_in(self, item: str | None, heard_ms: int) -> list[str | bytes]:
        """Messages to send when the caller cut the agent short, ``heard_ms``
        into the agent's turn ``item``; none by default."""
        return []


# -- what an application sees ----------------------------------------------


class AgentEventKind(enum.Enum):
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    USER_SPEECH_STARTED = "user_speech_started"
    INTERRUPTED = "interrupted"
    TURN_COMPLETE = "turn_complete"
    TRANSCRIPT = "transcript"
    ERROR = "error"
    ENDED = "ended"


@dataclass(frozen=True)
class AgentEvent:
    """One step of an :class:`AgentCall`.

    ``CONNECTED`` carries ``resumed`` (whether the service kept the
    session); ``RECONNECTING`` the ``attempt`` and ``delay`` in seconds;
    ``INTERRUPTED`` the ``heard_ms`` of the turn that was cut; ``TRANSCRIPT``
    ``role`` and ``text``; ``ERROR`` ``message``; ``ENDED`` ``reason``, one
    of ``"call_ended"``, ``"agent_closed"``, ``"gave_up"``, ``"closed"``.
    """

    kind: AgentEventKind
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Backoff:
    """How a dropped connection is retried: ``first`` seconds, doubling up
    to ``longest``, each with up to ``jitter`` of itself added at random;
    ``attempts`` tries in a row before the call is hung up (0: never)."""

    first: float = 0.5
    longest: float = 8.0
    jitter: float = 0.2
    attempts: int = 6

    def delay(self, attempt: int) -> float:
        base = min(self.first * (2 ** (attempt - 1)), self.longest)
        return base * (1 + random.uniform(0, self.jitter))


class _Ended(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AgentCall:
    """One call whose media has started, joined to one :class:`Provider`.

    ``await run()`` until the call or the session ends; ``close()`` ends
    both from outside. The call must be in application audio mode. While it
    runs, this reads ``call.events`` and ``media.frames``; nothing else
    should. Closing the call object stays with whoever answered or placed
    it.
    """

    def __init__(
        self,
        call: Call,
        provider: Provider,
        *,
        backoff: Backoff | None = None,
        send_ahead_ms: int = 40,
        connect_timeout: float = 10.0,
    ) -> None:
        media = call.media
        if media is None:
            raise ValueError("the call has no media yet")
        if media.pumped:
            raise ValueError(
                "the call's audio is the library's own (device mode): create the stack "
                "with audio=AudioMode.APPLICATION"
            )
        self.call = call
        self.provider = provider
        self.backoff = backoff or Backoff()
        self.connect_timeout = connect_timeout
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        self._send_ahead = send_ahead_ms / 1000.0
        self._ws: ClientConnection | None = None
        self._closing = False
        self._stopped = asyncio.Event()
        self._call_ended = asyncio.Event()
        # playout
        self._queued = bytearray()
        self._queued_item: str | None = None
        self._more = asyncio.Event()
        self._due = 0.0
        self._item: str | None = None
        self._item_sent = 0
        self._silenced: set[str] = set()

    # -- public ------------------------------------------------------------

    async def run(self) -> str:
        """Join the call to the service until either ends; returns the
        reason also carried by the ``ENDED`` event."""
        media = self.call.media
        media.set_app_rate(self.provider.sample_rate)
        while not media.frames.empty():
            media.frames.get_nowait()
        self._frame_bytes = media.frame_samples * 2
        self._frame_seconds = media.frame_samples / media.sample_rate
        self._ahead = max(self._send_ahead, self._frame_seconds)
        watcher = asyncio.create_task(self._watch_call())
        playout = asyncio.create_task(self._playout())
        try:
            reason = await self._sessions()
        finally:
            for task in (watcher, playout):
                task.cancel()
            await asyncio.gather(watcher, playout, return_exceptions=True)
            self._stopped.set()
        if reason != "call_ended":
            self._hang_up()
        self._emit(AgentEventKind.ENDED, reason=reason)
        return reason

    async def close(self) -> None:
        """Close the WebSocket normally, hang up the call, and wait for
        :meth:`run` to return."""
        self._closing = True
        self._hang_up()
        self._call_ended.set()
        if self._ws is not None:
            await self._ws.close()
        await self._stopped.wait()

    # -- sessions ----------------------------------------------------------

    async def _sessions(self) -> str:
        attempt = 0
        resuming = False
        while True:
            if self._call_ended.is_set():
                return "closed" if self._closing else "call_ended"
            try:
                ws = await asyncio.wait_for(self._connect(resuming), self.connect_timeout)
            except (OSError, InvalidHandshake, ConnectionClosed, TimeoutError) as failed:
                self._emit(AgentEventKind.ERROR, message=f"{self.provider.name}: {failed}")
                ws = None
            except _Ended as ended:
                return ended.reason
            if ws is not None:
                attempt = 0
                resuming = True
                try:
                    await self._session(ws)
                except _Ended as ended:
                    return ended.reason
                except _Replace:
                    continue
                except ConnectionClosed as dropped:
                    self._emit(AgentEventKind.ERROR, message=f"{self.provider.name}: {dropped}")
                finally:
                    # a cancelled run leaves here too, and the service still
                    # gets a normal closure
                    self._ws = None
                    await ws.close()
            attempt += 1
            if self.backoff.attempts and attempt > self.backoff.attempts:
                return "gave_up"
            delay = self.backoff.delay(attempt)
            self._emit(AgentEventKind.RECONNECTING, attempt=attempt, delay=delay)
            try:
                await asyncio.wait_for(self._call_ended.wait(), delay)
            except TimeoutError:
                pass

    async def _connect(self, resuming: bool) -> ClientConnection:
        ws = await connect(
            self.provider.url(),
            additional_headers=self.provider.headers(),
            max_size=None,
            open_timeout=self.connect_timeout,
        )
        try:
            opened = asyncio.create_task(self.provider.open(ws, resuming))
            ended = asyncio.create_task(self._call_ended.wait())
            done, _ = await asyncio.wait({opened, ended}, return_when=asyncio.FIRST_COMPLETED)
            if opened not in done:
                opened.cancel()
                await asyncio.gather(opened, return_exceptions=True)
                await ws.close()
                raise _Ended("closed" if self._closing else "call_ended")
            ended.cancel()
            resumed = opened.result()
        except BaseException:
            await ws.close()
            raise
        self._ws = ws
        self._emit(AgentEventKind.CONNECTED, resumed=bool(resumed))
        return ws

    async def _session(self, ws: ClientConnection) -> None:
        uplink = asyncio.create_task(self._uplink(ws))
        downlink = asyncio.create_task(self._downlink(ws))
        ended = asyncio.create_task(self._call_ended.wait())
        try:
            done, _ = await asyncio.wait(
                {uplink, downlink, ended}, return_when=asyncio.FIRST_COMPLETED
            )
            if ended in done:
                await ws.close()
                raise _Ended("closed" if self._closing else "call_ended")
            for task in done:
                task.result()
        finally:
            for task in (uplink, downlink, ended):
                task.cancel()
            await asyncio.gather(uplink, downlink, ended, return_exceptions=True)

    async def _uplink(self, ws: ClientConnection) -> None:
        frames = self.call.media.frames
        while not frames.empty():
            frames.get_nowait()
        while True:
            pcm = await frames.get()
            try:
                await ws.send(self.provider.audio_message(pcm))
            except ConnectionClosed:
                # how the connection ended is the downlink's to read
                await asyncio.Event().wait()

    async def _downlink(self, ws: ClientConnection) -> None:
        try:
            async for message in ws:
                for signal in self.provider.parse(message):
                    await self._handle(ws, signal)
        except ConnectionClosedOK:
            pass
        else:
            if ws.close_code not in (None, 1000, 1001):
                raise ConnectionClosed(ws.close_rcvd, ws.close_sent)
        if self._call_ended.is_set():
            raise _Ended("closed" if self._closing else "call_ended")
        await self._drain()
        raise _Ended("agent_closed")

    async def _handle(self, ws: ClientConnection, signal: Signal) -> None:
        if isinstance(signal, Audio):
            if signal.item is not None and signal.item in self._silenced:
                return
            if signal.item != self._queued_item and signal.item is not None:
                self._queued_item = signal.item
            self._queued += signal.pcm
            self._more.set()
        elif isinstance(signal, SpeechStarted):
            self._emit(AgentEventKind.USER_SPEECH_STARTED)
            item, heard = self._silence()
            if heard is not None:
                for message in self.provider.barge_in(item, heard):
                    await ws.send(message)
                self._emit(AgentEventKind.INTERRUPTED, heard_ms=heard)
        elif isinstance(signal, Interrupted):
            _, heard = self._silence()
            self._emit(AgentEventKind.INTERRUPTED, heard_ms=heard or 0)
        elif isinstance(signal, TurnComplete):
            self._emit(AgentEventKind.TURN_COMPLETE)
        elif isinstance(signal, Transcript):
            self._emit(AgentEventKind.TRANSCRIPT, role=signal.role, text=signal.text)
        elif isinstance(signal, ProviderError):
            self._emit(AgentEventKind.ERROR, message=signal.message)
            if signal.fatal:
                await ws.close()
                raise _Ended("agent_closed")
        elif isinstance(signal, GoAway):
            await ws.close()
            raise _Replace()

    # -- playout -----------------------------------------------------------

    def _silence(self) -> tuple[str | None, int | None]:
        """Drop what is queued; the turn that was playing and how much of it
        the caller heard, or ``None`` when nothing was playing."""
        playing = bool(self._queued) or self._due > time.monotonic()
        self._queued.clear()
        item = self._item if self._item is not None else self._queued_item
        if item is not None:
            self._silenced.add(item)
        if not playing:
            return item, None
        still_queued = max(0.0, self._due - time.monotonic())
        heard = self._item_sent / 2 / self.provider.sample_rate - still_queued
        return item, max(0, int(heard * 1000))

    async def _playout(self) -> None:
        media = self.call.media
        while True:
            if len(self._queued) < self._frame_bytes:
                self._more.clear()
                await self._more.wait()
                continue
            delay = self._due + self._frame_seconds - self._ahead - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
                continue
            if self._queued_item != self._item:
                self._item = self._queued_item
                self._item_sent = 0
            frame = bytes(self._queued[: self._frame_bytes])
            del self._queued[: self._frame_bytes]
            try:
                media.send_audio(frame)
            except (RuntimeError, SipralError):
                return
            self._item_sent += len(frame)
            self._due = max(self._due, time.monotonic()) + self._frame_seconds

    async def _drain(self) -> None:
        """Play the agent's last words before hanging up."""
        if self._queued and len(self._queued) < self._frame_bytes:
            self._queued += bytes(self._frame_bytes - len(self._queued))
            self._more.set()
        while self._queued and not self._call_ended.is_set():
            await asyncio.sleep(self._frame_seconds)
        delay = self._due - time.monotonic()
        if delay > 0 and not self._call_ended.is_set():
            await asyncio.sleep(delay)

    # -- the call ----------------------------------------------------------

    async def _watch_call(self) -> None:
        call = self.call
        if call.ended:
            self._call_ended.set()
            return
        while True:
            event = await call.events.get()
            if event.kind == EventKind.CALL_ENDED or call.ended:
                self._call_ended.set()
                return

    def _hang_up(self) -> None:
        if self.call.ended:
            return
        try:
            self.call.hangup()
        except SipralError:
            pass

    def _emit(self, kind: AgentEventKind, **data: Any) -> None:
        self.events.put_nowait(AgentEvent(kind, data))


class _Replace(Exception):
    """The service announced the end of this connection."""
