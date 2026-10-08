# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A voice agent that runs entirely on this machine: no key, no account,
no paid service.

:class:`LocalAgentServer` is a WebSocket server in this process that turns
the caller's audio into the agent's in three steps, each one a program
running locally:

- **Listening**: a whisper.cpp server (``whisper-server``, MIT), reached
  over its HTTP ``/inference`` endpoint (:class:`WhisperServer`).
- **Thinking**: Ollama (MIT) and a small model, over its HTTP chat API on
  ``127.0.0.1:11434`` (:class:`Ollama`); the reply is streamed and spoken a
  sentence at a time, so the caller hears the first sentence while the rest
  is still being written.
- **Speaking**: Kyutai's Pocket TTS (:class:`PocketVoice`, the
  package's ``local`` extra), loaded once and kept in this process,
  its audio streamed to the call as it is synthesised; or the operating
  system's own voice (:class:`SystemVoice`, ``say`` on macOS); or any
  program that reads text and writes a WAV file (:class:`CommandVoice`).
  :func:`local_voice` picks the first of the two that is there.

The caller's turn ends after ``end_silence_ms`` of quiet, measured on the
energy of each frame (:class:`EnergyVad`). Speech that starts while the
agent is talking cuts the agent short: its turn is cancelled and whatever
of it is still queued in the call is dropped.

:class:`LocalAgent` is the :class:`~sipral_agents.core.Provider` that joins
a call to the server, so the pacing, barge-in and events are those of every
other connector. Only :class:`PocketVoice` needs a Python package beyond
the ones ``sipral-agents`` already depends on, and imports it when it loads.
"""

from __future__ import annotations

import array
import asyncio
import base64
import concurrent.futures
import contextlib
import importlib.util
import json
import math
import operator
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
import wave
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from websockets.asyncio.client import ClientConnection
from websockets.asyncio.server import ServerConnection
from websockets.asyncio.server import serve as ws_serve
from websockets.exceptions import ConnectionClosed

from .core import Audio, Provider, ProviderError, Signal, SpeechStarted, Transcript, TurnComplete

__all__ = [
    "CommandVoice",
    "EnergyVad",
    "Listener",
    "LocalAgent",
    "LocalAgentServer",
    "Ollama",
    "PocketVoice",
    "Resampler",
    "Speaker",
    "SystemVoice",
    "Thinker",
    "WhisperServer",
    "local_voice",
]

RATE = 16000
_FRAME_BYTES = RATE // 50 * 2


class Listener(Protocol):
    async def transcribe(self, pcm: bytes) -> str:
        """The words in ``pcm``, 16-bit mono PCM at 16 kHz."""


class Thinker(Protocol):
    def reply(self, history: list[dict[str, str]]) -> AsyncIterator[str]:
        """The agent's answer to ``history`` (chat messages with ``role``
        and ``content``), in pieces as they are written."""


class Speaker(Protocol):
    """A voice. One that can also hand its audio over as it is made has a
    ``stream(text)`` method too, an async iterator of PCM pieces in the
    same format; :class:`LocalAgentServer` then sends each piece to the
    call as it comes instead of waiting for the sentence."""

    async def speak(self, text: str) -> bytes:
        """``text`` spoken, as 16-bit mono PCM at 16 kHz."""


# -- the three local programs ------------------------------------------------


def _wav(pcm: bytes) -> bytes:
    with tempfile.SpooledTemporaryFile() as out:
        with wave.open(out, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(RATE)
            w.writeframes(pcm)
        out.seek(0)
        return out.read()


def _pcm_of_wav(path: str) -> bytes:
    with wave.open(path, "rb") as w:
        if w.getnchannels() != 1 or w.getsampwidth() != 2 or w.getframerate() != RATE:
            raise ValueError(
                f"{path}: {w.getnchannels()} channel(s), {8 * w.getsampwidth()}-bit, "
                f"{w.getframerate()} Hz; the agent needs mono 16-bit at {RATE} Hz"
            )
        return w.readframes(w.getnframes())


@dataclass
class WhisperServer:
    """whisper.cpp's ``whisper-server``, started with a model:
    ``whisper-server -m ggml-base.en.bin --port 8178``."""

    url: str = "http://127.0.0.1:8178"
    timeout: float = 30.0

    async def transcribe(self, pcm: bytes) -> str:
        boundary = uuid.uuid4().hex
        body = b"".join(
            [
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"response_format\"\r\n\r\njson\r\n".encode(),
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"turn.wav\"\r\n"
                "Content-Type: audio/wav\r\n\r\n".encode(),
                _wav(pcm),
                f"\r\n--{boundary}--\r\n".encode(),
            ]
        )
        request = urllib.request.Request(
            f"{self.url}/inference",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )

        def post() -> str:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.load(response).get("text", "")

        return (await asyncio.to_thread(post)).strip()


@dataclass
class Ollama:
    """A model served by Ollama on this machine, through ``/api/chat`` with
    streaming on. ``system`` is the agent's instructions; ``keep_alive``
    how long Ollama keeps the model loaded after a reply, since loading it
    again takes seconds."""

    model: str = "qwen2.5:1.5b"
    system: str = "You answer the phone. Reply in one or two short spoken sentences, with no lists or markup."
    url: str = "http://127.0.0.1:11434"
    keep_alive: str = "30m"
    timeout: float = 120.0

    async def reply(self, history: list[dict[str, str]]) -> AsyncIterator[str]:
        body = json.dumps(
            {
                "model": self.model,
                "stream": True,
                "keep_alive": self.keep_alive,
                "messages": [{"role": "system", "content": self.system}, *history],
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.url}/api/chat", data=body, headers={"Content-Type": "application/json"}
        )
        loop = asyncio.get_running_loop()
        pieces: asyncio.Queue[str | BaseException | None] = asyncio.Queue()
        stop = False

        def read() -> None:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    for line in response:
                        if stop:
                            return
                        if not line.strip():
                            continue
                        chunk = json.loads(line)
                        if "error" in chunk:
                            raise RuntimeError(f"ollama: {chunk['error']}")
                        text = chunk.get("message", {}).get("content", "")
                        if text:
                            loop.call_soon_threadsafe(pieces.put_nowait, text)
                        if chunk.get("done"):
                            break
                loop.call_soon_threadsafe(pieces.put_nowait, None)
            except BaseException as failed:  # noqa: BLE001 -- handed to the event loop
                loop.call_soon_threadsafe(pieces.put_nowait, failed)

        loop.run_in_executor(None, read)
        try:
            while True:
                piece = await pieces.get()
                if piece is None:
                    break
                if isinstance(piece, BaseException):
                    raise piece
                yield piece
        finally:
            # the thread notices at its next line and closes the response
            stop = True


async def _run(argv: list[str], stdin: bytes | None = None) -> None:
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, err = await process.communicate(stdin)
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        raise
    if process.returncode != 0:
        raise RuntimeError(f"{argv[0]} exited with {process.returncode}: {err.decode(errors='replace').strip()}")


@dataclass
class CommandVoice:
    """Any text-to-speech program: ``argv`` is run once per sentence with
    the text on its standard input, and ``{out}`` in it is replaced by the
    path of the WAV file it must write, mono 16-bit at 16 kHz."""

    argv: list[str]

    async def speak(self, text: str) -> bytes:
        fd, path = tempfile.mkstemp(suffix=".wav")
        os.close(fd)
        try:
            await _run([arg.replace("{out}", path) for arg in self.argv], text.encode())
            return _pcm_of_wav(path)
        finally:
            os.unlink(path)


@dataclass
class SystemVoice:
    """macOS's own speech synthesis, ``say``; ``voice`` is one of
    ``say -v '?'``, the system's default when ``None``."""

    voice: str | None = None

    async def speak(self, text: str) -> bytes:
        argv = ["say", "-o", "{out}", "--data-format=LEI16@16000", "-f", "-"]
        if self.voice:
            argv[1:1] = ["-v", self.voice]
        return await CommandVoice(argv).speak(text)


class Resampler:
    """16-bit mono PCM from ``source`` Hz to ``target`` Hz, a piece at a
    time: a Blackman-windowed sinc low-pass at 90 % of the lower of the two
    Nyquist frequencies, ``zeros`` of its zero crossings on each side,
    applied one output sample at a time from the input it needs. Its delay
    is taken out, so the pieces :meth:`feed` returns, followed by what
    :meth:`flush` returns, are the whole input resampled at once:
    ``ceil(n * target / source)`` samples for ``n`` in."""

    def __init__(self, source: int, target: int, zeros: int = 8) -> None:
        common = math.gcd(source, target)
        self.up, self.down = target // common, source // common
        # in cycles per sample at source * up, the rate the filter runs at
        cutoff = 0.45 / max(self.up, self.down)
        self._half = math.ceil(zeros / (2 * cutoff))
        length = 2 * self._half + 1
        taps = []
        for n in range(length):
            x = 2 * cutoff * (n - self._half)
            sinc = 1.0 if x == 0 else math.sin(math.pi * x) / (math.pi * x)
            phase = 2 * math.pi * n / (length - 1)
            window = 0.42 - 0.5 * math.cos(phase) + 0.08 * math.cos(2 * phase)
            taps.append(self.up * 2 * cutoff * sinc * window)
        self._k = math.ceil(length / self.up)
        # phase p is every up-th tap from p, newest input last
        self._phases = [
            tuple(reversed(taps[p :: self.up] + [0.0] * (self._k - len(taps[p :: self.up])))) for p in range(self.up)
        ]
        self._x: list[int] = [0] * self._k
        self._base = -self._k  # the input index of self._x[0]
        self._made = 0
        self._seen = 0

    def feed(self, pcm: bytes) -> bytes:
        """What of the output ``pcm`` completes."""
        samples = array.array("h")
        samples.frombytes(pcm[: len(pcm) // 2 * 2])
        if sys.byteorder == "big":
            samples.byteswap()
        if self.up == self.down:
            return samples.tobytes() if sys.byteorder == "little" else pcm[: len(pcm) // 2 * 2]
        self._x.extend(samples)
        self._seen += len(samples)
        return self._produce(None)

    def flush(self) -> bytes:
        """The rest of the output, once the input has all been fed."""
        if self.up == self.down:
            return b""
        total = -(-self._seen * self.up // self.down)
        if total > self._made:
            needed = ((total - 1) * self.down + self._half) // self.up + 1
            self._x.extend([0] * max(0, needed - (self._base + len(self._x))))
        return self._produce(total)

    def _produce(self, limit: int | None) -> bytes:
        out = array.array("h")
        x, k, up, down, half, phases = self._x, self._k, self.up, self.down, self._half, self._phases
        end = self._base + len(x)
        made = self._made
        while limit is None or made < limit:
            t = made * down + half
            newest = t // up
            if newest >= end:
                break
            start = newest - k + 1 - self._base
            value = round(sum(map(operator.mul, phases[t % up], x[start : start + k])))
            out.append(32767 if value > 32767 else -32768 if value < -32768 else value)
            made += 1
        self._made = made
        drop = (made * down + half) // up - k + 1 - self._base
        if drop > 0:
            del x[:drop]
            self._base += drop
        if sys.byteorder == "big":
            out.byteswap()
        return out.tobytes()


class _PocketEngine:
    """Pocket TTS in this process: the model and the voice's state, loaded
    once; each sentence streamed in 16-bit pieces at the model's rate."""

    def __init__(self, voice: str | None, language: str | None) -> None:
        from pocket_tts import TTSModel

        if voice is None:
            from pocket_tts.default_parameters import get_default_voice_for_language

            voice = get_default_voice_for_language(language)
        self.voice = voice
        self._model = TTSModel.load_model(language=language)
        self.sample_rate: int = self._model.sample_rate
        self._state = self._model.get_state_for_audio_prompt(voice)

    def stream(self, text: str, stop: threading.Event) -> Iterator[bytes]:
        # the voice's state is copied for each sentence, so every one starts from it
        for chunk in self._model.generate_audio_stream(self._state, text, stop=stop):
            yield chunk.clamp(-1.0, 1.0).mul(32767.0).round().short().numpy().tobytes()


class PocketVoice:
    """Kyutai's Pocket TTS (code MIT, weights and voices CC BY 4.0), run in
    this process: the package's ``local`` extra. The weights and
    the voice are fetched from Hugging Face the first time and cached.

    ``language`` is one of its models -- ``"english"`` when ``None``,
    ``"french"``, ``"german"``, ``"spanish"``, ``"portuguese"``,
    ``"italian"``, ``"dutch"``, and a slower, better ``_24l`` variant of
    each but English -- and ``voice`` one of its catalogue's names or the
    path of a WAV file to clone, the model's own default for the language
    when ``None``.

    The model is loaded once, by :meth:`load` or the first sentence, and
    kept for the life of this object. A sentence is then streamed: each
    80 ms piece the model makes is resampled from 24 kHz to ``rate`` and
    handed over at once, so the call hears the start of a sentence while
    the rest is being made. The model is not safe to run twice at once, so
    sentences are made one at a time, on one thread, whichever call they
    are for. ``engine``, when given, is called instead of loading the model
    (for tests): it returns an object with ``sample_rate`` and
    ``stream(text, stop)``, an iterator of 16-bit pieces at that rate that
    ends early once the :class:`threading.Event` ``stop`` is set."""

    def __init__(
        self,
        voice: str | None = None,
        language: str | None = None,
        *,
        rate: int = RATE,
        engine: Callable[[], object] | None = None,
    ) -> None:
        self.voice = voice
        self.language = language
        self.rate = rate
        self._make = engine or (lambda: _PocketEngine(voice, language))
        self._engine = None
        self._loading = asyncio.Lock()
        self._worker = concurrent.futures.ThreadPoolExecutor(1, thread_name_prefix="pocket-tts")

    async def load(self) -> None:
        """Load the model now rather than on the first sentence."""
        await self._loaded()

    async def _loaded(self):
        async with self._loading:
            if self._engine is None:
                self._engine = await asyncio.get_running_loop().run_in_executor(self._worker, self._make)
        return self._engine

    async def stream(self, text: str) -> AsyncIterator[bytes]:
        """``text`` spoken, 16-bit mono PCM at ``rate``, in pieces as they
        are made. Closing the iterator early stops the model."""
        engine = await self._loaded()
        loop = asyncio.get_running_loop()
        pieces: asyncio.Queue[bytes | BaseException | None] = asyncio.Queue()
        stop = threading.Event()
        resampler = Resampler(engine.sample_rate, self.rate)

        def put(item: bytes | BaseException | None) -> None:
            with contextlib.suppress(RuntimeError):  # the loop has closed
                loop.call_soon_threadsafe(pieces.put_nowait, item)

        def make() -> None:
            try:
                for pcm in engine.stream(text, stop):
                    if stop.is_set():
                        return
                    out = resampler.feed(pcm)
                    if out:
                        put(out)
                if not stop.is_set():
                    put(resampler.flush())
                put(None)
            except BaseException as failed:  # noqa: BLE001 -- handed to the event loop
                put(failed)

        loop.run_in_executor(self._worker, make)
        try:
            while True:
                piece = await pieces.get()
                if piece is None:
                    return
                if isinstance(piece, BaseException):
                    raise piece
                if piece:
                    yield piece
        finally:
            stop.set()

    async def speak(self, text: str) -> bytes:
        return b"".join([piece async for piece in self.stream(text)])

    def close(self) -> None:
        """Let the model's thread go; the object is not used again."""
        self._worker.shutdown(wait=False, cancel_futures=True)


POCKET_INSTALL = (
    "pip install './integrations/agents[local]' from Sipral's checkout, or pip install 'pocket-tts>=3.3' "
    "(on Linux add --extra-index-url https://download.pytorch.org/whl/cpu, or pip pulls PyTorch's CUDA build)"
)


def local_voice(
    voice: str | None = None,
    language: str | None = None,
    *,
    rate: int = RATE,
    warn: Callable[[str], None] | None = None,
) -> Speaker:
    """The best voice this machine has: :class:`PocketVoice` when Pocket
    TTS is installed; on macOS without it, ``say`` (:class:`SystemVoice`,
    in the system's default voice, since ``voice`` and ``language`` name
    Pocket's), after one line to ``warn`` (standard error when ``None``)
    saying so; anywhere else, :class:`RuntimeError` naming what to
    install."""
    if importlib.util.find_spec("pocket_tts") is not None:
        return PocketVoice(voice, language, rate=rate)
    if sys.platform == "darwin" and shutil.which("say"):
        line = f"Pocket TTS is not installed, so the agent speaks with macOS's say; for a better voice: {POCKET_INSTALL}"
        (warn or (lambda text: print(text, file=sys.stderr, flush=True)))(line)
        return SystemVoice()
    raise RuntimeError(f"no local voice: Pocket TTS is not installed. {POCKET_INSTALL}")


# -- the end of a turn -------------------------------------------------------


@dataclass
class EnergyVad:
    """Speech is ``start_ms`` of frames louder than ``threshold`` (RMS of
    16-bit samples); the turn ends after ``end_silence_ms`` of frames that
    are not."""

    threshold: float = 500.0
    start_ms: int = 60
    end_silence_ms: int = 700
    speaking: bool = False
    _loud_ms: float = 0.0
    _quiet_ms: float = 0.0

    @staticmethod
    def rms(pcm: bytes) -> float:
        count = len(pcm) // 2
        if not count:
            return 0.0
        samples = memoryview(pcm[: count * 2]).cast("h")
        return math.sqrt(sum(s * s for s in samples) / count)

    def feed(self, pcm: bytes) -> str | None:
        """``"start"`` when speech starts, ``"end"`` when the turn ends,
        ``None`` otherwise."""
        ms = len(pcm) / 2 / RATE * 1000
        loud = self.rms(pcm) > self.threshold
        if not self.speaking:
            self._loud_ms = self._loud_ms + ms if loud else 0.0
            if self._loud_ms >= self.start_ms:
                self.speaking = True
                self._quiet_ms = 0.0
                return "start"
            return None
        self._quiet_ms = 0.0 if loud else self._quiet_ms + ms
        if self._quiet_ms >= self.end_silence_ms:
            self.speaking = False
            self._loud_ms = 0.0
            return "end"
        return None


# -- the server --------------------------------------------------------------

_SENTENCE_END = re.compile(r"(?<=[.!?;:])\s+")


@dataclass
class _Session:
    ws: ServerConnection
    vad: EnergyVad
    history: list[dict[str, str]] = field(default_factory=list)
    utterance: bytearray = field(default_factory=bytearray)
    preroll: list[bytes] = field(default_factory=list)
    turn: asyncio.Task | None = None
    turns: int = 0


class LocalAgentServer:
    """The local pipeline behind a WebSocket on ``127.0.0.1``: one session
    per connection, so per call. ``greeting``, when set, is spoken as soon
    as a call is joined. ``on_timing``, when set, is called with the
    seconds from the end of the caller's turn to the transcript, to the
    first piece of the reply and to the first audio of it."""

    def __init__(
        self,
        listener: Listener,
        thinker: Thinker,
        speaker: Speaker,
        *,
        greeting: str | None = None,
        vad: Callable[[], EnergyVad] = EnergyVad,
        on_timing: Callable[[dict[str, float]], None] | None = None,
    ) -> None:
        self.listener = listener
        self.thinker = thinker
        self.speaker = speaker
        self.greeting = greeting
        self.vad = vad
        self.on_timing = on_timing
        self.server = None
        self._greeting_pcm: bytes | None = None

    async def start(self) -> str:
        self.server = await ws_serve(self._handler, "127.0.0.1", 0, max_size=None)
        if self.greeting:
            self._greeting_pcm = await self.speaker.speak(self.greeting)
        return f"ws://127.0.0.1:{self.server.sockets[0].getsockname()[1]}/local"

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handler(self, ws: ServerConnection) -> None:
        session = _Session(ws, self.vad())
        try:
            async for message in ws:
                if isinstance(message, str):
                    if json.loads(message).get("type") == "hello":
                        await ws.send(json.dumps({"type": "ready"}))
                        if self.greeting:
                            self._begin(session, self._speak_greeting(session))
                    continue
                await self._hear(session, message)
        except ConnectionClosed:
            pass
        finally:
            if session.turn is not None:
                session.turn.cancel()
                await asyncio.gather(session.turn, return_exceptions=True)

    async def _hear(self, session: _Session, pcm: bytes) -> None:
        change = session.vad.feed(pcm)
        if session.vad.speaking or change == "end":
            session.utterance += pcm
        else:
            # what came just before the start of speech holds its first syllable
            session.preroll = (session.preroll + [pcm])[-10:]
        if change == "start":
            session.utterance = bytearray(b"".join(session.preroll)) + session.utterance
            session.preroll = []
            if session.turn is not None and not session.turn.done():
                session.turn.cancel()
                await asyncio.gather(session.turn, return_exceptions=True)
            # the reply may be written already and still be playing in the call
            await session.ws.send(json.dumps({"type": "speech_started"}))
        elif change == "end":
            utterance = bytes(session.utterance)
            session.utterance = bytearray()
            self._begin(session, self._answer(session, utterance, time.monotonic()))

    def _begin(self, session: _Session, work: Awaitable[None]) -> None:
        session.turns += 1
        session.turn = asyncio.ensure_future(work)

    async def _send_audio(self, session: _Session, pcm: bytes) -> None:
        # whole 20 ms frames: a remainder would wait in the call's queue for
        # more and count as still playing when the caller next speaks
        pcm += bytes(-len(pcm) % _FRAME_BYTES)
        await session.ws.send(
            json.dumps({"type": "audio", "turn": session.turns, "pcm": base64.b64encode(pcm).decode()})
        )

    async def _speak_greeting(self, session: _Session) -> None:
        try:
            if self._greeting_pcm is None:
                # the same words on every call: synthesised once
                self._greeting_pcm = await self.speaker.speak(self.greeting)
        except Exception as failed:  # noqa: BLE001 -- reported to the call, which goes on
            await session.ws.send(json.dumps({"type": "error", "message": f"greeting: {failed}"}))
            return
        await self._send_audio(session, self._greeting_pcm)
        session.history.append({"role": "assistant", "content": self.greeting})
        await session.ws.send(json.dumps({"type": "transcript", "role": "agent", "text": self.greeting}))
        await session.ws.send(json.dumps({"type": "turn_complete"}))

    async def _answer(self, session: _Session, utterance: bytes, ended: float) -> None:
        ws = session.ws
        timing: dict[str, float] = {}
        said: list[str] = []
        try:
            text = await self.listener.transcribe(utterance)
            timing["transcript"] = time.monotonic() - ended
            if not text:
                return
            await ws.send(json.dumps({"type": "transcript", "role": "user", "text": text}))
            session.history.append({"role": "user", "content": text})
            pending = ""
            async for piece in self.thinker.reply(session.history):
                timing.setdefault("first_words", time.monotonic() - ended)
                pending += piece
                *sentences, pending = _SENTENCE_END.split(pending)
                for sentence in sentences:
                    await self._say(session, sentence, said, timing, ended)
            await self._say(session, pending, said, timing, ended)
        except asyncio.CancelledError:
            if said:
                session.history.append({"role": "assistant", "content": " ".join(said)})
            raise
        except Exception as failed:  # noqa: BLE001 -- reported to the call, which goes on
            await ws.send(json.dumps({"type": "error", "message": f"{type(failed).__name__}: {failed}"}))
            return
        if said:
            reply = " ".join(said)
            session.history.append({"role": "assistant", "content": reply})
            await ws.send(json.dumps({"type": "transcript", "role": "agent", "text": reply}))
        await ws.send(json.dumps({"type": "turn_complete"}))
        if self.on_timing is not None:
            self.on_timing(timing)

    async def _say(
        self, session: _Session, sentence: str, said: list[str], timing: dict[str, float], ended: float
    ) -> None:
        sentence = sentence.strip()
        if not sentence:
            return
        stream = getattr(self.speaker, "stream", None)
        if stream is None:
            pcm = await self.speaker.speak(sentence)
            timing.setdefault("first_audio", time.monotonic() - ended)
            await self._send_audio(session, pcm)
            said.append(sentence)
            return
        # each piece goes out as it comes, in whole frames; only the
        # sentence's last one is padded
        pending = b""
        heard = False
        async with contextlib.aclosing(stream(sentence)) as pieces:
            async for piece in pieces:
                if not heard:
                    timing.setdefault("first_audio", time.monotonic() - ended)
                    # the caller is hearing it from now on
                    said.append(sentence)
                    heard = True
                pending += piece
                whole = len(pending) - len(pending) % _FRAME_BYTES
                if whole:
                    await self._send_audio(session, pending[:whole])
                    pending = pending[whole:]
        if pending:
            await self._send_audio(session, pending)


class LocalAgent(Provider):
    """A call joined to a :class:`LocalAgentServer` at ``url``."""

    name = "local"
    sample_rate = RATE

    def __init__(self, url: str) -> None:
        self._url = url

    def url(self) -> str:
        return self._url

    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        await ws.send(json.dumps({"type": "hello"}))
        async for message in ws:
            if isinstance(message, str) and json.loads(message).get("type") == "ready":
                return False
        raise ConnectionClosed(ws.close_rcvd, ws.close_sent)

    def audio_message(self, pcm: bytes) -> bytes:
        return pcm

    def parse(self, message: str | bytes) -> list[Signal]:
        event = json.loads(message)
        kind = event.get("type")
        if kind == "audio":
            return [Audio(base64.b64decode(event["pcm"]), item=f"turn-{event['turn']}")]
        if kind == "speech_started":
            return [SpeechStarted()]
        if kind == "transcript":
            return [Transcript(event["role"], event["text"])]
        if kind == "turn_complete":
            return [TurnComplete()]
        if kind == "error":
            return [ProviderError(event["message"])]
        return []
