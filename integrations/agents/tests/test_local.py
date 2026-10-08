# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The local agent's server on a call, with stand-ins for the listening,
thinking and speaking programs: no model, no Ollama, no whisper-server."""

from __future__ import annotations

import array
import asyncio
import math
import threading
import unittest
from unittest import mock

from sipral_agents import (
    AgentEventKind,
    EnergyVad,
    LocalAgent,
    LocalAgentServer,
    PocketVoice,
    Resampler,
    SystemVoice,
    local_voice,
)
from sipral_agents.local import RATE

from .harness import AgentCallTest, rms, tone, LOUD

POCKET_RATE = 24000
# what Pocket TTS hands over at a time: 80 ms at 24 kHz
POCKET_PIECE = 1920 * 2


class Listener:
    def __init__(self) -> None:
        self.heard: list[bytes] = []

    async def transcribe(self, pcm: bytes) -> str:
        self.heard.append(pcm)
        return "is anyone there" if rms(pcm) > LOUD else ""


class Thinker:
    def __init__(self) -> None:
        self.histories: list[list[dict[str, str]]] = []

    async def reply(self, history):
        self.histories.append(list(history))
        for piece in ["Yes", ", I am", " here.", " How can", " I help?"]:
            yield piece


class Speaker:
    """Each sentence as a tone a tenth of a second per character long."""

    def __init__(self) -> None:
        self.sentences: list[str] = []

    async def speak(self, text: str) -> bytes:
        self.sentences.append(text)
        return tone(RATE, len(text) / 10)


class FakePocket:
    """Stands in for the loaded model: each sentence is a tone a tenth of
    a second per character long at 24 kHz, in Pocket's 80 ms pieces."""

    sample_rate = POCKET_RATE

    def __init__(self) -> None:
        self.sentences: list[str] = []
        self.stops: list[threading.Event] = []
        self.pieces_made = 0

    def stream(self, text: str, stop: threading.Event):
        self.sentences.append(text)
        self.stops.append(stop)
        pcm = tone(POCKET_RATE, len(text) / 10)
        for at in range(0, len(pcm), POCKET_PIECE):
            if stop.is_set():
                return
            self.pieces_made += 1
            yield pcm[at : at + POCKET_PIECE]


class Loads:
    """An engine factory that counts how often it is called."""

    def __init__(self) -> None:
        self.engines: list[FakePocket] = []

    def __call__(self) -> FakePocket:
        self.engines.append(FakePocket())
        return self.engines[-1]


def samples(pcm: bytes) -> array.array:
    return array.array("h", pcm)


class ResamplerTest(unittest.TestCase):
    def test_pieces_of_any_size_give_what_the_whole_gives(self) -> None:
        source = tone(POCKET_RATE, 0.5)
        whole = Resampler(POCKET_RATE, RATE)
        at_once = whole.feed(source) + whole.flush()
        for size in (2, 6, 482, POCKET_PIECE, 9998):
            pieces = Resampler(POCKET_RATE, RATE)
            out = b"".join(pieces.feed(source[at : at + size]) for at in range(0, len(source), size))
            self.assertEqual(out + pieces.flush(), at_once, size)

    def test_24_to_16_khz_keeps_the_tone_and_the_length(self) -> None:
        resampler = Resampler(POCKET_RATE, RATE)
        out = samples(resampler.feed(tone(POCKET_RATE, 1.0)) + resampler.flush())
        self.assertEqual(len(out), RATE)
        expected = samples(tone(RATE, 1.0))
        # no delay and no change of level: within a few steps of the
        # ideal tone, away from the two ends
        self.assertLessEqual(max(abs(a - b) for a, b in zip(out[64:-64], expected[64:-64])), 4)

    def test_what_the_lower_rate_cannot_carry_is_filtered_out(self) -> None:
        # 6 kHz is above the 4 kHz an 8 kHz call carries: folded back in, it
        # would be a 2 kHz whistle
        loud = [int(8000 * math.sin(2 * math.pi * 6000 * n / POCKET_RATE)) for n in range(POCKET_RATE)]
        resampler = Resampler(POCKET_RATE, 8000)
        out = resampler.feed(array.array("h", loud).tobytes()) + resampler.flush()
        self.assertEqual(len(out), 2 * 8000)
        self.assertLess(rms(out[256:-256]), 8)

    def test_the_same_rate_is_passed_through(self) -> None:
        pcm = tone(RATE, 0.1)
        resampler = Resampler(RATE, RATE)
        self.assertEqual(resampler.feed(pcm) + resampler.flush(), pcm)


class PocketVoiceTest(unittest.IsolatedAsyncioTestCase):
    async def test_the_model_is_loaded_once_for_every_sentence_and_call(self) -> None:
        loads = Loads()
        voice = PocketVoice(engine=loads)
        self.addCleanup(voice.close)
        await voice.load()
        # two calls speaking at once, and one more sentence after
        await asyncio.gather(voice.speak("Hello there."), voice.speak("How can I help?"))
        await voice.speak("Goodbye.")
        await voice.load()
        self.assertEqual(len(loads.engines), 1)
        self.assertEqual(sorted(loads.engines[0].sentences), ["Goodbye.", "Hello there.", "How can I help?"])

    async def test_loading_on_the_first_sentence_is_once_too(self) -> None:
        loads = Loads()
        voice = PocketVoice(engine=loads)
        self.addCleanup(voice.close)
        await asyncio.gather(*(voice.speak("Hi.") for _ in range(3)))
        self.assertEqual(len(loads.engines), 1)

    async def test_a_sentence_streams_resampled_to_the_call_rate(self) -> None:
        voice = PocketVoice(engine=Loads())
        self.addCleanup(voice.close)
        pieces = [piece async for piece in voice.stream("One two three four.")]
        # 1.9 s of audio at 24 kHz came in 24 pieces of 80 ms; each goes on
        # as it comes, and the tail of the filter after the last
        self.assertGreaterEqual(len(pieces), 24)
        whole = Resampler(POCKET_RATE, RATE)
        source = tone(POCKET_RATE, 1.9)
        self.assertEqual(b"".join(pieces), whole.feed(source) + whole.flush())
        self.assertEqual(len(b"".join(pieces)), 2 * int(1.9 * RATE))

    async def test_the_rate_is_the_one_asked_for(self) -> None:
        voice = PocketVoice(engine=Loads(), rate=8000)
        self.addCleanup(voice.close)
        self.assertEqual(len(await voice.speak("Twelve chars")), 2 * int(1.2 * 8000))

    async def test_closing_the_stream_early_stops_the_model(self) -> None:
        loads = Loads()
        voice = PocketVoice(engine=loads)
        self.addCleanup(voice.close)
        text = "A long sentence that would take six seconds to say, at the least."
        stream = voice.stream(text)
        await anext(stream)
        await stream.aclose()
        engine = loads.engines[0]
        self.assertTrue(engine.stops[0].is_set())
        # the next sentence waits for the first to stop, and the rest of the first is never made
        await voice.speak("Next.")
        whole = math.ceil(len(text) / 10 * POCKET_RATE * 2 / POCKET_PIECE)
        next_one = math.ceil(len("Next.") / 10 * POCKET_RATE * 2 / POCKET_PIECE)
        self.assertLess(engine.pieces_made, whole // 2 + next_one)

    async def test_a_failing_model_is_an_error_of_the_sentence(self) -> None:
        def broken():
            raise RuntimeError("no weights")

        voice = PocketVoice(engine=broken)
        self.addCleanup(voice.close)
        with self.assertRaisesRegex(RuntimeError, "no weights"):
            await voice.speak("Hello.")


class LocalVoiceTest(unittest.TestCase):
    def pick(self, installed: bool, platform: str, say: str | None):
        warned: list[str] = []
        spec = object() if installed else None
        with (
            mock.patch("importlib.util.find_spec", lambda name: spec if name == "pocket_tts" else None),
            mock.patch("sys.platform", platform),
            mock.patch("shutil.which", lambda name: say if name == "say" else None),
        ):
            voice = local_voice("alba", "english", warn=warned.append)
        return voice, warned

    def test_pocket_when_it_is_installed(self) -> None:
        for platform in ("darwin", "linux"):
            voice, warned = self.pick(True, platform, "/usr/bin/say")
            self.addCleanup(voice.close)
            self.assertIsInstance(voice, PocketVoice)
            self.assertEqual((voice.voice, voice.language, voice.rate), ("alba", "english", RATE))
            self.assertEqual(warned, [])

    def test_say_on_a_mac_without_it_with_one_line_saying_so(self) -> None:
        voice, warned = self.pick(False, "darwin", "/usr/bin/say")
        self.assertIsInstance(voice, SystemVoice)
        self.assertIsNone(voice.voice)
        self.assertEqual(len(warned), 1)
        self.assertIn("Pocket TTS is not installed", warned[0])
        self.assertIn("[local]", warned[0])

    def test_elsewhere_without_it_an_error_says_how_to_install_it(self) -> None:
        for platform, say in (("linux", None), ("win32", None), ("darwin", None)):
            with self.assertRaisesRegex(RuntimeError, r"pip install .*download\.pytorch\.org/whl/cpu"):
                self.pick(False, platform, say)


class EnergyVadTest(unittest.TestCase):
    def test_a_turn_starts_on_speech_and_ends_on_silence(self) -> None:
        vad = EnergyVad(start_ms=60, end_silence_ms=200)
        loud, quiet = tone(RATE, 0.02), bytes(640)
        self.assertEqual([vad.feed(quiet) for _ in range(5)], [None] * 5)
        self.assertEqual([vad.feed(loud) for _ in range(3)], [None, None, "start"])
        # a pause shorter than the end of a turn is part of it
        self.assertEqual([vad.feed(quiet) for _ in range(5)], [None] * 5)
        vad.feed(loud)
        self.assertEqual([vad.feed(quiet) for _ in range(10)], [None] * 9 + ["end"])
        self.assertFalse(vad.speaking)

    def test_a_click_is_not_speech(self) -> None:
        vad = EnergyVad(start_ms=60)
        self.assertEqual([vad.feed(f) for f in (tone(RATE, 0.02), bytes(640)) * 5], [None] * 10)


class LocalAgentOnACall(AgentCallTest):
    def setUp(self) -> None:
        self.listener, self.thinker, self.speaker = Listener(), Thinker(), Speaker()
        self.service = LocalAgentServer(
            self.listener,
            self.thinker,
            self.speaker,
            vad=lambda: EnergyVad(end_silence_ms=300),
        )

    def provider(self, url: str) -> LocalAgent:
        return LocalAgent(url)

    async def say(self, call, seconds: float) -> None:
        """``seconds`` of tone, then silence for the agent to hear the end."""
        rate = call.media.sample_rate
        call.media.send_audio(tone(rate, seconds) + bytes(2 * rate))

    async def transcript(self, agent, role: str) -> str:
        while True:
            event = await self.event(agent, AgentEventKind.TRANSCRIPT)
            if event.data["role"] == role:
                return event.data["text"]

    async def test_a_question_is_answered_a_sentence_at_a_time(self) -> None:
        call, agent = await self.dial()
        self.drain(call)
        await self.say(call, 0.5)
        self.assertEqual(await self.transcript(agent, "user"), "is anyone there")
        heard = await self.hear(call, loud=50)
        self.assertGreaterEqual(sum(rms(pcm) > LOUD for pcm in heard), 50)
        self.assertEqual(await self.transcript(agent, "agent"), "Yes, I am here. How can I help?")
        await self.event(agent, AgentEventKind.TURN_COMPLETE)
        self.assertEqual(self.speaker.sentences, ["Yes, I am here.", "How can I help?"])
        self.assertEqual(self.thinker.histories, [[{"role": "user", "content": "is anyone there"}]])

    async def test_speaking_over_the_agent_cuts_it_short(self) -> None:
        call, agent = await self.dial()
        self.drain(call)
        await self.say(call, 0.5)
        await self.hear(call, loud=10)
        # the answer is three seconds of tone; the caller talks over it
        await self.say(call, 0.5)
        interrupted = await self.event(agent, AgentEventKind.INTERRUPTED)
        self.assertLess(interrupted.data["heard_ms"], 3000)
        # the words that cut it short are the next question
        self.assertEqual(await self.transcript(agent, "user"), "is anyone there")
        self.assertEqual(len(self.listener.heard), 2)

    async def test_the_greeting_is_spoken_once_the_call_is_joined(self) -> None:
        self.service.greeting = "Hello."
        call, agent = await self.dial()
        self.assertEqual(await self.transcript(agent, "agent"), "Hello.")
        heard = await self.hear(call, loud=10)
        self.assertGreaterEqual(sum(rms(pcm) > LOUD for pcm in heard), 10)


class StreamingVoiceOnACall(AgentCallTest):
    """The same pipeline with a :class:`PocketVoice` over a stand-in model:
    its pieces reach the caller, and the model is loaded once."""

    def setUp(self) -> None:
        self.loads = Loads()
        self.voice = PocketVoice(engine=self.loads)
        self.addCleanup(self.voice.close)
        self.service = LocalAgentServer(
            Listener(), Thinker(), self.voice, greeting="Hello.", vad=lambda: EnergyVad(end_silence_ms=300)
        )

    provider = LocalAgentOnACall.provider
    say = LocalAgentOnACall.say
    transcript = LocalAgentOnACall.transcript

    async def test_streamed_sentences_are_heard_and_the_model_loads_once(self) -> None:
        call, agent = await self.dial()
        self.assertEqual(await self.transcript(agent, "agent"), "Hello.")
        self.drain(call)
        await self.say(call, 0.5)
        self.assertEqual(await self.transcript(agent, "user"), "is anyone there")
        heard = await self.hear(call, loud=50)
        self.assertGreaterEqual(sum(rms(pcm) > LOUD for pcm in heard), 50)
        self.assertEqual(await self.transcript(agent, "agent"), "Yes, I am here. How can I help?")
        await self.event(agent, AgentEventKind.TURN_COMPLETE)
        self.assertEqual(len(self.loads.engines), 1)
        self.assertEqual(self.loads.engines[0].sentences, ["Hello.", "Yes, I am here.", "How can I help?"])


if __name__ == "__main__":
    unittest.main()
