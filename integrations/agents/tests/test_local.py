# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The local agent's server on a call, with stand-ins for the listening,
thinking and speaking programs: no model, no Ollama, no whisper-server."""

from __future__ import annotations

import array
import asyncio
import json
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
from sipral_agents.local import RATE, _pieces, _Session

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

    def test_a_pause_is_reported_once_and_speech_after_it_resumes_the_turn(self) -> None:
        vad = EnergyVad(start_ms=60, pause_ms=100, end_silence_ms=300)
        loud, quiet = tone(RATE, 0.02), bytes(640)
        self.assertEqual([vad.feed(loud) for _ in range(3)], [None, None, "start"])
        self.assertEqual([vad.feed(quiet) for _ in range(7)], [None] * 4 + ["pause", None, None])
        self.assertEqual(vad.quiet_ms, 140)
        self.assertEqual([vad.feed(loud) for _ in range(2)], ["resume", None])
        self.assertTrue(vad.speaking)
        self.assertEqual([vad.feed(quiet) for _ in range(15)], [None] * 4 + ["pause"] + [None] * 9 + ["end"])

    def test_without_pauses_only_the_end_is_reported(self) -> None:
        vad = EnergyVad(start_ms=20, pause_ms=None, end_silence_ms=100)
        self.assertEqual(vad.feed(tone(RATE, 0.02)), "start")
        self.assertEqual([vad.feed(bytes(640)) for _ in range(5)], [None] * 4 + ["end"])


class FirstClauseTest(unittest.TestCase):
    def test_the_first_piece_ends_at_a_clause_of_enough_words(self) -> None:
        self.assertEqual(
            _pieces("My opening hours vary, but I am usually", 3),
            (["My opening hours vary,"], "but I am usually"),
        )
        self.assertEqual(_pieces("To reset your password: open", 3), (["To reset your password:"], "open"))

    def test_a_short_clause_waits_for_more(self) -> None:
        self.assertEqual(_pieces("Yes, we are open", 3), ([], "Yes, we are open"))
        self.assertEqual(
            _pieces("Yes, we are open on Saturday, from nine", 3),
            (["Yes, we are open on Saturday,"], "from nine"),
        )

    def test_a_comma_not_yet_followed_by_a_word_is_not_an_end(self) -> None:
        # the next piece of the reply may still be "000 people"
        self.assertEqual(_pieces("We seat up to 9,", 3), ([], "We seat up to 9,"))
        self.assertEqual(_pieces("We seat up to 9,000 people", 3), ([], "We seat up to 9,000 people"))

    def test_a_sentence_ends_a_piece_however_short(self) -> None:
        self.assertEqual(_pieces("Sure. We open at nine, and close", 3), (["Sure."], "We open at nine, and close"))

    def test_later_pieces_are_whole_sentences(self) -> None:
        self.assertEqual(
            _pieces("We open at nine, and close at five. Book", None),
            (["We open at nine, and close at five."], "Book"),
        )


class Ws:
    """Stands in for the call's WebSocket: what the server sends to it."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def kinds(self) -> list[str]:
        return [m["type"] for m in self.sent]


class SlowThinker:
    """Writes its reply once ``go`` is set, and notes whether its reply was
    closed before the end."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.go = asyncio.Event()
        self.closed_early = 0
        self.histories: list[list[dict[str, str]]] = []

    async def reply(self, history):
        self.histories.append(list(history))
        self.started.set()
        finished = False
        try:
            await self.go.wait()
            for piece in ["Yes", ", I am", " here."]:
                yield piece
            finished = True
        finally:
            self.closed_early += not finished


class EarlyAnswerTest(unittest.IsolatedAsyncioTestCase):
    """The answer started at a pause, driven frame by frame: what reaches
    the call, and when."""

    def server(self, thinker, **vad) -> tuple[LocalAgentServer, _Session, Speaker]:
        speaker = Speaker()
        service = LocalAgentServer(Listener(), thinker, speaker, vad=lambda: EnergyVad(**vad))
        return service, _Session(Ws(), service.vad()), speaker

    async def feed(self, service, session, seconds: float, loud: bool) -> None:
        frame = tone(RATE, 0.02) if loud else bytes(640)
        for _ in range(round(seconds / 0.02)):
            await service._hear(session, frame)
            await asyncio.sleep(0)

    async def settle(self) -> None:
        for _ in range(20):
            await asyncio.sleep(0)

    async def test_nothing_reaches_the_call_before_the_turn_ends(self) -> None:
        thinker = SlowThinker()
        thinker.go.set()
        service, session, speaker = self.server(thinker, pause_ms=200, end_silence_ms=600)
        await self.feed(service, session, 0.5, loud=True)
        await self.feed(service, session, 0.3, loud=False)
        await self.settle()
        # the answer is written and spoken already ...
        self.assertEqual(speaker.sentences, ["Yes, I am here."])
        # ... and none of it, not even the question's words, has gone out
        self.assertEqual(session.ws.kinds(), ["speech_started"])
        self.assertEqual(session.history, [])
        await self.feed(service, session, 0.3, loud=False)
        await asyncio.wait_for(session.turn, 5)
        self.assertEqual(
            session.ws.kinds(), ["speech_started", "transcript", "audio", "transcript", "turn_complete"]
        )
        self.assertEqual(session.ws.sent[1], {"type": "transcript", "role": "user", "text": "is anyone there"})
        self.assertEqual([m["role"] for m in session.history], ["user", "assistant"])

    async def test_speech_after_the_pause_cancels_the_early_answer(self) -> None:
        thinker = SlowThinker()
        service, session, speaker = self.server(thinker, pause_ms=200, end_silence_ms=600)
        await self.feed(service, session, 0.5, loud=True)
        await self.feed(service, session, 0.25, loud=False)
        await asyncio.wait_for(thinker.started.wait(), 5)
        early = session.turn
        await self.feed(service, session, 0.04, loud=True)
        self.assertTrue(early.cancelled())
        self.assertEqual(thinker.closed_early, 1)
        self.assertEqual(speaker.sentences, [])
        self.assertEqual(session.ws.kinds(), ["speech_started"])
        # the caller goes on, then stops: one answer, to the whole of it
        thinker.go.set()
        await self.feed(service, session, 0.5, loud=True)
        await self.feed(service, session, 0.7, loud=False)
        await asyncio.wait_for(session.turn, 5)
        self.assertEqual(session.ws.kinds().count("transcript"), 2)
        self.assertEqual(session.ws.kinds().count("turn_complete"), 1)
        heard = service.listener.heard
        self.assertGreater(len(heard[-1]), len(heard[0]))
        self.assertEqual(thinker.histories[-1], [{"role": "user", "content": "is anyone there"}])
        self.assertEqual(session.history[0], {"role": "user", "content": "is anyone there"})
        self.assertEqual(len(session.history), 2)

    async def test_a_pause_mid_sentence_gets_no_reply_with_the_defaults(self) -> None:
        thinker = SlowThinker()
        thinker.go.set()
        service, session, _ = self.server(thinker)
        for pause in (0.3, 0.4):
            await self.feed(service, session, 0.5, loud=True)
            await self.feed(service, session, pause, loud=False)
            await self.settle()
            self.assertNotIn("audio", session.ws.kinds(), f"a reply after a pause of {pause} s")
            self.assertNotIn("transcript", session.ws.kinds())
        await self.feed(service, session, 0.5, loud=True)
        await self.feed(service, session, 1.0, loud=False)
        await asyncio.wait_for(session.turn, 5)
        self.assertEqual(session.ws.kinds().count("turn_complete"), 1)
        self.assertEqual([m["role"] for m in session.history], ["user", "assistant"])

    async def test_without_pauses_the_answer_starts_at_the_end_of_the_turn(self) -> None:
        thinker = SlowThinker()
        thinker.go.set()
        service, session, _ = self.server(thinker, pause_ms=None, end_silence_ms=300)
        await self.feed(service, session, 0.5, loud=True)
        await self.feed(service, session, 0.28, loud=False)
        await self.settle()
        self.assertEqual(service.listener.heard, [])
        await self.feed(service, session, 0.02, loud=False)
        await asyncio.wait_for(session.turn, 5)
        self.assertEqual(session.ws.kinds()[-1], "turn_complete")
        self.assertIn("audio", session.ws.kinds())


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
