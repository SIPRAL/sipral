# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The local agent's server on a call, with stand-ins for the listening,
thinking and speaking programs: no model, no Ollama, no whisper-server."""

from __future__ import annotations

import unittest

from sipral_agents import AgentEventKind, EnergyVad, LocalAgent, LocalAgentServer
from sipral_agents.local import RATE

from .harness import AgentCallTest, rms, tone, LOUD


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


if __name__ == "__main__":
    unittest.main()
