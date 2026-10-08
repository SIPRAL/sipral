#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A phone agent that runs entirely on this machine, with no key and no
paid service: whisper.cpp listens, Ollama thinks, Pocket TTS speaks.

    brew install whisper-cpp ollama
    curl -LO https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin
    whisper-server -m ggml-base.en.bin --port 8178 &
    ollama serve &
    ollama pull qwen2.5:1.5b
    pip install './integrations/agents[local]'
    python3 local_agent.py --port 5070

Pocket TTS (Kyutai; code MIT, weights and voices CC BY 4.0) is loaded
once, before the agent takes calls, and streams each sentence into the
call as it is made. Without it the agent speaks with macOS's ``say``, and
says so; ``--tts say`` asks for ``say``, ``--language`` and ``--voice``
pick Pocket's model and voice.

A softphone then calls ``sip:agent@<the address printed>``. With
``SIPRAL_REGISTRAR_ADDRESS`` set the agent answers what that PBX sends it,
registering with ``SIPRAL_AOR``, ``SIPRAL_REGISTRAR``, ``SIPRAL_AUTH_USER``
and ``SIPRAL_AUTH_PASSWORD`` when ``SIPRAL_REGISTRAR`` is set too.

``--ask question.wav --to sip:agent@127.0.0.1:5070`` plays the other part:
it calls the agent, says what is in the WAV file (mono, 16-bit, 16 kHz),
records what it hears back into ``--record`` and prints how long it took
from the end of the question to the first sound of the answer. With
``--barge-in`` it says the question again a second into the answer and
prints how soon the answer stopped.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import math
import os
import socket
import time
import wave

from sipral import Stack
from sipral.enums import AudioMode
from sipral_agents import (
    AgentCall,
    AgentEventKind,
    EnergyVad,
    LocalAgent,
    LocalAgentServer,
    Ollama,
    PocketVoice,
    SystemVoice,
    WhisperServer,
    local_voice,
    serve,
    wait_for_media,
)

RATE = 16000
FRAME = RATE // 50
LOUD = 300


def route_to(address: str) -> str:
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


async def report(agent: AgentCall) -> None:
    while True:
        event = await agent.events.get()
        if event.kind == AgentEventKind.TRANSCRIPT:
            print(f"{event.data['role']}: {event.data['text']}", flush=True)
        elif event.kind == AgentEventKind.INTERRUPTED:
            print(f"interrupted after {event.data['heard_ms']} ms", flush=True)
        elif event.kind == AgentEventKind.ERROR:
            print(f"error: {event.data['message']}", flush=True)
        elif event.kind == AgentEventKind.ENDED:
            print(f"call ended: {event.data['reason']}", flush=True)
            return


def print_timing(timing: dict[str, float]) -> None:
    parts = ", ".join(f"{name} {seconds * 1000:.0f} ms" for name, seconds in timing.items())
    print(f"after the caller stopped: {parts}", flush=True)


async def answer(args: argparse.Namespace) -> None:
    registrar_address = os.environ.get("SIPRAL_REGISTRAR_ADDRESS")
    host = args.host or (route_to(registrar_address) if registrar_address else "127.0.0.1")
    thinker = Ollama(model=args.model, url=args.ollama)
    print(f"loading {args.model}", flush=True)
    async for _ in thinker.reply([{"role": "user", "content": "Say OK."}]):
        pass
    if args.tts == "say":
        voice = SystemVoice(args.voice)
    elif args.tts == "pocket":
        voice = PocketVoice(args.voice, args.language)
    else:
        try:
            voice = local_voice(args.voice, args.language)
        except RuntimeError as failed:
            raise SystemExit(str(failed)) from None
    if isinstance(voice, PocketVoice):
        print(f"loading Pocket TTS ({args.language or 'english'})", flush=True)
        await voice.load()
    pipeline = LocalAgentServer(
        WhisperServer(args.whisper),
        thinker,
        voice,
        greeting=args.greeting or None,
        vad=lambda: EnergyVad(end_silence_ms=args.end_silence_ms, pause_ms=args.pause_ms or None),
        first_clause_words=args.first_clause_words or None,
        on_timing=print_timing,
    )
    url = await pipeline.start()
    stack = Stack(
        host, args.port, loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION,
        codecs="opus,G722,PCMU,PCMA",
    )
    try:
        account = stack.add_account(
            os.environ.get("SIPRAL_AOR", "sip:agent@sipral.invalid"),
            registrar=os.environ.get("SIPRAL_REGISTRAR"),
            registrar_address=registrar_address or f"{host}:{args.port}",
            auth_user=os.environ.get("SIPRAL_AUTH_USER"),
            auth_password=os.environ.get("SIPRAL_AUTH_PASSWORD"),
        )
        if os.environ.get("SIPRAL_REGISTRAR"):
            account.register()
        print(f"call sip:agent@{stack.bind_address}", flush=True)
        reports: set[asyncio.Task] = set()

        def watch(agent: AgentCall) -> None:
            task = asyncio.create_task(report(agent))
            reports.add(task)
            task.add_done_callback(reports.discard)

        await serve(account, lambda _call: LocalAgent(url), media_host=host, on_agent_call=watch)
    finally:
        stack.close()
        await pipeline.stop()
        if isinstance(voice, PocketVoice):
            voice.close()


def loud(pcm: bytes) -> bool:
    samples = memoryview(pcm).cast("h")
    return math.sqrt(sum(s * s for s in samples) / max(len(samples), 1)) > LOUD


async def ask(args: argparse.Namespace) -> None:
    with wave.open(args.ask, "rb") as w:
        if (w.getnchannels(), w.getsampwidth(), w.getframerate()) != (1, 2, RATE):
            raise SystemExit(f"{args.ask}: the question must be mono, 16-bit, {RATE} Hz")
        question = w.readframes(w.getnframes())
    question += bytes(-len(question) % (2 * FRAME))
    target = args.to.split("@", 1)[1]
    stack = Stack(args.host or route_to(target), 0, loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
    try:
        account = stack.add_account("sip:caller@sipral.invalid", registrar_address=target)
        call = stack.place_call(account, args.to)
        if not await wait_for_media(call, 30):
            raise SystemExit("the call never got media")
        media = call.media
        media.set_app_rate(RATE)
        heard = bytearray()
        start = time.monotonic()
        silence = bytes(2 * FRAME)
        # the greeting, if any, is heard out before the question
        await asyncio.sleep(args.wait)
        asked_at = time.monotonic()
        ended_at = asked_at + len(question) / 2 / RATE
        speaking = bytearray(question)
        first_sound = barged_at = fell_silent = None
        quiet_since = 0.0
        sent = 0
        while time.monotonic() - ended_at < args.listen and not call.ended:
            now = time.monotonic()
            if now >= asked_at + sent * FRAME / RATE:
                media.send_audio(bytes(speaking[: 2 * FRAME]) if speaking else silence)
                del speaking[: 2 * FRAME]
                sent += 1
            if args.barge_in and first_sound is not None and barged_at is None and now - first_sound >= 1.0:
                # talk over the answer with the question again
                speaking += question
                barged_at = now
            while not media.frames.empty():
                frame = media.frames.get_nowait()
                heard += frame
                now = time.monotonic()
                if loud(frame):
                    quiet_since = now
                    if first_sound is None and now > ended_at:
                        first_sound = now
                elif barged_at is not None and fell_silent is None and now - quiet_since >= 0.3:
                    fell_silent = quiet_since
            await asyncio.sleep(0.005)
        call.hangup()
        with wave.open(args.record, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(RATE)
            w.writeframes(bytes(heard))
        print(f"question: {len(question) / 2 / RATE:.2f} s, sent {asked_at - start:.1f} s into the call")
        if first_sound is None:
            print(f"no answer heard in {args.listen} s")
        else:
            print(f"first sound of the answer {1000 * (first_sound - ended_at):.0f} ms after the question ended")
        if barged_at is not None:
            if fell_silent is None:
                print("the answer went on over the caller")
            else:
                print(f"the answer stopped {1000 * (fell_silent - barged_at):.0f} ms after the caller talked over it")
        print(f"what the caller heard: {args.record}")
        call.close()
    finally:
        stack.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", help="the address to listen on (default 127.0.0.1, or the route to the PBX)")
    parser.add_argument("--port", type=int, default=5070, help="the SIP port (default 5070)")
    parser.add_argument("--whisper", default="http://127.0.0.1:8178", help="whisper-server's address")
    parser.add_argument("--ollama", default="http://127.0.0.1:11434", help="Ollama's address")
    parser.add_argument("--model", default="qwen2.5:1.5b", help="the Ollama model (default qwen2.5:1.5b)")
    parser.add_argument(
        "--tts",
        choices=["auto", "pocket", "say"],
        default="auto",
        help="the voice: Pocket TTS, macOS's say, or Pocket when installed and say otherwise (default auto)",
    )
    parser.add_argument(
        "--language",
        help="Pocket's model: english (default), french, german, spanish, portuguese, italian, dutch",
    )
    parser.add_argument(
        "--voice",
        help="Pocket: a voice of its catalogue or a WAV file to clone (default: the language's own); "
        "say: a voice of `say -v '?'` (default: the system's)",
    )
    parser.add_argument(
        "--end-silence-ms",
        type=int,
        default=EnergyVad.end_silence_ms,
        help=f"quiet that ends the caller's turn (default {EnergyVad.end_silence_ms})",
    )
    parser.add_argument(
        "--pause-ms",
        type=int,
        default=EnergyVad.pause_ms,
        help=f"quiet after which the answer is started, heard only once the turn ends; 0 waits for the end "
        f"(default {EnergyVad.pause_ms})",
    )
    parser.add_argument(
        "--first-clause-words",
        type=int,
        default=2,
        help="the reply's first clause is spoken once it has this many words; 0 speaks whole sentences (default 2)",
    )
    parser.add_argument("--greeting", default="Hello, how can I help?", help="said when a call is answered; empty for none")
    parser.add_argument("--ask", help="call the agent and say this WAV file instead of answering calls")
    parser.add_argument("--to", default="sip:agent@127.0.0.1:5070", help="with --ask: the agent's SIP URI")
    parser.add_argument("--wait", type=float, default=4.0, help="with --ask: seconds to listen before asking")
    parser.add_argument("--listen", type=float, default=15.0, help="with --ask: seconds to listen after asking")
    parser.add_argument("--barge-in", action="store_true", help="with --ask: say it again a second into the answer")
    parser.add_argument("--record", default="heard.wav", help="with --ask: where to write what was heard")
    args = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(ask(args) if args.ask else answer(args))


if __name__ == "__main__":
    main()
