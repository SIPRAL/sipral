#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A phone agent: answers every call to one SIP account and talks with the
caller through Deepgram (speech to text), OpenAI (the model) and OpenAI
(text to speech), one Pipecat pipeline per call.

    pip install sipral-pipecat "pipecat-ai[deepgram,openai,silero]"

    SIPRAL_AOR=sip:agent@example.invalid \\
    SIPRAL_REGISTRAR=sip:example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \\
    DEEPGRAM_API_KEY=... OPENAI_API_KEY=... \\
    python3 phone_agent.py

Without ``SIPRAL_REGISTRAR`` nothing registers: the agent answers what the
proxy at ``SIPRAL_REGISTRAR_ADDRESS`` sends it, or a softphone dialling
``sip:agent@<the address printed at start>``. ``SIPRAL_PORT`` is the port it
listens on (5060). ``AGENT_PROMPT`` replaces the system prompt. The agent
hangs up when the caller presses "#".
"""

from __future__ import annotations

import asyncio
import os
import socket

from pipecat.audio.vad.silero import SileroVADAnalyzer
from pipecat.frames.frames import EndWorkerFrame, Frame, InputDTMFFrame, LLMRunFrame
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.worker import PipelineParams, PipelineWorker
from pipecat.processors.aggregators.llm_context import LLMContext
from pipecat.processors.aggregators.llm_response_universal import (
    LLMContextAggregatorPair,
    LLMUserAggregatorParams,
)
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor
from pipecat.services.deepgram.stt import DeepgramSTTService
from pipecat.services.openai.llm import OpenAILLMService
from pipecat.services.openai.tts import OpenAITTSService

from sipral import Stack
from sipral.enums import AudioMode
from sipral_pipecat import SipralTransport, serve

PROMPT = (
    "You are a helpful assistant on a phone call. Keep every answer to one or "
    "two short sentences, with no lists or symbols: it is read aloud."
)


def route_to(address: str) -> str:
    """The address of this host's route toward ``address``: what the far end
    can reach, unlike 0.0.0.0. Connecting a datagram socket sends nothing."""
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


class HangUpOnPound(FrameProcessor):
    """Ends the pipeline -- and so the call -- when the caller presses "#"."""

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        await super().process_frame(frame, direction)
        if isinstance(frame, InputDTMFFrame) and frame.button.value == "#":
            await self.push_frame(EndWorkerFrame(reason="caller pressed #"), FrameDirection.UPSTREAM)
            return
        await self.push_frame(frame, direction)


def agent(transport: SipralTransport) -> PipelineWorker:
    """One call's pipeline."""
    stt = DeepgramSTTService(api_key=os.environ["DEEPGRAM_API_KEY"])
    llm = OpenAILLMService(api_key=os.environ["OPENAI_API_KEY"])
    tts = OpenAITTSService(api_key=os.environ["OPENAI_API_KEY"])
    context = LLMContext([{"role": "system", "content": os.environ.get("AGENT_PROMPT", PROMPT)}])
    aggregators = LLMContextAggregatorPair(
        context, user_params=LLMUserAggregatorParams(vad_analyzer=SileroVADAnalyzer())
    )
    pipeline = Pipeline(
        [
            transport.input(),
            HangUpOnPound(),
            stt,
            aggregators.user(),
            llm,
            tts,
            transport.output(),
            aggregators.assistant(),
        ]
    )
    # speech recognition and VAD hear the call's own rate; OpenAI speaks at
    # 24 kHz and the transport's output resamples it to the call's
    worker = PipelineWorker(
        pipeline, params=PipelineParams(audio_in_sample_rate=transport.sample_rate)
    )

    @worker.event_handler("on_pipeline_started")
    async def greet(worker, _frame):
        context.add_message({"role": "user", "content": "Greet the caller in one sentence."})
        await worker.queue_frame(LLMRunFrame())

    @transport.event_handler("on_call_ended")
    async def ended(_transport, call):
        print(f"call {call.handle:x} ended")

    return worker


async def main() -> None:
    loop = asyncio.get_running_loop()
    registrar_address = os.environ["SIPRAL_REGISTRAR_ADDRESS"]
    host = route_to(registrar_address)
    stack = Stack(
        host,
        int(os.environ.get("SIPRAL_PORT", "5060")),
        loop=loop,
        audio=AudioMode.APPLICATION,
        # Silero's VAD takes 8 or 16 kHz, so the codecs offered decode to one
        # of those: G.722 at 16 kHz, then G.711 at 8 kHz
        codecs="G722,PCMU,PCMA",
    )
    try:
        account = stack.add_account(
            os.environ.get("SIPRAL_AOR", "sip:agent@example.invalid"),
            registrar=os.environ.get("SIPRAL_REGISTRAR"),
            registrar_address=registrar_address,
            auth_user=os.environ.get("SIPRAL_AUTH_USER"),
            auth_password=os.environ.get("SIPRAL_AUTH_PASSWORD"),
        )
        if os.environ.get("SIPRAL_REGISTRAR"):
            account.register()
        print(f"answering calls on {stack.bind_address}")
        await serve(account, agent, media_host=host)
    finally:
        stack.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
