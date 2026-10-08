# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Sipral for voice-agent WebSocket APIs: a SIP call joined to OpenAI
Realtime, Gemini Live, ElevenLabs Agents, Vapi, Deepgram Voice Agent or a
local agent with no key, over one core, and a bridge that serves a PBX's
calls from a configuration file."""

from .core import (
    AgentCall,
    AgentEvent,
    AgentEventKind,
    Audio,
    Backoff,
    GoAway,
    Interrupted,
    Provider,
    ProviderError,
    Reply,
    SessionRefused,
    Signal,
    SpeechStarted,
    Transcript,
    TurnComplete,
)
from .deepgram import DeepgramAgent
from .elevenlabs import ElevenLabsAgent
from .gemini_live import GeminiLive
from .local import (
    CommandVoice,
    EnergyVad,
    LocalAgent,
    LocalAgentServer,
    Ollama,
    PocketVoice,
    Resampler,
    SystemVoice,
    WhisperServer,
    local_voice,
)
from .openai_realtime import OpenAIRealtime
from .outbound import MachinePolicy, dial
from .serve import ProviderFactory, serve, wait_for_media
from .vapi import VapiAgent

__all__ = [
    "AgentCall",
    "AgentEvent",
    "AgentEventKind",
    "Audio",
    "Backoff",
    "CommandVoice",
    "DeepgramAgent",
    "EnergyVad",
    "ElevenLabsAgent",
    "GeminiLive",
    "GoAway",
    "Interrupted",
    "LocalAgent",
    "LocalAgentServer",
    "MachinePolicy",
    "Ollama",
    "OpenAIRealtime",
    "PocketVoice",
    "Provider",
    "ProviderError",
    "ProviderFactory",
    "Reply",
    "Resampler",
    "SessionRefused",
    "Signal",
    "SpeechStarted",
    "SystemVoice",
    "Transcript",
    "TurnComplete",
    "VapiAgent",
    "WhisperServer",
    "dial",
    "local_voice",
    "serve",
    "wait_for_media",
]
