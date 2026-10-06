# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Sipral for voice-agent WebSocket APIs: a SIP call joined to OpenAI
Realtime, Gemini Live, ElevenLabs Agents, Vapi or Deepgram Voice Agent,
over one core, and a bridge that serves a PBX's calls from a configuration
file."""

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
from .openai_realtime import OpenAIRealtime
from .serve import ProviderFactory, serve, wait_for_media
from .vapi import VapiAgent

__all__ = [
    "AgentCall",
    "AgentEvent",
    "AgentEventKind",
    "Audio",
    "Backoff",
    "DeepgramAgent",
    "ElevenLabsAgent",
    "GeminiLive",
    "GoAway",
    "Interrupted",
    "OpenAIRealtime",
    "Provider",
    "ProviderError",
    "ProviderFactory",
    "Reply",
    "SessionRefused",
    "Signal",
    "SpeechStarted",
    "Transcript",
    "TurnComplete",
    "VapiAgent",
    "serve",
    "wait_for_media",
]
