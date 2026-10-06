# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Sipral for voice-agent WebSocket APIs: a SIP call joined to OpenAI
Realtime or Gemini Live, over a core the next services share."""

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
    Signal,
    SpeechStarted,
    Transcript,
    TurnComplete,
)
from .gemini_live import GeminiLive
from .openai_realtime import OpenAIRealtime
from .serve import ProviderFactory, serve, wait_for_media

__all__ = [
    "AgentCall",
    "AgentEvent",
    "AgentEventKind",
    "Audio",
    "Backoff",
    "GeminiLive",
    "GoAway",
    "Interrupted",
    "OpenAIRealtime",
    "Provider",
    "ProviderError",
    "ProviderFactory",
    "Signal",
    "SpeechStarted",
    "Transcript",
    "TurnComplete",
    "serve",
    "wait_for_media",
]
