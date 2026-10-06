# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Deepgram Voice Agent over its WebSocket API.

Written from Deepgram's public Voice Agent API reference: a ``Settings``
message answered by ``SettingsApplied``, the caller's and the agent's audio
as raw ``linear16`` PCM in binary frames, ``UserStartedSpeaking`` when the
caller speaks over the agent, ``AgentAudioDone`` at the end of a turn,
``ConversationText`` for what each side said, and ``Error`` and ``Warning``.
"""

from __future__ import annotations

import json

from websockets.asyncio.client import ClientConnection

from .core import (
    Audio,
    Provider,
    ProviderError,
    SessionRefused,
    Signal,
    SpeechStarted,
    Transcript,
    TurnComplete,
)

__all__ = ["DeepgramAgent"]

_ENDPOINT = "wss://agent.deepgram.com/v1/agent/converse"


class DeepgramAgent(Provider):
    """A Deepgram Voice Agent session: ``api_key`` and ``agent``, the
    ``agent`` object of the ``Settings`` message -- its ``listen``,
    ``think`` and ``speak`` providers and models, which this class does not
    choose for the application.

    The audio is ``linear16`` at ``sample_rate`` (24000 by default, the
    rate Deepgram recommends) both ways, with no container. ``settings`` is
    merged into the ``Settings`` message for anything else (``tags``,
    ``experimental``, ...); ``url`` replaces Deepgram's (the EU endpoint, a
    test server). A reconnection starts a new session.
    """

    name = "deepgram"

    def __init__(
        self,
        *,
        api_key: str,
        agent: dict,
        sample_rate: int = 24000,
        settings: dict | None = None,
        url: str = _ENDPOINT,
    ) -> None:
        if sample_rate not in (8000, 16000, 24000, 48000):
            raise ValueError("sample_rate must be 8000, 16000, 24000 or 48000")
        if not isinstance(agent, dict) or not agent:
            raise ValueError("agent must name the listen, think and speak providers")
        self.api_key = api_key
        self.agent = agent
        self.sample_rate = sample_rate
        self.extra = settings or {}
        self.base_url = url

    def url(self) -> str:
        return self.base_url

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.api_key}"}

    def settings_message(self) -> dict:
        message: dict = {
            "type": "Settings",
            "audio": {
                "input": {"encoding": "linear16", "sample_rate": self.sample_rate},
                "output": {
                    "encoding": "linear16",
                    "sample_rate": self.sample_rate,
                    "container": "none",
                },
            },
            "agent": self.agent,
        }
        message.update(self.extra)
        return message

    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        await ws.send(json.dumps(self.settings_message()))
        async for message in ws:
            if isinstance(message, bytes):
                continue
            event = json.loads(message)
            kind = event.get("type")
            if kind == "SettingsApplied":
                return False
            if kind == "Error":
                raise SessionRefused(_error_text(event))
        raise ConnectionError(
            f"the service closed the connection before the settings applied: {ws.close_reason}"
        )

    def audio_message(self, pcm: bytes) -> bytes:
        return pcm

    def parse(self, message: str | bytes) -> list[Signal]:
        if isinstance(message, bytes):
            return [Audio(message)]
        event = json.loads(message)
        kind = event.get("type")
        if kind == "UserStartedSpeaking":
            return [SpeechStarted()]
        if kind == "AgentAudioDone":
            return [TurnComplete()]
        if kind == "ConversationText":
            role = "user" if event.get("role") == "user" else "agent"
            return [Transcript(role, event.get("content", ""))]
        if kind in ("Error", "Warning"):
            return [ProviderError(_error_text(event))]
        return []


def _error_text(event: dict) -> str:
    code = event.get("code") or event.get("type", "error")
    return f"{code}: {event.get('description', '')}"
