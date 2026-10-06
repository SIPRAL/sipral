# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""ElevenLabs Agents over its conversation WebSocket.

Written from ElevenLabs' public Agents WebSocket API reference: a
``conversation_initiation_client_data`` message answered by
``conversation_initiation_metadata``, which names the PCM formats the agent
was configured with; the caller's audio as base64 in ``user_audio_chunk``;
the agent's as base64 in ``audio`` events numbered by ``event_id``; an
``interruption`` naming the last event that still counts; and ``ping``
events the client answers with a ``pong`` of the same ``event_id``.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

from websockets.asyncio.client import ClientConnection

from .core import (
    Audio,
    Interrupted,
    Provider,
    ProviderError,
    Reply,
    SessionRefused,
    Signal,
    Transcript,
)

__all__ = ["ElevenLabsAgent"]

_ENDPOINT = "wss://api.elevenlabs.io/v1/convai/conversation"


class ElevenLabsAgent(Provider):
    """A conversation with an ElevenLabs agent: ``agent_id``, and an
    ``api_key`` unless the agent is public.

    The audio formats are the agent's own, set in its configuration;
    ``sample_rate`` (16000 by default, ElevenLabs' ``pcm_16000``) must match
    them, and a session whose formats differ is refused rather than played
    at the wrong speed. ``overrides`` becomes the
    ``conversation_config_override`` and ``dynamic_variables`` the
    conversation's variables; ``url`` replaces ElevenLabs' (a regional
    endpoint, a test server). A reconnection starts a new conversation.
    """

    name = "elevenlabs"

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str | None = None,
        sample_rate: int = 16000,
        overrides: dict | None = None,
        dynamic_variables: dict | None = None,
        url: str = _ENDPOINT,
    ) -> None:
        if sample_rate not in (8000, 16000, 24000, 48000):
            raise ValueError("sample_rate must be 8000, 16000, 24000 or 48000")
        self.agent_id = agent_id
        self.api_key = api_key
        self.sample_rate = sample_rate
        self.overrides = overrides
        self.dynamic_variables = dynamic_variables
        self.base_url = url
        #: The current conversation's identifier, once the service gave it.
        self.conversation_id: str | None = None
        self._cut_at = -1

    def url(self) -> str:
        return f"{self.base_url}?agent_id={quote(self.agent_id)}"

    def headers(self) -> dict[str, str]:
        return {"xi-api-key": self.api_key} if self.api_key else {}

    def initiation(self) -> dict:
        message: dict = {"type": "conversation_initiation_client_data"}
        if self.overrides:
            message["conversation_config_override"] = self.overrides
        if self.dynamic_variables:
            message["dynamic_variables"] = self.dynamic_variables
        return message

    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        self._cut_at = -1
        await ws.send(json.dumps(self.initiation()))
        async for message in ws:
            event = json.loads(message)
            kind = event.get("type")
            if kind == "conversation_initiation_metadata":
                meta = event.get("conversation_initiation_metadata_event") or {}
                wanted = f"pcm_{self.sample_rate}"
                for side in ("user_input_audio_format", "agent_output_audio_format"):
                    given = meta.get(side, wanted)
                    if given != wanted:
                        raise SessionRefused(
                            f"the agent's {side} is {given}, and this session runs at {wanted}: "
                            "set the agent's formats or sample_rate to agree"
                        )
                self.conversation_id = meta.get("conversation_id")
                return False
            if kind == "ping":
                await ws.send(self._pong(event))
            elif kind in ("client_error", "error"):
                raise ConnectionError(_error_text(event))
        raise ConnectionError(
            f"the service closed the connection before the conversation started: {ws.close_reason}"
        )

    def audio_message(self, pcm: bytes) -> str:
        return json.dumps({"user_audio_chunk": base64.b64encode(pcm).decode()})

    def parse(self, message: str | bytes) -> list[Signal]:
        event = json.loads(message)
        kind = event.get("type")
        if kind == "audio":
            audio = event.get("audio_event") or {}
            if audio.get("event_id", 0) <= self._cut_at:
                # generated before the interruption, and arriving after it
                return []
            return [Audio(base64.b64decode(audio.get("audio_base_64", "")))]
        if kind == "interruption":
            self._cut_at = (event.get("interruption_event") or {}).get("event_id", self._cut_at)
            return [Interrupted()]
        if kind == "ping":
            return [Reply(self._pong(event))]
        if kind == "agent_response":
            text = (event.get("agent_response_event") or {}).get("agent_response", "")
            return [Transcript("agent", text)]
        if kind == "user_transcript":
            text = (event.get("user_transcription_event") or {}).get("user_transcript", "")
            return [Transcript("user", text)]
        if kind in ("client_error", "error"):
            return [ProviderError(_error_text(event))]
        return []

    @staticmethod
    def _pong(event: dict) -> str:
        ping = event.get("ping_event") or {}
        return json.dumps({"type": "pong", "event_id": ping.get("event_id")})


def _error_text(event: dict) -> str:
    error = event.get("error_event") or {}
    name = error.get("error_name") or error.get("code") or "error"
    return f"{name}: {error.get('message', '')}"
