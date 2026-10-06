# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""OpenAI Realtime over its WebSocket API.

Written from OpenAI's public Realtime documentation (the WebSocket guide and
the client and server event reference): PCM at 24 kHz both ways, base64 in
JSON events, the service's own voice activity detection deciding turns and
cancelling a response when the caller speaks over it.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

from websockets.asyncio.client import ClientConnection

from .core import (
    Audio,
    Provider,
    ProviderError,
    Signal,
    SpeechStarted,
    Transcript,
    TurnComplete,
)

__all__ = ["OpenAIRealtime"]

_AUDIO_DELTAS = ("response.output_audio.delta", "response.audio.delta")
_AGENT_TRANSCRIPTS = (
    "response.output_audio_transcript.done",
    "response.audio_transcript.done",
)


class OpenAIRealtime(Provider):
    """An OpenAI Realtime session: ``model`` (for example
    ``"gpt-realtime"``), ``api_key``, and optionally ``instructions``,
    ``voice`` and a ``url`` other than OpenAI's (a proxy, a test server).

    ``session`` is merged into the ``session.update`` sent on connecting,
    for any field this class does not set (tools, transcription, ...).
    A reconnection opens a new session: the service keeps no conversation
    across connections.
    """

    name = "openai-realtime"
    sample_rate = 24000

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        instructions: str | None = None,
        voice: str | None = None,
        url: str = "wss://api.openai.com/v1/realtime",
        session: dict | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.instructions = instructions
        self.voice = voice
        self.base_url = url
        self.extra = session or {}

    def url(self) -> str:
        return f"{self.base_url}?model={quote(self.model)}"

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    def session_update(self) -> dict:
        audio_format = {"type": "audio/pcm", "rate": self.sample_rate}
        output: dict = {"format": audio_format}
        if self.voice:
            output["voice"] = self.voice
        session: dict = {
            "type": "realtime",
            "output_modalities": ["audio"],
            "audio": {
                "input": {
                    "format": audio_format,
                    "turn_detection": {
                        "type": "server_vad",
                        "create_response": True,
                        "interrupt_response": True,
                    },
                },
                "output": output,
            },
        }
        if self.instructions:
            session["instructions"] = self.instructions
        session.update(self.extra)
        return {"type": "session.update", "session": session}

    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        await ws.send(json.dumps(self.session_update()))
        async for message in ws:
            event = json.loads(message)
            kind = event.get("type")
            if kind == "session.updated":
                return False
            if kind == "error":
                raise ConnectionError(_error_text(event))
        raise ConnectionError("the service closed the connection before the session was set up")

    def audio_message(self, pcm: bytes) -> str:
        return json.dumps(
            {"type": "input_audio_buffer.append", "audio": base64.b64encode(pcm).decode()}
        )

    def parse(self, message: str | bytes) -> list[Signal]:
        event = json.loads(message)
        kind = event.get("type")
        if kind in _AUDIO_DELTAS:
            return [Audio(base64.b64decode(event["delta"]), event.get("item_id"))]
        if kind == "input_audio_buffer.speech_started":
            return [SpeechStarted()]
        if kind == "response.done":
            return [TurnComplete()]
        if kind in _AGENT_TRANSCRIPTS:
            return [Transcript("agent", event.get("transcript", ""))]
        if kind == "conversation.item.input_audio_transcription.completed":
            return [Transcript("user", event.get("transcript", ""))]
        if kind == "error":
            return [ProviderError(_error_text(event))]
        return []

    def barge_in(self, item: str | None, heard_ms: int) -> list[str]:
        # the service cancels the response itself (interrupt_response); the
        # conversation is cut to what the caller actually heard
        if item is None:
            return []
        return [
            json.dumps(
                {
                    "type": "conversation.item.truncate",
                    "item_id": item,
                    "content_index": 0,
                    "audio_end_ms": heard_ms,
                }
            )
        ]


def _error_text(event: dict) -> str:
    error = event.get("error") or {}
    code = error.get("code") or error.get("type") or "error"
    return f"{code}: {error.get('message', '')}"
