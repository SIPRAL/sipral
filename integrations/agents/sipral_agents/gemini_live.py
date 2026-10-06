# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Gemini Live over its WebSocket API (``BidiGenerateContent``).

Written from Google's public Live API documentation and its WebSocket API
reference: a ``setup`` message answered by ``setupComplete``, the caller's
audio as base64 PCM in ``realtimeInput`` with its rate in the MIME type,
the model's as base64 PCM at 24 kHz in ``serverContent``, ``interrupted``
when the caller speaks over the model, ``goAway`` before the service closes
a connection, and session resumption handles to carry the conversation into
the next one.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

from websockets.asyncio.client import ClientConnection

from .core import (
    Audio,
    GoAway,
    Interrupted,
    Provider,
    ProviderError,
    Signal,
    Transcript,
    TurnComplete,
)

__all__ = ["GeminiLive"]

_ENDPOINT = (
    "wss://generativelanguage.googleapis.com/ws/"
    "google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"
)


class GeminiLive(Provider):
    """A Gemini Live session: ``model`` (the Live model's name, with or
    without ``models/``), ``api_key``, and optionally ``instructions``,
    ``voice`` and a ``url`` other than Google's.

    The output is 24 kHz, and the input is sent at that rate too, declared
    in its MIME type, so the call's frames run at one rate both ways.
    ``setup`` is merged into the setup message for any field this class
    does not set. Resumption is on: after a ``goAway`` or a dropped
    connection the next one resumes the conversation with the last handle
    the service gave.
    """

    name = "gemini-live"
    sample_rate = 24000

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        instructions: str | None = None,
        voice: str | None = None,
        url: str = _ENDPOINT,
        setup: dict | None = None,
    ) -> None:
        self.model = model if model.startswith("models/") else f"models/{model}"
        self.api_key = api_key
        self.instructions = instructions
        self.voice = voice
        self.base_url = url
        self.extra = setup or {}
        #: The last resumption handle the service gave, if any.
        self.handle: str | None = None

    def url(self) -> str:
        return f"{self.base_url}?key={quote(self.api_key)}"

    def setup_message(self) -> dict:
        generation: dict = {"responseModalities": ["AUDIO"]}
        if self.voice:
            generation["speechConfig"] = {
                "voiceConfig": {"prebuiltVoiceConfig": {"voiceName": self.voice}}
            }
        setup: dict = {
            "model": self.model,
            "generationConfig": generation,
            "inputAudioTranscription": {},
            "outputAudioTranscription": {},
            "sessionResumption": {"handle": self.handle} if self.handle else {},
        }
        if self.instructions:
            setup["systemInstruction"] = {"parts": [{"text": self.instructions}]}
        setup.update(self.extra)
        return {"setup": setup}

    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        resumed = resuming and self.handle is not None
        await ws.send(json.dumps(self.setup_message()))
        async for message in ws:
            body = json.loads(message)
            if "setupComplete" in body:
                return resumed
            if "error" in body:
                raise ConnectionError(str(body["error"]))
        raise ConnectionError(
            f"the service closed the connection before the setup completed: {ws.close_reason}"
        )

    def audio_message(self, pcm: bytes) -> str:
        return json.dumps(
            {
                "realtimeInput": {
                    "audio": {
                        "data": base64.b64encode(pcm).decode(),
                        "mimeType": f"audio/pcm;rate={self.sample_rate}",
                    }
                }
            }
        )

    def parse(self, message: str | bytes) -> list[Signal]:
        body = json.loads(message)
        signals: list[Signal] = []
        update = body.get("sessionResumptionUpdate")
        if update and update.get("resumable") and update.get("newHandle"):
            self.handle = update["newHandle"]
        content = body.get("serverContent")
        if content:
            if content.get("interrupted"):
                signals.append(Interrupted())
            for part in (content.get("modelTurn") or {}).get("parts", []):
                inline = part.get("inlineData")
                if inline and inline.get("mimeType", "audio/pcm").startswith("audio/pcm"):
                    signals.append(Audio(base64.b64decode(inline["data"])))
            heard = (content.get("inputTranscription") or {}).get("text")
            if heard:
                signals.append(Transcript("user", heard))
            said = (content.get("outputTranscription") or {}).get("text")
            if said:
                signals.append(Transcript("agent", said))
            if content.get("turnComplete"):
                signals.append(TurnComplete())
        if "goAway" in body:
            signals.append(GoAway())
        if "error" in body:
            signals.append(ProviderError(str(body["error"])))
        return signals
