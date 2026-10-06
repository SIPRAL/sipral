# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Vapi over its WebSocket transport.

Written from Vapi's public WebSocket transport guide and its call and
server-message references: a call created with ``POST /call`` and a
``vapi.websocket`` transport whose audio is raw ``pcm_s16le`` at 16 kHz,
the WebSocket at the ``websocketCallUrl`` the answer gives, the audio in
binary frames both ways, JSON control messages in text frames
(``speech-update``, ``transcript``, ``user-interrupted``), and a
``hangup`` message to end the call from this side.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

from websockets.asyncio.client import ClientConnection

from .core import (
    Audio,
    Interrupted,
    Provider,
    ProviderError,
    SessionRefused,
    Signal,
    Transcript,
    TurnComplete,
)

__all__ = ["VapiAgent"]

_API = "https://api.vapi.ai"


class VapiAgent(Provider):
    """A Vapi call over the WebSocket transport: ``api_key`` (the private
    key) and either ``assistant_id`` or an inline ``assistant``.

    Each session is one Vapi call, created when the SIP call starts.
    ``call`` is merged into the ``POST /call`` body for anything else
    (``assistantOverrides``, ``customer``, ...); ``api_url`` replaces
    Vapi's (a test server). A reconnection goes back to the same call's
    WebSocket.
    """

    name = "vapi"
    sample_rate = 16000

    def __init__(
        self,
        *,
        api_key: str,
        assistant_id: str | None = None,
        assistant: dict | None = None,
        call: dict | None = None,
        api_url: str = _API,
        request_timeout: float = 10.0,
    ) -> None:
        if (assistant_id is None) == (assistant is None):
            raise ValueError("give exactly one of assistant_id and assistant")
        self.api_key = api_key
        self.assistant_id = assistant_id
        self.assistant = assistant
        self.extra = call or {}
        self.api_url = api_url.rstrip("/")
        self.request_timeout = request_timeout
        #: The Vapi call's identifier and WebSocket, once created.
        self.call_id: str | None = None
        self.websocket_url: str | None = None

    def call_request(self) -> dict:
        body: dict = {
            "transport": {
                "provider": "vapi.websocket",
                "audioFormat": {
                    "format": "pcm_s16le",
                    "container": "raw",
                    "sampleRate": self.sample_rate,
                },
            }
        }
        if self.assistant_id is not None:
            body["assistantId"] = self.assistant_id
        else:
            body["assistant"] = self.assistant
        body.update(self.extra)
        return body

    async def prepare(self, resuming: bool) -> None:
        if self.websocket_url is None:
            answer = await asyncio.to_thread(self._create_call)
            self.call_id = answer.get("id")
            self.websocket_url = (answer.get("transport") or {}).get("websocketCallUrl")
            if not self.websocket_url:
                raise SessionRefused("the call Vapi created has no transport.websocketCallUrl")

    def _create_call(self) -> dict:
        request = urllib.request.Request(
            f"{self.api_url}/call",
            data=json.dumps(self.call_request()).encode(),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as refused:
            detail = refused.read().decode("utf-8", "replace")[:300]
            if refused.code >= 500 or refused.code == 429:
                raise ConnectionError(f"POST /call: {refused.code} {detail}") from None
            raise SessionRefused(f"POST /call: {refused.code} {detail}") from None

    def url(self) -> str:
        return self.websocket_url or ""

    async def open(self, ws: ClientConnection, resuming: bool) -> bool:
        return resuming

    def audio_message(self, pcm: bytes) -> bytes:
        return pcm

    def parse(self, message: str | bytes) -> list[Signal]:
        if isinstance(message, bytes):
            return [Audio(message)]
        body = json.loads(message)
        if not isinstance(body, dict):
            return []
        # the server-message reference wraps each in "message"; take both
        inner = body.get("message")
        event = inner if isinstance(inner, dict) else body
        kind = event.get("type")
        if kind == "user-interrupted":
            return [Interrupted()]
        if kind == "speech-update":
            if event.get("role") == "assistant" and event.get("status") == "stopped":
                return [TurnComplete()]
            return []
        if kind == "transcript" and event.get("transcriptType") == "final":
            role = "user" if event.get("role") == "user" else "agent"
            return [Transcript(role, event.get("transcript", ""))]
        if kind == "error":
            return [ProviderError(str(event.get("error") or event.get("message") or event))]
        return []

    def farewell(self) -> list[str]:
        return [json.dumps({"type": "hangup"})]
