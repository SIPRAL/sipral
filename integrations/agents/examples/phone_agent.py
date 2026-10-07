#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A phone agent: answers every call to one SIP account and joins it to
OpenAI Realtime or Gemini Live, one session per call.

    pip install ./integrations/agents

    SIPRAL_AOR=sip:agent@example.invalid \\
    SIPRAL_REGISTRAR=sip:example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \\
    AGENT_SERVICE=openai AGENT_MODEL=gpt-realtime OPENAI_API_KEY=... \\
    python3 phone_agent.py

``AGENT_SERVICE=gemini`` with ``AGENT_MODEL`` set to a Live model and
``GEMINI_API_KEY`` uses Gemini Live instead. ``AGENT_URL`` points either at
another WebSocket address, such as a proxy. Without ``SIPRAL_REGISTRAR``
nothing registers: the agent answers what the proxy at
``SIPRAL_REGISTRAR_ADDRESS`` sends it, or a softphone dialling
``sip:agent@<the address printed at start>``. ``SIPRAL_PORT`` is the port it
listens on (5060). ``AGENT_PROMPT`` replaces the instructions.
"""

from __future__ import annotations

import asyncio
import os
import socket

from sipral import Stack
from sipral.enums import AudioMode
from sipral_agents import AgentCall, AgentEventKind, GeminiLive, OpenAIRealtime, Provider, serve

PROMPT = os.environ.get("AGENT_PROMPT", "You answer the phone for a small business. Be brief.")


def route_to(address: str) -> str:
    """This host's address on its route toward ``address``, which the far
    end can reach. Connecting a datagram socket sends nothing."""
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


def provider(_call) -> Provider:
    service = os.environ.get("AGENT_SERVICE", "openai")
    model = os.environ["AGENT_MODEL"]
    extra = {"url": os.environ["AGENT_URL"]} if "AGENT_URL" in os.environ else {}
    if service == "gemini":
        return GeminiLive(
            model=model, api_key=os.environ["GEMINI_API_KEY"], instructions=PROMPT, **extra
        )
    return OpenAIRealtime(
        model=model, api_key=os.environ["OPENAI_API_KEY"], instructions=PROMPT, **extra
    )


async def report(agent: AgentCall) -> None:
    while True:
        event = await agent.events.get()
        if event.kind == AgentEventKind.TRANSCRIPT:
            print(f"{event.data['role']}: {event.data['text']}")
        elif event.kind in (AgentEventKind.ERROR, AgentEventKind.RECONNECTING):
            print(f"{event.kind.value}: {event.data}")
        elif event.kind == AgentEventKind.ENDED:
            print(f"call ended: {event.data['reason']}")
            return


async def main() -> None:
    registrar_address = os.environ["SIPRAL_REGISTRAR_ADDRESS"]
    host = route_to(registrar_address)
    # the frames are converted to the service's rate whatever the codec, so
    # the widest band the caller's side offers is the one to keep
    stack = Stack(
        host,
        int(os.environ.get("SIPRAL_PORT", "5060")),
        loop=asyncio.get_running_loop(),
        audio=AudioMode.APPLICATION,
        codecs="opus,G722,PCMU,PCMA",
    )
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
    reports: set[asyncio.Task] = set()

    def watch(agent: AgentCall) -> None:
        task = asyncio.create_task(report(agent))
        reports.add(task)
        task.add_done_callback(reports.discard)

    try:
        await serve(account, provider, media_host=host, on_agent_call=watch)
    finally:
        stack.close()


if __name__ == "__main__":
    asyncio.run(main())
