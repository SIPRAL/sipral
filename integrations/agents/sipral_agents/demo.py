# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``python -m sipral_agents.demo``: a voice agent on a phone line in one
command.

With ``OPENAI_API_KEY`` set, every call is joined to OpenAI Realtime.
Without it, every call is joined to a local echo agent: a WebSocket server
in this process that speaks the same protocol and plays the caller's own
voice back, so the whole path -- SIP, RTP, the codec, the rate conversion,
the WebSocket session -- runs with no key and no network.

With ``SIPRAL_REGISTRAR_ADDRESS`` set, the agent registers to that PBX
(``SIPRAL_AOR``, ``SIPRAL_REGISTRAR``, ``SIPRAL_AUTH_USER``,
``SIPRAL_AUTH_PASSWORD``); without it, it listens on ``--port`` (5060) and a
softphone calls it directly.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import socket
import sys

from websockets.asyncio.server import ServerConnection
from websockets.asyncio.server import serve as ws_serve
from websockets.exceptions import ConnectionClosed

from sipral import Stack
from sipral.enums import AudioMode

from .core import AgentCall, AgentEventKind, Provider
from .openai_realtime import OpenAIRealtime
from .serve import serve

__all__ = ["EchoServer", "main", "run"]

PROMPT = "You answer the phone for a small business. Be brief and friendly."


class EchoServer:
    """A local WebSocket server speaking the part of the OpenAI Realtime
    protocol the connector uses: it accepts the session and returns every
    frame of the caller's audio as the agent's."""

    def __init__(self) -> None:
        self.server = None

    async def start(self) -> str:
        self.server = await ws_serve(self._handler, "127.0.0.1", 0, max_size=None)
        return f"ws://127.0.0.1:{self.server.sockets[0].getsockname()[1]}/echo"

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handler(self, ws: ServerConnection) -> None:
        with contextlib.suppress(ConnectionClosed):
            async for message in ws:
                event = json.loads(message)
                kind = event.get("type")
                if kind == "session.update":
                    await ws.send(json.dumps({"type": "session.updated", "session": {}}))
                elif kind == "input_audio_buffer.append":
                    await ws.send(
                        json.dumps(
                            {
                                "type": "response.output_audio.delta",
                                "item_id": "echo",
                                "delta": event["audio"],
                            }
                        )
                    )


def _route_to(address: str) -> str:
    """This host's address on its route toward ``address``; connecting a
    datagram socket sends nothing."""
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


async def _report(agent: AgentCall) -> None:
    while True:
        event = await agent.events.get()
        if event.kind == AgentEventKind.CONNECTED:
            print("agent connected", flush=True)
        elif event.kind == AgentEventKind.TRANSCRIPT:
            print(f"{event.data['role']}: {event.data['text']}", flush=True)
        elif event.kind in (AgentEventKind.ERROR, AgentEventKind.RECONNECTING):
            print(f"{event.kind.value}: {event.data}", flush=True)
        elif event.kind == AgentEventKind.ENDED:
            print(f"call ended: {event.data['reason']}", flush=True)
            return


async def run(
    host: str | None,
    port: int,
    environ: dict[str, str],
    started: asyncio.Future | None = None,
) -> None:
    """Serve calls until cancelled. ``started``, when given, receives the
    stack's bind address once calls can come in."""
    loop = asyncio.get_running_loop()
    registrar_address = environ.get("SIPRAL_REGISTRAR_ADDRESS")
    if host is None:
        host = _route_to(registrar_address) if registrar_address else "0.0.0.0"
    media_host = None if host == "0.0.0.0" else host
    echo: EchoServer | None = None
    api_key = environ.get("OPENAI_API_KEY")
    if api_key:
        model = environ.get("AGENT_MODEL", "gpt-realtime")
        prompt = environ.get("AGENT_PROMPT", PROMPT)

        def factory(_call) -> Provider:
            return OpenAIRealtime(model=model, api_key=api_key, instructions=prompt)

        print(f"agent: OpenAI Realtime, model {model}", flush=True)
    else:
        echo = EchoServer()
        echo_url = await echo.start()

        def factory(_call) -> Provider:
            return OpenAIRealtime(model="echo", api_key="none", url=echo_url)

        print("agent: local echo (set OPENAI_API_KEY for OpenAI Realtime)", flush=True)
    stack = Stack(host, port, loop=loop, audio=AudioMode.APPLICATION, codecs="opus,G722,PCMU,PCMA")
    try:
        aor = environ.get("SIPRAL_AOR", "sip:agent@sipral.invalid")
        account = stack.add_account(
            aor,
            registrar=environ.get("SIPRAL_REGISTRAR"),
            registrar_address=registrar_address or f"127.0.0.1:{port or 5060}",
            auth_user=environ.get("SIPRAL_AUTH_USER"),
            auth_password=environ.get("SIPRAL_AUTH_PASSWORD"),
        )
        if environ.get("SIPRAL_REGISTRAR"):
            account.register()
            print(f"registering {aor} at {registrar_address}", flush=True)
        else:
            print(f"call sip:agent@{stack.bind_address} from a softphone", flush=True)
        if started is not None:
            started.set_result(stack.bind_address)
        reports: set[asyncio.Task] = set()

        def watch(agent: AgentCall) -> None:
            print("incoming call", flush=True)
            task = asyncio.create_task(_report(agent))
            reports.add(task)
            task.add_done_callback(reports.discard)

        await serve(account, factory, media_host=media_host, on_agent_call=watch)
    finally:
        stack.close()
        if echo is not None:
            await echo.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sipral_agents.demo",
        description="Answer SIP calls with a voice agent: OpenAI Realtime with "
        "OPENAI_API_KEY set, a local echo agent without it.",
    )
    parser.add_argument("--host", help="the address to listen on (default: all, or the route to the PBX)")
    parser.add_argument("--port", type=int, default=5060, help="the SIP port (default 5060)")
    args = parser.parse_args(argv)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run(args.host, args.port, dict(os.environ)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
