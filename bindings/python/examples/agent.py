#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""A headless voice agent: answers, listens, talks back, hangs up on "#".

Wires any model in through one function, ``respond``, which takes one
frame of 16-bit mono PCM and returns one back -- an echo by default, so
this runs with nothing else installed. A real agent replaces ``respond``
with a call into whatever transcribes, thinks and synthesizes; nothing
else here changes; a large recorded reply crosses just as well as a frame
at a time by queuing several calls to ``call.media.send_audio``.

    SIPRAL_AOR=sip:agent@example.invalid \\
    SIPRAL_REGISTRAR=example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \\
    python3 agent.py
"""

from __future__ import annotations

import asyncio
import os

from sipral import Call, Stack
from sipral.enums import EventKind


def respond(pcm: bytes) -> bytes:
    """The one function a real agent replaces. Default: an echo."""
    return pcm


async def run_call(call: Call) -> None:
    print(f"answered {call.handle:x}")
    while call.media is None:
        await call.events.get()

    async def talk() -> None:
        while True:
            heard = await call.media.frames.get()
            call.media.send_audio(respond(heard))

    async def listen_for_hangup() -> None:
        while True:
            digit = await call.dtmf.get()
            print("dtmf", digit)
            if digit == "#":
                call.hangup()
                return

    async def wait_for_remote_hangup() -> None:
        # The far end can end the call itself, with no "#" ever sent; a
        # peer that hangs up first is the ordinary case, not the
        # exception, and this is what keeps that call's own thread and
        # media socket from running forever with nobody listening.
        while not call.ended:
            await call.events.get()

    talking = asyncio.create_task(talk())
    hanging_up = asyncio.create_task(listen_for_hangup())
    ending = asyncio.create_task(wait_for_remote_hangup())
    try:
        await asyncio.wait({hanging_up, ending}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        talking.cancel()
        hanging_up.cancel()
        ending.cancel()
        # Read before closing: `call.close()` releases the media handle,
        # and a `sipral_media_statistics` call against a released one is
        # `SIPRAL_STATUS_STALE_HANDLE`, not a number.
        stats = call.media.statistics() if call.media else {}
        call.close()
        print(f"ended {call.handle:x}: {stats}")


async def main() -> None:
    loop = asyncio.get_running_loop()
    stack = Stack(loop=loop, bind_host="0.0.0.0")
    account = stack.add_account(
        os.environ.get("SIPRAL_AOR", "sip:agent@example.invalid"),
        registrar=os.environ.get("SIPRAL_REGISTRAR"),
        registrar_address=os.environ["SIPRAL_REGISTRAR_ADDRESS"],
        auth_user=os.environ.get("SIPRAL_AUTH_USER"),
        auth_password=os.environ.get("SIPRAL_AUTH_PASSWORD"),
    )
    if os.environ.get("SIPRAL_REGISTRAR"):
        account.register()

    print(f"listening on {stack.bind_address}")
    calls: set[asyncio.Task] = set()
    try:
        while True:
            event = await stack.events.get()
            if event.kind == EventKind.INCOMING_CALL:
                call = stack.answer_call(event)
                task = asyncio.create_task(run_call(call))
                calls.add(task)
                task.add_done_callback(calls.discard)
    finally:
        for task in calls:
            task.cancel()
        stack.close()


if __name__ == "__main__":
    asyncio.run(main())
