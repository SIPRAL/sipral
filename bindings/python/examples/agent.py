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
    SIPRAL_REGISTRAR=sip:example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \\
    python3 agent.py
"""

from __future__ import annotations

import asyncio
import os
import socket

from sipral import Call, Stack
from sipral.enums import EventKind
from sipral.errors import SipralError


def route_to(address: str) -> str:
    """Which of this host's addresses a datagram to ``address`` leaves from.

    That address goes in the ``Contact`` and in every answer's SDP, so it
    has to be one the far end can send to: a stack bound to ``0.0.0.0``
    advertises it, and a registrar or a phone handed ``0.0.0.0`` has
    nowhere to send anything back. Connecting a datagram socket sends
    nothing; it only asks the system which route it would take.
    """
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


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

    stats: dict[str, object] = {}

    async def poll_statistics() -> None:
        # Kept fresh at a steady interval, not read once after the call is
        # seen to have ended: once the far end's BYE is answered the stack
        # tears this call's media down on its own poll thread, so by the
        # time either task below notices the call is over,
        # `call.media.statistics()` can already answer with the ABI's
        # WRONG_STATE (bindings/c/include/sipral.h: `sipral_media_statistics`'s
        # end-of-call record "arrives instead as
        # SIPRAL_EVENT_KIND_MEDIA_STATISTICS ... because by then the stream
        # is gone"). A read that lands mid-teardown is skipped, not fatal --
        # `stats` just keeps its last good reading, at most one interval
        # stale. Cheap enough for this rate: the same doc calls it fit "at
        # the frame rate of a user interface".
        nonlocal stats
        while True:
            try:
                stats = call.media.statistics()
            except SipralError:
                pass
            await asyncio.sleep(0.2)

    async def listen_for_hangup() -> None:
        nonlocal stats
        while True:
            digit = await call.dtmf.get()
            print("dtmf", digit)
            if digit == "#":
                # One last read while the call is still certainly up, for
                # the freshest number this path can give.
                try:
                    stats = call.media.statistics()
                except SipralError:
                    pass
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
    polling = asyncio.create_task(poll_statistics())
    hanging_up = asyncio.create_task(listen_for_hangup())
    ending = asyncio.create_task(wait_for_remote_hangup())
    try:
        await asyncio.wait({hanging_up, ending}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        talking.cancel()
        polling.cancel()
        hanging_up.cancel()
        ending.cancel()
        call.close()
        print(f"ended {call.handle:x}: {stats}")


def report_failure(task: asyncio.Task) -> None:
    """Say why a call's task ended, if it ended by raising.

    An exception in a task nobody awaits is otherwise only mentioned when
    the task is garbage collected, which for a process that is stopped
    rather than left to exit is never.
    """
    if not task.cancelled() and task.exception() is not None:
        print(f"call failed: {task.exception()!r}")


async def main() -> None:
    loop = asyncio.get_running_loop()
    registrar_address = os.environ["SIPRAL_REGISTRAR_ADDRESS"]
    host = route_to(registrar_address)
    stack = Stack(loop=loop, bind_host=host)
    account = stack.add_account(
        os.environ.get("SIPRAL_AOR", "sip:agent@example.invalid"),
        registrar=os.environ.get("SIPRAL_REGISTRAR"),
        registrar_address=registrar_address,
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
                call = stack.answer_call(event, media_host=host)
                task = asyncio.create_task(run_call(call))
                calls.add(task)
                task.add_done_callback(calls.discard)
                task.add_done_callback(report_failure)
    finally:
        for task in calls:
            task.cancel()
        stack.close()


if __name__ == "__main__":
    asyncio.run(main())
