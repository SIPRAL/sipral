#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A headless voice agent: answers, listens, talks back, hangs up on "#".

A model plugs in through ``respond``, which takes one frame of 16-bit mono
PCM and returns one; the default is an echo, so this runs with nothing else
installed. Longer replies can be queued with ``call.media.send_audio``.

It uses ``audio=AudioMode.APPLICATION`` to handle frames itself (this also
suits a machine with no sound device); ``softphone.py`` lets the library
drive the devices instead.

    SIPRAL_AOR=sip:agent@example.invalid \\
    SIPRAL_REGISTRAR=sip:example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \\
    python3 agent.py

``SIPRAL_SIGNALLING`` is ``udp`` (default), ``tcp`` or ``tls``, on one
connection to ``SIPRAL_REGISTRAR_ADDRESS``. TLS checks the certificate
against ``SIPRAL_TLS_SERVER_NAME`` (default: the address's host) with
``SIPRAL_TLS_CA`` as the only trusted authority (default: the platform's).
Failures print ``transport failed error=<...> tls=<...>`` and are retried.
``SIPRAL_INVITE_LIMIT=voice-agent`` accepts a trunk's burst of calls.

``SIPRAL_TEXT=1`` answers with real-time text (RFC 4103) when offered and
echoes what the caller types. ``SIPRAL_PRESENCE=1`` publishes "Agent ready"
(RFC 3903) and prints the result.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl

from sipral import Call, InviteLimit, Stack, TlsTrust
from sipral.enums import (
    AudioMode,
    Basic,
    EventKind,
    Ice,
    Nat,
    TlsFailure,
    Transport,
    TransportError,
)
from sipral.errors import SipralError


def route_to(address: str) -> str:
    """The local address a datagram to ``address`` leaves from.

    It goes in the ``Contact`` and SDP, so it must be reachable; ``0.0.0.0``
    is not. A UDP `connect` sends nothing.
    """
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


def respond(pcm: bytes) -> bytes:
    """The one function a real agent replaces. Default: an echo."""
    return pcm


async def run_call(
    call: Call, *, patience: float | None = None, dwell: float | None = None
) -> bool:
    """Talk for the life of one call; `False` if media never started.

    ``patience`` bounds the wait for media: under `Ice.REQUIRED` with every
    path blocked the library sets no timer, so the application gives up.
    ``dwell`` hangs up that long after media starts, for a peer that never
    sends "#" or hangs up itself.
    """
    print(f"answered {call.handle:x}")

    async def wait_for_media() -> None:
        while call.media is None and not call.ended:
            await call.events.get()

    try:
        if patience is not None:
            await asyncio.wait_for(wait_for_media(), timeout=patience)
        else:
            await wait_for_media()
    except TimeoutError:
        print(f"ended {call.handle:x}: no media within {patience}s -- no path was ever chosen")
        try:
            call.hangup()
        except SipralError:
            pass
        call.close()
        return False
    if call.media is None:
        print(f"ended {call.handle:x}: no media -- the call never connected")
        call.close()
        return False

    async def talk() -> None:
        while True:
            heard = await call.media.frames.get()
            call.media.send_audio(respond(heard))

    async def type_back() -> None:
        while True:
            typed = await call.text.get()
            print("text", repr(typed))
            call.send_text(typed)

    stats: dict[str, object] = {}

    async def poll_statistics() -> None:
        # Sampled periodically: after the call ends the stream may already
        # be gone (WRONG_STATE), so keep the last good reading.
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
                # One last read while the call is surely up.
                try:
                    stats = call.media.statistics()
                except SipralError:
                    pass
                call.hangup()
                return

    async def wait_for_remote_hangup() -> None:
        # The far end usually hangs up first.
        while not call.ended:
            await call.events.get()

    async def hang_up_after_dwell() -> None:
        nonlocal stats
        assert dwell is not None
        await asyncio.sleep(dwell)
        try:
            stats = call.media.statistics()
        except SipralError:
            pass
        call.hangup()
        # Polled: `wait_for_remote_hangup` may consume the CALL_ENDED event.
        while not call.ended:
            await asyncio.sleep(0.05)

    talking = asyncio.create_task(talk())
    typing = asyncio.create_task(type_back()) if call.text_address else None
    polling = asyncio.create_task(poll_statistics())
    hanging_up = asyncio.create_task(listen_for_hangup())
    ending = asyncio.create_task(wait_for_remote_hangup())
    waiting = {hanging_up, ending}
    dwelling = asyncio.create_task(hang_up_after_dwell()) if dwell is not None else None
    if dwelling is not None:
        waiting.add(dwelling)
    try:
        await asyncio.wait(waiting, return_when=asyncio.FIRST_COMPLETED)
    finally:
        talking.cancel()
        if typing is not None:
            typing.cancel()
        polling.cancel()
        hanging_up.cancel()
        ending.cancel()
        if dwelling is not None:
            dwelling.cancel()
        if call.ended:
            # The farewell (RTCP BYE, TURN Refresh) may be queued a poll
            # after CALL_ENDED and is dropped if the call is already closed.
            await asyncio.sleep(0.2)
        call.close()
        print(f"ended {call.handle:x}: {stats}")
    return True


def report_failure(task: asyncio.Task) -> None:
    """Print a call task's exception, which nobody awaits."""
    if not task.cancelled() and task.exception() is not None:
        print(f"call failed: {task.exception()!r}")


async def run_direct_call() -> bool:
    """Dial ``SIPRAL_PEER_HOST``/``SIPRAL_PEER_PORT`` directly, with an
    account that never registers (the lab's two-NAT pair).

    ``SIPRAL_STUN_SERVER`` turns on `Nat.STUN`; ``SIPRAL_TURN_SERVER``,
    ``SIPRAL_TURN_USER`` and ``SIPRAL_TURN_PASSWORD`` add TURN over
    ``SIPRAL_TURN_TRANSPORT`` (``udp``, ``tcp``, ``tls``; RFC 8656 Section
    3.1). TLS checks against ``SIPRAL_TURN_NAME``, trusting
    ``SIPRAL_TURN_CA`` or the platform roots. ``SIPRAL_ICE=required`` makes
    a pathless call fail instead of falling back to the bound address,
    which would let a blocked NAT pair pass by accident.
    """
    loop = asyncio.get_running_loop()
    peer_host = os.environ["SIPRAL_PEER_HOST"]
    peer_port = os.environ.get("SIPRAL_PEER_PORT", "5060")
    peer_user = os.environ.get("SIPRAL_PEER_USER", "callee")
    peer = f"{peer_host}:{peer_port}"
    host = route_to(peer)

    stun_server = os.environ.get("SIPRAL_STUN_SERVER")
    turn_server = os.environ.get("SIPRAL_TURN_SERVER")
    over = os.environ.get("SIPRAL_TURN_TRANSPORT", "udp")
    turn_transport = {"udp": 0, "tcp": Transport.TCP, "tls": Transport.TLS}[over]
    trusted = os.environ.get("SIPRAL_TURN_CA")
    stack = Stack(
        bind_host=host,
        loop=loop,
        audio=AudioMode.APPLICATION,
        nat=Nat.STUN if stun_server else 0,
        stun_server=stun_server,
        turn_server=turn_server,
        turn_username=os.environ.get("SIPRAL_TURN_USER"),
        turn_password=os.environ.get("SIPRAL_TURN_PASSWORD"),
        turn_transport=turn_transport,
        turn_server_name=os.environ.get("SIPRAL_TURN_NAME"),
        turn_tls_context=ssl.create_default_context(cafile=trusted) if trusted else None,
        ice=Ice.REQUIRED if os.environ.get("SIPRAL_ICE") == "required" else 0,
    )
    account = stack.add_account(
        f"sip:caller@{stack.bind_address}", registrar_address=peer
    )
    print(f"dialling sip:{peer_user}@{peer} from {stack.bind_address}")
    try:
        call = stack.place_call(
            account,
            f"sip:{peer_user}@{peer}",
            media_host=host,
            destination=peer,
        )
    except SipralError as error:
        print(f"call failed: {error!r}")
        stack.close()
        return False
    ok = await run_call(
        call,
        patience=int(os.environ.get("SIPRAL_PATIENCE_MS", "20000")) / 1000,
        dwell=int(os.environ.get("SIPRAL_DWELL_MS", "2000")) / 1000,
    )
    stack.close()
    if ok and turn_server and turn_transport:
        print(f"relay over {over.upper()} to {turn_server}: the call ran through it")
    return ok


async def main() -> None:
    # `SIPRAL_PEER_HOST` selects the direct-dial mode.
    if os.environ.get("SIPRAL_PEER_HOST"):
        if not await run_direct_call():
            raise SystemExit(1)
        return
    loop = asyncio.get_running_loop()
    registrar_address = os.environ["SIPRAL_REGISTRAR_ADDRESS"]
    host = route_to(registrar_address)
    over = os.environ.get("SIPRAL_SIGNALLING", "udp")
    signalling = {"udp": 0, "tcp": Transport.TCP, "tls": Transport.TLS}[over]
    trusted = os.environ.get("SIPRAL_TLS_CA")
    stack = Stack(
        loop=loop,
        bind_host=host,
        audio=AudioMode.APPLICATION,
        signalling=signalling,
        signalling_server=registrar_address if signalling else None,
        tls_server_name=os.environ.get("SIPRAL_TLS_SERVER_NAME"),
        tls_trust=TlsTrust.only_authority(trusted) if trusted else None,
        invite_limit=InviteLimit.VOICE_AGENT
        if os.environ.get("SIPRAL_INVITE_LIMIT") == "voice-agent"
        else None,
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
    if os.environ.get("SIPRAL_PRESENCE") == "1":
        account.publish_presence(Basic.OPEN, note="Agent ready")
    text = os.environ.get("SIPRAL_TEXT") == "1"

    print(f"listening on {stack.bind_address}")
    calls: set[asyncio.Task] = set()
    try:
        while True:
            event = await stack.events.get()
            if event.kind == EventKind.TRANSPORT_FAILED:
                fields = event.fields
                print(
                    f"transport failed error={TransportError(fields['error']).name.lower()} "
                    f"tls={TlsFailure(fields['tls']).name.lower()}: {fields['detail'] or ''}"
                )
            if event.kind == EventKind.REGISTRATION_CHANGED:
                print(f"registration {event.fields.get('state')}")
            if event.presence is not None:
                presence = event.presence
                print(
                    f"presence {presence.publication_state.name.lower()} "
                    f"status={presence.status_code}"
                )
            if event.kind == EventKind.INCOMING_CALL:
                call = stack.answer_call(event, media_host=host, text=text)
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
