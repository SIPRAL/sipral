#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A headless voice agent: answers, listens, talks back, hangs up on "#".

Wires any model in through one function, ``respond``, which takes one
frame of 16-bit mono PCM and returns one back -- an echo by default, so
this runs with nothing else installed. A real agent replaces ``respond``
with a call into whatever transcribes, thinks and synthesizes; nothing
else here changes; a large recorded reply crosses just as well as a frame
at a time by queuing several calls to ``call.media.send_audio``.

The one example here that handles frames itself, because a voice agent's
frames are its whole job: it creates its stack with
``audio=AudioMode.APPLICATION``, which is also what a machine with no sound
device runs. A phone that a person talks into lets the library open the
devices instead -- see ``softphone.py``, which has no audio code at all.

    SIPRAL_AOR=sip:agent@example.invalid \\
    SIPRAL_REGISTRAR=sip:example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=secret \\
    python3 agent.py

``SIPRAL_SIGNALLING`` is ``udp`` (the default), ``tcp`` or ``tls``: over
either of the last two the agent keeps one connection to
``SIPRAL_REGISTRAR_ADDRESS`` and signals on it, and over TLS checks the
server's certificate against ``SIPRAL_TLS_SERVER_NAME`` (the address's host
when unset) with ``SIPRAL_TLS_CA`` as the only authority it trusts (the
platform's when unset). A connection that fails is printed as
``transport failed error=<...> tls=<...>`` with the TLS library's words, and
tried again. ``SIPRAL_INVITE_LIMIT=voice-agent`` takes a trunk's rush of
calls the default rate floor would answer 480.

``SIPRAL_TEXT=1`` answers every call with a real-time text stream beside
the audio (RFC 4103) where the caller offered one, and types back whatever
the caller types. ``SIPRAL_PRESENCE=1`` publishes the agent as open, "Agent
ready", once it starts (RFC 3903), and prints what the compositor made of it.
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


async def run_call(
    call: Call, *, patience: float | None = None, dwell: float | None = None
) -> bool:
    """Talk for the life of one call. `False` when it ended before its
    media ever started -- the lab's own TURN-blocked run
    (`run_direct_call`) needs to tell that apart from an ordinary hangup
    rather than wait here forever for a `Media` that is never coming, and
    ``patience`` is what stops that wait itself running forever: a call
    under `Ice.REQUIRED` with every path blocked is not refused by the
    library on any timer of its own -- `IceRequired` is only for a peer
    that answered with no ICE attributes at all -- so the application is
    what has to give up.

    ``dwell``, given only by `run_direct_call`, is how long this end
    waits once media has started before it hangs up on its own: the
    peer there is a lab harness with nothing of its own that would ever
    send "#" or hang up first, unlike the far end `respond` is written
    against, which always does one or the other.
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

    async def hang_up_after_dwell() -> None:
        nonlocal stats
        assert dwell is not None
        await asyncio.sleep(dwell)
        try:
            stats = call.media.statistics()
        except SipralError:
            pass
        call.hangup()
        # Polled rather than read off `call.events`:
        # `wait_for_remote_hangup` reads that same queue concurrently, and
        # the one `CALL_ENDED` on it is only ever delivered to whichever
        # of the two calls `get()` first.
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
            # A relayed call's farewell -- the TURN Refresh that gives its
            # allocation back, not only the RTCP BYE -- can be queued a
            # poll after `CALL_ENDED` (`Stack._drain_farewells`, on the poll
            # thread), and one that finds the call already closed is
            # dropped. Waited out here, where every way the call ends
            # passes: `wait_for_remote_hangup` sees the end of a call this
            # end hung up as soon as the dwell does, and wins as often.
            # `Stack.close`'s own docstring gives the same reasoning for
            # the same sleep.
            await asyncio.sleep(0.2)
        call.close()
        print(f"ended {call.handle:x}: {stats}")
    return True


def report_failure(task: asyncio.Task) -> None:
    """Say why a call's task ended, if it ended by raising.

    An exception in a task nobody awaits is otherwise only mentioned when
    the task is garbage collected, which for a process that is stopped
    rather than left to exit is never.
    """
    if not task.cancelled() and task.exception() is not None:
        print(f"call failed: {task.exception()!r}")


async def run_direct_call() -> bool:
    """Dial a peer straight at its address, no registrar between them --
    the lab's own two-NAT pair (`scripts/lab.sh`'s ``ice_turn_flow``),
    where the far end is the harness's own ``iceanswer`` role rather
    than a server. ``SIPRAL_PEER_HOST``/``SIPRAL_PEER_PORT`` name it, and
    the account this end adds is one `Account.add`'s own docstring
    describes: "an account that never registers", ``registrar`` left
    unset so `sipral_account_config_t::registrar_len` is zero.

    ``SIPRAL_STUN_SERVER`` turns on `Nat.STUN` the same way
    :class:`sipral.stack.Stack` already offers any application;
    ``SIPRAL_TURN_SERVER``/``SIPRAL_TURN_USER``/``SIPRAL_TURN_PASSWORD``
    ride on it. ``SIPRAL_TURN_TRANSPORT`` is ``udp``, ``tcp`` or ``tls``
    (RFC 8656 Section 3.1); over TLS the server's certificate is checked
    against ``SIPRAL_TURN_NAME`` and trusted if it chains to the PEM file
    ``SIPRAL_TURN_CA`` names, the platform's roots otherwise -- the lab's
    own coturn presents a certificate made for the run, and this is how the
    run tells the agent to trust it. ``SIPRAL_ICE=required`` asks `Ice.REQUIRED` of every
    call this account places, which is what makes a call that cannot
    find a path fail outright rather than fall back to the address this
    end bound to -- the one thing that would let a run through a blocked
    NAT pair pass by accident.
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
        # the relay was made and given back on its connection, as the
        # server's own log shows; this is what the agent itself saw
        print(f"relay over {over.upper()} to {turn_server}: the call ran through it")
    return ok


async def main() -> None:
    # The lab's own NAT-pair flow (`ice_turn_flow`) runs this mode instead
    # of the registrar-and-listen one below: `SIPRAL_PEER_HOST` is what
    # tells the two apart, since a real registrar address never doubles
    # as one.
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
