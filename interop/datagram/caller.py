# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The caller `scripts/lab.sh datagram` runs against Asterisk.

One call from the Python layer, over UDP, to an extension Asterisk answers,
from an account that offers every SDES suite it names in ``SIPRAL_SUITES``
(a comma-separated list): four make an INVITE that, once it answers
Asterisk's challenge, is past RFC 3261 section 18.1.1's 1300 bytes.
``SIPRAL_DISPLAY_NAME``, when set, makes it larger still -- too large for a
datagram even with one suite, the case the offer cannot be trimmed out of.
Once answered the call is held after ``SIPRAL_HOLD_AFTER_MS`` (by default
``SIPRAL_DWELL_MS``) and resumed, then hung up after ``SIPRAL_DWELL_MS``. A
hold well past the first keep-alive ping (20 to 25 seconds in) is what shows
a connection to a server that answers no ping outlives it. While the call is
up it sends a tone, so that an echo at the far end has something to send
back.

Environment: ``SIPRAL_AOR``, ``SIPRAL_AUTH_USER``, ``SIPRAL_AUTH_PASSWORD``,
``SIPRAL_SERVER`` (``host:port``, where the INVITE goes), ``SIPRAL_TARGET``.
``SIPRAL_SRTP=off`` places the call with no SDES at all, and
``SIPRAL_SRTP=best_effort`` offers SDES on plain ``RTP/AVP``, keyed when
the answer takes a key and plain when it takes none (required by default);
``SIPRAL_STREAM_FALLBACK=0`` turns the layer's stream fallback off, and
``SIPRAL_STREAM_SERVER`` (``host:port``) names where it connects, for a
server that takes TCP on another port than UDP. ``SIPRAL_UDP_ANYWAY_BYTES``
sends a request up to that many bytes over UDP when no stream is coming
(the stack's ``datagram_without_stream_bytes``).

``SIPRAL_SERVER_URI`` names the server by a URI for RFC 3263 to locate
instead (``SIPRAL_SERVER`` then only says which way this host's route
goes), and the call is placed once it is located; ``SIPRAL_SRV`` is one SRV
record, ``"<ttl> <priority> <weight> <port> <target>"``, a resolver of this
script's own answers every SRV query with, the platform's lookup answering
the rest. ``SIPRAL_REGISTER=1`` registers first, at ``SIPRAL_REGISTRAR``
or else the URI the server was named by, places the call once registered,
and takes the binding back at the end; ``SIPRAL_KEEPALIVE_MS`` is the account's own keep-alive
interval. ``SIPRAL_SIGNALLING=tls`` signals over TLS to ``SIPRAL_SERVER``,
trusting the one certificate whose SHA-256 fingerprint is
``SIPRAL_TLS_PIN``. ``SIPRAL_CODECS`` is the codecs to offer, in order
(``opus,PCMU,PCMA``); ``SIPRAL_DTMF`` digits sent as named events
``SIPRAL_DTMF_AFTER_MS`` (two seconds unless set) after the call is
confirmed, and every digit that comes back is printed.

Lines, one each, flushed as they happen, for the step to read:

    located <targets>
    locate failed <failure>
    registration <state>
    wanted <protocol> <destination> <request bytes> <limit bytes>
    transport failed <transport> <error>
    tls refused <failure>
    not placed <status>
    confirmed
    sent dtmf <digits>
    dtmf <digit>
    codec <codec>
    protection <key exchange> <encrypted|plain> <suite>
    media sent <packets> received <packets>
    held
    resumed
    change failed <status>
    ended <end reason> <status> <cause sip> <cause text>
"""

from __future__ import annotations

import asyncio
import math
import os
import socket

from sipral import Call, Stack
from sipral._sipral_cffi import lib
from sipral.enums import (
    AudioMode,
    CallEndReason,
    Codec,
    EventKind,
    LocateFailure,
    RegistrationState,
    SrtpSuite,
    TlsFailure,
    Transport,
)
from sipral.errors import SipralError
from sipral.locate import lookup
from sipral.signalling import TlsTrust

SRTP_POLICIES = {
    "off": lib.SIPRAL_SRTP_NOT_OFFERED,
    "best_effort": lib.SIPRAL_SRTP_BEST_EFFORT,
    "required": lib.SIPRAL_SRTP_REQUIRED,
}


def route_to(address: str) -> str:
    """The address of this host a datagram to ``address`` leaves from."""
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


def tone(samples: int, rate: int) -> bytes:
    """One frame of a 440 Hz tone at a quarter of full scale, 16-bit mono."""
    return b"".join(
        int(8192 * math.sin(2 * math.pi * 440 * n / rate)).to_bytes(2, "little", signed=True)
        for n in range(samples)
    )


async def talk(call: Call) -> None:
    """Send the tone for as long as the call has media, a frame for every
    frame the call plays."""
    while call.media is None and not call.ended:
        await asyncio.sleep(0.02)
    if call.media is None:
        return
    media = call.media
    frame = tone(media.frame_samples, media.frame_samples * 50)
    while not call.ended:
        await media.frames.get()
        try:
            media.send_audio(frame)
        except (SipralError, RuntimeError):
            return


def say_media(call: Call) -> None:
    """How many packets went each way so far, when the call has media."""
    if call.media is None:
        return
    try:
        stats = call.media.statistics()
    except SipralError:
        return
    print(f"media sent {stats['packets_sent']} received {stats['packets_received']}", flush=True)


async def listen(call: Call) -> None:
    """Every digit the far end sends, as it arrives."""
    while True:
        digit = await call.dtmf.get()
        print(f"dtmf {digit}", flush=True)


def say_protection(call: Call) -> None:
    """The codec the call settled on, and how its audio is protected, now:
    the key exchange, whether it is encrypted, and the suite that runs."""
    if call.media is None:
        return
    try:
        codec = Codec(call.media.statistics()["codec"]).name
        report = call.media.encryption()
    except SipralError:
        return
    print(f"codec {codec}", flush=True)
    for stream in report:
        suite = SrtpSuite(stream.suite).name if stream.suite else "-"
        state = "encrypted" if stream.encrypted else "plain"
        print(f"protection {stream.key_exchange.name} {state} {suite}", flush=True)


def say_transport_failed(fields: dict) -> None:
    """A transport the stack lost or could not have, and, for TLS, why the
    certificate was refused."""
    print(f"transport failed {fields['transport']} {fields['error']}", flush=True)
    if fields.get("tls"):
        print(f"tls refused {TlsFailure(fields['tls']).name}", flush=True)


async def say_transport(stack: Stack) -> None:
    """What the stack said about its transports in the next few seconds:
    the reason a call could not be placed is reported as an event, not in
    the refusal itself."""
    try:
        async with asyncio.timeout(3):
            while True:
                event = await stack.events.get()
                if event.kind == EventKind.TRANSPORT_FAILED:
                    say_transport_failed(event.fields)
    except TimeoutError:
        return


def resolver_answering_srv(record: str):
    """A resolver that answers every SRV query with ``record`` and leaves
    every other query to the platform's lookup: an application's own, the
    way one that reads SRV is given to the stack."""

    def resolve(name: str, kind: int) -> tuple[int, list[str]]:
        if kind == lib.SIPRAL_DNS_RECORD_TYPE_SRV:
            return lib.SIPRAL_DNS_ANSWER_RECORDS, [record]
        return lookup(name, kind)

    return resolve


async def main() -> None:
    server = os.environ["SIPRAL_SERVER"]
    server_uri = os.environ.get("SIPRAL_SERVER_URI") or None
    srv = os.environ.get("SIPRAL_SRV") or None
    suites = [suite for suite in os.environ.get("SIPRAL_SUITES", "").split(",") if suite]
    dwell = int(os.environ.get("SIPRAL_DWELL_MS", "2000")) / 1000
    hold_after = int(os.environ.get("SIPRAL_HOLD_AFTER_MS", "0")) / 1000 or dwell
    patience = int(os.environ.get("SIPRAL_PATIENCE_MS", "20000")) / 1000
    tls = os.environ.get("SIPRAL_SIGNALLING") == "tls"
    pin = os.environ.get("SIPRAL_TLS_PIN")
    stack = Stack(
        loop=asyncio.get_running_loop(),
        bind_host=route_to(server),
        audio=AudioMode.APPLICATION,
        codecs=os.environ.get("SIPRAL_CODECS") or None,
        stream_fallback=os.environ.get("SIPRAL_STREAM_FALLBACK", "1") != "0",
        stream_server=os.environ.get("SIPRAL_STREAM_SERVER") or None,
        datagram_without_stream_bytes=int(os.environ.get("SIPRAL_UDP_ANYWAY_BYTES", "0")),
        signalling=Transport.TLS if tls else 0,
        signalling_server=server if tls else None,
        tls_trust=TlsTrust.pinned(pin) if tls and pin else None,
        resolver=resolver_answering_srv(srv) if srv else None,
    )
    policy = os.environ.get("SIPRAL_SRTP", "required")
    plain = policy == "off"
    register = os.environ.get("SIPRAL_REGISTER") == "1"
    digits = os.environ.get("SIPRAL_DTMF") or ""
    digits_after = int(os.environ.get("SIPRAL_DTMF_AFTER_MS", "2000")) / 1000 if digits else 0
    tasks: list[asyncio.Task] = []
    account = None

    async def dial() -> Call | None:
        try:
            placed = stack.place_call(account, os.environ["SIPRAL_TARGET"])
        except SipralError as error:
            # a connection refused before the call is a call nobody can
            # place: say so, and what the transport said about it
            print(f"not placed {error.status_name}", flush=True)
            await say_transport(stack)
            return None
        tasks.append(asyncio.create_task(talk(placed)))
        tasks.append(asyncio.create_task(listen(placed)))
        return placed

    try:
        account = stack.add_account(
            os.environ["SIPRAL_AOR"],
            registrar_address=None if server_uri else server,
            server_uri=server_uri,
            registrar=(os.environ.get("SIPRAL_REGISTRAR") or server_uri) if register else None,
            keepalive_ms=int(os.environ.get("SIPRAL_KEEPALIVE_MS", "0")),
            display_name=os.environ.get("SIPRAL_DISPLAY_NAME") or None,
            auth_user=os.environ["SIPRAL_AUTH_USER"],
            auth_password=os.environ["SIPRAL_AUTH_PASSWORD"],
            srtp=SRTP_POLICIES[policy],
            srtp_suites=None if plain else suites or None,
        )
        if register:
            account.register()
        call = None
        if not register and not server_uri:
            call = await dial()
            if call is None:
                return
        async with asyncio.timeout(patience + digits_after + hold_after + dwell):
            while True:
                event = await stack.events.get()
                fields = event.fields
                if event.kind == EventKind.LOCATED:
                    print(f"located {fields['targets']}", flush=True)
                    if call is None and not register:
                        call = await dial()
                        if call is None:
                            return
                elif event.kind == EventKind.LOCATE_FAILED:
                    print(f"locate failed {LocateFailure(fields['failure']).name}", flush=True)
                    return
                elif event.kind == EventKind.REGISTRATION_CHANGED:
                    state = RegistrationState(fields["state"])
                    print(f"registration {state.name}", flush=True)
                    if call is None and state == RegistrationState.REGISTERED:
                        call = await dial()
                        if call is None:
                            return
                    elif call is None and state == RegistrationState.FAILED:
                        return
                elif event.kind == EventKind.TRANSPORT_WANTED:
                    print(
                        f"wanted {fields['protocol']} {fields['destination']} "
                        f"{fields['request_bytes']} {fields['limit_bytes']}",
                        flush=True,
                    )
                elif event.kind == EventKind.TRANSPORT_FAILED:
                    say_transport_failed(fields)
                elif call is None:
                    continue
                elif event.kind == EventKind.CALL_CONFIRMED and event.call == call.handle:
                    print("confirmed", flush=True)
                    if digits:
                        await asyncio.sleep(digits_after)
                        call.send_dtmf(digits)
                        print(f"sent dtmf {digits}", flush=True)
                    await asyncio.sleep(hold_after)
                    say_protection(call)
                    say_media(call)
                    call.hold()
                elif event.kind == EventKind.SESSION_CHANGED and event.call == call.handle:
                    if fields["held_here"]:
                        print("held", flush=True)
                        call.resume()
                    else:
                        print("resumed", flush=True)
                        await asyncio.sleep(dwell)
                        say_media(call)
                        call.hangup()
                elif event.kind == EventKind.SESSION_CHANGE_FAILED and event.call == call.handle:
                    print(f"change failed {fields['status_code']}", flush=True)
                    call.hangup()
                elif event.kind == EventKind.CALL_ENDED and event.call == call.handle:
                    cause = event.cause
                    print(
                        f"ended {CallEndReason(fields['end_reason']).name} {fields['status_code']} "
                        f"{cause.sip if cause else 0} {cause.text if cause and cause.text else '-'}",
                        flush=True,
                    )
                    return
    except TimeoutError:
        print("timed out", flush=True)
    finally:
        for task in tasks:
            task.cancel()
        if account is not None and register:
            await unregister(stack, account)
        await asyncio.to_thread(stack.close)


async def unregister(stack: Stack, account) -> None:
    """Take the binding back, and wait a few seconds for the registrar to
    say so, so that nothing is left registered behind the run."""
    try:
        account.unregister()
    except SipralError:
        return
    try:
        async with asyncio.timeout(5):
            while True:
                event = await stack.events.get()
                if event.kind != EventKind.REGISTRATION_CHANGED:
                    continue
                state = RegistrationState(event.fields["state"])
                print(f"registration {state.name}", flush=True)
                if state in (RegistrationState.UNREGISTERED, RegistrationState.FAILED):
                    return
    except TimeoutError:
        print("no answer to the unregister", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
