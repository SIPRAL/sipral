# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

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
``SIPRAL_SRTP=off`` places the call with no SDES at all (required by
default); ``SIPRAL_STREAM_FALLBACK=0`` turns the layer's stream fallback off,
and ``SIPRAL_STREAM_SERVER`` (``host:port``) names where it connects, for a
server that takes TCP on another port than UDP.

Lines, one each, flushed as they happen, for the step to read:

    wanted <protocol> <destination> <request bytes> <limit bytes>
    transport failed <transport> <error>
    confirmed
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
from sipral.enums import AudioMode, CallEndReason, EventKind
from sipral.errors import SipralError


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


async def main() -> None:
    server = os.environ["SIPRAL_SERVER"]
    suites = [suite for suite in os.environ.get("SIPRAL_SUITES", "").split(",") if suite]
    dwell = int(os.environ.get("SIPRAL_DWELL_MS", "2000")) / 1000
    hold_after = int(os.environ.get("SIPRAL_HOLD_AFTER_MS", "0")) / 1000 or dwell
    patience = int(os.environ.get("SIPRAL_PATIENCE_MS", "20000")) / 1000
    stack = Stack(
        loop=asyncio.get_running_loop(),
        bind_host=route_to(server),
        audio=AudioMode.APPLICATION,
        stream_fallback=os.environ.get("SIPRAL_STREAM_FALLBACK", "1") != "0",
        stream_server=os.environ.get("SIPRAL_STREAM_SERVER") or None,
    )
    plain = os.environ.get("SIPRAL_SRTP") == "off"
    talking = None
    try:
        account = stack.add_account(
            os.environ["SIPRAL_AOR"],
            registrar_address=server,
            display_name=os.environ.get("SIPRAL_DISPLAY_NAME") or None,
            auth_user=os.environ["SIPRAL_AUTH_USER"],
            auth_password=os.environ["SIPRAL_AUTH_PASSWORD"],
            srtp=lib.SIPRAL_SRTP_NOT_OFFERED if plain else lib.SIPRAL_SRTP_REQUIRED,
            srtp_suites=None if plain else suites or None,
        )
        call = stack.place_call(account, os.environ["SIPRAL_TARGET"])
        talking = asyncio.create_task(talk(call))
        async with asyncio.timeout(patience + hold_after + dwell):
            while True:
                event = await stack.events.get()
                fields = event.fields
                if event.kind == EventKind.TRANSPORT_WANTED:
                    print(
                        f"wanted {fields['protocol']} {fields['destination']} "
                        f"{fields['request_bytes']} {fields['limit_bytes']}",
                        flush=True,
                    )
                elif event.kind == EventKind.TRANSPORT_FAILED:
                    print(f"transport failed {fields['transport']} {fields['error']}", flush=True)
                elif event.kind == EventKind.CALL_CONFIRMED and event.call == call.handle:
                    print("confirmed", flush=True)
                    await asyncio.sleep(hold_after)
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
    finally:
        if talking is not None:
            talking.cancel()
        await asyncio.to_thread(stack.close)


if __name__ == "__main__":
    asyncio.run(main())
