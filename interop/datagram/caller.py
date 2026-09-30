# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""The caller `scripts/lab.sh datagram` runs against Asterisk.

One call from the Python layer, over UDP, to an extension Asterisk answers,
from an account that offers every SDES suite it names in ``SIPRAL_SUITES``
(a comma-separated list): four make an INVITE that, once it answers
Asterisk's challenge, is past RFC 3261 section 18.1.1's 1300 bytes.
``SIPRAL_DISPLAY_NAME``, when set, makes it larger still -- too large for a
datagram even with one suite, the case the offer cannot be trimmed out of.
Once answered the call is held and resumed, then hung up after
``SIPRAL_DWELL_MS``.

Environment: ``SIPRAL_AOR``, ``SIPRAL_AUTH_USER``, ``SIPRAL_AUTH_PASSWORD``,
``SIPRAL_SERVER`` (``host:port``, where the INVITE goes), ``SIPRAL_TARGET``.

Lines, one each, flushed as they happen, for the step to read:

    wanted <protocol> <destination> <request bytes> <limit bytes>
    transport failed <transport> <error>
    confirmed
    held
    resumed
    change failed <status>
    ended <end reason> <status> <cause sip> <cause text>
"""

from __future__ import annotations

import asyncio
import os
import socket

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode, CallEndReason, EventKind


def route_to(address: str) -> str:
    """The address of this host a datagram to ``address`` leaves from."""
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


async def main() -> None:
    server = os.environ["SIPRAL_SERVER"]
    suites = [suite for suite in os.environ.get("SIPRAL_SUITES", "").split(",") if suite]
    dwell = int(os.environ.get("SIPRAL_DWELL_MS", "2000")) / 1000
    patience = int(os.environ.get("SIPRAL_PATIENCE_MS", "20000")) / 1000
    stack = Stack(loop=asyncio.get_running_loop(), bind_host=route_to(server), audio=AudioMode.APPLICATION)
    try:
        account = stack.add_account(
            os.environ["SIPRAL_AOR"],
            registrar_address=server,
            display_name=os.environ.get("SIPRAL_DISPLAY_NAME") or None,
            auth_user=os.environ["SIPRAL_AUTH_USER"],
            auth_password=os.environ["SIPRAL_AUTH_PASSWORD"],
            srtp=lib.SIPRAL_SRTP_REQUIRED,
            srtp_suites=suites or None,
        )
        call = stack.place_call(account, os.environ["SIPRAL_TARGET"])
        async with asyncio.timeout(patience + dwell * 2):
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
                    await asyncio.sleep(dwell)
                    call.hold()
                elif event.kind == EventKind.SESSION_CHANGED and event.call == call.handle:
                    if fields["held_here"]:
                        print("held", flush=True)
                        call.resume()
                    else:
                        print("resumed", flush=True)
                        await asyncio.sleep(dwell)
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
        await asyncio.to_thread(stack.close)


if __name__ == "__main__":
    asyncio.run(main())
