# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""Two lines in one stack: one account on the stack's UDP socket, one on a
TLS connection of its own, each to a server of its own.

What a softphone with a desk line on the office PBX and a second line at a
provider that takes only TLS does: one Python ``Stack`` signalling over UDP,
an account added as usual for the first line, and one added with
``stream_protocol=Transport.TLS`` and the server's certificate pinned by its
SHA-256 fingerprint (``tls_pin``) for the second. Both register and have to
be registered at once; then a call is placed on each, both up together,
each sending a tone a frame for every frame it plays, and after
``SIPRAL_DWELL_MS`` both are hung up and both bindings taken back.

Environment, for each line ``UDP`` and ``TLS``: ``SIPRAL_<LINE>_AOR``,
``SIPRAL_<LINE>_USER``, ``SIPRAL_<LINE>_PASSWORD``, ``SIPRAL_<LINE>_SERVER``
(``host:port``, its registrar and proxy) and ``SIPRAL_<LINE>_TARGET`` (the
URI its call goes to); ``SIPRAL_TLS_PIN`` the fingerprint the TLS line's
server is held to. ``SIPRAL_SRTP`` is ``off`` (the default) or
``best_effort``, for both lines. ``SIPRAL_ECHO_KEY``, when set, is sent as
a named event on each call once it is confirmed: the key that starts an
echo a PBX plays a prompt in front of.

Lines, one each, flushed as they happen, each but the last two naming its
line first:

    <line> registration <state>
    <line> transport failed <transport> <error>
    <line> tls refused <failure>
    <line> confirmed
    <line> media sent <packets> received <packets> audible <frames>
    <line> ended <end reason> <status>
    both registered
    both up
"""

from __future__ import annotations

import asyncio
import math
import os
import socket
import struct

from sipral import Call, Stack
from sipral._sipral_cffi import lib
from sipral.enums import (
    AudioMode,
    CallEndReason,
    EventKind,
    RegistrationState,
    TlsFailure,
    Transport,
)
from sipral.errors import SipralError

LINES = ("udp", "tls")

SRTP_POLICIES = {
    "off": lib.SIPRAL_SRTP_NOT_OFFERED,
    "best_effort": lib.SIPRAL_SRTP_BEST_EFFORT,
}

#: A frame whose loudest sample reaches this is the far end's audio rather
#: than silence or concealment.
AUDIBLE = 1000


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


def registrar_of(aor: str) -> str:
    """The registrar's URI: the address-of-record's own domain."""
    return "sip:" + aor.rpartition("@")[2]


def setting(line: str, name: str) -> str:
    return os.environ[f"SIPRAL_{line.upper()}_{name}"]


class Line:
    """One account and the call placed on it."""

    def __init__(self, name: str, account) -> None:
        self.name = name
        self.account = account
        self.state = RegistrationState.UNREGISTERED
        self.call: Call | None = None
        self.confirmed = False
        self.ended = False
        self.audible = 0
        self.talking: asyncio.Task | None = None

    def say(self, text: str) -> None:
        print(f"{self.name} {text}", flush=True)

    async def talk(self) -> None:
        """Send the tone for as long as the call has media, a frame for
        every frame it plays, and count the frames that were audible."""
        call = self.call
        while call is not None and call.media is None and not call.ended:
            await asyncio.sleep(0.02)
        if call is None or call.media is None:
            return
        media = call.media
        frame = tone(media.frame_samples, media.frame_samples * 50)
        while not call.ended:
            played = await media.frames.get()
            samples = struct.unpack(f"<{len(played) // 2}h", played)
            if samples and max(abs(sample) for sample in samples) >= AUDIBLE:
                self.audible += 1
            try:
                media.send_audio(frame)
            except (SipralError, RuntimeError):
                return

    def say_media(self) -> None:
        if self.call is None or self.call.media is None:
            return
        try:
            stats = self.call.media.statistics()
        except SipralError:
            return
        self.say(
            f"media sent {stats['packets_sent']} received {stats['packets_received']} "
            f"audible {self.audible}"
        )


async def main() -> None:
    dwell = int(os.environ.get("SIPRAL_DWELL_MS", "8000")) / 1000
    patience = int(os.environ.get("SIPRAL_PATIENCE_MS", "30000")) / 1000
    srtp = SRTP_POLICIES[os.environ.get("SIPRAL_SRTP", "off")]
    stack = Stack(
        loop=asyncio.get_running_loop(),
        bind_host=route_to(setting("udp", "SERVER")),
        audio=AudioMode.APPLICATION,
    )
    lines: dict[str, Line] = {}
    try:
        lines["udp"] = Line(
            "udp",
            stack.add_account(
                setting("udp", "AOR"),
                registrar=registrar_of(setting("udp", "AOR")),
                registrar_address=setting("udp", "SERVER"),
                auth_user=setting("udp", "USER"),
                auth_password=setting("udp", "PASSWORD"),
                srtp=srtp,
            ),
        )
        lines["tls"] = Line(
            "tls",
            stack.add_account(
                setting("tls", "AOR"),
                registrar=registrar_of(setting("tls", "AOR")),
                registrar_address=setting("tls", "SERVER"),
                auth_user=setting("tls", "USER"),
                auth_password=setting("tls", "PASSWORD"),
                tls_pin=os.environ["SIPRAL_TLS_PIN"],
                stream_protocol=Transport.TLS,
                srtp=srtp,
            ),
        )
        by_account = {line.account.handle: line for line in lines.values()}
        by_call: dict[int, Line] = {}
        for line in lines.values():
            line.account.register()
        hung_up = False
        async with asyncio.timeout(patience + dwell):
            while not all(line.ended for line in lines.values()):
                event = await stack.events.get()
                fields = event.fields
                if event.kind == EventKind.REGISTRATION_CHANGED:
                    line = by_account.get(event.account)
                    if line is None:
                        continue
                    line.state = RegistrationState(fields["state"])
                    line.say(f"registration {line.state.name}")
                    if line.state == RegistrationState.FAILED:
                        return
                    if all(one.state == RegistrationState.REGISTERED for one in lines.values()) and all(
                        one.call is None for one in lines.values()
                    ):
                        print("both registered", flush=True)
                        for one in lines.values():
                            one.call = stack.place_call(one.account, setting(one.name, "TARGET"))
                            by_call[one.call.handle] = one
                            one.talking = asyncio.create_task(one.talk())
                elif event.kind == EventKind.TRANSPORT_FAILED:
                    print(f"transport failed {fields['transport']} {fields['error']}", flush=True)
                    if fields.get("tls"):
                        lines["tls"].say(f"tls refused {TlsFailure(fields['tls']).name}")
                elif event.kind == EventKind.CALL_CONFIRMED and event.call in by_call:
                    line = by_call[event.call]
                    line.confirmed = True
                    line.say("confirmed")
                    if os.environ.get("SIPRAL_ECHO_KEY"):
                        # an echo behind a prompt starts on a key
                        line.call.send_dtmf(os.environ["SIPRAL_ECHO_KEY"])
                    if all(one.confirmed and not one.ended for one in lines.values()) and not hung_up:
                        print("both up", flush=True)
                        await asyncio.sleep(dwell)
                        hung_up = True
                        for one in lines.values():
                            one.say_media()
                            one.call.hangup()
                elif event.kind == EventKind.CALL_ENDED and event.call in by_call:
                    line = by_call[event.call]
                    line.ended = True
                    line.say(f"ended {CallEndReason(fields['end_reason']).name} {fields['status_code']}")
                    if not hung_up:
                        for one in lines.values():
                            if one is not line and one.call is not None and not one.ended:
                                one.say_media()
                                one.call.hangup()
                        hung_up = True
    except TimeoutError:
        print("timed out", flush=True)
    finally:
        for line in lines.values():
            if line.talking is not None:
                line.talking.cancel()
        await unregister(stack, list(lines.values()))
        await asyncio.to_thread(stack.close)


async def unregister(stack: Stack, lines: list[Line]) -> None:
    """Take every binding back, and wait a few seconds for the registrars to
    say so, so that nothing is left registered behind the run."""
    waiting = {}
    for line in lines:
        try:
            line.account.unregister()
            waiting[line.account.handle] = line
        except SipralError:
            continue
    try:
        async with asyncio.timeout(6):
            while waiting:
                event = await stack.events.get()
                if event.kind != EventKind.REGISTRATION_CHANGED or event.account not in waiting:
                    continue
                state = RegistrationState(event.fields["state"])
                line = waiting[event.account]
                line.say(f"registration {state.name}")
                if state in (RegistrationState.UNREGISTERED, RegistrationState.FAILED):
                    del waiting[event.account]
    except TimeoutError:
        print("no answer to the unregister", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
