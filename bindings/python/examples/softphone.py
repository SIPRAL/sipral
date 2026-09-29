#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""A softphone in a terminal, with no audio code of its own.

The library opens this machine's microphone and loudspeaker (device mode,
the default wherever it can) and pumps every call through them; what is left
here is what a person decides: which device does what, how loud, and whom
to call. Incoming calls are answered, and the caller shown as the network
asserted them when the registrar is a trusted peer.

    python3 softphone.py --devices
    SIPRAL_AOR=sip:alice@example.invalid \\
    SIPRAL_REGISTRAR=sip:example.invalid \\
    SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \\
    SIPRAL_AUTH_USER=alice SIPRAL_AUTH_PASSWORD=secret \\
    python3 softphone.py --speaker 4 --volume 0.8 sip:9008@example.invalid
"""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import socket

from sipral import Call, Stack, features
from sipral.enums import AudioDirection, AudioOrigin, AudioRole, EventKind, Feature


def route_to(address: str) -> str:
    """The address of this host a datagram to ``address`` leaves from."""
    host, _, port = address.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]


def dbfs(peak: int) -> float:
    """A meter reading as decibels below full scale."""
    return 20 * math.log10(peak / 32767) if peak else -math.inf


def list_devices(stack: Stack) -> None:
    for device in stack.audio.refresh():
        roles = []
        if device.is_microphone:
            roles.append("microphone" + (" (default)" if device.default_input else ""))
        if device.is_speaker:
            roles.append("speaker" + (" (default)" if device.default_output else ""))
        absent = "" if device.present else ", unplugged"
        print(f"{device.id:3}  {device.name}  [{', '.join(roles)}{absent}]")


async def meter(stack: Stack, call: Call) -> None:
    """One line a second: what the microphone and the loudspeaker carry."""
    while not call.ended:
        heard = dbfs(stack.audio.level(AudioDirection.OUTPUT))
        said = dbfs(stack.audio.level(AudioDirection.INPUT))
        print(f"  loudspeaker {heard:6.1f} dBFS   microphone {said:6.1f} dBFS")
        await asyncio.sleep(1)


async def talk(stack: Stack, call: Call, seconds: float | None) -> None:
    """The life of one call: the meter while it lasts, the hangup at the end."""
    watching = asyncio.create_task(meter(stack, call))
    try:
        async with asyncio.timeout(seconds):
            while not call.ended:
                event = await call.events.get()
                if event.kind == EventKind.CALL_ENDED:
                    cause = event.cause
                    print(f"ended{f' ({cause.text or cause.sip or cause.q850})' if cause else ''}")
    except TimeoutError:
        call.hangup()
    finally:
        watching.cancel()
        call.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("target", nargs="?", help="whom to call; left out, wait for a call")
    parser.add_argument("--devices", action="store_true", help="list the devices and stop")
    parser.add_argument("--microphone", type=int, help="the id of the microphone to use")
    parser.add_argument("--speaker", type=int, help="the id of the loudspeaker to use")
    parser.add_argument("--ringer", type=int, help="the id of the device that rings")
    parser.add_argument("--volume", type=float, default=1.0, help="1.0 is unity")
    parser.add_argument("--seconds", type=float, help="hang up after this long")
    options = parser.parse_args()

    if Feature.AUDIO_DEVICE not in features():
        raise SystemExit("this build of the library cannot open audio devices on this platform")

    registrar_address = os.environ.get("SIPRAL_REGISTRAR_ADDRESS", "127.0.0.1:5060")
    stack = Stack(loop=asyncio.get_running_loop(), bind_host=route_to(registrar_address))
    try:
        if options.devices:
            list_devices(stack)
            return
        for role, chosen in (
            (AudioRole.MICROPHONE, options.microphone),
            (AudioRole.SPEAKER, options.speaker),
            (AudioRole.RINGER, options.ringer),
        ):
            if chosen is not None:
                stack.audio.select(role, chosen)
        stack.audio.volume = options.volume

        registrar = os.environ.get("SIPRAL_REGISTRAR")
        account = stack.add_account(
            os.environ.get("SIPRAL_AOR", "sip:softphone@example.invalid"),
            registrar=registrar,
            registrar_address=registrar_address,
            auth_user=os.environ.get("SIPRAL_AUTH_USER"),
            auth_password=os.environ.get("SIPRAL_AUTH_PASSWORD"),
            trusted_peers=[registrar_address.rpartition(":")[0]],
        )
        if registrar:
            account.register()

        if options.target:
            print(f"calling {options.target}")
            await talk(stack, stack.place_call(account, options.target), options.seconds)
            return
        print(f"waiting for a call on {stack.bind_address}")
        while True:
            event = await stack.events.get()
            notice = event.audio
            if notice is not None and notice.origin == AudioOrigin.SYSTEM:
                print(f"devices: {notice.change.name.lower().replace('_', ' ')}")
            if event.kind == EventKind.INCOMING_CALL:
                identity = event.identity
                who = identity.asserted_display or identity.asserted_uri or event.fields["from_uri"]
                print(f"call from {who}{'' if identity.trusted else ' (not verified)'}")
                await talk(stack, stack.answer_call(event), options.seconds)
    finally:
        stack.close()


if __name__ == "__main__":
    asyncio.run(main())
