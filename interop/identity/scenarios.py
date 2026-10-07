# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Who a call says it is from, and where it was sent: `scripts/lab.sh
identity` runs this against Asterisk.

One Python ``Stack``, two accounts registered at Asterisk
(``interop/asterisk/pjsip.conf``'s ``labuser-caller`` and
``labuser-callee``), each trusting Asterisk's address as RFC 3325's trust
domain. Then three calls from the first, each to a number of
``interop/asterisk/extensions.conf``:

- 9040, which dials the second account. The INVITE carries a
  `P-Asserted-Identity` the caller wrote, for a number no account has;
  Asterisk takes it as the caller's identity (``trust_id_inbound``) and
  asserts it again toward the callee (``send_pai``), whose stack reads it
  because it came from a peer it trusts. Sent and received, in one call.
- 9041, which marks the call diverted from 9041 for no answer before it
  dials the second account; Asterisk writes that as a `Diversion` (RFC 5806)
  the callee reads.
- 9042, which answers 302 with a `Contact` naming 9002, the cadenced tone.
  Nothing else answers 9042: the call coming up at all, with audio, is this
  stack having followed the redirect (RFC 3261 §8.1.3.4).

Environment: ``SIPRAL_SERVER`` (``host:port`` of Asterisk),
``SIPRAL_PASSWORD``, ``SIPRAL_DWELL_MS``, ``SIPRAL_PATIENCE_MS``.

Lines, one each, flushed as they happen, for the step to read:

    registered <account>
    incoming <number> trusted=<0|1> asserted=<uri> display=<name>
    incoming <number> diverted=<uri> reason=<reason> count=<n>
    confirmed <number>
    media <number> sent <packets> received <packets>
    media <number> callee sent <packets> received <packets>
    ended <number> <end reason> <status>
    timed out

The two ends of 9040 and 9041 are both this stack's, and Asterisk hands
their media to each other once the call is answered (``direct_media``, on
by default): audio counted at both ends is the stack following a re-INVITE
that moved its far end to another sender.
"""

from __future__ import annotations

import asyncio
import math
import os
import socket

from sipral import Call, Stack
from sipral.enums import AudioMode, CallEndReason, EventKind, RegistrationState
from sipral.errors import SipralError

ASSERTED = '"Lab Asserted" <sip:5550100@asterisk>'


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
    """Send the tone for as long as the call has media."""
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


async def main() -> None:
    server = os.environ["SIPRAL_SERVER"]
    host = server.rpartition(":")[0]
    password = os.environ.get("SIPRAL_PASSWORD", "labpass")
    dwell = int(os.environ.get("SIPRAL_DWELL_MS", "2000")) / 1000
    patience = int(os.environ.get("SIPRAL_PATIENCE_MS", "20000")) / 1000
    stack = Stack(
        loop=asyncio.get_running_loop(),
        bind_host=route_to(server),
        audio=AudioMode.APPLICATION,
    )
    accounts = {}
    for name in ("labuser-caller", "labuser-callee"):
        accounts[name] = stack.add_account(
            f"sip:{name}@asterisk",
            registrar="sip:asterisk",
            registrar_address=server,
            auth_user=name,
            auth_password=password,
            trusted_peers=[host],
        )
    by_handle = {account.handle: name for name, account in accounts.items()}
    tasks: list[asyncio.Task] = []
    try:
        for account in accounts.values():
            account.register()
        registered: set[str] = set()
        async with asyncio.timeout(patience):
            while len(registered) < len(accounts):
                event = await stack.events.get()
                if event.kind != EventKind.REGISTRATION_CHANGED:
                    continue
                state = RegistrationState(event.fields["state"])
                name = by_handle.get(event.account, "?")
                if state == RegistrationState.REGISTERED and name not in registered:
                    registered.add(name)
                    print(f"registered {name}", flush=True)
                elif state == RegistrationState.FAILED:
                    print(f"registration {name} {state.name}", flush=True)
                    return

        asserting = [("P-Asserted-Identity", ASSERTED)]
        for number, headers in (("9040", asserting), ("9041", None), ("9042", None)):
            await one_call(stack, accounts["labuser-caller"], number, headers, dwell, patience, tasks)
    except TimeoutError:
        print("timed out", flush=True)
    finally:
        for task in tasks:
            task.cancel()
        for account in accounts.values():
            try:
                account.unregister()
            except SipralError:
                pass
        await asyncio.sleep(1)
        await asyncio.to_thread(stack.close)


def say_media(label: str, call: Call) -> None:
    """How many packets went each way on ``call`` so far."""
    if call.media is None:
        print(f"media {label} none", flush=True)
        return
    stats = call.media.statistics()
    print(
        f"media {label} sent {stats['packets_sent']} received {stats['packets_received']}",
        flush=True,
    )


async def one_call(
    stack: Stack, caller, number: str, headers, dwell: float, patience: float, tasks
) -> None:
    """Place one call to ``number``, answer whatever reaches the callee,
    and hang up from the calling end once the call has been up for
    ``dwell``."""
    call = stack.place_call(caller, f"sip:{number}@asterisk", headers=headers)
    tasks.append(asyncio.create_task(talk(call)))
    answered: list[Call] = []
    async with asyncio.timeout(patience + dwell):
        while True:
            event = await stack.events.get()
            fields = event.fields
            if event.kind == EventKind.INCOMING_CALL:
                identity = event.identity
                print(
                    f"incoming {number} trusted={int(identity.trusted)} "
                    f"asserted={identity.asserted_uri or '-'} "
                    f"display={identity.asserted_display or '-'}",
                    flush=True,
                )
                print(
                    f"incoming {number} diverted={identity.diverted_from or '-'} "
                    f"reason={identity.diversion_reason or '-'} "
                    f"count={identity.diversion_count}",
                    flush=True,
                )
                taken = stack.answer_call(event)
                answered.append(taken)
                tasks.append(asyncio.create_task(talk(taken)))
            elif event.kind == EventKind.CALL_CONFIRMED and event.call == call.handle:
                print(f"confirmed {number}", flush=True)
                await asyncio.sleep(dwell)
                say_media(f"{number}", call)
                for taken in answered:
                    say_media(f"{number} callee", taken)
                call.hangup()
            elif event.kind == EventKind.CALL_ENDED and event.call == call.handle:
                print(
                    f"ended {number} {CallEndReason(fields['end_reason']).name} "
                    f"{fields['status_code']}",
                    flush=True,
                )
                # the callee's half ends with it; give its BYE a moment
                await asyncio.sleep(0.5)
                return


if __name__ == "__main__":
    asyncio.run(main())
