# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The message hook on the wire: the Python layer registers at Asterisk with
a hook that adds a header to every request it sends, changes another's value
and takes a third away, and reads the answers before the stack does.

scripts/lab.sh's `hook` step runs it in a container beside Asterisk, with
Asterisk's own message log on, and reads both: what this prints, and the
REGISTER Asterisk received.

    SIPRAL_AOR=sip:labuser-agent@asterisk SIPRAL_REGISTRAR=sip:asterisk \\
    SIPRAL_REGISTRAR_ADDRESS=172.18.0.2:5060 \\
    SIPRAL_AUTH_USER=labuser-agent SIPRAL_AUTH_PASSWORD=labpass \\
    python3 hooked.py

Prints one line for each request it changed and each answer it read, then
``registered`` and ``unregistered``; exits 0 when both came, 2 otherwise.
"""

from __future__ import annotations

import asyncio
import os
import socket

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode, EventKind


def route_to(address: str) -> str:
    """The local address the system routes toward ``address``."""
    host, _, port = address.rpartition(":")
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, int(port)))
        return probe.getsockname()[0]
    finally:
        probe.close()


def rewritten(message: bytes) -> tuple[bytes, str]:
    """``message`` with `X-Lab-Hook: added`, `Max-Forwards: 42`, and its
    `Expires` taken away unless it is zero, which the registrar then fills
    with its own default (RFC 3261 Section 10.2.1.1), a removal asking for
    zero being left whole; and the name of the field taken away, if any."""
    head, _, body = message.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    kept = [lines[0]]
    removed = "nothing"
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        name = name.strip().lower()
        if name == b"expires" and value.strip() != b"0":
            removed = "Expires"
            continue
        if name == b"max-forwards":
            line = b"Max-Forwards: 42"
        kept.append(line)
    kept.append(b"X-Lab-Hook: added")
    return b"\r\n".join(kept) + b"\r\n\r\n" + body, removed


def hook(outgoing: bool, message: bytes, _remote: str):
    start = message.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    if outgoing and not message.startswith(b"SIP/2.0 "):
        replacement, removed = rewritten(message)
        print(f"out {start.split(' ')[0]} rewritten, {removed} taken away")
        return replacement
    if not outgoing and message.startswith(b"SIP/2.0 ") and b" REGISTER\r\n" in message:
        print(f"in {start}")
    return None


async def main() -> int:
    registrar_address = os.environ["SIPRAL_REGISTRAR_ADDRESS"]
    stack = Stack(
        loop=asyncio.get_running_loop(),
        bind_host=route_to(registrar_address),
        audio=AudioMode.APPLICATION,
    )
    stack.set_message_hook(hook)
    account = stack.add_account(
        os.environ["SIPRAL_AOR"],
        registrar=os.environ["SIPRAL_REGISTRAR"],
        registrar_address=registrar_address,
        auth_user=os.environ["SIPRAL_AUTH_USER"],
        auth_password=os.environ["SIPRAL_AUTH_PASSWORD"],
    )
    registered = unregistered = False
    try:
        account.register()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 20.0
        while not unregistered and loop.time() < deadline:
            event = await asyncio.wait_for(stack.events.get(), timeout=max(deadline - loop.time(), 0.01))
            if event.kind != EventKind.REGISTRATION_CHANGED:
                continue
            state = event.fields.get("state")
            if state == lib.SIPRAL_REGISTRATION_STATE_REGISTERED and not registered:
                print("registered")
                registered = True
                account.unregister()
            elif state == lib.SIPRAL_REGISTRATION_STATE_UNREGISTERED and registered:
                print("unregistered")
                unregistered = True
    except asyncio.TimeoutError:
        pass
    finally:
        stack.close()
    return 0 if registered and unregistered else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
