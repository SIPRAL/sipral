# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""Sipral: a SIP client stack, over its C ABI.

``Stack``, ``Account`` and ``Call`` are the layer an application is meant
to use -- built with `cffi` in ABI mode against the same declarations the
C header, Swift, .NET and Kotlin bindings are printed from
(`docs/08-ffi.md`), so installing this package needs no C compiler and no
second source of truth for what the library exports. ``sipral._sipral_cffi``
is that raw layer (``ffi``/``lib``); reach for it directly only for
something this idiomatic layer has not grown yet.

::

    import asyncio
    from sipral import Stack

    async def main():
        loop = asyncio.get_running_loop()
        with Stack(loop=loop) as stack:
            account = stack.add_account(
                "sip:alice@example.invalid",
                registrar_address="127.0.0.1:5070",
            )
            call = stack.place_call(account, "sip:bob@example.invalid")
            event = await call.events.get()
            ...

On a platform the library has an audio backend for (``features()`` has
``Feature.AUDIO_DEVICE``: macOS, iOS, Windows) a stack opens the machine's
own microphone and loudspeaker and pumps every call through them, so the
code above is a whole softphone; ``stack.audio`` chooses the devices, the
volume and the mute. ``Stack(audio=AudioMode.APPLICATION)`` hands the frames
to the application instead: see ``examples/agent.py`` for a voice agent.
"""

from __future__ import annotations

from .account import Account
from .audio import Audio, AudioDevice, AudioInfo
from .call import Call
from .counters import Counters
from .errors import SipralError
from .events import (
    Answering,
    AudioNotice,
    CallerIdentity,
    EndCause,
    Event,
    Protection,
    Verification,
)
from .media import Media
from .signalling import InviteLimit, TlsTrust
from .stack import TRACE, Stack, features

__version__ = "0.0.1"

__all__ = [
    "Account",
    "Answering",
    "Audio",
    "AudioDevice",
    "AudioInfo",
    "AudioNotice",
    "Call",
    "CallerIdentity",
    "Counters",
    "EndCause",
    "Event",
    "InviteLimit",
    "Media",
    "Protection",
    "SipralError",
    "Stack",
    "TRACE",
    "TlsTrust",
    "Verification",
    "__version__",
    "features",
]
