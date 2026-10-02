# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""Sipral: a SIP client stack, over its C ABI.

``Stack``, ``Account`` and ``Call`` are the layer an application is meant
to use -- built with `cffi` in ABI mode against the same declarations the
C header, Swift, .NET, Kotlin and Dart bindings are printed from
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

from .account import Account, PinnedCertificate
from .audio import Audio, AudioDevice, AudioInfo
from .call import Call
from .conference import LocalConference
from .counters import Counters
from .errors import SipralError
from .events import (
    Answering,
    AudioNotice,
    CallerIdentity,
    ConferenceNotice,
    EndCause,
    Event,
    LocalConferenceNotice,
    Presence,
    Protection,
    TypedText,
    Verification,
)
from .locate import advertised_address, lookup
from .media import Media
from .settings import Settings
from .signalling import InviteLimit, TlsTrust
from .stack import TRACE, Stack, features
from .subscription import ConferencePicture, Participant, Subscription

__version__ = "1.0.0"

__all__ = [
    "Account",
    "Answering",
    "Audio",
    "AudioDevice",
    "AudioInfo",
    "AudioNotice",
    "Call",
    "CallerIdentity",
    "ConferenceNotice",
    "ConferencePicture",
    "Counters",
    "EndCause",
    "Event",
    "InviteLimit",
    "LocalConference",
    "LocalConferenceNotice",
    "Media",
    "Participant",
    "PinnedCertificate",
    "Presence",
    "Protection",
    "Settings",
    "SipralError",
    "Stack",
    "Subscription",
    "TRACE",
    "TlsTrust",
    "TypedText",
    "Verification",
    "__version__",
    "advertised_address",
    "features",
    "lookup",
]
