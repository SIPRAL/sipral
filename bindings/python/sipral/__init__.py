# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Sipral: a SIP client stack, over its C ABI.

``Stack``, ``Account`` and ``Call`` are the application layer, over `cffi`
in ABI mode, so installing needs no C compiler. ``sipral._sipral_cffi`` is
the raw ``ffi``/``lib`` layer, for anything not wrapped yet.

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

Where ``features()`` has ``Feature.AUDIO_DEVICE`` (macOS, iOS, Windows) the
stack drives the microphone and loudspeaker itself, so the code above is a
softphone. ``Stack(audio=AudioMode.APPLICATION)`` hands frames to the
application instead; see ``examples/agent.py``.
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

__version__ = "1.1.0"

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
