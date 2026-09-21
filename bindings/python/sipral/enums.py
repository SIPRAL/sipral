# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""Named integers, built from ``lib`` instead of copied out of it by hand.

The C header numbers a value once (`docs/08-ffi.md`, "A numbered space has
one declaration") and `tools/abi-gen` prints the same numbers into every
binding, this one included. Hand-writing a second Python enum for, say,
`sipral_event_kind_t` would be a second declaration a task like 8.6.5 or
8.6.9 -- each of which is allowed to spend an event kind the header already
reserved for it -- could add a value to without this module noticing. So
every enum here is read off `lib`'s own attribute names at import time: a
regenerated `_sipral_cffi.py` is the only file a new value ever has to reach.
"""

from __future__ import annotations

import enum

from ._sipral_cffi import lib

__all__ = [
    "Status",
    "EventKind",
    "CallState",
    "CallEndReason",
    "RegistrationState",
    "Arrival",
    "DigitSource",
    "DtmfVia",
    "Direction",
    "MediaFault",
]


def _members(prefix: str, *, exclude: tuple[str, ...] = ()) -> dict[str, int]:
    """Every integer attribute of ``lib`` named ``prefix`` plus a suffix.

    ``exclude`` keeps one numbered space from swallowing another that
    happens to share its start -- `SIPRAL_CODEC_OUTCOME_` out of
    `SIPRAL_CODEC_`, for instance.
    """
    found: dict[str, int] = {}
    for name in dir(lib):
        if not name.startswith(prefix):
            continue
        if any(name.startswith(bad) for bad in exclude):
            continue
        short = name[len(prefix) :]
        if not short:
            continue
        found[short] = int(getattr(lib, name))
    return found


def _enum(python_name: str, prefix: str, *, exclude: tuple[str, ...] = ()) -> type[enum.IntEnum]:
    return enum.IntEnum(python_name, _members(prefix, exclude=exclude))


#: A `sipral_status_t`. Application code rarely builds one of these itself --
#: :func:`sipral.errors.check` already turns a bad one into
#: :class:`sipral.errors.SipralError` -- but it is here for a caller that
#: wants to branch on `SIPRAL_STATUS_BUSY` without catching an exception for
#: an ordinary, expected contention.
Status = _enum("Status", "SIPRAL_STATUS_")

#: A `sipral_event_kind_t`. `Event.kind` in :mod:`sipral.events` is always a
#: plain `int`, never this enum, because a kind this build does not yet know
#: -- one spent by a task that ran after this package was generated against
#: -- must still be readable rather than raising `ValueError` on the way
#: into an enum member that does not exist yet. Look values up here instead:
#: ``EventKind(event.kind).name`` when the kind is a known one, and
#: `event.kind_name` (read from `sipral_event_kind_name`, which the library
#: itself keeps current) either way.
EventKind = _enum("EventKind", "SIPRAL_EVENT_KIND_")

#: A `sipral_call_state_t`, read from `sipral_call_state` or carried on a
#: call event.
CallState = _enum("CallState", "SIPRAL_CALL_STATE_")

#: A `sipral_call_end_reason_t`, meaningful once `CallState.TERMINATED`.
CallEndReason = _enum("CallEndReason", "SIPRAL_CALL_END_REASON_")

#: A `sipral_registration_state_t`, read from
#: `sipral_account_registration_state` or carried on
#: `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
RegistrationState = _enum("RegistrationState", "SIPRAL_REGISTRATION_STATE_")

#: A `sipral_arrival_t`: what `sipral_media_receive` made of one datagram.
Arrival = _enum("Arrival", "SIPRAL_ARRIVAL_")

#: A `sipral_digit_source_t`: which of the two ways a digit arrived.
DigitSource = _enum("DigitSource", "SIPRAL_DIGIT_SOURCE_")

#: A `sipral_dtmf_t`: which way `sipral_call_send_dtmf` sends a digit.
DtmfVia = _enum("DtmfVia", "SIPRAL_DTMF_")

#: A `sipral_direction_t`: which way audio may flow, as seen from here.
Direction = _enum("Direction", "SIPRAL_DIRECTION_")

#: A `sipral_media_fault_t`, on a media event that reports one.
MediaFault = _enum("MediaFault", "SIPRAL_MEDIA_FAULT_")
