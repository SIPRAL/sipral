# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""The one exception every entry point in this package can raise.

Every ``sipral_`` call in the C ABI answers a ``sipral_status_t`` and, on
anything but ``SIPRAL_STATUS_OK``, sets a thread-local last-error string
(``sipral_last_error_message``). :func:`check` is the one place that reads
both and turns them into :class:`SipralError`, so a caller never has to
compare a status against ``lib.SIPRAL_STATUS_OK`` by hand.
"""

from __future__ import annotations

import time
from typing import Callable

from ._sipral_cffi import ffi, lib

__all__ = ["SipralError", "check", "call", "status_name"]


def status_name(status: int) -> str:
    """The name the header gives a status, e.g. ``"SIPRAL_STATUS_BUSY"``.

    ``sipral_status_name`` never fails: an unrecognised number still comes
    back as a readable string, which is why this never raises.
    """
    return ffi.string(lib.sipral_status_name(status)).decode("utf-8")


def _last_error_message() -> str:
    """The thread-local last-error string, read the ask-then-fetch way.

    A first call with a modest buffer covers every message this library
    writes; the rare longer one answers `SIPRAL_STATUS_BUFFER_TOO_SMALL`
    with the length actually needed in ``out_needed``, and a second call with
    a buffer that size is guaranteed to fit it, since the message a thread
    last set does not change between the two calls made here.
    """
    capacity = 256
    buffer = ffi.new(f"char[{capacity}]")
    out_needed = ffi.new("size_t *")
    status = lib.sipral_last_error_message(buffer, capacity, out_needed)
    if status == lib.SIPRAL_STATUS_BUFFER_TOO_SMALL:
        capacity = int(out_needed[0])
        buffer = ffi.new(f"char[{capacity}]")
        status = lib.sipral_last_error_message(buffer, capacity, out_needed)
    if status != lib.SIPRAL_STATUS_OK or out_needed[0] == 0:
        return ""
    # the length the library reports counts the trailing NUL, which is not
    # part of the message
    return ffi.buffer(buffer, int(out_needed[0]) - 1)[:].decode("utf-8", "replace")


class SipralError(Exception):
    """Raised by every wrapped entry point that answered anything but OK.

    ``status`` is the raw ``sipral_status_t``, ``status_name`` is what the
    header calls it, and the message is whatever the library's own
    thread-local last error said about this particular failure -- often the
    only piece that names which argument was wrong.
    """

    def __init__(self, status: int, where: str) -> None:
        self.status = status
        self.status_name = status_name(status)
        self.where = where
        detail = _last_error_message()
        text = f"{where}: {self.status_name}"
        if detail:
            text = f"{text}: {detail}"
        super().__init__(text)


def check(status: int, where: str) -> int:
    """Raise :class:`SipralError` unless ``status`` is ``SIPRAL_STATUS_OK``.

    Returns the status so a call site that also wants to branch on
    ``SIPRAL_STATUS_BUSY`` without an exception can use :func:`status_name`
    directly instead; every other call site just calls this and moves on.
    """
    if status != lib.SIPRAL_STATUS_OK:
        raise SipralError(status, where)
    return status


#: The statuses :func:`call` waits out: another thread inside the stack, and a
#: clock reading the poll thread overtook.
PASSING = (lib.SIPRAL_STATUS_BUSY, lib.SIPRAL_STATUS_CLOCK_BEHIND)


def call(entry_point: Callable[[], int], where: str) -> None:
    """Call an entry point, waiting out an ordinary `SIPRAL_STATUS_BUSY`.

    "Signalling on one stack is one thread at a time, and a second thread
    is told so rather than made to wait" (`docs/08-ffi.md`) is a promise
    about the C ABI, made so the library itself never blocks a caller.
    :class:`sipral.stack.Stack` keeps one thread polling continuously, so
    every other entry point an application calls from its own thread is
    liable to collide with it for the length of one poll -- ordinary
    contention, not a real failure -- and retrying here rather than
    raising `SipralError` for it is what lets `Call.answer`,
    `Account.register` and the rest read as calls that simply work rather
    than calls an application has to wrap in its own busy loop. A
    contention that has not cleared in half a second is not ordinary any
    more, and is let through to :func:`check` as whatever it still is.

    `SIPRAL_STATUS_CLOCK_BEHIND` gets the same retry, as the .NET layer
    gives it: every ``entry_point`` here reads ``now_ms()`` afresh on the
    calling thread right before the call, so a reading the stack's last
    one beat was overtaken by the poll thread between the two, not stale,
    and the next reading can only be later.
    """
    deadline = time.monotonic() + 0.5
    status = entry_point()
    while status in PASSING and time.monotonic() < deadline:
        time.sleep(0.001)
        status = entry_point()
    check(status, where)
