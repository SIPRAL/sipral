# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The one exception every entry point in this package can raise.

:func:`check` turns a failed ``sipral_status_t`` and the thread-local last
error message into :class:`SipralError`.
"""

from __future__ import annotations

import time
from typing import Callable

from ._sipral_cffi import ffi, lib

__all__ = ["SipralError", "check", "call", "status_name"]


def status_name(status: int) -> str:
    """The name the header gives a status, e.g. ``"SIPRAL_STATUS_BUSY"``.

    Never raises: unknown numbers still get a readable string.
    """
    return ffi.string(lib.sipral_status_name(status)).decode("utf-8")


def _last_error_message() -> str:
    """The thread-local last error; a second call with the reported size
    always fits, since the message cannot change in between."""
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
    # The reported length counts the trailing NUL.
    return ffi.buffer(buffer, int(out_needed[0]) - 1)[:].decode("utf-8", "replace")


class SipralError(Exception):
    """Raised by every wrapped entry point that answered anything but OK.

    ``status`` is the raw ``sipral_status_t``, ``status_name`` its header
    name; the message includes the library's last error, which often names
    the bad argument.
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

    Returns the status.
    """
    if status != lib.SIPRAL_STATUS_OK:
        raise SipralError(status, where)
    return status


#: Statuses :func:`call` retries: another thread in the stack, and a clock
#: reading the poll thread overtook.
PASSING = (lib.SIPRAL_STATUS_BUSY, lib.SIPRAL_STATUS_CLOCK_BEHIND)


def call(entry_point: Callable[[], int], where: str) -> None:
    """Call an entry point, waiting out an ordinary `SIPRAL_STATUS_BUSY`.

    The C ABI answers BUSY instead of blocking, and the poll thread holds
    the stack for one poll at a time, so a collision is ordinary
    contention. Retried for up to half a second, then raised.

    `SIPRAL_STATUS_CLOCK_BEHIND` is retried too: ``entry_point`` reads
    ``now_ms()`` afresh each time, so the poll thread merely got there
    first and the next reading is later.
    """
    deadline = time.monotonic() + 0.5
    status = entry_point()
    while status in PASSING and time.monotonic() < deadline:
        time.sleep(0.001)
        status = entry_point()
    check(status, where)
