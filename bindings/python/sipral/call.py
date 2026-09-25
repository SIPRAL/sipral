# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Call``: one call handle, its events and, once media starts, its audio."""

from __future__ import annotations

import asyncio
import socket as socket_module
from typing import TYPE_CHECKING

from . import events as _events
from ._sipral_cffi import ffi, lib
from .enums import CallState, DtmfVia
from .errors import call as _call
from .media import Media

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["Call"]


class Call:
    """A `sipral_handle_t` naming one call, and the actions it takes.

    Built by :meth:`sipral.stack.Stack.place_call` for one this stack
    placed, and by :meth:`sipral.stack.Stack.answer_call` for one that
    came in; either way it is registered with its stack before the
    caller ever sees it, so :meth:`deliver` always has somewhere to put
    an event that names this call.
    """

    def __init__(
        self,
        stack: "Stack",
        handle: int,
        media_socket: socket_module.socket,
        media_address: str,
    ) -> None:
        self.stack = stack
        self.handle = handle
        self._media_socket = media_socket
        self._media_address = media_address
        self.media: Media | None = None
        self.ended = False

        #: Every event this call's handle names, decoded whole.
        self.events: asyncio.Queue[_events.Event] = asyncio.Queue()
        #: Just the digits: `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`'s own
        #: `fields["digit"]`, so a voice agent that only cares about DTMF
        #: does not have to filter `events` itself.
        self.dtmf: asyncio.Queue[str] = asyncio.Queue()

    def deliver(self, event: _events.Event) -> None:
        """Called by :class:`sipral.stack.Stack` on its own poll thread.

        Every side effect below -- minting :attr:`media`, marking
        :attr:`ended` -- happens before ``event`` is ever queued for a
        consumer. Queued first and updated after would let a coroutine
        that was already waiting on :attr:`events` wake, on the asyncio
        loop's own thread, and read ``call.media`` before this thread had
        actually set it: `call_soon_threadsafe` only schedules the queue
        put, it does not wait for the loop to run it, so this thread runs
        on regardless of when that happens.
        """
        if event.kind == lib.SIPRAL_EVENT_KIND_MEDIA_STARTED and self.media is None:
            # From here the socket is `Media`'s own to read
            # (`docs/08-ffi.md`, "From the media handle on, the socket's
            # datagrams go to sipral_media_receive and nowhere else") --
            # `Stack` stops treating it as a pre-media-handle STUN/TURN
            # socket first, so the two never race to read the same fd.
            self.stack._release_stun_socket(self._media_address)
            self.media = Media(self.stack, self.handle, self._media_socket)

        if event.kind == lib.SIPRAL_EVENT_KIND_CALL_ENDED:
            self.ended = True

        loop = self.stack._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.events.put_nowait, event)
        else:
            self.events.put_nowait(event)

        if event.kind == lib.SIPRAL_EVENT_KIND_DIGIT_RECEIVED:
            digit = event.fields.get("digit")
            if digit:
                if loop is not None and not loop.is_closed():
                    loop.call_soon_threadsafe(self.dtmf.put_nowait, digit)
                else:
                    self.dtmf.put_nowait(digit)

    # -- state --------------------------------------------------------

    @property
    def state(self) -> CallState:
        """`sipral_call_state`, read fresh -- not cached from the last
        event, which a status query between events would otherwise miss."""
        out_state = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_call_state(self.stack.handle, self.handle, out_state),
            "sipral_call_state",
        )
        return CallState(out_state[0])

    # -- actions --------------------------------------------------------

    def answer(self) -> None:
        """`sipral_call_answer_media`: accept, with this stack running the
        audio through the media socket this call already opened."""
        address = self._media_address.encode("utf-8")
        _call(
            lambda: lib.sipral_call_answer_media(
                self.stack.handle, self.handle, address, len(address), self.stack.now_ms()
            ),
            "sipral_call_answer_media",
        )

    def reject(self, code: int = 486) -> None:
        """`sipral_call_reject`: 486 Busy Here, 603 Decline, or whatever
        response code fits."""
        _call(
            lambda: lib.sipral_call_reject(
                self.stack.handle, self.handle, code, self.stack.now_ms()
            ),
            "sipral_call_reject",
        )

    def hangup(self) -> None:
        """`sipral_call_hangup`."""
        _call(
            lambda: lib.sipral_call_hangup(self.stack.handle, self.handle, self.stack.now_ms()),
            "sipral_call_hangup",
        )

    def hold(self) -> None:
        """`sipral_call_hold`."""
        _call(
            lambda: lib.sipral_call_hold(self.stack.handle, self.handle, self.stack.now_ms()),
            "sipral_call_hold",
        )

    def resume(self) -> None:
        """`sipral_call_resume`."""
        _call(
            lambda: lib.sipral_call_resume(self.stack.handle, self.handle, self.stack.now_ms()),
            "sipral_call_resume",
        )

    def send_dtmf(
        self,
        digits: str,
        *,
        via: int = int(DtmfVia.RTP),
        duration_ms: int = 100,
    ) -> None:
        """`sipral_call_send_dtmf`. ``via`` is a :class:`sipral.enums.DtmfVia`."""
        encoded = digits.encode("ascii")
        _call(
            lambda: lib.sipral_call_send_dtmf(
                self.stack.handle,
                self.handle,
                encoded,
                len(encoded),
                via,
                duration_ms,
                self.stack.now_ms(),
            ),
            "sipral_call_send_dtmf",
        )

    def close(self) -> None:
        """Hang up if this call is still up, release its media, forget it.

        Idempotent, and safe to call from a `finally` or a context
        manager's `__exit__` regardless of how the call ended.
        """
        if not self.ended:
            try:
                self.hangup()
            except Exception:  # noqa: BLE001 -- best effort on the way out
                pass
        if self.media is not None:
            self.media.close()
        else:
            # Never reached `SIPRAL_EVENT_KIND_MEDIA_STARTED`: refused,
            # failed before answer, or hung up while still ringing. A
            # socket `Stack._map_media_socket` named for it (`nat=Nat.STUN`)
            # is still the stack's to give back (`sipral_stack_nat_unmap`)
            # before the socket closes under it.
            self.stack._forget_media_socket(self._media_address)
            self._media_socket.close()
        self.stack.forget_call(self.handle)

    def __enter__(self) -> "Call":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
