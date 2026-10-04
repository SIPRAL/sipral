# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Subscription``: something at the far end this stack watches (RFC 6665).

A presentity's ``presence`` (RFC 3856), a focus's ``conference`` (RFC 4575),
or any other package named to :meth:`sipral.account.Account.subscribe`.
"""

from __future__ import annotations

import dataclasses
import time
from typing import TYPE_CHECKING, Callable

from ._sipral_cffi import ffi, lib
from .enums import ConferenceText, EndpointStatus, SubscriptionState
from .errors import call as _call
from .errors import check

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["ConferencePicture", "Participant", "Subscription"]


def read_text(copy: Callable[[object, int, object], int], where: str) -> str:
    """Copy a piece of text out the way every ``*_text`` entry point copies
    one: into a buffer with its NUL, answering
    `SIPRAL_STATUS_BUFFER_TOO_SMALL` and the bytes it needs when the buffer
    is short, so a second try with exactly that many always fits."""
    needed = ffi.new("size_t *")
    capacity = 256
    deadline = time.monotonic() + 0.5
    while True:
        buffer = ffi.new(f"char[{capacity}]")
        status = copy(buffer, capacity, needed)
        if status == lib.SIPRAL_STATUS_BUSY and time.monotonic() < deadline:
            time.sleep(0.001)
            continue
        if status == lib.SIPRAL_STATUS_BUFFER_TOO_SMALL:
            capacity = int(needed[0])
            continue
        break
    check(status, where)
    length = max(int(needed[0]) - 1, 0)
    return bytes(ffi.buffer(buffer, length)).decode("utf-8", "replace")


@dataclasses.dataclass(frozen=True)
class Participant:
    """One user of a conference: the address of record it takes part as, its
    display text, the device its first endpoint is on and where that endpoint
    is (RFC 4575 §5.7.2), how many endpoints it is in from, and how many
    media streams the first of them has."""

    entity: str | None
    display_text: str | None
    endpoint: str | None
    status: EndpointStatus
    endpoints: int
    media: int


@dataclasses.dataclass(frozen=True)
class ConferencePicture:
    """A conference as a ``conference`` subscription holds it (RFC 4575 §5).

    ``user_count`` is what `conference-state` said, which may differ from
    ``len(users)`` since a focus need not list everyone; ``active`` and
    ``locked`` are ``None`` when it said nothing. ``users`` are in the order
    the focus first named them."""

    version: int
    entity: str | None
    subject: str | None
    display_text: str | None
    user_count: int | None
    active: bool | None
    locked: bool | None
    users: tuple[Participant, ...]


def _tristate(value: int) -> bool | None:
    return {1: True, 2: False}.get(int(value))


class Subscription:
    """One `sipral_handle_t` naming a subscription.

    Made by :meth:`sipral.account.Account.subscribe`,
    :meth:`sipral.account.Account.watch_presence` and
    :meth:`sipral.call.Call.subscribe_conference`. The stack refreshes it for
    as long as it is live; what the notifier says arrives on the stack's
    events naming :attr:`handle`: `SIPRAL_EVENT_KIND_PRESENCE_CHANGED`
    (:attr:`sipral.events.Event.presence`) for a presentity and
    `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`
    (:attr:`sipral.events.Event.conference`) for a conference, whose whole
    picture :meth:`conference` then reads.
    """

    def __init__(self, stack: "Stack", handle: int, package: str) -> None:
        self.stack = stack
        #: The raw handle, which the events about this subscription name.
        self.handle = handle
        #: The event package, as it went out.
        self.package = package

    @property
    def state(self) -> SubscriptionState:
        """`sipral_subscription_state`, read fresh: ``UNKNOWN`` once it has
        ended."""
        out = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_subscription_state(self.stack.handle, self.handle, out),
            "sipral_subscription_state",
        )
        return SubscriptionState(int(out[0]))

    def end(self) -> None:
        """`sipral_subscription_end`: an unsubscribe goes out, and the
        subscription is over once the notifier's closing notification is
        answered."""
        _call(
            lambda: lib.sipral_subscription_end(
                self.stack.handle, self.handle, self.stack.now_ms()
            ),
            "sipral_subscription_end",
        )

    def conference(self) -> ConferencePicture | None:
        """The conference as this subscription holds it now, or ``None`` when
        it holds none: a subscription to another package, one no document
        has reached yet, or one that ended. Read it again after every
        `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED` naming :attr:`handle`."""
        out = ffi.new("sipral_conference_t *")
        out.size = ffi.sizeof("sipral_conference_t")
        deadline = time.monotonic() + 0.5
        while True:
            status = lib.sipral_subscription_conference(self.stack.handle, self.handle, out)
            if status != lib.SIPRAL_STATUS_BUSY or time.monotonic() >= deadline:
                break
            time.sleep(0.001)
        if status == lib.SIPRAL_STATUS_NOT_SUPPORTED:
            return None
        check(status, "sipral_subscription_conference")

        users = []
        user = ffi.new("sipral_conference_user_t *")
        for index in range(int(out.users)):
            user.size = ffi.sizeof("sipral_conference_user_t")
            _call(
                lambda: lib.sipral_subscription_conference_user_at(
                    self.stack.handle, self.handle, index, user
                ),
                "sipral_subscription_conference_user_at",
            )
            users.append(
                Participant(
                    entity=self._text(ConferenceText.USER_ENTITY, index),
                    display_text=self._text(ConferenceText.USER_DISPLAY_TEXT, index),
                    endpoint=self._text(ConferenceText.USER_ENDPOINT, index),
                    status=EndpointStatus(int(user.status)),
                    endpoints=int(user.endpoints),
                    media=int(user.media),
                )
            )
        return ConferencePicture(
            version=int(out.version),
            entity=self._text(ConferenceText.ENTITY),
            subject=self._text(ConferenceText.SUBJECT),
            display_text=self._text(ConferenceText.DISPLAY_TEXT),
            user_count=int(out.user_count) if out.has_user_count else None,
            active=_tristate(out.active),
            locked=_tristate(out.locked),
            users=tuple(users),
        )

    def _text(self, which: int, index: int = 0) -> str | None:
        """One piece of the conference's text, ``None`` for one the focus
        did not send."""
        text = read_text(
            lambda buffer, capacity, needed: lib.sipral_subscription_conference_text(
                self.stack.handle, self.handle, index, int(which), buffer, capacity, needed
            ),
            "sipral_subscription_conference_text",
        )
        return text or None
