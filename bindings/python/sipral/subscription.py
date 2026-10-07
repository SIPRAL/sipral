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
    """Read text from a ``*_text`` entry point, retrying with the size it
    reports on `SIPRAL_STATUS_BUFFER_TOO_SMALL`."""
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
    """One conference user: its AOR, display text, first endpoint and its
    status (RFC 4575 §5.7.2), endpoint count and media count."""

    entity: str | None
    display_text: str | None
    endpoint: str | None
    status: EndpointStatus
    endpoints: int
    media: int


@dataclasses.dataclass(frozen=True)
class ConferencePicture:
    """A conference as a ``conference`` subscription holds it (RFC 4575 §5).

    ``user_count`` is the focus's own count, which may exceed
    ``len(users)``; ``active`` and ``locked`` are ``None`` when unsaid.
    ``users`` keep the focus's order."""

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
    """A subscription handle.

    The stack refreshes it while live. Notifications arrive on the stack's
    events naming :attr:`handle` (presence or conference changes; read a
    conference with :meth:`conference`).
    """

    def __init__(self, stack: "Stack", handle: int, package: str) -> None:
        self.stack = stack
        #: The handle its events name.
        self.handle = handle
        #: The event package, as it went out.
        self.package = package

    @property
    def state(self) -> SubscriptionState:
        """The state, read fresh; ``UNKNOWN`` once ended."""
        out = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_subscription_state(self.stack.handle, self.handle, out),
            "sipral_subscription_state",
        )
        return SubscriptionState(int(out[0]))

    def end(self) -> None:
        """Unsubscribe; it ends once the closing NOTIFY is answered."""
        _call(
            lambda: lib.sipral_subscription_end(
                self.stack.handle, self.handle, self.stack.now_ms()
            ),
            "sipral_subscription_end",
        )

    def conference(self) -> ConferencePicture | None:
        """The current conference picture, or ``None`` (other package, no
        document yet, or ended). Re-read after each conference change."""
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
        """One conference text field, ``None`` if not sent."""
        text = read_text(
            lambda buffer, capacity, needed: lib.sipral_subscription_conference_text(
                self.stack.handle, self.handle, index, int(which), buffer, capacity, needed
            ),
            "sipral_subscription_conference_text",
        )
        return text or None
