# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Account``: one address of record on a :class:`sipral.stack.Stack`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from ._sipral_cffi import ffi, lib
from .enums import RegistrationState
from .errors import SipralError
from .errors import call as _call

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["Account"]


def _optional(text: str | None) -> bytes | None:
    return text.encode("utf-8") if text else None


def _default_contact(aor: str, bind_address: str, parameters: str = "") -> str:
    """Where this account can actually be reached, for a caller who gave
    no `Contact` of its own.

    The AOR itself is never a usable default: `sip:alice@example.invalid`
    names who this is, not a socket anything can write to, and a `Contact`
    that says so sends every dialog this account opens straight back to
    `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` asking this package to resolve a
    name that was never meant to resolve to anything. The user part is
    kept -- it is what a `sip:` URI's own grammar (RFC 3261 §19.1.1) calls
    `userinfo`, up to the first unescaped `@` -- and the host becomes the
    address this stack is actually listening on. ``parameters`` is what
    follows it, ``;transport=tls`` on a stack signalling over TLS: a
    server reaching this end names the transport it reaches it over.
    """
    scheme, _, rest = aor.partition(":")
    user, sep, _host = rest.partition("@")
    if not sep:
        return f"{scheme}:{bind_address}{parameters}"
    return f"{scheme}:{user}@{bind_address}{parameters}"


class Account:
    """`sipral_account_add`, and the entry points that take its handle.

    Built through :meth:`sipral.stack.Stack.add_account`, never directly:
    the handle only means something on the stack that minted it
    (`docs/08-ffi.md`, "A handle names something only on the stack that
    minted it"), so keeping the two together is what makes every method
    here safe to call with nothing further to pass.
    """

    def __init__(
        self,
        stack: "Stack",
        handle: int,
        aor: str,
        *,
        registrar_address: str = "",
        contact_given: bool = False,
    ) -> None:
        self.stack = stack
        self.handle = handle
        self.aor = aor
        #: Where this account's requests go, ``host:port``: the registrar or
        #: the outbound proxy it was added with.
        self.registrar_address = registrar_address
        #: Whether it was added with a `Contact` of its own, which
        #: :meth:`sipral.stack.Stack.move_to` then leaves to the application.
        self.contact_given = contact_given
        #: Whether it was asked to register and not to unregister since: the
        #: accounts a stack signalling over TCP or TLS registers again once
        #: its connection is made again.
        self.wants_registration = False

    @classmethod
    def add(
        cls,
        stack: "Stack",
        aor: str,
        *,
        registrar_address: str,
        registrar: str | None,
        contact: str | None,
        display_name: str | None,
        auth_user: str | None,
        auth_password: str | None,
        expires_seconds: int,
        session_timer: int = 0,
        session_interval_seconds: int = 0,
        privacy: int = 0,
        trusted_peers: Sequence[str] | str | None = None,
    ) -> "Account":
        aor_bytes = aor.encode("utf-8")
        registrar_address_bytes = registrar_address.encode("utf-8")
        registrar_bytes = _optional(registrar)
        contact_bytes = (
            contact or _default_contact(aor, stack.bind_address, stack.contact_parameters)
        ).encode("utf-8")
        display_name_bytes = _optional(display_name)
        auth_user_bytes = _optional(auth_user)
        auth_password_bytes = _optional(auth_password)

        # Local `char[]` buffers: read once by `sipral_account_add` and
        # never again, so nothing here needs to outlive this call.
        aor_buf = ffi.new("char[]", aor_bytes)
        registrar_address_buf = ffi.new("char[]", registrar_address_bytes)
        registrar_buf = ffi.new("char[]", registrar_bytes) if registrar_bytes else None
        contact_buf = ffi.new("char[]", contact_bytes)
        display_name_buf = (
            ffi.new("char[]", display_name_bytes) if display_name_bytes else None
        )
        auth_user_buf = ffi.new("char[]", auth_user_bytes) if auth_user_bytes else None
        auth_password_buf = (
            ffi.new("char[]", auth_password_bytes) if auth_password_bytes else None
        )

        config = ffi.new("sipral_account_config_t *")
        config.size = ffi.sizeof("sipral_account_config_t")
        config.aor = aor_buf
        config.aor_len = len(aor_bytes)
        if registrar_buf is not None:
            config.registrar = registrar_buf
            config.registrar_len = len(registrar_bytes)
        config.registrar_address = registrar_address_buf
        config.registrar_address_len = len(registrar_address_bytes)
        config.contact = contact_buf
        config.contact_len = len(contact_bytes)
        if display_name_buf is not None:
            config.display_name = display_name_buf
            config.display_name_len = len(display_name_bytes)
        if auth_user_buf is not None:
            config.auth_user = auth_user_buf
            config.auth_user_len = len(auth_user_bytes)
        if auth_password_buf is not None:
            config.auth_password = auth_password_buf
            config.auth_password_len = len(auth_password_bytes)
        config.expires_seconds = expires_seconds
        config.session_timer = session_timer
        config.session_interval_seconds = session_interval_seconds
        config.privacy = int(privacy)
        peers = trusted_peers if isinstance(trusted_peers, str) else ", ".join(trusted_peers or ())
        peers_bytes = peers.encode("utf-8")
        peers_buf = ffi.new("char[]", peers_bytes) if peers_bytes else None
        if peers_buf is not None:
            config.trusted_peers = peers_buf
            config.trusted_peers_len = len(peers_bytes)

        out_account = ffi.new("sipral_handle_t *")
        _call(
            lambda: lib.sipral_account_add(stack.handle, config, out_account),
            "sipral_account_add",
        )
        return cls(
            stack,
            int(out_account[0]),
            aor,
            registrar_address=registrar_address,
            contact_given=bool(contact),
        )

    def rebind(self, *, remote: str | None = None, contact: str | None = None) -> None:
        """`sipral_account_rebind`: point this account at ``remote``
        (``host:port``; the address it was added with when left out) and be
        reachable at ``contact`` (the AOR's user at the stack's current
        address when left out). What a network change asks for; the next
        REGISTER -- sent at once when the stack is waiting for it -- uses
        both."""
        remote_bytes = (remote or self.registrar_address).encode("utf-8")
        contact_bytes = (
            contact
            or _default_contact(self.aor, self.stack.bind_address, self.stack.contact_parameters)
        ).encode("utf-8")
        _call(
            lambda: lib.sipral_account_rebind(
                self.stack.handle,
                self.handle,
                lib.SIPRAL_TRANSPORT_MAIN,
                remote_bytes,
                len(remote_bytes),
                contact_bytes,
                len(contact_bytes),
                self.stack.now_ms(),
            ),
            "sipral_account_rebind",
        )

    def register(self) -> None:
        """`sipral_account_register`. A no-op account refuses this.

        On a stack signalling over TCP or TLS whose connection is down
        (``SIPRAL_STATUS_TRANSPORT_DOWN``, which the stack has already
        reported as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`) this is kept, and
        the REGISTER goes the moment the connection is made again."""
        self.wants_registration = True
        try:
            _call(
                lambda: lib.sipral_account_register(
                    self.stack.handle, self.handle, self.stack.now_ms()
                ),
                "sipral_account_register",
            )
        except SipralError as refused:
            if refused.status != lib.SIPRAL_STATUS_TRANSPORT_DOWN:
                raise

    def unregister(self) -> None:
        """`sipral_account_unregister`."""
        self.wants_registration = False
        _call(
            lambda: lib.sipral_account_unregister(
                self.stack.handle, self.handle, self.stack.now_ms()
            ),
            "sipral_account_unregister",
        )

    @property
    def registration_state(self) -> RegistrationState:
        """`sipral_account_registration_state`."""
        out_state = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_account_registration_state(
                self.stack.handle, self.handle, out_state
            ),
            "sipral_account_registration_state",
        )
        return RegistrationState(out_state[0])

    def remove(self) -> None:
        """`sipral_account_remove`. Every call this account placed ends."""
        _call(
            lambda: lib.sipral_account_remove(self.stack.handle, self.handle),
            "sipral_account_remove",
        )
        self.stack.forget_account(self)
