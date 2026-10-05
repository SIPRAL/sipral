# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Account``: one address of record on a :class:`sipral.stack.Stack`."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, NamedTuple, Sequence

from ._sipral_cffi import ffi, lib
from .enums import Activity, RegistrationState
from .errors import SipralError
from .errors import call as _call
from .subscription import Subscription

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["Account", "PinnedCertificate"]


class PinnedCertificate(NamedTuple):
    """What `sipral_account_check_certificate` found in a certificate the
    account pins: its dates, in seconds since 1970 (zero when its DER could
    not be read that far), and whether the clock is past or before them.
    Accepted either way; an expired one is worth a warning."""

    not_before: int
    not_after: int
    expired: bool
    not_yet_valid: bool


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


def _contact_parameters(stack: "Stack", stream_protocol: int) -> str:
    """``;transport=tcp`` or ``;transport=tls`` for an account on a
    connection of its own, the stack's own parameters otherwise."""
    if stream_protocol == lib.SIPRAL_TRANSPORT_TLS:
        return ";transport=tls"
    if stream_protocol == lib.SIPRAL_TRANSPORT_TCP:
        return ";transport=tcp"
    return stack.contact_parameters


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
        server_uri: str | None = None,
        advertised: str | None = None,
        stream_protocol: int = 0,
        tls_pin: str | None = None,
    ) -> None:
        self.stack = stack
        #: The protocol of the connection of its own the account's requests
        #: go over, ``Transport.TCP`` or ``Transport.TLS``, or ``0`` for the
        #: stack's own transport.
        self.stream_protocol = stream_protocol
        #: The certificate pin it was added with, which a TLS connection of
        #: its own is held to.
        self.tls_pin = tls_pin
        self.handle = handle
        self.aor = aor
        #: Where this account's requests go, ``host:port``: the registrar or
        #: the outbound proxy it was added with, or -- for one added with
        #: ``server_uri`` -- the address it was last located at, empty until
        #: then.
        self.registrar_address = registrar_address
        #: The server named by a URI RFC 3263 locates, or ``None``.
        self.server_uri = server_uri
        #: The ``host:port`` its `Contact` names, when the stack chose it.
        self.advertised = advertised
        #: Whether it was added with a `Contact` of its own, which
        #: :meth:`sipral.stack.Stack.move_to` then leaves to the application.
        self.contact_given = contact_given
        #: Whether it was asked to register and not to unregister since: the
        #: accounts a stack signalling over TCP or TLS registers again once
        #: its connection is made again.
        self.wants_registration = False

    @property
    def contact_parameters(self) -> str:
        """What goes after the address in the `Contact` this package derives
        for it: the parameter naming its own connection's protocol (RFC 3261
        Section 19.1.1), or the stack's."""
        return _contact_parameters(self.stack, self.stream_protocol)

    @classmethod
    def add(
        cls,
        stack: "Stack",
        aor: str,
        *,
        registrar_address: str | None,
        registrar: str | None,
        contact: str | None,
        server_uri: str | None = None,
        server_naptr: bool = False,
        keepalive_ms: int = 0,
        tls_pin: str | None = None,
        stream_protocol: int = 0,
        advertised: str | None = None,
        display_name: str | None,
        auth_user: str | None,
        auth_password: str | None,
        expires_seconds: int,
        session_timer: int = 0,
        session_interval_seconds: int = 0,
        privacy: int = 0,
        trusted_peers: Sequence[str] | str | None = None,
        srtp: int = 0,
        srtp_suites: Sequence[str] | str | None = None,
        stir_verification: int = 0,
        stir_key: bytes | None = None,
        stir_certificate_url: str | None = None,
        stir_orig: str | None = None,
        stir_origid: str | None = None,
        stir_attestation: int = 0,
        recording_in_clear: bool = False,
        realms: Sequence[str] | None = None,
    ) -> "Account":
        aor_bytes = aor.encode("utf-8")
        registrar_address_bytes = (registrar_address or "").encode("utf-8")
        registrar_bytes = _optional(registrar)
        contact_bytes = (
            contact
            or _default_contact(
                aor, advertised or stack.bind_address, _contact_parameters(stack, stream_protocol)
            )
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
        if registrar_address_bytes:
            config.registrar_address = registrar_address_buf
            config.registrar_address_len = len(registrar_address_bytes)
        server_uri_bytes = _optional(server_uri)
        server_uri_buf = ffi.new("char[]", server_uri_bytes) if server_uri_bytes else None
        if server_uri_buf is not None:
            config.server_uri = server_uri_buf
            config.server_uri_len = len(server_uri_bytes)
        if server_naptr:
            config.server_naptr = lib.SIPRAL_TOGGLE_ON
        config.keepalive_ms = keepalive_ms
        config.stream_protocol = int(stream_protocol)
        pin_bytes = _optional(tls_pin)
        pin_buf = ffi.new("char[]", pin_bytes) if pin_bytes else None
        if pin_buf is not None:
            config.tls_pin_sha256 = pin_buf
            config.tls_pin_sha256_len = len(pin_bytes)
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
        config.srtp = int(srtp)
        suites = srtp_suites if isinstance(srtp_suites, str) else ",".join(srtp_suites or ())
        # every buffer below is kept alive by a name until `sipral_account_add`
        # has read it, and not a moment longer is needed
        suites_buf = ffi.new("char[]", suites.encode("utf-8")) if suites else None
        if suites_buf is not None:
            config.srtp_suites = suites_buf
            config.srtp_suites_len = len(suites.encode("utf-8"))
        config.stir_verification = int(stir_verification)
        key_buf = ffi.new("uint8_t[]", stir_key) if stir_key else None
        if key_buf is not None:
            config.stir_key = key_buf
            config.stir_key_len = len(stir_key)
        url_bytes = _optional(stir_certificate_url)
        url_buf = ffi.new("char[]", url_bytes) if url_bytes else None
        if url_buf is not None:
            config.stir_certificate_url = url_buf
            config.stir_certificate_url_len = len(url_bytes)
        orig_bytes = _optional(stir_orig)
        orig_buf = ffi.new("char[]", orig_bytes) if orig_bytes else None
        if orig_buf is not None:
            config.stir_orig = orig_buf
            config.stir_orig_len = len(orig_bytes)
        origid_bytes = _optional(stir_origid)
        origid_buf = ffi.new("char[]", origid_bytes) if origid_bytes else None
        if origid_buf is not None:
            config.stir_origid = origid_buf
            config.stir_origid_len = len(origid_bytes)
        config.stir_attestation = int(stir_attestation)
        config.recording_in_clear = 1 if recording_in_clear else 0
        realms_bytes = "\n".join(realms or ()).encode("utf-8")
        realms_buf = ffi.new("char[]", realms_bytes) if realms_bytes else None
        if realms_buf is not None:
            config.realms = realms_buf
            config.realms_len = len(realms_bytes)

        out_account = ffi.new("sipral_handle_t *")
        _call(
            lambda: lib.sipral_account_add(stack.handle, config, out_account),
            "sipral_account_add",
        )
        return cls(
            stack,
            int(out_account[0]),
            aor,
            registrar_address=registrar_address or "",
            contact_given=bool(contact),
            server_uri=server_uri,
            advertised=advertised,
            stream_protocol=int(stream_protocol),
            tls_pin=tls_pin,
        )

    def check_certificate(self, certificate: bytes, unix_seconds: int | None = None) -> PinnedCertificate | None:
        """`sipral_account_check_certificate`: the verdict of this account's
        ``tls_pin`` on ``certificate``, the DER bytes of the leaf a TLS
        server presented, from inside the application's certificate check.

        A :class:`PinnedCertificate` when it is the pinned one -- accept the
        handshake whoever signed it, its dates reported, an expired one
        included; ``None`` when the account pins nothing and the platform's
        own checks decide; ``SipralError`` with
        ``SIPRAL_STATUS_CERTIFICATE_REFUSED`` when it pins another."""
        out = ffi.new("sipral_pinned_certificate_t *")
        out.size = ffi.sizeof("sipral_pinned_certificate_t")
        now = int(time.time()) if unix_seconds is None else unix_seconds
        _call(
            lambda: lib.sipral_account_check_certificate(
                self.stack.handle, self.handle, certificate, len(certificate), now, out
            ),
            "sipral_account_check_certificate",
        )
        if not out.pinned:
            return None
        return PinnedCertificate(
            not_before=int(out.not_before),
            not_after=int(out.not_after),
            expired=bool(out.expired),
            not_yet_valid=bool(out.not_yet_valid),
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
            or _default_contact(self.aor, self.stack.bind_address, self.contact_parameters)
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
        """`sipral_account_unregister`.

        Gives the binding up: a REGISTER with Expires: 0. The registration state
        reads unregistered as soon as this returns, before the registrar answers;
        the answer is the registration-changed event that follows. Wait for that
        event before closing the stack, which otherwise cannot answer a challenge
        to the un-REGISTER.
        """
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

    def subscribe(
        self,
        target: str,
        package: str,
        *,
        accept: str | None = None,
        expires_seconds: int = 0,
        destination: str | None = None,
    ) -> Subscription:
        """`sipral_account_subscribe`: watch ``target`` (a SIP URI) through
        the event package ``package`` -- ``presence``, ``conference``,
        ``dialog``... -- sent where this account sends, or to ``destination``
        (``host:port``). ``accept`` is the body type wanted when it is not the
        package's default; ``expires_seconds`` how long to ask for, zero for
        an hour. Nothing has happened when this returns: the SUBSCRIBE is on
        its way, and what the notifier says arrives on the stack's events
        naming :attr:`sipral.subscription.Subscription.handle`."""
        keep = []

        def text(value: str) -> tuple[object, int]:
            encoded = value.encode("utf-8")
            keep.append(ffi.new("char[]", encoded))
            return keep[-1], len(encoded)

        config = ffi.new("sipral_subscribe_config_t *")
        config.size = ffi.sizeof("sipral_subscribe_config_t")
        config.target, config.target_len = text(target)
        config.package, config.package_len = text(package)
        if accept is not None:
            config.accept, config.accept_len = text(accept)
        config.expires_seconds = expires_seconds
        if destination is not None:
            config.destination, config.destination_len = text(destination)
        out = ffi.new("sipral_handle_t *")
        _call(
            lambda: lib.sipral_account_subscribe(
                self.stack.handle, self.handle, config, out, self.stack.now_ms()
            ),
            "sipral_account_subscribe",
        )
        return Subscription(self.stack, int(out[0]), package)

    def watch_presence(
        self, target: str, *, expires_seconds: int = 0, destination: str | None = None
    ) -> Subscription:
        """Watch a presentity's presence (RFC 3856): :meth:`subscribe` to the
        ``presence`` package. Each document it sends arrives as
        `SIPRAL_EVENT_KIND_PRESENCE_CHANGED`, whose
        :attr:`sipral.events.Event.presence` has it decoded."""
        return self.subscribe(
            target, "presence", expires_seconds=expires_seconds, destination=destination
        )

    def publish_presence(
        self, basic: int, activity: int = Activity.NONE, note: str | None = None
    ) -> None:
        """`sipral_account_publish_presence`: publish this account's presence
        (RFC 3903) -- ``basic`` a :class:`sipral.enums.Basic`, open or closed
        (required), an RPID ``activity`` (``Activity.NONE`` publishes no
        person; ``Activity.OTHER`` is refused, having no name to publish
        under) and a one-line ``note``. The first call publishes and every
        later one modifies the same publication, which the stack keeps
        refreshed until :meth:`unpublish_presence`.
        `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with ``PresenceKind.PUBLICATION``
        says what the compositor did with it."""
        presence = ffi.new("sipral_presence_t *")
        presence.size = ffi.sizeof("sipral_presence_t")
        presence.basic = int(basic)
        presence.activity = int(activity)
        note_buf = None
        if note is not None:
            encoded = note.encode("utf-8")
            note_buf = ffi.new("char[]", encoded)
            presence.note = note_buf
            presence.note_len = len(encoded)
        _call(
            lambda: lib.sipral_account_publish_presence(
                self.stack.handle, self.handle, presence, self.stack.now_ms()
            ),
            "sipral_account_publish_presence",
        )

    def unpublish_presence(self) -> None:
        """`sipral_account_unpublish_presence`: take the published presence
        away (RFC 3903 Section 4.5); ``PublicationState.REMOVED`` says when it
        is gone. `SIPRAL_STATUS_WRONG_STATE` when nothing was published."""
        _call(
            lambda: lib.sipral_account_unpublish_presence(
                self.stack.handle, self.handle, self.stack.now_ms()
            ),
            "sipral_account_unpublish_presence",
        )

    def remove(self) -> None:
        """`sipral_account_remove`. Every call this account placed ends."""
        _call(
            lambda: lib.sipral_account_remove(self.stack.handle, self.handle),
            "sipral_account_remove",
        )
        self.stack.forget_account(self)
