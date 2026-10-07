# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""SIP over TCP or TLS: trust, connecting, and classifying failures.

Sipral links no TLS library (`docs/22-tls.md`), so TLS is Python's `ssl`.
The certificate check cannot be turned off; a failure is reported to the
stack and reaches the application as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import socket
import ssl
from typing import Callable

from ._sipral_cffi import lib

__all__ = ["InviteLimit", "PinRefused", "TlsTrust", "classify", "parse_pin"]

#: OpenSSL codes for expired/not-yet-valid (9, 10) and host/IP mismatch
#: (62, 64); any other verification failure counts as untrusted.
_EXPIRED = frozenset({9, 10})
_NAME_MISMATCH = frozenset({62, 64})

#: Errnos meaning no route, as opposed to a refusal.
_UNREACHABLE = frozenset(
    {
        getattr(errno, name)
        for name in ("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "EHOSTDOWN")
        if hasattr(errno, name)
    }
)


class TlsTrust:
    """Which authorities a TLS connection to the SIP server trusts.

    :meth:`platform` (the system store), :meth:`private_authority` (a
    private CA beside it), :meth:`only_authority` (that CA alone),
    :meth:`pinned` (one certificate by SHA-256, for a self-signed PBX) and
    :meth:`from_context` (the application's own). None disables checking.
    """

    def __init__(
        self, build: Callable[[], ssl.SSLContext], description: str, pin: bytes | None = None
    ) -> None:
        self._build = build
        self.description = description
        #: The pinned SHA-256 digest, or ``None``.
        self.pin = pin

    @classmethod
    def pinned(cls, fingerprint: str) -> "TlsTrust":
        """Trust only the certificate with this SHA-256 fingerprint.

        Accepts the forms ``openssl x509 -fingerprint -sha256`` and RFC 8122
        print: 64 hex digits, any case, colons and spaces ignored, optionally
        after ``sha-256 ``, ``SHA256=`` or ``SHA256 Fingerprint=``; else
        ``ValueError`` (``bindings/fixtures/pin-forms.txt``). The match is
        the whole verdict: no authority, name or date is checked. Compared
        in constant time over the leaf's DER."""
        digest = parse_pin(fingerprint)

        def build() -> ssl.SSLContext:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # The pin replaces chain and name checks; see `connect`.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

        return cls(build, "the pinned certificate", digest)

    @classmethod
    def platform(cls) -> "TlsTrust":
        """The platform's own trust anchors, as OpenSSL finds them."""
        return cls(ssl.create_default_context, "the platform's authorities")

    @classmethod
    def private_authority(cls, cafile: str) -> "TlsTrust":
        """The platform's anchors, and the PEM file ``cafile`` beside them."""

        def build() -> ssl.SSLContext:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=cafile)
            return context

        return cls(build, f"the platform's authorities and {cafile}")

    @classmethod
    def only_authority(cls, cafile: str) -> "TlsTrust":
        """Only the authorities in ``cafile``; the platform's are not trusted."""
        return cls(lambda: ssl.create_default_context(cafile=cafile), f"only {cafile}")

    @classmethod
    def from_context(cls, context: ssl.SSLContext) -> "TlsTrust":
        """A context the application built. It must verify the server
        (``CERT_REQUIRED`` and ``check_hostname``), or this refuses it."""
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("a TLS context for SIP must verify the server's certificate and name")
        return cls(lambda: context, "the application's own context")

    def context(self) -> ssl.SSLContext:
        """The context a connection is made with; at least TLS 1.2."""
        context = self._build()
        if context.minimum_version < ssl.TLSVersion.TLSv1_2:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


#: The prefixes a fingerprint may come after, lower case.
_PIN_PREFIXES = ("sha256 fingerprint=", "sha-256 ", "sha256=")


def parse_pin(fingerprint: str) -> bytes:
    """Parse a fingerprint as :meth:`TlsTrust.pinned` accepts; 32 bytes."""
    text = fingerprint.strip()
    for prefix in _PIN_PREFIXES:
        if text.lower().startswith(prefix):
            text = text[len(prefix) :]
            break
    digits = text.replace(":", "").replace(" ", "")
    if len(digits) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
        raise ValueError(
            "a certificate pin is a SHA-256 fingerprint: 64 hexadecimal digits, "
            "optionally after sha-256, SHA256= or SHA256 Fingerprint="
        )
    return bytes.fromhex(digits)


class PinRefused(ssl.SSLCertVerificationError):
    """The server presented a certificate other than the pinned one."""

    def __init__(self) -> None:
        super().__init__("the server's certificate is not the pinned one")
        self.reason = "CERTIFICATE_REFUSED"
        self.verify_code = 0
        self.verify_message = "the server's certificate is not the pinned one"


class InviteLimit(tuple):
    """Per-address INVITE rate: ``burst`` at once, then one per ``every_ms``.

    :attr:`DEFAULT`: ten, then one every two seconds, 480 past that.
    :attr:`VOICE_AGENT`: 128, then twenty a second, for a trunk.
    """

    __slots__ = ()

    def __new__(cls, burst: int, every_ms: int) -> "InviteLimit":
        return super().__new__(cls, (int(burst), int(every_ms)))

    @property
    def burst(self) -> int:
        return self[0]

    @property
    def every_ms(self) -> int:
        return self[1]


InviteLimit.DEFAULT = InviteLimit(lib.SIPRAL_INVITE_LIMIT_BURST, lib.SIPRAL_INVITE_LIMIT_EVERY_MS)
InviteLimit.VOICE_AGENT = InviteLimit(
    lib.SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST, lib.SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS
)


def _sentence(error: BaseException) -> str:
    """``error`` as one line within `SIPRAL_TRANSPORT_DETAIL_BYTES`."""
    if isinstance(error, ssl.SSLCertVerificationError) and error.verify_message:
        text = f"{error.reason or 'certificate verify failed'}: {error.verify_message}"
    else:
        text = str(error) or type(error).__name__
    text = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text).strip()
    encoded = text.encode("utf-8")[: lib.SIPRAL_TRANSPORT_DETAIL_BYTES]
    return encoded.decode("utf-8", "ignore")


def classify(error: BaseException) -> tuple[int, int, str]:
    """A failed connection as (`SipralTransportError`, `SipralTlsFailure`,
    detail sentence)."""
    detail = _sentence(error)
    if isinstance(error, ssl.SSLCertVerificationError):
        code = error.verify_code
        if code in _EXPIRED:
            tls = lib.SIPRAL_TLS_FAILURE_EXPIRED
        elif code in _NAME_MISMATCH:
            tls = lib.SIPRAL_TLS_FAILURE_NAME_MISMATCH
        else:
            tls = lib.SIPRAL_TLS_FAILURE_UNTRUSTED
        return lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, tls, detail
    if isinstance(error, ssl.SSLError):
        return lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, lib.SIPRAL_TLS_FAILURE_HANDSHAKE_REFUSED, detail
    if isinstance(error, (socket.timeout, TimeoutError)):
        return lib.SIPRAL_TRANSPORT_ERROR_TIMED_OUT, lib.SIPRAL_TLS_FAILURE_NONE, detail
    if isinstance(error, ConnectionRefusedError):
        return lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED, lib.SIPRAL_TLS_FAILURE_NONE, detail
    if isinstance(error, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
        return lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, lib.SIPRAL_TLS_FAILURE_NONE, detail
    if isinstance(error, OSError) and error.errno in _UNREACHABLE:
        return lib.SIPRAL_TRANSPORT_ERROR_UNREACHABLE, lib.SIPRAL_TLS_FAILURE_NONE, detail
    return lib.SIPRAL_TRANSPORT_ERROR_OTHER, lib.SIPRAL_TLS_FAILURE_NONE, detail


def connect(
    server: tuple[str, int],
    *,
    bind_host: str | None,
    context: ssl.SSLContext | None,
    server_name: str | None,
    timeout: float,
    pin: bytes | None = None,
) -> socket.socket:
    """Connect to ``server``, over TLS when ``context`` is given (checked
    against ``server_name``, or ``pin`` alone). Raises the failure for
    :func:`classify`."""
    raw = socket.socket(socket.AF_INET6 if ":" in server[0] else socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        if bind_host is not None:
            raw.bind((bind_host, 0))
        raw.connect(server)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if context is None:
            return raw
        wrapped = context.wrap_socket(raw, server_hostname=server_name)
    except BaseException:
        raw.close()
        raise
    if pin is not None:
        leaf = wrapped.getpeercert(binary_form=True) or b""
        if not hmac.compare_digest(hashlib.sha256(leaf).digest(), pin):
            wrapped.close()
            raise PinRefused()
    return wrapped
