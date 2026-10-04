# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""SIP over TCP or TLS: which authorities a TLS connection trusts, the one
connection a :class:`sipral.stack.Stack` signals on, and what a refused
connection is called.

Sipral links no TLS library (`docs/22-tls.md`), so the connection is
Python's own `ssl`, checked by OpenSSL against the name the server is
expected to have. Nothing here turns that check off: a certificate that
fails is a connection that is not made, and the stack hears why
(`sipral_stack_transport_failed_with`), which it passes on to the application
as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`.
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

#: What OpenSSL calls the verification failures that are an expired or a
#: not-yet-valid certificate, and one that names another host
#: (`X509_V_ERR_CERT_HAS_EXPIRED`, `X509_V_ERR_CERT_NOT_YET_VALID`,
#: `X509_V_ERR_HOSTNAME_MISMATCH`, `X509_V_ERR_IP_ADDRESS_MISMATCH`). Every
#: other verification failure is a chain that reaches no trusted authority.
_EXPIRED = frozenset({9, 10})
_NAME_MISMATCH = frozenset({62, 64})

#: The errnos that are a network with no way through, rather than a server
#: that said no.
_UNREACHABLE = frozenset(
    {
        getattr(errno, name)
        for name in ("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "EHOSTDOWN")
        if hasattr(errno, name)
    }
)


class TlsTrust:
    """Which authorities a TLS connection to the SIP server trusts.

    Three answers, the three `docs/22-tls.md` describes for every platform:
    :meth:`platform` (the machine's own store, what a public server's
    certificate is checked against), :meth:`private_authority` (a private
    CA beside the platform's), and :meth:`only_authority` (that one
    authority and nothing else: pinning it). :meth:`pinned` trusts one
    certificate by its SHA-256 fingerprint, for a PBX that signed its own.
    :meth:`from_context` takes a context the application built itself, for
    anything the others do not say. None of them turns the check off.
    """

    def __init__(
        self, build: Callable[[], ssl.SSLContext], description: str, pin: bytes | None = None
    ) -> None:
        self._build = build
        self.description = description
        #: The SHA-256 digest of the one certificate :meth:`pinned` trusts,
        #: or ``None``.
        self.pin = pin

    @classmethod
    def pinned(cls, fingerprint: str) -> "TlsTrust":
        """The one certificate whose SHA-256 fingerprint is ``fingerprint``,
        and nothing else: for a PBX serving a certificate it signed itself.

        ``fingerprint`` is written the way ``openssl x509 -fingerprint
        -sha256`` (``sha256 Fingerprint=``, or ``SHA256 Fingerprint=``
        before OpenSSL 3) or RFC 8122 prints it: 64 hexadecimal digits,
        either case, colons and spaces between them ignored, optionally
        after ``sha-256 ``, ``SHA256=`` or ``SHA256 Fingerprint=``, in any
        case; anything else raises ``ValueError``
        (``bindings/fixtures/pin-forms.txt`` lists what every layer takes).
        The fingerprint is
        the whole verdict: no authority, host name or date is consulted, and
        a certificate with any other fingerprint is refused as untrusted
        (`docs/22-tls.md`). It is compared in constant time, over the DER
        bytes of the certificate the server presented first."""
        digest = parse_pin(fingerprint)

        def build() -> ssl.SSLContext:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # the pin replaces the chain and the name: both are checked
            # below, against the digest, once the handshake is done
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
        """The authorities in the PEM file ``cafile`` and no others: a
        certificate any other authority signed is refused, the platform's
        included."""
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
    """The 32 bytes a SHA-256 fingerprint names, in any of the forms
    :meth:`TlsTrust.pinned` takes; ``ValueError`` for anything else."""
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
    """How fast one address may ring a stack: ``burst`` INVITEs at once,
    then one more every ``every_ms`` (`sipral_stack_invite_limit`).

    :attr:`DEFAULT` is what every stack starts with, ten then one every two
    seconds, past which an INVITE is answered 480; :attr:`VOICE_AGENT` is
    the preset for a headless service taking a trunk's calls, a hundred and
    twenty-eight at once and then twenty a second (`docs/08-ffi.md`, "How
    fast one address may ring this stack").
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
    """The platform's words for ``error``, as one line of at most
    `SIPRAL_TRANSPORT_DETAIL_BYTES` bytes of UTF-8."""
    if isinstance(error, ssl.SSLCertVerificationError) and error.verify_message:
        text = f"{error.reason or 'certificate verify failed'}: {error.verify_message}"
    else:
        text = str(error) or type(error).__name__
    text = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text).strip()
    encoded = text.encode("utf-8")[: lib.SIPRAL_TRANSPORT_DETAIL_BYTES]
    return encoded.decode("utf-8", "ignore")


def classify(error: BaseException) -> tuple[int, int, str]:
    """What a failed connection was, as the stack names it: a
    `SipralTransportError`, a `SipralTlsFailure` and the platform's own
    sentence.

    A certificate OpenSSL refused is untrusted, a name mismatch or expired
    by its verification code; any other TLS error during the handshake is
    a handshake refused. A server nothing answered for is refused, a
    network with no way through unreachable, silence timed out.
    """
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
    """One connection to ``server`` from ``bind_host`` (from the address of
    the route toward it when ``None``), over TLS when ``context`` is given
    with the certificate checked against ``server_name`` -- or, with
    ``pin``, against that SHA-256 digest alone; raises what refused it, for
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
