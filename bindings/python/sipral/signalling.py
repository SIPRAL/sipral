# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""SIP over TCP or TLS: trust, connecting, and classifying failures.

Sipral links no TLS library (`docs/22-tls.md`), so TLS is Python's `ssl`.
The certificate check cannot be turned off; a failure is reported to the
stack and reaches the application as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`.
"""

from __future__ import annotations

import datetime
import errno
import hashlib
import hmac
import ipaddress
import os
import select
import socket
import ssl
import time
from typing import Callable, Union

from ._sipral_cffi import ffi, lib
from .errors import _last_error_message

__all__ = [
    "ClientCertificateUnusable",
    "InviteLimit",
    "NameRefused",
    "PinRefused",
    "TlsClientCertificate",
    "TlsTrust",
    "classify",
    "parse_pin",
]

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
        self,
        build: Callable[[], ssl.SSLContext],
        description: str,
        pin: bytes | None = None,
        names_here: bool = True,
        shared: bool = False,
    ) -> None:
        self._build = build
        self.description = description
        #: The pinned SHA-256 digest, or ``None``.
        self.pin = pin
        #: Whether :func:`connect` reads the server's name, rather than
        #: OpenSSL during the handshake: for every context this class builds,
        #: so that a ``sip:`` URI can name the domain (RFC 5922 Section 7.1).
        self._names_here = names_here
        #: Whether :meth:`context` hands every connection the same object,
        #: the application's: ``ssl`` holds a client certificate per
        #: context, so one loaded into it is presented on all of them.
        self.shared = shared

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
        (``CERT_REQUIRED`` and ``check_hostname``), or this refuses it. Its
        own check reads the name; the stack's domain rules can only refuse
        more after it, never accept a ``sip:`` URI it refused. Every
        connection shares it, so it carries one client certificate at most:
        the stack's ``tls_client_certificate``, or one the application
        loaded; an account's own is refused unless the account pins."""
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("a TLS context for SIP must verify the server's certificate and name")
        return cls(lambda: context, "the application's own context", names_here=False, shared=True)

    def context(self) -> ssl.SSLContext:
        """The context a connection is made with; at least TLS 1.2. One this
        class built verifies the chain during the handshake and leaves the
        name to :func:`connect`, which reads it before anything is sent."""
        context = self._build()
        if context.minimum_version < ssl.TLSVersion.TLSv1_2:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self._names_here and context.verify_mode == ssl.CERT_REQUIRED:
            context.check_hostname = False
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


#: The `reason` OpenSSL gives a fatal alert from the server that says no to
#: this end's certificate, or to its absence.
_CLIENT_CERTIFICATE_ALERTS = frozenset(
    {
        "TLSV13_ALERT_CERTIFICATE_REQUIRED",
        "SSLV3_ALERT_BAD_CERTIFICATE",
        "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE",
        "SSLV3_ALERT_CERTIFICATE_REVOKED",
        "SSLV3_ALERT_CERTIFICATE_UNKNOWN",
        "TLSV1_ALERT_UNKNOWN_CA",
        "TLSV1_ALERT_ACCESS_DENIED",
    }
)
_CLIENT_CERTIFICATE_EXPIRED_ALERT = "SSLV3_ALERT_CERTIFICATE_EXPIRED"

#: What a password for an encrypted key file may be, as `load_cert_chain` takes it.
_Password = Union[str, bytes, bytearray, Callable[[], Union[str, bytes, bytearray]], None]


class ClientCertificateUnusable(OSError):
    """This end's client certificate could not be presented: the key cannot
    be used, or the certificate is out of its dates. :attr:`tls` is the
    `SipralTlsFailure` it is reported as; no connection was made."""

    def __init__(self, tls: int, sentence: str) -> None:
        super().__init__(sentence)
        self.tls = tls


class ClosedAfterHandshake(ConnectionAbortedError):
    """The server closed a TLS 1.3 connection cleanly while :func:`settle`
    waited, with no alert and nothing said: Asterisk's way of refusing a
    client certificate its authority did not sign."""


class TlsClientCertificate:
    """A client certificate this end presents on SIP over TLS (RFC 5246
    Section 7.4.6, RFC 8446 Section 4.4.2), from PEM files.

    ``certfile`` holds the certificate, leaf first, then any intermediates
    the server needs; ``keyfile`` its private key (PKCS #8 or the
    algorithm's own PEM), or ``None`` when ``certfile`` holds it too;
    ``password`` decrypts an encrypted key, as
    :meth:`ssl.SSLContext.load_cert_chain` takes it. Python's ``ssl`` reads
    keys from files only, so the key lives in a file this process can read;
    a key held by a platform key store needs the Swift, Kotlin or .NET layer.

    The files are read again before every connection, so a certificate
    renewed on disk is presented on the next one. Before connecting, a key
    that does not load, does not decrypt or does not match the certificate
    is `SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE`, and a certificate out
    of its dates `SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED`; neither
    reaches the server.
    """

    def __init__(self, certfile: str, keyfile: str | None = None, password: _Password = None) -> None:
        self.certfile = os.fspath(certfile)
        self.keyfile = os.fspath(keyfile) if keyfile is not None else None
        self._password = password

    def __repr__(self) -> str:
        return f"TlsClientCertificate({self.certfile!r}, {self.keyfile!r})"

    @property
    def tag(self) -> str:
        """What tells this certificate apart for the stack, the same each
        time (`sipral_account_config_t::tls_client_tag`): the SHA-256 of the
        two files' absolute paths, since the files are read only when a
        connection is made. Accounts whose tags match share a TLS
        connection; the others never do, since a connection presents one
        certificate."""
        named = "\0".join((os.path.abspath(self.certfile), os.path.abspath(self.keyfile or self.certfile)))
        return "files " + hashlib.sha256(named.encode("utf-8", "surrogateescape")).hexdigest()

    def present_with(self, context: ssl.SSLContext, now: datetime.datetime | None = None) -> None:
        """Load the certificate and its key into ``context``, after checking
        both; raises :class:`ClientCertificateUnusable` when they cannot be
        presented."""
        try:
            context.load_cert_chain(self.certfile, self.keyfile, self._password)
        except (OSError, ssl.SSLError, ValueError, TypeError) as refused:
            raise ClientCertificateUnusable(
                lib.SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE,
                f"the client certificate's key cannot be used: {_one_line(refused)}",
            ) from refused
        not_before, not_after = self.validity()
        moment = now or datetime.datetime.now(datetime.timezone.utc)
        if moment < not_before:
            raise ClientCertificateUnusable(
                lib.SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED,
                f"the client certificate is not valid until {not_before:%Y-%m-%d %H:%M:%S} UTC",
            )
        if moment > not_after:
            raise ClientCertificateUnusable(
                lib.SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED,
                f"the client certificate expired on {not_after:%Y-%m-%d %H:%M:%S} UTC",
            )

    def validity(self) -> tuple[datetime.datetime, datetime.datetime]:
        """The leaf's notBefore and notAfter (RFC 5280 Section 4.1.2.5), in UTC."""
        with open(self.certfile, encoding="ascii", errors="replace") as source:
            text = source.read()
        begin = text.find("-----BEGIN CERTIFICATE-----")
        end = text.find("-----END CERTIFICATE-----", begin)
        if begin < 0 or end < 0:
            raise ClientCertificateUnusable(
                lib.SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE,
                f"{self.certfile} holds no PEM certificate",
            )
        try:
            der = ssl.PEM_cert_to_DER_cert(text[begin : end + len("-----END CERTIFICATE-----")])
            return certificate_validity(der)
        except ValueError as unreadable:
            raise ClientCertificateUnusable(
                lib.SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE,
                f"the client certificate in {self.certfile} cannot be read: {unreadable}",
            ) from unreadable


def _der_item(data: bytes, at: int) -> tuple[int, int, int]:
    """One DER element at ``at``: (tag, where its contents start, where it ends)."""
    if at + 2 > len(data):
        raise ValueError("the certificate ends inside an element")
    tag = data[at]
    length = data[at + 1]
    start = at + 2
    if length & 0x80:
        octets = length & 0x7F
        if octets == 0 or octets > 4 or start + octets > len(data):
            raise ValueError("an element's length is not one DER allows")
        length = int.from_bytes(data[start : start + octets], "big")
        start += octets
    end = start + length
    if end > len(data):
        raise ValueError("an element runs past the end of the certificate")
    return tag, start, end


def _der_time(data: bytes, at: int) -> tuple[datetime.datetime, int]:
    """A UTCTime or GeneralizedTime at ``at`` (RFC 5280 Section 4.1.2.5.1-2)."""
    tag, start, end = _der_item(data, at)
    text = data[start:end].decode("ascii")
    if tag == 0x17 and len(text) == 13 and text.endswith("Z"):
        year = int(text[0:2])
        moment = datetime.datetime.strptime(f"{1900 + year if year >= 50 else 2000 + year}{text[2:12]}", "%Y%m%d%H%M%S")
    elif tag == 0x18 and len(text) == 15 and text.endswith("Z"):
        moment = datetime.datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    else:
        raise ValueError("a validity date is neither UTCTime nor GeneralizedTime in UTC")
    return moment.replace(tzinfo=datetime.timezone.utc), end


def certificate_validity(der: bytes) -> tuple[datetime.datetime, datetime.datetime]:
    """notBefore and notAfter of a DER certificate: Certificate, then
    TBSCertificate, past the version, serial number, signature algorithm and
    issuer, to the Validity sequence (RFC 5280 Section 4.1)."""
    tag, certificate, _ = _der_item(der, 0)
    if tag != 0x30:
        raise ValueError("not a certificate")
    tag, field, _ = _der_item(der, certificate)
    if tag != 0x30:
        raise ValueError("not a certificate")
    tag, _, after = _der_item(der, field)
    if tag == 0xA0:
        field = after
    for _skipped in ("serialNumber", "signature", "issuer"):
        _, _, field = _der_item(der, field)
    tag, validity, _ = _der_item(der, field)
    if tag != 0x30:
        raise ValueError("no validity in the certificate")
    not_before, following = _der_time(der, validity)
    not_after, _ = _der_time(der, following)
    return not_before, not_after


def _one_line(error: BaseException) -> str:
    text = str(error) or type(error).__name__
    return " ".join(text.split())


class PinRefused(ssl.SSLCertVerificationError):
    """The server presented a certificate other than the pinned one."""

    def __init__(self) -> None:
        super().__init__("the server's certificate is not the pinned one")
        self.reason = "CERTIFICATE_REFUSED"
        self.verify_code = 0
        self.verify_message = "the server's certificate is not the pinned one"


class NameRefused(ssl.SSLCertVerificationError):
    """The server's certificate was trusted, and does not name the server
    as the stack's domain rules read a name; reported as a name mismatch."""

    def __init__(self, sentence: str) -> None:
        super().__init__(sentence)
        self.reason = "CERTIFICATE_VERIFY_FAILED"
        # X509_V_ERR_HOSTNAME_MISMATCH, as OpenSSL's own check reports one
        self.verify_code = 62
        self.verify_message = sentence


def https_names(certificate: dict, name: str) -> bool:
    """Whether a verified certificate (``getpeercert()``) names ``name`` by
    the rules HTTPS uses, as OpenSSL's own check reads them: a DNS name equal
    to it without regard to case, a leading ``*.`` standing for one whole
    label under at least two more; an IP address against an IP address
    entry. The ``commonName`` is not read."""
    try:
        address = ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        address = None
    wanted = name.rstrip(".").lower()
    for kind, value in certificate.get("subjectAltName", ()):
        if address is not None and kind == "IP Address":
            try:
                if ipaddress.ip_address(value.strip()) == address:
                    return True
            except ValueError:
                continue
        elif address is None and kind == "DNS":
            pattern = value.rstrip(".").lower()
            if pattern == wanted:
                return True
            label, _, rest = wanted.partition(".")
            if pattern.startswith("*.") and pattern.count(".") >= 2 and label and rest == pattern[2:]:
                return True
    return False


def check_name(sock: ssl.SSLSocket, server_name: str, rules: int, matched_already: bool) -> None:
    """Hold a connection whose chain was trusted to ``server_name`` under
    ``rules`` (a `SipralDomainRules`): by default the HTTPS rules, with a
    ``sip:`` URI that names the domain accepted besides; RFC 5922 alone
    with ``SIPRAL_DOMAIN_RULES_RFC5922``. A ``sip:`` URI is held to the name
    constraints of the authorities above the leaf in the chain OpenSSL
    verified (``sipral_certificate_check_domain_in_chain``).
    ``matched_already`` says OpenSSL checked the name itself and it held.
    Raises :class:`NameRefused`."""
    leaf = sock.getpeercert(binary_form=True) or b""
    matched = matched_already or https_names(sock.getpeercert() or {}, server_name)
    if matched and rules == lib.SIPRAL_DOMAIN_RULES_PLATFORM:
        return
    # the verified chain is the ssl module's from Python 3.13 on; before it
    # there is none to read, and the leaf is read alone, its sip: URI held to
    # no authority's name constraints
    verified = sock.get_verified_chain() if hasattr(sock, "get_verified_chain") else [leaf]
    issuers = b"".join(verified[1:])
    domain = server_name.encode("utf-8")
    status = lib.sipral_certificate_check_domain_in_chain(
        leaf, len(leaf), issuers, len(issuers), domain, len(domain), rules, int(matched), ffi.NULL
    )
    if status != lib.SIPRAL_STATUS_OK:
        raise NameRefused(_last_error_message() or f"no name in the server's certificate is {server_name}")


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


def classify(error: BaseException, presented: bool = False) -> tuple[int, int, str]:
    """A failed connection as (`SipralTransportError`, `SipralTlsFailure`,
    detail sentence). ``presented`` says whether this end offered a client
    certificate, which decides what a server's alert about one means."""
    detail = _sentence(error)
    if isinstance(error, ClientCertificateUnusable):
        return lib.SIPRAL_TRANSPORT_ERROR_OTHER, error.tls, detail
    if presented and isinstance(error, ClosedAfterHandshake):
        return (
            lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET,
            lib.SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REFUSED,
            f"{detail}, no alert reaching this end",
        )
    if isinstance(error, ssl.SSLError) and not isinstance(error, ssl.SSLCertVerificationError):
        reason = getattr(error, "reason", None) or ""
        if presented and reason == _CLIENT_CERTIFICATE_EXPIRED_ALERT:
            return (
                lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET,
                lib.SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED,
                detail,
            )
        if reason in _CLIENT_CERTIFICATE_ALERTS:
            tls = (
                lib.SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REFUSED
                if presented
                else lib.SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REQUIRED
            )
            return lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, tls, detail
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


#: Bounds on how long a TLS 1.3 connection waits, after its handshake, for
#: the server's first records: its session tickets, or its verdict on this
#: end's certificate. Between them, twice what connecting took.
SETTLE_LEAST_SECONDS = 0.25
SETTLE_MOST_SECONDS = 3.0


def settle_seconds(connecting: float) -> float:
    """The wait :func:`settle` gives a connection that took ``connecting``
    seconds to make: the server's verdict is one round trip behind its
    handshake, and the handshake took about two."""
    return min(max(2 * connecting, SETTLE_LEAST_SECONDS), SETTLE_MOST_SECONDS)


def settle(sock: socket.socket, seconds: float = SETTLE_LEAST_SECONDS) -> bytes:
    """Wait up to ``seconds`` for a TLS 1.3 server to say whether it took
    this end's certificate, and return any SIP bytes read meanwhile.

    Under TLS 1.3 the client's handshake is over before the server has read
    the client's certificate (RFC 8446 Section 4.4.2), so a refusal arrives
    as an alert after it, and the server closes. A request written in that
    moment meets a reset connection that has lost the alert. A server that
    takes the certificate sends its session tickets at that point (Section
    4.6.1), which end the wait at once; its alert is raised here as the
    `ssl.SSLError` it is. A connection at another version, or plain TCP,
    returns at once."""
    if not isinstance(sock, ssl.SSLSocket) or sock.version() != "TLSv1.3":
        return b""
    patience = sock.gettimeout()
    deadline = time.monotonic() + seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
                return b""
            sock.settimeout(0.0)
            try:
                data = sock.recv(65536)
            except ssl.SSLWantReadError:
                # a session ticket: the certificate was taken
                return b""
            if not data:
                raise ClosedAfterHandshake("the server closed the connection after the handshake")
            return data
    finally:
        sock.settimeout(patience)


def connect(
    server: tuple[str, int],
    *,
    bind_host: str | None,
    context: ssl.SSLContext | None,
    server_name: str | None,
    timeout: float,
    pin: bytes | None = None,
    client: TlsClientCertificate | None = None,
    domain_rules: int = lib.SIPRAL_DOMAIN_RULES_PLATFORM,
) -> socket.socket:
    """Connect to ``server``, over TLS when ``context`` is given (checked
    against ``server_name`` under ``domain_rules``, or ``pin`` alone),
    presenting ``client`` when the server asks for a certificate. Raises the
    failure for :func:`classify`; a client certificate that cannot be
    presented raises before anything is sent."""
    if context is not None and client is not None:
        client.present_with(context)
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
    elif context.verify_mode == ssl.CERT_REQUIRED and server_name is not None:
        try:
            check_name(wrapped, server_name, domain_rules, context.check_hostname)
        except BaseException:
            wrapped.close()
            raise
    return wrapped
