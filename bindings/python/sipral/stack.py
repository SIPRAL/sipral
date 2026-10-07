# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Stack``: one SIP endpoint, headless and in-process.

It owns the signalling socket, a background thread that drains
`sipral_stack_poll` and the transport queues, and the `asyncio.Queue`
events land on. It is written directly against the raw `ffi`/`lib` pair
in `_sipral_cffi.py`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import selectors
import socket
import ssl
import threading
import time
from typing import Sequence

from . import events as _events
from ._sipral_cffi import ffi, lib
from .account import Account, _default_contact
from .audio import Audio
from .call import Call, header_array
from .counters import Counters
from .enums import AudioMode, Feature, Link, LogLevel, Recovery
from .errors import PASSING as _PASSING
from .errors import call as _retry
from .errors import SipralError, check
from .locate import Resolver, advertised_address, lookup
from .settings import Settings
from .signalling import InviteLimit, TlsTrust, classify, connect

__all__ = ["TRACE", "Stack", "features", "route_host"]

#: The :mod:`logging` level for ``LogLevel.TRACE``, below ``logging.DEBUG``:
#: a trace line holds a whole SIP message and is turned on separately.
TRACE = 5

_PYTHON_LEVELS = {
    LogLevel.ERROR: logging.ERROR,
    LogLevel.WARN: logging.WARNING,
    LogLevel.INFO: logging.INFO,
    LogLevel.DEBUG: logging.DEBUG,
    LogLevel.TRACE: TRACE,
}


def _log_level_for(python_level: int) -> LogLevel:
    """The quietest stack level that still carries every line a logger at
    ``python_level`` keeps."""
    if python_level <= TRACE:
        return LogLevel.TRACE
    if python_level <= logging.DEBUG:
        return LogLevel.DEBUG
    if python_level <= logging.INFO:
        return LogLevel.INFO
    if python_level <= logging.WARNING:
        return LogLevel.WARN
    return LogLevel.ERROR


def features() -> Feature:
    """What this build of the library has compiled in, as
    :class:`sipral.enums.Feature` bits.

    ``Feature.AUDIO_DEVICE`` is set on macOS, iOS and Windows, clear on
    Linux and Android; a :class:`Stack` defaults to device mode where it is
    set.
    """
    out = ffi.new("sipral_capabilities_t *")
    out.size = ffi.sizeof("sipral_capabilities_t")
    check(lib.sipral_capabilities(out), "sipral_capabilities")
    return Feature(int(out.features))

#: A signalling message can exceed one media datagram, so the transmit
#: buffer is larger than `SIPRAL_MEDIA_PACKET_BYTES`.
_TRANSMIT_BYTES = 1 << 16
_ADDRESS_BYTES = 128
#: How long a TURN write may wait for room before the connection, and the
#: relay on it, is given up.
_TURN_WRITE_PATIENCE = 5.0
#: Bound on one signalling connect (TLS handshake included) and on a write.
_SIGNALLING_PATIENCE = 5.0
#: An account's own connection: TCP, TLS, or a WebSocket on either.
_OWN_STREAMS = (
    lib.SIPRAL_TRANSPORT_TCP,
    lib.SIPRAL_TRANSPORT_TLS,
    lib.SIPRAL_TRANSPORT_WS,
    lib.SIPRAL_TRANSPORT_WSS,
)
#: Reconnect backoff, doubled per failure: quick for a restarting server,
#: not every second for one that refuses the certificate.
_RECONNECT_FIRST = 1.0
_RECONNECT_MOST = 30.0
#: First transport number for `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`
#: connections, clear of `SIPRAL_TRANSPORT_MAIN` and of small numbers an
#: application driving `lib` itself would pick.
_FIRST_STREAM = 1024


def _toggle(value: bool | None) -> int:
    """A Python `True`/`False`/`None` as a `sipral_toggle_t`."""
    if value is None:
        return lib.SIPRAL_TOGGLE_DEFAULT
    return lib.SIPRAL_TOGGLE_ON if value else lib.SIPRAL_TOGGLE_OFF


def format_address(host: str, port: int) -> str:
    """``host:port``, the text shape every address crosses this ABI as."""
    return f"{host}:{port}"


def parse_address(text: str) -> tuple[str, int]:
    """The inverse of :func:`format_address`."""
    host, _, port = text.rpartition(":")
    return host, int(port)


def _is_address(text: str) -> bool:
    """Whether ``text`` is ``host:port`` with an IP address for its host."""
    try:
        host, _port = parse_address(text)
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def route_host(peer: str | None) -> str:
    """The address of this machine's route toward ``peer`` (``host:port``).

    ``127.0.0.1`` when there is no peer, it is a name, or no route reaches
    it; the library refuses to advertise that to any other machine."""
    if not peer or not _is_address(peer):
        return "127.0.0.1"
    wildcard = "[::]:0" if peer.startswith("[") else "0.0.0.0:0"
    try:
        return parse_address(advertised_address(wildcard, peer))[0]
    except (SipralError, ValueError):
        return "127.0.0.1"


def _verdict(error: int) -> str:
    """What became of a connection, in the words a log line reads."""
    return {
        lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED: "refused",
        lib.SIPRAL_TRANSPORT_ERROR_TIMED_OUT: "timed out",
        lib.SIPRAL_TRANSPORT_ERROR_UNREACHABLE: "unreachable",
        lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET: "reset",
        lib.SIPRAL_TRANSPORT_ERROR_CLOSED: "closed",
    }.get(error, "failed")


class _TurnStream:
    """One media socket's TCP or TLS connection to the TURN server.

    Written by the poll thread and the call's media thread, so every socket
    operation holds :attr:`lock`: two threads on one TLS session interleave
    its records.
    """

    def __init__(self, local: str, sock: socket.socket) -> None:
        self.local = local
        self.sock = sock
        self.lock = threading.Lock()


class _SipStream:
    """One TCP connection opened because a request was too large for a
    datagram (RFC 3261 Section 18.1.1), bound at :attr:`transport`.

    :attr:`lock` is held for every operation: the opening thread hands it
    over while the poll thread may already be writing.
    """

    def __init__(self, transport: int, destination: str, sock: socket.socket) -> None:
        self.transport = transport
        self.destination = destination
        self.sock = sock
        self.lock = threading.Lock()


class Stack:
    """One `sipral_stack_create` handle, its socket and its poll thread.

    :meth:`close` (or leaving ``with Stack(...) as stack:``) calls
    `sipral_stack_destroy` exactly once; garbage collection does it for a
    stack never closed. Prefer closing: until then the port stays bound.
    """

    def __init__(
        self,
        bind_host: str | None = None,
        bind_port: int = 0,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        user_agent: str | None = None,
        codecs: str | None = None,
        frame_ms: int = 0,
        offer_dtmf: bool | None = None,
        srtp: int = 0,
        ice: int = 0,
        nat: int = 0,
        stun_server: str | None = None,
        stun_fallbacks: Sequence[str] | None = None,
        turn_server: str | None = None,
        turn_username: str | None = None,
        turn_password: str | None = None,
        turn_transport: int = 0,
        turn_server_name: str | None = None,
        turn_tls_context: ssl.SSLContext | None = None,
        g729_annex_b: bool | None = None,
        referrals: bool | None = None,
        registrar_keepalive: bool | None = None,
        registrar_keepalive_ms: int = 0,
        audio: int | None = None,
        audio_activation: int = 0,
        audio_probe_ms: int = 0,
        audio_device_rate_hz: int = 0,
        max_dialogs: int = 0,
        max_server_transactions: int = 0,
        diagnostic_decisions: int = 0,
        diagnostic_records: int = 0,
        rtp_port_min: int = 0,
        rtp_port_max: int = 0,
        dtmf_detection: int = 0,
        signalling: int = 0,
        signalling_server: str | None = None,
        tls_server_name: str | None = None,
        tls_trust: TlsTrust | None = None,
        invite_limit: InviteLimit | tuple[int, int] | None = None,
        stream_fallback: bool = True,
        stream_server: str | None = None,
        srtp_suites: Sequence[str] | str | None = None,
        path_mtu: int = 0,
        datagram_without_stream_bytes: int = 0,
        pseudonym_salt: bytes | None = None,
        diagnostic_trace: bool | None = None,
        resolver: Resolver | None = None,
        system_echo_cancellation: bool | None = None,
        held_audio: int = 0,
    ) -> None:
        """Create the stack, bind or connect its signalling, start polling.

        ``bind_host`` is where the signalling socket binds and what the stack
        advertises. Left out, it listens on every interface and advertises
        the route toward its first account's server
        (`sipral_advertised_address`); each account, and each call's media
        socket without ``media_host``, uses the route toward its own peer. A
        loopback address is never advertised off this machine: the library
        refuses with ``SIPRAL_STATUS_UNREACHABLE_ADDRESS``.

        ``signalling`` (:class:`sipral.enums.Transport`) is ``UDP`` (``0``,
        default) on ``bind_host``, or ``TCP``/``TLS`` on one connection to
        ``signalling_server`` (``host:port``, the registrar or outbound proxy)
        shared by every account and call. Over TLS the certificate is checked
        against ``tls_server_name`` (default: the host of
        ``signalling_server``) with ``tls_trust``
        (:class:`sipral.signalling.TlsTrust`, default the platform's
        authorities; `docs/22-tls.md`). The check cannot be turned off.

        The first connection is made before this returns. When it fails or
        breaks, the stack reports it as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`
        on :attr:`events` and this class reconnects after one second,
        doubling up to thirty. On reconnect every account is re-pointed and
        re-registered if it was registering. :meth:`sipral.account.Account.register`
        while down is deferred; a call placed meanwhile raises
        ``SIPRAL_STATUS_TRANSPORT_DOWN``.

        ``invite_limit`` (:class:`sipral.signalling.InviteLimit`) is how fast
        one address may ring this stack: ``DEFAULT`` (ten at once, then one
        every two seconds, 480 past that) or ``VOICE_AGENT`` for a trunk.

        ``audio`` (:class:`sipral.enums.AudioMode`): ``DEVICE`` has the library
        drive the platform microphone and loudspeaker for every call
        (controlled through :attr:`audio`), the packets still leaving from
        each call's media socket; ``APPLICATION`` leaves frames to
        :class:`sipral.media.Media`. Default: ``DEVICE`` where :func:`features`
        has ``Feature.AUDIO_DEVICE``, else ``APPLICATION``; :attr:`audio_mode`
        says which. ``DEVICE`` on a build without it raises
        ``SIPRAL_STATUS_NOT_SUPPORTED``.

        ``audio_activation`` (:class:`sipral.enums.AudioActivation`):
        ``AUTOMATIC`` (``0``) opens the devices with the first call's media or
        ring and closes them with the last; ``MANUAL`` only between
        :meth:`sipral.audio.Audio.activate` and ``deactivate``.
        ``audio_probe_ms`` bounds every platform call (``0`` for three
        seconds); a silent driver is ``SIPRAL_STATUS_DEVICE_TIMED_OUT``.
        ``audio_device_rate_hz`` is the rate asked of the devices (``0`` for
        48 000).

        ``max_dialogs`` (``0`` for 128): a call arriving past it is answered
        503, one placed past it raises ``SIPRAL_STATUS_LIMIT_REACHED``.
        ``max_server_transactions`` (``0`` for 256) bounds concurrent incoming
        requests. ``diagnostic_decisions`` (``0`` for 64 per call) and
        ``diagnostic_records`` (``0`` for 32 calls) bound the diagnostic record.

        ``ice`` and ``nat`` are :class:`sipral.enums.Ice` /
        :class:`sipral.enums.Nat`, ``0`` for off. ``Ice.LITE`` suits a server
        reachable only at its advertised address: it answers a full ICE
        peer's checks and sends none (`docs/06-nat.md`, "ICE-lite").

        ``referrals=True`` delivers an out-of-dialog REFER (click-to-dial) as
        `SIPRAL_EVENT_KIND_REFERRAL`, to :meth:`accept_referral` or
        :meth:`reject_referral`. Off by default, refused 403: a peer that can
        make the phone dial is a toll-fraud vector.

        ``registrar_keepalive`` (on by default): each account found behind a
        NAT via ``stun_server`` sends its registrar a double CRLF every
        ``registrar_keepalive_ms`` (``0`` for 25 s, 1 000 to 120 000), so a
        port-filtering NAT still lets the registrar's INVITE in. An interval
        with it off is refused. Nothing is sent while suspended.

        ``stun_fallbacks`` (``host:port``, in order) are used when
        ``stun_server`` gives no address within 5.5 s. A failed server is
        skipped for 30 s, doubling up to ten minutes;
        `SIPRAL_EVENT_KIND_STUN_SERVER` reports each move or total failure.

        ``nat=Nat.STUN`` needs ``stun_server``; ``turn_server`` needs it plus
        ``turn_username`` and ``turn_password`` (`docs/06-nat.md`). The TURN
        credentials are copied into the library and never appear in any log,
        event or error.

        ``turn_transport`` (:class:`sipral.enums.Transport`): ``TCP`` for a
        network without UDP out, ``TLS`` for one open port (5349), ``0`` for
        UDP (RFC 8656 Section 3.1). Streamed, one connection per media socket
        is opened when `SIPRAL_EVENT_KIND_TURN_STREAM` asks. Over TLS the
        certificate is checked against ``turn_server_name`` (default: the host
        of ``turn_server``, so an IP certificate for an address) with
        ``turn_tls_context`` or the platform trust; checking cannot be off.

        ``rtp_port_min``/``rtp_port_max`` restrict media sockets without an
        explicit port to even ports from that range
        (`sipral_stack_rtp_port_reserve`), the odd one above kept for RTCP
        (RFC 3550 Section 11). Both ``0`` (default) leaves ports to the OS.
        An exhausted range raises ``SIPRAL_STATUS_EXHAUSTED``.

        ``stream_fallback`` handles a request too large for a UDP datagram
        (RFC 3261 Section 18.1.1, typically a challenge answer with two SRTP
        suites). On (default), `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` opens a
        TCP connection to the named address and binds it
        (`sipral_stack_transport_bind`); the held request goes on it. When the
        connection fails, or with ``False``, the stack is told at once
        (`sipral_stack_transport_failed_with`) and the waiting call ends as
        unreachable with `cause_sip` 513 and a `cause_text` naming size and
        limit. The event reaches :attr:`events` either way. ``stream_server``
        (``host:port``) redirects that connection, for a server with TCP on
        another port than UDP.

        ``dtmf_detection`` (:class:`sipral.enums.DtmfDetection`): ``AUTO``
        (``0``) listens for in-band digits on calls without telephone events,
        or ``ALWAYS``/``OFF``; :meth:`sipral.call.Call.set_dtmf_detection`
        overrides per call.

        ``srtp=SIPRAL_SRTP_BEST_EFFORT`` (:class:`sipral.enums.Srtp`) offers
        SDES on plain ``RTP/AVP``, for a PBX that answers ``RTP/SAVP`` with
        488. ``srtp_suites`` are offered and accepted unless an account names
        its own, most preferred first, by RFC 4568 / RFC 7714 names.

        ``path_mtu`` (``0`` unknown, else 576 or more): RFC 3261 Section 18.1.1
        moves a request to a stream within 200 bytes of it.
        ``datagram_without_stream_bytes`` deliberately deviates from that
        section for UDP-only servers: when no stream can be had, requests up to
        this size still go over UDP (``0`` never, at most 65 507), recorded as
        ``transport.kept.datagram``.

        ``pseudonym_salt`` (16+ bytes, a secret) keys the pseudonyms in logs
        and :meth:`state` so traces from two runs compare.
        ``diagnostic_trace`` logs whole SIP messages at trace level,
        credentials and keys removed; :meth:`set_diagnostic_trace` toggles it.

        ``system_echo_cancellation=False`` opens devices without the platform's
        echo cancellation, gain control and noise suppression (headset, or the
        application cancels itself); Linux has none.
        :meth:`sipral.audio.Audio.info` says what the platform did.

        ``held_audio`` (:class:`sipral.enums.HeldAudio`) is what a party this
        end holds hears. ``DEFAULT``/``SILENCE`` send silence in either mode,
        since application frames may be a microphone; ``APPLICATION`` sends
        the application's frames (music, announcement, agent speech).

        ``resolver`` (:data:`sipral.locate.Resolver`) answers
        `SIPRAL_EVENT_KIND_LOOKUP_WANTED` for ``server_uri`` accounts, one
        thread per lookup. Default :func:`sipral.locate.lookup` has no SRV or
        NAPTR; pass one that does (dnspython's) for servers that publish SRV.
        """
        self._loop = loop
        self.events: asyncio.Queue[_events.Event] = asyncio.Queue()
        self._calls: dict[int, Call] = {}
        #: Every account added and not removed, for :meth:`move_to`.
        self._accounts: list[Account] = []
        self._lock = threading.Lock()
        self._nat = nat
        self._turn = turn_server is not None
        self._turn_server_name = turn_server_name or (
            parse_address(turn_server)[0] if turn_server else None
        )
        self._turn_tls_context = turn_tls_context
        #: Every media socket's open connection to the TURN server, by the
        #: socket's `host:port`, under :attr:`_nat_lock`.
        self._turn_streams: dict[str, _TurnStream] = {}
        #: `SIPRAL_EVENT_KIND_TURN_STREAM` requests, acted on after the poll:
        #: nothing may call back into the stack from inside its callback.
        self._turn_asked: list[tuple[int, str, str, int]] = []
        #: Media socket per call handle while its TURN connection stands: the
        #: Refresh that frees the relay can come after the :class:`Call` is
        #: closed. Under :attr:`_nat_lock`.
        self._turn_sockets: dict[int, str] = {}
        self._turn_streamed = turn_transport in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS)
        #: Whether a request too large for a datagram gets a connection.
        self._stream_fallback = stream_fallback
        #: Where such a connection goes, when not to the address asked for.
        self._stream_server = parse_address(stream_server) if stream_server else None
        #: Stream requests and failed transports from one poll, acted on
        #: right after it.
        self._streams_asked: list[dict] = []
        self._streams_let_go: list[int] = []
        #: The stack retired the main TCP/TLS connection (keep-alives
        #: unanswered, RFC 5626 Section 4.4.1): nothing goes on it until a
        #: new one is bound.
        self._main_let_go = False
        #: Open stream connections by transport number, and destinations
        #: being connected; both under :attr:`_stream_lock`.
        self._stream_lock = threading.Lock()
        self._sip_streams: dict[int, _SipStream] = {}
        self._streams_opening: set[str] = set()
        self._next_stream = _FIRST_STREAM

        #: Media sockets named with `sipral_stack_nat_map`, by `host:port`,
        #: until `SIPRAL_EVENT_KIND_MEDIA_STARTED` hands them to
        #: :class:`sipral.media.Media` or the call drops them. Written by the
        #: caller's thread, read by the poll thread; :attr:`_nat_lock` covers
        #: this and the two dicts below.
        self._nat_lock = threading.Lock()
        self._stun_sockets: dict[str, socket.socket] = {}
        #: The probe socket of every network test under way, by its number.
        self._probes: dict[int, tuple[str, socket.socket]] = {}
        #: Per socket, events for the NAT mapping and (with TURN) the relay:
        #: a call on the socket waits for them, or the library answers
        #: `SIPRAL_STATUS_WRONG_STATE`.
        self._nat_waiters: dict[str, dict[str, threading.Event]] = {}

        signalling = signalling or lib.SIPRAL_TRANSPORT_UDP
        if signalling not in (lib.SIPRAL_TRANSPORT_UDP, lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS):
            raise ValueError("signalling is Transport.UDP, Transport.TCP or Transport.TLS")
        if signalling != lib.SIPRAL_TRANSPORT_UDP and not signalling_server:
            raise ValueError("SIP over TCP or TLS needs signalling_server, host:port")
        #: What SIP travels over, a `SipralTransport`.
        self.signalling = signalling
        self._streamed = signalling != lib.SIPRAL_TRANSPORT_UDP
        self._bind_host = bind_host
        #: No ``bind_host``: this class picks the advertised address (the
        #: route toward the first account's server), again after each
        #: :meth:`move_to`.
        self._routes = bind_host is None
        self._route_chosen = not self._routes or self._streamed or stream_server is not None
        self._resolver = resolver or lookup
        #: Lookups asked and locations found during a poll, acted on after it.
        self._lookups_asked: list[tuple[int, str, int]] = []
        self._located: list[tuple[int, str]] = []
        #: The signalling connection; every read and write holds the lock
        #: so TLS records from two threads do not interleave.
        self._link: socket.socket | None = None
        self._link_lock = threading.Lock()
        self._reconnecting = False
        self._server = parse_address(signalling_server) if self._streamed else None
        self._server_name = tls_server_name or (self._server[0] if self._server else None)
        self._tls_context = (
            (tls_trust or TlsTrust.platform()).context()
            if signalling == lib.SIPRAL_TRANSPORT_TLS
            else None
        )
        self._tls_pin = tls_trust.pin if tls_trust is not None else None
        #: Trust and server name for an account's own TLS connection when the
        #: account pins nothing.
        self._tls_trust = tls_trust or TlsTrust.platform()
        self._given_tls_server_name = tls_server_name
        self._first_failure: tuple[int, int, str] | None = None
        remote = ""
        if self._streamed:
            self._socket = None
            try:
                self._link = self._connect(bind_host)
                self.bind_address = format_address(*self._link.getsockname()[:2])
                remote = format_address(*self._link.getpeername()[:2])
            except (OSError, ssl.SSLError, ValueError) as refused:
                # told to the stack as soon as there is one, and tried again
                self._first_failure = classify(refused)
                host = bind_host if bind_host is not None else route_host(signalling_server)
                self.bind_address = format_address(host, bind_port)
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((bind_host if bind_host is not None else "0.0.0.0", bind_port))
        self._chosen_port = bind_port
        #: Whether the last :meth:`move_to` kept the UDP signalling port.
        #: ``False`` when it was taken at the new address and the system chose
        #: another (see :attr:`bind_address`); a peer or firewall rule knowing
        #: only the old port has to be told. ``True`` before any move.
        self.kept_signalling_port = True
        if not self._streamed:
            self._socket.setblocking(False)
            bound_host, bound_port = self._socket.getsockname()
            if bind_host is None:
                bound_host = route_host(stream_server)
            self.bind_address = format_address(bound_host, bound_port)

        self._origin = time.monotonic()

        # Kept on the instance: cffi frees a callback's trampoline once
        # Python drops it, and C would call freed memory.
        self._callback = ffi.callback("void(const sipral_event_t *, void *)")(
            self._on_event
        )

        if audio is None:
            audio = AudioMode.DEVICE if Feature.AUDIO_DEVICE in features() else AudioMode.APPLICATION
        #: Who pumps this stack's audio, an :class:`sipral.enums.AudioMode`.
        self.audio_mode = AudioMode(audio)
        #: The library's audio engine in device mode (:class:`sipral.audio.Audio`).
        self.audio = Audio(self)
        #: TURN connections the engine's thread found broken, reported from
        #: the poll thread: the engine's thread must not call into the stack.
        self._turn_lost: list[str] = []
        # Kept alive like the event callback; called on the engine's thread.
        self._audio_transmit = ffi.callback("void(const sipral_audio_transmit_t *, void *)")(
            self._on_audio_transmit
        )

        # The library copies the config during `sipral_stack_create`, so
        # these buffers need only outlive the call.
        bind_address = ffi.new("char[]", self.bind_address.encode("utf-8"))
        user_agent_buf = ffi.new("char[]", user_agent.encode("utf-8")) if user_agent else None
        codecs_buf = ffi.new("char[]", codecs.encode("utf-8")) if codecs else None
        entropy = ffi.new("uint8_t[]", os.urandom(32))
        media_seed = ffi.new("uint8_t[]", os.urandom(32))
        stun_server_buf = (
            ffi.new("char[]", stun_server.encode("utf-8")) if stun_server else None
        )
        stun_fallbacks_text = ",".join(stun_fallbacks).encode("utf-8") if stun_fallbacks else b""
        stun_fallbacks_buf = ffi.new("char[]", stun_fallbacks_text) if stun_fallbacks_text else None
        turn_server_buf = (
            ffi.new("char[]", turn_server.encode("utf-8")) if turn_server else None
        )
        turn_username_buf = (
            ffi.new("char[]", turn_username.encode("utf-8")) if turn_username else None
        )
        turn_password_buf = (
            ffi.new("char[]", turn_password.encode("utf-8")) if turn_password else None
        )

        config = ffi.new("sipral_stack_config_t *")
        config.size = ffi.sizeof("sipral_stack_config_t")
        config.event_callback = self._callback
        config.event_user_data = ffi.NULL
        config.transport = signalling
        config.bind_address = bind_address
        config.bind_address_len = len(self.bind_address)
        config.user_agent = user_agent_buf or ffi.NULL
        config.user_agent_len = len(user_agent.encode("utf-8")) if user_agent else 0
        config.entropy = entropy
        config.entropy_len = 32
        config.codecs = codecs_buf or ffi.NULL
        config.codecs_len = len(codecs.encode("utf-8")) if codecs else 0
        config.frame_ms = frame_ms
        config.offer_dtmf = _toggle(offer_dtmf)
        config.media_clock_unix_seconds = int(time.time())
        config.media_seed = media_seed
        config.media_seed_len = 32
        config.srtp = srtp
        config.ice = ice
        config.nat = nat
        if stun_server_buf is not None:
            config.stun_server = stun_server_buf
            config.stun_server_len = len(stun_server.encode("utf-8"))
        if stun_fallbacks_buf is not None:
            config.stun_fallbacks = stun_fallbacks_buf
            config.stun_fallbacks_len = len(stun_fallbacks_text)
        config.g729_annex_b = _toggle(g729_annex_b)
        if turn_server_buf is not None:
            config.turn_server = turn_server_buf
            config.turn_server_len = len(turn_server.encode("utf-8"))
        if turn_username_buf is not None:
            config.turn_username = turn_username_buf
            config.turn_username_len = len(turn_username.encode("utf-8"))
        if turn_password_buf is not None:
            config.turn_password = turn_password_buf
            config.turn_password_len = len(turn_password.encode("utf-8"))
        config.referrals = _toggle(referrals)
        config.registrar_keepalive = _toggle(registrar_keepalive)
        config.registrar_keepalive_ms = registrar_keepalive_ms
        config.turn_transport = turn_transport
        config.audio = int(self.audio_mode)
        config.audio_activation = audio_activation
        if self.audio_mode == AudioMode.DEVICE:
            config.audio_transmit_callback = self._audio_transmit
        config.audio_probe_ms = audio_probe_ms
        config.audio_device_rate_hz = audio_device_rate_hz
        config.max_dialogs = max_dialogs
        config.max_server_transactions = max_server_transactions
        config.diagnostic_decisions = diagnostic_decisions
        config.diagnostic_records = diagnostic_records
        config.rtp_port_min = rtp_port_min
        config.rtp_port_max = rtp_port_max
        config.dtmf_detection = int(dtmf_detection)
        suites = srtp_suites if isinstance(srtp_suites, str) else ",".join(srtp_suites or ())
        suites_bytes = suites.encode("utf-8")
        suites_buf = ffi.new("char[]", suites_bytes) if suites_bytes else None
        if suites_buf is not None:
            config.srtp_suites = suites_buf
            config.srtp_suites_len = len(suites_bytes)
        config.path_mtu = path_mtu
        config.datagram_without_stream_bytes = datagram_without_stream_bytes
        salt_buf = ffi.new("uint8_t[]", pseudonym_salt) if pseudonym_salt else None
        if salt_buf is not None:
            config.pseudonym_salt = salt_buf
            config.pseudonym_salt_len = len(pseudonym_salt)
        config.diagnostic_trace = _toggle(diagnostic_trace)
        config.system_echo_cancellation = _toggle(system_echo_cancellation)
        config.held_audio = int(held_audio)
        #: The RTP port range media sockets are bound in, or ``None``.
        self.rtp_ports = (rtp_port_min, rtp_port_max) if rtp_port_min or rtp_port_max else None
        #: Callbacks given to `sipral_stack_log`, kept alive.
        self._log_callbacks: list = []

        out_stack = ffi.new("sipral_handle_t *")
        try:
            check(lib.sipral_stack_create(config, out_stack), "sipral_stack_create")
        except Exception:
            # e.g. device mode without a backend here: release the socket
            if self._socket is not None:
                self._socket.close()
            if self._link is not None:
                self._link.close()
            raise
        self.handle = int(out_stack[0])

        self._selector = selectors.DefaultSelector()
        self._closed = threading.Event()
        if self._socket is not None:
            self._selector.register(self._socket, selectors.EVENT_READ, data="main")
        if invite_limit is not None:
            limit = InviteLimit(*invite_limit)
            check(
                lib.sipral_stack_invite_limit(self.handle, limit.every_ms, limit.burst),
                "sipral_stack_invite_limit",
            )
        if self._link is not None:
            self._install_link(self._link, remote)
        elif self._streamed:
            error, tls, detail = self._first_failure or classify(OSError("no connection"))
            self._report_failure(error, tls, detail)
            self._reconnect_later()
        self._transmit = ffi.new("sipral_transmit_t *")
        self._transmit_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._transmit_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._transmit_source = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._stun_transmit = ffi.new("sipral_transmit_t *")
        self._stun_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._stun_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._stun_source = ffi.new(f"char[{_ADDRESS_BYTES}]")
        self._farewell = ffi.new("sipral_media_packet_t *")
        self._farewell_data = ffi.new(f"uint8_t[{_TRANSMIT_BYTES}]")
        self._farewell_destination = ffi.new(f"char[{_ADDRESS_BYTES}]")

        self._thread = threading.Thread(
            target=self._run, name="sipral-stack", daemon=True
        )
        self._thread.start()

    def __enter__(self) -> "Stack":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001 -- never raise out of __del__
            pass

    def now_ms(self) -> int:
        """Milliseconds since creation: the `now_ms` every entry point takes."""
        return int((time.monotonic() - self._origin) * 1000)

    def settings(self) -> Settings:
        """The settings in effect, defaults filled in, with the SRTP suites
        in offer order."""
        raw = ffi.new("sipral_stack_settings_t *")
        raw.size = ffi.sizeof("sipral_stack_settings_t")
        _retry(lambda: lib.sipral_stack_settings(self.handle, raw), "sipral_stack_settings")
        count = int(raw.srtp_suite_count)
        suites = ffi.new("sipral_srtp_suite_t[]", max(count, 1))
        written = ffi.new("size_t *")
        _retry(
            lambda: lib.sipral_stack_srtp_suite_order(self.handle, suites, count, written),
            "sipral_stack_srtp_suite_order",
        )
        return Settings.read(raw, [int(suites[i]) for i in range(count)])

    def set_diagnostic_trace(self, on: bool) -> None:
        """Whether trace-level logging writes SIP messages whole, with peers,
        instead of pseudonymised (the default). Credentials and keys are
        removed either way; needs the log at ``LogLevel.TRACE``."""
        _retry(
            lambda: lib.sipral_stack_diagnostic_trace(self.handle, _toggle(on)),
            "sipral_stack_diagnostic_trace",
        )

    def _advertise_toward(self, peer: str) -> str:
        """The route toward ``peer`` on this stack's port; the first one
        also becomes the stack's `Via` address."""
        port = parse_address(self.bind_address)[1]
        address = format_address(route_host(peer), port)
        if not self._route_chosen:
            self._route_chosen = True
            if address != self.bind_address:
                self._advertise_main(address)
        return address

    def _advertise_main(self, address: str) -> None:
        """Make ``address`` the one the stack's `Via` carries."""
        local = address.encode("utf-8")
        _retry(
            lambda: lib.sipral_stack_transport_bind(
                self.handle,
                lib.SIPRAL_TRANSPORT_MAIN,
                lib.SIPRAL_TRANSPORT_UDP,
                local,
                len(local),
                ffi.NULL,
                0,
                self.now_ms(),
                ffi.NULL,
            ),
            "sipral_stack_transport_bind",
        )
        self.bind_address = address

    # -- accounts and calls --------------------------------------------

    def add_account(
        self,
        aor: str,
        *,
        registrar_address: str | None = None,
        server_uri: str | None = None,
        server_naptr: bool = False,
        keepalive_ms: int = 0,
        tls_pin: str | None = None,
        stream_protocol: int = 0,
        registrar: str | None = None,
        contact: str | None = None,
        display_name: str | None = None,
        auth_user: str | None = None,
        auth_password: str | None = None,
        expires_seconds: int = 0,
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
        websocket_host: str | None = None,
        websocket_resource: str | None = None,
    ) -> Account:
        """`sipral_account_add`. See :class:`sipral.account.Account`.

        ``realms`` the password answers (RFC 3261 Section 22.1). Left out: the
        realm the server first challenges with plus every REGISTER realm; an
        SBC challenging calls under its own realm needs both named. Other
        challenges go unanswered, reported as
        `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED` with ``fields["refusal"]``
        (:class:`sipral.enums.ChallengeRefusal`), ``"server"`` and ``"realms"``.

        ``srtp`` is a floor over the stack's own (a call may ask for more,
        never less); ``srtp_suites`` by RFC 4568 / RFC 7714 name, most
        preferred first. ``stir_verification``
        (:class:`sipral.enums.StirVerification`) applies to incoming
        `Identity` once :meth:`stir` set anchors. ``stir_key`` (P-256: bare 32
        bytes, or SEC1/PKCS #8 in DER or PEM) with ``stir_certificate_url``
        signs every outgoing call (RFC 8224) as ``stir_orig`` or the number in
        ``aor``, with ``stir_attestation`` (:class:`sipral.enums.Attestation`,
        ``NONE`` for A) and ``stir_origid``. Call :meth:`stir` first (anchors
        ``None`` to only sign): it gives the stack the clock.
        ``recording_in_clear`` lets encrypted calls be recorded as plain RTP;
        otherwise copies go as SRTP or not at all (RFC 7866 §12.2).

        ``session_timer`` (:class:`sipral.enums.SessionTimer`): ``0`` default,
        ``OFF``, or ``INTERVAL`` with ``session_interval_seconds`` (90+,
        RFC 4028). ``privacy`` (:class:`sipral.enums.Privacy`, RFC 3323):
        ``Privacy.ID`` places calls anonymous in `From`. ``trusted_peers`` (IP
        literals, list or comma-separated) are the only peers whose
        `P-Asserted-Identity` is believed and to whom ours is sent (RFC 3325);
        :attr:`sipral.events.Event.identity` tells which.

        Without ``registrar`` the account never registers; ``registrar_address``
        is still its outbound proxy. Two loopback stacks calling directly each
        add such an account pointed at the other's :attr:`bind_address`.

        ``server_uri`` (``sip:pbx.example.com``, ``sips:example.com:5061``) is
        located per RFC 3263 with the stack's ``resolver``, instead of
        ``registrar_address``: give exactly one. `SIPRAL_EVENT_KIND_LOCATED`
        and `SIPRAL_EVENT_KIND_LOCATE_FAILED` report the result. A REGISTER
        waits for it; a call without ``destination`` before then raises
        ``SIPRAL_STATUS_WRONG_STATE``. ``server_naptr`` queries NAPTR before
        SRV (RFC 3263 Section 4.1).

        ``keepalive_ms`` (1 000 to 120 000, ``0`` never) keeps the flow open
        regardless of STUN (CRLF on UDP, ping on a stream), for a NAT that
        forgets sooner than the REGISTER refresh.

        ``tls_pin`` is the SHA-256 fingerprint of the one certificate trusted
        (forms as :meth:`TlsTrust.pinned`), for an application running the
        account's TLS itself; :meth:`sipral.account.Account.check_certificate`
        judges a presented certificate.

        ``stream_protocol`` (``Transport.TCP``/``TLS``/``WS``/``WSS``, UDP
        stacks only) gives the account its own connection to its server,
        beside UDP accounts on the same stack. This class opens it on
        `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` regardless of ``stream_fallback``
        and reopens it when it closes; TLS is checked against ``tls_pin`` or
        the stack's ``tls_trust``. Until open, a call raises
        ``SIPRAL_STATUS_TRANSPORT_DOWN``. ``WS``/``WSS`` run a WebSocket (RFC
        7118) asking for ``websocket_resource`` (``/ws``) with
        ``websocket_host`` as ``Host`` (the server's address).
        """
        if (registrar_address is None) == (server_uri is None):
            raise ValueError("an account names its server by registrar_address or by server_uri, one of the two")
        if stream_protocol and (
            stream_protocol not in _OWN_STREAMS or self._streamed
        ):
            raise ValueError("stream_protocol is Transport.TCP, TLS, WS or WSS, on a stack that signals over UDP")
        advertised = None
        if self._routes and contact is None and registrar_address is not None and not self._streamed:
            advertised = self._advertise_toward(registrar_address)
        account = Account.add(
            self,
            aor,
            registrar_address=registrar_address,
            server_uri=server_uri,
            server_naptr=server_naptr,
            keepalive_ms=keepalive_ms,
            tls_pin=tls_pin,
            stream_protocol=stream_protocol,
            websocket_host=websocket_host,
            websocket_resource=websocket_resource,
            advertised=advertised,
            registrar=registrar,
            contact=contact,
            display_name=display_name,
            auth_user=auth_user,
            auth_password=auth_password,
            expires_seconds=expires_seconds,
            session_timer=session_timer,
            session_interval_seconds=session_interval_seconds,
            privacy=privacy,
            trusted_peers=trusted_peers,
            srtp=srtp,
            srtp_suites=srtp_suites,
            stir_verification=stir_verification,
            stir_key=stir_key,
            stir_certificate_url=stir_certificate_url,
            stir_orig=stir_orig,
            stir_origid=stir_origid,
            stir_attestation=stir_attestation,
            recording_in_clear=recording_in_clear,
            realms=realms,
        )
        with self._lock:
            self._accounts.append(account)
        return account

    def stir(
        self,
        anchors: bytes | str | None,
        *,
        freshness_seconds: int = 0,
        certificate_wait_ms: int = 0,
        unix_seconds: int | None = None,
        accept_service_provider_codes: bool = False,
    ) -> None:
        """Verify incoming callers against ``anchors`` (PEM or DER, the STI-PA
        roots under SHAKEN) from now on (RFC 8224).

        ``unix_seconds`` is the wall clock PASSporTs are signed and judged by
        (default: this machine's); a signing-only stack calls this with
        ``None`` anchors before adding accounts. A wanted certificate arrives
        as `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` and is supplied with
        :meth:`stir_certificate`. ``accept_service_provider_codes`` lets an
        SPC certificate vouch for any caller, as in SHAKEN; otherwise a
        certificate covers only the numbers it names.
        """
        raw = anchors.encode("utf-8") if isinstance(anchors, str) else anchors
        anchors_buf = ffi.new("uint8_t[]", raw) if raw else None
        config = ffi.new("sipral_stir_config_t *")
        config.size = ffi.sizeof("sipral_stir_config_t")
        if anchors_buf is not None:
            config.anchors = anchors_buf
            config.anchors_len = len(raw)
        config.freshness_seconds = freshness_seconds
        config.certificate_wait_ms = certificate_wait_ms
        config.unix_seconds = int(time.time()) if unix_seconds is None else unix_seconds
        config.accept_service_provider_codes = 1 if accept_service_provider_codes else 0
        _retry(
            lambda: lib.sipral_stack_stir(self.handle, config, self.now_ms()),
            "sipral_stack_stir",
        )

    def stir_certificate(self, call: int, chain: bytes | None) -> None:
        """Supply the chain a verification asked for (PEM or DER, signing
        certificate first), or ``None`` if it could not be fetched. ``call``
        is the handle from the event; the call is not announced yet."""
        chain_buf = ffi.new("uint8_t[]", chain) if chain else None
        _retry(
            lambda: lib.sipral_call_stir_certificate(
                self.handle,
                call,
                chain_buf if chain_buf is not None else ffi.NULL,
                len(chain) if chain else 0,
                self.now_ms(),
            ),
            "sipral_call_stir_certificate",
        )

    def place_call(
        self,
        account: Account,
        target: str,
        *,
        media_host: str | None = None,
        media_port: int = 0,
        destination: str | None = None,
        srtp: int = 0,
        ice: int = 0,
        text: bool = False,
        feedback: bool = False,
        focus: bool = False,
        codecs: str | None = None,
        headers=None,
        follow_redirects: bool = False,
    ) -> Call:
        """Place a call, this stack running its audio.

        A media socket is opened before the INVITE and offered as the call's
        media address; :class:`sipral.media.Media` starts on
        `SIPRAL_EVENT_KIND_MEDIA_STARTED`.

        ``ice`` is a :class:`sipral.enums.Ice`, ``0`` for the stack default.
        With ``nat=Nat.STUN`` this blocks the calling thread (never the poll
        thread) until the socket's `SIPRAL_EVENT_KIND_NAT_MAPPING`; sooner
        would be `SIPRAL_STATUS_WRONG_STATE`.

        ``text`` offers real-time text (RFC 4103) on a second socket
        (:meth:`sipral.call.Call.send_text`, ``call.text``); not offered with
        SRTP or ICE, which the stream lacks. ``feedback`` offers RTP/AVPF
        (RFC 4585) with NACK and reduced-size RTCP (RFC 5506); off by default
        because an AVP-only peer refuses it. ``focus`` marks this end a
        conference focus (RFC 4579, `isfocus`). ``codecs`` (``"PCMA,PCMU"``)
        replaces the stack's offer order. ``headers`` (pairs or a mapping) go
        on the INVITE. ``follow_redirects`` follows a 3xx's targets (RFC 3261
        §8.1.3.4); otherwise a 3xx ends the call and its `Contact` is the
        application's to act on.

        ``media_host`` defaults to the route toward ``destination`` or the
        account's server.
        """
        media_host = self._media_host(media_host, account, destination)
        media_socket = self.open_media_socket(media_host, media_port)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)
        text_socket = self.open_media_socket(media_host) if text else None

        target_buf = ffi.new("char[]", target.encode("utf-8"))
        media_address_buf = ffi.new("char[]", media_address.encode("utf-8"))
        destination_buf = (
            ffi.new("char[]", destination.encode("utf-8")) if destination else None
        )

        config = ffi.new("sipral_call_config_t *")
        config.size = ffi.sizeof("sipral_call_config_t")
        config.target = target_buf
        config.target_len = len(target.encode("utf-8"))
        config.media_address = media_address_buf
        config.media_address_len = len(media_address.encode("utf-8"))
        config.srtp = srtp
        config.ice = ice
        if destination_buf is not None:
            config.destination = destination_buf
            config.destination_len = len(destination.encode("utf-8"))
        text_buf = None
        if text_socket is not None:
            text_address = format_address(*text_socket.getsockname()).encode("utf-8")
            text_buf = ffi.new("char[]", text_address)
            config.text_address = text_buf
            config.text_address_len = len(text_address)
        config.feedback = lib.SIPRAL_TOGGLE_ON if feedback else lib.SIPRAL_TOGGLE_DEFAULT
        config.focus = 1 if focus else 0
        config.follow_redirects = 1 if follow_redirects else 0
        codecs_buf = None
        if codecs is not None:
            codecs_bytes = codecs.encode("utf-8")
            codecs_buf = ffi.new("char[]", codecs_bytes)
            config.codecs = codecs_buf
            config.codecs_len = len(codecs_bytes)
        headers_kept = None
        if headers:
            headers_array, headers_kept = header_array(headers)
            config.headers = headers_array
            config.headers_len = len(headers_kept) // 2

        out_call = ffi.new("sipral_handle_t *")
        try:
            _retry(
                lambda: lib.sipral_call_place(
                    self.handle, account.handle, config, out_call, self.now_ms()
                ),
                "sipral_call_place",
            )
        except Exception:
            self._forget_media_socket(media_address)
            media_socket.close()
            if text_socket is not None:
                self._close_socket(text_socket)
            raise
        call = Call(self, int(out_call[0]), media_socket, media_address, text_socket)
        self.register_call(call)
        return call

    def answer_call(
        self,
        event: _events.Event,
        *,
        media_host: str | None = None,
        media_port: int = 0,
        text: bool = False,
        feedback: bool = False,
        focus: bool = False,
        codecs: str | None = None,
    ) -> Call:
        """Open a media socket for an incoming call and answer it there.

        ``event`` is the `SIPRAL_EVENT_KIND_INCOMING_CALL`; the :class:`Call`
        is built here. To refuse, :meth:`reject_call` needs no socket.

        With ``nat=Nat.STUN`` this blocks like :meth:`place_call`.

        ``text``, ``feedback``, ``focus``, ``codecs`` are as for
        :meth:`place_call`. An answer keeps the offer's order (RFC 3264
        §6.1), so ``codecs`` picks which codecs, not which comes first.

        ``media_host`` defaults to the route toward the account's server.
        """
        rung = self.call_for(event.call)
        if rung is not None:
            if text or feedback or focus or codecs is not None:
                rung.answer_with(feedback=feedback, focus=focus, codecs=codecs)
            else:
                rung.answer()
            return rung
        call = self._incoming(event, media_host, media_port, text)
        media_socket, media_address = call._media_socket, call._media_address
        text_socket = call._text_socket
        try:
            if text or feedback or focus or codecs is not None:
                call.answer_with(feedback=feedback, focus=focus, codecs=codecs)
            else:
                call.answer()
        except Exception:
            self.forget_call(call.handle)
            self._forget_media_socket(media_address)
            media_socket.close()
            if text_socket is not None:
                self._close_socket(text_socket)
            raise
        return call

    def _incoming(
        self, event: _events.Event, media_host: str | None, media_port: int, text: bool
    ) -> Call:
        """The registered, unanswered :class:`Call` with its socket mapped."""
        media_host = self._media_host(media_host, self._account_for(event.account), None)
        media_socket = self.open_media_socket(media_host, media_port)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)
        text_socket = self.open_media_socket(media_host) if text else None
        call = Call(self, event.call, media_socket, media_address, text_socket)
        self.register_call(call)
        return call

    def ring_call(
        self,
        event: _events.Event,
        *,
        media: bool = False,
        media_host: str | None = None,
        media_port: int = 0,
        srtp: int = 0,
        codecs: str | None = None,
    ) -> Call:
        """Say an incoming call is ringing, and build its :class:`Call`.

        The media socket is opened now; :meth:`answer_call` with the same
        event, or :meth:`Call.answer`, answers later on it. Without ``media``
        this sends 180 Ringing; with it a 183 with an answer, so the caller
        hears what the application plays before anyone answers (``srtp`` and
        ``codecs`` as for :meth:`place_call`).
        """
        call = self._incoming(event, media_host, media_port, False)
        try:
            if media:
                call.ring_media(srtp=srtp, codecs=codecs)
            else:
                call.ring()
        except Exception:
            self.forget_call(call.handle)
            self._forget_media_socket(call._media_address)
            call._media_socket.close()
            raise
        return call

    def accept_transfer_placed(self, event: _events.Event, placed: Call) -> None:
        """Accept a `SIPRAL_EVENT_KIND_TRANSFER_REQUESTED` REFER with a call
        the application placed itself: 202, then ``placed``'s progress is
        reported to the far end in NOTIFYs."""
        _retry(
            lambda: lib.sipral_call_accept_transfer_placed(
                self.handle, event.call, placed.handle, self.now_ms()
            ),
            "sipral_call_accept_transfer_placed",
        )

    def _close_socket(self, sock: socket.socket) -> None:
        """Close a secondary media socket and give its port back to the range."""
        try:
            port = sock.getsockname()[1]
        except OSError:
            return
        sock.close()
        self._give_back_port(port)

    def open_media_socket(self, host: str, port: int = 0) -> socket.socket:
        """A non-blocking UDP socket for a call's media, bound at ``host``.

        At ``port`` when given; else at an even port reserved from the RTP
        range (a port another process holds is skipped), or wherever the OS
        puts it without a range. ``SIPRAL_STATUS_EXHAUSTED`` when every pair
        is taken.
        """
        if port or self.rtp_ports is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((host, port))
            sock.setblocking(False)
            return sock
        low, high = self.rtp_ports
        failure: OSError | None = None
        for _ in range(max(1, (high - low + 1) // 2)):
            reserved = ffi.new("uint32_t *")
            _retry(
                lambda: lib.sipral_stack_rtp_port_reserve(self.handle, reserved),
                "sipral_stack_rtp_port_reserve",
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((host, int(reserved[0])))
            except OSError as error:
                sock.close()
                self._give_back_port(int(reserved[0]))
                failure = error
                continue
            sock.setblocking(False)
            return sock
        assert failure is not None
        raise failure

    def _give_back_port(self, port: int) -> None:
        """Release a reserved port no call took; best effort, since a call's
        port comes back when the call ends."""
        if self.rtp_ports is None:
            return
        try:
            _retry(
                lambda: lib.sipral_stack_rtp_port_release(self.handle, port),
                "sipral_stack_rtp_port_release",
            )
        except Exception:  # noqa: BLE001 -- nothing reserved, nothing to give back
            pass

    def set_log(self, level: int, handler=None) -> None:
        """Send the log at ``level`` (:class:`sipral.enums.LogLevel`) and
        louder to ``handler``; ``LogLevel.OFF`` or no handler turns it off.

        ``handler(level, target, message, suppressed)`` runs on the thread
        that just left the stack (usually the poll thread), outside the
        stack's lock, so it may call back in. Lines are redacted: no user
        part, number, IP address or credential (`docs/17-observability.md`).
        ``suppressed`` counts lines dropped by flood control before this one.
        """
        if handler is None or level == LogLevel.OFF:
            _retry(
                lambda: lib.sipral_stack_log(self.handle, LogLevel.OFF, ffi.NULL, ffi.NULL),
                "sipral_stack_log",
            )
            return

        def deliver(record, _user_data) -> None:
            target = ffi.unpack(record.target, record.target_len).decode("utf-8")
            message = ffi.unpack(record.message, record.message_len).decode("utf-8")
            handler(LogLevel(record.level), target, message, int(record.suppressed))

        callback = ffi.callback("void(const sipral_log_record_t *, void *)")(deliver)
        _retry(
            lambda: lib.sipral_stack_log(self.handle, int(level), callback, ffi.NULL),
            "sipral_stack_log",
        )
        # The replaced callback may still be delivering on the poll thread.
        self._log_callbacks.append(callback)

    def state(self) -> str:
        """The stack's state as redacted text for a crash report. Safe from
        any thread; never waits."""
        buffer = ffi.new(f"char[{lib.SIPRAL_STATE_TEXT_MAX}]")
        length = ffi.new("size_t *")
        check(
            lib.sipral_stack_state_text(self.handle, buffer, lib.SIPRAL_STATE_TEXT_MAX, length),
            "sipral_stack_state_text",
        )
        return ffi.string(buffer, int(length[0]) - 1).decode("utf-8")

    def diagnostics_json(self) -> str:
        """The diagnostic record of every kept call as JSON: each decision
        the stack made and why."""
        needed = ffi.new("size_t *")
        capacity = 4096
        while True:
            buffer = ffi.new(f"char[{capacity}]")
            status = lib.sipral_stack_diagnostics_json(self.handle, buffer, capacity, needed)
            if status == lib.SIPRAL_STATUS_BUFFER_TOO_SMALL:
                capacity = int(needed[0])
                continue
            if status == lib.SIPRAL_STATUS_BUSY:
                time.sleep(0.001)
                continue
            check(status, "sipral_stack_diagnostics_json")
            return ffi.string(buffer).decode("utf-8")

    def log_to(self, logger: logging.Logger | None = None, level: int | None = None) -> None:
        """Send this stack's log to the standard :mod:`logging` module.

        Each line goes to ``logger.getChild(target)`` (``sipral.call``,
        ``sipral.sip``, ...; `docs/17-observability.md`). Levels map to the
        same-named :mod:`logging` levels, ``TRACE`` to :data:`TRACE`.
        ``level`` defaults to the logger's effective level now, so dropped
        lines are never formatted. ``record.sipral_suppressed`` counts lines
        lost to flood control. Replaces :meth:`set_log`'s handler;
        ``set_log(LogLevel.OFF)`` turns it off.
        """
        logger = logger if logger is not None else logging.getLogger("sipral")
        if level is None:
            level = _log_level_for(logger.getEffectiveLevel())
        children: dict[str, logging.Logger] = {}

        def deliver(line_level: int, target: str, message: str, suppressed: int) -> None:
            child = children.get(target)
            if child is None:
                child = children.setdefault(target, logger.getChild(target))
            python_level = _PYTHON_LEVELS.get(line_level, logging.DEBUG)
            if child.isEnabledFor(python_level):
                child.log(python_level, "%s", message, extra={"sipral_suppressed": suppressed})

        self.set_log(level, deliver)

    def counters(self) -> Counters:
        """Health counters since creation; one struct copy, cheap enough to
        sample on a timer."""
        out = ffi.new("sipral_counters_t *")
        out.size = ffi.sizeof("sipral_counters_t")
        _retry(lambda: lib.sipral_stack_counters(self.handle, out), "sipral_stack_counters")
        return Counters.from_raw(out)

    def set_stun_servers(self, servers: Sequence[str]) -> None:
        """Replace the STUN servers (``host:port``, preferred first) in place.

        Every mapped socket is asked again at once; ``EventKind.STUN_SERVER``
        and ``EventKind.NAT_MAPPING`` report the result. On a stack created
        without STUN, mapping starts now for signalling and new media
        sockets. An empty list stops STUN: moved accounts re-register their
        own address. With a TURN server an empty list raises
        ``SIPRAL_STATUS_INVALID_ARGUMENT``.
        """
        text = ",".join(servers).encode("utf-8")
        buffer = ffi.new("char[]", text) if text else ffi.NULL
        _retry(
            lambda: lib.sipral_stack_stun_servers(self.handle, buffer, len(text), self.now_ms()),
            "sipral_stack_stun_servers",
        )
        self._nat = lib.SIPRAL_NAT_STUN if text else lib.SIPRAL_NAT_OFF

    def reject_call(self, event: _events.Event, code: int = 486) -> None:
        """Reject an unanswered incoming call; no :class:`Call` or socket needed."""
        _retry(
            lambda: lib.sipral_call_reject(self.handle, event.call, code, self.now_ms()),
            "sipral_call_reject",
        )

    def accept_referral(
        self,
        event: _events.Event,
        *,
        media_host: str | None = None,
        media_port: int = 0,
        srtp: int = 0,
        ice: int = 0,
    ) -> Call:
        """Take a REFER outside any dialog and place the call it asks for.

        ``event`` is a `SIPRAL_EVENT_KIND_REFERRAL` with
        ``fields["status_code"]`` zero. The stack answers 202, places the call
        from the event's account to ``fields["target"]`` (the REFER's, never
        the caller's) and reports progress to the referrer. Returns the
        placed :class:`Call`. Never automatic: whoever sends a REFER can make
        this line dial anything.
        """
        media_host = self._media_host(media_host, self._account_for(event.account), None)
        media_socket = self.open_media_socket(media_host, media_port)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)

        media_address_buf = ffi.new("char[]", media_address.encode("utf-8"))
        config = ffi.new("sipral_call_config_t *")
        config.size = ffi.sizeof("sipral_call_config_t")
        config.media_address = media_address_buf
        config.media_address_len = len(media_address.encode("utf-8"))
        config.srtp = srtp
        config.ice = ice

        out_placed = ffi.new("sipral_handle_t *")
        try:
            _retry(
                lambda: lib.sipral_call_accept_transfer(
                    self.handle, event.call, config, out_placed, self.now_ms()
                ),
                "sipral_call_accept_transfer",
            )
        except Exception:
            self._forget_media_socket(media_address)
            media_socket.close()
            raise
        call = Call(self, int(out_placed[0]), media_socket, media_address)
        self.register_call(call)
        return call

    def reject_referral(self, event: _events.Event, code: int = 603) -> None:
        """Refuse an out-of-dialog REFER with ``code`` (300 to 699)."""
        _retry(
            lambda: lib.sipral_call_reject_transfer(
                self.handle, event.call, code, self.now_ms()
            ),
            "sipral_call_reject_transfer",
        )

    def redirect_call(
        self,
        event: _events.Event,
        targets: Sequence[str] | str,
        *,
        status_code: int = 302,
        reason: str | None = None,
    ) -> None:
        """Redirect an unanswered incoming call: ``status_code`` 300 to 399
        (302 default), ``targets`` (list or comma-separated URIs) in
        `Contact`. With ``reason`` (RFC 5806: ``unconditional``,
        ``user-busy``, ``no-answer``...) a `Diversion` names the called
        address, so the next phone shows why it was forwarded."""
        listed = targets if isinstance(targets, str) else ", ".join(targets)
        targets_bytes = listed.encode("utf-8")
        reason_bytes = (reason or "").encode("utf-8")
        _retry(
            lambda: lib.sipral_call_redirect(
                self.handle,
                event.call,
                status_code,
                targets_bytes,
                len(targets_bytes),
                reason_bytes or ffi.NULL,
                len(reason_bytes),
                self.now_ms(),
            ),
            "sipral_call_redirect",
        )

    def call_identity(self, call: int | _events.Event, which: int) -> list[str]:
        """One identity list from the INVITE (``which``: an
        :class:`sipral.enums.IdentityText`) for a call without a
        :class:`sipral.call.Call` yet; ``call`` is its incoming event or
        handle. See :meth:`sipral.call.Call.identity` otherwise."""
        handle = call.call if isinstance(call, _events.Event) else call
        count = ffi.new("size_t *")
        _retry(
            lambda: lib.sipral_call_identity_count(self.handle, handle, which, count),
            "sipral_call_identity_count",
        )
        texts = []
        needed = ffi.new("size_t *")
        for index in range(int(count[0])):
            capacity = 256
            while True:
                buffer = ffi.new(f"char[{capacity}]")
                status = lib.sipral_call_identity_text(
                    self.handle, handle, index, which, buffer, capacity, needed
                )
                if status == lib.SIPRAL_STATUS_BUFFER_TOO_SMALL:
                    capacity = int(needed[0])
                    continue
                break
            check(status, "sipral_call_identity_text")
            texts.append(ffi.string(buffer).decode("utf-8", "replace"))
        return texts

    def move_to(self, host: str, *, link: int = Link.WIRED) -> Recovery:
        """The network changed; ``host`` is this machine's new address.

        Signalling is rebound (or reconnected over TCP/TLS) at ``host``, the
        change reported with ``link`` (:class:`sipral.enums.Link`), and every
        account without its own `Contact` rebound. Returns the stack's
        :class:`sipral.enums.Recovery`. On ``REBUILD`` each call described at
        the old address gets `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`, to answer
        with :meth:`sipral.call.Call.readdress`. Accounts with an explicit
        ``contact`` are the application's to :meth:`sipral.account.Account.rebind`.

        A stack without ``bind_host`` keeps its wildcard socket and port and
        re-picks routes: toward the first account's server (``host`` only
        when no server is an address), each account toward its own.
        """
        previous = parse_address(self.bind_address)[0]
        picks = self._routes and not self._streamed
        if self._streamed:
            self._move_link(host)
        elif picks:
            self._advertise_again(host)
        else:
            self._move_socket(host)

        before = previous.encode("utf-8")
        after = host.encode("utf-8")
        recovery = ffi.new("uint32_t *")
        _retry(
            lambda: lib.sipral_stack_network_changed(
                self.handle,
                link,
                before,
                len(before),
                ffi.NULL,
                0,
                1,
                link,
                after,
                len(after),
                ffi.NULL,
                0,
                1,
                self.now_ms(),
                recovery,
            ),
            "sipral_stack_network_changed",
        )
        with self._lock:
            accounts = list(self._accounts)
        for account in accounts:
            if account.contact_given:
                continue
            if picks and _is_address(account.registrar_address):
                advertised = self._advertise_toward(account.registrar_address)
                account.rebind(
                    contact=_default_contact(account.aor, advertised, account.contact_parameters)
                )
                account.advertised = advertised
            else:
                account.rebind()
        return Recovery(int(recovery[0]))

    def _advertise_again(self, host: str) -> None:
        """Re-pick the advertised address of a wildcard-bound stack after a
        move; the socket stays. Raises if ``host`` is not on this machine."""
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.bind((host, 0))
        self.kept_signalling_port = True
        self._route_chosen = False
        with self._lock:
            servers = [account.registrar_address for account in self._accounts]
        server = next((one for one in servers if one and _is_address(one)), None)
        if server is not None:
            self._advertise_toward(server)
            return
        local = format_address(host, parse_address(self.bind_address)[1])
        if local != self.bind_address:
            self._advertise_main(local)


    def _move_link(self, host: str) -> None:
        """Reconnect signalling from ``host``; on failure, report and retry."""
        self._bind_host = host
        with self._link_lock:
            old, self._link = self._link, None
        if old is not None:
            try:
                self._selector.unregister(old)
            except (KeyError, ValueError, OSError):
                pass
            old.close()
        try:
            sock = self._connect(host)
            self.bind_address = format_address(*sock.getsockname()[:2])
            self._install_link(sock, format_address(*sock.getpeername()[:2]))
        except (OSError, ssl.SSLError, ValueError) as refused:
            self.bind_address = format_address(host, 0)
            self._report_failure(*classify(refused))
            self._reconnect_later()

    def _signalling_socket(self, host: str) -> socket.socket:
        """A UDP signalling socket at ``host`` on the same port, or a system
        port if another socket holds it (:attr:`kept_signalling_port`).

        The old socket may hold the port itself, so it is closed before a
        second try, but only once ``host`` is known to be local: a move to a
        foreign address raises with the old socket still open."""
        in_use = self._socket.getsockname()[1] if self._socket is not None else 0
        wanted = self._chosen_port or in_use

        def on(port: int) -> socket.socket | None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((host, port))
            except OSError:
                sock.close()
                return None
            return sock

        def usable() -> bool:
            probe = on(0)
            if probe is None:
                return False
            probe.close()
            return True

        made = on(wanted) if wanted else None
        if made is None and wanted and in_use == wanted and usable():
            old, self._socket = self._socket, None
            try:
                self._selector.unregister(old)
            except (KeyError, ValueError, OSError):
                pass
            old.close()
            made = on(wanted)
        self.kept_signalling_port = made is not None or not wanted
        if made is None:
            made = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            made.bind((host, 0))
        return made

    def _move_socket(self, host: str) -> None:
        """Rebind UDP signalling at ``host`` and tell the main transport."""
        sock = self._signalling_socket(host)
        sock.setblocking(False)
        bound = format_address(*sock.getsockname())
        local = bound.encode("utf-8")
        try:
            _retry(
                lambda: lib.sipral_stack_transport_bind(
                    self.handle,
                    lib.SIPRAL_TRANSPORT_MAIN,
                    lib.SIPRAL_TRANSPORT_UDP,
                    local,
                    len(local),
                    ffi.NULL,
                    0,
                    self.now_ms(),
                    ffi.NULL,
                ),
                "sipral_stack_transport_bind",
            )
        except Exception:
            sock.close()
            raise
        old = self._socket
        self._selector.register(sock, selectors.EVENT_READ, data="main")
        self._socket = sock
        self.bind_address = bound
        if old is not None:
            try:
                self._selector.unregister(old)
            except (KeyError, ValueError, OSError):
                pass
            old.close()

    def call_for(self, handle: int) -> Call | None:
        """The :class:`sipral.call.Call` already made for a call handle."""
        with self._lock:
            return self._calls.get(handle)

    def register_call(self, call: Call) -> None:
        """Track a :class:`Call` so events for its handle reach it."""
        with self._lock:
            self._calls[call.handle] = call
        if self._turn_streamed:
            with self._nat_lock:
                self._turn_sockets[call.handle] = call.media_address

    def forget_account(self, account: Account) -> None:
        """Stop tracking a removed account."""
        with self._lock:
            if account in self._accounts:
                self._accounts.remove(account)

    def forget_call(self, handle: int) -> None:
        with self._lock:
            self._calls.pop(handle, None)

    # -- the poll thread --------------------------------------------------

    def _on_event(self, raw, _user_data: object) -> None:
        """The C callback, on the poll thread with nothing held.

        `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` is delivered but not answered: the
        dialog keeps the flow its INVITE used (the only path through a NAT),
        and answering with the far `Contact` as a literal would send the BYE
        where nothing answers. An application with a real lookup answers it
        via `sipral_stack_resolved`.
        """
        self._deliver(_events.decode(raw[0]))

    def _deliver(self, event: _events.Event) -> None:
        # Call state is updated before the event is queued, so a consumer
        # reading `call_for(event.call)` sees it current.
        if event.kind == lib.SIPRAL_EVENT_KIND_TRANSPORT_WANTED and not self._streamed:
            self._streams_asked.append(event.fields)
        if event.kind == lib.SIPRAL_EVENT_KIND_TRANSPORT_FAILED:
            if not self._streamed:
                self._streams_let_go.append(event.fields["transport"])
            elif event.fields["transport"] == lib.SIPRAL_TRANSPORT_MAIN:
                self._main_let_go = True
        if event.kind == lib.SIPRAL_EVENT_KIND_LOOKUP_WANTED:
            self._lookups_asked.append((event.account, event.fields["name"], event.fields["record"]))
        if event.kind == lib.SIPRAL_EVENT_KIND_LOCATED and event.fields["targets"]:
            self._located.append((event.account, event.fields["targets"].split(",")[0]))
        if event.kind == lib.SIPRAL_EVENT_KIND_TURN_STREAM:
            fields = event.fields
            self._turn_asked.append(
                (fields["state"], fields["local"], fields["server"], fields["protocol"])
            )
        if event.kind == lib.SIPRAL_EVENT_KIND_NETWORK_TEST:
            self._network_tested(event.fields["test"])
        if event.kind in (lib.SIPRAL_EVENT_KIND_NAT_MAPPING, lib.SIPRAL_EVENT_KIND_NAT_RELAY):
            local = event.fields.get("local")
            if local:
                with self._nat_lock:
                    waiters = self._nat_waiters.get(local)
                if waiters is not None:
                    key = "mapping" if event.kind == lib.SIPRAL_EVENT_KIND_NAT_MAPPING else "relay"
                    waiters[key].set()

        call = self.call_for(event.call) if event.call else None
        if call is not None and event.kind == lib.SIPRAL_EVENT_KIND_CALL_ENDED:
            # Send the RTCP BYE and relay Refresh now, before anyone hears the
            # call ended and closes its socket; otherwise the relay lapses on
            # the server. Re-entering the library here is allowed.
            self._drain_farewells()
        if call is not None:
            call.deliver(event)

        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.events.put_nowait, event)
        else:
            self.events.put_nowait(event)

    def network_test(
        self,
        account: Account | None = None,
        *,
        probe: bool = True,
        media_host: str | None = None,
        echo_call: Call | None = None,
        echo_ms: int = 0,
        timeout_ms: int = 0,
    ) -> int:
        """Test the network before a call. Returns the test number; the
        result is `SIPRAL_EVENT_KIND_NETWORK_TEST` with ``fields["test"]`` and
        ``fields["verdict"]`` (:class:`sipral.enums.NetworkVerdict`).

        ``account``'s server gets an ``OPTIONS``. With ``probe`` and
        ``nat=Nat.STUN`` a temporary socket goes through STUN (and TURN if
        configured). ``echo_call``, a call to an echo service, is measured
        for ``echo_ms`` (8000 default) after media starts, then hung up. Parts
        silent past ``timeout_ms`` (30000 default) fail.
        """
        probe_socket = None
        probe_address = ""
        if probe and self._nat == lib.SIPRAL_NAT_STUN:
            probe_socket = self.open_media_socket(self._media_host(media_host, account, None))
            probe_address = format_address(*probe_socket.getsockname())
            with self._nat_lock:
                self._stun_sockets[probe_address] = probe_socket
            self._selector.register(probe_socket, selectors.EVENT_READ, data=("stun", probe_address))
        address_bytes = probe_address.encode("utf-8")
        address_buf = ffi.new("char[]", address_bytes) if address_bytes else ffi.NULL
        config = ffi.new("sipral_network_test_config_t *")
        config.size = ffi.sizeof("sipral_network_test_config_t")
        config.account = account.handle if account is not None else lib.SIPRAL_HANDLE_NONE
        config.probe_socket = address_buf
        config.probe_socket_len = len(address_bytes)
        config.echo_call = echo_call.handle if echo_call is not None else lib.SIPRAL_HANDLE_NONE
        config.echo_ms = echo_ms
        config.timeout_ms = timeout_ms
        out_test = ffi.new("uint32_t *")
        try:
            _retry(
                lambda: lib.sipral_stack_network_test(self.handle, config, self.now_ms(), out_test),
                "sipral_stack_network_test",
            )
        except Exception:
            if probe_socket is not None:
                self._release_stun_socket(probe_address)
                self._close_socket(probe_socket)
            raise
        test = int(out_test[0])
        if probe_socket is not None:
            with self._nat_lock:
                self._probes[test] = (probe_address, probe_socket)
        return test

    def _network_tested(self, test: int) -> None:
        """Send the probe's relay Refresh, then close the probe socket."""
        with self._nat_lock:
            probe = self._probes.pop(test, None)
        if probe is None:
            return
        address, sock = probe
        self._drain_stun()
        self._release_stun_socket(address)
        self._close_socket(sock)

    def _on_audio_transmit(self, raw, _user_data: object) -> None:
        """Device mode: send one encoded packet from its call's media socket,
        or on its TURN connection. Runs on the engine's thread and must not
        call the library, which could wait on the engine waiting on us."""
        try:
            transmit = raw[0]
            call = self.call_for(int(transmit.call))
            if call is None:
                return
            payload = bytes(ffi.buffer(transmit.payload, transmit.payload_len))
            if transmit.protocol in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS):
                self.write_turn(call.media_address, payload, from_engine=True)
                return
            destination = ffi.buffer(transmit.destination, transmit.destination_len)[:]
            host, port = parse_address(destination.decode("utf-8"))
            call.media_socket.sendto(payload, (host, port))
        except (OSError, ValueError):
            # Socket closed by a racing readdress or hangup: one lost packet.
            pass

    def _drain_transmit(self) -> None:
        """`sipral_stack_poll_transmit`, until nothing is left to send.

        `SIPRAL_STATUS_BUSY` only means another thread holds the stack. Nothing
        may raise here: it would end the poll thread for good. What is left
        drains on the next pass.
        """
        transmit = self._transmit
        while True:
            transmit.size = ffi.sizeof("sipral_transmit_t")
            transmit.data = self._transmit_data
            transmit.capacity = _TRANSMIT_BYTES
            transmit.destination = self._transmit_destination
            transmit.destination_capacity = _ADDRESS_BYTES
            transmit.source = ffi.NULL
            transmit.source_capacity = 0
            status = lib.sipral_stack_poll_transmit(self.handle, transmit)
            if status != lib.SIPRAL_STATUS_OK:
                return
            if transmit.len == 0:
                return
            payload = bytes(ffi.buffer(transmit.data, transmit.len))
            if transmit.transport >= _FIRST_STREAM:
                self._write_sip_stream(int(transmit.transport), payload)
                continue
            if self._socket is None:
                # One connection to the outbound proxy carries everything.
                self._write_link(payload)
                continue
            destination = ffi.string(transmit.destination, transmit.destination_len)
            host, port = parse_address(destination.decode("utf-8"))
            try:
                self._socket.sendto(payload, (host, port))
            except OSError:
                # Unreachable from this bind: lost as on the wire; the
                # transaction's retransmissions and timeout handle it.
                continue

    def _drain_farewells(self) -> None:
        """Send what ended calls still owe (RTCP BYE, TURN relay Refresh)
        from each call's media socket to the address the stack names (the
        ICE path or TURN server; the last media source only as fallback).
        Calls already closed, or with nowhere to send, are skipped.
        """
        out_call = ffi.new("sipral_handle_t *")
        packet = self._farewell
        while True:
            packet.size = ffi.sizeof("sipral_media_packet_t")
            packet.data = self._farewell_data
            packet.capacity = _TRANSMIT_BYTES
            packet.destination = self._farewell_destination
            packet.destination_capacity = _ADDRESS_BYTES
            status = lib.sipral_stack_poll_farewell(self.handle, out_call, packet)
            if status != lib.SIPRAL_STATUS_OK:
                return
            if packet.len == 0:
                return
            if packet.protocol in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS):
                # The relay connection is the stack's and outlives the call.
                with self._nat_lock:
                    local = self._turn_sockets.get(int(out_call[0]))
                if local is not None:
                    self.write_turn(local, bytes(ffi.buffer(packet.data, packet.len)))
                continue
            call = self.call_for(int(out_call[0]))
            if call is None:
                continue
            if packet.destination_len > 0:
                address = ffi.string(packet.destination, packet.destination_len).decode("utf-8")
            elif call.media is not None:
                address = call.media.remote_address
            else:
                address = None
            if call.media is None or address is None:
                continue
            call.media.send_to(bytes(ffi.buffer(packet.data, packet.len)), address)

    # -- STUN/TURN on a media socket, before it has a call's media handle -

    def _map_media_socket(self, sock: socket.socket, address: str, *, timeout: float = 7.0) -> None:
        """Map ``sock`` through STUN and wait until a call may use it.

        No-op without `nat=Nat.STUN`. Otherwise the poll thread routes the
        socket's traffic to the STUN entry points, and the *calling* thread
        blocks until `SIPRAL_EVENT_KIND_NAT_MAPPING`. The library answers
        within 5.5 s; ``timeout`` above that only trips if the poll thread
        stopped.
        """
        if self._nat != lib.SIPRAL_NAT_STUN:
            return
        waiters = {"mapping": threading.Event(), "relay": threading.Event()}
        with self._nat_lock:
            self._stun_sockets[address] = sock
            self._nat_waiters[address] = waiters
        self._selector.register(sock, selectors.EVENT_READ, data=("stun", address))
        address_bytes = address.encode("utf-8")
        local_buf = ffi.new("char[]", address_bytes)
        try:
            _retry(
                lambda: lib.sipral_stack_nat_map(
                    self.handle, local_buf, len(address_bytes), self.now_ms()
                ),
                "sipral_stack_nat_map",
            )
        except Exception:
            self._release_stun_socket(address)
            raise
        if not waiters["mapping"].wait(timeout):
            self._release_stun_socket(address)
            raise TimeoutError(f"no NAT mapping answer for {address} within {timeout}s")
        # With TURN, the library also refuses the socket until
        # `SIPRAL_EVENT_KIND_NAT_RELAY`, allocated or not.
        if self._turn and not waiters["relay"].wait(timeout):
            self._release_stun_socket(address)
            raise TimeoutError(f"no TURN allocation answer for {address} within {timeout}s")

    def _release_stun_socket(self, address: str) -> None:
        """Stop routing ``address`` to STUN: :class:`sipral.media.Media` owns
        it now, or the call dropped it."""
        with self._nat_lock:
            sock = self._stun_sockets.pop(address, None)
            self._nat_waiters.pop(address, None)
        if sock is not None:
            try:
                self._selector.unregister(sock)
            except (KeyError, ValueError, OSError):
                pass

    def _forget_media_socket(self, address: str) -> None:
        """Unmap a mapped media socket that will carry no call (refused, or
        the stack closing). No-op for unmapped sockets or ones `Media` owns.
        """
        self._give_back_port(parse_address(address)[1])
        with self._nat_lock:
            mapped = address in self._stun_sockets
        if not mapped:
            return
        address_bytes = address.encode("utf-8")
        local_buf = ffi.new("char[]", address_bytes)
        try:
            _retry(
                lambda: lib.sipral_stack_nat_unmap(
                    self.handle, local_buf, len(address_bytes), self.now_ms()
                ),
                "sipral_stack_nat_unmap",
            )
        except Exception:  # noqa: BLE001 -- best effort on the way out
            pass
        else:
            # Send the zero-lifetime Refresh while the socket is still open.
            self._drain_stun()
        self._release_stun_socket(address)

    def _drain_stun(self) -> None:
        """`sipral_stack_poll_stun`, until nothing is left to send.

        `transmit.source` names the socket to send from: sent from another,
        a STUN request would silently learn the wrong mapping.
        """
        transmit = self._stun_transmit
        while True:
            transmit.size = ffi.sizeof("sipral_transmit_t")
            transmit.data = self._stun_data
            transmit.capacity = _TRANSMIT_BYTES
            transmit.destination = self._stun_destination
            transmit.destination_capacity = _ADDRESS_BYTES
            transmit.source = self._stun_source
            transmit.source_capacity = _ADDRESS_BYTES
            status = lib.sipral_stack_poll_stun(self.handle, transmit)
            if status != lib.SIPRAL_STATUS_OK or transmit.len == 0:
                return
            payload = bytes(ffi.buffer(transmit.data, transmit.len))
            destination = ffi.string(transmit.destination, transmit.destination_len).decode("utf-8")
            source_text = ffi.string(transmit.source, transmit.source_len).decode("utf-8")
            if transmit.protocol in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS):
                # Never as a datagram: the network may block UDP.
                self.write_turn(source_text, payload)
                continue
            with self._nat_lock:
                sock = self._stun_sockets.get(source_text)
            if sock is None:
                continue
            host, port = parse_address(destination)
            try:
                sock.sendto(payload, (host, port))
            except OSError:
                pass

    # -- the TURN server over TCP or TLS -----------------------------------

    def write_turn(self, local: str, payload: bytes, *, from_engine: bool = False) -> None:
        """Write ``payload`` whole on ``local``'s TURN connection.

        Thread-safe. On failure the connection is closed and the stack told,
        losing the relay; from the engine thread (``from_engine``) the report
        is deferred to the poll thread."""
        with self._nat_lock:
            stream = self._turn_streams.get(local)
        if stream is None:
            return
        try:
            with stream.lock:
                stream.sock.sendall(payload)
        except (OSError, ssl.SSLError):
            if from_engine:
                with self._nat_lock:
                    self._turn_lost.append(local)
                return
            self._lose_turn_stream(local, tell=True)

    def _act_on_turn_streams(self) -> None:
        """Act on this poll's TURN stream requests. Opening runs on its own
        thread so the poll thread never waits out a TLS handshake."""
        asked, self._turn_asked = self._turn_asked, []
        for state, local, server, protocol in asked:
            if state == lib.SIPRAL_TURN_STREAM_OPEN:
                threading.Thread(
                    target=self._open_turn_stream,
                    args=(local, server, protocol),
                    name="sipral-turn",
                    daemon=True,
                ).start()
            elif state == lib.SIPRAL_TURN_STREAM_CLOSE:
                with self._nat_lock:
                    self._turn_sockets = {
                        handle: named for handle, named in self._turn_sockets.items() if named != local
                    }
                self._lose_turn_stream(local, tell=False)

    def _open_turn_stream(self, local: str, server: str, protocol: int) -> None:
        """Connect ``local`` to the TURN server (TLS checked against
        :attr:`_turn_server_name`) and report connected or closed."""
        local_bytes = local.encode("utf-8")
        host, port = parse_address(server)
        try:
            raw = socket.create_connection((host, port), timeout=5.0)
        except OSError:
            self._say_turn(lib.sipral_stack_turn_closed, local_bytes)
            return
        try:
            if protocol == lib.SIPRAL_TRANSPORT_TLS:
                context = self._turn_tls_context or ssl.create_default_context()
                sock: socket.socket = context.wrap_socket(raw, server_hostname=self._turn_server_name)
            else:
                sock = raw
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(_TURN_WRITE_PATIENCE)
        except (OSError, ssl.SSLError, ValueError):
            raw.close()
            self._say_turn(lib.sipral_stack_turn_closed, local_bytes)
            return
        if self._closed.is_set():
            sock.close()
            return
        with self._nat_lock:
            self._turn_streams[local] = _TurnStream(local, sock)
        self._selector.register(sock, selectors.EVENT_READ, data=("turn", local))
        self._say_turn(lib.sipral_stack_turn_connected, local_bytes)

    def _say_turn(self, entry_point, local_bytes: bytes) -> None:
        """Report a TURN connection state; never raises."""
        local_buf = ffi.new("char[]", local_bytes)
        try:
            _retry(
                lambda: entry_point(self.handle, local_buf, len(local_bytes), self.now_ms()),
                "a TURN connection",
            )
        except Exception:  # noqa: BLE001 -- the stack is going away
            pass

    def _read_turn_stream(self, local: str) -> None:
        """Feed what ``local``'s TURN connection carried to the stack.

        Every byte must arrive in order, so a busy stack is waited for, never
        skipped. A stream the stack reports broken is closed silently."""
        with self._nat_lock:
            stream = self._turn_streams.get(local)
        if stream is None:
            return
        try:
            with stream.lock:
                # Non-blocking: readable may be only a TLS 1.3 session ticket,
                # and a blocking read would stall the poll thread.
                stream.sock.settimeout(0.0)
                try:
                    data = stream.sock.recv(_TRANSMIT_BYTES)
                    pending = getattr(stream.sock, "pending", None)
                    while pending is not None and pending() > 0:
                        data += stream.sock.recv(pending())
                finally:
                    stream.sock.settimeout(_TURN_WRITE_PATIENCE)
        except (ssl.SSLWantReadError, BlockingIOError, socket.timeout):
            return
        except (OSError, ssl.SSLError):
            data = b""
        if not data:
            self._lose_turn_stream(local, tell=True)
            return
        local_bytes = local.encode("utf-8")
        local_buf = ffi.new("char[]", local_bytes)
        while True:
            status = lib.sipral_stack_turn_receive(
                self.handle, local_buf, len(local_bytes), data, len(data), self.now_ms()
            )
            if status not in _PASSING or self._closed.is_set():
                break
            time.sleep(0.001)
        if status == lib.SIPRAL_STATUS_STREAM_BROKEN:
            self._lose_turn_stream(local, tell=False)

    def _lose_turn_stream(self, local: str, *, tell: bool) -> None:
        """Close ``local``'s TURN connection; ``tell`` reports it, unless the
        stack itself closed or broke it."""
        with self._nat_lock:
            stream = self._turn_streams.pop(local, None)
        if stream is None:
            return
        try:
            self._selector.unregister(stream.sock)
        except (KeyError, ValueError, OSError):
            pass
        with stream.lock:
            try:
                stream.sock.close()
            except OSError:
                pass
        if tell:
            self._say_turn(lib.sipral_stack_turn_closed, local.encode("utf-8"))

    # -- RFC 3261 Section 18.1.1: a request too large for a datagram -------

    def _account_for(self, handle: int) -> Account | None:
        with self._lock:
            return next((account for account in self._accounts if account.handle == handle), None)

    def _act_on_lookups(self) -> None:
        """Run this poll's lookups, each on its own thread (a resolver may
        take seconds), and point accounts at newly located servers."""
        asked, self._lookups_asked = self._lookups_asked, []
        for account, name, record in asked:
            threading.Thread(
                target=self._look_up, args=(account, name, record), name="sipral-lookup", daemon=True
            ).start()
        located, self._located = self._located, []
        for handle, target in located:
            account = self._account_for(handle)
            if account is None:
                continue
            account.registrar_address = target
            if not self._routes or self._streamed or account.contact_given:
                continue
            advertised = self._advertise_toward(target)
            if advertised == (account.advertised or self.bind_address):
                continue
            account.advertised = advertised
            try:
                account.rebind(
                    remote=target,
                    contact=_default_contact(account.aor, advertised, account.contact_parameters),
                )
            except SipralError:
                # Removed meanwhile, or busy; the next location retries.
                pass

    def _look_up(self, account: int, name: str, record: int) -> None:
        """Run one lookup and hand back the answer; a raising resolver is a
        failed answer, since the procedure waits for every one."""
        try:
            answer, records = self._resolver(name, record)
        except Exception:  # noqa: BLE001 -- the resolver's failure is an answer
            answer, records = lib.SIPRAL_DNS_ANSWER_FAILED, []
        name_bytes = name.encode("utf-8")
        records_bytes = ",".join(records).encode("utf-8")
        records_buf = ffi.new("char[]", records_bytes) if records_bytes else ffi.NULL
        if self._closed.is_set():
            return
        try:
            _retry(
                lambda: lib.sipral_account_looked_up(
                    self.handle,
                    account,
                    name_bytes,
                    len(name_bytes),
                    record,
                    answer,
                    records_buf,
                    len(records_bytes),
                    self.now_ms(),
                ),
                "sipral_account_looked_up",
            )
        except SipralError:
            # The account was removed while the resolver ran.
            pass

    def _media_host(self, media_host: str | None, account: Account | None, destination: str | None) -> str:
        """``media_host``, else the route toward ``destination`` or the
        account's server, else this stack's address."""
        if media_host is not None:
            return media_host
        for peer in (destination, account.registrar_address if account else None):
            if peer and _is_address(peer):
                return route_host(peer)
        return parse_address(self.bind_address)[0]

    def _act_on_streams_wanted(self) -> None:
        """Open a connection per newly wanted destination on its own thread,
        or refuse when ``stream_fallback`` is off.

        Retired connections (RFC 5626 Section 4.4.1) are closed first, or
        they would stand in for the new one the stack asks for."""
        let_go, self._streams_let_go = self._streams_let_go, []
        for transport in let_go:
            self._lose_sip_stream(transport, tell=False)
        asked, self._streams_asked = self._streams_asked, []
        seen: set[str] = set()
        for wanted in asked:
            destination = wanted["destination"]
            if destination in seen:
                continue
            seen.add(destination)
            # An account's own connection (nothing outgrown) always opens.
            opens = self._stream_fallback or (wanted["request_bytes"] == 0 and wanted["limit_bytes"] == 0)
            # a WebSocket is a TCP or TLS connection bound as WS or WSS, whose
            # handshake and frames are the stack's
            bound = wanted["protocol"] if wanted["protocol"] in _OWN_STREAMS else lib.SIPRAL_TRANSPORT_TCP
            over = (
                lib.SIPRAL_TRANSPORT_TLS
                if bound in (lib.SIPRAL_TRANSPORT_TLS, lib.SIPRAL_TRANSPORT_WSS)
                else lib.SIPRAL_TRANSPORT_TCP
            )
            with self._stream_lock:
                if destination in self._streams_opening or any(
                    stream.destination == destination for stream in self._sip_streams.values()
                ):
                    continue
                transport = self._next_stream
                self._next_stream += 1
                if opens:
                    self._streams_opening.add(destination)
            if not opens:
                self._say_no_stream(
                    transport,
                    lib.SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED,
                    f"to {destination} not tried: stream_fallback is off",
                )
                continue
            threading.Thread(
                target=self._open_sip_stream,
                args=(transport, destination, over, bound),
                name="sipral-stream",
                daemon=True,
            ).start()

    def _stream_trust(self, destination: str) -> TlsTrust:
        """The pin of a TLS account on ``destination``, else the stack's trust."""
        with self._lock:
            accounts = list(self._accounts)
        for account in accounts:
            if (
                account.stream_protocol in (lib.SIPRAL_TRANSPORT_TLS, lib.SIPRAL_TRANSPORT_WSS)
                and account.registrar_address == destination
                and account.tls_pin is not None
            ):
                return TlsTrust.pinned(account.tls_pin)
        return self._tls_trust

    def _open_sip_stream(
        self, transport: int, destination: str, over: int = lib.SIPRAL_TRANSPORT_TCP, bound: int | None = None
    ) -> None:
        """Connect to ``destination`` (or ``stream_server`` for TCP) and bind
        it at ``transport`` as ``bound`` (WS/WSS for a WebSocket); a failure
        is reported on that number, ending what waited for it."""
        tls = over == lib.SIPRAL_TRANSPORT_TLS
        try:
            host, port = parse_address(destination) if tls else self._stream_server or parse_address(destination)
            if tls:
                trust = self._stream_trust(destination)
                sock = connect(
                    (host, port),
                    bind_host=None,
                    context=trust.context(),
                    server_name=self._given_tls_server_name or host,
                    timeout=_SIGNALLING_PATIENCE,
                    pin=trust.pin,
                )
            else:
                sock = socket.create_connection((host, port), timeout=_SIGNALLING_PATIENCE)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(_SIGNALLING_PATIENCE)
            local = format_address(*sock.getsockname()[:2])
        except (OSError, ValueError, ssl.SSLError) as refused:
            with self._stream_lock:
                self._streams_opening.discard(destination)
            error, tls_failure, said = classify(refused)
            server = format_address(*self._stream_server) if self._stream_server and not tls else destination
            target = destination if server == destination else f"{server} (for {destination})"
            why = f": {said}" if said else ""
            self._say_no_stream(
                transport,
                error,
                f"to {target} {_verdict(error)}{why}",
                over=over,
                tls=tls_failure if tls else lib.SIPRAL_TLS_FAILURE_NONE,
            )
            return
        stream = _SipStream(transport, destination, sock)
        with self._stream_lock:
            self._streams_opening.discard(destination)
            if self._closed.is_set():
                sock.close()
                return
            self._sip_streams[transport] = stream
        local_bytes = local.encode("utf-8")
        far = destination.encode("utf-8")
        try:
            _retry(
                lambda: lib.sipral_stack_transport_bind(
                    self.handle,
                    transport,
                    over if bound is None else bound,
                    local_bytes,
                    len(local_bytes),
                    far,
                    len(far),
                    self.now_ms(),
                    ffi.NULL,
                ),
                "sipral_stack_transport_bind",
            )
        except Exception as refused:  # noqa: BLE001 -- told as a connection that failed
            self._lose_sip_stream(transport, tell=False)
            self._say_no_stream(
                transport,
                lib.SIPRAL_TRANSPORT_ERROR_OTHER,
                f"to {destination} connected, and the stack would not bind it: {refused}",
            )
            return
        # Nothing arrives before the request the bind released.
        self._selector.register(sock, selectors.EVENT_READ, data=("sip", transport))

    def _say_no_stream(
        self,
        transport: int,
        error: int,
        what: str,
        *,
        over: int = lib.SIPRAL_TRANSPORT_TCP,
        tls: int = lib.SIPRAL_TLS_FAILURE_NONE,
    ) -> None:
        """Report a connection not made; never raises. ``what`` completes a
        detail sentence starting "TCP" or "TLS"."""
        text = f"{'TLS' if over == lib.SIPRAL_TRANSPORT_TLS else 'TCP'} {what}"
        text = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text)
        encoded = text.encode("utf-8")[: lib.SIPRAL_TRANSPORT_DETAIL_BYTES].decode("utf-8", "ignore")
        detail = encoded.encode("utf-8")
        failure = ffi.new("sipral_transport_failure_t *")
        failure.size = ffi.sizeof("sipral_transport_failure_t")
        failure.transport = transport
        failure.error = error
        failure.tls = tls
        detail_buf = ffi.new("char[]", detail)
        failure.detail = detail_buf
        failure.detail_len = len(detail)
        try:
            _retry(
                lambda: lib.sipral_stack_transport_failed_with(self.handle, failure, self.now_ms()),
                "sipral_stack_transport_failed_with",
            )
        except Exception:  # noqa: BLE001 -- nothing was waiting any more
            pass

    def _write_sip_stream(self, transport: int, payload: bytes) -> None:
        """Write one message whole; a failed write loses the connection."""
        with self._stream_lock:
            stream = self._sip_streams.get(transport)
        if stream is None:
            return
        try:
            with stream.lock:
                stream.sock.sendall(payload)
        except OSError:
            self._lose_sip_stream(transport, tell=True)

    def _read_sip_stream(self, transport: int) -> None:
        """Feed the connection's bytes to the stack, in order; a close by the
        far end is reported."""
        with self._stream_lock:
            stream = self._sip_streams.get(transport)
        if stream is None:
            return
        try:
            with stream.lock:
                # Non-blocking: readable TLS may hold no application data.
                stream.sock.settimeout(0.0)
                try:
                    data = stream.sock.recv(_TRANSMIT_BYTES)
                    pending = getattr(stream.sock, "pending", None)
                    while pending is not None and pending() > 0:
                        data += stream.sock.recv(pending())
                finally:
                    stream.sock.settimeout(_SIGNALLING_PATIENCE)
        except (ssl.SSLWantReadError, BlockingIOError, socket.timeout):
            return
        except (OSError, ssl.SSLError):
            data = b""
        if not data:
            self._lose_sip_stream(transport, tell=True)
            return
        while True:
            status = lib.sipral_stack_receive_stream(
                self.handle, transport, data, len(data), self.now_ms()
            )
            if status not in _PASSING or self._closed.is_set():
                break
            time.sleep(0.001)
        if status != lib.SIPRAL_STATUS_OK and status not in _PASSING:
            # Framing lost: the stack retired the transport itself.
            self._lose_sip_stream(transport, tell=False)

    def _lose_sip_stream(self, transport: int, *, tell: bool) -> None:
        """Close the connection; ``tell`` reports it to the stack."""
        with self._stream_lock:
            stream = self._sip_streams.pop(transport, None)
        if stream is None:
            return
        try:
            self._selector.unregister(stream.sock)
        except (KeyError, ValueError, OSError):
            pass
        with stream.lock:
            try:
                stream.sock.close()
            except OSError:
                pass
        if tell:
            try:
                _retry(
                    lambda: lib.sipral_stack_stream_closed(self.handle, transport, self.now_ms()),
                    "sipral_stack_stream_closed",
                )
            except Exception:  # noqa: BLE001 -- the stack is going away
                pass

    # -- SIP over TCP or TLS: the one connection signalling travels on -----

    @property
    def contact_parameters(self) -> str:
        """``;transport=tcp``/``;transport=tls`` for a `Contact` over a
        connection (RFC 3261 Section 19.1.1), empty over UDP."""
        if self.signalling == lib.SIPRAL_TRANSPORT_TLS:
            return ";transport=tls"
        if self.signalling == lib.SIPRAL_TRANSPORT_TCP:
            return ";transport=tcp"
        return ""

    @property
    def connected(self) -> bool:
        """Whether SIP can go out now: always over UDP, over TCP/TLS while
        connected."""
        return not self._streamed or self._link is not None

    def _connect(self, bind_host: str | None) -> socket.socket:
        """One connection to the signalling server; raises what refused it."""
        assert self._server is not None
        return connect(
            self._server,
            bind_host=bind_host,
            context=self._tls_context,
            server_name=self._server_name,
            timeout=_SIGNALLING_PATIENCE,
            pin=self._tls_pin,
        )

    def _install_link(self, sock: socket.socket, remote: str) -> None:
        """Bind the connection in the stack and start reading it; on error
        the socket is closed and the error raised."""
        local = self.bind_address.encode("utf-8")
        far = remote.encode("utf-8")
        try:
            _retry(
                lambda: lib.sipral_stack_transport_bind(
                    self.handle,
                    lib.SIPRAL_TRANSPORT_MAIN,
                    self.signalling,
                    local,
                    len(local),
                    far,
                    len(far),
                    self.now_ms(),
                    ffi.NULL,
                ),
                "sipral_stack_transport_bind",
            )
        except Exception:
            sock.close()
            raise
        sock.settimeout(_SIGNALLING_PATIENCE)
        with self._link_lock:
            self._link = sock
        self._selector.register(sock, selectors.EVENT_READ, data="signalling")

    def _report_failure(self, error: int, tls: int, detail: str) -> None:
        """Report a signalling failure to the stack; never raises."""
        failure = ffi.new("sipral_transport_failure_t *")
        failure.size = ffi.sizeof("sipral_transport_failure_t")
        failure.transport = lib.SIPRAL_TRANSPORT_MAIN
        failure.error = error
        failure.tls = tls if self.signalling == lib.SIPRAL_TRANSPORT_TLS else lib.SIPRAL_TLS_FAILURE_NONE
        text = detail.encode("utf-8")
        text_buf = ffi.new("char[]", text) if text else ffi.NULL
        failure.detail = text_buf
        failure.detail_len = len(text)
        try:
            _retry(
                lambda: lib.sipral_stack_transport_failed_with(self.handle, failure, self.now_ms()),
                "sipral_stack_transport_failed_with",
            )
        except Exception:  # noqa: BLE001 -- the stack is going away
            pass

    def _lose_link(self, error: int, tls: int, detail: str, *, closed: bool = False, tell: bool = True) -> None:
        """Close signalling, report how it ended (nothing if the stack broke
        it) and reconnect."""
        with self._link_lock:
            sock, self._link = self._link, None
        if sock is None:
            return
        try:
            self._selector.unregister(sock)
        except (KeyError, ValueError, OSError):
            pass
        try:
            sock.close()
        except OSError:
            pass
        if tell and closed:
            try:
                _retry(
                    lambda: lib.sipral_stack_stream_closed(
                        self.handle, lib.SIPRAL_TRANSPORT_MAIN, self.now_ms()
                    ),
                    "sipral_stack_stream_closed",
                )
            except Exception:  # noqa: BLE001 -- the stack is going away
                pass
        elif tell:
            self._report_failure(error, tls, detail)
        self._reconnect_later()

    def _reconnect_later(self) -> None:
        """Start the thread that connects again, unless one is running."""
        with self._link_lock:
            if self._reconnecting or self._closed.is_set():
                return
            self._reconnecting = True
        threading.Thread(target=self._reconnect, name="sipral-reconnect", daemon=True).start()

    def _reconnect(self) -> None:
        """Reconnect with backoff until it works or the stack closes."""
        delay = _RECONNECT_FIRST
        try:
            while not self._closed.wait(delay):
                delay = min(delay * 2, _RECONNECT_MOST)
                try:
                    sock = self._connect(self._bind_host)
                    local = format_address(*sock.getsockname()[:2])
                    remote = format_address(*sock.getpeername()[:2])
                except (OSError, ssl.SSLError, ValueError) as refused:
                    self._report_failure(*classify(refused))
                    continue
                if self._closed.is_set():
                    sock.close()
                    return
                self.bind_address = local
                try:
                    self._install_link(sock, remote)
                except Exception:  # noqa: BLE001 -- tried again after the wait
                    continue
                self._after_reconnect()
                return
        finally:
            with self._link_lock:
                self._reconnecting = False

    def _after_reconnect(self) -> None:
        """Rebind accounts without their own `Contact`; re-register now
        rather than at the next back-off."""
        with self._lock:
            accounts = list(self._accounts)
        for account in accounts:
            try:
                if not account.contact_given:
                    account.rebind()
                if account.wants_registration:
                    account.register()
            except Exception:  # noqa: BLE001 -- the next loss or refresh tries again
                pass

    def _write_link(self, payload: bytes) -> None:
        """Write one message whole; a failed write loses the connection."""
        with self._link_lock:
            sock = self._link
            if sock is None:
                return
            try:
                sock.sendall(payload)
                return
            except (OSError, ssl.SSLError) as broken:
                failed = broken
        self._lose_link(*classify(failed))

    def _read_link(self) -> None:
        """Feed signalling bytes to the stack in order; a busy stack is
        waited for, since a stream that loses a byte cannot resync."""
        with self._link_lock:
            sock = self._link
            if sock is None:
                return
            try:
                # Non-blocking: a TLS 1.3 session ticket holds no data.
                sock.settimeout(0.0)
                try:
                    data = sock.recv(_TRANSMIT_BYTES)
                    pending = getattr(sock, "pending", None)
                    while pending is not None and pending() > 0:
                        data += sock.recv(pending())
                finally:
                    sock.settimeout(_SIGNALLING_PATIENCE)
            except (ssl.SSLWantReadError, BlockingIOError, socket.timeout):
                return
            except (OSError, ssl.SSLError) as broken:
                failed: BaseException | None = broken
                data = b""
            else:
                failed = None
        if failed is not None:
            self._lose_link(*classify(failed))
            return
        if not data:
            self._lose_link(lib.SIPRAL_TRANSPORT_ERROR_CLOSED, lib.SIPRAL_TLS_FAILURE_NONE, "", closed=True)
            return
        while True:
            status = lib.sipral_stack_receive_stream(
                self.handle, lib.SIPRAL_TRANSPORT_MAIN, data, len(data), self.now_ms()
            )
            if status not in _PASSING or self._closed.is_set():
                break
            time.sleep(0.001)
        if status != lib.SIPRAL_STATUS_OK and status not in _PASSING:
            # Framing lost: the stack retired the transport and reported it.
            self._lose_link(lib.SIPRAL_TRANSPORT_ERROR_OTHER, lib.SIPRAL_TLS_FAILURE_NONE, "", tell=False)

    def _wait_for_sockets(self, timeout: float) -> list:
        """What the selector has ready within ``timeout`` seconds.

        With TCP/TLS down there may be nothing to watch, and Windows'
        ``select()`` fails on empty sets (WinError 10022), which would kill
        the poll thread. Then this just waits out the timeout."""
        if self._selector.get_map():
            try:
                return self._selector.select(timeout)
            except OSError:
                if self._selector.get_map():
                    raise
        self._closed.wait(timeout)
        return []

    def _run(self) -> None:
        result = ffi.new("sipral_poll_result_t *")
        while not self._closed.is_set():
            events = self._wait_for_sockets(0.05)
            for key, _mask in events:
                if isinstance(key.data, tuple) and key.data[0] == "turn":
                    self._read_turn_stream(key.data[1])
                elif isinstance(key.data, tuple) and key.data[0] == "sip":
                    self._read_sip_stream(key.data[1])
                elif key.data == "signalling":
                    self._read_link()
                elif key.data == "main":
                    try:
                        data, from_address = self._socket.recvfrom(_TRANSMIT_BYTES)
                    except (BlockingIOError, OSError):
                        continue
                    from_text = format_address(*from_address).encode("utf-8")
                    lib.sipral_stack_receive_datagram(
                        self.handle,
                        lib.SIPRAL_TRANSPORT_MAIN,
                        data,
                        len(data),
                        from_text,
                        len(from_text),
                        ffi.NULL,
                        0,
                        self.now_ms(),
                    )
                else:
                    # A mapped media socket without a media handle yet:
                    # everything on it goes to the STUN entry point.
                    _tag, address = key.data
                    sock = key.fileobj
                    try:
                        data, from_address = sock.recvfrom(_TRANSMIT_BYTES)
                    except (BlockingIOError, OSError):
                        continue
                    from_text = format_address(*from_address).encode("utf-8")
                    to_text = address.encode("utf-8")
                    lib.sipral_stack_receive_stun(
                        self.handle,
                        data,
                        len(data),
                        from_text,
                        len(from_text),
                        to_text,
                        len(to_text),
                        self.now_ms(),
                    )
            result.size = ffi.sizeof("sipral_poll_result_t")
            status = lib.sipral_stack_poll(self.handle, self.now_ms(), result)
            if status != lib.SIPRAL_STATUS_OK:
                continue
            self._drain_transmit()
            self._drain_stun()
            self._drain_farewells()
            self._act_on_turn_streams()
            self._act_on_streams_wanted()
            self._act_on_lookups()
            if self._main_let_go:
                self._main_let_go = False
                self._lose_link(lib.SIPRAL_TRANSPORT_ERROR_OTHER, lib.SIPRAL_TLS_FAILURE_NONE, "", tell=False)
            with self._nat_lock:
                lost, self._turn_lost = self._turn_lost, []
            for local in lost:
                self._lose_turn_stream(local, tell=True)

    def close(self) -> None:
        """Destroy the stack and everything this wrapper opened.

        Open calls are hung up first and closed only after the poll thread
        has had a round to send their BYE and RTCP BYE: closing a call first
        would close the socket those go out on.
        """
        if self._closed.is_set():
            return
        with self._lock:
            calls = list(self._calls.values())
        for call in calls:
            if not call.ended:
                try:
                    call.hangup()
                except Exception:  # noqa: BLE001 -- best effort on the way out
                    pass
        if calls:
            # Time for BYEs, their answers and farewells; ample on a LAN.
            time.sleep(0.2)
        for call in calls:
            call.close()
        # Unmap sockets mapped but never used by a call: destroy sends
        # nothing, and a relay would stay allocated until it lapses.
        with self._nat_lock:
            leftover = list(self._stun_sockets)
        for address in leftover:
            self._forget_media_socket(address)
        self._closed.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)
        with self._nat_lock:
            streams = list(self._turn_streams)
        for local in streams:
            self._lose_turn_stream(local, tell=False)
        with self._stream_lock:
            opened = list(self._sip_streams)
        for transport in opened:
            self._lose_sip_stream(transport, tell=False)
        lib.sipral_stack_destroy(self.handle)
        self._selector.close()
        if self._socket is not None:
            self._socket.close()
        with self._link_lock:
            link, self._link = self._link, None
        if link is not None:
            try:
                link.close()
            except OSError:
                pass
