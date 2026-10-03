# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Stack``: one SIP endpoint, headless and in-process.

This is the object an application actually reaches for. It owns the UDP
socket signalling travels on, a background thread that drains
`sipral_stack_poll` and the transport queues around it, and the
`asyncio.Queue` events land on -- the layer `_sipral_cffi.py` (the raw
`ffi`/`lib` pair, printed by `tools/abi-gen` from `crates/sipral-ffi`) is
written against directly, the way `SipralAbi.swift` is the base the Swift
package is written by hand against (`docs/08-ffi.md`, "Swift").
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
from .call import Call
from .counters import Counters
from .enums import AudioMode, Feature, Link, LogLevel, Recovery
from .errors import PASSING as _PASSING
from .errors import call as _retry
from .errors import SipralError, check
from .locate import Resolver, advertised_address, lookup
from .settings import Settings
from .signalling import InviteLimit, TlsTrust, classify, connect

__all__ = ["TRACE", "Stack", "features", "route_host"]

#: The :mod:`logging` level a ``LogLevel.TRACE`` line is logged at: below
#: ``logging.DEBUG``, which ``LogLevel.DEBUG`` takes, since a trace line holds
#: a whole SIP message and wants turning on apart from the debug lines.
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
    """What this build of the library has compiled in:
    `sipral_capabilities_t::features`, as :class:`sipral.enums.Feature` bits.

    ``Feature.AUDIO_DEVICE`` is set where the library can open the
    platform's own audio devices (macOS, iOS, Windows) and clear where it
    cannot (Linux, Android); a :class:`Stack` is created in device mode by
    default exactly where it is set.
    """
    out = ffi.new("sipral_capabilities_t *")
    out.size = ffi.sizeof("sipral_capabilities_t")
    check(lib.sipral_capabilities(out), "sipral_capabilities")
    return Feature(int(out.features))

#: `sipral_transmit_t` and `sipral_media_packet_t` both bound a single
#: datagram at this many bytes (`SIPRAL_MEDIA_PACKET_BYTES`); a signalling
#: message can be larger, so the transmit buffer below is a comfortable
#: multiple of it rather than that same bound.
_TRANSMIT_BYTES = 1 << 16
_ADDRESS_BYTES = 128
#: How long a write on a connection to the TURN server may wait for room
#: before the connection is given up as dead, which loses the relay on it.
_TURN_WRITE_PATIENCE = 5.0
#: How long one attempt at the signalling connection may take, the TLS
#: handshake included, and how long a write on it may wait for room.
_SIGNALLING_PATIENCE = 5.0
#: The wait before the first attempt to connect again after the signalling
#: connection was lost, doubled after every attempt that fails, up to the
#: second number: soon enough for a server restarting, not so often that a
#: server refusing the certificate is asked every second for ever.
_RECONNECT_FIRST = 1.0
_RECONNECT_MOST = 30.0
#: The first number a connection this class opens for
#: `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` is bound at (``stream_fallback``), one
#: more for each destination after it: well clear of `SIPRAL_TRANSPORT_MAIN`
#: and of the small numbers an application driving `lib` itself would pick.
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
    """Whether ``text`` is ``host:port`` with an IP address for its host,
    rather than a name."""
    try:
        host, _port = parse_address(text)
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def route_host(peer: str | None) -> str:
    """The address of this machine's route toward ``peer`` (``host:port``),
    the one a socket bound on every interface is reached at from there:
    `sipral_advertised_address` for a wildcard bind. ``127.0.0.1`` when
    there is no peer yet, it is a name rather than an address, or no route
    reaches it -- the address that works for a peer on this machine and
    that the library refuses to advertise to any other."""
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

    Read by the poll thread alone, and written by it and by the call's
    :class:`sipral.media.Media` thread: every operation on the socket holds
    :attr:`lock`, since one TLS session read and written from two threads
    at once is a session whose records interleave.
    """

    def __init__(self, local: str, sock: socket.socket) -> None:
        self.local = local
        self.sock = sock
        self.lock = threading.Lock()


class _SipStream:
    """One TCP connection opened because a request was too large for a
    datagram (RFC 3261 Section 18.1.1), bound at :attr:`transport`.

    Read and written by the poll thread; :attr:`lock` is still held for
    every operation, since the thread that opened it hands it over while
    the poll thread may already be writing to it.
    """

    def __init__(self, transport: int, destination: str, sock: socket.socket) -> None:
        self.transport = transport
        self.destination = destination
        self.sock = sock
        self.lock = threading.Lock()


class Stack:
    """One `sipral_stack_create` handle, its socket and its poll thread.

    Built and torn down like the handle it wraps: :meth:`close` (also
    reached through ``with Stack(...) as stack:``) calls
    `sipral_stack_destroy` exactly once, and a stack a caller lets go of
    without closing still does at garbage collection -- the deterministic
    path is the one to prefer, since a stack still bound to a socket is a
    port nothing else can use until Python's collector gets around to it.
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
        """See the class docstring for the socket and thread this owns.

        ``bind_host`` is the address the signalling socket is bound at, and
        the one this stack advertises. Left out, the socket listens on every
        interface and the stack advertises the address of the operating
        system's route toward the server of its first account
        (`sipral_advertised_address`): the address a PBX on the network
        reaches this machine at, and ``127.0.0.1`` for a server on this
        machine. Each account the stack adds is reached at the route toward
        its own server, and a call's media socket, when ``media_host`` is
        left out, at the route toward the far end or the account's server.
        A loopback address is never advertised to a peer that is not on this
        machine: the library refuses that with
        ``SIPRAL_STATUS_UNREACHABLE_ADDRESS``.

        ``signalling`` is what SIP travels over, a
        :class:`sipral.enums.Transport`: ``UDP`` (``0``, the default) on a
        socket bound at ``bind_host``, or ``TCP`` or ``TLS`` on one
        connection to ``signalling_server`` (``host:port`` -- the registrar
        or the outbound proxy, 5061 for TLS by convention), which every
        account and every call on this stack then shares, and on which the
        server's own requests arrive. Over TLS the server's certificate is
        checked against ``tls_server_name`` (the host part of
        ``signalling_server`` when left out) with ``tls_trust``, a
        :class:`sipral.signalling.TlsTrust`: the platform's authorities
        when left out, a private authority beside them, or only one
        authority -- `docs/22-tls.md` says what each checks. Nothing here
        turns the check off.

        The first connection is made here, before this returns. When it
        fails, or later breaks, the stack is told why
        (`sipral_stack_transport_failed_with`) and says so as
        `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` on :attr:`events` -- untrusted,
        a name that does not match, expired, a handshake refused, a server
        that refused the connection -- and this class connects again, one
        second after the loss and twice as long after each attempt that
        fails, up to thirty seconds. Once connected again every account is
        pointed at the new connection and registered again if it was
        registering. :meth:`sipral.account.Account.register` asked while it
        is down is kept for then; a call placed meanwhile raises
        ``SIPRAL_STATUS_TRANSPORT_DOWN``.

        ``invite_limit`` is how fast one address may ring this stack, an
        :class:`sipral.signalling.InviteLimit`: ``InviteLimit.DEFAULT``
        (what every stack starts with, ten INVITEs at once then one every
        two seconds, past which a call is answered 480) or
        ``InviteLimit.VOICE_AGENT`` for a service taking a trunk's calls.

        ``audio`` is who pumps the calls' audio, an
        :class:`sipral.enums.AudioMode`. ``AudioMode.DEVICE`` has the library
        open the platform's own microphone and loudspeaker and run every
        call through them -- the application writes no audio code at all,
        and chooses devices, volume, mute and the ring through
        :attr:`audio` -- and the packets it encodes still leave from each
        call's own media socket, which this class sends for it.
        ``AudioMode.APPLICATION`` leaves the frames to
        :class:`sipral.media.Media` (:attr:`sipral.media.Media.frames` in,
        :meth:`sipral.media.Media.send_audio` out): a voice agent, a
        recorder, a machine with no sound device. Left out, it is
        ``DEVICE`` where :func:`features` has ``Feature.AUDIO_DEVICE`` and
        ``APPLICATION`` elsewhere; :attr:`audio_mode` says which this stack
        got. Asking for ``DEVICE`` on a build without it raises
        ``SIPRAL_STATUS_NOT_SUPPORTED``.

        ``audio_activation`` (an :class:`sipral.enums.AudioActivation`) is
        when device mode opens the devices: ``AUTOMATIC`` (``0``) with the
        first call's media or the first ring, closed with the last;
        ``MANUAL`` only between :meth:`sipral.audio.Audio.activate` and
        :meth:`sipral.audio.Audio.deactivate`, whatever the calls do.
        ``audio_probe_ms`` bounds every platform call (``0`` for three
        seconds): a driver that does not answer is
        ``SIPRAL_STATUS_DEVICE_TIMED_OUT``, not a hang.
        ``audio_device_rate_hz`` is the rate the devices are asked for
        (``0`` for 48 000).

        ``max_dialogs`` is the most calls the stack holds at once, either
        way (``0`` for 128): one that arrives past it is answered 503, and
        one placed past it raises ``SIPRAL_STATUS_LIMIT_REACHED``.
        ``max_server_transactions`` is the most requests from other ends it
        works on at once (``0`` for 256). ``diagnostic_decisions`` and
        ``diagnostic_records`` bound the diagnostic record: decisions kept
        per call (``0`` for 64) and calls kept (``0`` for 32).

        ``ice`` and ``nat`` are :class:`sipral.enums.Ice` /
        :class:`sipral.enums.Nat` values, or ``0`` for this build's own
        default (`SIPRAL_ICE_OFF`, `SIPRAL_NAT_OFF` -- exactly today's
        behaviour). ``Ice.LITE`` is for a server reachable at the address
        it advertises and nowhere else: it answers a full ICE peer's checks
        and never sends its own (`docs/06-nat.md`, "ICE-lite").

        ``referrals=True`` hands a REFER outside any dialog -- click-to-dial
        from a switchboard -- to the application as
        `SIPRAL_EVENT_KIND_REFERRAL`, to take with :meth:`accept_referral`
        or refuse with :meth:`reject_referral`. Off by default, when every
        one is refused 403: a peer that can make a phone dial is a
        toll-fraud vector, so each one is the application's decision.

        ``registrar_keepalive`` keeps the registrar's flow open behind a
        NAT: every account ``stun_server`` showed to be behind one sends its
        registrar a double CRLF every ``registrar_keepalive_ms`` (``0`` for
        25 seconds, 1 000 to 120 000), so that a NAT filtering by address
        and port still lets the registrar's INVITE in minutes after the
        REGISTER. On by default; ``False`` turns it off, and an interval
        with it off is refused. Nothing is sent while the stack is
        suspended.

        ``stun_fallbacks`` are the STUN servers to turn to, in order, when
        ``stun_server`` does not answer in five and a half seconds or answers
        without an address, each ``host:port``: every socket asking the one
        that failed moves to the next at once, the one that failed is passed
        over for thirty seconds and twice as long each time it fails again,
        up to ten minutes, and `SIPRAL_EVENT_KIND_STUN_SERVER` says when the
        server in use moves or every one has failed.

        ``nat=Nat.STUN`` needs ``stun_server`` as ``host:port``;
        ``turn_server`` rides on it and needs ``turn_username`` and
        ``turn_password`` with it (`docs/06-nat.md`, `docs/08-ffi.md`
        "Behind a NAT"). The TURN credentials are copied into the library
        and kept out of every log, event and error this package raises --
        neither is in `repr(stack)` (there is none) or anywhere else this
        module writes text.

        ``turn_transport`` is a :class:`sipral.enums.Transport` --
        ``Transport.TCP`` for a network that lets no UDP out,
        ``Transport.TLS`` for one that lets one port out (5349 is TURN's) --
        or ``0`` for UDP (RFC 8656 Section 3.1). Over either this stack opens
        one connection per media socket, when
        `SIPRAL_EVENT_KIND_TURN_STREAM` asks, and carries everything for the
        relay on it. Over TLS the server's certificate is checked against
        ``turn_server_name`` -- the host part of ``turn_server`` when left
        out, which for an address is an IP-address certificate -- with
        ``turn_tls_context``, or with the platform's default trust when none
        is given: a context built with ``cafile=`` trusts a private CA or a
        self-signed certificate, and nothing here ever turns checking off.

        ``rtp_port_min`` and ``rtp_port_max`` are the range a firewall in
        front of this machine was opened for: every media socket this class
        opens without an explicit port then binds an even port from it,
        reserved with `sipral_stack_rtp_port_reserve`, with the odd one above
        it kept for RTCP (RFC 3550 Section 11), and a call is refused a port
        outside it. Both ``0`` -- the default -- leaves the ports to the
        operating system. Every pair taken raises
        ``SIPRAL_STATUS_EXHAUSTED`` rather than binding outside the range.

        ``stream_fallback`` is what a stack signalling over UDP does when a
        request is too large for a datagram -- nearly always the answer to a
        challenge, whose ``Authorization`` takes a call offering two SRTP
        suites past RFC 3261 Section 18.1.1's 1300 bytes. On (the default),
        `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` is answered by opening a TCP
        connection to the address it names -- the registrar or proxy the
        request was going to, on the same port -- and binding it
        (`sipral_stack_transport_bind`): the request the stack was holding
        goes on it, and the call or registration carries on over it. When
        that connection is refused or times out, or with ``False``, the
        stack is told at once (`sipral_stack_transport_failed_with`, whose detail
        names where the connection was going and whether it was refused,
        timed out or not tried), and what
        was waiting ends rather than hanging: a call as unreachable, its
        `cause_sip` 513 and its `cause_text` naming the size and the limit.
        The event reaches :attr:`events` either way. ``stream_server``
        (``host:port``) is where that connection goes instead, for a server
        that takes TCP on another port than UDP -- a PBX on 5060 for one and
        5160 for the other: the connection stands for the address the event
        named, and everything the stack sends there goes on it.

        ``dtmf_detection`` (a :class:`sipral.enums.DtmfDetection`) is when a
        call listens for keypad digits in the far end's audio: ``AUTO``
        (``0``) on the calls that negotiated no telephone event, ``ALWAYS``
        or ``OFF``; :meth:`sipral.call.Call.set_dtmf_detection` changes it
        for one call.

        ``srtp`` may be ``SIPRAL_SRTP_BEST_EFFORT`` (:class:`sipral.enums.Srtp`):
        SDES offered on plain ``RTP/AVP``, the call encrypted when the answer
        takes a key and plain when it takes none, for a PBX that answers an
        ``RTP/SAVP`` offer with 488. ``srtp_suites`` are the SRTP suites
        every call offers and accepts unless its account names its own, most
        preferred first, by their RFC 4568 and RFC 7714 names.

        ``path_mtu`` is the MTU of the path toward the server when the
        deployment knows it (``0`` for unknown, else 576 or more): RFC 3261
        Section 18.1.1 moves a request to a stream within 200 bytes of it.
        ``datagram_without_stream_bytes`` is a deliberate deviation from
        that section, for a server that takes SIP over UDP alone: once no
        stream to it can be had -- ``stream_fallback`` off, or the
        connection refused -- a request up to this many bytes goes over UDP
        anyway (``0`` for never, at most 65 507), and the call's diagnostic
        record says so as ``transport.kept.datagram``.

        ``pseudonym_salt`` (16 bytes or more, kept by the installation) keys
        the pseudonyms the log and :meth:`state` write, so that two runs'
        traces compare line by line; a secret, like a key. ``diagnostic_trace``
        writes whole SIP messages at the trace level, peers included and
        credentials and keys taken out, for a diagnosis;
        :meth:`set_diagnostic_trace` turns it on and off later.

        ``system_echo_cancellation`` ``False`` opens the devices of a stack in
        device mode past the platform's echo cancellation, gain control and
        noise suppression, for a headset, which has no echo to cancel, or an
        application that cancels it on each call itself; Linux has none to
        turn off. :meth:`sipral.audio.Audio.info` says what the platform did.

        ``held_audio`` is a :class:`sipral.enums.HeldAudio`: what a party
        this end holds is sent while the hold lasts. ``DEFAULT`` and
        ``SILENCE`` are silence in either mode, since in application mode too
        the frames sent may be a microphone's; ``APPLICATION`` sends the
        frames the application sends -- hold music, an announcement, a voice
        agent's own speech.

        ``resolver`` answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED` for the
        accounts added with ``server_uri``, on a thread of its own, one per
        lookup: a callable taking the name and the record type
        (:class:`sipral.enums.DnsRecordType`) and returning a
        :class:`sipral.enums.DnsAnswer` and the records
        (:data:`sipral.locate.Resolver`). Left out, it is
        :func:`sipral.locate.lookup`, the platform's own address lookup,
        which has no SRV or NAPTR: an application whose server publishes SRV
        records passes a resolver that reads them (dnspython's, say).
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
        #: What `SIPRAL_EVENT_KIND_TURN_STREAM` asked for during the poll
        #: that raised it -- nothing may call back into the stack from
        #: inside its own callback -- acted on right after that poll.
        self._turn_asked: list[tuple[int, str, str, int]] = []
        #: Every call's media socket, by the call's handle, for as long as
        #: the socket's connection to the TURN server stands: a call's last
        #: farewell -- the Refresh that gives its relay back -- can come
        #: after the :class:`Call` was closed and forgotten, and still goes
        #: on that connection. Under :attr:`_nat_lock`.
        self._turn_sockets: dict[int, str] = {}
        self._turn_streamed = turn_transport in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS)
        #: Whether a request too large for a datagram gets a connection.
        self._stream_fallback = stream_fallback
        #: Where such a connection goes, when not to the address asked for.
        self._stream_server = parse_address(stream_server) if stream_server else None
        #: Where `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for a stream,
        #: during the poll that raised it, acted on right after that poll.
        self._streams_asked: list[dict] = []
        #: The transport numbers `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` named
        #: during that same poll, acted on at the same moment.
        self._streams_let_go: list[int] = []
        #: Whether that same poll named the main transport of a stack that
        #: signals over TCP or TLS: the stack retires a connection that stopped
        #: answering keep-alives (RFC 5626 Section 4.4.1) with its socket still
        #: open here, and nothing is sent on it again until a new one is bound.
        self._main_let_go = False
        #: Every connection opened for one, by the transport number it is
        #: bound at, and the destinations a connection is being opened to;
        #: both under :attr:`_stream_lock`.
        self._stream_lock = threading.Lock()
        self._sip_streams: dict[int, _SipStream] = {}
        self._streams_opening: set[str] = set()
        self._next_stream = _FIRST_STREAM

        #: Media sockets currently named with `sipral_stack_nat_map`, keyed
        #: by their own `host:port` text -- from that call until either
        #: `SIPRAL_EVENT_KIND_MEDIA_STARTED` hands the socket to
        #: :class:`sipral.media.Media` or the call gives up on it. Written
        #: from the calling thread (:meth:`_map_media_socket`,
        #: :meth:`_release_stun_socket`) and read from the poll thread
        #: (:meth:`_run`, :meth:`_drain_stun`); :attr:`_nat_lock` covers
        #: this and the two dicts below.
        self._nat_lock = threading.Lock()
        self._stun_sockets: dict[str, socket.socket] = {}
        #: Per socket, one `threading.Event` for `SIPRAL_EVENT_KIND_NAT_MAPPING`
        #: and one for `SIPRAL_EVENT_KIND_NAT_RELAY` -- a stack built with
        #: `turn_server` waits out both before a call may be placed or
        #: answered on the socket (`sipral_call_place`'s own
        #: `SIPRAL_STATUS_WRONG_STATE` for one that has not), a stack
        #: without it only the first.
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
        #: Whether this class picks the address peers reach this stack at --
        #: no ``bind_host`` was given, and it keeps picking across every
        #: :meth:`move_to` -- and whether it has picked it yet: the route
        #: toward the first server an account names, since creation or since
        #: the network last moved it.
        self._routes = bind_host is None
        self._route_chosen = not self._routes or self._streamed or stream_server is not None
        self._resolver = resolver or lookup
        #: What `SIPRAL_EVENT_KIND_LOOKUP_WANTED` asked during the poll that
        #: raised it, and what `SIPRAL_EVENT_KIND_LOCATED` found, acted on
        #: right after that poll.
        self._lookups_asked: list[tuple[int, str, int]] = []
        self._located: list[tuple[int, str]] = []
        #: The signalling connection, when there is one, and the lock every
        #: read and write on it holds: one TLS session read and written from
        #: two threads at once is a session whose records interleave.
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
        #: What a TLS connection of an account's own trusts when the account
        #: pins nothing, and the name it is opened under (the server's host
        #: when ``None``).
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
        #: Whether the last :meth:`move_to` that bound the UDP signalling
        #: socket again kept its port -- ``bind_port``, or the port in use
        #: when that was 0. ``False`` when another socket held that port at
        #: the new address and the system chose one instead, which
        #: :attr:`bind_address` then names: a peer or a firewall rule that
        #: only knows the old port has to be told. ``True`` before any move.
        self.kept_signalling_port = True
        if not self._streamed:
            self._socket.setblocking(False)
            bound_host, bound_port = self._socket.getsockname()
            if bind_host is None:
                bound_host = route_host(stream_server)
            self.bind_address = format_address(bound_host, bound_port)

        self._origin = time.monotonic()

        # Kept alive on the instance: cffi frees a callback's trampoline
        # once nothing in Python still references it, and C would be
        # calling into freed memory on the very next event if this were a
        # local instead.
        self._callback = ffi.callback("void(const sipral_event_t *, void *)")(
            self._on_event
        )

        if audio is None:
            audio = AudioMode.DEVICE if Feature.AUDIO_DEVICE in features() else AudioMode.APPLICATION
        #: Who pumps this stack's audio, an :class:`sipral.enums.AudioMode`.
        self.audio_mode = AudioMode(audio)
        #: The library's audio engine: devices, roles, gain, mute, the meter,
        #: activation and the ring (device mode; see :class:`sipral.audio.Audio`).
        self.audio = Audio(self)
        #: Connections to the TURN server a write from the engine's thread
        #: found broken, told to the stack from the poll thread: the engine's
        #: thread must not call back into the stack.
        self._turn_lost: list[str] = []
        # Kept alive on the instance for the same reason as the event
        # callback; the engine calls it from its own thread, once per packet.
        self._audio_transmit = ffi.callback("void(const sipral_audio_transmit_t *, void *)")(
            self._on_audio_transmit
        )

        # Everything else here is read once, inside `sipral_stack_create`,
        # and never touched again (`docs/08-ffi.md` calls a struct like
        # this one "versioned" precisely because the library copies what
        # it needs out of it before answering) -- so a local `char[]`/
        # `uint8_t[]` that outlives the call and nothing longer is enough;
        # nothing here has to be kept on `self`.
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
        #: Every callback `sipral_stack_log` was given, kept alive here for
        #: the reason the event callback is.
        self._log_callbacks: list = []

        out_stack = ffi.new("sipral_handle_t *")
        try:
            check(lib.sipral_stack_create(config, out_stack), "sipral_stack_create")
        except Exception:
            # refused -- device mode on a build with no backend for this
            # platform, say -- so the socket bound above has nothing to serve
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
        # A safety net, not the intended path: see the class docstring.
        try:
            self.close()
        except Exception:  # noqa: BLE001 -- never raise out of __del__
            pass

    def now_ms(self) -> int:
        """Elapsed milliseconds since this stack was created.

        `sipral_stack_create` fixed its own origin at that same moment
        (`crates/sipral-ffi/src/stack.rs`), so a reading taken from here
        a few milliseconds later is exactly the figure every entry point
        below expects `now_ms` to be.
        """
        return int((time.monotonic() - self._origin) * 1000)

    def settings(self) -> Settings:
        """What the stack runs with, every default filled in
        (`sipral_stack_settings`), with the SRTP suites its calls offer in
        order (`sipral_stack_srtp_suite_order`)."""
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
        """`sipral_stack_diagnostic_trace`: whether the trace level writes
        every SIP message whole, with its peer, from now on -- credentials
        and keys taken out either way -- or pseudonymised, as it does by
        default. Nothing is written unless the log is at
        ``LogLevel.TRACE``."""
        _retry(
            lambda: lib.sipral_stack_diagnostic_trace(self.handle, _toggle(on)),
            "sipral_stack_diagnostic_trace",
        )

    def _advertise_toward(self, peer: str) -> str:
        """The ``host:port`` an account whose server is ``peer`` is reached
        at, on a stack that picks its own address: the route toward the
        server, on this stack's port. The first server named also becomes
        the address the stack's `Via` carries."""
        port = parse_address(self.bind_address)[1]
        address = format_address(route_host(peer), port)
        if not self._route_chosen:
            self._route_chosen = True
            if address != self.bind_address:
                self._advertise_main(address)
        return address

    def _advertise_main(self, address: str) -> None:
        """The UDP transport the stack writes in its `Via` named ``address``
        from now on, on a stack that picks its own address."""
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
    ) -> Account:
        """`sipral_account_add`. See :class:`sipral.account.Account`.

        ``realms`` are the realms the password answers (RFC 3261 Section
        22.1). Left out, the account answers the realm its server first
        challenges it with and every realm its REGISTERs are challenged
        with, and no other; an SBC or outbound proxy at the server's address
        that challenges calls under a realm of its own needs both named. A
        challenge the password is not for is not answered, and
        `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED` says who asked and why:
        ``fields["refusal"]`` (a :class:`sipral.enums.ChallengeRefusal`),
        ``fields["server"]`` and ``fields["realms"]``.

        ``srtp`` is a `SIPRAL_SRTP_*` every call of this account is held to,
        over the stack's own -- a call may ask for more and never for less
        -- and ``srtp_suites`` the suites those calls run, most preferred
        first, by their RFC 4568 and RFC 7714 names. ``stir_verification`` is
        a :class:`sipral.enums.StirVerification`: what the account does with
        the `Identity` of the calls it receives, once :meth:`stir` gave the
        stack trust anchors. ``stir_key`` (a P-256 key: the bare 32 bytes, or
        SEC1 or PKCS #8 in DER or PEM) with ``stir_certificate_url`` signs
        every call the account places (RFC 8224), as ``stir_orig`` or the
        number in ``aor``, claiming ``stir_attestation`` (a
        :class:`sipral.enums.Attestation`, ``NONE`` for A) and
        ``stir_origid``. A PASSporT carries the time, which :meth:`stir`
        gives the stack: call it first, with ``None`` for anchors on a stack
        that only signs. ``recording_in_clear`` lets the account's encrypted
        calls be recorded to a recording server as plain RTP; left off, their
        copies go as SRTP or not at all (RFC 7866 §12.2).

        ``session_timer`` is an :class:`sipral.enums.SessionTimer`: ``0`` for
        the stack's default, ``OFF``, or ``INTERVAL`` with
        ``session_interval_seconds`` (90 or more, RFC 4028). ``privacy`` is
        :class:`sipral.enums.Privacy` bits every call this account places
        asks for (RFC 3323) -- ``Privacy.ID`` places them anonymous in
        `From`. ``trusted_peers`` are the addresses (IP literals, a list or
        one comma-separated string) whose `P-Asserted-Identity` this account
        believes and toward which alone it asserts its own (RFC 3325): an
        incoming call from anywhere else carries no asserted identity, and
        :attr:`sipral.events.Event.identity` says which it was.

        ``registrar`` left out makes an account that never registers --
        `docs/08-ffi.md`'s "An account with no registrar never registers"
        -- with ``registrar_address`` as the outbound proxy every request
        it places still goes to; two stacks on loopback that want to call
        each other directly, with no registrar between them at all, each
        add one account this way, pointed at the other's own
        :attr:`bind_address`.

        ``server_uri`` names the server by a URI whose host RFC 3263 locates
        -- ``sip:pbx.example.com``, ``sips:example.com:5061`` -- in place of
        ``registrar_address``: exactly one of the two is given. The lookups
        are answered with this stack's ``resolver``;
        `SIPRAL_EVENT_KIND_LOCATED` says where the server was found, and
        `SIPRAL_EVENT_KIND_LOCATE_FAILED` why not. A REGISTER waits for the
        first answer, and a call placed before it with no ``destination``
        raises ``SIPRAL_STATUS_WRONG_STATE``. ``server_naptr`` asks the
        domain for NAPTR records before SRV (RFC 3263 Section 4.1).

        ``keepalive_ms`` keeps the account's flow to its server open at that
        interval whatever STUN found -- a double CRLF on UDP, a ping on a
        stream -- for a NAT that forgets a flow sooner than the REGISTER
        refresh comes round: 1 000 to 120 000, ``0`` for never.

        ``tls_pin`` is the SHA-256 fingerprint of the one TLS certificate
        the account trusts, in the forms :meth:`TlsTrust.pinned` takes, for
        an application that runs the account's TLS itself:
        :meth:`sipral.account.Account.check_certificate` is its verdict on a
        certificate a server presented.

        ``stream_protocol`` (``Transport.TCP`` or ``Transport.TLS``) puts the
        account on a connection of its own to its server, beside accounts on
        this stack's UDP socket to other servers, in one stack with one
        audio engine: the stack asks for the connection
        (`SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, nothing outgrown), this stack
        opens it to the account's server whatever ``stream_fallback`` says
        and binds it, and the REGISTER and every call of the account go over
        it. A TLS one is held to ``tls_pin`` when the account has one, to the
        stack's ``tls_trust`` otherwise, under ``tls_server_name`` or the
        server's host. One that closes is opened again. Until it is open a
        call the account places raises ``SIPRAL_STATUS_TRANSPORT_DOWN``. Only
        on a stack that signals over UDP.
        """
        if (registrar_address is None) == (server_uri is None):
            raise ValueError("an account names its server by registrar_address or by server_uri, one of the two")
        if stream_protocol and (
            stream_protocol not in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS) or self._streamed
        ):
            raise ValueError("stream_protocol is Transport.TCP or Transport.TLS, on a stack that signals over UDP")
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
        """`sipral_stack_stir`: verify the callers of the calls this stack's
        accounts receive against ``anchors`` (PEM or DER certificates, the
        STI-PA's roots in a SHAKEN deployment) from now on (RFC 8224).

        ``unix_seconds`` is the wall clock now, which a PASSporT is signed
        and judged by, and defaults to this machine's; a stack whose
        accounts only sign calls this too, with ``None`` for ``anchors``,
        before adding them. The certificate a call names
        is wanted through `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`
        (:attr:`sipral.events.Event.verification`) and handed over with
        :meth:`stir_certificate`. ``accept_service_provider_codes`` lets a
        certificate that names a service provider code rather than numbers
        vouch for any caller, as a SHAKEN deployment's do; left off, a
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
        """`sipral_call_stir_certificate`: the chain the certificate URL a
        verification wanted yielded -- PEM or DER, the signing certificate
        first -- or ``None`` for one that could not be had. ``call`` is the
        handle the event named: the call has not been announced yet."""
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
    ) -> Call:
        """`sipral_call_place`, with this stack running the call's audio.

        A media socket is opened here, before the INVITE goes out, and its
        `host:port` is what `media_address` in `sipral_call_config_t`
        offers: the stack writes the offer from its own codec order and
        reads the answer, and :class:`sipral.media.Media` starts once
        `SIPRAL_EVENT_KIND_MEDIA_STARTED` says the session is up
        (`docs/08-ffi.md`, "A call is described one way or the other").

        ``ice`` is a :class:`sipral.enums.Ice` value, or ``0`` for the
        stack's own default. On a stack built with ``nat=Nat.STUN``, the
        socket is named with `sipral_stack_nat_map` first and this call
        blocks the calling thread -- never the poll thread -- until its
        `SIPRAL_EVENT_KIND_NAT_MAPPING` arrives, exactly as
        `sipral_stack_nat_map`'s own doc comment requires: placing a call
        on the socket any sooner is `SIPRAL_STATUS_WRONG_STATE`.

        ``text`` opens a second socket and offers a real-time text stream on
        it (RFC 4103), which :meth:`sipral.call.Call.send_text` writes to and
        ``call.text`` reads; it is not offered on a call keyed by SRTP or
        gathering ICE, the stream having no key or candidates of its own.
        ``feedback`` offers RTP/AVPF (RFC 4585) with Generic NACKs and
        reduced-size RTCP (RFC 5506), off by default since a far end that
        knows only RTP/AVP refuses the profile. ``focus`` says this end is
        the focus of a conference (RFC 4579): `isfocus` on its `Contact`.

        ``media_host`` left out binds the media socket at the address of the
        route toward ``destination``, or toward the account's server.
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
    ) -> Call:
        """Open a media socket for an incoming call and answer it there.

        ``event`` is the `SIPRAL_EVENT_KIND_INCOMING_CALL` a listener read
        off :attr:`events`: an incoming call has no :class:`Call` of its
        own until the application decides what to do with it, which is
        exactly what this builds -- `sipral_call_answer_media` under it,
        the other half of :meth:`place_call`. Call :meth:`Call.reject`
        instead when the application does not want it; that needs no
        socket, so it takes the call handle straight off ``event.call``.

        On a stack built with ``nat=Nat.STUN`` this blocks the calling
        thread until the socket's `SIPRAL_EVENT_KIND_NAT_MAPPING` arrives,
        the same wait :meth:`place_call` makes.

        With ``text``, ``feedback`` or ``focus`` -- as :meth:`place_call`
        takes them -- the call is answered through `sipral_call_answer_with`,
        a text socket opened for the real-time text stream the offer carried.

        ``media_host`` left out binds the media socket at the address of the
        route toward the server of the account the call came to.
        """
        media_host = self._media_host(media_host, self._account_for(event.account), None)
        media_socket = self.open_media_socket(media_host, media_port)
        media_address = format_address(*media_socket.getsockname())
        self._map_media_socket(media_socket, media_address)
        text_socket = self.open_media_socket(media_host) if text else None

        call = Call(self, event.call, media_socket, media_address, text_socket)
        self.register_call(call)
        try:
            if text or feedback or focus:
                call.answer_with(feedback=feedback, focus=focus)
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

    def _close_socket(self, sock: socket.socket) -> None:
        """Close a socket :meth:`open_media_socket` opened beside a call's
        media one -- its text socket, a recording server's two -- and give
        its port back to the RTP range."""
        try:
            port = sock.getsockname()[1]
        except OSError:
            return
        sock.close()
        self._give_back_port(port)

    def open_media_socket(self, host: str, port: int = 0) -> socket.socket:
        """A non-blocking UDP socket for a call's media, bound at ``host``.

        At ``port`` when one is named. Otherwise, on a stack built with an
        RTP port range, at an even port reserved from it
        (`sipral_stack_rtp_port_reserve`) -- one another process already
        holds is given back and the next tried, round the range -- and on a
        stack without one wherever the operating system puts it.
        ``SIPRAL_STATUS_EXHAUSTED`` once every pair is taken.
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
        """`sipral_stack_rtp_port_release` for a port no call took, on a
        stack with a range; best effort, since a port a call did take comes
        back by itself when the call ends."""
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
        """Send this stack's log to ``handler`` at ``level`` and louder, a
        :class:`sipral.enums.LogLevel`; ``LogLevel.OFF`` or no handler turns
        it off (`sipral_stack_log`).

        ``handler(level, target, message, suppressed)`` is called on
        whichever thread has just finished a call into the stack -- the
        poll thread, usually -- with the stack let go, so it may call back
        into it. Every line is already redacted: no user part, number, IP
        address or credential reaches it (`docs/17-observability.md`).
        ``suppressed`` counts the lines a flood had turned away before this
        one.
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
        # every one is kept for the stack's life: the one this replaced may
        # still be delivering a batch on the poll thread after this returns
        self._log_callbacks.append(callback)

    def state(self) -> str:
        """Everything this stack is holding, as the redacted text
        `sipral_stack_state_text` writes for a crash report: accounts, calls,
        transports, media sessions, the last refused calls, the queues, the
        RTP range and the counters. Safe from any thread, and never waits."""
        buffer = ffi.new(f"char[{lib.SIPRAL_STATE_TEXT_MAX}]")
        length = ffi.new("size_t *")
        check(
            lib.sipral_stack_state_text(self.handle, buffer, lib.SIPRAL_STATE_TEXT_MAX, length),
            "sipral_stack_state_text",
        )
        return ffi.string(buffer, int(length[0]) - 1).decode("utf-8")

    def diagnostics_json(self) -> str:
        """`sipral_stack_diagnostics_json`: the diagnostic record of every
        call the stack keeps, as JSON -- each decision the stack made and
        why, ``transport.kept.datagram`` among them for a request that went
        over UDP past RFC 3261 Section 18.1.1's line because
        ``datagram_without_stream_bytes`` let it."""
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

        Each line goes to ``logger.getChild(target)`` -- ``sipral.call``,
        ``sipral.sip``, ``sipral.api`` and so on under the default ``sipral``
        logger (`docs/17-observability.md` lists the targets) -- so an application filters by the part of the stack that wrote it
        the way it filters any library. The levels map as ``ERROR`` to
        ``logging.ERROR``, ``WARN`` to ``logging.WARNING``, ``INFO`` to
        ``logging.INFO``, ``DEBUG`` to ``logging.DEBUG`` and ``TRACE`` to
        :data:`TRACE` (5, below ``DEBUG``). ``level`` is the stack's own
        :class:`sipral.enums.LogLevel`; left out, it follows the logger's
        effective level when this is called, so lines the logger would drop
        are never formatted. A line that follows a flood carries the count
        of lines turned away before it as ``record.sipral_suppressed``.
        ``log_to`` replaces whatever :meth:`set_log` installed, and
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
        """This stack's health counters since it was created
        (`sipral_stack_counters`): registrations, how calls ended, what was
        screened, what went out again, what timed out and what was refused
        at a limit. One struct copy -- cheap enough to sample on a timer."""
        out = ffi.new("sipral_counters_t *")
        out.size = ffi.sizeof("sipral_counters_t")
        _retry(lambda: lib.sipral_stack_counters(self.handle, out), "sipral_stack_counters")
        return Counters.from_raw(out)

    def set_stun_servers(self, servers: Sequence[str]) -> None:
        """Ask these STUN servers from now on, in order of preference, each
        ``host:port`` -- what ``stun_server`` and ``stun_fallbacks`` would
        have named -- without creating the stack again
        (`sipral_stack_stun_servers`).

        Every socket the stack keeps mapped is asked again of the new list
        at once; ``EventKind.STUN_SERVER`` says the server in use moved and
        ``EventKind.NAT_MAPPING`` what the new one answers. On a stack
        created without a STUN server the signalling socket starts being
        kept mapped, and every media socket opened from then on is asked
        where it appears from before its call is described. An empty list
        asks nobody any more: accounts a STUN answer moved register their
        own address again, and calls are described by their sockets' own
        addresses. A stack with a TURN server keeps asking STUN, so an empty
        list there raises :class:`SipralError` with
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
        """`sipral_call_reject` for an incoming call nothing has answered,
        so no :class:`Call` -- and no media socket -- was ever needed."""
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

        ``event`` is the `SIPRAL_EVENT_KIND_REFERRAL` a listener read off
        :attr:`events`, with ``event.fields["status_code"]`` zero. This is
        `sipral_call_accept_transfer` on the referral's handle: the stack
        answers 202, reports on the call to whoever asked, and places it
        from the account the event names -- to ``event.fields["target"]``,
        which is the REFER's and never the caller's. A media socket is
        opened for it here, the way :meth:`place_call` opens one, and the
        :class:`Call` returned is that placed call. Taking one is a decision
        with a bill attached -- whoever sent it can make this line dial
        anything -- so it is never made on the application's behalf.
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
        """Refuse a REFER outside any dialog with ``code``, 300 to 699:
        `sipral_call_reject_transfer` on the referral's handle."""
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
        """Answer an incoming call nothing has answered with a redirection
        (`sipral_call_redirect`): ``status_code`` 300 to 399, 302 Moved
        Temporarily by default, with ``targets`` (URIs, a list or one
        comma-separated string) in `Contact`. With ``reason`` -- RFC 5806's
        ``unconditional``, ``user-busy``, ``no-answer``... -- a `Diversion`
        names the address that was called, so the next phone says the call
        was forwarded and why."""
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
        """Every entry of one identity list a call's INVITE carried --
        ``which`` an :class:`sipral.enums.IdentityText` -- for a call that
        has no :class:`sipral.call.Call` yet (``call`` its
        `SIPRAL_EVENT_KIND_INCOMING_CALL` event, or its handle).
        :meth:`sipral.call.Call.identity` is the same for one that has."""
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
        """The network under this stack changed, and ``host`` is this
        machine's address on the new one.

        The signalling socket is bound again at ``host`` -- over TCP or TLS,
        the connection made again from it -- and the main transport told
        (`sipral_stack_transport_bind`), the change reported
        (`sipral_stack_network_changed`, with ``link`` an
        :class:`sipral.enums.Link`), and every account added without a
        `Contact` of its own pointed at the new address
        (`sipral_account_rebind`). What the stack decided comes back as a
        :class:`sipral.enums.Recovery`. On ``Recovery.REBUILD`` every call
        whose media was described at the old address gets
        `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`, which
        :meth:`sipral.call.Call.readdress` answers -- the far end is still
        sending to an address this machine no longer has. An account added
        with an explicit ``contact`` is the application's to rebind with
        :meth:`sipral.account.Account.rebind`.

        A stack created with no ``bind_host`` keeps its socket on every
        interface, and its port, and keeps picking its own address: it
        advertises the route toward its first account's server again, as when
        it was created -- ``host`` only when no account names a server by its
        address -- and each account is reached at the route toward its own.
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
            # on a stack that picks its own address, each account is reached
            # at the route toward its own server, as when it was added
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
        """What a stack bound on every interface advertises after a move,
        chosen again as it was at creation: the route toward its first
        account's server, or with no server to route toward, ``host`` -- the
        new network's own address -- on the same port. The socket on every
        interface already receives there, on the port it had, and stays; an
        address this machine lacks raises, as binding the socket there
        would."""
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
        """The signalling connection made again from ``host``: the old one
        belongs to a network this machine has left. When the new one cannot
        be made, the stack hears why and this class keeps trying."""
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
        """The UDP signalling socket bound again at ``host``, on the port
        chosen at creation or, when that was 0, the port in use now; on a
        port the system picks only when that one is held there by another
        socket, which :attr:`kept_signalling_port` then says. The old socket
        holds the port itself when it is bound on every interface or at
        ``host`` already, so it is let go of before the port is tried a
        second time -- once ``host`` is known to be an address this machine
        has, so that a move to one it lacks raises with the old socket still
        open."""
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
        """The UDP signalling socket bound again at ``host``, and the main
        transport told."""
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
        """Track a call this ``Stack`` did not place itself.

        Used for a call `SIPRAL_EVENT_KIND_INCOMING_CALL` reports: the
        application answers it and only then does a :class:`Call` exist
        to dispatch that event's own delivery to, since the constructor
        is what would have to send it.
        """
        with self._lock:
            self._calls[call.handle] = call
        if self._turn_streamed:
            with self._nat_lock:
                self._turn_sockets[call.handle] = call.media_address

    def forget_account(self, account: Account) -> None:
        """Stop tracking an account :meth:`sipral.account.Account.remove`
        removed."""
        with self._lock:
            if account in self._accounts:
                self._accounts.remove(account)

    def forget_call(self, handle: int) -> None:
        with self._lock:
            self._calls.pop(handle, None)

    # -- the poll thread --------------------------------------------------

    def _on_event(self, raw, _user_data: object) -> None:
        """The C callback. Runs on the poll thread, with nothing held.

        `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` is delivered and not answered
        here. A dialog keeps the flow its INVITE went out on -- the
        registrar or outbound proxy the account names, the only path that
        survives a NAT -- and the event only says that the far end's
        `Contact` names some other address. This package has no resolver to
        answer it with, and answering with that `Contact` as a literal
        address moves the rest of the call onto it: behind a registrar
        reached through a port mapping or a NAT, the BYE then goes to an
        address nothing answers on. An application with a real lookup
        answers the event itself, through `sipral_stack_resolved`
        (`sipral._sipral_cffi.lib`).
        """
        self._deliver(_events.decode(raw[0]))

    def _deliver(self, event: _events.Event) -> None:
        # The call's own side effects (minting `Call.media`, marking it
        # ended) happen before `event` reaches any queue, for the same
        # reason `Call.deliver` orders its own steps that way: a consumer
        # of `self.events` may look up `self.call_for(event.call)` and
        # read its state, and that state has to already be current.
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
            # What the call still owes -- its RTCP BYE, and the Refresh that
            # gives its relay back -- was queued by the poll delivering this
            # event, and goes out through the call's own socket before
            # anything can hear that the call ended: an application that
            # closes the call the moment it does would otherwise forget it
            # and close that socket ahead of the drain after the poll, and
            # the relay would lapse on its server instead. Nothing is held
            # while the callback runs, so the library may be re-entered
            # from inside it (`docs/08-ffi.md`, "The shape").
            self._drain_farewells()
        if call is not None:
            call.deliver(event)

        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.events.put_nowait, event)
        else:
            self.events.put_nowait(event)

    def _on_audio_transmit(self, raw, _user_data: object) -> None:
        """`audio_transmit_callback`, in device mode: one packet the engine
        encoded from the microphone, sent from its call's media socket -- or,
        marked TCP or TLS, written on that socket's connection to the TURN
        server. Runs on the engine's own thread, once per frame per call, and
        calls nothing in the library: an entry point reached from here could
        wait on the engine that is waiting on this callback."""
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
            # a socket closed by a readdress or a hangup racing this send, or
            # a destination that is not host:port: the packet is lost, which
            # the far end's jitter buffer already knows how to hide
            pass

    def _drain_transmit(self) -> None:
        """`sipral_stack_poll_transmit`, until nothing is left to send.

        `SIPRAL_STATUS_BUSY` here means another thread -- an application
        thread answering or placing a call while this one is between two
        polls -- holds this stack's lock right now, not that anything is
        wrong (`docs/08-ffi.md`, "Signalling on one stack is one thread at
        a time"). This is the poll thread: nothing here may raise on it,
        because a `SipralError` that reached the top would end the thread
        for good and this stack would never poll again. Whatever is still
        queued is drained on the next pass instead.
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
                # one connection carries everything, whatever it names:
                # the server it reaches is the outbound proxy
                self._write_link(payload)
                continue
            destination = ffi.string(transmit.destination, transmit.destination_len)
            host, port = parse_address(destination.decode("utf-8"))
            self._socket.sendto(payload, (host, port))

    def _drain_farewells(self) -> None:
        """`sipral_stack_poll_farewell`: what a call that just ended still
        owes -- its RTCP BYE, and with a TURN server the Refresh that gives
        its relay back -- sent through that call's own media socket to the
        address the stack names. Under ICE that is the path ICE chose or
        the TURN server, not necessarily the last address media came from,
        which is only the fallback for a packet that names none. A call
        whose :class:`sipral.call.Call` was already closed, or that named
        no destination and never heard from the far end at all, is
        skipped: there is nothing left here that could still reach it.
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
                # given back on the relay's connection, which is the
                # stack's and not the call's, and outlives it
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
        """`sipral_stack_nat_map`, and the wait its own doc comment
        requires before a call may be described on ``sock``.

        A no-op when this stack was not built with `nat=Nat.STUN`: exactly
        today's behaviour for every other stack. Otherwise ``sock`` is
        registered with the poll thread's own selector under the
        ``("stun", address)`` tag -- :meth:`_run` then hands what arrives
        on it to `sipral_stack_receive_stun` instead of treating it as
        ordinary media, and :meth:`_drain_stun` sends what
        `sipral_stack_poll_stun` hands out for it -- and this call blocks
        the *calling* thread, never the poll thread, until
        `SIPRAL_EVENT_KIND_NAT_MAPPING` names this socket. `docs/06-nat.md`
        and `docs/08-ffi.md` ("Behind a NAT") put that within five and a
        half seconds whatever the server does; ``timeout`` leaves
        comfortable room over that before raising `TimeoutError`, which
        should not happen unless the poll thread itself has stopped.
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
        # `turn_server` rides the same socket: `sipral_call_place` and
        # `sipral_call_answer_media` both refuse a socket named here until
        # its `SIPRAL_EVENT_KIND_NAT_RELAY` has arrived too, allocated or
        # not (`docs/08-ffi.md`, "Behind a NAT").
        if self._turn and not waiters["relay"].wait(timeout):
            self._release_stun_socket(address)
            raise TimeoutError(f"no TURN allocation answer for {address} within {timeout}s")

    def _release_stun_socket(self, address: str) -> None:
        """Stop treating ``address`` as a pre-media-handle STUN/TURN
        socket: called once `SIPRAL_EVENT_KIND_MEDIA_STARTED` hands it to
        :class:`sipral.media.Media` (which reads it from then on) or once
        a call gives up on it before that ever happens."""
        with self._nat_lock:
            sock = self._stun_sockets.pop(address, None)
            self._nat_waiters.pop(address, None)
        if sock is not None:
            try:
                self._selector.unregister(sock)
            except (KeyError, ValueError, OSError):
                pass

    def _forget_media_socket(self, address: str) -> None:
        """`sipral_stack_nat_unmap` for a media socket named with
        `sipral_stack_nat_map` that will carry no call after all --
        `sipral_call_place` or `sipral_call_answer_media` refused it, or
        :meth:`close` is tearing the stack down with it still named. A
        no-op for a socket this stack never mapped (no `nat=Nat.STUN`,
        or the socket already reached `SIPRAL_EVENT_KIND_MEDIA_STARTED`
        and belongs to `Media` now).
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
            # A relayed socket owes the server a Refresh with a lifetime
            # of zero, waiting in `sipral_stack_poll_stun` now
            # (`docs/08-ffi.md`, "sipral_stack_nat_unmap"); one drain
            # sends it from the socket while it is still registered and
            # still open.
            self._drain_stun()
        self._release_stun_socket(address)

    def _drain_stun(self) -> None:
        """`sipral_stack_poll_stun`, until nothing is left to send.

        `transmit.source` names which media socket to send from --
        exactly the point of this queue being separate from
        `_drain_transmit`'s: a STUN request for one socket sent from
        another would teach the server the wrong socket's mapping,
        silently (`docs/08-ffi.md`, "Three entry points rather than a
        second use of the two signalling ones").
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
                # for the TURN server, on the socket's connection to it:
                # never a datagram, which a network that blocks UDP drops
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
        """Write ``payload`` on media socket ``local``'s connection to the
        TURN server, whole: what `sipral_stack_poll_stun`,
        `sipral_stack_poll_farewell` and a call's media hand out marked TCP
        or TLS. Thread-safe; a connection that fails here is closed and the
        stack is told, which loses the relay on it -- from the poll thread
        when the write came from the audio engine's (``from_engine``)."""
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
        """Open or close what `SIPRAL_EVENT_KIND_TURN_STREAM` asked for in
        the poll that just ran. A connection is opened on a thread of its
        own -- a TLS handshake is round trips the poll thread does not wait
        out -- and closed here, after this round's queues were written."""
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
        """Connect to the TURN server for media socket ``local``, over TLS
        when ``protocol`` says so with the certificate checked against
        :attr:`_turn_server_name`, and say how that went:
        `sipral_stack_turn_connected`, or `sipral_stack_turn_closed` for a
        connection that could not be made -- a refused port, a handshake
        that failed, a certificate nobody vouches for."""
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
        """`sipral_stack_turn_connected` or `sipral_stack_turn_closed`,
        from whichever thread knows; never raising on the way out."""
        local_buf = ffi.new("char[]", local_bytes)
        try:
            _retry(
                lambda: entry_point(self.handle, local_buf, len(local_bytes), self.now_ms()),
                "a TURN connection",
            )
        except Exception:  # noqa: BLE001 -- the stack is going away
            pass

    def _read_turn_stream(self, local: str) -> None:
        """What media socket ``local``'s connection to the TURN server
        carried, to `sipral_stack_turn_receive` -- every byte, in order,
        since a stream that loses one never finds its place again: a busy
        stack is waited for rather than skipped. The connection closing is
        `sipral_stack_turn_closed`; one the stack found broken
        (`SIPRAL_STATUS_STREAM_BROKEN`) is closed and needs no word."""
        with self._nat_lock:
            stream = self._turn_streams.get(local)
        if stream is None:
            return
        try:
            with stream.lock:
                # read without waiting: the selector said bytes arrived, not
                # that they make application data -- TLS 1.3's session
                # tickets come after the handshake and hold none, and a
                # read waiting on the rest would hold this, the poll
                # thread, for the socket's whole timeout
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
        """Close media socket ``local``'s connection, and when ``tell``, say
        so with `sipral_stack_turn_closed` -- not for one the stack itself
        asked to close or found broken."""
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
        """Answer what `SIPRAL_EVENT_KIND_LOOKUP_WANTED` asked in the poll
        that just ran, each lookup on a thread of its own -- a resolver may
        take seconds, and the poll thread may not wait for it -- and act on
        what `SIPRAL_EVENT_KIND_LOCATED` found: an account whose server was
        located at an address it has not been told of is pointed at it, and,
        on a stack that picks its own address, reached at the route toward
        it."""
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
                # the account was removed meanwhile, or the stack is busy
                # past patience: the next location says it again
                pass

    def _look_up(self, account: int, name: str, record: int) -> None:
        """One lookup through the resolver, and its answer handed back
        (`sipral_account_looked_up`); a resolver that raised is an answer
        that failed, since the procedure waits for every one."""
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
            # the account was removed while the resolver ran
            pass

    def _media_host(self, media_host: str | None, account: Account | None, destination: str | None) -> str:
        """The address a call's media socket is bound at: ``media_host``
        when one was given, else the route toward where the media will come
        from -- ``destination``, the account's server, or the address this
        stack is reached at."""
        if media_host is not None:
            return media_host
        for peer in (destination, account.registrar_address if account else None):
            if peer and _is_address(peer):
                return route_host(peer)
        return parse_address(self.bind_address)[0]

    def _act_on_streams_wanted(self) -> None:
        """Answer what `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for in the
        poll that just ran: a connection to each destination not already
        connected or being connected to, opened on a thread of its own, or
        -- with ``stream_fallback`` off -- the word that none is coming.

        First the connections the stack let go of in that poll: one that
        stopped answering keep-alives (RFC 5626 Section 4.4.1) is retired by
        the stack while its socket is still open here, and a connection kept
        open that the stack will never write to again would stand in for the
        new one it asks for."""
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
            # an account on a connection of its own asks with nothing
            # outgrown; that one is opened whatever stream_fallback says
            opens = self._stream_fallback or (wanted["request_bytes"] == 0 and wanted["limit_bytes"] == 0)
            over = (
                lib.SIPRAL_TRANSPORT_TLS
                if wanted["protocol"] == lib.SIPRAL_TRANSPORT_TLS
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
                args=(transport, destination, over),
                name="sipral-stream",
                daemon=True,
            ).start()

    def _stream_trust(self, destination: str) -> TlsTrust:
        """What a TLS connection to ``destination`` trusts: the pin of an
        account on a connection of its own to that server when it has one,
        the stack's ``tls_trust`` otherwise."""
        with self._lock:
            accounts = list(self._accounts)
        for account in accounts:
            if (
                account.stream_protocol == lib.SIPRAL_TRANSPORT_TLS
                and account.registrar_address == destination
                and account.tls_pin is not None
            ):
                return TlsTrust.pinned(account.tls_pin)
        return self._tls_trust

    def _open_sip_stream(self, transport: int, destination: str, over: int = lib.SIPRAL_TRANSPORT_TCP) -> None:
        """Connect over TCP -- or TLS, for an account whose connection speaks
        it -- to ``destination``, or to ``stream_server`` when one was given
        for TCP, and bind the connection at ``transport`` as the stream to
        ``destination``; a connection that cannot be made is told to the
        stack on that same number, which ends what was waiting for it."""
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
                    over,
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
        # read from here on: nothing arrives before the request the bind
        # just released, and a selector reports what is already waiting
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
        """`sipral_stack_transport_failed_with` for a connection that was not
        made; never raising on the way out. ``what`` finishes a sentence
        that begins with the protocol, "TCP" or "TLS" -- where the connection
        was going and what became of it -- carried to the event's detail."""
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
        """One message on the connection bound at ``transport``, whole; a
        write that fails loses the connection."""
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
        """What the connection bound at ``transport`` carried, to
        `sipral_stack_receive_stream`, every byte and in order; the far end
        closing it is `sipral_stack_stream_closed`."""
        with self._stream_lock:
            stream = self._sip_streams.get(transport)
        if stream is None:
            return
        try:
            with stream.lock:
                # read without waiting: over TLS the selector said bytes
                # arrived, not that they make application data
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
            # the framing is lost: the stack retired the transport itself
            self._lose_sip_stream(transport, tell=False)

    def _lose_sip_stream(self, transport: int, *, tell: bool) -> None:
        """Close the connection bound at ``transport`` and, when ``tell``,
        say so with `sipral_stack_stream_closed`."""
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
        """What goes after the address in a `Contact` this package writes:
        ``;transport=tcp`` or ``;transport=tls`` for a stack signalling over
        a connection (RFC 3261 Section 19.1.1), nothing over UDP."""
        if self.signalling == lib.SIPRAL_TRANSPORT_TLS:
            return ";transport=tls"
        if self.signalling == lib.SIPRAL_TRANSPORT_TCP:
            return ";transport=tcp"
        return ""

    @property
    def connected(self) -> bool:
        """Whether SIP can go out now: always over UDP, and over TCP or TLS
        while the connection to the server stands."""
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
        """Tell the stack a connection is open (`sipral_stack_transport_bind`
        naming both ends) and start reading it. Raises what the bind said,
        with the connection closed."""
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
        """`sipral_stack_transport_failed_with`, from whichever thread found out;
        never raising on the way out."""
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
        """Close the signalling connection, tell the stack how it ended --
        `sipral_stack_stream_closed` for an orderly close,
        `sipral_stack_transport_failed_with` otherwise, nothing for one the
        stack itself found broken -- and connect again."""
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
        """Connect again, backing off, until it works or the stack closes;
        then point every account at the new connection and register again
        the ones that were registering."""
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
        """Every account added without a `Contact` of its own moves to the
        new connection's address, and every one that was registering
        registers again now rather than at its next back-off."""
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
        """Write one message on the signalling connection, whole; a write
        that fails loses the connection."""
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
        """What the signalling connection carried, to
        `sipral_stack_receive_stream` -- every byte, in order: a busy stack
        is waited for rather than skipped, since a stream that loses a byte
        never finds its place again."""
        with self._link_lock:
            sock = self._link
            if sock is None:
                return
            try:
                # read without waiting: the selector said bytes arrived, not
                # that they make application data (a TLS 1.3 session ticket
                # holds none)
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
            # the framing is lost: the stack has retired the transport and
            # said so itself
            self._lose_link(lib.SIPRAL_TRANSPORT_ERROR_OTHER, lib.SIPRAL_TLS_FAILURE_NONE, "", tell=False)

    def _run(self) -> None:
        result = ffi.new("sipral_poll_result_t *")
        while not self._closed.is_set():
            timeout = 0.05
            events = self._selector.select(timeout)
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
                    # A media socket `_map_media_socket` named, still
                    # waiting for `SIPRAL_EVENT_KIND_NAT_MAPPING` or a
                    # call, or already described but with no media handle
                    # yet: everything arriving on it still goes to
                    # `sipral_stack_receive_stun` (`docs/08-ffi.md`,
                    # "Behind a NAT" -- "Until the call's media handle
                    # exists, everything arriving on its socket still
                    # goes to sipral_stack_receive_stun").
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
        """`sipral_stack_destroy`, and everything this wrapper opened.

        Whatever calls are still open are hung up first, while the poll
        thread can still send what that queues, and while each call is
        still tracked and its media socket still open: `sipral_call_hangup`
        only enqueues the BYE and, once it is answered, the RTCP BYE
        `sipral_stack_poll_farewell` owes the far end
        (`docs/08-ffi.md`, "A call that ends owes the far end an RTCP
        BYE") -- `_drain_transmit` and `_drain_farewells` are what
        actually write those, and that only happens from inside this
        thread's own loop, through `Stack.call_for` and the call's own
        `Media`. Calling `Call.close` on each call before that poll has
        had a chance to run would forget the call and close its media
        socket first, and a farewell drained afterwards would find
        nothing left to send it through -- a clean call reaching for the
        door on its way out and finding it already locked. So hanging up
        happens first, `Call.close` -- which releases the media handle
        and forgets the call -- only after the poll thread has had this
        round to drain both queues.
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
            # One more round of polling for the hangups just queued to go
            # out and, on loopback, for their answers to come back and be
            # read, and for the farewell each one then owes to be drained
            # and sent while the call is still tracked and its media
            # socket still open -- 200ms is comfortably more than a direct
            # call over a local network needs and still bounded.
            time.sleep(0.2)
        for call in calls:
            call.close()
        # Every media socket still named with `sipral_stack_nat_map` and
        # never reached by a call's own media handle -- `sipral_stack_destroy`
        # sends nothing, and a relay left allocated stays on the server
        # until its lifetime runs out (`docs/08-ffi.md`,
        # "sipral_stack_nat_unmap"). `Call.close` above already did this
        # for every socket a call still owned; this catches one mapped
        # and then abandoned before any call was ever placed on it.
        with self._nat_lock:
            leftover = list(self._stun_sockets)
        for address in leftover:
            self._forget_media_socket(address)
        self._closed.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)
        # and every connection to the TURN server still open: what it
        # carried was given back through it above, or lapses with it
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
