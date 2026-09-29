# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Call``: one call handle, its events and, once media starts, its audio."""

from __future__ import annotations

import asyncio
import socket as socket_module
from typing import TYPE_CHECKING

from . import events as _events
from ._sipral_cffi import ffi, lib
from .enums import AudioMode, CallState, DtmfVia, SrtpSuite
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
        self._suite: SrtpSuite | None = None

        #: Every event this call's handle names, decoded whole.
        self.events: asyncio.Queue[_events.Event] = asyncio.Queue()
        #: Just the digits: `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`'s and
        #: `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`'s own `fields["digit"]`, so a
        #: voice agent that only cares about DTMF does not have to filter
        #: `events` itself, nor care which way the far end sent the key.
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
            self.media = Media(
                self.stack,
                self.handle,
                self._media_socket,
                pumped=self.stack.audio_mode == AudioMode.DEVICE,
            )

        if event.kind == lib.SIPRAL_EVENT_KIND_MEDIA_SECURED:
            # a suite a newer library names and this binding does not is
            # still a secured call, whose transform this build cannot name
            try:
                self._suite = SrtpSuite(int(event.fields.get("suite", 0)))
            except ValueError:
                self._suite = SrtpSuite.UNKNOWN

        if event.kind == lib.SIPRAL_EVENT_KIND_CALL_ENDED:
            self.ended = True

        loop = self.stack._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.events.put_nowait, event)
        else:
            self.events.put_nowait(event)

        if event.kind in (
            lib.SIPRAL_EVENT_KIND_DIGIT_RECEIVED,
            lib.SIPRAL_EVENT_KIND_IN_BAND_DIGIT,
        ):
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

    def restart_ice(self) -> None:
        """`sipral_call_restart_ice`: offer the call again with new ICE
        credentials (RFC 8445 §9) and check every pair again once the far
        end answers, while the path it has carries the audio. The new path
        arrives as another `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`."""
        _call(
            lambda: lib.sipral_call_restart_ice(
                self.stack.handle, self.handle, self.stack.now_ms()
            ),
            "sipral_call_restart_ice",
        )

    def send_dtmf(
        self,
        digits: str,
        *,
        via: int = int(DtmfVia.RTP),
        duration_ms: int = 100,
    ) -> None:
        """`sipral_call_send_dtmf`. ``via`` is a :class:`sipral.enums.DtmfVia`:
        ``RTP`` sends named events, or the tones in the audio on a call that
        negotiated none; ``IN_BAND`` sends the tones on any call."""
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

    def set_dtmf_detection(self, mode: int) -> None:
        """`sipral_call_dtmf_detection`: when this call listens for digits
        in the far end's audio, a :class:`sipral.enums.DtmfDetection`. A
        digit heard there is a `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`, and lands
        in :attr:`dtmf` like any other."""
        _call(
            lambda: lib.sipral_call_dtmf_detection(self.stack.handle, self.handle, int(mode)),
            "sipral_call_dtmf_detection",
        )

    def detect_progress(
        self,
        *,
        region: int = 0,
        answering_machine: bool = True,
        beep: bool = True,
        beep_window_ms: int = 0,
        max_initial_silence_ms: int = 0,
        max_greeting_ms: int = 0,
        silence_after_greeting_ms: int = 0,
        max_words: int = 0,
        min_word_ms: int = 0,
        min_word_gap_ms: int = 0,
        max_decision_ms: int = 0,
        min_speech_above_floor_db: int = 0,
        beep_min_ms: int = 0,
        beep_max_ms: int = 0,
        tone_cycles: int = 0,
    ) -> None:
        """`sipral_call_detect_progress`: listen for the network's tones
        (``region``, a :class:`sipral.enums.ToneRegion`), decide who answered
        and listen for the machine's beep. Call it straight after
        :meth:`sipral.stack.Stack.place_call`, before the far end answers.
        Each thing heard is a `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`. Every
        limit left at zero is the library's default."""
        config = ffi.new("sipral_progress_config_t *")
        config.size = ffi.sizeof("sipral_progress_config_t")
        config.listen = lib.SIPRAL_TOGGLE_ON
        config.region = int(region)
        config.answering_machine = lib.SIPRAL_TOGGLE_ON if answering_machine else lib.SIPRAL_TOGGLE_OFF
        config.beep = lib.SIPRAL_TOGGLE_ON if beep else lib.SIPRAL_TOGGLE_OFF
        config.beep_window_ms = beep_window_ms
        config.max_initial_silence_ms = max_initial_silence_ms
        config.max_greeting_ms = max_greeting_ms
        config.silence_after_greeting_ms = silence_after_greeting_ms
        config.max_words = max_words
        config.min_word_ms = min_word_ms
        config.min_word_gap_ms = min_word_gap_ms
        config.max_decision_ms = max_decision_ms
        config.min_speech_above_floor_db = min_speech_above_floor_db
        config.beep_min_ms = beep_min_ms
        config.beep_max_ms = beep_max_ms
        config.tone_cycles = tone_cycles
        _call(
            lambda: lib.sipral_call_detect_progress(self.stack.handle, self.handle, config),
            "sipral_call_detect_progress",
        )

    def stop_progress(self) -> None:
        """`sipral_call_detect_progress` with ``listen`` off: stop listening."""
        config = ffi.new("sipral_progress_config_t *")
        config.size = ffi.sizeof("sipral_progress_config_t")
        config.listen = lib.SIPRAL_TOGGLE_OFF
        _call(
            lambda: lib.sipral_call_detect_progress(self.stack.handle, self.handle, config),
            "sipral_call_detect_progress",
        )

    def set_consent_tone(
        self,
        *,
        frequency_hz: int = 0,
        attenuation_db: int = 0,
        length_ms: int = 0,
        interval_ms: int = 0,
        local: bool = True,
    ) -> None:
        """`sipral_call_consent_tone`: beep while this call is recorded,
        every value left at zero the library's default (1400 Hz, 18 dB below
        0 dBm0, 200 ms every fifteen seconds); ``local`` has this end hear it
        too."""
        self._consent(lib.SIPRAL_TOGGLE_ON, frequency_hz, attenuation_db, length_ms, interval_ms, local)

    def clear_consent_tone(self) -> None:
        """`sipral_call_consent_tone` with ``enabled`` off: no tone."""
        self._consent(lib.SIPRAL_TOGGLE_OFF, 0, 0, 0, 0, True)

    def _consent(
        self,
        enabled: int,
        frequency_hz: int,
        attenuation_db: int,
        length_ms: int,
        interval_ms: int,
        local: bool,
    ) -> None:
        tone = ffi.new("sipral_consent_tone_t *")
        tone.size = ffi.sizeof("sipral_consent_tone_t")
        tone.enabled = enabled
        tone.frequency_hz = frequency_hz
        tone.attenuation_db = attenuation_db
        tone.length_ms = length_ms
        tone.interval_ms = interval_ms
        tone.local = lib.SIPRAL_TOGGLE_ON if local else lib.SIPRAL_TOGGLE_OFF
        _call(
            lambda: lib.sipral_call_consent_tone(self.stack.handle, self.handle, tone),
            "sipral_call_consent_tone",
        )

    def hangup_for(
        self,
        *,
        sip_cause: int = 0,
        q850_cause: int = 0,
        text: str | None = None,
    ) -> None:
        """`sipral_call_hangup_for`: end the call saying why, as a `Reason`
        (RFC 3326) on the BYE or the CANCEL -- ``sip_cause`` a SIP status,
        ``q850_cause`` a Q.850 cause (16 is normal clearing), either or both,
        with ``text`` beside them. The refusal of an incoming call nothing
        answered carries only the Q.850 value (RFC 6432)."""
        said = (text or "").encode("utf-8")
        _call(
            lambda: lib.sipral_call_hangup_for(
                self.stack.handle,
                self.handle,
                sip_cause,
                q850_cause,
                said or ffi.NULL,
                len(said),
                self.stack.now_ms(),
            ),
            "sipral_call_hangup_for",
        )

    def identity(self, which: int) -> list[str]:
        """Every entry of one identity list the INVITE of this call carried --
        ``which`` an :class:`sipral.enums.IdentityText`: every asserted party,
        every `Diversion` and its reason, every `History-Info` target and
        index, every `Alert-Info` URI. :attr:`sipral.events.Event.identity`
        has the first of each; this is the rest."""
        return self.stack.call_identity(self.handle, which)

    @property
    def srtp_suite(self) -> SrtpSuite | None:
        """The SRTP transform a DTLS-SRTP handshake settled this call's media
        on, as the last `SIPRAL_EVENT_KIND_MEDIA_SECURED` said -- from
        ``AES_CM80`` to RFC 7714's ``AEAD_AES256_GCM``, which two ends of
        this stack agree on -- or ``None`` before the handshake and for a
        call not keyed by one. A call keyed by SDES agreed its suite in the
        SDP and raises no such event: ``media.info()["secured"]`` says it is
        encrypted."""
        return self._suite

    def readdress(
        self,
        media_host: str,
        *,
        media_port: int = 0,
        public_address: str | None = None,
    ) -> None:
        """Move this call's audio to a new network: what
        `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks for once
        :meth:`sipral.stack.Stack.move_to` changed the stack's address.

        A media socket is bound at ``media_host:media_port`` and the call
        offered at it (`sipral_call_media_readdress`): a re-INVITE with the
        call's last description, only `c=` and the `m=` port moved, and
        ``public_address`` (``host:port``) in their place when the socket
        sits behind a NAT whose mapping the application knows. The new
        socket is the call's from here, whatever the far end answers --
        `SIPRAL_EVENT_KIND_SESSION_CHANGED`, or
        `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` -- and the old one is
        closed. ``SIPRAL_STATUS_WRONG_STATE`` for a call running ICE, which
        :meth:`restart_ice` moves instead, or one with a change already on
        its way.
        """
        sock = self.stack.open_media_socket(media_host, media_port)
        host, port = sock.getsockname()
        address = f"{host}:{port}".encode("utf-8")
        public = (public_address or "").encode("utf-8")
        try:
            _call(
                lambda: lib.sipral_call_media_readdress(
                    self.stack.handle,
                    self.handle,
                    address,
                    len(address),
                    public or ffi.NULL,
                    len(public),
                    self.stack.now_ms(),
                ),
                "sipral_call_media_readdress",
            )
        except Exception:
            sock.close()
            self.stack._give_back_port(port)
            raise
        old = self._media_socket
        self._media_socket = sock
        self._media_address = address.decode("utf-8")
        if self.media is not None:
            self.media.rebind(sock)
        else:
            old.close()

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

    @property
    def media_socket(self) -> socket_module.socket:
        """This call's media socket: where device mode's encoded packets
        leave from, and what :meth:`readdress` replaces."""
        return self._media_socket

    @property
    def media_address(self) -> str:
        """This call's media socket, as ``host:port``: the name
        `sipral_stack_nat_map` gave it, and so of its connection to a TURN
        server reached over TCP or TLS."""
        return self._media_address

    def __enter__(self) -> "Call":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
