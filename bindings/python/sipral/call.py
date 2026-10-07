# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Call``: one call handle, its events and, once media starts, its audio."""

from __future__ import annotations

import asyncio
import socket as socket_module
from typing import TYPE_CHECKING

from . import events as _events
from ._sipral_cffi import ffi, lib
from .enums import AudioMode, CallState, DtmfVia, SrtpSuite, Status
from .errors import SipralError
from .errors import call as _call
from .media import Media
from .subscription import Subscription, read_text

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["Call", "header_array"]


def header_array(fields) -> tuple[object, list[object]]:
    """``fields`` (pairs or a mapping) as a `sipral_header_t` array, plus the
    buffers it points into, which must outlive the call it is passed to."""
    pairs = list(fields.items()) if hasattr(fields, "items") else list(fields)
    array = ffi.new("sipral_header_t[]", max(len(pairs), 1))
    kept: list[object] = [array]
    for i, (name, value) in enumerate(pairs):
        name_bytes, value_bytes = name.encode("utf-8"), value.encode("utf-8")
        name_buf, value_buf = ffi.new("char[]", name_bytes), ffi.new("char[]", value_bytes)
        kept += [name_buf, value_buf]
        array[i].name, array[i].name_len = name_buf, len(name_bytes)
        array[i].value, array[i].value_len = value_buf, len(value_bytes)
    return array, kept


class Call:
    """One call handle and its actions.

    Built by :meth:`sipral.stack.Stack.place_call` or
    :meth:`sipral.stack.Stack.answer_call`, already registered with its
    stack so no event for it is lost.
    """

    def __init__(
        self,
        stack: "Stack",
        handle: int,
        media_socket: socket_module.socket,
        media_address: str,
        text_socket: socket_module.socket | None = None,
    ) -> None:
        self.stack = stack
        self.handle = handle
        self._media_socket = media_socket
        self._media_address = media_address
        self.media: Media | None = None
        self.ended = False
        #: The final media statistics, which arrive right after
        #: `SIPRAL_EVENT_KIND_CALL_ENDED`; ``None`` before, or if media never
        #: started.
        self.final_statistics: dict[str, object] | None = None
        self._suite: SrtpSuite | None = None

        #: Every event this call's handle names, decoded whole.
        self.events: asyncio.Queue[_events.Event] = asyncio.Queue()
        #: Just the DTMF digits, whether sent as events or in band.
        self.dtmf: asyncio.Queue[str] = asyncio.Queue()
        #: Just the real-time text (RFC 4103), control characters as in
        #: :class:`sipral.events.TypedText`.
        self.text: asyncio.Queue[str] = asyncio.Queue()
        self._text_socket = text_socket
        #: ``host:port`` of the text socket, with ``text=True``.
        self.text_address: str | None = (
            "{}:{}".format(*text_socket.getsockname()) if text_socket is not None else None
        )
        #: The recording session's call handle while :meth:`record_to` runs;
        #: its events arrive on the stack's queue.
        self.recording_session: int | None = None

    def deliver(self, event: _events.Event) -> None:
        """Called on the poll thread.

        State (:attr:`media`, :attr:`ended`) is updated before the event is
        queued, so a waiting coroutine never sees it stale.
        """
        if event.kind == lib.SIPRAL_EVENT_KIND_MEDIA_STARTED and self.media is None:
            # The socket becomes `Media`'s; the stack stops reading it first
            # so the two never race on one fd.
            self.stack._release_stun_socket(self._media_address)
            self.media = Media(
                self.stack,
                self.handle,
                self._media_socket,
                pumped=self.stack.audio_mode == AudioMode.DEVICE,
                text_socket=self._text_socket,
            )

        if event.kind == lib.SIPRAL_EVENT_KIND_MEDIA_SECURED:
            # A suite newer than this binding is still secured.
            try:
                self._suite = SrtpSuite(int(event.fields.get("suite", 0)))
            except ValueError:
                self._suite = SrtpSuite.UNKNOWN

        if event.kind == lib.SIPRAL_EVENT_KIND_CALL_ENDED:
            self.ended = True

        record = event.fields.get("statistics")
        if event.kind == lib.SIPRAL_EVENT_KIND_MEDIA_STATISTICS and record is not None:
            self.final_statistics = record
            if self.media is not None:
                self.media.ended_with(record)

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

        if event.kind == lib.SIPRAL_EVENT_KIND_TEXT_RECEIVED:
            typed = event.fields.get("text")
            if typed:
                if loop is not None and not loop.is_closed():
                    loop.call_soon_threadsafe(self.text.put_nowait, typed)
                else:
                    self.text.put_nowait(typed)

    # -- state --------------------------------------------------------

    @property
    def state(self) -> CallState:
        """The call state, read fresh rather than cached from events."""
        out_state = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_call_state(self.stack.handle, self.handle, out_state),
            "sipral_call_state",
        )
        return CallState(out_state[0])

    # -- actions --------------------------------------------------------

    def answer(self) -> None:
        """Accept, the stack running audio on this call's media socket."""
        address = self._media_address.encode("utf-8")
        _call(
            lambda: lib.sipral_call_answer_media(
                self.stack.handle, self.handle, address, len(address), self.stack.now_ms()
            ),
            "sipral_call_answer_media",
        )

    def ring(self, sdp: bytes | None = None) -> None:
        """180 Ringing, or with ``sdp`` a 183 carrying that description."""
        body = ffi.from_buffer(sdp) if sdp else ffi.NULL
        _call(
            lambda: lib.sipral_call_ring(
                self.stack.handle, self.handle, body, len(sdp or b""), self.stack.now_ms()
            ),
            "sipral_call_ring",
        )

    def ring_media(self, *, srtp: int = 0, codecs: str | None = None) -> None:
        """A 183 with an answer on this call's media socket, so the caller
        hears the application before :meth:`answer`, which reuses the
        session. ``srtp`` and ``codecs`` as for
        :meth:`sipral.stack.Stack.place_call`."""
        address = self._media_address.encode("utf-8")
        address_buf = ffi.new("char[]", address)
        config = ffi.new("sipral_call_config_t *")
        config.size = ffi.sizeof("sipral_call_config_t")
        config.media_address = address_buf
        config.media_address_len = len(address)
        config.srtp = srtp
        codecs_buf = None
        if codecs is not None:
            codecs_bytes = codecs.encode("utf-8")
            codecs_buf = ffi.new("char[]", codecs_bytes)
            config.codecs = codecs_buf
            config.codecs_len = len(codecs_bytes)
        _call(
            lambda: lib.sipral_call_ring_media(
                self.stack.handle, self.handle, config, self.stack.now_ms()
            ),
            "sipral_call_ring_media",
        )

    def set_headers(self, fields) -> None:
        """Header fields (pairs or a mapping) for what the call sends at the
        application's request from now on (180, 200, refusal, BYE),
        replacing earlier ones; empty clears them."""
        array, kept = header_array(fields)
        count = len(kept) // 2
        _call(
            lambda: lib.sipral_call_set_headers(
                self.stack.handle, self.handle, array if count else ffi.NULL, count
            ),
            "sipral_call_set_headers",
        )

    def transfer(self, target: str) -> None:
        """REFER the far end to ``target`` (RFC 3515). ``TRANSFER_PROGRESS``
        then ``TRANSFER_DONE`` follow; a refused REFER is a ``TRANSFER_DONE``
        with the refusal's status."""
        encoded = target.encode("utf-8")
        _call(
            lambda: lib.sipral_call_transfer(
                self.stack.handle, self.handle, encoded, len(encoded), self.stack.now_ms()
            ),
            "sipral_call_transfer",
        )

    def reject(self, code: int = 486) -> None:
        """Reject with ``code`` (486 Busy Here, 603 Decline, ...)."""
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
        """Re-offer with new ICE credentials (RFC 8445 §9); audio stays on
        the current path until a new `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`."""
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
        """Send DTMF. ``via`` (:class:`sipral.enums.DtmfVia`): ``RTP`` sends
        events, or tones if none were negotiated; ``IN_BAND`` always tones."""
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
        """When to detect digits in the far end's audio
        (:class:`sipral.enums.DtmfDetection`); they land in :attr:`dtmf`."""
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
        """Listen for network tones (``region``:
        :class:`sipral.enums.ToneRegion`), detect who answered and the
        machine's beep. Call right after placing, before the answer. Results
        are `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`; zero limits mean defaults."""
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
        """Stop progress detection."""
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
        """Beep while recorded; zeros mean 1400 Hz, -18 dBm0, 200 ms every
        15 s. ``local`` plays it here too."""
        self._consent(lib.SIPRAL_TOGGLE_ON, frequency_hz, attenuation_db, length_ms, interval_ms, local)

    def clear_consent_tone(self) -> None:
        """Turn the consent tone off."""
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
        """End the call with a `Reason` (RFC 3326): ``sip_cause``,
        ``q850_cause`` (16 is normal clearing) or both, plus ``text``. Refusing
        an unanswered incoming call carries only the Q.850 value (RFC 6432)."""
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
        """All entries of one identity list from the INVITE (``which``:
        :class:`sipral.enums.IdentityText`);
        :attr:`sipral.events.Event.identity` has only the first of each."""
        return self.stack.call_identity(self.handle, which)

    @property
    def srtp_suite(self) -> SrtpSuite | None:
        """The SRTP suite DTLS-SRTP settled on, or ``None`` before the
        handshake or without DTLS. SDES calls raise no such event; check
        ``media.info()["secured"]``."""
        return self._suite

    def readdress(
        self,
        media_host: str,
        *,
        media_port: int = 0,
        public_address: str | None = None,
    ) -> None:
        """Move the call's audio to a new network, answering
        `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`.

        Binds a socket at ``media_host:media_port`` and re-INVITEs with only
        `c=` and the `m=` port changed (``public_address`` instead when a
        known NAT sits in front). The new socket is kept whatever the answer
        (`SESSION_CHANGED` or `SESSION_CHANGE_FAILED`); the old one closes.
        ``SIPRAL_STATUS_WRONG_STATE`` under ICE (use :meth:`restart_ice`) or
        with a change already pending.
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

    def answer_with(
        self, *, feedback: bool = False, focus: bool = False, codecs: str | None = None
    ) -> None:
        """Accept like :meth:`answer`, plus real-time text (if built with a
        text socket), RTCP feedback, conference focus, or ``codecs``."""
        address = self._media_address.encode("utf-8")
        address_buf = ffi.new("char[]", address)
        config = ffi.new("sipral_call_config_t *")
        config.size = ffi.sizeof("sipral_call_config_t")
        config.media_address = address_buf
        config.media_address_len = len(address)
        text_buf = None
        if self.text_address is not None:
            text = self.text_address.encode("utf-8")
            text_buf = ffi.new("char[]", text)
            config.text_address = text_buf
            config.text_address_len = len(text)
        config.feedback = lib.SIPRAL_TOGGLE_ON if feedback else lib.SIPRAL_TOGGLE_DEFAULT
        config.focus = 1 if focus else 0
        codecs_buf = None
        if codecs is not None:
            codecs_bytes = codecs.encode("utf-8")
            codecs_buf = ffi.new("char[]", codecs_bytes)
            config.codecs = codecs_buf
            config.codecs_len = len(codecs_bytes)
        _call(
            lambda: lib.sipral_call_answer_with(
                self.stack.handle, self.handle, config, self.stack.now_ms()
            ),
            "sipral_call_answer_with",
        )

    # -- real-time text ---------------------------------------------------

    def send_text(self, text: str) -> None:
        """Queue typed text (RFC 4103), sent in the next 300 ms interval;
        U+0008 erases the far end's last character.
        `SIPRAL_STATUS_NOT_NEGOTIATED` without a text stream,
        `SIPRAL_STATUS_EXHAUSTED` when the backlog is full, `RuntimeError`
        before media starts."""
        if self.media is None:
            raise RuntimeError("the call has no media yet; wait for MEDIA_STARTED")
        self.media.send_text(text)

    # -- conferences ------------------------------------------------------

    def set_focus(self, focus: bool) -> None:
        """Set or clear `isfocus` on this call's `Contact` from now on
        (RFC 4579)."""
        _call(
            lambda: lib.sipral_call_set_focus(self.stack.handle, self.handle, 1 if focus else 0),
            "sipral_call_set_focus",
        )

    @property
    def conference_uri(self) -> str | None:
        """The conference URI when the far end is a focus (RFC 4579 Section
        4.2), else ``None``."""
        try:
            return read_text(
                lambda buffer, capacity, needed: lib.sipral_call_conference_uri(
                    self.stack.handle, self.handle, buffer, capacity, needed
                ),
                "sipral_call_conference_uri",
            )
        except SipralError as refused:
            if refused.status == Status.NOT_A_FOCUS:
                return None
            raise

    def subscribe_conference(self) -> Subscription:
        """Subscribe to the focus's conference (RFC 4579 Section 3.4). The
        subscription outlives the call; updates are
        `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
        `SIPRAL_STATUS_NOT_A_FOCUS` when the far end is not a focus."""
        out = ffi.new("sipral_handle_t *")
        _call(
            lambda: lib.sipral_call_subscribe_conference(
                self.stack.handle, self.handle, out, self.stack.now_ms()
            ),
            "sipral_call_subscribe_conference",
        )
        return Subscription(self.stack, int(out[0]), "conference")

    # -- recording to a server (SIPREC) -----------------------------------

    def record_to(self, server: str, *, destination: str | None = None) -> int:
        """Record this call to a recording server (RFC 7866).

        Two extra sockets carry this end's audio (label ``1``) and the far
        end's (label ``2``). The session goes to ``server`` from the call's
        account, or to ``destination`` (``host:port``). Its INVITE exceeds a
        datagram, so the stack must reach the server over TCP or TLS. Needs
        media started and no recording running, else
        `SIPRAL_STATUS_WRONG_STATE`. Returns the session handle.
        """
        if self.media is None:
            raise SipralError(lib.SIPRAL_STATUS_WRONG_STATE, "sipral_call_record_to")
        host = self._media_address.rpartition(":")[0]
        this_end = self.stack.open_media_socket(host)
        far_end = self.stack.open_media_socket(host)
        try:
            server_bytes = server.encode("utf-8")
            this_bytes = "{}:{}".format(*this_end.getsockname()).encode("utf-8")
            far_bytes = "{}:{}".format(*far_end.getsockname()).encode("utf-8")
            keep = [ffi.new("char[]", server_bytes), ffi.new("char[]", this_bytes), ffi.new("char[]", far_bytes)]
            config = ffi.new("sipral_record_config_t *")
            config.size = ffi.sizeof("sipral_record_config_t")
            config.server, config.server_len = keep[0], len(server_bytes)
            config.this_end, config.this_end_len = keep[1], len(this_bytes)
            config.far_end, config.far_end_len = keep[2], len(far_bytes)
            if destination is not None:
                destination_bytes = destination.encode("utf-8")
                keep.append(ffi.new("char[]", destination_bytes))
                config.destination, config.destination_len = keep[-1], len(destination_bytes)
            out = ffi.new("sipral_handle_t *")
            _call(
                lambda: lib.sipral_call_record_to(
                    self.stack.handle, self.handle, config, out, self.stack.now_ms()
                ),
                "sipral_call_record_to",
            )
        except Exception:
            self.stack._close_socket(this_end)
            self.stack._close_socket(far_end)
            raise
        self.media.attach_recording(this_end, far_end)
        self.recording_session = int(out[0])
        return self.recording_session

    def stop_recording_to(self) -> None:
        """Stop recording at once and hang up the session.
        `SIPRAL_STATUS_WRONG_STATE` when not recording."""
        _call(
            lambda: lib.sipral_call_stop_recording_to(
                self.stack.handle, self.handle, self.stack.now_ms()
            ),
            "sipral_call_stop_recording_to",
        )
        if self.media is not None:
            self.media.detach_recording()
        self.recording_session = None

    def close(self) -> None:
        """Hang up if this call is still up, release its media, forget it.

        Idempotent.
        """
        if not self.ended:
            try:
                self.hangup()
            except Exception:  # noqa: BLE001 -- best effort on the way out
                pass
        if self.media is not None:
            self.media.close()
        else:
            # Media never started: unmap the socket before closing it.
            self.stack._forget_media_socket(self._media_address)
            self._media_socket.close()
            if self._text_socket is not None:
                self.stack._close_socket(self._text_socket)
        self.stack.forget_call(self.handle)

    @property
    def media_socket(self) -> socket_module.socket:
        """This call's media socket; :meth:`readdress` replaces it."""
        return self._media_socket

    @property
    def media_address(self) -> str:
        """The media socket as ``host:port``, which also names its TURN
        connection."""
        return self._media_address

    def __enter__(self) -> "Call":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
