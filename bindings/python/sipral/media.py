# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Media``: one call's audio, paced at its own frame rate.

Media has its own handle and never takes the stack's lock, so it runs on
its own thread, paced by the negotiated frame length rather than by the
application.
"""

from __future__ import annotations

import asyncio
import queue
import selectors
import socket as socket_module
import threading
import time
from typing import TYPE_CHECKING

from . import events as _events
from ._sipral_cffi import ffi, lib
from .enums import KeyExchange
from .errors import SipralError
from .errors import call as _call
from .errors import check

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["Media"]

_PACKET_BYTES = lib.SIPRAL_MEDIA_PACKET_BYTES
_ADDRESS_BYTES = 128


def _format_address(host: str, port: int) -> str:
    return f"{host}:{port}"


def _parse_address(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


class Media:
    """A call's media handle and packet pump.

    Not built directly: it appears as ``call.media`` on
    `SIPRAL_EVENT_KIND_MEDIA_STARTED`.
    """

    def __init__(
        self,
        stack: "Stack",
        call_handle: int,
        sock: socket_module.socket,
        *,
        pumped: bool = False,
        text_socket: socket_module.socket | None = None,
    ) -> None:
        self.stack = stack
        self.call_handle = call_handle
        self._final_statistics: dict[str, object] | None = None
        #: Device mode: the engine pumps audio, :attr:`frames` stays empty and
        #: :meth:`send_audio` is refused; this thread only carries packets.
        self.pumped = pumped
        self._socket = sock
        self._socket.setblocking(False)
        #: The socket's `host:port`, which also names its TURN connection.
        self.local_address = _format_address(*sock.getsockname())

        out_media = ffi.new("sipral_handle_t *")
        _call(
            lambda: lib.sipral_call_media(stack.handle, call_handle, out_media),
            "sipral_call_media",
        )
        self.handle = int(out_media[0])

        info = self.info()
        self.sample_rate = info["sample_rate"]
        self.frame_samples = info["frame_samples"]
        self._frame_seconds = max(info["frame_ms"], 1) / 1000.0
        self._silence = bytes(self.frame_samples * 2)

        #: Source of the last datagram received, the fallback for the
        #: farewell RTCP BYE; `None` until a packet arrives.
        self.remote_address: str | None = None

        #: Decoded 16-bit mono PCM, one frame per item, on the stack's
        #: asyncio loop when one was given.
        self.frames: asyncio.Queue[bytes] = asyncio.Queue()
        self._to_send: queue.Queue[bytes] = queue.Queue()
        self._pending = bytearray()
        #: Held per frame, and while :meth:`set_app_rate` changes its length.
        self._frame_lock = threading.Lock()
        self._active = True
        self._closed = threading.Event()

        #: Held while the socket is read or replaced (:meth:`rebind`).
        self._socket_lock = threading.Lock()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ)
        self._text_socket = text_socket
        if text_socket is not None:
            text_socket.setblocking(False)
        #: Recording sockets (this end, far end) while recording.
        self._recording: tuple[socket_module.socket, socket_module.socket] | None = None

        self._thread = threading.Thread(
            target=self._run, name="sipral-media", daemon=True
        )
        self._thread.start()

    def send_to(self, payload: bytes, address: str) -> None:
        """Write ``payload`` straight from this call's RTP socket (farewells,
        local conference audio); a call's own audio uses :meth:`send_audio`.
        """
        host, _, port = address.rpartition(":")
        try:
            self._socket.sendto(payload, (host, int(port)))
        except OSError:
            pass

    def info(self) -> dict[str, object]:
        """`sipral_media_info`, as a plain `dict`."""
        out = ffi.new("sipral_media_info_t *")
        out.size = ffi.sizeof("sipral_media_info_t")
        _call(lambda: lib.sipral_media_info(self.handle, out), "sipral_media_info")
        return {
            "codec": int(out.codec),
            "payload_type": int(out.payload_type),
            "clock_rate": int(out.clock_rate),
            "sample_rate": int(out.sample_rate),
            "frame_ms": int(out.frame_ms),
            "frame_samples": int(out.frame_samples),
            "direction": int(out.direction),
            "sending": bool(out.sending),
            "receiving": bool(out.receiving),
            "has_dtmf": bool(out.has_dtmf),
            "secured": bool(out.secured),
            "recording": bool(out.recording),
            "recorded_ms": int(out.recorded_ms),
            "stalled": bool(out.stalled),
            "has_text": bool(out.has_text),
            "feedback": bool(out.feedback),
            "generic_nack": bool(out.generic_nack),
            "reduced_size": bool(out.reduced_size),
        }

    def encryption(self) -> list[_events.Protection]:
        """How each stream (here: the audio) is protected now."""
        count = ffi.new("size_t *")
        _call(
            lambda: lib.sipral_media_encryption_count(self.handle, count),
            "sipral_media_encryption_count",
        )
        report = []
        for index in range(int(count[0])):
            out = ffi.new("sipral_stream_encryption_t *")
            out.size = ffi.sizeof("sipral_stream_encryption_t")
            _call(
                lambda: lib.sipral_media_encryption_at(self.handle, index, out),
                "sipral_media_encryption_at",
            )
            report.append(
                _events.Protection(
                    key_exchange=KeyExchange(int(out.key_exchange)),
                    encrypted=bool(out.encrypted),
                    authenticated=bool(out.authenticated),
                    suite=int(out.suite),
                    awaiting_keys=bool(out.awaiting_keys),
                )
            )
        return report

    def ended_with(self, record: dict[str, object]) -> None:
        """Keep the end-of-call record for :meth:`statistics`."""
        self._final_statistics = record

    def statistics(self) -> dict[str, object]:
        """`sipral_media_statistics`, as a plain `dict`.

        ``frames_underrun`` counts frames played empty because the jitter
        buffer ran dry while the far end still sent; ``loss_rate``, ``score``
        and ``suffering`` include them. ``feedback`` holds RTP/AVPF (RFC
        4585, RFC 5506) counters, or ``None`` when not in use.

        After the call ends this returns the end-of-call record
        (:attr:`sipral.call.Call.final_statistics`, no ``feedback``) instead
        of raising ``WRONG_STATE``.
        """
        out = ffi.new("sipral_stream_stats_t *")
        out.size = ffi.sizeof("sipral_stream_stats_t")
        try:
            _call(
                lambda: lib.sipral_media_statistics(self.handle, self.stack.now_ms(), out),
                "sipral_media_statistics",
            )
        except SipralError as refused:
            final = self._final_statistics
            if refused.status != lib.SIPRAL_STATUS_WRONG_STATE or final is None:
                raise
            return dict(final)
        return {
            "codec": int(out.codec),
            "round_trip_us": int(out.round_trip_us) if out.has_round_trip else None,
            "packets_sent": int(out.packets_sent),
            "octets_sent": int(out.octets_sent),
            "packets_received": int(out.packets_received),
            "packets_lost": int(out.packets_lost),
            "delay_us": int(out.delay_us),
            "jitter_us": int(out.jitter_us),
            "loss_rate": float(out.loss_rate),
            "score": float(out.score),
            "suffering": bool(out.suffering),
            "frames_underrun": int(out.frames_underrun),
            "feedback": {
                "trr_interval_ms": int(out.trr_interval_ms),
                "nacks_sent": int(out.nacks_sent),
                "packets_nacked": int(out.packets_nacked),
                "nacks_received": int(out.nacks_received),
                "packets_asked_for": int(out.packets_asked_for),
                "early_packets": int(out.early_packets),
                "reduced_size_packets": int(out.reduced_size_packets),
                "feedback_suppressed": int(out.feedback_suppressed),
            }
            if out.feedback
            else None,
        }

    def path_candidates(self) -> list[dict[str, object]]:
        """Every ICE pair and relay tried, and its outcome, as dicts. Empty
        without ICE."""
        count = ffi.new("size_t *")
        _call(
            lambda: lib.sipral_media_path_candidate_count(self.handle, count),
            "sipral_media_path_candidate_count",
        )
        paths = []
        for index in range(int(count[0])):
            out = ffi.new("sipral_path_candidate_t *")
            out.size = ffi.sizeof("sipral_path_candidate_t")
            local = ffi.new(f"char[{lib.SIPRAL_ADDRESS_BYTES}]")
            remote = ffi.new(f"char[{lib.SIPRAL_ADDRESS_BYTES}]")
            out.local = local
            out.local_capacity = lib.SIPRAL_ADDRESS_BYTES
            out.remote = remote
            out.remote_capacity = lib.SIPRAL_ADDRESS_BYTES
            _call(
                lambda: lib.sipral_media_path_candidate_at(self.handle, index, out),
                "sipral_media_path_candidate_at",
            )
            paths.append(
                {
                    "kind": int(out.kind),
                    "outcome": int(out.outcome),
                    "code": int(out.code),
                    "local_kind": int(out.local_kind),
                    "remote_kind": int(out.remote_kind),
                    "priority": int(out.priority),
                    "local": ffi.string(local, out.local_len).decode(),
                    "remote": ffi.string(remote, out.remote_len).decode(),
                }
            )
        return paths

    def set_app_rate(self, hz: int) -> None:
        """The rate of :attr:`frames` and :meth:`send_audio`, independent of
        the codec.

        8000, 16000, 24000 or 48000, or 0 for the codec's own (the start).
        The library resamples both ways; :attr:`sample_rate` and
        :attr:`frame_samples` update. Unsent queued audio is dropped. Other
        rates raise ``INVALID_ARGUMENT``; device mode ``WRONG_STATE``.
        """
        with self._frame_lock:
            _call(
                lambda: lib.sipral_media_set_app_rate(self.handle, hz),
                "sipral_media_set_app_rate",
            )
            info = self.info()
            self.sample_rate = info["sample_rate"]
            self.frame_samples = info["frame_samples"]
            self._silence = bytes(self.frame_samples * 2)
            self._pending.clear()
            while True:
                try:
                    self._to_send.get_nowait()
                except queue.Empty:
                    break

    def send_audio(self, pcm: bytes | memoryview) -> None:
        """Queue 16-bit mono PCM to go out, one frame at a time.

        Any length is accepted, at :attr:`sample_rate`, and cut into
        :attr:`frame_samples` frames as it is sent. Thread-safe. Raises
        `RuntimeError` in device mode, where the microphone is the audio.
        """
        if self.pumped:
            raise RuntimeError(
                "this call's audio is pumped by the library's own engine "
                "(device mode); create the stack with audio=AudioMode.APPLICATION "
                "to send frames of your own"
            )
        self._to_send.put(bytes(pcm))

    def record(
        self,
        path: str,
        *,
        format: int = 0,
        layout: int = 0,
        sample_rate: int = 0,
        bitrate: int = 0,
        checkpoint_ms: int = 0,
    ) -> None:
        """Record both directions to ``path``.

        ``format``: :class:`sipral.enums.RecordingFormat` (WAV, or Ogg Opus
        where built). ``layout``: :class:`sipral.enums.RecordingLayout` (mono,
        or this end left, far end right). ``sample_rate`` 0 for the call's;
        ``bitrate`` for Opus; ``checkpoint_ms`` how often the file is made
        crash-safe (0 for 5 s). Finished by :meth:`stop_recording`, the call
        ending, or the stack closing."""
        encoded = path.encode("utf-8")
        options = ffi.new("sipral_recording_options_t *")
        options.size = ffi.sizeof("sipral_recording_options_t")
        options.format = int(format)
        options.layout = int(layout)
        options.sample_rate = sample_rate
        options.bitrate = bitrate
        options.checkpoint_ms = checkpoint_ms
        _call(
            lambda: lib.sipral_media_record_start_with(
                self.handle, encoded, len(encoded), options
            ),
            "sipral_media_record_start_with",
        )

    def stop_recording(self) -> None:
        """Stop recording and finish the file."""
        _call(lambda: lib.sipral_media_record_stop(self.handle), "sipral_media_record_stop")

    @property
    def recording(self) -> tuple[bool, int]:
        """Whether recording runs, and milliseconds recorded."""
        running = ffi.new("uint32_t *")
        taken = ffi.new("uint64_t *")
        _call(
            lambda: lib.sipral_media_record_state(self.handle, running, taken),
            "sipral_media_record_state",
        )
        return bool(running[0]), int(taken[0])

    def send_text(self, text: str) -> None:
        """See :meth:`sipral.call.Call.send_text`."""
        encoded = text.encode("utf-8")
        check(
            lib.sipral_media_send_text(self.handle, encoded, len(encoded)),
            "sipral_media_send_text",
        )

    def attach_recording(
        self, this_end: socket_module.socket, far_end: socket_module.socket
    ) -> None:
        """Send recording copies from these two sockets."""
        this_end.setblocking(False)
        far_end.setblocking(False)
        with self._socket_lock:
            self._recording = (this_end, far_end)

    def detach_recording(self) -> None:
        """Close the recording sockets."""
        with self._socket_lock:
            taken, self._recording = self._recording, None
        if taken is not None:
            for sock in taken:
                self.stack._close_socket(sock)

    def _carry_text(self) -> None:
        """Receive and send pending real-time text packets."""
        sock = self._text_socket
        if sock is None:
            return
        taken = ffi.new("uint32_t *")
        while True:
            try:
                data, from_address = sock.recvfrom(2048)
            except (BlockingIOError, OSError):
                break
            from_text = _format_address(*from_address).encode("utf-8")
            lib.sipral_media_receive_text(
                self.handle, data, len(data), from_text, len(from_text), self.stack.now_ms(), taken
            )
        self._drain_packets(
            lambda packet: lib.sipral_media_poll_text(self.handle, self.stack.now_ms(), packet),
            sock,
        )

    def _carry_recording(self) -> None:
        """Send pending recording copies; the server's RTCP back is discarded."""
        with self._socket_lock:
            sockets = self._recording
        if sockets is None:
            return
        for sock in sockets:
            while True:
                try:
                    sock.recv(2048)
                except (BlockingIOError, OSError):
                    break
        far_end = ffi.new("uint32_t *")
        packet = ffi.new("sipral_media_packet_t *")
        data = ffi.new(f"uint8_t[{_PACKET_BYTES}]")
        destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        while True:
            packet.size = ffi.sizeof("sipral_media_packet_t")
            packet.data = data
            packet.capacity = _PACKET_BYTES
            packet.destination = destination
            packet.destination_capacity = _ADDRESS_BYTES
            status = lib.sipral_media_poll_recording(self.handle, packet, far_end)
            if status != lib.SIPRAL_STATUS_OK or packet.len == 0:
                return
            self._send(packet, sockets[1] if far_end[0] else sockets[0])

    def rebind(self, sock: socket_module.socket) -> None:
        """Switch media to ``sock`` and close the old socket. Thread-safe."""
        sock.setblocking(False)
        with self._socket_lock:
            old = self._socket
            try:
                self._selector.unregister(old)
            except (KeyError, ValueError, OSError):
                pass
            self._selector.register(sock, selectors.EVENT_READ)
            self._socket = sock
            self.local_address = _format_address(*sock.getsockname())
        old.close()

    def close(self) -> None:
        """Stop the thread, release the handle, close the sockets. Normally
        called by :meth:`sipral.call.Call.close`."""
        if self._closed.is_set():
            return
        self._closed.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)
        lib.sipral_media_release(self.handle)
        self._selector.close()
        self._socket.close()
        if self._text_socket is not None:
            self.stack._close_socket(self._text_socket)
        self.detach_recording()

    # -- the frame-rate thread --------------------------------------------

    def _put_frame(self, pcm: bytes) -> None:
        loop = self.stack._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.frames.put_nowait, pcm)
        else:
            self.frames.put_nowait(pcm)

    def _drain_receive(self) -> None:
        out_arrival = ffi.new("uint32_t *")
        while True:
            with self._socket_lock:
                events = self._selector.select(0)
                if not events:
                    return
                try:
                    data, from_address = self._socket.recvfrom(2048)
                except (BlockingIOError, OSError):
                    return
            self.remote_address = _format_address(*from_address)
            from_text = self.remote_address.encode("utf-8")
            lib.sipral_media_receive(
                self.handle,
                data,
                len(data),
                from_text,
                len(from_text),
                self.stack.now_ms(),
                out_arrival,
            )

    def _drain_packets(self, poll, sock: socket_module.socket | None = None) -> None:
        packet = ffi.new("sipral_media_packet_t *")
        data = ffi.new(f"uint8_t[{_PACKET_BYTES}]")
        destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        while True:
            packet.size = ffi.sizeof("sipral_media_packet_t")
            packet.data = data
            packet.capacity = _PACKET_BYTES
            packet.destination = destination
            packet.destination_capacity = _ADDRESS_BYTES
            status = poll(packet)
            if status != lib.SIPRAL_STATUS_OK or packet.len == 0:
                return
            self._send(packet, sock)

    def _send(self, packet, sock: socket_module.socket | None = None) -> None:
        """Send one packet from this call's socket (or ``sock``), or on the
        TURN connection when marked TCP/TLS."""
        payload = bytes(ffi.buffer(packet.data, packet.len))
        if sock is None and packet.protocol in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS):
            self.stack.write_turn(self.local_address, payload)
            return
        text = ffi.string(packet.destination, packet.destination_len).decode("utf-8")
        host, port = _parse_address(text)
        try:
            (sock or self._socket).sendto(payload, (host, port))
        except OSError:
            pass

    def _capture_once(self, samples) -> None:
        """Capture one frame; yields at most one packet, so no drain loop."""
        packet = ffi.new("sipral_media_packet_t *")
        data = ffi.new(f"uint8_t[{_PACKET_BYTES}]")
        destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        packet.size = ffi.sizeof("sipral_media_packet_t")
        packet.data = data
        packet.capacity = _PACKET_BYTES
        packet.destination = destination
        packet.destination_capacity = _ADDRESS_BYTES
        status = lib.sipral_media_capture(
            self.handle, self.stack.now_ms(), samples, self.frame_samples, packet
        )
        if status != lib.SIPRAL_STATUS_OK or packet.len == 0:
            return
        self._send(packet)

    def _next_chunk(self) -> bytes:
        needed = self.frame_samples * 2
        while len(self._pending) < needed:
            try:
                self._pending += self._to_send.get_nowait()
            except queue.Empty:
                return self._silence
        chunk = bytes(self._pending[:needed])
        del self._pending[:needed]
        return chunk

    def _run(self) -> None:
        out_written = ffi.new("size_t *")
        out_source = ffi.new("uint32_t *")
        due = time.monotonic()
        while not self._closed.is_set():
            self._drain_receive()

            if self._active:
                status = lib.SIPRAL_STATUS_OK
                # In device mode the engine handles frames; RTCP and DTMF
                # still go out below.
                if not self.pumped:
                    with self._frame_lock:
                        playback = ffi.new(f"int16_t[{self.frame_samples}]")
                        status = lib.sipral_media_playback(
                            self.handle, playback, self.frame_samples, out_written, out_source
                        )
                        if status == lib.SIPRAL_STATUS_OK and out_written[0] > 0:
                            self._put_frame(bytes(ffi.buffer(playback, out_written[0] * 2)))

                        chunk = self._next_chunk()
                        capture_in = ffi.new(f"int16_t[{self.frame_samples}]")
                        ffi.buffer(capture_in)[: len(chunk)] = chunk
                        self._capture_once(capture_in)
                self._drain_packets(
                    lambda packet: lib.sipral_media_poll_rtcp(
                        self.handle, self.stack.now_ms(), packet
                    )
                )
                self._drain_packets(
                    lambda packet: lib.sipral_media_poll_transmit(
                        self.handle, self.stack.now_ms(), packet
                    )
                )
                self._carry_text()
                self._carry_recording()
                if status not in (lib.SIPRAL_STATUS_OK, lib.SIPRAL_STATUS_BUSY):
                    self._active = False

            # A fixed schedule, not a sleep per frame: oversleeping would
            # send fewer frames than the far end expects.
            due += self._frame_seconds
            remaining = due - time.monotonic()
            if remaining > 0:
                self._closed.wait(remaining)
            else:
                due = time.monotonic()
