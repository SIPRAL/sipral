# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Media``: one call's audio, paced at its own frame rate.

A call's media has a handle of its own and never takes the stack's lock
(`docs/08-ffi.md`, "A call's media has a handle of its own"), so it runs on
a thread of its own too: this is the one place in the package where audio
crosses as `bytes`/`memoryview`, paced by `sipral_media_info_t::frame_ms`
rather than by whatever rate the application happens to call in at.
"""

from __future__ import annotations

import asyncio
import queue
import selectors
import socket as socket_module
import threading
import time
from typing import TYPE_CHECKING

from ._sipral_cffi import ffi, lib
from .errors import call as _call

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
    """`sipral_call_media`, and the four calls that carry the packets.

    Not built directly: :class:`sipral.call.Call` mints one from its own
    `SIPRAL_EVENT_KIND_MEDIA_STARTED` and hands it over as ``call.media``.
    """

    def __init__(
        self,
        stack: "Stack",
        call_handle: int,
        sock: socket_module.socket,
    ) -> None:
        self.stack = stack
        self.call_handle = call_handle
        self._socket = sock
        self._socket.setblocking(False)
        #: The socket's own `host:port`, which names its connection to a
        #: TURN server reached over TCP or TLS (:meth:`Stack.write_turn`).
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

        #: Where the last datagram this call's media received came from --
        #: the address `sipral_stack_poll_farewell`'s goodbye is sent to,
        #: since nothing in this ABI hands that back as a struct member
        #: (media is described in SDP, not carried as an address of its
        #: own). `None` until at least one packet has arrived.
        self.remote_address: str | None = None

        #: Decoded 16-bit mono PCM, one frame per item, on the stack's
        #: asyncio loop when one was given.
        self.frames: asyncio.Queue[bytes] = asyncio.Queue()
        self._to_send: queue.Queue[bytes] = queue.Queue()
        self._pending = bytearray()
        self._active = True
        self._closed = threading.Event()

        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ)

        self._thread = threading.Thread(
            target=self._run, name="sipral-media", daemon=True
        )
        self._thread.start()

    def send_to(self, payload: bytes, address: str) -> None:
        """Write ``payload`` straight to this call's own RTP socket.

        Used by :class:`sipral.stack.Stack` to send the RTCP BYE
        `sipral_stack_poll_farewell` hands back once the signalling that
        owned it has already ended; nothing about ordinary audio goes
        through this, which is what :meth:`send_audio` is for.
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
        }

    def statistics(self) -> dict[str, object]:
        """`sipral_media_statistics`, as a plain `dict`.

        ``frames_underrun`` counts frames the earpiece played as nothing
        because the jitter buffer had run dry while the far end was still
        sending; ``loss_rate``, ``score`` and ``suffering`` take them in.
        """
        out = ffi.new("sipral_stream_stats_t *")
        out.size = ffi.sizeof("sipral_stream_stats_t")
        _call(
            lambda: lib.sipral_media_statistics(self.handle, self.stack.now_ms(), out),
            "sipral_media_statistics",
        )
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
        }

    def path_candidates(self) -> list[dict[str, object]]:
        """Every path this call's ICE agent tried -- the candidate pairs its
        checklist held, then the relays it held -- and what became of each
        (`sipral_media_path_candidate_count`/`_at`; D5's transport and NAT
        half, `docs/05-media.md`), each as a plain `dict`. Empty for a call
        not using ICE."""
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

    def send_audio(self, pcm: bytes | memoryview) -> None:
        """Queue 16-bit mono PCM to go out, one frame at a time.

        Cut to whatever :attr:`frame_samples` this call negotiated as it is
        sent, not as it is queued: a chunk shorter or longer than one frame
        is accepted here and split across as many capture calls as it
        takes. Thread-safe -- called from whatever thread the application
        runs its own audio loop or voice-agent callback on, not from
        :attr:`stack`'s poll thread.
        """
        self._to_send.put(bytes(pcm))

    def close(self) -> None:
        """Stop the frame-rate thread, `sipral_media_release`, close the
        socket. Called by :meth:`sipral.call.Call.close`, not usually by
        an application directly."""
        if self._closed.is_set():
            return
        self._closed.set()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)
        lib.sipral_media_release(self.handle)
        self._selector.close()
        self._socket.close()

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

    def _drain_packets(self, poll) -> None:
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
            self._send(packet)

    def _send(self, packet) -> None:
        """One packet out where it says: a datagram from this call's
        socket, or -- marked TCP or TLS -- bytes on the socket's connection
        to the TURN server, which the stack holds."""
        payload = bytes(ffi.buffer(packet.data, packet.len))
        if packet.protocol in (lib.SIPRAL_TRANSPORT_TCP, lib.SIPRAL_TRANSPORT_TLS):
            self.stack.write_turn(self.local_address, payload)
            return
        text = ffi.string(packet.destination, packet.destination_len).decode("utf-8")
        host, port = _parse_address(text)
        try:
            self._socket.sendto(payload, (host, port))
        except OSError:
            pass

    def _capture_once(self, samples) -> None:
        """One `sipral_media_capture` call, not a drain: it consumes one
        frame of input and produces at most one packet, unlike
        `poll_rtcp`/`poll_transmit`, which may have several queued."""
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
        playback = ffi.new(f"int16_t[{self.frame_samples}]")
        while not self._closed.is_set():
            started = time.monotonic()
            self._drain_receive()

            if self._active:
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
                if status not in (lib.SIPRAL_STATUS_OK, lib.SIPRAL_STATUS_BUSY):
                    self._active = False

            elapsed = time.monotonic() - started
            remaining = self._frame_seconds - elapsed
            if remaining > 0:
                self._closed.wait(remaining)
