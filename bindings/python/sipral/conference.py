# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``LocalConference``: any number of this stack's calls, mixed here.

Each member hears everyone but itself, each call on its own codec and rate;
this end is a member unless made without. A member's frames are carried by
the conference (its :class:`sipral.media.Media` still reads the socket and
sends RTCP): by the audio engine in device mode, or in application mode by
this class's own 20 ms thread, where :meth:`send_audio` is this end's
microphone and :attr:`frames` what it hears.

Changes arrive as ``SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED``.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from typing import TYPE_CHECKING

from ._sipral_cffi import ffi, lib
from .enums import AudioDirection, AudioMode
from .errors import call as _call

if TYPE_CHECKING:
    from .call import Call
    from .stack import Stack

__all__ = ["LocalConference"]

_PACKET_BYTES = lib.SIPRAL_MEDIA_PACKET_BYTES
_ADDRESS_BYTES = 128
_TICK_SECONDS = 0.02


class LocalConference:
    """A local mixing conference.

    ``max_members`` counts this end; ``local`` says whether this end takes
    part; ``sample_rate`` (8, 16, 32 or 48 kHz) is its frame rate in
    application mode. Other rates, or more than 1024 members, raise
    ``SIPRAL_STATUS_CONFERENCE_REFUSED``.
    """

    def __init__(
        self,
        stack: "Stack",
        *,
        max_members: int = 16,
        local: bool = True,
        sample_rate: int = 16000,
    ) -> None:
        self.stack = stack
        config = ffi.new("sipral_local_conference_config_t *")
        config.size = ffi.sizeof("sipral_local_conference_config_t")
        config.max_members = max_members
        config.local = 0 if local else lib.SIPRAL_TOGGLE_OFF
        config.sample_rate = sample_rate
        out = ffi.new("sipral_handle_t *")
        _call(
            lambda: lib.sipral_local_conference_create(stack.handle, config, out),
            "sipral_local_conference_create",
        )
        #: The conference handle, also this end's member id.
        self.handle = int(out[0])
        info = self.info()
        #: Whether this end takes part.
        self.local = info["local"]
        self.sample_rate = info["sample_rate"]
        self.frame_samples = info["frame_samples"]
        #: What this end hears (16-bit mono frames), in application mode.
        self.frames: asyncio.Queue[bytes] = asyncio.Queue()
        self._to_send: queue.Queue[bytes] = queue.Queue()
        self._pending = bytearray()
        self._members: dict[int, "Call"] = {}
        self._closed = threading.Event()
        self._thread: threading.Thread | None = None
        if stack.audio_mode != AudioMode.DEVICE:
            self._thread = threading.Thread(
                target=self._run, name="sipral-conference", daemon=True
            )
            self._thread.start()

    # -- members ---------------------------------------------------------

    def add(self, call: "Call") -> None:
        """Add ``call`` from the next tick. A full conference, a call already
        in one, or an unmixable codec raises
        ``SIPRAL_STATUS_CONFERENCE_REFUSED``."""
        # Stop the call's own pump first so no frame is taken twice.
        was = call.media.pumped if call.media is not None else None
        if call.media is not None:
            call.media.pumped = True
        try:
            _call(
                lambda: lib.sipral_local_conference_add(self.handle, call.handle),
                "sipral_local_conference_add",
            )
        except Exception:
            if call.media is not None and was is not None:
                call.media.pumped = was
            raise
        self._members[call.handle] = call

    def remove(self, call: "Call") -> None:
        """Remove ``call``; it pumps its own frames from the next tick."""
        _call(
            lambda: lib.sipral_local_conference_remove(self.handle, call.handle),
            "sipral_local_conference_remove",
        )
        self._members.pop(call.handle, None)
        if call.media is not None:
            call.media.pumped = self.stack.audio_mode == AudioMode.DEVICE

    def _member(self, member: "Call | None") -> int:
        return self.handle if member is None else member.handle

    def set_muted(
        self, member: "Call | None", direction: AudioDirection, muted: bool = True
    ) -> None:
        """Mute a member's ``INPUT`` (what it says) or ``OUTPUT`` (what it
        hears); ``None`` is this end."""
        _call(
            lambda: lib.sipral_local_conference_set_muted(
                self.handle, self._member(member), int(direction), int(muted)
            ),
            "sipral_local_conference_set_muted",
        )

    def set_gain(self, member: "Call | None", direction: AudioDirection, gain: int) -> None:
        """A member's gain in steps: 256 is unity, 1024 the maximum."""
        _call(
            lambda: lib.sipral_local_conference_set_gain(
                self.handle, self._member(member), int(direction), gain
            ),
            "sipral_local_conference_set_gain",
        )

    # -- what it is --------------------------------------------------------

    def info(self) -> dict[str, int | bool]:
        """Counts, rate and recording state."""
        out = ffi.new("sipral_local_conference_info_t *")
        out.size = ffi.sizeof("sipral_local_conference_info_t")
        _call(
            lambda: lib.sipral_local_conference_info(self.handle, out),
            "sipral_local_conference_info",
        )
        return {
            "members": int(out.members),
            "capacity": int(out.capacity),
            "talkers": int(out.talkers),
            "local": bool(out.local),
            "sample_rate": int(out.sample_rate),
            "frame_samples": int(out.frame_samples),
            "recording": bool(out.recording),
            "recorded_ms": int(out.recorded_ms),
            "packets_dropped": int(out.packets_dropped),
        }

    def members(self) -> list[dict[str, int | bool]]:
        """Every member, this end first, with talking, mutes and gains."""
        found = []
        for index in range(self.info()["members"]):
            out = ffi.new("sipral_local_conference_member_t *")
            out.size = ffi.sizeof("sipral_local_conference_member_t")
            _call(
                lambda: lib.sipral_local_conference_member_at(self.handle, index, out),
                "sipral_local_conference_member_at",
            )
            found.append(
                {
                    "member": int(out.member),
                    "talking": bool(out.talking),
                    "muted_input": bool(out.muted_input),
                    "muted_output": bool(out.muted_output),
                    "gain_input": int(out.gain_input),
                    "gain_output": int(out.gain_output),
                }
            )
        return found

    def talkers(self) -> list[int]:
        """Who was talking in the last tick, loudest first, by handle."""
        found = []
        for index in range(self.info()["talkers"]):
            out = ffi.new("sipral_handle_t *")
            status = lib.sipral_local_conference_talker_at(self.handle, index, out)
            if status != lib.SIPRAL_STATUS_OK:
                break
            found.append(int(out[0]))
        return found

    # -- recording ---------------------------------------------------------

    def record(self, path: str, *, format: int = 0, sample_rate: int = 0) -> None:
        """Record the whole mix, mono, to ``path``. ``sample_rate`` 0 for the
        conference's."""
        encoded = path.encode("utf-8")
        options = ffi.new("sipral_recording_options_t *")
        options.size = ffi.sizeof("sipral_recording_options_t")
        options.format = int(format)
        options.sample_rate = sample_rate
        _call(
            lambda: lib.sipral_local_conference_record_start(
                self.handle, encoded, len(encoded), options
            ),
            "sipral_local_conference_record_start",
        )

    def stop_recording(self) -> None:
        """Stop recording and finish the file."""
        _call(
            lambda: lib.sipral_local_conference_record_stop(self.handle),
            "sipral_local_conference_record_stop",
        )

    # -- this end's audio, in application mode -----------------------------

    def send_audio(self, pcm: bytes | memoryview) -> None:
        """Queue this end's 16-bit mono PCM at :attr:`sample_rate`, any length."""
        self._to_send.put(bytes(pcm))

    def _next_chunk(self) -> bytes:
        needed = self.frame_samples * 2
        while len(self._pending) < needed:
            try:
                self._pending += self._to_send.get_nowait()
            except queue.Empty:
                return bytes(needed)
        chunk = bytes(self._pending[:needed])
        del self._pending[:needed]
        return chunk

    def _put_frame(self, pcm: bytes) -> None:
        loop = self.stack._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(self.frames.put_nowait, pcm)
        else:
            self.frames.put_nowait(pcm)

    def _send(self, call_handle: int, packet) -> None:
        call = self._members.get(call_handle) or self.stack.call_for(call_handle)
        if call is None or call.media is None:
            return
        payload = bytes(ffi.buffer(packet.data, packet.len))
        destination = ffi.string(packet.destination, packet.destination_len).decode("utf-8")
        try:
            call.media.send_to(payload, destination)
        except OSError:
            # Socket closed by a racing hangup: one lost packet.
            pass

    def _run(self) -> None:
        mic = ffi.new(f"int16_t[{self.frame_samples}]")
        speaker = ffi.new(f"int16_t[{self.frame_samples}]")
        written = ffi.new("size_t *")
        out_call = ffi.new("sipral_handle_t *")
        packet = ffi.new("sipral_media_packet_t *")
        data = ffi.new(f"uint8_t[{_PACKET_BYTES}]")
        destination = ffi.new(f"char[{_ADDRESS_BYTES}]")
        next_tick = time.monotonic()
        while not self._closed.is_set():
            chunk = self._next_chunk()
            ffi.buffer(mic)[: len(chunk)] = chunk
            status = lib.sipral_local_conference_tick(
                self.handle,
                self.stack.now_ms(),
                mic,
                self.frame_samples,
                speaker,
                self.frame_samples,
                written,
            )
            if status != lib.SIPRAL_STATUS_OK:
                return
            if self.local:
                self._put_frame(bytes(ffi.buffer(speaker, written[0] * 2)))
            while True:
                packet.size = ffi.sizeof("sipral_media_packet_t")
                packet.data = data
                packet.capacity = _PACKET_BYTES
                packet.destination = destination
                packet.destination_capacity = _ADDRESS_BYTES
                status = lib.sipral_local_conference_poll_transmit(self.handle, out_call, packet)
                if status != lib.SIPRAL_STATUS_OK or packet.len == 0:
                    break
                self._send(int(out_call[0]), packet)
            next_tick += _TICK_SECONDS
            remaining = next_tick - time.monotonic()
            if remaining > 0:
                self._closed.wait(remaining)
            else:
                next_tick = time.monotonic()

    # -- the end -------------------------------------------------------------

    def close(self) -> None:
        """Destroy: members pump their own frames again, a recording is
        finished."""
        if self._closed.is_set():
            return
        self._closed.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        for call in self._members.values():
            if call.media is not None:
                call.media.pumped = self.stack.audio_mode == AudioMode.DEVICE
        self._members.clear()
        _call(
            lambda: lib.sipral_local_conference_destroy(self.handle),
            "sipral_local_conference_destroy",
        )

    def __enter__(self) -> "LocalConference":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
