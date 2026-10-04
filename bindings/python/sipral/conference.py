# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``LocalConference``: any number of this stack's calls, mixed here.

Every member hears everybody but itself, each call on its own codec and
rate; this end is a member too unless it was made without
(`docs/08-ffi.md`, "A local conference"). A call added stops carrying its
own frames -- its :class:`sipral.media.Media` goes on reading the socket and
sending RTCP -- and the conference carries them instead:

- on a stack in device mode the library's audio engine does it, and every
  packet leaves through the stack's own transmit path, from the member's
  own socket;
- in application mode a thread of this class's own ticks every twenty
  milliseconds: :meth:`send_audio` is this end's microphone, :attr:`frames`
  what it hears, and the packets go out from each member's own socket.

``SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`` arrives on ``stack.events``;
:attr:`sipral.events.Event.local_conference` reads it.
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
    """`sipral_local_conference_create`, and what a conference is asked.

    ``max_members`` counts this end; ``local`` says whether this end takes
    part, and ``sample_rate`` is the rate of its frames -- 8, 16, 32 or
    48 kHz -- in application mode. A rate the conference cannot mix, or more
    than 1024 members, raises :class:`sipral.errors.SipralError` with
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
        #: The conference's handle, which is also this end's name as a
        #: member: in :meth:`members`, :meth:`talkers` and every event.
        self.handle = int(out[0])
        info = self.info()
        #: Whether this end takes part.
        self.local = info["local"]
        self.sample_rate = info["sample_rate"]
        self.frame_samples = info["frame_samples"]
        #: What this end hears, one frame of 16-bit mono PCM per item, in
        #: application mode.
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
        """`sipral_local_conference_add`: ``call`` takes part from the next
        tick, at its own codec's rate. A full conference, a call already in
        one, or a codec it cannot mix raises with
        ``SIPRAL_STATUS_CONFERENCE_REFUSED``."""
        # the call's own thread stops carrying frames before the conference
        # starts, so that no frame is taken twice
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
        """`sipral_local_conference_remove`: ``call`` carries its own frames
        again from the next tick."""
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
        """Mute or unmute one way of a member -- ``None`` for this end:
        ``AudioDirection.INPUT`` is what it says, ``OUTPUT`` what it hears."""
        _call(
            lambda: lib.sipral_local_conference_set_muted(
                self.handle, self._member(member), int(direction), int(muted)
            ),
            "sipral_local_conference_set_muted",
        )

    def set_gain(self, member: "Call | None", direction: AudioDirection, gain: int) -> None:
        """The level of one way of a member, in the audio engine's steps:
        256 is unity, 1024 four times."""
        _call(
            lambda: lib.sipral_local_conference_set_gain(
                self.handle, self._member(member), int(direction), gain
            ),
            "sipral_local_conference_set_gain",
        )

    # -- what it is --------------------------------------------------------

    def info(self) -> dict[str, int | bool]:
        """`sipral_local_conference_info`."""
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
        """Every member, this end first: its handle (a call's, or
        :attr:`handle` for this end), whether it is talking, its mutes and
        its gains."""
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
        """`sipral_local_conference_record_start`: the whole mix, one
        channel, to ``path``; ``format`` a
        :class:`sipral.enums.RecordingFormat`, ``sample_rate`` the file's
        own (zero for the conference's)."""
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
        """`sipral_local_conference_record_stop`: stop, and finish the file."""
        _call(
            lambda: lib.sipral_local_conference_record_stop(self.handle),
            "sipral_local_conference_record_stop",
        )

    # -- this end's audio, in application mode -----------------------------

    def send_audio(self, pcm: bytes | memoryview) -> None:
        """What this end says, 16-bit mono PCM at :attr:`sample_rate`, in any
        length: the conference's thread takes a frame of it every tick."""
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
            # a socket closed by a hangup racing this send: the packet is
            # lost, which the far end's jitter buffer already hides
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
        """`sipral_local_conference_destroy`: every call still in it carries
        its own frames again, a recording running is finished, and the
        handle is spent."""
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
