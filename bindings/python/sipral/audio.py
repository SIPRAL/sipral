# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Audio``: the library's own audio engine, for a stack in device mode.

In device mode the library drives the platform's microphone and loudspeaker
for every call; ``stack.audio`` chooses devices, gain, mute, activation and
the ring. In application mode each method raises
``SIPRAL_STATUS_WRONG_STATE``.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from ._sipral_cffi import ffi, lib
from .enums import AudioDirection
from .errors import call as _call
from .errors import check

if TYPE_CHECKING:
    from .call import Call
    from .stack import Stack

__all__ = ["Audio", "AudioDevice", "AudioInfo", "UNITY_GAIN"]

#: `sipral_audio_set_gain`'s fixed-point unity: 256 steps is a ratio of 1.
_GAIN_STEPS = 256

#: A gain of one: what every direction starts at.
UNITY_GAIN = 1.0

#: Gains above this are clamped to it.
_GAIN_MOST = 4.0


@dataclasses.dataclass(frozen=True)
class AudioDevice:
    """One device, as `sipral_audio_device_at` lists it.

    ``id`` is stable across refreshes, never reused, never zero. An
    unplugged device stays listed with ``present`` false, so a saved
    selection still names it and resumes when it returns.
    """

    id: int
    name: str
    input_channels: int
    output_channels: int
    default_input: bool
    default_output: bool
    present: bool

    @property
    def is_microphone(self) -> bool:
        """Whether it captures."""
        return self.input_channels > 0

    @property
    def is_speaker(self) -> bool:
        """Whether it plays."""
        return self.output_channels > 0


@dataclasses.dataclass(frozen=True)
class AudioInfo:
    """What the engine is doing.

    ``system_echo_cancellation``: the platform's processing is in the
    microphone path (Apple voice processing, a Windows communications
    stream). ``render_delay_ms`` is the reported speaker-to-microphone
    delay. Device ids are ``None`` while a role is not open.
    """

    active: bool
    system_echo_cancellation: bool
    render_delay_ms: int
    microphone_rate_hz: int
    speaker_rate_hz: int
    microphone: int | None
    speaker: int | None
    ringer: int | None


class Audio:
    """``stack.audio``: devices, roles, gain, mute, meter, activation, ring.

    Safe from any thread. A platform call silent past ``audio_probe_ms``
    raises ``SIPRAL_STATUS_DEVICE_TIMED_OUT`` instead of hanging.
    """

    def __init__(self, stack: "Stack") -> None:
        self._stack = stack

    @property
    def _handle(self) -> int:
        return self._stack.handle

    # -- the list ----------------------------------------------------------

    def refresh(self) -> list[AudioDevice]:
        """Re-list devices from the platform.

        The engine already refreshes on platform notifications, so this is
        for a settings screen opening, not for polling.
        """
        count = ffi.new("size_t *")
        _call(lambda: lib.sipral_audio_refresh(self._handle, count), "sipral_audio_refresh")
        return self.devices()

    def devices(self) -> list[AudioDevice]:
        """Every device seen, present or not; lists them first if needed."""
        count = ffi.new("size_t *")
        _call(
            lambda: lib.sipral_audio_device_count(self._handle, count),
            "sipral_audio_device_count",
        )
        if count[0] == 0:
            _call(lambda: lib.sipral_audio_refresh(self._handle, count), "sipral_audio_refresh")
        listed = []
        for index in range(int(count[0])):
            listed.append(self._device_at(index))
        return listed

    def _device_at(self, index: int) -> AudioDevice:
        device = ffi.new("sipral_audio_device_t *")
        device.size = ffi.sizeof("sipral_audio_device_t")
        needed = ffi.new("size_t *")
        capacity = 128
        while True:
            name = ffi.new(f"char[{capacity}]")
            status = lib.sipral_audio_device_at(
                self._handle, index, device, name, capacity, needed
            )
            if status == lib.SIPRAL_STATUS_BUFFER_TOO_SMALL:
                capacity = int(needed[0])
                continue
            break
        check(status, "sipral_audio_device_at")
        return AudioDevice(
            id=int(device.id),
            # The length counts the trailing NUL.
            name=ffi.buffer(name, int(needed[0]) - 1)[:].decode("utf-8", "replace"),
            input_channels=int(device.input_channels),
            output_channels=int(device.output_channels),
            default_input=bool(device.default_input),
            default_output=bool(device.default_output),
            present=bool(device.present),
        )

    # -- roles -------------------------------------------------------------

    def select(self, role: int, device: int | AudioDevice | None) -> None:
        """Put ``role`` (:class:`sipral.enums.AudioRole`) on ``device``, or on
        the system route with ``None``.

        Raises ``SIPRAL_STATUS_NO_SUCH_DEVICE`` for an unknown id,
        ``SIPRAL_STATUS_DEVICE_UNUSABLE`` for a device without channels in
        that direction or unplugged, ``SIPRAL_STATUS_NOT_SUPPORTED`` where
        the platform owns the route (iOS microphone and ringer). On macOS the
        system default input is not moved. Open devices switch at once,
        keeping gain and mute. If the chosen device is unplugged, the role
        uses the system route until it returns.
        """
        device_id = device.id if isinstance(device, AudioDevice) else (device or 0)
        _call(
            lambda: lib.sipral_audio_select(self._handle, int(role), device_id),
            "sipral_audio_select",
        )

    def selection(self, role: int) -> tuple[int | None, int | None]:
        """``(chosen, running)`` device ids for ``role``; ``None`` for the
        system route or not open. They differ while the chosen one is
        unplugged."""
        selected = ffi.new("uint32_t *")
        running = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_audio_selection(self._handle, int(role), selected, running),
            "sipral_audio_selection",
        )
        return (int(selected[0]) or None, int(running[0]) or None)

    # -- gain, mute and the meter -----------------------------------------

    def set_gain(self, direction: int, gain: float, *, call: "Call | None" = None) -> None:
        """Set ``direction``'s gain as a ratio (``1.0`` unity, clamped at
        ``4.0``). Applied in the engine, not the OS mixer, and kept across
        device changes.

        With ``call``, that call's own gain on top: kept through hold and
        local conferences, gone when the call ends;
        ``SIPRAL_STATUS_WRONG_STATE`` outside its media's lifetime."""
        if gain < 0:
            raise ValueError(f"a gain is a ratio of zero or more, not {gain}")
        steps = round(min(gain, _GAIN_MOST) * _GAIN_STEPS)
        if call is not None:
            _call(
                lambda: lib.sipral_audio_call_set_gain(self._handle, call.handle, int(direction), steps),
                "sipral_audio_call_set_gain",
            )
            return
        _call(
            lambda: lib.sipral_audio_set_gain(self._handle, int(direction), steps),
            "sipral_audio_set_gain",
        )

    def gain(self, direction: int, *, call: "Call | None" = None) -> float:
        """``direction``'s gain (``call``'s own, with one) as a ratio."""
        out = ffi.new("uint32_t *")
        if call is not None:
            _call(
                lambda: lib.sipral_audio_call_gain(self._handle, call.handle, int(direction), out),
                "sipral_audio_call_gain",
            )
        else:
            _call(
                lambda: lib.sipral_audio_gain(self._handle, int(direction), out),
                "sipral_audio_gain",
            )
        return int(out[0]) / _GAIN_STEPS

    def set_muted(self, direction: int, muted: bool, *, call: "Call | None" = None) -> None:
        """Mute or unmute ``direction``, kept across device changes. A muted
        microphone still sends silence, not a gap. With ``call``, only that
        call."""
        if call is not None:
            _call(
                lambda: lib.sipral_audio_call_set_muted(
                    self._handle, call.handle, int(direction), int(bool(muted))
                ),
                "sipral_audio_call_set_muted",
            )
            return
        _call(
            lambda: lib.sipral_audio_set_muted(self._handle, int(direction), int(bool(muted))),
            "sipral_audio_set_muted",
        )

    def muted(self, direction: int, *, call: "Call | None" = None) -> bool:
        """Whether ``direction`` is muted (for ``call`` alone, with one)."""
        out = ffi.new("uint32_t *")
        if call is not None:
            _call(
                lambda: lib.sipral_audio_call_muted(self._handle, call.handle, int(direction), out),
                "sipral_audio_call_muted",
            )
        else:
            _call(
                lambda: lib.sipral_audio_muted(self._handle, int(direction), out),
                "sipral_audio_muted",
            )
        return bool(out[0])

    def set_system_echo_cancellation(self, on: bool) -> None:
        """Toggle the platform's echo cancellation at runtime. Open devices
        reopen at once on the same devices, keeping gain and mute; calls
        bridge the short gap. :meth:`info` reports what the platform did.
        ``SIPRAL_STATUS_WRONG_STATE`` in application mode."""
        toggle = lib.SIPRAL_TOGGLE_ON if on else lib.SIPRAL_TOGGLE_OFF
        _call(
            lambda: lib.sipral_audio_set_system_echo_cancellation(self._handle, toggle),
            "sipral_audio_set_system_echo_cancellation",
        )

    def level(self, direction: int, *, call: "Call | None" = None) -> int:
        """Peak of the last 100 ms in ``direction``, 0 to 32767, smoothed for
        a level bar; zero while closed. Cheap enough for a UI timer. With
        ``call``, that call's level after its gain and mute."""
        out = ffi.new("uint32_t *")
        if call is not None:
            _call(
                lambda: lib.sipral_audio_call_level(self._handle, call.handle, int(direction), out),
                "sipral_audio_call_level",
            )
        else:
            _call(
                lambda: lib.sipral_audio_level(self._handle, int(direction), out),
                "sipral_audio_level",
            )
        return int(out[0])

    @property
    def microphone_gain(self) -> float:
        """The input direction's gain."""
        return self.gain(AudioDirection.INPUT)

    @microphone_gain.setter
    def microphone_gain(self, gain: float) -> None:
        self.set_gain(AudioDirection.INPUT, gain)

    @property
    def volume(self) -> float:
        """The output direction's gain."""
        return self.gain(AudioDirection.OUTPUT)

    @volume.setter
    def volume(self, gain: float) -> None:
        self.set_gain(AudioDirection.OUTPUT, gain)

    # -- activation --------------------------------------------------------

    def activate(self) -> None:
        """Open the devices now. Under ``AudioActivation.MANUAL`` only this
        does (for CallKit's ``didActivate`` or audio focus); otherwise it
        opens them early. A direction that fails raises, but the engine stays
        active, silent there (see :meth:`info`)."""
        _call(lambda: lib.sipral_audio_activate(self._handle), "sipral_audio_activate")

    def deactivate(self) -> None:
        """Close the devices; calls resume audio on the next :meth:`activate`."""
        _call(lambda: lib.sipral_audio_deactivate(self._handle), "sipral_audio_deactivate")

    def info(self) -> AudioInfo:
        """The engine's current state."""
        out = ffi.new("sipral_audio_info_t *")
        out.size = ffi.sizeof("sipral_audio_info_t")
        _call(lambda: lib.sipral_audio_info(self._handle, out), "sipral_audio_info")
        return AudioInfo(
            active=bool(out.active),
            system_echo_cancellation=bool(out.system_echo_cancellation),
            render_delay_ms=int(out.render_delay_ms),
            microphone_rate_hz=int(out.microphone_rate_hz),
            speaker_rate_hz=int(out.speaker_rate_hz),
            microphone=int(out.microphone) or None,
            speaker=int(out.speaker) or None,
            ringer=int(out.ringer) or None,
        )

    # -- the ring ----------------------------------------------------------

    def ring(self, pcm: bytes | memoryview, sample_rate: int, *, looped: bool = True) -> None:
        """Play 16-bit mono PCM on the ringer (or loudspeaker) until
        :meth:`stop_ringing`, or once with ``looped=False``. Samples are
        copied. Under automatic activation this opens the devices."""
        raw = bytes(pcm)
        if len(raw) % 2:
            raise ValueError("a ring tone is 16-bit samples: an even number of bytes")
        count = len(raw) // 2
        samples = ffi.new(f"int16_t[{max(count, 1)}]")
        ffi.buffer(samples)[: len(raw)] = raw
        _call(
            lambda: lib.sipral_audio_ring(self._handle, samples, count, sample_rate, int(looped)),
            "sipral_audio_ring",
        )

    def stop_ringing(self) -> None:
        """Stop the tone :meth:`ring` started."""
        _call(lambda: lib.sipral_audio_stop_ringing(self._handle), "sipral_audio_stop_ringing")

