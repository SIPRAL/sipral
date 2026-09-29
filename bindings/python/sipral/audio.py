# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""``Audio``: the library's own audio engine, for a stack in device mode.

A :class:`sipral.stack.Stack` created with ``audio=AudioMode.DEVICE`` -- the
default wherever :func:`sipral.features` has ``Feature.AUDIO_DEVICE`` --
opens the platform's microphone and loudspeaker itself and pumps every call
through them (`docs/08-ffi.md`, "The built-in audio engine"). This is what
the application still decides: which device plays which role, how loud, what
is muted, when the devices are open, and what rings. Everything here is
``stack.audio``; on a stack in application mode each method raises
:class:`sipral.errors.SipralError` with ``SIPRAL_STATUS_WRONG_STATE``.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from ._sipral_cffi import ffi, lib
from .enums import AudioDirection
from .errors import call as _call
from .errors import check

if TYPE_CHECKING:
    from .stack import Stack

__all__ = ["Audio", "AudioDevice", "AudioInfo", "UNITY_GAIN"]

#: `sipral_audio_set_gain`'s fixed-point unity: 256 steps is a ratio of 1.
_GAIN_STEPS = 256

#: A gain of one: what every direction starts at.
UNITY_GAIN = 1.0

#: The most a gain goes up to, four times unity; more is taken as this.
_GAIN_MOST = 4.0


@dataclasses.dataclass(frozen=True)
class AudioDevice:
    """One device, as `sipral_audio_device_at` lists it.

    ``id`` is the engine's name for it: stable across refreshes, never
    reused, never zero, and what :meth:`Audio.select` takes. A device that
    was unplugged keeps its row with ``present`` false, so a selection saved
    against it still names something and comes back when it does.
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
        """Whether it captures: what ``AudioRole.MICROPHONE`` needs."""
        return self.input_channels > 0

    @property
    def is_speaker(self) -> bool:
        """Whether it plays: what the speaker and the ringer need."""
        return self.output_channels > 0


@dataclasses.dataclass(frozen=True)
class AudioInfo:
    """What the engine is doing, as `sipral_audio_info` says.

    ``system_echo_cancellation`` is whether the platform's own processing
    sits behind the microphone -- the voice-processing unit on Apple's
    platforms, a Windows communications stream (which cancels only where
    the endpoint has processing of its own) -- and ``render_delay_ms`` is
    the loudspeaker-to-microphone delay the devices report, which the engine
    hands every call for a canceller attached to it. The three device ids
    are ``None`` while that role is not open.
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
    """``stack.audio``: devices, roles, gain, mute, the meter, activation and
    the ring, over the `sipral_audio_*` entry points.

    Every method is safe from any thread; none waits on the stack's poll.
    A platform call that does not answer within the stack's
    ``audio_probe_ms`` raises ``SIPRAL_STATUS_DEVICE_TIMED_OUT`` instead of
    hanging the caller.
    """

    def __init__(self, stack: "Stack") -> None:
        self._stack = stack

    @property
    def _handle(self) -> int:
        return self._stack.handle

    # -- the list ----------------------------------------------------------

    def refresh(self) -> list[AudioDevice]:
        """Ask the platform again, and return the list as it now is.

        The engine refreshes by itself when the platform announces a device
        arriving or leaving (and says so with
        `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`), so this is for a settings
        screen opening, not for polling.
        """
        count = ffi.new("size_t *")
        _call(lambda: lib.sipral_audio_refresh(self._handle, count), "sipral_audio_refresh")
        return self.devices()

    def devices(self) -> list[AudioDevice]:
        """Every device the engine has seen, present or not, as last listed
        -- asking the platform first when nothing has been listed yet."""
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
            name=ffi.buffer(name, int(needed[0]))[:].decode("utf-8", "replace"),
            input_channels=int(device.input_channels),
            output_channels=int(device.output_channels),
            default_input=bool(device.default_input),
            default_output=bool(device.default_output),
            present=bool(device.present),
        )

    # -- roles -------------------------------------------------------------

    def select(self, role: int, device: int | AudioDevice | None) -> None:
        """Put ``role`` (an :class:`sipral.enums.AudioRole`) on ``device``,
        or back on the system's route with ``None``.

        Refused before any platform call: ``SIPRAL_STATUS_NO_SUCH_DEVICE`` for
        an id the list never held, ``SIPRAL_STATUS_DEVICE_UNUSABLE`` for a
        device with no channels in the role's direction or one not plugged
        in, ``SIPRAL_STATUS_NOT_SUPPORTED`` where the platform cannot put the
        role on a device of its own (macOS runs the microphone and the
        loudspeaker as one unit, so there only the speaker is chosen). While
        the devices are open the role moves at once, keeping its direction's
        gain and mute. A chosen device that is later unplugged stays the
        choice: the role runs on the system's route meanwhile and goes back
        when it returns.
        """
        device_id = device.id if isinstance(device, AudioDevice) else (device or 0)
        _call(
            lambda: lib.sipral_audio_select(self._handle, int(role), device_id),
            "sipral_audio_select",
        )

    def selection(self, role: int) -> tuple[int | None, int | None]:
        """``(chosen, running)`` for ``role``: the id :meth:`select` was given
        (``None`` for the system's route) and the id of the device the role
        is open on (``None`` while it is not open). They differ while a
        chosen device is unplugged."""
        selected = ffi.new("uint32_t *")
        running = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_audio_selection(self._handle, int(role), selected, running),
            "sipral_audio_selection",
        )
        return (int(selected[0]) or None, int(running[0]) or None)

    # -- gain, mute and the meter -----------------------------------------

    def set_gain(self, direction: int, gain: float) -> None:
        """Set ``direction``'s gain as a ratio: ``1.0`` is unity, ``0.5``
        halves, ``2.0`` doubles, anything above ``4.0`` is ``4.0``. The input
        gain is the microphone gain, the output gain the volume. Applied to
        the call's audio rather than to the operating system's control, and
        kept across every device change."""
        if gain < 0:
            raise ValueError(f"a gain is a ratio of zero or more, not {gain}")
        steps = round(min(gain, _GAIN_MOST) * _GAIN_STEPS)
        _call(
            lambda: lib.sipral_audio_set_gain(self._handle, int(direction), steps),
            "sipral_audio_set_gain",
        )

    def gain(self, direction: int) -> float:
        """``direction``'s gain, as the ratio :meth:`set_gain` takes."""
        out = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_audio_gain(self._handle, int(direction), out),
            "sipral_audio_gain",
        )
        return int(out[0]) / _GAIN_STEPS

    def set_muted(self, direction: int, muted: bool) -> None:
        """Mute ``direction`` or unmute it, kept across every device change. A
        muted microphone still sends silence, so the far end hears a stream
        rather than a gap."""
        _call(
            lambda: lib.sipral_audio_set_muted(self._handle, int(direction), int(bool(muted))),
            "sipral_audio_set_muted",
        )

    def muted(self, direction: int) -> bool:
        """Whether ``direction`` is muted."""
        out = ffi.new("uint32_t *")
        _call(
            lambda: lib.sipral_audio_muted(self._handle, int(direction), out),
            "sipral_audio_muted",
        )
        return bool(out[0])

    def level(self, direction: int) -> int:
        """The meter: the loudest sample of the last tenth of a second in
        ``direction``, 0 to 32767, held long enough that a bar drawn from it
        neither flickers nor sticks. Cheap enough for a window's timer; zero
        while nothing is open."""
        out = ffi.new("uint32_t *")
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
        """Open the devices and start the pump now, whatever the calls are
        doing. Under ``AudioActivation.MANUAL`` this is the only thing that
        does -- what CallKit's ``didActivate`` and a telecom framework's audio
        focus are for; under automatic activation it opens them early. A
        direction that could not be opened raises, and the engine is active
        all the same, silent in that direction (:meth:`info` says which)."""
        _call(lambda: lib.sipral_audio_activate(self._handle), "sipral_audio_activate")

    def deactivate(self) -> None:
        """Close the devices and stop the pump. The calls stay attached and
        get their audio back on the next :meth:`activate`."""
        _call(lambda: lib.sipral_audio_deactivate(self._handle), "sipral_audio_deactivate")

    def info(self) -> AudioInfo:
        """`sipral_audio_info`."""
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
        """Play a tone -- 16-bit mono PCM at ``sample_rate`` -- on the ringer's
        device (the loudspeaker when the ringer is on none of its own) until
        :meth:`stop_ringing`, or once through with ``looped=False``. The
        samples are copied. Under automatic activation a ring opens the
        devices."""
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

