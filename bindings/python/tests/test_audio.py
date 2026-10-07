# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The audio engine through ``Stack(audio=...)`` and ``stack.audio``.

Device tests use manual activation so no microphone is opened on the gate
machine. Without a backend (Linux) they check the default is application
mode and device mode is refused.
"""

from __future__ import annotations

import array
import asyncio
import math
import os
import socket
import unittest

from sipral import AudioDevice, SipralError, Stack, features
from sipral._sipral_cffi import ffi, lib
from sipral.enums import (
    AudioActivation,
    AudioDirection,
    AudioMode,
    AudioRole,
    EventKind,
    Feature,
    Status,
)

_HAS_DEVICES = Feature.AUDIO_DEVICE in features()

# A virtual loopback device, used when present so tests stay silent.
QUIET_DEVICE = "BlackHole 2ch"


def quiet_device(devices: list[AudioDevice], role: int) -> AudioDevice | None:
    """The loopback device for ``role`` if present, else None."""
    for device in devices:
        serves = device.is_microphone if role == AudioRole.MICROPHONE else device.is_speaker
        if device.present and device.name == QUIET_DEVICE and serves:
            return device
    return None


class TheQuietDeviceIsChosenWhereTheMachineHasIt(unittest.TestCase):
    def test_every_role_goes_on_it_and_nowhere_new_without_it(self) -> None:
        def device(number: int, name: str, inputs: int, outputs: int, present: bool = True):
            return AudioDevice(number, name, inputs, outputs, False, number == 1, present)

        laptop = [device(1, "MacBook Air Speakers", 0, 2), device(2, "MacBook Air Microphone", 1, 0)]
        roles = (AudioRole.SPEAKER, AudioRole.MICROPHONE, AudioRole.RINGER)
        for role in roles:
            self.assertIsNone(quiet_device(laptop, role))
            self.assertEqual(quiet_device(laptop + [device(3, QUIET_DEVICE, 2, 2)], role).id, 3)
        self.assertIsNone(quiet_device(laptop + [device(3, QUIET_DEVICE, 2, 2, False)], roles[0]))
        self.assertIsNone(quiet_device(laptop + [device(4, "BlackHole 16ch", 16, 16)], roles[0]))


class AStackPicksWhoPumpsItsAudio(unittest.TestCase):
    def test_the_default_is_the_devices_wherever_the_build_can_open_them(self) -> None:
        with Stack() as stack:
            expected = AudioMode.DEVICE if _HAS_DEVICES else AudioMode.APPLICATION
            self.assertEqual(stack.audio_mode, expected)

    def test_application_mode_is_kept_when_asked_for(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            self.assertEqual(stack.audio_mode, AudioMode.APPLICATION)
            with self.assertRaises(SipralError) as raised:
                stack.audio.devices()
            self.assertEqual(raised.exception.status, Status.WRONG_STATE)
            # The reported length counts the trailing NUL.
            self.assertNotIn("\0", str(raised.exception))
            self.assertTrue(str(raised.exception).endswith("pumps its own frames"), str(raised.exception))

    def test_the_echo_cancellation_switch_is_refused_in_application_mode(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            with self.assertRaises(SipralError) as raised:
                stack.audio.set_system_echo_cancellation(False)
            self.assertEqual(raised.exception.status, Status.WRONG_STATE)
            self.assertTrue(stack.settings().system_echo_cancellation)

    @unittest.skipIf(_HAS_DEVICES, "this build has an audio backend")
    def test_device_mode_on_a_build_without_a_backend_is_refused(self) -> None:
        with self.assertRaises(SipralError) as raised:
            Stack(audio=AudioMode.DEVICE)
        self.assertEqual(raised.exception.status, Status.NOT_SUPPORTED)


@unittest.skipUnless(_HAS_DEVICES, "this build has no audio backend for this platform")
class TheDevicesAreTheLibrarys(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = Stack(audio=AudioMode.DEVICE, audio_activation=AudioActivation.MANUAL)
        self.addCleanup(self.stack.close)
        self.audio = self.stack.audio

    def test_every_device_is_listed_with_an_id_that_survives_a_refresh(self) -> None:
        listed = self.audio.devices()
        self.assertTrue(listed, "a machine with an audio backend lists at least one device")
        for device in listed:
            self.assertIsInstance(device, AudioDevice)
            self.assertGreater(device.id, 0)
            self.assertTrue(device.name)
            # The reported length counts the trailing NUL.
            self.assertNotIn("\0", device.name)
            self.assertTrue(device.is_microphone or device.is_speaker, device)
        again = self.audio.refresh()
        self.assertEqual(
            {device.name: device.id for device in listed},
            {device.name: device.id for device in again if device.present},
        )

    def test_the_echo_cancellation_switch_opens_nothing_and_is_read_back(self) -> None:
        self.audio.set_system_echo_cancellation(False)
        self.assertFalse(self.stack.settings().system_echo_cancellation)
        self.assertFalse(self.audio.info().active, "the switch opened the devices")
        self.audio.set_system_echo_cancellation(True)
        self.assertTrue(self.stack.settings().system_echo_cancellation)

    def test_the_speaker_is_chosen_on_its_own_and_read_back(self) -> None:
        speaker = next(device for device in self.audio.devices() if device.is_speaker)
        self.audio.select(AudioRole.SPEAKER, speaker)
        self.assertEqual(self.audio.selection(AudioRole.SPEAKER), (speaker.id, None))
        self.audio.select(AudioRole.SPEAKER, None)
        self.assertEqual(self.audio.selection(AudioRole.SPEAKER), (None, None))

    def test_a_choice_the_device_cannot_serve_is_refused_before_the_platform(self) -> None:
        with self.assertRaises(SipralError) as raised:
            self.audio.select(AudioRole.SPEAKER, 0xFFFF)
        self.assertEqual(raised.exception.status, Status.NO_SUCH_DEVICE)
        microphone_only = [d for d in self.audio.devices() if d.is_microphone and not d.is_speaker]
        if microphone_only:
            with self.assertRaises(SipralError) as raised:
                self.audio.select(AudioRole.SPEAKER, microphone_only[0])
            self.assertEqual(raised.exception.status, Status.DEVICE_UNUSABLE)
        self.assertEqual(self.audio.selection(AudioRole.SPEAKER), (None, None))

    def test_the_microphone_and_the_ringer_are_roles_of_their_own(self) -> None:
        microphone = next(device for device in self.audio.devices() if device.is_microphone)
        speaker = next(device for device in self.audio.devices() if device.is_speaker)
        for role, device in ((AudioRole.MICROPHONE, microphone), (AudioRole.RINGER, speaker)):
            try:
                self.audio.select(role, device)
            except SipralError as refused:
                # iOS: the audio session owns the route.
                self.assertEqual(refused.status, Status.NOT_SUPPORTED)
                continue
            self.assertEqual(self.audio.selection(role), (device.id, None))

    def test_gain_and_mute_belong_to_the_direction(self) -> None:
        self.assertEqual(self.audio.microphone_gain, 1.0)
        self.audio.microphone_gain = 0.5
        self.audio.volume = 2.0
        self.assertEqual(self.audio.gain(AudioDirection.INPUT), 0.5)
        self.assertEqual(self.audio.gain(AudioDirection.OUTPUT), 2.0)
        self.audio.set_gain(AudioDirection.OUTPUT, 10.0)
        self.assertEqual(self.audio.volume, 4.0, "anything above four times unity is four")
        with self.assertRaises(ValueError):
            self.audio.set_gain(AudioDirection.INPUT, -1.0)

        self.assertFalse(self.audio.muted(AudioDirection.INPUT))
        self.audio.set_muted(AudioDirection.INPUT, True)
        self.assertTrue(self.audio.muted(AudioDirection.INPUT))
        self.assertFalse(self.audio.muted(AudioDirection.OUTPUT))

    def test_nothing_is_open_until_activated(self) -> None:
        info = self.audio.info()
        self.assertFalse(info.active)
        self.assertIsNone(info.microphone)
        self.assertIsNone(info.speaker)
        self.assertEqual(self.audio.level(AudioDirection.INPUT), 0)
        self.assertEqual(self.audio.level(AudioDirection.OUTPUT), 0)
        self.audio.deactivate()
        self.assertFalse(self.audio.info().active)

    def test_a_ring_tone_is_whole_samples(self) -> None:
        with self.assertRaises(ValueError):
            self.audio.ring(b"\x00\x01\x02", 8000)
        # Under manual activation a ring opens nothing.
        self.audio.stop_ringing()
        self.assertFalse(self.audio.info().active)


class TheEnginesPacketsLeaveFromTheCallsSocket(unittest.IsolatedAsyncioTestCase):
    """A transmit callback packet leaves from its call's media socket. The
    record is built by hand, so this runs everywhere."""

    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.bob = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close)
        self.far = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.far.bind(("127.0.0.1", 0))
        self.far.settimeout(3)

    async def _close(self) -> None:
        self.alice.close()
        self.bob.close()
        self.far.close()

    async def test_a_packet_the_engine_encoded_goes_out_on_the_calls_socket(self) -> None:
        account = self.alice.add_account("sip:alice@sipral.invalid", registrar_address=self.bob.bind_address)
        self.bob.add_account("sip:bob@sipral.invalid", registrar_address=self.alice.bind_address)
        call = self.alice.place_call(account, f"sip:bob@{self.bob.bind_address}")
        self.addAsyncCleanup(asyncio.to_thread, call.close)

        destination = ("127.0.0.1:%d" % self.far.getsockname()[1]).encode()
        payload = b"\x80\x00rtp-shaped"
        record = ffi.new("sipral_audio_transmit_t *")
        record.size = ffi.sizeof("sipral_audio_transmit_t")
        record.call = call.handle
        record.protocol = lib.SIPRAL_TRANSPORT_UDP
        keep_destination = ffi.new("char[]", destination)
        keep_payload = ffi.new("uint8_t[]", payload)
        record.destination = keep_destination
        record.destination_len = len(destination)
        record.payload = keep_payload
        record.payload_len = len(payload)

        self.alice._on_audio_transmit(record, ffi.NULL)
        received, sender = await asyncio.to_thread(self.far.recvfrom, 2048)
        self.assertEqual(received, payload)
        self.assertEqual("%s:%d" % sender, call.media_address)

        record.call = call.handle + 1000
        self.alice._on_audio_transmit(record, ffi.NULL)
        self.far.settimeout(0.3)
        with self.assertRaises(TimeoutError):
            self.far.recvfrom(2048)


@unittest.skipUnless(_HAS_DEVICES, "this build has no audio backend for this platform")
class ACallInDeviceModeIsTheEnginesToPump(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(loop=loop, audio=AudioMode.DEVICE, audio_activation=AudioActivation.MANUAL)
        self.bob = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        self.alice.close()
        self.bob.close()

    async def test_the_call_connects_and_its_media_carries_no_frames_of_the_applications(self) -> None:
        account = self.alice.add_account("sip:alice@sipral.invalid", registrar_address=self.bob.bind_address)
        self.bob.add_account("sip:bob@sipral.invalid", registrar_address=self.alice.bind_address)
        call = self.alice.place_call(account, f"sip:bob@{self.bob.bind_address}")
        answered = None
        while answered is None:
            event = await asyncio.wait_for(self.bob.events.get(), timeout=5)
            if event.kind == EventKind.INCOMING_CALL:
                answered = self.bob.answer_call(event)
        self.addAsyncCleanup(asyncio.to_thread, answered.close)
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=5)
        while answered.media is None:
            await asyncio.wait_for(answered.events.get(), timeout=5)

        self.assertTrue(call.media.pumped)
        self.assertFalse(answered.media.pumped)
        with self.assertRaises(RuntimeError):
            call.media.send_audio(bytes(320))
        # In device mode the engine plays the far end; no frames here.
        answered.media.send_audio(bytes([0x00, 0x10]) * 800)
        await asyncio.sleep(0.3)
        self.assertTrue(call.media.frames.empty())
        self.assertFalse(self.alice.audio.info().active)


@unittest.skipUnless(
    _HAS_DEVICES and os.environ.get("SIPRAL_AUDIO_DEVICES") == "1",
    "opens the machine's real devices: set SIPRAL_AUDIO_DEVICES=1 where a test may",
)
class ACallOnRealDevicesCarriesAudioBothWays(unittest.IsolatedAsyncioTestCase):
    """One end on real devices: the far end reaches the speaker meter and the
    microphone's packets reach the far end. Opt-in (e.g. a virtual cable)."""

    async def test_the_far_end_is_heard_and_hears(self) -> None:
        loop = asyncio.get_running_loop()
        alice = Stack(loop=loop, audio=AudioMode.DEVICE)
        devices = alice.audio.refresh()
        for role in (AudioRole.SPEAKER, AudioRole.MICROPHONE, AudioRole.RINGER):
            quiet = quiet_device(devices, role)
            if quiet is not None:
                alice.audio.select(role, quiet)
        bob = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(asyncio.to_thread, bob.close)
        self.addAsyncCleanup(asyncio.to_thread, alice.close)
        account = alice.add_account("sip:alice@sipral.invalid", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@sipral.invalid", registrar_address=alice.bind_address)
        call = alice.place_call(account, f"sip:bob@{bob.bind_address}")
        answered = None
        while answered is None:
            event = await asyncio.wait_for(bob.events.get(), timeout=10)
            if event.kind == EventKind.INCOMING_CALL:
                answered = bob.answer_call(event)
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=10)
        while answered.media is None:
            await asyncio.wait_for(answered.events.get(), timeout=10)

        tone = array.array(
            "h", (int(8000 * math.sin(2 * math.pi * 440 * i / 8000)) for i in range(1600))
        ).tobytes()
        loudest = 0
        for _ in range(30):
            answered.media.send_audio(tone)
            await asyncio.sleep(0.1)
            loudest = max(loudest, alice.audio.level(AudioDirection.OUTPUT))
        info = alice.audio.info()
        self.assertTrue(info.active)
        self.assertIsNotNone(info.speaker)
        self.assertGreater(loudest, 1000, "the loudspeaker's meter")
        self.assertGreater(answered.media.frames.qsize(), 50, "frames the far end decoded")
        self.assertGreater(call.media.statistics()["packets_sent"], 50, "packets through the callback")



@unittest.skipUnless(
    _HAS_DEVICES and os.environ.get("SIPRAL_AUDIO_DEVICES") == "1",
    "opens the machine's real devices: set SIPRAL_AUDIO_DEVICES=1 where a test may",
)
class TheEchoCancellationSwitchReopensTheOpenDevices(unittest.TestCase):
    """Toggling echo cancellation reopens devices in place, keeping gain and
    mute. Opt-in."""

    def test_the_devices_are_kept_and_the_state_read_back(self) -> None:
        with Stack(audio=AudioMode.DEVICE, audio_activation=AudioActivation.MANUAL) as stack:
            audio = stack.audio
            devices = audio.refresh()
            for role in (AudioRole.SPEAKER, AudioRole.MICROPHONE):
                quiet = quiet_device(devices, role)
                if quiet is not None:
                    audio.select(role, quiet)
            audio.set_muted(AudioDirection.OUTPUT, True)
            audio.set_gain(AudioDirection.INPUT, 0.5)
            audio.activate()
            before = audio.info()
            audio.set_system_echo_cancellation(False)
            off = audio.info()
            self.assertTrue(off.active)
            self.assertFalse(off.system_echo_cancellation)
            self.assertEqual((off.speaker, off.microphone), (before.speaker, before.microphone))
            self.assertTrue(audio.muted(AudioDirection.OUTPUT))
            self.assertEqual(audio.gain(AudioDirection.INPUT), 0.5)
            audio.set_system_echo_cancellation(True)
            self.assertTrue(stack.settings().system_echo_cancellation)
            audio.deactivate()


if __name__ == "__main__":
    unittest.main()
