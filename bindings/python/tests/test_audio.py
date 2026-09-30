# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""The library's own audio engine through ``Stack(audio=...)`` and
``stack.audio``: which mode a stack gets, the device list, roles, gain,
mute, the meter, activation, the ring, and the packets the engine hands
back to be sent.

Everything here that touches a device stays on the manual activation, so
no microphone is ever opened on the machine the gate runs on: a stack in
device mode that is never activated lists and configures devices, and the
engine opens nothing until it is told to. Where the build has no backend
(Linux), the tests check the other half of the contract: the default is
application mode and asking for device mode is refused.
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
            # the library counts the trailing NUL in the length it reports;
            # the message is the text before it
            self.assertNotIn("\0", str(raised.exception))
            self.assertTrue(str(raised.exception).endswith("pumps its own frames"), str(raised.exception))

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
            # the library counts the name's trailing NUL, which is not the name's
            self.assertNotIn("\0", device.name)
            self.assertTrue(device.is_microphone or device.is_speaker, device)
        again = self.audio.refresh()
        self.assertEqual(
            {device.name: device.id for device in listed},
            {device.name: device.id for device in again if device.present},
        )

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
                # macOS runs the microphone and the loudspeaker as one unit
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
        # deactivating what was never activated changes nothing
        self.audio.deactivate()
        self.assertFalse(self.audio.info().active)

    def test_a_ring_tone_is_whole_samples(self) -> None:
        with self.assertRaises(ValueError):
            self.audio.ring(b"\x00\x01\x02", 8000)
        # under manual activation a ring opens nothing, and stopping it
        # needs nothing open
        self.audio.stop_ringing()
        self.assertFalse(self.audio.info().active)


class TheEnginesPacketsLeaveFromTheCallsSocket(unittest.IsolatedAsyncioTestCase):
    """`audio_transmit_callback`, the way the engine calls it: a packet naming
    a call and a destination leaves from that call's own media socket. The
    record is built here, so this runs on every platform and opens nothing."""

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

        # a call this stack does not know is nobody's packet
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
        # the far end's audio is the engine's to play, not a frame here
        answered.media.send_audio(bytes([0x00, 0x10]) * 800)
        await asyncio.sleep(0.3)
        self.assertTrue(call.media.frames.empty())
        # parked until activated: nothing is open
        self.assertFalse(self.alice.audio.info().active)


@unittest.skipUnless(
    _HAS_DEVICES and os.environ.get("SIPRAL_AUDIO_DEVICES") == "1",
    "opens the machine's real devices: set SIPRAL_AUDIO_DEVICES=1 where a test may",
)
class ACallOnRealDevicesCarriesAudioBothWays(unittest.IsolatedAsyncioTestCase):
    """One end of the call runs on the machine's real devices: activated, the
    engine opens them, the far end's audio reaches the loudspeaker's meter and
    the microphone's packets reach the far end through the transmit
    callback. Opt-in, for a machine whose devices a test may open (the
    Windows lab's virtual cable)."""

    async def test_the_far_end_is_heard_and_hears(self) -> None:
        loop = asyncio.get_running_loop()
        alice = Stack(loop=loop, audio=AudioMode.DEVICE)
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


if __name__ == "__main__":
    unittest.main()
