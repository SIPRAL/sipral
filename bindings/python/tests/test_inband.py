# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""In-band DTMF (no telephone event offered), answering-machine detection,
the consent beep, and recording files.
"""

from __future__ import annotations

import asyncio
import math
import os
import struct
import tempfile
import unittest

from sipral import Stack, features
from sipral.enums import (
    AmdVerdict,
    AudioMode,
    DigitSource,
    DtmfDetection,
    EventKind,
    Feature,
    ProgressKind,
    RecordingFormat,
    RecordingLayout,
)


def _voiced(n: int, rate: int) -> int:
    """A voice-like signal the answering-machine detector takes as speech."""
    t = n / rate
    value = 6_000.0 * math.sin(2 * math.pi * 180 * t) * (1 + 0.5 * math.sin(2 * math.pi * 700 * t))
    return int(round(value))


class InBandAndRecording(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        # No telephone event: digits cross in the audio, detected by default.
        self.alice_stack = Stack(
            loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU", offer_dtmf=False
        )
        self.bob_stack = Stack(
            loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU", offer_dtmf=False
        )
        self.addAsyncCleanup(self._close_stacks)
        self.scratch = tempfile.mkdtemp(prefix="sipral-inband-")

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def _place_and_answer(self, before_answer=None):
        alice_account = self.alice_stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=self.bob_stack.bind_address,
        )
        self.bob_stack.add_account(
            "sip:bob@sipral.invalid",
            registrar_address=self.alice_stack.bind_address,
        )
        alice_call = self.alice_stack.place_call(
            alice_account, f"sip:bob@{self.bob_stack.bind_address}"
        )
        if before_answer is not None:
            before_answer(alice_call)
        bob_call = None
        while bob_call is None:
            event = await asyncio.wait_for(self.bob_stack.events.get(), timeout=5)
            if event.kind == EventKind.INCOMING_CALL:
                bob_call = self.bob_stack.answer_call(event)
        while alice_call.media is None:
            await asyncio.wait_for(alice_call.events.get(), timeout=5)
        while bob_call.media is None:
            await asyncio.wait_for(bob_call.events.get(), timeout=5)
        self.addAsyncCleanup(self._close_calls, alice_call, bob_call)
        return alice_call, bob_call

    async def _close_calls(self, *calls) -> None:
        for call in calls:
            call.close()

    async def _event_of(self, call, kind: int, timeout: float = 8):
        async def find():
            while True:
                event = await call.events.get()
                if event.kind == kind:
                    return event

        return await asyncio.wait_for(find(), timeout=timeout)

    async def test_a_digit_crosses_in_the_audio_where_no_telephone_event_was_offered(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        # Past the far end's RTP probation.
        await asyncio.sleep(0.2)
        alice_call.send_dtmf("7")
        digit = await asyncio.wait_for(bob_call.dtmf.get(), timeout=5)
        self.assertEqual(digit, "7")
        heard = await self._event_of(bob_call, EventKind.IN_BAND_DIGIT)
        self.assertEqual(heard.fields["source"], DigitSource.IN_BAND)
        self.assertEqual(heard.fields["event_code"], 7)
        self.assertLess(abs(heard.fields["held_ms"] - 100), 25)

    async def test_a_call_told_not_to_listen_hears_no_digit(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        bob_call.set_dtmf_detection(DtmfDetection.OFF)
        await asyncio.sleep(0.2)
        alice_call.send_dtmf("3")
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(bob_call.dtmf.get(), timeout=1.5)

    async def test_a_stereo_recording_keeps_this_end_on_the_left(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        path = os.path.join(self.scratch, "stereo.wav")
        alice_call.media.record(path, layout=RecordingLayout.STEREO, sample_rate=16_000)
        frame = alice_call.media.frame_samples
        alice_call.media.send_audio(struct.pack(f"<{frame}h", *([3_000] * frame)) * 25)
        await asyncio.sleep(0.8)
        running, taken = alice_call.media.recording
        self.assertTrue(running)
        self.assertGreater(taken, 0)
        alice_call.media.stop_recording()
        self.assertFalse(alice_call.media.recording[0])
        with open(path, "rb") as file:
            wav = file.read()
        self.assertEqual(wav[:4], b"RIFF")
        channels, rate = struct.unpack_from("<HI", wav, 58)
        self.assertEqual((channels, rate), (2, 16_000))
        (data,) = struct.unpack_from("<I", wav, 76)
        self.assertEqual(data, len(wav) - 80, "the data length was written")
        left = struct.unpack_from(f"<{(len(wav) - 80) // 2}h", wav, 80)[0::2]
        self.assertTrue(any(abs(sample - 3_000) < 100 for sample in left))

    @unittest.skipUnless(Feature.OPUS in features(), "this build has no Opus")
    async def test_an_ogg_opus_recording_is_an_opus_stream(self) -> None:
        alice_call, _ = await self._place_and_answer()
        path = os.path.join(self.scratch, "call.opus")
        alice_call.media.record(path, format=RecordingFormat.OGG_OPUS)
        await asyncio.sleep(0.5)
        alice_call.media.stop_recording()
        with open(path, "rb") as file:
            data = file.read()
        self.assertEqual(data[:4], b"OggS")
        self.assertIn(b"OpusHead", data[:64])
        self.assertIn(b"OpusTags", data)

    async def test_a_greeting_that_runs_on_is_reported_as_a_machine(self) -> None:
        # A short greeting limit for a quick decision.
        alice_call, bob_call = await self._place_and_answer(
            before_answer=lambda call: call.detect_progress(max_greeting_ms=600, beep=False)
        )
        rate = bob_call.media.sample_rate
        greeting = bytearray()
        for n in range(rate * 2):
            voiced = (n // (rate // 5)) % 2 == 0
            greeting += struct.pack("<h", _voiced(n, rate) if voiced else 0)
        bob_call.media.send_audio(bytes(greeting))
        heard = await self._event_of(alice_call, EventKind.PROGRESS_DETECTED)
        self.assertEqual(heard.fields["what"], ProgressKind.ANSWERED_BY)
        self.assertEqual(heard.fields["verdict"], AmdVerdict.MACHINE)
        self.assertGreater(heard.fields["at_ms"], 0)

    async def test_the_consent_tone_reaches_the_far_end_while_recording(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        alice_call.set_consent_tone(interval_ms=1_000)
        alice_call.media.record(os.path.join(self.scratch, "consent.wav"))

        async def loud_frame():
            while True:
                frame = await bob_call.media.frames.get()
                samples = struct.unpack(f"<{len(frame) // 2}h", frame)
                if max(abs(sample) for sample in samples) > 1_000:
                    return True

        self.assertTrue(await asyncio.wait_for(loud_frame(), timeout=3))
        alice_call.media.stop_recording()
        alice_call.clear_consent_tone()


if __name__ == "__main__":
    unittest.main()
