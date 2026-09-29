# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""A local conference through this package: made on its own and asked
about, recorded, refused at a rate it cannot mix, and -- with three stacks
on 127.0.0.1 -- two calls bridged so that what one far end says the other
hears.
"""

from __future__ import annotations

import array
import asyncio
import os
import tempfile
import unittest

from sipral import LocalConference, SipralError, Stack
from sipral.enums import AudioDirection, AudioMode, EventKind, LocalConferenceChange, Status

TIMEOUT = 10.0


def _loudness(pcm: bytes) -> int:
    samples = array.array("h", pcm)
    return sum(abs(sample) for sample in samples) // max(len(samples), 1)


def _square(frames: int, samples: int) -> bytes:
    """A 500 Hz square wave at 8 kHz, ``frames`` frames of ``samples``."""
    wave = array.array("h", [8000 if (n // 8) % 2 == 0 else -8000 for n in range(samples)])
    return wave.tobytes() * frames


class ALocalConferenceOnItsOwn(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        self.stack.close()

    async def test_this_end_is_its_first_member_and_is_announced(self) -> None:
        with LocalConference(self.stack, max_members=3, sample_rate=8000) as conference:
            info = conference.info()
            self.assertEqual((info["members"], info["capacity"], info["local"]), (1, 3, True))
            self.assertEqual((conference.sample_rate, conference.frame_samples), (8000, 160))
            members = conference.members()
            self.assertEqual(members[0]["member"], conference.handle)
            self.assertEqual(members[0]["gain_input"], 256)

            conference.set_muted(None, AudioDirection.INPUT)
            conference.set_gain(None, AudioDirection.OUTPUT, 128)
            members = conference.members()
            self.assertTrue(members[0]["muted_input"])
            self.assertEqual(members[0]["gain_output"], 128)

            while True:
                event = await asyncio.wait_for(self.stack.events.get(), timeout=TIMEOUT)
                if event.kind == EventKind.LOCAL_CONFERENCE_CHANGED:
                    break
            notice = event.local_conference
            self.assertEqual(notice.conference, conference.handle)
            self.assertEqual(notice.change, LocalConferenceChange.JOINED)
            self.assertEqual(notice.member, conference.handle)
            self.assertEqual(notice.members, 1)

    async def test_the_mix_is_recorded_to_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "conference.wav")
            with LocalConference(self.stack, max_members=2, sample_rate=16000) as conference:
                conference.record(path)
                conference.send_audio(_square(10, 320))
                await asyncio.sleep(0.3)
                self.assertTrue(conference.info()["recording"])
                conference.stop_recording()
                with self.assertRaises(SipralError) as refused:
                    conference.stop_recording()
                self.assertEqual(refused.exception.status, Status.WRONG_STATE)
            with open(path, "rb") as written:
                header = written.read(4)
            self.assertEqual(header, b"RIFF")
            self.assertGreater(os.path.getsize(path), 44)

    async def test_a_rate_it_cannot_mix_is_refused(self) -> None:
        with self.assertRaises(SipralError) as refused:
            LocalConference(self.stack, sample_rate=44100)
        self.assertEqual(refused.exception.status, Status.CONFERENCE_REFUSED)


class TwoCallsBridged(unittest.IsolatedAsyncioTestCase):
    """Alice calls Bob and Carol and bridges the two calls, taking no part
    herself: what Bob says, Carol hears, and Bob does not hear himself."""

    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.bob = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.carol = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        for stack in (self.alice, self.bob, self.carol):
            stack.close()

    async def _call(self, far: Stack, user: str):
        """Alice calls ``far`` directly, through an account of her own that
        names it as the next hop, and it answers."""
        account = self.alice.add_account(
            f"sip:alice-to-{user}@sipral.invalid", registrar_address=far.bind_address
        )
        far.add_account(f"sip:{user}@sipral.invalid", registrar_address=self.alice.bind_address)
        near = self.alice.place_call(account, f"sip:{user}@{far.bind_address}")
        answered = None
        while answered is None:
            event = await asyncio.wait_for(far.events.get(), timeout=TIMEOUT)
            if event.kind == EventKind.INCOMING_CALL:
                answered = far.answer_call(event)
        while near.media is None:
            await asyncio.wait_for(near.events.get(), timeout=TIMEOUT)
        while answered.media is None:
            await asyncio.wait_for(answered.events.get(), timeout=TIMEOUT)
        return near, answered

    async def test_what_one_far_end_says_the_other_hears(self) -> None:
        to_bob, bob_call = await self._call(self.bob, "bob")
        to_carol, carol_call = await self._call(self.carol, "carol")
        with LocalConference(self.alice, max_members=2, local=False) as conference:
            conference.add(to_bob)
            conference.add(to_carol)
            with self.assertRaises(SipralError) as refused:
                conference.add(to_bob)
            self.assertEqual(refused.exception.status, Status.CONFERENCE_REFUSED)
            self.assertEqual(conference.info()["members"], 2)

            samples = bob_call.media.frame_samples
            bob_call.media.send_audio(_square(100, samples))
            loudest = 0
            deadline = asyncio.get_running_loop().time() + TIMEOUT
            while loudest < 2000 and asyncio.get_running_loop().time() < deadline:
                frame = await asyncio.wait_for(carol_call.media.frames.get(), timeout=TIMEOUT)
                loudest = max(loudest, _loudness(frame))
            self.assertGreater(loudest, 2000, "Carol never heard Bob")
            # and steadily, for sixty of Bob's hundred frames: a call whose
            # own thread still carried frames beside the conference would
            # have every other frame taken from under it, and a frame clock
            # slower than the conference's leaves gaps the buffers fill with
            # silence
            steady = 0
            for _ in range(60):
                frame = await asyncio.wait_for(carol_call.media.frames.get(), timeout=TIMEOUT)
                steady += _loudness(frame) > 2000
            self.assertGreaterEqual(steady, 57, f"Carol heard Bob in {steady} of 60 frames")

            while not bob_call.media.frames.empty():
                bob_call.media.frames.get_nowait()
            await asyncio.sleep(0.2)
            heard_by_bob = 0
            while not bob_call.media.frames.empty():
                heard_by_bob = max(heard_by_bob, _loudness(bob_call.media.frames.get_nowait()))
            self.assertLess(heard_by_bob, 500, "Bob heard himself")

            talkers = conference.talkers()
            self.assertEqual(talkers[:1], [to_bob.handle])
            conference.remove(to_carol)
            self.assertEqual(conference.info()["members"], 1)
        for call in (to_bob, to_carol, bob_call, carol_call):
            call.close()


if __name__ == "__main__":
    unittest.main()
