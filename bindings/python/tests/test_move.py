# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""A call in progress moves with the network under it, and a call's media
says which SRTP transform it runs.

Alice starts on loopback and moves to this machine's own address on its
default route: ``Stack.move_to`` binds signalling there and reports the
change, the call asks to be moved (`SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`),
``Call.readdress`` offers it at a socket on the new address, and audio
crosses both ways from that socket once the far end answers.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import unittest

from sipral import SipralError, Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode, EventKind, Recovery, SrtpSuite, Status


def _routable_address() -> str | None:
    """This host's address on its default route: `connect` on a UDP socket
    picks a source address and sends nothing."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("203.0.113.1", 80))  # RFC 5737 TEST-NET-3: never dialled
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def _loud(pcm: bytes) -> bool:
    samples = memoryview(pcm).cast("h")
    return any(abs(sample) > 1000 for sample in samples)


class _Pair(unittest.IsolatedAsyncioTestCase):
    srtp = 0

    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(loop=loop, audio=AudioMode.APPLICATION, srtp=self.srtp)
        self.bob = Stack(loop=loop, audio=AudioMode.APPLICATION, srtp=self.srtp)
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        await asyncio.to_thread(self.alice.close)
        await asyncio.to_thread(self.bob.close)

    async def connect(self):
        account = self.alice.add_account(
            "sip:alice@sipral.invalid", registrar_address=self.bob.bind_address
        )
        self.bob.add_account("sip:bob@sipral.invalid", registrar_address=self.alice.bind_address)
        call = self.alice.place_call(account, f"sip:bob@{self.bob.bind_address}")
        answered = None
        while answered is None:
            event = await asyncio.wait_for(self.bob.events.get(), timeout=5)
            if event.kind == EventKind.INCOMING_CALL:
                answered = self.bob.answer_call(event)
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=5)
        while answered.media is None:
            await asyncio.wait_for(answered.events.get(), timeout=5)
        return call, answered

    @staticmethod
    async def until(call, kind: int, seconds: float = 5):
        while True:
            event = await asyncio.wait_for(call.events.get(), timeout=seconds)
            if event.kind == kind:
                return event


class ACallMovesWithTheNetwork(_Pair):
    async def asyncSetUp(self) -> None:
        self.host = _routable_address()
        if self.host is None or self.host.startswith("127."):
            self.skipTest("no address besides loopback on this machine to move to")
        if sys.platform == "win32":
            # Windows routes no datagram between a socket bound to loopback
            # and one bound to the machine's own LAN address
            self.skipTest("a far end on loopback cannot reach the LAN address on Windows")
        await super().asyncSetUp()

    async def heard(self, media, seconds: float = 3) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        while loop.time() < deadline:
            try:
                frame = await asyncio.wait_for(media.frames.get(), timeout=0.5)
            except TimeoutError:
                continue
            if _loud(frame):
                return True
        return False

    def speak(self, media) -> None:
        media.send_audio(bytes([0x00, 0x20]) * media.frame_samples * 100)

    async def test_the_call_is_offered_at_the_new_address_and_heard_both_ways_after(self) -> None:
        call, answered = await self.connect()
        self.addAsyncCleanup(asyncio.to_thread, answered.close)
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        before = call.media_address

        recovery = self.alice.move_to(self.host)
        self.assertEqual(recovery, Recovery.REBUILD)
        self.assertTrue(self.alice.bind_address.startswith(f"{self.host}:"))

        wanted = await self.until(call, EventKind.CALL_ADDRESS_WANTED)
        self.assertEqual(wanted.call, call.handle)
        old = call.media_socket
        call.readdress(self.host)
        self.assertNotEqual(call.media_address, before)
        self.assertTrue(call.media_address.startswith(f"{self.host}:"))
        # the media reads and sends on the new socket, and the old one is
        # gone: on a real network its address no longer exists, and a far
        # end that latches onto where packets come from must not be led back
        self.assertEqual(call.media.local_address, call.media_address)
        self.assertEqual(old.fileno(), -1)
        await self.until(call, EventKind.SESSION_CHANGED)

        # drain what was heard before the move, then listen at the new socket
        while not call.media.frames.empty():
            call.media.frames.get_nowait()
        self.speak(answered.media)
        self.assertTrue(await self.heard(call.media), "no audio reached the moved socket")
        self.speak(call.media)
        self.assertTrue(await self.heard(answered.media), "the far end heard nothing from the new address")

    async def test_a_second_move_while_the_first_is_on_its_way_is_refused(self) -> None:
        call, answered = await self.connect()
        self.addAsyncCleanup(asyncio.to_thread, answered.close)
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        self.alice.move_to(self.host)
        call.readdress(self.host)
        moved = call.media_address
        with self.assertRaises(SipralError) as refused:
            call.readdress(self.host)
        self.assertEqual(refused.exception.status, Status.WRONG_STATE)
        self.assertEqual(call.media_address, moved, "a refused move keeps the socket it had")


class ACallSaysWhichTransformSecuresIt(_Pair):
    srtp = lib.SIPRAL_SRTP_DTLS

    async def test_two_ends_of_this_stack_settle_on_aes_256_gcm(self) -> None:
        call, answered = await self.connect()
        self.addAsyncCleanup(asyncio.to_thread, answered.close)
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        # MEDIA_SECURED may have been read already while waiting for media
        if call.srtp_suite is None:
            await self.until(call, EventKind.MEDIA_SECURED)
        if answered.srtp_suite is None:
            await self.until(answered, EventKind.MEDIA_SECURED)
        self.assertEqual(call.srtp_suite, SrtpSuite.AEAD_AES256_GCM)
        self.assertEqual(answered.srtp_suite, SrtpSuite.AEAD_AES256_GCM)


class ACallNotSecuredNamesNoTransform(_Pair):
    srtp = lib.SIPRAL_SRTP_NOT_OFFERED

    async def test_its_suite_is_none(self) -> None:
        call, answered = await self.connect()
        self.addAsyncCleanup(asyncio.to_thread, answered.close)
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        await asyncio.sleep(0.3)
        self.assertIsNone(call.srtp_suite)


if __name__ == "__main__":
    unittest.main()
