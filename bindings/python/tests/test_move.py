# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A call in progress moves with the network under it, and a call's media
says which SRTP transform it runs.

Alice moves from loopback to the default-route address; the call asks to
move (`SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`), ``Call.readdress`` re-offers
it, and audio flows both ways on the new socket.
"""

from __future__ import annotations

import array
import asyncio
import math
import socket
import sys
import unittest

from sipral import SipralError, Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode, EventKind, Recovery, SrtpSuite, Status


def _routable_address() -> str | None:
    """This host's default-route address; a UDP `connect` sends nothing."""
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
    #: Alice's signalling bind; ``None`` for every interface.
    alice_host: str | None = None

    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice = Stack(self.alice_host, loop=loop, audio=AudioMode.APPLICATION, srtp=self.srtp)
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
    # Bound to one address so the move rebinds; a wildcard stack would keep
    # advertising loopback here.
    alice_host = "127.0.0.1"

    async def asyncSetUp(self) -> None:
        self.host = _routable_address()
        if self.host is None or self.host.startswith("127."):
            self.skipTest("no address besides loopback on this machine to move to")
        if sys.platform == "win32":
            # Windows routes nothing between loopback and the LAN address.
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
        # A tone, not DC, which Opus filters out. 40-sample period.
        count = media.frame_samples * 100
        tone = array.array(
            "h", (int(8000 * math.sin(2 * math.pi * n / 40)) for n in range(count))
        )
        media.send_audio(tone.tobytes())

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
        # The old socket is closed: a latching far end must not be led back.
        self.assertEqual(call.media.local_address, call.media_address)
        self.assertEqual(old.fileno(), -1)
        await self.until(call, EventKind.SESSION_CHANGED)

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


def _free_port(host: str) -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((host, 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


class TheSignallingPortSurvivesAMove(unittest.TestCase):
    """``move_to`` keeps the signalling port unless another socket holds
    it at the new address."""

    def setUp(self) -> None:
        self.host = _routable_address()
        if self.host is None or self.host.startswith("127."):
            self.skipTest("no address besides loopback on this machine to move to")

    def test_the_chosen_port_moves_with_the_address_and_back(self) -> None:
        chosen = _free_port(self.host)
        with Stack("127.0.0.1", chosen, audio=AudioMode.APPLICATION) as stack:
            stack.move_to(self.host)
            self.assertEqual(stack.bind_address, f"{self.host}:{chosen}")
            self.assertTrue(stack.kept_signalling_port)
            stack.move_to("127.0.0.1")
            self.assertEqual(stack.bind_address, f"127.0.0.1:{chosen}")

    def test_with_none_chosen_the_port_in_use_is_kept(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            port = stack.bind_address.rsplit(":", 1)[1]
            stack.move_to(self.host)
            self.assertEqual(stack.bind_address, f"{self.host}:{port}")
            self.assertTrue(stack.kept_signalling_port)

    def test_a_port_taken_at_the_new_address_falls_back_and_says_so(self) -> None:
        squatter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(squatter.close)
        squatter.bind((self.host, 0))
        taken = squatter.getsockname()[1]
        with Stack("127.0.0.1", taken, audio=AudioMode.APPLICATION) as stack:
            stack.move_to(self.host)
            host, port = stack.bind_address.rsplit(":", 1)
            self.assertEqual(host, self.host)
            self.assertNotIn(int(port), (taken, 0))
            self.assertFalse(stack.kept_signalling_port)

    def test_a_move_to_an_address_this_machine_lacks_keeps_the_socket_it_had(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            before = stack.bind_address
            port = before.rsplit(":", 1)[1]
            # TEST-NET-1 (RFC 5737): not local.
            with self.assertRaises(OSError):
                stack.move_to("192.0.2.77")
            self.assertEqual(stack.bind_address, before)
            stack.move_to(self.host)
            self.assertEqual(stack.bind_address, f"{self.host}:{port}")
            self.assertTrue(stack.kept_signalling_port)


    def test_a_stack_on_every_interface_keeps_choosing_its_route_across_a_move(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            port = stack.bind_address.rsplit(":", 1)[1]
            away = stack.add_account("sip:alice@192.0.2.1", registrar_address="192.0.2.1:5060")
            self.assertEqual(stack.bind_address, f"{self.host}:{port}")

            stack.move_to(self.host)
            here = stack.add_account("sip:bob@127.0.0.1", registrar_address="127.0.0.1:5060")
            self.assertEqual(here.advertised, f"127.0.0.1:{port}")

            stack.move_to("127.0.0.1")
            self.assertEqual(
                stack.bind_address,
                f"{self.host}:{port}",
                "the route toward the first account's server, not the address the move named",
            )
            self.assertTrue(stack.kept_signalling_port)
            self.assertEqual(away.advertised, f"{self.host}:{port}")
            self.assertEqual(here.advertised, f"127.0.0.1:{port}")


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
