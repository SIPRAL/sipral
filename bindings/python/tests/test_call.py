# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""Two stacks on 127.0.0.1, talking directly, with no registrar between them.

This is the proof the lab is not: `scripts/lab.sh` exercises this package
against FreeSWITCH, on a machine that runs it, and is the integrator's to
run. What runs here instead is what `interop/harness-c/main.c` already
does for the C ABI directly -- an account with no registrar
(`sipral_account_config_t::registrar_len` left at zero), pointed at the
other stack's own address as its outbound proxy -- carried through this
package's idiomatic layer: place a call, answer it, exchange audio, send
one DTMF digit, and read back what the call cost.
"""

from __future__ import annotations

import asyncio
import time
import unittest

from sipral import SipralError, Stack
from sipral._sipral_cffi import ffi, lib
from sipral.enums import AudioMode, CallState, EventKind
from sipral.events import _statistics


class TwoStacksTalkDirectly(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.alice_stack = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.bob_stack = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(self._close_stacks)

    async def _close_stacks(self) -> None:
        self.alice_stack.close()
        self.bob_stack.close()

    async def _place_and_answer(self):
        """Alice calls Bob direct; Bob answers. Returns both `Call`s."""
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

        bob_call = None
        while bob_call is None:
            event = await asyncio.wait_for(self.bob_stack.events.get(), timeout=5)
            if event.kind == EventKind.INCOMING_CALL:
                bob_call = self.bob_stack.answer_call(event)

        while alice_call.media is None:
            await asyncio.wait_for(alice_call.events.get(), timeout=5)
        while bob_call.media is None:
            await asyncio.wait_for(bob_call.events.get(), timeout=5)

        return alice_call, bob_call

    async def test_call_reaches_confirmed_with_media_both_ways(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        self.addAsyncCleanup(self._close_calls, alice_call, bob_call)

        self.assertEqual(alice_call.state, CallState.CONFIRMED)
        self.assertEqual(bob_call.state, CallState.CONFIRMED)
        self.assertTrue(alice_call.media.info()["sending"])
        self.assertTrue(bob_call.media.info()["receiving"])

    async def test_audio_crosses_as_bytes_in_both_directions(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        self.addAsyncCleanup(self._close_calls, alice_call, bob_call)

        frame_bytes = alice_call.media.frame_samples * 2
        tone = bytes([0x10, 0x00]) * (frame_bytes // 2) * 5  # five frames

        alice_call.media.send_audio(tone)
        heard = await asyncio.wait_for(bob_call.media.frames.get(), timeout=5)
        self.assertIsInstance(heard, bytes)
        self.assertEqual(len(heard), frame_bytes)

        bob_call.media.send_audio(tone)
        heard_back = await asyncio.wait_for(alice_call.media.frames.get(), timeout=5)
        self.assertEqual(len(heard_back), frame_bytes)

    async def test_dtmf_and_statistics(self) -> None:
        alice_call, bob_call = await self._place_and_answer()
        self.addAsyncCleanup(self._close_calls, alice_call, bob_call)

        bob_call.send_dtmf("5")
        digit = await asyncio.wait_for(alice_call.dtmf.get(), timeout=5)
        self.assertEqual(digit, "5")

        # A little audio first, so there is something in the counters.
        frame_bytes = alice_call.media.frame_samples * 2
        for _ in range(5):
            alice_call.media.send_audio(bytes(frame_bytes))
        await asyncio.sleep(0.3)

        stats = alice_call.media.statistics()
        self.assertGreater(stats["packets_sent"], 0)
        self.assertIn("score", stats)

        # the dict copies frames_underrun, not a neighbour of it: the
        # library's own count, read either side, brackets it
        def raw() -> int:
            out = ffi.new("sipral_stream_stats_t *")
            out.size = ffi.sizeof("sipral_stream_stats_t")
            self.assertEqual(lib.sipral_media_statistics(alice_call.media.handle, 0, out), 0)
            return int(out.frames_underrun)

        before = raw()
        read = alice_call.media.statistics()["frames_underrun"]
        self.assertLessEqual(before, read)
        self.assertLessEqual(read, raw())

    async def test_the_end_of_call_record_is_kept_and_still_readable(self) -> None:
        """The record `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` carries is kept on
        the call, and is what the media answers once the library has nothing
        left and says ``WRONG_STATE``."""
        alice_call, bob_call = await self._place_and_answer()
        self.addAsyncCleanup(self._close_calls, alice_call, bob_call)
        media = alice_call.media
        frame_bytes = media.frame_samples * 2
        for _ in range(5):
            media.send_audio(bytes(frame_bytes))
        deadline = time.monotonic() + 5
        while media.statistics()["packets_sent"] < 5 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)

        bob_call.hangup()
        record = None
        async with asyncio.timeout(5):
            while record is None:
                event = await self.alice_stack.events.get()
                if event.kind == EventKind.MEDIA_STATISTICS and event.call == alice_call.handle:
                    record = event.fields["statistics"]
        self.assertGreaterEqual(record["packets_sent"], 5)
        self.assertEqual(alice_call.final_statistics, record)
        out = ffi.new("sipral_stream_stats_t *")
        out.size = ffi.sizeof("sipral_stream_stats_t")
        self.assertEqual(
            lib.sipral_media_statistics(media.handle, 0, out), lib.SIPRAL_STATUS_WRONG_STATE
        )
        self.assertEqual(media.statistics()["packets_sent"], record["packets_sent"])

    def test_an_under_run_count_crosses_into_the_events_record(self) -> None:
        """The end-of-call record a MEDIA_STATISTICS event carries copies
        `frames_underrun` under its own name, the member beside it untouched."""
        native = ffi.new("sipral_stream_stats_t *")
        native.size = ffi.sizeof("sipral_stream_stats_t")
        native.frames_underrun = 7
        native.silent_for_ms = 11
        record = _statistics(native)
        self.assertIsNotNone(record)
        self.assertEqual(record["frames_underrun"], 7)
        self.assertEqual(record["silent_for_ms"], 11)

    async def _close_calls(self, *calls) -> None:
        for call in calls:
            call.close()


class ACeilingOnCalls(unittest.IsolatedAsyncioTestCase):
    async def test_a_call_placed_past_max_dialogs_is_refused(self) -> None:
        loop = asyncio.get_running_loop()
        alice = Stack(loop=loop, audio=AudioMode.APPLICATION, max_dialogs=1)
        bob = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.addCleanup(bob.close)
        self.addCleanup(alice.close)

        settings = ffi.new("sipral_stack_settings_t *")
        settings.size = ffi.sizeof("sipral_stack_settings_t")
        self.assertEqual(lib.sipral_stack_settings(alice.handle, settings), 0)
        self.assertEqual(settings.max_dialogs, 1)
        self.assertEqual(settings.max_server_transactions, 256)

        account = alice.add_account(
            "sip:alice@sipral.invalid", registrar_address=bob.bind_address
        )
        first = alice.place_call(account, f"sip:bob@{bob.bind_address}")
        self.addCleanup(first.close)
        with self.assertRaises(SipralError) as raised:
            alice.place_call(account, f"sip:bob@{bob.bind_address}")
        self.assertEqual(raised.exception.status, lib.SIPRAL_STATUS_LIMIT_REACHED)


if __name__ == "__main__":
    unittest.main()
