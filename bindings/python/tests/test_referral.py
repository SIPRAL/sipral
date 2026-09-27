# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""A REFER outside any dialog, and ICE-lite, through this package.

The referrer is a plain UDP socket writing RFC 3515 §4.1's own REFER by
hand -- a switchboard asking Bob's line to ring Carol -- so what is proved
is the wire: 403 while the stack has not been told to take referrals, and
with it told, the application asked, a 202, `NOTIFY`s carrying
`message/sipfrag`, and the call placed from Bob's account to a second stack
that answers it.

The ICE-lite case is two stacks on loopback: Alice a full agent that
requires ICE, Bob `Ice.LITE`, both choosing the one pair and audio crossing
it both ways.
"""

from __future__ import annotations

import asyncio
import socket
import unittest

from sipral import Stack
from sipral.enums import EventKind, Ice

from .test_nat import _routable_address


def _refer(stack_address: str, referrer_address: str, target: str) -> bytes:
    return (
        f"REFER sip:bob@{stack_address} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {referrer_address};branch=z9hG4bK-click-to-dial\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:switchboard@sipral.invalid>;tag=switchboard\r\n"
        "To: <sip:bob@sipral.invalid>\r\n"
        "Call-ID: click-to-dial@sipral.invalid\r\n"
        "CSeq: 1 REFER\r\n"
        f"Contact: <sip:switchboard@{referrer_address}>\r\n"
        f"Refer-To: <{target}>\r\n"
        "Referred-By: <sip:switchboard@sipral.invalid>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return None


def _ok_to(request: str) -> bytes:
    """The switchboard's 200 to a NOTIFY the stack sent it."""
    lines = ["SIP/2.0 200 OK"]
    for name in ("Via", "From", "To", "Call-ID", "CSeq"):
        value = _header(name, request)
        if value is not None:
            lines.append(f"{name}: {value}")
    lines += ["Content-Length: 0", "", ""]
    return "\r\n".join(lines).encode("utf-8")


class AReferralOutsideAnyDialog(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.referrer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.referrer.bind(("127.0.0.1", 0))
        self.referrer.setblocking(False)
        self.referrer_address = "%s:%d" % self.referrer.getsockname()
        self.addAsyncCleanup(self._close_socket)

    async def _close_socket(self) -> None:
        self.referrer.close()

    async def _read(self, seconds: float, until) -> list[str]:
        """Everything the referrer's socket receives, answering each NOTIFY
        with a 200, until ``until`` holds for what arrived or time runs out."""
        loop = asyncio.get_running_loop()
        seen: list[str] = []
        deadline = loop.time() + seconds
        while loop.time() < deadline and not until(seen):
            try:
                data, source = self.referrer.recvfrom(65536)
            except BlockingIOError:
                await asyncio.sleep(0.01)
                continue
            text = data.decode("utf-8", "replace")
            seen.append(text)
            if text.startswith("NOTIFY "):
                self.referrer.sendto(_ok_to(text), source)
        return seen

    async def test_a_stack_that_was_not_told_to_take_them_refuses_them_403(self) -> None:
        loop = asyncio.get_running_loop()
        bob = Stack(loop=loop)
        self.addAsyncCleanup(self._close, bob)
        bob.add_account("sip:bob@sipral.invalid", registrar_address=self.referrer_address)
        host, port = bob.bind_address.rsplit(":", 1)
        self.referrer.sendto(
            _refer(bob.bind_address, self.referrer_address, "sip:carol@sipral.invalid"),
            (host, int(port)),
        )
        seen = await self._read(3, lambda seen: any(m.startswith("SIP/2.0 ") for m in seen))
        self.assertTrue(any(m.startswith("SIP/2.0 403 ") for m in seen), seen)

    async def test_a_referral_taken_places_the_call_and_reports_it_to_the_referrer(self) -> None:
        loop = asyncio.get_running_loop()
        carol = Stack(loop=loop)
        bob = Stack(loop=loop, referrals=True)
        self.addAsyncCleanup(self._close, bob, carol)
        carol.add_account("sip:carol@sipral.invalid", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@sipral.invalid", registrar_address=carol.bind_address)

        host, port = bob.bind_address.rsplit(":", 1)
        target = f"sip:carol@{carol.bind_address}"
        self.referrer.sendto(
            _refer(bob.bind_address, self.referrer_address, target), (host, int(port))
        )

        referral = None
        async with asyncio.timeout(5):
            while referral is None:
                event = await bob.events.get()
                if event.kind == EventKind.REFERRAL:
                    referral = event
        self.assertEqual(referral.fields["status_code"], 0)
        self.assertEqual(referral.fields["target"], target)
        self.assertEqual(referral.fields["referred_by"], "<sip:switchboard@sipral.invalid>")
        self.assertFalse(referral.fields["attended"])
        self.assertNotEqual(referral.account, 0, "the line it arrived for")

        placed = bob.accept_referral(referral)
        self.addAsyncCleanup(self._close_calls, placed)

        answered = None
        async with asyncio.timeout(5):
            while answered is None:
                event = await carol.events.get()
                if event.kind == EventKind.INCOMING_CALL:
                    answered = carol.answer_call(event)
        self.addAsyncCleanup(self._close_calls, answered)

        seen = await self._read(
            8,
            lambda seen: any(
                m.startswith("NOTIFY ") and "SIP/2.0 200 OK" in m for m in seen
            ),
        )
        self.assertTrue(any(m.startswith("SIP/2.0 202 ") for m in seen), seen)
        notifies = [m for m in seen if m.startswith("NOTIFY ")]
        self.assertTrue(notifies, seen)
        self.assertIn("SIP/2.0 100 Trying", notifies[0])
        self.assertTrue(_header("Subscription-State", notifies[0]).startswith("active"))
        final = notifies[-1]
        self.assertIn("SIP/2.0 200 OK", final)
        self.assertEqual(
            _header("Subscription-State", final), "terminated;reason=noresource"
        )
        self.assertEqual(_header("Content-Type", final), "message/sipfrag;version=2.0")

        async with asyncio.timeout(5):
            while placed.media is None:
                await placed.events.get()

    async def _close(self, *stacks: Stack) -> None:
        for stack in stacks:
            stack.close()

    async def _close_calls(self, *calls) -> None:
        for call in calls:
            call.close()


class ALiteStackAnsweringAFullOne(unittest.IsolatedAsyncioTestCase):
    """On this host's own routable address, never `127.0.0.1`, for the reason
    `test_nat.TwoStacksTalkThroughIce` gives: RFC 8445 §5.1.1.1 keeps a
    loopback address out of every candidate list, and a lite end has one
    candidate to offer and nothing else."""

    async def test_the_pair_the_full_end_nominates_carries_audio_both_ways(self) -> None:
        host = _routable_address()
        if host is None:
            self.skipTest("no routable address on this machine to gather a host candidate from")
        loop = asyncio.get_running_loop()
        alice_stack = Stack(bind_host=host, loop=loop)
        bob_stack = Stack(bind_host=host, loop=loop, ice=Ice.LITE)
        self.addAsyncCleanup(self._close, alice_stack, bob_stack)
        alice = alice_stack.add_account(
            "sip:alice@sipral.invalid", registrar_address=bob_stack.bind_address
        )
        bob_stack.add_account("sip:bob@sipral.invalid", registrar_address=alice_stack.bind_address)

        alice_call = alice_stack.place_call(
            alice, f"sip:bob@{bob_stack.bind_address}", media_host=host, ice=Ice.REQUIRED
        )
        bob_call = None
        async with asyncio.timeout(5):
            while bob_call is None:
                event = await bob_stack.events.get()
                if event.kind == EventKind.INCOMING_CALL:
                    bob_call = bob_stack.answer_call(event, media_host=host)
        self.addAsyncCleanup(self._close_calls, alice_call, bob_call)

        for call in (alice_call, bob_call):
            async with asyncio.timeout(10):
                while True:
                    event = await call.events.get()
                    if event.kind == EventKind.MEDIA_PATH_CHOSEN:
                        break
                    self.assertNotEqual(event.kind, EventKind.MEDIA_FAILED, event.fields)

        frame_bytes = alice_call.media.frame_samples * 2
        tone = bytes([0x10, 0x00]) * (frame_bytes // 2) * 5
        alice_call.media.send_audio(tone)
        heard = await asyncio.wait_for(bob_call.media.frames.get(), timeout=5)
        self.assertEqual(len(heard), frame_bytes)
        bob_call.media.send_audio(tone)
        heard_back = await asyncio.wait_for(alice_call.media.frames.get(), timeout=5)
        self.assertEqual(len(heard_back), frame_bytes)

    async def _close(self, *stacks: Stack) -> None:
        for stack in stacks:
            stack.close()

    async def _close_calls(self, *calls) -> None:
        for call in calls:
            call.close()


if __name__ == "__main__":
    unittest.main()
