# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""Who is calling, why a call ended, where it went, and what an account
asks for: the caller's typed identity behind a per-account trust gate,
Answer-Mode and Alert-Info, `Reason` read and written, a 3xx redirect, and
the per-account session timer, anonymity and trusted peers -- each against
a far end played by a plain UDP socket, so every header is the test's own.
"""

from __future__ import annotations

import asyncio
import re
import socket
import unittest

from sipral import SipralError, Stack
from sipral.enums import (
    AnswerMode,
    AudioMode,
    EventKind,
    IdentityText,
    Privacy,
    RingSource,
    SessionTimer,
    Status,
    Verstat,
)

_ASSERTING = (
    'P-Asserted-Identity: "Bob Jones" <tel:+15551234567;verstat=TN-Validation-Passed>\r\n'
    "Diversion: <sip:desk@example.com>;reason=no-answer, "
    "<sip:front@example.com>;reason=unconditional\r\n"
    "History-Info: <sip:front@example.com>;index=1\r\n"
    "Privacy: id\r\n"
    "Answer-Mode: Auto;require\r\n"
    "Alert-Info: <urn:alert:source:external>\r\n"
)


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return None


class _FarEnd:
    """A UDP socket that writes and reads SIP by hand."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.address = "127.0.0.1:%d" % self.sock.getsockname()[1]
        audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        audio.bind(("127.0.0.1", 0))
        self.audio = audio

    def close(self) -> None:
        self.sock.close()
        self.audio.close()

    def sdp(self) -> str:
        return (
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            f"m=audio {self.audio.getsockname()[1]} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )

    def send(self, text: str, to: str) -> None:
        host, _, port = to.rpartition(":")
        self.sock.sendto(text.encode("utf-8"), (host, int(port)))

    async def receive(self, starts: str, seconds: float = 5) -> str:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        while loop.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(65536)
            except BlockingIOError:
                await asyncio.sleep(0.01)
                continue
            text = data.decode("utf-8", "replace")
            if text.startswith(starts):
                return text
        raise AssertionError(f"nothing starting {starts!r} arrived")

    def invite(self, to: str, extra: str = "", branch: str = "z9hG4bK-far-1") -> str:
        body = self.sdp()
        return (
            f"INVITE sip:bob@{to} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {self.address};branch={branch}\r\n"
            "Max-Forwards: 70\r\n"
            f"From: <sip:caller@{self.address}>;tag=far\r\n"
            f"To: <sip:bob@{to}>\r\n"
            "Call-ID: identity-1@far\r\n"
            "CSeq: 1 INVITE\r\n"
            f"Contact: <sip:caller@{self.address}>\r\n"
            f"{extra}"
            "Content-Type: application/sdp\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        )

    def cancel(self, to: str, extra: str = "", branch: str = "z9hG4bK-far-1") -> str:
        return (
            f"CANCEL sip:bob@{to} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {self.address};branch={branch}\r\n"
            "Max-Forwards: 70\r\n"
            f"From: <sip:caller@{self.address}>;tag=far\r\n"
            f"To: <sip:bob@{to}>\r\n"
            "Call-ID: identity-1@far\r\n"
            "CSeq: 1 CANCEL\r\n"
            f"{extra}"
            "Content-Length: 0\r\n\r\n"
        )


class _WithAFarEnd(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.far = _FarEnd()
        self.addAsyncCleanup(self._close_far)

    async def _close_far(self) -> None:
        self.far.close()

    def stack(self) -> Stack:
        stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def next_event(self, stack: Stack, kind: int):
        while True:
            event = await asyncio.wait_for(stack.events.get(), timeout=5)
            if event.kind == kind:
                return event


class AnIncomingCallSaysWhoIsCalling(_WithAFarEnd):
    async def test_a_trusted_peer_is_believed_and_every_list_is_read(self) -> None:
        stack = self.stack()
        stack.add_account(
            "sip:bob@sipral.invalid",
            registrar_address=self.far.address,
            trusted_peers=["127.0.0.1"],
        )
        self.far.send(self.far.invite(stack.bind_address, _ASSERTING), stack.bind_address)
        event = await self.next_event(stack, EventKind.INCOMING_CALL)

        identity = event.identity
        self.assertTrue(identity.trusted)
        self.assertEqual(identity.asserted_uri, "tel:+15551234567;verstat=TN-Validation-Passed")
        self.assertEqual(identity.asserted_display, "Bob Jones")
        self.assertEqual(identity.verstat, Verstat.PASSED)
        self.assertEqual(identity.privacy, Privacy.ID)
        self.assertEqual(identity.diverted_from, "sip:desk@example.com")
        self.assertEqual(identity.diversion_reason, "no-answer")
        self.assertEqual((identity.diversion_count, identity.history_count), (2, 1))

        answering = event.answering
        self.assertEqual(answering.answer_mode, AnswerMode.AUTO)
        self.assertTrue(answering.answer_mode_required)
        self.assertEqual(answering.answer_after_ms, 0)
        self.assertEqual(answering.ring_source, RingSource.EXTERNAL)
        self.assertEqual(answering.alert_info, "urn:alert:source:external")
        self.assertIsNone(event.cause, "an incoming call has not ended")

        self.assertEqual(
            stack.call_identity(event, IdentityText.DIVERSION),
            ["sip:desk@example.com", "sip:front@example.com"],
        )
        self.assertEqual(
            stack.call_identity(event, IdentityText.DIVERSION_REASON),
            ["no-answer", "unconditional"],
        )
        self.assertEqual(stack.call_identity(event.call, IdentityText.HISTORY), ["sip:front@example.com"])
        stack.reject_call(event, 486)

    async def test_a_peer_the_account_does_not_trust_asserts_nothing(self) -> None:
        stack = self.stack()
        stack.add_account("sip:bob@sipral.invalid", registrar_address=self.far.address)
        self.far.send(self.far.invite(stack.bind_address, _ASSERTING), stack.bind_address)
        event = await self.next_event(stack, EventKind.INCOMING_CALL)

        identity = event.identity
        self.assertFalse(identity.trusted)
        self.assertIsNone(identity.asserted_uri)
        self.assertEqual(identity.verstat, Verstat.NONE)
        self.assertEqual(identity.diverted_from, "sip:desk@example.com", "forwarding is still told")
        self.assertEqual(stack.call_identity(event, IdentityText.ASSERTED), [])
        stack.reject_call(event, 486)

    async def test_a_call_redirected_is_answered_3xx_with_where_to_go_and_why(self) -> None:
        stack = self.stack()
        stack.add_account("sip:bob@sipral.invalid", registrar_address=self.far.address)
        self.far.send(self.far.invite(stack.bind_address), stack.bind_address)
        event = await self.next_event(stack, EventKind.INCOMING_CALL)

        with self.assertRaises(SipralError) as refused:
            stack.redirect_call(event, ["sip:carol@example.com"], status_code=486)
        self.assertEqual(refused.exception.status, Status.INVALID_ARGUMENT)

        stack.redirect_call(
            event, ["sip:carol@example.com", "tel:+15550001111"], reason="no-answer"
        )
        answer = await self.far.receive("SIP/2.0 302 ")
        self.assertEqual(_header("Contact", answer), "<sip:carol@example.com>, <tel:+15550001111>")
        diversion = _header("Diversion", answer)
        self.assertIsNotNone(diversion)
        self.assertIn(";reason=no-answer", diversion)


class ACallSaysWhyItEnded(_WithAFarEnd):
    async def test_a_cancel_for_a_call_answered_elsewhere_is_not_a_missed_call(self) -> None:
        stack = self.stack()
        stack.add_account("sip:bob@sipral.invalid", registrar_address=self.far.address)
        self.far.send(self.far.invite(stack.bind_address), stack.bind_address)
        await self.next_event(stack, EventKind.INCOMING_CALL)
        self.far.send(
            self.far.cancel(
                stack.bind_address, 'Reason: SIP ;cause=200 ;text="Call completed elsewhere"\r\n'
            ),
            stack.bind_address,
        )
        ended = await self.next_event(stack, EventKind.CALL_ENDED)
        self.assertEqual(ended.cause.sip, 200)
        self.assertEqual(ended.cause.q850, 0)
        self.assertEqual(ended.cause.text, "Call completed elsewhere")

    async def test_a_hangup_for_a_reason_writes_it_on_the_bye(self) -> None:
        stack = self.stack()
        account = stack.add_account("sip:alice@sipral.invalid", registrar_address=self.far.address)
        call = stack.place_call(account, f"sip:bob@{self.far.address}")
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        invite = await self.far.receive("INVITE ")
        body = self.far.sdp()
        copied = [
            f"{name}: {_header(name, invite)}" for name in ("Via", "From", "Call-ID", "CSeq")
        ]
        answer = "\r\n".join(
            [
                "SIP/2.0 200 OK",
                *copied,
                f"To: {_header('To', invite)};tag=far",
                f"Contact: <sip:bob@{self.far.address}>",
                "Content-Type: application/sdp",
                f"Content-Length: {len(body)}",
                "",
                body,
            ]
        )
        via_port = re.search(r"127\.0\.0\.1:(\d+)", _header("Via", invite)).group(1)
        self.far.send(answer, f"127.0.0.1:{via_port}")
        while True:
            event = await asyncio.wait_for(call.events.get(), timeout=5)
            if event.kind == EventKind.CALL_CONFIRMED:
                break

        call.hangup_for(q850_cause=16, text="Normal call clearing")
        bye = await self.far.receive("BYE ")
        self.assertEqual(_header("Reason", bye), 'Q.850;cause=16;text="Normal call clearing"')


class AnAccountSaysWhatItAsksFor(_WithAFarEnd):
    async def test_its_session_timer_its_anonymity_and_whom_it_trusts(self) -> None:
        stack = self.stack()
        account = stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=self.far.address,
            session_timer=SessionTimer.INTERVAL,
            session_interval_seconds=120,
            privacy=Privacy.ID,
            trusted_peers="127.0.0.1",
        )
        call = stack.place_call(account, f"sip:bob@{self.far.address}")
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        invite = await self.far.receive("INVITE ")
        self.assertEqual(_header("Session-Expires", invite), "120")
        self.assertIn("anonymous@anonymous.invalid", _header("From", invite))
        self.assertEqual(_header("Privacy", invite), "id")
        self.assertEqual(
            _header("P-Asserted-Identity", invite),
            "<sip:alice@sipral.invalid>",
            "the trusted peer is still told who is calling",
        )

    async def test_an_option_out_of_range_is_refused(self) -> None:
        stack = self.stack()
        for options in (
            {"session_timer": SessionTimer.INTERVAL, "session_interval_seconds": 30},
            {"trusted_peers": ["proxy.example.com"]},
        ):
            with self.subTest(options=options), self.assertRaises(SipralError) as refused:
                stack.add_account(
                    "sip:alice@sipral.invalid", registrar_address=self.far.address, **options
                )
            self.assertEqual(refused.exception.status, Status.INVALID_ARGUMENT)


if __name__ == "__main__":
    unittest.main()
