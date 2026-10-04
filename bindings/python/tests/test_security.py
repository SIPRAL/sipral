# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""STIR/SHAKEN, the SRTP policy per account and the encryption report,
through this package: two stacks on 127.0.0.1 with no registrar between
them, one signing the call it places and the other verifying it.

A certificate chain cannot be made here without a cryptography package this
binding does not depend on, so a valid signature is verified against the
chain the C ABI's tests keep in `bindings/fixtures/stir-provider-709J`, whose
signing certificate names a service provider code and no number. Beside
that, what this proves is the plumbing every half of it runs through: the
account's signing key and URL reach the INVITE, the verifying stack asks for
the certificate by `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
:meth:`Stack.stir_certificate` answers it, and a strict account refuses what
does not verify.
"""

from __future__ import annotations

import asyncio
import pathlib
import unittest

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.enums import (
    AudioMode,
    EventKind,
    KeyExchange,
    StirVerification,
    VerificationFailure,
    VerificationOutcome,
    VerificationStage,
)

#: short, and the stacks below offer one codec: a signed INVITE is some
#: five hundred octets longer than an unsigned one, and past RFC 3261
#: Section 18.1.1's 1300 it needs a stream transport this test does not open
_URL = "https://c.test/p"
#: a P-256 private key as the bare scalar: any 32 octets below the group
#: order are one, and these are nobody's
_KEY = bytes([0x2B]) * 32
#: the credentials `sipral_stir::testing` issues for the service provider
#: code 709J, checked against it by the C ABI's own tests: a root, a chain
#: whose signing certificate names that code and no number, and its key
_PROVIDER = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "stir-provider-709J"
#: a moment inside every certificate of that chain
_WITHIN = 1_790_000_000


class _TwoStacks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.caller = Stack(loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.callee = Stack(loop=loop, audio=AudioMode.APPLICATION, codecs="PCMU")
        self.addAsyncCleanup(asyncio.to_thread, self.caller.close)
        self.addAsyncCleanup(asyncio.to_thread, self.callee.close)

    async def next_event(self, stack: Stack, kind: int):
        while True:
            event = await asyncio.wait_for(stack.events.get(), timeout=5)
            if event.kind == kind:
                return event


class ACallerIsVerifiedBeforeThePhoneRings(_TwoStacks):
    async def test_a_signed_call_asks_for_its_certificate_and_a_strict_account_refuses_it(
        self,
    ) -> None:
        # a stack that only signs is given the time, and no anchors
        self.caller.stir(None)
        self.callee.stir(None)
        signing = self.caller.add_account(
            "sip:+12155551212@a.test",
            registrar_address=self.callee.bind_address,
            stir_key=_KEY,
            stir_certificate_url=_URL,
        )
        self.callee.add_account(
            "sip:12125551213@b.test",
            registrar_address=self.caller.bind_address,
            stir_verification=StirVerification.STRICT,
        )
        call = self.caller.place_call(
            signing, f"sip:12125551213@{self.callee.bind_address}"
        )
        self.addAsyncCleanup(asyncio.to_thread, call.close)

        wanted = await self.next_event(self.callee, EventKind.CALLER_VERIFICATION)
        asked = wanted.verification
        self.assertEqual(asked.stage, VerificationStage.CERTIFICATE_WANTED)
        self.assertEqual(asked.certificate_url, _URL)

        # a certificate that could not be had: RFC 8224's 436, sent
        self.callee.stir_certificate(wanted.call, None)
        verdict = (await self.next_event(self.callee, EventKind.CALLER_VERIFICATION)).verification
        self.assertEqual(verdict.stage, VerificationStage.VERIFIED)
        self.assertEqual(verdict.outcome, VerificationOutcome.INVALID)
        self.assertEqual(verdict.failure, VerificationFailure.CERTIFICATE_UNAVAILABLE)
        self.assertEqual(verdict.response_code, 436)
        self.assertTrue(verdict.refused)
        ended = await self.next_event(self.caller, EventKind.CALL_ENDED)
        self.assertEqual(ended.fields["status_code"], 436)


class AServiceProviderCodeCoversOnlyWhenTheStackSaysSo(_TwoStacks):
    async def verdict(self, *, accept_service_provider_codes: bool):
        self.caller.stir(None, unix_seconds=_WITHIN)
        self.callee.stir(
            (_PROVIDER / "anchor.pem").read_bytes(),
            unix_seconds=_WITHIN,
            accept_service_provider_codes=accept_service_provider_codes,
        )
        signing = self.caller.add_account(
            "sip:+12155551212@a.test",
            registrar_address=self.callee.bind_address,
            stir_key=bytes.fromhex((_PROVIDER / "signing-scalar.hex").read_text().strip()),
            stir_certificate_url=_URL,
        )
        self.callee.add_account(
            "sip:12125551213@b.test",
            registrar_address=self.caller.bind_address,
        )
        call = self.caller.place_call(
            signing, f"sip:12125551213@{self.callee.bind_address}"
        )
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        wanted = await self.next_event(self.callee, EventKind.CALLER_VERIFICATION)
        self.assertEqual(wanted.verification.stage, VerificationStage.CERTIFICATE_WANTED)
        self.callee.stir_certificate(wanted.call, (_PROVIDER / "chain.pem").read_bytes())
        verdict = await self.next_event(self.callee, EventKind.CALLER_VERIFICATION)
        self.assertEqual(verdict.verification.stage, VerificationStage.VERIFIED)
        return verdict.verification

    async def test_a_certificate_naming_only_a_code_covers_no_number_by_default(self) -> None:
        verdict = await self.verdict(accept_service_provider_codes=False)
        self.assertEqual(verdict.outcome, VerificationOutcome.INVALID)
        self.assertEqual(verdict.failure, VerificationFailure.NUMBER_NOT_COVERED)

    async def test_a_stack_that_accepts_codes_verifies_the_caller(self) -> None:
        verdict = await self.verdict(accept_service_provider_codes=True)
        self.assertEqual(verdict.outcome, VerificationOutcome.VALID)


class EachAccountHoldsItsCallsToItsOwnPolicy(_TwoStacks):
    async def test_an_sdes_call_reports_how_it_is_protected(self) -> None:
        required = int(lib.SIPRAL_SRTP_REQUIRED)
        placing = self.caller.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=self.callee.bind_address,
            srtp=required,
            srtp_suites=["AES_CM_128_HMAC_SHA1_80"],
        )
        self.callee.add_account(
            "sip:bob@sipral.invalid",
            registrar_address=self.caller.bind_address,
            srtp=required,
        )
        call = self.caller.place_call(placing, f"sip:bob@{self.callee.bind_address}")
        incoming = await self.next_event(self.callee, EventKind.INCOMING_CALL)
        answered = self.callee.answer_call(incoming)
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        self.addAsyncCleanup(asyncio.to_thread, answered.close)

        started = await self.next_event(self.caller, EventKind.MEDIA_STARTED)
        self.assertEqual(started.protection.key_exchange, KeyExchange.SDES)
        self.assertTrue(started.protection.encrypted)
        self.assertEqual(started.protection.suite, int(lib.SIPRAL_SRTP_SUITE_AES_CM80))
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=5)
        report = call.media.encryption()
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0].key_exchange, KeyExchange.SDES)
        self.assertTrue(report[0].encrypted)
        self.assertFalse(report[0].authenticated, "SDES authenticates nothing")

    async def test_a_suite_no_srtp_names_is_refused_where_it_is_given(self) -> None:
        from sipral import SipralError

        with self.assertRaises(SipralError):
            self.caller.add_account(
                "sip:alice@sipral.invalid",
                registrar_address=self.callee.bind_address,
                srtp_suites="AES_CM_128_HMAC_SHA1_80,NOT_A_SUITE",
            )


if __name__ == "__main__":
    unittest.main()
