# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Per-account stream connections beside UDP accounts, per-call gain and
mute in device mode (devices closed), and ``Stack.settings()``.
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import ssl
import tempfile
import time
import unittest

from sipral import SipralError, Stack, features
from sipral._sipral_cffi import lib
from sipral.enums import (
    AudioActivation,
    AudioDirection,
    AudioMode,
    EventKind,
    Feature,
    RegistrationState,
    SrtpSuite,
    Transport,
)

from .test_reachability import _Registrar as _DatagramRegistrar
from .test_signalling import _SERVER_NAME, _certificate, _header
from .test_signalling import _Registrar as _StreamRegistrar


class _Case(unittest.IsolatedAsyncioTestCase):
    def stack(self, **options) -> Stack:
        options.setdefault("audio", AudioMode.APPLICATION)
        stack = Stack(loop=asyncio.get_running_loop(), bind_host="127.0.0.1", **options)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def until(self, what, seconds: float = 8.0) -> bool:
        deadline = time.monotonic() + seconds
        while not what() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        return bool(what())


class AnAccountOnAConnectionOfItsOwn(_Case):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.mkdtemp()
        cls._good = _certificate(cls._directory, "account", "-days", "1")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._directory, ignore_errors=True)

    async def test_one_over_tls_and_one_over_udp_each_reach_their_own_server(self) -> None:
        if self._good is None:
            self.skipTest("no openssl command to make the registrar's certificate with")
        udp_registrar = _DatagramRegistrar()
        self.addCleanup(udp_registrar.close)
        tls_registrar = _StreamRegistrar(self._good)
        self.addCleanup(tls_registrar.close)
        with open(self._good[0], encoding="ascii") as pem:
            der = ssl.PEM_cert_to_DER_cert(pem.read())
        pin = "sha256 Fingerprint=" + ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())

        # The account's own connection opens even with stream_fallback off.
        stack = self.stack(stream_fallback=False)
        over_udp = stack.add_account(
            "sip:alice@udp.sipral.test", registrar="sip:udp.sipral.test", registrar_address=udp_registrar.address
        )
        over_tls = stack.add_account(
            f"sip:bob@{_SERVER_NAME}",
            registrar=f"sip:{_SERVER_NAME}",
            registrar_address=tls_registrar.address,
            tls_pin=pin,
            stream_protocol=Transport.TLS,
        )
        self.assertEqual(over_tls.stream_protocol, Transport.TLS)
        self.assertEqual(over_udp.stream_protocol, 0)
        over_udp.register()
        over_tls.register()
        self.assertTrue(await self.until(lambda: over_udp.registration_state == RegistrationState.REGISTERED))
        self.assertTrue(await self.until(lambda: over_tls.registration_state == RegistrationState.REGISTERED))

        wanted = []
        while not stack.events.empty():
            event = stack.events.get_nowait()
            if event.kind == EventKind.TRANSPORT_WANTED:
                wanted.append(event.fields)
        self.assertEqual(len(wanted), 1, wanted)
        self.assertEqual(wanted[0]["protocol"], Transport.TLS)
        self.assertEqual(wanted[0]["destination"], tls_registrar.address)
        self.assertEqual(wanted[0]["request_bytes"], 0)
        [(connection, register)] = tls_registrar.registers()
        self.assertTrue(_header("Via", register).startswith("SIP/2.0/TLS "), register)
        self.assertIn(";transport=tls", _header("Contact", register))
        self.assertIn("sip:bob@", register)
        self.assertTrue(udp_registrar.registers())
        self.assertTrue(all("sip:alice@" in one for one in udp_registrar.registers()))

        first = stack.place_call(over_udp, "sip:carol@udp.sipral.test")
        second = stack.place_call(over_tls, f"sip:dave@{_SERVER_NAME}")
        self.addAsyncCleanup(asyncio.to_thread, first.close)
        self.addAsyncCleanup(asyncio.to_thread, second.close)
        self.assertTrue(
            await self.until(lambda: any(m.startswith("INVITE sip:carol@") for m in udp_registrar.received)),
            "the UDP account's call never reached its server",
        )
        self.assertTrue(
            await self.until(lambda: any(m.startswith("INVITE sip:dave@") for _, m in tls_registrar.requests)),
            "the TLS account's call never reached its server",
        )
        number, invite = next((n, m) for n, m in tls_registrar.requests if m.startswith("INVITE "))
        self.assertEqual(number, connection, "the call went over the account's own connection")
        self.assertTrue(_header("Via", invite).startswith("SIP/2.0/TLS "), invite)
        self.assertFalse(any("dave@" in m for m in udp_registrar.received))
        self.assertFalse(any("carol@" in m for _, m in tls_registrar.requests))

    async def test_one_over_tcp_is_opened_again_when_its_server_drops_the_connection(self) -> None:
        registrar = _StreamRegistrar()
        self.addCleanup(registrar.close)
        stack = self.stack()
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}",
            registrar=f"sip:{_SERVER_NAME}",
            registrar_address=registrar.address,
            stream_protocol=Transport.TCP,
        )
        account.register()
        self.assertTrue(await self.until(lambda: account.registration_state == RegistrationState.REGISTERED))
        [(_, register)] = registrar.registers()
        self.assertTrue(_header("Via", register).startswith("SIP/2.0/TCP "), register)
        self.assertIn(";transport=tcp", _header("Contact", register))

        registrar.drop()
        self.assertTrue(
            await self.until(lambda: any(number == 2 for number, _ in registrar.registers())),
            "the account did not register again over a new connection",
        )

    async def test_only_a_stream_on_a_stack_that_signals_over_udp_is_taken(self) -> None:
        stack = self.stack()
        with self.assertRaises(ValueError):
            stack.add_account(
                "sip:alice@example.com", registrar_address="127.0.0.1:5060", stream_protocol=Transport.UDP
            )


class TheSettingsAreReadBack(_Case):
    async def test_with_the_defaults_filled_in_and_what_was_given(self) -> None:
        defaults = self.stack().settings()
        self.assertEqual(defaults.transport, Transport.UDP)
        self.assertTrue(defaults.retransmits)
        self.assertTrue(defaults.system_echo_cancellation)
        self.assertFalse(defaults.pseudonym_salted)
        self.assertFalse(defaults.diagnostic_trace)
        self.assertTrue(defaults.srtp_suites, "this build's own suites")
        self.assertGreater(defaults.codec_count, 0)
        self.assertIsNone(defaults.rtp_ports)

        given = self.stack(
            rtp_port_min=40000,
            rtp_port_max=40100,
            srtp_suites=["AES_CM_128_HMAC_SHA1_32", "AES_CM_128_HMAC_SHA1_80"],
            pseudonym_salt=bytes([7]) * 16,
            diagnostic_trace=True,
            system_echo_cancellation=False,
        )
        settings = given.settings()
        self.assertEqual(settings.srtp_suites, (SrtpSuite.AES_CM32, SrtpSuite.AES_CM80))
        self.assertTrue(settings.pseudonym_salted)
        self.assertTrue(settings.diagnostic_trace)
        self.assertFalse(settings.system_echo_cancellation)
        self.assertEqual(settings.rtp_ports, (40000, 40100))
        given.set_diagnostic_trace(False)
        self.assertFalse(given.settings().diagnostic_trace)


@unittest.skipUnless(Feature.AUDIO_DEVICE in features(), "this build has no audio engine for this platform")
class ACallsOwnGainAndMute(_Case):
    async def test_last_from_its_media_to_its_end(self) -> None:
        alice = self.stack(audio=AudioMode.DEVICE, audio_activation=AudioActivation.MANUAL)
        bob = self.stack()
        account = alice.add_account("sip:alice@sipral.invalid", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@sipral.invalid", registrar_address=alice.bind_address)
        call = alice.place_call(account, f"sip:bob@{bob.bind_address}")
        self.addAsyncCleanup(asyncio.to_thread, call.close)
        with self.assertRaises(SipralError) as early:
            alice.audio.set_gain(AudioDirection.OUTPUT, 0.5, call=call)
        self.assertEqual(early.exception.status, lib.SIPRAL_STATUS_WRONG_STATE)
        answered = None
        while answered is None:
            event = await asyncio.wait_for(bob.events.get(), timeout=5)
            if event.kind == EventKind.INCOMING_CALL:
                answered = bob.answer_call(event)
        self.addAsyncCleanup(asyncio.to_thread, answered.close)
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=5)

        audio = alice.audio
        audio.set_gain(AudioDirection.OUTPUT, 0.5, call=call)
        audio.set_muted(AudioDirection.INPUT, True, call=call)
        self.assertEqual(audio.gain(AudioDirection.OUTPUT, call=call), 0.5)
        self.assertEqual(audio.gain(AudioDirection.INPUT, call=call), 1.0)
        self.assertTrue(audio.muted(AudioDirection.INPUT, call=call))
        self.assertFalse(audio.muted(AudioDirection.OUTPUT, call=call))
        self.assertFalse(audio.muted(AudioDirection.INPUT), "the stack's own mute is another")
        self.assertEqual(audio.level(AudioDirection.OUTPUT, call=call), 0, "the devices are closed")
        with self.assertRaises(SipralError) as application:
            bob.audio.set_muted(AudioDirection.INPUT, True, call=answered)
        self.assertEqual(application.exception.status, lib.SIPRAL_STATUS_WRONG_STATE)

        call.hangup()

        def forgotten() -> bool:
            try:
                audio.gain(AudioDirection.OUTPUT, call=call)
            except SipralError as ended:
                return ended.status == lib.SIPRAL_STATUS_WRONG_STATE
            return False

        self.assertTrue(await self.until(forgotten), "a call that ended still has controls")
