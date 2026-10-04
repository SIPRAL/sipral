# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Where a stack is reached and where its server is, through the Python
layer: the address a stack advertises when the application names none, a
server named by a URI and located by RFC 3263, the account's keep-alive, a
certificate trusted by its fingerprint, and the diagnostic trace.

The registrar here is this test's own, a UDP socket on loopback that answers
every REGISTER 200 and records what arrived, keep-alives included.
"""

from __future__ import annotations

import asyncio
import hashlib
import pathlib
import socket
import threading
import time
import unittest

from sipral import (
    SipralError,
    Stack,
    advertised_address,
    lookup,
)
from sipral._sipral_cffi import lib
from sipral.enums import (
    AudioMode,
    DnsAnswer,
    DnsRecordType,
    EventKind,
    LocateFailure,
    LogLevel,
    RegistrationFailure,
    RegistrationState,
    Srtp,
    Status,
)
from sipral.signalling import parse_pin
from sipral.stack import route_host


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return None


class _Registrar:
    """A registrar on a loopback UDP port: every REGISTER is answered 200,
    and :attr:`received` holds every datagram, as text."""

    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.05)
        self.port = self._socket.getsockname()[1]
        self.address = f"127.0.0.1:{self.port}"
        self.received: list[str] = []
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._socket.recvfrom(65536)
            except (socket.timeout, OSError):
                continue
            message = data.decode("utf-8", "replace")
            self.received.append(message)
            if message.startswith("REGISTER "):
                lines = ["SIP/2.0 200 OK"]
                for name in ("Via", "From", "To", "Call-ID", "CSeq"):
                    value = _header(name, message)
                    if name == "To":
                        value = f"{value};tag=registrar"
                    lines.append(f"{name}: {value}")
                lines.append(f"Contact: {_header('Contact', message)};expires=3600")
                lines.append("Content-Length: 0")
                self._socket.sendto(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"), peer)

    def registers(self) -> list[str]:
        return [message for message in self.received if message.startswith("REGISTER ")]

    def close(self) -> None:
        self._stop.set()
        self._socket.close()


class _Case(unittest.IsolatedAsyncioTestCase):
    def registrar(self) -> _Registrar:
        registrar = _Registrar()
        self.addCleanup(registrar.close)
        return registrar

    def stack(self, **options) -> Stack:
        stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION, **options)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def next_event(self, stack: Stack, kind: int, seconds: float = 5.0):
        while True:
            event = await asyncio.wait_for(stack.events.get(), timeout=seconds)
            if event.kind == kind:
                return event

    async def registered(self, stack: Stack, seconds: float = 5.0) -> None:
        while True:
            event = await self.next_event(stack, EventKind.REGISTRATION_CHANGED, seconds)
            if event.fields.get("state") == RegistrationState.REGISTERED:
                return

    async def until(self, what, seconds: float = 5.0) -> bool:
        deadline = time.monotonic() + seconds
        while not what() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        return bool(what())


class AStackGivenNoAddressAdvertisesTheRoute(_Case):
    def test_the_address_of_a_wildcard_socket_is_the_route_toward_the_peer(self) -> None:
        self.assertEqual(advertised_address("0.0.0.0:5060", "127.0.0.1:5070"), "127.0.0.1:5060")
        with self.assertRaises(SipralError) as refused:
            advertised_address("127.0.0.1:5060", "192.0.2.1:5060")
        self.assertEqual(refused.exception.status, Status.UNREACHABLE_ADDRESS)
        self.assertEqual(route_host("pbx.example.com:5060"), "127.0.0.1", "a name has no route")

    async def test_an_account_on_loopback_registers_from_loopback(self) -> None:
        registrar = self.registrar()
        stack = self.stack()
        self.assertEqual(stack._socket.getsockname()[0], "0.0.0.0", "listening on every interface")
        account = stack.add_account(
            "sip:alice@example.com", registrar="sip:example.com", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)
        contact = _header("Contact", registrar.registers()[0])
        self.assertIn(f"@127.0.0.1:{stack._socket.getsockname()[1]}", contact)

    async def test_an_account_on_the_network_is_reached_at_the_route_toward_its_server(self) -> None:
        stack = self.stack()
        remote = "192.0.2.1:5060"
        route = route_host(remote)
        if route == "127.0.0.1":
            self.skipTest("this machine has no route off itself")
        account = stack.add_account(
            "sip:alice@example.com", registrar="sip:example.com", registrar_address=remote
        )
        self.assertEqual(account.advertised, f"{route}:{stack._socket.getsockname()[1]}")
        self.assertEqual(stack.bind_address, account.advertised, "and the stack's Via with it")

    def test_a_loopback_contact_toward_a_registrar_elsewhere_is_refused_with_nothing_sent(self) -> None:
        with Stack(audio=AudioMode.APPLICATION, bind_host="127.0.0.1") as stack:
            account = stack.add_account(
                "sip:alice@example.com", registrar="sip:example.com", registrar_address="192.0.2.1:5060"
            )
            with self.assertRaises(SipralError) as refused:
                account.register()
            self.assertEqual(refused.exception.status, Status.UNREACHABLE_ADDRESS)
            self.assertEqual(RegistrationFailure.UNREACHABLE_CONTACT, 5)

    async def test_a_call_between_two_stacks_that_named_nothing_carries_media_on_loopback(self) -> None:
        alice = self.stack()
        bob = self.stack()
        to_bob = alice.add_account("sip:alice@example.com", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@example.com", registrar_address=alice.bind_address)
        call = alice.place_call(to_bob, "sip:bob@example.com")
        self.assertTrue(call.media_address.startswith("127.0.0.1:"), call.media_address)
        incoming = await self.next_event(bob, EventKind.INCOMING_CALL)
        answered = bob.answer_call(incoming)
        self.assertTrue(answered.media_address.startswith("127.0.0.1:"), answered.media_address)
        await self.next_event(alice, EventKind.CALL_CONFIRMED)


class AServerNamedByAUriIsLocated(_Case):
    async def test_a_host_with_a_port_is_asked_for_its_addresses_and_registered_with(self) -> None:
        registrar = self.registrar()
        stack = self.stack()
        account = stack.add_account(
            "sip:alice@example.com", registrar="sip:example.com", server_uri=f"sip:localhost:{registrar.port}"
        )
        account.register()
        located = await self.next_event(stack, EventKind.LOCATED)
        self.assertIn(f"127.0.0.1:{registrar.port}", located.fields["targets"].split(","))
        await self.registered(stack)
        self.assertEqual(len(registrar.registers()), 1)

    async def test_an_srv_answer_names_the_host_and_port_the_requests_go_to(self) -> None:
        registrar = self.registrar()
        asked: list[tuple[str, int]] = []

        def resolver(name: str, record: int) -> tuple[int, list[str]]:
            asked.append((name, record))
            if record == DnsRecordType.SRV and name == "_sip._udp.pbx.sipral.test":
                return DnsAnswer.RECORDS, [f"300 10 60 {registrar.port} host.sipral.test"]
            if record == DnsRecordType.A and name == "host.sipral.test":
                return DnsAnswer.RECORDS, ["300 127.0.0.1"]
            return DnsAnswer.NOTHING, []

        stack = self.stack(resolver=resolver)
        account = stack.add_account(
            "sip:alice@pbx.sipral.test", registrar="sip:pbx.sipral.test", server_uri="sip:pbx.sipral.test"
        )
        account.register()
        located = await self.next_event(stack, EventKind.LOCATED)
        self.assertEqual(located.fields["targets"].split(",")[0], f"127.0.0.1:{registrar.port}")
        self.assertIn(("_sip._udp.pbx.sipral.test", DnsRecordType.SRV), asked)
        await self.registered(stack)
        self.assertEqual(account.registrar_address, f"127.0.0.1:{registrar.port}")

    async def test_a_name_with_no_address_is_a_located_failure_that_says_why(self) -> None:
        stack = self.stack(resolver=lambda name, record: (DnsAnswer.NOTHING, []))
        account = stack.add_account("sip:alice@example.com", registrar="sip:example.com", server_uri="sip:nowhere.sipral.test")
        account.register()
        failed = await self.next_event(stack, EventKind.LOCATE_FAILED)
        self.assertEqual(failed.fields["failure"], LocateFailure.NOT_FOUND)
        self.assertGreater(failed.fields["retry_in_ms"], 0)

    def test_the_platform_lookup_has_no_srv_and_finds_localhost(self) -> None:
        self.assertEqual(lookup("_sip._udp.example.com", DnsRecordType.SRV), (DnsAnswer.NOTHING, []))
        answer, records = lookup("localhost", DnsRecordType.A)
        self.assertEqual(answer, DnsAnswer.RECORDS)
        self.assertIn("60 127.0.0.1", records)

    def test_exactly_one_of_the_two_names_the_server(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            with self.assertRaises(ValueError):
                stack.add_account("sip:alice@example.com")
            with self.assertRaises(ValueError):
                stack.add_account("sip:alice@example.com", registrar_address="127.0.0.1:5060", server_uri="sip:a.test")


class AnAccountKeepsItsFlowOpen(_Case):
    async def test_a_double_crlf_goes_to_the_registrar_at_the_interval(self) -> None:
        registrar = self.registrar()
        stack = self.stack()
        account = stack.add_account(
            "sip:alice@example.com",
            registrar="sip:example.com",
            registrar_address=registrar.address,
            keepalive_ms=1000,
        )
        account.register()
        await self.registered(stack)
        self.assertTrue(await self.until(lambda: "\r\n\r\n" in registrar.received, seconds=3.0), registrar.received)

    def test_an_interval_under_a_second_is_refused(self) -> None:
        with Stack(audio=AudioMode.APPLICATION) as stack:
            with self.assertRaises(SipralError) as refused:
                stack.add_account("sip:alice@example.com", registrar_address="127.0.0.1:5060", keepalive_ms=999)
            self.assertEqual(refused.exception.status, Status.INVALID_ARGUMENT)


class ACertificateIsTrustedByItsFingerprint(unittest.TestCase):
    def test_every_form_an_administrator_copies_is_read(self) -> None:
        """Every line of ``bindings/fixtures/pin-forms.txt``, the list each
        layer's parser is held to."""
        listed = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "pin-forms.txt"
        digest = b""
        checked = 0
        for line in listed.read_text(encoding="utf-8").split("\n"):
            if not line or line.startswith("#"):
                continue
            verdict, _, text = line.partition("\t")
            if verdict == "digest":
                digest = bytes.fromhex(text)
            elif verdict == "accept":
                self.assertEqual(parse_pin(text), digest, text)
                checked += 1
            else:
                with self.assertRaises(ValueError, msg=text):
                    parse_pin(text)
                checked += 1
        self.assertEqual(len(digest), 32)
        self.assertGreater(checked, 20)

    def test_the_accounts_pin_decides_on_the_certificate_a_server_presented(self) -> None:
        certificate = b"the DER bytes of a leaf"
        pin = "SHA256=" + ":".join(f"{byte:02X}" for byte in hashlib.sha256(certificate).digest())
        with Stack(audio=AudioMode.APPLICATION) as stack:
            pinned = stack.add_account("sip:alice@example.com", registrar_address="127.0.0.1:5060", tls_pin=pin)
            verdict = pinned.check_certificate(certificate)
            self.assertIsNotNone(verdict)
            self.assertFalse(verdict.expired)
            with self.assertRaises(SipralError) as refused:
                pinned.check_certificate(b"another certificate")
            self.assertEqual(refused.exception.status, Status.CERTIFICATE_REFUSED)
            unpinned = stack.add_account("sip:bob@example.com", registrar_address="127.0.0.1:5060")
            self.assertIsNone(unpinned.check_certificate(certificate))
            with self.assertRaises(SipralError):
                stack.add_account("sip:carol@example.com", registrar_address="127.0.0.1:5060", tls_pin="00")


class TheStacksNewOptionsReachTheLibrary(_Case):
    def test_a_suite_the_library_does_not_run_and_a_short_salt_are_refused(self) -> None:
        with self.assertRaises(SipralError) as suite:
            Stack(audio=AudioMode.APPLICATION, srtp_suites="NOT_A_SUITE")
        self.assertEqual(suite.exception.status, Status.INVALID_ARGUMENT)
        with self.assertRaises(SipralError) as salt:
            Stack(audio=AudioMode.APPLICATION, pseudonym_salt=b"short")
        self.assertEqual(salt.exception.status, Status.INVALID_ARGUMENT)
        with Stack(
            audio=AudioMode.APPLICATION,
            srtp=Srtp.BEST_EFFORT,
            srtp_suites=["AES_CM_128_HMAC_SHA1_80"],
            pseudonym_salt=bytes(range(16)),
        ):
            pass

    async def test_the_trace_writes_whole_messages_only_while_the_diagnostic_trace_is_on(self) -> None:
        registrar = self.registrar()
        stack = self.stack()
        lines: list[str] = []
        stack.set_log(LogLevel.TRACE, lambda level, target, message, suppressed: lines.append(message))
        account = stack.add_account(
            "sip:alice@example.com", registrar="sip:example.com", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)
        self.assertFalse([line for line in lines if "sip:alice@example.com" in line], "pseudonymised")
        stack.set_diagnostic_trace(True)
        account.register()
        self.assertTrue(
            await self.until(lambda: [line for line in lines if "sip:alice@example.com" in line]),
            "a whole REGISTER, the AOR as it went on the wire",
        )

    async def test_best_effort_offers_keys_on_plain_rtp(self) -> None:
        alice = self.stack(srtp=Srtp.BEST_EFFORT)
        bob = self.stack()
        to_bob = alice.add_account("sip:alice@example.com", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@example.com", registrar_address=alice.bind_address)
        alice.place_call(to_bob, "sip:bob@example.com")
        incoming = await self.next_event(bob, EventKind.INCOMING_CALL)
        offer = incoming.message.decode("utf-8")
        self.assertIn("RTP/AVP", offer)
        self.assertNotIn("RTP/SAVP", offer)
        self.assertIn("a=crypto:", offer)


if __name__ == "__main__":
    unittest.main()
