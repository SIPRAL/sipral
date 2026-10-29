# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A client certificate on SIP over TLS through the Python layer.

A registrar in this file requires a client certificate signed by an
authority made for the run with `openssl`, at TLS 1.3 (where the server's
verdict arrives after the client's handshake is over) and at TLS 1.2 (where
it arrives inside it). Checked: the right certificate is presented and the
account registers, on the stack's connection and on an account's own; no
certificate, one from another authority, an expired one and a key that does
not match each arrive as their own `SipralTlsFailure`, the last two before
any connection is made.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import ssl
import subprocess
import tempfile
import unittest

from sipral import Stack, TlsClientCertificate, TlsTrust
from sipral.enums import AudioMode, EventKind, RegistrationState, TlsFailure, Transport, TransportError
from sipral.signalling import ClientCertificateUnusable, ClosedAfterHandshake, certificate_validity, classify

from .test_signalling import _SERVER_NAME, _certificate, _Registrar

_CLIENT_NAME = "alice.sipral.test"


def _openssl(*arguments: str) -> bool:
    openssl = shutil.which("openssl")
    return openssl is not None and subprocess.run([openssl, *arguments], capture_output=True).returncode == 0


def _authority(directory: str, name: str) -> str | None:
    """A self-signed authority's certificate, its key beside it."""
    certificate = os.path.join(directory, f"{name}.pem")
    made = _openssl(
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-days", "1", "-subj", f"/CN={name}",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
        "-keyout", os.path.join(directory, f"{name}.key"), "-out", certificate,
    )
    return certificate if made else None


def _client(directory: str, name: str, authority: str, *dates: str) -> tuple[str, str] | None:
    """A client certificate ``authority`` signed, and its key."""
    key = os.path.join(directory, f"{name}.key")
    request = os.path.join(directory, f"{name}.csr")
    extensions = os.path.join(directory, f"{name}.ext")
    certificate = os.path.join(directory, f"{name}.pem")
    with open(extensions, "w", encoding="ascii") as out:
        out.write(f"subjectAltName=DNS:{_CLIENT_NAME}\nextendedKeyUsage=clientAuth\n")
    made = _openssl(
        "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-subj", f"/CN={_CLIENT_NAME}", "-keyout", key, "-out", request,
    ) and _openssl(
        "x509", "-req", "-in", request, "-CA", authority, "-CAkey", authority[: -len(".pem")] + ".key",
        "-CAcreateserial", "-extfile", extensions, *(dates or ("-days", "1")), "-out", certificate,
    )
    return (certificate, key) if made else None


class _Case(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.mkdtemp()
        d = cls._directory
        cls._server = _certificate(d, "server", "-days", "1")
        cls._authority = _authority(d, "clients")
        cls._other_authority = _authority(d, "strangers")
        cls._good = _client(d, "good", cls._authority) if cls._authority else None
        cls._stranger = _client(d, "stranger", cls._other_authority) if cls._other_authority else None
        cls._expired = (
            _client(d, "expired", cls._authority, "-not_before", "20200101000000Z", "-not_after", "20200102000000Z")
            if cls._authority
            else None
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._directory, ignore_errors=True)

    def setUp(self) -> None:
        if None in (self._server, self._good, self._stranger, self._expired):
            self.skipTest("no openssl command to make the certificates with")

    def registrar(self, version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3) -> _Registrar:
        registrar = _Registrar(self._server, client_authority=self._authority, tls_version=version)
        self.addCleanup(registrar.close)
        return registrar

    def stack(self, registrar: _Registrar, client: TlsClientCertificate | None) -> Stack:
        stack = Stack(
            loop=asyncio.get_running_loop(),
            audio=AudioMode.APPLICATION,
            signalling=Transport.TLS,
            signalling_server=registrar.address,
            tls_server_name=_SERVER_NAME,
            tls_trust=TlsTrust.only_authority(self._server[0]),
            tls_client_certificate=client,
        )
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def next_event(self, stack: Stack, kind: int, seconds: float = 8):
        while True:
            event = await asyncio.wait_for(stack.events.get(), timeout=seconds)
            if event.kind == kind:
                return event

    async def registered(self, account, seconds: float = 8) -> bool:
        deadline = asyncio.get_running_loop().time() + seconds
        while account.registration_state != RegistrationState.REGISTERED:
            if asyncio.get_running_loop().time() > deadline:
                return False
            await asyncio.sleep(0.02)
        return True

    async def failure(self, registrar: _Registrar, client: TlsClientCertificate | None):
        stack = self.stack(registrar, client)
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        event = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertEqual(event.fields["protocol"], Transport.TLS)
        self.assertEqual(registrar.registers(), [], "the registrar took nothing from it")
        return event.fields


class TheCertificateIsPresented(_Case):
    async def check_registers(self, version: ssl.TLSVersion) -> None:
        registrar = self.registrar(version)
        stack = self.stack(registrar, TlsClientCertificate(*self._good))
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        self.assertTrue(await self.registered(account), "never registered")
        self.assertEqual(registrar.client_subjects, [((("commonName", _CLIENT_NAME),),)])
        self.assertEqual(len(registrar.registers()), 1)

    async def test_at_tls_1_3_the_server_takes_it_and_the_account_registers(self) -> None:
        await self.check_registers(ssl.TLSVersion.TLSv1_3)

    async def test_at_tls_1_2_the_server_takes_it_and_the_account_registers(self) -> None:
        await self.check_registers(ssl.TLSVersion.TLSv1_2)

    async def test_an_account_on_a_connection_of_its_own_presents_its_own(self) -> None:
        registrar = self.registrar()
        stack = Stack(loop=asyncio.get_running_loop(), bind_host="127.0.0.1", audio=AudioMode.APPLICATION,
                      tls_trust=TlsTrust.only_authority(self._server[0]), tls_server_name=_SERVER_NAME)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}",
            registrar=f"sip:{_SERVER_NAME}",
            registrar_address=registrar.address,
            stream_protocol=Transport.TLS,
            tls_client_certificate=TlsClientCertificate(*self._good),
        )
        account.register()
        self.assertTrue(await self.registered(account), "never registered")
        self.assertEqual(registrar.client_subjects, [((("commonName", _CLIENT_NAME),),)])

    async def test_an_account_of_its_own_without_one_is_told_the_server_requires_one(self) -> None:
        registrar = self.registrar()
        stack = Stack(loop=asyncio.get_running_loop(), bind_host="127.0.0.1", audio=AudioMode.APPLICATION,
                      tls_trust=TlsTrust.only_authority(self._server[0]), tls_server_name=_SERVER_NAME)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}",
            registrar=f"sip:{_SERVER_NAME}",
            registrar_address=registrar.address,
            stream_protocol=Transport.TLS,
        )
        account.register()
        event = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertEqual(event.fields["tls"], TlsFailure.CLIENT_CERTIFICATE_REQUIRED, event.fields)


class TheApplicationsContextHoldsOneIdentity(_Case):
    # `TlsTrust.from_context` hands every connection the application's one
    # context, and Python's `ssl` holds a certificate per context: one an
    # account loaded there would be presented on every other connection.
    def stack_on(self, context: ssl.SSLContext) -> Stack:
        stack = Stack(loop=asyncio.get_running_loop(), bind_host="127.0.0.1", audio=AudioMode.APPLICATION,
                      tls_trust=TlsTrust.from_context(context), tls_server_name=_SERVER_NAME)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def test_an_accounts_own_is_refused_and_another_account_presents_none(self) -> None:
        first, second = self.registrar(), self.registrar()
        stack = self.stack_on(ssl.create_default_context(cafile=self._server[0]))
        with self.assertRaisesRegex(ValueError, "application's TLS context"):
            stack.add_account(
                f"sip:alice@{_SERVER_NAME}",
                registrar=f"sip:{_SERVER_NAME}",
                registrar_address=first.address,
                stream_protocol=Transport.TLS,
                tls_client_certificate=TlsClientCertificate(*self._good),
            )
        account = stack.add_account(
            f"sip:bob@{_SERVER_NAME}",
            registrar=f"sip:{_SERVER_NAME}",
            registrar_address=second.address,
            stream_protocol=Transport.TLS,
        )
        account.register()
        event = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertEqual(event.fields["tls"], TlsFailure.CLIENT_CERTIFICATE_REQUIRED, event.fields)
        self.assertEqual(second.client_subjects, [], "an account without a certificate presented one")
        self.assertEqual(first.connections, 0)

    async def test_a_pinned_account_presents_its_own_on_a_context_of_its_own(self) -> None:
        registrar = self.registrar()
        stack = self.stack_on(ssl.create_default_context(cafile=self._server[0]))
        with open(self._server[0], encoding="ascii") as pem:
            leaf = ssl.PEM_cert_to_DER_cert(pem.read())
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}",
            registrar=f"sip:{_SERVER_NAME}",
            registrar_address=registrar.address,
            stream_protocol=Transport.TLS,
            tls_pin=hashlib.sha256(leaf).hexdigest(),
            tls_client_certificate=TlsClientCertificate(*self._good),
        )
        account.register()
        self.assertTrue(await self.registered(account), "never registered")
        self.assertEqual(registrar.client_subjects, [((("commonName", _CLIENT_NAME),),)])


class WhyItWasNotTaken(_Case):
    async def test_none_where_the_server_requires_one_is_required(self) -> None:
        fields = await self.failure(self.registrar(), None)
        self.assertEqual(fields["tls"], TlsFailure.CLIENT_CERTIFICATE_REQUIRED, fields)
        self.assertIn("CERTIFICATE_REQUIRED", fields["detail"])

    async def test_each_attempt_again_says_the_same_although_a_register_waits(self) -> None:
        # At TLS 1.3 the refusal follows the handshake; the REGISTER waiting
        # for the connection must not race it onto a reset socket.
        registrar = self.registrar()
        stack = self.stack(registrar, None)
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        reasons = []
        while len(reasons) < 3:
            event = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
            reasons.append(event.fields["tls"])
        self.assertEqual(reasons, [TlsFailure.CLIENT_CERTIFICATE_REQUIRED] * 3)
        self.assertEqual(registrar.registers(), [])

    async def test_one_from_another_authority_is_refused_at_tls_1_3(self) -> None:
        fields = await self.failure(self.registrar(), TlsClientCertificate(*self._stranger))
        self.assertEqual(fields["tls"], TlsFailure.CLIENT_CERTIFICATE_REFUSED, fields)

    async def test_one_from_another_authority_is_refused_at_tls_1_2(self) -> None:
        fields = await self.failure(self.registrar(ssl.TLSVersion.TLSv1_2), TlsClientCertificate(*self._stranger))
        self.assertEqual(fields["tls"], TlsFailure.CLIENT_CERTIFICATE_REFUSED, fields)
        self.assertEqual(fields["error"], TransportError.CONNECTION_RESET)

    async def test_an_expired_one_is_said_before_any_connection(self) -> None:
        registrar = self.registrar()
        fields = await self.failure(registrar, TlsClientCertificate(*self._expired))
        self.assertEqual(fields["tls"], TlsFailure.CLIENT_CERTIFICATE_EXPIRED, fields)
        self.assertEqual(fields["error"], TransportError.OTHER)
        self.assertIn("expired on 2020-01-02", fields["detail"])
        self.assertEqual(registrar.connections, 0, "nothing reached the server")

    async def test_a_key_that_does_not_match_is_unavailable_before_any_connection(self) -> None:
        registrar = self.registrar()
        fields = await self.failure(registrar, TlsClientCertificate(self._good[0], self._stranger[1]))
        self.assertEqual(fields["tls"], TlsFailure.CLIENT_KEY_UNAVAILABLE, fields)
        self.assertEqual(fields["error"], TransportError.OTHER)
        self.assertEqual(registrar.connections, 0, "nothing reached the server")

    async def test_a_key_file_that_is_gone_is_unavailable(self) -> None:
        registrar = self.registrar()
        missing = os.path.join(self._directory, "no-such.key")
        fields = await self.failure(registrar, TlsClientCertificate(self._good[0], missing))
        self.assertEqual(fields["tls"], TlsFailure.CLIENT_KEY_UNAVAILABLE, fields)
        self.assertEqual(registrar.connections, 0)


class TheAlertsAreRead(unittest.TestCase):
    """The mapping alone, without a server."""

    @staticmethod
    def alert(reason: str) -> ssl.SSLError:
        error = ssl.SSLError(1, f"[SSL: {reason}] alert")
        error.reason = reason
        return error

    def test_each_alert_means_what_this_end_presented(self) -> None:
        cases = [
            ("TLSV13_ALERT_CERTIFICATE_REQUIRED", False, TlsFailure.CLIENT_CERTIFICATE_REQUIRED),
            ("SSLV3_ALERT_BAD_CERTIFICATE", False, TlsFailure.CLIENT_CERTIFICATE_REQUIRED),
            ("SSLV3_ALERT_BAD_CERTIFICATE", True, TlsFailure.CLIENT_CERTIFICATE_REFUSED),
            ("TLSV1_ALERT_UNKNOWN_CA", True, TlsFailure.CLIENT_CERTIFICATE_REFUSED),
            ("TLSV1_ALERT_ACCESS_DENIED", True, TlsFailure.CLIENT_CERTIFICATE_REFUSED),
            ("SSLV3_ALERT_CERTIFICATE_REVOKED", True, TlsFailure.CLIENT_CERTIFICATE_REFUSED),
            ("SSLV3_ALERT_CERTIFICATE_EXPIRED", True, TlsFailure.CLIENT_CERTIFICATE_EXPIRED),
            ("SSLV3_ALERT_HANDSHAKE_FAILURE", False, TlsFailure.HANDSHAKE_REFUSED),
            ("SSLV3_ALERT_HANDSHAKE_FAILURE", True, TlsFailure.HANDSHAKE_REFUSED),
            ("WRONG_VERSION_NUMBER", True, TlsFailure.HANDSHAKE_REFUSED),
        ]
        for reason, presented, expected in cases:
            with self.subTest(reason=reason, presented=presented):
                _, tls, _ = classify(self.alert(reason), presented)
                self.assertEqual(tls, expected)

    def test_a_certificate_that_cannot_be_presented_is_its_own_reason(self) -> None:
        error, tls, detail = classify(ClientCertificateUnusable(TlsFailure.CLIENT_KEY_UNAVAILABLE, "locked"))
        self.assertEqual((error, tls, detail), (TransportError.OTHER, TlsFailure.CLIENT_KEY_UNAVAILABLE, "locked"))

    def test_a_silent_close_after_the_handshake_refuses_only_a_presented_certificate(self) -> None:
        # Asterisk refuses a certificate its authority did not sign this way
        closed = ClosedAfterHandshake("the server closed the connection after the handshake")
        error, tls, detail = classify(closed, True)
        self.assertEqual((error, tls), (TransportError.CONNECTION_RESET, TlsFailure.CLIENT_CERTIFICATE_REFUSED))
        self.assertIn("no alert", detail)
        self.assertEqual(classify(closed, False)[1], TlsFailure.NONE)

    def test_both_kinds_of_date_are_read(self) -> None:
        # RFC 5280 Section 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050.
        def element(tag: int, body: bytes) -> bytes:
            return bytes([tag, len(body)]) + body

        validity = element(0x30, element(0x17, b"200101000000Z") + element(0x18, b"20510102030405Z"))
        tbs = element(0x30, element(0xA0, element(0x02, b"\x02")) + element(0x02, b"\x01")
                      + element(0x30, b"") + element(0x30, b"") + validity)
        not_before, not_after = certificate_validity(element(0x30, tbs))
        self.assertEqual(not_before.isoformat(), "2020-01-01T00:00:00+00:00")
        self.assertEqual(not_after.isoformat(), "2051-01-02T03:04:05+00:00")


if __name__ == "__main__":
    unittest.main()
