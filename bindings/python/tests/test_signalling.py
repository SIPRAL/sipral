# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""SIP over TCP and TLS through the Python layer: ``Stack(signalling=...)``.

The registrar here is this test's own, on loopback: a TCP listener, over TLS
when given a certificate, that frames what arrives on `Content-Length`
(RFC 3261 Section 18.3) and answers every REGISTER 200. Its certificates are
made for each run with the `openssl` command, for :data:`_SERVER_NAME`, and
one of them expired before the run began.

What is proved: a stack registers over the one connection it opened, with a
`Via` and a `Contact` that name TLS; a certificate refused for each of the
reasons `SipralTlsFailure` names arrives as
`SIPRAL_EVENT_KIND_TRANSPORT_FAILED` carrying that reason and OpenSSL's own
sentence; a registrar that closes the connection is connected to again and
the account registers again on the new one; and the INVITE rate floor's
voice-agent preset lets through a burst the default answers 480.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from sipral import InviteLimit, Stack, TlsTrust
from sipral._sipral_cffi import lib
from sipral.errors import SipralError
from sipral.errors import call as retry_busy
from sipral.enums import AudioMode, EventKind, RegistrationState, TlsFailure, Transport, TransportError

_SERVER_NAME = "registrar.sipral.test"


def _header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return None


def _certificate(directory: str, name: str, *extra: str) -> tuple[str, str] | None:
    """A self-signed certificate and key for :data:`_SERVER_NAME`, made with
    the `openssl` command, or `None` where it cannot make one."""
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    certificate = os.path.join(directory, f"{name}.pem")
    key = os.path.join(directory, f"{name}.key")
    made = subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-subj", f"/CN={_SERVER_NAME}",
            "-addext", f"subjectAltName=DNS:{_SERVER_NAME}",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", key, "-out", certificate, *extra,
        ],
        capture_output=True,
    )
    return (certificate, key) if made.returncode == 0 else None


class _Registrar:
    """A registrar on a TCP port, over TLS when given a certificate, or one
    that answers a TLS client in plain text when ``plain_to_tls``.

    :attr:`requests` holds ``(connection, message)`` for every request, in
    order, ``connection`` counting from one.
    """

    def __init__(self, certificate: tuple[str, str] | None = None, *, plain_to_tls: bool = False) -> None:
        self._context = None
        if certificate is not None:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.load_cert_chain(*certificate)
        self._plain_to_tls = plain_to_tls
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen()
        self._listener.settimeout(0.05)
        self.address = f"127.0.0.1:{self._listener.getsockname()[1]}"
        self.requests: list[tuple[int, str]] = []
        self._open: list[socket.socket] = []
        self.connections = 0
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn, self.connections), daemon=True).start()

    def _serve(self, conn: socket.socket, number: int) -> None:
        if self._plain_to_tls:
            conn.settimeout(5.0)
            try:
                conn.recv(4096)
                conn.sendall(b"SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            conn.close()
            return
        if self._context is not None:
            conn.settimeout(5.0)
            try:
                conn = self._context.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                conn.close()
                return
        conn.settimeout(0.05)
        self._open.append(conn)
        held = b""
        while not self._stop.is_set():
            try:
                data = conn.recv(65536)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except (OSError, ssl.SSLError):
                data = b""
            if not data:
                conn.close()
                return
            held += data
            while b"\r\n\r\n" in held:
                head, _, rest = held.partition(b"\r\n\r\n")
                text = head.decode("utf-8", "replace")
                length = int(_header("Content-Length", text + "\r\n") or 0)
                if len(rest) < length:
                    break
                held = rest[length:]
                message = text + "\r\n\r\n" + rest[:length].decode("utf-8", "replace")
                self.requests.append((number, message))
                if message.startswith("REGISTER "):
                    conn.sendall(self._ok(message).encode("utf-8"))

    @staticmethod
    def _ok(request: str) -> str:
        lines = ["SIP/2.0 200 OK"]
        for name in ("Via", "From", "To", "Call-ID", "CSeq"):
            value = _header(name, request)
            if name == "To":
                value = f"{value};tag=registrar"
            lines.append(f"{name}: {value}")
        lines.append(f"Contact: {_header('Contact', request)};expires=3600")
        lines.append("Content-Length: 0")
        return "\r\n".join(lines) + "\r\n\r\n"

    def drop(self) -> None:
        """Close every connection from this end, the way a registrar that
        restarted does."""
        open_now, self._open = self._open, []
        for conn in open_now:
            try:
                conn.close()
            except OSError:
                pass

    def registers(self) -> list[tuple[int, str]]:
        return [(number, message) for number, message in self.requests if message.startswith("REGISTER ")]

    def close(self) -> None:
        self._stop.set()
        self.drop()
        self._listener.close()


class _OverAConnection(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.mkdtemp()
        cls._good = _certificate(cls._directory, "good", "-days", "1")
        cls._expired = _certificate(
            cls._directory, "expired", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._directory, ignore_errors=True)

    def good(self) -> tuple[str, str]:
        if self._good is None:
            self.skipTest("no openssl command to make the registrar's certificate with")
        return self._good

    def registrar(self, certificate: tuple[str, str] | None = None, **options) -> _Registrar:
        registrar = _Registrar(certificate, **options)
        self.addCleanup(registrar.close)
        return registrar

    def stack(self, server: str, signalling: int = Transport.TLS, **options) -> Stack:
        stack = Stack(
            loop=asyncio.get_running_loop(),
            audio=AudioMode.APPLICATION,
            signalling=signalling,
            signalling_server=server,
            **options,
        )
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        return stack

    async def next_event(self, stack: Stack, kind: int, seconds: float = 5):
        while True:
            event = await asyncio.wait_for(stack.events.get(), timeout=seconds)
            if event.kind == kind:
                return event

    async def registered(self, stack: Stack, seconds: float = 5) -> None:
        while True:
            event = await self.next_event(stack, EventKind.REGISTRATION_CHANGED, seconds)
            if event.fields.get("state") == RegistrationState.REGISTERED:
                return

    async def until(self, what, seconds: float = 5.0) -> None:
        deadline = asyncio.get_running_loop().time() + seconds
        while not what() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)


class RegisteringOverTls(_OverAConnection):
    async def test_a_registrar_whose_authority_is_pinned_registers_the_account_over_tls(self) -> None:
        certificate = self.good()
        registrar = self.registrar(certificate)
        stack = self.stack(
            registrar.address,
            tls_server_name=_SERVER_NAME,
            tls_trust=TlsTrust.only_authority(certificate[0]),
        )
        self.assertTrue(stack.connected)
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)
        self.assertEqual(account.registration_state, RegistrationState.REGISTERED)
        [(connection, register)] = registrar.registers()
        self.assertEqual(connection, 1, "on the one connection the stack opened")
        self.assertTrue(_header("Via", register).startswith("SIP/2.0/TLS "), register)
        self.assertIn(";transport=tls", _header("Contact", register))
        self.assertIn(stack.bind_address, _header("Contact", register), "the connection's own address")

    async def test_a_private_authority_is_trusted_beside_the_platforms(self) -> None:
        certificate = self.good()
        registrar = self.registrar(certificate)
        stack = self.stack(
            registrar.address,
            tls_server_name=_SERVER_NAME,
            tls_trust=TlsTrust.private_authority(certificate[0]),
        )
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)


class ACertificateIsPinnedByItsFingerprint(_OverAConnection):
    def fingerprint(self, certificate: tuple[str, str]) -> str:
        with open(certificate[0], encoding="ascii") as pem:
            der = ssl.PEM_cert_to_DER_cert(pem.read())
        return "SHA256=" + ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())

    async def test_the_pinned_certificate_is_trusted_whatever_its_name_and_signer(self) -> None:
        certificate = self.good()
        registrar = self.registrar(certificate)
        stack = self.stack(
            registrar.address,
            tls_server_name="a-name-the-certificate-does-not-carry.test",
            tls_trust=TlsTrust.pinned(self.fingerprint(certificate)),
        )
        self.assertTrue(stack.connected)
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)

    async def test_any_other_certificate_is_refused_as_untrusted(self) -> None:
        registrar = self.registrar(self.good())
        stack = self.stack(
            registrar.address,
            tls_server_name=_SERVER_NAME,
            tls_trust=TlsTrust.pinned(hashlib.sha256(b"another certificate").hexdigest()),
        )
        event = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertFalse(stack.connected)
        self.assertEqual(event.fields["tls"], TlsFailure.UNTRUSTED, event.fields)
        self.assertIn("pinned", event.fields["detail"])


class ATlsRefusalSaysWhy(_OverAConnection):
    async def refused(self, stack: Stack):
        event = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertFalse(stack.connected)
        self.assertEqual(event.fields["protocol"], Transport.TLS)
        return event

    async def test_a_certificate_no_trusted_authority_signed_is_untrusted(self) -> None:
        registrar = self.registrar(self.good())
        stack = self.stack(registrar.address, tls_server_name=_SERVER_NAME)
        event = await self.refused(stack)
        self.assertEqual(event.fields["tls"], TlsFailure.UNTRUSTED, event.fields)
        self.assertIn("certificate", event.fields["detail"], "OpenSSL's own words come with it")
        account = stack.add_account(
            f"sip:alice@{_SERVER_NAME}", registrar=f"sip:{_SERVER_NAME}", registrar_address=registrar.address
        )
        account.register()
        self.assertTrue(account.wants_registration, "kept for when the connection is made")
        self.assertEqual(registrar.registers(), [], "nothing went out in the clear or otherwise")

    async def test_a_certificate_for_another_name_is_a_name_mismatch(self) -> None:
        certificate = self.good()
        registrar = self.registrar(certificate)
        stack = self.stack(
            registrar.address,
            tls_server_name="other.sipral.test",
            tls_trust=TlsTrust.only_authority(certificate[0]),
        )
        event = await self.refused(stack)
        self.assertEqual(event.fields["tls"], TlsFailure.NAME_MISMATCH, event.fields)

    async def test_an_expired_certificate_is_expired(self) -> None:
        if self._expired is None:
            self.skipTest("this openssl cannot date a certificate in the past")
        registrar = self.registrar(self._expired)
        stack = self.stack(
            registrar.address,
            tls_server_name=_SERVER_NAME,
            tls_trust=TlsTrust.only_authority(self._expired[0]),
        )
        event = await self.refused(stack)
        self.assertEqual(event.fields["tls"], TlsFailure.EXPIRED, event.fields)

    async def test_a_server_that_does_not_speak_tls_refuses_the_handshake(self) -> None:
        registrar = self.registrar(plain_to_tls=True)
        stack = self.stack(registrar.address, tls_server_name=_SERVER_NAME)
        event = await self.refused(stack)
        self.assertEqual(event.fields["tls"], TlsFailure.HANDSHAKE_REFUSED, event.fields)

    async def test_nobody_listening_is_a_refused_connection_and_no_tls_reason(self) -> None:
        nobody = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        nobody.bind(("127.0.0.1", 0))
        address = f"127.0.0.1:{nobody.getsockname()[1]}"
        nobody.close()
        stack = self.stack(address, tls_server_name=_SERVER_NAME)
        event = await self.refused(stack)
        self.assertEqual(event.fields["error"], TransportError.CONNECTION_REFUSED, event.fields)
        self.assertEqual(event.fields["tls"], TlsFailure.NONE)

    def test_a_context_that_checks_nothing_is_refused(self) -> None:
        careless = ssl.create_default_context()
        careless.check_hostname = False
        careless.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ValueError):
            TlsTrust.from_context(careless)


class AConnectionLostIsMadeAgain(_OverAConnection):
    async def test_the_account_registers_again_on_the_new_connection(self) -> None:
        registrar = self.registrar()
        stack = self.stack(registrar.address, signalling=Transport.TCP)
        account = stack.add_account(
            "sip:alice@sipral.invalid", registrar="sip:sipral.invalid", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)
        first = stack.bind_address

        registrar.drop()
        lost = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertEqual(lost.fields["error"], TransportError.CLOSED, lost.fields)
        self.assertEqual(lost.fields["protocol"], Transport.TCP)
        await self.until(lambda: any(number == 2 for number, _ in registrar.registers()), seconds=10)
        again = [message for number, message in registrar.registers() if number == 2]
        self.assertTrue(again, "no REGISTER on a second connection")
        self.assertNotEqual(stack.bind_address, first, "a new connection, from a new port")
        self.assertIn(stack.bind_address, _header("Contact", again[0]), "the Contact moved with it")
        self.assertIn(";transport=tcp", _header("Contact", again[0]))

    async def test_a_connection_the_stack_let_go_of_is_made_again(self) -> None:
        # the stack retires the main connection on its own when a flow that
        # answered keep-alives stops answering them (RFC 5626 Section 4.4.1),
        # with the socket still open here; said here the way it says it
        registrar = self.registrar()
        stack = self.stack(registrar.address, signalling=Transport.TCP)
        account = stack.add_account(
            "sip:alice@sipral.invalid", registrar="sip:sipral.invalid", registrar_address=registrar.address
        )
        account.register()
        await self.registered(stack)
        first = stack.bind_address

        await asyncio.to_thread(
            retry_busy,
            lambda: lib.sipral_stack_transport_failed(
                stack.handle, lib.SIPRAL_TRANSPORT_MAIN, TransportError.TIMED_OUT, stack.now_ms()
            ),
            "sipral_stack_transport_failed",
        )
        lost = await self.next_event(stack, EventKind.TRANSPORT_FAILED)
        self.assertEqual(lost.fields["transport"], lib.SIPRAL_TRANSPORT_MAIN)
        await self.until(lambda: any(number == 2 for number, _ in registrar.registers()), seconds=10)
        again = [message for number, message in registrar.registers() if number == 2]
        self.assertTrue(again, "no REGISTER on a second connection")
        self.assertNotEqual(stack.bind_address, first, "a new connection, from a new port")
        self.assertIn(stack.bind_address, _header("Contact", again[0]), "the Contact moved with it")


class AClockBehindIsRetriedLikeABusy(unittest.TestCase):
    """A clock reading the poll thread overtook is read again, as a
    collision with it is; anything else goes straight through."""

    def test_both_are_waited_out_and_nothing_else(self) -> None:
        for status in (lib.SIPRAL_STATUS_BUSY, lib.SIPRAL_STATUS_CLOCK_BEHIND):
            answers = iter((status, status, lib.SIPRAL_STATUS_OK))
            retry_busy(lambda: next(answers), "a test")
            self.assertIsNone(next(answers, None), f"{status} was not retried")
        attempts = []

        def refused() -> int:
            attempts.append(1)
            return lib.SIPRAL_STATUS_WRONG_STATE

        with self.assertRaises(SipralError):
            retry_busy(refused, "a test")
        self.assertEqual(len(attempts), 1)


class TheInviteRateFloor(unittest.IsolatedAsyncioTestCase):
    async def burst(self, **options) -> int:
        """Twenty INVITEs from one address at once: how many of them were
        answered 480 -- each counted once, however often its refusal is
        sent again for want of an ACK."""
        stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION, **options)
        self.addAsyncCleanup(asyncio.to_thread, stack.close)
        stack.add_account("sip:bob@sipral.invalid", registrar_address="127.0.0.1:9")
        caller = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        caller.bind(("127.0.0.1", 0))
        caller.settimeout(0.2)
        self.addCleanup(caller.close)
        here = "127.0.0.1:%d" % caller.getsockname()[1]
        host, _, port = stack.bind_address.rpartition(":")
        for n in range(20):
            invite = (
                f"INVITE sip:bob@{stack.bind_address} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {here};branch=z9hG4bK-rush-{n}\r\n"
                "Max-Forwards: 70\r\n"
                f"From: <sip:trunk@{here}>;tag=rush{n}\r\n"
                f"To: <sip:bob@{stack.bind_address}>\r\n"
                f"Call-ID: rush-{n}@trunk\r\n"
                "CSeq: 1 INVITE\r\n"
                f"Contact: <sip:trunk@{here}>\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            caller.sendto(invite.encode("utf-8"), (host, int(port)))
        refused: set[str] = set()
        deadline = asyncio.get_running_loop().time() + 2.0
        while asyncio.get_running_loop().time() < deadline:
            try:
                data = await asyncio.to_thread(caller.recv, 65536)
            except socket.timeout:
                continue
            text = data.decode("utf-8", "replace")
            if text.startswith("SIP/2.0 480 "):
                refused.add(_header("Call-ID", text) or "")
        return len(refused)

    async def test_the_default_answers_a_rush_480_and_the_voice_agent_preset_takes_it(self) -> None:
        self.assertEqual(await self.burst(), 10, "ten at once, then one every two seconds")
        self.assertEqual(await self.burst(invite_limit=InviteLimit.VOICE_AGENT), 0)
        self.assertEqual(InviteLimit.VOICE_AGENT.burst, 128)
        self.assertEqual(InviteLimit.DEFAULT, (10, 2000))


if __name__ == "__main__":
    unittest.main()
