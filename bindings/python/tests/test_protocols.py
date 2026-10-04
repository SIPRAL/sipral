# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The protocols a call and an account carry beyond audio, through this
package: real-time text and RTCP feedback agreed between two stacks on
127.0.0.1, a focus named on an answer, L16 as the codec, and -- against
this test's own UDP or TCP peer writing RFC text by hand -- a conference
picture, presence published and watched, and a call recorded to a
recording server.
"""

from __future__ import annotations

import asyncio
import base64
import queue
import socket
import threading
import unittest

from sipral import (
    ConferencePicture,
    Participant,
    Presence,
    SipralError,
    Stack,
)
from sipral._sipral_cffi import lib
from sipral.enums import (
    Activity,
    AudioMode,
    Basic,
    Codec,
    ConferenceUpdate,
    EndpointStatus,
    EventKind,
    PresenceKind,
    PublicationState,
    PublishFailure,
    Status,
    SubscriptionState,
    Transport,
)

TIMEOUT = 20.0

ROOM = (
    '<?xml version="1.0"?>\r\n'
    '<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@example.com" state="full" version="1">\r\n'
    "  <conference-description><subject>Weekly</subject><display-text>Team room</display-text></conference-description>\r\n"
    "  <conference-state><user-count>3</user-count><active>true</active><locked>false</locked></conference-state>\r\n"
    "  <users>\r\n"
    '    <user entity="sip:bob@example.com" state="full"><display-text>Bob</display-text>\r\n'
    '      <endpoint entity="sip:bob@203.0.113.5"><status>connected</status><media id="1"><type>audio</type></media></endpoint>\r\n'
    "    </user>\r\n"
    '    <user entity="sip:carol@example.com" state="full">\r\n'
    '      <endpoint entity="sip:carol@203.0.113.6"><status>alerting</status></endpoint>\r\n'
    "    </user>\r\n"
    "  </users>\r\n"
    "</conference-info>"
)

DELETED = (
    '<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" '
    'entity="sip:room@example.com" state="deleted" version="2"/>'
)

BUDDY = (
    '<?xml version="1.0" encoding="UTF-8"?>\r\n'
    '<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" '
    'xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:bob@example.com">\r\n'
    '  <tuple id="t1"><status><basic>open</basic></status><note>Back at four</note></tuple>\r\n'
    '  <dm:person id="p1"><rpid:activities><rpid:meeting/></rpid:activities></dm:person>\r\n'
    "</presence>"
)


def header(name: str, message: str) -> str | None:
    for line in message.split("\r\n"):
        if not line:
            return None
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None


def uri(name_addr: str) -> str:
    start, end = name_addr.find("<"), name_addr.find(">")
    return name_addr[start + 1 : end] if 0 <= start < end else name_addr


def answer(request: str, status: str, tag: str, more: str, body: str = "") -> str:
    """A response to ``request``, its dialog's headers copied and ``tag`` on
    its `To`."""
    out = f"SIP/2.0 {status}\r\n"
    for name in ("Via", "From", "To", "Call-ID", "CSeq"):
        value = header(name, request)
        out += f"To: {value};tag={tag}\r\n" if name == "To" else f"{name}: {value}\r\n"
    return out + more + f"Content-Length: {len(body.encode())}\r\n\r\n" + body


def notify(subscribe: str, sender: str, package: str, content_type: str, body: str, cseq: int) -> str:
    """A notification in the dialog ``subscribe`` opened."""
    return (
        f"NOTIFY {uri(header('Contact', subscribe))} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sender};branch=z9hG4bK-notify-{cseq}\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {header('To', subscribe)};tag=notifier\r\n"
        f"To: {header('From', subscribe)}\r\n"
        f"Call-ID: {header('Call-ID', subscribe)}\r\n"
        f"CSeq: {cseq} NOTIFY\r\n"
        f"Contact: <sip:notifier@{sender}>\r\n"
        f"Event: {package}\r\n"
        "Subscription-State: active;expires=3600\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body.encode())}\r\n\r\n" + body
    )


class Peer:
    """A UDP socket on loopback that reads SIP as text and writes what a
    test hands it: a notifier, a compositor, or a far end's RTP port."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(TIMEOUT)
        self.port = self.sock.getsockname()[1]
        self.address = f"127.0.0.1:{self.port}"

    def send(self, message: str, to: str) -> None:
        host, _, port = to.rpartition(":")
        self.sock.sendto(message.encode(), (host, int(port)))

    def datagram(self) -> bytes:
        return self.sock.recv(65536)

    def request(self, method: str) -> str:
        """The next request with ``method``, every other datagram -- the
        stack's answers to NOTIFYs among them -- passed over."""
        while True:
            text = self.datagram().decode()
            if text.startswith(method + " "):
                return text

    def close(self) -> None:
        self.sock.close()


class StreamPeer:
    """A TCP listener on loopback that takes the one connection a stack
    signalling over TCP opens, and reads and writes SIP on it."""

    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.address = "127.0.0.1:{}".format(self.listener.getsockname()[1])
        self.messages: queue.Queue[str] = queue.Queue()
        self.connected = threading.Event()
        self.conn: socket.socket | None = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        try:
            self.conn, _ = self.listener.accept()
        except OSError:
            return
        self.connected.set()
        held = b""
        while True:
            try:
                data = self.conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            held += data
            while b"\r\n\r\n" in held:
                end = held.index(b"\r\n\r\n")
                length = int(header("Content-Length", held[: end + 2].decode()) or 0)
                if len(held) < end + 4 + length:
                    break
                self.messages.put(held[: end + 4 + length].decode())
                held = held[end + 4 + length :].lstrip(b"\r\n")

    def send(self, message: str) -> None:
        assert self.conn is not None
        self.conn.sendall(message.encode())

    def message(self, wanted) -> str:
        while True:
            text = self.messages.get(timeout=TIMEOUT)
            if wanted(text):
                return text

    def close(self) -> None:
        self.listener.close()
        if self.conn is not None:
            self.conn.close()


class Protocols(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.stacks: list[Stack] = []
        self.calls = []
        self.addAsyncCleanup(self._close)

    async def _close(self) -> None:
        for call in self.calls:
            call.close()
        for stack in self.stacks:
            stack.close()

    def stack(self, codecs: str = "PCMU", **more) -> Stack:
        made = Stack(loop=self.loop, audio=AudioMode.APPLICATION, codecs=codecs, **more)
        self.stacks.append(made)
        return made

    def peer(self) -> Peer:
        made = Peer()
        self.addCleanup(made.close)
        return made

    async def first(self, events: asyncio.Queue, kind: int):
        while True:
            event = await asyncio.wait_for(events.get(), timeout=TIMEOUT)
            if event.kind == kind:
                return event

    async def place_and_answer(self, alice: Stack, bob: Stack, placed=None, answered=None):
        account = alice.add_account("sip:alice@sipral.invalid", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@sipral.invalid", registrar_address=alice.bind_address)
        alice_call = alice.place_call(account, f"sip:bob@{bob.bind_address}", **(placed or {}))
        self.calls.append(alice_call)
        incoming = await self.first(bob.events, EventKind.INCOMING_CALL)
        bob_call = bob.answer_call(incoming, **(answered or {}))
        self.calls.append(bob_call)
        await self.first(alice_call.events, EventKind.CALL_CONFIRMED)
        while alice_call.media is None:
            await asyncio.wait_for(alice_call.events.get(), timeout=TIMEOUT)
        while bob_call.media is None:
            await asyncio.wait_for(bob_call.events.get(), timeout=TIMEOUT)
        return alice_call, bob_call

    async def typed(self, text: asyncio.Queue, expected: str) -> str:
        got = ""
        while len(got) < len(expected):
            got += await asyncio.wait_for(text.get(), timeout=TIMEOUT)
        return got

    # -- between two stacks ------------------------------------------------

    async def test_real_time_text_crosses_both_ways(self) -> None:
        alice, bob = await self.place_and_answer(
            self.stack(), self.stack(), {"text": True}, {"text": True}
        )
        self.assertIsNotNone(alice.text_address)
        self.assertTrue(alice.media.info()["has_text"])
        self.assertTrue(bob.media.info()["has_text"])
        alice.send_text("hello")
        self.assertEqual(await self.typed(bob.text, "hello"), "hello")
        bob.send_text("hi\b")
        self.assertEqual(await self.typed(alice.text, "hi\b"), "hi\b")

    async def test_text_on_a_call_that_agreed_none_is_not_negotiated(self) -> None:
        alice, _ = await self.place_and_answer(self.stack(), self.stack())
        self.assertIsNone(alice.text_address)
        self.assertFalse(alice.media.info()["has_text"])
        with self.assertRaises(SipralError) as refused:
            alice.send_text("lost")
        self.assertEqual(refused.exception.status, Status.NOT_NEGOTIATED)

    async def test_feedback_asked_for_is_agreed_and_counted(self) -> None:
        alice, bob = await self.place_and_answer(
            self.stack(), self.stack(), {"feedback": True}, {"feedback": True}
        )
        for media in (alice.media, bob.media):
            info = media.info()
            self.assertTrue(info["feedback"])
            self.assertTrue(info["generic_nack"])
            self.assertTrue(info["reduced_size"])
            self.assertIsNotNone(media.statistics()["feedback"])

    async def test_feedback_is_off_by_default(self) -> None:
        alice, _ = await self.place_and_answer(self.stack(), self.stack())
        info = alice.media.info()
        self.assertFalse(info["feedback"])
        self.assertFalse(info["generic_nack"])
        self.assertIsNone(alice.media.statistics()["feedback"])

    async def test_a_focus_that_answered_names_its_conference(self) -> None:
        alice, bob = await self.place_and_answer(
            self.stack(), self.stack(), answered={"focus": True}
        )
        self.assertTrue(alice.conference_uri.startswith("sip:"))
        self.assertIsNone(bob.conference_uri)
        watched = alice.subscribe_conference()
        self.assertEqual(watched.package, "conference")
        self.assertNotEqual(watched.handle, 0)

    async def test_a_call_from_anyone_else_has_no_conference(self) -> None:
        alice, _ = await self.place_and_answer(self.stack(), self.stack())
        self.assertIsNone(alice.conference_uri)
        with self.assertRaises(SipralError) as refused:
            alice.subscribe_conference()
        self.assertEqual(refused.exception.status, Status.NOT_A_FOCUS)

    async def test_l16_is_the_codec_when_it_is_the_only_one_named(self) -> None:
        alice, bob = await self.place_and_answer(
            self.stack("L16/16000"), self.stack("L16/16000")
        )
        info = alice.media.info()
        self.assertEqual(Codec(info["codec"]), Codec.L16_WIDEBAND)
        self.assertEqual(info["clock_rate"], 16_000)
        self.assertEqual(Codec(bob.media.info()["codec"]), Codec.L16_WIDEBAND)

    # -- against a notifier and a compositor of this test's own -------------

    async def test_a_conference_is_read_back_whole_and_its_end_is_told(self) -> None:
        stack = self.stack()
        notifier = self.peer()
        account = stack.add_account("sip:alice@sipral.invalid", registrar_address=notifier.address)
        subscription = account.subscribe("sip:room@example.com", "conference")
        self.assertIsNone(subscription.conference())

        subscribe = await asyncio.to_thread(notifier.request, "SUBSCRIBE")
        self.assertEqual(header("Event", subscribe), "conference")
        notifier.send(
            answer(subscribe, "200 OK", "notifier",
                   f"Expires: 3600\r\nContact: <sip:room@{notifier.address}>\r\n"),
            stack.bind_address,
        )
        notifier.send(
            notify(subscribe, notifier.address, "conference", "application/conference-info+xml", ROOM, 1),
            stack.bind_address,
        )
        changed = (await self.first(stack.events, EventKind.CONFERENCE_CHANGED)).conference
        self.assertEqual(changed.subscription, subscription.handle)
        self.assertEqual(changed.update, ConferenceUpdate.APPLIED)
        self.assertEqual((changed.version, changed.users), (1, 2))

        self.assertEqual(
            subscription.conference(),
            ConferencePicture(
                version=1,
                entity="sip:room@example.com",
                subject="Weekly",
                display_text="Team room",
                user_count=3,
                active=True,
                locked=False,
                users=(
                    Participant("sip:bob@example.com", "Bob", "sip:bob@203.0.113.5",
                                EndpointStatus.CONNECTED, 1, 1),
                    Participant("sip:carol@example.com", None, "sip:carol@203.0.113.6",
                                EndpointStatus.ALERTING, 1, 0),
                ),
            ),
        )

        notifier.send(
            notify(subscribe, notifier.address, "conference", "application/conference-info+xml", DELETED, 2),
            stack.bind_address,
        )
        ended = (await self.first(stack.events, EventKind.CONFERENCE_CHANGED)).conference
        self.assertEqual(ended.update, ConferenceUpdate.ENDED)
        self.assertEqual(ended.users, 0)

    async def test_presence_is_published_modified_and_taken_away(self) -> None:
        stack = self.stack()
        compositor = self.peer()
        account = stack.add_account("sip:alice@sipral.invalid", registrar_address=compositor.address)

        with self.assertRaises(SipralError) as nothing:
            account.unpublish_presence()
        self.assertEqual(nothing.exception.status, Status.WRONG_STATE)
        with self.assertRaises(SipralError) as unnamed:
            account.publish_presence(Basic.OPEN, Activity.OTHER)
        self.assertEqual(unnamed.exception.status, Status.INVALID_ARGUMENT)

        account.publish_presence(Basic.OPEN, Activity.ON_THE_PHONE, "In a call")
        publish = await asyncio.to_thread(compositor.request, "PUBLISH")
        self.assertEqual(header("Event", publish), "presence")
        for said in ("<basic>open</basic>", "on-the-phone", "In a call"):
            self.assertIn(said, publish)
        compositor.send(
            answer(publish, "200 OK", "compositor", "SIP-ETag: tag-one\r\nExpires: 1800\r\n"),
            stack.bind_address,
        )
        published = await self.first(stack.events, EventKind.PRESENCE_CHANGED)
        self.assertEqual(published.account, account.handle)
        told = published.presence
        self.assertEqual(told.kind, PresenceKind.PUBLICATION)
        self.assertEqual(told.publication_state, PublicationState.PUBLISHED)
        self.assertEqual(told.expires_ms, 1_800_000)
        self.assertTrue(0 < told.refresh_in_ms < 1_800_000)

        account.publish_presence(Basic.CLOSED, Activity.AWAY)
        modified = await asyncio.to_thread(compositor.request, "PUBLISH")
        self.assertEqual(header("SIP-If-Match", modified), "tag-one")
        self.assertIn("<basic>closed</basic>", modified)
        compositor.send(
            answer(modified, "200 OK", "compositor", "SIP-ETag: tag-two\r\nExpires: 1800\r\n"),
            stack.bind_address,
        )
        await self.first(stack.events, EventKind.PRESENCE_CHANGED)

        account.unpublish_presence()
        removal = await asyncio.to_thread(compositor.request, "PUBLISH")
        self.assertEqual(header("Expires", removal), "0")
        compositor.send(
            answer(removal, "200 OK", "compositor", "SIP-ETag: tag-two\r\nExpires: 0\r\n"),
            stack.bind_address,
        )
        removed = await self.first(stack.events, EventKind.PRESENCE_CHANGED)
        self.assertEqual(removed.presence.publication_state, PublicationState.REMOVED)

    async def test_a_compositor_that_knows_no_presence_is_a_failure_with_its_reason(self) -> None:
        stack = self.stack()
        compositor = self.peer()
        account = stack.add_account("sip:alice@sipral.invalid", registrar_address=compositor.address)
        account.publish_presence(Basic.OPEN)
        publish = await asyncio.to_thread(compositor.request, "PUBLISH")
        compositor.send(answer(publish, "489 Bad Event", "compositor", ""), stack.bind_address)
        failed = (await self.first(stack.events, EventKind.PRESENCE_CHANGED)).presence
        self.assertEqual(failed.publication_state, PublicationState.FAILED)
        self.assertEqual(failed.failure, PublishFailure.BAD_EVENT)
        self.assertEqual(failed.status_code, 489)

    async def test_a_watched_presentity_is_told_with_its_activity_and_note(self) -> None:
        stack = self.stack()
        notifier = self.peer()
        account = stack.add_account("sip:alice@sipral.invalid", registrar_address=notifier.address)
        watched = account.watch_presence("sip:bob@example.com")
        self.assertEqual(watched.package, "presence")

        subscribe = await asyncio.to_thread(notifier.request, "SUBSCRIBE")
        self.assertEqual(header("Event", subscribe), "presence")
        notifier.send(
            answer(subscribe, "200 OK", "notifier",
                   f"Expires: 3600\r\nContact: <sip:bob@{notifier.address}>\r\n"),
            stack.bind_address,
        )
        notifier.send(
            notify(subscribe, notifier.address, "presence", "application/pidf+xml", BUDDY, 1),
            stack.bind_address,
        )
        told = await self.first(stack.events, EventKind.PRESENCE_CHANGED)
        self.assertEqual(
            told.presence,
            Presence(
                kind=PresenceKind.WATCHED,
                subscription=watched.handle,
                basic=Basic.OPEN,
                activity=Activity.MEETING,
                entity="sip:bob@example.com",
                note="Back at four",
                publication_state=PublicationState.UNKNOWN,
                failure=PublishFailure.NONE,
                status_code=0,
                expires_ms=0,
                refresh_in_ms=0,
            ),
        )
        self.assertEqual(watched.state, SubscriptionState.ACTIVE)

        watched.end()
        ending = await asyncio.to_thread(notifier.request, "SUBSCRIBE")
        self.assertEqual(header("Expires", ending), "0")

    # -- a recording server ------------------------------------------------

    async def test_a_call_is_recorded_to_a_recording_server(self) -> None:
        server = StreamPeer()
        self.addCleanup(server.close)
        rtp, label_one, label_two = self.peer(), self.peer(), self.peer()
        stack = self.stack(signalling=Transport.TCP, signalling_server=server.address)
        stack.add_account("sip:alice@sipral.invalid", registrar_address=server.address)
        self.assertTrue(await asyncio.to_thread(server.connected.wait, TIMEOUT))

        sdp = (
            "v=0\r\no=bob 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            f"m=audio {rtp.port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        )
        server.send(
            "INVITE sip:alice@sipral.invalid SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {server.address};branch=z9hG4bK-recorded-1\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:bob@example.com>;tag=bob\r\n"
            "To: <sip:alice@sipral.invalid>\r\n"
            "Call-ID: recorded-call\r\n"
            "CSeq: 1 INVITE\r\n"
            f"Contact: <sip:bob@{server.address};transport=tcp>\r\n"
            "Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n\r\n" + sdp
        )
        incoming = await self.first(stack.events, EventKind.INCOMING_CALL)
        call = stack.answer_call(incoming)
        self.calls.append(call)
        ok = await asyncio.to_thread(
            server.message,
            lambda m: m.startswith("SIP/2.0 200") and header("CSeq", m) == "1 INVITE",
        )
        server.send(
            f"ACK {uri(header('Contact', ok))} SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {server.address};branch=z9hG4bK-recorded-ack\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:bob@example.com>;tag=bob\r\n"
            f"To: {header('To', ok)}\r\n"
            "Call-ID: recorded-call\r\n"
            "CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
        )
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=TIMEOUT)

        session = call.record_to("sip:srs@example.com")
        self.assertEqual(call.recording_session, session)
        offer = await asyncio.to_thread(
            server.message, lambda m: m.startswith("INVITE sip:srs@example.com")
        )
        self.assertEqual(header("Require", offer), "siprec")
        self.assertTrue(header("Content-Type", offer).startswith("multipart/mixed"))
        for said in ("a=label:1", "a=label:2", "application/rs-metadata+xml"):
            self.assertIn(said, offer)

        recorder_sdp = (
            "v=0\r\no=srs 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            f"m=audio {label_one.port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:1\r\na=recvonly\r\n"
            f"m=audio {label_two.port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:2\r\na=recvonly\r\n"
        )
        server.send(
            answer(offer, "200 OK", "srs",
                   f"Contact: <sip:srs@{server.address};transport=tcp>\r\n"
                   "Content-Type: application/sdp\r\n", recorder_sdp)
        )
        copy = await asyncio.to_thread(label_one.datagram)
        self.assertEqual(copy[0] & 0xC0, 0x80)
        self.assertEqual(copy[1] & 0x7F, 0)

        call.stop_recording_to()
        self.assertIsNone(call.recording_session)
        await asyncio.to_thread(
            server.message,
            lambda m: m.startswith("BYE ") and header("Call-ID", m) == header("Call-ID", offer),
        )
        with self.assertRaises(SipralError) as twice:
            call.stop_recording_to()
        self.assertEqual(twice.exception.status, Status.WRONG_STATE)

    async def test_a_call_with_no_media_yet_cannot_be_recorded(self) -> None:
        alice, bob = self.stack(), self.stack()
        account = alice.add_account("sip:alice@sipral.invalid", registrar_address=bob.bind_address)
        call = alice.place_call(account, f"sip:bob@{bob.bind_address}")
        self.calls.append(call)
        with self.assertRaises(SipralError) as refused:
            call.record_to("sip:srs@example.com")
        self.assertEqual(refused.exception.status, Status.WRONG_STATE)
        await self.first(bob.events, EventKind.INCOMING_CALL)

    async def recording_offer_of_an_encrypted_call(self, *, recording_in_clear: bool) -> str:
        """The recording session's offer for a call keyed with SDES (RFC
        4568), from an account that does or does not let its encrypted calls
        be recorded in the clear."""
        server = StreamPeer()
        self.addCleanup(server.close)
        rtp = self.peer()
        stack = self.stack(signalling=Transport.TCP, signalling_server=server.address)
        stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address=server.address,
            srtp=int(lib.SIPRAL_SRTP_REQUIRED),
            recording_in_clear=recording_in_clear,
        )
        self.assertTrue(await asyncio.to_thread(server.connected.wait, TIMEOUT))

        # thirty octets of key and salt, nobody's
        key = base64.b64encode(bytes(range(30))).decode()
        sdp = (
            "v=0\r\no=bob 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            f"m=audio {rtp.port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}\r\n"
        )
        server.send(
            "INVITE sip:alice@sipral.invalid SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {server.address};branch=z9hG4bK-keyed-1\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:bob@example.com>;tag=bob\r\n"
            "To: <sip:alice@sipral.invalid>\r\n"
            "Call-ID: keyed-call\r\n"
            "CSeq: 1 INVITE\r\n"
            f"Contact: <sip:bob@{server.address};transport=tcp>\r\n"
            "Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n\r\n" + sdp
        )
        incoming = await self.first(stack.events, EventKind.INCOMING_CALL)
        call = stack.answer_call(incoming)
        self.calls.append(call)
        ok = await asyncio.to_thread(
            server.message,
            lambda m: m.startswith("SIP/2.0 200") and header("CSeq", m) == "1 INVITE",
        )
        self.assertIn("RTP/SAVP", ok, "the call itself is keyed")
        server.send(
            f"ACK {uri(header('Contact', ok))} SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {server.address};branch=z9hG4bK-keyed-ack\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:bob@example.com>;tag=bob\r\n"
            f"To: {header('To', ok)}\r\n"
            "Call-ID: keyed-call\r\n"
            "CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
        )
        while call.media is None:
            await asyncio.wait_for(call.events.get(), timeout=TIMEOUT)
        call.record_to("sip:srs@example.com")
        return await asyncio.to_thread(
            server.message, lambda m: m.startswith("INVITE sip:srs@example.com")
        )

    async def test_an_encrypted_call_is_offered_to_its_recorder_as_srtp(self) -> None:
        offer = await self.recording_offer_of_an_encrypted_call(recording_in_clear=False)
        self.assertEqual(offer.count("RTP/SAVP"), 2, offer)
        self.assertIn("a=crypto:", offer)

    async def test_an_account_that_allows_it_records_an_encrypted_call_in_the_clear(self) -> None:
        offer = await self.recording_offer_of_an_encrypted_call(recording_in_clear=True)
        self.assertEqual(offer.count("RTP/AVP"), 2, offer)
        self.assertNotIn("RTP/SAVP", offer)
        self.assertNotIn("a=crypto:", offer)


if __name__ == "__main__":
    unittest.main()
