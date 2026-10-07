# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Every event the C ABI raises reaches Python with its payload read.

Checked against `EVENT_KIND_ARMS` in `crates/sipral-ffi/src/event.rs`, so a
new kind without a decoder fails here.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from sipral import events
from sipral._sipral_cffi import ffi, lib

_REPO_ROOT = Path(__file__).resolve().parents[3]
_EVENT_RS = _REPO_ROOT / "crates" / "sipral-ffi" / "src" / "event.rs"


def _arms() -> dict[str, str]:
    """`EVENT_KIND_ARMS`, as `SIPRAL_EVENT_KIND_*` name to arm name."""
    table = _EVENT_RS.read_text(encoding="utf-8").split("pub const EVENT_KIND_ARMS", 1)[1].split("];", 1)[0]
    arms = {}
    for kind, arm in re.findall(r'\(SipralEventKind::(\w+), "(\w+)"\)', table):
        name = re.sub(r"(?<!^)(?=[A-Z])", "_", kind).upper()
        arms[f"SIPRAL_EVENT_KIND_{name}"] = arm
    return arms


def _raw(kind: int):
    raw = ffi.new("sipral_event_t *")
    raw.size = ffi.sizeof("sipral_event_t")
    raw.kind = kind
    return raw


class EveryArmIsRead(unittest.TestCase):
    def test_every_kind_with_a_payload_is_decoded(self) -> None:
        arms = _arms()
        self.assertGreater(len(arms), 50, "EVENT_KIND_ARMS was not found in event.rs")
        unread = []
        for name, arm in arms.items():
            if name == "SIPRAL_EVENT_KIND_STARTED":
                # the first event on every stack; its arm carries nothing
                continue
            decoded = events.decode(_raw(getattr(lib, name)))
            if not decoded.fields:
                unread.append(f"{name} ({arm})")
        self.assertEqual(unread, [], "kinds whose payload this layer never reads")

    def test_a_declined_challenge_carries_who_asked_and_for_what(self) -> None:
        raw = _raw(lib.SIPRAL_EVENT_KIND_CHALLENGE_DECLINED)
        server = ffi.new("char[]", b"203.0.113.9:5060")
        realms = ffi.new("char[]", b"sbc.example\ncallee, inc.")
        raw.payload.challenge.refusal = lib.SIPRAL_CHALLENGE_REFUSAL_NOT_THE_ACCOUNTS_REALM
        raw.payload.challenge.server = server
        raw.payload.challenge.server_len = len(b"203.0.113.9:5060")
        raw.payload.challenge.realms = realms
        raw.payload.challenge.realms_len = len(b"sbc.example\ncallee, inc.")
        fields = events.decode(raw).fields
        self.assertEqual(fields["refusal"], lib.SIPRAL_CHALLENGE_REFUSAL_NOT_THE_ACCOUNTS_REALM)
        self.assertEqual(fields["server"], "203.0.113.9:5060")
        self.assertEqual(fields["realms"], ["sbc.example", "callee, inc."])

    def test_a_token_required_carries_where_a_token_comes_from(self) -> None:
        raw = _raw(lib.SIPRAL_EVENT_KIND_TOKEN_REQUIRED)
        texts = {
            "server": b"203.0.113.9:5060",
            "realm": b"example.com",
            "scope": b"sip register",
            "authz_server": b"https://as.example.com",
            "error_code": b"invalid_token",
        }
        kept = []
        for name, value in texts.items():
            buffer = ffi.new("char[]", value)
            kept.append(buffer)
            setattr(raw.payload.token, name, buffer)
            setattr(raw.payload.token, f"{name}_len", len(value))
        raw.payload.token.error = lib.SIPRAL_TOKEN_ERROR_INVALID_TOKEN
        raw.payload.token.proxy = lib.SIPRAL_TOGGLE_OFF
        fields = events.decode(raw).fields
        self.assertEqual(fields["error"], lib.SIPRAL_TOKEN_ERROR_INVALID_TOKEN)
        self.assertEqual(fields["error_code"], "invalid_token")
        self.assertFalse(fields["proxy"])
        self.assertEqual(fields["server"], "203.0.113.9:5060")
        self.assertEqual(fields["realm"], "example.com")
        self.assertEqual(fields["scope"], "sip register")
        self.assertEqual(fields["authz_server"], "https://as.example.com")

    def test_a_subscription_notice_carries_its_state(self) -> None:
        raw = _raw(lib.SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED)
        raw.payload.subscription.subscription = 7
        raw.payload.subscription.state = lib.SIPRAL_SUBSCRIPTION_STATE_ACTIVE
        raw.payload.subscription.status_code = 202
        raw.payload.subscription.expires_ms = 600_000
        raw.payload.subscription.has_dialog_info = 1
        fields = events.decode(raw).fields
        self.assertEqual(fields["subscription"], 7)
        self.assertEqual(fields["state"], lib.SIPRAL_SUBSCRIPTION_STATE_ACTIVE)
        self.assertEqual(fields["status_code"], 202)
        self.assertEqual(fields["expires_ms"], 600_000)
        self.assertTrue(fields["has_dialog_info"])

    def test_a_message_carries_its_body_and_counts(self) -> None:
        raw = _raw(lib.SIPRAL_EVENT_KIND_MESSAGE_RECEIVED)
        body = ffi.new("uint8_t[]", b"hello")
        content_type = ffi.new("char[]", b"text/plain")
        raw.payload.message.message = 3
        raw.payload.message.body = body
        raw.payload.message.body_len = 5
        raw.payload.message.content_type = content_type
        raw.payload.message.content_type_len = len(b"text/plain")
        fields = events.decode(raw).fields
        self.assertEqual(fields["message"], 3)
        self.assertEqual(fields["body"], b"hello")
        self.assertEqual(fields["content_type"], "text/plain")

        waiting = _raw(lib.SIPRAL_EVENT_KIND_MESSAGES_WAITING)
        waiting.payload.message.waiting = 1
        waiting.payload.message.new_messages = 2
        waiting.payload.message.urgent_old_messages = 1
        fields = events.decode(waiting).fields
        self.assertTrue(fields["waiting"])
        self.assertEqual(fields["new_messages"], 2)
        self.assertEqual(fields["urgent_old_messages"], 1)

    def test_a_recovery_and_an_announcement_carry_their_payloads(self) -> None:
        raw = _raw(lib.SIPRAL_EVENT_KIND_RECOVERY)
        raw.payload.recovery.state = lib.SIPRAL_RECOVERY_OUTCOME_GAVE_UP
        raw.payload.recovery.unverified = 2
        fields = events.decode(raw).fields
        self.assertEqual(fields["state"], lib.SIPRAL_RECOVERY_OUTCOME_GAVE_UP)
        self.assertEqual(fields["unverified"], 2)

        announced = _raw(lib.SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING)
        announced.payload.announce.announcement = 9
        announced.payload.announce.waited_ms = 30_000
        fields = events.decode(announced).fields
        self.assertEqual(fields["announcement"], 9)
        self.assertEqual(fields["waited_ms"], 30_000)


if __name__ == "__main__":
    unittest.main()
