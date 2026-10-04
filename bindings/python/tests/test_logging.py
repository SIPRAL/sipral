# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The log, the state snapshot and the RTP port range, through this package.

`crates/sipral-ffi/src/log.rs` and `ports.rs` prove the C ABI itself; what
runs here is the same three things carried through :class:`sipral.Stack`:
a log handler that hears a refused call with nobody named in it, a state
text for a crash report, and two stacks on loopback whose call is carried
on media ports out of the range each was given.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
import unittest

from sipral import TRACE, Stack
from sipral._sipral_cffi import ffi, lib
from sipral.enums import AudioMode, EventKind, Feature, LogLevel, Status
from sipral.errors import SipralError
from sipral.stack import features


class Logging(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = Stack(audio=AudioMode.APPLICATION)
        self.addCleanup(self.stack.close)

    def _refuse(self) -> int:
        """A call the stack refuses: it has no RTP range to reserve from."""
        return lib.sipral_stack_rtp_port_reserve(self.stack.handle, ffi.new("uint32_t *"))

    def test_a_refused_call_is_logged_with_nobody_in_it(self) -> None:
        self.assertIn(Feature.LOGGING, features())
        heard: list[tuple[LogLevel, str, str, int]] = []
        done = threading.Event()

        def handler(level, target, message, suppressed) -> None:
            heard.append((level, target, message, suppressed))
            done.set()

        self.stack.set_log(LogLevel.DEBUG, handler)
        self.assertEqual(self._refuse(), Status.WRONG_STATE)
        self.assertTrue(done.wait(5))
        level, target, message, suppressed = heard[0]
        self.assertEqual((level, target, suppressed), (LogLevel.DEBUG, "api", 0))
        self.assertIn("refused, WrongState", message)
        self.assertNotIn("127.0.0.1", message)

        self.stack.set_log(LogLevel.OFF)
        count = len(heard)
        self.assertEqual(self._refuse(), Status.WRONG_STATE)
        self.assertEqual(len(heard), count, "a log turned off says nothing")

    def test_the_state_names_the_account_and_not_the_person(self) -> None:
        self.stack.add_account("sip:alice@example.invalid", registrar_address="127.0.0.1:5999")
        text = self.stack.state()
        self.assertIn("accounts: 1", text)
        self.assertIn("transports: 1", text)
        self.assertIn("counters: ", text)
        self.assertNotIn("alice", text)
        self.assertNotIn("127.0.0.1", text)


class _Caught(logging.Handler):
    """Every record a logger passed on, from whichever thread logged it."""

    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.records: list[logging.LogRecord] = []
        self.arrived = threading.Event()

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.arrived.set()


class LogToTheLoggingModule(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = Stack(audio=AudioMode.APPLICATION)
        self.addCleanup(self.stack.close)
        self.logger = logging.getLogger(f"sipral-test-{id(self)}")
        self.logger.propagate = False
        self.caught = _Caught()
        self.logger.addHandler(self.caught)
        self.addCleanup(self.logger.removeHandler, self.caught)

    def _refuse(self) -> int:
        return lib.sipral_stack_rtp_port_reserve(self.stack.handle, ffi.new("uint32_t *"))

    def _state_says(self, line: str) -> None:
        """The state text names the level the stack logs at -- once a poll
        has kept a snapshot, if the poll thread held the stack when asked."""
        deadline = time.monotonic() + 3
        text = self.stack.state()
        while line not in text and time.monotonic() < deadline:
            time.sleep(0.05)
            text = self.stack.state()
        self.assertIn(line, text)

    def test_a_line_reaches_the_child_logger_of_its_target_at_its_level(self) -> None:
        self.logger.setLevel(logging.DEBUG)
        self.stack.log_to(self.logger)
        self.assertEqual(self._refuse(), Status.WRONG_STATE)
        self.assertTrue(self.caught.arrived.wait(5))
        record = self.caught.records[0]
        self.assertEqual(record.name, f"{self.logger.name}.api")
        self.assertEqual(record.levelno, logging.DEBUG)
        self.assertIn("refused, WrongState", record.getMessage())
        self.assertEqual(record.sipral_suppressed, 0)

    def test_the_stack_is_as_quiet_as_the_logger(self) -> None:
        self.logger.setLevel(logging.INFO)
        self.stack.log_to(self.logger)
        self.assertEqual(self._refuse(), Status.WRONG_STATE)
        self.assertEqual(self.caught.records, [], "a debug line reached a logger at INFO")
        self._state_says("log: info,")

    def test_trace_sits_below_debug(self) -> None:
        self.assertLess(TRACE, logging.DEBUG)
        self.logger.setLevel(TRACE)
        self.stack.log_to(self.logger)
        self._state_says("log: trace,")


class Counting(unittest.TestCase):
    def test_a_request_nobody_answers_is_counted_as_sent_again(self) -> None:
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        stack = Stack(audio=AudioMode.APPLICATION)
        self.addCleanup(stack.close)
        before = stack.counters()
        self.assertEqual(before.requests_retransmitted, 0)
        account = stack.add_account(
            "sip:alice@sipral.invalid",
            registrar_address="127.0.0.1:%d" % silent.getsockname()[1],
            registrar="sip:sipral.invalid",
        )
        account.register()
        deadline = time.monotonic() + 5
        while stack.counters().requests_retransmitted == 0 and time.monotonic() < deadline:
            time.sleep(0.1)
        after = stack.counters()
        self.assertGreater(after.requests_retransmitted, 0)
        self.assertGreater(after.registrations_attempted, 0)
        self.assertEqual(after.requests_refused_at_limit, 0)


class PortRange(unittest.IsolatedAsyncioTestCase):
    async def test_a_call_is_carried_on_even_ports_from_each_stacks_range(self) -> None:
        loop = asyncio.get_running_loop()
        alice = Stack(loop=loop, audio=AudioMode.APPLICATION, rtp_port_min=46100, rtp_port_max=46119)
        bob = Stack(loop=loop, audio=AudioMode.APPLICATION, rtp_port_min=46200, rtp_port_max=46219)
        self.addCleanup(alice.close)
        self.addCleanup(bob.close)
        account = alice.add_account("sip:alice@sipral.invalid", registrar_address=bob.bind_address)
        bob.add_account("sip:bob@sipral.invalid", registrar_address=alice.bind_address)

        alice_call = alice.place_call(account, f"sip:bob@{bob.bind_address}")
        bob_call = None
        while bob_call is None:
            event = await asyncio.wait_for(bob.events.get(), timeout=5)
            if event.kind == EventKind.INCOMING_CALL:
                bob_call = bob.answer_call(event)
        while alice_call.media is None or bob_call.media is None:
            await asyncio.sleep(0.05)

        for call, low, high in ((alice_call, 46100, 46119), (bob_call, 46200, 46219)):
            _, port = call.media_socket.getsockname()
            self.assertTrue(low <= port < high and port % 2 == 0, port)
        alice_call.close()
        bob_call.close()

    def test_a_range_with_no_pair_left_says_so(self) -> None:
        stack = Stack(audio=AudioMode.APPLICATION, rtp_port_min=46300, rtp_port_max=46301)
        self.addCleanup(stack.close)
        first = stack.open_media_socket("127.0.0.1")
        self.addCleanup(first.close)
        self.assertEqual(first.getsockname()[1], 46300)
        with self.assertRaises(SipralError) as refused:
            stack.open_media_socket("127.0.0.1")
        self.assertEqual(refused.exception.status, Status.EXHAUSTED)


if __name__ == "__main__":
    unittest.main()
