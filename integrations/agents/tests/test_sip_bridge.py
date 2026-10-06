# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The SIP bridge between three stacks on loopback: a PBX, the bridge and a
SIP voice agent.

The caller's context goes on the INVITE to the agent, the outcome the agent
names on its BYE goes on the BYE to the PBX, and a transfer the bridge
places itself is reported to the agent's REFER as the call it placed.
"""

from __future__ import annotations

import asyncio
import unittest

from sipral import Stack
from sipral.enums import AudioMode, EventKind

from sipral_agents.sip_bridge import BridgeConfig, BridgedCall, outcome_of


def header(message: bytes | None, name: str) -> str | None:
    for line in (message or b"").decode("utf-8", "replace").split("\r\n"):
        if line.lower().startswith(f"{name.lower()}:"):
            return line.split(":", 1)[1].strip()
    return None


async def next_event(queue: asyncio.Queue, kind: int, status: int | None = None):
    async with asyncio.timeout(5):
        while True:
            event = await queue.get()
            if event.kind == kind and status in (None, event.fields.get("status_code")):
                return event


class TheOutcomeOnABye(unittest.TestCase):
    def test_only_a_bye_naming_a_known_outcome_counts(self) -> None:
        bye = b"BYE sip:a@b SIP/2.0\r\nX-Sipral-Outcome: Callback\r\n\r\n"
        self.assertEqual(outcome_of(bye), "callback")
        self.assertIsNone(outcome_of(bye.replace(b"Callback", b"lunch")))
        self.assertIsNone(outcome_of(b"SIP/2.0 486 Busy\r\nX-Sipral-Outcome: resolved\r\n\r\n"))
        self.assertIsNone(outcome_of(None))


class ABridgeBetweenAPbxAndAnAgent(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        loop = asyncio.get_running_loop()
        self.pbx = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.agent = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.bridge = Stack(loop=loop, audio=AudioMode.APPLICATION)
        self.pbx_line = self.pbx.add_account(
            "sip:pbx@sipral.invalid", registrar_address=self.bridge.bind_address
        )
        self.agent.add_account("sip:agent@sipral.invalid", registrar_address=self.bridge.bind_address)
        self.cfg = BridgeConfig(
            pbx_domain=self.pbx.bind_address,
            agent_uri=f"sip:agent@{self.agent.bind_address}",
            agent_account=self.bridge.add_account(
                "sip:bridge@sipral.invalid", registrar_address=self.agent.bind_address
            ),
            line=self.bridge.add_account(
                "sip:bridge@sipral.invalid", registrar_address=self.pbx.bind_address
            ),
            transfer="bridge",
        )
        self.serving = asyncio.create_task(self.serve())
        self.addAsyncCleanup(self._close)

    async def serve(self) -> None:
        pairs = set()
        try:
            while True:
                event = await self.bridge.events.get()
                if event.kind == EventKind.INCOMING_CALL:
                    caller = self.bridge.answer_call(event)
                    task = asyncio.create_task(
                        BridgedCall(self.bridge, self.cfg, caller, event.message).run()
                    )
                    pairs.add(task)
        finally:
            for task in pairs:
                task.cancel()

    async def _close(self) -> None:
        self.serving.cancel()
        await asyncio.gather(self.serving, return_exceptions=True)
        for stack in (self.pbx, self.agent, self.bridge):
            stack.close()

    async def connected(self):
        """The PBX's call to the bridge, and the agent's end of it, up."""
        caller = self.pbx.place_call(
            self.pbx_line,
            f"sip:bridge@{self.bridge.bind_address}",
            headers={"X-Ticket": "42"},
        )
        incoming = await next_event(self.agent.events, EventKind.INCOMING_CALL)
        agent_call = self.agent.answer_call(incoming)
        await next_event(agent_call.events, EventKind.CALL_CONFIRMED)
        return caller, agent_call, incoming

    async def test_the_context_goes_to_the_agent_and_its_outcome_back(self) -> None:
        caller, agent_call, incoming = await self.connected()
        self.assertEqual(header(incoming.message, "X-Ticket"), "42")
        self.assertEqual(header(incoming.message, "X-Sipral-Caller-Number"), "pbx")

        agent_call.set_headers([("X-Sipral-Outcome", "callback")])
        agent_call.hangup()
        ended = await next_event(caller.events, EventKind.CALL_ENDED)
        self.assertTrue(ended.message.startswith(b"BYE "), ended.message)
        self.assertEqual(header(ended.message, "X-Sipral-Outcome"), "callback")

    async def test_a_transfer_placed_by_the_bridge_is_reported_to_the_agent(self) -> None:
        caller, agent_call, _ = await self.connected()
        agent_call.transfer(f"sip:200@{self.pbx.bind_address}")
        person = await next_event(self.pbx.events, EventKind.INCOMING_CALL)
        self.pbx.answer_call(person)
        done = await next_event(agent_call.events, EventKind.TRANSFER_DONE)
        self.assertEqual(done.fields.get("status_code"), 200)
        await next_event(agent_call.events, EventKind.CALL_ENDED)
        self.assertFalse(caller.ended, "the caller stays, with the person now")


if __name__ == "__main__":
    unittest.main()
