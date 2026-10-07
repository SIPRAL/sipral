# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Calls the agent places: ``dial`` rings a number, decides who answered,
and joins the call to the agent only when the answer is one the
application wants the agent to talk to.

Who answered is decided by the library (``Call.detect_progress``, the
answering-machine detector of ``docs/05-media.md``) from the first seconds
of the far end's audio: a short greeting and then silence is a person; a
greeting that runs on, or has more words than a person answers with, is a
machine. :class:`MachinePolicy` says what happens next:

- ``on_machine = "hangup"`` (the default): the call is hung up and the
  agent never connects.
- ``on_machine = "message"``: the agent connects at the machine's beep, so
  that what it says is recorded from its first word; with no beep within
  ``beep_wait_s``, it connects then.
- ``on_machine = "agent"``: the agent connects as it would for a person.

``on_unknown`` does the same for a verdict the detector could not reach
("hangup" or "agent", the default). A call nobody answers ends with
``"no_answer"``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sipral import Account, Call, SipralError, Stack
from sipral.enums import AmdVerdict, EventKind, ProgressKind

from .core import AgentCall, Backoff
from .serve import ProviderFactory, _maybe_await, wait_for_media

__all__ = ["MachinePolicy", "dial"]

_log = logging.getLogger("sipral_agents.outbound")

#: What ``on_machine`` takes.
ON_MACHINE = ("hangup", "message", "agent")
#: What ``on_unknown`` takes.
ON_UNKNOWN = ("hangup", "agent")

#: The detector's limits a policy may set, each passed to
#: ``Call.detect_progress`` as it is; zero or absent is the library's default.
DETECTOR_KEYS = (
    "max_initial_silence_ms",
    "max_greeting_ms",
    "silence_after_greeting_ms",
    "max_words",
    "min_word_ms",
    "min_word_gap_ms",
    "max_decision_ms",
    "min_speech_above_floor_db",
    "beep_min_ms",
    "beep_max_ms",
)


@dataclass
class MachinePolicy:
    """What a placed call does once the detector has said who answered.

    ``detector`` holds any of :data:`DETECTOR_KEYS`, in milliseconds (and
    dB for ``min_speech_above_floor_db``).
    """

    on_machine: str = "hangup"
    on_unknown: str = "agent"
    beep_wait_s: float = 20.0
    detector: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.on_machine not in ON_MACHINE:
            raise ValueError(f"on_machine is one of {', '.join(ON_MACHINE)}")
        if self.on_unknown not in ON_UNKNOWN:
            raise ValueError(f"on_unknown is one of {', '.join(ON_UNKNOWN)}")
        if not 0 < self.beep_wait_s <= 120:
            raise ValueError("beep_wait_s is more than 0 and at most 120 seconds")
        unknown = set(self.detector) - set(DETECTOR_KEYS)
        if unknown:
            raise ValueError(f"the detector has no setting {', '.join(sorted(unknown))}")
        for key, value in self.detector.items():
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{key} is a whole number of milliseconds")


async def dial(
    stack: Stack,
    account: Account,
    target: str,
    factory: ProviderFactory,
    *,
    policy: MachinePolicy | None = None,
    media_host: str | None = None,
    backoff: Backoff | None = None,
    ring_timeout: float = 60.0,
    on_agent_call: Callable[[AgentCall], object] | None = None,
) -> str:
    """Place a call from ``account`` to ``target`` and join it to the
    provider ``factory(call)`` builds once the policy says so.

    Returns what became of it: ``"human"``, ``"machine"`` (hung up),
    ``"message"`` (the agent left one after the beep), ``"machine_agent"``
    (the agent talked to the machine), ``"unknown"`` (the detector could not
    tell, and the agent talked) or ``"unknown_hangup"``, ``"no_answer"``.
    The stack must run with ``loop=`` the running loop and
    ``audio=AudioMode.APPLICATION``; this reads the call's own ``events``
    until the agent joins.
    """
    policy = policy or MachinePolicy()
    call = stack.place_call(account, target, media_host=media_host)
    agent: AgentCall | None = None
    try:
        call.detect_progress(
            answering_machine=True,
            beep=policy.on_machine == "message",
            beep_window_ms=int(policy.beep_wait_s * 1000),
            **policy.detector,
        )
        verdict = await _answered_by(call, ring_timeout)
        if verdict is None:
            return "no_answer"
        if verdict == AmdVerdict.HUMAN:
            outcome = "human"
        elif verdict == AmdVerdict.MACHINE:
            if policy.on_machine == "hangup":
                return "machine"
            if policy.on_machine == "message":
                await _beep(call, policy.beep_wait_s)
                outcome = "message"
            else:
                outcome = "machine_agent"
        else:
            if policy.on_unknown == "hangup":
                return "unknown_hangup"
            outcome = "unknown"
        if call.ended or not await wait_for_media(call, 5.0):
            return "no_answer"
        _log.info("call %x to %s: %s", call.handle, target, outcome)
        provider = await _maybe_await(factory(call))
        agent = AgentCall(call, provider, backoff=backoff)
        if on_agent_call is not None:
            await _maybe_await(on_agent_call(agent))
        await agent.run()
        return outcome
    except asyncio.CancelledError:
        if agent is not None:
            await agent.close()
        raise
    finally:
        await _end(call)


async def _answered_by(call: Call, ring_timeout: float) -> Any:
    """The detector's verdict, or ``None`` for a call that ended or was not
    answered in time."""
    try:
        async with asyncio.timeout(ring_timeout):
            while True:
                event = await call.events.get()
                if event.kind == EventKind.CALL_ENDED:
                    return None
                if (
                    event.kind == EventKind.PROGRESS_DETECTED
                    and event.fields.get("what") == ProgressKind.ANSWERED_BY
                ):
                    return event.fields.get("verdict")
    except TimeoutError:
        return None


async def _beep(call: Call, wait_s: float) -> None:
    """Until the machine's beep, the call's end, or ``wait_s`` seconds."""
    try:
        async with asyncio.timeout(wait_s):
            while True:
                event = await call.events.get()
                if event.kind == EventKind.CALL_ENDED:
                    return
                if (
                    event.kind == EventKind.PROGRESS_DETECTED
                    and event.fields.get("what") == ProgressKind.BEEP
                ):
                    return
    except TimeoutError:
        return


async def _end(call: Call) -> None:
    if not call.ended:
        try:
            call.hangup()
        except SipralError:
            pass
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 2.0
    while not call.ended and loop.time() < deadline:
        await asyncio.sleep(0.02)
    # the call's RTCP goodbye can be queued a poll after CALL_ENDED
    await asyncio.sleep(0.2)
    call.close()
