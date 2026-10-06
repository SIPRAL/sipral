# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``serve``: answer every call to one account, one agent session per call."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable

from sipral import Account, Call, Event, SipralError
from sipral.enums import EventKind

from .core import AgentCall, Backoff, Provider

__all__ = ["ProviderFactory", "serve", "wait_for_media"]

_log = logging.getLogger("sipral_agents")

#: Builds the provider for one call, given the call.
ProviderFactory = Callable[[Call], "Provider | Awaitable[Provider]"]


async def wait_for_media(call: Call, timeout: float | None = None) -> bool:
    """Wait until ``call.media`` exists; `False` when the call ended first
    or ``timeout`` passed."""

    async def started() -> None:
        while call.media is None and not call.ended:
            await asyncio.sleep(0.01)

    try:
        await asyncio.wait_for(started(), timeout)
    except TimeoutError:
        return False
    return call.media is not None and not call.ended


async def serve(
    account: Account,
    factory: ProviderFactory,
    *,
    backoff: Backoff | None = None,
    media_host: str | None = None,
    media_timeout: float = 10.0,
    on_event: Callable[[Event], object] | None = None,
    on_agent_call: Callable[[AgentCall], object] | None = None,
) -> None:
    """Answer every call that comes to ``account`` and join each to the
    provider ``factory(call)`` builds, until cancelled.

    Calls run side by side, so one process serves as many as the stack
    takes. This reads ``account.stack.events``: every event is handed to
    ``on_event`` first. ``on_agent_call`` sees each :class:`AgentCall`
    before it runs, to read its ``events``. Either may be a coroutine
    function. The stack must have been created with ``loop=`` the running
    loop and ``audio=AudioMode.APPLICATION``.
    """
    stack = account.stack
    calls: set[asyncio.Task] = set()
    try:
        while True:
            event = await stack.events.get()
            if on_event is not None:
                await _maybe_await(on_event(event))
            if event.kind != EventKind.INCOMING_CALL or event.account != account.handle:
                continue
            try:
                call = stack.answer_call(event, media_host=media_host)
            except SipralError as refused:
                _log.warning("could not answer call %x: %s", event.call, refused)
                continue
            task = asyncio.create_task(
                _run_call(call, factory, backoff, media_timeout, on_agent_call)
            )
            calls.add(task)
            task.add_done_callback(calls.discard)
    finally:
        running = list(calls)
        for task in running:
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)


async def _run_call(
    call: Call,
    factory: ProviderFactory,
    backoff: Backoff | None,
    media_timeout: float,
    on_agent_call: Callable[[AgentCall], object] | None,
) -> None:
    agent: AgentCall | None = None
    try:
        if not await wait_for_media(call, media_timeout):
            _log.warning("call %x ended before its media started", call.handle)
            return
        provider = await _maybe_await(factory(call))
        agent = AgentCall(call, provider, backoff=backoff)
        if on_agent_call is not None:
            await _maybe_await(on_agent_call(agent))
        await agent.run()
    except asyncio.CancelledError:
        if agent is not None:
            await agent.close()
        raise
    except Exception:
        _log.exception("the agent session of call %x failed", call.handle)
    finally:
        if not call.ended:
            try:
                call.hangup()
            except SipralError:
                pass
        deadline = asyncio.get_running_loop().time() + 2.0
        while not call.ended and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        # the call's farewell (its RTCP BYE) can be queued a poll after
        # CALL_ENDED, and closing first would drop it
        await asyncio.sleep(0.2)
        call.close()


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value
