# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``serve``: answer every call to one account, one pipeline per call."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable

from loguru import logger
from pipecat.pipeline.worker import PipelineWorker
from pipecat.workers.runner import WorkerRunner

from sipral import Account, Call, Event, SipralError
from sipral.enums import EventKind

from .transport import SipralTransport, SipralTransportParams, wait_for_media

__all__ = ["PipelineFactory", "serve"]

#: Builds the pipeline for one call, given its transport.
PipelineFactory = Callable[[SipralTransport], "PipelineWorker | Awaitable[PipelineWorker]"]


async def serve(
    account: Account,
    factory: PipelineFactory,
    *,
    params: SipralTransportParams | None = None,
    media_host: str | None = None,
    media_timeout: float = 10.0,
    on_event: Callable[[Event], object] | None = None,
) -> None:
    """Answer every call that comes to ``account`` and run, for each, the
    `PipelineWorker` ``factory`` builds over its :class:`SipralTransport`,
    until cancelled.

    Calls run side by side, each in a runner of its own, so one process
    serves as many as the stack takes; a call whose pipeline fails is hung
    up and the others go on. This reads ``account.stack.events``: every
    event, the incoming calls included, is handed to ``on_event`` first,
    which may be a coroutine function. The stack must have been created with
    ``loop=`` the running loop and ``audio=AudioMode.APPLICATION``.
    """
    stack = account.stack
    calls: set[asyncio.Task] = set()
    try:
        while True:
            event = await stack.events.get()
            if on_event is not None:
                handled = on_event(event)
                if inspect.isawaitable(handled):
                    await handled
            if event.kind != EventKind.INCOMING_CALL or event.account != account.handle:
                continue
            try:
                call = stack.answer_call(event, media_host=media_host)
            except SipralError as refused:
                logger.warning(f"sipral: could not answer call {event.call:x}: {refused}")
                continue
            task = asyncio.create_task(_run_call(call, factory, params, media_timeout))
            calls.add(task)
            task.add_done_callback(calls.discard)
    finally:
        running = list(calls)
        for task in running:
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)


async def _run_call(
    call: Call,
    factory: PipelineFactory,
    params: SipralTransportParams | None,
    media_timeout: float,
) -> None:
    try:
        if not await wait_for_media(call, media_timeout):
            logger.warning(f"sipral: call {call.handle:x} ended before its media started")
            return
        worker = factory(SipralTransport(call, params))
        if inspect.isawaitable(worker):
            worker = await worker
        runner = WorkerRunner(handle_sigint=False)
        await runner.add_workers(worker)
        await runner.run()
    except Exception:
        logger.exception(f"sipral: the pipeline of call {call.handle:x} failed")
    finally:
        if not call.ended:
            try:
                call.hangup()
            except SipralError:
                pass
        await _wait_for_end(call, 2.0)
        # the call's farewell (its RTCP BYE) can be queued a poll after
        # CALL_ENDED, and closing first would drop it
        await asyncio.sleep(0.2)
        call.close()


async def _wait_for_end(call: Call, timeout: float) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not call.ended and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.02)
