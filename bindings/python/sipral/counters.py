# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Counters``: a stack's health counters, `sipral_counters_t` as Python.

Read with :meth:`sipral.Stack.counters`. Every field only ever grows, except
``active_calls``, which is a gauge. Sampled on a timer, the difference
between two readings is the rate an application ships as telemetry: over UDP,
``requests_retransmitted`` and ``responses_retransmitted`` climbing while
calls still connect is a path losing packets before it loses calls
(`docs/08-ffi.md`, "Limits, and what went out twice").
"""

from __future__ import annotations

import dataclasses

__all__ = ["Counters"]


@dataclasses.dataclass(frozen=True)
class Counters:
    """One reading of `sipral_stack_counters`, since the stack was created."""

    #: A REGISTER went out, counted once per attempt including a retry.
    registrations_attempted: int
    #: The registrar granted a binding.
    registrations_succeeded: int
    #: The registrar refused, and will refuse the same request again.
    registrations_failed_rejected: int
    #: The password was wrong, or there was none to answer a challenge with.
    registrations_failed_bad_credentials: int
    #: The registrar did not answer, or said it could not serve this now.
    registrations_failed_unreachable: int
    #: The registrar moved.
    registrations_failed_redirected: int
    #: Calls this end hung up.
    calls_ended_local_hangup: int
    #: Calls the far end hung up.
    calls_ended_remote_hangup: int
    #: Calls the far end refused: busy, declined, not found.
    calls_ended_refused: int
    #: Calls given up before they were answered, from either end.
    calls_ended_cancelled: int
    #: Calls to which nothing came back, or whose transport died.
    calls_ended_unreachable: int
    #: Branches of a fork that were not kept when another was.
    calls_ended_fork_lost: int
    #: Branches still ringing when the answer window closed.
    calls_ended_abandoned: int
    #: Calls whose session timer ran out with no refresh.
    calls_ended_expired: int
    #: Times inbound audio stopped past the threshold while signalling
    #: stayed healthy.
    media_gaps: int
    #: Times a jitter buffer shrank or stretched the stream to hold its delay.
    jitter_buffer_events: int
    #: Requests too large for a datagram with no stream to put them on, so
    #: the stack asked for one (RFC 3261 section 18.1.1).
    stream_transport_wanted: int
    #: Calls with media running right now: the one gauge here.
    active_calls: int
    #: Events raised with nowhere to queue, the outbox at its ceiling.
    events_dropped: int
    #: RTCP goodbyes dropped, oldest first, their queue at its ceiling.
    farewells_dropped: int
    #: INVITEs the screening policy refused.
    screened_refused_by_policy: int
    #: INVITEs refused for arriving faster than the INVITE limit allows.
    screened_refused_by_rate: int
    #: INVITEs refused because every seat for a watched source was taken.
    screened_refused_by_crowding: int
    #: INVITEs refused 403 for naming a call they could not replace
    #: (RFC 3891 section 3).
    screened_refused_by_replaces: int
    #: Requests sent again because nothing answered in time (RFC 3261
    #: timers A and E), and ACKs sent again for a 2xx that arrived again.
    requests_retransmitted: int
    #: Responses sent again: timer G, a reliable provisional response's own
    #: timer (RFC 3262), and a last response repeated for a repeated request.
    responses_retransmitted: int
    #: Transactions that ended because the far end never answered or never
    #: acknowledged (timers B, F, H and L), and a reliable provisional
    #: response never PRACKed.
    transactions_timed_out: int
    #: ``503`` responses sent because a request or an INVITE arrived past
    #: ``max_server_transactions`` or ``max_dialogs``.
    requests_refused_at_limit: int

    @classmethod
    def from_raw(cls, raw) -> "Counters":
        """Read every field of a filled-in `sipral_counters_t`."""
        return cls(**{field.name: int(getattr(raw, field.name)) for field in dataclasses.fields(cls)})
