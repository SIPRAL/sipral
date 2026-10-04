// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// One reading of a stack's health counters since it was created
/// (`sipral_stack_counters`), read with `SipralStack.counters()`.
///
/// Every field only grows, except `activeCalls`, which is a gauge. Sampled on
/// a timer, the difference between two readings is the rate an application
/// ships as telemetry: over UDP, `requestsRetransmitted` and
/// `responsesRetransmitted` climbing while calls still connect is a path
/// losing packets before it loses calls (`docs/08-ffi.md`, "Limits, and what
/// went out twice").
public struct SipralCounters: Sendable, Equatable {
    /// A REGISTER went out, counted once per attempt including a retry.
    public let registrationsAttempted: UInt64
    /// The registrar granted a binding.
    public let registrationsSucceeded: UInt64
    /// The registrar refused, and will refuse the same request again.
    public let registrationsFailedRejected: UInt64
    /// The password was wrong, or there was none to answer a challenge with.
    public let registrationsFailedBadCredentials: UInt64
    /// The registrar did not answer, or said it could not serve this now.
    public let registrationsFailedUnreachable: UInt64
    /// The registrar moved.
    public let registrationsFailedRedirected: UInt64
    /// Calls this end hung up.
    public let callsEndedLocalHangup: UInt64
    /// Calls the far end hung up.
    public let callsEndedRemoteHangup: UInt64
    /// Calls the far end refused: busy, declined, not found.
    public let callsEndedRefused: UInt64
    /// Calls given up before they were answered, from either end.
    public let callsEndedCancelled: UInt64
    /// Calls to which nothing came back, or whose transport died.
    public let callsEndedUnreachable: UInt64
    /// Branches of a fork that were not kept when another was.
    public let callsEndedForkLost: UInt64
    /// Branches still ringing when the answer window closed.
    public let callsEndedAbandoned: UInt64
    /// Calls whose session timer ran out with no refresh.
    public let callsEndedExpired: UInt64
    /// Times inbound audio stopped past the threshold while signalling stayed
    /// healthy.
    public let mediaGaps: UInt64
    /// Times a jitter buffer shrank or stretched the stream to hold its delay.
    public let jitterBufferEvents: UInt64
    /// Requests too large for a datagram with no stream to put them on, so
    /// the stack asked for one (RFC 3261 §18.1.1).
    public let streamTransportWanted: UInt64
    /// Calls with media running right now: the one gauge here.
    public let activeCalls: UInt64
    /// Events raised with nowhere to queue, the outbox at its ceiling.
    public let eventsDropped: UInt64
    /// RTCP goodbyes dropped, oldest first, their queue at its ceiling.
    public let farewellsDropped: UInt64
    /// INVITEs the screening policy refused.
    public let screenedRefusedByPolicy: UInt64
    /// INVITEs refused for arriving faster than the INVITE limit allows.
    public let screenedRefusedByRate: UInt64
    /// INVITEs refused because every seat for a watched source was taken.
    public let screenedRefusedByCrowding: UInt64
    /// INVITEs refused 403 for naming a call they could not replace (RFC 3891
    /// §3).
    public let screenedRefusedByReplaces: UInt64
    /// Requests sent again because nothing answered in time (RFC 3261 timers
    /// A and E), and ACKs sent again for a 2xx that arrived again.
    public let requestsRetransmitted: UInt64
    /// Responses sent again: timer G, a reliable provisional response's own
    /// timer (RFC 3262), and a last response repeated for a repeated request.
    public let responsesRetransmitted: UInt64
    /// Transactions that ended because the far end never answered or never
    /// acknowledged (timers B, F, H and L), and a reliable provisional
    /// response never PRACKed.
    public let transactionsTimedOut: UInt64
    /// `503` responses sent because a request or an INVITE arrived past
    /// `maxServerTransactions` or `maxDialogs`.
    public let requestsRefusedAtLimit: UInt64

    init(_ raw: sipral_counters_t) {
        registrationsAttempted = raw.registrations_attempted
        registrationsSucceeded = raw.registrations_succeeded
        registrationsFailedRejected = raw.registrations_failed_rejected
        registrationsFailedBadCredentials = raw.registrations_failed_bad_credentials
        registrationsFailedUnreachable = raw.registrations_failed_unreachable
        registrationsFailedRedirected = raw.registrations_failed_redirected
        callsEndedLocalHangup = raw.calls_ended_local_hangup
        callsEndedRemoteHangup = raw.calls_ended_remote_hangup
        callsEndedRefused = raw.calls_ended_refused
        callsEndedCancelled = raw.calls_ended_cancelled
        callsEndedUnreachable = raw.calls_ended_unreachable
        callsEndedForkLost = raw.calls_ended_fork_lost
        callsEndedAbandoned = raw.calls_ended_abandoned
        callsEndedExpired = raw.calls_ended_expired
        mediaGaps = raw.media_gaps
        jitterBufferEvents = raw.jitter_buffer_events
        streamTransportWanted = raw.stream_transport_wanted
        activeCalls = raw.active_calls
        eventsDropped = raw.events_dropped
        farewellsDropped = raw.farewells_dropped
        screenedRefusedByPolicy = raw.screened_refused_by_policy
        screenedRefusedByRate = raw.screened_refused_by_rate
        screenedRefusedByCrowding = raw.screened_refused_by_crowding
        screenedRefusedByReplaces = raw.screened_refused_by_replaces
        requestsRetransmitted = raw.requests_retransmitted
        responsesRetransmitted = raw.responses_retransmitted
        transactionsTimedOut = raw.transactions_timed_out
        requestsRefusedAtLimit = raw.requests_refused_at_limit
    }
}
