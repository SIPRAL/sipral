// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A flat set of counters, cheap enough to sample on a timer.
//!
//! D3: instead of grepping logs to judge health, an operator reads a few numbers: registrations
//! attempted and succeeded, failures split by [`RegistrationFailure`], call endings split by
//! [`CallEndReason`], and three numbers only this layer can see: media gaps caught by the stall
//! watchdog, jitter buffer adjustments, and requests too large for a datagram with no stream to
//! send them on.
//!
//! # Counters and gauges
//!
//! [`Counter`] only grows; [`Gauge`] moves both ways. Subtracting an earlier [`Counters`] reading
//! from a later one gives each counter's growth and each gauge's current value.
//!
//! # Sources
//!
//! Only the events [`crate::MediaEngine::poll_event`] already drains. Reading is a struct copy;
//! nothing walks the call table.
//!
//! Retransmissions are deliberately absent: `sipral-core` keeps them inside its transaction state
//! machines and raises no event, and reading them would need a second path into the lower layers.
//! `docs/17-observability.md` says so too.

use sipral_core::endpoint::Event as CoreEvent;
use sipral_ua::{CallEndReason, RegistrationFailure, UaEvent};

use crate::event::MediaEvent;

/// A count that only grows. A distinct type from [`Gauge`], so readings are subtracted ("how many
/// happened"), never compared for decrease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counter(u64);

impl Counter {
    /// The count itself.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn tick(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    fn tick_by(&mut self, amount: u64) {
        self.0 = self.0.saturating_add(amount);
    }
}

impl core::ops::Sub for Counter {
    type Output = Self;

    /// How many happened between an earlier reading and this one. Saturates to zero if the readings
    /// are swapped, rather than panicking.
    fn sub(self, earlier: Self) -> Self {
        Self(self.0.saturating_sub(earlier.0))
    }
}

/// A count that moves both ways: the current value, not a running total.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gauge(u64);

impl Gauge {
    /// What it reads now.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    fn decrement(&mut self) {
        self.0 = self.0.saturating_sub(1);
    }
}

/// Registration failures, split the four ways [`RegistrationFailure`] reports them, so an operator
/// knows where to look.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegistrationFailureCounts {
    /// The registrar refused, and will refuse the same request again.
    pub rejected: Counter,
    /// The password was wrong, or there was none to answer a challenge with.
    pub bad_credentials: Counter,
    /// The registrar did not answer, or said it could not serve this now.
    pub unreachable: Counter,
    /// The registrar moved.
    pub redirected: Counter,
}

impl RegistrationFailureCounts {
    fn tick(&mut self, reason: RegistrationFailure) {
        match reason {
            RegistrationFailure::Rejected => self.rejected.tick(),
            RegistrationFailure::BadCredentials => self.bad_credentials.tick(),
            RegistrationFailure::Unreachable => self.unreachable.tick(),
            RegistrationFailure::Redirected => self.redirected.tick(),
            // `RegistrationFailure` is non_exhaustive: an unknown future reason is better uncounted
            // than counted under the wrong name
            _ => {}
        }
    }

    /// Every failure, whatever the reason.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.rejected.get()
            + self.bad_credentials.get()
            + self.unreachable.get()
            + self.redirected.get()
    }
}

impl core::ops::Sub for RegistrationFailureCounts {
    type Output = Self;

    fn sub(self, earlier: Self) -> Self {
        Self {
            rejected: self.rejected - earlier.rejected,
            bad_credentials: self.bad_credentials - earlier.bad_credentials,
            unreachable: self.unreachable - earlier.unreachable,
            redirected: self.redirected - earlier.redirected,
        }
    }
}

/// Why a call ended, tallied the same eight ways [`CallEndReason`] can say it
/// did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallDispositionCounts {
    /// This end hung up.
    pub local_hangup: Counter,
    /// The far end hung up.
    pub remote_hangup: Counter,
    /// The far end refused it: busy, declined, not found.
    pub refused: Counter,
    /// Given up before it was answered, from either end.
    pub cancelled: Counter,
    /// Nothing came back, or the transport died.
    pub unreachable: Counter,
    /// Another branch of the same fork was kept and this one was not.
    pub fork_lost: Counter,
    /// The branch was still ringing when the answer window closed.
    pub abandoned: Counter,
    /// The session timer ran out and no refresh arrived.
    pub expired: Counter,
}

impl CallDispositionCounts {
    fn tick(&mut self, reason: CallEndReason) {
        match reason {
            CallEndReason::LocalHangup => self.local_hangup.tick(),
            CallEndReason::RemoteHangup => self.remote_hangup.tick(),
            CallEndReason::Refused => self.refused.tick(),
            CallEndReason::Cancelled => self.cancelled.tick(),
            CallEndReason::Unreachable => self.unreachable.tick(),
            CallEndReason::ForkLost => self.fork_lost.tick(),
            CallEndReason::Abandoned => self.abandoned.tick(),
            CallEndReason::Expired => self.expired.tick(),
            // non_exhaustive, as above
            _ => {}
        }
    }

    /// Every call that has ended, whatever the disposition.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.local_hangup.get()
            + self.remote_hangup.get()
            + self.refused.get()
            + self.cancelled.get()
            + self.unreachable.get()
            + self.fork_lost.get()
            + self.abandoned.get()
            + self.expired.get()
    }
}

impl core::ops::Sub for CallDispositionCounts {
    type Output = Self;

    fn sub(self, earlier: Self) -> Self {
        Self {
            local_hangup: self.local_hangup - earlier.local_hangup,
            remote_hangup: self.remote_hangup - earlier.remote_hangup,
            refused: self.refused - earlier.refused,
            cancelled: self.cancelled - earlier.cancelled,
            unreachable: self.unreachable - earlier.unreachable,
            fork_lost: self.fork_lost - earlier.fork_lost,
            abandoned: self.abandoned - earlier.abandoned,
            expired: self.expired - earlier.expired,
        }
    }
}

/// D3's health counters for one [`crate::MediaEngine`], since it was created.
///
/// Reading is a struct copy, cheap enough to sample on a timer for telemetry. `later - earlier`
/// gives each counter's growth over the interval and each gauge's current value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counters {
    /// REGISTER requests sent ([`UaEvent::Registering`]), retries included.
    pub registrations_attempted: Counter,
    /// The registrar granted a binding.
    pub registrations_succeeded: Counter,
    /// The registrar did not, split by why.
    pub registrations_failed: RegistrationFailureCounts,
    /// How every call that has ended, ended.
    pub calls_ended: CallDispositionCounts,
    /// Times [`MediaEvent::Stalled`] fired: inbound audio stopped longer than the threshold while
    /// signalling was fine (B5).
    pub media_gaps: Counter,
    /// Times a call's jitter buffer shrank or stretched the stream to hold its target delay
    /// ([`sipral_rtp::Quality`]'s `shrunk` and `stretched`, added at call end). Not loss:
    /// adaptation hides loss, so a rising count shows a worsening network before callers notice.
    pub jitter_buffer_events: Counter,
    /// Times a request did not fit a datagram and no stream to the destination existed, so the
    /// stack asked for one (RFC 3261 §18.1.1, B1).
    ///
    /// A request moved onto an existing connection does **not** count here, since nothing is
    /// requested; those appear in the diagnostic record as `transport.promoted.size`
    /// (`docs/14-diagnostics.md`). Do not read this as "how often promotion happens".
    pub stream_transport_wanted: Counter,
    /// Calls with media running right now.
    pub active_calls: Gauge,
}

impl Counters {
    /// Take in a signalling event. Called from [`crate::MediaEngine::poll_event`] for every one it
    /// drains.
    pub(crate) fn observe_signalling(&mut self, event: &UaEvent) {
        match event {
            UaEvent::Registering { .. } => self.registrations_attempted.tick(),
            UaEvent::Registered { .. } => self.registrations_succeeded.tick(),
            UaEvent::RegistrationFailed { reason, .. } => self.registrations_failed.tick(*reason),
            UaEvent::CallEnded { reason, .. } => self.calls_ended.tick(*reason),
            // B1: a message did not fit a datagram and there was no stream, so the endpoint asked
            // for one; sipral-ua passes it through unhandled
            UaEvent::Unclaimed(CoreEvent::TransportWanted { .. }) => {
                self.stream_transport_wanted.tick();
            }
            _ => {}
        }
    }

    /// Take in a media event, from the same place as [`Counters::observe_signalling`].
    pub(crate) fn observe_media(&mut self, event: &MediaEvent) {
        match event {
            MediaEvent::Started { .. } => self.active_calls.increment(),
            MediaEvent::Stalled { .. } => self.media_gaps.tick(),
            MediaEvent::Ended(statistics) => {
                self.active_calls.decrement();
                let adaptations = statistics
                    .quality
                    .shrunk
                    .saturating_add(statistics.quality.stretched);
                self.jitter_buffer_events.tick_by(adaptations);
            }
            _ => {}
        }
    }
}

impl core::ops::Sub for Counters {
    type Output = Self;

    /// The difference from an earlier reading: counters as growth, gauges as current value.
    fn sub(self, earlier: Self) -> Self {
        Self {
            registrations_attempted: self.registrations_attempted - earlier.registrations_attempted,
            registrations_succeeded: self.registrations_succeeded - earlier.registrations_succeeded,
            registrations_failed: self.registrations_failed - earlier.registrations_failed,
            calls_ended: self.calls_ended - earlier.calls_ended,
            media_gaps: self.media_gaps - earlier.media_gaps,
            jitter_buffer_events: self.jitter_buffer_events - earlier.jitter_buffer_events,
            stream_transport_wanted: self.stream_transport_wanted - earlier.stream_transport_wanted,
            active_calls: self.active_calls,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_core::endpoint::{Event as CoreEvent, TransportProtocol};
    use sipral_core::msg::{ParseMode, ParseScratch, parse};
    use sipral_core::sdp::Direction;
    use sipral_ua::{
        Account, AccountId, CallEndReason, Input, OutgoingCall, RegistrarInfo, RegistrationFailure,
        TransportId, UaEvent, Uri, UserAgent,
    };

    use super::{CallDispositionCounts, Counter, Counters, Gauge, RegistrationFailureCounts};
    use crate::codec::Codec;
    use crate::event::MediaEvent;
    use crate::stats::StreamStatistics;

    const TRANSPORT: TransportId = TransportId(1);

    fn local() -> SocketAddr {
        "192.0.2.1:5060".parse().expect("an address")
    }

    fn registrar() -> SocketAddr {
        "192.0.2.50:5060".parse().expect("an address")
    }

    /// A user agent with a bound transport, which [`UserAgent::call`] needs to route an INVITE.
    fn agent(now: Instant) -> UserAgent {
        let mut agent =
            UserAgent::new(sipral_ua::EndpointConfig::default(), [11; 32]).expect("a user agent");
        agent
            .receive(
                Input::TransportBound {
                    transport: TRANSPORT,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .expect("binding a transport");
        agent
    }

    fn account_id(agent: &mut UserAgent) -> AccountId {
        let account = Account::new(
            Uri::parse_str("sip:counter@example.com").expect("a URI"),
            Uri::parse_str("sip:example.com").expect("a URI"),
            Uri::parse_str("sip:counter@192.0.2.1").expect("a URI"),
            TRANSPORT,
            registrar(),
        );
        agent.add_account(account)
    }

    fn statistics(shrunk: u64, stretched: u64) -> StreamStatistics {
        let quality = sipral_rtp::Quality {
            shrunk,
            stretched,
            ..sipral_rtp::Quality::default()
        };
        StreamStatistics {
            codec: Codec::G722,
            quality,
            round_trip: None,
            packets_sent: 0,
            octets_sent: 0,
            fec_recovered: 0,
            silent_for: Duration::ZERO,
            voip_metrics: None,
            feedback: None,
            feedback_counts: sipral_rtp::avpf::FeedbackCounts::default(),
        }
    }

    #[test]
    fn a_counter_only_ever_grows() {
        let mut counter = Counter::default();
        assert_eq!(counter.get(), 0);
        counter.tick();
        counter.tick_by(4);
        assert_eq!(counter.get(), 5);
    }

    #[test]
    fn subtracting_counters_is_saturating_rather_than_panicking() {
        let earlier = Counter::default();
        let mut later = Counter::default();
        later.tick_by(3);
        assert_eq!((later - earlier).get(), 3);
        // readings swapped: zero, not a panic
        assert_eq!((earlier - later).get(), 0);
    }

    #[test]
    fn a_gauge_moves_both_ways_and_never_goes_below_zero() {
        let mut gauge = Gauge::default();
        gauge.increment();
        gauge.increment();
        gauge.decrement();
        assert_eq!(gauge.get(), 1);
        gauge.decrement();
        gauge.decrement();
        assert_eq!(gauge.get(), 0, "a decrement past zero saturates");
    }

    #[test]
    fn registration_failures_are_tallied_by_reason() {
        let mut counts = RegistrationFailureCounts::default();
        counts.tick(RegistrationFailure::Rejected);
        counts.tick(RegistrationFailure::BadCredentials);
        counts.tick(RegistrationFailure::BadCredentials);
        counts.tick(RegistrationFailure::Unreachable);
        counts.tick(RegistrationFailure::Redirected);
        assert_eq!(counts.rejected.get(), 1);
        assert_eq!(counts.bad_credentials.get(), 2);
        assert_eq!(counts.unreachable.get(), 1);
        assert_eq!(counts.redirected.get(), 1);
        assert_eq!(counts.total(), 5);
    }

    #[test]
    fn call_dispositions_are_tallied_by_reason() {
        let mut counts = CallDispositionCounts::default();
        for reason in [
            CallEndReason::LocalHangup,
            CallEndReason::RemoteHangup,
            CallEndReason::Refused,
            CallEndReason::Cancelled,
            CallEndReason::Unreachable,
            CallEndReason::ForkLost,
            CallEndReason::Abandoned,
            CallEndReason::Expired,
        ] {
            counts.tick(reason);
        }
        assert_eq!(counts.local_hangup.get(), 1);
        assert_eq!(counts.remote_hangup.get(), 1);
        assert_eq!(counts.refused.get(), 1);
        assert_eq!(counts.cancelled.get(), 1);
        assert_eq!(counts.unreachable.get(), 1);
        assert_eq!(counts.fork_lost.get(), 1);
        assert_eq!(counts.abandoned.get(), 1);
        assert_eq!(counts.expired.get(), 1);
        assert_eq!(counts.total(), 8);
    }

    #[test]
    fn a_registration_going_out_taking_and_failing_are_told_apart() {
        let now = Instant::now();
        let mut agent = agent(now);
        let account = account_id(&mut agent);
        let mut counters = Counters::default();

        counters.observe_signalling(&UaEvent::Registering { account });
        assert_eq!(counters.registrations_attempted.get(), 1);
        assert_eq!(counters.registrations_succeeded.get(), 0);

        let mut scratch = ParseScratch::new();
        let granted = parse(
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKcounted\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:alice@example.com>;tag=2\r\n\
Call-ID: counted\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
            &mut scratch,
            ParseMode::Strict,
        )
        .expect("a 200 to a REGISTER")
        .to_owned();
        counters.observe_signalling(&UaEvent::Registered {
            account,
            expires: Duration::from_secs(3600),
            refresh_in: Duration::from_secs(3000),
            response: granted,
            info: RegistrarInfo::default(),
        });
        assert_eq!(counters.registrations_succeeded.get(), 1);

        counters.observe_signalling(&UaEvent::RegistrationFailed {
            account,
            reason: RegistrationFailure::Unreachable,
            status: None,
            retry_in: None,
            response: None,
        });
        assert_eq!(counters.registrations_failed.unreachable.get(), 1);
        assert_eq!(counters.registrations_failed.total(), 1);

        // Refreshing and Unregistered are neither attempts nor outcomes; the binding was counted
        // when won
        counters.observe_signalling(&UaEvent::Refreshing { account });
        counters.observe_signalling(&UaEvent::Unregistered { account });
        assert_eq!(counters.registrations_attempted.get(), 1);
        assert_eq!(counters.registrations_succeeded.get(), 1);
    }

    #[test]
    fn a_call_ending_is_counted_under_its_disposition() {
        let now = Instant::now();
        let mut agent = agent(now);
        let account = account_id(&mut agent);
        let call = agent
            .call(
                account,
                &OutgoingCall::new(Uri::parse_str("sip:bob@example.com").expect("a URI")),
                now,
            )
            .expect("the INVITE can be built now that a transport is bound");
        let mut counters = Counters::default();
        counters.observe_signalling(&UaEvent::CallEnded {
            call,
            reason: CallEndReason::Refused,
            status: None,
            response: None,
            request: None,
            causes: Box::default(),
        });
        assert_eq!(counters.calls_ended.refused.get(), 1);
        assert_eq!(counters.calls_ended.total(), 1);
    }

    #[test]
    fn a_message_too_large_for_a_datagram_with_nowhere_to_go_is_counted() {
        let mut counters = Counters::default();
        let event = UaEvent::Unclaimed(CoreEvent::TransportWanted {
            protocol: TransportProtocol::Tcp,
            destination: registrar(),
            request_bytes: 1785,
            limit_bytes: 1299,
        });
        counters.observe_signalling(&event);
        counters.observe_signalling(&event);
        assert_eq!(counters.stream_transport_wanted.get(), 2);
    }

    #[test]
    fn an_unclaimed_event_that_is_not_about_transport_size_counts_nowhere() {
        let mut counters = Counters::default();
        counters.observe_signalling(&UaEvent::Unclaimed(CoreEvent::Overloaded { refused: 9 }));
        assert_eq!(counters.stream_transport_wanted.get(), 0);
    }

    #[test]
    fn media_starting_and_ending_move_the_active_calls_gauge() {
        let mut counters = Counters::default();
        counters.observe_media(&MediaEvent::Started {
            codec: Codec::G722,
            direction: Direction::SendRecv,
        });
        assert_eq!(counters.active_calls.get(), 1);
        counters.observe_media(&MediaEvent::Ended(statistics(0, 0)));
        assert_eq!(counters.active_calls.get(), 0);
    }

    #[test]
    fn a_codec_change_under_a_live_call_does_not_move_the_gauge() {
        // Changed replaces an already counted session; counting it would make the gauge drift up on
        // every re-offer
        let mut counters = Counters::default();
        counters.observe_media(&MediaEvent::Started {
            codec: Codec::G722,
            direction: Direction::SendRecv,
        });
        counters.observe_media(&MediaEvent::Changed {
            codec: Codec::Pcmu,
            direction: Direction::SendRecv,
        });
        assert_eq!(counters.active_calls.get(), 1);
    }

    #[test]
    fn a_stall_counts_as_a_media_gap_and_resuming_does_not_undo_it() {
        let mut counters = Counters::default();
        counters.observe_media(&MediaEvent::Stalled {
            silent_for: Duration::from_secs(11),
        });
        counters.observe_media(&MediaEvent::Resumed {
            silent_for: Duration::from_secs(12),
        });
        assert_eq!(counters.media_gaps.get(), 1);
    }

    #[test]
    fn the_jitter_buffer_adaptations_of_a_finished_call_are_folded_in() {
        let mut counters = Counters::default();
        counters.observe_media(&MediaEvent::Ended(statistics(3, 5)));
        assert_eq!(counters.jitter_buffer_events.get(), 8);
        counters.observe_media(&MediaEvent::Ended(statistics(1, 0)));
        assert_eq!(
            counters.jitter_buffer_events.get(),
            9,
            "cumulative across calls"
        );
    }

    #[test]
    fn a_later_snapshot_minus_an_earlier_one_is_what_happened_in_between() {
        let now = Instant::now();
        let mut agent = agent(now);
        let account = account_id(&mut agent);

        let mut earlier = Counters::default();
        earlier.observe_signalling(&UaEvent::Registering { account });
        earlier.observe_media(&MediaEvent::Started {
            codec: Codec::G722,
            direction: Direction::SendRecv,
        });

        let mut later = earlier;
        later.observe_signalling(&UaEvent::Registering { account });
        later.observe_signalling(&UaEvent::RegistrationFailed {
            account,
            reason: RegistrationFailure::Rejected,
            status: None,
            retry_in: None,
            response: None,
        });

        let delta = later - earlier;
        assert_eq!(
            delta.registrations_attempted.get(),
            1,
            "one more attempt happened"
        );
        assert_eq!(delta.registrations_failed.rejected.get(), 1);
        assert_eq!(
            delta.active_calls.get(),
            later.active_calls.get(),
            "a gauge in a difference reads what it reads now, not a difference"
        );
    }
}
