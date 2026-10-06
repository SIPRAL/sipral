// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A flat set of counters, cheap enough to sample on a timer.
//!
//! D3's complaint is that "is this deployment healthy" gets answered by
//! grepping a log file for a phrase somebody remembers roughly. What is here
//! instead is a handful of numbers an operator reads by asking rather than by
//! searching: how many registrations were attempted, how many of those
//! succeeded, and — the part that actually earns its keep — how the rest
//! failed, split by [`RegistrationFailure`] rather than folded into one
//! number nobody can act on. The same split for [`CallEndReason`]. And three
//! numbers this crate is the first place able to say at all, because they
//! live where signalling and media meet: how many gaps the stall watchdog
//! caught, how many times a call's jitter buffer had to shrink or stretch to
//! stay in sequence, and how many requests would not fit a datagram and found
//! no stream to the destination to go on instead.
//!
//! # Counters and gauges are not the same shape
//!
//! [`Counter`] only grows. [`Gauge`] moves both ways. The distinction is not
//! decoration: a counter answers "how many since I last looked", a gauge
//! answers "how many right now", and a type that let the two be added
//! together would make both answers wrong. Subtracting one [`Counters`]
//! reading from a later one is how the first question gets asked twice and
//! turned into a number — every counter becomes how much it grew, every
//! gauge stays what it currently reads.
//!
//! # Where the numbers come from, and where one of them does not
//!
//! Nowhere but the events [`crate::MediaEngine::poll_event`] already drains.
//! Reading [`Counters`] is one struct copy — nothing here walks the call
//! table or the session map to produce a reading, and nothing here opens a
//! second path to the layers below to learn something the event stream does
//! not already say.
//!
//! Retransmissions are the deliberate absence. `sipral-core` keeps a
//! per-transaction retransmission count privately, inside the transaction
//! state machine that paces timer A, and never raises it as an event; there
//! is nothing passing through [`crate::MediaEngine::poll_event`] to count.
//! Adding one here would mean reading that state through a path this crate
//! does not have rather than one it does, which is exactly the second path
//! this module exists to avoid. `docs/17-observability.md` says the same
//! thing where an operator reading the counter list will look for it.

use sipral_core::endpoint::Event as CoreEvent;
use sipral_ua::{CallEndReason, RegistrationFailure, UaEvent};

use crate::event::MediaEvent;

/// A count that only grows.
///
/// Distinguished from [`Gauge`] in the type, so that a reading of one can
/// never be mistaken for the other: an operator subtracts two of these across
/// a sampling interval and asks "how many happened", never "did it go down".
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

    /// How many happened between an earlier reading and this one.
    ///
    /// Saturating rather than panicking on two readings taken in the wrong
    /// order: a counter that only grows still owes a caller that mixed up
    /// its snapshots an honest answer, and zero is that answer, not a panic
    /// telemetry code should never be able to cause.
    fn sub(self, earlier: Self) -> Self {
        Self(self.0.saturating_sub(earlier.0))
    }
}

/// A count that moves both ways: what is true right now, not what has
/// happened since this engine was created.
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

/// Why a registration attempt failed, tallied the same four ways
/// [`RegistrationFailure`] can say it did.
///
/// A count of failures alone says a deployment is unwell; this says which
/// kind of unwell, which is the difference between paging somebody and
/// telling them what to look at first.
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
            // RegistrationFailure is non_exhaustive: a reason a future minor
            // adds is counted nowhere sooner than it is counted under the
            // wrong name
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
            // CallEndReason is non_exhaustive, for the same reason as above
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

/// D3's flat set of health counters, kept by one [`crate::MediaEngine`] since
/// it was created.
///
/// Reading it is one struct copy: nothing here walks the call table or the
/// session map, so sampling it on a timer and shipping it as telemetry costs
/// nothing an application was not already spending on the poll loop it runs
/// anyway. Subtracting an earlier reading from a later one (`later - earlier`)
/// turns every counter into how much it grew across the interval and leaves
/// every gauge exactly where it reads now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counters {
    /// A REGISTER went out — [`UaEvent::Registering`], counted once per
    /// attempt including a retry, because a retry is a REGISTER that goes out
    /// exactly the way the first one did.
    pub registrations_attempted: Counter,
    /// The registrar granted a binding.
    pub registrations_succeeded: Counter,
    /// The registrar did not, split by why.
    pub registrations_failed: RegistrationFailureCounts,
    /// How every call that has ended, ended.
    pub calls_ended: CallDispositionCounts,
    /// How many times [`MediaEvent::Stalled`] fired: inbound audio stopped
    /// for longer than the configured threshold while signalling stayed
    /// healthy. B5's watchdog, counted rather than only reported live.
    pub media_gaps: Counter,
    /// How many times a call's jitter buffer had to shrink or stretch the
    /// stream to keep its delay where it was aiming —
    /// [`sipral_rtp::Quality`]'s `shrunk` and `stretched`, folded in as each
    /// call ends. Not loss by itself: the buffer adapting is what keeps loss
    /// from becoming audible, and a deployment where this climbs is one whose
    /// network is getting worse before a caller can describe why.
    pub jitter_buffer_events: Counter,
    /// How many times a request would not fit a datagram and there was no
    /// stream to the destination to put it on, so the stack asked for one —
    /// RFC 3261 §18.1.1, B1's own failure story counted rather than only
    /// logged.
    ///
    /// Named for what it counts rather than for what it is about. A request
    /// promoted onto a connection that already existed does **not** raise it,
    /// because nothing is asked for and no event goes out; those live in the
    /// diagnostic record as `transport.promoted.size`
    /// (`docs/14-diagnostics.md`). An operator reading this as "how often does
    /// promotion happen" would read it low and conclude the path is fine.
    pub stream_transport_wanted: Counter,
    /// Calls with media running right now.
    pub active_calls: Gauge,
}

impl Counters {
    /// Take in what the user agent said.
    ///
    /// Called from [`crate::MediaEngine::poll_event`] on every signalling
    /// event it drains, which is the one place this crate already sees all
    /// of them.
    pub(crate) fn observe_signalling(&mut self, event: &UaEvent) {
        match event {
            UaEvent::Registering { .. } => self.registrations_attempted.tick(),
            UaEvent::Registered { .. } => self.registrations_succeeded.tick(),
            UaEvent::RegistrationFailed { reason, .. } => self.registrations_failed.tick(*reason),
            UaEvent::CallEnded { reason, .. } => self.calls_ended.tick(*reason),
            // B1: a message would not fit a datagram and there was no stream
            // to the destination to put it on, so the endpoint asked for one.
            // sipral-ua has no policy for the event and passes it through
            // whole; counting it here does not need one either.
            UaEvent::Unclaimed(CoreEvent::TransportWanted { .. }) => {
                self.stream_transport_wanted.tick();
            }
            _ => {}
        }
    }

    /// Take in what one call's media said.
    ///
    /// Called from [`crate::MediaEngine::poll_event`] on every media event it
    /// drains, for the same reason as [`Counters::observe_signalling`].
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

    /// What changed between an earlier reading and this one: every counter
    /// as how much it grew, every gauge as what it reads now.
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

    /// A user agent with a transport already bound, which is what
    /// [`UserAgent::call`] needs in order to know where an INVITE goes.
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
        // taken the wrong way round: an honest zero, not a panic
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

        // Refreshing and Unregistered are neither an attempt nor a
        // disposition of their own — the binding they describe was already
        // counted when it was won, so counting them again would be counting
        // the same registration twice
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
        // Changed replaces a session that already counted; it must not be
        // counted a second time or the gauge drifts upward on every re-offer
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
