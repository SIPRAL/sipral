// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Time, as a value the caller supplies.
//!
//! Nothing here reads a clock. The caller says what time it is, asks what the
//! next deadline is, and comes back when it has passed — so a timer diagram
//! from RFC 3261 §17 is an ordinary test that runs in microseconds rather than
//! a wait.
//!
//! RFC 3261 Table 4, and RFC 6026 §7.1 and §8.1 for the last two:
//!
//! ```text
//! T1  500 ms   round-trip estimate
//! T2  4 s      longest retransmit interval for non-INVITE requests
//!              and INVITE responses
//! T4  5 s      longest a message stays in the network
//! A   T1, doubling      INVITE retransmit, unreliable transport only
//! B   64*T1             INVITE transaction timeout
//! D   >32 s / 0         wait for response retransmits
//! E   T1, doubling to T2   non-INVITE retransmit, unreliable only
//! F   64*T1             non-INVITE transaction timeout
//! G   T1, doubling to T2   INVITE response retransmit
//! H   64*T1             wait for the ACK
//! I   T4 / 0            absorb ACK retransmits
//! J   64*T1 / 0         absorb request retransmits
//! K   T4 / 0            absorb response retransmits
//! L   64*T1             absorb INVITE retransmits after a 2xx
//! M   64*T1             absorb further 2xx from other forks
//! ```
//!
//! The `/ 0` ones are zero on a reliable transport: nothing retransmits there,
//! so there is nothing to absorb and the machine can terminate at once.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// T1, T2 and T4, from which every other timer is derived.
///
/// The defaults are RFC 3261 Table 4. T1 is an RTT estimate: raising it on a
/// satellite link and lowering it on a LAN are both reasonable, and everything
/// else moves with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerConfig {
    /// Round-trip estimate. 500 ms.
    pub t1: Duration,
    /// Longest retransmit interval. 4 s.
    pub t2: Duration,
    /// Longest a message stays in the network. 5 s.
    pub t4: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TimerConfig {
    /// Table 4's own values: T1 500 ms, T2 4 s, T4 5 s.
    pub const DEFAULT: Self = Self {
        t1: Duration::from_millis(500),
        t2: Duration::from_secs(4),
        t4: Duration::from_secs(5),
    };

    /// 64·T1, which is B, F, H, L and M, and J on an unreliable transport.
    #[must_use]
    pub const fn sixty_four_t1(&self) -> Duration {
        self.t1.saturating_mul(64)
    }

    /// Timer A or G: the *n*-th retransmit interval, doubling from T1.
    ///
    /// `cap` is T2 for timer G and for timer E; timer A has no cap, because
    /// timer B ends the transaction long before doubling would matter (RFC
    /// 3261 §17.1.1.2).
    #[must_use]
    pub fn retransmit(&self, attempt: u32, cap: Option<Duration>) -> Duration {
        let interval = self
            .t1
            .saturating_mul(1_u32.checked_shl(attempt).unwrap_or(u32::MAX));
        match cap {
            Some(cap) if interval > cap => cap,
            _ => interval,
        }
    }

    /// Timer D: how long a client INVITE transaction absorbs retransmissions
    /// of a non-2xx final response.
    ///
    /// "MUST be equal to at least 32 seconds" on an unreliable transport, and
    /// zero on a reliable one.
    #[must_use]
    pub const fn d(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            Duration::from_secs(32)
        }
    }

    /// Timer I or K: T4 on an unreliable transport, zero on a reliable one.
    #[must_use]
    pub const fn t4_or_zero(&self, reliable: bool) -> Duration {
        if reliable { Duration::ZERO } else { self.t4 }
    }

    /// Timer J: 64·T1 on an unreliable transport, zero on a reliable one.
    #[must_use]
    pub const fn j(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            self.sixty_four_t1()
        }
    }

    /// Whether timers A, E and G can ever move: refused otherwise.
    ///
    /// [`Self::retransmit`] is `t1 * 2^attempt`, capped at `t2` for E and G.
    /// `t1` zero makes attempt 0 already zero — the interval A, E and G are
    /// first armed with — and `t2` zero clamps every attempt of E and G down
    /// to zero the moment it is capped, whatever `t1` is. Either way the timer
    /// re-arms at the exact instant it just fired: `Endpoint::handle_timeout`
    /// asks its transactions what is due at `now` in a loop that stops only
    /// when nothing is, and a timer that is always due at `now` again never
    /// lets it stop.
    ///
    /// # Errors
    /// [`TimerConfigError::Unarmable`] when `t1` or `t2` is zero.
    pub const fn validate(&self) -> Result<(), TimerConfigError> {
        if self.t1.is_zero() || self.t2.is_zero() {
            return Err(TimerConfigError::Unarmable);
        }
        Ok(())
    }
}

/// Why an [`TimerConfig`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerConfigError {
    /// `t1` or `t2` is zero, which [`TimerConfig::validate`]'s doc explains.
    Unarmable,
    /// The endpoint's keep-alive interval is zero. RFC 5626 §4.4.1's next
    /// ping is armed at the instant the last one went plus a jitter of that
    /// interval, which is then nothing, so `Endpoint::handle_timeout` would
    /// send pings at one instant forever. No interval at all is how
    /// keep-alives are turned off.
    KeepaliveUnarmable,
}

impl core::fmt::Display for TimerConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unarmable => f.write_str(
                "timers.t1 and timers.t2 must both be greater than zero, or a \
                 retransmit timer re-arms at the same instant forever",
            ),
            Self::KeepaliveUnarmable => f.write_str(
                "keepalive_interval must be greater than zero, or None for no \
                 keep-alives, or a ping re-arms at the same instant forever",
            ),
        }
    }
}

impl core::error::Error for TimerConfigError {}

/// Which timer a firing belongs to, by its RFC 3261 letter.
///
/// The letters are the RFC's, kept as they are: a log line saying "timer B
/// fired" can be read straight against §17.1.1.2 by whoever is holding the
/// capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimerName {
    /// Retransmit the INVITE (§17.1.1.2).
    A,
    /// The INVITE transaction timed out (§17.1.1.2).
    B,
    /// Stop absorbing retransmissions of the final response (§17.1.1.2).
    D,
    /// Retransmit the non-INVITE request (§17.1.2.2).
    E,
    /// The non-INVITE transaction timed out (§17.1.2.2).
    F,
    /// Retransmit the final response (§17.2.1).
    G,
    /// The ACK never came (§17.2.1).
    H,
    /// Stop absorbing retransmissions of the ACK (§17.2.1).
    I,
    /// Stop absorbing retransmissions of the request (§17.2.2).
    J,
    /// Stop absorbing retransmissions of the response (§17.1.2.2).
    K,
    /// Stop absorbing retransmissions of the INVITE after a 2xx
    /// (RFC 6026 §8.1).
    L,
    /// Stop passing further 2xx up from other forks (RFC 6026 §7.1).
    M,
}

impl core::fmt::Display for TimerName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let letter = match *self {
            Self::A => "A",
            Self::B => "B",
            Self::D => "D",
            Self::E => "E",
            Self::F => "F",
            Self::G => "G",
            Self::H => "H",
            Self::I => "I",
            Self::J => "J",
            Self::K => "K",
            Self::L => "L",
            Self::M => "M",
        };
        write!(f, "timer {letter}")
    }
}

/// Where a scheduled timer can be found again, to cancel it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TimerHandle {
    at: Instant,
    seq: u64,
}

/// Deadlines in order, with whatever the caller wants to hang on them.
///
/// A `BTreeMap` rather than a heap with lazy deletion, so that the earliest
/// deadline can be read through a shared reference and is never a cancelled
/// one. Two timers due at the same instant fire in the order they were
/// scheduled, which keeps a test's expectations stable.
#[derive(Debug)]
pub(crate) struct Timers<T> {
    due: BTreeMap<TimerHandle, T>,
    next_seq: u64,
}

impl<T> Timers<T> {
    /// An empty schedule.
    pub(crate) const fn new() -> Self {
        Self {
            due: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Hang `value` on `at`.
    pub(crate) fn schedule(&mut self, at: Instant, value: T) -> TimerHandle {
        let handle = TimerHandle {
            at,
            seq: self.next_seq,
        };
        self.next_seq += 1;
        self.due.insert(handle, value);
        handle
    }

    /// Take one back off, if it is still scheduled.
    pub(crate) fn cancel(&mut self, handle: TimerHandle) -> Option<T> {
        self.due.remove(&handle)
    }

    /// When the caller has to come back. `None` means never, on its own.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.due.keys().next().map(|handle| handle.at)
    }

    /// The next timer that is due at `now`, earliest first.
    ///
    /// Call until it returns `None`: firing one timer can schedule another,
    /// and a caller that comes back late has several to work through.
    pub(crate) fn fire(&mut self, now: Instant) -> Option<T> {
        let handle = *self.due.keys().next()?;
        if handle.at > now {
            return None;
        }
        self.due.remove(&handle)
    }
}

impl<T> Default for Timers<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{TimerConfig, TimerName, Timers};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Fired(TimerName);

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn the_defaults_are_the_ones_in_table_4() {
        let c = TimerConfig::default();
        assert_eq!(c.t1, Duration::from_millis(500));
        assert_eq!(c.t2, Duration::from_secs(4));
        assert_eq!(c.t4, Duration::from_secs(5));
        assert_eq!(c.sixty_four_t1(), Duration::from_secs(32));
    }

    #[test]
    fn a_retransmit_interval_doubles_and_stops_at_its_cap() {
        // timer E and timer G double up to T2; timer A has no cap because
        // timer B ends the transaction first
        let c = TimerConfig::default();
        let capped = |n| c.retransmit(n, Some(c.t2));
        assert_eq!(capped(0), Duration::from_millis(500));
        assert_eq!(capped(1), Duration::from_secs(1));
        assert_eq!(capped(2), Duration::from_secs(2));
        assert_eq!(capped(3), Duration::from_secs(4));
        assert_eq!(capped(4), Duration::from_secs(4));
        assert_eq!(capped(40), Duration::from_secs(4));

        assert_eq!(c.retransmit(3, None), Duration::from_secs(4));
        assert_eq!(c.retransmit(5, None), Duration::from_secs(16));
        // no overflow, whatever the shift
        assert!(c.retransmit(u32::MAX, None) >= Duration::from_secs(16));
    }

    #[test]
    fn the_absorbing_timers_are_zero_on_a_reliable_transport() {
        // nothing retransmits on TCP, so there is nothing to absorb
        let c = TimerConfig::default();
        assert_eq!(c.d(false), Duration::from_secs(32));
        assert_eq!(c.d(true), Duration::ZERO);
        assert_eq!(c.t4_or_zero(false), Duration::from_secs(5));
        assert_eq!(c.t4_or_zero(true), Duration::ZERO);
        assert_eq!(c.j(false), Duration::from_secs(32));
        assert_eq!(c.j(true), Duration::ZERO);
    }

    #[test]
    fn a_timer_config_can_be_tightened_and_everything_moves_with_it() {
        let fast = TimerConfig {
            t1: Duration::from_millis(50),
            ..TimerConfig::default()
        };
        assert_eq!(fast.sixty_four_t1(), Duration::from_millis(3200));
        assert_eq!(fast.retransmit(1, None), Duration::from_millis(100));
    }

    #[test]
    fn nothing_is_due_before_its_deadline() {
        let base = Instant::now();
        let mut timers = Timers::new();
        timers.schedule(at(base, 500), Fired(TimerName::A));
        assert_eq!(timers.next_deadline(), Some(at(base, 500)));
        assert_eq!(timers.fire(at(base, 499)), None);
        assert_eq!(timers.fire(at(base, 500)), Some(Fired(TimerName::A)));
        assert_eq!(timers.next_deadline(), None);
    }

    #[test]
    fn a_caller_that_comes_back_late_gets_them_all_in_order() {
        let base = Instant::now();
        let mut timers = Timers::new();
        timers.schedule(at(base, 4000), Fired(TimerName::B));
        timers.schedule(at(base, 500), Fired(TimerName::A));
        timers.schedule(at(base, 1000), Fired(TimerName::E));
        assert_eq!(timers.next_deadline(), Some(at(base, 500)));

        let mut fired = Vec::new();
        while let Some(Fired(name)) = timers.fire(at(base, 10_000)) {
            fired.push(name);
        }
        assert_eq!(fired, vec![TimerName::A, TimerName::E, TimerName::B]);
    }

    #[test]
    fn two_timers_at_the_same_instant_fire_in_the_order_they_were_scheduled() {
        let base = Instant::now();
        let mut timers = Timers::new();
        timers.schedule(at(base, 100), Fired(TimerName::G));
        timers.schedule(at(base, 100), Fired(TimerName::H));
        let mut fired = Vec::new();
        while let Some(Fired(name)) = timers.fire(at(base, 100)) {
            fired.push(name);
        }
        assert_eq!(fired, vec![TimerName::G, TimerName::H]);
    }

    #[test]
    fn a_cancelled_timer_never_fires_and_is_not_the_next_deadline() {
        let base = Instant::now();
        let mut timers = Timers::new();
        let early = timers.schedule(at(base, 100), Fired(TimerName::A));
        timers.schedule(at(base, 200), Fired(TimerName::B));

        assert_eq!(timers.cancel(early), Some(Fired(TimerName::A)));
        assert_eq!(timers.cancel(early), None);
        assert_eq!(timers.next_deadline(), Some(at(base, 200)));
        assert_eq!(timers.fire(at(base, 1000)), Some(Fired(TimerName::B)));
    }

    #[test]
    fn a_timer_scheduled_in_the_past_is_due_at_once() {
        // timers D, I, J and K are zero on a reliable transport, which means
        // "terminate now" rather than "never"
        let base = Instant::now();
        let mut timers = Timers::new();
        timers.schedule(base, Fired(TimerName::K));
        assert_eq!(timers.next_deadline(), Some(base));
        assert!(timers.fire(base).is_some());
    }

    #[test]
    fn the_letters_read_the_way_the_rfc_writes_them() {
        assert_eq!(TimerName::B.to_string(), "timer B");
        assert_eq!(TimerName::M.to_string(), "timer M");
    }

    #[test]
    fn a_config_with_zero_t1_or_t2_is_refused() {
        assert!(TimerConfig::DEFAULT.validate().is_ok());
        assert_eq!(
            TimerConfig {
                t1: Duration::ZERO,
                ..TimerConfig::DEFAULT
            }
            .validate(),
            Err(super::TimerConfigError::Unarmable)
        );
        assert_eq!(
            TimerConfig {
                t2: Duration::ZERO,
                ..TimerConfig::DEFAULT
            }
            .validate(),
            Err(super::TimerConfigError::Unarmable)
        );
    }

    #[test]
    fn a_zero_t1_would_have_timer_a_re_arm_at_the_same_instant_forever() {
        // the hang `TimerConfig::validate` exists to refuse, shown without a
        // wall clock: an unreliable INVITE client transaction's timer A,
        // driven the way `Endpoint::handle_timeout` drives every transaction's
        // timers — fire whatever is due at `now`, feed the result back in,
        // stop only once nothing is due — for a bounded number of rounds
        // rather than a real one, because a config that is actually broken
        // must not be given the chance to hang the test that proves it
        use crate::msg::{Method, RequestBuilder};
        use crate::transaction::invite_client::InviteClientMachine;
        // bounded rather than "until it stops", because a config that is
        // genuinely broken must not be given the chance to hang the test
        // that proves it: a thousand rounds at the same `now`, all still
        // finding timer A due, is the hang `TimerConfig::validate` exists to
        // refuse — `Endpoint::handle_timeout`'s own loop has nothing else
        // to tell it to stop
        const ROUNDS: u32 = 1_000;

        let broken = TimerConfig {
            t1: Duration::ZERO,
            ..TimerConfig::DEFAULT
        };
        assert!(
            broken.validate().is_err(),
            "the config under test is invalid"
        );

        let request = RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1")
            .from(b"<sip:alice@example.com>;tag=1")
            .to(b"<sip:bob@example.com>")
            .call_id(b"a84b4c76e66710")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap();
        let now = Instant::now();
        let (mut machine, _) = InviteClientMachine::start(request, false, broken, now);

        let mut fired = 0;
        for _ in 0..ROUNDS {
            let Some((_, effects)) = machine.handle_timeout(now) else {
                break;
            };
            assert!(!effects.terminated, "timer A does not end the transaction");
            fired += 1;
        }
        assert_eq!(
            fired, ROUNDS,
            "timer A stopped re-arming at the same instant on its own; the \
             hang this config was refused for no longer reproduces"
        );
    }
}
