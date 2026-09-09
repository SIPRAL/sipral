// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What an endpoint is told once, and then never asked again.
//!
//! Every value here has a default that works against a normal registrar on a
//! normal network. They are settable because the field is full of networks
//! that are not normal: carriers whose round trip is long enough that T1 at
//! 500 ms retransmits into its own echo, access networks whose real MTU is
//! nowhere near Ethernet's, and firewalls that drop an idle connection in
//! well under the two minutes RFC 5626 assumes.

use std::time::Duration;

use crate::msg::{Limits, ParseMode};
use crate::transaction::TimerConfig;

/// The size rule of RFC 3261 §18.1.1, as two numbers.
///
/// "If a request is within 200 bytes of the path MTU, or if it is larger than
/// 1300 bytes and the path MTU is unknown, the request MUST be sent using an
/// RFC 2914 congestion controlled transport protocol, such as TCP."
///
/// The RFC explains both figures: the 200 bytes are headroom for a response
/// that is larger than its request, because a proxy adds `Record-Route` on
/// the way back, and 1300 is what is left of a 1500-byte Ethernet MTU once
/// that headroom is taken off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramLimit {
    /// The path MTU, when the caller knows it. Nothing here measures one.
    pub path_mtu: Option<u32>,
    /// How much of a known MTU to leave for the response. 200.
    pub headroom_bytes: u32,
    /// The largest request to put in a datagram when the MTU is unknown. 1300.
    pub max_datagram_bytes: u32,
}

impl DatagramLimit {
    /// The figures from §18.1.1.
    pub const DEFAULT: Self = Self {
        path_mtu: None,
        headroom_bytes: 200,
        max_datagram_bytes: 1_300,
    };

    /// The largest request that still goes in a datagram, and `None` when the
    /// configured MTU leaves room for none at all.
    ///
    /// A size that did not fit says nothing on its own, so this is the other
    /// half of what a bug report needs: the number the request was measured
    /// against. It is carried by [`Event::TransportWanted`], which is where an
    /// application reads it.
    ///
    /// [`Event::TransportWanted`]: super::Event::TransportWanted
    #[must_use]
    pub const fn largest_datagram_request(&self) -> Option<u32> {
        match self.path_mtu {
            // "within 200 bytes of the path MTU" — at the boundary too, since
            // a request exactly 200 bytes short of the MTU leaves a response
            // no room at all, so the last size that fits is one below the
            // difference
            Some(mtu) => match mtu.checked_sub(self.headroom_bytes) {
                Some(room) => room.checked_sub(1),
                None => None,
            },
            None => Some(self.max_datagram_bytes),
        }
    }

    /// Whether a request of this size has to leave over something congestion
    /// controlled rather than over a datagram.
    #[must_use]
    pub fn too_big_for_a_datagram(&self, request_bytes: usize) -> bool {
        let Ok(size) = u32::try_from(request_bytes) else {
            // larger than four gigabytes is not a datagram by any reading
            return true;
        };
        self.largest_datagram_request()
            .is_none_or(|largest| size > largest)
    }
}

impl Default for DatagramLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Everything an endpoint is configured with.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct EndpointConfig {
    /// T1, T2 and T4, from which every RFC 3261 §17 timer is derived.
    pub timers: TimerConfig,
    /// How strictly to read what arrives. Lenient by default: real
    /// deployments emit malformed messages daily, and a stack that refuses
    /// them loses calls a competitor completes.
    pub parse_mode: ParseMode,
    /// The parser's bounds, which are what stops a hostile peer from making
    /// it do unbounded work.
    pub limits: Limits,
    /// When a request is too large for a datagram (§18.1.1).
    pub datagram_limit: DatagramLimit,
    /// Whether to put `;rport` on every `Via` we write (RFC 3581 §3).
    ///
    /// The RFC makes this a MAY. It is on, because the alternative is not
    /// receiving responses from behind the NAT that nearly every softphone
    /// sits behind, and a server that does not implement RFC 3581 ignores an
    /// empty `rport` rather than failing on it.
    pub always_request_rport: bool,
    /// The longest a stream transport may sit idle before a double-CRLF goes
    /// out on it (RFC 5626 §4.4.1). `None` turns keepalives off.
    ///
    /// This is an upper bound, not a period: §4.4.1 requires the interval to
    /// be picked at random between it and 20% below it, so that a server does
    /// not get every client's ping at the same instant.
    pub keepalive_interval: Option<Duration>,
    /// The most server transactions a peer may have open here at once.
    ///
    /// Once the parser has refused what it can refuse, an arriving request is a
    /// well-formed request, and a peer that sends a thousand of them a second
    /// costs a transaction each. This is the ceiling on that: past it a request
    /// that would create a new server transaction is answered 503 rather than
    /// held, and the endpoint keeps answering the ones it already has.
    pub max_server_transactions: usize,
    /// The most dialogs that may be live at once, in either direction.
    ///
    /// A transaction lasts seconds and a dialog lasts as long as the call, so
    /// this is the one a slow flood reaches: a thousand INVITEs that are all
    /// answered leave a thousand calls standing.
    pub max_dialogs: usize,
}

impl EndpointConfig {
    /// The defaults.
    ///
    /// `keepalive_interval` is 25 s rather than the 120 s RFC 5626 §4.4.1
    /// suggests. That figure assumes a network which leaves an idle TCP
    /// connection alone for longer than two minutes, and carrier-grade NATs
    /// routinely do not; a softphone that discovers a dead flow two minutes
    /// after it died has already missed the call it existed for. The cost is
    /// four bytes every 25 seconds per connection.
    ///
    /// The two ceilings are set where a softphone will never see them and a
    /// flood will: 256 concurrent server transactions is an order of magnitude
    /// more than a busy desk phone reaches, and 128 live dialogs is more calls
    /// than one person can hold. A media server built on this crate raises
    /// them; nothing here has to guess how far.
    pub const DEFAULT: Self = Self {
        timers: TimerConfig::DEFAULT,
        parse_mode: ParseMode::Lenient,
        limits: Limits::DEFAULT,
        datagram_limit: DatagramLimit::DEFAULT,
        always_request_rport: true,
        keepalive_interval: Some(Duration::from_secs(25)),
        max_server_transactions: 256,
        max_dialogs: 128,
    };
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::{DatagramLimit, EndpointConfig};
    use std::time::Duration;

    #[test]
    fn with_no_known_mtu_the_line_is_1300() {
        let limit = DatagramLimit::DEFAULT;
        assert!(!limit.too_big_for_a_datagram(1_300));
        assert!(limit.too_big_for_a_datagram(1_301));
        assert!(!limit.too_big_for_a_datagram(0));
    }

    #[test]
    fn a_known_mtu_keeps_200_bytes_back_for_the_response() {
        // the headroom is there because a response can be larger than its
        // request: a proxy adds Record-Route on the way back
        let limit = DatagramLimit {
            path_mtu: Some(1_500),
            ..DatagramLimit::DEFAULT
        };
        assert!(!limit.too_big_for_a_datagram(1_299));
        assert!(limit.too_big_for_a_datagram(1_300));
        assert!(limit.too_big_for_a_datagram(1_400));
    }

    #[test]
    fn a_small_mtu_moves_the_line_with_it() {
        // access networks where the real MTU is nowhere near Ethernet's are
        // the reason this is configurable at all
        let limit = DatagramLimit {
            path_mtu: Some(576),
            ..DatagramLimit::DEFAULT
        };
        assert!(!limit.too_big_for_a_datagram(375));
        assert!(limit.too_big_for_a_datagram(376));
    }

    #[test]
    fn an_mtu_smaller_than_the_headroom_sends_nothing_by_datagram() {
        let limit = DatagramLimit {
            path_mtu: Some(100),
            ..DatagramLimit::DEFAULT
        };
        assert!(limit.too_big_for_a_datagram(0));
    }

    #[test]
    fn a_size_that_does_not_fit_in_the_arithmetic_is_too_big() {
        let limit = DatagramLimit::DEFAULT;
        assert!(limit.too_big_for_a_datagram(usize::MAX));
    }

    #[test]
    fn the_limit_reported_is_the_last_size_that_would_have_gone() {
        assert_eq!(
            DatagramLimit::DEFAULT.largest_datagram_request(),
            Some(1_300)
        );
        assert_eq!(
            DatagramLimit {
                path_mtu: Some(1_500),
                ..DatagramLimit::DEFAULT
            }
            .largest_datagram_request(),
            Some(1_299)
        );
        // no room for a request of any size, not even an empty one
        assert_eq!(
            DatagramLimit {
                path_mtu: Some(200),
                ..DatagramLimit::DEFAULT
            }
            .largest_datagram_request(),
            None
        );
    }

    #[test]
    fn the_limit_reported_is_the_one_the_switch_was_decided_on() {
        // the two are read side by side in a bug report — "1785 bytes, limit
        // 1299" — so a limit that disagreed with the decision would be worse
        // than none at all
        for mtu in [None, Some(200), Some(576), Some(1_500), Some(9_000)] {
            let limit = DatagramLimit {
                path_mtu: mtu,
                ..DatagramLimit::DEFAULT
            };
            let largest = limit
                .largest_datagram_request()
                .map(|largest| usize::try_from(largest).expect("a size that fits a pointer"));
            for size in 0..2_000_usize {
                assert_eq!(
                    limit.too_big_for_a_datagram(size),
                    largest.is_none_or(|largest| size > largest),
                    "{mtu:?} at {size}"
                );
            }
        }
    }

    #[test]
    fn the_defaults_are_the_ones_the_documents_promise() {
        let config = EndpointConfig::default();
        assert_eq!(config.timers.t1, Duration::from_millis(500));
        assert!(config.always_request_rport);
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(25)));
        assert_eq!(config.datagram_limit.max_datagram_bytes, 1_300);
        assert_eq!(config.datagram_limit.headroom_bytes, 200);
        assert_eq!(config.datagram_limit.path_mtu, None);
        assert_eq!(config.max_server_transactions, 256);
        assert_eq!(config.max_dialogs, 128);
    }
}
