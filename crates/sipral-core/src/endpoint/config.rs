// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What an endpoint is told once, and then never asked again.
//!
//! The defaults suit a normal network. They are settable for the others:
//! long round trips, small MTUs, firewalls that drop idle connections early.

use std::time::Duration;

use crate::diag::RecordLimits;
use crate::msg::{Limits, ParseMode};
use crate::transaction::TimerConfig;

/// The size rule of RFC 3261 §18.1.1, as two numbers.
///
/// The 200 bytes are headroom for a response that a proxy grew with
/// `Record-Route`; 1300 is a 1500-byte MTU less that headroom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramLimit {
    /// The path MTU, when the caller knows it. Nothing here measures one.
    pub path_mtu: Option<u32>,
    /// How much of a known MTU to leave for the response. 200.
    pub headroom_bytes: u32,
    /// The largest request to put in a datagram when the MTU is unknown. 1300.
    pub max_datagram_bytes: u32,
    /// The largest request to send over the datagram anyway, once the caller
    /// has said the stream §18.1.1 asked for cannot be had
    /// ([`Endpoint::no_stream_coming`](super::Endpoint::no_stream_coming)).
    ///
    /// **A deliberate deviation from §18.1.1**, off by default, for a PBX
    /// that takes SIP over UDP only. A caller that knows its path should set
    /// [`DatagramLimit::path_mtu`] instead. A request past this size is still
    /// not sent. Each request sent this way is
    /// recorded as `transport.kept.datagram`.
    pub without_stream_bytes: Option<u32>,
    /// When a request bound for a datagram is written in its compact form
    /// ([`Compaction`]). Only when it would not fit otherwise, by default.
    pub compaction: Compaction,
}

/// When a request bound for a datagram is written small, before RFC 3261
/// §18.1.1 moves it to a stream.
///
/// Compact means the §7.3.3 one-letter header names and no optional spaces,
/// about ninety bytes off an INVITE. A request still too large then drops
/// `Allow` (§20.5). Stream transports are never written compact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compaction {
    /// Every request in full, and §18.1.1 decides on the full size.
    Never,
    /// Only a request too large for a datagram is written compact. The
    /// default: it keeps UDP-only servers reachable without hurting
    /// readability.
    #[default]
    WhenOversize,
    /// Every datagram request is written compact, for a path narrower than
    /// the limit says (a 1280-byte tunnel).
    Always,
}

impl DatagramLimit {
    /// The figures from §18.1.1.
    pub const DEFAULT: Self = Self {
        path_mtu: None,
        headroom_bytes: 200,
        max_datagram_bytes: 1_300,
        without_stream_bytes: None,
        compaction: Compaction::WhenOversize,
    };

    /// Whether a request of this size goes over the datagram once no stream
    /// is coming ([`DatagramLimit::without_stream_bytes`]).
    #[must_use]
    pub fn fits_without_stream(&self, request_bytes: usize) -> bool {
        self.without_stream_bytes
            .is_some_and(|largest| u32::try_from(request_bytes).is_ok_and(|size| size <= largest))
    }

    /// The largest request that still goes in a datagram, and `None` when the
    /// configured MTU leaves room for none at all.
    ///
    /// Reported in [`Event::TransportWanted`].
    ///
    /// [`Event::TransportWanted`]: super::Event::TransportWanted
    #[must_use]
    pub const fn largest_datagram_request(&self) -> Option<u32> {
        match self.path_mtu {
            // "within 200 bytes" includes the boundary, hence the minus one
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
    /// deployments send malformed messages daily.
    pub parse_mode: ParseMode,
    /// The parser's bounds against a hostile peer.
    pub limits: Limits,
    /// The same for the SDP body (RFC 4566).
    pub sdp_limits: crate::sdp::Limits,
    /// When a request is too large for a datagram (§18.1.1).
    pub datagram_limit: DatagramLimit,
    /// Whether to put `;rport` on every `Via` we write (RFC 3581 §3).
    ///
    /// A MAY, on by default: without it responses do not reach a phone behind
    /// NAT, and servers without RFC 3581 ignore it.
    pub always_request_rport: bool,
    /// The longest a stream transport may sit idle before a double-CRLF goes
    /// out on it (RFC 5626 §4.4.1). `None` turns keepalives off.
    ///
    /// An upper bound: §4.4.1 picks the interval at random up to 20% below it.
    pub keepalive_interval: Option<Duration>,
    /// The most server transactions a peer may have open here at once.
    ///
    /// Past it, a request that would open a new one is answered 503.
    pub max_server_transactions: usize,
    /// The most dialogs that may be live at once, in either direction.
    ///
    /// Calls count from their INVITE, not from the dialog, so INVITEs that
    /// arrive together cannot pass the ceiling. An incoming one with no room
    /// gets 503 with `Retry-After: 2` (RFC 3261 §21.5.4); an outgoing one
    /// fails with [`super::SendError::LimitReached`].
    ///
    /// The first dialog and the first 2xx of a sent INVITE always open.
    /// Further fork branches need room; a 2xx without it is not acknowledged
    /// and the far end sends BYE (RFC 3261 §13.3.1.4).
    pub max_dialogs: usize,
    /// How much of what the endpoint decided it keeps
    /// ([`crate::diag`]).
    pub diagnostics: RecordLimits,
}

impl EndpointConfig {
    /// The defaults.
    ///
    /// `keepalive_interval` is 25 s, not the 120 s of RFC 5626 §4.4.1:
    /// carrier-grade NATs drop idle TCP sooner. The ceilings are far above a
    /// softphone's needs; a media server raises them.
    pub const DEFAULT: Self = Self {
        timers: TimerConfig::DEFAULT,
        parse_mode: ParseMode::Lenient,
        limits: Limits::DEFAULT,
        sdp_limits: crate::sdp::Limits::DEFAULT,
        datagram_limit: DatagramLimit::DEFAULT,
        always_request_rport: true,
        keepalive_interval: Some(Duration::from_secs(25)),
        max_server_transactions: 256,
        max_dialogs: 128,
        diagnostics: RecordLimits::DEFAULT,
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
        // §18.1.1 is kept unless a deployment says otherwise
        assert_eq!(config.datagram_limit.without_stream_bytes, None);
        assert!(!config.datagram_limit.fits_without_stream(1));
        assert_eq!(config.max_server_transactions, 256);
        assert_eq!(config.max_dialogs, 128);
        assert_eq!(config.diagnostics.max_decisions, 64);
        assert_eq!(config.diagnostics.max_records, 32);
    }

    #[test]
    fn the_size_kept_on_the_datagram_without_a_stream_is_inclusive() {
        let limit = DatagramLimit {
            without_stream_bytes: Some(1_500),
            ..DatagramLimit::DEFAULT
        };
        assert!(limit.fits_without_stream(1_500));
        assert!(!limit.fits_without_stream(1_501));
        assert!(limit.too_big_for_a_datagram(1_301));
    }
}
